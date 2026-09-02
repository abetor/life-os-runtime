"""Portable project lifecycle with crash-replayable scheduler boundaries.

The projects zone is the source of truth.  Lifecycle transitions are prepared
as durable local intents, applied under a zone lock, and only then exposed to
the optional scheduler port and the run envelope.  The scheduler is never
imported and this module never reads or writes ``agent/schedule``.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
from typing import Callable, Mapping, Protocol, Sequence
import unicodedata
import uuid

from tool_life_os_runtime.ext.review.authority import (
    ActionCapability,
    AuthorityError,
    AuthorityPolicy,
)
from tool_life_os_runtime.ext.runs import (
    ActionUse,
    PreparedArtifact,
    RunError,
    RunStore,
)
from tool_life_os_runtime.ext.vault.schema import VaultPathResolver, VaultSchemaError


PROJECT_SCHEMA_VERSION = 1
PROJECT_STATE_SCHEMA_VERSION = 1
PROJECT_TRANSITION_SCHEMA_VERSION = 1
PROJECT_SCHEDULE_SCHEMA_VERSION = 1
PROJECT_MIGRATION_SCHEMA_VERSION = 1

_ID = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
_SLUG = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_KINDS = frozenset({"general", "research"})
_STATUSES = frozenset({"active", "on-hold", "archived"})
_STEP_STATUSES = frozenset({"open", "done", "skipped"})
_PRIORITIES = frozenset({"low", "medium", "high"})
_ITEM_STATUSES = frozenset({"open", "resolved"})
_QUESTION_STATUSES = frozenset({"open", "answered"})
_MILESTONE_STATUSES = frozenset({"planned", "reached", "dropped"})
_CHILD_POLICIES = frozenset({"refuse", "cascade", "keep-active"})
_SCHEDULE_STATUSES = frozenset({"active", "paused", "disabled"})
_ARCHIVE_KEYS = frozenset({"_archive", "_trash", "_on_hold"})
_MAX_JSON = 1024 * 1024
_MAX_LOG = 4 * 1024 * 1024
_PRIVATE_PATH = re.compile(r"(?i)(?:/users/|/home/|[a-z]:\\users\\|[a-z]:\\home\\)")
_FILE_SCHEME = re.compile(r"(?i)(?:^|[^a-z0-9_])file:")
_SECRET = re.compile(
    r"(?i)(?:api[_ -]?key|authorization|bearer|cookie|credential|password|secret|token)"
    r"[\"']?\s*[:=]"
)


class ProjectFlowError(ValueError):
    """Project input, durable state, authority, or replay is unsafe."""


def _fail(message: str) -> None:
    raise ProjectFlowError(message)


def _portable_key(value: str) -> str:
    return unicodedata.normalize("NFC", value).casefold()


def _text(
    value: object, label: str, *, limit: int = 4096, allow_empty: bool = False
) -> str:
    if not isinstance(value, str) or value != unicodedata.normalize("NFC", value):
        _fail(f"{label} must be NFC text")
    try:
        encoded = value.encode("utf-8")
    except UnicodeError:
        _fail(f"{label} must be valid UTF-8 text")
    if (not allow_empty and not value.strip()) or len(encoded) > limit:
        _fail(f"{label} must be bounded text")
    if any(
        unicodedata.category(character).startswith("C")
        or unicodedata.category(character) in {"Zl", "Zp"}
        for character in value
    ):
        _fail(f"{label} contains non-portable characters")
    folded = value.casefold()
    if (
        _PRIVATE_PATH.search(folded)
        or _FILE_SCHEME.search(folded)
        or _SECRET.search(value)
    ):
        _fail(f"{label} contains private or credential-like text")
    return value


def _identifier(value: object, label: str, pattern: re.Pattern[str] = _ID) -> str:
    text = _text(value, label, limit=64)
    if pattern.fullmatch(text) is None or _portable_key(text) in _ARCHIVE_KEYS:
        _fail(f"{label} is invalid")
    return text


def _timestamp(value: object, label: str) -> str:
    text = _text(value, label, limit=40)
    if _UTC.fullmatch(text) is None:
        _fail(f"{label} must be UTC")
    try:
        parsed = datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError:
        _fail(f"{label} must be UTC")
    if parsed.tzinfo is None:
        _fail(f"{label} must be UTC")
    return text


def _hash(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        _fail(f"{label} must be sha256")
    return value


def _canonical(payload: Mapping[str, object]) -> bytes:
    try:
        data = (
            json.dumps(
                payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
            + b"\n"
        )
    except (TypeError, ValueError, UnicodeError, RecursionError):
        _fail("project payload is not canonical UTF-8 JSON")
    if len(data) > _MAX_JSON:
        _fail("project payload is too large")
    return data


def _digest_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _digest_payload(payload: Mapping[str, object]) -> str:
    return _digest_bytes(_canonical(payload))


def _decode_json(
    data: bytes, label: str, *, maximum: int = _MAX_JSON
) -> dict[str, object]:
    if not isinstance(data, bytes) or not data or len(data) > maximum:
        _fail(f"{label} bytes are invalid or too large")
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeError, ValueError, RecursionError):
        _fail(f"{label} is invalid JSON")
    if not isinstance(value, dict):
        _fail(f"{label} must be a JSON object")
    return value


@dataclass(frozen=True)
class ProjectStep:
    step_id: str
    text: str
    status: str = "open"
    priority: str = "medium"


@dataclass(frozen=True)
class ProjectBlocker:
    blocker_id: str
    text: str
    status: str = "open"


@dataclass(frozen=True)
class ProjectQuestion:
    question_id: str
    text: str
    status: str = "open"
    answer: str | None = None


@dataclass(frozen=True)
class ProjectMilestone:
    milestone_id: str
    text: str
    status: str = "planned"


@dataclass(frozen=True)
class ProjectSession:
    at: str
    summary: str


@dataclass(frozen=True)
class ProjectState:
    schema_version: int
    project_slug: str
    revision: int
    next_steps: tuple[ProjectStep, ...]
    blockers: tuple[ProjectBlocker, ...]
    open_questions: tuple[ProjectQuestion, ...]
    milestones: tuple[ProjectMilestone, ...]
    last_session: ProjectSession | None


@dataclass(frozen=True)
class ProjectRecord:
    schema_version: int
    slug: str
    name: str
    goal: str
    domains: tuple[str, ...]
    kind: str
    status: str
    created_at: str
    updated_at: str
    on_hold_since: str | None
    on_hold_reason: str | None
    archived_at: str | None
    revision: int
    last_transition_id: str
    schedule_ids: tuple[str, ...]


@dataclass(frozen=True)
class ProjectSnapshot:
    record: ProjectRecord
    state: ProjectState
    location: str
    project_sha256: str
    state_sha256: str
    log_sha256: str
    snapshot_sha256: str


@dataclass(frozen=True)
class ProjectAdvance:
    next_steps: tuple[ProjectStep, ...]
    blockers: tuple[ProjectBlocker, ...]
    open_questions: tuple[ProjectQuestion, ...]
    milestones: tuple[ProjectMilestone, ...]
    session: ProjectSession
    summary: str


@dataclass(frozen=True)
class ScheduleSnapshot:
    schedule_id: str
    status: str
    sha256: str


@dataclass(frozen=True)
class ProjectScheduleIntent:
    schema_version: int
    transition_id: str
    project_slug: str
    action: str
    schedule_ids: tuple[str, ...]
    reason: str
    expected: tuple[ScheduleSnapshot, ...] = ()


@dataclass(frozen=True)
class ScheduleReceipt:
    schema_version: int
    transition_id: str
    status: str
    effect_hash: str


class ProjectSchedulePort(Protocol):
    """Connector-owned idempotent scheduler boundary."""

    def observe(
        self, project_slug: str, schedule_ids: tuple[str, ...]
    ) -> tuple[ScheduleSnapshot, ...]: ...

    def apply(self, intent: ProjectScheduleIntent) -> ScheduleReceipt: ...


@dataclass(frozen=True)
class ProjectTransitionResult:
    snapshot: ProjectSnapshot
    transition_id: str
    operation: str
    child_policy: str | None
    archived_children: tuple[str, ...]
    schedule_pending: bool
    schedule_receipt: ScheduleReceipt | None
    replayed: bool


@dataclass(frozen=True)
class ProjectMigrationPlan:
    schema_version: int
    slug: str
    target_relative: str
    source_project_sha256: str
    source_state_sha256: str
    source_log_sha256: str
    project_bytes: bytes
    state_bytes: bytes
    log_bytes: bytes
    plan_sha256: str


@dataclass(frozen=True)
class ProjectCapabilities:
    read: ActionCapability
    commit: ActionCapability
    run: ActionCapability
    schedule: ActionCapability | None = None


def expected_schedule_effect_hash(intent: ProjectScheduleIntent) -> str:
    """Bind a scheduler receipt to the exact canonical connector request."""

    if not isinstance(intent, ProjectScheduleIntent):
        _fail("schedule effect requires a ProjectScheduleIntent")
    if (
        intent.schema_version != PROJECT_SCHEDULE_SCHEMA_VERSION
        or intent.action not in {"pause", "verify"}
    ):
        _fail("schedule effect intent schema or action is invalid")
    _identifier(intent.transition_id, "schedule effect transition_id")
    _identifier(intent.project_slug, "schedule effect project_slug", _SLUG)
    schedule_ids = tuple(
        _identifier(item, "schedule effect schedule_id") for item in intent.schedule_ids
    )
    if len(schedule_ids) != len(set(schedule_ids)):
        _fail("schedule effect schedule ids are duplicated")
    _text(intent.reason, "schedule effect reason")
    expected_ids: list[str] = []
    for item in intent.expected:
        if (
            not isinstance(item, ScheduleSnapshot)
            or item.status not in _SCHEDULE_STATUSES
        ):
            _fail("schedule effect expected state is invalid")
        expected_ids.append(
            _identifier(item.schedule_id, "schedule effect expected id")
        )
        _hash(item.sha256, "schedule effect expected hash")
    if len(expected_ids) != len(set(expected_ids)):
        _fail("schedule effect expected ids are duplicated")
    payload = {
        "schema_version": intent.schema_version,
        "transition_id": intent.transition_id,
        "project_slug": intent.project_slug,
        "action": intent.action,
        "schedule_ids": list(intent.schedule_ids),
        "reason": intent.reason,
        "expected": [
            {
                "schedule_id": item.schedule_id,
                "status": item.status,
                "sha256": item.sha256,
            }
            for item in intent.expected
        ],
    }
    return hashlib.sha256(
        b"lifeos-project-schedule-effect-v1\0" + _canonical(payload)
    ).hexdigest()


def _step_payload(item: ProjectStep) -> dict[str, object]:
    if not isinstance(item, ProjectStep):
        _fail("project step has invalid type")
    step_id = _identifier(item.step_id, "step_id")
    text = _text(item.text, "step text")
    if item.status not in _STEP_STATUSES or item.priority not in _PRIORITIES:
        _fail("project step status or priority is invalid")
    return {
        "id": step_id,
        "text": text,
        "status": item.status,
        "priority": item.priority,
    }


def _blocker_payload(item: ProjectBlocker) -> dict[str, object]:
    if not isinstance(item, ProjectBlocker):
        _fail("project blocker has invalid type")
    if item.status not in _ITEM_STATUSES:
        _fail("project blocker status is invalid")
    return {
        "id": _identifier(item.blocker_id, "blocker_id"),
        "text": _text(item.text, "blocker text"),
        "status": item.status,
    }


def _question_payload(item: ProjectQuestion) -> dict[str, object]:
    if not isinstance(item, ProjectQuestion) or item.status not in _QUESTION_STATUSES:
        _fail("project question is invalid")
    answer = None if item.answer is None else _text(item.answer, "question answer")
    if (item.status == "answered") != (answer is not None):
        _fail("question answer disagrees with status")
    return {
        "id": _identifier(item.question_id, "question_id"),
        "text": _text(item.text, "question text"),
        "status": item.status,
        "answer": answer,
    }


def _milestone_payload(item: ProjectMilestone) -> dict[str, object]:
    if not isinstance(item, ProjectMilestone) or item.status not in _MILESTONE_STATUSES:
        _fail("project milestone is invalid")
    return {
        "id": _identifier(item.milestone_id, "milestone_id"),
        "text": _text(item.text, "milestone text"),
        "status": item.status,
    }


def _session_payload(item: ProjectSession | None) -> dict[str, object] | None:
    if item is None:
        return None
    if not isinstance(item, ProjectSession):
        _fail("project session has invalid type")
    return {
        "at": _timestamp(item.at, "session at"),
        "summary": _text(item.summary, "session summary"),
    }


def _unique_payloads(
    items: Sequence[object], render: Callable[[object], dict[str, object]]
) -> list[dict[str, object]]:
    if not isinstance(items, tuple) or len(items) > 256:
        _fail("project collection must be a bounded tuple")
    payloads = [render(item) for item in items]
    ids = [str(item["id"]) for item in payloads]
    if len(ids) != len(set(ids)):
        _fail("project collection ids must be unique")
    return payloads


def _state_payload(state: ProjectState) -> dict[str, object]:
    if (
        not isinstance(state, ProjectState)
        or state.schema_version != PROJECT_STATE_SCHEMA_VERSION
    ):
        _fail("project state schema is invalid")
    slug = _identifier(state.project_slug, "project slug", _SLUG)
    if type(state.revision) is not int or state.revision < 1:
        _fail("project state revision is invalid")
    return {
        "schema_version": PROJECT_STATE_SCHEMA_VERSION,
        "project_slug": slug,
        "revision": state.revision,
        "next_steps": _unique_payloads(state.next_steps, _step_payload),
        "blockers": _unique_payloads(state.blockers, _blocker_payload),
        "open_questions": _unique_payloads(state.open_questions, _question_payload),
        "milestones": _unique_payloads(state.milestones, _milestone_payload),
        "last_session": _session_payload(state.last_session),
    }


def _record_payload(record: ProjectRecord) -> dict[str, object]:
    if (
        not isinstance(record, ProjectRecord)
        or record.schema_version != PROJECT_SCHEMA_VERSION
    ):
        _fail("project record schema is invalid")
    slug = _identifier(record.slug, "project slug", _SLUG)
    if record.kind not in _KINDS or record.status not in _STATUSES:
        _fail("project kind or status is invalid")
    if type(record.revision) is not int or record.revision < 1:
        _fail("project revision is invalid")
    domains = tuple(_identifier(item, "domain", _SLUG) for item in record.domains)
    schedules = tuple(_identifier(item, "schedule_id") for item in record.schedule_ids)
    if not domains or len(domains) > 32 or len(set(domains)) != len(domains):
        _fail("project domains are invalid")
    if len(schedules) > 128 or len(set(schedules)) != len(schedules):
        _fail("project schedule ids are invalid")
    created = _timestamp(record.created_at, "created_at")
    updated = _timestamp(record.updated_at, "updated_at")
    hold_since = (
        None
        if record.on_hold_since is None
        else _timestamp(record.on_hold_since, "on_hold_since")
    )
    hold_reason = (
        None
        if record.on_hold_reason is None
        else _text(record.on_hold_reason, "on_hold_reason")
    )
    archived = (
        None
        if record.archived_at is None
        else _timestamp(record.archived_at, "archived_at")
    )
    if record.status == "active" and any(
        value is not None for value in (hold_since, hold_reason, archived)
    ):
        _fail("active project has lifecycle-only fields")
    if record.status == "on-hold" and (
        hold_since is None or hold_reason is None or archived is not None
    ):
        _fail("held project lifecycle fields are invalid")
    if record.status == "archived" and archived is None:
        _fail("archived project lacks archived_at")
    return {
        "schema_version": PROJECT_SCHEMA_VERSION,
        "slug": slug,
        "name": _text(record.name, "project name", limit=512),
        "goal": _text(record.goal, "project goal", limit=16384),
        "domains": list(domains),
        "kind": record.kind,
        "status": record.status,
        "created_at": created,
        "updated_at": updated,
        "on_hold_since": hold_since,
        "on_hold_reason": hold_reason,
        "archived_at": archived,
        "revision": record.revision,
        "last_transition_id": _identifier(
            record.last_transition_id, "last_transition_id"
        ),
        "schedule_ids": list(schedules),
    }


def _parse_state(payload: Mapping[str, object]) -> ProjectState:
    expected = {
        "schema_version",
        "project_slug",
        "revision",
        "next_steps",
        "blockers",
        "open_questions",
        "milestones",
        "last_session",
    }
    if set(payload) != expected:
        _fail("project state has missing or unknown fields")
    if (
        type(payload["schema_version"]) is not int
        or not isinstance(payload["project_slug"], str)
        or type(payload["revision"]) is not int
    ):
        _fail("project state scalar fields are invalid")

    def sequence(name: str) -> list[Mapping[str, object]]:
        value = payload[name]
        if not isinstance(value, list) or not all(
            isinstance(item, Mapping) for item in value
        ):
            _fail(f"project state {name} is invalid")
        return list(value)

    raw_steps = sequence("next_steps")
    raw_blockers = sequence("blockers")
    raw_questions = sequence("open_questions")
    raw_milestones = sequence("milestones")
    for item in raw_steps:
        if set(item) != {"id", "text", "status", "priority"} or not all(
            isinstance(item[key], str) for key in item
        ):
            _fail("project step payload is invalid")
    for item in raw_blockers:
        if set(item) != {"id", "text", "status"} or not all(
            isinstance(item[key], str) for key in item
        ):
            _fail("project blocker payload is invalid")
    for item in raw_questions:
        if (
            set(item) != {"id", "text", "status", "answer"}
            or not all(isinstance(item[key], str) for key in ("id", "text", "status"))
            or (item["answer"] is not None and not isinstance(item["answer"], str))
        ):
            _fail("project question payload is invalid")
    for item in raw_milestones:
        if set(item) != {"id", "text", "status"} or not all(
            isinstance(item[key], str) for key in item
        ):
            _fail("project milestone payload is invalid")
    steps = tuple(
        ProjectStep(x["id"], x["text"], x["status"], x["priority"]) for x in raw_steps
    )
    blockers = tuple(
        ProjectBlocker(x["id"], x["text"], x["status"]) for x in raw_blockers
    )
    questions = tuple(
        ProjectQuestion(x["id"], x["text"], x["status"], x["answer"])
        for x in raw_questions
    )
    milestones = tuple(
        ProjectMilestone(x["id"], x["text"], x["status"]) for x in raw_milestones
    )
    raw_session = payload["last_session"]
    if raw_session is None:
        session = None
    elif isinstance(raw_session, Mapping) and set(raw_session) == {"at", "summary"}:
        if not isinstance(raw_session["at"], str) or not isinstance(
            raw_session["summary"], str
        ):
            _fail("project last_session is invalid")
        session = ProjectSession(raw_session["at"], raw_session["summary"])
    else:
        _fail("project last_session is invalid")
    state = ProjectState(
        payload["schema_version"],
        payload["project_slug"],
        payload["revision"],
        steps,
        blockers,
        questions,
        milestones,
        session,
    )
    _state_payload(state)
    return state


def _parse_record(payload: Mapping[str, object]) -> ProjectRecord:
    expected = {
        "schema_version",
        "slug",
        "name",
        "goal",
        "domains",
        "kind",
        "status",
        "created_at",
        "updated_at",
        "on_hold_since",
        "on_hold_reason",
        "archived_at",
        "revision",
        "last_transition_id",
        "schedule_ids",
    }
    if set(payload) != expected:
        _fail("project record has missing or unknown fields")
    string_fields = {
        "slug",
        "name",
        "goal",
        "kind",
        "status",
        "created_at",
        "updated_at",
        "last_transition_id",
    }
    if (
        type(payload["schema_version"]) is not int
        or type(payload["revision"]) is not int
        or not all(isinstance(payload[name], str) for name in string_fields)
        or not isinstance(payload["domains"], list)
        or not all(isinstance(item, str) for item in payload["domains"])
        or not isinstance(payload["schedule_ids"], list)
        or not all(isinstance(item, str) for item in payload["schedule_ids"])
        or any(
            payload[name] is not None and not isinstance(payload[name], str)
            for name in ("on_hold_since", "on_hold_reason", "archived_at")
        )
    ):
        _fail("project record collections are invalid")
    record = ProjectRecord(
        payload["schema_version"],
        payload["slug"],
        payload["name"],
        payload["goal"],
        tuple(payload["domains"]),
        payload["kind"],
        payload["status"],
        payload["created_at"],
        payload["updated_at"],
        payload["on_hold_since"],
        payload["on_hold_reason"],
        payload["archived_at"],
        payload["revision"],
        payload["last_transition_id"],
        tuple(payload["schedule_ids"]),
    )
    _record_payload(record)
    return record


def _safe_parts(relative: str) -> tuple[str, ...]:
    if not isinstance(relative, str) or "\\" in relative:
        _fail("project relative path is invalid")
    path = PurePosixPath(relative)
    if path.is_absolute() or not path.parts or ".." in path.parts:
        _fail("project relative path is invalid")
    for part in path.parts:
        if part in {"", "."} or part != unicodedata.normalize("NFC", part):
            _fail("project relative path is invalid")
        if any(unicodedata.category(c).startswith("C") for c in part):
            _fail("project relative path is invalid")
        portable = _portable_key(part)
        if portable in _ARCHIVE_KEYS and part != portable:
            _fail("project path aliases a reserved lifecycle component")
    return path.parts


def _open_dir_at(root_fd: int, relative: str, *, create: bool = False) -> int:
    current = os.dup(root_fd)
    try:
        for part in _safe_parts(relative):
            if create:
                try:
                    os.mkdir(part, mode=0o700, dir_fd=current)
                    os.fsync(current)
                except FileExistsError:
                    pass
                except OSError:
                    _fail("project directory cannot be created")
            child: int | None = None
            try:
                child = os.open(
                    part,
                    os.O_RDONLY
                    | getattr(os, "O_DIRECTORY", 0)
                    | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=current,
                )
                opened = os.fstat(child)
                named = os.stat(part, dir_fd=current, follow_symlinks=False)
            except OSError:
                if child is not None:
                    os.close(child)
                _fail("project directory cannot be opened safely")
            if not stat.S_ISDIR(opened.st_mode) or (opened.st_dev, opened.st_ino) != (
                named.st_dev,
                named.st_ino,
            ):
                os.close(child)
                _fail("project directory changed while opened")
            os.close(current)
            current = child
        return current
    except BaseException:
        os.close(current)
        raise


def _read_file_at(directory_fd: int, name: str, maximum: int) -> bytes:
    try:
        fd = os.open(
            name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=directory_fd
        )
        before = os.fstat(fd)
        named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(before.st_mode)
            or (before.st_dev, before.st_ino) != (named.st_dev, named.st_ino)
            or before.st_size > maximum
        ):
            _fail("project file is unsafe or too large")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(fd, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        after = os.fstat(fd)
        final_named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if (
            len(data) > maximum
            or (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            )
            != (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            )
            or (after.st_dev, after.st_ino) != (final_named.st_dev, final_named.st_ino)
        ):
            _fail("project file changed while read")
        return data
    except OSError:
        _fail("project file cannot be read safely")
    finally:
        if "fd" in locals():
            os.close(fd)


def _read_bundle_at(
    directory_fd: int, specifications: Sequence[tuple[str, int]]
) -> dict[str, bytes]:
    """Read related files while retaining every identity until all reads finish."""

    opened: dict[str, tuple[int, os.stat_result]] = {}
    try:
        for name, maximum in specifications:
            fd: int | None = None
            try:
                fd = os.open(
                    name,
                    os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=directory_fd,
                )
                metadata = os.fstat(fd)
                named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            except OSError:
                if fd is not None:
                    os.close(fd)
                _fail("project file bundle cannot be opened safely")
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_size > maximum
                or (metadata.st_dev, metadata.st_ino) != (named.st_dev, named.st_ino)
            ):
                os.close(fd)
                _fail("project file bundle is unsafe or too large")
            opened[name] = (fd, metadata)
        result: dict[str, bytes] = {}
        for name, maximum in specifications:
            fd, _metadata = opened[name]
            chunks: list[bytes] = []
            remaining = maximum + 1
            while remaining:
                chunk = os.read(fd, min(65536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            data = b"".join(chunks)
            if len(data) > maximum:
                _fail("project file bundle is too large")
            result[name] = data
        for name, _maximum in specifications:
            fd, before = opened[name]
            after = os.fstat(fd)
            named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            ) != (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            ) or (after.st_dev, after.st_ino) != (named.st_dev, named.st_ino):
                _fail("project file bundle changed while read")
        return result
    except OSError:
        _fail("project file bundle changed while read")
    finally:
        for fd, _metadata in opened.values():
            os.close(fd)


def _directory_exists_at(root_fd: int, relative: str) -> bool:
    parts = _safe_parts(relative)
    parent_fd = (
        root_fd if len(parts) == 1 else _open_dir_at(root_fd, "/".join(parts[:-1]))
    )
    try:
        try:
            named = os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            return False
        except OSError:
            _fail("project directory cannot be inspected safely")
        if not stat.S_ISDIR(named.st_mode):
            _fail("project lifecycle path is not a real directory")
        child = os.open(
            parts[-1],
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent_fd,
        )
        try:
            opened = os.fstat(child)
            if (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino):
                _fail("project directory changed while inspected")
        finally:
            os.close(child)
        return True
    except OSError:
        _fail("project directory cannot be inspected safely")
    finally:
        if parent_fd != root_fd:
            os.close(parent_fd)


def _atomic_file_at(directory_fd: int, name: str, data: bytes) -> None:
    if not isinstance(data, bytes) or not data or len(data) > _MAX_LOG:
        _fail("project output bytes are invalid")
    temporary = f".{name}.{uuid.uuid4().hex}.tmp"
    fd: int | None = None
    staged_identity: tuple[int, int] | None = None
    original_fd: int | None = None
    original_identity: tuple[int, int] | None = None
    backup = f".{name}.{uuid.uuid4().hex}.backup"
    backup_created = False
    publication_verified = False
    try:
        fd = os.open(
            temporary,
            os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=directory_fd,
        )
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            if written < 1:
                _fail("project output write made no progress")
            view = view[written:]
        os.fsync(fd)
        staged = os.fstat(fd)
        staged_identity = (staged.st_dev, staged.st_ino)
        named_staged = os.stat(temporary, dir_fd=directory_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(staged.st_mode)
            or staged.st_size != len(data)
            or staged_identity != (named_staged.st_dev, named_staged.st_ino)
        ):
            _fail("project staged file changed before publication")
        try:
            original_fd = os.open(
                name,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=directory_fd,
            )
        except FileNotFoundError:
            original_fd = None
        except OSError:
            _fail("project destination cannot be backed up safely")
        if original_fd is not None:
            original = os.fstat(original_fd)
            named_original = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            original_identity = (original.st_dev, original.st_ino)
            if not stat.S_ISREG(original.st_mode) or original_identity != (
                named_original.st_dev,
                named_original.st_ino,
            ):
                _fail("project destination changed before publication")
            os.link(
                name,
                backup,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
                follow_symlinks=False,
            )
            backup_created = True
            named_backup = os.stat(backup, dir_fd=directory_fd, follow_symlinks=False)
            if original_identity != (named_backup.st_dev, named_backup.st_ino):
                _fail("project destination backup is not inode-bound")
        os.replace(temporary, name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
        os.fsync(directory_fd)
        published_named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        retained = os.fstat(fd)
        if (
            staged_identity != (published_named.st_dev, published_named.st_ino)
            or staged_identity != (retained.st_dev, retained.st_ino)
            or retained.st_size != len(data)
        ):
            foreign_name = f".project-flow-foreign-{uuid.uuid4().hex}"
            try:
                os.rename(
                    name,
                    foreign_name,
                    src_dir_fd=directory_fd,
                    dst_dir_fd=directory_fd,
                )
                os.fsync(directory_fd)
                if backup_created:
                    named_backup = os.stat(
                        backup, dir_fd=directory_fd, follow_symlinks=False
                    )
                    if original_identity != (
                        named_backup.st_dev,
                        named_backup.st_ino,
                    ):
                        _fail("project destination backup changed before restore")
                    os.replace(
                        backup,
                        name,
                        src_dir_fd=directory_fd,
                        dst_dir_fd=directory_fd,
                    )
                    backup_created = False
                    restored = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                    if original_identity != (restored.st_dev, restored.st_ino):
                        _fail("project destination restore is not inode-bound")
                    os.fsync(directory_fd)
            finally:
                pass
            _fail("project staged inode was not the published inode; foreign preserved")
        os.lseek(fd, 0, os.SEEK_SET)
        digest = hashlib.sha256()
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            digest.update(chunk)
        if digest.hexdigest() != _digest_bytes(data):
            _fail("project published bytes disagree with staged content")
        retained_after_hash = os.fstat(fd)
        named_fd: int | None = None
        try:
            named_fd = os.open(
                name,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=directory_fd,
            )
            named_before = os.fstat(named_fd)
            named_entry = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if (
                staged_identity
                != (retained_after_hash.st_dev, retained_after_hash.st_ino)
                or staged_identity != (named_before.st_dev, named_before.st_ino)
                or staged_identity != (named_entry.st_dev, named_entry.st_ino)
                or retained_after_hash.st_size != len(data)
                or named_before.st_size != len(data)
            ):
                _fail("project named entry changed after publication")
            named_chunks: list[bytes] = []
            remaining = len(data) + 1
            while remaining:
                chunk = os.read(named_fd, min(65536, remaining))
                if not chunk:
                    break
                named_chunks.append(chunk)
                remaining -= len(chunk)
            named_data = b"".join(named_chunks)
            named_after = os.fstat(named_fd)
            final_named_entry = os.stat(
                name, dir_fd=directory_fd, follow_symlinks=False
            )
            if (
                named_data != data
                or (
                    named_before.st_dev,
                    named_before.st_ino,
                    named_before.st_size,
                    named_before.st_mtime_ns,
                    named_before.st_ctime_ns,
                )
                != (
                    named_after.st_dev,
                    named_after.st_ino,
                    named_after.st_size,
                    named_after.st_mtime_ns,
                    named_after.st_ctime_ns,
                )
                or staged_identity
                != (final_named_entry.st_dev, final_named_entry.st_ino)
            ):
                _fail("project named entry changed after publication")
        finally:
            if named_fd is not None:
                os.close(named_fd)
        publication_verified = True
    except (OSError, ProjectFlowError):
        _fail("project file cannot be committed")
    finally:
        if fd is not None:
            os.close(fd)
        if original_fd is not None:
            os.close(original_fd)
        if publication_verified and backup_created and original_identity is not None:
            try:
                metadata = os.stat(backup, dir_fd=directory_fd, follow_symlinks=False)
                if (metadata.st_dev, metadata.st_ino) == original_identity:
                    os.unlink(backup, dir_fd=directory_fd)
            except OSError:
                pass
        try:
            metadata = os.stat(temporary, dir_fd=directory_fd, follow_symlinks=False)
            if (
                staged_identity is not None
                and (
                    metadata.st_dev,
                    metadata.st_ino,
                )
                == staged_identity
            ):
                os.unlink(temporary, dir_fd=directory_fd)
        except OSError:
            pass


def _create_file_at(directory_fd: int, name: str, data: bytes) -> bool:
    try:
        fd = os.open(
            name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=directory_fd,
        )
    except FileExistsError:
        return False
    except OSError:
        _fail("project evidence cannot be created")
    try:
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            if written < 1:
                _fail("project evidence write made no progress")
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)
    os.fsync(directory_fd)
    return True


class ProjectFlow:
    """Versioned project records, lifecycle transitions, and replay evidence."""

    def __init__(
        self,
        resolver: VaultPathResolver,
        run_store: RunStore,
        policy: AuthorityPolicy,
        *,
        clock: Callable[[], datetime] | None = None,
        schedule_port: ProjectSchedulePort | None = None,
    ) -> None:
        if (
            not isinstance(resolver, VaultPathResolver)
            or not isinstance(run_store, RunStore)
            or not isinstance(policy, AuthorityPolicy)
        ):
            _fail("project flow dependencies are invalid")
        if getattr(run_store, "_resolver", None) is not resolver:
            _fail("project flow and run store must share one vault resolver")
        self._resolver = resolver
        self._runs = run_store
        self._policy = policy
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._schedule = schedule_port
        try:
            projects = resolver.resolve("projects", allow_archive=True, must_exist=True)
            configured = resolver.config.zone("projects")
            vault_root = projects
            for _part in configured.parts:
                vault_root = vault_root.parent
            vault_fd = os.open(
                vault_root,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
            opened = os.fstat(vault_fd)
            named = os.stat(vault_root, follow_symlinks=False)
            if not stat.S_ISDIR(opened.st_mode) or (opened.st_dev, opened.st_ino) != (
                named.st_dev,
                named.st_ino,
            ):
                _fail("configured vault root cannot be pinned")
            self._vault_root_path = Path(vault_root)
            self._vault_root_identity = (opened.st_dev, opened.st_ino)
            self._projects_relative = configured.as_posix()
        except (OSError, VaultSchemaError, ProjectFlowError):
            _fail("configured vault root cannot be pinned")
        finally:
            if "vault_fd" in locals():
                os.close(vault_fd)

    def _now(self) -> str:
        value = self._clock()
        if not isinstance(value, datetime) or value.tzinfo is None:
            _fail("project clock must return an aware datetime")
        return (
            value.astimezone(timezone.utc)
            .isoformat(timespec="microseconds")
            .replace("+00:00", "Z")
        )

    def _require(
        self, capability: ActionCapability, action_id: str
    ) -> ActionCapability:
        try:
            grant = self._policy.require(capability)
        except AuthorityError as error:
            raise ProjectFlowError(str(error)) from None
        expected = {
            "read-project-state": ("runtime", "read", "vault:projects"),
            "commit-project-transition": ("runtime", "domain-write", "vault:projects"),
            "apply-linked-schedule-transition": (
                "runtime",
                "domain-write",
                "tool:scheduler",
            ),
            "record-run-state": ("runtime", "internal-write", "vault:agent/runs"),
        }
        if (
            action_id not in expected
            or (grant.flow_id, grant.action_id) != ("project", action_id)
            or (grant.actor, grant.authority, grant.target) != expected[action_id]
        ):
            _fail("project action capability is not exact")
        return grant

    def _root(self, *, for_write: bool) -> tuple[int, object, tuple[int, int]]:
        try:
            vault_fd = os.open(
                self._vault_root_path,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
            opened_vault = os.fstat(vault_fd)
            named_vault = os.stat(self._vault_root_path, follow_symlinks=False)
            if (
                opened_vault.st_dev,
                opened_vault.st_ino,
            ) != self._vault_root_identity or (
                named_vault.st_dev,
                named_vault.st_ino,
            ) != self._vault_root_identity:
                _fail("configured vault root identity changed")
            fd = _open_dir_at(vault_fd, self._projects_relative)
            path = self._vault_root_path / self._projects_relative
            opened = os.fstat(fd)
            named = os.stat(path, follow_symlinks=False)
            if not stat.S_ISDIR(opened.st_mode) or (opened.st_dev, opened.st_ino) != (
                named.st_dev,
                named.st_ino,
            ):
                _fail("projects zone changed while opened")
            self._resolver.revalidate(
                path,
                "projects",
                for_write=for_write,
                allow_archive=True,
                must_exist=True,
            )
            return fd, path, (opened.st_dev, opened.st_ino)
        except (OSError, VaultSchemaError, ProjectFlowError):
            if "fd" in locals():
                os.close(fd)
            _fail("projects zone cannot be anchored safely")
        finally:
            if "vault_fd" in locals():
                os.close(vault_fd)

    def _revalidate_root(
        self, root_fd: int, path: object, identity: tuple[int, int], *, for_write: bool
    ) -> None:
        try:
            pinned_named = os.stat(self._vault_root_path, follow_symlinks=False)
            if (
                pinned_named.st_dev,
                pinned_named.st_ino,
            ) != self._vault_root_identity:
                _fail("configured vault root identity changed")
            opened = os.fstat(root_fd)
            named = os.stat(path, follow_symlinks=False)
            self._resolver.revalidate(
                path,
                "projects",
                for_write=for_write,
                allow_archive=True,
                must_exist=True,
            )
        except (OSError, VaultSchemaError):
            _fail("projects zone changed during operation")
        if (opened.st_dev, opened.st_ino) != identity or (
            named.st_dev,
            named.st_ino,
        ) != identity:
            _fail("projects zone changed during operation")

    @staticmethod
    def _location(status: str, slug: str, archived_at: str | None = None) -> str:
        if status == "active":
            return slug
        if status == "on-hold":
            return f"_on_hold/{slug}"
        if archived_at is None:
            _fail("archive location requires archived_at")
        return f"_archive/{slug}-{archived_at[:10]}"

    def _read_snapshot_at(
        self, root_fd: int, location: str, *, require_committed_bundle: bool = False
    ) -> ProjectSnapshot:
        directory_fd = _open_dir_at(root_fd, location)
        try:
            bundle = _read_bundle_at(
                directory_fd,
                (
                    ("project.json", _MAX_JSON),
                    ("state.json", _MAX_JSON),
                    ("log.md", _MAX_LOG),
                ),
            )
        finally:
            os.close(directory_fd)
        project_bytes = bundle["project.json"]
        state_bytes = bundle["state.json"]
        log_bytes = bundle["log.md"]
        record = _parse_record(_decode_json(project_bytes, "project record"))
        state = _parse_state(_decode_json(state_bytes, "project state"))
        if record.slug != state.project_slug or record.revision != state.revision:
            _fail("project record and state disagree")
        expected_location = self._location(
            record.status, record.slug, record.archived_at
        )
        if location != expected_location:
            _fail("project physical location disagrees with lifecycle")
        try:
            log_bytes.decode("utf-8")
        except UnicodeError:
            _fail("project log is not UTF-8")
        if not log_bytes:
            _fail("project log is empty")
        hashes = (
            _digest_bytes(project_bytes),
            _digest_bytes(state_bytes),
            _digest_bytes(log_bytes),
        )
        snapshot_hash = _digest_payload(
            {
                "location": location,
                "project_sha256": hashes[0],
                "state_sha256": hashes[1],
                "log_sha256": hashes[2],
            }
        )
        snapshot = ProjectSnapshot(record, state, location, *hashes, snapshot_hash)
        if require_committed_bundle:
            self._validate_committed_bundle(root_fd, snapshot)
        return snapshot

    def _validate_committed_bundle(
        self, root_fd: int, snapshot: ProjectSnapshot
    ) -> None:
        try:
            metadata = os.stat(
                ".lifeos-project-intents", dir_fd=root_fd, follow_symlinks=False
            )
        except FileNotFoundError:
            _fail("project bundle lacks transition evidence")
        except OSError:
            _fail("project transition evidence cannot be inspected")
        if not stat.S_ISDIR(metadata.st_mode):
            _fail("project transition evidence namespace is unsafe")
        intents_fd = _open_dir_at(root_fd, ".lifeos-project-intents")
        matching: list[dict[str, object]] = []
        try:
            for name in sorted(os.listdir(intents_fd)):
                if not name.endswith(".json"):
                    _fail("project transition evidence contains an unsafe entry")
                intent = _decode_json(
                    _read_file_at(intents_fd, name, _MAX_JSON),
                    "project transition intent",
                )
                request = intent.get("request")
                if not isinstance(request, Mapping):
                    _fail("project transition intent lacks request evidence")
                self._validate_replay(intent, request)
                if intent["slug"] == snapshot.record.slug:
                    matching.append(intent)
        finally:
            os.close(intents_fd)
        if any(intent["status"] != "complete" for intent in matching):
            _fail("project has a pending transition requiring reconciliation")
        current = [
            intent
            for intent in matching
            if intent["transition_id"] == snapshot.record.last_transition_id
        ]
        if len(current) != 1:
            _fail("project bundle lacks exact completed transition evidence")
        intent = current[0]
        hashes = intent["target_sha256"]
        if (
            not isinstance(hashes, Mapping)
            or intent["destination"] != snapshot.location
            or hashes.get("project.json") != snapshot.project_sha256
            or hashes.get("state.json") != snapshot.state_sha256
            or hashes.get("log.md") != snapshot.log_sha256
        ):
            _fail("project bundle hashes disagree with completed transition")

    def _find_locations(self, root_fd: int, slug: str) -> list[str]:
        key = _portable_key(slug)
        found: list[str] = []
        try:
            root_names = os.listdir(root_fd)
        except OSError:
            _fail("projects namespace cannot be listed")
        for name in root_names:
            portable = _portable_key(name)
            if portable in _ARCHIVE_KEYS:
                if name != portable:
                    _fail("projects namespace aliases a reserved lifecycle component")
                continue
            if name.startswith("."):
                continue
            if _portable_key(name) == key:
                found.append(name)
        for container in ("_on_hold", "_archive"):
            try:
                container_metadata = os.stat(
                    container, dir_fd=root_fd, follow_symlinks=False
                )
            except FileNotFoundError:
                continue
            except OSError:
                _fail("projects lifecycle namespace cannot be inspected")
            if not stat.S_ISDIR(container_metadata.st_mode):
                _fail("projects lifecycle namespace is unsafe")
            parent_fd = _open_dir_at(root_fd, container)
            try:
                for name in os.listdir(parent_fd):
                    child_fd: int | None = None
                    try:
                        child_fd = _open_dir_at(parent_fd, name)
                        project_bytes = _read_file_at(
                            child_fd, "project.json", _MAX_JSON
                        )
                        record = _parse_record(
                            _decode_json(project_bytes, "project record")
                        )
                    except ProjectFlowError:
                        _fail("projects lifecycle namespace contains corrupt data")
                    finally:
                        if child_fd is not None:
                            os.close(child_fd)
                    if _portable_key(record.slug) == key:
                        found.append(f"{container}/{name}")
            finally:
                os.close(parent_fd)
        return sorted(found)

    def list(
        self,
        capability: ActionCapability,
        *,
        include_held: bool = True,
        include_archived: bool = False,
    ) -> tuple[ProjectSnapshot, ...]:
        self._require(capability, "read-project-state")
        root_fd, path, identity = self._root(for_write=False)
        snapshots: list[ProjectSnapshot] = []
        try:
            locations: list[str] = []
            for name in sorted(os.listdir(root_fd)):
                portable = _portable_key(name)
                if portable in _ARCHIVE_KEYS:
                    if name != portable:
                        _fail(
                            "projects namespace aliases a reserved lifecycle component"
                        )
                    continue
                if name.startswith("."):
                    continue
                locations.append(name)
            if include_held:
                try:
                    held_metadata = os.stat(
                        "_on_hold", dir_fd=root_fd, follow_symlinks=False
                    )
                except FileNotFoundError:
                    held_fd = None
                except OSError:
                    _fail("held projects namespace cannot be inspected")
                else:
                    if not stat.S_ISDIR(held_metadata.st_mode):
                        _fail("held projects namespace is unsafe")
                    held_fd = _open_dir_at(root_fd, "_on_hold")
                if held_fd is not None:
                    try:
                        locations.extend(
                            f"_on_hold/{name}" for name in sorted(os.listdir(held_fd))
                        )
                    finally:
                        os.close(held_fd)
            if include_archived:
                try:
                    archive_metadata = os.stat(
                        "_archive", dir_fd=root_fd, follow_symlinks=False
                    )
                except FileNotFoundError:
                    archive_fd = None
                except OSError:
                    _fail("archive projects namespace cannot be inspected")
                else:
                    if not stat.S_ISDIR(archive_metadata.st_mode):
                        _fail("archive projects namespace is unsafe")
                    archive_fd = _open_dir_at(root_fd, "_archive")
                if archive_fd is not None:
                    try:
                        locations.extend(
                            f"_archive/{name}"
                            for name in sorted(os.listdir(archive_fd))
                        )
                    finally:
                        os.close(archive_fd)
            for location in locations:
                snapshots.append(
                    self._read_snapshot_at(
                        root_fd, location, require_committed_bundle=True
                    )
                )
            keys = [_portable_key(item.record.slug) for item in snapshots]
            if len(keys) != len(set(keys)):
                _fail("project namespace has portable-name aliases")
            self._revalidate_root(root_fd, path, identity, for_write=False)
            return tuple(
                sorted(
                    snapshots,
                    key=lambda item: (_portable_key(item.record.slug), item.location),
                )
            )
        finally:
            os.close(root_fd)

    def status(self, capability: ActionCapability, slug: str) -> ProjectSnapshot:
        self._require(capability, "read-project-state")
        checked = _identifier(slug, "project slug", _SLUG)
        root_fd, path, identity = self._root(for_write=False)
        try:
            locations = self._find_locations(root_fd, checked)
            if len(locations) != 1:
                _fail("project is missing or has a portable-name collision")
            snapshot = self._read_snapshot_at(
                root_fd, locations[0], require_committed_bundle=True
            )
            self._revalidate_root(root_fd, path, identity, for_write=False)
            return snapshot
        finally:
            os.close(root_fd)

    @staticmethod
    def _request(
        operation: str, slug: str, transition_id: str, fields: Mapping[str, object]
    ) -> dict[str, object]:
        return {
            "schema_version": PROJECT_TRANSITION_SCHEMA_VERSION,
            "operation": operation,
            "slug": slug,
            "transition_id": transition_id,
            "fields": dict(fields),
        }

    @staticmethod
    def _intent_payload(
        *,
        request: Mapping[str, object],
        source: str | None,
        destination: str,
        before: Mapping[str, str | None],
        targets: Mapping[str, bytes],
        archived_children: Sequence[str],
        child_policy: str | None,
        schedule: ProjectScheduleIntent | None,
        status: str = "prepared",
        receipt: ScheduleReceipt | None = None,
        child_observation: Mapping[str, str] | None = None,
        schedule_observation: Sequence[ScheduleSnapshot] = (),
    ) -> dict[str, object]:
        return {
            "schema_version": PROJECT_TRANSITION_SCHEMA_VERSION,
            "transition_id": request["transition_id"],
            "operation": request["operation"],
            "slug": request["slug"],
            "request_sha256": _digest_payload(request),
            "request": dict(request),
            "source": source,
            "destination": destination,
            "project_directory_identity": None,
            "before": dict(before),
            "preimages": {},
            "targets": {
                name: base64.b64encode(data).decode("ascii")
                for name, data in sorted(targets.items())
            },
            "target_sha256": {
                name: _digest_bytes(data) for name, data in sorted(targets.items())
            },
            "archived_children": list(archived_children),
            "child_observation": dict(child_observation or {}),
            "child_policy": child_policy,
            "schedule": None
            if schedule is None
            else {
                "schema_version": schedule.schema_version,
                "transition_id": schedule.transition_id,
                "project_slug": schedule.project_slug,
                "action": schedule.action,
                "schedule_ids": list(schedule.schedule_ids),
                "reason": schedule.reason,
                "expected": [
                    {
                        "schedule_id": item.schedule_id,
                        "status": item.status,
                        "sha256": item.sha256,
                    }
                    for item in schedule.expected
                ],
            },
            "schedule_observation": [
                {
                    "schedule_id": item.schedule_id,
                    "status": item.status,
                    "sha256": item.sha256,
                }
                for item in schedule_observation
            ],
            "schedule_receipt": None
            if receipt is None
            else {
                "schema_version": receipt.schema_version,
                "transition_id": receipt.transition_id,
                "status": receipt.status,
                "effect_hash": receipt.effect_hash,
            },
            "status": status,
        }

    def _intent_dir(self, root_fd: int) -> int:
        return _open_dir_at(root_fd, ".lifeos-project-intents", create=True)

    def _evidence_dir(self, root_fd: int) -> int:
        return _open_dir_at(root_fd, ".lifeos-project-evidence", create=True)

    def _load_intent(
        self, intents_fd: int, transition_id: str
    ) -> dict[str, object] | None:
        name = f"{transition_id}.json"
        try:
            return _decode_json(
                _read_file_at(intents_fd, name, _MAX_JSON), "project transition intent"
            )
        except ProjectFlowError as error:
            try:
                os.stat(name, dir_fd=intents_fd, follow_symlinks=False)
            except FileNotFoundError:
                return None
            except OSError:
                pass
            raise error

    def _require_no_other_pending_intent(
        self, intents_fd: int, *, slug: str, transition_id: str
    ) -> None:
        for name in sorted(os.listdir(intents_fd)):
            if name == f"{transition_id}.json":
                continue
            if not name.endswith(".json"):
                _fail("project intent namespace contains an unsafe entry")
            other = _decode_json(
                _read_file_at(intents_fd, name, _MAX_JSON),
                "project transition intent",
            )
            request = other.get("request")
            if not isinstance(request, Mapping):
                _fail("project transition intent lacks request evidence")
            self._validate_replay(other, request)
            if other["slug"] == slug and other["status"] != "complete":
                _fail("project has another pending transition requiring reconciliation")

    def _validate_replay(
        self, intent: Mapping[str, object], request: Mapping[str, object]
    ) -> None:
        if (
            intent.get("schema_version") != PROJECT_TRANSITION_SCHEMA_VERSION
            or intent.get("transition_id") != request["transition_id"]
            or intent.get("operation") != request["operation"]
            or intent.get("slug") != request["slug"]
            or intent.get("request_sha256") != _digest_payload(request)
        ):
            _fail("transition replay disagrees with durable intent")
        if intent.get("status") not in {
            "prepared",
            "domain_committed",
            "schedule_committed",
            "complete",
        }:
            _fail("transition intent status is invalid")
        self._validate_intent_structure(intent, request)

    def _validate_intent_structure(
        self, intent: Mapping[str, object], request: Mapping[str, object]
    ) -> None:
        expected_keys = {
            "schema_version",
            "transition_id",
            "operation",
            "slug",
            "request_sha256",
            "request",
            "source",
            "destination",
            "project_directory_identity",
            "before",
            "preimages",
            "targets",
            "target_sha256",
            "archived_children",
            "child_observation",
            "child_policy",
            "schedule",
            "schedule_observation",
            "schedule_receipt",
            "status",
        }
        if set(intent) != expected_keys:
            _fail("transition intent has missing or unknown fields")
        if intent["request"] != request:
            _fail("transition intent request evidence disagrees")
        operation = str(intent["operation"])
        slug = _identifier(intent["slug"], "intent project slug", _SLUG)
        source = intent["source"]
        destination = intent["destination"]
        if (
            source is not None
            and not isinstance(source, str)
            or not isinstance(destination, str)
        ):
            _fail("transition intent locations are invalid")
        raw_directory_identity = intent["project_directory_identity"]
        if raw_directory_identity is None:
            if operation != "create":
                _fail("transition intent lacks project directory identity")
        elif (
            not isinstance(raw_directory_identity, Mapping)
            or set(raw_directory_identity) != {"device", "inode"}
            or type(raw_directory_identity["device"]) is not int
            or type(raw_directory_identity["inode"]) is not int
            or raw_directory_identity["device"] < 0
            or raw_directory_identity["inode"] <= 0
        ):
            _fail("transition project directory identity is invalid")
        allowed_locations: dict[str, tuple[set[str | None], re.Pattern[str]]] = {
            "create": ({None}, re.compile(rf"^{re.escape(slug)}$")),
            "advance": ({slug}, re.compile(rf"^{re.escape(slug)}$")),
            "hold": ({slug}, re.compile(rf"^_on_hold/{re.escape(slug)}$")),
            "resume": ({f"_on_hold/{slug}"}, re.compile(rf"^{re.escape(slug)}$")),
            "archive": (
                {slug, f"_on_hold/{slug}"},
                re.compile(rf"^_archive/{re.escape(slug)}-\d{{4}}-\d{{2}}-\d{{2}}$"),
            ),
        }
        if operation not in allowed_locations:
            _fail("transition intent operation is invalid")
        sources, destination_pattern = allowed_locations[operation]
        if source not in sources or destination_pattern.fullmatch(destination) is None:
            _fail("transition intent location disagrees with operation")
        targets = self._target_bytes(intent)
        before = intent["before"]
        preimages = intent["preimages"]
        if (
            not isinstance(before, Mapping)
            or not isinstance(preimages, Mapping)
            or set(before) != set(targets)
            or set(preimages) != set(targets)
        ):
            _fail("transition preimage keys disagree with targets")
        for name, value in before.items():
            if value is not None:
                _hash(value, "transition preimage hash")
            encoded = preimages[name]
            if value is None:
                if encoded is not None:
                    _fail("absent transition preimage has bytes")
                continue
            if not isinstance(encoded, str):
                _fail("transition preimage encoding is invalid")
            try:
                preimage = base64.b64decode(encoded, validate=True)
            except (ValueError, UnicodeError):
                _fail("transition preimage encoding is invalid")
            if _digest_bytes(preimage) != value:
                _fail("transition preimage bytes disagree with hash")
        if operation == "create" and any(
            value is not None for value in before.values()
        ):
            _fail("create intent has non-empty preimage")
        required = {"project.json", "state.json", "log.md"}
        if not required.issubset(targets):
            _fail("transition target lacks a project artifact")
        extra = set(targets) - required
        if operation != "archive" and extra:
            _fail("non-archive transition targets child artifacts")
        for relative in extra:
            parts = _safe_parts(relative)
            if len(parts) != 3 or parts[0] != "research" or parts[2] != "project.json":
                _fail("archive child target is invalid")
            _identifier(parts[1], "archive child id")
        record = _parse_record(
            _decode_json(targets["project.json"], "intent project record")
        )
        state = _parse_state(
            _decode_json(targets["state.json"], "intent project state")
        )
        if (
            record.slug != slug
            or state.project_slug != slug
            or record.revision != state.revision
            or record.last_transition_id != intent["transition_id"]
        ):
            _fail("transition target record and state disagree")
        expected_status = {
            "create": "active",
            "advance": "active",
            "hold": "on-hold",
            "resume": "active",
            "archive": "archived",
        }[operation]
        if (
            record.status != expected_status
            or self._location(record.status, record.slug, record.archived_at)
            != destination
        ):
            _fail("transition target lifecycle disagrees with operation")
        try:
            targets["log.md"].decode("utf-8")
        except UnicodeError:
            _fail("transition target log is not UTF-8")
        archived_children = intent["archived_children"]
        child_observation = intent["child_observation"]
        if (
            not isinstance(archived_children, list)
            or not all(isinstance(item, str) for item in archived_children)
            or not isinstance(child_observation, Mapping)
        ):
            _fail("transition child evidence is invalid")
        observed_ids: set[str] = set()
        for child_id, digest in child_observation.items():
            checked_child = _identifier(child_id, "observed child id")
            if checked_child in observed_ids:
                _fail("transition child evidence has duplicate aliases")
            observed_ids.add(checked_child)
            _hash(digest, "observed child hash")
        archived_set = {
            _identifier(item, "archived child id") for item in archived_children
        }
        if len(archived_set) != len(archived_children):
            _fail("archive child evidence has duplicate ids")
        target_children = {PurePosixPath(item).parts[1] for item in extra}
        if archived_set != target_children or not archived_set.issubset(observed_ids):
            _fail("archive child evidence disagrees with targets")
        child_policy = intent["child_policy"]
        if operation == "archive":
            if child_policy not in _CHILD_POLICIES:
                _fail("archive intent child policy is invalid")
            if child_policy != "cascade" and archived_set:
                _fail("non-cascade archive targets child engines")
        elif child_policy is not None or archived_set or child_observation:
            _fail("non-archive transition has child policy evidence")
        schedule = self._schedule_from_intent(intent["schedule"])
        raw_schedule_observation = intent["schedule_observation"]
        if not isinstance(raw_schedule_observation, list):
            _fail("schedule observation is invalid")
        schedule_observation: list[ScheduleSnapshot] = []
        for item in raw_schedule_observation:
            if (
                not isinstance(item, Mapping)
                or set(item) != {"schedule_id", "status", "sha256"}
                or not all(
                    isinstance(item[name], str)
                    for name in ("schedule_id", "status", "sha256")
                )
            ):
                _fail("schedule observation is invalid")
            observed = ScheduleSnapshot(
                item["schedule_id"], item["status"], item["sha256"]
            )
            _identifier(observed.schedule_id, "observed schedule_id")
            if observed.status not in _SCHEDULE_STATUSES:
                _fail("observed schedule status is invalid")
            _hash(observed.sha256, "observed schedule hash")
            schedule_observation.append(observed)
        if len({item.schedule_id for item in schedule_observation}) != len(
            schedule_observation
        ):
            _fail("schedule observation has duplicate ids")
        receipt = self._receipt_from_intent(intent["schedule_receipt"])
        if receipt is not None and (
            schedule is None or receipt.transition_id != schedule.transition_id
        ):
            _fail("schedule receipt lacks matching intent")
        if receipt is not None and receipt.effect_hash != expected_schedule_effect_hash(
            schedule
        ):
            _fail("schedule receipt effect hash disagrees with intent")
        if schedule is not None:
            if (
                schedule.transition_id != intent["transition_id"]
                or schedule.project_slug != slug
            ):
                _fail("schedule transition is not bound to project transition")
            if operation == "hold" and schedule.schedule_ids != record.schedule_ids:
                _fail("hold schedule transition omits linked schedules")
            if operation == "hold" and schedule.action != "pause":
                _fail("hold schedule transition must pause")
            if operation not in {"hold", "archive"}:
                _fail("project operation cannot invoke scheduler")
        fields = request.get("fields")
        if not isinstance(fields, Mapping):
            _fail("transition request fields are invalid")
        if operation == "create":
            expected_record_fields = {
                "name": record.name,
                "goal": record.goal,
                "domains": list(record.domains),
                "kind": record.kind,
                "schedule_ids": list(record.schedule_ids),
            }
            if dict(fields) != expected_record_fields or record.revision != 1:
                _fail("create target disagrees with request")
        else:
            expected_revision = fields.get("expected_revision")
            if (
                type(expected_revision) is not int
                or record.revision != expected_revision + 1
            ):
                _fail("transition target revision disagrees with request")
        if operation == "advance" and _state_payload(state) != fields.get("state"):
            _fail("advance state disagrees with request")
        if operation == "hold":
            if record.on_hold_reason != fields.get("reason"):
                _fail("hold target reason disagrees with request")
            if record.schedule_ids and schedule is None:
                _fail("hold target omits linked schedule transition")
        if operation == "archive":
            if {item.schedule_id for item in schedule_observation} != set(
                record.schedule_ids
            ):
                _fail("archive schedule observation omits linked schedules")
            if record.schedule_ids:
                if schedule is None or set(schedule.schedule_ids) != set(
                    record.schedule_ids
                ):
                    _fail("archive schedule boundary omits linked schedules")
                expected_schedule = {
                    item.schedule_id: (item.status, item.sha256)
                    for item in schedule.expected
                }
                requested_schedule = {
                    item.schedule_id: (item.status, item.sha256)
                    for item in schedule_observation
                }
                if expected_schedule != requested_schedule:
                    _fail("archive scheduler precondition is not exact")
                expected_action = "pause" if child_policy == "cascade" else "verify"
                if schedule.action != expected_action:
                    _fail("archive scheduler action disagrees with child policy")
            elif schedule is not None:
                _fail("archive without linked schedules invokes scheduler")
        elif schedule_observation:
            _fail("non-archive transition has schedule observation")

    def _target_bytes(self, intent: Mapping[str, object]) -> dict[str, bytes]:
        raw = intent.get("targets")
        hashes = intent.get("target_sha256")
        if (
            not isinstance(raw, Mapping)
            or not isinstance(hashes, Mapping)
            or set(raw) != set(hashes)
        ):
            _fail("transition target evidence is invalid")
        result: dict[str, bytes] = {}
        for name, encoded in raw.items():
            _safe_parts(str(name))
            if not isinstance(encoded, str):
                _fail("transition target encoding is invalid")
            try:
                data = base64.b64decode(encoded, validate=True)
            except (ValueError, UnicodeError):
                _fail("transition target encoding is invalid")
            if len(data) > _MAX_LOG or hashes[name] != _digest_bytes(data):
                _fail("transition target hash is invalid")
            result[str(name)] = data
        return result

    def _attach_preimages(
        self, root_fd: int, intent: Mapping[str, object]
    ) -> dict[str, object]:
        before = intent.get("before")
        source = intent.get("source")
        if not isinstance(before, Mapping):
            _fail("transition preimage evidence is invalid")
        encoded: dict[str, str | None] = {}
        if source is None:
            if any(value is not None for value in before.values()):
                _fail("create transition has unexpected preimages")
            encoded = {str(name): None for name in before}
        else:
            if not isinstance(source, str):
                _fail("transition source is invalid")
            project_fd = _open_dir_at(root_fd, source)
            try:
                metadata = os.fstat(project_fd)
                for relative, expected in before.items():
                    parts = _safe_parts(str(relative))
                    parent_fd = (
                        project_fd
                        if len(parts) == 1
                        else _open_dir_at(project_fd, "/".join(parts[:-1]))
                    )
                    try:
                        raw = _read_file_at(parent_fd, parts[-1], _MAX_LOG)
                    finally:
                        if parent_fd != project_fd:
                            os.close(parent_fd)
                    if expected != _digest_bytes(raw):
                        _fail("transition preimage changed while intent was prepared")
                    encoded[str(relative)] = base64.b64encode(raw).decode("ascii")
            finally:
                os.close(project_fd)
        result = dict(intent)
        result["preimages"] = encoded
        if source is not None:
            result["project_directory_identity"] = {
                "device": metadata.st_dev,
                "inode": metadata.st_ino,
            }
        return result

    @staticmethod
    def _project_directory_identity(
        intent: Mapping[str, object], *, required: bool
    ) -> tuple[int, int] | None:
        raw = intent.get("project_directory_identity")
        if raw is None:
            if required:
                _fail("transition intent lacks project directory identity")
            return None
        if (
            not isinstance(raw, Mapping)
            or set(raw) != {"device", "inode"}
            or type(raw["device"]) is not int
            or type(raw["inode"]) is not int
            or raw["device"] < 0
            or raw["inode"] <= 0
        ):
            _fail("transition project directory identity is invalid")
        return raw["device"], raw["inode"]

    @staticmethod
    def _directory_identity_at(root_fd: int, relative: str) -> tuple[int, int] | None:
        parts = _safe_parts(relative)
        if len(parts) == 1:
            parent_fd = root_fd
        else:
            try:
                parent_fd = _open_dir_at(root_fd, "/".join(parts[:-1]))
            except ProjectFlowError:
                try:
                    os.stat(parts[0], dir_fd=root_fd, follow_symlinks=False)
                except FileNotFoundError:
                    return None
                except OSError:
                    _fail("project directory cannot be inspected safely")
                raise
        child_fd: int | None = None
        try:
            try:
                named = os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                return None
            except OSError:
                _fail("project directory cannot be inspected safely")
            if not stat.S_ISDIR(named.st_mode):
                _fail("project lifecycle path is not a real directory")
            try:
                child_fd = os.open(
                    parts[-1],
                    os.O_RDONLY
                    | getattr(os, "O_DIRECTORY", 0)
                    | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=parent_fd,
                )
                opened = os.fstat(child_fd)
                final_named = os.stat(
                    parts[-1], dir_fd=parent_fd, follow_symlinks=False
                )
            except OSError:
                _fail("project directory cannot be inspected safely")
            if (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino) or (
                opened.st_dev,
                opened.st_ino,
            ) != (final_named.st_dev, final_named.st_ino):
                _fail("project directory changed while inspected")
            return opened.st_dev, opened.st_ino
        finally:
            if child_fd is not None:
                os.close(child_fd)
            if parent_fd != root_fd:
                os.close(parent_fd)

    def _find_project_directory_by_identity(
        self,
        root_fd: int,
        intent: Mapping[str, object],
        identity: tuple[int, int],
    ) -> str | None:
        source = intent.get("source")
        destination = intent.get("destination")
        if (source is not None and not isinstance(source, str)) or not isinstance(
            destination, str
        ):
            _fail("transition locations are invalid")
        parents = {
            location.rsplit("/", 1)[0] if "/" in location else None
            for location in (destination, source)
            if isinstance(location, str)
        }
        matches: list[str] = []
        for parent in sorted(parents, key=lambda item: "" if item is None else item):
            if parent is None:
                parent_fd = root_fd
            else:
                try:
                    parent_fd = _open_dir_at(root_fd, parent)
                except ProjectFlowError:
                    try:
                        parent_exists = self._directory_identity_at(root_fd, parent)
                    except ProjectFlowError:
                        raise
                    if parent_exists is None:
                        continue
                    raise
            try:
                try:
                    names = os.listdir(parent_fd)
                except OSError:
                    _fail("project directory namespace cannot be inspected")
                for name in names:
                    relative = name if parent is None else f"{parent}/{name}"
                    try:
                        _safe_parts(relative)
                    except ProjectFlowError:
                        continue
                    try:
                        candidate = self._directory_identity_at(root_fd, relative)
                    except ProjectFlowError:
                        continue
                    if candidate == identity:
                        matches.append(relative)
            finally:
                if parent_fd != root_fd:
                    os.close(parent_fd)
        unique = sorted(set(matches))
        if len(unique) > 1:
            _fail("project directory identity has multiple names")
        return unique[0] if unique else None

    @staticmethod
    def _preserve_foreign_directory_at(root_fd: int, relative: str) -> None:
        parts = _safe_parts(relative)
        parent_fd = (
            root_fd if len(parts) == 1 else _open_dir_at(root_fd, "/".join(parts[:-1]))
        )
        try:
            try:
                metadata = os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                return
            except OSError:
                _fail("replacement project directory cannot be inspected")
            if not stat.S_ISDIR(metadata.st_mode):
                _fail("replacement project entry is not a directory")
            preserved = f".project-flow-foreign-{uuid.uuid4().hex}"
            try:
                os.rename(
                    parts[-1],
                    preserved,
                    src_dir_fd=parent_fd,
                    dst_dir_fd=parent_fd,
                )
                os.fsync(parent_fd)
            except OSError:
                _fail("replacement project directory cannot be preserved")
        finally:
            if parent_fd != root_fd:
                os.close(parent_fd)

    def _restore_project_directory_name(
        self,
        root_fd: int,
        *,
        found: str,
        destination: str,
        source: str | None,
        identity: tuple[int, int],
    ) -> None:
        for occupied in {destination, source}:
            if occupied is None or occupied == found:
                continue
            occupied_identity = self._directory_identity_at(root_fd, occupied)
            if occupied_identity is not None and occupied_identity != identity:
                self._preserve_foreign_directory_at(root_fd, occupied)
        if found == destination:
            return
        src_parts = _safe_parts(found)
        dst_parts = _safe_parts(destination)
        src_parent_fd = (
            root_fd
            if len(src_parts) == 1
            else _open_dir_at(root_fd, "/".join(src_parts[:-1]))
        )
        dst_parent_fd = (
            root_fd
            if len(dst_parts) == 1
            else _open_dir_at(root_fd, "/".join(dst_parts[:-1]), create=True)
        )
        try:
            try:
                os.rename(
                    src_parts[-1],
                    dst_parts[-1],
                    src_dir_fd=src_parent_fd,
                    dst_dir_fd=dst_parent_fd,
                )
                os.fsync(src_parent_fd)
                if dst_parent_fd != src_parent_fd:
                    os.fsync(dst_parent_fd)
            except OSError:
                _fail("project directory name cannot be reconciled")
        finally:
            if src_parent_fd != root_fd:
                os.close(src_parent_fd)
            if dst_parent_fd != root_fd:
                os.close(dst_parent_fd)
        if self._directory_identity_at(root_fd, destination) != identity:
            _fail("project directory identity was not restored")

    def _bind_or_reconcile_project_directory(
        self, root_fd: int, intent: Mapping[str, object]
    ) -> dict[str, object]:
        source = intent.get("source")
        destination = intent.get("destination")
        if (source is not None and not isinstance(source, str)) or not isinstance(
            destination, str
        ):
            _fail("transition locations are invalid")
        identity = self._project_directory_identity(intent, required=False)
        if identity is None:
            if source is not None or intent.get("status") != "prepared":
                _fail("transition intent lacks project directory identity")
            if "/" in destination:
                parent = destination.rsplit("/", 1)[0]
                parent_fd = _open_dir_at(root_fd, parent, create=True)
                os.close(parent_fd)
            if not _directory_exists_at(root_fd, destination):
                parent, leaf = (
                    destination.rsplit("/", 1)
                    if "/" in destination
                    else (None, destination)
                )
                parent_fd = (
                    root_fd
                    if parent is None
                    else _open_dir_at(root_fd, parent, create=True)
                )
                try:
                    os.mkdir(leaf, mode=0o700, dir_fd=parent_fd)
                    os.fsync(parent_fd)
                except OSError:
                    _fail("project directory cannot be created")
                finally:
                    if parent_fd != root_fd:
                        os.close(parent_fd)
            project_fd = _open_dir_at(root_fd, destination)
            try:
                if os.listdir(project_fd):
                    _fail("unbound project directory contains unrelated files")
                metadata = os.fstat(project_fd)
            finally:
                os.close(project_fd)
            result = dict(intent)
            result["project_directory_identity"] = {
                "device": metadata.st_dev,
                "inode": metadata.st_ino,
            }
            return result

        destination_identity = self._directory_identity_at(root_fd, destination)
        if destination_identity == identity:
            return dict(intent)
        source_identity = (
            self._directory_identity_at(root_fd, source)
            if source is not None and source != destination
            else None
        )
        if intent.get("status") == "prepared" and source_identity == identity:
            return dict(intent)
        found = self._find_project_directory_by_identity(root_fd, intent, identity)
        if found is None:
            _fail("project directory identity changed and cannot be reconciled")
        self._restore_project_directory_name(
            root_fd,
            found=found,
            destination=destination,
            source=source,
            identity=identity,
        )
        return dict(intent)

    def _require_project_directory_binding(
        self,
        root_fd: int,
        intent: Mapping[str, object],
        retained_fd: int | None = None,
    ) -> None:
        destination = intent.get("destination")
        if not isinstance(destination, str):
            _fail("transition destination is invalid")
        identity = self._project_directory_identity(intent, required=True)
        if retained_fd is not None:
            try:
                retained = os.fstat(retained_fd)
            except OSError:
                _fail("project directory descriptor cannot be revalidated")
            if (retained.st_dev, retained.st_ino) != identity:
                _fail("project directory descriptor identity changed")
        if self._directory_identity_at(root_fd, destination) != identity:
            _fail("project directory changed during transition")

    def _validate_file_delta(
        self,
        *,
        relative: str,
        current: bytes | None,
        target: bytes,
        targets: Mapping[str, bytes],
        request: Mapping[str, object],
    ) -> None:
        operation = str(request["operation"])
        fields = request["fields"]
        if not isinstance(fields, Mapping):
            _fail("transition request fields are invalid")
        target_record = _parse_record(
            _decode_json(targets["project.json"], "target project record")
        )
        if relative == "project.json":
            if current is None:
                if operation != "create":
                    _fail("non-create transition lacks a project preimage")
                return
            old = _parse_record(_decode_json(current, "project preimage"))
            new = _parse_record(_decode_json(target, "project target"))
            if old.slug != new.slug or new.revision != old.revision + 1:
                _fail("project record delta is invalid")
            allowed = {
                "advance": {"updated_at", "revision", "last_transition_id"},
                "hold": {
                    "status",
                    "updated_at",
                    "on_hold_since",
                    "on_hold_reason",
                    "revision",
                    "last_transition_id",
                },
                "resume": {
                    "status",
                    "updated_at",
                    "on_hold_since",
                    "on_hold_reason",
                    "revision",
                    "last_transition_id",
                },
                "archive": {
                    "status",
                    "updated_at",
                    "archived_at",
                    "revision",
                    "last_transition_id",
                },
            }.get(operation)
            if allowed is None:
                _fail("project record delta operation is invalid")
            old_payload = _record_payload(old)
            new_payload = _record_payload(new)
            if {
                key: value for key, value in old_payload.items() if key not in allowed
            } != {
                key: value for key, value in new_payload.items() if key not in allowed
            }:
                _fail("project transition changes unrelated record fields")
            return
        if relative == "state.json":
            if current is None:
                if operation != "create":
                    _fail("non-create transition lacks a state preimage")
                return
            old_state = _parse_state(_decode_json(current, "project state preimage"))
            new_state = _parse_state(_decode_json(target, "project state target"))
            if (
                old_state.project_slug != new_state.project_slug
                or new_state.revision != old_state.revision + 1
            ):
                _fail("project state delta is invalid")
            if operation != "advance":
                old_payload = _state_payload(old_state)
                new_payload = _state_payload(new_state)
                old_payload.pop("revision")
                new_payload.pop("revision")
                if old_payload != new_payload:
                    _fail("lifecycle transition changes project work state")
            return
        if relative == "log.md":
            if operation == "create":
                expected = f"# Project log: {target_record.name}\n".encode(
                    "utf-8"
                ) + self._log_entry(
                    target_record.updated_at, "create", "Created project."
                )
            else:
                if current is None:
                    _fail("project transition lacks a log preimage")
                summary = {
                    "advance": fields.get("summary"),
                    "hold": fields.get("reason"),
                    "resume": "Resumed project.",
                    "archive": (
                        f"Archived project with child policy {fields.get('child_policy')}."
                    ),
                }.get(operation)
                if not isinstance(summary, str):
                    _fail("project log request summary is invalid")
                expected = current + self._log_entry(
                    target_record.updated_at, operation, summary
                )
            if target != expected:
                _fail("project target log is not the exact append")
            return
        parts = _safe_parts(relative)
        if operation != "archive" or len(parts) != 3 or current is None:
            _fail("project child delta is invalid")
        old_child = _decode_json(current, "child project preimage")
        new_child = _decode_json(target, "child project target")
        expected_child = dict(old_child)
        expected_child["status"] = "archived"
        expected_child["archived_at"] = target_record.archived_at
        if new_child != expected_child:
            _fail("archive changes unrelated child engine fields")

    def _apply_domain(
        self,
        root_fd: int,
        intent: Mapping[str, object],
        request: Mapping[str, object],
    ) -> None:
        source = intent.get("source")
        destination = intent.get("destination")
        if (
            source is not None
            and not isinstance(source, str)
            or not isinstance(destination, str)
        ):
            _fail("transition locations are invalid")
        if source is not None:
            _safe_parts(source)
        _safe_parts(destination)
        before = intent.get("before")
        if not isinstance(before, Mapping):
            _fail("transition preimage evidence is invalid")
        targets = self._target_bytes(intent)
        self._validate_child_observation(root_fd, intent, targets)
        # First establish the physical lifecycle location.  An exact destination
        # from a crashed prior attempt is accepted; two simultaneous locations are not.
        # Materialize the destination parent before exact no-follow existence
        # checks.  Existing non-directory leaves are corruption, not absence.
        if "/" in destination:
            destination_parent = destination.rsplit("/", 1)[0]
            parent_fd = _open_dir_at(root_fd, destination_parent, create=True)
            os.close(parent_fd)
        source_exists = (
            _directory_exists_at(root_fd, source) if source is not None else False
        )
        destination_exists = _directory_exists_at(root_fd, destination)
        if source is None:
            if not destination_exists:
                _fail("bound project directory disappeared before commit")
        elif source != destination:
            if source_exists and destination_exists:
                _fail("transition has both source and destination locations")
            if source_exists:
                src_parent, src_leaf = (
                    source.rsplit("/", 1) if "/" in source else (None, source)
                )
                dst_parent, dst_leaf = (
                    destination.rsplit("/", 1)
                    if "/" in destination
                    else (None, destination)
                )
                src_fd = (
                    root_fd if src_parent is None else _open_dir_at(root_fd, src_parent)
                )
                dst_fd = (
                    root_fd
                    if dst_parent is None
                    else _open_dir_at(root_fd, dst_parent, create=True)
                )
                try:
                    os.rename(src_leaf, dst_leaf, src_dir_fd=src_fd, dst_dir_fd=dst_fd)
                    os.fsync(src_fd)
                    if dst_fd != src_fd:
                        os.fsync(dst_fd)
                except OSError:
                    _fail("project lifecycle move cannot be committed")
                finally:
                    if src_fd != root_fd:
                        os.close(src_fd)
                    if dst_fd != root_fd:
                        os.close(dst_fd)
            elif not destination_exists:
                _fail("project lifecycle source disappeared")
        project_fd = _open_dir_at(root_fd, destination)
        try:
            self._require_project_directory_binding(
                root_fd, intent, retained_fd=project_fd
            )
            for relative, target in sorted(targets.items()):
                self._require_project_directory_binding(
                    root_fd, intent, retained_fd=project_fd
                )
                parts = _safe_parts(relative)
                parent_fd = (
                    project_fd
                    if len(parts) == 1
                    else _open_dir_at(project_fd, "/".join(parts[:-1]))
                )
                try:
                    try:
                        current = _read_file_at(parent_fd, parts[-1], _MAX_LOG)
                        current_hash: str | None = _digest_bytes(current)
                    except ProjectFlowError:
                        try:
                            os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
                        except FileNotFoundError:
                            current_hash = None
                        else:
                            raise
                    target_hash = _digest_bytes(target)
                    if current_hash == target_hash:
                        self._require_project_directory_binding(
                            root_fd, intent, retained_fd=project_fd
                        )
                        continue
                    if before.get(relative) != current_hash:
                        _fail("project file changed after transition was prepared")
                    self._validate_file_delta(
                        relative=relative,
                        current=current if current_hash is not None else None,
                        target=target,
                        targets=targets,
                        request=request,
                    )
                    self._require_project_directory_binding(
                        root_fd, intent, retained_fd=project_fd
                    )
                    _atomic_file_at(parent_fd, parts[-1], target)
                    self._require_project_directory_binding(
                        root_fd, intent, retained_fd=project_fd
                    )
                finally:
                    if parent_fd != project_fd:
                        os.close(parent_fd)
            self._require_project_directory_binding(
                root_fd, intent, retained_fd=project_fd
            )
        finally:
            os.close(project_fd)

    def _rollback_domain(self, root_fd: int, intent: Mapping[str, object]) -> None:
        """Restore the exact preimage after detecting a detached vault root."""

        source = intent.get("source")
        destination = intent.get("destination")
        before = intent.get("before")
        preimages = intent.get("preimages")
        targets = self._target_bytes(intent)
        if (
            (source is not None and not isinstance(source, str))
            or not isinstance(destination, str)
            or not isinstance(before, Mapping)
            or not isinstance(preimages, Mapping)
        ):
            _fail("transition rollback evidence is invalid")
        location = destination
        if not _directory_exists_at(root_fd, destination):
            if source is None or not _directory_exists_at(root_fd, source):
                _fail("transition rollback location is missing")
            location = source
        project_fd = _open_dir_at(root_fd, location)
        try:
            if source is None:
                for relative in sorted(
                    targets, key=lambda item: (-len(_safe_parts(item)), item)
                ):
                    parts = _safe_parts(relative)
                    parent_fd = (
                        project_fd
                        if len(parts) == 1
                        else _open_dir_at(project_fd, "/".join(parts[:-1]))
                    )
                    try:
                        try:
                            os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
                        except FileNotFoundError:
                            continue
                        current = _read_file_at(parent_fd, parts[-1], _MAX_LOG)
                        if _digest_bytes(current) != _digest_bytes(targets[relative]):
                            _fail("create rollback preserves a changed foreign file")
                        os.unlink(parts[-1], dir_fd=parent_fd)
                        os.fsync(parent_fd)
                    finally:
                        if parent_fd != project_fd:
                            os.close(parent_fd)
            else:
                for relative in sorted(targets):
                    expected_hash = before[relative]
                    encoded = preimages[relative]
                    if not isinstance(expected_hash, str) or not isinstance(
                        encoded, str
                    ):
                        _fail("transition rollback preimage is invalid")
                    raw = base64.b64decode(encoded, validate=True)
                    parts = _safe_parts(relative)
                    parent_fd = (
                        project_fd
                        if len(parts) == 1
                        else _open_dir_at(project_fd, "/".join(parts[:-1]))
                    )
                    try:
                        current = _read_file_at(parent_fd, parts[-1], _MAX_LOG)
                        current_hash = _digest_bytes(current)
                        if current_hash == expected_hash:
                            continue
                        if current_hash != _digest_bytes(targets[relative]):
                            _fail(
                                "transition rollback preserves a changed foreign file"
                            )
                        _atomic_file_at(parent_fd, parts[-1], raw)
                    finally:
                        if parent_fd != project_fd:
                            os.close(parent_fd)
        finally:
            os.close(project_fd)
        if source is None:
            parent, leaf = (
                destination.rsplit("/", 1)
                if "/" in destination
                else (None, destination)
            )
            parent_fd = root_fd if parent is None else _open_dir_at(root_fd, parent)
            try:
                os.rmdir(leaf, dir_fd=parent_fd)
                os.fsync(parent_fd)
            except OSError:
                _fail("created project rollback found unexpected files")
            finally:
                if parent_fd != root_fd:
                    os.close(parent_fd)
        elif source != destination and _directory_exists_at(root_fd, destination):
            if _directory_exists_at(root_fd, source):
                _fail("transition rollback source appeared concurrently")
            src_parent, src_leaf = (
                source.rsplit("/", 1) if "/" in source else (None, source)
            )
            dst_parent, dst_leaf = (
                destination.rsplit("/", 1)
                if "/" in destination
                else (None, destination)
            )
            src_fd = (
                root_fd
                if src_parent is None
                else _open_dir_at(root_fd, src_parent, create=True)
            )
            dst_fd = (
                root_fd if dst_parent is None else _open_dir_at(root_fd, dst_parent)
            )
            try:
                os.rename(dst_leaf, src_leaf, src_dir_fd=dst_fd, dst_dir_fd=src_fd)
                os.fsync(dst_fd)
                if src_fd != dst_fd:
                    os.fsync(src_fd)
            except OSError:
                _fail("project lifecycle rollback cannot restore source")
            finally:
                if src_fd != root_fd:
                    os.close(src_fd)
                if dst_fd != root_fd:
                    os.close(dst_fd)

    def _write_intent(
        self,
        intents_fd: int,
        transition_id: str,
        payload: Mapping[str, object],
        *,
        create: bool,
    ) -> None:
        data = _canonical(payload)
        name = f"{transition_id}.json"
        if create:
            if not _create_file_at(intents_fd, name, data):
                _fail("transition intent appeared concurrently")
        else:
            _atomic_file_at(intents_fd, name, data)

    def _cleanup_detached_transaction(
        self,
        root_fd: int,
        intents_fd: int,
        transition_id: str,
        intent: Mapping[str, object],
        *,
        replayed: bool,
        intent_dir_created: bool,
        lock_created: bool,
    ) -> None:
        if not replayed:
            name = f"{transition_id}.json"
            try:
                current = _decode_json(
                    _read_file_at(intents_fd, name, _MAX_JSON),
                    "detached transition intent",
                )
                if current.get("transition_id") == intent.get(
                    "transition_id"
                ) and current.get("request_sha256") == intent.get("request_sha256"):
                    os.unlink(name, dir_fd=intents_fd)
                    os.fsync(intents_fd)
            except (OSError, ProjectFlowError):
                pass
        if intent_dir_created:
            try:
                os.rmdir(".lifeos-project-intents", dir_fd=root_fd)
                os.fsync(root_fd)
            except OSError:
                pass
        if lock_created:
            try:
                lock_metadata = os.stat(
                    ".project-flow.lock", dir_fd=root_fd, follow_symlinks=False
                )
                if stat.S_ISREG(lock_metadata.st_mode) and lock_metadata.st_size == 0:
                    os.unlink(".project-flow.lock", dir_fd=root_fd)
                    os.fsync(root_fd)
            except OSError:
                pass

    def _schedule_from_intent(self, payload: object) -> ProjectScheduleIntent | None:
        if payload is None:
            return None
        if (
            not isinstance(payload, Mapping)
            or set(payload)
            != {
                "schema_version",
                "transition_id",
                "project_slug",
                "action",
                "schedule_ids",
                "reason",
                "expected",
            }
            or not isinstance(payload["schedule_ids"], list)
            or not isinstance(payload["expected"], list)
        ):
            _fail("schedule transition intent is invalid")
        if (
            type(payload["schema_version"]) is not int
            or not all(
                isinstance(payload[name], str)
                for name in ("transition_id", "project_slug", "action", "reason")
            )
            or not all(isinstance(item, str) for item in payload["schedule_ids"])
        ):
            _fail("schedule transition intent scalar fields are invalid")
        expected: list[ScheduleSnapshot] = []
        for item in payload["expected"]:
            if (
                not isinstance(item, Mapping)
                or set(item) != {"schedule_id", "status", "sha256"}
                or not all(
                    isinstance(item[name], str)
                    for name in ("schedule_id", "status", "sha256")
                )
            ):
                _fail("schedule transition expected state is invalid")
            expected.append(
                ScheduleSnapshot(
                    str(item["schedule_id"]), str(item["status"]), str(item["sha256"])
                )
            )
        value = ProjectScheduleIntent(
            payload["schema_version"],
            payload["transition_id"],
            payload["project_slug"],
            payload["action"],
            tuple(payload["schedule_ids"]),
            payload["reason"],
            tuple(expected),
        )
        if (
            value.schema_version != PROJECT_SCHEDULE_SCHEMA_VERSION
            or value.action not in {"pause", "verify"}
        ):
            _fail("schedule transition intent is invalid")
        _identifier(value.transition_id, "schedule transition_id")
        _identifier(value.project_slug, "schedule project_slug", _SLUG)
        tuple(_identifier(x, "schedule_id") for x in value.schedule_ids)
        _text(value.reason, "schedule reason")
        for item in value.expected:
            _identifier(item.schedule_id, "expected schedule_id")
            if item.status not in _SCHEDULE_STATUSES:
                _fail("expected schedule status is invalid")
            _hash(item.sha256, "expected schedule sha256")
        if len({item.schedule_id for item in value.expected}) != len(value.expected):
            _fail("expected schedule ids are duplicated")
        return value

    def _receipt_from_intent(self, payload: object) -> ScheduleReceipt | None:
        if payload is None:
            return None
        if not isinstance(payload, Mapping) or set(payload) != {
            "schema_version",
            "transition_id",
            "status",
            "effect_hash",
        }:
            _fail("schedule receipt is invalid")
        if type(payload["schema_version"]) is not int or not all(
            isinstance(payload[name], str)
            for name in ("transition_id", "status", "effect_hash")
        ):
            _fail("schedule receipt is invalid")
        receipt = ScheduleReceipt(
            payload["schema_version"],
            payload["transition_id"],
            payload["status"],
            payload["effect_hash"],
        )
        if (
            receipt.schema_version != PROJECT_SCHEDULE_SCHEMA_VERSION
            or receipt.status != "succeeded"
        ):
            _fail("schedule receipt is invalid")
        _identifier(receipt.transition_id, "schedule receipt transition_id")
        _hash(receipt.effect_hash, "schedule receipt effect_hash")
        return receipt

    def _commit_run(
        self,
        *,
        run_id: str,
        transition_id: str,
        request_hash: str,
        evidence_relative: str,
        evidence_hash: str,
        read: ActionCapability,
        commit: ActionCapability,
        run: ActionCapability,
        schedule: ActionCapability | None,
    ) -> None:
        actions = [ActionUse(read), ActionUse(commit)]
        if schedule is not None:
            actions.append(ActionUse(schedule))
        actions.append(ActionUse(run))
        prepared = PreparedArtifact(
            name="project_transition",
            zone="projects",
            relative=evidence_relative,
            state_ref=f"projects/{evidence_relative}",
            sha256=evidence_hash,
        )
        try:
            state = self._runs.commit_step(
                run_id,
                step_id=transition_id,
                authority="domain-write",
                input_hash=request_hash,
                output_hash=evidence_hash,
                next_phase="project-committed",
                next_status="running",
                prepared_artifacts=(prepared,),
                # The local intent is the domain precondition.  Omitting a run
                # precondition also makes replay safe after RunStore committed
                # but the local intent status replace crashed.
                expected_state_sha256=None,
                action_uses=tuple(actions),
                authority_policy=self._policy,
            )
        except RunError as error:
            raise ProjectFlowError(str(error)) from None
        if state["status"] != "running":
            _fail("project commit must leave run running")

    def _verify_completed_run(
        self,
        *,
        run_id: str,
        transition_id: str,
        request_hash: str,
        evidence_hash: str,
    ) -> None:
        try:
            matches = tuple(
                event
                for event in self._runs.trace_events(run_id)
                if event.get("step_id") == transition_id
            )
        except RunError as error:
            raise ProjectFlowError(str(error)) from None
        if (
            len(matches) != 1
            or matches[0].get("input_hash") != request_hash
            or matches[0].get("output_hash") != evidence_hash
            or matches[0].get("authority") != "domain-write"
        ):
            _fail("completed transition lacks exact run evidence")

    def _execute(
        self,
        *,
        capabilities: ProjectCapabilities,
        run_id: str,
        request: Mapping[str, object],
        build: Callable[[int, str], dict[str, object]],
    ) -> ProjectTransitionResult:
        if not isinstance(capabilities, ProjectCapabilities):
            _fail("project transition requires ProjectCapabilities")
        read = self._require(capabilities.read, "read-project-state")
        commit = self._require(capabilities.commit, "commit-project-transition")
        run = self._require(capabilities.run, "record-run-state")
        schedule_grant = None
        if capabilities.schedule is not None:
            schedule_grant = self._require(
                capabilities.schedule, "apply-linked-schedule-transition"
            )
        transition_id = _identifier(request["transition_id"], "transition_id")
        _identifier(run_id, "run_id", re.compile(r"^run_[a-z0-9][a-z0-9_-]{0,62}$"))
        try:
            run_state = self._runs.status(run_id)
        except RunError as error:
            raise ProjectFlowError(str(error)) from None
        if (
            run_state.get("flow") != "project"
            or run_state.get("status") != "running"
            or run_state.get("authority") != "domain-write"
        ):
            _fail("project transition requires a running project run")
        root_fd, root_path, root_identity = self._root(for_write=True)
        lock_fd: int | None = None
        try:
            try:
                os.stat(".project-flow.lock", dir_fd=root_fd, follow_symlinks=False)
                lock_created = False
            except FileNotFoundError:
                lock_created = True
            try:
                os.stat(
                    ".lifeos-project-intents",
                    dir_fd=root_fd,
                    follow_symlinks=False,
                )
                intent_dir_created = False
            except FileNotFoundError:
                intent_dir_created = True
            try:
                lock_fd = os.open(
                    ".project-flow.lock",
                    os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
                    0o600,
                    dir_fd=root_fd,
                )
                if not stat.S_ISREG(os.fstat(lock_fd).st_mode):
                    _fail("project lock is invalid")
                fcntl.flock(lock_fd, fcntl.LOCK_EX)
            except OSError:
                _fail("project lock cannot be acquired")
            intents_fd = self._intent_dir(root_fd)
            try:
                self._require_no_other_pending_intent(
                    intents_fd,
                    slug=str(request["slug"]),
                    transition_id=transition_id,
                )
                intent = self._load_intent(intents_fd, transition_id)
                replayed = intent is not None
                if intent is None:
                    intent = build(root_fd, self._now())
                    intent = self._attach_preimages(root_fd, intent)
                    self._validate_replay(intent, request)
                    prepared_schedule = self._schedule_from_intent(
                        intent.get("schedule")
                    )
                    prepared_schedule_used = prepared_schedule is not None or bool(
                        intent.get("schedule_observation")
                    )
                    if prepared_schedule_used and schedule_grant is None:
                        _fail("schedule capability is required for linked schedules")
                    self._write_intent(intents_fd, transition_id, intent, create=True)
                else:
                    self._validate_replay(intent, request)
                    prepared_schedule = self._schedule_from_intent(
                        intent.get("schedule")
                    )
                    prepared_schedule_used = prepared_schedule is not None or bool(
                        intent.get("schedule_observation")
                    )
                    if prepared_schedule_used and schedule_grant is None:
                        _fail("schedule capability is required for linked schedules")
                self._before_domain_commit()
                try:
                    self._revalidate_root(
                        root_fd, root_path, root_identity, for_write=True
                    )
                except ProjectFlowError:
                    self._cleanup_detached_transaction(
                        root_fd,
                        intents_fd,
                        transition_id,
                        intent,
                        replayed=replayed,
                        intent_dir_created=intent_dir_created,
                        lock_created=lock_created,
                    )
                    raise
                durable_intent = self._load_intent(intents_fd, transition_id)
                if durable_intent != intent:
                    _fail("transition intent changed before domain commit")
                bound_intent = self._bind_or_reconcile_project_directory(
                    root_fd, intent
                )
                if bound_intent != intent:
                    self._write_intent(
                        intents_fd, transition_id, bound_intent, create=False
                    )
                    intent = bound_intent
                    durable_intent = self._load_intent(intents_fd, transition_id)
                    if durable_intent != intent:
                        _fail("project directory binding was not durable")
                if intent["status"] == "prepared":
                    self._apply_domain(root_fd, intent, request)
                    try:
                        self._revalidate_root(
                            root_fd, root_path, root_identity, for_write=True
                        )
                    except ProjectFlowError:
                        self._rollback_domain(root_fd, intent)
                        reverted = dict(intent)
                        reverted["status"] = "prepared"
                        self._write_intent(
                            intents_fd, transition_id, reverted, create=False
                        )
                        self._cleanup_detached_transaction(
                            root_fd,
                            intents_fd,
                            transition_id,
                            reverted,
                            replayed=replayed,
                            intent_dir_created=intent_dir_created,
                            lock_created=lock_created,
                        )
                        raise
                    self._require_project_directory_binding(root_fd, intent)
                    intent = dict(intent)
                    intent["status"] = "domain_committed"
                    self._write_intent(intents_fd, transition_id, intent, create=False)
                    self._require_project_directory_binding(root_fd, intent)
                    try:
                        self._revalidate_root(
                            root_fd, root_path, root_identity, for_write=True
                        )
                    except ProjectFlowError:
                        self._rollback_domain(root_fd, intent)
                        reverted = dict(intent)
                        reverted["status"] = "prepared"
                        self._write_intent(
                            intents_fd, transition_id, reverted, create=False
                        )
                        self._cleanup_detached_transaction(
                            root_fd,
                            intents_fd,
                            transition_id,
                            reverted,
                            replayed=replayed,
                            intent_dir_created=intent_dir_created,
                            lock_created=lock_created,
                        )
                        raise
                destination = str(intent["destination"])
                self._require_project_directory_binding(root_fd, intent)
                snapshot = self._read_snapshot_at(root_fd, destination)
                self._require_project_directory_binding(root_fd, intent)
                schedule_intent = self._schedule_from_intent(intent.get("schedule"))
                schedule_observed = intent.get("schedule_observation")
                schedule_used = schedule_intent is not None or bool(schedule_observed)
                receipt = self._receipt_from_intent(intent.get("schedule_receipt"))
                if schedule_used and schedule_grant is None:
                    _fail("schedule capability is required for linked schedules")
                if schedule_intent is not None and receipt is None:
                    if self._schedule is None:
                        self._require_project_directory_binding(root_fd, intent)
                        return ProjectTransitionResult(
                            snapshot,
                            transition_id,
                            str(intent["operation"]),
                            intent.get("child_policy")
                            if isinstance(intent.get("child_policy"), str)
                            else None,
                            tuple(str(x) for x in intent.get("archived_children", [])),
                            True,
                            None,
                            replayed,
                        )
                    self._require_project_directory_binding(root_fd, intent)
                    try:
                        produced = self._schedule.apply(schedule_intent)
                    except Exception:
                        _fail("linked schedule transition failed")
                    self._require_project_directory_binding(root_fd, intent)
                    if (
                        not isinstance(produced, ScheduleReceipt)
                        or produced.schema_version != PROJECT_SCHEDULE_SCHEMA_VERSION
                        or produced.transition_id != transition_id
                        or produced.status != "succeeded"
                    ):
                        _fail("scheduler returned an invalid receipt")
                    _hash(produced.effect_hash, "schedule receipt effect_hash")
                    if produced.effect_hash != expected_schedule_effect_hash(
                        schedule_intent
                    ):
                        _fail("scheduler receipt is not bound to exact intent")
                    receipt = produced
                    intent = dict(intent)
                    intent["schedule_receipt"] = {
                        "schema_version": receipt.schema_version,
                        "transition_id": receipt.transition_id,
                        "status": receipt.status,
                        "effect_hash": receipt.effect_hash,
                    }
                    intent["status"] = "schedule_committed"
                    self._write_intent(intents_fd, transition_id, intent, create=False)
                    self._require_project_directory_binding(root_fd, intent)
                evidence = {
                    "schema_version": PROJECT_TRANSITION_SCHEMA_VERSION,
                    "transition_id": transition_id,
                    "operation": intent["operation"],
                    "request_sha256": intent["request_sha256"],
                    "location": snapshot.location,
                    "snapshot_sha256": snapshot.snapshot_sha256,
                    "archived_children": intent.get("archived_children", []),
                    "child_policy": intent.get("child_policy"),
                    "schedule_observation": intent.get("schedule_observation"),
                    "schedule_receipt": intent.get("schedule_receipt"),
                }
                evidence_bytes = _canonical(evidence)
                evidence_fd = self._evidence_dir(root_fd)
                evidence_name = f"{transition_id}.json"
                try:
                    self._require_project_directory_binding(root_fd, intent)
                    if not _create_file_at(evidence_fd, evidence_name, evidence_bytes):
                        if (
                            _read_file_at(evidence_fd, evidence_name, _MAX_JSON)
                            != evidence_bytes
                        ):
                            _fail("project transition evidence conflicts")
                    self._require_project_directory_binding(root_fd, intent)
                finally:
                    os.close(evidence_fd)
                evidence_hash = _digest_bytes(evidence_bytes)
                self._revalidate_root(root_fd, root_path, root_identity, for_write=True)
                if intent["status"] != "complete":
                    self._require_project_directory_binding(root_fd, intent)
                    self._commit_run(
                        run_id=run_id,
                        transition_id=transition_id,
                        request_hash=str(intent["request_sha256"]),
                        evidence_relative=f".lifeos-project-evidence/{evidence_name}",
                        evidence_hash=evidence_hash,
                        read=read,
                        commit=commit,
                        run=run,
                        schedule=schedule_grant if schedule_used else None,
                    )
                    self._require_project_directory_binding(root_fd, intent)
                    self._after_run_commit()
                    self._require_project_directory_binding(root_fd, intent)
                    intent = dict(intent)
                    intent["status"] = "complete"
                    self._write_intent(intents_fd, transition_id, intent, create=False)
                    self._require_project_directory_binding(root_fd, intent)
                else:
                    self._verify_completed_run(
                        run_id=run_id,
                        transition_id=transition_id,
                        request_hash=str(intent["request_sha256"]),
                        evidence_hash=evidence_hash,
                    )
                    self._require_project_directory_binding(root_fd, intent)
                self._revalidate_root(root_fd, root_path, root_identity, for_write=True)
                self._require_project_directory_binding(root_fd, intent)
                return ProjectTransitionResult(
                    snapshot,
                    transition_id,
                    str(intent["operation"]),
                    intent.get("child_policy")
                    if isinstance(intent.get("child_policy"), str)
                    else None,
                    tuple(str(x) for x in intent.get("archived_children", [])),
                    False,
                    receipt,
                    replayed,
                )
            finally:
                os.close(intents_fd)
        finally:
            if lock_fd is not None:
                try:
                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
                finally:
                    os.close(lock_fd)
            os.close(root_fd)

    def _before_domain_commit(self) -> None:
        """Test seam immediately before the first domain effect."""

    def _after_run_commit(self) -> None:
        """Test seam after RunStore commit but before local completion."""

    @staticmethod
    def _log_entry(at: str, operation: str, summary: str) -> bytes:
        clean = _text(summary, "project log summary", limit=16384)
        return f"\n## {at} - {operation}\n\n{clean}\n".encode("utf-8")

    def _before_hashes(
        self, root_fd: int, snapshot: ProjectSnapshot
    ) -> dict[str, str | None]:
        return {
            "project.json": snapshot.project_sha256,
            "state.json": snapshot.state_sha256,
            "log.md": snapshot.log_sha256,
        }

    def create(
        self,
        capabilities: ProjectCapabilities,
        *,
        run_id: str,
        transition_id: str,
        slug: str,
        name: str,
        goal: str,
        domains: Sequence[str],
        kind: str = "general",
        schedule_ids: Sequence[str] = (),
    ) -> ProjectTransitionResult:
        checked_slug = _identifier(slug, "project slug", _SLUG)
        checked_name = _text(name, "project name", limit=512)
        checked_goal = _text(goal, "project goal", limit=16384)
        checked_domains = tuple(_identifier(x, "domain", _SLUG) for x in domains)
        checked_schedules = tuple(_identifier(x, "schedule_id") for x in schedule_ids)
        checked_transition = _identifier(transition_id, "transition_id")
        if (
            kind not in _KINDS
            or not checked_domains
            or len(checked_domains) > 32
            or len(set(checked_domains)) != len(checked_domains)
            or len(checked_schedules) > 128
            or len(set(checked_schedules)) != len(checked_schedules)
        ):
            _fail("project create collections or kind are invalid")
        fields = {
            "name": checked_name,
            "goal": checked_goal,
            "domains": list(checked_domains),
            "kind": kind,
            "schedule_ids": list(checked_schedules),
        }
        request = self._request("create", checked_slug, checked_transition, fields)

        def build(root_fd: int, now: str) -> dict[str, object]:
            if self._find_locations(root_fd, checked_slug):
                _fail("project already exists or collides portably")
            record = ProjectRecord(
                PROJECT_SCHEMA_VERSION,
                checked_slug,
                checked_name,
                checked_goal,
                checked_domains,
                kind,
                "active",
                now,
                now,
                None,
                None,
                None,
                1,
                checked_transition,
                checked_schedules,
            )
            state = ProjectState(
                PROJECT_STATE_SCHEMA_VERSION, checked_slug, 1, (), (), (), (), None
            )
            project_bytes = _canonical(_record_payload(record))
            state_bytes = _canonical(_state_payload(state))
            log_bytes = f"# Project log: {checked_name}\n".encode(
                "utf-8"
            ) + self._log_entry(now, "create", "Created project.")
            return self._intent_payload(
                request=request,
                source=None,
                destination=checked_slug,
                before={"project.json": None, "state.json": None, "log.md": None},
                targets={
                    "project.json": project_bytes,
                    "state.json": state_bytes,
                    "log.md": log_bytes,
                },
                archived_children=(),
                child_policy=None,
                schedule=None,
            )

        return self._execute(
            capabilities=capabilities, run_id=run_id, request=request, build=build
        )

    def advance(
        self,
        capabilities: ProjectCapabilities,
        *,
        run_id: str,
        transition_id: str,
        slug: str,
        advance: ProjectAdvance,
        expected_revision: int,
        expected_snapshot_sha256: str,
    ) -> ProjectTransitionResult:
        checked_slug = _identifier(slug, "project slug", _SLUG)
        checked_transition = _identifier(transition_id, "transition_id")
        _hash(expected_snapshot_sha256, "expected_snapshot_sha256")
        if (
            type(expected_revision) is not int
            or expected_revision < 1
            or not isinstance(advance, ProjectAdvance)
        ):
            _fail("project advance precondition is invalid")
        state_probe = ProjectState(
            PROJECT_STATE_SCHEMA_VERSION,
            checked_slug,
            expected_revision + 1,
            advance.next_steps,
            advance.blockers,
            advance.open_questions,
            advance.milestones,
            advance.session,
        )
        desired_state = _state_payload(state_probe)
        summary = _text(advance.summary, "advance summary", limit=16384)
        fields = {
            "expected_revision": expected_revision,
            "expected_snapshot_sha256": expected_snapshot_sha256,
            "state": desired_state,
            "summary": summary,
        }
        request = self._request("advance", checked_slug, checked_transition, fields)

        def build(root_fd: int, now: str) -> dict[str, object]:
            locations = self._find_locations(root_fd, checked_slug)
            if len(locations) != 1:
                _fail("project is missing or collides portably")
            snapshot = self._read_snapshot_at(root_fd, locations[0])
            if snapshot.record.status != "active":
                _fail("only an active project can advance")
            if (
                snapshot.record.revision != expected_revision
                or snapshot.snapshot_sha256 != expected_snapshot_sha256
            ):
                _fail("project advance precondition is stale")
            record = replace(
                snapshot.record,
                updated_at=now,
                revision=expected_revision + 1,
                last_transition_id=checked_transition,
            )
            state = replace(state_probe, revision=record.revision)
            directory_fd = _open_dir_at(root_fd, snapshot.location)
            try:
                old_log = _read_file_at(directory_fd, "log.md", _MAX_LOG)
            finally:
                os.close(directory_fd)
            targets = {
                "project.json": _canonical(_record_payload(record)),
                "state.json": _canonical(_state_payload(state)),
                "log.md": old_log + self._log_entry(now, "advance", summary),
            }
            return self._intent_payload(
                request=request,
                source=snapshot.location,
                destination=snapshot.location,
                before=self._before_hashes(root_fd, snapshot),
                targets=targets,
                archived_children=(),
                child_policy=None,
                schedule=None,
            )

        return self._execute(
            capabilities=capabilities, run_id=run_id, request=request, build=build
        )

    def hold(
        self,
        capabilities: ProjectCapabilities,
        *,
        run_id: str,
        transition_id: str,
        slug: str,
        reason: str,
        expected_revision: int,
        expected_snapshot_sha256: str,
    ) -> ProjectTransitionResult:
        return self._lifecycle(
            capabilities,
            run_id=run_id,
            transition_id=transition_id,
            slug=slug,
            operation="hold",
            reason=reason,
            expected_revision=expected_revision,
            expected_snapshot_sha256=expected_snapshot_sha256,
        )

    def resume(
        self,
        capabilities: ProjectCapabilities,
        *,
        run_id: str,
        transition_id: str,
        slug: str,
        expected_revision: int,
        expected_snapshot_sha256: str,
    ) -> ProjectTransitionResult:
        return self._lifecycle(
            capabilities,
            run_id=run_id,
            transition_id=transition_id,
            slug=slug,
            operation="resume",
            reason="Resumed project.",
            expected_revision=expected_revision,
            expected_snapshot_sha256=expected_snapshot_sha256,
        )

    def _lifecycle(
        self,
        capabilities: ProjectCapabilities,
        *,
        run_id: str,
        transition_id: str,
        slug: str,
        operation: str,
        reason: str,
        expected_revision: int,
        expected_snapshot_sha256: str,
    ) -> ProjectTransitionResult:
        checked_slug = _identifier(slug, "project slug", _SLUG)
        checked_transition = _identifier(transition_id, "transition_id")
        clean_reason = _text(reason, "transition reason", limit=4096)
        _hash(expected_snapshot_sha256, "expected_snapshot_sha256")
        if (
            operation not in {"hold", "resume"}
            or type(expected_revision) is not int
            or expected_revision < 1
        ):
            _fail("project lifecycle request is invalid")
        fields = {
            "reason": clean_reason,
            "expected_revision": expected_revision,
            "expected_snapshot_sha256": expected_snapshot_sha256,
        }
        request = self._request(operation, checked_slug, checked_transition, fields)

        def build(root_fd: int, now: str) -> dict[str, object]:
            locations = self._find_locations(root_fd, checked_slug)
            if len(locations) != 1:
                _fail("project is missing or collides portably")
            snapshot = self._read_snapshot_at(root_fd, locations[0])
            expected_status = "active" if operation == "hold" else "on-hold"
            if snapshot.record.status != expected_status:
                _fail("project lifecycle transition is invalid")
            if (
                snapshot.record.revision != expected_revision
                or snapshot.snapshot_sha256 != expected_snapshot_sha256
            ):
                _fail("project lifecycle precondition is stale")
            if operation == "hold":
                record = replace(
                    snapshot.record,
                    status="on-hold",
                    updated_at=now,
                    on_hold_since=now,
                    on_hold_reason=clean_reason,
                    revision=expected_revision + 1,
                    last_transition_id=checked_transition,
                )
            else:
                record = replace(
                    snapshot.record,
                    status="active",
                    updated_at=now,
                    on_hold_since=None,
                    on_hold_reason=None,
                    revision=expected_revision + 1,
                    last_transition_id=checked_transition,
                )
            state = replace(snapshot.state, revision=record.revision)
            directory_fd = _open_dir_at(root_fd, snapshot.location)
            try:
                old_log = _read_file_at(directory_fd, "log.md", _MAX_LOG)
            finally:
                os.close(directory_fd)
            destination = self._location(record.status, checked_slug)
            schedule_intent = None
            if operation == "hold" and record.schedule_ids:
                schedule_intent = ProjectScheduleIntent(
                    PROJECT_SCHEDULE_SCHEMA_VERSION,
                    checked_transition,
                    checked_slug,
                    "pause",
                    record.schedule_ids,
                    "project-on-hold",
                )
            return self._intent_payload(
                request=request,
                source=snapshot.location,
                destination=destination,
                before=self._before_hashes(root_fd, snapshot),
                targets={
                    "project.json": _canonical(_record_payload(record)),
                    "state.json": _canonical(_state_payload(state)),
                    "log.md": old_log + self._log_entry(now, operation, clean_reason),
                },
                archived_children=(),
                child_policy=None,
                schedule=schedule_intent,
            )

        return self._execute(
            capabilities=capabilities, run_id=run_id, request=request, build=build
        )

    def _children(
        self, root_fd: int, location: str
    ) -> tuple[tuple[str, str, bytes], ...]:
        project_fd = _open_dir_at(root_fd, location)
        try:
            try:
                research_metadata = os.stat(
                    "research", dir_fd=project_fd, follow_symlinks=False
                )
            except FileNotFoundError:
                return ()
            except OSError:
                _fail("child engine namespace cannot be inspected")
            if not stat.S_ISDIR(research_metadata.st_mode):
                _fail("child engine namespace is unsafe")
            research_fd = _open_dir_at(project_fd, "research")
        finally:
            os.close(project_fd)
        result: list[tuple[str, str, bytes]] = []
        try:
            for name in sorted(os.listdir(research_fd)):
                _identifier(name, "child engine id")
                child_fd = _open_dir_at(research_fd, name)
                try:
                    raw = _read_file_at(child_fd, "project.json", _MAX_JSON)
                finally:
                    os.close(child_fd)
                payload = _decode_json(raw, "child engine project")
                status = payload.get("status")
                if not isinstance(status, str):
                    _fail("child engine status is invalid")
                result.append((name, status, raw))
        finally:
            os.close(research_fd)
        return tuple(result)

    def _validate_child_observation(
        self,
        root_fd: int,
        intent: Mapping[str, object],
        targets: Mapping[str, bytes],
    ) -> None:
        if intent["operation"] != "archive":
            return
        source = intent["source"]
        destination = str(intent["destination"])
        if isinstance(source, str):
            source_exists = _directory_exists_at(root_fd, source)
        else:
            source_exists = False
        location = source if source_exists and isinstance(source, str) else destination
        current = self._children(root_fd, location)
        observed = intent["child_observation"]
        if not isinstance(observed, Mapping):
            _fail("archive child observation is invalid")
        current_by_id = {child_id: raw for child_id, _status, raw in current}
        if set(current_by_id) != set(observed):
            _fail("child engine set changed after archive was prepared")
        for child_id, raw in current_by_id.items():
            digest = _digest_bytes(raw)
            target = targets.get(f"research/{child_id}/project.json")
            allowed = {observed[child_id]}
            if target is not None:
                allowed.add(_digest_bytes(target))
            if digest not in allowed:
                _fail("child engine changed after archive was prepared")

    def archive(
        self,
        capabilities: ProjectCapabilities,
        *,
        run_id: str,
        transition_id: str,
        slug: str,
        child_policy: str,
        expected_revision: int,
        expected_snapshot_sha256: str,
    ) -> ProjectTransitionResult:
        checked_slug = _identifier(slug, "project slug", _SLUG)
        checked_transition = _identifier(transition_id, "transition_id")
        if child_policy not in _CHILD_POLICIES:
            _fail("archive child policy is invalid")
        if type(expected_revision) is not int or expected_revision < 1:
            _fail("archive revision is invalid")
        _hash(expected_snapshot_sha256, "expected_snapshot_sha256")
        fields = {
            "child_policy": child_policy,
            "expected_revision": expected_revision,
            "expected_snapshot_sha256": expected_snapshot_sha256,
        }
        request = self._request("archive", checked_slug, checked_transition, fields)

        def build(root_fd: int, now: str) -> dict[str, object]:
            locations = self._find_locations(root_fd, checked_slug)
            if len(locations) != 1:
                _fail("project is missing or collides portably")
            snapshot = self._read_snapshot_at(root_fd, locations[0])
            if snapshot.record.status == "archived":
                _fail("archive is terminal")
            if (
                snapshot.record.revision != expected_revision
                or snapshot.snapshot_sha256 != expected_snapshot_sha256
            ):
                _fail("archive precondition is stale")
            observed_schedules: tuple[ScheduleSnapshot, ...] = ()
            if snapshot.record.schedule_ids:
                if capabilities.schedule is None or self._schedule is None:
                    _fail("authoritative linked schedule state is unavailable")
                try:
                    observed = self._schedule.observe(
                        checked_slug, snapshot.record.schedule_ids
                    )
                except Exception as error:
                    if isinstance(error, (KeyboardInterrupt, SystemExit)):
                        raise
                    _fail("authoritative linked schedule observation failed")
                if not isinstance(observed, tuple):
                    _fail("scheduler observation must be a tuple")
                checked_observed: list[ScheduleSnapshot] = []
                for item in observed:
                    if (
                        not isinstance(item, ScheduleSnapshot)
                        or item.status not in _SCHEDULE_STATUSES
                    ):
                        _fail("scheduler observation is invalid")
                    checked_observed.append(
                        ScheduleSnapshot(
                            _identifier(item.schedule_id, "observed schedule_id"),
                            item.status,
                            _hash(item.sha256, "observed schedule hash"),
                        )
                    )
                if {item.schedule_id for item in checked_observed} != set(
                    snapshot.record.schedule_ids
                ) or len(checked_observed) != len(snapshot.record.schedule_ids):
                    _fail("scheduler observation omits or duplicates linked schedules")
                observed_schedules = tuple(
                    sorted(checked_observed, key=lambda item: item.schedule_id)
                )
            active_schedules = tuple(
                item.schedule_id
                for item in observed_schedules
                if item.status == "active"
            )
            children = self._children(root_fd, snapshot.location)
            active_children = tuple(
                item
                for item in children
                if item[1] not in {"archived", "done", "completed"}
            )
            if child_policy == "refuse" and (active_children or active_schedules):
                _fail("archive refuses active child engines or schedules")
            record = replace(
                snapshot.record,
                status="archived",
                updated_at=now,
                archived_at=now,
                revision=expected_revision + 1,
                last_transition_id=checked_transition,
            )
            state = replace(snapshot.state, revision=record.revision)
            directory_fd = _open_dir_at(root_fd, snapshot.location)
            try:
                old_log = _read_file_at(directory_fd, "log.md", _MAX_LOG)
            finally:
                os.close(directory_fd)
            targets: dict[str, bytes] = {
                "project.json": _canonical(_record_payload(record)),
                "state.json": _canonical(_state_payload(state)),
                "log.md": old_log
                + self._log_entry(
                    now,
                    "archive",
                    f"Archived project with child policy {child_policy}.",
                ),
            }
            before = self._before_hashes(root_fd, snapshot)
            archived_children: list[str] = []
            if child_policy == "cascade":
                for child_id, _status, raw in active_children:
                    payload = _decode_json(raw, "child engine project")
                    payload["status"] = "archived"
                    payload["archived_at"] = now
                    relative = f"research/{child_id}/project.json"
                    before[relative] = _digest_bytes(raw)
                    targets[relative] = _canonical(payload)
                    archived_children.append(child_id)
            schedule_intent = None
            if observed_schedules:
                schedule_intent = ProjectScheduleIntent(
                    PROJECT_SCHEDULE_SCHEMA_VERSION,
                    checked_transition,
                    checked_slug,
                    "pause" if child_policy == "cascade" else "verify",
                    tuple(item.schedule_id for item in observed_schedules),
                    f"project-archive-{child_policy}",
                    observed_schedules,
                )
            destination = self._location("archived", checked_slug, now)
            return self._intent_payload(
                request=request,
                source=snapshot.location,
                destination=destination,
                before=before,
                targets=targets,
                archived_children=archived_children,
                child_policy=child_policy,
                schedule=schedule_intent,
                child_observation={
                    child_id: _digest_bytes(raw) for child_id, _status, raw in children
                },
                schedule_observation=observed_schedules,
            )

        return self._execute(
            capabilities=capabilities, run_id=run_id, request=request, build=build
        )


def plan_legacy_project_migration(
    *,
    project_bytes: bytes,
    state_bytes: bytes,
    log_bytes: bytes,
    transition_id: str = "legacy_migration",
) -> ProjectMigrationPlan:
    """Pure byte-in/plan-out conversion; it never resolves or writes a path."""

    transition = _identifier(transition_id, "migration transition_id")
    project = _decode_json(project_bytes, "legacy project")
    state = _decode_json(state_bytes, "legacy state")
    if not isinstance(log_bytes, bytes) or not log_bytes or len(log_bytes) > _MAX_LOG:
        _fail("legacy log bytes are invalid")
    try:
        log_bytes.decode("utf-8")
    except UnicodeError:
        _fail("legacy log is not UTF-8")
    slug = _identifier(project.get("slug"), "legacy project slug", _SLUG)
    now = project.get("updated_at") or project.get("created_at")
    created = project.get("created_at") or now
    if now is None:
        _fail("legacy project requires a stable timestamp")
    status = str(project.get("status", "active"))
    if status == "on_hold":
        status = "on-hold"
    if status not in _STATUSES:
        _fail("legacy project status is invalid")
    legacy_domains = project.get("domains", ["general"])
    legacy_schedules = project.get("schedule_ids", [])
    if (
        not isinstance(legacy_domains, list)
        or not legacy_domains
        or not all(isinstance(item, str) for item in legacy_domains)
        or not isinstance(legacy_schedules, list)
        or not all(isinstance(item, str) for item in legacy_schedules)
    ):
        _fail("legacy project domains or schedule_ids must be arrays of strings")
    record = ProjectRecord(
        PROJECT_SCHEMA_VERSION,
        slug,
        str(project.get("name", slug)),
        str(project.get("goal", "Migrated project.")),
        tuple(legacy_domains),
        str(project.get("kind", "general")),
        status,
        str(created),
        str(now),
        str(project.get("on_hold_since"))
        if status == "on-hold" and project.get("on_hold_since")
        else (str(now) if status == "on-hold" else None),
        str(project.get("on_hold_reason", "Migrated held project."))
        if status == "on-hold"
        else None,
        str(project.get("archived_at", now)) if status == "archived" else None,
        1,
        transition,
        tuple(legacy_schedules),
    )

    def legacy_items(
        name: str, cls: type[object], defaults: tuple[str, ...]
    ) -> tuple[object, ...]:
        raw = state.get(name, [])
        if not isinstance(raw, list):
            _fail(f"legacy state {name} is invalid")
        values: list[object] = []
        for index, item in enumerate(raw):
            if not isinstance(item, Mapping):
                _fail(f"legacy state {name} item is invalid")
            identifier = str(item.get("id", f"{defaults[0]}_{index + 1}"))
            text = str(item.get("text", item.get("title", "")))
            if cls is ProjectStep:
                values.append(
                    ProjectStep(
                        identifier,
                        text,
                        str(item.get("status", "open")),
                        str(item.get("priority", "medium")),
                    )
                )
            elif cls is ProjectBlocker:
                values.append(
                    ProjectBlocker(identifier, text, str(item.get("status", "open")))
                )
            elif cls is ProjectQuestion:
                values.append(
                    ProjectQuestion(
                        identifier,
                        text,
                        str(item.get("status", "open")),
                        item.get("answer")
                        if isinstance(item.get("answer"), str)
                        else None,
                    )
                )
            else:
                values.append(
                    ProjectMilestone(
                        identifier, text, str(item.get("status", "planned"))
                    )
                )
        return tuple(values)

    last = state.get("last_session")
    if last is None:
        session = None
    elif isinstance(last, str):
        session = ProjectSession(
            _timestamp(last, "legacy last_session"), "Migrated legacy session."
        )
    elif isinstance(last, Mapping):
        session = ProjectSession(str(last.get("at", "")), str(last.get("summary", "")))
    else:
        _fail("legacy last_session is invalid")
    target_state = ProjectState(
        PROJECT_STATE_SCHEMA_VERSION,
        slug,
        1,
        legacy_items("next_steps", ProjectStep, ("step",)),
        legacy_items("blockers", ProjectBlocker, ("blocker",)),
        legacy_items("open_questions", ProjectQuestion, ("question",)),
        legacy_items("milestones", ProjectMilestone, ("milestone",)),
        session,
    )
    out_project = _canonical(_record_payload(record))
    out_state = _canonical(_state_payload(target_state))
    target = ProjectFlow._location(status, slug, record.archived_at)
    plan_payload = {
        "schema_version": PROJECT_MIGRATION_SCHEMA_VERSION,
        "slug": slug,
        "target_relative": target,
        "source_project_sha256": _digest_bytes(project_bytes),
        "source_state_sha256": _digest_bytes(state_bytes),
        "source_log_sha256": _digest_bytes(log_bytes),
        "project_sha256": _digest_bytes(out_project),
        "state_sha256": _digest_bytes(out_state),
        "log_sha256": _digest_bytes(log_bytes),
    }
    return ProjectMigrationPlan(
        PROJECT_MIGRATION_SCHEMA_VERSION,
        slug,
        target,
        _digest_bytes(project_bytes),
        _digest_bytes(state_bytes),
        _digest_bytes(log_bytes),
        out_project,
        out_state,
        log_bytes,
        _digest_payload(plan_payload),
    )
