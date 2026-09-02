"""Deterministic reading lifecycle over external source-manifest references.

The flow owns portable reading state, its retained human log, and review-only
knowledge anchors. It never fetches, copies, or extracts source material.
Every mutation persists exact replay evidence in ``RunStore`` before changing
``agent/reading`` and leaves the producer run running for unified finalization.
"""

from __future__ import annotations

from contextlib import contextmanager
import ctypes
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
from typing import Callable, Iterator, Mapping, Sequence
import unicodedata
import uuid

from tool_life_os_runtime.ext.review.artifact import (
    ARTIFACT_SCHEMA_VERSION,
    PLAN_SCHEMA_VERSION,
    MutationOperation,
    MutationPlan,
    Provenance,
    ReviewArtifact,
    ReviewArtifactError,
    SourceRef,
    parse_mutation_plan,
    parse_review_artifact,
    provenance_sha256,
    render_mutation_plan,
    render_review_artifact,
    review_body_sha256,
    validate_artifact_plan,
)
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


BOOK_SCHEMA_VERSION = 1

_MAX_COMMAND_BYTES = 64 * 1024
_MAX_MANIFEST_BYTES = 64 * 1024
_MAX_STATE_BYTES = 256 * 1024
_MAX_RESULT_BYTES = 1024 * 1024
_MAX_EVIDENCE_BYTES = 768 * 1024
_MAX_LOG_BYTES = 2 * 1024 * 1024
_MAX_ANCHORS = 256
_MAX_PRIOR_CHAIN = 256
_ARCHIVES = frozenset({"_archive", "_trash", "_on_hold"})
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_RUN_ID = re.compile(r"^run_[a-z0-9][a-z0-9_-]{0,62}$")
_REVIEW_ID = re.compile(r"^rev_[a-z0-9][a-z0-9_-]{0,62}$")
_MUTATION_ID = re.compile(r"^mut_[a-z0-9][a-z0-9_-]{0,62}$")
_ANCHOR_ID = re.compile(r"^anchor_[a-z0-9][a-z0-9_-]{0,58}$")
_SLUG = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
_LOGICAL_ID = re.compile(r"^[a-z][a-z0-9_-]{0,127}$")
_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$")
_LOG_EVENT = re.compile(
    rb"<!-- lifeos-book-event:(mut_[a-z0-9][a-z0-9_-]{0,62}):[0-9a-f]{64} -->"
)
_LOG_EVENT_PREFIX = b"<!-- lifeos-book-event:"
_OPERATIONS = frozenset({"active", "discuss", "progress", "anchor", "close"})
_SURFACES = frozenset({"silent", "batched", "gated"})
_DECISIONS = frozenset({"finished", "dropped"})
_PRIVATE_PATH = re.compile(r"(?i)(?:/users/|/home/|[a-z]:\\users\\|[a-z]:\\home\\)")
_FILE_SCHEME = re.compile(r"(?i)(?:^|[^a-z0-9_])file:")

_COMMAND_KEYS = frozenset(
    {
        "schema_version",
        "run_id",
        "mutation_id",
        "operation",
        "slug",
        "occurred_at",
        "chapter",
        "text",
        "decision",
        "reason",
        "anchor_id",
        "review_id",
        "target_path",
        "surface",
    }
)
_MANIFEST_KEYS = frozenset(
    {
        "schema_version",
        "manifest_id",
        "manifest_ref",
        "manifest_sha256",
        "source_sha256",
        "title",
        "chapter_count",
    }
)
_SOURCE_KEYS = frozenset(
    {"manifest_id", "manifest_ref", "manifest_sha256", "source_sha256"}
)
_ANCHOR_KEYS = frozenset(
    {
        "anchor_id",
        "text",
        "chapter",
        "created_at",
        "run_id",
        "review_id",
        "target_path",
        "surface",
        "manifest_ref",
        "manifest_sha256",
    }
)
_STATE_KEYS = frozenset(
    {
        "schema_version",
        "slug",
        "title",
        "status",
        "revision",
        "started_at",
        "current_chapter",
        "chapter_count",
        "anchors",
        "last_session_at",
        "log_ref",
        "source",
        "last_mutation_id",
        "last_mutation_sha256",
    }
)
_RESULT_KEYS = frozenset(
    {
        "schema_version",
        "operation",
        "state",
        "review_artifact",
        "mutation_plan",
        "review_artifact_name",
        "mutation_plan_name",
        "replayed",
    }
)
_STALE_QUERY_KEYS = frozenset({"schema_version", "slug", "as_of", "threshold_days"})
_EVIDENCE_KEYS = frozenset(
    {
        "schema_version",
        "flow",
        "request",
        "request_sha256",
        "run_state_sha256",
        "base_state",
        "base_state_sha256",
        "target_state",
        "log_block",
        "log_block_sha256",
        "review_sha256",
        "plan_sha256",
    }
)

_BOOK_ACTIONS = {
    "read-source-manifest": (
        "runtime",
        "read",
        "tool:source-manifest",
        "read",
        "read-only",
        False,
    ),
    "read-reading-state": (
        "runtime",
        "read",
        "vault:agent/reading",
        "read",
        "read-only",
        False,
    ),
    "read-reading-knowledge": (
        "runtime",
        "read",
        "vault:knowledge",
        "read",
        "read-only",
        False,
    ),
    "commit-reading-state": (
        "runtime",
        "domain-write",
        "vault:agent/reading",
        "write",
        "artifact-commit",
        True,
    ),
    "commit-reading-knowledge-proposal": (
        "runtime",
        "proposal",
        "vault:review",
        "write",
        "proposal-commit",
        True,
    ),
    "record-run-state": (
        "runtime",
        "internal-write",
        "vault:agent/runs",
        "write",
        "run-state-commit",
        True,
    ),
}


class BookFlowError(ValueError):
    """Reading input, state, authority, or recovery evidence is invalid."""


def _fail(message: str) -> None:
    raise BookFlowError(message)


@dataclass(frozen=True)
class BookSourceManifest:
    schema_version: int
    manifest_id: str
    manifest_ref: str
    manifest_sha256: str
    source_sha256: str
    title: str
    chapter_count: int


@dataclass(frozen=True)
class ReadingSourceLink:
    manifest_id: str
    manifest_ref: str
    manifest_sha256: str
    source_sha256: str


@dataclass(frozen=True)
class ReadingAnchor:
    anchor_id: str
    text: str
    chapter: int
    created_at: str
    run_id: str
    review_id: str
    target_path: str
    surface: str
    manifest_ref: str
    manifest_sha256: str


@dataclass(frozen=True)
class ReadingState:
    schema_version: int
    slug: str
    title: str
    status: str
    revision: int
    started_at: str
    current_chapter: int
    chapter_count: int
    anchors: tuple[ReadingAnchor, ...]
    last_session_at: str
    log_ref: str
    source: ReadingSourceLink
    last_mutation_id: str
    last_mutation_sha256: str


@dataclass(frozen=True)
class BookCommand:
    schema_version: int
    run_id: str
    mutation_id: str
    operation: str
    slug: str
    occurred_at: str
    chapter: int | None = None
    text: str | None = None
    decision: str | None = None
    reason: str | None = None
    anchor_id: str | None = None
    review_id: str | None = None
    target_path: str | None = None
    surface: str | None = None


@dataclass(frozen=True)
class BookCapabilities:
    read_source_manifest: ActionCapability | None = None
    read_reading_state: ActionCapability | None = None
    read_reading_knowledge: ActionCapability | None = None
    commit_reading_state: ActionCapability | None = None
    commit_knowledge_proposal: ActionCapability | None = None
    record_run_state: ActionCapability | None = None


@dataclass(frozen=True)
class BookResult:
    schema_version: int
    operation: str
    state: ReadingState
    review_artifact: ReviewArtifact | None
    mutation_plan: MutationPlan | None
    review_artifact_name: str | None
    mutation_plan_name: str | None
    replayed: bool


@dataclass(frozen=True)
class StaleReadingQuery:
    schema_version: int
    slug: str
    as_of: str
    threshold_days: int


@dataclass(frozen=True)
class StaleReading:
    schema_version: int
    slug: str
    as_of: str
    threshold_days: int
    last_session_at: str
    stale_since: str
    stale: bool
    source_moved: bool


@dataclass(frozen=True)
class BookCrashHooks:
    after_evidence: Callable[[], None] | None = None
    after_log: Callable[[], None] | None = None
    after_state: Callable[[], None] | None = None
    after_proposal: Callable[[], None] | None = None
    before_run_commit: Callable[[], None] | None = None


def _validate_crash_hooks(value: object) -> BookCrashHooks:
    if value is None:
        return BookCrashHooks()
    if type(value) is not BookCrashHooks:
        _fail("book crash hooks are invalid")
    hooks = (
        value.after_evidence,
        value.after_log,
        value.after_state,
        value.after_proposal,
        value.before_run_commit,
    )
    if any(item is not None and not callable(item) for item in hooks):
        _fail("book crash hooks must contain callables or null")
    return BookCrashHooks(*hooks)


@dataclass(frozen=True)
class _ReadingZone:
    parent_path: Path
    path: Path
    runs_path: Path
    parent_fd: int
    fd: int
    parent_identity: tuple[int, int]
    identity: tuple[int, int]
    runs_identity: tuple[int, int]


@dataclass(frozen=True)
class _PriorEvidence:
    command: BookCommand
    manifest: BookSourceManifest
    request: Mapping[str, object]
    request_hash: str
    run_hash: str
    base: ReadingState | None
    base_hash: str | None
    target: ReadingState
    block: str
    review_hash: str | None
    plan_hash: str | None


def _has_control(value: str, *, layout: bool = False) -> bool:
    allowed = {"\n", "\r", "\t"} if layout else set()
    return any(
        character not in allowed
        and (
            unicodedata.category(character).startswith("C")
            or unicodedata.category(character) in {"Zl", "Zp"}
        )
        for character in value
    )


def _text(
    value: object,
    label: str,
    *,
    maximum: int,
    allow_empty: bool = False,
    layout: bool = False,
) -> str:
    if not isinstance(value, str):
        _fail(f"{label} must be text")
    try:
        raw = value.encode("utf-8")
    except UnicodeError:
        _fail(f"{label} must be valid UTF-8")
    if (
        (not allow_empty and not value)
        or len(raw) > maximum
        or unicodedata.normalize("NFC", value) != value
        or _has_control(value, layout=layout)
        or _PRIVATE_PATH.search(value)
        or _FILE_SCHEME.search(value)
    ):
        _fail(f"{label} must be bounded portable NFC text")
    if not layout and value.strip() != value:
        _fail(f"{label} must not have surrounding whitespace")
    return value


def _identifier(value: object, label: str, pattern: re.Pattern[str]) -> str:
    text = _text(value, label, maximum=128)
    if pattern.fullmatch(text) is None:
        _fail(f"{label} has invalid syntax")
    return text


def _hash(value: object, label: str) -> str:
    text = _text(value, label, maximum=64)
    if _SHA256.fullmatch(text) is None:
        _fail(f"{label} must be a sha256 digest")
    return text


def _exact_int(value: object, label: str, *, minimum: int, maximum: int) -> int:
    if type(value) is not int or value < minimum or value > maximum:
        _fail(f"{label} is outside its integer bounds")
    return value


def _timestamp(value: object, label: str) -> str:
    text = _text(value, label, maximum=40)
    if _UTC.fullmatch(text) is None:
        _fail(f"{label} must be a UTC timestamp")
    try:
        parsed = datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError:
        _fail(f"{label} must be a valid UTC timestamp")
    if parsed.tzinfo is None:
        _fail(f"{label} must include UTC")
    return text


def _instant(value: str) -> datetime:
    return datetime.fromisoformat(value[:-1] + "+00:00")


def _canonical(value: object) -> bytes:
    try:
        return (
            json.dumps(
                value,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
            + b"\n"
        )
    except (TypeError, ValueError, UnicodeError, RecursionError):
        _fail("book value is not canonical JSON")


def _object_no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            _fail("book JSON contains duplicate fields")
        result[key] = value
    return result


def _decode(raw: str | bytes, label: str, maximum: int) -> tuple[object, bytes]:
    if isinstance(raw, str):
        try:
            data = raw.encode("utf-8")
        except UnicodeError:
            _fail(f"{label} must be UTF-8")
    elif isinstance(raw, bytes):
        data = raw
    else:
        _fail(f"{label} must be text or bytes")
    if not data or len(data) > maximum:
        _fail(f"{label} is not bounded")
    try:
        value = json.loads(
            data.decode("utf-8"), object_pairs_hook=_object_no_duplicates
        )
    except BookFlowError:
        raise
    except (UnicodeError, ValueError, RecursionError):
        _fail(f"{label} is malformed")
    return value, data


def _mapping(value: object, label: str, keys: frozenset[str]) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or set(value) != keys:
        _fail(f"{label} has missing or unknown fields")
    return value


def _safe_ref(value: object, label: str, *, maximum: int = 2048) -> str:
    text = _text(value, label, maximum=maximum)
    if "\\" in text:
        _fail(f"{label} must use portable separators")
    path = PurePosixPath(text)
    if (
        path.is_absolute()
        or path == PurePosixPath(".")
        or path.as_posix() != text
        or ".." in path.parts
        or len(path.parts) > 24
        or any(part.startswith(".") for part in path.parts)
        or any(part.casefold() in _ARCHIVES for part in path.parts)
    ):
        _fail(f"{label} must be an active logical reference")
    for part in path.parts:
        if len(part.encode("utf-8")) > 255 or part.strip() != part:
            _fail(f"{label} has a non-portable component")
    return text


def _knowledge_target(value: object) -> str:
    text = _safe_ref(value, "target_path", maximum=4096)
    path = PurePosixPath(text)
    if len(path.parts) < 2 or path.parts[0] != "knowledge" or path.suffix != ".md":
        _fail("target_path must name active Markdown knowledge")
    return text


def _manifest_payload(value: BookSourceManifest) -> dict[str, object]:
    checked = _validate_manifest(value)
    return {
        "schema_version": checked.schema_version,
        "manifest_id": checked.manifest_id,
        "manifest_ref": checked.manifest_ref,
        "manifest_sha256": checked.manifest_sha256,
        "source_sha256": checked.source_sha256,
        "title": checked.title,
        "chapter_count": checked.chapter_count,
    }


def _validate_manifest(value: object) -> BookSourceManifest:
    if (
        not isinstance(value, BookSourceManifest)
        or type(value.schema_version) is not int
    ):
        _fail("book source manifest is invalid")
    if value.schema_version != BOOK_SCHEMA_VERSION:
        _fail("unsupported book source manifest schema_version")
    return BookSourceManifest(
        BOOK_SCHEMA_VERSION,
        _identifier(value.manifest_id, "manifest_id", _LOGICAL_ID),
        _safe_ref(value.manifest_ref, "manifest_ref"),
        _hash(value.manifest_sha256, "manifest_sha256"),
        _hash(value.source_sha256, "source_sha256"),
        _text(value.title, "title", maximum=512),
        _exact_int(value.chapter_count, "chapter_count", minimum=1, maximum=100_000),
    )


def render_book_source_manifest(value: BookSourceManifest) -> bytes:
    return _canonical(_manifest_payload(value))


def parse_book_source_manifest(raw: str | bytes) -> BookSourceManifest:
    payload, data = _decode(raw, "book source manifest", _MAX_MANIFEST_BYTES)
    item = _mapping(payload, "book source manifest", _MANIFEST_KEYS)
    value = _validate_manifest(
        BookSourceManifest(
            item["schema_version"],
            item["manifest_id"],
            item["manifest_ref"],
            item["manifest_sha256"],
            item["source_sha256"],
            item["title"],
            item["chapter_count"],
        )
    )
    if data != render_book_source_manifest(value):
        _fail("book source manifest must use canonical JSON")
    return value


def _command_payload(value: BookCommand) -> dict[str, object]:
    checked = _validate_command(value)
    return {
        "schema_version": checked.schema_version,
        "run_id": checked.run_id,
        "mutation_id": checked.mutation_id,
        "operation": checked.operation,
        "slug": checked.slug,
        "occurred_at": checked.occurred_at,
        "chapter": checked.chapter,
        "text": checked.text,
        "decision": checked.decision,
        "reason": checked.reason,
        "anchor_id": checked.anchor_id,
        "review_id": checked.review_id,
        "target_path": checked.target_path,
        "surface": checked.surface,
    }


def _validate_command(value: object) -> BookCommand:
    if not isinstance(value, BookCommand) or type(value.schema_version) is not int:
        _fail("book command is invalid")
    if value.schema_version != BOOK_SCHEMA_VERSION:
        _fail("unsupported book command schema_version")
    operation = _text(value.operation, "operation", maximum=16)
    if operation not in _OPERATIONS:
        _fail("book operation is unsupported")
    chapter = (
        None
        if value.chapter is None
        else _exact_int(value.chapter, "chapter", minimum=1, maximum=100_000)
    )
    text = None if value.text is None else _text(value.text, "text", maximum=16 * 1024)
    decision = (
        None
        if value.decision is None
        else _text(value.decision, "decision", maximum=16)
    )
    reason = (
        None if value.reason is None else _text(value.reason, "reason", maximum=4096)
    )
    anchor_id = (
        None
        if value.anchor_id is None
        else _identifier(value.anchor_id, "anchor_id", _ANCHOR_ID)
    )
    review_id = (
        None
        if value.review_id is None
        else _identifier(value.review_id, "review_id", _REVIEW_ID)
    )
    target_path = (
        None if value.target_path is None else _knowledge_target(value.target_path)
    )
    surface = (
        None if value.surface is None else _text(value.surface, "surface", maximum=16)
    )
    if surface is not None and surface not in _SURFACES:
        _fail("book surface is unsupported")
    optional = {
        "chapter": chapter,
        "text": text,
        "decision": decision,
        "reason": reason,
        "anchor_id": anchor_id,
        "review_id": review_id,
        "target_path": target_path,
        "surface": surface,
    }
    if operation == "active" and any(item is not None for item in optional.values()):
        _fail("active command has unrelated fields")
    if operation == "discuss" and (
        text is None
        or any(
            optional[name] is not None
            for name in (
                "chapter",
                "decision",
                "reason",
                "anchor_id",
                "review_id",
                "target_path",
                "surface",
            )
        )
    ):
        _fail("discuss command fields are invalid")
    if operation == "progress" and (
        chapter is None
        or any(
            optional[name] is not None
            for name in (
                "decision",
                "reason",
                "anchor_id",
                "review_id",
                "target_path",
                "surface",
            )
        )
    ):
        _fail("progress command fields are invalid")
    if operation == "anchor" and (
        chapter is None
        or text is None
        or anchor_id is None
        or review_id is None
        or target_path is None
        or surface is None
        or decision is not None
        or reason is not None
    ):
        _fail("anchor command fields are invalid")
    if operation == "close" and (
        decision not in _DECISIONS
        or reason is None
        or any(
            optional[name] is not None
            for name in (
                "chapter",
                "text",
                "anchor_id",
                "review_id",
                "target_path",
                "surface",
            )
        )
    ):
        _fail("close command fields are invalid")
    return BookCommand(
        BOOK_SCHEMA_VERSION,
        _identifier(value.run_id, "run_id", _RUN_ID),
        _identifier(value.mutation_id, "mutation_id", _MUTATION_ID),
        operation,
        _identifier(value.slug, "slug", _SLUG),
        _timestamp(value.occurred_at, "occurred_at"),
        chapter,
        text,
        decision,
        reason,
        anchor_id,
        review_id,
        target_path,
        surface,
    )


def render_book_command(value: BookCommand) -> bytes:
    return _canonical(_command_payload(value))


def parse_book_command(raw: str | bytes) -> BookCommand:
    payload, data = _decode(raw, "book command", _MAX_COMMAND_BYTES)
    item = _mapping(payload, "book command", _COMMAND_KEYS)
    value = _validate_command(
        BookCommand(
            item["schema_version"],
            item["run_id"],
            item["mutation_id"],
            item["operation"],
            item["slug"],
            item["occurred_at"],
            item["chapter"],
            item["text"],
            item["decision"],
            item["reason"],
            item["anchor_id"],
            item["review_id"],
            item["target_path"],
            item["surface"],
        )
    )
    if data != render_book_command(value):
        _fail("book command must use canonical JSON")
    return value


def _source_payload(value: ReadingSourceLink) -> dict[str, str]:
    checked = _validate_source(value)
    return {
        "manifest_id": checked.manifest_id,
        "manifest_ref": checked.manifest_ref,
        "manifest_sha256": checked.manifest_sha256,
        "source_sha256": checked.source_sha256,
    }


def _validate_source(value: object) -> ReadingSourceLink:
    if not isinstance(value, ReadingSourceLink):
        _fail("reading source link is invalid")
    return ReadingSourceLink(
        _identifier(value.manifest_id, "source manifest_id", _LOGICAL_ID),
        _safe_ref(value.manifest_ref, "source manifest_ref"),
        _hash(value.manifest_sha256, "source manifest_sha256"),
        _hash(value.source_sha256, "source source_sha256"),
    )


def _parse_source(value: object) -> ReadingSourceLink:
    item = _mapping(value, "reading source", _SOURCE_KEYS)
    return _validate_source(
        ReadingSourceLink(
            item["manifest_id"],
            item["manifest_ref"],
            item["manifest_sha256"],
            item["source_sha256"],
        )
    )


def _anchor_payload(value: ReadingAnchor) -> dict[str, object]:
    checked = _validate_anchor(value)
    return {
        "anchor_id": checked.anchor_id,
        "text": checked.text,
        "chapter": checked.chapter,
        "created_at": checked.created_at,
        "run_id": checked.run_id,
        "review_id": checked.review_id,
        "target_path": checked.target_path,
        "surface": checked.surface,
        "manifest_ref": checked.manifest_ref,
        "manifest_sha256": checked.manifest_sha256,
    }


def _validate_anchor(value: object) -> ReadingAnchor:
    if not isinstance(value, ReadingAnchor):
        _fail("reading anchor is invalid")
    surface = _text(value.surface, "anchor surface", maximum=16)
    if surface not in _SURFACES:
        _fail("reading anchor surface is invalid")
    return ReadingAnchor(
        _identifier(value.anchor_id, "anchor_id", _ANCHOR_ID),
        _text(value.text, "anchor text", maximum=16 * 1024),
        _exact_int(value.chapter, "anchor chapter", minimum=1, maximum=100_000),
        _timestamp(value.created_at, "anchor created_at"),
        _identifier(value.run_id, "anchor run_id", _RUN_ID),
        _identifier(value.review_id, "anchor review_id", _REVIEW_ID),
        _knowledge_target(value.target_path),
        surface,
        _safe_ref(value.manifest_ref, "anchor manifest_ref"),
        _hash(value.manifest_sha256, "anchor manifest_sha256"),
    )


def _parse_anchor(value: object) -> ReadingAnchor:
    item = _mapping(value, "reading anchor", _ANCHOR_KEYS)
    return _validate_anchor(
        ReadingAnchor(
            item["anchor_id"],
            item["text"],
            item["chapter"],
            item["created_at"],
            item["run_id"],
            item["review_id"],
            item["target_path"],
            item["surface"],
            item["manifest_ref"],
            item["manifest_sha256"],
        )
    )


def _state_payload(value: ReadingState) -> dict[str, object]:
    checked = _validate_state(value)
    return {
        "schema_version": checked.schema_version,
        "slug": checked.slug,
        "title": checked.title,
        "status": checked.status,
        "revision": checked.revision,
        "started_at": checked.started_at,
        "current_chapter": checked.current_chapter,
        "chapter_count": checked.chapter_count,
        "anchors": [_anchor_payload(item) for item in checked.anchors],
        "last_session_at": checked.last_session_at,
        "log_ref": checked.log_ref,
        "source": _source_payload(checked.source),
        "last_mutation_id": checked.last_mutation_id,
        "last_mutation_sha256": checked.last_mutation_sha256,
    }


def _validate_state(value: object) -> ReadingState:
    if not isinstance(value, ReadingState) or type(value.schema_version) is not int:
        _fail("reading state is invalid")
    if value.schema_version != BOOK_SCHEMA_VERSION:
        _fail("unsupported reading state schema_version")
    slug = _identifier(value.slug, "reading slug", _SLUG)
    status = _text(value.status, "reading status", maximum=16)
    if status not in {"active", "closed"}:
        _fail("reading status is invalid")
    revision = _exact_int(
        value.revision, "reading revision", minimum=1, maximum=2**31 - 1
    )
    started_at = _timestamp(value.started_at, "reading started_at")
    current_chapter = _exact_int(
        value.current_chapter, "current_chapter", minimum=1, maximum=100_000
    )
    chapter_count = _exact_int(
        value.chapter_count, "chapter_count", minimum=1, maximum=100_000
    )
    if current_chapter > chapter_count:
        _fail("current_chapter exceeds chapter_count")
    if not isinstance(value.anchors, tuple) or len(value.anchors) > _MAX_ANCHORS:
        _fail("reading anchors must be a bounded tuple")
    anchors = tuple(_validate_anchor(item) for item in value.anchors)
    if len({item.anchor_id for item in anchors}) != len(anchors):
        _fail("reading anchor ids collide")
    if len({item.review_id for item in anchors}) != len(anchors):
        _fail("reading anchor review ids collide")
    if len({item.target_path for item in anchors}) != len(anchors):
        _fail("reading anchor targets collide")
    if any(item.chapter > chapter_count for item in anchors):
        _fail("reading anchor chapter exceeds chapter_count")
    last_session_at = _timestamp(value.last_session_at, "last_session_at")
    if _instant(last_session_at) < _instant(started_at):
        _fail("last_session_at precedes started_at")
    log_ref = _safe_ref(value.log_ref, "reading log_ref")
    if log_ref != f"agent/reading/{slug}-log.md":
        _fail("reading log_ref does not match slug")
    return ReadingState(
        BOOK_SCHEMA_VERSION,
        slug,
        _text(value.title, "reading title", maximum=512),
        status,
        revision,
        started_at,
        current_chapter,
        chapter_count,
        anchors,
        last_session_at,
        log_ref,
        _validate_source(value.source),
        _identifier(value.last_mutation_id, "last_mutation_id", _MUTATION_ID),
        _hash(value.last_mutation_sha256, "last_mutation_sha256"),
    )


def render_reading_state(value: ReadingState) -> bytes:
    data = _canonical(_state_payload(value))
    if len(data) > _MAX_STATE_BYTES:
        _fail("reading state exceeds its byte limit")
    return data


def _state_from_payload(value: object) -> ReadingState:
    item = _mapping(value, "reading state", _STATE_KEYS)
    anchors_raw = item["anchors"]
    if not isinstance(anchors_raw, list):
        _fail("reading anchors must be a list")
    return _validate_state(
        ReadingState(
            item["schema_version"],
            item["slug"],
            item["title"],
            item["status"],
            item["revision"],
            item["started_at"],
            item["current_chapter"],
            item["chapter_count"],
            tuple(_parse_anchor(anchor) for anchor in anchors_raw),
            item["last_session_at"],
            item["log_ref"],
            _parse_source(item["source"]),
            item["last_mutation_id"],
            item["last_mutation_sha256"],
        )
    )


def parse_reading_state(raw: str | bytes) -> ReadingState:
    payload, data = _decode(raw, "reading state", _MAX_STATE_BYTES)
    value = _state_from_payload(payload)
    if data != render_reading_state(value):
        _fail("reading state must use canonical JSON")
    return value


def _knowledge_content(title: str, anchor: ReadingAnchor) -> str:
    date = anchor.created_at[:10]
    return (
        "---\n"
        "tags:\n"
        "  - reading-anchor\n"
        f'date: "{date}"\n'
        "---\n\n"
        f"# {title}: reading anchor\n\n"
        f"{anchor.text}\n\n"
        f"- Chapter: {anchor.chapter}\n"
        f"- Source manifest: {anchor.manifest_ref}\n"
        f"- Source manifest sha256: {anchor.manifest_sha256}\n"
    )


def _proposal_body(title: str, anchor: ReadingAnchor) -> str:
    return (
        "# Reading anchor proposal\n\n"
        f"- Book: {json.dumps(title, ensure_ascii=False)}\n"
        f"- Chapter: {anchor.chapter}\n"
        f"- Source manifest: {anchor.manifest_ref}\n"
        f"- Source manifest sha256: {anchor.manifest_sha256}\n"
        f"- Target: {anchor.target_path}\n"
    )


def _proposal(title: str, anchor: ReadingAnchor) -> tuple[ReviewArtifact, MutationPlan]:
    source = SourceRef("coursedump-manifest", anchor.manifest_ref)
    provenance = Provenance(
        anchor.run_id, ((anchor.manifest_ref, anchor.manifest_sha256),)
    )
    body = _proposal_body(title, anchor)
    content = _knowledge_content(title, anchor)
    artifact = ReviewArtifact(
        ARTIFACT_SCHEMA_VERSION,
        anchor.review_id,
        "proposed",
        "book",
        anchor.created_at,
        anchor.surface,
        (source,),
        provenance,
        f".lifeos/review-plans/{anchor.review_id}.json",
        body,
    )
    plan = MutationPlan(
        PLAN_SCHEMA_VERSION,
        anchor.review_id,
        review_body_sha256(body),
        provenance_sha256(provenance),
        (
            MutationOperation(
                "create",
                anchor.target_path,
                None,
                (anchor.manifest_ref,),
                None,
                hashlib.sha256(content.encode("utf-8")).hexdigest(),
                content,
            ),
        ),
    )
    try:
        checked_artifact = parse_review_artifact(render_review_artifact(artifact))
        checked_plan = parse_mutation_plan(render_mutation_plan(plan))
        validate_artifact_plan(checked_artifact, checked_plan)
    except ReviewArtifactError:
        _fail("reading anchor proposal violates the review contract")
    return checked_artifact, checked_plan


def _artifact_names(mutation_id: str) -> tuple[str, str, str, str]:
    token = hashlib.sha256(mutation_id.encode("ascii")).hexdigest()[:40]
    return (
        f"book-{token}",
        f"book-review-{token}",
        f"book-plan-{token}",
        f"book-{token}",
    )


def _validate_result(value: object) -> BookResult:
    if not isinstance(value, BookResult) or type(value.schema_version) is not int:
        _fail("book result is invalid")
    if value.schema_version != BOOK_SCHEMA_VERSION:
        _fail("unsupported book result schema_version")
    operation = _text(value.operation, "result operation", maximum=16)
    if operation not in _OPERATIONS:
        _fail("book result operation is invalid")
    state = _validate_state(value.state)
    if operation == "close" and state.status != "closed":
        _fail("close result must contain closed state")
    if operation != "close" and state.status != "active":
        _fail("non-close result must contain active state")
    if type(value.replayed) is not bool:
        _fail("book result replayed flag is invalid")
    if operation != "anchor":
        if any(
            item is not None
            for item in (
                value.review_artifact,
                value.mutation_plan,
                value.review_artifact_name,
                value.mutation_plan_name,
            )
        ):
            _fail("non-anchor result cannot contain a knowledge proposal")
        return BookResult(
            BOOK_SCHEMA_VERSION,
            operation,
            state,
            None,
            None,
            None,
            None,
            value.replayed,
        )
    if (
        value.review_artifact is None
        or value.mutation_plan is None
        or value.review_artifact_name is None
        or value.mutation_plan_name is None
        or not state.anchors
    ):
        _fail("anchor result requires exact proposal artifacts")
    review_name = _identifier(
        value.review_artifact_name, "review artifact name", _LOGICAL_ID
    )
    plan_name = _identifier(value.mutation_plan_name, "plan artifact name", _LOGICAL_ID)
    try:
        artifact = parse_review_artifact(render_review_artifact(value.review_artifact))
        plan = parse_mutation_plan(render_mutation_plan(value.mutation_plan))
        validate_artifact_plan(artifact, plan)
    except ReviewArtifactError:
        _fail("anchor result contains an invalid review proposal")
    anchor = state.anchors[-1]
    expected_artifact, expected_plan = _proposal(state.title, anchor)
    if artifact != expected_artifact or plan != expected_plan:
        _fail("anchor result proposal is not bound to reading state")
    return BookResult(
        BOOK_SCHEMA_VERSION,
        operation,
        state,
        artifact,
        plan,
        review_name,
        plan_name,
        value.replayed,
    )


def _result_payload(value: BookResult) -> dict[str, object]:
    checked = _validate_result(value)
    return {
        "schema_version": checked.schema_version,
        "operation": checked.operation,
        "state": _state_payload(checked.state),
        "review_artifact": (
            None
            if checked.review_artifact is None
            else render_review_artifact(checked.review_artifact)
        ),
        "mutation_plan": (
            None
            if checked.mutation_plan is None
            else render_mutation_plan(checked.mutation_plan).decode("utf-8")
        ),
        "review_artifact_name": checked.review_artifact_name,
        "mutation_plan_name": checked.mutation_plan_name,
        "replayed": checked.replayed,
    }


def render_book_result(value: BookResult) -> bytes:
    data = _canonical(_result_payload(value))
    if len(data) > _MAX_RESULT_BYTES:
        _fail("book result exceeds its byte limit")
    return data


def parse_book_result(raw: str | bytes) -> BookResult:
    payload, data = _decode(raw, "book result", _MAX_RESULT_BYTES)
    item = _mapping(payload, "book result", _RESULT_KEYS)
    try:
        artifact = (
            None
            if item["review_artifact"] is None
            else parse_review_artifact(item["review_artifact"])
        )
        plan = (
            None
            if item["mutation_plan"] is None
            else parse_mutation_plan(item["mutation_plan"])
        )
    except ReviewArtifactError:
        _fail("book result contains malformed proposal artifacts")
    value = _validate_result(
        BookResult(
            item["schema_version"],
            item["operation"],
            _state_from_payload(item["state"]),
            artifact,
            plan,
            item["review_artifact_name"],
            item["mutation_plan_name"],
            item["replayed"],
        )
    )
    if data != render_book_result(value):
        _fail("book result must use canonical JSON")
    return value


def _safe_name(value: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value in {".", ".."}
        or "/" in value
        or "\\" in value
        or _has_control(value)
        or len(value.encode("utf-8")) > 255
    ):
        _fail("filesystem leaf is invalid")
    return value


def _directory_identity(fd: int) -> tuple[int, int]:
    item = os.fstat(fd)
    if not stat.S_ISDIR(item.st_mode):
        _fail("opened reading path is not a directory")
    return item.st_dev, item.st_ino


def _read_file_at(
    directory_fd: int, name: str, maximum: int
) -> tuple[bytes, tuple[int, int]]:
    checked = _safe_name(name)
    try:
        fd = os.open(
            checked, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=directory_fd
        )
    except FileNotFoundError:
        raise
    except OSError:
        _fail("reading file cannot be opened safely")
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
            _fail("reading file is not a bounded regular file")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(fd, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) > maximum:
            _fail("reading file exceeds its byte limit")
        after = os.fstat(fd)
        try:
            named = os.stat(checked, dir_fd=directory_fd, follow_symlinks=False)
        except OSError:
            _fail("reading file changed during read")
        identity = (before.st_dev, before.st_ino)
        if (
            identity != (after.st_dev, after.st_ino)
            or identity != (named.st_dev, named.st_ino)
            or not stat.S_ISREG(named.st_mode)
        ):
            _fail("reading file changed during read")
        return data, identity
    finally:
        os.close(fd)


def _file_identity(directory_fd: int, name: str) -> tuple[int, int] | None:
    try:
        item = os.stat(_safe_name(name), dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    except OSError:
        _fail("reading file identity cannot be inspected")
    if not stat.S_ISREG(item.st_mode):
        _fail("reading file must be regular")
    return item.st_dev, item.st_ino


def _rename_with_flags_at(
    directory_fd: int, source: str, target: str, *, exchange: bool
) -> None:
    source_name = os.fsencode(_safe_name(source))
    target_name = os.fsencode(_safe_name(target))
    libc = ctypes.CDLL(None, use_errno=True)
    if hasattr(libc, "renameatx_np"):
        function = libc.renameatx_np
        flag = 0x00000002 if exchange else 0x00000004
    elif hasattr(libc, "renameat2"):
        function = libc.renameat2
        flag = 0x00000002 if exchange else 0x00000001
    else:
        _fail("identity-bound rename capability is unavailable")
    function.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    function.restype = ctypes.c_int
    if function(directory_fd, source_name, directory_fd, target_name, flag) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def _rename_exchange_at(directory_fd: int, source: str, target: str) -> None:
    _rename_with_flags_at(directory_fd, source, target, exchange=True)


def _rename_noreplace_at(directory_fd: int, source: str, target: str) -> None:
    _rename_with_flags_at(directory_fd, source, target, exchange=False)


def _restore_exchange_at(
    directory_fd: int,
    quarantine: str,
    target: str,
    quarantined_identity: tuple[int, int],
    staged_identity: tuple[int, int],
) -> bool:
    if _file_identity(directory_fd, quarantine) != quarantined_identity:
        return False
    try:
        _rename_exchange_at(directory_fd, quarantine, target)
        os.fsync(directory_fd)
    except OSError:
        return False
    restored = _file_identity(directory_fd, target) == quarantined_identity
    if _file_identity(directory_fd, quarantine) == staged_identity:
        try:
            os.unlink(quarantine, dir_fd=directory_fd)
            os.fsync(directory_fd)
        except OSError:
            return False
    return restored


def _atomic_replace_at(
    directory_fd: int,
    name: str,
    data: bytes,
    *,
    expected_identity: tuple[int, int] | None,
    maximum: int,
) -> None:
    checked = _safe_name(name)
    if not isinstance(data, bytes) or not data or len(data) > maximum:
        _fail("reading replacement bytes are invalid")
    temporary = f".{checked}.{os.getpid()}.{uuid.uuid4().hex}.tmp"
    fd: int | None = None
    staged_identity: tuple[int, int] | None = None
    published = False
    try:
        fd = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=directory_fd,
        )
        offset = 0
        while offset < len(data):
            written = os.write(fd, data[offset:])
            if written <= 0:
                _fail("reading replacement write did not progress")
            offset += written
        os.fsync(fd)
        staged = os.fstat(fd)
        if not stat.S_ISREG(staged.st_mode):
            _fail("reading temporary is not regular")
        os.close(fd)
        fd = None
        named = os.stat(temporary, dir_fd=directory_fd, follow_symlinks=False)
        staged_identity = (staged.st_dev, staged.st_ino)
        if staged_identity != (named.st_dev, named.st_ino):
            _fail("reading temporary changed before publish")
        if expected_identity is None:
            try:
                _rename_noreplace_at(directory_fd, temporary, checked)
            except OSError:
                _fail("reading file changed before publish")
            published = True
        else:
            try:
                _rename_exchange_at(directory_fd, temporary, checked)
            except OSError:
                _fail("reading file changed before publish")
            quarantined_identity = _file_identity(directory_fd, temporary)
            if quarantined_identity != expected_identity:
                if quarantined_identity is not None:
                    _restore_exchange_at(
                        directory_fd,
                        temporary,
                        checked,
                        quarantined_identity,
                        staged_identity,
                    )
                _fail("reading file changed before publish")
        os.fsync(directory_fd)
        try:
            current, identity = _read_file_at(directory_fd, checked, maximum)
        except BookFlowError:
            if expected_identity is not None:
                _restore_exchange_at(
                    directory_fd,
                    temporary,
                    checked,
                    expected_identity,
                    staged_identity,
                )
            raise
        if identity != staged_identity or current != data:
            if expected_identity is not None:
                _restore_exchange_at(
                    directory_fd,
                    temporary,
                    checked,
                    expected_identity,
                    staged_identity,
                )
            _fail("reading replacement verification failed")
        if expected_identity is not None:
            try:
                os.unlink(temporary, dir_fd=directory_fd)
                os.fsync(directory_fd)
            except OSError:
                _fail("reading replaced state could not be retired safely")
        published = True
    except BookFlowError:
        raise
    except OSError:
        _fail("reading replacement failed")
    finally:
        if fd is not None:
            os.close(fd)
        if not published and staged_identity is not None:
            try:
                if _file_identity(directory_fd, temporary) == staged_identity:
                    os.unlink(temporary, dir_fd=directory_fd)
            except (BookFlowError, OSError):
                pass


def _close_residue_names(name: str) -> tuple[str, str]:
    checked = _safe_name(name)
    return f".{checked}.close-quarantine", f".{checked}.close-retire"


def _close_quarantine_at(
    directory_fd: int, name: str, expected_data: bytes
) -> tuple[bytes, tuple[int, int]] | None:
    quarantine, _retire = _close_residue_names(name)
    try:
        raw, identity = _read_file_at(directory_fd, quarantine, _MAX_STATE_BYTES)
    except FileNotFoundError:
        return None
    if raw != expected_data:
        _fail("close quarantine conflicts with durable reading preimage")
    return raw, identity


def _remove_identity_bound_at(
    directory_fd: int,
    name: str,
    expected_identity: tuple[int, int] | None,
    expected_data: bytes,
) -> None:
    checked = _safe_name(name)
    if not isinstance(expected_data, bytes) or not expected_data:
        _fail("close preimage bytes are invalid")
    quarantine, retire = _close_residue_names(checked)
    retained = _close_quarantine_at(directory_fd, checked, expected_data)
    if retained is None:
        if expected_identity is None:
            _fail("close recovery lost its active reading precondition")
        try:
            _rename_noreplace_at(directory_fd, checked, quarantine)
        except OSError:
            _fail("active reading state could not be quarantined safely")
        moved, quarantine_identity = _read_file_at(
            directory_fd, quarantine, _MAX_STATE_BYTES
        )
        if moved != expected_data or quarantine_identity != expected_identity:
            try:
                _rename_noreplace_at(directory_fd, quarantine, checked)
                os.fsync(directory_fd)
            except OSError:
                pass
            _fail("active reading state changed before close")
    else:
        _retained_raw, quarantine_identity = retained

    try:
        retired = _read_file_at(directory_fd, retire, _MAX_STATE_BYTES)
    except FileNotFoundError:
        retired = None
    if retired is not None:
        retired_raw, retired_identity = retired
        if (
            retired_raw != expected_data
            or retired_identity != quarantine_identity
            or _file_identity(directory_fd, checked) is not None
        ):
            _fail("close retirement residue conflicts with named reading state")
        try:
            os.unlink(retire, dir_fd=directory_fd)
            os.fsync(directory_fd)
        except OSError:
            _fail("close retirement residue cannot be reconciled")

    named_identity = _file_identity(directory_fd, checked)
    if named_identity is None:
        try:
            os.link(
                quarantine,
                checked,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
                follow_symlinks=False,
            )
            os.fsync(directory_fd)
        except OSError:
            _fail("active reading state changed before close retirement")
    elif named_identity != quarantine_identity:
        _fail("active reading state was substituted before close retirement")

    try:
        _rename_noreplace_at(directory_fd, checked, retire)
        os.fsync(directory_fd)
    except OSError:
        _fail("active reading state could not enter close retirement")
    retired_raw, retired_identity = _read_file_at(
        directory_fd, retire, _MAX_STATE_BYTES
    )
    if retired_raw != expected_data or retired_identity != quarantine_identity:
        try:
            _rename_noreplace_at(directory_fd, retire, checked)
            os.fsync(directory_fd)
        except OSError:
            pass
        _fail("active reading state was substituted during close retirement")
    if (
        _file_identity(directory_fd, quarantine) != quarantine_identity
        or _file_identity(directory_fd, checked) is not None
    ):
        _fail("close retirement did not commit named-leaf absence")
    try:
        os.unlink(retire, dir_fd=directory_fd)
        os.unlink(quarantine, dir_fd=directory_fd)
        os.fsync(directory_fd)
    except OSError:
        _fail("active reading state could not be retired safely")


class BookFlow:
    """Versioned, restart-safe reading lifecycle without extraction ownership."""

    def __init__(
        self,
        resolver: VaultPathResolver,
        run_store: RunStore,
        policy: AuthorityPolicy,
    ) -> None:
        if (
            not isinstance(resolver, VaultPathResolver)
            or not isinstance(run_store, RunStore)
            or not isinstance(policy, AuthorityPolicy)
            or getattr(run_store, "_resolver", None) is not resolver
        ):
            _fail("book flow requires one resolver, RunStore, and AuthorityPolicy")
        self._resolver = resolver
        self._runs = run_store
        self._policy = policy

    def _require(
        self, capability: ActionCapability | None, action_id: str
    ) -> ActionCapability:
        if capability is None:
            _fail(f"book action {action_id} requires a capability")
        try:
            grant = self._policy.require(capability)
        except AuthorityError as error:
            raise BookFlowError(str(error)) from None
        actor, authority, target, access, effect_kind, artifact_commit = _BOOK_ACTIONS[
            action_id
        ]
        if (
            grant.flow_id != "book"
            or grant.action_id != action_id
            or grant.actor != actor
            or grant.authority != authority
            or grant.target != target
            or grant.access != access
            or grant.effect_kind != effect_kind
            or grant.artifact_commit is not artifact_commit
        ):
            _fail(f"capability does not authorize exact book action {action_id}")
        return grant

    def _preflight(
        self, command: BookCommand, capabilities: BookCapabilities
    ) -> tuple[ActionCapability, ...]:
        if not isinstance(capabilities, BookCapabilities):
            _fail("book operation requires BookCapabilities")
        grants = [
            self._require(capabilities.read_source_manifest, "read-source-manifest"),
            self._require(capabilities.read_reading_state, "read-reading-state"),
        ]
        if command.operation == "anchor":
            grants.append(
                self._require(
                    capabilities.read_reading_knowledge, "read-reading-knowledge"
                )
            )
        grants.append(
            self._require(capabilities.commit_reading_state, "commit-reading-state")
        )
        if command.operation == "anchor":
            grants.append(
                self._require(
                    capabilities.commit_knowledge_proposal,
                    "commit-reading-knowledge-proposal",
                )
            )
        grants.append(self._require(capabilities.record_run_state, "record-run-state"))
        return tuple(grants)

    def _run_snapshot(self, run_id: str):
        try:
            snapshot = self._runs.snapshot(run_id)
        except RunError as error:
            raise BookFlowError(str(error)) from None
        if (
            snapshot.state.get("flow") != "book"
            or snapshot.state.get("status") != "running"
            or snapshot.state.get("authority") != "domain-write"
        ):
            _fail("book mutation requires a running domain-write book run")
        return snapshot

    def _open_reading_zone(self, *, for_write: bool) -> _ReadingZone | None:
        try:
            runs_path = self._resolver.resolve(
                "agent/runs", for_write=for_write, must_exist=True
            )
            reading_path = self._resolver.resolve(
                "agent/reading", for_write=for_write, must_exist=False
            )
        except VaultSchemaError:
            _fail("reading vault zone is unsafe")
        parent_path = runs_path.parent
        if reading_path.parent != parent_path or reading_path.name != "reading":
            _fail("reading zone is not bound to the runtime agent parent")
        flags = (
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            parent_fd = os.open(parent_path, flags)
        except OSError:
            _fail("reading authority parent cannot be opened safely")
        zone_fd: int | None = None
        try:
            parent_identity = _directory_identity(parent_fd)
            runs_named = os.stat("runs", dir_fd=parent_fd, follow_symlinks=False)
            runs_actual = os.stat(runs_path, follow_symlinks=False)
            runs_identity = (runs_named.st_dev, runs_named.st_ino)
            if not stat.S_ISDIR(runs_named.st_mode) or runs_identity != (
                runs_actual.st_dev,
                runs_actual.st_ino,
            ):
                _fail("reading authority parent is not bound to runs")
            try:
                reading_named = os.stat(
                    "reading", dir_fd=parent_fd, follow_symlinks=False
                )
            except FileNotFoundError:
                if not for_write:
                    os.close(parent_fd)
                    return None
                try:
                    os.mkdir("reading", mode=0o700, dir_fd=parent_fd)
                    os.fsync(parent_fd)
                    reading_named = os.stat(
                        "reading", dir_fd=parent_fd, follow_symlinks=False
                    )
                except OSError:
                    _fail("reading zone cannot be created safely")
            if not stat.S_ISDIR(reading_named.st_mode):
                _fail("reading zone must be a real directory")
            try:
                zone_fd = os.open("reading", flags, dir_fd=parent_fd)
            except OSError:
                _fail("reading zone cannot be opened safely")
            identity = _directory_identity(zone_fd)
            if identity != (reading_named.st_dev, reading_named.st_ino):
                _fail("reading zone changed while opening")
            zone = _ReadingZone(
                parent_path,
                reading_path,
                runs_path,
                parent_fd,
                zone_fd,
                parent_identity,
                identity,
                runs_identity,
            )
            self._revalidate_zone(zone, for_write=for_write)
            return zone
        except BaseException:
            if zone_fd is not None:
                os.close(zone_fd)
            os.close(parent_fd)
            raise

    def _revalidate_zone(self, zone: _ReadingZone, *, for_write: bool) -> None:
        try:
            actual_runs = self._resolver.revalidate(
                zone.runs_path,
                "agent/runs",
                for_write=for_write,
                must_exist=True,
            )
            actual_reading = self._resolver.revalidate(
                zone.path,
                "agent/reading",
                for_write=for_write,
                must_exist=True,
            )
            parent_named = os.stat(zone.parent_path, follow_symlinks=False)
            runs_named = os.stat("runs", dir_fd=zone.parent_fd, follow_symlinks=False)
            runs_actual = os.stat(actual_runs, follow_symlinks=False)
            reading_named = os.stat(
                "reading", dir_fd=zone.parent_fd, follow_symlinks=False
            )
            reading_actual = os.stat(actual_reading, follow_symlinks=False)
        except (OSError, VaultSchemaError):
            _fail("reading zone changed during operation")
        if (
            _directory_identity(zone.parent_fd) != zone.parent_identity
            or _directory_identity(zone.fd) != zone.identity
            or (parent_named.st_dev, parent_named.st_ino) != zone.parent_identity
            or (runs_named.st_dev, runs_named.st_ino) != zone.runs_identity
            or (runs_actual.st_dev, runs_actual.st_ino) != zone.runs_identity
            or (reading_named.st_dev, reading_named.st_ino) != zone.identity
            or (reading_actual.st_dev, reading_actual.st_ino) != zone.identity
        ):
            _fail("reading zone identity changed during operation")

    @staticmethod
    def _close_zone(zone: _ReadingZone | None) -> None:
        if zone is not None:
            os.close(zone.fd)
            os.close(zone.parent_fd)

    @contextmanager
    def _locked_reading_zone(self) -> Iterator[_ReadingZone]:
        zone = self._open_reading_zone(for_write=True)
        assert zone is not None
        lock_fd: int | None = None
        try:
            try:
                lock_fd = os.open(
                    ".book-flow.lock",
                    os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
                    0o600,
                    dir_fd=zone.fd,
                )
                if not stat.S_ISREG(os.fstat(lock_fd).st_mode):
                    _fail("book flow lock is invalid")
                fcntl.flock(lock_fd, fcntl.LOCK_EX)
            except OSError:
                _fail("book flow lock cannot be acquired")
            self._revalidate_zone(zone, for_write=True)
            yield zone
            self._revalidate_zone(zone, for_write=True)
        finally:
            if lock_fd is not None:
                try:
                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
                finally:
                    os.close(lock_fd)
            self._close_zone(zone)

    @staticmethod
    def _state_name(slug: str) -> str:
        return f"{slug}.json"

    @staticmethod
    def _log_name(slug: str) -> str:
        return f"{slug}-log.md"

    def _load_state_at(
        self, zone: _ReadingZone, slug: str
    ) -> tuple[ReadingState | None, bytes | None, tuple[int, int] | None]:
        try:
            raw, identity = _read_file_at(
                zone.fd, self._state_name(slug), _MAX_STATE_BYTES
            )
        except FileNotFoundError:
            return None, None, None
        state = parse_reading_state(raw)
        if state.slug != slug or state.status != "active":
            _fail("active reading state does not match its filename")
        return state, raw, identity

    def _load_log_at(
        self, zone: _ReadingZone, slug: str
    ) -> tuple[bytes, tuple[int, int] | None]:
        try:
            raw, identity = _read_file_at(zone.fd, self._log_name(slug), _MAX_LOG_BYTES)
        except FileNotFoundError:
            return b"", None
        try:
            text = raw.decode("utf-8")
        except UnicodeError:
            _fail("reading log is not valid UTF-8")
        if "\x00" in text or _has_control(text, layout=True):
            _fail("reading log contains invalid controls")
        return raw, identity

    def _validate_committed_history(
        self,
        zone: _ReadingZone,
        slug: str,
        current: ReadingState | None,
        committed_names: frozenset[str],
    ) -> None:
        raw, _identity = self._load_log_at(zone, slug)
        if not raw and current is None:
            return
        markers = tuple(_LOG_EVENT.finditer(raw))
        if (
            not markers
            or len(markers) != raw.count(_LOG_EVENT_PREFIX)
            or (
                current is not None
                and markers[-1].group(1).decode("ascii") != current.last_mutation_id
            )
        ):
            _fail("reading log does not match the active reading state")
        mutation_id = markers[-1].group(1).decode("ascii")
        evidence_name, _review_name, _plan_name, _step = _artifact_names(mutation_id)
        if evidence_name not in committed_names:
            _fail("reading history has an uncommitted lifecycle event")

    def _load_evidence(
        self, run_id: str, mutation_id: str
    ) -> Mapping[str, object] | None:
        evidence_name, _review_name, _plan_name, _step = _artifact_names(mutation_id)
        filename = f"{evidence_name}.json"
        try:
            run_path = self._resolver.resolve(
                "agent/runs", run_id, for_write=False, must_exist=True
            )
        except VaultSchemaError:
            _fail("book run evidence path is unsafe")
        flags = (
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            fd = os.open(run_path, flags)
        except OSError:
            _fail("book run evidence directory cannot be opened safely")
        try:
            identity = _directory_identity(fd)
            try:
                raw, _ = _read_file_at(fd, filename, _MAX_EVIDENCE_BYTES)
            except FileNotFoundError:
                return None
            try:
                actual = self._resolver.revalidate(
                    run_path,
                    "agent/runs",
                    run_id,
                    for_write=False,
                    must_exist=True,
                )
                named = os.stat(actual, follow_symlinks=False)
            except (OSError, VaultSchemaError):
                _fail("book run evidence directory changed")
            if identity != (named.st_dev, named.st_ino):
                _fail("book run evidence directory changed")
            payload, data = _decode(raw, "book replay evidence", _MAX_EVIDENCE_BYTES)
            item = _mapping(payload, "book replay evidence", _EVIDENCE_KEYS)
            if data != _canonical(dict(item)):
                _fail("book replay evidence is not canonical")
            return item
        finally:
            os.close(fd)

    @staticmethod
    def _request_payload(
        command: BookCommand, manifest: BookSourceManifest
    ) -> dict[str, object]:
        return {
            "command": _command_payload(command),
            "source_manifest": _manifest_payload(manifest),
        }

    @staticmethod
    def _request_hash(payload: Mapping[str, object]) -> str:
        return hashlib.sha256(_canonical(dict(payload))).hexdigest()

    @staticmethod
    def _source_link(manifest: BookSourceManifest) -> ReadingSourceLink:
        return ReadingSourceLink(
            manifest.manifest_id,
            manifest.manifest_ref,
            manifest.manifest_sha256,
            manifest.source_sha256,
        )

    @staticmethod
    def _compatible_source(
        state: ReadingState, manifest: BookSourceManifest
    ) -> ReadingSourceLink:
        source = state.source
        if (
            source.manifest_id != manifest.manifest_id
            or source.manifest_sha256 != manifest.manifest_sha256
            or source.source_sha256 != manifest.source_sha256
            or state.title != manifest.title
            or state.chapter_count != manifest.chapter_count
        ):
            _fail("reading source manifest is stale or belongs to another source")
        return BookFlow._source_link(manifest)

    @staticmethod
    def _derive_target(
        command: BookCommand,
        manifest: BookSourceManifest,
        current: ReadingState | None,
        request_hash: str,
    ) -> ReadingState:
        if command.operation == "active" and current is None:
            return _validate_state(
                ReadingState(
                    BOOK_SCHEMA_VERSION,
                    command.slug,
                    manifest.title,
                    "active",
                    1,
                    command.occurred_at,
                    1,
                    manifest.chapter_count,
                    (),
                    command.occurred_at,
                    f"agent/reading/{command.slug}-log.md",
                    BookFlow._source_link(manifest),
                    command.mutation_id,
                    request_hash,
                )
            )
        if current is None:
            _fail("book is not currently being read")
        source = BookFlow._compatible_source(current, manifest)
        if _instant(command.occurred_at) < _instant(current.last_session_at):
            _fail("book command timestamp is stale")
        chapter = current.current_chapter
        anchors = current.anchors
        status = "active"
        if command.operation == "progress":
            assert command.chapter is not None
            if command.chapter < current.current_chapter:
                _fail("reading progress cannot move backwards")
            if command.chapter > manifest.chapter_count:
                _fail("reading progress exceeds source chapter_count")
            chapter = command.chapter
        elif command.operation == "anchor":
            assert command.chapter is not None
            assert command.text is not None
            assert command.anchor_id is not None
            assert command.review_id is not None
            assert command.target_path is not None
            assert command.surface is not None
            if command.chapter > manifest.chapter_count:
                _fail("reading anchor exceeds source chapter_count")
            if any(
                command.anchor_id == item.anchor_id
                or command.review_id == item.review_id
                or command.target_path == item.target_path
                for item in current.anchors
            ):
                _fail("reading anchor identity already exists")
            chapter = max(chapter, command.chapter)
            anchors = (
                *anchors,
                ReadingAnchor(
                    command.anchor_id,
                    command.text,
                    command.chapter,
                    command.occurred_at,
                    command.run_id,
                    command.review_id,
                    command.target_path,
                    command.surface,
                    manifest.manifest_ref,
                    manifest.manifest_sha256,
                ),
            )
        elif command.operation == "close":
            status = "closed"
        return _validate_state(
            ReadingState(
                BOOK_SCHEMA_VERSION,
                current.slug,
                current.title,
                status,
                current.revision + 1,
                current.started_at,
                chapter,
                current.chapter_count,
                anchors,
                command.occurred_at,
                current.log_ref,
                source,
                command.mutation_id,
                request_hash,
            )
        )

    @staticmethod
    def _event_block(
        command: BookCommand,
        manifest: BookSourceManifest,
        target: ReadingState,
        request_hash: str,
    ) -> str:
        event = {
            "schema_version": BOOK_SCHEMA_VERSION,
            "mutation_id": command.mutation_id,
            "operation": command.operation,
            "slug": command.slug,
            "occurred_at": command.occurred_at,
            "chapter": target.current_chapter,
            "text": command.text,
            "decision": command.decision,
            "reason": command.reason,
            "manifest_ref": manifest.manifest_ref,
            "request_sha256": request_hash,
        }
        digest = hashlib.sha256(_canonical(event)).hexdigest()
        lines = [
            f"<!-- lifeos-book-event:{command.mutation_id}:{digest} -->",
            f"## {command.occurred_at} - {command.operation}",
            f"- Title: {json.dumps(target.title, ensure_ascii=False)}",
            f"- Chapter: {target.current_chapter}",
            f"- Source manifest: {manifest.manifest_ref}",
        ]
        if command.text is not None:
            lines.append(f"- Detail: {json.dumps(command.text, ensure_ascii=False)}")
        if command.operation == "close":
            lines.append(f"- closed: {command.decision}")
            lines.append(f"- Reason: {json.dumps(command.reason, ensure_ascii=False)}")
        return "\n".join(lines) + "\n\n"

    @staticmethod
    def _log_marker_prefix(mutation_id: str) -> bytes:
        return f"<!-- lifeos-book-event:{mutation_id}:".encode("ascii")

    @staticmethod
    def _log_header(slug: str) -> bytes:
        return (f"---\ntags:\n  - system\n---\n\n# Reading log: {slug}\n\n").encode(
            "utf-8"
        )

    def _ensure_log_block(
        self,
        zone: _ReadingZone,
        slug: str,
        mutation_id: str,
        block: bytes,
    ) -> None:
        current, identity = self._load_log_at(zone, slug)
        prefix = self._log_marker_prefix(mutation_id)
        if prefix in current:
            if not current.endswith(block) or current.count(prefix) != 1:
                _fail("reading log replay conflicts with retained history")
            return
        if current:
            separator = b"" if current.endswith(b"\n") else b"\n"
            target = current + separator + block
        else:
            target = self._log_header(slug) + block
        if len(target) > _MAX_LOG_BYTES:
            _fail("reading log exceeds its retention bound")
        _atomic_replace_at(
            zone.fd,
            self._log_name(slug),
            target,
            expected_identity=identity,
            maximum=_MAX_LOG_BYTES,
        )

    def _knowledge_target_absent(self, target_path: str) -> None:
        relative = PurePosixPath(target_path)
        try:
            root = self._resolver.resolve("knowledge", for_write=False, must_exist=True)
        except VaultSchemaError:
            _fail("reading knowledge zone is unsafe")
        flags = (
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            root_fd = os.open(root, flags)
        except OSError:
            _fail("reading knowledge zone cannot be opened safely")
        current_fd = root_fd
        owned: list[int] = []
        try:
            root_identity = _directory_identity(root_fd)
            missing_parent = False
            for part in relative.parts[1:-1]:
                try:
                    child_fd = os.open(part, flags, dir_fd=current_fd)
                except FileNotFoundError:
                    missing_parent = True
                    break
                except OSError:
                    _fail("reading knowledge parent cannot be opened safely")
                owned.append(child_fd)
                current_fd = child_fd
            if not missing_parent:
                try:
                    os.stat(relative.name, dir_fd=current_fd, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                except OSError:
                    _fail("reading knowledge target cannot be inspected safely")
                else:
                    _fail("reading anchor target already exists")
            try:
                actual = self._resolver.revalidate(
                    root, "knowledge", for_write=False, must_exist=True
                )
                named = os.stat(actual, follow_symlinks=False)
            except (OSError, VaultSchemaError):
                _fail("reading knowledge zone changed during read")
            if root_identity != (named.st_dev, named.st_ino):
                _fail("reading knowledge zone changed during read")
        finally:
            for fd in reversed(owned):
                os.close(fd)
            os.close(root_fd)

    @contextmanager
    def _managed_zone(
        self, symbolic: str, *, for_write: bool
    ) -> Iterator[tuple[int, tuple[int, int]]]:
        try:
            path = self._resolver.resolve(
                symbolic, for_write=for_write, must_exist=True
            )
        except VaultSchemaError:
            _fail("book proposal zone is unsafe")
        flags = (
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            directory_fd = os.open(path, flags)
        except OSError:
            _fail("book proposal zone cannot be opened safely")
        try:
            identity = _directory_identity(directory_fd)
            try:
                actual = self._resolver.revalidate(
                    path,
                    symbolic,
                    for_write=for_write,
                    must_exist=True,
                )
                named = os.stat(actual, follow_symlinks=False)
            except (OSError, VaultSchemaError):
                _fail("book proposal zone changed during operation")
            if identity != (named.st_dev, named.st_ino):
                _fail("book proposal zone changed during operation")
            yield directory_fd, identity
            try:
                actual = self._resolver.revalidate(
                    path,
                    symbolic,
                    for_write=for_write,
                    must_exist=True,
                )
                named = os.stat(actual, follow_symlinks=False)
            except (OSError, VaultSchemaError):
                _fail("book proposal zone changed during operation")
            if _directory_identity(directory_fd) != identity or identity != (
                named.st_dev,
                named.st_ino,
            ):
                _fail("book proposal zone changed during operation")
        finally:
            os.close(directory_fd)

    @staticmethod
    def _check_exact_or_missing(
        directory_fd: int, name: str, data: bytes, maximum: int
    ) -> None:
        try:
            existing, _identity = _read_file_at(directory_fd, name, maximum)
        except FileNotFoundError:
            return
        if existing != data:
            _fail("book proposal identity already contains different bytes")

    @staticmethod
    def _publish_create_once(
        directory_fd: int, name: str, data: bytes, maximum: int
    ) -> tuple[int, int]:
        checked = _safe_name(name)
        if not isinstance(data, bytes) or not data or len(data) > maximum:
            _fail("book proposal bytes are invalid")
        try:
            existing, identity = _read_file_at(directory_fd, checked, maximum)
        except FileNotFoundError:
            existing = None
            identity = None
        if existing is not None:
            if existing != data:
                _fail("book proposal identity already contains different bytes")
            assert identity is not None
            return identity
        temporary = f".{checked}.{os.getpid()}.{uuid.uuid4().hex}.tmp"
        fd: int | None = None
        try:
            fd = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=directory_fd,
            )
            offset = 0
            while offset < len(data):
                written = os.write(fd, data[offset:])
                if written <= 0:
                    _fail("book proposal write did not progress")
                offset += written
            os.fsync(fd)
            staged = os.fstat(fd)
            if not stat.S_ISREG(staged.st_mode):
                _fail("book proposal temporary is not regular")
            staged_identity = (staged.st_dev, staged.st_ino)
            os.close(fd)
            fd = None
            named_temp = os.stat(temporary, dir_fd=directory_fd, follow_symlinks=False)
            if staged_identity != (named_temp.st_dev, named_temp.st_ino):
                _fail("book proposal temporary changed before publish")
            try:
                os.link(
                    temporary,
                    checked,
                    src_dir_fd=directory_fd,
                    dst_dir_fd=directory_fd,
                    follow_symlinks=False,
                )
                os.fsync(directory_fd)
            except FileExistsError:
                current, current_identity = _read_file_at(
                    directory_fd, checked, maximum
                )
                if current != data:
                    _fail("book proposal appeared with different bytes")
                return current_identity
            published, published_identity = _read_file_at(
                directory_fd, checked, maximum
            )
            if published != data or published_identity != staged_identity:
                _fail("book proposal publish verification failed")
            return published_identity
        except BookFlowError:
            raise
        except OSError:
            _fail("book proposal could not be published safely")
        finally:
            if fd is not None:
                os.close(fd)
            try:
                os.unlink(temporary, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
            except OSError:
                pass

    def _check_proposal_targets(
        self, artifact: ReviewArtifact, plan: MutationPlan
    ) -> None:
        review_raw = render_review_artifact(artifact).encode("utf-8")
        plan_raw = render_mutation_plan(plan)
        with self._managed_zone("review", for_write=False) as (review_fd, _identity):
            self._check_exact_or_missing(
                review_fd, f"{artifact.review_id}.md", review_raw, 512 * 1024
            )
        with self._managed_zone(".lifeos/review-plans", for_write=False) as (
            plan_fd,
            _identity,
        ):
            self._check_exact_or_missing(
                plan_fd, f"{artifact.review_id}.json", plan_raw, 512 * 1024
            )

    def _publish_proposal(
        self,
        artifact: ReviewArtifact,
        plan: MutationPlan,
        *,
        review_name: str,
        plan_name: str,
    ) -> tuple[PreparedArtifact, PreparedArtifact]:
        review_raw = render_review_artifact(artifact).encode("utf-8")
        plan_raw = render_mutation_plan(plan)
        review_relative = f"{artifact.review_id}.md"
        plan_relative = f"{artifact.review_id}.json"
        with self._managed_zone("review", for_write=True) as (review_fd, _identity):
            self._publish_create_once(
                review_fd, review_relative, review_raw, 512 * 1024
            )
        with self._managed_zone(".lifeos/review-plans", for_write=True) as (
            plan_fd,
            _identity,
        ):
            self._publish_create_once(plan_fd, plan_relative, plan_raw, 512 * 1024)
        return (
            PreparedArtifact(
                review_name,
                "review",
                review_relative,
                f"review/{review_relative}",
                hashlib.sha256(review_raw).hexdigest(),
            ),
            PreparedArtifact(
                plan_name,
                ".lifeos/review-plans",
                plan_relative,
                f".lifeos/review-plans/{plan_relative}",
                hashlib.sha256(plan_raw).hexdigest(),
            ),
        )

    def _derive_evidence_chain(
        self,
        prior: Mapping[str, object],
        *,
        run_id: str,
        committed_names: frozenset[str],
    ) -> tuple[
        BookCommand,
        BookSourceManifest,
        ReadingState,
        str,
        str | None,
        str | None,
        str,
        ReadingState | None,
        str | None,
        str,
    ]:
        try:
            return self._derive_evidence_chain_iterative(
                prior,
                run_id=run_id,
                committed_names=committed_names,
            )
        except RecursionError:
            _fail("book replay evidence chain exceeds its bound")

    def _derive_evidence_chain_iterative(
        self,
        prior: Mapping[str, object],
        *,
        run_id: str,
        committed_names: frozenset[str],
    ) -> tuple[
        BookCommand,
        BookSourceManifest,
        ReadingState,
        str,
        str | None,
        str | None,
        str,
        ReadingState | None,
        str | None,
        str,
    ]:
        nodes: list[_PriorEvidence] = []
        seen: set[str] = set()
        current = prior
        while True:
            if len(nodes) >= _MAX_PRIOR_CHAIN:
                _fail("book replay evidence chain exceeds its bound")
            if (
                type(current["schema_version"]) is not int
                or current["schema_version"] != BOOK_SCHEMA_VERSION
                or current["flow"] != "book"
            ):
                _fail("book replay request conflicts with durable evidence")
            request_item = _mapping(
                current["request"],
                "book replay request",
                frozenset({"command", "source_manifest"}),
            )
            command_payload = _mapping(
                request_item["command"], "book replay command", _COMMAND_KEYS
            )
            manifest_payload = _mapping(
                request_item["source_manifest"],
                "book replay source manifest",
                _MANIFEST_KEYS,
            )
            command = parse_book_command(_canonical(dict(command_payload)))
            manifest = parse_book_source_manifest(_canonical(dict(manifest_payload)))
            request = self._request_payload(command, manifest)
            request_hash = self._request_hash(request)
            if command.mutation_id in seen:
                _fail("book replay evidence chain contains a cycle")
            if (
                command.run_id != run_id
                or current["request"] != request
                or _hash(current["request_sha256"], "evidence request_sha256")
                != request_hash
            ):
                _fail("book replay request conflicts with durable evidence")
            seen.add(command.mutation_id)
            run_hash = _hash(current["run_state_sha256"], "evidence run_state_sha256")
            base_hash = current["base_state_sha256"]
            base_payload = current["base_state"]
            if base_payload is None:
                if base_hash is not None or command.operation != "active":
                    _fail("book replay base state evidence is incomplete")
                base = None
            else:
                if base_hash is None or command.operation == "active":
                    _fail("book replay base state evidence is incomplete")
                base = _state_from_payload(base_payload)
                if base.status != "active" or base.slug != command.slug:
                    _fail("book replay base state is not an active command preimage")
                base_hash = _hash(base_hash, "evidence base_state_sha256")
                if hashlib.sha256(render_reading_state(base)).hexdigest() != base_hash:
                    _fail("book replay base state hash is invalid")
            target = _state_from_payload(current["target_state"])
            block = _text(
                current["log_block"],
                "evidence log_block",
                maximum=64 * 1024,
                layout=True,
            )
            if hashlib.sha256(block.encode("utf-8")).hexdigest() != _hash(
                current["log_block_sha256"], "evidence log_block_sha256"
            ):
                _fail("book replay log evidence hash is invalid")
            review_hash = current["review_sha256"]
            plan_hash = current["plan_sha256"]
            if review_hash is not None:
                review_hash = _hash(review_hash, "evidence review_sha256")
            if plan_hash is not None:
                plan_hash = _hash(plan_hash, "evidence plan_sha256")
            if (review_hash is None) != (plan_hash is None):
                _fail("book replay proposal evidence is incomplete")
            nodes.append(
                _PriorEvidence(
                    command,
                    manifest,
                    request,
                    request_hash,
                    run_hash,
                    base,
                    base_hash,
                    target,
                    block,
                    review_hash,
                    plan_hash,
                )
            )
            if base is None:
                break
            if len(nodes) >= _MAX_PRIOR_CHAIN:
                _fail("book replay evidence chain exceeds its bound")
            if base.last_mutation_id in seen:
                _fail("book replay evidence chain contains a cycle")
            previous_name, _review, _plan, _step = _artifact_names(
                base.last_mutation_id
            )
            if previous_name not in committed_names:
                _fail("book replay base state lacks committed provenance")
            previous = self._load_evidence(run_id, base.last_mutation_id)
            if previous is None:
                _fail("book replay base state lacks committed provenance")
            current = previous

        previous_target: ReadingState | None = None
        derived_target: ReadingState | None = None
        derived_block = ""
        for node in reversed(nodes):
            if node.base != previous_target:
                _fail("book replay base state conflicts with committed provenance")
            derived_target = self._derive_target(
                node.command,
                node.manifest,
                previous_target,
                node.request_hash,
            )
            if node.target != derived_target:
                _fail("book replay target is not derived from its exact preimage")
            derived_block = self._event_block(
                node.command,
                node.manifest,
                derived_target,
                node.request_hash,
            )
            if node.block != derived_block:
                _fail("book replay log is not derived from its command")
            if node.command.operation == "anchor":
                derived_artifact, derived_plan = _proposal(
                    derived_target.title, derived_target.anchors[-1]
                )
                if (
                    node.review_hash
                    != hashlib.sha256(
                        render_review_artifact(derived_artifact).encode("utf-8")
                    ).hexdigest()
                    or node.plan_hash
                    != hashlib.sha256(render_mutation_plan(derived_plan)).hexdigest()
                ):
                    _fail("book replay proposal is not derived from its command")
            elif node.review_hash is not None or node.plan_hash is not None:
                _fail("non-anchor replay contains proposal evidence")
            previous_target = derived_target

        root = nodes[0]
        assert derived_target is not None
        return (
            root.command,
            root.manifest,
            derived_target,
            derived_block,
            root.review_hash,
            root.plan_hash,
            root.run_hash,
            root.base,
            root.base_hash,
            root.request_hash,
        )

    def _validate_prior(
        self,
        prior: Mapping[str, object],
        request: Mapping[str, object],
        request_hash: str,
        *,
        command: BookCommand,
        manifest: BookSourceManifest,
        committed_names: frozenset[str],
    ) -> tuple[
        ReadingState,
        str,
        str | None,
        str | None,
        str,
        ReadingState | None,
        str | None,
    ]:
        (
            derived_command,
            derived_manifest,
            target,
            block,
            review_hash,
            plan_hash,
            run_hash,
            base,
            base_hash,
            derived_request_hash,
        ) = self._derive_evidence_chain(
            prior,
            run_id=command.run_id,
            committed_names=committed_names,
        )
        if (
            derived_command != command
            or derived_manifest != manifest
            or prior["request"] != request
            or derived_request_hash != request_hash
        ):
            _fail("book replay request conflicts with durable evidence")
        return target, block, review_hash, plan_hash, run_hash, base, base_hash

    def _prepare_artifacts(
        self,
        command: BookCommand,
        evidence_payload: Mapping[str, object],
    ) -> tuple[PreparedArtifact, ...]:
        evidence_name, _review_name, _plan_name, _step = _artifact_names(
            command.mutation_id
        )
        try:
            prepared = (
                self._runs.prepare_run_artifact(
                    command.run_id,
                    name=evidence_name,
                    data=_canonical(dict(evidence_payload)),
                    maximum_bytes=_MAX_EVIDENCE_BYTES,
                ),
            )
        except RunError as error:
            raise BookFlowError(str(error)) from None
        return prepared

    def _commit_run(
        self,
        command: BookCommand,
        *,
        request_hash: str,
        run_state_sha256: str,
        prepared: Sequence[PreparedArtifact],
        grants: Sequence[ActionCapability],
        hooks: BookCrashHooks,
    ) -> None:
        if hooks.before_run_commit is not None:
            hooks.before_run_commit()
        _evidence_name, _review_name, _plan_name, step_id = _artifact_names(
            command.mutation_id
        )
        output_hash = prepared[0].sha256
        try:
            state = self._runs.commit_step(
                command.run_id,
                step_id=step_id,
                authority="domain-write",
                input_hash=request_hash,
                output_hash=output_hash,
                next_phase=f"book-{command.operation}-committed",
                next_status="running",
                prepared_artifacts=prepared,
                expected_state_sha256=run_state_sha256,
                action_uses=tuple(ActionUse(item) for item in grants),
                authority_policy=self._policy,
            )
        except RunError as error:
            raise BookFlowError(str(error)) from None
        if state.get("status") != "running":
            _fail("book mutation must leave its run running for finalize")

    def execute(
        self,
        command: BookCommand,
        manifest: BookSourceManifest,
        *,
        capabilities: BookCapabilities,
        crash_hooks: BookCrashHooks | None = None,
    ) -> BookResult:
        checked_command = _validate_command(command)
        hooks = _validate_crash_hooks(crash_hooks)
        grants = self._preflight(checked_command, capabilities)
        self._require(grants[0], "read-source-manifest")
        checked_manifest = _validate_manifest(manifest)
        run_snapshot = self._run_snapshot(checked_command.run_id)
        request = self._request_payload(checked_command, checked_manifest)
        request_hash = self._request_hash(request)
        prior = self._load_evidence(checked_command.run_id, checked_command.mutation_id)
        _evidence_name, review_name, plan_name, _step = _artifact_names(
            checked_command.mutation_id
        )

        if prior is None and checked_command.operation != "active":
            probe = self._open_reading_zone(for_write=False)
            if probe is None:
                _fail("book is not currently being read")
            try:
                self._require(grants[1], "read-reading-state")
                probe_state, _probe_raw, _probe_identity = self._load_state_at(
                    probe, checked_command.slug
                )
                self._revalidate_zone(probe, for_write=False)
                if probe_state is None:
                    _fail("book is not currently being read")
            finally:
                self._close_zone(probe)

        with self._locked_reading_zone() as zone:
            self._require(grants[1], "read-reading-state")
            current, current_raw, current_identity = self._load_state_at(
                zone, checked_command.slug
            )
            replayed = prior is not None
            if prior is not None:
                (
                    target,
                    block,
                    review_hash,
                    plan_hash,
                    run_state_hash,
                    base_state,
                    base_hash,
                ) = self._validate_prior(
                    prior,
                    request,
                    request_hash,
                    command=checked_command,
                    manifest=checked_manifest,
                    committed_names=frozenset(
                        item.name for item in run_snapshot.artifacts
                    ),
                )
                if (
                    target.slug != checked_command.slug
                    or target.last_mutation_id != checked_command.mutation_id
                    or target.last_mutation_sha256 != request_hash
                    or target.status
                    != ("closed" if checked_command.operation == "close" else "active")
                ):
                    _fail("book replay target is not bound to the command")
                artifact = None
                plan = None
                if checked_command.operation == "anchor":
                    if not target.anchors:
                        _fail("anchor replay lacks its proposed anchor")
                    artifact, plan = _proposal(target.title, target.anchors[-1])
                    if (
                        hashlib.sha256(
                            render_review_artifact(artifact).encode("utf-8")
                        ).hexdigest()
                        != review_hash
                        or hashlib.sha256(render_mutation_plan(plan)).hexdigest()
                        != plan_hash
                    ):
                        _fail("anchor replay proposal disagrees with durable evidence")
                current_hash = (
                    None
                    if current_raw is None
                    else hashlib.sha256(current_raw).hexdigest()
                )
                target_raw = render_reading_state(target)
                target_hash = hashlib.sha256(target_raw).hexdigest()
                log_raw, _log_identity = self._load_log_at(zone, checked_command.slug)
                marker = self._log_marker_prefix(checked_command.mutation_id)
                block_raw = block.encode("utf-8")
                log_done = log_raw.endswith(block_raw) and log_raw.count(marker) == 1
                if marker in log_raw and not log_done:
                    _fail("book replay log is no longer the latest lifecycle event")
                if checked_command.operation == "close":
                    if base_state is None:
                        _fail("close replay lacks its active reading preimage")
                    close_preimage = render_reading_state(base_state)
                    retained_close = _close_quarantine_at(
                        zone.fd,
                        self._state_name(checked_command.slug),
                        close_preimage,
                    )
                    if current is None and log_done:
                        domain_done = retained_close is None
                    elif current_hash == base_hash:
                        domain_done = False
                    else:
                        _fail("close replay conflicts with current reading state")
                else:
                    if current_hash == target_hash and log_done:
                        domain_done = True
                    elif current_hash == base_hash:
                        domain_done = False
                    else:
                        _fail("book replay conflicts with current reading state")
            else:
                self._validate_committed_history(
                    zone,
                    checked_command.slug,
                    current,
                    frozenset(item.name for item in run_snapshot.artifacts),
                )
                target = self._derive_target(
                    checked_command, checked_manifest, current, request_hash
                )
                artifact = None
                plan = None
                if checked_command.operation == "anchor":
                    self._require(grants[2], "read-reading-knowledge")
                    assert checked_command.target_path is not None
                    self._knowledge_target_absent(checked_command.target_path)
                    artifact, plan = _proposal(target.title, target.anchors[-1])
                    self._check_proposal_targets(artifact, plan)
                block = self._event_block(
                    checked_command, checked_manifest, target, request_hash
                )
                base_hash = (
                    None
                    if current_raw is None
                    else hashlib.sha256(current_raw).hexdigest()
                )
                base_state = current
                run_state_hash = run_snapshot.state_sha256
                review_hash = (
                    None
                    if artifact is None
                    else hashlib.sha256(
                        render_review_artifact(artifact).encode("utf-8")
                    ).hexdigest()
                )
                plan_hash = (
                    None
                    if plan is None
                    else hashlib.sha256(render_mutation_plan(plan)).hexdigest()
                )
                domain_done = False

            evidence_payload = {
                "schema_version": BOOK_SCHEMA_VERSION,
                "flow": "book",
                "request": request,
                "request_sha256": request_hash,
                "run_state_sha256": run_state_hash,
                "base_state": (
                    None if base_state is None else _state_payload(base_state)
                ),
                "base_state_sha256": base_hash,
                "target_state": _state_payload(target),
                "log_block": block,
                "log_block_sha256": hashlib.sha256(block.encode("utf-8")).hexdigest(),
                "review_sha256": review_hash,
                "plan_sha256": plan_hash,
            }
            prepared = self._prepare_artifacts(checked_command, evidence_payload)
            if hooks.after_evidence is not None:
                hooks.after_evidence()
            self._revalidate_zone(zone, for_write=True)
            if not domain_done:
                self._require(capabilities.commit_reading_state, "commit-reading-state")
                self._ensure_log_block(
                    zone,
                    checked_command.slug,
                    checked_command.mutation_id,
                    block.encode("utf-8"),
                )
                if hooks.after_log is not None:
                    hooks.after_log()
                self._revalidate_zone(zone, for_write=True)
                if checked_command.operation == "close":
                    if base_state is None:
                        _fail("close recovery lost its active reading precondition")
                    close_preimage = render_reading_state(base_state)
                    if current_raw is not None and current_identity is not None:
                        latest, latest_identity = _read_file_at(
                            zone.fd,
                            self._state_name(checked_command.slug),
                            _MAX_STATE_BYTES,
                        )
                        if (
                            latest != close_preimage
                            or latest_identity != current_identity
                        ):
                            _fail("active reading state changed before close")
                    elif (
                        _close_quarantine_at(
                            zone.fd,
                            self._state_name(checked_command.slug),
                            close_preimage,
                        )
                        is None
                    ):
                        _fail("close recovery lost its retained reading precondition")
                    _remove_identity_bound_at(
                        zone.fd,
                        self._state_name(checked_command.slug),
                        current_identity,
                        close_preimage,
                    )
                else:
                    _atomic_replace_at(
                        zone.fd,
                        self._state_name(checked_command.slug),
                        render_reading_state(target),
                        expected_identity=current_identity,
                        maximum=_MAX_STATE_BYTES,
                    )
                if hooks.after_state is not None:
                    hooks.after_state()
                self._revalidate_zone(zone, for_write=True)
            if artifact is not None and plan is not None:
                self._require(
                    capabilities.commit_knowledge_proposal,
                    "commit-reading-knowledge-proposal",
                )
                proposal_prepared = self._publish_proposal(
                    artifact,
                    plan,
                    review_name=review_name,
                    plan_name=plan_name,
                )
                prepared = (*prepared, *proposal_prepared)
                if hooks.after_proposal is not None:
                    hooks.after_proposal()
                self._revalidate_zone(zone, for_write=True)
            self._commit_run(
                checked_command,
                request_hash=request_hash,
                run_state_sha256=run_state_hash,
                prepared=prepared,
                grants=grants,
                hooks=hooks,
            )

        result = BookResult(
            BOOK_SCHEMA_VERSION,
            checked_command.operation,
            target,
            artifact,
            plan,
            review_name if artifact is not None else None,
            plan_name if plan is not None else None,
            replayed,
        )
        return _validate_result(result)

    def stale(
        self,
        query: StaleReadingQuery,
        manifest: BookSourceManifest,
        *,
        capabilities: BookCapabilities,
    ) -> StaleReading:
        if (
            not isinstance(query, StaleReadingQuery)
            or type(query.schema_version) is not int
        ):
            _fail("stale reading query is invalid")
        if query.schema_version != BOOK_SCHEMA_VERSION:
            _fail("unsupported stale reading query schema_version")
        slug = _identifier(query.slug, "stale reading slug", _SLUG)
        as_of = _timestamp(query.as_of, "stale reading as_of")
        threshold = _exact_int(
            query.threshold_days,
            "stale reading threshold_days",
            minimum=1,
            maximum=3650,
        )
        if not isinstance(capabilities, BookCapabilities):
            _fail("stale reading query requires BookCapabilities")
        self._require(capabilities.read_source_manifest, "read-source-manifest")
        checked_manifest = _validate_manifest(manifest)
        self._require(capabilities.read_reading_state, "read-reading-state")
        zone = self._open_reading_zone(for_write=False)
        if zone is None:
            _fail("book is not currently being read")
        try:
            self._revalidate_zone(zone, for_write=False)
            state, _raw, _identity = self._load_state_at(zone, slug)
            if state is None:
                _fail("book is not currently being read")
            self._compatible_source(state, checked_manifest)
            self._revalidate_zone(zone, for_write=False)
        finally:
            self._close_zone(zone)
        last = _instant(state.last_session_at)
        now = _instant(as_of)
        if now < last:
            _fail("stale reading as_of precedes the last session")
        stale_at = last + timedelta(days=threshold)
        stale_text = (
            stale_at.astimezone(timezone.utc)
            .isoformat(timespec="microseconds")
            .replace("+00:00", "Z")
        )
        return StaleReading(
            BOOK_SCHEMA_VERSION,
            slug,
            as_of,
            threshold,
            state.last_session_at,
            stale_text,
            now >= stale_at,
            state.source.manifest_ref != checked_manifest.manifest_ref,
        )
