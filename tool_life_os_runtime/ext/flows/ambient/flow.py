"""Bounded ambient scanner with durable semantic dedupe and recovery."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from datetime import date, datetime, timedelta
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
from typing import Callable, Iterator, Mapping, Sequence
import unicodedata
import uuid

from tool_life_os_runtime.ext.flows.memory import (
    MemoryFlowError,
    parse_memory_proposal,
)
from tool_life_os_runtime.ext.flows.plan import (
    DayPlan,
    PlanFlowError,
    WeekPlan,
    parse_day_plan,
    parse_week_plan,
)
from tool_life_os_runtime.ext.review.artifact import (
    ReviewArtifactError,
    parse_review_artifact,
)
from tool_life_os_runtime.ext.review.authority import (
    ActionCapability,
    AuthorityError,
    AuthorityPolicy,
)
from tool_life_os_runtime.ext.runs import (
    ActionUse,
    CommittedArtifact,
    OutboxError,
    OutboxStore,
    PreparedArtifact,
    RunError,
    RunStore,
    validate_event,
)
from tool_life_os_runtime.ext.vault.config import ConfigError
from tool_life_os_runtime.ext.vault.schema import VaultPathResolver, VaultSchemaError


AMBIENT_SCHEMA_VERSION = 1
_ID = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
_RUN_ID = re.compile(r"^run_[a-z0-9][a-z0-9_-]{0,62}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$")
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_PROJECT_SLUG = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
_PRIORITIES = ("low", "medium", "high", "critical")
_SURFACES = frozenset({"silent", "batched", "gated"})
_AVAILABILITY = frozenset({"available", "quiet", "unavailable"})
_KINDS = frozenset(
    {
        "task-due",
        "project-blocked",
        "project-next-step",
        "entity-due",
        "review-decision",
    }
)
_KIND_RANK = {
    "review-decision": 0,
    "project-blocked": 1,
    "task-due": 2,
    "entity-due": 3,
    "project-next-step": 4,
}
_DISPOSITIONS = frozenset(
    {
        "emitted",
        "expired",
        "superseded",
        "review-backpressure",
        "lower-ranked",
        "availability-deferred",
        "intentional-silent",
    }
)
_MAX_JSON = 4 * 1024 * 1024
_MAX_EVIDENCE = 1024 * 1024
_MAX_FILES = 512
_MAX_TOTAL = 4 * 1024 * 1024
_MAX_CANDIDATES = 512
_PRIVATE_PATH = re.compile(
    r"(?i)(?:file:|/(?:users|home)/|[a-z]:[\\/]|\\\\[^\\]+[\\]+[^\\]+)"
)
_SECRET = re.compile(
    r"(?i)(?:authorization|api[_ -]?key|token|secret|password|passwd|cookie|credential|chat[_ -]?id)\s*[:=]"
)


class AmbientFlowError(ValueError):
    """Ambient input, evidence, or filesystem state is unsafe."""


def _fail(message: str) -> None:
    raise AmbientFlowError(message)


def _has_control(value: str) -> bool:
    return any(
        unicodedata.category(character).startswith("C")
        or unicodedata.category(character) in {"Zl", "Zp"}
        for character in value
    )


def _text(
    value: object,
    label: str,
    *,
    limit: int = 4096,
    pattern: re.Pattern[str] | None = None,
    allow_empty: bool = False,
    privacy: bool = True,
) -> str:
    if not isinstance(value, str):
        _fail(f"{label} must be bounded text")
    try:
        size = len(value.encode("utf-8"))
    except UnicodeError:
        _fail(f"{label} must be valid UTF-8 text")
    if (
        (not value and not allow_empty)
        or size > limit
        or value.strip() != value
        or _has_control(value)
        or (privacy and (_PRIVATE_PATH.search(value) or _SECRET.search(value)))
        or (pattern is not None and pattern.fullmatch(value) is None)
    ):
        _fail(f"{label} must be bounded privacy-safe text")
    return value


def _identifier(value: object, label: str) -> str:
    return _text(value, label, limit=64, pattern=_ID)


def _run_id(value: object) -> str:
    return _text(value, "run_id", limit=64, pattern=_RUN_ID)


def _hash(value: object, label: str) -> str:
    return _text(value, label, limit=64, pattern=_SHA256)


def _timestamp(value: object, label: str) -> str:
    checked = _text(value, label, limit=32)
    if _UTC.fullmatch(checked) is None:
        _fail(f"{label} must be a UTC timestamp")
    try:
        datetime.fromisoformat(checked[:-1] + "+00:00")
    except ValueError:
        _fail(f"{label} must be a valid UTC timestamp")
    return checked


def _instant(value: str) -> datetime:
    return datetime.fromisoformat(value[:-1] + "+00:00")


def _date_text(value: object, label: str) -> str:
    checked = _text(value, label, limit=10)
    if _DATE.fullmatch(checked) is None:
        _fail(f"{label} must be a date")
    try:
        date.fromisoformat(checked)
    except ValueError:
        _fail(f"{label} must be a valid date")
    return checked


def _safe_ref(value: object, label: str) -> str:
    checked = _text(value, label, limit=1024)
    if "\\" in checked:
        _fail(f"{label} must be a portable relative reference")
    path = PurePosixPath(checked)
    if path.is_absolute() or path == PurePosixPath(".") or ".." in path.parts:
        _fail(f"{label} must be a portable relative reference")
    return checked


def _portable(value: str) -> str:
    return unicodedata.normalize("NFC", value).casefold()


def _json_safe(value: object, label: str, *, depth: int = 0) -> None:
    if depth > 10:
        _fail(f"{label} is too deeply nested")
    if value is None or isinstance(value, bool) or type(value) in {int, float}:
        return
    if isinstance(value, str):
        _text(value, label, limit=65536, allow_empty=True, privacy=False)
        return
    if isinstance(value, list):
        if len(value) > 2048:
            _fail(f"{label} has too many items")
        for item in value:
            _json_safe(item, label, depth=depth + 1)
        return
    if isinstance(value, Mapping):
        if len(value) > 256:
            _fail(f"{label} has too many fields")
        for key, item in value.items():
            _text(key, f"{label} field", limit=128, privacy=False)
            _json_safe(item, label, depth=depth + 1)
        return
    _fail(f"{label} contains a non-JSON value")


def _canonical(payload: Mapping[str, object], *, maximum: int = _MAX_JSON) -> bytes:
    _json_safe(payload, "payload")
    try:
        raw = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError):
        _fail("payload is not canonical JSON")
    if not raw or len(raw) > maximum:
        _fail("payload is too large")
    return raw


def _pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            _fail("JSON has duplicate fields")
        result[key] = value
    return result


def _decode(raw: bytes, label: str, *, maximum: int = _MAX_JSON) -> object:
    if not isinstance(raw, bytes) or not raw or len(raw) > maximum:
        _fail(f"{label} is empty or too large")
    try:
        value = json.loads(raw, object_pairs_hook=_pairs)
    except AmbientFlowError:
        raise
    except (UnicodeError, ValueError, RecursionError):
        _fail(f"{label} is not valid JSON")
    _json_safe(value, label)
    return value


def _mapping(
    value: object, label: str, keys: set[str] | frozenset[str]
) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or set(value) != set(keys):
        _fail(f"{label} has missing or unknown fields")
    return value


@dataclass(frozen=True)
class AmbientAvailability:
    status: str
    valid_from: str
    valid_until: str
    schema_version: int = AMBIENT_SCHEMA_VERSION


@dataclass(frozen=True)
class AmbientReviewBudget:
    soft_limit: int
    hard_limit: int
    schema_version: int = AMBIENT_SCHEMA_VERSION


@dataclass(frozen=True)
class AmbientRequest:
    operation_id: str
    observed_at: str
    availability: AmbientAvailability
    review_budget: AmbientReviewBudget
    schema_version: int = AMBIENT_SCHEMA_VERSION


@dataclass(frozen=True)
class AmbientCandidate:
    candidate_id: str
    kind: str
    semantic_slot: str
    source_ref: str
    source_sha256: str
    source_revision: int
    priority: str
    eligible_at: str
    expires_at: str | None
    supersedes: str | None
    surface: str
    summary: str
    schema_version: int = AMBIENT_SCHEMA_VERSION


@dataclass(frozen=True)
class AmbientDisposition:
    candidate_id: str
    reason: str
    schema_version: int = AMBIENT_SCHEMA_VERSION


@dataclass(frozen=True)
class AmbientCapabilities:
    scan_eligible_signals: ActionCapability
    read_ambient_projects: ActionCapability
    read_ambient_review: ActionCapability
    read_ambient_memory: ActionCapability
    commit_nudge_outbox_event: ActionCapability
    record_run_state: ActionCapability


@dataclass(frozen=True)
class AmbientCrashHooks:
    after_source_read: Callable[[], None] | None = None
    after_payload_prepare: Callable[[], None] | None = None
    after_event_publish: Callable[[], None] | None = None
    after_evidence_prepare: Callable[[], None] | None = None
    after_run_intent: Callable[[], None] | None = None
    after_run_state: Callable[[], None] | None = None
    after_run_trace: Callable[[], None] | None = None


@dataclass(frozen=True)
class AmbientRunEvidence:
    run_id: str
    operation_id: str
    request_sha256: str
    run_state_sha256: str
    outcome: str
    candidate_count: int
    review_debt: int
    candidates_sha256: str
    selected: AmbientCandidate | None
    dispositions: tuple[AmbientDisposition, ...]
    marker_ref: str | None
    marker_sha256: str | None
    payload_ref: str | None
    payload_sha256: str | None
    event_ref: str | None
    event_sha256: str | None
    event_id: str | None
    schema_version: int = AMBIENT_SCHEMA_VERSION


@dataclass(frozen=True)
class AmbientResult:
    outcome: str
    event_id: str | None
    evidence_artifact: str
    selected_candidate_id: str | None
    replayed: bool


def _availability_payload(value: AmbientAvailability) -> dict[str, object]:
    if (
        not isinstance(value, AmbientAvailability)
        or type(value.schema_version) is not int
        or value.schema_version != 1
    ):
        _fail("availability schema is invalid")
    status = _text(value.status, "availability status", limit=16)
    if status not in _AVAILABILITY:
        _fail("availability status is invalid")
    start = _timestamp(value.valid_from, "availability valid_from")
    end = _timestamp(value.valid_until, "availability valid_until")
    if _instant(start) >= _instant(end):
        _fail("availability interval is invalid")
    return {
        "schema_version": 1,
        "status": status,
        "valid_from": start,
        "valid_until": end,
    }


def _budget_payload(value: AmbientReviewBudget) -> dict[str, object]:
    if (
        not isinstance(value, AmbientReviewBudget)
        or type(value.schema_version) is not int
        or value.schema_version != 1
    ):
        _fail("review budget schema is invalid")
    if (
        type(value.soft_limit) is not int
        or type(value.hard_limit) is not int
        or value.soft_limit < 0
        or value.hard_limit < 1
        or value.soft_limit > value.hard_limit
        or value.hard_limit > 100000
    ):
        _fail("review budget bounds are invalid")
    return {
        "schema_version": 1,
        "soft_limit": value.soft_limit,
        "hard_limit": value.hard_limit,
    }


def _request_payload(value: AmbientRequest) -> dict[str, object]:
    if (
        not isinstance(value, AmbientRequest)
        or type(value.schema_version) is not int
        or value.schema_version != 1
    ):
        _fail("ambient request schema is invalid")
    operation = _identifier(value.operation_id, "operation_id")
    observed = _timestamp(value.observed_at, "observed_at")
    availability = _availability_payload(value.availability)
    if not (
        _instant(str(availability["valid_from"]))
        <= _instant(observed)
        < _instant(str(availability["valid_until"]))
    ):
        _fail("availability observation is stale")
    return {
        "schema_version": 1,
        "operation_id": operation,
        "observed_at": observed,
        "availability": availability,
        "review_budget": _budget_payload(value.review_budget),
    }


def _candidate_payload(value: AmbientCandidate) -> dict[str, object]:
    if (
        not isinstance(value, AmbientCandidate)
        or type(value.schema_version) is not int
        or value.schema_version != 1
    ):
        _fail("ambient candidate schema is invalid")
    kind = _text(value.kind, "candidate kind", limit=32)
    if kind not in _KINDS:
        _fail("ambient candidate kind is invalid")
    priority = _text(value.priority, "candidate priority", limit=16)
    if priority not in _PRIORITIES:
        _fail("ambient candidate priority is invalid")
    surface = _text(value.surface, "candidate surface", limit=16)
    if surface not in _SURFACES:
        _fail("ambient candidate surface is invalid")
    if (
        type(value.source_revision) is not int
        or not 0 <= value.source_revision <= 2**31 - 1
    ):
        _fail("ambient candidate revision is invalid")
    payload = {
        "schema_version": 1,
        "candidate_id": _identifier(value.candidate_id, "candidate_id"),
        "kind": kind,
        "semantic_slot": _text(value.semantic_slot, "semantic_slot", limit=256),
        "source_ref": _safe_ref(value.source_ref, "source_ref"),
        "source_sha256": _hash(value.source_sha256, "source_sha256"),
        "source_revision": value.source_revision,
        "priority": priority,
        "eligible_at": _timestamp(value.eligible_at, "eligible_at"),
        "expires_at": None
        if value.expires_at is None
        else _timestamp(value.expires_at, "expires_at"),
        "supersedes": None
        if value.supersedes is None
        else _identifier(value.supersedes, "supersedes"),
        "surface": surface,
        "summary": _text(value.summary, "candidate summary", limit=256),
    }
    identity = dict(payload)
    identity.pop("candidate_id")
    expected = "cand_" + hashlib.sha256(_canonical(identity)).hexdigest()[:48]
    if payload["candidate_id"] != expected:
        _fail("ambient candidate id is invalid")
    return payload


def _parse_candidate(value: object) -> AmbientCandidate:
    item = _mapping(
        value,
        "ambient candidate",
        {
            "schema_version",
            "candidate_id",
            "kind",
            "semantic_slot",
            "source_ref",
            "source_sha256",
            "source_revision",
            "priority",
            "eligible_at",
            "expires_at",
            "supersedes",
            "surface",
            "summary",
        },
    )
    candidate = AmbientCandidate(
        item["candidate_id"] if isinstance(item["candidate_id"], str) else "",
        item["kind"] if isinstance(item["kind"], str) else "",
        item["semantic_slot"] if isinstance(item["semantic_slot"], str) else "",
        item["source_ref"] if isinstance(item["source_ref"], str) else "",
        item["source_sha256"] if isinstance(item["source_sha256"], str) else "",
        item["source_revision"] if type(item["source_revision"]) is int else -1,
        item["priority"] if isinstance(item["priority"], str) else "",
        item["eligible_at"] if isinstance(item["eligible_at"], str) else "",
        item["expires_at"] if isinstance(item["expires_at"], str) else None,
        item["supersedes"] if isinstance(item["supersedes"], str) else None,
        item["surface"] if isinstance(item["surface"], str) else "",
        item["summary"] if isinstance(item["summary"], str) else "",
        item["schema_version"] if type(item["schema_version"]) is int else -1,
    )
    if item["expires_at"] is not None and candidate.expires_at is None:
        _fail("candidate expires_at has invalid type")
    if item["supersedes"] is not None and candidate.supersedes is None:
        _fail("candidate supersedes has invalid type")
    _candidate_payload(candidate)
    return candidate


def _disposition_payload(value: AmbientDisposition) -> dict[str, object]:
    if (
        not isinstance(value, AmbientDisposition)
        or type(value.schema_version) is not int
        or value.schema_version != 1
    ):
        _fail("ambient disposition schema is invalid")
    reason = _text(value.reason, "disposition reason", limit=32)
    if reason not in _DISPOSITIONS:
        _fail("ambient disposition reason is invalid")
    return {
        "schema_version": 1,
        "candidate_id": _identifier(value.candidate_id, "candidate_id"),
        "reason": reason,
    }


def _parse_disposition(value: object) -> AmbientDisposition:
    item = _mapping(
        value,
        "ambient disposition",
        {"schema_version", "candidate_id", "reason"},
    )
    disposition = AmbientDisposition(
        item["candidate_id"] if isinstance(item["candidate_id"], str) else "",
        item["reason"] if isinstance(item["reason"], str) else "",
        item["schema_version"] if type(item["schema_version"]) is int else -1,
    )
    _disposition_payload(disposition)
    return disposition


def _evidence_payload(value: AmbientRunEvidence) -> dict[str, object]:
    if (
        not isinstance(value, AmbientRunEvidence)
        or type(value.schema_version) is not int
        or value.schema_version != 1
    ):
        _fail("ambient evidence schema is invalid")
    outcome = _text(value.outcome, "ambient outcome", limit=32)
    if outcome not in {
        "emitted",
        "zero",
        "suppressed",
        "availability-deferred",
        "intentional-silent",
        "review-backpressure",
    }:
        _fail("ambient evidence outcome is invalid")
    if (
        type(value.candidate_count) is not int
        or type(value.review_debt) is not int
        or not 0 <= value.candidate_count <= _MAX_CANDIDATES
        or not 0 <= value.review_debt <= _MAX_FILES
    ):
        _fail("ambient evidence counts are invalid")
    dispositions = [_disposition_payload(item) for item in value.dispositions]
    if len(dispositions) != value.candidate_count:
        _fail("ambient evidence does not disposition every candidate")
    ids = [str(item["candidate_id"]) for item in dispositions]
    if len(ids) != len(set(ids)):
        _fail("ambient evidence dispositions collide")
    selected = None if value.selected is None else _candidate_payload(value.selected)
    nullable = (
        value.marker_ref,
        value.marker_sha256,
        value.payload_ref,
        value.payload_sha256,
        value.event_ref,
        value.event_sha256,
        value.event_id,
    )
    if value.outcome == "emitted":
        if selected is None or any(item is None for item in nullable):
            _fail("emitted ambient evidence is incomplete")
        if (
            dispositions[ids.index(str(selected["candidate_id"]))]["reason"]
            != "emitted"
        ):
            _fail("emitted candidate disposition is invalid")
    elif any(item is not None for item in nullable):
        _fail("non-emitted ambient evidence contains outbox state")
    if value.outcome == "zero" and (selected is not None or value.candidate_count != 0):
        _fail("zero ambient evidence contains candidates")
    payload = {
        "schema_version": 1,
        "flow": "ambient",
        "run_id": _run_id(value.run_id),
        "operation_id": _identifier(value.operation_id, "operation_id"),
        "request_sha256": _hash(value.request_sha256, "request_sha256"),
        "run_state_sha256": _hash(value.run_state_sha256, "run_state_sha256"),
        "outcome": outcome,
        "candidate_count": value.candidate_count,
        "review_debt": value.review_debt,
        "candidates_sha256": _hash(value.candidates_sha256, "candidates_sha256"),
        "selected": selected,
        "dispositions": dispositions,
        "marker_ref": None
        if value.marker_ref is None
        else _safe_ref(value.marker_ref, "marker_ref"),
        "marker_sha256": None
        if value.marker_sha256 is None
        else _hash(value.marker_sha256, "marker_sha256"),
        "payload_ref": None
        if value.payload_ref is None
        else _safe_ref(value.payload_ref, "payload_ref"),
        "payload_sha256": None
        if value.payload_sha256 is None
        else _hash(value.payload_sha256, "payload_sha256"),
        "event_ref": None
        if value.event_ref is None
        else _safe_ref(value.event_ref, "event_ref"),
        "event_sha256": None
        if value.event_sha256 is None
        else _hash(value.event_sha256, "event_sha256"),
        "event_id": None
        if value.event_id is None
        else _identifier(value.event_id, "event_id"),
    }
    return payload


def render_ambient_run_evidence(value: AmbientRunEvidence) -> bytes:
    return _canonical(_evidence_payload(value), maximum=_MAX_EVIDENCE)


def parse_ambient_run_evidence(raw: bytes | str) -> AmbientRunEvidence:
    if isinstance(raw, str):
        try:
            raw = raw.encode("utf-8")
        except UnicodeError:
            _fail("ambient evidence is not valid UTF-8")
    item = _mapping(
        _decode(raw, "ambient evidence", maximum=_MAX_EVIDENCE),
        "ambient evidence",
        {
            "schema_version",
            "flow",
            "run_id",
            "operation_id",
            "request_sha256",
            "run_state_sha256",
            "outcome",
            "candidate_count",
            "review_debt",
            "candidates_sha256",
            "selected",
            "dispositions",
            "marker_ref",
            "marker_sha256",
            "payload_ref",
            "payload_sha256",
            "event_ref",
            "event_sha256",
            "event_id",
        },
    )
    if item["flow"] != "ambient" or not isinstance(item["dispositions"], list):
        _fail("ambient evidence shape is invalid")
    evidence = AmbientRunEvidence(
        item["run_id"] if isinstance(item["run_id"], str) else "",
        item["operation_id"] if isinstance(item["operation_id"], str) else "",
        item["request_sha256"] if isinstance(item["request_sha256"], str) else "",
        item["run_state_sha256"] if isinstance(item["run_state_sha256"], str) else "",
        item["outcome"] if isinstance(item["outcome"], str) else "",
        item["candidate_count"] if type(item["candidate_count"]) is int else -1,
        item["review_debt"] if type(item["review_debt"]) is int else -1,
        item["candidates_sha256"] if isinstance(item["candidates_sha256"], str) else "",
        None if item["selected"] is None else _parse_candidate(item["selected"]),
        tuple(_parse_disposition(value) for value in item["dispositions"]),
        item["marker_ref"] if isinstance(item["marker_ref"], str) else None,
        item["marker_sha256"] if isinstance(item["marker_sha256"], str) else None,
        item["payload_ref"] if isinstance(item["payload_ref"], str) else None,
        item["payload_sha256"] if isinstance(item["payload_sha256"], str) else None,
        item["event_ref"] if isinstance(item["event_ref"], str) else None,
        item["event_sha256"] if isinstance(item["event_sha256"], str) else None,
        item["event_id"] if isinstance(item["event_id"], str) else None,
        item["schema_version"] if type(item["schema_version"]) is int else -1,
    )
    for name in (
        "marker_ref",
        "marker_sha256",
        "payload_ref",
        "payload_sha256",
        "event_ref",
        "event_sha256",
        "event_id",
    ):
        if item[name] is not None and getattr(evidence, name) is None:
            _fail("ambient evidence nullable field has invalid type")
    _evidence_payload(evidence)
    return evidence


def ambient_evidence_artifact_name(operation_id: str) -> str:
    checked = _identifier(operation_id, "operation_id")
    return "ambient-evidence-" + hashlib.sha256(checked.encode()).hexdigest()[:32]


def _ambient_anchor_artifact_name(operation_id: str) -> str:
    checked = _identifier(operation_id, "operation_id")
    return "ambient-anchor-" + hashlib.sha256(checked.encode()).hexdigest()[:32]


def inspect_ambient_run_evidence(
    artifact: CommittedArtifact, raw: bytes
) -> AmbientRunEvidence:
    if not isinstance(artifact, CommittedArtifact):
        _fail("ambient evidence artifact has invalid type")
    evidence = parse_ambient_run_evidence(raw)
    expected_name = ambient_evidence_artifact_name(evidence.operation_id)
    token = hashlib.sha256(evidence.operation_id.encode()).hexdigest()[:32]
    if (
        artifact.name != expected_name
        or artifact.zone != "agent/runs"
        or artifact.relative != f"{evidence.run_id}/{expected_name}.json"
        or artifact.state_ref != f"agent/runs/{artifact.relative}"
        or artifact.sha256 != hashlib.sha256(raw).hexdigest()
        or artifact.step_id != f"ambient-{token}"
    ):
        _fail("ambient evidence artifact binding is invalid")
    return evidence


@dataclass(frozen=True)
class _File:
    relative: str
    raw: bytes
    sha256: str
    signature: tuple[int, int, int, int, int]


@dataclass(frozen=True)
class _Zone:
    fd: int
    path: Path
    symbolic: str
    relative: str
    identity: tuple[int, int]


@dataclass(frozen=True, order=True)
class _SourceIdentity:
    logical_ref: str
    device: int
    inode: int
    file_type: int
    size: int
    mtime_ns: int
    ctime_ns: int


def _read_fd(fd: int, maximum: int) -> bytes:
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
            _fail("source is not a bounded regular file")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            block = os.read(fd, min(65536, remaining))
            if not block:
                break
            chunks.append(block)
            remaining -= len(block)
        if remaining == 0:
            _fail("source is too large")
        after = os.fstat(fd)
        signature = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        if signature != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            _fail("source changed while read")
        return b"".join(chunks)
    except OSError:
        _fail("source cannot be read safely")


class AmbientFlow:
    """Scan exact structured state and publish at most one semantic nudge."""

    def __init__(
        self,
        resolver: VaultPathResolver,
        run_store: RunStore,
        policy: AuthorityPolicy,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if (
            not isinstance(resolver, VaultPathResolver)
            or not isinstance(run_store, RunStore)
            or not isinstance(policy, AuthorityPolicy)
        ):
            _fail("ambient dependencies are invalid")
        if getattr(run_store, "_resolver", None) is not resolver:
            _fail("ambient dependencies must share one resolver")
        root = getattr(resolver, "_root_input", None)
        if not isinstance(root, Path) or not root.is_absolute():
            _fail("ambient vault root is unavailable")
        self._resolver = resolver
        self._runs = run_store
        self._policy = policy
        self._clock = clock
        self._root_path = root
        self._source_identities: dict[str, _SourceIdentity] | None = None
        try:
            self._root_fd = os.open(
                root,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
            opened = os.fstat(self._root_fd)
            named = os.stat(root, follow_symlinks=False)
            if not stat.S_ISDIR(opened.st_mode) or (opened.st_dev, opened.st_ino) != (
                named.st_dev,
                named.st_ino,
            ):
                _fail("ambient vault root cannot be pinned")
            self._root_identity = (opened.st_dev, opened.st_ino)
        except (OSError, AmbientFlowError):
            if hasattr(self, "_root_fd"):
                os.close(self._root_fd)
            raise AmbientFlowError("ambient vault root cannot be pinned") from None

    def close(self) -> None:
        fd = getattr(self, "_root_fd", -1)
        if fd >= 0:
            os.close(fd)
            self._root_fd = -1

    def __enter__(self) -> AmbientFlow:
        self._check_root()
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except OSError:
            pass

    def _check_root(self) -> None:
        try:
            opened = os.fstat(self._root_fd)
            named = os.stat(self._root_path, follow_symlinks=False)
        except OSError:
            _fail("ambient vault root changed")
        if (
            not stat.S_ISDIR(opened.st_mode)
            or (opened.st_dev, opened.st_ino) != self._root_identity
            or (named.st_dev, named.st_ino) != self._root_identity
        ):
            _fail("ambient vault root changed")
        self._record_source_identity(".", opened)

    def _record_source_identity(
        self, logical_ref: str, metadata: os.stat_result
    ) -> None:
        capture = self._source_identities
        if capture is None:
            return
        identity = _SourceIdentity(
            logical_ref,
            metadata.st_dev,
            metadata.st_ino,
            stat.S_IFMT(metadata.st_mode),
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
        )
        prior = capture.get(logical_ref)
        if prior is not None and prior != identity:
            _fail("ambient source identity changed within the bounded snapshot")
        capture[logical_ref] = identity

    @contextmanager
    def _source_identity_snapshot(self) -> Iterator[dict[str, _SourceIdentity]]:
        if self._source_identities is not None:
            _fail("ambient source identity snapshot is already active")
        capture: dict[str, _SourceIdentity] = {}
        self._source_identities = capture
        try:
            yield capture
        finally:
            self._source_identities = None

    @staticmethod
    def _identity_manifest(
        capture: Mapping[str, _SourceIdentity],
    ) -> tuple[_SourceIdentity, ...]:
        return tuple(sorted(capture.values()))

    def _zone_parts(self, symbolic: str) -> tuple[str, ...]:
        names = {
            "tasks": "tasks",
            "projects": "projects",
            "review": "review",
            "agent/memory": "memory",
            "agent/outbox": "outbox",
            "agent/runs": "runs",
        }
        try:
            return tuple(self._resolver.config.zone(names[symbolic]).parts)
        except (KeyError, ConfigError):
            _fail("ambient zone configuration is invalid")

    def _open_zone(self, symbolic: str, *, for_write: bool = False) -> _Zone:
        self._check_root()
        parts = self._zone_parts(symbolic)
        try:
            current = os.dup(self._root_fd)
        except OSError:
            _fail("ambient root binding cannot be duplicated")
        try:
            consumed: list[str] = []
            for part in parts:
                child = os.open(
                    part,
                    os.O_RDONLY
                    | getattr(os, "O_DIRECTORY", 0)
                    | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=current,
                )
                opened = os.fstat(child)
                named = os.stat(part, dir_fd=current, follow_symlinks=False)
                if not stat.S_ISDIR(opened.st_mode) or (
                    opened.st_dev,
                    opened.st_ino,
                ) != (named.st_dev, named.st_ino):
                    os.close(child)
                    _fail("ambient zone parent changed")
                consumed.append(part)
                self._record_source_identity(
                    PurePosixPath(*consumed).as_posix(), opened
                )
                os.close(current)
                current = child
            path = self._root_path.joinpath(*parts)
            opened = os.fstat(current)
            identity = (opened.st_dev, opened.st_ino)
            self._resolver.revalidate(
                path, symbolic, for_write=for_write, must_exist=True
            )
            return _Zone(
                current, path, symbolic, PurePosixPath(*parts).as_posix(), identity
            )
        except (OSError, VaultSchemaError, AmbientFlowError):
            os.close(current)
            raise AmbientFlowError("ambient zone cannot be opened safely") from None

    def _revalidate_zone(self, zone: _Zone, *, for_write: bool = False) -> None:
        try:
            self._check_root()
            opened = os.fstat(zone.fd)
            named = os.stat(zone.path, follow_symlinks=False)
            self._resolver.revalidate(
                zone.path, zone.symbolic, for_write=for_write, must_exist=True
            )
        except (OSError, VaultSchemaError):
            _fail("ambient zone changed")
        if (
            not stat.S_ISDIR(opened.st_mode)
            or (opened.st_dev, opened.st_ino) != zone.identity
            or (named.st_dev, named.st_ino) != zone.identity
        ):
            _fail("ambient zone changed")

    def _read_at(
        self, directory_fd: int, name: str, relative: str, maximum: int = _MAX_JSON
    ) -> _File:
        try:
            fd = os.open(
                name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=directory_fd
            )
            opened = os.fstat(fd)
            named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            signature = (
                opened.st_dev,
                opened.st_ino,
                opened.st_size,
                opened.st_mtime_ns,
                opened.st_ctime_ns,
            )
            if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (
                named.st_dev,
                named.st_ino,
            ):
                _fail("ambient source leaf changed")
            raw = _read_fd(fd, maximum)
            final = os.fstat(fd)
            named_after = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if signature != (
                final.st_dev,
                final.st_ino,
                final.st_size,
                final.st_mtime_ns,
                final.st_ctime_ns,
            ) or (final.st_dev, final.st_ino) != (
                named_after.st_dev,
                named_after.st_ino,
            ):
                _fail("ambient source leaf changed")
            self._record_source_identity(relative, final)
            return _File(relative, raw, hashlib.sha256(raw).hexdigest(), signature)
        except (OSError, AmbientFlowError):
            raise AmbientFlowError("ambient source cannot be read safely") from None
        finally:
            if "fd" in locals():
                os.close(fd)

    def _open_child(
        self,
        directory_fd: int,
        name: str,
        logical_ref: str | None = None,
    ) -> tuple[int, tuple[int, int]]:
        try:
            fd = os.open(
                name,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=directory_fd,
            )
            opened = os.fstat(fd)
            named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if not stat.S_ISDIR(opened.st_mode) or (opened.st_dev, opened.st_ino) != (
                named.st_dev,
                named.st_ino,
            ):
                _fail("ambient source parent changed")
            if self._source_identities is not None:
                if logical_ref is None:
                    _fail("ambient source parent logical reference is missing")
                self._record_source_identity(logical_ref, opened)
            return fd, (opened.st_dev, opened.st_ino)
        except (OSError, AmbientFlowError):
            if "fd" in locals():
                os.close(fd)
            raise AmbientFlowError(
                "ambient source parent cannot be opened safely"
            ) from None

    @staticmethod
    def _revalidate_child(
        parent_fd: int, name: str, fd: int, identity: tuple[int, int]
    ) -> None:
        try:
            opened = os.fstat(fd)
            named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except OSError:
            _fail("ambient source parent changed")
        if (
            not stat.S_ISDIR(opened.st_mode)
            or (opened.st_dev, opened.st_ino) != identity
            or (named.st_dev, named.st_ino) != identity
        ):
            _fail("ambient source parent changed")

    def _require_capabilities(
        self, value: AmbientCapabilities
    ) -> tuple[ActionCapability, ...]:
        if not isinstance(value, AmbientCapabilities):
            _fail("ambient capabilities are invalid")
        expected = (
            (
                value.scan_eligible_signals,
                "scan-eligible-signals",
                "read",
                "vault:tasks",
            ),
            (
                value.read_ambient_projects,
                "read-ambient-projects",
                "read",
                "vault:projects",
            ),
            (value.read_ambient_review, "read-ambient-review", "read", "vault:review"),
            (
                value.read_ambient_memory,
                "read-ambient-memory",
                "read",
                "vault:agent/memory",
            ),
            (
                value.commit_nudge_outbox_event,
                "commit-nudge-outbox-event",
                "internal-write",
                "vault:agent/outbox",
            ),
            (
                value.record_run_state,
                "record-run-state",
                "internal-write",
                "vault:agent/runs",
            ),
        )
        grants: list[ActionCapability] = []
        for capability, action, authority, target in expected:
            try:
                grant = self._policy.require(capability)
            except AuthorityError as error:
                raise AmbientFlowError(str(error)) from None
            if (
                grant.flow_id,
                grant.action_id,
                grant.actor,
                grant.authority,
                grant.target,
            ) != ("ambient", action, "system", authority, target):
                _fail("ambient action capability is not exact")
            grants.append(grant)
        return tuple(grants)

    def _run_snapshot(self, run_id: str):
        checked = _run_id(run_id)
        try:
            snapshot = self._runs.snapshot(checked)
        except RunError as error:
            raise AmbientFlowError(str(error)) from None
        if (
            snapshot.state.get("flow") != "ambient"
            or snapshot.state.get("status") != "running"
            or snapshot.state.get("authority") != "internal-write"
        ):
            _fail("ambient scan requires a running internal-write ambient run")
        return snapshot

    @staticmethod
    def _make_candidate(
        *,
        kind: str,
        slot: str,
        source_ref: str,
        source_hash: str,
        revision: int,
        priority: str,
        eligible: str,
        expires: str | None,
        supersedes: str | None,
        surface: str,
    ) -> AmbientCandidate:
        summary = {
            "task-due": "A scheduled task signal is due.",
            "project-blocked": "A project blocker needs attention.",
            "project-next-step": "A project next step is available.",
            "entity-due": "An entity follow-up is due.",
            "review-decision": "A review decision is pending.",
        }[kind]
        base = {
            "schema_version": 1,
            "kind": kind,
            "semantic_slot": slot,
            "source_ref": source_ref,
            "source_sha256": source_hash,
            "source_revision": revision,
            "priority": priority,
            "eligible_at": eligible,
            "expires_at": expires,
            "supersedes": supersedes,
            "surface": surface,
            "summary": summary,
        }
        candidate_id = "cand_" + hashlib.sha256(_canonical(base)).hexdigest()[:48]
        candidate = AmbientCandidate(
            candidate_id=candidate_id,
            **{
                "kind": kind,
                "semantic_slot": slot,
                "source_ref": source_ref,
                "source_sha256": source_hash,
                "source_revision": revision,
                "priority": priority,
                "eligible_at": eligible,
                "expires_at": expires,
                "supersedes": supersedes,
                "surface": surface,
                "summary": summary,
            },
        )
        _candidate_payload(candidate)
        return candidate

    @staticmethod
    def _raised_priority(priority: str, *, overdue: bool) -> str:
        if priority not in _PRIORITIES:
            _fail("source priority is invalid")
        if not overdue:
            return priority
        return _PRIORITIES[min(_PRIORITIES.index(priority) + 1, len(_PRIORITIES) - 1)]

    @staticmethod
    def _temporal(value: object, label: str) -> tuple[str, datetime]:
        if not isinstance(value, str):
            _fail(f"{label} is invalid")
        if _DATE.fullmatch(value):
            checked = _date_text(value, label)
            return checked + "T00:00:00Z", datetime.fromisoformat(
                checked + "T00:00:00+00:00"
            )
        checked = _timestamp(value, label)
        return checked, _instant(checked)

    def _scan_tasks(self, observed_at: str) -> list[AmbientCandidate]:
        zone = self._open_zone("tasks")
        candidates: list[AmbientCandidate] = []
        files = 0
        total = 0
        try:
            for dirname, kind in (("days", "day"), ("weeks", "week")):
                try:
                    child, identity = self._open_child(
                        zone.fd, dirname, f"{zone.relative}/{dirname}"
                    )
                except AmbientFlowError:
                    try:
                        os.stat(dirname, dir_fd=zone.fd, follow_symlinks=False)
                    except FileNotFoundError:
                        continue
                    raise
                try:
                    names = sorted(os.listdir(child), key=_portable)
                    if len(names) > _MAX_FILES:
                        _fail("tasks namespace has too many entries")
                    seen: set[str] = set()
                    for name in names:
                        key = _portable(name)
                        if key in seen:
                            _fail("tasks namespace has portable-name collisions")
                        seen.add(key)
                        if not name.endswith(".json"):
                            continue
                        source = self._read_at(
                            child, name, f"{zone.relative}/{dirname}/{name}"
                        )
                        files += 1
                        total += len(source.raw)
                        if files > _MAX_FILES or total > _MAX_TOTAL:
                            _fail("tasks snapshot exceeds its bound")
                        try:
                            plan = (
                                parse_day_plan(source.raw)
                                if kind == "day"
                                else parse_week_plan(source.raw)
                            )
                        except PlanFlowError:
                            _fail("tasks source violates the accepted plan schema")
                        if isinstance(plan, DayPlan):
                            if name != f"{plan.date}.json":
                                _fail("day plan filename disagrees with its schema")
                        elif isinstance(plan, WeekPlan):
                            if name != f"{plan.week_start}.json":
                                _fail("week plan filename disagrees with its schema")
                        else:
                            _fail("tasks source has the wrong plan type")
                        if plan.status != "active":
                            continue
                        for task in plan.tasks:
                            if task.status not in {"open", "rolled-over"}:
                                continue
                            eligible_text, eligible = self._temporal(
                                task.scheduled_for, "task schedule"
                            )
                            if eligible > _instant(observed_at):
                                continue
                            candidates.append(
                                self._make_candidate(
                                    kind="task-due",
                                    slot=f"task:{task.task_id}",
                                    source_ref=source.relative,
                                    source_hash=source.sha256,
                                    revision=plan.revision,
                                    priority=self._raised_priority(
                                        task.priority,
                                        overdue=eligible.date()
                                        < _instant(observed_at).date(),
                                    ),
                                    eligible=eligible_text,
                                    expires=None,
                                    supersedes=None,
                                    surface=self._resolver.config.surface,
                                )
                            )
                    self._revalidate_child(zone.fd, dirname, child, identity)
                finally:
                    os.close(child)
            self._revalidate_zone(zone)
            return candidates
        except OSError:
            raise AmbientFlowError("tasks namespace cannot be scanned safely") from None
        finally:
            os.close(zone.fd)

    @staticmethod
    def _project_record(value: object, dirname: str) -> Mapping[str, object]:
        item = _mapping(
            value,
            "project record",
            {
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
            },
        )
        if (
            type(item["schema_version"]) is not int
            or item["schema_version"] != 1
            or not isinstance(item["slug"], str)
            or _portable(str(item["slug"])) != _portable(dirname)
            or not isinstance(item["status"], str)
            or item["status"] not in {"active", "on-hold", "archived"}
            or type(item["revision"]) is not int
            or item["revision"] < 1
            or not isinstance(item["domains"], list)
            or not isinstance(item["schedule_ids"], list)
        ):
            _fail("project record violates its accepted schema")
        _text(item["slug"], "project slug", limit=63, pattern=_PROJECT_SLUG)
        _text(item["name"], "project name", limit=512, privacy=False)
        _text(item["goal"], "project goal", limit=16384, privacy=False)
        if not isinstance(item["kind"], str) or item["kind"] not in {
            "general",
            "research",
        }:
            _fail("project kind is invalid")
        domains = item["domains"]
        schedules = item["schedule_ids"]
        if (
            not domains
            or len(domains) > 32
            or len(schedules) > 128
            or any(not isinstance(value, str) for value in (*domains, *schedules))
        ):
            _fail("project identities are invalid")
        for value in domains:
            _text(value, "project domain", limit=63, pattern=_PROJECT_SLUG)
        for value in schedules:
            _identifier(value, "project schedule id")
        if len({_portable(value) for value in domains}) != len(domains) or len(
            {_portable(value) for value in schedules}
        ) != len(schedules):
            _fail("project identities collide")
        _timestamp(item["created_at"], "project created_at")
        _timestamp(item["updated_at"], "project updated_at")
        _identifier(item["last_transition_id"], "project transition id")
        hold_since = item["on_hold_since"]
        hold_reason = item["on_hold_reason"]
        archived_at = item["archived_at"]
        if hold_since is not None:
            _timestamp(hold_since, "project on_hold_since")
        if hold_reason is not None:
            _text(hold_reason, "project on_hold_reason", limit=4096, privacy=False)
        if archived_at is not None:
            _timestamp(archived_at, "project archived_at")
        if item["status"] == "active" and any(
            item[field] is not None
            for field in ("on_hold_since", "on_hold_reason", "archived_at")
        ):
            _fail("active project lifecycle fields are invalid")
        if item["status"] == "on-hold" and (
            hold_since is None or hold_reason is None or archived_at is not None
        ):
            _fail("held project lifecycle fields are invalid")
        if item["status"] == "archived" and archived_at is None:
            _fail("archived project lifecycle fields are invalid")
        return item

    @staticmethod
    def _project_state(value: object, slug: str) -> Mapping[str, object]:
        item = _mapping(
            value,
            "project state",
            {
                "schema_version",
                "project_slug",
                "revision",
                "next_steps",
                "blockers",
                "open_questions",
                "milestones",
                "last_session",
            },
        )
        if (
            type(item["schema_version"]) is not int
            or item["schema_version"] != 1
            or item["project_slug"] != slug
            or type(item["revision"]) is not int
            or item["revision"] < 1
        ):
            _fail("project state violates its accepted schema")
        for key, fields in (
            ("next_steps", {"id", "text", "status", "priority"}),
            ("blockers", {"id", "text", "status"}),
            ("open_questions", {"id", "text", "status", "answer"}),
            ("milestones", {"id", "text", "status"}),
        ):
            values = item[key]
            if not isinstance(values, list) or len(values) > 256:
                _fail("project state collection is invalid")
            seen: set[str] = set()
            for raw in values:
                entry = _mapping(raw, "project state item", fields)
                identifier = _identifier(entry["id"], "project item id")
                portable = _portable(identifier)
                if portable in seen:
                    _fail("project state item ids collide")
                seen.add(portable)
                _text(entry["text"], "project item text", limit=8192, privacy=False)
                if key == "next_steps" and (
                    not isinstance(entry["status"], str)
                    or entry["status"] not in {"open", "done", "skipped"}
                    or not isinstance(entry["priority"], str)
                    or entry["priority"] not in {"low", "medium", "high"}
                ):
                    _fail("project step state is invalid")
                if key == "blockers" and (
                    not isinstance(entry["status"], str)
                    or entry["status"] not in {"open", "resolved"}
                ):
                    _fail("project blocker state is invalid")
                if key == "open_questions" and (
                    not isinstance(entry["status"], str)
                    or entry["status"] not in {"open", "answered"}
                    or (
                        entry["answer"] is not None
                        and not isinstance(entry["answer"], str)
                    )
                ):
                    _fail("project question state is invalid")
                if key == "open_questions" and entry["answer"] is not None:
                    _text(
                        entry["answer"],
                        "project question answer",
                        limit=8192,
                        privacy=False,
                    )
                if key == "milestones" and (
                    not isinstance(entry["status"], str)
                    or entry["status"] not in {"planned", "reached", "dropped"}
                ):
                    _fail("project milestone state is invalid")
        session = item["last_session"]
        if session is not None:
            checked_session = _mapping(
                session, "project last session", {"at", "summary"}
            )
            _timestamp(checked_session["at"], "project session at")
            _text(
                checked_session["summary"],
                "project session summary",
                limit=8192,
                privacy=False,
            )
        return item

    def _scan_projects(self, observed_at: str) -> list[AmbientCandidate]:
        zone = self._open_zone("projects")
        candidates: list[AmbientCandidate] = []
        try:
            names = sorted(os.listdir(zone.fd), key=_portable)
            if len(names) > _MAX_FILES:
                _fail("projects namespace exceeds its bound")
            seen: set[str] = set()
            for name in names:
                portable = _portable(name)
                if portable in seen:
                    _fail("projects namespace has portable-name collisions")
                seen.add(portable)
                if name.startswith(".") or name in {"_archive", "_on_hold"}:
                    continue
                project_fd, identity = self._open_child(
                    zone.fd, name, f"{zone.relative}/{name}"
                )
                try:
                    record_file = self._read_at(
                        project_fd,
                        "project.json",
                        f"{zone.relative}/{name}/project.json",
                    )
                    state_file = self._read_at(
                        project_fd, "state.json", f"{zone.relative}/{name}/state.json"
                    )
                    record = self._project_record(
                        _decode(record_file.raw, "project record"), name
                    )
                    state = self._project_state(
                        _decode(state_file.raw, "project state"), str(record["slug"])
                    )
                    if record["status"] != "active":
                        continue
                    combined_hash = hashlib.sha256(
                        _canonical(
                            {
                                "project_sha256": record_file.sha256,
                                "state_sha256": state_file.sha256,
                            }
                        )
                    ).hexdigest()
                    project_ref = f"{zone.relative}/{name}"
                    eligible = _timestamp(record["updated_at"], "project updated_at")
                    for blocker in state["blockers"]:  # type: ignore[index]
                        assert isinstance(blocker, Mapping)
                        if blocker["status"] != "open":
                            continue
                        candidates.append(
                            self._make_candidate(
                                kind="project-blocked",
                                slot=f"project:{record['slug']}:blocker:{blocker['id']}",
                                source_ref=project_ref,
                                source_hash=combined_hash,
                                revision=int(state["revision"]),
                                priority="high",
                                eligible=eligible,
                                expires=None,
                                supersedes=None,
                                surface=self._resolver.config.surface,
                            )
                        )
                    for step in state["next_steps"]:  # type: ignore[index]
                        assert isinstance(step, Mapping)
                        if step["status"] != "open" or step["priority"] not in {
                            "low",
                            "medium",
                            "high",
                        }:
                            continue
                        candidates.append(
                            self._make_candidate(
                                kind="project-next-step",
                                slot=f"project:{record['slug']}:step:{step['id']}",
                                source_ref=project_ref,
                                source_hash=combined_hash,
                                revision=int(state["revision"]),
                                priority=str(step["priority"]),
                                eligible=eligible,
                                expires=None,
                                supersedes=None,
                                surface=self._resolver.config.surface,
                            )
                        )
                    self._revalidate_child(zone.fd, name, project_fd, identity)
                finally:
                    os.close(project_fd)
            self._revalidate_zone(zone)
            return candidates
        except OSError:
            raise AmbientFlowError(
                "projects namespace cannot be scanned safely"
            ) from None
        finally:
            os.close(zone.fd)

    @staticmethod
    def _entity_collection(
        value: object, expected_domain: str
    ) -> tuple[int, list[Mapping[str, object]]]:
        _text(expected_domain, "entity domain", limit=63, pattern=_PROJECT_SLUG)
        item = _mapping(
            value,
            "entity collection",
            {"schema_version", "domain", "revision", "entities"},
        )
        if (
            type(item["schema_version"]) is not int
            or item["schema_version"] != 1
            or item["domain"] != expected_domain
            or type(item["revision"]) is not int
            or not 0 <= int(item["revision"]) <= 2**31 - 1
            or not isinstance(item["entities"], list)
            or len(item["entities"]) > 1024
        ):
            _fail("entity collection violates its accepted schema")
        entities: list[Mapping[str, object]] = []
        keys = {
            "schema_version",
            "id",
            "domain",
            "title",
            "description",
            "status",
            "priority",
            "steps",
            "deadline",
            "next_review_at",
            "next_check",
            "escalation_paused_until",
            "created_at",
            "updated_at",
            "closed_at",
            "revision",
            "last_mutation_id",
            "last_mutation_sha256",
        }
        seen: set[str] = set()
        for raw in item["entities"]:
            entity = _mapping(raw, "entity record", keys)
            if (
                type(entity["schema_version"]) is not int
                or entity["schema_version"] != 1
                or entity["domain"] != expected_domain
                or not isinstance(entity["status"], str)
                or entity["status"] not in {"active", "closed", "dropped"}
                or not isinstance(entity["priority"], str)
                or entity["priority"] not in {"low", "medium", "high"}
                or type(entity["revision"]) is not int
                or not isinstance(entity["steps"], list)
            ):
                _fail("entity record violates its accepted schema")
            entity_id = _identifier(entity["id"], "entity id")
            portable = _portable(entity_id)
            if portable in seen:
                _fail("entity ids collide")
            seen.add(portable)
            _text(entity["title"], "entity title", limit=512, privacy=False)
            _text(
                entity["description"],
                "entity description",
                limit=8192,
                allow_empty=True,
                privacy=False,
            )
            steps = entity["steps"]
            if len(steps) > 256:
                _fail("entity steps exceed their bound")
            step_ids: set[str] = set()
            for raw_step in steps:
                step = _mapping(
                    raw_step,
                    "entity step",
                    {"schema_version", "id", "text", "status", "checked_at"},
                )
                if (
                    type(step["schema_version"]) is not int
                    or step["schema_version"] != 1
                    or not isinstance(step["status"], str)
                    or step["status"] not in {"open", "done", "skipped"}
                ):
                    _fail("entity step violates its accepted schema")
                step_id = _identifier(step["id"], "entity step id")
                if _portable(step_id) in step_ids:
                    _fail("entity step ids collide")
                step_ids.add(_portable(step_id))
                _text(step["text"], "entity step text", limit=4096, privacy=False)
                checked_at = step["checked_at"]
                if checked_at is not None:
                    _timestamp(checked_at, "entity step checked_at")
                if (step["status"] == "done") != (checked_at is not None):
                    _fail("entity step status disagrees with checked_at")
            for field in ("deadline", "next_review_at", "escalation_paused_until"):
                if entity[field] is not None:
                    AmbientFlow._temporal(entity[field], f"entity {field}")
            next_check = entity["next_check"]
            if next_check is not None:
                check = _mapping(
                    next_check,
                    "entity next check",
                    {"schema_version", "kind", "due_at", "interval_days"},
                )
                if (
                    type(check["schema_version"]) is not int
                    or check["schema_version"] != 1
                    or not isinstance(check["kind"], str)
                    or check["kind"] not in {"at", "after-update"}
                ):
                    _fail("entity next check violates its accepted schema")
                if check["kind"] == "at":
                    if check["due_at"] is None or check["interval_days"] is not None:
                        _fail("entity at check fields are invalid")
                    AmbientFlow._temporal(check["due_at"], "entity next check due")
                elif (
                    check["due_at"] is not None
                    or type(check["interval_days"]) is not int
                    or not 1 <= int(check["interval_days"]) <= 3650
                ):
                    _fail("entity interval check fields are invalid")
            created = _timestamp(entity["created_at"], "entity created_at")
            updated = _timestamp(entity["updated_at"], "entity updated_at")
            if _instant(updated) < _instant(created):
                _fail("entity updated_at precedes created_at")
            closed_at = entity["closed_at"]
            if closed_at is not None:
                _timestamp(closed_at, "entity closed_at")
            if (entity["status"] == "active") != (closed_at is None):
                _fail("entity closed_at disagrees with status")
            _identifier(entity["last_mutation_id"], "entity mutation id")
            _hash(entity["last_mutation_sha256"], "entity mutation hash")
            entities.append(entity)
        if [_portable(str(entity["id"])) for entity in entities] != sorted(
            _portable(str(entity["id"])) for entity in entities
        ):
            _fail("entity collection is not deterministically sorted")
        return int(item["revision"]), entities

    def _scan_memory(self, observed_at: str) -> list[AmbientCandidate]:
        zone = self._open_zone("agent/memory")
        candidates: list[AmbientCandidate] = []
        try:
            try:
                entities_fd, identity = self._open_child(
                    zone.fd, "entities", f"{zone.relative}/entities"
                )
            except AmbientFlowError:
                try:
                    os.stat("entities", dir_fd=zone.fd, follow_symlinks=False)
                except FileNotFoundError:
                    self._revalidate_zone(zone)
                    return []
                raise
            try:
                names = sorted(os.listdir(entities_fd), key=_portable)
                if len(names) > _MAX_FILES:
                    _fail("entity namespace exceeds its bound")
                seen_names: set[str] = set()
                for name in names:
                    portable_name = _portable(name)
                    if portable_name in seen_names:
                        _fail("entity namespace has portable-name collisions")
                    seen_names.add(portable_name)
                    if not name.endswith(".json"):
                        continue
                    source = self._read_at(
                        entities_fd, name, f"{zone.relative}/entities/{name}"
                    )
                    value = _decode(source.raw, "entity collection")
                    if source.raw != _canonical(value) + b"\n":
                        _fail("entity collection is not canonical JSON")
                    _collection_revision, entities = self._entity_collection(
                        value, name[:-5]
                    )
                    for entity in entities:
                        if entity["status"] != "active":
                            continue
                        paused = entity["escalation_paused_until"]
                        if paused is not None:
                            _, paused_at = self._temporal(paused, "entity pause")
                            if _instant(observed_at) < paused_at:
                                continue
                        due_values: list[datetime] = []
                        due_texts: list[str] = []
                        for field in ("deadline", "next_review_at"):
                            if entity[field] is not None:
                                text, instant = self._temporal(
                                    entity[field], f"entity {field}"
                                )
                                if instant <= _instant(observed_at):
                                    due_values.append(instant)
                                    due_texts.append(text)
                        next_check = entity["next_check"]
                        if next_check is not None:
                            check = _mapping(
                                next_check,
                                "entity next check",
                                {"schema_version", "kind", "due_at", "interval_days"},
                            )
                            if (
                                type(check["schema_version"]) is not int
                                or check["schema_version"] != 1
                                or not isinstance(check["kind"], str)
                                or check["kind"] not in {"at", "after-update"}
                            ):
                                _fail("entity next check is invalid")
                            if check["kind"] == "at":
                                text, instant = self._temporal(
                                    check["due_at"], "entity next check due"
                                )
                            else:
                                if (
                                    type(check["interval_days"]) is not int
                                    or not 1 <= int(check["interval_days"]) <= 3650
                                ):
                                    _fail("entity next check interval is invalid")
                                updated = _instant(
                                    _timestamp(
                                        entity["updated_at"], "entity updated_at"
                                    )
                                )
                                instant = updated + timedelta(
                                    days=int(check["interval_days"])
                                )
                                text = instant.isoformat(
                                    timespec="microseconds"
                                ).replace("+00:00", "Z")
                            if instant <= _instant(observed_at):
                                due_values.append(instant)
                                due_texts.append(text)
                        if not due_values:
                            continue
                        earliest_index = due_values.index(min(due_values))
                        candidates.append(
                            self._make_candidate(
                                kind="entity-due",
                                slot=f"entity:{entity['id']}",
                                source_ref=source.relative,
                                source_hash=source.sha256,
                                revision=int(entity["revision"]),
                                priority=self._raised_priority(
                                    str(entity["priority"]),
                                    overdue=due_values[earliest_index]
                                    < _instant(observed_at),
                                ),
                                eligible=due_texts[earliest_index],
                                expires=None,
                                supersedes=None,
                                surface=self._resolver.config.surface,
                            )
                        )
                self._revalidate_child(zone.fd, "entities", entities_fd, identity)
            finally:
                os.close(entities_fd)
            self._revalidate_zone(zone)
            return candidates
        except OSError:
            raise AmbientFlowError(
                "memory namespace cannot be scanned safely"
            ) from None
        finally:
            os.close(zone.fd)

    @staticmethod
    def _plan_feedback(raw: bytes) -> Mapping[str, object]:
        item = _mapping(
            _decode(raw, "plan feedback proposal"),
            "plan feedback proposal",
            {
                "schema_version",
                "proposal_id",
                "operation_id",
                "status",
                "created_at",
                "items",
            },
        )
        if (
            type(item["schema_version"]) is not int
            or item["schema_version"] != 1
            or item["status"] != "proposed"
            or not isinstance(item["items"], list)
            or not item["items"]
            or len(item["items"]) > 1024
        ):
            _fail("plan feedback proposal violates its accepted schema")
        _identifier(item["proposal_id"], "proposal_id")
        _identifier(item["operation_id"], "operation_id")
        _timestamp(item["created_at"], "proposal created_at")
        for raw_item in item["items"]:
            entry = _mapping(
                raw_item,
                "plan feedback item",
                {"task_id", "task_text", "feedback", "source_date"},
            )
            _identifier(entry["task_id"], "feedback task_id")
            _text(entry["task_text"], "feedback task text", limit=2048, privacy=False)
            _text(entry["feedback"], "feedback text", limit=4096, privacy=False)
            _date_text(entry["source_date"], "feedback source date")
        return item

    def _scan_review(self, observed_at: str) -> tuple[list[AmbientCandidate], int]:
        zone = self._open_zone("review")
        candidates: list[AmbientCandidate] = []
        debt = 0
        try:
            names = sorted(os.listdir(zone.fd), key=_portable)
            if len(names) > _MAX_FILES:
                _fail("review namespace exceeds its bound")
            seen: set[str] = set()
            total = 0
            for name in names:
                key = _portable(name)
                if key in seen:
                    _fail("review namespace has portable-name collisions")
                seen.add(key)
                if name.startswith("."):
                    continue
                try:
                    metadata = os.stat(name, dir_fd=zone.fd, follow_symlinks=False)
                except OSError:
                    _fail("review namespace cannot be inspected safely")
                if not stat.S_ISREG(metadata.st_mode):
                    _fail("review namespace contains an unsafe entry")
                source = self._read_at(zone.fd, name, f"{zone.relative}/{name}")
                total += len(source.raw)
                if total > _MAX_TOTAL:
                    _fail("review snapshot exceeds its byte bound")
                status: str | None = None
                proposal_id: str | None = None
                created_at: str | None = None
                surface = self._resolver.config.surface
                expires: str | None = None
                revision = 0
                if name.endswith(".md"):
                    try:
                        review = parse_review_artifact(source.raw)
                    except ReviewArtifactError:
                        _fail("review source violates the accepted review schema")
                    status, proposal_id, created_at, surface = (
                        review.status,
                        review.review_id,
                        review.created_at,
                        review.surface,
                    )
                    revision = len(review.decisions)
                elif name.endswith(".memory.json"):
                    try:
                        proposal = parse_memory_proposal(source.raw)
                    except MemoryFlowError:
                        _fail(
                            "review source violates the accepted memory proposal schema"
                        )
                    status, proposal_id, created_at = (
                        proposal.status,
                        proposal.proposal_id,
                        proposal.created_at,
                    )
                    revision = (
                        0
                        if proposal.human_decision is None
                        else proposal.human_decision.sequence
                    )
                    if proposal.decay.mode == "expires":
                        expires = proposal.decay.expires_at
                elif name.startswith("tasks-feedback-") and name.endswith(".json"):
                    proposal = self._plan_feedback(source.raw)
                    status = str(proposal["status"])
                    proposal_id = str(proposal["proposal_id"])
                    created_at = str(proposal["created_at"])
                else:
                    debt += 1
                    continue
                if status in {"approved", "rejected", "applied", "superseded"}:
                    continue
                if status != "proposed" or proposal_id is None or created_at is None:
                    _fail("review source status is invalid")
                if expires is None or _instant(expires) > _instant(observed_at):
                    debt += 1
                priority = {"silent": "low", "batched": "medium", "gated": "high"}[
                    surface
                ]
                candidates.append(
                    self._make_candidate(
                        kind="review-decision",
                        slot=f"review:{proposal_id}",
                        source_ref=source.relative,
                        source_hash=source.sha256,
                        revision=revision,
                        priority=priority,
                        eligible=created_at,
                        expires=expires,
                        supersedes=None,
                        surface=surface,
                    )
                )
            self._revalidate_zone(zone)
            return candidates, debt
        except OSError:
            raise AmbientFlowError(
                "review namespace cannot be scanned safely"
            ) from None
        finally:
            os.close(zone.fd)

    def _scan_all(self, request: AmbientRequest) -> tuple[list[AmbientCandidate], int]:
        task_candidates = self._scan_tasks(request.observed_at)
        project_candidates = self._scan_projects(request.observed_at)
        review_candidates, review_debt = self._scan_review(request.observed_at)
        memory_candidates = self._scan_memory(request.observed_at)
        candidates = [
            *task_candidates,
            *project_candidates,
            *review_candidates,
            *memory_candidates,
        ]
        if len(candidates) > _MAX_CANDIDATES:
            _fail("ambient candidate set exceeds its bound")
        if request.availability.status == "quiet":
            candidates = [
                self._make_candidate(
                    kind=item.kind,
                    slot=item.semantic_slot,
                    source_ref=item.source_ref,
                    source_hash=item.source_sha256,
                    revision=item.source_revision,
                    priority=item.priority,
                    eligible=item.eligible_at,
                    expires=item.expires_at,
                    supersedes=item.supersedes,
                    surface="batched" if item.surface == "gated" else item.surface,
                )
                for item in candidates
            ]
        return candidates, review_debt

    @staticmethod
    def _candidate_order(value: AmbientCandidate) -> tuple[object, ...]:
        expiry = value.expires_at or "9999-12-31T23:59:59Z"
        return (
            -_PRIORITIES.index(value.priority),
            expiry,
            value.eligible_at,
            _KIND_RANK[value.kind],
            _portable(value.semantic_slot),
            value.source_sha256,
        )

    def _select(
        self,
        candidates: Sequence[AmbientCandidate],
        *,
        observed_at: str,
        availability: str,
        debt: int,
        budget: AmbientReviewBudget,
    ) -> tuple[str, AmbientCandidate | None, tuple[AmbientDisposition, ...], str]:
        unique: dict[str, AmbientCandidate] = {}
        for candidate in candidates:
            prior = unique.get(candidate.candidate_id)
            if prior is not None and _candidate_payload(prior) != _candidate_payload(
                candidate
            ):
                _fail("ambient candidate id collision")
            unique[candidate.candidate_id] = candidate
        ordered_all = tuple(sorted(unique.values(), key=self._candidate_order))
        for candidate in ordered_all:
            if candidate.supersedes is None:
                continue
            if candidate.supersedes == candidate.candidate_id:
                _fail("ambient candidate cannot supersede itself")
            if candidate.supersedes not in unique:
                _fail("ambient candidate supersedes an unknown candidate")
        for candidate in ordered_all:
            seen: set[str] = set()
            current = candidate
            while current.supersedes is not None:
                if current.candidate_id in seen:
                    _fail("ambient candidate supersession cycle")
                seen.add(current.candidate_id)
                current = unique[current.supersedes]
        candidates_sha = hashlib.sha256(
            _canonical(
                {
                    "schema_version": 1,
                    "candidates": [_candidate_payload(item) for item in ordered_all],
                }
            )
        ).hexdigest()
        dispositions: dict[str, str] = {}
        active: list[AmbientCandidate] = []
        by_slot: dict[str, list[AmbientCandidate]] = {}
        for candidate in ordered_all:
            if candidate.expires_at is not None and _instant(
                candidate.expires_at
            ) <= _instant(observed_at):
                dispositions[candidate.candidate_id] = "expired"
                continue
            by_slot.setdefault(_portable(candidate.semantic_slot), []).append(candidate)
        for values in by_slot.values():
            winner = max(
                values,
                key=lambda item: (
                    item.source_revision,
                    item.eligible_at,
                    item.source_sha256,
                ),
            )
            active.append(winner)
            for item in values:
                if item.candidate_id != winner.candidate_id:
                    dispositions[item.candidate_id] = "superseded"
        explicit_targets = {
            candidate.supersedes
            for candidate in active
            if candidate.supersedes is not None
        }
        active = [
            candidate
            for candidate in active
            if candidate.candidate_id not in explicit_targets
        ]
        for target in explicit_targets:
            if target not in dispositions:
                dispositions[target] = "superseded"
        allowed: list[AmbientCandidate] = []
        for candidate in active:
            if debt >= budget.hard_limit:
                accepted = candidate.priority == "critical"
            elif debt >= budget.soft_limit:
                accepted = candidate.priority in {"high", "critical"}
            else:
                accepted = True
            if accepted:
                allowed.append(candidate)
            else:
                dispositions[candidate.candidate_id] = "review-backpressure"
        ranked = sorted(allowed, key=self._candidate_order)
        if not ranked:
            outcome = (
                "review-backpressure"
                if any(
                    reason == "review-backpressure" for reason in dispositions.values()
                )
                else "suppressed"
            )
            for candidate in ordered_all:
                dispositions.setdefault(candidate.candidate_id, "superseded")
            return (
                outcome,
                None,
                tuple(
                    AmbientDisposition(
                        item.candidate_id, dispositions[item.candidate_id]
                    )
                    for item in ordered_all
                ),
                candidates_sha,
            )
        selected = ranked[0]
        if availability == "unavailable":
            outcome = "availability-deferred"
            selected_result: AmbientCandidate | None = None
            for item in ranked:
                dispositions[item.candidate_id] = "availability-deferred"
        else:
            selected_result = selected
            if selected_result.surface == "silent":
                outcome = "intentional-silent"
                dispositions[selected.candidate_id] = "intentional-silent"
            else:
                outcome = "emitted"
                dispositions[selected.candidate_id] = "emitted"
            for item in ranked[1:]:
                dispositions[item.candidate_id] = "lower-ranked"
        for candidate in ordered_all:
            dispositions.setdefault(candidate.candidate_id, "lower-ranked")
        return (
            outcome,
            selected_result,
            tuple(
                AmbientDisposition(item.candidate_id, dispositions[item.candidate_id])
                for item in ordered_all
            ),
            candidates_sha,
        )

    def _artifacts_directory(self) -> tuple[_Zone, int, tuple[int, int]]:
        zone = self._open_zone("agent/outbox", for_write=True)
        try:
            try:
                os.mkdir("artifacts", mode=0o700, dir_fd=zone.fd)
                os.fsync(zone.fd)
            except FileExistsError:
                pass
            child, identity = self._open_child(zone.fd, "artifacts")
            self._revalidate_zone(zone, for_write=True)
            return zone, child, identity
        except (OSError, AmbientFlowError):
            os.close(zone.fd)
            raise AmbientFlowError(
                "ambient outbox artifacts directory is unsafe"
            ) from None

    def _publish_outbox_payload(
        self, *, name: str, relative_name: str, raw: bytes
    ) -> tuple[PreparedArtifact, bool]:
        _identifier(name, "artifact name")
        _text(
            relative_name[:-5],
            "artifact filename",
            limit=128,
            pattern=re.compile(r"^[a-z][a-z0-9_-]{0,127}$"),
        )
        if not raw or len(raw) > _MAX_EVIDENCE:
            _fail("ambient outbox payload is invalid")
        zone, artifacts_fd, identity = self._artifacts_directory()
        temporary = ".ambient-" + uuid.uuid4().hex + ".tmp"
        created = False
        try:
            output = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=artifacts_fd,
            )
            try:
                view = memoryview(raw)
                while view:
                    written = os.write(output, view)
                    if written < 1:
                        _fail("ambient outbox payload write stalled")
                    view = view[written:]
                os.fsync(output)
            finally:
                os.close(output)
            try:
                os.link(
                    temporary,
                    relative_name,
                    src_dir_fd=artifacts_fd,
                    dst_dir_fd=artifacts_fd,
                    follow_symlinks=False,
                )
                os.fsync(artifacts_fd)
                created = True
            except FileExistsError:
                existing = self._read_at(
                    artifacts_fd,
                    relative_name,
                    f"agent/outbox/artifacts/{relative_name}",
                    maximum=_MAX_EVIDENCE,
                )
                if existing.raw != raw:
                    _fail("ambient outbox replay disagrees with durable bytes")
            current = self._read_at(
                artifacts_fd,
                relative_name,
                f"agent/outbox/artifacts/{relative_name}",
                maximum=_MAX_EVIDENCE,
            )
            if current.raw != raw:
                _fail("ambient outbox payload changed after publication")
            self._revalidate_child(zone.fd, "artifacts", artifacts_fd, identity)
            self._revalidate_zone(zone, for_write=True)
        except (OSError, AmbientFlowError):
            raise AmbientFlowError(
                "ambient outbox payload cannot be published safely"
            ) from None
        finally:
            try:
                os.unlink(temporary, dir_fd=artifacts_fd)
            except (FileNotFoundError, OSError):
                pass
            os.close(artifacts_fd)
            os.close(zone.fd)
        digest = hashlib.sha256(raw).hexdigest()
        relative = f"artifacts/{relative_name}"
        state_ref = f"{self._resolver.config.zone('outbox').as_posix()}/{relative}"
        return PreparedArtifact(
            name, "agent/outbox", relative, state_ref, digest
        ), not created

    def _read_optional_outbox(
        self, relative: str, *, maximum: int = _MAX_EVIDENCE
    ) -> _File | None:
        checked = PurePosixPath(_safe_ref(relative, "outbox relative"))
        if checked.parts[0] != "artifacts" or len(checked.parts) != 2:
            _fail("ambient recovery reference is invalid")
        zone = self._open_zone("agent/outbox", for_write=True)
        try:
            try:
                child, identity = self._open_child(zone.fd, "artifacts")
            except AmbientFlowError:
                try:
                    os.stat("artifacts", dir_fd=zone.fd, follow_symlinks=False)
                except FileNotFoundError:
                    return None
                raise
            try:
                try:
                    result = self._read_at(
                        child,
                        checked.name,
                        f"{zone.relative}/{relative}",
                        maximum=maximum,
                    )
                except AmbientFlowError:
                    try:
                        os.stat(checked.name, dir_fd=child, follow_symlinks=False)
                    except FileNotFoundError:
                        return None
                    raise
                self._revalidate_child(zone.fd, "artifacts", child, identity)
                self._revalidate_zone(zone, for_write=True)
                return result
            finally:
                os.close(child)
        finally:
            os.close(zone.fd)

    def _read_ref(self, state_ref: str, *, maximum: int = _MAX_EVIDENCE) -> bytes:
        checked = PurePosixPath(_safe_ref(state_ref, "artifact reference"))
        prefixes = {
            "agent/outbox": self._resolver.config.zone("outbox"),
            "agent/runs": self._resolver.config.zone("runs"),
        }
        for symbolic, prefix in prefixes.items():
            try:
                suffix = checked.relative_to(prefix)
            except ValueError:
                continue
            zone = self._open_zone(symbolic, for_write=symbolic == "agent/outbox")
            current = zone.fd
            opened_children: list[tuple[int, int, str, tuple[int, int]]] = []
            try:
                for part in suffix.parts[:-1]:
                    parent = current
                    child, identity = self._open_child(parent, part)
                    opened_children.append((parent, child, part, identity))
                    current = child
                result = self._read_at(
                    current, suffix.name, state_ref, maximum=maximum
                ).raw
                for parent, child, part, identity in reversed(opened_children):
                    self._revalidate_child(parent, part, child, identity)
                self._revalidate_zone(zone, for_write=symbolic == "agent/outbox")
                return result
            finally:
                for _parent, fd, _part, _identity in reversed(opened_children):
                    os.close(fd)
                os.close(zone.fd)
        _fail("artifact reference is outside ambient recovery zones")

    @staticmethod
    def _marker_payload(
        *,
        request_sha: str,
        outcome: str,
        candidate_count: int,
        review_debt: int,
        candidates_sha: str,
        selected: AmbientCandidate,
        dispositions: Sequence[AmbientDisposition],
        payload: PreparedArtifact,
    ) -> dict[str, object]:
        return {
            "schema_version": 1,
            "kind": "ambient-operation",
            "request_sha256": request_sha,
            "outcome": outcome,
            "candidate_count": candidate_count,
            "review_debt": review_debt,
            "candidates_sha256": candidates_sha,
            "selected": _candidate_payload(selected),
            "dispositions": [_disposition_payload(item) for item in dispositions],
            "payload_ref": payload.state_ref,
            "payload_sha256": payload.sha256,
        }

    def _parse_marker(self, raw: bytes, request_sha: str) -> Mapping[str, object]:
        item = _mapping(
            _decode(raw, "ambient operation marker", maximum=_MAX_EVIDENCE),
            "ambient operation marker",
            {
                "schema_version",
                "kind",
                "request_sha256",
                "outcome",
                "candidate_count",
                "review_debt",
                "candidates_sha256",
                "selected",
                "dispositions",
                "payload_ref",
                "payload_sha256",
            },
        )
        if (
            type(item["schema_version"]) is not int
            or item["schema_version"] != 1
            or item["kind"] != "ambient-operation"
            or item["request_sha256"] != request_sha
            or item["outcome"] != "emitted"
        ):
            _fail("ambient operation marker conflicts with the request")
        selected = _parse_candidate(item["selected"])
        if not isinstance(item["dispositions"], list):
            _fail("ambient operation marker dispositions are invalid")
        dispositions = tuple(
            _parse_disposition(entry) for entry in item["dispositions"]
        )
        if (
            type(item["candidate_count"]) is not int
            or item["candidate_count"] != len(dispositions)
            or type(item["review_debt"]) is not int
        ):
            _fail("ambient operation marker counts are invalid")
        _hash(item["candidates_sha256"], "candidates_sha256")
        payload_ref = _safe_ref(item["payload_ref"], "payload_ref")
        payload_sha = _hash(item["payload_sha256"], "payload_sha256")
        if PurePosixPath(payload_ref).name != f"ambient-{payload_sha}.json":
            _fail("ambient operation payload name disagrees with its hash")
        payload_raw = self._read_ref(payload_ref)
        if hashlib.sha256(payload_raw).hexdigest() != payload_sha:
            _fail("ambient operation payload changed")
        payload_item = _mapping(
            _decode(payload_raw, "ambient nudge payload"),
            "ambient nudge payload",
            {
                "schema_version",
                "kind",
                "candidate_id",
                "candidate_kind",
                "priority",
                "eligible_at",
                "surface",
                "summary",
            },
        )
        if type(payload_item["schema_version"]) is not int:
            _fail("ambient operation payload schema is invalid")
        expected_payload = {
            "schema_version": 1,
            "kind": "ambient-nudge",
            "candidate_id": selected.candidate_id,
            "candidate_kind": selected.kind,
            "priority": selected.priority,
            "eligible_at": selected.eligible_at,
            "surface": selected.surface,
            "summary": selected.summary,
        }
        if dict(payload_item) != expected_payload:
            _fail("ambient operation payload disagrees with its marker")
        return {
            **item,
            "selected_record": selected,
            "disposition_records": dispositions,
            "payload_raw": payload_raw,
        }

    @staticmethod
    def _anchor_payload(
        *,
        operation_id: str,
        request_sha: str,
        marker: PreparedArtifact,
        payload: PreparedArtifact,
    ) -> dict[str, object]:
        return {
            "schema_version": 1,
            "kind": "ambient-pre-event-anchor",
            "operation_id": _identifier(operation_id, "operation_id"),
            "request_sha256": _hash(request_sha, "request_sha256"),
            "marker_ref": _safe_ref(marker.state_ref, "marker_ref"),
            "marker_sha256": _hash(marker.sha256, "marker_sha256"),
            "payload_ref": _safe_ref(payload.state_ref, "payload_ref"),
            "payload_sha256": _hash(payload.sha256, "payload_sha256"),
        }

    def _parse_anchor(
        self, raw: bytes, *, operation_id: str, request_sha: str
    ) -> Mapping[str, object]:
        item = _mapping(
            _decode(raw, "ambient pre-event anchor", maximum=_MAX_EVIDENCE),
            "ambient pre-event anchor",
            {
                "schema_version",
                "kind",
                "operation_id",
                "request_sha256",
                "marker_ref",
                "marker_sha256",
                "payload_ref",
                "payload_sha256",
            },
        )
        if (
            type(item["schema_version"]) is not int
            or item["schema_version"] != 1
            or item["kind"] != "ambient-pre-event-anchor"
            or item["operation_id"] != operation_id
            or item["request_sha256"] != request_sha
        ):
            _fail("ambient pre-event anchor conflicts with the request")
        marker_ref = _safe_ref(item["marker_ref"], "marker_ref")
        marker_sha = _hash(item["marker_sha256"], "marker_sha256")
        payload_ref = _safe_ref(item["payload_ref"], "payload_ref")
        payload_sha = _hash(item["payload_sha256"], "payload_sha256")
        token = hashlib.sha256(operation_id.encode()).hexdigest()
        if (
            PurePosixPath(marker_ref).name != f"ambient-op-{token[:32]}.json"
            or PurePosixPath(payload_ref).name != f"ambient-{payload_sha}.json"
        ):
            _fail("ambient pre-event anchor has invalid content-address bindings")
        return {
            **item,
            "marker_ref": marker_ref,
            "marker_sha256": marker_sha,
            "payload_ref": payload_ref,
            "payload_sha256": payload_sha,
        }

    def _commit_pre_event_anchor(
        self,
        *,
        snapshot,
        operation_id: str,
        request_sha: str,
        marker: PreparedArtifact,
        payload: PreparedArtifact,
        record_run_state: ActionCapability,
    ):
        anchor_name = _ambient_anchor_artifact_name(operation_id)
        anchor_raw = _canonical(
            self._anchor_payload(
                operation_id=operation_id,
                request_sha=request_sha,
                marker=marker,
                payload=payload,
            ),
            maximum=_MAX_EVIDENCE,
        )
        try:
            anchor = self._runs.prepare_run_artifact(
                str(snapshot.state["run_id"]),
                name=anchor_name,
                data=anchor_raw,
                maximum_bytes=_MAX_EVIDENCE,
            )
            self._runs.commit_step(
                str(snapshot.state["run_id"]),
                step_id=anchor_name,
                authority="internal-write",
                input_hash=request_sha,
                output_hash=anchor.sha256,
                next_phase="ambient-prepared",
                next_status="running",
                prepared_artifacts=(marker, payload, anchor),
                expected_state_sha256=snapshot.state_sha256,
                action_uses=(ActionUse(record_run_state),),
                authority_policy=self._policy,
            )
        except RunError as error:
            raise AmbientFlowError(str(error)) from None
        return self._run_snapshot(str(snapshot.state["run_id"]))

    def _anchored_recovery(
        self,
        *,
        snapshot,
        operation_id: str,
        request_sha: str,
    ) -> tuple[Mapping[str, object], PreparedArtifact, PreparedArtifact] | None:
        anchor_name = _ambient_anchor_artifact_name(operation_id)
        if not any(item.name == anchor_name for item in snapshot.artifacts):
            return None
        try:
            producer = self._runs.producer_snapshot(
                str(snapshot.state["run_id"]), producer_evidence=anchor_name
            )
        except RunError as error:
            raise AmbientFlowError(str(error)) from None
        artifacts = {item.name: item for item in producer.artifacts}
        anchor = artifacts.get(anchor_name)
        if anchor is None:
            _fail("ambient pre-event anchor is not committed")
        self._require_exact_anchor_trace(
            snapshot=snapshot,
            flow_id="ambient",
            request_sha=request_sha,
            anchor_name=anchor_name,
        )
        anchor_raw = self._read_ref(anchor.state_ref)
        anchor_data = self._parse_anchor(
            anchor_raw, operation_id=operation_id, request_sha=request_sha
        )
        token = hashlib.sha256(operation_id.encode()).hexdigest()
        marker_name = "ambient-marker-" + token[:24]
        payload_name = "ambient-payload-" + str(anchor_data["payload_sha256"])[:24]
        if set(artifacts) != {anchor_name, marker_name, payload_name}:
            _fail("ambient pre-event producer bundle is not exact")
        marker_committed = artifacts[marker_name]
        payload_committed = artifacts[payload_name]
        bindings = (
            (
                marker_committed,
                str(anchor_data["marker_ref"]),
                str(anchor_data["marker_sha256"]),
            ),
            (
                payload_committed,
                str(anchor_data["payload_ref"]),
                str(anchor_data["payload_sha256"]),
            ),
        )
        for artifact, state_ref, digest in bindings:
            if artifact.state_ref != state_ref or artifact.sha256 != digest:
                _fail("ambient pre-event artifact binding is invalid")
        marker = self._outbox_prepared(
            name=marker_name,
            state_ref=marker_committed.state_ref,
            sha256=marker_committed.sha256,
        )
        payload = self._outbox_prepared(
            name=payload_name,
            state_ref=payload_committed.state_ref,
            sha256=payload_committed.sha256,
        )
        marker_data = self._parse_marker(self._read_ref(marker.state_ref), request_sha)
        if (
            marker_data["payload_ref"] != payload.state_ref
            or marker_data["payload_sha256"] != payload.sha256
        ):
            _fail("ambient marker disagrees with its committed anchor")
        return marker_data, marker, payload

    def _prior_committed_recovery(
        self,
        *,
        snapshot,
        operation_id: str,
        request_sha: str,
    ) -> tuple[Mapping[str, object], PreparedArtifact, PreparedArtifact] | None:
        token = hashlib.sha256(operation_id.encode()).hexdigest()
        marker_relative = f"artifacts/ambient-op-{token[:32]}.json"
        marker_file = self._read_optional_outbox(marker_relative)
        if marker_file is None:
            return None
        marker_data = self._parse_marker(marker_file.raw, request_sha)
        selected = marker_data["selected_record"]
        if not isinstance(selected, AmbientCandidate):
            _fail("ambient prior marker has no selected candidate")
        payload_ref = str(marker_data["payload_ref"])
        payload_sha = str(marker_data["payload_sha256"])
        expected_urgency = {
            "low": "low",
            "medium": "normal",
            "high": "high",
            "critical": "critical",
        }[selected.priority]
        zone = self._open_zone("agent/outbox")
        matches: list[tuple[Mapping[str, object], _File]] = []
        try:
            names = sorted(os.listdir(zone.fd), key=_portable)
            if len(names) > _MAX_FILES:
                _fail("ambient recovery outbox namespace exceeds its bound")
            seen: set[str] = set()
            for name in names:
                portable = _portable(name)
                if portable in seen:
                    _fail(
                        "ambient recovery outbox namespace has portable-name collisions"
                    )
                seen.add(portable)
                if not name.endswith(".json"):
                    continue
                source = self._read_at(
                    zone.fd,
                    name,
                    f"{zone.relative}/{name}",
                    maximum=64 * 1024,
                )
                try:
                    event = validate_event(
                        _decode(source.raw, "ambient recovery event", maximum=64 * 1024)
                    )
                except (OutboxError, ValueError):
                    _fail("ambient recovery outbox event is invalid")
                if (
                    source.raw != self._event_raw(event)
                    or name != f"{event['event_id']}.json"
                ):
                    _fail("ambient recovery outbox event is not canonical")
                if (
                    event["flow_id"] == "ambient"
                    and event["type"] == "ambient_nudge"
                    and event["artifact_ref"] == payload_ref
                    and event["artifact_sha256"] == payload_sha
                    and event["summary"] == selected.summary
                    and event["urgency"] == expected_urgency
                    and event["delivery_policy"]["surface"] == selected.surface  # type: ignore[index]
                ):
                    matches.append((event, source))
            self._revalidate_zone(zone)
        except OSError:
            raise AmbientFlowError(
                "ambient prior event cannot be scanned safely"
            ) from None
        finally:
            os.close(zone.fd)
        if not matches:
            return None
        if len(matches) != 1:
            _fail("ambient prior event binding is ambiguous")
        event, event_source = matches[0]
        prior_run_id = str(event["run_id"])
        if prior_run_id == snapshot.state["run_id"]:
            _fail("ambient current-run event lacks its pre-event anchor")
        try:
            prior_snapshot = self._runs.snapshot(prior_run_id)
        except RunError as error:
            raise AmbientFlowError(str(error)) from None
        if (
            prior_snapshot.state.get("flow") != "ambient"
            or prior_snapshot.state.get("status") != "running"
            or prior_snapshot.state.get("authority") != "internal-write"
        ):
            _fail("ambient prior event run is invalid")
        replay = self._validate_replay_bundle(
            snapshot=prior_snapshot,
            evidence_name=ambient_evidence_artifact_name(operation_id),
            request_sha=request_sha,
            operation_id=operation_id,
        )
        if replay is None or replay.event_id != event["event_id"]:
            _fail("ambient prior event lacks exact committed producer evidence")
        try:
            producer = self._runs.producer_snapshot(
                prior_run_id,
                producer_evidence=ambient_evidence_artifact_name(operation_id),
            )
        except RunError as error:
            raise AmbientFlowError(str(error)) from None
        evidence_artifact = next(
            (
                item
                for item in producer.artifacts
                if item.name == ambient_evidence_artifact_name(operation_id)
            ),
            None,
        )
        if evidence_artifact is None:
            _fail("ambient prior evidence is missing")
        evidence = inspect_ambient_run_evidence(
            evidence_artifact, self._read_ref(evidence_artifact.state_ref)
        )
        dispositions = marker_data["disposition_records"]
        if (
            evidence.marker_ref
            != f"{self._resolver.config.zone('outbox').as_posix()}/{marker_relative}"
            or evidence.marker_sha256 != marker_file.sha256
            or evidence.payload_ref != payload_ref
            or evidence.payload_sha256 != payload_sha
            or evidence.event_ref != event_source.relative
            or evidence.event_sha256 != event_source.sha256
            or evidence.selected != selected
            or evidence.dispositions != dispositions
            or evidence.candidate_count != marker_data["candidate_count"]
            or evidence.review_debt != marker_data["review_debt"]
            or evidence.candidates_sha256 != marker_data["candidates_sha256"]
        ):
            _fail("ambient prior marker disagrees with committed evidence")
        marker = self._outbox_prepared(
            name="ambient-marker-" + token[:24],
            state_ref=str(evidence.marker_ref),
            sha256=str(evidence.marker_sha256),
        )
        payload = self._outbox_prepared(
            name="ambient-payload-" + payload_sha[:24],
            state_ref=payload_ref,
            sha256=payload_sha,
        )
        return marker_data, marker, payload

    def _outbox_prepared(
        self, *, name: str, state_ref: str, sha256: str
    ) -> PreparedArtifact:
        prefix = self._resolver.config.zone("outbox")
        try:
            relative = (
                PurePosixPath(_safe_ref(state_ref, "outbox state_ref"))
                .relative_to(prefix)
                .as_posix()
            )
        except ValueError:
            _fail("ambient outbox state_ref is invalid")
        raw = self._read_ref(state_ref)
        if hashlib.sha256(raw).hexdigest() != sha256:
            _fail("ambient durable outbox artifact changed")
        return PreparedArtifact(name, "agent/outbox", relative, state_ref, sha256)

    @staticmethod
    def _event_raw(event: Mapping[str, object]) -> bytes:
        return _canonical(dict(event), maximum=64 * 1024) + b"\n"

    def _publish_event(
        self,
        *,
        capability: ActionCapability,
        run_id: str,
        candidate: AmbientCandidate,
        payload: PreparedArtifact,
    ) -> tuple[Mapping[str, object], PreparedArtifact]:
        urgency = {
            "low": "low",
            "medium": "normal",
            "high": "high",
            "critical": "critical",
        }[candidate.priority]
        try:
            with OutboxStore(
                self._resolver,
                self._runs,
                policy=self._policy,
                clock=self._clock,
            ) as outbox:
                event = outbox.enqueue(
                    capability,
                    run_id=run_id,
                    event_type="ambient_nudge",
                    semantic_key=f"ambient:v1:{candidate.candidate_id}",
                    summary=candidate.summary,
                    artifact_zone="agent/outbox",
                    artifact_relative=payload.relative,
                    urgency=urgency,
                    surface=candidate.surface,
                    requires_receipt=True,
                )
        except OutboxError as error:
            raise AmbientFlowError(str(error)) from None
        event_raw = self._event_raw(event)
        event_id = _identifier(event.get("event_id"), "event_id")
        event_ref = f"{self._resolver.config.zone('outbox').as_posix()}/{event_id}.json"
        actual = self._read_ref(event_ref, maximum=64 * 1024)
        if actual != event_raw:
            _fail("ambient event bytes disagree with the outbox commit")
        digest = hashlib.sha256(event_raw).hexdigest()
        prepared = PreparedArtifact(
            "ambient-event-" + event_id.removeprefix("event_")[:24],
            "agent/outbox",
            f"{event_id}.json",
            event_ref,
            digest,
        )
        return event, prepared

    def _commit_evidence(
        self,
        *,
        snapshot,
        evidence: AmbientRunEvidence,
        evidence_raw: bytes,
        external: Sequence[PreparedArtifact],
        grants: Sequence[ActionCapability],
        hooks: AmbientCrashHooks,
    ) -> AmbientResult:
        try:
            evidence_artifact = self._runs.prepare_run_artifact(
                evidence.run_id,
                name=ambient_evidence_artifact_name(evidence.operation_id),
                data=evidence_raw,
                maximum_bytes=_MAX_EVIDENCE,
            )
        except RunError as error:
            raise AmbientFlowError(str(error)) from None
        if hooks.after_evidence_prepare is not None:
            hooks.after_evidence_prepare()
        uses = tuple(
            grants if evidence.outcome == "emitted" else (*grants[:4], grants[5])
        )
        token = hashlib.sha256(evidence.operation_id.encode()).hexdigest()[:32]
        try:
            self._runs.commit_step(
                evidence.run_id,
                step_id=f"ambient-{token}",
                authority="internal-write",
                input_hash=evidence.request_sha256,
                output_hash=evidence_artifact.sha256,
                next_phase="ambient-committed",
                next_status="running",
                prepared_artifacts=(*external, evidence_artifact),
                expected_state_sha256=snapshot.state_sha256,
                action_uses=tuple(ActionUse(item) for item in uses),
                authority_policy=self._policy,
                after_prepare=hooks.after_run_intent,
                after_state=hooks.after_run_state,
                after_trace=hooks.after_run_trace,
            )
        except RunError as error:
            raise AmbientFlowError(str(error)) from None
        return AmbientResult(
            evidence.outcome,
            evidence.event_id,
            evidence_artifact.name,
            None if evidence.selected is None else evidence.selected.candidate_id,
            False,
        )

    def _require_exact_committed_trace(
        self,
        *,
        snapshot,
        flow_id: str,
        step_id: str,
        input_hash: str,
        output_hash: str,
        action_ids: Sequence[str],
    ) -> None:
        try:
            traces = self._runs.trace_events(str(snapshot.state["run_id"]))
        except RunError as error:
            raise AmbientFlowError(str(error)) from None
        matches = tuple(trace for trace in traces if trace.get("step_id") == step_id)
        if len(matches) != 1:
            _fail("committed replay requires exactly one expected producer trace")
        trace = matches[0]
        if (
            trace.get("schema_version") != 2
            or trace.get("run_id") != snapshot.state.get("run_id")
            or trace.get("authority") != "internal-write"
            or trace.get("input_hash") != input_hash
            or trace.get("output_hash") != output_hash
            or trace.get("executor_profile") != snapshot.state.get("executor")
            or trace.get("tool_outcomes") != []
        ):
            _fail("committed replay producer trace is not exact")
        actions = trace.get("actions")
        if not isinstance(actions, list) or len(actions) != len(action_ids):
            _fail("committed replay action trace is not exact")
        actual = tuple(
            (
                action.get("sequence"),
                action.get("flow_id"),
                action.get("action_id"),
                action.get("status"),
            )
            if isinstance(action, Mapping)
            else None
            for action in actions
        )
        expected = tuple(
            (sequence, flow_id, action_id, "succeeded")
            for sequence, action_id in enumerate(action_ids, start=1)
        )
        if actual != expected:
            _fail("committed replay action trace is not exact")

    def _require_exact_anchor_trace(
        self,
        *,
        snapshot,
        flow_id: str,
        request_sha: str,
        anchor_name: str,
    ) -> None:
        anchors = tuple(
            artifact for artifact in snapshot.artifacts if artifact.name == anchor_name
        )
        if len(anchors) != 1 or anchors[0].step_id != anchor_name:
            _fail("committed replay pre-event anchor is not exact")
        self._require_exact_committed_trace(
            snapshot=snapshot,
            flow_id=flow_id,
            step_id=anchor_name,
            input_hash=request_sha,
            output_hash=anchors[0].sha256,
            action_ids=("record-run-state",),
        )

    def _validate_replay_bundle(
        self,
        *,
        snapshot,
        evidence_name: str,
        request_sha: str,
        operation_id: str,
    ) -> AmbientResult | None:
        existing = next(
            (item for item in snapshot.artifacts if item.name == evidence_name), None
        )
        if existing is None:
            return None
        try:
            bundle = self._runs.producer_snapshot(
                snapshot.state["run_id"], producer_evidence=evidence_name
            )
        except RunError as error:
            raise AmbientFlowError(str(error)) from None
        artifacts = {item.name: item for item in bundle.artifacts}
        committed = artifacts.get(evidence_name)
        if committed is None:
            _fail("ambient replay lacks committed evidence")
        evidence = inspect_ambient_run_evidence(
            committed, self._read_ref(committed.state_ref)
        )
        if (
            evidence.request_sha256 != request_sha
            or evidence.operation_id != operation_id
            or evidence.run_id != snapshot.state["run_id"]
        ):
            _fail("ambient replay conflicts with the request")
        final_actions = (
            (
                "scan-eligible-signals",
                "read-ambient-projects",
                "read-ambient-review",
                "read-ambient-memory",
                "commit-nudge-outbox-event",
                "record-run-state",
            )
            if evidence.outcome == "emitted"
            else (
                "scan-eligible-signals",
                "read-ambient-projects",
                "read-ambient-review",
                "read-ambient-memory",
                "record-run-state",
            )
        )
        self._require_exact_committed_trace(
            snapshot=snapshot,
            flow_id="ambient",
            step_id=f"ambient-{hashlib.sha256(operation_id.encode()).hexdigest()[:32]}",
            input_hash=request_sha,
            output_hash=committed.sha256,
            action_ids=final_actions,
        )
        expected = {evidence_name}
        if evidence.outcome == "emitted":
            self._require_exact_anchor_trace(
                snapshot=snapshot,
                flow_id="ambient",
                request_sha=request_sha,
                anchor_name=_ambient_anchor_artifact_name(operation_id),
            )
            assert (
                evidence.marker_ref is not None and evidence.marker_sha256 is not None
            )
            assert (
                evidence.payload_ref is not None and evidence.payload_sha256 is not None
            )
            assert (
                evidence.event_ref is not None
                and evidence.event_sha256 is not None
                and evidence.event_id is not None
            )
            marker_name = (
                "ambient-marker-"
                + hashlib.sha256(operation_id.encode()).hexdigest()[:24]
            )
            payload_name = "ambient-payload-" + evidence.payload_sha256[:24]
            event_name = (
                "ambient-event-" + evidence.event_id.removeprefix("event_")[:24]
            )
            expected.update({marker_name, payload_name, event_name})
            bindings = (
                (marker_name, evidence.marker_ref, evidence.marker_sha256),
                (payload_name, evidence.payload_ref, evidence.payload_sha256),
                (event_name, evidence.event_ref, evidence.event_sha256),
            )
            for name, state_ref, digest in bindings:
                artifact = artifacts.get(name)
                if (
                    artifact is None
                    or artifact.state_ref != state_ref
                    or artifact.sha256 != digest
                    or hashlib.sha256(self._read_ref(state_ref)).hexdigest() != digest
                ):
                    _fail("ambient replay outbox binding is invalid")
        if set(artifacts) != expected:
            _fail("ambient replay producer bundle is not exact")
        return AmbientResult(
            evidence.outcome,
            evidence.event_id,
            evidence_name,
            None if evidence.selected is None else evidence.selected.candidate_id,
            True,
        )

    def _prepared_evidence(
        self, *, run_id: str, evidence_name: str, request_sha: str, operation_id: str
    ) -> tuple[AmbientRunEvidence, bytes] | None:
        state_ref = f"{self._resolver.config.zone('runs').as_posix()}/{run_id}/{evidence_name}.json"
        try:
            raw = self._read_ref(state_ref)
        except AmbientFlowError:
            path = self._root_path / PurePosixPath(state_ref)
            try:
                os.stat(path, follow_symlinks=False)
            except FileNotFoundError:
                return None
            except OSError:
                _fail("ambient prepared evidence cannot be inspected")
            raise
        evidence = parse_ambient_run_evidence(raw)
        if (
            evidence.run_id != run_id
            or evidence.operation_id != operation_id
            or evidence.request_sha256 != request_sha
        ):
            _fail("ambient prepared evidence conflicts with the request")
        return evidence, raw

    def _commit_recomputed_prepared(
        self,
        *,
        snapshot,
        evidence: AmbientRunEvidence,
        raw: bytes,
        grants: Sequence[ActionCapability],
        hooks: AmbientCrashHooks,
    ) -> AmbientResult:
        if evidence.run_state_sha256 != snapshot.state_sha256:
            _fail("ambient prepared evidence has a stale run precondition")
        if evidence.outcome == "emitted":
            _fail("ambient emitted recovery requires a committed pre-event anchor")
        result = self._commit_evidence(
            snapshot=snapshot,
            evidence=evidence,
            evidence_raw=raw,
            external=(),
            grants=grants,
            hooks=hooks,
        )
        return AmbientResult(
            result.outcome,
            result.event_id,
            result.evidence_artifact,
            result.selected_candidate_id,
            True,
        )

    def _verified_sources(
        self,
        request: AmbientRequest,
        hooks: AmbientCrashHooks,
    ) -> tuple[list[AmbientCandidate], int]:
        with self._source_identity_snapshot() as source_identities:
            candidates, review_debt = self._scan_all(request)
        identity_manifest = self._identity_manifest(source_identities)
        if hooks.after_source_read is not None:
            hooks.after_source_read()
        with self._source_identity_snapshot() as verified_source_identities:
            verified_candidates, verified_debt = self._scan_all(request)
        verified_identity_manifest = self._identity_manifest(verified_source_identities)
        if (
            identity_manifest != verified_identity_manifest
            or review_debt != verified_debt
            or [
                _candidate_payload(item)
                for item in sorted(candidates, key=self._candidate_order)
            ]
            != [
                _candidate_payload(item)
                for item in sorted(verified_candidates, key=self._candidate_order)
            ]
        ):
            _fail("ambient sources changed after the bounded snapshot")
        return candidates, review_debt

    def scan(
        self,
        capabilities: AmbientCapabilities,
        *,
        run_id: str,
        request: AmbientRequest,
        crash_hooks: AmbientCrashHooks | None = None,
    ) -> AmbientResult:
        grants = self._require_capabilities(capabilities)
        self._check_root()
        request_data = _request_payload(request)
        request_raw = _canonical(request_data)
        request_sha = hashlib.sha256(request_raw).hexdigest()
        checked_run = _run_id(run_id)
        snapshot = self._run_snapshot(checked_run)
        hooks = crash_hooks or AmbientCrashHooks()
        if not isinstance(hooks, AmbientCrashHooks) or any(
            value is not None and not callable(value)
            for value in hooks.__dict__.values()
        ):
            _fail("ambient crash hooks are invalid")
        evidence_name = ambient_evidence_artifact_name(request.operation_id)
        replay = self._validate_replay_bundle(
            snapshot=snapshot,
            evidence_name=evidence_name,
            request_sha=request_sha,
            operation_id=request.operation_id,
        )
        if replay is not None:
            return replay
        prepared = self._prepared_evidence(
            run_id=checked_run,
            evidence_name=evidence_name,
            request_sha=request_sha,
            operation_id=request.operation_id,
        )
        token = hashlib.sha256(request.operation_id.encode()).hexdigest()
        anchored = self._anchored_recovery(
            snapshot=snapshot,
            operation_id=request.operation_id,
            request_sha=request_sha,
        )
        if anchored is None:
            anchored = self._prior_committed_recovery(
                snapshot=snapshot,
                operation_id=request.operation_id,
                request_sha=request_sha,
            )
        if anchored is not None:
            if prepared is not None and prepared[0].outcome != "emitted":
                _fail("ambient prepared evidence conflicts with its committed anchor")
            marker_data, marker_artifact, payload = anchored
            selected = marker_data["selected_record"]
            dispositions = marker_data["disposition_records"]
            assert isinstance(selected, AmbientCandidate) and isinstance(
                dispositions, tuple
            )
            event, event_artifact = self._publish_event(
                capability=grants[4],
                run_id=checked_run,
                candidate=selected,
                payload=payload,
            )
            if hooks.after_event_publish is not None:
                hooks.after_event_publish()
            event_raw = self._event_raw(event)
            evidence = AmbientRunEvidence(
                checked_run,
                request.operation_id,
                request_sha,
                snapshot.state_sha256,
                "emitted",
                int(marker_data["candidate_count"]),
                int(marker_data["review_debt"]),
                str(marker_data["candidates_sha256"]),
                selected,
                dispositions,
                marker_artifact.state_ref,
                marker_artifact.sha256,
                payload.state_ref,
                payload.sha256,
                event_artifact.state_ref,
                hashlib.sha256(event_raw).hexdigest(),
                str(event["event_id"]),
            )
            raw = render_ambient_run_evidence(evidence)
            result = self._commit_evidence(
                snapshot=snapshot,
                evidence=evidence,
                evidence_raw=raw,
                external=(marker_artifact, payload, event_artifact),
                grants=grants,
                hooks=hooks,
            )
            return AmbientResult(
                result.outcome,
                result.event_id,
                result.evidence_artifact,
                result.selected_candidate_id,
                True,
            )

        if prepared is not None and prepared[0].outcome == "emitted":
            _fail("ambient emitted recovery requires a committed pre-event anchor")
        candidates, review_debt = self._verified_sources(request, hooks)
        if not candidates:
            outcome, selected, dispositions = "zero", None, ()
            candidates_sha = hashlib.sha256(
                _canonical({"schema_version": 1, "candidates": []})
            ).hexdigest()
        else:
            outcome, selected, dispositions, candidates_sha = self._select(
                candidates,
                observed_at=request.observed_at,
                availability=request.availability.status,
                debt=review_debt,
                budget=request.review_budget,
            )
        if prepared is not None:
            if outcome == "emitted":
                _fail("ambient prepared evidence disagrees with recomputed sources")
            recomputed = AmbientRunEvidence(
                checked_run,
                request.operation_id,
                request_sha,
                snapshot.state_sha256,
                outcome,
                len(candidates),
                review_debt,
                candidates_sha,
                selected,
                dispositions,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            )
            recomputed_raw = render_ambient_run_evidence(recomputed)
            if prepared[0] != recomputed or prepared[1] != recomputed_raw:
                _fail("ambient prepared evidence disagrees with recomputed sources")
            return self._commit_recomputed_prepared(
                snapshot=snapshot,
                evidence=recomputed,
                raw=recomputed_raw,
                grants=grants,
                hooks=hooks,
            )
        marker_artifact: PreparedArtifact | None = None
        payload_artifact: PreparedArtifact | None = None
        event_artifact: PreparedArtifact | None = None
        event: Mapping[str, object] | None = None
        if outcome == "emitted":
            assert selected is not None
            payload_raw = _canonical(
                {
                    "schema_version": 1,
                    "kind": "ambient-nudge",
                    "candidate_id": selected.candidate_id,
                    "candidate_kind": selected.kind,
                    "priority": selected.priority,
                    "eligible_at": selected.eligible_at,
                    "surface": selected.surface,
                    "summary": selected.summary,
                }
            )
            payload_sha = hashlib.sha256(payload_raw).hexdigest()
            payload_artifact, _ = self._publish_outbox_payload(
                name="ambient-payload-" + payload_sha[:24],
                relative_name=f"ambient-{payload_sha}.json",
                raw=payload_raw,
            )
            marker_raw = _canonical(
                self._marker_payload(
                    request_sha=request_sha,
                    outcome=outcome,
                    candidate_count=len(candidates),
                    review_debt=review_debt,
                    candidates_sha=candidates_sha,
                    selected=selected,
                    dispositions=dispositions,
                    payload=payload_artifact,
                ),
                maximum=_MAX_EVIDENCE,
            )
            marker_artifact, _ = self._publish_outbox_payload(
                name="ambient-marker-" + token[:24],
                relative_name=f"ambient-op-{token[:32]}.json",
                raw=marker_raw,
            )
            snapshot = self._commit_pre_event_anchor(
                snapshot=snapshot,
                operation_id=request.operation_id,
                request_sha=request_sha,
                marker=marker_artifact,
                payload=payload_artifact,
                record_run_state=grants[5],
            )
            if hooks.after_payload_prepare is not None:
                hooks.after_payload_prepare()
            event, event_artifact = self._publish_event(
                capability=grants[4],
                run_id=checked_run,
                candidate=selected,
                payload=payload_artifact,
            )
            if hooks.after_event_publish is not None:
                hooks.after_event_publish()
        evidence = AmbientRunEvidence(
            checked_run,
            request.operation_id,
            request_sha,
            snapshot.state_sha256,
            outcome,
            len(candidates),
            review_debt,
            candidates_sha,
            selected,
            dispositions,
            None if marker_artifact is None else marker_artifact.state_ref,
            None if marker_artifact is None else marker_artifact.sha256,
            None if payload_artifact is None else payload_artifact.state_ref,
            None if payload_artifact is None else payload_artifact.sha256,
            None if event_artifact is None else event_artifact.state_ref,
            None if event_artifact is None else event_artifact.sha256,
            None if event is None else str(event["event_id"]),
        )
        evidence_raw = render_ambient_run_evidence(evidence)
        external = tuple(
            item
            for item in (marker_artifact, payload_artifact, event_artifact)
            if item is not None
        )
        return self._commit_evidence(
            snapshot=snapshot,
            evidence=evidence,
            evidence_raw=evidence_raw,
            external=external,
            grants=grants,
            hooks=hooks,
        )
