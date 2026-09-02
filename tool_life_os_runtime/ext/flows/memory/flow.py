"""Proposal-only semantic memory and deterministic metadata lifecycle.

Semantic text is allowed only in review proposals backed by primary human
evidence.  The only direct domain writes are prose-free metadata records and
verifiable forget outcomes under ``agent/memory/metadata``.
"""

from __future__ import annotations

from contextlib import contextmanager
import ctypes
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
import errno
import fcntl
import hashlib
import json
import os
from pathlib import PurePosixPath
import re
import stat
import sys
from typing import Callable, Iterator, Mapping, Sequence
import unicodedata
import uuid

from tool_life_os_runtime.ext.review.authority import (
    ActionCapability,
    AuthorityError,
    AuthorityPolicy,
)
from tool_life_os_runtime.ext.runs import (
    ActionUse,
    CommittedArtifact,
    PreparedArtifact,
    RunError,
    RunStore,
)
from tool_life_os_runtime.ext.vault.schema import VaultPathResolver, VaultSchemaError


MEMORY_SCHEMA_VERSION = 1

_MAX_JSON = 512 * 1024
_MAX_PROPOSAL = 512 * 1024
_MAX_METADATA = 128 * 1024
_MAX_TEXT = 32 * 1024
_MAX_EVIDENCE = 64
_MAX_RECORDS = 2048
_MAX_DEPTH = 16
_MAX_ENTRIES = 4096
_ID = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
_MEMORY_ID = re.compile(r"^mem-[a-z0-9][a-z0-9_-]{0,58}$")
_PROPOSAL_ID = re.compile(r"^memprop-[a-z0-9][a-z0-9_-]{0,54}$")
_FORGET_ID = re.compile(r"^forget-[a-z0-9][a-z0-9_-]{0,55}$")
_REPORT_ID = re.compile(r"^rpt-[a-z0-9][a-z0-9_-]{0,58}$")
_DONE_ID = re.compile(r"^done-[a-z0-9][a-z0-9_-]{0,57}$")
_ENTITY_ID = re.compile(r"^ent-[a-z0-9][a-z0-9_-]{0,58}$")
_RUN_ID = re.compile(r"^run_[a-z0-9][a-z0-9_-]{0,62}$")
_SHA = re.compile(r"^[0-9a-f]{64}$")
_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$")
_DAY = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_MEMORY_KINDS = frozenset(
    {"persona", "decision", "feedback", "workflow", "toolbox", "episodic", "entity-fact"}
)
_PROPOSAL_OPERATIONS = frozenset({"create", "update", "retain", "decay", "delete", "forget"})
_PROPOSAL_STATUSES = frozenset({"proposed", "approved", "rejected", "superseded"})
_METADATA_STATUSES = frozenset({"active", "stale", "forgotten", "deleted"})
_PRIMARY_KINDS = frozenset(
    {
        "daily-human-entry",
        "task-feedback",
        "project-human-log",
        "confirmed-done-event",
        "reading-human-note",
        "human-correction",
    }
)
_ARCHIVES = frozenset({"_archive", "_trash", "_on_hold"})


class MemoryFlowError(ValueError):
    """Memory input, evidence, authority, or recovery state is invalid."""


def _fail(message: str) -> None:
    raise MemoryFlowError(message)


def _portable(value: str) -> str:
    try:
        value.encode("utf-8")
    except UnicodeError:
        _fail("memory namespace is not portable")
    if unicodedata.normalize("NFC", value) != value or any(
        unicodedata.category(char).startswith("C")
        or unicodedata.category(char) in {"Zl", "Zp"}
        for char in value
    ):
        _fail("memory namespace is not portable")
    return value.casefold()


def _text(value: object, label: str, maximum: int = 4096, *, layout: bool = False) -> str:
    if type(value) is not str or not value or len(value) > maximum:
        _fail(f"{label} is invalid")
    try:
        value.encode("utf-8")
    except UnicodeError:
        _fail(f"{label} is invalid")
    if unicodedata.normalize("NFC", value) != value or any(
        unicodedata.category(char).startswith("C")
        and not (layout and char in "\n\t")
        or unicodedata.category(char) in {"Zl", "Zp"}
        for char in value
    ):
        _fail(f"{label} is invalid")
    lowered = value.casefold()
    if "/users/" in lowered or "/home/" in lowered or "file:" in lowered:
        _fail(f"{label} contains a private path")
    return value


def _identifier(value: object, label: str, pattern: re.Pattern[str] = _ID) -> str:
    checked = _text(value, label, 128)
    if pattern.fullmatch(checked) is None:
        _fail(f"{label} is invalid")
    return checked


def _timestamp(value: object, label: str) -> str:
    checked = _text(value, label, 40)
    if _UTC.fullmatch(checked) is None:
        _fail(f"{label} must be UTC")
    try:
        datetime.fromisoformat(checked[:-1] + "+00:00")
    except ValueError:
        _fail(f"{label} must be UTC")
    return checked


def _instant(value: str) -> datetime:
    return datetime.fromisoformat(value[:-1] + "+00:00")


def _hash(value: object, label: str) -> str:
    checked = _text(value, label, 64)
    if _SHA.fullmatch(checked) is None:
        _fail(f"{label} is invalid")
    return checked


def _exact_int(value: object, label: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        _fail(f"{label} is invalid")
    return value


def _safe_ref(
    value: object,
    label: str,
    *,
    memory: bool = False,
    allow_archive: bool = False,
) -> str:
    checked = _text(value, label, 2048)
    if "\\" in checked:
        _fail(f"{label} is invalid")
    path = PurePosixPath(checked)
    if path.is_absolute() or path == PurePosixPath(".") or ".." in path.parts:
        _fail(f"{label} is invalid")
    if path.as_posix() != checked or (
        not allow_archive
        and any(_portable(part) in _ARCHIVES for part in path.parts)
    ):
        _fail(f"{label} is invalid")
    if memory:
        if len(path.parts) < 2 or path.parts[:2] != ("agent", "memory"):
            _fail(f"{label} must be inside agent/memory")
        if len(path.parts) < 3 or _portable(path.parts[2]) in {"metadata", "entities", "trails"}:
            _fail(f"{label} must name semantic memory")
    return checked


def _canonical(value: object, maximum: int = _MAX_JSON) -> bytes:
    try:
        raw = (
            json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
            + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError):
        _fail("memory payload is not canonical JSON")
    if len(raw) > maximum:
        _fail("memory payload is too large")
    return raw


def _pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            _fail("memory JSON has duplicate fields")
        result[key] = value
    return result


def _decode(raw: bytes | str, label: str, maximum: int) -> object:
    if isinstance(raw, str):
        try:
            data = raw.encode("utf-8")
        except UnicodeError:
            _fail(f"{label} is invalid")
    elif isinstance(raw, bytes):
        data = raw
    else:
        _fail(f"{label} is invalid")
    if not data or len(data) > maximum:
        _fail(f"{label} is invalid")
    try:
        return json.loads(data, object_pairs_hook=_pairs)
    except MemoryFlowError:
        raise
    except (UnicodeError, ValueError, RecursionError):
        _fail(f"{label} is invalid")


def _mapping(value: object, label: str, keys: frozenset[str]) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or set(value) != keys:
        _fail(f"{label} has missing or unknown fields")
    return value


@dataclass(frozen=True)
class RetentionPolicy:
    mode: str
    review_at: str | None = None
    retain_until: str | None = None
    schema_version: int = MEMORY_SCHEMA_VERSION


@dataclass(frozen=True)
class DecayPolicy:
    mode: str
    stale_after_days: int | None = None
    expires_at: str | None = None
    schema_version: int = MEMORY_SCHEMA_VERSION


@dataclass(frozen=True)
class DeletionPolicy:
    mode: str
    archive_ref: str | None = None
    schema_version: int = MEMORY_SCHEMA_VERSION


@dataclass(frozen=True)
class MemoryEvidence:
    evidence_id: str
    source_kind: str
    source_ref: str
    source_sha256: str
    anchor: str
    actor: str
    occurred_at: str
    exact_text: str
    schema_version: int = MEMORY_SCHEMA_VERSION


@dataclass(frozen=True)
class HumanProposalDecision:
    action: str
    actor: str
    at: str
    sequence: int = 1
    superseded_by: str | None = None
    schema_version: int = MEMORY_SCHEMA_VERSION


@dataclass(frozen=True)
class MemoryProposalRecord:
    proposal_id: str
    status: str
    operation: str
    memory_id: str
    memory_kind: str
    scope: str
    candidate_text: str
    evidence: tuple[MemoryEvidence, ...]
    current_memory_ref: str | None
    current_memory_sha256: str | None
    precondition_sha256: str | None
    retention: RetentionPolicy
    decay: DecayPolicy
    deletion: DeletionPolicy
    producer_flow: str
    run_id: str
    operation_id: str
    created_at: str
    human_decision: HumanProposalDecision | None = None
    schema_version: int = MEMORY_SCHEMA_VERSION


@dataclass(frozen=True)
class EvidenceBinding:
    evidence_id: str
    source_sha256: str


@dataclass(frozen=True)
class MemoryMetadataRecord:
    memory_id: str
    semantic_ref: str
    semantic_sha256: str
    memory_kind: str
    scope: str
    evidence: tuple[EvidenceBinding, ...]
    proposal_id: str
    created_at: str
    last_confirmed_at: str
    retention: RetentionPolicy
    decay: DecayPolicy
    deletion: DeletionPolicy
    status: str
    revision: int
    last_operation_id: str
    last_operation_sha256: str
    schema_version: int = MEMORY_SCHEMA_VERSION


@dataclass(frozen=True)
class MemoryHygieneQuery:
    as_of: str
    threshold_days: int
    kinds: tuple[str, ...] = ()
    limit: int = 256
    schema_version: int = MEMORY_SCHEMA_VERSION


@dataclass(frozen=True)
class StaleMemory:
    metadata: MemoryMetadataRecord
    reasons: tuple[str, ...]
    stale_since: str


@dataclass(frozen=True)
class ForgetRequest:
    outcome_id: str
    memory_id: str
    proposal_id: str
    verified_at: str
    schema_version: int = MEMORY_SCHEMA_VERSION


@dataclass(frozen=True)
class ForgetOutcome:
    outcome_id: str
    memory_id: str
    proposal_id: str
    verification: str
    semantic_ref: str | None
    prior_semantic_sha256: str | None
    verified_at: str
    metadata_sha256: str | None
    schema_version: int = MEMORY_SCHEMA_VERSION


@dataclass(frozen=True)
class MemoryMutationResult:
    operation_id: str
    operation: str
    proposal_ref: str | None
    metadata: MemoryMetadataRecord | None
    forget_outcome: ForgetOutcome | None
    replayed: bool
    output_sha256: str
    schema_version: int = MEMORY_SCHEMA_VERSION


@dataclass(frozen=True)
class MemoryRunEvidence:
    operation_id: str
    operation: str
    output_ref: str
    request_sha256: str
    run_state_sha256: str
    preimage_sha256: str | None
    target_sha256: str
    outcome_class: str
    role: str = "memory-operation-evidence"
    flow: str = "memory"
    schema_version: int = MEMORY_SCHEMA_VERSION


@dataclass(frozen=True)
class MemoryCapabilities:
    read_current_memory: ActionCapability
    check_evidence_and_retention: ActionCapability
    read_memory_review_state: ActionCapability
    commit_semantic_memory_proposal: ActionCapability
    commit_deterministic_memory_metadata: ActionCapability
    record_run_state: ActionCapability


@dataclass(frozen=True)
class MemoryCrashHooks:
    after_prepare: Callable[[], None] | None = None
    after_domain_publish: Callable[[], None] | None = None
    before_run_commit: Callable[[], None] | None = None


def memory_evidence_artifact_name(operation_id: str) -> str:
    checked = _identifier(operation_id, "operation_id")
    return "memory-evidence-" + hashlib.sha256(checked.encode()).hexdigest()[:32]


def _run_evidence_payload(value: MemoryRunEvidence) -> dict[str, object]:
    if (
        not isinstance(value, MemoryRunEvidence)
        or value.schema_version != MEMORY_SCHEMA_VERSION
        or value.role != "memory-operation-evidence"
        or value.flow != "memory"
        or type(value.operation) is not str
        or value.operation not in {"propose", "commit-metadata", "forget"}
    ):
        _fail("memory run evidence is invalid")
    output_ref = _safe_ref(value.output_ref, "memory evidence output_ref")
    allowed_prefix = {
        "propose": "review/",
        "commit-metadata": "agent/memory/metadata/records/",
        "forget": "agent/memory/metadata/outcomes/",
    }[value.operation]
    if not output_ref.startswith(allowed_prefix):
        _fail("memory run evidence output role is invalid")
    expected_class = (
        "proposal-pending"
        if value.operation == "propose"
        else "deterministic-metadata"
    )
    if type(value.outcome_class) is not str or value.outcome_class != expected_class:
        _fail("memory run evidence outcome class is invalid")
    return {
        "schema_version": 1,
        "role": value.role,
        "flow": value.flow,
        "operation_id": _identifier(value.operation_id, "operation_id"),
        "operation": value.operation,
        "output_ref": output_ref,
        "request_sha256": _hash(value.request_sha256, "request_sha256"),
        "run_state_sha256": _hash(value.run_state_sha256, "run_state_sha256"),
        "preimage_sha256": (
            None
            if value.preimage_sha256 is None
            else _hash(value.preimage_sha256, "preimage_sha256")
        ),
        "target_sha256": _hash(value.target_sha256, "target_sha256"),
        "outcome_class": value.outcome_class,
    }


def render_memory_run_evidence(value: MemoryRunEvidence) -> bytes:
    return _canonical(_run_evidence_payload(value), _MAX_JSON)


def parse_memory_run_evidence(raw: bytes | str) -> MemoryRunEvidence:
    keys = frozenset(
        {
            "schema_version",
            "role",
            "flow",
            "operation_id",
            "operation",
            "output_ref",
            "request_sha256",
            "run_state_sha256",
            "preimage_sha256",
            "target_sha256",
            "outcome_class",
        }
    )
    item = _mapping(
        _decode(raw, "memory run evidence", _MAX_JSON),
        "memory run evidence",
        keys,
    )
    result = MemoryRunEvidence(
        operation_id=item["operation_id"],
        operation=item["operation"],
        output_ref=item["output_ref"],
        request_sha256=item["request_sha256"],
        run_state_sha256=item["run_state_sha256"],
        preimage_sha256=item["preimage_sha256"],
        target_sha256=item["target_sha256"],
        outcome_class=item["outcome_class"],
        role=item["role"],
        flow=item["flow"],
        schema_version=item["schema_version"],
    )
    source = raw.encode("utf-8") if isinstance(raw, str) else raw
    if source != render_memory_run_evidence(result):
        _fail("memory run evidence must use canonical JSON")
    return result


def inspect_memory_run_evidence(
    artifact: PreparedArtifact | CommittedArtifact, raw: bytes | str
) -> MemoryRunEvidence:
    if not isinstance(artifact, (PreparedArtifact, CommittedArtifact)):
        _fail("memory run evidence artifact is invalid")
    evidence = parse_memory_run_evidence(raw)
    source = raw.encode("utf-8") if isinstance(raw, str) else raw
    relative = _safe_ref(artifact.relative, "memory run artifact relative")
    expected_name = f"{memory_evidence_artifact_name(evidence.operation_id)}.json"
    if (
        artifact.name != memory_evidence_artifact_name(evidence.operation_id)
        or artifact.zone != "agent/runs"
        or PurePosixPath(relative).name != expected_name
        or artifact.state_ref != f"agent/runs/{relative}"
        or artifact.sha256 != hashlib.sha256(source).hexdigest()
    ):
        _fail("memory run evidence artifact binding is invalid")
    return evidence


def _retention_payload(value: RetentionPolicy) -> dict[str, object]:
    if not isinstance(value, RetentionPolicy) or value.schema_version != MEMORY_SCHEMA_VERSION:
        _fail("retention policy is invalid")
    if type(value.mode) is not str or value.mode not in {"manual", "review", "until"}:
        _fail("retention policy is invalid")
    review = None if value.review_at is None else _timestamp(value.review_at, "retention review_at")
    until = None if value.retain_until is None else _timestamp(value.retain_until, "retention retain_until")
    if (value.mode == "manual" and (review is not None or until is not None)) or (
        value.mode == "review" and (review is None or until is not None)
    ) or (value.mode == "until" and (until is None or review is not None)):
        _fail("retention policy fields are inconsistent")
    return {"schema_version": 1, "mode": value.mode, "review_at": review, "retain_until": until}


def _parse_retention(value: object) -> RetentionPolicy:
    item = _mapping(value, "retention policy", frozenset({"schema_version", "mode", "review_at", "retain_until"}))
    return RetentionPolicy(item["mode"], item["review_at"], item["retain_until"], item["schema_version"])


def _decay_payload(value: DecayPolicy) -> dict[str, object]:
    if not isinstance(value, DecayPolicy) or value.schema_version != MEMORY_SCHEMA_VERSION:
        _fail("decay policy is invalid")
    if type(value.mode) is not str or value.mode not in {"none", "stale-after", "expires"}:
        _fail("decay policy is invalid")
    days = None if value.stale_after_days is None else _exact_int(value.stale_after_days, "stale_after_days", 1, 36500)
    expires = None if value.expires_at is None else _timestamp(value.expires_at, "decay expires_at")
    if (value.mode == "none" and (days is not None or expires is not None)) or (
        value.mode == "stale-after" and (days is None or expires is not None)
    ) or (value.mode == "expires" and (expires is None or days is not None)):
        _fail("decay policy fields are inconsistent")
    return {"schema_version": 1, "mode": value.mode, "stale_after_days": days, "expires_at": expires}


def _parse_decay(value: object) -> DecayPolicy:
    item = _mapping(value, "decay policy", frozenset({"schema_version", "mode", "stale_after_days", "expires_at"}))
    return DecayPolicy(item["mode"], item["stale_after_days"], item["expires_at"], item["schema_version"])


def _deletion_payload(value: DeletionPolicy) -> dict[str, object]:
    if not isinstance(value, DeletionPolicy) or value.schema_version != MEMORY_SCHEMA_VERSION:
        _fail("deletion policy is invalid")
    if type(value.mode) is not str or value.mode not in {"archive", "forget"}:
        _fail("deletion policy is invalid")
    archive = (
        None
        if value.archive_ref is None
        else _safe_ref(value.archive_ref, "archive_ref", allow_archive=True)
    )
    if (value.mode == "archive") != (archive is not None):
        _fail("deletion policy fields are inconsistent")
    if archive is not None and PurePosixPath(archive).parts[:3] != (
        "agent",
        "memory",
        "_archive",
    ):
        _fail("archive_ref must be inside agent/memory/_archive")
    return {"schema_version": 1, "mode": value.mode, "archive_ref": archive}


def _parse_deletion(value: object) -> DeletionPolicy:
    item = _mapping(value, "deletion policy", frozenset({"schema_version", "mode", "archive_ref"}))
    return DeletionPolicy(item["mode"], item["archive_ref"], item["schema_version"])


def _evidence_payload(value: MemoryEvidence) -> dict[str, object]:
    if not isinstance(value, MemoryEvidence) or value.schema_version != MEMORY_SCHEMA_VERSION:
        _fail("memory evidence is invalid")
    kind = value.source_kind
    if type(kind) is not str or kind not in _PRIMARY_KINDS:
        _fail("memory evidence is not primary human material")
    actor = value.actor
    if type(actor) is not str or actor not in {"human", "runtime-human-confirmed"}:
        _fail("memory evidence actor is not primary human")
    return {
        "schema_version": 1,
        "evidence_id": _identifier(value.evidence_id, "evidence_id"),
        "source_kind": kind,
        "source_ref": _safe_ref(value.source_ref, "evidence source_ref"),
        "source_sha256": _hash(value.source_sha256, "evidence source_sha256"),
        "anchor": _text(value.anchor, "evidence anchor", 256),
        "actor": actor,
        "occurred_at": _timestamp(value.occurred_at, "evidence occurred_at"),
        "exact_text": _text(value.exact_text, "evidence exact_text", _MAX_TEXT, layout=True),
    }


def _parse_evidence(value: object) -> MemoryEvidence:
    keys = frozenset({"schema_version", "evidence_id", "source_kind", "source_ref", "source_sha256", "anchor", "actor", "occurred_at", "exact_text"})
    item = _mapping(value, "memory evidence", keys)
    return MemoryEvidence(
        item["evidence_id"], item["source_kind"], item["source_ref"], item["source_sha256"],
        item["anchor"], item["actor"], item["occurred_at"], item["exact_text"], item["schema_version"]
    )


def validate_primary_evidence_record(
    evidence: MemoryEvidence, record: bytes | str
) -> None:
    """Re-derive one evidence anchor from an accepted retained record."""

    checked = _evidence_payload(evidence)
    payload = _decode(record, "primary evidence record", _MAX_JSON)
    if not isinstance(payload, Mapping):
        _fail("primary evidence record must be an object")
    source = record.encode("utf-8") if isinstance(record, str) else record
    if source != _canonical(dict(payload), _MAX_JSON):
        _fail("primary evidence record must be canonical JSON")

    if checked["source_kind"] == "confirmed-done-event":
        done_keys = frozenset(
            {
                "schema_version",
                "id",
                "type",
                "summary",
                "occurred_at",
                "recorded_at",
                "confirmation",
                "entity_id",
                "root_event_id",
                "related_event_id",
                "followup_due_at",
                "merged_into_event_id",
            }
        )
        item = _mapping(payload, "confirmed done evidence", done_keys)
        confirmation = _mapping(
            item["confirmation"],
            "done confirmation",
            frozenset(
                {
                    "schema_version",
                    "confirmation_id",
                    "actor",
                    "confirmed_at",
                    "exact_text",
                }
            ),
        )
        event_id = _identifier(item["id"], "done id", _DONE_ID)
        event_type = item["type"]
        if type(event_type) is not str or event_type not in {
            "created",
            "followup-sent",
            "followup-answered",
            "closed",
            "merged",
            "correction",
        }:
            _fail("confirmed done evidence type is invalid")
        occurred_at = _timestamp(item["occurred_at"], "done occurred_at")
        recorded_at = _timestamp(item["recorded_at"], "done recorded_at")
        confirmed_at = _timestamp(
            confirmation["confirmed_at"], "confirmation confirmed_at"
        )
        entity_id = item["entity_id"]
        root_event_id = item["root_event_id"]
        related_event_id = item["related_event_id"]
        followup_due_at = item["followup_due_at"]
        merged_into_event_id = item["merged_into_event_id"]
        if entity_id is not None:
            _identifier(entity_id, "done entity_id", _ENTITY_ID)
        if root_event_id is not None:
            _identifier(root_event_id, "done root_event_id", _DONE_ID)
        if related_event_id is not None:
            _identifier(related_event_id, "done related_event_id", _DONE_ID)
        if followup_due_at is not None:
            due = _text(followup_due_at, "done followup_due_at", 40)
            if _DAY.fullmatch(due) is None:
                _timestamp(due, "done followup_due_at")
        if merged_into_event_id is not None:
            _identifier(merged_into_event_id, "done merged_into_event_id", _DONE_ID)
        if (
            type(item["schema_version"]) is not int
            or item["schema_version"] != 1
            or type(confirmation["schema_version"]) is not int
            or confirmation["schema_version"] != 1
            or confirmation["actor"] != "human"
            or checked["actor"] != "runtime-human-confirmed"
            or _identifier(confirmation["confirmation_id"], "confirmation_id")
            != checked["anchor"]
            or _text(item["summary"], "done summary", _MAX_TEXT)
            != checked["exact_text"]
            or _text(
                confirmation["exact_text"],
                "done confirmation exact_text",
                _MAX_TEXT,
            )
            != checked["exact_text"]
            or occurred_at != checked["occurred_at"]
            or _instant(confirmed_at) > _instant(recorded_at)
        ):
            _fail("confirmed done evidence does not match its exact anchor")
        if event_type == "created":
            if any(
                value is not None
                for value in (root_event_id, related_event_id, merged_into_event_id)
            ):
                _fail("confirmed done created record has invalid references")
        elif root_event_id is None or root_event_id == event_id or followup_due_at is not None:
            _fail("confirmed done derived record has invalid references")
        if event_type in {"followup-answered", "correction"} and related_event_id is None:
            _fail("confirmed done derived record lacks its related event")
        if event_type == "merged":
            if merged_into_event_id is None or merged_into_event_id == root_event_id:
                _fail("confirmed done merge target is invalid")
        elif merged_into_event_id is not None:
            _fail("confirmed done non-merge record has a merge target")
        return

    daily_keys = frozenset(
        {
            "schema_version",
            "record_type",
            "report_id",
            "day",
            "run_id",
            "operation_id",
            "recorded_at",
            "materials",
            "context",
            "reflection_text",
        }
    )
    item = _mapping(payload, "daily primary evidence", daily_keys)
    materials = item["materials"]
    if (
        type(item["schema_version"]) is not int
        or item["schema_version"] != 1
        or item["record_type"] != "daily"
        or not isinstance(materials, list)
        or not materials
        or len(materials) > _MAX_EVIDENCE
    ):
        _fail("daily primary evidence schema is invalid")
    _identifier(item["report_id"], "report_id", _REPORT_ID)
    day = _text(item["day"], "daily day", 10)
    if _DAY.fullmatch(day) is None:
        _fail("daily primary evidence day is invalid")
    try:
        datetime.strptime(day, "%Y-%m-%d")
    except ValueError:
        _fail("daily primary evidence day is invalid")
    _identifier(item["run_id"], "run_id", _RUN_ID)
    _identifier(item["operation_id"], "operation_id")
    if _timestamp(item["recorded_at"], "daily recorded_at")[:10] != day:
        _fail("daily primary evidence day is inconsistent")
    _text(item["reflection_text"], "daily reflection_text", _MAX_TEXT, layout=True)
    context = _mapping(
        item["context"],
        "daily primary evidence context",
        frozenset({"schema_version", "items"}),
    )
    context_items = context["items"]
    if (
        type(context["schema_version"]) is not int
        or context["schema_version"] != 1
        or not isinstance(context_items, list)
        or len(context_items) > 128
    ):
        _fail("daily primary evidence context is invalid")
    context_keys: list[tuple[str, str]] = []
    for value in context_items:
        context_item = _mapping(
            value,
            "daily primary evidence context item",
            frozenset({"schema_version", "kind", "logical_ref", "state_sha256"}),
        )
        kind = context_item["kind"]
        if (
            type(context_item["schema_version"]) is not int
            or context_item["schema_version"] != 1
            or type(kind) is not str
            or kind not in {"project", "task", "entity", "memory"}
        ):
            _fail("daily primary evidence context item is invalid")
        logical_ref = _safe_ref(
            context_item["logical_ref"], "daily context logical_ref"
        )
        _hash(context_item["state_sha256"], "daily context state_sha256")
        context_keys.append((_portable(kind), _portable(logical_ref)))
    if len(context_keys) != len(set(context_keys)) or context_keys != sorted(context_keys):
        _fail("daily primary evidence context is not deterministic")

    matches: list[Mapping[str, object]] = []
    seen: set[str] = set()
    material_keys = frozenset(
        {
            "schema_version",
            "material_id",
            "kind",
            "actor",
            "occurred_at",
            "exact_text",
        }
    )
    for value in materials:
        material = _mapping(value, "daily human material", material_keys)
        material_id = _identifier(material["material_id"], "material_id")
        if material_id.casefold() in seen:
            _fail("daily human material ids collide")
        seen.add(material_id.casefold())
        if (
            type(material["schema_version"]) is not int
            or material["schema_version"] != 1
            or type(material["kind"]) is not str
            or material["kind"] not in _PRIMARY_KINDS - {"confirmed-done-event"}
            or material["actor"] != "human"
        ):
            _fail("daily human material schema is invalid")
        _timestamp(material["occurred_at"], "material occurred_at")
        _text(material["exact_text"], "material exact_text", _MAX_TEXT, layout=True)
        if material_id == checked["anchor"]:
            matches.append(material)
    if len(matches) != 1:
        _fail("primary evidence anchor does not identify one human material")
    material = matches[0]
    if (
        material["kind"] != checked["source_kind"]
        or checked["actor"] != "human"
        or material["occurred_at"] != checked["occurred_at"]
        or material["exact_text"] != checked["exact_text"]
    ):
        _fail("primary evidence does not match its exact human material field")


def _decision_payload(value: HumanProposalDecision | None) -> dict[str, object] | None:
    if value is None:
        return None
    if not isinstance(value, HumanProposalDecision) or value.schema_version != 1:
        _fail("human proposal decision is invalid")
    if type(value.action) is not str or value.action not in {"approve", "reject", "supersede"} or value.actor != "human":
        _fail("human proposal decision is invalid")
    superseded = None if value.superseded_by is None else _identifier(value.superseded_by, "superseded_by", _PROPOSAL_ID)
    if (value.action == "supersede") != (superseded is not None):
        _fail("human proposal decision is invalid")
    return {"schema_version": 1, "action": value.action, "actor": "human", "at": _timestamp(value.at, "decision at"), "sequence": _exact_int(value.sequence, "decision sequence", 1, 2**31 - 1), "superseded_by": superseded}


def _parse_decision(value: object) -> HumanProposalDecision | None:
    if value is None:
        return None
    item = _mapping(value, "human proposal decision", frozenset({"schema_version", "action", "actor", "at", "sequence", "superseded_by"}))
    return HumanProposalDecision(item["action"], item["actor"], item["at"], item["sequence"], item["superseded_by"], item["schema_version"])


def _proposal_payload(value: MemoryProposalRecord) -> dict[str, object]:
    if not isinstance(value, MemoryProposalRecord) or value.schema_version != 1:
        _fail("memory proposal is invalid")
    proposal_id = _identifier(value.proposal_id, "proposal_id", _PROPOSAL_ID)
    if type(value.status) is not str or value.status not in _PROPOSAL_STATUSES:
        _fail("memory proposal status is invalid")
    if type(value.operation) is not str or value.operation not in _PROPOSAL_OPERATIONS:
        _fail("memory proposal operation is invalid")
    if type(value.memory_kind) is not str or value.memory_kind not in _MEMORY_KINDS:
        _fail("memory kind is invalid")
    if not isinstance(value.evidence, tuple) or not value.evidence or len(value.evidence) > _MAX_EVIDENCE:
        _fail("memory proposal requires bounded primary evidence")
    evidence = tuple(_evidence_payload(item) for item in value.evidence)
    ids = [_portable(str(item["evidence_id"])) for item in evidence]
    if len(ids) != len(set(ids)):
        _fail("memory evidence ids collide")
    current_ref = None if value.current_memory_ref is None else _safe_ref(value.current_memory_ref, "current_memory_ref", memory=True)
    current_hash = None if value.current_memory_sha256 is None else _hash(value.current_memory_sha256, "current_memory_sha256")
    precondition = None if value.precondition_sha256 is None else _hash(value.precondition_sha256, "precondition_sha256")
    if value.operation == "create":
        if any(item is not None for item in (current_ref, current_hash, precondition)):
            _fail("create memory proposal cannot name a current memory")
    elif any(item is None for item in (current_ref, current_hash, precondition)):
        _fail("memory change proposal requires an exact current precondition")
    if current_hash != precondition:
        _fail("memory proposal precondition is inconsistent")
    decision = _decision_payload(value.human_decision)
    expected = {None: "proposed", "approve": "approved", "reject": "rejected", "supersede": "superseded"}[None if decision is None else decision["action"]]
    if value.status != expected:
        _fail("memory proposal status disagrees with human decision")
    return {
        "schema_version": 1,
        "proposal_id": proposal_id,
        "status": value.status,
        "operation": value.operation,
        "memory_id": _identifier(value.memory_id, "memory_id", _MEMORY_ID),
        "memory_kind": value.memory_kind,
        "scope": _text(value.scope, "memory scope", 256),
        "candidate_text": _text(value.candidate_text, "candidate_text", _MAX_TEXT, layout=True),
        "evidence": list(evidence),
        "current_memory_ref": current_ref,
        "current_memory_sha256": current_hash,
        "precondition_sha256": precondition,
        "retention": _retention_payload(value.retention),
        "decay": _decay_payload(value.decay),
        "deletion": _deletion_payload(value.deletion),
        "producer_flow": _text(value.producer_flow, "producer_flow", 32),
        "run_id": _identifier(value.run_id, "run_id", _RUN_ID),
        "operation_id": _identifier(value.operation_id, "operation_id"),
        "created_at": _timestamp(value.created_at, "proposal created_at"),
        "human_decision": decision,
    }


def render_memory_proposal(value: MemoryProposalRecord) -> bytes:
    return _canonical(_proposal_payload(value), _MAX_PROPOSAL)


def parse_memory_proposal(raw: bytes | str) -> MemoryProposalRecord:
    keys = frozenset({"schema_version", "proposal_id", "status", "operation", "memory_id", "memory_kind", "scope", "candidate_text", "evidence", "current_memory_ref", "current_memory_sha256", "precondition_sha256", "retention", "decay", "deletion", "producer_flow", "run_id", "operation_id", "created_at", "human_decision"})
    item = _mapping(_decode(raw, "memory proposal", _MAX_PROPOSAL), "memory proposal", keys)
    evidence = item["evidence"]
    if not isinstance(evidence, list):
        _fail("memory proposal evidence is invalid")
    result = MemoryProposalRecord(
        item["proposal_id"], item["status"], item["operation"], item["memory_id"], item["memory_kind"],
        item["scope"], item["candidate_text"], tuple(_parse_evidence(value) for value in evidence),
        item["current_memory_ref"], item["current_memory_sha256"], item["precondition_sha256"],
        _parse_retention(item["retention"]), _parse_decay(item["decay"]), _parse_deletion(item["deletion"]),
        item["producer_flow"], item["run_id"], item["operation_id"], item["created_at"],
        _parse_decision(item["human_decision"]), item["schema_version"]
    )
    canonical = render_memory_proposal(result)
    source = raw.encode("utf-8") if isinstance(raw, str) else raw
    if source != canonical:
        _fail("memory proposal must use canonical JSON")
    return result


def _binding_payload(value: EvidenceBinding) -> dict[str, str]:
    if not isinstance(value, EvidenceBinding):
        _fail("evidence binding is invalid")
    return {"evidence_id": _identifier(value.evidence_id, "evidence_id"), "source_sha256": _hash(value.source_sha256, "source_sha256")}


def _metadata_payload(value: MemoryMetadataRecord) -> dict[str, object]:
    if not isinstance(value, MemoryMetadataRecord) or value.schema_version != 1:
        _fail("memory metadata is invalid")
    if type(value.memory_kind) is not str or value.memory_kind not in _MEMORY_KINDS:
        _fail("memory kind is invalid")
    if type(value.status) is not str or value.status not in _METADATA_STATUSES:
        _fail("memory metadata status is invalid")
    if not isinstance(value.evidence, tuple) or not value.evidence or len(value.evidence) > _MAX_EVIDENCE:
        _fail("memory metadata evidence is invalid")
    bindings = tuple(_binding_payload(item) for item in value.evidence)
    if len({item["evidence_id"].casefold() for item in bindings}) != len(bindings):
        _fail("memory metadata evidence ids collide")
    created = _timestamp(value.created_at, "metadata created_at")
    confirmed = _timestamp(value.last_confirmed_at, "last_confirmed_at")
    if _instant(confirmed) < _instant(created):
        _fail("memory confirmation precedes creation")
    return {
        "schema_version": 1,
        "memory_id": _identifier(value.memory_id, "memory_id", _MEMORY_ID),
        "semantic_ref": _safe_ref(value.semantic_ref, "semantic_ref", memory=True),
        "semantic_sha256": _hash(value.semantic_sha256, "semantic_sha256"),
        "memory_kind": value.memory_kind,
        "scope": _text(value.scope, "scope", 256),
        "evidence": list(bindings),
        "proposal_id": _identifier(value.proposal_id, "proposal_id", _PROPOSAL_ID),
        "created_at": created,
        "last_confirmed_at": confirmed,
        "retention": _retention_payload(value.retention),
        "decay": _decay_payload(value.decay),
        "deletion": _deletion_payload(value.deletion),
        "status": value.status,
        "revision": _exact_int(value.revision, "metadata revision", 1, 2**31 - 1),
        "last_operation_id": _identifier(value.last_operation_id, "last_operation_id"),
        "last_operation_sha256": _hash(value.last_operation_sha256, "last_operation_sha256"),
    }


def render_memory_metadata(value: MemoryMetadataRecord) -> bytes:
    return _canonical(_metadata_payload(value), _MAX_METADATA)


def parse_memory_metadata(raw: bytes | str) -> MemoryMetadataRecord:
    keys = frozenset({"schema_version", "memory_id", "semantic_ref", "semantic_sha256", "memory_kind", "scope", "evidence", "proposal_id", "created_at", "last_confirmed_at", "retention", "decay", "deletion", "status", "revision", "last_operation_id", "last_operation_sha256"})
    item = _mapping(_decode(raw, "memory metadata", _MAX_METADATA), "memory metadata", keys)
    bindings = item["evidence"]
    if not isinstance(bindings, list):
        _fail("memory metadata evidence is invalid")
    result = MemoryMetadataRecord(
        item["memory_id"], item["semantic_ref"], item["semantic_sha256"], item["memory_kind"], item["scope"],
        tuple(EvidenceBinding(_mapping(value, "evidence binding", frozenset({"evidence_id", "source_sha256"}))["evidence_id"], value["source_sha256"]) for value in bindings),
        item["proposal_id"], item["created_at"], item["last_confirmed_at"], _parse_retention(item["retention"]),
        _parse_decay(item["decay"]), _parse_deletion(item["deletion"]), item["status"], item["revision"],
        item["last_operation_id"], item["last_operation_sha256"], item["schema_version"]
    )
    canonical = render_memory_metadata(result)
    source = raw.encode("utf-8") if isinstance(raw, str) else raw
    if source != canonical:
        _fail("memory metadata must use canonical JSON")
    return result


def _outcome_payload(value: ForgetOutcome) -> dict[str, object]:
    if not isinstance(value, ForgetOutcome) or value.schema_version != 1:
        _fail("forget outcome is invalid")
    if type(value.verification) is not str or value.verification not in {"semantic-absence-verified", "archive-ref-verified", "proposal-never-shared"}:
        _fail("forget verification is invalid")
    semantic_ref = None if value.semantic_ref is None else _safe_ref(value.semantic_ref, "semantic_ref", memory=True)
    prior = None if value.prior_semantic_sha256 is None else _hash(value.prior_semantic_sha256, "prior_semantic_sha256")
    metadata = None if value.metadata_sha256 is None else _hash(value.metadata_sha256, "metadata_sha256")
    if value.verification == "proposal-never-shared" and any(item is not None for item in (semantic_ref, prior, metadata)):
        _fail("never-shared outcome cannot name semantic state")
    if value.verification != "proposal-never-shared" and any(item is None for item in (semantic_ref, prior)):
        _fail("forget outcome lacks semantic precondition")
    return {"schema_version": 1, "outcome_id": _identifier(value.outcome_id, "outcome_id", _FORGET_ID), "memory_id": _identifier(value.memory_id, "memory_id", _MEMORY_ID), "proposal_id": _identifier(value.proposal_id, "proposal_id", _PROPOSAL_ID), "verification": value.verification, "semantic_ref": semantic_ref, "prior_semantic_sha256": prior, "verified_at": _timestamp(value.verified_at, "verified_at"), "metadata_sha256": metadata}


def render_forget_outcome(value: ForgetOutcome) -> bytes:
    return _canonical(_outcome_payload(value), _MAX_METADATA)


def parse_forget_outcome(raw: bytes | str) -> ForgetOutcome:
    keys = frozenset({"schema_version", "outcome_id", "memory_id", "proposal_id", "verification", "semantic_ref", "prior_semantic_sha256", "verified_at", "metadata_sha256"})
    item = _mapping(_decode(raw, "forget outcome", _MAX_METADATA), "forget outcome", keys)
    result = ForgetOutcome(item["outcome_id"], item["memory_id"], item["proposal_id"], item["verification"], item["semantic_ref"], item["prior_semantic_sha256"], item["verified_at"], item["metadata_sha256"], item["schema_version"])
    canonical = render_forget_outcome(result)
    source = raw.encode("utf-8") if isinstance(raw, str) else raw
    if source != canonical:
        _fail("forget outcome must use canonical JSON")
    return result


@dataclass(frozen=True)
class _Zone:
    fd: int
    path: object
    identity: tuple[int, int]
    symbolic: str


def _read_at(fd: int, name: str, maximum: int) -> tuple[bytes, tuple[int, int]]:
    _portable(name)
    file_fd: int | None = None
    try:
        named = os.stat(name, dir_fd=fd, follow_symlinks=False)
        file_fd = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=fd)
        opened = os.fstat(file_fd)
        if not stat.S_ISREG(named.st_mode) or (named.st_dev, named.st_ino) != (opened.st_dev, opened.st_ino) or opened.st_size > maximum:
            _fail("memory file is unsafe or too large")
        data = b""
        while len(data) <= maximum:
            chunk = os.read(file_fd, min(65536, maximum + 1 - len(data)))
            if not chunk:
                break
            data += chunk
        after = os.fstat(file_fd)
        linked = os.stat(name, dir_fd=fd, follow_symlinks=False)
        if len(data) > maximum or _stat_signature(opened) != _stat_signature(after) or _stat_signature(opened) != _stat_signature(linked):
            _fail("memory file changed while read")
        return data, (opened.st_dev, opened.st_ino)
    except FileNotFoundError:
        raise
    except MemoryFlowError:
        raise
    except OSError:
        _fail("memory file cannot be read safely")
    finally:
        if file_fd is not None:
            os.close(file_fd)


def _identity_at(fd: int, name: str) -> tuple[int, int] | None:
    try:
        item = os.stat(name, dir_fd=fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    except OSError:
        _fail("memory namespace cannot be inspected")
    if not stat.S_ISREG(item.st_mode):
        _fail("memory named leaf is unsafe")
    return item.st_dev, item.st_ino


def _stat_signature(item: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        item.st_dev,
        item.st_ino,
        item.st_size,
        item.st_mtime_ns,
        item.st_ctime_ns,
    )


def _write_all(fd: int, data: bytes) -> None:
    offset = 0
    while offset < len(data):
        try:
            count = os.write(fd, data[offset:])
        except OSError:
            _fail("memory write failed")
        if count <= 0:
            _fail("memory write did not progress")
        offset += count


def _rename_noreplace_between(
    source_fd: int,
    source: str,
    destination_fd: int,
    destination: str,
) -> None:
    library = ctypes.CDLL(None, use_errno=True)
    if sys.platform == "darwin":
        function, flag = library.renameatx_np, 0x00000004
    elif sys.platform.startswith("linux") and hasattr(library, "renameat2"):
        function, flag = library.renameat2, 0x00000001
    else:
        _fail("atomic no-replace memory retirement is unavailable")
    function.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    function.restype = ctypes.c_int
    if (
        function(
            source_fd,
            os.fsencode(source),
            destination_fd,
            os.fsencode(destination),
            flag,
        )
        == 0
    ):
        return
    code = ctypes.get_errno()
    if code == errno.EEXIST:
        raise FileExistsError(code, os.strerror(code), destination)
    if code == errno.ENOENT:
        raise FileNotFoundError(code, os.strerror(code), source)
    raise OSError(code, os.strerror(code), source)


def _retire_exact(
    source_fd: int,
    source: str,
    expected_identity: tuple[int, int],
    recovery_fd: int,
    kind: str,
) -> bool:
    """Move exact owned bytes to retained run recovery without unlinking."""

    recovery_key = hashlib.sha256(
        f"memory\0{kind}\0{expected_identity[0]}\0{expected_identity[1]}".encode()
    ).hexdigest()[:32]
    recovery_name = f"memory-{recovery_key}.recovery"
    try:
        _rename_noreplace_between(
            source_fd, source, recovery_fd, recovery_name
        )
        os.fsync(source_fd)
        os.fsync(recovery_fd)
        moved = os.stat(recovery_name, dir_fd=recovery_fd, follow_symlinks=False)
        if (moved.st_dev, moved.st_ino) == expected_identity:
            return True
        try:
            _rename_noreplace_between(
                recovery_fd, recovery_name, source_fd, source
            )
            os.fsync(source_fd)
            os.fsync(recovery_fd)
        except OSError:
            pass
        return False
    except FileExistsError:
        try:
            source_named = os.stat(source, dir_fd=source_fd, follow_symlinks=False)
            retained = os.stat(
                recovery_name, dir_fd=recovery_fd, follow_symlinks=False
            )
            return (
                (source_named.st_dev, source_named.st_ino) == expected_identity
                and (retained.st_dev, retained.st_ino) == expected_identity
            )
        except OSError:
            return False
    except (FileNotFoundError, OSError):
        return False


def _create_once(
    fd: int,
    name: str,
    data: bytes,
    maximum: int,
    recovery_fd: int,
    recovery_kind: str,
    validate_parent: Callable[[], None],
) -> bool:
    validate_parent()
    if not isinstance(data, bytes) or not data or len(data) > maximum:
        _fail("immutable memory bytes are invalid")
    try:
        existing, _ = _read_at(fd, name, maximum)
    except FileNotFoundError:
        existing = None
    if existing is not None:
        if existing != data:
            _fail("immutable memory replay conflicts with existing bytes")
        validate_parent()
        return False
    temporary = f".{name}.{os.getpid()}.{uuid.uuid4().hex}.tmp"
    staged_fd: int | None = None
    identity: tuple[int, int] | None = None
    try:
        staged_fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=fd)
        _write_all(staged_fd, data)
        os.fsync(staged_fd)
        item = os.fstat(staged_fd)
        identity = item.st_dev, item.st_ino
        os.close(staged_fd)
        staged_fd = None
        named = os.stat(temporary, dir_fd=fd, follow_symlinks=False)
        if identity != (named.st_dev, named.st_ino):
            _fail("immutable memory stage changed")
        validate_parent()
        try:
            os.link(temporary, name, src_dir_fd=fd, dst_dir_fd=fd, follow_symlinks=False)
        except FileExistsError:
            current, _ = _read_at(fd, name, maximum)
            if current != data:
                _fail("immutable memory publication collided")
            return False
        published = os.stat(name, dir_fd=fd, follow_symlinks=False)
        if identity != (published.st_dev, published.st_ino):
            _fail("immutable memory publication changed")
        try:
            validate_parent()
        except MemoryFlowError:
            if not _retire_exact(
                fd,
                name,
                identity,
                recovery_fd,
                recovery_kind + "-publish",
            ):
                _fail("memory publication rollback could not retain exact bytes")
            raise
        os.fsync(fd)
        return True
    except MemoryFlowError:
        raise
    except OSError:
        _fail("immutable memory publication failed")
    finally:
        if staged_fd is not None:
            os.close(staged_fd)
        if identity is not None:
            if not _retire_exact(
                fd,
                temporary,
                identity,
                recovery_fd,
                recovery_kind + "-stage",
            ):
                _fail("memory stage cleanup could not retain exact bytes")


def _rename_exchange(fd: int, source: str, target: str) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    if hasattr(libc, "renameatx_np"):
        fn, flag = libc.renameatx_np, 0x00000002
    elif hasattr(libc, "renameat2"):
        fn, flag = libc.renameat2, 0x00000002
    else:
        _fail("identity-bound rename is unavailable")
    fn.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    fn.restype = ctypes.c_int
    if fn(fd, os.fsencode(source), fd, os.fsencode(target), flag) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def _atomic_replace(
    fd: int,
    name: str,
    data: bytes,
    expected_identity: tuple[int, int] | None,
    maximum: int,
    validate_parent: Callable[[], None],
    recovery_fd: int,
    recovery_kind: str,
) -> None:
    validate_parent()
    if expected_identity is None:
        _create_once(
            fd,
            name,
            data,
            maximum,
            recovery_fd,
            recovery_kind,
            validate_parent,
        )
        return
    temporary = f".{name}.{os.getpid()}.{uuid.uuid4().hex}.tmp"
    staged_fd: int | None = None
    staged_identity: tuple[int, int] | None = None
    try:
        staged_fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=fd)
        _write_all(staged_fd, data)
        os.fsync(staged_fd)
        item = os.fstat(staged_fd)
        staged_identity = item.st_dev, item.st_ino
        os.close(staged_fd)
        staged_fd = None
        validate_parent()
        _rename_exchange(fd, temporary, name)
        try:
            validate_parent()
        except MemoryFlowError:
            try:
                _rename_exchange(fd, temporary, name)
                os.fsync(fd)
            except OSError:
                pass
            raise
        old_identity = _identity_at(fd, temporary)
        if old_identity != expected_identity:
            if old_identity is not None:
                try:
                    _rename_exchange(fd, temporary, name)
                    os.fsync(fd)
                except OSError:
                    pass
            _fail("memory metadata changed before publish")
        current, identity = _read_at(fd, name, maximum)
        if current != data or identity != staged_identity:
            try:
                _rename_exchange(fd, temporary, name)
                os.fsync(fd)
            except OSError:
                pass
            _fail("memory metadata publication is not exact")
        try:
            validate_parent()
        except MemoryFlowError:
            try:
                _rename_exchange(fd, temporary, name)
                os.fsync(fd)
            except OSError:
                pass
            raise
        if old_identity != expected_identity or not _retire_exact(
            fd,
            temporary,
            expected_identity,
            recovery_fd,
            recovery_kind + "-preimage",
        ):
            _fail("memory metadata preimage could not be retained exactly")
        staged_identity = None
    except MemoryFlowError:
        raise
    except OSError:
        _fail("memory metadata publication failed")
    finally:
        if staged_fd is not None:
            os.close(staged_fd)
        if staged_identity is not None:
            if not _retire_exact(
                fd,
                temporary,
                staged_identity,
                recovery_fd,
                recovery_kind + "-stage",
            ):
                _fail("memory metadata stage could not be retained exactly")


class MemoryFlow:
    """Evidence-gated proposals plus deterministic metadata and outcomes."""

    def __init__(self, resolver: VaultPathResolver, run_store: RunStore, policy: AuthorityPolicy, *, clock: Callable[[], datetime] | None = None) -> None:
        if not isinstance(resolver, VaultPathResolver) or not isinstance(run_store, RunStore) or not isinstance(policy, AuthorityPolicy) or getattr(run_store, "_resolver", None) is not resolver:
            _fail("memory flow dependencies are invalid")
        self._resolver, self._runs, self._policy = resolver, run_store, policy
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        try:
            root = resolver.resolve("agent/memory", must_exist=True)
            relative = resolver.config.zone("memory")
            vault = root
            for _ in relative.parts:
                vault = vault.parent
            fd = os.open(vault, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
            item = os.fstat(fd)
            named = os.stat(vault, follow_symlinks=False)
            if (item.st_dev, item.st_ino) != (named.st_dev, named.st_ino):
                _fail("memory vault root cannot be pinned")
            self._root_path, self._root_identity = vault, (item.st_dev, item.st_ino)
        except (OSError, VaultSchemaError, MemoryFlowError):
            _fail("memory vault root cannot be pinned")
        finally:
            if "fd" in locals():
                os.close(fd)

    def _now(self) -> str:
        value = self._clock()
        if not isinstance(value, datetime) or value.tzinfo is None:
            _fail("memory clock must return aware datetime")
        return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")

    def _check_root(self) -> None:
        try:
            root = os.stat(self._root_path, follow_symlinks=False)
        except OSError:
            _fail("memory vault root changed")
        if self._root_identity != (root.st_dev, root.st_ino):
            _fail("memory vault root changed")

    def _require(self, capability: ActionCapability, action_id: str) -> ActionCapability:
        expected = {
            "read-current-memory": ("read", "vault:agent/memory"),
            "check-evidence-and-retention": ("read", "vault:agent/logs"),
            "read-memory-review-state": ("read", "vault:review"),
            "commit-semantic-memory-proposal": ("proposal", "vault:review"),
            "commit-deterministic-memory-metadata": ("domain-write", "vault:agent/memory-metadata"),
            "record-run-state": ("internal-write", "vault:agent/runs"),
        }
        try:
            grant = self._policy.require(capability)
        except AuthorityError as error:
            raise MemoryFlowError(str(error)) from None
        if action_id not in expected or (grant.flow_id, grant.action_id, grant.actor, grant.authority, grant.target) != ("memory", action_id, "runtime", *expected[action_id]):
            _fail("memory action capability is not exact")
        return grant

    def _check_run(self, run_id: str) -> tuple[str, str]:
        checked = _identifier(run_id, "run_id", _RUN_ID)
        try:
            snapshot = self._runs.snapshot(checked)
        except RunError as error:
            raise MemoryFlowError(str(error)) from None
        if snapshot.state.get("flow") != "memory" or snapshot.state.get("status") != "running" or snapshot.state.get("authority") != "domain-write":
            _fail("memory mutation requires a running domain-write memory run")
        return checked, snapshot.state_sha256

    @staticmethod
    def _hooks(value: MemoryCrashHooks | None) -> MemoryCrashHooks:
        hooks = MemoryCrashHooks() if value is None else value
        if not isinstance(hooks, MemoryCrashHooks) or any(
            item is not None and not callable(item)
            for item in (
                hooks.after_prepare,
                hooks.after_domain_publish,
                hooks.before_run_commit,
            )
        ):
            _fail("memory crash hooks are invalid")
        return hooks

    def _open_zone(self, symbolic: str, *, for_write: bool) -> _Zone:
        try:
            path = self._resolver.resolve(symbolic, for_write=for_write, must_exist=True)
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
            opened = os.fstat(fd)
            named = os.stat(path, follow_symlinks=False)
            if not stat.S_ISDIR(opened.st_mode) or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino):
                _fail("memory zone is unsafe")
            return _Zone(fd, path, (opened.st_dev, opened.st_ino), symbolic)
        except (OSError, VaultSchemaError, MemoryFlowError):
            if "fd" in locals():
                os.close(fd)
            _fail("memory zone cannot be opened safely")

    def _open_optional_zone(self, symbolic: str) -> _Zone | None:
        fd: int | None = None
        try:
            path = self._resolver.resolve(symbolic, must_exist=False)
            try:
                fd = os.open(
                    path,
                    os.O_RDONLY
                    | getattr(os, "O_DIRECTORY", 0)
                    | getattr(os, "O_NOFOLLOW", 0),
                )
            except FileNotFoundError:
                return None
            opened = os.fstat(fd)
            named = os.stat(path, follow_symlinks=False)
            if (
                not stat.S_ISDIR(opened.st_mode)
                or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
            ):
                _fail("memory zone is unsafe")
            return _Zone(fd, path, (opened.st_dev, opened.st_ino), symbolic)
        except (OSError, VaultSchemaError, MemoryFlowError):
            if fd is not None:
                os.close(fd)
            _fail("memory zone cannot be opened safely")

    def _revalidate(self, zone: _Zone, *, for_write: bool) -> None:
        try:
            actual = self._resolver.revalidate(zone.path, zone.symbolic, for_write=for_write, must_exist=True)
            opened, named = os.fstat(zone.fd), os.stat(actual, follow_symlinks=False)
            root = os.stat(self._root_path, follow_symlinks=False)
        except (OSError, VaultSchemaError):
            _fail("memory zone changed")
        if (
            zone.identity != (opened.st_dev, opened.st_ino)
            or zone.identity != (named.st_dev, named.st_ino)
            or self._root_identity != (root.st_dev, root.st_ino)
        ):
            _fail("memory zone changed")

    @staticmethod
    def _revalidate_metadata_dirs(
        memory: _Zone,
        metadata_fd: int,
        records_fd: int,
        outcomes_fd: int,
    ) -> None:
        try:
            metadata = os.fstat(metadata_fd)
            named_metadata = os.stat(
                "metadata", dir_fd=memory.fd, follow_symlinks=False
            )
            records = os.fstat(records_fd)
            named_records = os.stat(
                "records", dir_fd=metadata_fd, follow_symlinks=False
            )
            outcomes = os.fstat(outcomes_fd)
            named_outcomes = os.stat(
                "outcomes", dir_fd=metadata_fd, follow_symlinks=False
            )
        except OSError:
            _fail("memory metadata namespace changed")
        if any(
            not stat.S_ISDIR(item.st_mode)
            for item in (
                metadata,
                named_metadata,
                records,
                named_records,
                outcomes,
                named_outcomes,
            )
        ) or any(
            (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
            for opened, named in (
                (metadata, named_metadata),
                (records, named_records),
                (outcomes, named_outcomes),
            )
        ):
            _fail("memory metadata namespace changed")

    @staticmethod
    def _mkdir_at(fd: int, name: str) -> int:
        _portable(name)
        try:
            os.mkdir(name, mode=0o700, dir_fd=fd)
            os.fsync(fd)
        except FileExistsError:
            pass
        except OSError:
            _fail("memory metadata namespace cannot be created")
        try:
            child = os.open(name, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0), dir_fd=fd)
            item = os.fstat(child)
            linked = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if not stat.S_ISDIR(item.st_mode) or (item.st_dev, item.st_ino) != (linked.st_dev, linked.st_ino):
                _fail("memory metadata namespace is unsafe")
            return child
        except (OSError, MemoryFlowError):
            if "child" in locals():
                os.close(child)
            _fail("memory metadata namespace is unsafe")

    @contextmanager
    def _metadata_dirs(self) -> Iterator[tuple[_Zone, int, int, int]]:
        memory = self._open_zone("agent/memory", for_write=True)
        lock_fd: int | None = None
        metadata_fd: int | None = None
        records_fd: int | None = None
        outcomes_fd: int | None = None
        try:
            metadata_fd = self._mkdir_at(memory.fd, "metadata")
            lock_fd = os.open(
                ".lock",
                os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=metadata_fd,
            )
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            records_fd = self._mkdir_at(metadata_fd, "records")
            outcomes_fd = self._mkdir_at(metadata_fd, "outcomes")
            self._revalidate(memory, for_write=True)
            self._revalidate_metadata_dirs(
                memory, metadata_fd, records_fd, outcomes_fd
            )
            yield memory, metadata_fd, records_fd, outcomes_fd
            self._revalidate_metadata_dirs(
                memory, metadata_fd, records_fd, outcomes_fd
            )
            self._revalidate(memory, for_write=True)
        finally:
            for item in (outcomes_fd, records_fd, metadata_fd, lock_fd):
                if item is not None:
                    os.close(item)
            os.close(memory.fd)

    def _proposal(self, proposal_id: str) -> tuple[MemoryProposalRecord, bytes]:
        zone = self._open_zone("review", for_write=False)
        try:
            raw, _ = _read_at(zone.fd, f"{_identifier(proposal_id, 'proposal_id', _PROPOSAL_ID)}.memory.json", _MAX_PROPOSAL)
            value = parse_memory_proposal(raw)
            self._revalidate(zone, for_write=False)
            return value, raw
        except FileNotFoundError:
            _fail("memory proposal is missing")
        finally:
            os.close(zone.fd)

    def _semantic_bytes(self, ref: str, *, archive: bool = False) -> bytes | None:
        self._check_root()
        checked = _safe_ref(
            ref,
            "semantic_ref",
            memory=not archive,
            allow_archive=archive,
        )
        relative = PurePosixPath(checked).relative_to("agent/memory")
        try:
            path = self._resolver.resolve(
                "agent/memory",
                relative,
                must_exist=True,
                allow_archive=archive,
            )
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            item = os.fstat(fd)
            if not stat.S_ISREG(item.st_mode) or item.st_size > _MAX_TEXT:
                _fail("semantic memory is unsafe or too large")
            data = os.read(fd, _MAX_TEXT + 1)
            after = os.fstat(fd)
            if len(data) > _MAX_TEXT or (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                _fail("semantic memory changed while read")
            self._check_root()
            return data
        except FileNotFoundError:
            return None
        except (OSError, VaultSchemaError):
            _fail("semantic memory cannot be read safely")
        finally:
            if "fd" in locals():
                os.close(fd)

    def _verify_primary_evidence(self, items: tuple[MemoryEvidence, ...]) -> None:
        self._check_root()
        for item in items:
            payload = _evidence_payload(item)
            source_ref = str(payload["source_ref"])
            path = PurePosixPath(source_ref)
            if path.parts[:2] != ("agent", "logs") or len(path.parts) < 3:
                _fail("primary memory evidence must be retained under agent/logs")
            relative = PurePosixPath(*path.parts[2:])
            file_fd: int | None = None
            try:
                source = self._resolver.resolve(
                    "agent/logs", relative, must_exist=True, for_write=False
                )
                file_fd = os.open(
                    source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                )
                before = os.fstat(file_fd)
                if not stat.S_ISREG(before.st_mode) or before.st_size > 2 * 1024 * 1024:
                    _fail("primary memory evidence source is unsafe or too large")
                raw = os.read(file_fd, 2 * 1024 * 1024 + 1)
                after = os.fstat(file_fd)
                named = os.stat(source, follow_symlinks=False)
                if (
                    len(raw) > 2 * 1024 * 1024
                    or _stat_signature(before) != _stat_signature(after)
                    or _stat_signature(before) != _stat_signature(named)
                ):
                    _fail("primary memory evidence changed while read")
                source_hash = str(payload["source_sha256"])
                matching_records = [
                    line + b"\n"
                    for line in raw.splitlines()
                    if line
                    and hashlib.sha256(line + b"\n").hexdigest() == source_hash
                ]
                if len(matching_records) != 1:
                    _fail("primary memory evidence does not match retained bytes")
                validate_primary_evidence_record(item, matching_records[0])
                self._check_root()
            except MemoryFlowError:
                raise
            except (FileNotFoundError, OSError, VaultSchemaError):
                _fail("primary memory evidence cannot be read safely")
            finally:
                if file_fd is not None:
                    os.close(file_fd)

    @staticmethod
    def _evidence_name(operation_id: str) -> str:
        return memory_evidence_artifact_name(operation_id)

    def _load_run_evidence(
        self, run_id: str, operation_id: str
    ) -> MemoryRunEvidence | None:
        filename = f"{self._evidence_name(operation_id)}.json"
        directory_fd: int | None = None
        try:
            path = self._resolver.resolve(
                "agent/runs", run_id, must_exist=True, for_write=False
            )
            directory_fd = os.open(
                path,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
            opened = os.fstat(directory_fd)
            named = os.stat(path, follow_symlinks=False)
            if (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino):
                _fail("memory run evidence directory changed")
            try:
                raw, _ = _read_at(directory_fd, filename, _MAX_JSON)
            except FileNotFoundError:
                return None
            actual = self._resolver.revalidate(
                path,
                "agent/runs",
                run_id,
                must_exist=True,
                for_write=False,
            )
            linked = os.stat(actual, follow_symlinks=False)
            if (opened.st_dev, opened.st_ino) != (linked.st_dev, linked.st_ino):
                _fail("memory run evidence directory changed")
            return parse_memory_run_evidence(raw)
        except MemoryFlowError:
            raise
        except (OSError, VaultSchemaError):
            _fail("memory run evidence cannot be read safely")
        finally:
            if directory_fd is not None:
                os.close(directory_fd)

    @contextmanager
    def _run_recovery(self, run_id: str) -> Iterator[int]:
        run_fd: int | None = None
        recovery_fd: int | None = None
        try:
            path = self._resolver.resolve(
                "agent/runs", run_id, for_write=True, must_exist=True
            )
            run_fd = os.open(
                path,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
            opened = os.fstat(run_fd)
            named = os.stat(path, follow_symlinks=False)
            if (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino):
                _fail("memory run recovery parent changed")
            recovery_fd = self._mkdir_at(run_fd, "rollback")
            yield recovery_fd
            actual = self._resolver.revalidate(
                path,
                "agent/runs",
                run_id,
                for_write=True,
                must_exist=True,
            )
            linked = os.stat(actual, follow_symlinks=False)
            if (opened.st_dev, opened.st_ino) != (linked.st_dev, linked.st_ino):
                _fail("memory run recovery parent changed")
        except MemoryFlowError:
            raise
        except (OSError, VaultSchemaError):
            _fail("memory run recovery cannot be opened safely")
        finally:
            if recovery_fd is not None:
                os.close(recovery_fd)
            if run_fd is not None:
                os.close(run_fd)

    def _prepare(
        self,
        run_id: str,
        evidence: MemoryRunEvidence,
    ) -> tuple[PreparedArtifact, str, bool]:
        prior = self._load_run_evidence(run_id, evidence.operation_id)
        replayed = prior is not None
        if prior is not None:
            expected = replace(evidence, run_state_sha256=prior.run_state_sha256)
            if prior != expected:
                _fail("memory replay conflicts with durable run evidence")
            evidence = prior
        try:
            prepared = self._runs.prepare_run_artifact(
                run_id,
                name=self._evidence_name(evidence.operation_id),
                data=render_memory_run_evidence(evidence),
                maximum_bytes=_MAX_JSON,
            )
        except RunError as error:
            raise MemoryFlowError(str(error)) from None
        return prepared, evidence.run_state_sha256, replayed

    def _commit_run(self, *, run_id: str, operation_id: str, operation: str, request_hash: str, artifact: PreparedArtifact, run_hash: str, actions: Sequence[ActionCapability], hooks: MemoryCrashHooks) -> None:
        if hooks.before_run_commit is not None:
            hooks.before_run_commit()
        self._require(actions[-1], "record-run-state")
        step = "memory-" + hashlib.sha256((operation + ":" + operation_id).encode()).hexdigest()[:32]
        try:
            state = self._runs.commit_step(run_id, step_id=step, authority=max((item.authority for item in actions), key=lambda item: {"read": 0, "internal-write": 1, "proposal": 2, "domain-write": 3}[item]), input_hash=request_hash, output_hash=artifact.sha256, next_phase=f"memory-{operation}-committed", next_status="running", prepared_artifacts=(artifact,), expected_state_sha256=run_hash, action_uses=tuple(ActionUse(item) for item in actions), authority_policy=self._policy)
        except RunError as error:
            raise MemoryFlowError(str(error)) from None
        if state.get("status") != "running":
            _fail("memory flow must remain running for finalize")

    def _read_sequence(self, caps: MemoryCapabilities) -> tuple[ActionCapability, ActionCapability, ActionCapability]:
        if not isinstance(caps, MemoryCapabilities):
            _fail("memory operation requires MemoryCapabilities")
        read = self._require(caps.read_current_memory, "read-current-memory")
        memory = self._open_zone("agent/memory", for_write=False)
        try:
            self._revalidate(memory, for_write=False)
        finally:
            os.close(memory.fd)
        evidence = self._require(caps.check_evidence_and_retention, "check-evidence-and-retention")
        logs = self._open_zone("agent/logs", for_write=False)
        try:
            self._revalidate(logs, for_write=False)
        finally:
            os.close(logs.fd)
        review = self._require(caps.read_memory_review_state, "read-memory-review-state")
        review_zone = self._open_zone("review", for_write=False)
        try:
            self._revalidate(review_zone, for_write=False)
        finally:
            os.close(review_zone.fd)
        return read, evidence, review

    def propose(
        self,
        capabilities: MemoryCapabilities,
        proposal: MemoryProposalRecord,
        *,
        crash_hooks: MemoryCrashHooks | None = None,
    ) -> MemoryMutationResult:
        hooks = self._hooks(crash_hooks)
        checked = parse_memory_proposal(render_memory_proposal(proposal))
        if checked.producer_flow != "memory" or checked.status != "proposed":
            _fail("memory flow can publish only its proposed records")
        run_id, run_hash = self._check_run(checked.run_id)
        reads = self._read_sequence(capabilities)
        self._verify_primary_evidence(checked.evidence)
        if checked.current_memory_ref is not None:
            current = self._semantic_bytes(checked.current_memory_ref)
            if (
                current is None
                or hashlib.sha256(current).hexdigest()
                != checked.precondition_sha256
            ):
                _fail("memory proposal current precondition is stale")
        commit = self._require(capabilities.commit_semantic_memory_proposal, "commit-semantic-memory-proposal")
        run = self._require(capabilities.record_run_state, "record-run-state")
        raw = render_memory_proposal(checked)
        request = {"schema_version": 1, "operation": "propose", "proposal_sha256": hashlib.sha256(raw).hexdigest()}
        request_hash = hashlib.sha256(_canonical(request)).hexdigest()
        evidence = MemoryRunEvidence(
            operation_id=checked.operation_id,
            operation="propose",
            output_ref=f"review/{checked.proposal_id}.memory.json",
            request_sha256=request_hash,
            run_state_sha256=run_hash,
            preimage_sha256=None,
            target_sha256=hashlib.sha256(raw).hexdigest(),
            outcome_class="proposal-pending",
        )
        prepared, run_hash, evidence_replay = self._prepare(run_id, evidence)
        if hooks.after_prepare is not None:
            hooks.after_prepare()
        with self._run_recovery(run_id) as recovery_fd:
            zone = self._open_zone("review", for_write=True)
            try:
                self._require(commit, "commit-semantic-memory-proposal")
                created = _create_once(
                    zone.fd,
                    f"{checked.proposal_id}.memory.json",
                    raw,
                    _MAX_PROPOSAL,
                    recovery_fd,
                    f"proposal-{checked.operation_id}",
                    lambda: self._revalidate(zone, for_write=True),
                )
                self._revalidate(zone, for_write=True)
            finally:
                os.close(zone.fd)
        if hooks.after_domain_publish is not None:
            hooks.after_domain_publish()
        self._commit_run(run_id=run_id, operation_id=checked.operation_id, operation="propose", request_hash=request_hash, artifact=prepared, run_hash=run_hash, actions=(*reads, commit, run), hooks=hooks)
        return MemoryMutationResult(checked.operation_id, "propose", f"review/{checked.proposal_id}.memory.json", None, None, evidence_replay or not created, hashlib.sha256(raw).hexdigest())

    def list_metadata(self, capability: ActionCapability) -> tuple[MemoryMetadataRecord, ...]:
        self._require(capability, "read-current-memory")
        return self._list_metadata()

    def _list_metadata(self) -> tuple[MemoryMetadataRecord, ...]:
        zone = self._open_optional_zone("agent/memory-metadata")
        if zone is None:
            return ()
        records_fd: int | None = None
        try:
            try:
                records_fd = os.open("records", os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0), dir_fd=zone.fd)
            except FileNotFoundError:
                return ()
            names = os.listdir(records_fd)
            if len(names) > _MAX_RECORDS:
                _fail("memory metadata has too many records")
            result = []
            for name in sorted(names, key=_portable):
                if not name.endswith(".json"):
                    _fail("memory metadata namespace contains an unknown entry")
                raw, _ = _read_at(records_fd, name, _MAX_METADATA)
                record = parse_memory_metadata(raw)
                if name != f"{record.memory_id}.json":
                    _fail("memory metadata filename disagrees with id")
                result.append(record)
            self._revalidate(zone, for_write=False)
            return tuple(sorted(result, key=lambda item: _portable(item.memory_id)))
        finally:
            if records_fd is not None:
                os.close(records_fd)
            os.close(zone.fd)

    def stale(self, capability: ActionCapability, query: MemoryHygieneQuery) -> tuple[StaleMemory, ...]:
        if not isinstance(query, MemoryHygieneQuery) or query.schema_version != 1:
            _fail("memory hygiene query is invalid")
        as_of = _timestamp(query.as_of, "query as_of")
        threshold = _exact_int(query.threshold_days, "threshold_days", 0, 36500)
        limit = _exact_int(query.limit, "query limit", 1, _MAX_RECORDS)
        if not isinstance(query.kinds, tuple) or any(type(kind) is not str or kind not in _MEMORY_KINDS for kind in query.kinds):
            _fail("memory hygiene query kinds are invalid")
        result = []
        instant = _instant(as_of)
        for record in self.list_metadata(capability):
            if record.status in {"forgotten", "deleted"}:
                continue
            if query.kinds and record.memory_kind not in query.kinds:
                continue
            reasons: list[str] = []
            boundaries = [_instant(record.last_confirmed_at) + timedelta(days=threshold)]
            if record.retention.mode == "review" and record.retention.review_at is not None:
                boundaries.append(_instant(record.retention.review_at))
                if instant >= boundaries[-1]:
                    reasons.append("retention-review")
            if record.retention.mode == "until" and record.retention.retain_until is not None:
                retain_until = _instant(record.retention.retain_until)
                boundaries.append(retain_until)
                if instant >= retain_until:
                    reasons.append("retention-ended")
            if record.decay.mode == "stale-after" and record.decay.stale_after_days is not None:
                decay_at = _instant(record.last_confirmed_at) + timedelta(days=record.decay.stale_after_days)
                boundaries.append(decay_at)
                if instant >= decay_at:
                    reasons.append("decayed")
            if record.decay.mode == "expires" and record.decay.expires_at is not None:
                expires_at = _instant(record.decay.expires_at)
                boundaries.append(expires_at)
                if instant >= expires_at:
                    reasons.append("expired")
            if instant >= boundaries[0]:
                reasons.append("threshold")
            if reasons:
                result.append(StaleMemory(record, tuple(sorted(set(reasons))), min(boundaries).isoformat().replace("+00:00", "Z")))
        return tuple(sorted(result, key=lambda item: (_instant(item.stale_since), _portable(item.metadata.memory_id))))[:limit]

    def propose_stale_review(
        self,
        capabilities: MemoryCapabilities,
        stale: StaleMemory,
        proposal: MemoryProposalRecord,
        *,
        crash_hooks: MemoryCrashHooks | None = None,
    ) -> MemoryMutationResult:
        if (
            not isinstance(stale, StaleMemory)
            or not isinstance(stale.reasons, tuple)
            or not stale.reasons
            or any(
                type(reason) is not str
                or reason
                not in {
                    "threshold",
                    "retention-review",
                    "retention-ended",
                    "decayed",
                    "expired",
                }
                for reason in stale.reasons
            )
        ):
            _fail("stale memory review input is invalid")
        if (
            proposal.operation not in {"retain", "decay", "delete"}
            or proposal.memory_id != stale.metadata.memory_id
            or proposal.current_memory_ref != stale.metadata.semantic_ref
            or proposal.current_memory_sha256 != stale.metadata.semantic_sha256
            or proposal.precondition_sha256 != stale.metadata.semantic_sha256
        ):
            _fail("stale memory review must bind the exact current memory")
        return self.propose(
            capabilities,
            proposal,
            crash_hooks=crash_hooks,
        )

    def commit_metadata(
        self,
        capabilities: MemoryCapabilities,
        *,
        run_id: str,
        operation_id: str,
        record: MemoryMetadataRecord,
        expected_revision: int | None = None,
        crash_hooks: MemoryCrashHooks | None = None,
    ) -> MemoryMutationResult:
        hooks = self._hooks(crash_hooks)
        checked_run, run_hash = self._check_run(run_id)
        checked_op = _identifier(operation_id, "operation_id")
        reads = self._read_sequence(capabilities)
        proposal, _ = self._proposal(record.proposal_id)
        if proposal.status != "approved" or proposal.memory_id != record.memory_id or proposal.memory_kind != record.memory_kind or proposal.scope != record.scope:
            _fail("metadata requires an exact approved memory proposal")
        self._verify_primary_evidence(proposal.evidence)
        semantic = self._semantic_bytes(record.semantic_ref)
        if semantic is None or hashlib.sha256(semantic).hexdigest() != record.semantic_sha256:
            _fail("metadata semantic precondition is not present")
        try:
            semantic_text = semantic.decode("utf-8")
        except UnicodeError:
            _fail("semantic memory is not UTF-8 text")
        if (
            semantic_text != proposal.candidate_text
            or record.evidence
            != tuple(
                EvidenceBinding(item.evidence_id, item.source_sha256)
                for item in proposal.evidence
            )
            or record.retention != proposal.retention
            or record.decay != proposal.decay
            or record.deletion != proposal.deletion
        ):
            _fail("metadata disagrees with the approved proposal")
        requested = _metadata_payload(record)
        requested["last_operation_id"] = checked_op
        requested["last_operation_sha256"] = None
        request_base = {"schema_version": 1, "operation": "commit-metadata", "operation_id": checked_op, "record": requested, "expected_revision": expected_revision}
        request_hash = hashlib.sha256(_canonical(request_base)).hexdigest()
        record = replace(
            record,
            last_operation_id=checked_op,
            last_operation_sha256=request_hash,
        )
        commit = self._require(capabilities.commit_deterministic_memory_metadata, "commit-deterministic-memory-metadata")
        run = self._require(capabilities.record_run_state, "record-run-state")
        raw = render_memory_metadata(record)
        prior_evidence = self._load_run_evidence(checked_run, checked_op)
        old = next(
            (
                item
                for item in self._list_metadata()
                if item.memory_id == record.memory_id
            ),
            None,
        )
        old_raw = None if old is None else render_memory_metadata(old)
        replayed = old_raw == raw
        if replayed:
            pass
        elif old is None:
            if expected_revision is not None or record.revision != 1:
                _fail("metadata create revision is stale")
        elif (
            type(expected_revision) is not int
            or old.revision != expected_revision
            or record.revision != old.revision + 1
            or old.memory_id != record.memory_id
        ):
            _fail("metadata expected revision is stale")
        evidence = MemoryRunEvidence(
            operation_id=checked_op,
            operation="commit-metadata",
            output_ref=f"agent/memory/metadata/records/{record.memory_id}.json",
            request_sha256=request_hash,
            run_state_sha256=run_hash,
            preimage_sha256=(
                prior_evidence.preimage_sha256
                if prior_evidence is not None
                else (
                    None
                    if old_raw is None
                    else hashlib.sha256(old_raw).hexdigest()
                )
            ),
            target_sha256=hashlib.sha256(raw).hexdigest(),
            outcome_class="deterministic-metadata",
        )
        prepared, run_hash, evidence_replay = self._prepare(
            checked_run, evidence
        )
        if hooks.after_prepare is not None:
            hooks.after_prepare()
        if not replayed:
            with self._run_recovery(checked_run) as recovery_fd:
                with self._metadata_dirs() as (
                    memory_zone,
                    metadata_fd,
                    records_fd,
                    outcomes_fd,
                ):
                    name = f"{record.memory_id}.json"
                    try:
                        actual_old, old_identity = _read_at(
                            records_fd, name, _MAX_METADATA
                        )
                    except FileNotFoundError:
                        actual_old, old_identity = None, None
                    if actual_old != old_raw:
                        _fail("memory metadata changed before publication")

                    def validate_parent() -> None:
                        self._revalidate_metadata_dirs(
                            memory_zone,
                            metadata_fd,
                            records_fd,
                            outcomes_fd,
                        )

                    self._require(
                        commit, "commit-deterministic-memory-metadata"
                    )
                    _atomic_replace(
                        records_fd,
                        name,
                        raw,
                        old_identity,
                        _MAX_METADATA,
                        validate_parent,
                        recovery_fd,
                        f"metadata-{checked_op}",
                    )
        if hooks.after_domain_publish is not None:
            hooks.after_domain_publish()
        self._commit_run(run_id=checked_run, operation_id=checked_op, operation="commit-metadata", request_hash=request_hash, artifact=prepared, run_hash=run_hash, actions=(*reads, commit, run), hooks=hooks)
        return MemoryMutationResult(checked_op, "commit-metadata", None, record, None, evidence_replay or replayed, hashlib.sha256(raw).hexdigest())

    def forget(
        self,
        capabilities: MemoryCapabilities,
        *,
        run_id: str,
        operation_id: str,
        request: ForgetRequest,
        crash_hooks: MemoryCrashHooks | None = None,
    ) -> MemoryMutationResult:
        hooks = self._hooks(crash_hooks)
        if not isinstance(request, ForgetRequest) or request.schema_version != 1:
            _fail("forget request is invalid")
        outcome_id = _identifier(request.outcome_id, "outcome_id", _FORGET_ID)
        memory_id = _identifier(request.memory_id, "memory_id", _MEMORY_ID)
        proposal_id = _identifier(request.proposal_id, "proposal_id", _PROPOSAL_ID)
        verified_at = _timestamp(request.verified_at, "verified_at")
        checked_run, run_hash = self._check_run(run_id)
        checked_op = _identifier(operation_id, "operation_id")
        reads = self._read_sequence(capabilities)
        proposal, proposal_raw = self._proposal(proposal_id)
        if proposal.memory_id != memory_id:
            _fail("forget request does not match proposal")
        self._verify_primary_evidence(proposal.evidence)
        request_payload = {
            "schema_version": 1,
            "operation": "forget",
            "operation_id": checked_op,
            "request": {
                "schema_version": 1,
                "outcome_id": outcome_id,
                "memory_id": memory_id,
                "proposal_id": proposal_id,
                "verified_at": verified_at,
            },
            "proposal_sha256": hashlib.sha256(proposal_raw).hexdigest(),
        }
        request_hash = hashlib.sha256(_canonical(request_payload)).hexdigest()
        prior_evidence = self._load_run_evidence(checked_run, checked_op)
        metadata = next(
            (item for item in self._list_metadata() if item.memory_id == memory_id),
            None,
        )
        current_raw = None if metadata is None else render_memory_metadata(metadata)

        existing_outcome: ForgetOutcome | None = None
        outcomes_zone = self._open_optional_zone("agent/memory-metadata")
        if outcomes_zone is not None:
            outcomes_fd: int | None = None
            try:
                try:
                    outcomes_fd = os.open(
                        "outcomes",
                        os.O_RDONLY
                        | getattr(os, "O_DIRECTORY", 0)
                        | getattr(os, "O_NOFOLLOW", 0),
                        dir_fd=outcomes_zone.fd,
                    )
                    outcome_bytes, _ = _read_at(
                        outcomes_fd, f"{outcome_id}.json", _MAX_METADATA
                    )
                except FileNotFoundError:
                    pass
                else:
                    existing_outcome = parse_forget_outcome(outcome_bytes)
            finally:
                if outcomes_fd is not None:
                    os.close(outcomes_fd)
                os.close(outcomes_zone.fd)

        target_metadata: MemoryMetadataRecord | None
        if metadata is None:
            if proposal.status not in {"rejected", "superseded"}:
                _fail("never-shared forget requires a rejected proposal")
            target_metadata = None
            outcome = ForgetOutcome(
                outcome_id,
                memory_id,
                proposal_id,
                "proposal-never-shared",
                None,
                None,
                verified_at,
                None,
            )
        else:
            if proposal.operation != "forget" or proposal.status != "approved":
                _fail("shared forget requires an approved forget proposal")
            if metadata.status == "forgotten":
                if (
                    existing_outcome is None
                    or existing_outcome.metadata_sha256
                    != hashlib.sha256(current_raw or b"").hexdigest()
                ):
                    _fail("forgotten metadata lacks its exact outcome")
                target_metadata = metadata
                outcome = existing_outcome
            else:
                semantic = self._semantic_bytes(metadata.semantic_ref)
                if semantic is not None:
                    _fail("forget cannot verify semantic absence")
                verification = "semantic-absence-verified"
                if metadata.deletion.mode == "archive":
                    if metadata.deletion.archive_ref is None:
                        _fail("archive deletion policy lacks its archive ref")
                    archived = self._semantic_bytes(
                        metadata.deletion.archive_ref, archive=True
                    )
                    if (
                        archived is None
                        or hashlib.sha256(archived).hexdigest()
                        != metadata.semantic_sha256
                    ):
                        _fail("forget cannot verify the archived semantic bytes")
                    verification = "archive-ref-verified"
                target_metadata = replace(
                    metadata,
                    status="forgotten",
                    revision=metadata.revision + 1,
                    last_operation_id=checked_op,
                    last_operation_sha256=request_hash,
                )
                target_raw = render_memory_metadata(target_metadata)
                outcome = ForgetOutcome(
                    outcome_id,
                    memory_id,
                    proposal_id,
                    verification,
                    metadata.semantic_ref,
                    metadata.semantic_sha256,
                    verified_at,
                    hashlib.sha256(target_raw).hexdigest(),
                )
        outcome_raw = render_forget_outcome(outcome)
        if existing_outcome is not None and outcome != existing_outcome:
            _fail("forget replay conflicts with the existing outcome")
        commit = self._require(capabilities.commit_deterministic_memory_metadata, "commit-deterministic-memory-metadata")
        run = self._require(capabilities.record_run_state, "record-run-state")
        evidence = MemoryRunEvidence(
            operation_id=checked_op,
            operation="forget",
            output_ref=f"agent/memory/metadata/outcomes/{outcome_id}.json",
            request_sha256=request_hash,
            run_state_sha256=run_hash,
            preimage_sha256=(
                prior_evidence.preimage_sha256
                if prior_evidence is not None
                else (None if current_raw is None else hashlib.sha256(current_raw).hexdigest())
            ),
            target_sha256=hashlib.sha256(outcome_raw).hexdigest(),
            outcome_class="deterministic-metadata",
        )
        prepared, run_hash, evidence_replay = self._prepare(checked_run, evidence)
        if hooks.after_prepare is not None:
            hooks.after_prepare()
        with self._run_recovery(checked_run) as recovery_fd:
            with self._metadata_dirs() as (
                _memory,
                metadata_fd,
                records_fd,
                outcomes_fd,
            ):
                def validate() -> None:
                    self._revalidate_metadata_dirs(
                        _memory, metadata_fd, records_fd, outcomes_fd
                    )
                self._require(commit, "commit-deterministic-memory-metadata")
                created = _create_once(
                    outcomes_fd,
                    f"{outcome.outcome_id}.json",
                    outcome_raw,
                    _MAX_METADATA,
                    recovery_fd,
                    f"outcome-{checked_op}",
                    validate,
                )
                if target_metadata is not None:
                    name = f"{target_metadata.memory_id}.json"
                    old_raw, old_identity = _read_at(
                        records_fd, name, _MAX_METADATA
                    )
                    target_raw = render_memory_metadata(target_metadata)
                    if old_raw != target_raw:
                        _atomic_replace(
                            records_fd,
                            name,
                            target_raw,
                            old_identity,
                            _MAX_METADATA,
                            validate,
                            recovery_fd,
                            f"forget-metadata-{checked_op}",
                        )
        if hooks.after_domain_publish is not None:
            hooks.after_domain_publish()
        self._commit_run(run_id=checked_run, operation_id=checked_op, operation="forget", request_hash=request_hash, artifact=prepared, run_hash=run_hash, actions=(*reads, commit, run), hooks=hooks)
        return MemoryMutationResult(checked_op, "forget", None, target_metadata, outcome, evidence_replay or not created, hashlib.sha256(outcome_raw).hexdigest())
