"""Bounded report logs and proposal-only memory extraction.

Daily and weekly records are retained append-only projections.  Semantic
memory candidates are immutable review proposals and never shared-memory
writes.  Every memory candidate is bound to retained primary human bytes.
"""

from __future__ import annotations

import ctypes
from contextlib import contextmanager
from dataclasses import dataclass, replace
from datetime import date, datetime, timezone
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
from typing import Callable, Iterator, Mapping, Sequence
import unicodedata
import uuid

from tool_life_os_runtime.ext.flows.memory import (
    DecayPolicy,
    DeletionPolicy,
    MemoryEvidence,
    MemoryFlowError,
    MemoryProposalRecord,
    RetentionPolicy,
    parse_memory_proposal,
    render_memory_proposal,
    validate_primary_evidence_record,
)
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


REPORT_SCHEMA_VERSION = 1

_MAX_JSON = 512 * 1024
_MAX_LINE = 128 * 1024
_MAX_LOG = 4 * 1024 * 1024
_MAX_RECORDS = 4096
_MAX_TEXT = 32 * 1024
_MAX_MATERIALS = 64
_MAX_CONTEXT = 128
_ID = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
_REPORT_ID = re.compile(r"^rpt-[a-z0-9][a-z0-9_-]{0,58}$")
_REFLECTION_ID = re.compile(r"^refl-[a-z0-9][a-z0-9_-]{0,57}$")
_PROPOSAL_ID = re.compile(r"^memprop-[a-z0-9][a-z0-9_-]{0,54}$")
_RUN_ID = re.compile(r"^run_[a-z0-9][a-z0-9_-]{0,62}$")
_SHA = re.compile(r"^[0-9a-f]{64}$")
_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$")
_DAY = re.compile(r"^\d{4}-\d{2}-\d{2}$")
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
_CONTEXT_KINDS = {
    "project": ("projects", "projects/"),
    "task": ("tasks", "tasks/"),
    "entity": ("agent/memory", "agent/memory/entities/"),
    "memory": ("agent/memory", "agent/memory/"),
}
_ARCHIVES = frozenset({"_archive", "_trash", "_on_hold"})


class ReportFlowError(ValueError):
    """Report input, authority, persistence, or replay state is invalid."""


def _fail(message: str) -> None:
    raise ReportFlowError(message)


def _portable(value: str) -> str:
    try:
        value.encode("utf-8")
    except UnicodeError:
        _fail("report namespace is not portable")
    if unicodedata.normalize("NFC", value) != value or any(
        unicodedata.category(char).startswith("C")
        or unicodedata.category(char) in {"Zl", "Zp"}
        for char in value
    ):
        _fail("report namespace is not portable")
    return value.casefold()


def _text(
    value: object,
    label: str,
    maximum: int = 4096,
    *,
    layout: bool = False,
) -> str:
    if type(value) is not str or not value or len(value) > maximum:
        _fail(f"{label} is invalid")
    try:
        value.encode("utf-8")
    except UnicodeError:
        _fail(f"{label} is invalid")
    if unicodedata.normalize("NFC", value) != value or any(
        (
            unicodedata.category(char).startswith("C")
            and not (layout and char in "\n\t")
        )
        or unicodedata.category(char) in {"Zl", "Zp"}
        for char in value
    ):
        _fail(f"{label} is invalid")
    lowered = value.casefold()
    if "/users/" in lowered or "/home/" in lowered or "file:" in lowered:
        _fail(f"{label} contains a private path")
    return value


def _identifier(
    value: object, label: str, pattern: re.Pattern[str] = _ID
) -> str:
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


def _date(value: object, label: str, *, monday: bool = False) -> str:
    checked = _text(value, label, 10)
    if _DAY.fullmatch(checked) is None:
        _fail(f"{label} is invalid")
    try:
        parsed = date.fromisoformat(checked)
    except ValueError:
        _fail(f"{label} is invalid")
    if monday and parsed.weekday() != 0:
        _fail(f"{label} must be a Monday")
    return checked


def _hash(value: object, label: str) -> str:
    checked = _text(value, label, 64)
    if _SHA.fullmatch(checked) is None:
        _fail(f"{label} is invalid")
    return checked


def _safe_ref(value: object, label: str) -> str:
    checked = _text(value, label, 2048)
    if "\\" in checked:
        _fail(f"{label} is invalid")
    path = PurePosixPath(checked)
    if (
        path.is_absolute()
        or path == PurePosixPath(".")
        or ".." in path.parts
        or path.as_posix() != checked
        or any(_portable(part) in _ARCHIVES for part in path.parts)
    ):
        _fail(f"{label} is invalid")
    return checked


def _canonical(value: object, maximum: int = _MAX_JSON) -> bytes:
    try:
        raw = (
            json.dumps(
                value,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
            + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError):
        _fail("report payload is not canonical JSON")
    if len(raw) > maximum:
        _fail("report payload is too large")
    return raw


def _pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            _fail("report JSON has duplicate fields")
        result[key] = value
    return result


def _decode(raw: bytes | str, label: str, maximum: int) -> object:
    if isinstance(raw, str):
        try:
            source = raw.encode("utf-8")
        except UnicodeError:
            _fail(f"{label} is invalid")
    elif isinstance(raw, bytes):
        source = raw
    else:
        _fail(f"{label} is invalid")
    if not source or len(source) > maximum:
        _fail(f"{label} is invalid")
    try:
        return json.loads(source, object_pairs_hook=_pairs)
    except ReportFlowError:
        raise
    except (UnicodeError, ValueError, RecursionError):
        _fail(f"{label} is invalid")


def _mapping(
    value: object, label: str, keys: frozenset[str]
) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or set(value) != keys:
        _fail(f"{label} has missing or unknown fields")
    return value


@dataclass(frozen=True)
class HumanMaterial:
    material_id: str
    kind: str
    actor: str
    occurred_at: str
    exact_text: str
    schema_version: int = REPORT_SCHEMA_VERSION


@dataclass(frozen=True)
class ReportContextItem:
    kind: str
    logical_ref: str
    state_sha256: str
    schema_version: int = REPORT_SCHEMA_VERSION


@dataclass(frozen=True)
class ReportContext:
    items: tuple[ReportContextItem, ...] = ()
    schema_version: int = REPORT_SCHEMA_VERSION


@dataclass(frozen=True)
class DailyLogRecord:
    report_id: str
    day: str
    run_id: str
    operation_id: str
    recorded_at: str
    materials: tuple[HumanMaterial, ...]
    context: ReportContext
    reflection_text: str
    record_type: str = "daily"
    schema_version: int = REPORT_SCHEMA_VERSION


@dataclass(frozen=True)
class WeeklyReflection:
    reflection_id: str
    week_start: str
    run_id: str
    operation_id: str
    recorded_at: str
    primary_evidence: tuple[MemoryEvidence, ...]
    context: ReportContext
    reflection_text: str
    record_type: str = "weekly"
    schema_version: int = REPORT_SCHEMA_VERSION


@dataclass(frozen=True)
class MemoryExtractionEvent:
    event_id: str
    run_id: str
    operation_id: str
    recorded_at: str
    proposal_id: str
    proposal_sha256: str
    evidence_ids: tuple[str, ...]
    record_type: str = "memory-extracted"
    schema_version: int = REPORT_SCHEMA_VERSION


@dataclass(frozen=True)
class ReportMutationResult:
    operation_id: str
    operation: str
    log_ref: str
    proposal_ref: str | None
    replayed: bool
    output_sha256: str
    schema_version: int = REPORT_SCHEMA_VERSION


@dataclass(frozen=True)
class ReportRunEvidence:
    operation_id: str
    operation: str
    output_ref: str
    request_sha256: str
    run_state_sha256: str
    log_preimage_sha256: str
    log_line_sha256: str
    proposal_ref: str | None
    proposal_sha256: str | None
    outcome_class: str
    role: str = "report-operation-evidence"
    flow: str = "report"
    schema_version: int = REPORT_SCHEMA_VERSION


@dataclass(frozen=True)
class ReportCapabilities:
    read_report_projects: ActionCapability
    read_report_tasks: ActionCapability
    collect_primary_evidence: ActionCapability
    read_report_memory: ActionCapability
    commit_memory_proposal: ActionCapability
    append_report_log: ActionCapability
    record_run_state: ActionCapability


@dataclass(frozen=True)
class ReportCrashHooks:
    after_prepare: Callable[[], None] | None = None
    after_proposal_publish: Callable[[], None] | None = None
    after_log_publish: Callable[[], None] | None = None
    before_run_commit: Callable[[], None] | None = None


def _material_payload(value: HumanMaterial) -> dict[str, object]:
    if not isinstance(value, HumanMaterial) or value.schema_version != 1:
        _fail("human material is invalid")
    if type(value.kind) is not str or value.kind not in _PRIMARY_KINDS:
        _fail("human material kind is invalid")
    if type(value.actor) is not str or value.actor not in {
        "human",
        "runtime-human-confirmed",
    }:
        _fail("report material is not exact human input")
    return {
        "schema_version": 1,
        "material_id": _identifier(value.material_id, "material_id"),
        "kind": value.kind,
        "actor": value.actor,
        "occurred_at": _timestamp(value.occurred_at, "material occurred_at"),
        "exact_text": _text(
            value.exact_text, "material exact_text", _MAX_TEXT, layout=True
        ),
    }


def _parse_material(value: object) -> HumanMaterial:
    item = _mapping(
        value,
        "human material",
        frozenset(
            {
                "schema_version",
                "material_id",
                "kind",
                "actor",
                "occurred_at",
                "exact_text",
            }
        ),
    )
    result = HumanMaterial(
        item["material_id"],
        item["kind"],
        item["actor"],
        item["occurred_at"],
        item["exact_text"],
        item["schema_version"],
    )
    _material_payload(result)
    return result


def _context_item_payload(value: ReportContextItem) -> dict[str, object]:
    if not isinstance(value, ReportContextItem) or value.schema_version != 1:
        _fail("report context item is invalid")
    if type(value.kind) is not str or value.kind not in _CONTEXT_KINDS:
        _fail("report context kind is invalid")
    logical_ref = _safe_ref(value.logical_ref, "context logical_ref")
    if not logical_ref.startswith(_CONTEXT_KINDS[value.kind][1]):
        _fail("report context ref disagrees with kind")
    if value.kind == "memory" and logical_ref.startswith(
        ("agent/memory/metadata/", "agent/memory/entities/", "agent/memory/trails/")
    ):
        _fail("semantic memory context cannot alias runtime metadata")
    return {
        "schema_version": 1,
        "kind": value.kind,
        "logical_ref": logical_ref,
        "state_sha256": _hash(value.state_sha256, "context state_sha256"),
    }


def _parse_context_item(value: object) -> ReportContextItem:
    item = _mapping(
        value,
        "report context item",
        frozenset({"schema_version", "kind", "logical_ref", "state_sha256"}),
    )
    result = ReportContextItem(
        item["kind"], item["logical_ref"], item["state_sha256"], item["schema_version"]
    )
    _context_item_payload(result)
    return result


def _context_payload(value: ReportContext) -> dict[str, object]:
    if (
        not isinstance(value, ReportContext)
        or value.schema_version != 1
        or not isinstance(value.items, tuple)
        or len(value.items) > _MAX_CONTEXT
    ):
        _fail("report context is invalid")
    items = tuple(_context_item_payload(item) for item in value.items)
    keys = [(_portable(str(item["kind"])), _portable(str(item["logical_ref"]))) for item in items]
    if len(keys) != len(set(keys)) or keys != sorted(keys):
        _fail("report context must be uniquely and deterministically ordered")
    return {"schema_version": 1, "items": list(items)}


def _parse_context(value: object) -> ReportContext:
    item = _mapping(
        value, "report context", frozenset({"schema_version", "items"})
    )
    values = item["items"]
    if not isinstance(values, list):
        _fail("report context items are invalid")
    result = ReportContext(
        tuple(_parse_context_item(value) for value in values), item["schema_version"]
    )
    _context_payload(result)
    return result


def _daily_payload(value: DailyLogRecord) -> dict[str, object]:
    if (
        not isinstance(value, DailyLogRecord)
        or value.schema_version != 1
        or value.record_type != "daily"
        or not isinstance(value.materials, tuple)
        or not value.materials
        or len(value.materials) > _MAX_MATERIALS
    ):
        _fail("daily log record is invalid")
    materials = tuple(_material_payload(item) for item in value.materials)
    ids = [_portable(str(item["material_id"])) for item in materials]
    if len(ids) != len(set(ids)):
        _fail("daily material ids collide")
    day = _date(value.day, "daily day")
    recorded = _timestamp(value.recorded_at, "daily recorded_at")
    if recorded[:10] != day:
        _fail("daily record timestamp disagrees with day")
    return {
        "schema_version": 1,
        "record_type": "daily",
        "report_id": _identifier(value.report_id, "report_id", _REPORT_ID),
        "day": day,
        "run_id": _identifier(value.run_id, "run_id", _RUN_ID),
        "operation_id": _identifier(value.operation_id, "operation_id"),
        "recorded_at": recorded,
        "materials": list(materials),
        "context": _context_payload(value.context),
        "reflection_text": _text(
            value.reflection_text, "daily reflection_text", _MAX_TEXT, layout=True
        ),
    }


def render_daily_log(value: DailyLogRecord) -> bytes:
    return _canonical(_daily_payload(value), _MAX_LINE)


def parse_daily_log(raw: bytes | str) -> DailyLogRecord:
    keys = frozenset(
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
    item = _mapping(_decode(raw, "daily log", _MAX_LINE), "daily log", keys)
    materials = item["materials"]
    if not isinstance(materials, list):
        _fail("daily materials are invalid")
    result = DailyLogRecord(
        item["report_id"],
        item["day"],
        item["run_id"],
        item["operation_id"],
        item["recorded_at"],
        tuple(_parse_material(value) for value in materials),
        _parse_context(item["context"]),
        item["reflection_text"],
        item["record_type"],
        item["schema_version"],
    )
    source = raw.encode("utf-8") if isinstance(raw, str) else raw
    if source != render_daily_log(result):
        _fail("daily log must use canonical JSON")
    return result


def _memory_evidence_payload(value: MemoryEvidence) -> dict[str, object]:
    proposal = MemoryProposalRecord(
        proposal_id="memprop-validation",
        status="proposed",
        operation="create",
        memory_id="mem-validation",
        memory_kind="episodic",
        scope="validation",
        candidate_text="validation",
        evidence=(value,),
        current_memory_ref=None,
        current_memory_sha256=None,
        precondition_sha256=None,
        retention=RetentionPolicy("manual"),
        decay=DecayPolicy("none"),
        deletion=DeletionPolicy("forget"),
        producer_flow="report",
        run_id="run_validation",
        operation_id="validation",
        created_at="2000-01-01T00:00:00Z",
    )
    try:
        return json.loads(render_memory_proposal(proposal))["evidence"][0]
    except MemoryFlowError as error:
        raise ReportFlowError(str(error)) from None


def _parse_memory_evidence(value: object) -> MemoryEvidence:
    payload = {
        "schema_version": 1,
        "proposal_id": "memprop-validation",
        "status": "proposed",
        "operation": "create",
        "memory_id": "mem-validation",
        "memory_kind": "episodic",
        "scope": "validation",
        "candidate_text": "validation",
        "evidence": [value],
        "current_memory_ref": None,
        "current_memory_sha256": None,
        "precondition_sha256": None,
        "retention": {"schema_version": 1, "mode": "manual", "review_at": None, "retain_until": None},
        "decay": {"schema_version": 1, "mode": "none", "stale_after_days": None, "expires_at": None},
        "deletion": {"schema_version": 1, "mode": "forget", "archive_ref": None},
        "producer_flow": "report",
        "run_id": "run_validation",
        "operation_id": "validation",
        "created_at": "2000-01-01T00:00:00Z",
        "human_decision": None,
    }
    try:
        proposal = parse_memory_proposal(_canonical(payload))
    except MemoryFlowError as error:
        raise ReportFlowError(str(error)) from None
    return proposal.evidence[0]


def _weekly_payload(value: WeeklyReflection) -> dict[str, object]:
    if (
        not isinstance(value, WeeklyReflection)
        or value.schema_version != 1
        or value.record_type != "weekly"
        or not isinstance(value.primary_evidence, tuple)
        or not value.primary_evidence
        or len(value.primary_evidence) > _MAX_MATERIALS
    ):
        _fail("weekly reflection is invalid")
    evidence = tuple(_memory_evidence_payload(item) for item in value.primary_evidence)
    ids = [_portable(str(item["evidence_id"])) for item in evidence]
    if len(ids) != len(set(ids)):
        _fail("weekly evidence ids collide")
    return {
        "schema_version": 1,
        "record_type": "weekly",
        "reflection_id": _identifier(
            value.reflection_id, "reflection_id", _REFLECTION_ID
        ),
        "week_start": _date(value.week_start, "week_start", monday=True),
        "run_id": _identifier(value.run_id, "run_id", _RUN_ID),
        "operation_id": _identifier(value.operation_id, "operation_id"),
        "recorded_at": _timestamp(value.recorded_at, "weekly recorded_at"),
        "primary_evidence": list(evidence),
        "context": _context_payload(value.context),
        "reflection_text": _text(
            value.reflection_text, "weekly reflection_text", _MAX_TEXT, layout=True
        ),
    }


def render_weekly_reflection(value: WeeklyReflection) -> bytes:
    return _canonical(_weekly_payload(value), _MAX_LINE)


def parse_weekly_reflection(raw: bytes | str) -> WeeklyReflection:
    keys = frozenset(
        {
            "schema_version",
            "record_type",
            "reflection_id",
            "week_start",
            "run_id",
            "operation_id",
            "recorded_at",
            "primary_evidence",
            "context",
            "reflection_text",
        }
    )
    item = _mapping(
        _decode(raw, "weekly reflection", _MAX_LINE), "weekly reflection", keys
    )
    evidence = item["primary_evidence"]
    if not isinstance(evidence, list):
        _fail("weekly primary evidence is invalid")
    result = WeeklyReflection(
        item["reflection_id"],
        item["week_start"],
        item["run_id"],
        item["operation_id"],
        item["recorded_at"],
        tuple(_parse_memory_evidence(value) for value in evidence),
        _parse_context(item["context"]),
        item["reflection_text"],
        item["record_type"],
        item["schema_version"],
    )
    source = raw.encode("utf-8") if isinstance(raw, str) else raw
    if source != render_weekly_reflection(result):
        _fail("weekly reflection must use canonical JSON")
    return result


def _extraction_payload(value: MemoryExtractionEvent) -> dict[str, object]:
    if (
        not isinstance(value, MemoryExtractionEvent)
        or value.schema_version != 1
        or value.record_type != "memory-extracted"
        or not isinstance(value.evidence_ids, tuple)
        or not value.evidence_ids
        or len(value.evidence_ids) > _MAX_MATERIALS
    ):
        _fail("memory extraction event is invalid")
    evidence_ids = tuple(
        _identifier(item, "extraction evidence_id") for item in value.evidence_ids
    )
    portable = [_portable(item) for item in evidence_ids]
    if portable != sorted(portable) or len(portable) != len(set(portable)):
        _fail("extraction evidence ids must be uniquely ordered")
    return {
        "schema_version": 1,
        "record_type": "memory-extracted",
        "event_id": _identifier(value.event_id, "event_id", _REPORT_ID),
        "run_id": _identifier(value.run_id, "run_id", _RUN_ID),
        "operation_id": _identifier(value.operation_id, "operation_id"),
        "recorded_at": _timestamp(value.recorded_at, "extraction recorded_at"),
        "proposal_id": _identifier(
            value.proposal_id, "proposal_id", _PROPOSAL_ID
        ),
        "proposal_sha256": _hash(value.proposal_sha256, "proposal_sha256"),
        "evidence_ids": list(evidence_ids),
    }


def _parse_extraction(raw: bytes | str) -> MemoryExtractionEvent:
    keys = frozenset(
        {
            "schema_version",
            "record_type",
            "event_id",
            "run_id",
            "operation_id",
            "recorded_at",
            "proposal_id",
            "proposal_sha256",
            "evidence_ids",
        }
    )
    item = _mapping(
        _decode(raw, "memory extraction event", _MAX_LINE),
        "memory extraction event",
        keys,
    )
    evidence_ids = item["evidence_ids"]
    if not isinstance(evidence_ids, list):
        _fail("extraction evidence ids are invalid")
    result = MemoryExtractionEvent(
        item["event_id"],
        item["run_id"],
        item["operation_id"],
        item["recorded_at"],
        item["proposal_id"],
        item["proposal_sha256"],
        tuple(evidence_ids),
        item["record_type"],
        item["schema_version"],
    )
    source = raw.encode("utf-8") if isinstance(raw, str) else raw
    if source != _canonical(_extraction_payload(result), _MAX_LINE):
        _fail("memory extraction event must use canonical JSON")
    return result


def daily_memory_evidence(
    record: DailyLogRecord, material_id: str
) -> MemoryEvidence:
    checked = parse_daily_log(render_daily_log(record))
    material = next(
        (
            item
            for item in checked.materials
            if _portable(item.material_id) == _portable(material_id)
        ),
        None,
    )
    if material is None:
        _fail("daily material does not exist")
    raw = render_daily_log(checked)
    return MemoryEvidence(
        evidence_id=material.material_id,
        source_kind=material.kind,
        source_ref=f"agent/logs/reports/daily/{checked.day}.jsonl",
        source_sha256=hashlib.sha256(raw).hexdigest(),
        anchor=material.material_id,
        actor=material.actor,
        occurred_at=material.occurred_at,
        exact_text=material.exact_text,
    )


def report_evidence_artifact_name(operation_id: str) -> str:
    checked = _identifier(operation_id, "operation_id")
    return "report-evidence-" + hashlib.sha256(checked.encode()).hexdigest()[:32]


def _run_evidence_payload(value: ReportRunEvidence) -> dict[str, object]:
    if (
        not isinstance(value, ReportRunEvidence)
        or value.schema_version != 1
        or value.role != "report-operation-evidence"
        or value.flow != "report"
        or type(value.operation) is not str
        or value.operation not in {"daily", "weekly", "extract"}
    ):
        _fail("report run evidence is invalid")
    output_ref = _safe_ref(value.output_ref, "report evidence output_ref")
    if not output_ref.startswith("agent/logs/reports/"):
        _fail("report evidence output role is invalid")
    proposal_ref = (
        None
        if value.proposal_ref is None
        else _safe_ref(value.proposal_ref, "report evidence proposal_ref")
    )
    proposal_hash = (
        None
        if value.proposal_sha256 is None
        else _hash(value.proposal_sha256, "proposal_sha256")
    )
    if value.operation == "extract":
        if proposal_ref is None or proposal_hash is None or not proposal_ref.startswith(
            "review/"
        ):
            _fail("extraction evidence requires a memory proposal role")
        if value.outcome_class != "proposal-pending":
            _fail("extraction evidence outcome class is invalid")
    elif proposal_ref is not None or proposal_hash is not None:
        _fail("non-extraction evidence cannot name a proposal")
    elif value.outcome_class != "report-log":
        _fail("report log evidence outcome class is invalid")
    return {
        "schema_version": 1,
        "role": value.role,
        "flow": value.flow,
        "operation_id": _identifier(value.operation_id, "operation_id"),
        "operation": value.operation,
        "output_ref": output_ref,
        "request_sha256": _hash(value.request_sha256, "request_sha256"),
        "run_state_sha256": _hash(
            value.run_state_sha256, "run_state_sha256"
        ),
        "log_preimage_sha256": _hash(
            value.log_preimage_sha256, "log_preimage_sha256"
        ),
        "log_line_sha256": _hash(value.log_line_sha256, "log_line_sha256"),
        "proposal_ref": proposal_ref,
        "proposal_sha256": proposal_hash,
        "outcome_class": value.outcome_class,
    }


def render_report_run_evidence(value: ReportRunEvidence) -> bytes:
    return _canonical(_run_evidence_payload(value), _MAX_JSON)


def parse_report_run_evidence(raw: bytes | str) -> ReportRunEvidence:
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
            "log_preimage_sha256",
            "log_line_sha256",
            "proposal_ref",
            "proposal_sha256",
            "outcome_class",
        }
    )
    item = _mapping(
        _decode(raw, "report run evidence", _MAX_JSON),
        "report run evidence",
        keys,
    )
    result = ReportRunEvidence(
        operation_id=item["operation_id"],
        operation=item["operation"],
        output_ref=item["output_ref"],
        request_sha256=item["request_sha256"],
        run_state_sha256=item["run_state_sha256"],
        log_preimage_sha256=item["log_preimage_sha256"],
        log_line_sha256=item["log_line_sha256"],
        proposal_ref=item["proposal_ref"],
        proposal_sha256=item["proposal_sha256"],
        outcome_class=item["outcome_class"],
        role=item["role"],
        flow=item["flow"],
        schema_version=item["schema_version"],
    )
    source = raw.encode("utf-8") if isinstance(raw, str) else raw
    if source != render_report_run_evidence(result):
        _fail("report run evidence must use canonical JSON")
    return result


def inspect_report_run_evidence(
    artifact: PreparedArtifact | CommittedArtifact, raw: bytes | str
) -> ReportRunEvidence:
    if not isinstance(artifact, (PreparedArtifact, CommittedArtifact)):
        _fail("report run evidence artifact is invalid")
    evidence = parse_report_run_evidence(raw)
    source = raw.encode("utf-8") if isinstance(raw, str) else raw
    relative = _safe_ref(artifact.relative, "report run artifact relative")
    expected_name = f"{report_evidence_artifact_name(evidence.operation_id)}.json"
    if (
        artifact.name != report_evidence_artifact_name(evidence.operation_id)
        or artifact.zone != "agent/runs"
        or PurePosixPath(relative).name != expected_name
        or artifact.state_ref != f"agent/runs/{relative}"
        or artifact.sha256 != hashlib.sha256(source).hexdigest()
    ):
        _fail("report run evidence artifact binding is invalid")
    return evidence


@dataclass(frozen=True)
class _Zone:
    symbolic: str
    path: Path
    fd: int
    identity: tuple[int, int]


def _read_at(fd: int, name: str, maximum: int) -> tuple[bytes, tuple[int, int]]:
    _portable(name)
    file_fd: int | None = None
    try:
        named = os.stat(name, dir_fd=fd, follow_symlinks=False)
        file_fd = os.open(
            name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=fd
        )
        opened = os.fstat(file_fd)
        if (
            not stat.S_ISREG(named.st_mode)
            or (named.st_dev, named.st_ino) != (opened.st_dev, opened.st_ino)
            or opened.st_size > maximum
        ):
            _fail("report file is unsafe or too large")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(file_fd, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(file_fd)
        linked = os.stat(name, dir_fd=fd, follow_symlinks=False)
        if (
            len(raw) > maximum
            or _stat_signature(opened) != _stat_signature(after)
            or _stat_signature(opened) != _stat_signature(linked)
        ):
            _fail("report file changed while read")
        return raw, (opened.st_dev, opened.st_ino)
    except FileNotFoundError:
        raise
    except ReportFlowError:
        raise
    except OSError:
        _fail("report file cannot be read safely")
    finally:
        if file_fd is not None:
            os.close(file_fd)


def _identity_at(fd: int, name: str) -> tuple[int, int] | None:
    try:
        item = os.stat(name, dir_fd=fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    except OSError:
        _fail("report leaf identity cannot be inspected")
    if not stat.S_ISREG(item.st_mode):
        _fail("report named leaf is unsafe")
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
            _fail("report write failed")
        if count <= 0:
            _fail("report write did not progress")
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
        _fail("atomic no-replace report retirement is unavailable")
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
    """Move one exact owned inode to retained run recovery without unlinking."""

    recovery_key = hashlib.sha256(
        f"report\0{kind}\0{expected_identity[0]}\0{expected_identity[1]}".encode()
    ).hexdigest()[:32]
    recovery_name = f"report-{recovery_key}.recovery"
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
    except FileNotFoundError:
        return False
    except OSError:
        return False


def _create_once(
    fd: int,
    name: str,
    data: bytes,
    maximum: int,
    recovery_fd: int,
    recovery_kind: str,
    validate_parent: Callable[[], None] | None = None,
) -> bool:
    validate = (lambda: None) if validate_parent is None else validate_parent
    validate()
    if not isinstance(data, bytes) or not data or len(data) > maximum:
        _fail("immutable report bytes are invalid")
    try:
        current, _ = _read_at(fd, name, maximum)
    except FileNotFoundError:
        current = None
    if current is not None:
        if current != data:
            _fail("immutable report replay conflicts with existing bytes")
        validate()
        return False
    temporary = f".{name}.{os.getpid()}.{uuid.uuid4().hex}.tmp"
    staged_fd: int | None = None
    staged_identity: tuple[int, int] | None = None
    try:
        staged_fd = os.open(
            temporary,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=fd,
        )
        _write_all(staged_fd, data)
        os.fsync(staged_fd)
        staged = os.fstat(staged_fd)
        staged_identity = staged.st_dev, staged.st_ino
        os.close(staged_fd)
        staged_fd = None
        named_stage = os.stat(temporary, dir_fd=fd, follow_symlinks=False)
        if staged_identity != (named_stage.st_dev, named_stage.st_ino):
            _fail("immutable report stage changed")
        validate()
        try:
            os.link(
                temporary,
                name,
                src_dir_fd=fd,
                dst_dir_fd=fd,
                follow_symlinks=False,
            )
        except FileExistsError:
            current, _ = _read_at(fd, name, maximum)
            if current != data:
                _fail("immutable report publication collided")
            return False
        published = os.stat(name, dir_fd=fd, follow_symlinks=False)
        if staged_identity != (published.st_dev, published.st_ino):
            _fail("immutable report publication changed")
        try:
            validate()
        except ReportFlowError:
            if not _retire_exact(
                fd, name, staged_identity, recovery_fd, recovery_kind + "-publish"
            ):
                _fail("report publication rollback could not retain exact bytes")
            raise
        os.fsync(fd)
        return True
    except ReportFlowError:
        raise
    except OSError:
        _fail("immutable report publication failed")
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
                _fail("report stage cleanup could not retain exact bytes")


def _rename_exchange(fd: int, source: str, target: str) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    if hasattr(libc, "renameatx_np"):
        fn, flag = libc.renameatx_np, 0x00000002
    elif hasattr(libc, "renameat2"):
        fn, flag = libc.renameat2, 0x00000002
    else:
        _fail("identity-bound report rename is unavailable")
    fn.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    fn.restype = ctypes.c_int
    if fn(fd, os.fsencode(source), fd, os.fsencode(target), flag) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def _atomic_replace(
    fd: int,
    name: str,
    data: bytes,
    expected_identity: tuple[int, int] | None,
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
            _MAX_LOG,
            recovery_fd,
            recovery_kind,
            validate_parent=validate_parent,
        )
        return
    if _identity_at(fd, name) != expected_identity:
        _fail("report log changed before publish")
    temporary = f".{name}.{os.getpid()}.{uuid.uuid4().hex}.tmp"
    staged_fd: int | None = None
    staged_identity: tuple[int, int] | None = None
    try:
        staged_fd = os.open(
            temporary,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=fd,
        )
        _write_all(staged_fd, data)
        os.fsync(staged_fd)
        staged = os.fstat(staged_fd)
        staged_identity = staged.st_dev, staged.st_ino
        os.close(staged_fd)
        staged_fd = None
        validate_parent()
        _rename_exchange(fd, temporary, name)
        try:
            validate_parent()
        except ReportFlowError:
            try:
                _rename_exchange(fd, temporary, name)
                os.fsync(fd)
            except OSError:
                pass
            raise
        old = _identity_at(fd, temporary)
        if old != expected_identity:
            if old is not None:
                try:
                    _rename_exchange(fd, temporary, name)
                    os.fsync(fd)
                except OSError:
                    pass
            _fail("report log changed during publish")
        current, identity = _read_at(fd, name, _MAX_LOG)
        if current != data or identity != staged_identity:
            try:
                _rename_exchange(fd, temporary, name)
                os.fsync(fd)
            except OSError:
                pass
            _fail("report log publication is not exact")
        try:
            validate_parent()
        except ReportFlowError:
            try:
                _rename_exchange(fd, temporary, name)
                os.fsync(fd)
            except OSError:
                pass
            raise
        if old != expected_identity or not _retire_exact(
            fd,
            temporary,
            expected_identity,
            recovery_fd,
            recovery_kind + "-preimage",
        ):
            _fail("report log preimage could not be retained exactly")
        staged_identity = None
        validate_parent()
    except ReportFlowError:
        raise
    except OSError:
        _fail("report log publication failed")
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
                _fail("report replacement stage could not be retained exactly")


def _jsonl(raw: bytes, kind: str) -> tuple[DailyLogRecord | WeeklyReflection | MemoryExtractionEvent, ...]:
    if len(raw) > _MAX_LOG or (raw and not raw.endswith(b"\n")):
        _fail("report log is oversized or torn")
    lines = raw.splitlines()
    if len(lines) > _MAX_RECORDS:
        _fail("report log has too many records")
    result: list[DailyLogRecord | WeeklyReflection | MemoryExtractionEvent] = []
    seen: set[str] = set()
    seen_records: set[str] = set()
    for line in lines:
        if not line or len(line) + 1 > _MAX_LINE:
            _fail("report log line is invalid")
        source = line + b"\n"
        if kind == "daily":
            record = parse_daily_log(source)
        elif kind == "weekly":
            record = parse_weekly_reflection(source)
        else:
            record = _parse_extraction(source)
        key = _portable(record.operation_id)
        if key in seen:
            _fail("report operation ids collide")
        seen.add(key)
        record_id = (
            record.report_id
            if isinstance(record, DailyLogRecord)
            else record.reflection_id
            if isinstance(record, WeeklyReflection)
            else record.event_id
        )
        portable_record_id = _portable(record_id)
        if portable_record_id in seen_records:
            _fail("report record ids collide")
        seen_records.add(portable_record_id)
        result.append(record)
    return tuple(result)


class ReportFlow:
    """Write bounded report logs and evidence-gated review proposals."""

    def __init__(
        self,
        resolver: VaultPathResolver,
        run_store: RunStore,
        policy: AuthorityPolicy,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if (
            not isinstance(resolver, VaultPathResolver)
            or not isinstance(run_store, RunStore)
            or not isinstance(policy, AuthorityPolicy)
            or getattr(run_store, "_resolver", None) is not resolver
        ):
            _fail("report flow dependencies are invalid")
        self._resolver, self._runs, self._policy = resolver, run_store, policy
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        fd: int | None = None
        try:
            logs = resolver.resolve("agent/logs", must_exist=True)
            root = logs
            for _ in PurePosixPath("agent/logs").parts:
                root = root.parent
            fd = os.open(
                root,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
            opened = os.fstat(fd)
            named = os.stat(root, follow_symlinks=False)
            if (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino):
                _fail("report vault root cannot be pinned")
            self._root_path = root
            self._root_identity = (opened.st_dev, opened.st_ino)
        except (OSError, VaultSchemaError, ReportFlowError):
            _fail("report vault root cannot be pinned")
        finally:
            if fd is not None:
                os.close(fd)

    @staticmethod
    def _hooks(value: ReportCrashHooks | None) -> ReportCrashHooks:
        hooks = ReportCrashHooks() if value is None else value
        if not isinstance(hooks, ReportCrashHooks) or any(
            item is not None and not callable(item)
            for item in (
                hooks.after_prepare,
                hooks.after_proposal_publish,
                hooks.after_log_publish,
                hooks.before_run_commit,
            )
        ):
            _fail("report crash hooks are invalid")
        return hooks

    def _now(self) -> str:
        value = self._clock()
        if not isinstance(value, datetime) or value.tzinfo is None:
            _fail("report clock must return aware datetime")
        return (
            value.astimezone(timezone.utc)
            .isoformat(timespec="microseconds")
            .replace("+00:00", "Z")
        )

    def _require(
        self, capability: ActionCapability, action_id: str
    ) -> ActionCapability:
        expected = {
            "read-report-projects": ("read", "vault:projects"),
            "read-report-tasks": ("read", "vault:tasks"),
            "collect-primary-evidence": ("read", "vault:agent/logs"),
            "read-report-memory": ("read", "vault:agent/memory"),
            "commit-memory-proposal": ("proposal", "vault:review"),
            "append-report-log": ("internal-write", "vault:agent/logs"),
            "record-run-state": ("internal-write", "vault:agent/runs"),
        }
        try:
            grant = self._policy.require(capability)
        except AuthorityError as error:
            raise ReportFlowError(str(error)) from None
        if action_id not in expected or (
            grant.flow_id,
            grant.action_id,
            grant.actor,
            grant.authority,
            grant.target,
        ) != ("report", action_id, "runtime", *expected[action_id]):
            _fail("report action capability is not exact")
        return grant

    def _check_run(self, run_id: str) -> tuple[str, str]:
        checked = _identifier(run_id, "run_id", _RUN_ID)
        try:
            snapshot = self._runs.snapshot(checked)
        except RunError as error:
            raise ReportFlowError(str(error)) from None
        if (
            snapshot.state.get("flow") != "report"
            or snapshot.state.get("status") != "running"
            or snapshot.state.get("authority") != "proposal"
        ):
            _fail("report mutation requires a running proposal report run")
        return checked, snapshot.state_sha256

    def _open_zone(self, symbolic: str, *, for_write: bool) -> _Zone:
        fd: int | None = None
        try:
            path = self._resolver.resolve(
                symbolic, for_write=for_write, must_exist=True
            )
            fd = os.open(
                path,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
            opened = os.fstat(fd)
            named = os.stat(path, follow_symlinks=False)
            if (
                not stat.S_ISDIR(opened.st_mode)
                or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
            ):
                _fail("report zone is unsafe")
            return _Zone(symbolic, path, fd, (opened.st_dev, opened.st_ino))
        except (OSError, VaultSchemaError, ReportFlowError):
            if fd is not None:
                os.close(fd)
            _fail("report zone cannot be opened safely")

    def _revalidate(self, zone: _Zone, *, for_write: bool) -> None:
        try:
            actual = self._resolver.revalidate(
                zone.path,
                zone.symbolic,
                for_write=for_write,
                must_exist=True,
            )
            opened = os.fstat(zone.fd)
            named = os.stat(actual, follow_symlinks=False)
            root = os.stat(self._root_path, follow_symlinks=False)
        except (OSError, VaultSchemaError):
            _fail("report zone changed")
        if (
            zone.identity != (opened.st_dev, opened.st_ino)
            or zone.identity != (named.st_dev, named.st_ino)
            or self._root_identity != (root.st_dev, root.st_ino)
        ):
            _fail("report zone changed")

    @staticmethod
    def _mkdir_at(fd: int, name: str) -> int:
        _portable(name)
        try:
            os.mkdir(name, 0o700, dir_fd=fd)
            os.fsync(fd)
        except FileExistsError:
            pass
        except OSError:
            _fail("report namespace cannot be created")
        child: int | None = None
        try:
            child = os.open(
                name,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=fd,
            )
            opened = os.fstat(child)
            named = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if (
                not stat.S_ISDIR(opened.st_mode)
                or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
            ):
                _fail("report namespace is unsafe")
            return child
        except (OSError, ReportFlowError):
            if child is not None:
                os.close(child)
            _fail("report namespace is unsafe")

    @contextmanager
    def _report_dir(self, kind: str) -> Iterator[tuple[_Zone, int, int]]:
        if kind not in {"daily", "weekly", "extract"}:
            _fail("report log kind is invalid")
        logs = self._open_zone("agent/logs", for_write=True)
        reports_fd: int | None = None
        lock_fd: int | None = None
        kind_fd: int | None = None
        try:
            reports_fd = self._mkdir_at(logs.fd, "reports")
            lock_fd = os.open(
                ".lock",
                os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=reports_fd,
            )
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            kind_fd = self._mkdir_at(reports_fd, kind)
            self._revalidate(logs, for_write=True)
            self._revalidate_report_dirs(logs, reports_fd, kind_fd, kind)
            yield logs, reports_fd, kind_fd
            self._revalidate_report_dirs(logs, reports_fd, kind_fd, kind)
            self._revalidate(logs, for_write=True)
        finally:
            for item in (kind_fd, lock_fd, reports_fd):
                if item is not None:
                    os.close(item)
            os.close(logs.fd)

    @staticmethod
    def _revalidate_report_dirs(
        logs: _Zone, reports_fd: int, kind_fd: int, kind: str
    ) -> None:
        try:
            reports = os.fstat(reports_fd)
            named_reports = os.stat(
                "reports", dir_fd=logs.fd, follow_symlinks=False
            )
            leaf = os.fstat(kind_fd)
            named_leaf = os.stat(kind, dir_fd=reports_fd, follow_symlinks=False)
        except OSError:
            _fail("report log namespace changed")
        if (
            not all(
                stat.S_ISDIR(item.st_mode)
                for item in (reports, named_reports, leaf, named_leaf)
            )
            or (reports.st_dev, reports.st_ino)
            != (named_reports.st_dev, named_reports.st_ino)
            or (leaf.st_dev, leaf.st_ino)
            != (named_leaf.st_dev, named_leaf.st_ino)
        ):
            _fail("report log namespace changed")

    def _touch_zone(self, symbolic: str) -> None:
        zone = self._open_zone(symbolic, for_write=False)
        try:
            names = os.listdir(zone.fd)
            if len(names) > _MAX_RECORDS:
                _fail("report input zone has too many entries")
            for name in names:
                _portable(name)
            self._revalidate(zone, for_write=False)
        finally:
            os.close(zone.fd)

    def _verify_context_kind(
        self, context: ReportContext, kind: str
    ) -> None:
        _context_payload(context)
        symbolic, _prefix = _CONTEXT_KINDS[kind]
        for item in context.items:
            if item.kind != kind:
                continue
            relative = PurePosixPath(item.logical_ref).relative_to(
                PurePosixPath(symbolic)
            )
            fd: int | None = None
            try:
                path = self._resolver.resolve(symbolic, relative, must_exist=True)
                fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
                opened = os.fstat(fd)
                if not stat.S_ISREG(opened.st_mode) or opened.st_size > _MAX_JSON:
                    _fail("report context state is unsafe or too large")
                raw = os.read(fd, _MAX_JSON + 1)
                after = os.fstat(fd)
                named = os.stat(path, follow_symlinks=False)
                if (
                    len(raw) > _MAX_JSON
                    or _stat_signature(opened) != _stat_signature(after)
                    or _stat_signature(opened) != _stat_signature(named)
                    or hashlib.sha256(raw).hexdigest() != item.state_sha256
                ):
                    _fail("report context state changed or disagrees with its hash")
            except ReportFlowError:
                raise
            except (OSError, VaultSchemaError):
                _fail("report context state cannot be read safely")
            finally:
                if fd is not None:
                    os.close(fd)

    def _verify_primary(self, evidence: Sequence[MemoryEvidence]) -> None:
        for item in evidence:
            payload = _memory_evidence_payload(item)
            source_ref = _safe_ref(payload["source_ref"], "evidence source_ref")
            source = PurePosixPath(source_ref)
            if source.parts[:2] != ("agent", "logs") or len(source.parts) < 3:
                _fail("report primary evidence must be retained under agent/logs")
            relative = PurePosixPath(*source.parts[2:])
            fd: int | None = None
            try:
                path = self._resolver.resolve(
                    "agent/logs", relative, must_exist=True
                )
                fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
                before = os.fstat(fd)
                if not stat.S_ISREG(before.st_mode) or before.st_size > _MAX_LOG:
                    _fail("report evidence source is unsafe or too large")
                raw = os.read(fd, _MAX_LOG + 1)
                after = os.fstat(fd)
                named = os.stat(path, follow_symlinks=False)
                matching_records = [
                    line + b"\n"
                    for line in raw.splitlines()
                    if line
                    and hashlib.sha256(line + b"\n").hexdigest()
                    == payload["source_sha256"]
                ]
                if (
                    len(raw) > _MAX_LOG
                    or _stat_signature(before) != _stat_signature(after)
                    or _stat_signature(before) != _stat_signature(named)
                    or len(matching_records) != 1
                ):
                    _fail("report evidence does not match retained primary bytes")
                try:
                    validate_primary_evidence_record(item, matching_records[0])
                except MemoryFlowError as error:
                    raise ReportFlowError(str(error)) from None
            except ReportFlowError:
                raise
            except (OSError, VaultSchemaError):
                _fail("report primary evidence cannot be read safely")
            finally:
                if fd is not None:
                    os.close(fd)

    def _read_sequence(
        self,
        capabilities: ReportCapabilities,
        context: ReportContext,
        evidence: Sequence[MemoryEvidence],
    ) -> tuple[ActionCapability, ActionCapability, ActionCapability, ActionCapability]:
        if not isinstance(capabilities, ReportCapabilities):
            _fail("report operation requires ReportCapabilities")
        projects = self._require(
            capabilities.read_report_projects, "read-report-projects"
        )
        self._touch_zone("projects")
        self._verify_context_kind(context, "project")
        tasks = self._require(capabilities.read_report_tasks, "read-report-tasks")
        self._touch_zone("tasks")
        self._verify_context_kind(context, "task")
        primary = self._require(
            capabilities.collect_primary_evidence, "collect-primary-evidence"
        )
        self._touch_zone("agent/logs")
        self._verify_primary(evidence)
        memory = self._require(
            capabilities.read_report_memory, "read-report-memory"
        )
        self._touch_zone("agent/memory")
        self._verify_context_kind(context, "entity")
        self._verify_context_kind(context, "memory")
        return projects, tasks, primary, memory

    def _load_run_evidence(
        self, run_id: str, operation_id: str
    ) -> ReportRunEvidence | None:
        name = report_evidence_artifact_name(operation_id)
        directory_fd: int | None = None
        try:
            path = self._resolver.resolve("agent/runs", run_id, must_exist=True)
            directory_fd = os.open(
                path,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
            opened = os.fstat(directory_fd)
            named = os.stat(path, follow_symlinks=False)
            if (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino):
                _fail("report run evidence directory changed")
            try:
                raw, _ = _read_at(directory_fd, f"{name}.json", _MAX_JSON)
            except FileNotFoundError:
                return None
            actual = self._resolver.revalidate(
                path, "agent/runs", run_id, must_exist=True
            )
            linked = os.stat(actual, follow_symlinks=False)
            if (opened.st_dev, opened.st_ino) != (linked.st_dev, linked.st_ino):
                _fail("report run evidence directory changed")
            return parse_report_run_evidence(raw)
        except ReportFlowError:
            raise
        except (OSError, VaultSchemaError):
            _fail("report run evidence cannot be read safely")
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
                _fail("report run recovery parent changed")
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
                _fail("report run recovery parent changed")
        except ReportFlowError:
            raise
        except (OSError, VaultSchemaError):
            _fail("report run recovery cannot be opened safely")
        finally:
            if recovery_fd is not None:
                os.close(recovery_fd)
            if run_fd is not None:
                os.close(run_fd)

    def _prepare(
        self, run_id: str, evidence: ReportRunEvidence
    ) -> tuple[PreparedArtifact, str, bool]:
        prior = self._load_run_evidence(run_id, evidence.operation_id)
        replayed = prior is not None
        if prior is not None:
            expected = replace(
                evidence,
                run_state_sha256=prior.run_state_sha256,
                log_preimage_sha256=prior.log_preimage_sha256,
            )
            if prior != expected:
                _fail("report replay conflicts with durable run evidence")
            evidence = prior
        try:
            artifact = self._runs.prepare_run_artifact(
                run_id,
                name=report_evidence_artifact_name(evidence.operation_id),
                data=render_report_run_evidence(evidence),
                maximum_bytes=_MAX_JSON,
            )
        except RunError as error:
            raise ReportFlowError(str(error)) from None
        return artifact, evidence.run_state_sha256, replayed

    def _commit_run(
        self,
        *,
        run_id: str,
        operation_id: str,
        operation: str,
        request_hash: str,
        artifact: PreparedArtifact,
        run_hash: str,
        actions: Sequence[ActionCapability],
        hooks: ReportCrashHooks,
    ) -> None:
        if hooks.before_run_commit is not None:
            hooks.before_run_commit()
        self._require(actions[-1], "record-run-state")
        step_id = "report-" + hashlib.sha256(
            (operation + ":" + operation_id).encode()
        ).hexdigest()[:32]
        ranks = {"read": 0, "internal-write": 1, "proposal": 2, "domain-write": 3}
        authority = max((item.authority for item in actions), key=ranks.__getitem__)
        try:
            state = self._runs.commit_step(
                run_id,
                step_id=step_id,
                authority=authority,
                input_hash=request_hash,
                output_hash=artifact.sha256,
                next_phase=f"report-{operation}-committed",
                next_status="running",
                prepared_artifacts=(artifact,),
                expected_state_sha256=run_hash,
                action_uses=tuple(ActionUse(item) for item in actions),
                authority_policy=self._policy,
            )
        except RunError as error:
            raise ReportFlowError(str(error)) from None
        if state.get("status") != "running":
            _fail("report flow must remain running for finalize")

    def _optional_log(self, kind: str, filename: str) -> bytes:
        try:
            path = self._resolver.resolve(
                "agent/logs",
                PurePosixPath("reports") / kind / filename,
                must_exist=True,
            )
        except VaultSchemaError:
            # Missing reports/kind/file is the only accepted empty preimage.
            try:
                expected = self._resolver.resolve(
                    "agent/logs",
                    PurePosixPath("reports") / kind / filename,
                    must_exist=False,
                )
            except VaultSchemaError:
                _fail("report log path is unsafe")
            if expected.exists() or expected.is_symlink():
                _fail("report log path is unsafe")
            return b""
        fd: int | None = None
        try:
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            item = os.fstat(fd)
            if not stat.S_ISREG(item.st_mode) or item.st_size > _MAX_LOG:
                _fail("report log is unsafe or too large")
            raw = os.read(fd, _MAX_LOG + 1)
            after = os.fstat(fd)
            named = os.stat(path, follow_symlinks=False)
            if (
                len(raw) > _MAX_LOG
                or _stat_signature(item) != _stat_signature(after)
                or _stat_signature(item) != _stat_signature(named)
            ):
                _fail("report log changed while read")
            _jsonl(raw, kind)
            return raw
        except ReportFlowError:
            raise
        except OSError:
            _fail("report log cannot be read safely")
        finally:
            if fd is not None:
                os.close(fd)

    def _append_line(
        self,
        *,
        kind: str,
        filename: str,
        operation_id: str,
        line: bytes,
        append_grant: ActionCapability,
        recovery_fd: int,
    ) -> bool:
        with self._report_dir(kind) as (logs, reports_fd, directory_fd):
            try:
                raw, identity = _read_at(directory_fd, filename, _MAX_LOG)
            except FileNotFoundError:
                raw, identity = b"", None
            records = _jsonl(raw, kind)
            matches = [
                record
                for record in records
                if _portable(record.operation_id) == _portable(operation_id)
            ]
            if matches:
                existing = (
                    render_daily_log(matches[0])
                    if isinstance(matches[0], DailyLogRecord)
                    else render_weekly_reflection(matches[0])
                    if isinstance(matches[0], WeeklyReflection)
                    else _canonical(_extraction_payload(matches[0]), _MAX_LINE)
                )
                if len(matches) != 1 or existing != line:
                    _fail("report replay conflicts with an existing log event")
                return True
            if records:
                previous = records[-1].recorded_at
                current_payload = json.loads(line)
                if _instant(
                    _timestamp(current_payload["recorded_at"], "recorded_at")
                ) < _instant(previous):
                    _fail("report events must be appended in recorded_at order")
            if len(raw) + len(line) > _MAX_LOG:
                _fail("report log would exceed its bound")
            self._revalidate_report_dirs(logs, reports_fd, directory_fd, kind)
            self._require(append_grant, "append-report-log")
            _atomic_replace(
                directory_fd,
                filename,
                raw + line,
                identity,
                lambda: self._revalidate_report_dirs(
                    logs, reports_fd, directory_fd, kind
                ),
                recovery_fd,
                f"{kind}-{operation_id}",
            )
            self._revalidate_report_dirs(logs, reports_fd, directory_fd, kind)
            return False

    def _publish_proposal(
        self,
        proposal: MemoryProposalRecord,
        raw: bytes,
        proposal_grant: ActionCapability,
        recovery_fd: int,
    ) -> bool:
        zone = self._open_zone("review", for_write=True)
        try:
            self._require(proposal_grant, "commit-memory-proposal")
            created = _create_once(
                zone.fd,
                f"{proposal.proposal_id}.memory.json",
                raw,
                _MAX_JSON,
                recovery_fd,
                f"proposal-{proposal.operation_id}",
                validate_parent=lambda: self._revalidate(zone, for_write=True),
            )
            self._revalidate(zone, for_write=True)
            return not created
        finally:
            os.close(zone.fd)

    def record_daily(
        self,
        record: DailyLogRecord,
        *,
        capabilities: ReportCapabilities,
        crash_hooks: ReportCrashHooks | None = None,
    ) -> ReportMutationResult:
        hooks = self._hooks(crash_hooks)
        checked = parse_daily_log(render_daily_log(record))
        run_id, run_hash = self._check_run(checked.run_id)
        reads = self._read_sequence(capabilities, checked.context, ())
        append = self._require(capabilities.append_report_log, "append-report-log")
        run = self._require(capabilities.record_run_state, "record-run-state")
        line = render_daily_log(checked)
        log_ref = f"agent/logs/reports/daily/{checked.day}.jsonl"
        request = {
            "schema_version": 1,
            "operation": "daily",
            "record_sha256": hashlib.sha256(line).hexdigest(),
        }
        request_hash = hashlib.sha256(_canonical(request)).hexdigest()
        preimage = self._optional_log("daily", f"{checked.day}.jsonl")
        evidence = ReportRunEvidence(
            checked.operation_id,
            "daily",
            log_ref,
            request_hash,
            run_hash,
            hashlib.sha256(preimage).hexdigest(),
            hashlib.sha256(line).hexdigest(),
            None,
            None,
            "report-log",
        )
        artifact, run_hash, evidence_replay = self._prepare(run_id, evidence)
        if hooks.after_prepare is not None:
            hooks.after_prepare()
        with self._run_recovery(run_id) as recovery_fd:
            replayed = self._append_line(
                kind="daily",
                filename=f"{checked.day}.jsonl",
                operation_id=checked.operation_id,
                line=line,
                append_grant=append,
                recovery_fd=recovery_fd,
            )
        if hooks.after_log_publish is not None:
            hooks.after_log_publish()
        self._commit_run(
            run_id=run_id,
            operation_id=checked.operation_id,
            operation="daily",
            request_hash=request_hash,
            artifact=artifact,
            run_hash=run_hash,
            actions=(*reads, append, run),
            hooks=hooks,
        )
        return ReportMutationResult(
            checked.operation_id,
            "daily",
            log_ref,
            None,
            replayed or evidence_replay,
            hashlib.sha256(line).hexdigest(),
        )

    def record_weekly(
        self,
        record: WeeklyReflection,
        *,
        capabilities: ReportCapabilities,
        crash_hooks: ReportCrashHooks | None = None,
    ) -> ReportMutationResult:
        hooks = self._hooks(crash_hooks)
        checked = parse_weekly_reflection(render_weekly_reflection(record))
        run_id, run_hash = self._check_run(checked.run_id)
        reads = self._read_sequence(
            capabilities, checked.context, checked.primary_evidence
        )
        append = self._require(capabilities.append_report_log, "append-report-log")
        run = self._require(capabilities.record_run_state, "record-run-state")
        line = render_weekly_reflection(checked)
        log_ref = f"agent/logs/reports/weekly/{checked.week_start}.jsonl"
        request = {
            "schema_version": 1,
            "operation": "weekly",
            "record_sha256": hashlib.sha256(line).hexdigest(),
        }
        request_hash = hashlib.sha256(_canonical(request)).hexdigest()
        preimage = self._optional_log("weekly", f"{checked.week_start}.jsonl")
        evidence = ReportRunEvidence(
            checked.operation_id,
            "weekly",
            log_ref,
            request_hash,
            run_hash,
            hashlib.sha256(preimage).hexdigest(),
            hashlib.sha256(line).hexdigest(),
            None,
            None,
            "report-log",
        )
        artifact, run_hash, evidence_replay = self._prepare(run_id, evidence)
        if hooks.after_prepare is not None:
            hooks.after_prepare()
        with self._run_recovery(run_id) as recovery_fd:
            replayed = self._append_line(
                kind="weekly",
                filename=f"{checked.week_start}.jsonl",
                operation_id=checked.operation_id,
                line=line,
                append_grant=append,
                recovery_fd=recovery_fd,
            )
        if hooks.after_log_publish is not None:
            hooks.after_log_publish()
        self._commit_run(
            run_id=run_id,
            operation_id=checked.operation_id,
            operation="weekly",
            request_hash=request_hash,
            artifact=artifact,
            run_hash=run_hash,
            actions=(*reads, append, run),
            hooks=hooks,
        )
        return ReportMutationResult(
            checked.operation_id,
            "weekly",
            log_ref,
            None,
            replayed or evidence_replay,
            hashlib.sha256(line).hexdigest(),
        )

    def extract_memory(
        self,
        proposal: MemoryProposalRecord,
        *,
        event_id: str,
        recorded_at: str,
        context: ReportContext,
        capabilities: ReportCapabilities,
        crash_hooks: ReportCrashHooks | None = None,
    ) -> ReportMutationResult:
        hooks = self._hooks(crash_hooks)
        try:
            checked = parse_memory_proposal(render_memory_proposal(proposal))
        except MemoryFlowError as error:
            raise ReportFlowError(str(error)) from None
        if (
            checked.producer_flow != "report"
            or checked.status != "proposed"
            or checked.human_decision is not None
        ):
            _fail("report extraction can publish only a proposed memory record")
        checked_event = _identifier(event_id, "event_id", _REPORT_ID)
        checked_at = _timestamp(recorded_at, "extraction recorded_at")
        checked_context = _parse_context(
            json.loads(_canonical(_context_payload(context)))
        )
        run_id, run_hash = self._check_run(checked.run_id)
        reads = self._read_sequence(
            capabilities, checked_context, checked.evidence
        )
        proposal_grant = self._require(
            capabilities.commit_memory_proposal, "commit-memory-proposal"
        )
        append = self._require(capabilities.append_report_log, "append-report-log")
        run = self._require(capabilities.record_run_state, "record-run-state")
        proposal_raw = render_memory_proposal(checked)
        proposal_hash = hashlib.sha256(proposal_raw).hexdigest()
        event = MemoryExtractionEvent(
            checked_event,
            checked.run_id,
            checked.operation_id,
            checked_at,
            checked.proposal_id,
            proposal_hash,
            tuple(
                sorted(
                    (item.evidence_id for item in checked.evidence), key=_portable
                )
            ),
        )
        line = _canonical(_extraction_payload(event), _MAX_LINE)
        log_ref = "agent/logs/reports/extract/events.jsonl"
        proposal_ref = f"review/{checked.proposal_id}.memory.json"
        request = {
            "schema_version": 1,
            "operation": "extract",
            "proposal_sha256": proposal_hash,
            "event_sha256": hashlib.sha256(line).hexdigest(),
            "context_sha256": hashlib.sha256(
                _canonical(_context_payload(checked_context))
            ).hexdigest(),
        }
        request_hash = hashlib.sha256(_canonical(request)).hexdigest()
        preimage = self._optional_log("extract", "events.jsonl")
        evidence = ReportRunEvidence(
            checked.operation_id,
            "extract",
            log_ref,
            request_hash,
            run_hash,
            hashlib.sha256(preimage).hexdigest(),
            hashlib.sha256(line).hexdigest(),
            proposal_ref,
            proposal_hash,
            "proposal-pending",
        )
        artifact, run_hash, evidence_replay = self._prepare(run_id, evidence)
        if hooks.after_prepare is not None:
            hooks.after_prepare()
        with self._run_recovery(run_id) as recovery_fd:
            proposal_replay = self._publish_proposal(
                checked, proposal_raw, proposal_grant, recovery_fd
            )
            if hooks.after_proposal_publish is not None:
                hooks.after_proposal_publish()
            log_replay = self._append_line(
                kind="extract",
                filename="events.jsonl",
                operation_id=checked.operation_id,
                line=line,
                append_grant=append,
                recovery_fd=recovery_fd,
            )
        if hooks.after_log_publish is not None:
            hooks.after_log_publish()
        self._commit_run(
            run_id=run_id,
            operation_id=checked.operation_id,
            operation="extract",
            request_hash=request_hash,
            artifact=artifact,
            run_hash=run_hash,
            actions=(*reads, proposal_grant, append, run),
            hooks=hooks,
        )
        return ReportMutationResult(
            checked.operation_id,
            "extract",
            log_ref,
            proposal_ref,
            evidence_replay or proposal_replay or log_replay,
            hashlib.sha256(line).hexdigest(),
        )
