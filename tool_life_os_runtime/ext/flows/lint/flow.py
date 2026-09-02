"""P3-09 deterministic lint, bounded semantic packets, and exact recovery.

The flow deliberately scans only the five zones granted by the current P0
matrix. Reading state and report logs are outside that contract. Semantic
output is a review finding, never a mutation instruction. The only direct
write is an exact byte normalization in an explicitly allowed active note.
"""

from __future__ import annotations

import ctypes
from dataclasses import dataclass, replace
from datetime import datetime
import errno
import hashlib
import json
import os
from pathlib import PurePosixPath
import re
import stat
from typing import Callable, Iterator, Mapping, Protocol, Sequence
import unicodedata
import weakref

from tool_life_os_runtime.ext.flows.memory import (
    MemoryFlowError,
    parse_forget_outcome,
    parse_memory_metadata,
)
from tool_life_os_runtime.ext.flows.obsidian import (
    OBSIDIAN_SCHEMA_VERSION,
    NoteRef,
    ObsidianError,
    parse_note,
    validate_note,
)
from tool_life_os_runtime.ext.flows.plan import (
    PlanFlowError,
    parse_day_plan,
    parse_week_plan,
    render_day_markdown,
    render_week_markdown,
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
from tool_life_os_runtime.ext.vault.schema import (
    ARCHIVE_COMPONENTS,
    VaultPathResolver,
    VaultSchemaError,
)


LINT_SCHEMA_VERSION = 1
LINT_ZONE_ORDER = ("inbox", "knowledge", "tasks", "projects", "agent/memory")
LINT_DIRECT_FIX_TRANSFORMS = (
    "strip-utf8-bom",
    "crlf-to-lf",
    "append-final-newline",
)

_MODES = frozenset({"infra", "content", "deep"})
_RESOLUTIONS = frozenset({"auto-fixed", "review"})
_SEVERITIES = frozenset({"warning", "error"})
_STATUSES = frozenset({"clean", "findings"})
_REVIEW_STATUSES = frozenset({"proposed", "approved", "rejected", "superseded"})
_DECISIONS = frozenset({"approve", "reject", "supersede"})
_CONTENT_RULES = frozenset(
    {
        "content.duplicate",
        "content.stale-reference",
        "content.unresolved-placeholder",
        "content.unsupported-claim",
    }
)
_DEEP_RULES = _CONTENT_RULES | frozenset(
    {
        "deep.cross-source-conflict",
        "deep.near-duplicate",
        "deep.orphan-reference",
        "deep.stale-cross-reference",
    }
)
_CROSS_SOURCE_RULES = frozenset(
    {
        "deep.cross-source-conflict",
        "deep.near-duplicate",
        "deep.stale-cross-reference",
    }
)
_ZONE_ACTIONS = {
    "inbox": ("scan-inbox-zone", "vault:inbox"),
    "knowledge": ("scan-non-archive-zones", "vault:knowledge"),
    "tasks": ("scan-task-zone", "vault:tasks"),
    "projects": ("scan-project-zone", "vault:projects"),
    "agent/memory": ("scan-memory-zone", "vault:agent/memory"),
}
_FIX_ACTIONS = {
    "inbox": ("apply-allowlisted-inbox-fix", "vault:inbox"),
    "tasks": ("apply-allowlisted-task-fix", "vault:tasks"),
    "projects": ("apply-allowlisted-project-fix", "vault:projects"),
}
_ID = re.compile(r"^[a-z][a-z0-9_.-]{0,127}$")
_RUN_ID = re.compile(r"^run_[a-z0-9][a-z0-9_-]{0,62}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$")
_PRIVATE_MARKERS = ("/" + "Users" + "/", "/" + "home" + "/", "file:")
_RUNTIME_PREFIX = ".lifeos-lint-"
_MAX_JSON = 1024 * 1024
_MAX_BATCH_EVIDENCE = 4 * 1024 * 1024


class LintFlowError(ValueError):
    """Lint input, evidence, executor output, or durable state is invalid."""


def _fail(message: str) -> None:
    raise LintFlowError(message)


@dataclass(frozen=True)
class LintLimits:
    max_file_bytes: int = 1024 * 1024
    max_total_bytes: int = 64 * 1024 * 1024
    max_entries_per_directory: int = 4096
    max_depth: int = 16
    max_sources: int = 8192
    max_findings: int = 4096
    max_fixes: int = 512
    max_span_bytes: int = 8 * 1024
    max_spans: int = 16384
    max_packet_bytes: int = 256 * 1024
    max_batches: int = 8192
    max_context_bytes: int = 64 * 1024 * 1024
    max_output_bytes: int = 256 * 1024
    max_report_bytes: int = 1024 * 1024

    def validate(self) -> None:
        values = (
            self.max_file_bytes,
            self.max_total_bytes,
            self.max_entries_per_directory,
            self.max_depth,
            self.max_sources,
            self.max_findings,
            self.max_fixes,
            self.max_span_bytes,
            self.max_spans,
            self.max_packet_bytes,
            self.max_batches,
            self.max_context_bytes,
            self.max_output_bytes,
            self.max_report_bytes,
        )
        if any(type(value) is not int or value < 1 for value in values):
            _fail("lint limits must be positive exact integers")
        if self.max_file_bytes > 4 * 1024 * 1024:
            _fail("lint file bound exceeds the run artifact ceiling")
        if self.max_total_bytes > 256 * 1024 * 1024:
            _fail("lint total source bound is unreasonable")
        if (
            self.max_depth > 64
            or self.max_sources > 65536
            or self.max_spans > 131072
            or self.max_batches > 65536
            or self.max_context_bytes > 256 * 1024 * 1024
        ):
            _fail("lint traversal limits are unreasonable")
        if self.max_span_bytes > self.max_packet_bytes:
            _fail("lint span cannot exceed its packet")
        if self.max_report_bytes > 4 * 1024 * 1024:
            _fail("lint report bound exceeds the run artifact ceiling")


@dataclass(frozen=True)
class LintRequest:
    schema_version: int
    run_id: str
    mode: str
    zones: tuple[str, ...] = LINT_ZONE_ORDER
    apply_fixes: bool = False


@dataclass(frozen=True)
class LintSource:
    zone: str
    path: str
    sha256: str
    size_bytes: int


@dataclass(frozen=True)
class LintEvidenceAnchor:
    path: str
    source_sha256: str | None
    line_start: int | None = None
    line_end: int | None = None
    span_sha256: str | None = None


@dataclass(frozen=True)
class LintFix:
    fix_id: str
    rule_id: str
    zone: str
    path: str
    precondition_sha256: str
    postcondition_sha256: str
    transforms: tuple[str, ...]


@dataclass(frozen=True)
class LintFinding:
    finding_id: str
    mode: str
    rule_id: str
    severity: str
    anchors: tuple[LintEvidenceAnchor, ...]
    evidence_sha256: str
    fix: LintFix | None
    resolution: str


@dataclass(frozen=True)
class LintFixReceipt:
    fix_id: str
    path: str
    before_sha256: str
    after_sha256: str
    status: str


@dataclass(frozen=True)
class LintReport:
    schema_version: int
    run_id: str
    operation_id: str
    mode: str
    status: str
    request_sha256: str
    source_bundle_sha256: str
    sources: tuple[LintSource, ...]
    findings: tuple[LintFinding, ...]
    context_sha256: str
    context_bytes: int
    batch_ids: tuple[str, ...]


@dataclass(frozen=True)
class LintReviewDecision:
    action: str
    actor: str
    at: str
    sequence: int = 1
    superseded_by: str | None = None


@dataclass(frozen=True)
class LintReviewRecord:
    schema_version: int
    proposal_id: str
    status: str
    run_id: str
    operation_id: str
    mode: str
    report_ref: str
    report_sha256: str
    finding_ids: tuple[str, ...]
    created_at: str
    human_decision: LintReviewDecision | None = None


@dataclass(frozen=True)
class LintRunEvidence:
    schema_version: int
    operation_id: str
    request_sha256: str
    run_state_sha256: str
    report: LintReport
    proposal_ref: str | None
    proposal_sha256: str | None
    receipts: tuple[LintFixReceipt, ...]
    flow: str = "lint"
    role: str = "lint-operation-evidence"


@dataclass(frozen=True)
class LintResult:
    report: LintReport
    receipts: tuple[LintFixReceipt, ...]
    proposal: LintReviewRecord | None
    prepared_artifact: PreparedArtifact | CommittedArtifact
    replayed: bool


@dataclass(frozen=True)
class LintCapabilities:
    scan_inbox_zone: ActionCapability
    scan_non_archive_zones: ActionCapability
    scan_task_zone: ActionCapability
    scan_project_zone: ActionCapability
    scan_memory_zone: ActionCapability
    apply_allowlisted_inbox_fix: ActionCapability
    apply_allowlisted_task_fix: ActionCapability
    apply_allowlisted_project_fix: ActionCapability
    commit_semantic_lint_findings: ActionCapability
    record_run_state: ActionCapability


@dataclass(frozen=True)
class LintCrashHooks:
    after_scan: Callable[[], None] | None = None
    after_fix_prepare: Callable[[], None] | None = None
    after_fix_publish: Callable[[], None] | None = None
    after_fix_commit: Callable[[], None] | None = None
    after_packet_prepare: Callable[[], None] | None = None
    after_proposal_publish: Callable[[], None] | None = None
    before_run_commit: Callable[[], None] | None = None


@dataclass(frozen=True)
class _Span:
    span_id: str
    path: str
    source_sha256: str
    line_start: int
    line_end: int
    sha256: str
    text: str


@dataclass(frozen=True)
class _Packet:
    run_id: str
    mode: str
    batch_id: str
    spans: tuple[_Span, ...]
    context_bytes: int
    context_sha256: str


@dataclass(frozen=True)
class _Observed:
    data: bytes
    digest: str
    identity: tuple[int, int, int, int, int]


@dataclass(frozen=True)
class _Scanned:
    sources: tuple[LintSource, ...]
    content: Mapping[tuple[str, str], bytes]
    findings: tuple[LintFinding, ...]
    fixes: tuple[LintFix, ...]


@dataclass(frozen=True)
class _PendingFix:
    fix: LintFix
    preimage: bytes
    raw: bytes
    run_state_sha256: str
    committed: CommittedArtifact | None


class LintExecutor(Protocol):
    def execute(self, task_packet: bytes) -> bytes | str | Mapping[str, object]: ...


def _has_control(value: str, *, layout: bool = False) -> bool:
    for character in value:
        if layout and character in {"\n", "\t"}:
            continue
        category = unicodedata.category(character)
        if category.startswith("C") or category in {"Zl", "Zp"}:
            return True
    return False


def _text(
    value: object,
    label: str,
    maximum: int = 4096,
    *,
    layout: bool = False,
) -> str:
    if not isinstance(value, str):
        _fail(f"{label} must be bounded text")
    try:
        raw = value.encode("utf-8")
    except UnicodeError:
        _fail(f"{label} must be valid UTF-8")
    if (
        not value
        or len(raw) > maximum
        or value.strip() != value
        or _has_control(value, layout=layout)
        or unicodedata.normalize("NFC", value) != value
        or any(marker in value for marker in _PRIVATE_MARKERS)
    ):
        _fail(f"{label} must be bounded portable text")
    return value


def _identifier(value: object, label: str, pattern: re.Pattern[str] = _ID) -> str:
    checked = _text(value, label, 128)
    if pattern.fullmatch(checked) is None:
        _fail(f"{label} has invalid syntax")
    return checked


def _hash(value: object, label: str) -> str:
    checked = _text(value, label, 64)
    if _SHA256.fullmatch(checked) is None:
        _fail(f"{label} must be sha256")
    return checked


def _timestamp(value: object, label: str) -> str:
    checked = _text(value, label, 40)
    if _UTC.fullmatch(checked) is None:
        _fail(f"{label} must be a UTC timestamp")
    try:
        datetime.fromisoformat(checked[:-1] + "+00:00")
    except ValueError:
        _fail(f"{label} must be a valid UTC timestamp")
    return checked


def _safe_relative(value: object, label: str) -> str:
    checked = _text(value, label, 4096)
    if "\\" in checked:
        _fail(f"{label} must be a relative POSIX path")
    path = PurePosixPath(checked)
    if (
        path.is_absolute()
        or path.as_posix() != checked
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        _fail(f"{label} must be a relative POSIX path")
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
            ).encode("utf-8")
            + b"\n"
        )
    except (TypeError, ValueError, UnicodeError, RecursionError):
        _fail("lint value is not canonical JSON")
    if len(raw) > maximum:
        _fail("lint value exceeds its byte bound")
    return raw


def _pairs(items: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in items:
        if key in result:
            _fail("lint JSON contains duplicate fields")
        result[key] = value
    return result


def _decode(raw: bytes | str, label: str, maximum: int = _MAX_JSON) -> object:
    if isinstance(raw, str):
        try:
            source = raw.encode("utf-8")
        except UnicodeError:
            _fail(f"{label} is not UTF-8")
    elif isinstance(raw, bytes):
        source = raw
    else:
        _fail(f"{label} must be bytes or text")
    if not source or len(source) > maximum:
        _fail(f"{label} is empty or too large")
    try:
        return json.loads(source, object_pairs_hook=_pairs)
    except LintFlowError:
        raise
    except (UnicodeError, ValueError, RecursionError):
        _fail(f"{label} is invalid JSON")


def _mapping(value: object, label: str, keys: frozenset[str]) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or set(value) != keys:
        _fail(f"{label} has missing or unknown fields")
    return value


def _request_payload(value: LintRequest) -> dict[str, object]:
    if (
        not isinstance(value, LintRequest)
        or type(value.schema_version) is not int
        or value.schema_version != 1
    ):
        _fail("lint request is invalid")
    run_id = _identifier(value.run_id, "run_id", _RUN_ID)
    if value.mode not in _MODES:
        _fail("lint mode is invalid")
    if not isinstance(value.zones, tuple):
        _fail("lint zones must use the exact five-zone tuple")
    zones = tuple(_text(item, "lint zone", 32) for item in value.zones)
    if zones != LINT_ZONE_ORDER:
        _fail("lint zones must use the exact five-zone order")
    if type(value.apply_fixes) is not bool:
        _fail("apply_fixes must be boolean")
    return {
        "apply_fixes": value.apply_fixes,
        "mode": value.mode,
        "run_id": run_id,
        "schema_version": 1,
        "zones": list(zones),
    }


def render_lint_request(value: LintRequest) -> bytes:
    return _canonical(_request_payload(value))


def parse_lint_request(raw: bytes | str) -> LintRequest:
    item = _mapping(
        _decode(raw, "lint request"),
        "lint request",
        frozenset({"schema_version", "run_id", "mode", "zones", "apply_fixes"}),
    )
    if not isinstance(item["zones"], list):
        _fail("lint request zones are invalid")
    result = LintRequest(
        schema_version=item["schema_version"],
        run_id=item["run_id"],
        mode=item["mode"],
        zones=tuple(item["zones"]),
        apply_fixes=item["apply_fixes"],
    )
    source = raw.encode("utf-8") if isinstance(raw, str) else raw
    if render_lint_request(result) != source:
        _fail("lint request must use canonical JSON")
    return result


def _source_payload(value: LintSource) -> dict[str, object]:
    if not isinstance(value, LintSource) or value.zone not in LINT_ZONE_ORDER:
        _fail("lint source is invalid")
    path = _safe_relative(value.path, "source path")
    zone_parts = PurePosixPath(value.zone).parts
    if PurePosixPath(path).parts[: len(zone_parts)] != zone_parts:
        _fail("lint source path disagrees with its zone")
    return {
        "path": path,
        "sha256": _hash(value.sha256, "source sha256"),
        "size_bytes": _exact_int(value.size_bytes, "source size", 0, 4 * 1024 * 1024),
        "zone": value.zone,
    }


def _exact_int(value: object, label: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        _fail(f"{label} is outside its bound")
    return value


def _anchor_payload(value: LintEvidenceAnchor) -> dict[str, object]:
    if not isinstance(value, LintEvidenceAnchor):
        _fail("lint evidence anchor is invalid")
    source = (
        None
        if value.source_sha256 is None
        else _hash(value.source_sha256, "anchor source sha256")
    )
    span = (
        None
        if value.span_sha256 is None
        else _hash(value.span_sha256, "anchor span sha256")
    )
    start = value.line_start
    end = value.line_end
    if (start is None) != (end is None):
        _fail("lint anchor line range is incomplete")
    if start is not None:
        start = _exact_int(start, "anchor line_start", 1, 2**31 - 1)
        end = _exact_int(end, "anchor line_end", start, 2**31 - 1)
    if span is not None and (source is None or start is None):
        _fail("lint span anchor lacks source and lines")
    return {
        "line_end": end,
        "line_start": start,
        "path": _safe_relative(value.path, "anchor path"),
        "source_sha256": source,
        "span_sha256": span,
    }


def _parse_anchor(value: object) -> LintEvidenceAnchor:
    item = _mapping(
        value,
        "lint anchor",
        frozenset({"path", "source_sha256", "line_start", "line_end", "span_sha256"}),
    )
    result = LintEvidenceAnchor(
        item["path"],
        item["source_sha256"],
        item["line_start"],
        item["line_end"],
        item["span_sha256"],
    )
    _anchor_payload(result)
    return result


def _fix_payload(value: LintFix | None) -> dict[str, object] | None:
    if value is None:
        return None
    if not isinstance(value, LintFix) or value.zone not in _FIX_ACTIONS:
        _fail("lint fix is invalid")
    if not isinstance(value.transforms, tuple) or not value.transforms:
        _fail("lint fix transforms are invalid")
    transforms = tuple(_text(item, "lint transform", 64) for item in value.transforms)
    expected = tuple(item for item in LINT_DIRECT_FIX_TRANSFORMS if item in transforms)
    if transforms != expected or len(transforms) != len(set(transforms)):
        _fail("lint fix transforms are outside the ordered allowlist")
    path = _safe_relative(value.path, "fix path")
    zone_parts = PurePosixPath(value.zone).parts
    if PurePosixPath(path).parts[: len(zone_parts)] != zone_parts:
        _fail("lint fix path disagrees with its zone")
    precondition = _hash(value.precondition_sha256, "fix precondition")
    postcondition = _hash(value.postcondition_sha256, "fix postcondition")
    fix_id = _identifier(value.fix_id, "fix_id")
    expected_id = (
        "lint-fix-"
        + _digest(
            {
                "path": path,
                "post": postcondition,
                "pre": precondition,
                "transforms": list(transforms),
            }
        )[:32]
    )
    if fix_id != expected_id:
        _fail("lint fix id is not its canonical hash")
    return {
        "fix_id": fix_id,
        "path": path,
        "postcondition_sha256": postcondition,
        "precondition_sha256": precondition,
        "rule_id": _identifier(value.rule_id, "fix rule_id"),
        "transforms": list(transforms),
        "zone": value.zone,
    }


def _parse_fix(value: object) -> LintFix | None:
    if value is None:
        return None
    item = _mapping(
        value,
        "lint fix",
        frozenset(
            {
                "fix_id",
                "rule_id",
                "zone",
                "path",
                "precondition_sha256",
                "postcondition_sha256",
                "transforms",
            }
        ),
    )
    if not isinstance(item["transforms"], list):
        _fail("lint fix transforms are invalid")
    result = LintFix(
        item["fix_id"],
        item["rule_id"],
        item["zone"],
        item["path"],
        item["precondition_sha256"],
        item["postcondition_sha256"],
        tuple(item["transforms"]),
    )
    _fix_payload(result)
    return result


def _finding_payload(value: LintFinding) -> dict[str, object]:
    if not isinstance(value, LintFinding) or value.mode not in _MODES:
        _fail("lint finding is invalid")
    if value.severity not in _SEVERITIES or value.resolution not in _RESOLUTIONS:
        _fail("lint finding classification is invalid")
    if (
        not isinstance(value.anchors, tuple)
        or not value.anchors
        or len(value.anchors) > 16
    ):
        _fail("lint finding anchors are invalid")
    anchors = tuple(_anchor_payload(item) for item in value.anchors)
    if len({_canonical(item) for item in anchors}) != len(anchors):
        _fail("lint finding contains duplicate anchors")
    fix = _fix_payload(value.fix)
    if value.resolution == "auto-fixed" and fix is None:
        _fail("auto-fixed finding lacks its exact fix")
    if value.mode != "infra" and fix is not None:
        _fail("semantic lint finding cannot carry a direct fix")
    evidence = _hash(value.evidence_sha256, "finding evidence sha256")
    if evidence != _digest(list(anchors)):
        _fail("lint finding evidence is not its canonical anchor hash")
    finding_id = _identifier(value.finding_id, "finding_id")
    expected_id = (
        "lint-find-"
        + _digest(
            {
                "anchors": list(anchors),
                "evidence": evidence,
                "fix": fix,
                "mode": value.mode,
                "resolution": value.resolution,
                "rule": value.rule_id,
                "severity": value.severity,
            }
        )[:32]
    )
    if finding_id != expected_id:
        _fail("lint finding id is not its canonical hash")
    return {
        "anchors": list(anchors),
        "evidence_sha256": evidence,
        "finding_id": finding_id,
        "fix": fix,
        "mode": value.mode,
        "resolution": value.resolution,
        "rule_id": _identifier(value.rule_id, "finding rule_id"),
        "severity": value.severity,
    }


def _parse_finding(value: object) -> LintFinding:
    item = _mapping(
        value,
        "lint finding",
        frozenset(
            {
                "finding_id",
                "mode",
                "rule_id",
                "severity",
                "anchors",
                "evidence_sha256",
                "fix",
                "resolution",
            }
        ),
    )
    if not isinstance(item["anchors"], list):
        _fail("lint finding anchors are invalid")
    result = LintFinding(
        item["finding_id"],
        item["mode"],
        item["rule_id"],
        item["severity"],
        tuple(_parse_anchor(entry) for entry in item["anchors"]),
        item["evidence_sha256"],
        _parse_fix(item["fix"]),
        item["resolution"],
    )
    _finding_payload(result)
    return result


def _receipt_payload(value: LintFixReceipt) -> dict[str, object]:
    if not isinstance(value, LintFixReceipt) or value.status not in {
        "applied",
        "already-applied",
        "precondition-changed",
    }:
        _fail("lint fix receipt is invalid")
    return {
        "after_sha256": _hash(value.after_sha256, "receipt after sha256"),
        "before_sha256": _hash(value.before_sha256, "receipt before sha256"),
        "fix_id": _identifier(value.fix_id, "receipt fix_id"),
        "path": _safe_relative(value.path, "receipt path"),
        "status": value.status,
    }


def _parse_receipt(value: object) -> LintFixReceipt:
    item = _mapping(
        value,
        "lint receipt",
        frozenset({"fix_id", "path", "before_sha256", "after_sha256", "status"}),
    )
    result = LintFixReceipt(
        item["fix_id"],
        item["path"],
        item["before_sha256"],
        item["after_sha256"],
        item["status"],
    )
    _receipt_payload(result)
    return result


def _receipt_payloads_for_findings(
    findings: Sequence[LintFinding], receipts: object
) -> tuple[dict[str, object], ...]:
    if not isinstance(receipts, tuple):
        _fail("lint run evidence receipts are invalid")
    payloads = tuple(_receipt_payload(item) for item in receipts)
    if len({item["fix_id"] for item in payloads}) != len(payloads):
        _fail("lint run evidence receipts collide")
    fixes = {item.fix.fix_id: item.fix for item in findings if item.fix is not None}
    if set(item["fix_id"] for item in payloads) != set(fixes):
        _fail("lint run evidence receipts do not cover its exact fixes")
    for receipt in receipts:
        fix = fixes[receipt.fix_id]
        if (
            receipt.path != fix.path
            or receipt.before_sha256 != fix.precondition_sha256
            or (
                receipt.status in {"applied", "already-applied"}
                and receipt.after_sha256 != fix.postcondition_sha256
            )
        ):
            _fail("lint run evidence receipt disagrees with its fix")
    return payloads


def _report_payload(value: LintReport) -> dict[str, object]:
    if (
        not isinstance(value, LintReport)
        or type(value.schema_version) is not int
        or value.schema_version != 1
    ):
        _fail("lint report is invalid")
    if value.mode not in _MODES or value.status not in _STATUSES:
        _fail("lint report status is invalid")
    if not isinstance(value.sources, tuple) or len(value.sources) > 65536:
        _fail("lint report sources are invalid")
    sources = tuple(_source_payload(item) for item in value.sources)
    if len({str(item["path"]) for item in sources}) != len(sources):
        _fail("lint report sources collide")
    if list(sources) != sorted(
        sources,
        key=lambda item: (
            LINT_ZONE_ORDER.index(str(item["zone"])),
            str(item["path"]).casefold(),
            str(item["path"]),
        ),
    ):
        _fail("lint report sources are not canonically ordered")
    if not isinstance(value.findings, tuple):
        _fail("lint report findings are invalid")
    findings = tuple(_finding_payload(item) for item in value.findings)
    if len({item["finding_id"] for item in findings}) != len(findings):
        _fail("lint report finding ids collide")
    if list(findings) != sorted(
        findings,
        key=lambda item: (
            str(item["anchors"][0]["path"]).casefold(),
            str(item["anchors"][0]["path"]),
            str(item["rule_id"]),
            str(item["finding_id"]),
        ),
    ):
        _fail("lint report findings are not canonically ordered")
    if value.status != ("findings" if findings else "clean"):
        _fail("lint report status disagrees with its findings")
    if not isinstance(value.batch_ids, tuple):
        _fail("lint report batch ids are invalid")
    batches = tuple(_identifier(item, "batch_id") for item in value.batch_ids)
    if len(batches) != len(set(batches)):
        _fail("lint report batch ids collide")
    request_hash = _hash(value.request_sha256, "request_sha256")
    operation_id = _identifier(value.operation_id, "operation_id")
    if operation_id != _operation(request_hash):
        _fail("lint report operation id is not request-bound")
    source_bundle = _hash(value.source_bundle_sha256, "source bundle sha256")
    if source_bundle != _digest(list(sources)):
        _fail("lint report source bundle hash is invalid")
    return {
        "batch_ids": list(batches),
        "context_bytes": _exact_int(value.context_bytes, "context_bytes", 0, 2**63 - 1),
        "context_sha256": _hash(value.context_sha256, "context_sha256"),
        "findings": list(findings),
        "mode": value.mode,
        "operation_id": operation_id,
        "request_sha256": request_hash,
        "run_id": _identifier(value.run_id, "run_id", _RUN_ID),
        "schema_version": 1,
        "source_bundle_sha256": source_bundle,
        "sources": list(sources),
        "status": value.status,
    }


def render_lint_report(value: LintReport) -> bytes:
    return _canonical(_report_payload(value), 4 * 1024 * 1024)


def parse_lint_report(raw: bytes | str) -> LintReport:
    keys = frozenset(
        {
            "schema_version",
            "run_id",
            "operation_id",
            "mode",
            "status",
            "request_sha256",
            "source_bundle_sha256",
            "sources",
            "findings",
            "context_sha256",
            "context_bytes",
            "batch_ids",
        }
    )
    item = _mapping(_decode(raw, "lint report", 4 * 1024 * 1024), "lint report", keys)
    if (
        not isinstance(item["sources"], list)
        or not isinstance(item["findings"], list)
        or not isinstance(item["batch_ids"], list)
    ):
        _fail("lint report lists are invalid")
    sources = tuple(
        LintSource(entry["zone"], entry["path"], entry["sha256"], entry["size_bytes"])
        for entry in item["sources"]
        if isinstance(entry, Mapping)
        and set(entry) == {"zone", "path", "sha256", "size_bytes"}
    )
    if len(sources) != len(item["sources"]):
        _fail("lint report source is invalid")
    result = LintReport(
        schema_version=item["schema_version"],
        run_id=item["run_id"],
        operation_id=item["operation_id"],
        mode=item["mode"],
        status=item["status"],
        request_sha256=item["request_sha256"],
        source_bundle_sha256=item["source_bundle_sha256"],
        sources=sources,
        findings=tuple(_parse_finding(entry) for entry in item["findings"]),
        context_sha256=item["context_sha256"],
        context_bytes=item["context_bytes"],
        batch_ids=tuple(item["batch_ids"]),
    )
    source = raw.encode("utf-8") if isinstance(raw, str) else raw
    if render_lint_report(result) != source:
        _fail("lint report must use canonical JSON")
    return result


def _decision_payload(value: LintReviewDecision | None) -> dict[str, object] | None:
    if value is None:
        return None
    if (
        not isinstance(value, LintReviewDecision)
        or value.action not in _DECISIONS
        or value.actor != "human"
    ):
        _fail("lint review decision is invalid")
    superseded = (
        None
        if value.superseded_by is None
        else _identifier(value.superseded_by, "superseded_by")
    )
    if (value.action == "supersede") != (superseded is not None):
        _fail("lint review supersede binding is invalid")
    return {
        "action": value.action,
        "actor": "human",
        "at": _timestamp(value.at, "decision at"),
        "sequence": _exact_int(value.sequence, "decision sequence", 1, 2**31 - 1),
        "superseded_by": superseded,
    }


def _review_payload(value: LintReviewRecord) -> dict[str, object]:
    if (
        not isinstance(value, LintReviewRecord)
        or type(value.schema_version) is not int
        or value.schema_version != 1
        or value.mode not in _MODES
        or value.status not in _REVIEW_STATUSES
    ):
        _fail("lint review is invalid")
    if not isinstance(value.finding_ids, tuple) or not value.finding_ids:
        _fail("lint review requires findings")
    findings = tuple(
        _identifier(item, "review finding id") for item in value.finding_ids
    )
    if len(findings) != len(set(findings)):
        _fail("lint review finding ids collide")
    decision = _decision_payload(value.human_decision)
    expected = {
        None: "proposed",
        "approve": "approved",
        "reject": "rejected",
        "supersede": "superseded",
    }[None if decision is None else decision["action"]]
    if value.status != expected:
        _fail("lint review status disagrees with its decision")
    run_id = _identifier(value.run_id, "review run_id", _RUN_ID)
    operation_id = _identifier(value.operation_id, "review operation_id")
    report_ref = _safe_relative(value.report_ref, "review report_ref")
    expected_ref = (
        f"agent/runs/{run_id}/{lint_evidence_artifact_name(operation_id)}.json"
    )
    if report_ref != expected_ref:
        _fail("lint review report reference is invalid")
    return {
        "created_at": _timestamp(value.created_at, "review created_at"),
        "finding_ids": list(findings),
        "human_decision": decision,
        "mode": value.mode,
        "operation_id": operation_id,
        "proposal_id": _identifier(value.proposal_id, "proposal_id"),
        "report_ref": report_ref,
        "report_sha256": _hash(value.report_sha256, "review report sha256"),
        "run_id": run_id,
        "schema_version": 1,
        "status": value.status,
    }


def render_lint_review(value: LintReviewRecord) -> bytes:
    return _canonical(_review_payload(value))


def parse_lint_review(raw: bytes | str) -> LintReviewRecord:
    keys = frozenset(
        {
            "schema_version",
            "proposal_id",
            "status",
            "run_id",
            "operation_id",
            "mode",
            "report_ref",
            "report_sha256",
            "finding_ids",
            "created_at",
            "human_decision",
        }
    )
    item = _mapping(_decode(raw, "lint review"), "lint review", keys)
    if not isinstance(item["finding_ids"], list):
        _fail("lint review finding ids are invalid")
    decision = None
    if item["human_decision"] is not None:
        raw_decision = _mapping(
            item["human_decision"],
            "lint review decision",
            frozenset({"action", "actor", "at", "sequence", "superseded_by"}),
        )
        decision = LintReviewDecision(
            raw_decision["action"],
            raw_decision["actor"],
            raw_decision["at"],
            raw_decision["sequence"],
            raw_decision["superseded_by"],
        )
    result = LintReviewRecord(
        schema_version=item["schema_version"],
        proposal_id=item["proposal_id"],
        status=item["status"],
        run_id=item["run_id"],
        operation_id=item["operation_id"],
        mode=item["mode"],
        report_ref=item["report_ref"],
        report_sha256=item["report_sha256"],
        finding_ids=tuple(item["finding_ids"]),
        created_at=item["created_at"],
        human_decision=decision,
    )
    source = raw.encode("utf-8") if isinstance(raw, str) else raw
    if render_lint_review(result) != source:
        _fail("lint review must use canonical JSON")
    return result


def _evidence_payload(value: LintRunEvidence) -> dict[str, object]:
    if (
        not isinstance(value, LintRunEvidence)
        or type(value.schema_version) is not int
        or value.schema_version != 1
        or value.flow != "lint"
        or value.role != "lint-operation-evidence"
    ):
        _fail("lint run evidence is invalid")
    proposal_ref = (
        None
        if value.proposal_ref is None
        else _safe_relative(value.proposal_ref, "evidence proposal_ref")
    )
    proposal_hash = (
        None
        if value.proposal_sha256 is None
        else _hash(value.proposal_sha256, "evidence proposal sha256")
    )
    if (proposal_ref is None) != (proposal_hash is None):
        _fail("lint run evidence proposal binding is incomplete")
    if proposal_ref is not None:
        proposal_path = PurePosixPath(proposal_ref)
        if (
            proposal_path.parts[:1] != ("review",)
            or len(proposal_path.parts) != 2
            or not proposal_path.name.startswith("lintprop-")
            or not proposal_path.name.endswith(".lint.json")
        ):
            _fail("lint run evidence proposal reference is invalid")
    report = _report_payload(value.report)
    if (
        value.operation_id != value.report.operation_id
        or value.request_sha256 != value.report.request_sha256
    ):
        _fail("lint run evidence report binding is invalid")
    needs_review = any(item.resolution == "review" for item in value.report.findings)
    if needs_review != (proposal_ref is not None):
        _fail("lint run evidence proposal disagrees with review findings")
    receipts = _receipt_payloads_for_findings(value.report.findings, value.receipts)
    return {
        "flow": "lint",
        "operation_id": _identifier(value.operation_id, "evidence operation_id"),
        "proposal_ref": proposal_ref,
        "proposal_sha256": proposal_hash,
        "receipts": list(receipts),
        "report": report,
        "request_sha256": _hash(value.request_sha256, "evidence request sha256"),
        "role": "lint-operation-evidence",
        "run_state_sha256": _hash(value.run_state_sha256, "evidence run state sha256"),
        "schema_version": 1,
    }


def render_lint_run_evidence(value: LintRunEvidence) -> bytes:
    return _canonical(_evidence_payload(value), 4 * 1024 * 1024)


def parse_lint_run_evidence(raw: bytes | str) -> LintRunEvidence:
    keys = frozenset(
        {
            "schema_version",
            "flow",
            "role",
            "operation_id",
            "request_sha256",
            "run_state_sha256",
            "report",
            "proposal_ref",
            "proposal_sha256",
            "receipts",
        }
    )
    item = _mapping(
        _decode(raw, "lint run evidence", 4 * 1024 * 1024), "lint run evidence", keys
    )
    if not isinstance(item["receipts"], list) or not isinstance(
        item["report"], Mapping
    ):
        _fail("lint run evidence nested values are invalid")
    report_raw = _canonical(dict(item["report"]), 4 * 1024 * 1024)
    result = LintRunEvidence(
        schema_version=item["schema_version"],
        operation_id=item["operation_id"],
        request_sha256=item["request_sha256"],
        run_state_sha256=item["run_state_sha256"],
        report=parse_lint_report(report_raw),
        proposal_ref=item["proposal_ref"],
        proposal_sha256=item["proposal_sha256"],
        receipts=tuple(_parse_receipt(entry) for entry in item["receipts"]),
        flow=item["flow"],
        role=item["role"],
    )
    source = raw.encode("utf-8") if isinstance(raw, str) else raw
    if render_lint_run_evidence(result) != source:
        _fail("lint run evidence must use canonical JSON")
    return result


def lint_evidence_artifact_name(operation_id: str) -> str:
    checked = _identifier(operation_id, "operation_id")
    return "lint-evidence-" + hashlib.sha256(checked.encode()).hexdigest()[:24]


def _lint_infra_evidence_artifact_name(operation_id: str) -> str:
    checked = _identifier(operation_id, "operation_id")
    return "lint-infra-evidence-" + hashlib.sha256(checked.encode()).hexdigest()[:24]


def inspect_lint_run_evidence(
    artifact: PreparedArtifact | CommittedArtifact, raw: bytes | str
) -> LintRunEvidence:
    if not isinstance(artifact, (PreparedArtifact, CommittedArtifact)):
        _fail("lint evidence inspector requires a run artifact")
    record = parse_lint_run_evidence(raw)
    expected_name = lint_evidence_artifact_name(record.operation_id)
    expected_relative = f"{record.report.run_id}/{expected_name}.json"
    expected_step = (
        "lint-final-" + hashlib.sha256(record.operation_id.encode()).hexdigest()[:32]
    )
    source = raw.encode("utf-8") if isinstance(raw, str) else raw
    if (
        artifact.name != expected_name
        or artifact.zone != "agent/runs"
        or artifact.relative != expected_relative
        or artifact.state_ref != f"agent/runs/{expected_relative}"
        or artifact.sha256 != hashlib.sha256(source).hexdigest()
        or record.report.operation_id != record.operation_id
        or record.report.request_sha256 != record.request_sha256
        or (
            isinstance(artifact, CommittedArtifact)
            and artifact.step_id != expected_step
        )
    ):
        _fail("lint run evidence artifact binding is invalid")
    return record


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value, 4 * 1024 * 1024)).hexdigest()


def _portable_key(value: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value in {".", ".."}
        or "/" in value
        or "\\" in value
        or _has_control(value)
        or unicodedata.normalize("NFC", value) != value
    ):
        _fail("vault entry name is not portable")
    return value.casefold()


def _identity(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _read_at(directory_fd: int, name: str, maximum: int) -> _Observed:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(name, flags, dir_fd=directory_fd)
    except OSError:
        _fail("lint source cannot be opened safely")
    try:
        before = os.fstat(fd)
        named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(before.st_mode)
            or _identity(before)[:2] != _identity(named)[:2]
        ):
            _fail("lint source is not a stable regular file")
        if before.st_size > maximum:
            _fail("lint source exceeds its byte bound")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            part = os.read(fd, min(64 * 1024, remaining))
            if not part:
                break
            chunks.append(part)
            remaining -= len(part)
        after = os.fstat(fd)
        data = b"".join(chunks)
        if len(data) > maximum or _identity(before) != _identity(after):
            _fail("lint source changed during bounded read")
        return _Observed(data, hashlib.sha256(data).hexdigest(), _identity(after))
    finally:
        os.close(fd)


def _write_once_at(directory_fd: int, name: str, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(name, flags, 0o600, dir_fd=directory_fd)
    except OSError:
        _fail("lint transaction slot cannot be created")
    try:
        offset = 0
        while offset < len(data):
            written = os.write(fd, data[offset:])
            if written <= 0:
                _fail("lint transaction slot cannot be written")
            offset += written
        os.fsync(fd)
    finally:
        os.close(fd)
    os.fsync(directory_fd)


def _rename_exchange(directory_fd: int, first: str, second: str) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    first_raw = os.fsencode(first)
    second_raw = os.fsencode(second)
    if hasattr(libc, "renameatx_np"):
        result = libc.renameatx_np(
            directory_fd,
            ctypes.c_char_p(first_raw),
            directory_fd,
            ctypes.c_char_p(second_raw),
            0x00000002,
        )
    elif hasattr(libc, "renameat2"):
        result = libc.renameat2(
            directory_fd,
            ctypes.c_char_p(first_raw),
            directory_fd,
            ctypes.c_char_p(second_raw),
            2,
        )
    else:
        raise OSError(errno.ENOSYS, "atomic exchange is unavailable")
    if result != 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))


def _normalization(data: bytes) -> tuple[bytes, tuple[str, ...]]:
    result = data
    transforms: list[str] = []
    if result.startswith(b"\xef\xbb\xbf"):
        result = result[3:]
        transforms.append("strip-utf8-bom")
    if b"\r\n" in result:
        result = result.replace(b"\r\n", b"\n")
        transforms.append("crlf-to-lf")
    if result and not result.endswith(b"\n"):
        result += b"\n"
        transforms.append("append-final-newline")
    return result, tuple(transforms)


def _finding(
    *,
    mode: str,
    rule: str,
    anchors: tuple[LintEvidenceAnchor, ...],
    fix: LintFix | None = None,
    resolution: str = "review",
    severity: str = "error",
) -> LintFinding:
    anchor_payloads = [_anchor_payload(item) for item in anchors]
    evidence = _digest(anchor_payloads)
    identity = _digest(
        {
            "anchors": anchor_payloads,
            "evidence": evidence,
            "fix": _fix_payload(fix),
            "mode": mode,
            "resolution": resolution,
            "rule": rule,
            "severity": severity,
        }
    )
    return LintFinding(
        "lint-find-" + identity[:32],
        mode,
        rule,
        severity,
        anchors,
        evidence,
        fix,
        resolution,
    )


def _reclassify_finding(
    value: LintFinding, *, fix: LintFix | None, resolution: str
) -> LintFinding:
    return _finding(
        mode=value.mode,
        rule=value.rule_id,
        severity=value.severity,
        anchors=value.anchors,
        fix=fix,
        resolution=resolution,
    )


def _operation(request_hash: str) -> str:
    return "lint-" + request_hash[:32]


class LintFlow:
    def __init__(
        self,
        resolver: VaultPathResolver,
        run_store: RunStore,
        policy: AuthorityPolicy,
        *,
        executor: LintExecutor | None = None,
        limits: LintLimits | None = None,
    ) -> None:
        if (
            not isinstance(resolver, VaultPathResolver)
            or not isinstance(run_store, RunStore)
            or not isinstance(policy, AuthorityPolicy)
            or getattr(run_store, "_resolver", None) is not resolver
        ):
            _fail("lint resolver, run store, and policy are inconsistent")
        if executor is not None and not callable(getattr(executor, "execute", None)):
            _fail("lint executor is invalid")
        self._resolver = resolver
        self._runs = run_store
        self._policy = policy
        self._executor = executor
        self._limits = limits or LintLimits()
        self._limits.validate()
        try:
            runs = resolver.resolve("agent/runs", must_exist=True)
            root = runs
            for _ in resolver.config.zone("runs").parts:
                root = root.parent
            root_fd = os.open(
                root,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
            metadata = os.fstat(root_fd)
            named = os.stat(root, follow_symlinks=False)
            if _identity(metadata)[:2] != _identity(named)[:2]:
                raise OSError("vault root changed while opened")
            zone_parts: dict[str, tuple[str, ...]] = {}
            zone_identities: dict[str, tuple[int, int]] = {}
            for zone in (*LINT_ZONE_ORDER, "review", "agent/runs"):
                resolved = resolver.resolve(zone, must_exist=True)
                relative = resolved.relative_to(root)
                zone_metadata = os.stat(resolved, follow_symlinks=False)
                if not stat.S_ISDIR(zone_metadata.st_mode):
                    raise OSError("lint zone is not a directory")
                zone_parts[zone] = relative.parts
                zone_identities[zone] = _identity(zone_metadata)[:2]
        except (OSError, ValueError, VaultSchemaError):
            if "root_fd" in locals():
                os.close(root_fd)
            _fail("lint vault root cannot be pinned")
        if not stat.S_ISDIR(metadata.st_mode):
            os.close(root_fd)
            _fail("lint vault root is not a directory")
        self._root = root
        self._root_fd = root_fd
        self._root_identity = _identity(metadata)[:2]
        self._zone_parts = zone_parts
        self._zone_identities = zone_identities
        self._root_finalizer = weakref.finalize(self, os.close, root_fd)

    def _require_root(self) -> None:
        try:
            opened = os.fstat(self._root_fd)
            current = os.stat(self._root, follow_symlinks=False)
        except OSError:
            _fail("lint vault root cannot be revalidated")
        if (
            not stat.S_ISDIR(opened.st_mode)
            or not stat.S_ISDIR(current.st_mode)
            or _identity(opened)[:2] != self._root_identity
            or _identity(current)[:2] != self._root_identity
        ):
            _fail("lint vault root identity changed")

    def _open_zone_fd(self, zone: str, *, write: bool) -> int:
        if zone not in self._zone_parts:
            _fail("lint zone is outside its pinned namespace")
        try:
            resolved = self._resolver.resolve(zone, for_write=write, must_exist=True)
            relative = resolved.relative_to(self._root)
        except (OSError, ValueError, VaultSchemaError):
            _fail("lint zone cannot be resolved safely")
        if relative.parts != self._zone_parts[zone]:
            _fail("lint zone path changed after root pinning")
        self._require_root()
        current = os.dup(self._root_fd)
        try:
            for part in self._zone_parts[zone]:
                named = os.stat(part, dir_fd=current, follow_symlinks=False)
                child = os.open(
                    part,
                    os.O_RDONLY
                    | getattr(os, "O_DIRECTORY", 0)
                    | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=current,
                )
                opened = os.fstat(child)
                if (
                    not stat.S_ISDIR(named.st_mode)
                    or not stat.S_ISDIR(opened.st_mode)
                    or _identity(named)[:2] != _identity(opened)[:2]
                ):
                    os.close(child)
                    _fail("lint zone changed while opened from its pinned root")
                os.close(current)
                current = child
            if _identity(os.fstat(current))[:2] != self._zone_identities[zone]:
                _fail("lint zone identity changed after flow construction")
            self._require_root()
            return current
        except LintFlowError:
            os.close(current)
            raise
        except OSError:
            os.close(current)
            _fail("lint zone cannot be opened from its pinned root")

    def _revalidate_zone_fd(self, zone: str, zone_fd: int, *, write: bool) -> None:
        fresh = self._open_zone_fd(zone, write=write)
        try:
            opened = os.fstat(zone_fd)
            current = os.fstat(fresh)
            if (
                not stat.S_ISDIR(opened.st_mode)
                or _identity(opened)[:2] != _identity(current)[:2]
            ):
                _fail("lint zone identity changed during the operation")
        finally:
            os.close(fresh)

    def _revalidate_parent_fd(
        self,
        zone: str,
        zone_fd: int,
        parent_fd: int,
        relative: str,
        *,
        write: bool,
    ) -> None:
        path = PurePosixPath(_safe_relative(relative, "lint pinned relative path"))
        self._revalidate_zone_fd(zone, zone_fd, write=write)
        current = os.dup(zone_fd)
        try:
            for part in path.parts[:-1]:
                named = os.stat(part, dir_fd=current, follow_symlinks=False)
                child = os.open(
                    part,
                    os.O_RDONLY
                    | getattr(os, "O_DIRECTORY", 0)
                    | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=current,
                )
                opened = os.fstat(child)
                if (
                    not stat.S_ISDIR(named.st_mode)
                    or _identity(named)[:2] != _identity(opened)[:2]
                ):
                    os.close(child)
                    _fail("lint parent changed during fd-relative traversal")
                os.close(current)
                current = child
            expected = os.fstat(parent_fd)
            actual = os.fstat(current)
            if (
                not stat.S_ISDIR(expected.st_mode)
                or _identity(expected)[:2] != _identity(actual)[:2]
            ):
                _fail("lint parent identity changed during the operation")
            self._require_root()
        finally:
            os.close(current)

    def _require(
        self, capability: ActionCapability, action_id: str
    ) -> ActionCapability:
        expected = {
            **{
                action: ("read", target, "read", "read-only", False)
                for action, target in _ZONE_ACTIONS.values()
            },
            **{
                action: ("domain-write", target, "write", "artifact-commit", True)
                for action, target in _FIX_ACTIONS.values()
            },
            "commit-semantic-lint-findings": (
                "proposal",
                "vault:review",
                "write",
                "proposal-commit",
                True,
            ),
            "record-run-state": (
                "internal-write",
                "vault:agent/runs",
                "write",
                "run-state-commit",
                True,
            ),
        }
        try:
            grant = self._policy.require(capability)
        except AuthorityError as error:
            raise LintFlowError(str(error)) from None
        authority, target, access, effect, commit = expected[action_id]
        if (
            grant.flow_id,
            grant.action_id,
            grant.actor,
            grant.authority,
            grant.target,
            grant.access,
            grant.effect_kind,
            grant.artifact_commit,
        ) != ("lint", action_id, "runtime", authority, target, access, effect, commit):
            _fail(f"capability does not authorize lint action {action_id}")
        return grant

    @staticmethod
    def _cap(capabilities: LintCapabilities, action_id: str) -> ActionCapability:
        names = {
            "scan-inbox-zone": "scan_inbox_zone",
            "scan-non-archive-zones": "scan_non_archive_zones",
            "scan-task-zone": "scan_task_zone",
            "scan-project-zone": "scan_project_zone",
            "scan-memory-zone": "scan_memory_zone",
            "apply-allowlisted-inbox-fix": "apply_allowlisted_inbox_fix",
            "apply-allowlisted-task-fix": "apply_allowlisted_task_fix",
            "apply-allowlisted-project-fix": "apply_allowlisted_project_fix",
            "commit-semantic-lint-findings": "commit_semantic_lint_findings",
            "record-run-state": "record_run_state",
        }
        if not isinstance(capabilities, LintCapabilities):
            _fail("lint capabilities are invalid")
        return getattr(capabilities, names[action_id])

    def _scan_caps(
        self, request: LintRequest, caps: LintCapabilities
    ) -> tuple[ActionCapability, ...]:
        return tuple(
            self._require(
                self._cap(caps, _ZONE_ACTIONS[zone][0]), _ZONE_ACTIONS[zone][0]
            )
            for zone in request.zones
        )

    def _run_state(self, request: LintRequest) -> tuple[Mapping[str, object], str]:
        try:
            snapshot = self._runs.snapshot(request.run_id)
            state = snapshot.state
        except RunError as error:
            raise LintFlowError("lint run state is unavailable") from error
        expected_input = {
            "apply_fixes": request.apply_fixes,
            "mode": request.mode,
            "zones": list(request.zones),
        }
        if (
            state.get("flow") != "lint"
            or state.get("status") != "running"
            or state.get("input") != expected_input
            or state.get("authority") != "domain-write"
        ):
            _fail("lint request is not bound to the active run state")
        return state, snapshot.state_sha256

    def _walk_zone(self, zone: str) -> tuple[dict[str, bytes], list[LintFinding]]:
        try:
            root_fd = self._open_zone_fd(zone, write=False)
        except LintFlowError:
            _fail("lint zone cannot be opened safely")
        content: dict[str, bytes] = {}
        findings: list[LintFinding] = []
        stack: list[tuple[int, tuple[str, ...]]] = []
        try:
            opened_root = os.fstat(root_fd)
            if not stat.S_ISDIR(opened_root.st_mode):
                _fail("lint zone changed while opened")
            stack.append((os.dup(root_fd), ()))
            while stack:
                directory_fd, parts = stack.pop()
                try:
                    names = os.listdir(directory_fd)
                    if len(names) > self._limits.max_entries_per_directory:
                        _fail("lint directory exceeds its entry bound")
                    keyed: dict[str, str] = {}
                    for name in names:
                        key = _portable_key(name)
                        if key in keyed and keyed[key] != name:
                            _fail("lint directory has a portable namespace collision")
                        keyed[key] = name
                    for name in reversed(
                        sorted(names, key=lambda item: (item.casefold(), item))
                    ):
                        key = name.casefold()
                        if key in ARCHIVE_COMPONENTS or name.startswith(
                            _RUNTIME_PREFIX
                        ):
                            continue
                        relative_parts = (*parts, name)
                        relative = PurePosixPath(*relative_parts).as_posix()
                        metadata = os.stat(
                            name, dir_fd=directory_fd, follow_symlinks=False
                        )
                        if stat.S_ISDIR(metadata.st_mode):
                            if len(relative_parts) > self._limits.max_depth:
                                _fail("lint traversal exceeds its depth bound")
                            child_fd = os.open(
                                name,
                                os.O_RDONLY
                                | getattr(os, "O_DIRECTORY", 0)
                                | getattr(os, "O_NOFOLLOW", 0),
                                dir_fd=directory_fd,
                            )
                            opened = os.fstat(child_fd)
                            if _identity(opened)[:2] != _identity(metadata)[:2]:
                                os.close(child_fd)
                                _fail("lint directory changed during traversal")
                            stack.append((child_fd, relative_parts))
                            continue
                        logical = f"{zone}/{relative}"
                        if not stat.S_ISREG(metadata.st_mode):
                            anchor = LintEvidenceAnchor(logical, None)
                            findings.append(
                                _finding(
                                    mode="infra",
                                    rule="infra.entry.unsupported",
                                    anchors=(anchor,),
                                )
                            )
                            continue
                        if metadata.st_size > self._limits.max_file_bytes:
                            anchor = LintEvidenceAnchor(logical, None)
                            findings.append(
                                _finding(
                                    mode="infra",
                                    rule="infra.file.too-large",
                                    anchors=(anchor,),
                                )
                            )
                            continue
                        observed = _read_at(
                            directory_fd, name, self._limits.max_file_bytes
                        )
                        content[relative] = observed.data
                        if len(content) > self._limits.max_sources:
                            _fail("lint source count exceeds its hard bound")
                finally:
                    os.close(directory_fd)
            self._revalidate_zone_fd(zone, root_fd, write=False)
            return content, findings
        except OSError:
            _fail("lint traversal failed safely")
        finally:
            for pending_fd, _parts in stack:
                try:
                    os.close(pending_fd)
                except OSError:
                    pass
            os.close(root_fd)

    @staticmethod
    def _fix_eligible(zone: str, relative: str) -> bool:
        path = PurePosixPath(relative)
        if zone not in _FIX_ACTIONS or path.suffix.casefold() != ".md":
            return False
        if any(
            part.casefold() in ARCHIVE_COMPONENTS or part.startswith(".lifeos-")
            for part in path.parts
        ):
            return False
        if zone == "tasks" and path.parts and path.parts[0] in {"days", "weeks"}:
            return False
        if zone == "projects" and (
            path.name == "log.md" or path.parts[0] == ".lifeos-project-evidence"
        ):
            return False
        return True

    def _scan(self, request: LintRequest) -> _Scanned:
        raw_by_zone: dict[str, dict[str, bytes]] = {}
        findings: list[LintFinding] = []
        for zone in request.zones:
            raw_by_zone[zone], zone_findings = self._walk_zone(zone)
            findings.extend(zone_findings)
        all_content = {
            (zone, relative): raw
            for zone in request.zones
            for relative, raw in raw_by_zone[zone].items()
        }
        if len(all_content) > self._limits.max_sources:
            _fail("lint source count exceeds its hard bound")
        if sum(len(raw) for raw in all_content.values()) > self._limits.max_total_bytes:
            _fail("lint source bytes exceed their hard bound")
        sources = tuple(
            LintSource(
                zone, f"{zone}/{relative}", hashlib.sha256(raw).hexdigest(), len(raw)
            )
            for zone in request.zones
            for relative, raw in sorted(
                raw_by_zone[zone].items(),
                key=lambda item: (item[0].casefold(), item[0]),
            )
        )
        markdown_paths = tuple(
            source.path
            for source in sources
            if PurePosixPath(source.path).suffix.casefold() == ".md"
        )
        fixes: dict[str, LintFix] = {}
        for source in sources:
            relative = source.path[len(source.zone) + 1 :]
            raw = all_content[(source.zone, relative)]
            if PurePosixPath(relative).suffix.casefold() == ".md":
                normalized, transforms = _normalization(raw)
                fix: LintFix | None = None
                candidate_valid = False
                try:
                    text = normalized.decode("utf-8")
                    snapshot = parse_note(
                        NoteRef(OBSIDIAN_SCHEMA_VERSION, source.zone, relative),
                        text,
                        path=source.path,
                    )
                    validation = validate_note(snapshot, link_index=markdown_paths)
                    candidate_valid = validation.valid
                    for issue in validation.issues:
                        anchor = LintEvidenceAnchor(
                            source.path, source.sha256, issue.line, issue.line
                        )
                        findings.append(
                            _finding(
                                mode="infra",
                                rule=issue.rule_id,
                                anchors=(anchor,),
                                severity=issue.severity,
                            )
                        )
                except (UnicodeDecodeError, ObsidianError):
                    anchor = LintEvidenceAnchor(source.path, source.sha256)
                    findings.append(
                        _finding(
                            mode="infra", rule="infra.note.parse", anchors=(anchor,)
                        )
                    )
                if (
                    transforms
                    and request.apply_fixes
                    and candidate_valid
                    and self._fix_eligible(source.zone, relative)
                ):
                    payload = {
                        "path": source.path,
                        "pre": source.sha256,
                        "post": hashlib.sha256(normalized).hexdigest(),
                        "transforms": list(transforms),
                    }
                    fix_id = "lint-fix-" + _digest(payload)[:32]
                    fix = LintFix(
                        fix_id,
                        "infra.text.normalization",
                        source.zone,
                        source.path,
                        source.sha256,
                        payload["post"],
                        transforms,
                    )
                    fixes[fix_id] = fix
                for transform, rule in (
                    ("strip-utf8-bom", "infra.utf8-bom"),
                    ("crlf-to-lf", "infra.crlf"),
                    ("append-final-newline", "infra.final-newline"),
                ):
                    if transform in transforms:
                        anchor = LintEvidenceAnchor(source.path, source.sha256)
                        findings.append(
                            _finding(
                                mode="infra",
                                rule=rule,
                                anchors=(anchor,),
                                fix=fix,
                                resolution="auto-fixed"
                                if fix is not None
                                else "review",
                            )
                        )
                continue
            try:
                path = PurePosixPath(relative)
                if (
                    source.zone == "tasks"
                    and len(path.parts) == 2
                    and path.parts[0] == "days"
                    and path.suffix == ".json"
                ):
                    plan = parse_day_plan(raw)
                    paired = raw_by_zone[source.zone].get(f"days/{path.stem}.md")
                    if paired is None or paired != render_day_markdown(plan):
                        raise PlanFlowError("day plan projection differs")
                elif (
                    source.zone == "tasks"
                    and len(path.parts) == 2
                    and path.parts[0] == "weeks"
                    and path.suffix == ".json"
                ):
                    plan = parse_week_plan(raw)
                    paired = raw_by_zone[source.zone].get(f"weeks/{path.stem}.md")
                    if paired is None or paired != render_week_markdown(plan):
                        raise PlanFlowError("week plan projection differs")
                elif (
                    source.zone == "agent/memory"
                    and len(path.parts) == 3
                    and path.parts[:2] == ("metadata", "records")
                    and path.suffix == ".json"
                ):
                    parse_memory_metadata(raw)
                elif (
                    source.zone == "agent/memory"
                    and len(path.parts) == 3
                    and path.parts[:2] == ("metadata", "outcomes")
                    and path.suffix == ".json"
                ):
                    parse_forget_outcome(raw)
            except (PlanFlowError, MemoryFlowError):
                anchor = LintEvidenceAnchor(source.path, source.sha256)
                findings.append(
                    _finding(
                        mode="infra", rule="infra.domain.invalid", anchors=(anchor,)
                    )
                )
        if (
            len(findings) > self._limits.max_findings
            or len(fixes) > self._limits.max_fixes
        ):
            _fail("lint findings or fixes exceed their hard bound")
        ordered_findings = tuple(
            sorted(
                findings,
                key=lambda item: (
                    item.anchors[0].path.casefold(),
                    item.anchors[0].path,
                    item.rule_id,
                    item.finding_id,
                ),
            )
        )
        return _Scanned(
            sources,
            all_content,
            ordered_findings,
            tuple(fixes[key] for key in sorted(fixes)),
        )

    def _open_parent(
        self, zone: str, relative: str, *, write: bool
    ) -> tuple[int, int, str, str]:
        checked = _safe_relative(relative, "lint target relative path")
        path = PurePosixPath(checked)
        zone_fd: int | None = None
        current: int | None = None
        try:
            zone_fd = self._open_zone_fd(zone, write=write)
            current = os.dup(zone_fd)
            for part in path.parts[:-1]:
                named = os.stat(part, dir_fd=current, follow_symlinks=False)
                child = os.open(
                    part,
                    os.O_RDONLY
                    | getattr(os, "O_DIRECTORY", 0)
                    | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=current,
                )
                opened = os.fstat(child)
                if (
                    not stat.S_ISDIR(named.st_mode)
                    or _identity(named)[:2] != _identity(opened)[:2]
                ):
                    os.close(child)
                    _fail("lint target parent changed during traversal")
                os.close(current)
                current = child
            self._revalidate_parent_fd(zone, zone_fd, current, checked, write=write)
            return zone_fd, current, path.name, checked
        except LintFlowError:
            if current is not None:
                os.close(current)
            if zone_fd is not None:
                os.close(zone_fd)
            raise
        except OSError:
            if current is not None:
                os.close(current)
            if zone_fd is not None:
                os.close(zone_fd)
            _fail("lint fix target cannot be opened safely")

    def _revalidate_fix_parent(
        self,
        zone_fd: int,
        parent_fd: int,
        fix: LintFix,
        relative: str,
    ) -> None:
        try:
            self._resolver.resolve(fix.zone, relative, must_exist=True, for_write=True)
            self._revalidate_parent_fd(
                fix.zone, zone_fd, parent_fd, relative, write=True
            )
        except (OSError, VaultSchemaError, LintFlowError):
            _fail("lint fix parent cannot be revalidated")

    def _remove_slot(
        self,
        parent_fd: int,
        slot: str,
        expected: str,
        *,
        maximum: int | None = None,
    ) -> None:
        observed = self._optional_at(parent_fd, slot, maximum=maximum)
        if observed is None:
            return
        if observed.digest != expected:
            _fail("lint transaction slot contains foreign bytes")
        os.unlink(slot, dir_fd=parent_fd)
        os.fsync(parent_fd)

    def _optional_at(
        self, parent_fd: int, leaf: str, *, maximum: int | None = None
    ) -> _Observed | None:
        try:
            metadata = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            return None
        except OSError:
            _fail("lint transaction slot cannot be inspected")
        if not stat.S_ISREG(metadata.st_mode):
            _fail("lint transaction slot is not a regular file")
        return _read_at(
            parent_fd,
            leaf,
            self._limits.max_file_bytes if maximum is None else maximum,
        )

    def _cleanup_fix_slot(self, fix: LintFix) -> None:
        relative = fix.path[len(fix.zone) + 1 :]
        zone_fd, parent_fd, _leaf, _relative = self._open_parent(
            fix.zone, relative, write=True
        )
        slot = (
            f"{_RUNTIME_PREFIX}"
            f"{hashlib.sha256(fix.fix_id.encode()).hexdigest()[:24]}.slot"
        )
        try:
            observed = self._optional_at(parent_fd, slot)
            if observed is None:
                return
            if observed.digest not in {
                fix.precondition_sha256,
                fix.postcondition_sha256,
            }:
                _fail("lint transaction slot contains foreign bytes")
            self._remove_slot(parent_fd, slot, observed.digest)
        finally:
            os.close(parent_fd)
            os.close(zone_fd)

    def _apply_fix_bytes(self, fix: LintFix, candidate: bytes) -> LintFixReceipt:
        relative = fix.path[len(fix.zone) + 1 :]
        if not self._fix_eligible(fix.zone, relative):
            _fail("lint fix candidate exceeds its byte-only allowlist")
        zone_fd, parent_fd, leaf, _relative = self._open_parent(
            fix.zone, relative, write=True
        )
        slot = f"{_RUNTIME_PREFIX}{hashlib.sha256(fix.fix_id.encode()).hexdigest()[:24]}.slot"
        try:
            current = _read_at(parent_fd, leaf, self._limits.max_file_bytes)
            if current.digest == fix.postcondition_sha256:
                return LintFixReceipt(
                    fix.fix_id,
                    fix.path,
                    fix.precondition_sha256,
                    fix.postcondition_sha256,
                    "already-applied",
                )
            if current.digest != fix.precondition_sha256:
                staged = self._optional_at(parent_fd, slot)
                if staged is not None:
                    if staged.digest != fix.postcondition_sha256:
                        _fail("lint transaction slot contains foreign bytes")
                    self._remove_slot(parent_fd, slot, staged.digest)
                return LintFixReceipt(
                    fix.fix_id,
                    fix.path,
                    fix.precondition_sha256,
                    current.digest,
                    "precondition-changed",
                )
            if (
                _normalization(candidate)[0] != candidate
                or hashlib.sha256(candidate).hexdigest() != fix.postcondition_sha256
            ):
                _fail("lint fix candidate exceeds its byte-only allowlist")
            self._revalidate_fix_parent(zone_fd, parent_fd, fix, relative)
            staged = self._optional_at(parent_fd, slot)
            if staged is None:
                _write_once_at(parent_fd, slot, candidate)
                staged = _read_at(parent_fd, slot, self._limits.max_file_bytes)
            if staged.digest != fix.postcondition_sha256:
                _fail("lint transaction slot contains foreign bytes")
            try:
                self._revalidate_fix_parent(zone_fd, parent_fd, fix, relative)
            except LintFlowError:
                self._remove_slot(parent_fd, slot, staged.digest)
                raise
            current = _read_at(parent_fd, leaf, self._limits.max_file_bytes)
            if current.digest != fix.precondition_sha256:
                self._remove_slot(parent_fd, slot, staged.digest)
                return LintFixReceipt(
                    fix.fix_id,
                    fix.path,
                    fix.precondition_sha256,
                    current.digest,
                    "precondition-changed",
                )
            try:
                _rename_exchange(parent_fd, slot, leaf)
            except OSError:
                self._remove_slot(parent_fd, slot, staged.digest)
                _fail("lint fix cannot be published atomically")
            os.fsync(parent_fd)
            published = _read_at(parent_fd, leaf, self._limits.max_file_bytes)
            displaced = _read_at(parent_fd, slot, self._limits.max_file_bytes)
            binding_valid = True
            try:
                self._revalidate_fix_parent(zone_fd, parent_fd, fix, relative)
            except LintFlowError:
                binding_valid = False
            hashes_valid = (
                published.digest == fix.postcondition_sha256
                and displaced.digest == fix.precondition_sha256
            )
            if not hashes_valid or not binding_valid:
                if published.digest == fix.postcondition_sha256:
                    try:
                        _rename_exchange(parent_fd, slot, leaf)
                        os.fsync(parent_fd)
                        rolled_back = _read_at(
                            parent_fd, leaf, self._limits.max_file_bytes
                        )
                        if rolled_back.digest != displaced.digest:
                            _fail("lint fix rollback cannot be verified")
                        self._remove_slot(parent_fd, slot, fix.postcondition_sha256)
                    except OSError:
                        _fail("lint fix rollback cannot be published atomically")
                _fail("lint fix exchange cannot be verified")
            return LintFixReceipt(
                fix.fix_id,
                fix.path,
                fix.precondition_sha256,
                fix.postcondition_sha256,
                "applied",
            )
        finally:
            os.close(parent_fd)
            os.close(zone_fd)

    def _read_run_file(self, run_id: str, name: str, maximum: int) -> bytes | None:
        relative = f"{run_id}/{name}.json"
        try:
            zone_fd, parent_fd, leaf, checked = self._open_parent(
                "agent/runs", relative, write=False
            )
        except LintFlowError:
            _fail("lint run artifact cannot be read safely")
        try:
            try:
                os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                return None
            raw = _read_at(parent_fd, leaf, maximum).data
            self._revalidate_parent_fd(
                "agent/runs", zone_fd, parent_fd, checked, write=False
            )
            return raw
        except OSError:
            _fail("lint run artifact cannot be read safely")
        finally:
            os.close(parent_fd)
            os.close(zone_fd)

    def _committed(self, run_id: str) -> Mapping[str, CommittedArtifact]:
        try:
            return {item.name: item for item in self._runs.snapshot(run_id).artifacts}
        except RunError as error:
            raise LintFlowError("lint run artifacts are invalid") from error

    def _require_step_trace(
        self,
        run_id: str,
        *,
        step_id: str,
        authority: str,
        input_hash: str,
        output_hash: str,
        action_ids: Sequence[str],
    ) -> None:
        try:
            events = tuple(
                event
                for event in self._runs.trace_events(run_id)
                if event["step_id"] == step_id
            )
        except RunError as error:
            raise LintFlowError("lint committed trace is invalid") from error
        if len(events) != 1:
            _fail("lint committed step lacks one exact trace event")
        event = events[0]
        actions = event.get("actions")
        expected_actions = tuple(action_ids)
        if (
            event["authority"] != authority
            or event["input_hash"] != input_hash
            or event["output_hash"] != output_hash
            or event["tool_outcomes"] != []
            or not isinstance(actions, list)
            or tuple(
                (
                    action.get("flow_id"),
                    action.get("action_id"),
                    action.get("actor"),
                    action.get("status"),
                )
                for action in actions
                if isinstance(action, Mapping)
            )
            != tuple(
                ("lint", action_id, "runtime", "succeeded")
                for action_id in expected_actions
            )
        ):
            _fail("lint committed step trace binding is invalid")

    @staticmethod
    def _scan_action_ids(request: LintRequest) -> tuple[str, ...]:
        return tuple(_ZONE_ACTIONS[zone][0] for zone in request.zones)

    def _pending_fix_payloads(self, request: LintRequest) -> tuple[_PendingFix, ...]:
        try:
            zone_fd = self._open_zone_fd("agent/runs", write=False)
            named_run = os.stat(request.run_id, dir_fd=zone_fd, follow_symlinks=False)
            run_fd = os.open(
                request.run_id,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=zone_fd,
            )
            opened_run = os.fstat(run_fd)
            if (
                not stat.S_ISDIR(named_run.st_mode)
                or _identity(opened_run)[:2] != _identity(named_run)[:2]
            ):
                _fail("lint run directory changed while opened")
        except (OSError, LintFlowError):
            if "run_fd" in locals():
                os.close(run_fd)
            if "zone_fd" in locals():
                os.close(zone_fd)
            _fail("lint run directory cannot be inspected safely")
        try:
            names = os.listdir(run_fd)
            if len(names) > self._limits.max_entries_per_directory:
                _fail("lint run directory exceeds its entry bound")
            committed = self._committed(request.run_id)
            result: list[_PendingFix] = []
            pending_count = 0
            for filename in sorted(names, key=lambda item: (item.casefold(), item)):
                if not filename.startswith(
                    "lint-fix-evidence-"
                ) or not filename.endswith(".json"):
                    continue
                name = filename[:-5]
                raw = _read_at(run_fd, filename, _MAX_JSON).data
                payload = _mapping(
                    _decode(raw, "pending lint fix evidence"),
                    "pending lint fix evidence",
                    frozenset(
                        {
                            "schema_version",
                            "flow",
                            "role",
                            "run_state_sha256",
                            "preimage_name",
                            "preimage_sha256",
                            "fix",
                        }
                    ),
                )
                if raw != _canonical(dict(payload)):
                    _fail("pending lint fix evidence must use canonical JSON")
                fix = _parse_fix(payload["fix"])
                preimage_name = payload["preimage_name"]
                if (
                    type(payload["schema_version"]) is not int
                    or payload["schema_version"] != 1
                    or payload["flow"] != "lint"
                    or payload["role"] != "lint-fix-evidence"
                    or fix is None
                    or name
                    != "lint-fix-evidence-"
                    + hashlib.sha256(fix.fix_id.encode()).hexdigest()[:24]
                    or preimage_name
                    != "lint-fix-preimage-"
                    + hashlib.sha256(fix.fix_id.encode()).hexdigest()[:24]
                    or fix.zone not in request.zones
                    or not request.apply_fixes
                ):
                    _fail("pending lint fix evidence is invalid")
                run_state_sha256 = _hash(
                    payload["run_state_sha256"], "pending fix run state"
                )
                preimage_sha256 = _hash(
                    payload["preimage_sha256"], "pending fix preimage hash"
                )
                try:
                    preimage = _read_at(
                        run_fd,
                        f"{preimage_name}.json",
                        self._limits.max_file_bytes,
                    ).data
                except LintFlowError:
                    _fail("pending lint fix lacks its exact preimage bytes")
                if (
                    hashlib.sha256(preimage).hexdigest() != preimage_sha256
                    or preimage_sha256 != fix.precondition_sha256
                ):
                    _fail("pending lint fix preimage binding is invalid")
                artifact = committed.get(name)
                preimage_artifact = committed.get(str(preimage_name))
                if (artifact is None) != (preimage_artifact is None):
                    _fail("pending lint fix has a partial committed source bundle")
                if artifact is None:
                    pending_count += 1
                result.append(
                    _PendingFix(fix, preimage, raw, run_state_sha256, artifact)
                )
            self._revalidate_parent_fd(
                "agent/runs",
                zone_fd,
                run_fd,
                f"{request.run_id}/state.json",
                write=False,
            )
            if pending_count > 1:
                _fail("lint run has multiple pending direct fixes")
            return tuple(sorted(result, key=lambda item: item.fix.fix_id))
        finally:
            os.close(run_fd)
            os.close(zone_fd)

    def _derive_pending_fix(
        self,
        request: LintRequest,
        pending: _PendingFix,
        scanned: _Scanned,
    ) -> bytes:
        fix = pending.fix
        if (
            not request.apply_fixes
            or fix.zone not in request.zones
            or fix.rule_id != "infra.text.normalization"
            or hashlib.sha256(pending.preimage).hexdigest() != fix.precondition_sha256
        ):
            _fail("pending lint fix is not request-bound")
        relative = fix.path[len(fix.zone) + 1 :]
        candidate, transforms = _normalization(pending.preimage)
        if (
            not self._fix_eligible(fix.zone, relative)
            or not transforms
            or transforms != fix.transforms
            or hashlib.sha256(candidate).hexdigest() != fix.postcondition_sha256
        ):
            _fail("pending lint fix cannot be re-derived exactly")
        markdown_paths = tuple(
            source.path
            for source in scanned.sources
            if PurePosixPath(source.path).suffix.casefold() == ".md"
        )
        try:
            text = candidate.decode("utf-8")
            snapshot = parse_note(
                NoteRef(OBSIDIAN_SCHEMA_VERSION, fix.zone, relative),
                text,
                path=fix.path,
            )
            validation = validate_note(snapshot, link_index=markdown_paths)
        except (UnicodeDecodeError, ObsidianError):
            _fail("pending lint fix preimage is not an allowlisted note")
        if not validation.valid:
            _fail("pending lint fix preimage is not an allowlisted note")
        payload = {
            "path": fix.path,
            "pre": hashlib.sha256(pending.preimage).hexdigest(),
            "post": hashlib.sha256(candidate).hexdigest(),
            "transforms": list(transforms),
        }
        derived = LintFix(
            "lint-fix-" + _digest(payload)[:32],
            "infra.text.normalization",
            fix.zone,
            fix.path,
            str(payload["pre"]),
            str(payload["post"]),
            transforms,
        )
        if derived != fix:
            _fail("pending lint fix differs from deterministic scan output")
        return candidate

    def _validate_committed_fix_source(
        self, request: LintRequest, pending: _PendingFix
    ) -> None:
        fix = pending.fix
        token = hashlib.sha256(fix.fix_id.encode()).hexdigest()
        evidence_name = "lint-fix-evidence-" + token[:24]
        preimage_name = "lint-fix-preimage-" + token[:24]
        step_id = "lint-fix-" + token[:32]
        committed = self._committed(request.run_id)
        evidence_artifact = committed.get(evidence_name)
        preimage_artifact = committed.get(preimage_name)
        if (
            pending.committed != evidence_artifact
            or evidence_artifact is None
            or preimage_artifact is None
            or evidence_artifact.step_id != step_id
            or preimage_artifact.step_id != step_id
            or evidence_artifact.zone != "agent/runs"
            or preimage_artifact.zone != "agent/runs"
            or evidence_artifact.relative != f"{request.run_id}/{evidence_name}.json"
            or preimage_artifact.relative != f"{request.run_id}/{preimage_name}.json"
            or evidence_artifact.state_ref != f"agent/runs/{evidence_artifact.relative}"
            or preimage_artifact.state_ref != f"agent/runs/{preimage_artifact.relative}"
            or evidence_artifact.sha256 != hashlib.sha256(pending.raw).hexdigest()
            or preimage_artifact.sha256 != hashlib.sha256(pending.preimage).hexdigest()
        ):
            _fail("committed lint fix lacks its exact source bundle")
        self._require_step_trace(
            request.run_id,
            step_id=step_id,
            authority="domain-write",
            input_hash=fix.precondition_sha256,
            output_hash=evidence_artifact.sha256,
            action_ids=(
                _ZONE_ACTIONS[fix.zone][0],
                _FIX_ACTIONS[fix.zone][0],
                "record-run-state",
            ),
        )

    def _recover_pending_fixes(
        self,
        request: LintRequest,
        capabilities: LintCapabilities,
        hooks: LintCrashHooks,
    ) -> tuple[tuple[LintFix, LintFixReceipt], ...]:
        recovered: list[tuple[LintFix, LintFixReceipt]] = []
        pending_fixes = self._pending_fix_payloads(request)
        if not pending_fixes:
            return ()
        self._scan_caps(request, capabilities)
        scanned = self._scan(request)
        state, run_hash = self._run_state(request)
        del state
        for pending in pending_fixes:
            if pending.committed is None:
                if pending.run_state_sha256 != run_hash:
                    _fail("pending lint fix has a stale run-state precondition")
            else:
                self._validate_committed_fix_source(request, pending)
            candidate = self._derive_pending_fix(request, pending, scanned)
            receipt = self._fix_step(
                request,
                pending.fix,
                pending.preimage,
                candidate,
                capabilities,
                hooks,
            )
            recovered.append((pending.fix, receipt))
        return tuple(recovered)

    def _fix_step(
        self,
        request: LintRequest,
        fix: LintFix,
        preimage: bytes,
        candidate: bytes,
        caps: LintCapabilities,
        hooks: LintCrashHooks,
    ) -> LintFixReceipt:
        scan_action = _ZONE_ACTIONS[fix.zone][0]
        apply_action = _FIX_ACTIONS[fix.zone][0]
        actions = (
            self._require(self._cap(caps, scan_action), scan_action),
            self._require(self._cap(caps, apply_action), apply_action),
            self._require(self._cap(caps, "record-run-state"), "record-run-state"),
        )
        artifact_name = (
            "lint-fix-evidence-" + hashlib.sha256(fix.fix_id.encode()).hexdigest()[:24]
        )
        preimage_name = (
            "lint-fix-preimage-" + hashlib.sha256(fix.fix_id.encode()).hexdigest()[:24]
        )
        if (
            not isinstance(preimage, bytes)
            or hashlib.sha256(preimage).hexdigest() != fix.precondition_sha256
            or _normalization(preimage)[0] != candidate
        ):
            _fail("lint fix bytes disagree with their exact preimage")
        committed = self._committed(request.run_id)
        if artifact_name in committed:
            if preimage_name not in committed:
                _fail("committed lint fix lost its exact preimage")
            receipt = self._apply_fix_bytes(fix, candidate)
            if receipt.status == "precondition-changed":
                _fail("committed lint fix no longer matches its exact target")
            self._cleanup_fix_slot(fix)
            return replace(receipt, status="already-applied")
        _, run_hash = self._run_state(request)
        payload = {
            "fix": _fix_payload(fix),
            "flow": "lint",
            "preimage_name": preimage_name,
            "preimage_sha256": fix.precondition_sha256,
            "role": "lint-fix-evidence",
            "run_state_sha256": run_hash,
            "schema_version": 1,
        }
        raw = _canonical(payload)
        try:
            prepared = self._runs.prepare_run_artifact(
                request.run_id, name=artifact_name, data=raw, maximum_bytes=_MAX_JSON
            )
            prepared_preimage = self._runs.prepare_run_artifact(
                request.run_id,
                name=preimage_name,
                data=preimage,
                maximum_bytes=self._limits.max_file_bytes,
            )
        except RunError as error:
            raise LintFlowError(str(error)) from None
        if hooks.after_fix_prepare is not None:
            hooks.after_fix_prepare()
        receipt = self._apply_fix_bytes(fix, candidate)
        if receipt.status == "precondition-changed":
            return receipt
        if hooks.after_fix_publish is not None:
            hooks.after_fix_publish()
        try:
            self._runs.commit_step(
                request.run_id,
                step_id="lint-fix-"
                + hashlib.sha256(fix.fix_id.encode()).hexdigest()[:32],
                authority="domain-write",
                input_hash=fix.precondition_sha256,
                output_hash=prepared.sha256,
                next_phase="lint-fix-committed",
                prepared_artifacts=(prepared, prepared_preimage),
                expected_state_sha256=run_hash,
                action_uses=tuple(ActionUse(item) for item in actions),
                authority_policy=self._policy,
            )
        except RunError as error:
            raise LintFlowError("lint fix run commit failed safely") from error
        if hooks.after_fix_commit is not None:
            hooks.after_fix_commit()
        self._cleanup_fix_slot(fix)
        return receipt

    def _infra_evidence_raw(
        self,
        request: LintRequest,
        operation_id: str,
        sources: tuple[LintSource, ...],
        findings: tuple[LintFinding, ...],
        receipts: tuple[LintFixReceipt, ...],
    ) -> bytes:
        if any(finding.mode != "infra" for finding in findings):
            _fail("lint infra evidence contains a semantic finding")
        request_hash = hashlib.sha256(render_lint_request(request)).hexdigest()
        source_payloads = [_source_payload(source) for source in sources]
        report = LintReport(
            schema_version=LINT_SCHEMA_VERSION,
            run_id=request.run_id,
            operation_id=operation_id,
            mode=request.mode,
            status="findings" if findings else "clean",
            request_sha256=request_hash,
            source_bundle_sha256=_digest(source_payloads),
            sources=sources,
            findings=findings,
            context_sha256=_digest([]),
            context_bytes=0,
            batch_ids=(),
        )
        report_payload = _report_payload(report)
        receipt_payloads = _receipt_payloads_for_findings(findings, receipts)
        return _canonical(
            {
                "flow": "lint",
                "receipts": list(receipt_payloads),
                "report": report_payload,
                "role": "lint-infra-evidence",
                "schema_version": 1,
            },
            4 * 1024 * 1024,
        )

    def _parse_infra_evidence(
        self,
        request: LintRequest,
        operation_id: str,
        raw: bytes,
    ) -> tuple[LintReport, tuple[LintFixReceipt, ...]]:
        payload = _mapping(
            _decode(raw, "lint infra evidence", 4 * 1024 * 1024),
            "lint infra evidence",
            frozenset({"schema_version", "flow", "role", "report", "receipts"}),
        )
        if (
            type(payload["schema_version"]) is not int
            or payload["schema_version"] != 1
            or payload["flow"] != "lint"
            or payload["role"] != "lint-infra-evidence"
            or not isinstance(payload["report"], Mapping)
            or not isinstance(payload["receipts"], list)
            or raw != _canonical(dict(payload), 4 * 1024 * 1024)
        ):
            _fail("lint infra evidence is invalid")
        report = parse_lint_report(_canonical(dict(payload["report"]), 4 * 1024 * 1024))
        receipts = tuple(_parse_receipt(item) for item in payload["receipts"])
        request_hash = hashlib.sha256(render_lint_request(request)).hexdigest()
        if (
            report.run_id != request.run_id
            or report.operation_id != operation_id
            or report.request_sha256 != request_hash
            or report.mode != request.mode
            or any(finding.mode != "infra" for finding in report.findings)
            or report.batch_ids
            or report.context_bytes != 0
            or report.context_sha256 != _digest([])
        ):
            _fail("lint infra evidence request binding is invalid")
        _receipt_payloads_for_findings(report.findings, receipts)
        return report, receipts

    def _commit_infra_evidence(
        self,
        request: LintRequest,
        operation_id: str,
        sources: tuple[LintSource, ...],
        findings: tuple[LintFinding, ...],
        receipts: tuple[LintFixReceipt, ...],
        capabilities: LintCapabilities,
    ) -> None:
        actions = self._scan_caps(request, capabilities) + (
            self._require(
                self._cap(capabilities, "record-run-state"), "record-run-state"
            ),
        )
        raw = self._infra_evidence_raw(
            request, operation_id, sources, findings, receipts
        )
        name = _lint_infra_evidence_artifact_name(operation_id)
        step_id = "lint-infra-" + hashlib.sha256(operation_id.encode()).hexdigest()[:32]
        committed = self._committed(request.run_id).get(name)
        if committed is not None:
            existing = self._read_run_file(request.run_id, name, 4 * 1024 * 1024)
            if (
                existing != raw
                or committed.step_id != step_id
                or committed.zone != "agent/runs"
                or committed.relative != f"{request.run_id}/{name}.json"
                or committed.state_ref != f"agent/runs/{committed.relative}"
                or committed.sha256 != hashlib.sha256(raw).hexdigest()
            ):
                _fail("committed lint infra evidence changed during replay")
            self._require_step_trace(
                request.run_id,
                step_id=step_id,
                authority="internal-write",
                input_hash=hashlib.sha256(render_lint_request(request)).hexdigest(),
                output_hash=committed.sha256,
                action_ids=(*self._scan_action_ids(request), "record-run-state"),
            )
            return
        _, run_hash = self._run_state(request)
        try:
            prepared = self._runs.prepare_run_artifact(
                request.run_id,
                name=name,
                data=raw,
                maximum_bytes=4 * 1024 * 1024,
            )
            self._runs.commit_step(
                request.run_id,
                step_id=step_id,
                authority="internal-write",
                input_hash=hashlib.sha256(render_lint_request(request)).hexdigest(),
                output_hash=prepared.sha256,
                next_phase="lint-infra-committed",
                prepared_artifacts=(prepared,),
                expected_state_sha256=run_hash,
                action_uses=tuple(ActionUse(action) for action in actions),
                authority_policy=self._policy,
            )
        except RunError as error:
            raise LintFlowError("lint infra evidence commit failed safely") from error

    def _spans(self, scanned: _Scanned) -> tuple[_Span, ...]:
        result: list[_Span] = []
        for source in scanned.sources:
            if PurePosixPath(source.path).suffix.casefold() != ".md":
                continue
            relative = source.path[len(source.zone) + 1 :]
            raw = scanned.content[(source.zone, relative)]
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError:
                continue
            lines = text.splitlines(keepends=True)
            blocks: list[tuple[int, int, str]] = []
            current: list[str] = []
            current_bytes = 0
            start = 1
            for number, line in enumerate(lines, start=1):
                encoded = line.encode("utf-8")
                if len(encoded) > self._limits.max_span_bytes:
                    if current:
                        blocks.append((start, number - 1, "".join(current)))
                        current = []
                        current_bytes = 0
                    chunk: list[str] = []
                    chunk_bytes = 0
                    for character in line:
                        raw_character = character.encode("utf-8")
                        if len(raw_character) > self._limits.max_span_bytes:
                            _fail("lint span bound cannot hold one UTF-8 character")
                        if (
                            chunk
                            and chunk_bytes + len(raw_character)
                            > self._limits.max_span_bytes
                        ):
                            blocks.append((number, number, "".join(chunk)))
                            chunk = []
                            chunk_bytes = 0
                        chunk.append(character)
                        chunk_bytes += len(raw_character)
                    if chunk:
                        blocks.append((number, number, "".join(chunk)))
                    start = number + 1
                    continue
                if (
                    current
                    and current_bytes + len(encoded) > self._limits.max_span_bytes
                ):
                    blocks.append((start, number - 1, "".join(current)))
                    current = []
                    current_bytes = 0
                    start = number
                current.append(line)
                current_bytes += len(encoded)
            if current or not lines:
                blocks.append((start, max(start, len(lines)), "".join(current)))
            for ordinal, (line_start, line_end, block) in enumerate(blocks):
                digest = hashlib.sha256(block.encode()).hexdigest()
                token = _digest(
                    {
                        "ordinal": ordinal,
                        "path": source.path,
                        "source": source.sha256,
                        "start": line_start,
                        "end": line_end,
                        "span": digest,
                    }
                )
                result.append(
                    _Span(
                        "lint-span-" + token[:32],
                        source.path,
                        source.sha256,
                        line_start,
                        line_end,
                        digest,
                        block,
                    )
                )
                if len(result) > self._limits.max_spans:
                    _fail("lint semantic spans exceed their hard bound")
        return tuple(result)

    @staticmethod
    def _span_payload(value: _Span) -> dict[str, object]:
        return {
            "line_end": value.line_end,
            "line_start": value.line_start,
            "path": value.path,
            "source_sha256": value.source_sha256,
            "span_id": value.span_id,
            "span_sha256": value.sha256,
            "text": value.text,
        }

    def _packet_raw(
        self, run_id: str, mode: str, batch_id: str, spans: Sequence[_Span]
    ) -> bytes:
        payload = {
            "acceptance_checks": [
                "only-supplied-anchors",
                "no-mutation-instructions",
                "complete-batch",
            ],
            "batch_id": batch_id,
            "flow": "lint",
            "mode": mode,
            "output_schema_version": 1,
            "run_id": run_id,
            "schema_version": 1,
            "spans": [self._span_payload(item) for item in spans],
        }
        return _canonical(payload, self._limits.max_packet_bytes)

    @staticmethod
    def _split_deep_span(value: _Span) -> tuple[_Span, _Span]:
        characters = tuple(value.text)
        if len(characters) < 2:
            _fail("lint deep source pair cannot fit its bounded packet")
        total = len(value.text.encode("utf-8"))
        consumed = 0
        split_at = 0
        for index, character in enumerate(characters[:-1], start=1):
            consumed += len(character.encode("utf-8"))
            split_at = index
            if consumed * 2 >= total:
                break
        left_text = "".join(characters[:split_at])
        right_text = "".join(characters[split_at:])
        if not left_text or not right_text:
            _fail("lint deep source pair cannot be split deterministically")

        def child(part: int, text: str) -> _Span:
            digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
            token = _digest(
                {
                    "parent": value.span_id,
                    "part": part,
                    "span": digest,
                }
            )
            return _Span(
                "lint-span-" + token[:32],
                value.path,
                value.source_sha256,
                value.line_start,
                value.line_end,
                digest,
                text,
            )

        return child(1, left_text), child(2, right_text)

    def _deep_pair_units(
        self, request: LintRequest, left: _Span, right: _Span
    ) -> Iterator[tuple[_Span, _Span]]:
        pair = (left, right)
        probe_id = (
            "lint-batch-"
            + _digest({"mode": request.mode, "spans": [item.span_id for item in pair]})[
                :32
            ]
        )
        try:
            self._packet_raw(request.run_id, request.mode, probe_id, pair)
        except LintFlowError:
            empty_digest = hashlib.sha256(b"").hexdigest()
            minimum_pair = (
                replace(left, text="", sha256=empty_digest),
                replace(right, text="", sha256=empty_digest),
            )
            try:
                self._packet_raw(request.run_id, request.mode, probe_id, minimum_pair)
            except LintFlowError:
                _fail("lint deep source pair metadata exceeds its bounded packet")
            left_bytes = len(left.text.encode("utf-8"))
            right_bytes = len(right.text.encode("utf-8"))
            if left_bytes >= right_bytes and len(left.text) > 1:
                first, second = self._split_deep_span(left)
                yield from self._deep_pair_units(request, first, right)
                yield from self._deep_pair_units(request, second, right)
                return
            if len(right.text) > 1:
                first, second = self._split_deep_span(right)
                yield from self._deep_pair_units(request, left, first)
                yield from self._deep_pair_units(request, left, second)
                return
            if len(left.text) > 1:
                first, second = self._split_deep_span(left)
                yield from self._deep_pair_units(request, first, right)
                yield from self._deep_pair_units(request, second, right)
                return
            _fail("lint deep source pair cannot fit its bounded packet")
        yield pair

    def _deep_groups(
        self, request: LintRequest, spans: tuple[_Span, ...]
    ) -> list[list[_Span]]:
        by_path: dict[str, list[_Span]] = {}
        for span in spans:
            by_path.setdefault(span.path, []).append(span)
        ordered = tuple(
            (path, by_path[path])
            for path in sorted(by_path, key=lambda item: (item.casefold(), item))
        )
        if len(ordered) < 2:
            groups: list[list[_Span]] = []
            for _path, items in ordered:
                current: list[_Span] = []
                for span in items:
                    trial = [*current, span]
                    probe_id = (
                        "lint-batch-"
                        + _digest(
                            {
                                "mode": request.mode,
                                "spans": [item.span_id for item in trial],
                            }
                        )[:32]
                    )
                    try:
                        self._packet_raw(request.run_id, request.mode, probe_id, trial)
                    except LintFlowError:
                        if not current:
                            raise
                        groups.append(current)
                        current = [span]
                    else:
                        current = trial
                if current:
                    groups.append(current)
            return groups

        groups: list[list[_Span]] = []
        expected_pairs: set[tuple[str, str]] = set()
        for left_index, (left_path, left_spans) in enumerate(ordered):
            for right_path, right_spans in ordered[left_index + 1 :]:
                expected_pairs.add((left_path, right_path))
                for left in left_spans:
                    for right in right_spans:
                        for unit in self._deep_pair_units(request, left, right):
                            groups.append(list(unit))
                            if len(groups) > self._limits.max_batches:
                                _fail("lint semantic batches exceed their hard bound")
        actual_pairs = {
            tuple(sorted({item.path for item in group}))
            for group in groups
            if len({item.path for item in group}) == 2
        }
        if actual_pairs != expected_pairs:
            _fail("lint deep schedule omits a cross-source pair")
        return groups

    def _packets(
        self, request: LintRequest, scanned: _Scanned
    ) -> tuple[tuple[str, bytes, tuple[_Span, ...]], ...]:
        spans = self._spans(scanned)
        groups: list[list[_Span]] = []
        if request.mode == "content":
            by_path: dict[str, list[_Span]] = {}
            for span in spans:
                by_path.setdefault(span.path, []).append(span)
            seeds = [
                items
                for _, items in sorted(
                    by_path.items(), key=lambda item: (item[0].casefold(), item[0])
                )
            ]
            for seed in seeds:
                current: list[_Span] = []
                for span in seed:
                    trial = [*current, span]
                    probe_id = (
                        "lint-batch-" + _digest([item.span_id for item in trial])[:32]
                    )
                    try:
                        self._packet_raw(request.run_id, request.mode, probe_id, trial)
                    except LintFlowError:
                        if not current:
                            raise
                        groups.append(current)
                        current = [span]
                    else:
                        current = trial
                if current:
                    groups.append(current)
        else:
            groups = self._deep_groups(request, spans)
        result = []
        total_context = 0
        for group in groups:
            batch_id = (
                "lint-batch-"
                + _digest(
                    {"mode": request.mode, "spans": [item.span_id for item in group]}
                )[:32]
            )
            packet_raw = self._packet_raw(request.run_id, request.mode, batch_id, group)
            total_context += len(packet_raw)
            if total_context > self._limits.max_context_bytes:
                _fail("lint semantic context exceeds its hard bound")
            result.append((batch_id, packet_raw, tuple(group)))
            if len(result) > self._limits.max_batches:
                _fail("lint semantic batches exceed their hard bound")
        return tuple(result)

    def _executor_findings(
        self,
        raw: bytes | str | Mapping[str, object],
        *,
        packet_raw: bytes,
        spans: Sequence[_Span],
        mode: str,
    ) -> tuple[LintFinding, ...]:
        if isinstance(raw, Mapping):
            encoded = _canonical(raw, self._limits.max_output_bytes)
        elif isinstance(raw, str):
            try:
                encoded = raw.encode("utf-8")
            except UnicodeError:
                _fail("lint executor output is not valid UTF-8")
        else:
            encoded = raw
        if (
            not isinstance(encoded, bytes)
            or not encoded
            or len(encoded) > self._limits.max_output_bytes
        ):
            _fail("lint executor output is invalid or too large")
        item = _mapping(
            _decode(encoded, "lint executor output", self._limits.max_output_bytes),
            "lint executor output",
            frozenset({"schema_version", "task_packet_sha256", "findings"}),
        )
        if encoded != _canonical(dict(item), self._limits.max_output_bytes):
            _fail("lint executor output must use canonical JSON")
        if (
            item["schema_version"] != 1
            or type(item["schema_version"]) is not int
            or item["task_packet_sha256"] != hashlib.sha256(packet_raw).hexdigest()
            or not isinstance(item["findings"], list)
        ):
            _fail("lint executor output binding is invalid")
        known = {span.span_id: span for span in spans}
        allowed = _CONTENT_RULES if mode == "content" else _DEEP_RULES
        findings: list[LintFinding] = []
        for row in item["findings"]:
            entry = _mapping(
                row, "executor finding", frozenset({"rule_id", "severity", "anchors"})
            )
            rule = _identifier(entry["rule_id"], "executor rule_id")
            if (
                rule not in allowed
                or entry["severity"] not in _SEVERITIES
                or not isinstance(entry["anchors"], list)
                or not entry["anchors"]
                or len(entry["anchors"]) > 16
            ):
                _fail("lint executor finding is outside its contract")
            anchors: list[LintEvidenceAnchor] = []
            ids: set[str] = set()
            for raw_anchor in entry["anchors"]:
                anchor_item = _mapping(
                    raw_anchor,
                    "executor anchor",
                    frozenset(
                        {
                            "span_id",
                            "path",
                            "source_sha256",
                            "span_sha256",
                            "line_start",
                            "line_end",
                        }
                    ),
                )
                span_id = _identifier(anchor_item["span_id"], "executor span_id")
                span = known.get(span_id)
                if span is None or span_id in ids:
                    _fail("lint executor cites an unknown or duplicate span")
                ids.add(span_id)
                if (
                    anchor_item["path"],
                    anchor_item["source_sha256"],
                    anchor_item["span_sha256"],
                    anchor_item["line_start"],
                    anchor_item["line_end"],
                ) != (
                    span.path,
                    span.source_sha256,
                    span.sha256,
                    span.line_start,
                    span.line_end,
                ):
                    _fail("lint executor anchor disagrees with supplied evidence")
                anchors.append(
                    LintEvidenceAnchor(
                        span.path,
                        span.source_sha256,
                        span.line_start,
                        span.line_end,
                        span.sha256,
                    )
                )
            if rule in _CROSS_SOURCE_RULES and len({item.path for item in anchors}) < 2:
                _fail("cross-source lint rule lacks two exact sources")
            findings.append(
                _finding(
                    mode=mode,
                    rule=rule,
                    severity=entry["severity"],
                    anchors=tuple(anchors),
                )
            )
        return self._validate_semantic_findings(
            findings,
            spans=spans,
            mode=mode,
        )

    def _validate_semantic_findings(
        self,
        findings: Sequence[LintFinding],
        *,
        spans: Sequence[_Span],
        mode: str,
    ) -> tuple[LintFinding, ...]:
        if mode not in {"content", "deep"}:
            _fail("lint semantic finding mode is invalid")
        allowed = _CONTENT_RULES if mode == "content" else _DEEP_RULES
        supplied = {
            (
                span.path,
                span.source_sha256,
                span.line_start,
                span.line_end,
                span.sha256,
            )
            for span in spans
        }
        checked: list[LintFinding] = []
        for finding in findings:
            _finding_payload(finding)
            if (
                finding.mode != mode
                or finding.rule_id not in allowed
                or finding.resolution != "review"
                or finding.fix is not None
            ):
                _fail("lint semantic finding is outside its packet contract")
            anchor_keys = {
                (
                    anchor.path,
                    anchor.source_sha256,
                    anchor.line_start,
                    anchor.line_end,
                    anchor.span_sha256,
                )
                for anchor in finding.anchors
            }
            if len(anchor_keys) != len(finding.anchors) or not anchor_keys <= supplied:
                _fail("lint semantic finding cites evidence outside its packet")
            if (
                finding.rule_id in _CROSS_SOURCE_RULES
                and len({anchor.path for anchor in finding.anchors}) < 2
            ):
                _fail("cross-source lint rule lacks two exact sources")
            checked.append(finding)
        finding_ids = [item.finding_id for item in checked]
        if len(finding_ids) != len(set(finding_ids)):
            _fail("lint executor output contains duplicate findings")
        if len(checked) > self._limits.max_findings:
            _fail("lint executor findings exceed their bound")
        return tuple(checked)

    def _parse_packet_evidence(
        self, request: LintRequest, raw: bytes
    ) -> tuple[str, tuple[_Span, ...]]:
        item = _mapping(
            _decode(raw, "lint packet evidence", self._limits.max_packet_bytes),
            "lint packet evidence",
            frozenset(
                {
                    "schema_version",
                    "flow",
                    "run_id",
                    "mode",
                    "batch_id",
                    "output_schema_version",
                    "acceptance_checks",
                    "spans",
                }
            ),
        )
        if (
            type(item["schema_version"]) is not int
            or item["schema_version"] != 1
            or item["flow"] != "lint"
            or item["run_id"] != request.run_id
            or item["mode"] != request.mode
            or type(item["output_schema_version"]) is not int
            or item["output_schema_version"] != 1
            or item["acceptance_checks"]
            != [
                "only-supplied-anchors",
                "no-mutation-instructions",
                "complete-batch",
            ]
            or not isinstance(item["spans"], list)
            or not item["spans"]
        ):
            _fail("lint packet replay evidence is invalid")
        batch_id = _identifier(item["batch_id"], "packet batch_id")
        spans: list[_Span] = []
        span_ids: set[str] = set()
        for raw_span in item["spans"]:
            span_item = _mapping(
                raw_span,
                "lint packet span",
                frozenset(
                    {
                        "span_id",
                        "path",
                        "source_sha256",
                        "line_start",
                        "line_end",
                        "span_sha256",
                        "text",
                    }
                ),
            )
            span_id = _identifier(span_item["span_id"], "packet span_id")
            path = _safe_relative(span_item["path"], "packet span path")
            source_sha256 = _hash(
                span_item["source_sha256"], "packet span source sha256"
            )
            line_start = _exact_int(
                span_item["line_start"], "packet span line_start", 1, 2**31 - 1
            )
            line_end = _exact_int(
                span_item["line_end"],
                "packet span line_end",
                line_start,
                2**31 - 1,
            )
            span_sha256 = _hash(span_item["span_sha256"], "packet span sha256")
            text = span_item["text"]
            if not isinstance(text, str):
                _fail("lint packet span text is invalid")
            try:
                text_raw = text.encode("utf-8")
            except UnicodeError:
                _fail("lint packet span text is not valid UTF-8")
            if (
                len(text_raw) > self._limits.max_span_bytes
                or hashlib.sha256(text_raw).hexdigest() != span_sha256
                or not any(path.startswith(zone + "/") for zone in request.zones)
                or not span_id.startswith("lint-span-")
                or span_id in span_ids
            ):
                _fail("lint packet span binding is invalid")
            span_ids.add(span_id)
            spans.append(
                _Span(
                    span_id,
                    path,
                    source_sha256,
                    line_start,
                    line_end,
                    span_sha256,
                    text,
                )
            )
        expected_batch_id = (
            "lint-batch-"
            + _digest(
                {
                    "mode": request.mode,
                    "spans": [span.span_id for span in spans],
                }
            )[:32]
        )
        checked_spans = tuple(spans)
        if (
            batch_id != expected_batch_id
            or self._packet_raw(request.run_id, request.mode, batch_id, checked_spans)
            != raw
        ):
            _fail("lint packet replay binding is invalid")
        return batch_id, checked_spans

    def _parse_batch_evidence(
        self,
        request: LintRequest,
        batch_id: str,
        packet_raw: bytes,
        spans: Sequence[_Span],
        raw: bytes,
    ) -> tuple[tuple[LintFinding, ...], str]:
        payload = _mapping(
            _decode(raw, "lint batch evidence", _MAX_BATCH_EVIDENCE),
            "lint batch evidence",
            frozenset(
                {
                    "schema_version",
                    "flow",
                    "role",
                    "batch_id",
                    "packet_sha256",
                    "run_state_sha256",
                    "findings",
                }
            ),
        )
        if raw != _canonical(dict(payload), _MAX_BATCH_EVIDENCE):
            _fail("lint batch replay evidence must use canonical JSON")
        if (
            type(payload["schema_version"]) is not int
            or payload["schema_version"] != 1
            or payload["flow"] != "lint"
            or payload["role"] != "lint-batch-evidence"
            or payload["batch_id"] != batch_id
            or payload["packet_sha256"] != hashlib.sha256(packet_raw).hexdigest()
            or not isinstance(payload["findings"], list)
        ):
            _fail("lint batch replay evidence is invalid")
        findings = self._validate_semantic_findings(
            tuple(_parse_finding(entry) for entry in payload["findings"]),
            spans=spans,
            mode=request.mode,
        )
        return findings, _hash(payload["run_state_sha256"], "batch run state hash")

    def _batch_step(
        self,
        request: LintRequest,
        batch_id: str,
        packet_raw: bytes,
        spans: tuple[_Span, ...],
        caps: LintCapabilities,
        hooks: LintCrashHooks,
    ) -> tuple[LintFinding, ...]:
        used_zones = tuple(
            zone
            for zone in request.zones
            if any(span.path.startswith(zone + "/") for span in spans)
        )
        actions = tuple(
            self._require(
                self._cap(caps, _ZONE_ACTIONS[zone][0]), _ZONE_ACTIONS[zone][0]
            )
            for zone in used_zones
        ) + (self._require(self._cap(caps, "record-run-state"), "record-run-state"),)
        token = hashlib.sha256(batch_id.encode()).hexdigest()[:24]
        packet_name = "lint-packet-" + token
        output_name = "lint-batch-evidence-" + token
        existing_output = self._read_run_file(
            request.run_id, output_name, _MAX_BATCH_EVIDENCE
        )
        if existing_output is not None:
            findings, run_hash = self._parse_batch_evidence(
                request,
                batch_id,
                packet_raw,
                spans,
                existing_output,
            )
            committed = self._committed(request.run_id)
            if output_name in committed:
                packet_artifact = committed.get(packet_name)
                output_artifact = committed[output_name]
                step_id = (
                    "lint-batch-" + hashlib.sha256(batch_id.encode()).hexdigest()[:32]
                )
                if (
                    packet_artifact is None
                    or packet_artifact.step_id != step_id
                    or output_artifact.step_id != step_id
                    or packet_artifact.zone != "agent/runs"
                    or output_artifact.zone != "agent/runs"
                    or packet_artifact.relative
                    != f"{request.run_id}/{packet_name}.json"
                    or output_artifact.relative
                    != f"{request.run_id}/{output_name}.json"
                    or packet_artifact.state_ref
                    != f"agent/runs/{packet_artifact.relative}"
                    or output_artifact.state_ref
                    != f"agent/runs/{output_artifact.relative}"
                    or packet_artifact.sha256 != hashlib.sha256(packet_raw).hexdigest()
                    or output_artifact.sha256
                    != hashlib.sha256(existing_output).hexdigest()
                ):
                    _fail("committed lint batch source bundle is invalid")
                self._require_step_trace(
                    request.run_id,
                    step_id=step_id,
                    authority="internal-write",
                    input_hash=hashlib.sha256(packet_raw).hexdigest(),
                    output_hash=output_artifact.sha256,
                    action_ids=(
                        *(_ZONE_ACTIONS[zone][0] for zone in used_zones),
                        "record-run-state",
                    ),
                )
                return findings
        else:
            _, run_hash = self._run_state(request)
            if self._executor is None:
                _fail("semantic lint mode requires an explicit executor")
            try:
                packet_artifact = self._runs.prepare_run_artifact(
                    request.run_id,
                    name=packet_name,
                    data=packet_raw,
                    maximum_bytes=self._limits.max_packet_bytes,
                )
            except RunError as error:
                raise LintFlowError(str(error)) from None
            if hooks.after_packet_prepare is not None:
                hooks.after_packet_prepare()
            try:
                output = self._executor.execute(packet_raw)
            except Exception:
                raise LintFlowError("lint executor failed") from None
            findings = self._executor_findings(
                output, packet_raw=packet_raw, spans=spans, mode=request.mode
            )
            payload = {
                "batch_id": batch_id,
                "findings": [_finding_payload(item) for item in findings],
                "flow": "lint",
                "packet_sha256": packet_artifact.sha256,
                "role": "lint-batch-evidence",
                "run_state_sha256": run_hash,
                "schema_version": 1,
            }
            existing_output = _canonical(payload, _MAX_BATCH_EVIDENCE)
        try:
            packet_artifact = self._runs.prepare_run_artifact(
                request.run_id,
                name=packet_name,
                data=packet_raw,
                maximum_bytes=self._limits.max_packet_bytes,
            )
            output_artifact = self._runs.prepare_run_artifact(
                request.run_id,
                name=output_name,
                data=existing_output,
                maximum_bytes=_MAX_BATCH_EVIDENCE,
            )
        except RunError as error:
            raise LintFlowError(str(error)) from None
        try:
            self._runs.commit_step(
                request.run_id,
                step_id="lint-batch-"
                + hashlib.sha256(batch_id.encode()).hexdigest()[:32],
                authority="internal-write",
                input_hash=hashlib.sha256(packet_raw).hexdigest(),
                output_hash=output_artifact.sha256,
                next_phase="lint-batch-committed",
                prepared_artifacts=(packet_artifact, output_artifact),
                expected_state_sha256=run_hash,
                action_uses=tuple(ActionUse(item) for item in actions),
                authority_policy=self._policy,
            )
        except RunError as error:
            raise LintFlowError("lint batch run commit failed safely") from error
        return findings

    def _publish_review(self, value: LintReviewRecord) -> str:
        raw = render_lint_review(value)
        name = f"{value.proposal_id}.lint.json"
        try:
            root_fd = self._open_zone_fd("review", write=True)
        except LintFlowError:
            _fail("lint review zone cannot be opened safely")
        try:
            opened_root = os.fstat(root_fd)
            if not stat.S_ISDIR(opened_root.st_mode):
                _fail("lint review zone changed while opened")
            existing = self._optional_at(root_fd, name, maximum=_MAX_JSON)
            if existing is None:
                temp = (
                    f"{_RUNTIME_PREFIX}{hashlib.sha256(raw).hexdigest()[:24]}.publish"
                )
                staged = self._optional_at(root_fd, temp, maximum=_MAX_JSON)
                if staged is None:
                    _write_once_at(root_fd, temp, raw)
                    staged = _read_at(root_fd, temp, _MAX_JSON)
                if staged.digest != hashlib.sha256(raw).hexdigest():
                    _fail("lint review stage contains foreign bytes")
                self._revalidate_zone_fd("review", root_fd, write=True)
                try:
                    os.link(
                        temp,
                        name,
                        src_dir_fd=root_fd,
                        dst_dir_fd=root_fd,
                        follow_symlinks=False,
                    )
                    os.fsync(root_fd)
                except FileExistsError:
                    pass
                except OSError:
                    _fail("lint review cannot be published atomically")
                existing = _read_at(root_fd, name, _MAX_JSON)
                if existing.data != raw:
                    _fail("lint review publication contains foreign bytes")
                self._remove_slot(root_fd, temp, staged.digest, maximum=_MAX_JSON)
            current = parse_lint_review(existing.data)
            if current.status != "proposed":
                proposed = replace(current, status="proposed", human_decision=None)
                if render_lint_review(proposed) != raw:
                    _fail("lint review replay conflicts with durable proposal")
            elif existing.data != raw:
                _fail("lint review replay conflicts with durable proposal")
            self._revalidate_zone_fd("review", root_fd, write=True)
            return f"review/{name}"
        finally:
            os.close(root_fd)

    def _read_review(self, relative: str) -> tuple[LintReviewRecord, bytes]:
        checked = _safe_relative(relative, "lint proposal relative path")
        if len(PurePosixPath(checked).parts) != 1:
            _fail("lint proposal must be a direct review child")
        try:
            root_fd = self._open_zone_fd("review", write=False)
        except LintFlowError:
            _fail("lint review zone cannot be opened safely")
        try:
            raw = _read_at(root_fd, checked, _MAX_JSON).data
            self._revalidate_zone_fd("review", root_fd, write=False)
            return parse_lint_review(raw), raw
        finally:
            os.close(root_fd)

    @staticmethod
    def _canonical_finding_union(
        infra: Sequence[LintFinding], semantic: Sequence[LintFinding]
    ) -> tuple[LintFinding, ...]:
        by_id: dict[str, LintFinding] = {}
        for finding in (*infra, *semantic):
            _finding_payload(finding)
            previous = by_id.get(finding.finding_id)
            if previous is not None and previous != finding:
                _fail("lint finding id collision changes canonical content")
            by_id[finding.finding_id] = finding
        return tuple(
            sorted(
                by_id.values(),
                key=lambda item: (
                    item.anchors[0].path.casefold(),
                    item.anchors[0].path,
                    item.rule_id,
                    item.finding_id,
                ),
            )
        )

    def _validate_recovered_infra_evidence(
        self, request: LintRequest, evidence: LintRunEvidence
    ) -> tuple[LintFinding, ...]:
        name = _lint_infra_evidence_artifact_name(evidence.operation_id)
        committed = self._committed(request.run_id)
        infra_names = {
            artifact_name
            for artifact_name in committed
            if artifact_name.startswith("lint-infra-evidence-")
        }
        artifact = committed.get(name)
        raw = self._read_run_file(request.run_id, name, 4 * 1024 * 1024)
        expected_step = (
            "lint-infra-"
            + hashlib.sha256(evidence.operation_id.encode()).hexdigest()[:32]
        )
        if (
            infra_names != {name}
            or artifact is None
            or raw is None
            or artifact.step_id != expected_step
            or artifact.relative != f"{request.run_id}/{name}.json"
            or artifact.state_ref != f"agent/runs/{artifact.relative}"
            or artifact.sha256 != hashlib.sha256(raw).hexdigest()
        ):
            _fail("prepared lint report lacks exact committed infra evidence")
        self._require_step_trace(
            request.run_id,
            step_id=expected_step,
            authority="internal-write",
            input_hash=hashlib.sha256(render_lint_request(request)).hexdigest(),
            output_hash=artifact.sha256,
            action_ids=(*self._scan_action_ids(request), "record-run-state"),
        )
        infra_report, receipts = self._parse_infra_evidence(
            request, evidence.operation_id, raw
        )
        report_infra_findings = tuple(
            finding for finding in evidence.report.findings if finding.mode == "infra"
        )
        if (
            evidence.report.sources != infra_report.sources
            or report_infra_findings != infra_report.findings
            or evidence.receipts != receipts
        ):
            _fail("prepared lint report disagrees with committed infra evidence")
        return infra_report.findings

    def _validate_recovered_semantic_context(
        self, request: LintRequest, evidence: LintRunEvidence
    ) -> tuple[LintFinding, ...]:
        if request.mode == "infra":
            return ()
        committed = self._committed(request.run_id)
        packets = {
            name.removeprefix("lint-packet-"): artifact
            for name, artifact in committed.items()
            if name.startswith("lint-packet-")
        }
        batches = {
            name.removeprefix("lint-batch-evidence-"): artifact
            for name, artifact in committed.items()
            if name.startswith("lint-batch-evidence-")
        }
        if set(packets) != set(batches):
            _fail("prepared lint context lacks an exact committed batch pair")
        source_bindings = {
            (source.path, source.sha256) for source in evidence.report.sources
        }
        recovered: dict[str, tuple[bytes, tuple[LintFinding, ...], str]] = {}
        step_to_batch: dict[str, str] = {}
        for token in sorted(packets):
            packet_artifact = packets[token]
            batch_artifact = batches[token]
            packet_raw = self._read_run_file(
                request.run_id, packet_artifact.name, self._limits.max_packet_bytes
            )
            batch_raw = self._read_run_file(
                request.run_id, batch_artifact.name, _MAX_BATCH_EVIDENCE
            )
            if packet_raw is None or batch_raw is None:
                _fail("committed lint context evidence is missing")
            batch_id, spans = self._parse_packet_evidence(request, packet_raw)
            expected_token = hashlib.sha256(batch_id.encode()).hexdigest()[:24]
            expected_step = (
                "lint-batch-" + hashlib.sha256(batch_id.encode()).hexdigest()[:32]
            )
            expected_packet_name = "lint-packet-" + expected_token
            expected_batch_name = "lint-batch-evidence-" + expected_token
            if (
                token != expected_token
                or packet_artifact.name != expected_packet_name
                or batch_artifact.name != expected_batch_name
                or packet_artifact.step_id != expected_step
                or batch_artifact.step_id != expected_step
                or packet_artifact.relative
                != f"{request.run_id}/{expected_packet_name}.json"
                or batch_artifact.relative
                != f"{request.run_id}/{expected_batch_name}.json"
                or packet_artifact.state_ref != f"agent/runs/{packet_artifact.relative}"
                or batch_artifact.state_ref != f"agent/runs/{batch_artifact.relative}"
                or packet_artifact.sha256 != hashlib.sha256(packet_raw).hexdigest()
                or batch_artifact.sha256 != hashlib.sha256(batch_raw).hexdigest()
                or any(
                    (span.path, span.source_sha256) not in source_bindings
                    for span in spans
                )
                or batch_id in recovered
                or expected_step in step_to_batch
            ):
                _fail("prepared lint context artifact binding is invalid")
            findings, _run_hash = self._parse_batch_evidence(
                request, batch_id, packet_raw, spans, batch_raw
            )
            used_zones = tuple(
                zone
                for zone in request.zones
                if any(span.path.startswith(zone + "/") for span in spans)
            )
            self._require_step_trace(
                request.run_id,
                step_id=expected_step,
                authority="internal-write",
                input_hash=hashlib.sha256(packet_raw).hexdigest(),
                output_hash=batch_artifact.sha256,
                action_ids=(
                    *(_ZONE_ACTIONS[zone][0] for zone in used_zones),
                    "record-run-state",
                ),
            )
            recovered[batch_id] = (packet_raw, findings, expected_step)
            step_to_batch[expected_step] = batch_id
        ordered_batches = tuple(
            step_to_batch[step_id]
            for event in self._runs.trace_events(request.run_id)
            if (step_id := str(event["step_id"])) in step_to_batch
        )
        if (
            len(ordered_batches) != len(recovered)
            or len(ordered_batches) != len(set(ordered_batches))
            or evidence.report.batch_ids != ordered_batches
        ):
            _fail("prepared lint context batch order is invalid")
        packet_hashes = [
            hashlib.sha256(recovered[batch_id][0]).hexdigest()
            for batch_id in ordered_batches
        ]
        if evidence.report.context_bytes != sum(
            len(recovered[batch_id][0]) for batch_id in ordered_batches
        ) or evidence.report.context_sha256 != _digest(packet_hashes):
            _fail("prepared lint context hash or byte count is invalid")
        findings_by_id: dict[str, LintFinding] = {}
        for batch_id in ordered_batches:
            for finding in recovered[batch_id][1]:
                previous = findings_by_id.get(finding.finding_id)
                if previous is not None and previous != finding:
                    _fail("recovered lint batch finding id changes canonical content")
                findings_by_id[finding.finding_id] = finding
        recovered_findings = tuple(
            sorted(
                findings_by_id.values(),
                key=lambda item: (
                    item.anchors[0].path.casefold(),
                    item.anchors[0].path,
                    item.rule_id,
                    item.finding_id,
                ),
            )
        )
        report_findings = tuple(
            finding for finding in evidence.report.findings if finding.mode != "infra"
        )
        if report_findings != recovered_findings:
            _fail("prepared lint findings disagree with committed batch evidence")
        return recovered_findings

    @staticmethod
    def _validate_final_request_binding(
        request: LintRequest,
        operation_id: str,
        evidence: LintRunEvidence,
    ) -> None:
        request_hash = hashlib.sha256(render_lint_request(request)).hexdigest()
        report = evidence.report
        finding_modes = {item.mode for item in report.findings}
        has_direct_fix = any(item.fix is not None for item in report.findings)
        if (
            evidence.operation_id != operation_id
            or evidence.request_sha256 != request_hash
            or report.run_id != request.run_id
            or report.operation_id != operation_id
            or report.request_sha256 != request_hash
            or report.mode != request.mode
            or not finding_modes
            <= ({"infra"} if request.mode == "infra" else {"infra", request.mode})
            or (not request.apply_fixes and (bool(evidence.receipts) or has_direct_fix))
            or (
                request.mode == "infra"
                and (
                    bool(report.batch_ids)
                    or report.context_bytes != 0
                    or report.context_sha256 != _digest([])
                )
            )
        ):
            _fail("prepared lint evidence conflicts with this request")

    def _validate_committed_fix_lineage(
        self, request: LintRequest, evidence: LintRunEvidence
    ) -> None:
        pending = self._pending_fix_payloads(request)
        committed = {
            item.fix.fix_id: item for item in pending if item.committed is not None
        }
        expected = {
            receipt.fix_id
            for receipt in evidence.receipts
            if receipt.status in {"applied", "already-applied"}
        }
        if set(committed) != expected:
            _fail("lint final lacks its exact committed fix lineage")
        for item in committed.values():
            self._validate_committed_fix_source(request, item)

    def _existing(self, request: LintRequest, operation_id: str) -> LintResult | None:
        name = lint_evidence_artifact_name(operation_id)
        committed = self._committed(request.run_id)
        if name not in committed:
            return None
        try:
            producer = self._runs.producer_snapshot(
                request.run_id, producer_evidence=name
            )
        except RunError as error:
            raise LintFlowError(
                "committed lint final is not the latest exact producer"
            ) from error
        if len(producer.artifacts) != 1 or producer.artifacts[0].name != name:
            _fail("committed lint final producer bundle is not exact")
        artifact = producer.artifacts[0]
        raw = self._read_run_file(request.run_id, name, 4 * 1024 * 1024)
        if raw is None:
            _fail("committed lint evidence is missing")
        evidence = inspect_lint_run_evidence(artifact, raw)
        self._validate_final_request_binding(request, operation_id, evidence)
        infra_findings = self._validate_recovered_infra_evidence(request, evidence)
        semantic_findings = self._validate_recovered_semantic_context(request, evidence)
        if evidence.report.findings != self._canonical_finding_union(
            infra_findings, semantic_findings
        ):
            _fail("committed lint final is not the exact canonical finding union")
        self._validate_committed_fix_lineage(request, evidence)
        has_proposal = evidence.proposal_ref is not None
        self._require_step_trace(
            request.run_id,
            step_id="lint-final-"
            + hashlib.sha256(operation_id.encode()).hexdigest()[:32],
            authority="proposal" if has_proposal else "internal-write",
            input_hash=evidence.request_sha256,
            output_hash=artifact.sha256,
            action_ids=(
                *self._scan_action_ids(request),
                *(("commit-semantic-lint-findings",) if has_proposal else ()),
                "record-run-state",
            ),
        )
        proposal = None
        if evidence.proposal_ref is not None:
            relative = evidence.proposal_ref.removeprefix("review/")
            try:
                proposal, _proposal_raw = self._read_review(relative)
            except LintFlowError:
                _fail("lint proposal cannot be replayed safely")
            proposed_view = replace(proposal, status="proposed", human_decision=None)
            if (
                hashlib.sha256(render_lint_review(proposed_view)).hexdigest()
                != evidence.proposal_sha256
                or proposal.run_id != request.run_id
                or proposal.operation_id != operation_id
                or proposal.report_sha256
                != hashlib.sha256(render_lint_report(evidence.report)).hexdigest()
                or proposal.finding_ids
                != tuple(
                    item.finding_id
                    for item in evidence.report.findings
                    if item.resolution == "review"
                )
            ):
                _fail("lint proposal replay binding is invalid")
        return LintResult(evidence.report, evidence.receipts, proposal, artifact, True)

    def _proposal_for_report(
        self, report: LintReport, *, created_at: str
    ) -> LintReviewRecord | None:
        finding_ids = tuple(
            item.finding_id for item in report.findings if item.resolution == "review"
        )
        if not finding_ids:
            return None
        report_raw = render_lint_report(report)
        proposal_id = (
            "lintprop-"
            + _digest(
                {
                    "report": hashlib.sha256(report_raw).hexdigest(),
                    "findings": list(finding_ids),
                }
            )[:32]
        )
        report_ref = (
            f"agent/runs/{report.run_id}/"
            f"{lint_evidence_artifact_name(report.operation_id)}.json"
        )
        return LintReviewRecord(
            schema_version=LINT_SCHEMA_VERSION,
            proposal_id=proposal_id,
            status="proposed",
            run_id=report.run_id,
            operation_id=report.operation_id,
            mode=report.mode,
            report_ref=report_ref,
            report_sha256=hashlib.sha256(report_raw).hexdigest(),
            finding_ids=finding_ids,
            created_at=_timestamp(created_at, "run created_at"),
        )

    def _final_actions(
        self,
        request: LintRequest,
        capabilities: LintCapabilities,
        *,
        has_proposal: bool,
    ) -> tuple[ActionCapability, ...]:
        actions = self._scan_caps(request, capabilities)
        if has_proposal:
            actions += (
                self._require(
                    self._cap(capabilities, "commit-semantic-lint-findings"),
                    "commit-semantic-lint-findings",
                ),
            )
        return actions + (
            self._require(
                self._cap(capabilities, "record-run-state"), "record-run-state"
            ),
        )

    def _recover_final(
        self,
        request: LintRequest,
        operation_id: str,
        capabilities: LintCapabilities,
    ) -> LintResult | None:
        name = lint_evidence_artifact_name(operation_id)
        raw = self._read_run_file(request.run_id, name, 4 * 1024 * 1024)
        if raw is None:
            return None
        evidence = parse_lint_run_evidence(raw)
        self._validate_final_request_binding(request, operation_id, evidence)
        state, run_hash = self._run_state(request)
        if run_hash != evidence.run_state_sha256:
            _fail("prepared lint evidence has a stale run precondition")
        infra_findings = self._validate_recovered_infra_evidence(request, evidence)
        semantic_findings = self._validate_recovered_semantic_context(request, evidence)
        if evidence.report.findings != self._canonical_finding_union(
            infra_findings, semantic_findings
        ):
            _fail("prepared lint report is not the exact canonical finding union")
        self._validate_committed_fix_lineage(request, evidence)
        proposal = self._proposal_for_report(
            evidence.report, created_at=str(state["created_at"])
        )
        if proposal is None:
            if evidence.proposal_ref is not None:
                _fail("prepared lint evidence has an unexpected proposal")
        else:
            proposal_raw = render_lint_review(proposal)
            expected_ref = f"review/{proposal.proposal_id}.lint.json"
            if (
                evidence.proposal_ref != expected_ref
                or evidence.proposal_sha256 != hashlib.sha256(proposal_raw).hexdigest()
            ):
                _fail("prepared lint proposal binding is invalid")
        actions = self._final_actions(
            request, capabilities, has_proposal=proposal is not None
        )
        try:
            prepared = self._runs.prepare_run_artifact(
                request.run_id,
                name=name,
                data=raw,
                maximum_bytes=4 * 1024 * 1024,
            )
        except RunError as error:
            raise LintFlowError(str(error)) from None
        if proposal is not None:
            self._publish_review(proposal)
            proposal, published_raw = self._read_review(
                f"{proposal.proposal_id}.lint.json"
            )
            proposed_view = replace(proposal, status="proposed", human_decision=None)
            if (
                hashlib.sha256(render_lint_review(proposed_view)).hexdigest()
                != hashlib.sha256(proposal_raw).hexdigest()
            ):
                _fail("prepared lint proposal publication is invalid")
            if (
                hashlib.sha256(published_raw).hexdigest() != evidence.proposal_sha256
                and proposal.status == "proposed"
            ):
                _fail("prepared lint proposal bytes changed")
        try:
            self._runs.commit_step(
                request.run_id,
                step_id="lint-final-"
                + hashlib.sha256(operation_id.encode()).hexdigest()[:32],
                authority="proposal" if proposal is not None else "internal-write",
                input_hash=evidence.request_sha256,
                output_hash=prepared.sha256,
                next_phase="lint-report-committed",
                prepared_artifacts=(prepared,),
                expected_state_sha256=run_hash,
                action_uses=tuple(ActionUse(item) for item in actions),
                authority_policy=self._policy,
            )
        except RunError as error:
            raise LintFlowError("lint final recovery failed safely") from error
        return LintResult(
            evidence.report,
            evidence.receipts,
            proposal,
            prepared,
            True,
        )

    def execute(
        self,
        request: LintRequest,
        *,
        capabilities: LintCapabilities,
        crash_hooks: LintCrashHooks | None = None,
    ) -> LintResult:
        request_raw = render_lint_request(request)
        request = parse_lint_request(request_raw)
        hooks = crash_hooks or LintCrashHooks()
        if not isinstance(hooks, LintCrashHooks):
            _fail("lint crash hooks are invalid")
        if any(
            hook is not None and not callable(hook)
            for hook in (
                hooks.after_scan,
                hooks.after_fix_prepare,
                hooks.after_fix_publish,
                hooks.after_fix_commit,
                hooks.after_packet_prepare,
                hooks.after_proposal_publish,
                hooks.before_run_commit,
            )
        ):
            _fail("lint crash hooks must be callable")
        if request.mode != "infra" and self._executor is None:
            _fail("semantic lint mode requires an explicit executor")
        request_hash = hashlib.sha256(request_raw).hexdigest()
        operation_id = _operation(request_hash)
        existing = self._existing(request, operation_id)
        if existing is not None:
            return existing
        self._run_state(request)
        self._scan_caps(request, capabilities)
        recovered_fixes = self._recover_pending_fixes(request, capabilities, hooks)
        recovered = self._recover_final(request, operation_id, capabilities)
        if recovered is not None:
            return recovered
        scanned = self._scan(request)
        if hooks.after_scan is not None:
            hooks.after_scan()
        conflicted_paths = {
            fix.path
            for fix, receipt in recovered_fixes
            if receipt.status == "precondition-changed"
        }
        if conflicted_paths:
            blocked_fix_ids = {
                fix.fix_id for fix in scanned.fixes if fix.path in conflicted_paths
            }
            scanned = _Scanned(
                scanned.sources,
                scanned.content,
                tuple(
                    _reclassify_finding(item, fix=None, resolution="review")
                    if item.fix is not None and item.fix.fix_id in blocked_fix_ids
                    else item
                    for item in scanned.findings
                ),
                tuple(
                    fix for fix in scanned.fixes if fix.fix_id not in blocked_fix_ids
                ),
            )
        receipts = [item[1] for item in recovered_fixes]
        for fix in scanned.fixes:
            relative = fix.path[len(fix.zone) + 1 :]
            candidate, transforms = _normalization(
                scanned.content[(fix.zone, relative)]
            )
            if (
                transforms != fix.transforms
                or hashlib.sha256(candidate).hexdigest() != fix.postcondition_sha256
            ):
                _fail("lint fix candidate changed after scan")
            receipts.append(
                self._fix_step(
                    request,
                    fix,
                    scanned.content[(fix.zone, relative)],
                    candidate,
                    capabilities,
                    hooks,
                )
            )
        final_scan = self._scan(request) if receipts else scanned
        receipt_by_fix = {item.fix_id: item for item in receipts}
        attempted_findings: list[LintFinding] = []
        normalization_rules = (
            ("strip-utf8-bom", "infra.utf8-bom"),
            ("crlf-to-lf", "infra.crlf"),
            ("append-final-newline", "infra.final-newline"),
        )
        for fix, receipt in recovered_fixes:
            anchor = LintEvidenceAnchor(fix.path, fix.precondition_sha256)
            for transform, rule in normalization_rules:
                if transform in fix.transforms:
                    attempted_findings.append(
                        _finding(
                            mode="infra",
                            rule=rule,
                            anchors=(anchor,),
                            fix=fix,
                            resolution=(
                                "auto-fixed"
                                if receipt.status in {"applied", "already-applied"}
                                else "review"
                            ),
                        )
                    )
        for item in scanned.findings:
            if item.resolution != "auto-fixed" or item.fix is None:
                continue
            receipt = receipt_by_fix.get(item.fix.fix_id)
            if receipt is None:
                _fail("lint fix lacks its exact receipt")
            attempted_findings.append(
                item
                if receipt.status in {"applied", "already-applied"}
                else _reclassify_finding(item, fix=item.fix, resolution="review")
            )
        final_unresolved = tuple(
            _reclassify_finding(item, fix=None, resolution="review")
            if item.resolution == "auto-fixed"
            else item
            for item in final_scan.findings
        )
        infra_by_id: dict[str, LintFinding] = {}
        for finding in (*attempted_findings, *final_unresolved):
            previous = infra_by_id.get(finding.finding_id)
            if previous is not None and previous != finding:
                _fail("lint infra finding id collision changes canonical content")
            infra_by_id[finding.finding_id] = finding
        infra_findings = tuple(
            sorted(
                infra_by_id.values(),
                key=lambda item: (
                    item.anchors[0].path.casefold(),
                    item.anchors[0].path,
                    item.rule_id,
                    item.finding_id,
                ),
            )
        )
        if len(infra_findings) > self._limits.max_findings:
            _fail("lint infra findings exceed their hard bound")
        self._commit_infra_evidence(
            request,
            operation_id,
            final_scan.sources,
            infra_findings,
            tuple(receipts),
            capabilities,
        )
        semantic: list[LintFinding] = []
        batch_ids: list[str] = []
        packet_hashes: list[str] = []
        context_bytes = 0
        if request.mode != "infra":
            for batch_id, packet_raw, spans in self._packets(request, final_scan):
                batch_ids.append(batch_id)
                packet_hashes.append(hashlib.sha256(packet_raw).hexdigest())
                context_bytes += len(packet_raw)
                if context_bytes > self._limits.max_context_bytes:
                    _fail("lint semantic context exceeds its hard bound")
                semantic.extend(
                    self._batch_step(
                        request, batch_id, packet_raw, spans, capabilities, hooks
                    )
                )
        findings_by_id: dict[str, LintFinding] = {}
        for item in (*infra_findings, *semantic):
            previous = findings_by_id.get(item.finding_id)
            if previous is not None and previous != item:
                _fail("lint finding id collision changes canonical content")
            findings_by_id[item.finding_id] = item
        if len(findings_by_id) > self._limits.max_findings:
            _fail("lint final findings exceed their hard bound")
        findings = tuple(
            sorted(
                findings_by_id.values(),
                key=lambda item: (
                    item.anchors[0].path.casefold(),
                    item.anchors[0].path,
                    item.rule_id,
                    item.finding_id,
                ),
            )
        )
        source_payloads = [_source_payload(item) for item in final_scan.sources]
        source_bundle = _digest(source_payloads)
        context_hash = _digest(packet_hashes)
        report = LintReport(
            schema_version=LINT_SCHEMA_VERSION,
            run_id=request.run_id,
            operation_id=operation_id,
            mode=request.mode,
            status="findings" if findings else "clean",
            request_sha256=request_hash,
            source_bundle_sha256=source_bundle,
            sources=final_scan.sources,
            findings=findings,
            context_sha256=context_hash,
            context_bytes=context_bytes,
            batch_ids=tuple(batch_ids),
        )
        report_raw = render_lint_report(report)
        if len(report_raw) > self._limits.max_report_bytes:
            _fail("lint report exceeds its configured byte bound")
        state, run_hash = self._run_state(request)
        proposal = self._proposal_for_report(
            report, created_at=str(state["created_at"])
        )
        proposal_raw = None if proposal is None else render_lint_review(proposal)
        proposal_ref = (
            None if proposal is None else f"review/{proposal.proposal_id}.lint.json"
        )
        evidence_name = lint_evidence_artifact_name(operation_id)
        evidence = LintRunEvidence(
            schema_version=LINT_SCHEMA_VERSION,
            operation_id=operation_id,
            request_sha256=request_hash,
            run_state_sha256=run_hash,
            report=report,
            proposal_ref=proposal_ref,
            proposal_sha256=(
                None
                if proposal_raw is None
                else hashlib.sha256(proposal_raw).hexdigest()
            ),
            receipts=tuple(receipts),
        )
        evidence_raw = render_lint_run_evidence(evidence)
        self._validate_final_request_binding(request, operation_id, evidence)
        actions = self._final_actions(
            request, capabilities, has_proposal=proposal is not None
        )
        try:
            prepared = self._runs.prepare_run_artifact(
                request.run_id,
                name=evidence_name,
                data=evidence_raw,
                maximum_bytes=4 * 1024 * 1024,
            )
        except RunError as error:
            raise LintFlowError(str(error)) from None
        if proposal is not None:
            actual_ref = self._publish_review(proposal)
            if actual_ref != proposal_ref:
                _fail("lint proposal publication changed its reference")
            if hooks.after_proposal_publish is not None:
                hooks.after_proposal_publish()
        if hooks.before_run_commit is not None:
            hooks.before_run_commit()
        authority = "proposal" if proposal is not None else "internal-write"
        try:
            self._runs.commit_step(
                request.run_id,
                step_id="lint-final-"
                + hashlib.sha256(operation_id.encode()).hexdigest()[:32],
                authority=authority,
                input_hash=request_hash,
                output_hash=prepared.sha256,
                next_phase="lint-report-committed",
                prepared_artifacts=(prepared,),
                expected_state_sha256=run_hash,
                action_uses=tuple(ActionUse(item) for item in actions),
                authority_policy=self._policy,
            )
        except RunError as error:
            raise LintFlowError("lint final run commit failed safely") from error
        return LintResult(
            report,
            tuple(receipts),
            proposal,
            prepared,
            bool(recovered_fixes),
        )
