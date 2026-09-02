"""Replay-safe finalization of validated run artifacts.

Producer flows own their artifacts and leave the run in ``running`` state.
This module consumes only public run snapshots and strict artifact contracts,
then commits append-only outcome/metric records, one semantic outbox event,
and the final run state/trace intent.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, replace
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
from typing import Callable, Mapping, Sequence
import unicodedata

from tool_life_os_runtime.ext.flows.ask import AskError, parse_ask_result
from tool_life_os_runtime.ext.flows.book import (
    BookFlowError,
    parse_book_command,
    parse_book_source_manifest,
    parse_reading_state,
)
from tool_life_os_runtime.ext.review.artifact import (
    ReviewArtifactError,
    mutation_plan_sha256,
    parse_apply_journal,
    parse_mutation_plan,
    parse_review_artifact,
    render_review_artifact,
    validate_artifact_plan,
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
    RunSnapshot,
    RunStore,
    semantic_dedupe_key,
    validate_event,
)
from tool_life_os_runtime.ext.vault.schema import VaultPathResolver, VaultSchemaError
from tool_life_os_runtime.failure_authority import authority_at_most


FINALIZE_SCHEMA_VERSION = 1
FINALIZE_P3_SCHEMA_VERSION = 2
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ID = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
_RUN_ID = re.compile(r"^run_[a-z0-9][a-z0-9_-]{0,62}$")
_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$")
_PRIVATE_MARKERS = ("/" + "Users" + "/", "/" + "home" + "/", "file:")
_SECRET = re.compile(
    r"(?i)(?:api[_ -]?key|authorization|cookie|credential|password|secret|token)"
    r"[\"']?\s*[:=]"
)
_OUTCOME_KINDS = frozenset(
    {
        "review-ready",
        "review-approved",
        "review-rejected",
        "review-superseded",
        "review-applied",
        "knowledge-applied",
        "answer-ready",
        "evidence-gap",
        "validation-failed",
        "domain-updated",
        "proposal-ready",
        "report-ready",
    }
)
_TERMINAL_STATUSES = frozenset({"waiting_human", "succeeded", "failed"})
_REVIEW_STATUSES = frozenset(
    {"proposed", "approved", "rejected", "superseded", "applied"}
)
_OUTCOME_KEYS_V1 = frozenset(
    {
        "schema_version",
        "outcome_id",
        "run_id",
        "flow_id",
        "terminal_status",
        "outcome_kind",
        "artifact_valid",
        "review_id",
        "review_status",
        "plan_sha256",
        "journal_sha256",
        "ask_result_sha256",
        "accepted",
        "applied",
        "evidence_gap",
        "citation_count",
        "observed_at",
    }
)
_METRIC_KEYS_V1 = frozenset(
    {
        "schema_version",
        "metric_id",
        "outcome_id",
        "run_id",
        "flow_id",
        "terminal_status",
        "artifact_valid",
        "review_id",
        "review_status",
        "plan_sha256",
        "decision_sequence",
        "accepted",
        "applied",
        "review_queue_open",
        "review_queue_age_seconds",
        "evidence_gap",
        "citation_count",
        "observed_at",
    }
)
_P3_FIELDS = frozenset(
    {
        "source_step_id",
        "source_bundle_sha256",
        "producer_operation",
        "pending_kind",
        "pending_id",
        "decision_status",
        "decision_sequence",
        "decision_sha256",
    }
)
_OUTCOME_KEYS_V2 = _OUTCOME_KEYS_V1 | _P3_FIELDS
_METRIC_KEYS_V2 = _METRIC_KEYS_V1 | _P3_FIELDS
_MAX_OUTCOME_BYTES = 64 * 1024
_MAX_METRIC_BYTES = 16 * 1024
_MAX_ARTIFACT_BYTES = 1024 * 1024
_SIDECAR_NAMES = frozenset(
    {"finalize-log", "finalize-metric", "finalize-event", "finalize-decision"}
)

_FINALIZE_GRANTS: Mapping[str, Mapping[str, object]] = {
    "validate-run-artifacts": {
        "actor": "runtime",
        "authority": "read",
        "target": "vault:agent/runs",
        "access": "read",
        "effect_kind": "read-only",
        "artifact_commit": False,
    },
    "read-review-outcome": {
        "actor": "runtime",
        "authority": "read",
        "target": "vault:review",
        "access": "read",
        "effect_kind": "read-only",
        "artifact_commit": False,
    },
    "append-domain-log": {
        "actor": "runtime",
        "authority": "internal-write",
        "target": "vault:agent/logs",
        "access": "write",
        "effect_kind": "append-only-log",
        "artifact_commit": True,
    },
    "append-run-trace": {
        "actor": "runtime",
        "authority": "internal-write",
        "target": "vault:agent/runs/trace",
        "access": "write",
        "effect_kind": "append-only-trace",
        "artifact_commit": True,
    },
    "commit-bounded-metrics": {
        "actor": "runtime",
        "authority": "internal-write",
        "target": "vault:agent/logs/metrics",
        "access": "write",
        "effect_kind": "bounded-metrics-commit",
        "artifact_commit": True,
    },
    "emit-semantic-outbox-event": {
        "actor": "runtime",
        "authority": "internal-write",
        "target": "vault:agent/outbox",
        "access": "write",
        "effect_kind": "outbox-artifact-commit",
        "artifact_commit": True,
    },
    "finalize-run-state": {
        "actor": "runtime",
        "authority": "internal-write",
        "target": "vault:agent/runs",
        "access": "write",
        "effect_kind": "run-state-commit",
        "artifact_commit": True,
    },
}


class FinalizeError(ValueError):
    """Finalization input, evidence, authority, or durable output is invalid."""


def _fail(message: str) -> None:
    raise FinalizeError(message)


@dataclass(frozen=True)
class FinalizeArtifactRoles:
    review: str | None = None
    plan: str | None = None
    apply_journal: str | None = None
    ask_result: str | None = None
    producer_evidence: str | None = None


@dataclass(frozen=True)
class FinalizeCapabilities:
    validate_run_artifacts: ActionCapability
    read_review_outcome: ActionCapability | None
    append_domain_log: ActionCapability
    append_run_trace: ActionCapability
    commit_bounded_metrics: ActionCapability
    emit_semantic_outbox_event: ActionCapability
    finalize_run_state: ActionCapability


@dataclass(frozen=True)
class FinalizeCrashHooks:
    after_domain_log: Callable[[], None] | None = None
    after_metric: Callable[[], None] | None = None
    after_outbox: Callable[[], None] | None = None
    after_run_prepare: Callable[[], None] | None = None
    after_run_state: Callable[[], None] | None = None
    after_run_trace: Callable[[], None] | None = None


@dataclass(frozen=True)
class OutcomeRecord:
    schema_version: int
    outcome_id: str
    run_id: str
    flow_id: str
    terminal_status: str
    outcome_kind: str
    artifact_valid: bool
    review_id: str | None
    review_status: str | None
    plan_sha256: str | None
    journal_sha256: str | None
    ask_result_sha256: str | None
    accepted: bool
    applied: bool
    evidence_gap: bool | None
    citation_count: int | None
    observed_at: str
    source_step_id: str | None = None
    source_bundle_sha256: str | None = None
    producer_operation: str | None = None
    pending_kind: str | None = None
    pending_id: str | None = None
    decision_status: str | None = None
    decision_sequence: int | None = None
    decision_sha256: str | None = None


@dataclass(frozen=True)
class MetricRecord:
    schema_version: int
    metric_id: str
    outcome_id: str
    run_id: str
    flow_id: str
    terminal_status: str
    artifact_valid: bool
    review_id: str | None
    review_status: str | None
    plan_sha256: str | None
    decision_sequence: int | None
    accepted: bool
    applied: bool
    review_queue_open: bool | None
    review_queue_age_seconds: int | None
    evidence_gap: bool | None
    citation_count: int | None
    observed_at: str
    source_step_id: str | None = None
    source_bundle_sha256: str | None = None
    producer_operation: str | None = None
    pending_kind: str | None = None
    pending_id: str | None = None
    decision_status: str | None = None
    decision_sha256: str | None = None


@dataclass(frozen=True)
class FinalizeResult:
    schema_version: int
    run_id: str
    source_flow: str
    terminal_status: str
    outcome_id: str
    outcome_kind: str
    domain_log_ref: str
    metric_ref: str
    outbox_event_id: str | None


@dataclass(frozen=True)
class _ProducerOutcome:
    operation: str
    outcome_kind: str
    terminal_status: str
    source_artifacts: tuple[CommittedArtifact, ...]
    source_step_id: str
    source_bundle_sha256: str
    surface: str
    pending_kind: str | None = None
    pending_id: str | None = None
    decision_status: str | None = None
    decision_sequence: int | None = None
    decision_sha256: str | None = None
    decision_artifact: PreparedArtifact | None = None


def _has_control(value: str) -> bool:
    return any(
        unicodedata.category(character).startswith("C")
        or unicodedata.category(character) in {"Zl", "Zp"}
        for character in value
    )


def _text(value: object, label: str, *, maximum: int = 256) -> str:
    if not isinstance(value, str) or not value:
        _fail(f"{label} must be bounded privacy-safe text")
    try:
        encoded = value.encode("utf-8")
    except UnicodeError:
        _fail(f"{label} must be valid UTF-8 text")
    if (
        len(encoded) > maximum
        or value.strip() != value
        or _has_control(value)
        or any(marker in value for marker in _PRIVATE_MARKERS)
        or _SECRET.search(value) is not None
    ):
        _fail(f"{label} must be bounded privacy-safe text")
    return value


def _identifier(value: object, label: str, pattern: re.Pattern[str] = _ID) -> str:
    checked = _text(value, label, maximum=64)
    if pattern.fullmatch(checked) is None:
        _fail(f"{label} has invalid syntax")
    return checked


def _hash(value: object, label: str) -> str:
    checked = _text(value, label, maximum=64)
    if _SHA256.fullmatch(checked) is None:
        _fail(f"{label} must be sha256")
    return checked


def _timestamp(value: object, label: str) -> str:
    checked = _text(value, label, maximum=40)
    if _UTC.fullmatch(checked) is None:
        _fail(f"{label} must be a UTC timestamp")
    try:
        datetime.fromisoformat(checked[:-1] + "+00:00")
    except ValueError:
        _fail(f"{label} must be a valid UTC timestamp")
    return checked


def _canonical_bytes(payload: Mapping[str, object], maximum: int) -> bytes:
    try:
        raw = (
            json.dumps(
                payload,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
            + b"\n"
        )
    except (TypeError, ValueError, UnicodeError, RecursionError):
        _fail("finalize record is not canonical JSON")
    if len(raw) > maximum:
        _fail("finalize record is too large")
    return raw


def _object_no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            _fail("finalize JSON contains duplicate fields")
        result[key] = value
    return result


def _decode(
    raw: str | bytes, label: str, maximum: int
) -> tuple[bytes, Mapping[str, object]]:
    if isinstance(raw, str):
        try:
            encoded = raw.encode("utf-8")
        except UnicodeError:
            _fail(f"{label} is not valid UTF-8")
    elif isinstance(raw, bytes):
        encoded = raw
    else:
        _fail(f"{label} must be bytes or text")
    if not encoded or len(encoded) > maximum:
        _fail(f"{label} is empty or too large")
    try:
        payload = json.loads(encoded, object_pairs_hook=_object_no_duplicates)
    except FinalizeError:
        raise
    except (UnicodeError, ValueError, RecursionError):
        _fail(f"{label} is not valid JSON")
    if not isinstance(payload, Mapping):
        _fail(f"{label} must be an object")
    return encoded, payload


def _exact_json(
    raw: bytes, label: str, keys: frozenset[str], maximum: int = _MAX_ARTIFACT_BYTES
) -> Mapping[str, object]:
    encoded, payload = _decode(raw, label, maximum)
    if set(payload) != keys:
        _fail(f"{label} has missing or unknown fields")
    if _canonical_bytes(dict(payload), maximum) != encoded:
        _fail(f"{label} must use exact canonical JSON")
    return payload


def _exact_unterminated_json(
    raw: bytes, label: str, keys: frozenset[str], maximum: int = _MAX_ARTIFACT_BYTES
) -> Mapping[str, object]:
    encoded, payload = _decode(raw, label, maximum)
    if set(payload) != keys:
        _fail(f"{label} has missing or unknown fields")
    try:
        canonical = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError):
        _fail(f"{label} is not canonical JSON")
    if canonical != encoded:
        _fail(f"{label} must use exact canonical JSON")
    return payload


def _safe_ref(value: object, label: str) -> str:
    checked = _text(value, label, maximum=1024)
    path = PurePosixPath(checked)
    if (
        path.is_absolute()
        or path.as_posix() != checked
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        _fail(f"{label} must be a safe relative reference")
    return checked


def _bundle_sha256(artifacts: Sequence[CommittedArtifact]) -> str:
    if not artifacts or len({item.step_id for item in artifacts}) != 1:
        _fail("producer bundle must belong to one semantic step")
    payload = {
        "artifacts": [
            {
                "name": item.name,
                "zone": item.zone,
                "relative": item.relative,
                "state_ref": item.state_ref,
                "sha256": item.sha256,
            }
            for item in sorted(artifacts, key=lambda value: value.name)
        ]
    }
    return hashlib.sha256(_canonical_bytes(payload, _MAX_ARTIFACT_BYTES)).hexdigest()


def _decision_kind(status: str) -> str:
    return {
        "proposed": "proposal-ready",
        "approved": "review-approved",
        "rejected": "review-rejected",
        "superseded": "review-superseded",
        "applied": "review-applied",
    }[status]


def _optional_hash(value: object, label: str) -> str | None:
    return None if value is None else _hash(value, label)


def _optional_id(value: object, label: str) -> str | None:
    return None if value is None else _identifier(value, label)


def _exact_optional_int(value: object, label: str) -> int | None:
    if value is None:
        return None
    if type(value) is not int or value < 0 or value > 2**63 - 1:
        _fail(f"{label} must be a bounded non-negative integer")
    return value


def _outcome_payload(value: OutcomeRecord) -> dict[str, object]:
    keys = (
        _OUTCOME_KEYS_V1
        if value.schema_version == FINALIZE_SCHEMA_VERSION
        else _OUTCOME_KEYS_V2
    )
    return {key: getattr(value, key) for key in sorted(keys)}


def _metric_payload(value: MetricRecord) -> dict[str, object]:
    keys = (
        _METRIC_KEYS_V1
        if value.schema_version == FINALIZE_SCHEMA_VERSION
        else _METRIC_KEYS_V2
    )
    return {key: getattr(value, key) for key in sorted(keys)}


_P3_FINALIZE_FLOWS = frozenset(
    {
        "project",
        "entities",
        "plan",
        "book",
        "report",
        "memory",
        "mentor",
        "grill-me",
        "lint",
        "ambient",
        "bundle",
    }
)
_P3_COMPLETE_BUNDLE_FLOWS = frozenset(
    {"mentor", "grill-me", "lint", "ambient", "bundle"}
)
_P3_DECISION_STATUSES = frozenset(
    {"proposed", "approved", "rejected", "superseded", "applied"}
)


def _validate_p3_outcome_semantics(result: OutcomeRecord) -> None:
    generic = (
        result.source_step_id,
        result.source_bundle_sha256,
        result.producer_operation,
    )
    p2_fields = (
        result.review_id,
        result.review_status,
        result.plan_sha256,
        result.journal_sha256,
        result.ask_result_sha256,
        result.evidence_gap,
        result.citation_count,
    )
    if result.outcome_kind == "validation-failed":
        if (
            result.flow_id not in _P3_FINALIZE_FLOWS
            or result.artifact_valid
            or result.terminal_status != "failed"
            or any(value is not None for value in generic + p2_fields)
            or any(
                value is not None
                for value in (
                    result.pending_kind,
                    result.pending_id,
                    result.decision_status,
                    result.decision_sequence,
                    result.decision_sha256,
                )
            )
            or result.accepted
            or result.applied
        ):
            _fail("P3 validation-failed outcome has invalid state")
        return
    if (
        result.flow_id not in _P3_FINALIZE_FLOWS
        or not result.artifact_valid
        or any(value is None for value in generic)
        or any(value is not None for value in p2_fields)
    ):
        _fail("P3 outcome lacks exact producer evidence")
    decision_fields = (
        result.decision_status,
        result.decision_sha256,
    )
    if any(value is None for value in decision_fields) != all(
        value is None for value in decision_fields
    ):
        _fail("P3 outcome decision evidence is incomplete")
    if result.decision_status is None:
        if (
            result.decision_sequence is not None
            or result.pending_kind is not None
            or result.pending_id is not None
            or result.accepted
            or result.applied
            or result.terminal_status != "succeeded"
            or result.outcome_kind not in {"domain-updated", "report-ready"}
        ):
            _fail("P3 direct-domain outcome is inconsistent")
        return
    if result.decision_status not in _P3_DECISION_STATUSES:
        _fail("P3 outcome decision status is invalid")
    if result.decision_status == "proposed":
        if (
            result.decision_sequence is not None
            or result.pending_kind is None
            or result.pending_id is None
            or result.terminal_status != "waiting_human"
            or result.outcome_kind != "proposal-ready"
            or result.accepted
            or result.applied
        ):
            _fail("P3 pending proposal outcome is inconsistent")
        return
    expected_kind = {
        "approved": "review-approved",
        "rejected": "review-rejected",
        "superseded": "review-superseded",
        "applied": "review-applied",
    }[result.decision_status]
    if (
        result.decision_sequence is None
        or result.decision_sequence < 1
        or result.pending_kind is not None
        or result.pending_id is not None
        or result.terminal_status != "succeeded"
        or result.outcome_kind != expected_kind
        or result.accepted != (result.decision_status in {"approved", "applied"})
        or result.applied != (result.decision_status == "applied")
    ):
        _fail("P3 decided proposal outcome is inconsistent")


def _validate_outcome_semantics(result: OutcomeRecord) -> None:
    if result.schema_version == FINALIZE_P3_SCHEMA_VERSION:
        _validate_p3_outcome_semantics(result)
        return
    if result.flow_id not in {"distill", "apply", "ask"}:
        _fail("outcome flow is not a finalizable knowledge flow")
    review_fields = (result.review_id, result.review_status, result.plan_sha256)
    if any(value is None for value in review_fields) != all(
        value is None for value in review_fields
    ):
        _fail("outcome review evidence is incomplete")
    ask_fields = (
        result.ask_result_sha256,
        result.evidence_gap,
        result.citation_count,
    )
    if any(value is None for value in ask_fields) != all(
        value is None for value in ask_fields
    ):
        _fail("outcome ask evidence is incomplete")
    if result.ask_result_sha256 is not None:
        if result.flow_id != "ask":
            _fail("ask outcome evidence belongs only to ask flow")
        if result.evidence_gap != (result.citation_count == 0):
            _fail("outcome evidence gap disagrees with citation count")
    expected_accepted = result.review_status in {"approved", "applied"}
    expected_applied = result.review_status == "applied"
    if result.accepted != expected_accepted or result.applied != expected_applied:
        _fail("outcome acceptance flags disagree with current review status")
    if (result.journal_sha256 is not None) != result.applied:
        _fail("outcome journal evidence disagrees with applied status")

    if result.outcome_kind == "validation-failed":
        if (
            result.artifact_valid
            or result.terminal_status != "failed"
            or any(value is not None for value in review_fields + ask_fields)
            or result.journal_sha256 is not None
            or result.accepted
            or result.applied
        ):
            _fail("validation-failed outcome has invalid state")
        return
    if not result.artifact_valid:
        _fail("successful finalize outcome requires valid artifacts")
    if result.outcome_kind == "review-ready":
        expected = ("waiting_human", "proposed")
    elif result.outcome_kind == "review-approved":
        expected = ("succeeded", "approved")
    elif result.outcome_kind == "review-rejected":
        expected = ("succeeded", "rejected")
    elif result.outcome_kind == "review-superseded":
        expected = ("succeeded", "superseded")
    elif result.outcome_kind == "review-applied":
        expected = ("succeeded", "applied")
    elif result.outcome_kind == "knowledge-applied":
        expected = ("succeeded", "applied")
        if result.flow_id != "apply":
            _fail("knowledge-applied outcome requires apply flow")
    else:
        expected = (
            "succeeded",
            None,
        )
        if (
            result.flow_id != "ask"
            or result.ask_result_sha256 is None
            or result.outcome_kind
            != ("evidence-gap" if result.evidence_gap else "answer-ready")
        ):
            _fail("answer outcome evidence is inconsistent")
    if (result.terminal_status, result.review_status) != expected:
        _fail("outcome kind disagrees with terminal or review status")
    if result.flow_id == "apply" and result.outcome_kind != "knowledge-applied":
        _fail("apply flow has an invalid outcome kind")
    if result.flow_id == "distill" and result.ask_result_sha256 is not None:
        _fail("distill outcome cannot contain ask evidence")


def parse_outcome_record(raw: str | bytes) -> OutcomeRecord:
    encoded, payload = _decode(raw, "outcome record", _MAX_OUTCOME_BYTES)
    version = payload.get("schema_version")
    expected_keys = (
        {
            FINALIZE_SCHEMA_VERSION: _OUTCOME_KEYS_V1,
            FINALIZE_P3_SCHEMA_VERSION: _OUTCOME_KEYS_V2,
        }.get(version)
        if type(version) is int
        else None
    )
    if expected_keys is None:
        _fail("unsupported outcome schema_version")
    if set(payload) != expected_keys:
        _fail("outcome record has missing or unknown fields")
    terminal = payload["terminal_status"]
    kind = payload["outcome_kind"]
    if (
        not isinstance(terminal, str)
        or terminal not in _TERMINAL_STATUSES
        or not isinstance(kind, str)
        or kind not in _OUTCOME_KINDS
    ):
        _fail("outcome status or kind is invalid")
    if not isinstance(payload["artifact_valid"], bool):
        _fail("outcome artifact_valid must be boolean")
    review_status = payload["review_status"]
    if review_status is not None and (
        not isinstance(review_status, str) or review_status not in _REVIEW_STATUSES
    ):
        _fail("outcome review_status is invalid")
    for field in ("accepted", "applied"):
        if not isinstance(payload[field], bool):
            _fail(f"outcome {field} must be boolean")
    gap = payload["evidence_gap"]
    if gap is not None and not isinstance(gap, bool):
        _fail("outcome evidence_gap must be boolean or null")
    result = OutcomeRecord(
        schema_version=version,
        outcome_id=_identifier(payload["outcome_id"], "outcome_id"),
        run_id=_identifier(payload["run_id"], "run_id", _RUN_ID),
        flow_id=_identifier(payload["flow_id"], "flow_id"),
        terminal_status=str(terminal),
        outcome_kind=str(kind),
        artifact_valid=payload["artifact_valid"],
        review_id=_optional_id(payload["review_id"], "review_id"),
        review_status=review_status,
        plan_sha256=_optional_hash(payload["plan_sha256"], "plan_sha256"),
        journal_sha256=_optional_hash(payload["journal_sha256"], "journal_sha256"),
        ask_result_sha256=_optional_hash(
            payload["ask_result_sha256"], "ask_result_sha256"
        ),
        accepted=payload["accepted"],
        applied=payload["applied"],
        evidence_gap=gap,
        citation_count=_exact_optional_int(payload["citation_count"], "citation_count"),
        observed_at=_timestamp(payload["observed_at"], "observed_at"),
        source_step_id=(
            None
            if version == FINALIZE_SCHEMA_VERSION
            else _optional_id(payload["source_step_id"], "source_step_id")
        ),
        source_bundle_sha256=(
            None
            if version == FINALIZE_SCHEMA_VERSION
            else _optional_hash(payload["source_bundle_sha256"], "source_bundle_sha256")
        ),
        producer_operation=(
            None
            if version == FINALIZE_SCHEMA_VERSION
            else _optional_id(payload["producer_operation"], "producer_operation")
        ),
        pending_kind=(
            None
            if version == FINALIZE_SCHEMA_VERSION
            else _optional_id(payload["pending_kind"], "pending_kind")
        ),
        pending_id=(
            None
            if version == FINALIZE_SCHEMA_VERSION
            else _optional_id(payload["pending_id"], "pending_id")
        ),
        decision_status=(
            None
            if version == FINALIZE_SCHEMA_VERSION
            else (
                None
                if payload["decision_status"] is None
                else _text(payload["decision_status"], "decision_status", maximum=16)
            )
        ),
        decision_sequence=(
            None
            if version == FINALIZE_SCHEMA_VERSION
            else _exact_optional_int(payload["decision_sequence"], "decision_sequence")
        ),
        decision_sha256=(
            None
            if version == FINALIZE_SCHEMA_VERSION
            else _optional_hash(payload["decision_sha256"], "decision_sha256")
        ),
    )
    _validate_outcome_semantics(result)
    if _canonical_bytes(_outcome_payload(result), _MAX_OUTCOME_BYTES) != encoded:
        _fail("outcome record must use exact canonical JSON encoding")
    identity = dict(_outcome_payload(result))
    identity.pop("outcome_id")
    identity.pop("observed_at")
    expected = (
        "outcome_"
        + hashlib.sha256(_canonical_bytes(identity, _MAX_OUTCOME_BYTES)).hexdigest()[
            :56
        ]
    )
    if result.outcome_id != expected:
        _fail("outcome_id does not match semantic record fields")
    return result


def render_outcome_record(value: OutcomeRecord) -> bytes:
    checked = parse_outcome_record(
        _canonical_bytes(_outcome_payload(value), _MAX_OUTCOME_BYTES)
    )
    if checked != value:
        _fail("outcome record cannot be rendered canonically")
    return _canonical_bytes(_outcome_payload(checked), _MAX_OUTCOME_BYTES)


def parse_metric_record(raw: str | bytes) -> MetricRecord:
    encoded, payload = _decode(raw, "metric record", _MAX_METRIC_BYTES)
    version = payload.get("schema_version")
    expected_keys = (
        {
            FINALIZE_SCHEMA_VERSION: _METRIC_KEYS_V1,
            FINALIZE_P3_SCHEMA_VERSION: _METRIC_KEYS_V2,
        }.get(version)
        if type(version) is int
        else None
    )
    if expected_keys is None:
        _fail("unsupported metric schema_version")
    if set(payload) != expected_keys:
        _fail("metric record has missing or unknown fields")
    if (
        not isinstance(payload["terminal_status"], str)
        or payload["terminal_status"] not in _TERMINAL_STATUSES
    ):
        _fail("metric terminal_status is invalid")
    review_status = payload["review_status"]
    if review_status is not None and (
        not isinstance(review_status, str) or review_status not in _REVIEW_STATUSES
    ):
        _fail("metric review_status is invalid")
    for field in ("artifact_valid", "accepted", "applied"):
        if not isinstance(payload[field], bool):
            _fail(f"metric {field} must be boolean")
    queue_open = payload["review_queue_open"]
    if queue_open is not None and not isinstance(queue_open, bool):
        _fail("metric review_queue_open must be boolean or null")
    gap = payload["evidence_gap"]
    if gap is not None and not isinstance(gap, bool):
        _fail("metric evidence_gap must be boolean or null")
    result = MetricRecord(
        schema_version=version,
        metric_id=_identifier(payload["metric_id"], "metric_id"),
        outcome_id=_identifier(payload["outcome_id"], "outcome_id"),
        run_id=_identifier(payload["run_id"], "run_id", _RUN_ID),
        flow_id=_identifier(payload["flow_id"], "flow_id"),
        terminal_status=str(payload["terminal_status"]),
        artifact_valid=payload["artifact_valid"],
        review_id=_optional_id(payload["review_id"], "review_id"),
        review_status=review_status,
        plan_sha256=_optional_hash(payload["plan_sha256"], "plan_sha256"),
        decision_sequence=_exact_optional_int(
            payload["decision_sequence"], "decision_sequence"
        ),
        accepted=payload["accepted"],
        applied=payload["applied"],
        review_queue_open=queue_open,
        review_queue_age_seconds=_exact_optional_int(
            payload["review_queue_age_seconds"], "review_queue_age_seconds"
        ),
        evidence_gap=gap,
        citation_count=_exact_optional_int(payload["citation_count"], "citation_count"),
        observed_at=_timestamp(payload["observed_at"], "observed_at"),
        source_step_id=(
            None
            if version == FINALIZE_SCHEMA_VERSION
            else _optional_id(payload["source_step_id"], "source_step_id")
        ),
        source_bundle_sha256=(
            None
            if version == FINALIZE_SCHEMA_VERSION
            else _optional_hash(payload["source_bundle_sha256"], "source_bundle_sha256")
        ),
        producer_operation=(
            None
            if version == FINALIZE_SCHEMA_VERSION
            else _optional_id(payload["producer_operation"], "producer_operation")
        ),
        pending_kind=(
            None
            if version == FINALIZE_SCHEMA_VERSION
            else _optional_id(payload["pending_kind"], "pending_kind")
        ),
        pending_id=(
            None
            if version == FINALIZE_SCHEMA_VERSION
            else _optional_id(payload["pending_id"], "pending_id")
        ),
        decision_status=(
            None
            if version == FINALIZE_SCHEMA_VERSION
            else (
                None
                if payload["decision_status"] is None
                else _text(payload["decision_status"], "decision_status", maximum=16)
            )
        ),
        decision_sha256=(
            None
            if version == FINALIZE_SCHEMA_VERSION
            else _optional_hash(payload["decision_sha256"], "decision_sha256")
        ),
    )
    if version == FINALIZE_P3_SCHEMA_VERSION:
        shadow = OutcomeRecord(
            schema_version=version,
            outcome_id=result.outcome_id,
            run_id=result.run_id,
            flow_id=result.flow_id,
            terminal_status=result.terminal_status,
            outcome_kind=(
                "validation-failed"
                if not result.artifact_valid
                else (
                    "proposal-ready"
                    if result.decision_status == "proposed"
                    else {
                        "approved": "review-approved",
                        "rejected": "review-rejected",
                        "superseded": "review-superseded",
                        "applied": "review-applied",
                    }.get(
                        result.decision_status,
                        "report-ready"
                        if result.flow_id == "report"
                        and result.producer_operation in {"daily", "weekly"}
                        else "domain-updated",
                    )
                )
            ),
            artifact_valid=result.artifact_valid,
            review_id=None,
            review_status=None,
            plan_sha256=None,
            journal_sha256=None,
            ask_result_sha256=None,
            accepted=result.accepted,
            applied=result.applied,
            evidence_gap=None,
            citation_count=None,
            observed_at=result.observed_at,
            source_step_id=result.source_step_id,
            source_bundle_sha256=result.source_bundle_sha256,
            producer_operation=result.producer_operation,
            pending_kind=result.pending_kind,
            pending_id=result.pending_id,
            decision_status=result.decision_status,
            decision_sequence=result.decision_sequence,
            decision_sha256=result.decision_sha256,
        )
        _validate_p3_outcome_semantics(shadow)
        if (
            result.review_id is not None
            or result.review_status is not None
            or result.plan_sha256 is not None
        ):
            _fail("P3 metric cannot contain P2 review fields")
        if any(
            value is not None
            for value in (
                result.evidence_gap,
                result.citation_count,
                result.review_queue_open,
                result.review_queue_age_seconds,
            )
        ):
            _fail("P3 metric cannot contain P2 queue or ask fields")
        if _canonical_bytes(_metric_payload(result), _MAX_METRIC_BYTES) != encoded:
            _fail("metric record must use exact canonical JSON encoding")
        expected = (
            "metric_"
            + hashlib.sha256(result.outcome_id.encode("ascii")).hexdigest()[:56]
        )
        if result.metric_id != expected:
            _fail("metric_id does not match outcome_id")
        return result
    if result.flow_id not in {"distill", "apply", "ask"}:
        _fail("metric flow is not a finalizable knowledge flow")
    review_fields = (result.review_id, result.review_status, result.plan_sha256)
    if any(value is None for value in review_fields) != all(
        value is None for value in review_fields
    ):
        _fail("metric review evidence is incomplete")
    if result.review_id is None:
        if any(
            value is not None
            for value in (
                result.decision_sequence,
                result.review_queue_open,
                result.review_queue_age_seconds,
            )
        ):
            _fail("metric review queue fields require review evidence")
    elif result.review_status == "proposed":
        if result.decision_sequence is not None or result.review_queue_open is not True:
            _fail("proposed review metric must describe an open queue")
    elif (
        result.decision_sequence is None
        or result.decision_sequence < 1
        or result.review_queue_open is not False
    ):
        _fail("decided review metric must describe a closed queue")
    if result.review_id is not None and result.review_queue_age_seconds is None:
        _fail("metric review queue age is incomplete")
    expected_accepted = result.review_status in {"approved", "applied"}
    expected_applied = result.review_status == "applied"
    if result.accepted != expected_accepted or result.applied != expected_applied:
        _fail("metric acceptance flags disagree with current review status")
    if (result.evidence_gap is None) != (result.citation_count is None):
        _fail("metric ask evidence is incomplete")
    if result.evidence_gap is not None:
        if result.flow_id != "ask" or result.evidence_gap != (
            result.citation_count == 0
        ):
            _fail("metric evidence gap disagrees with citation count")
    if not result.artifact_valid:
        if (
            result.terminal_status != "failed"
            or any(value is not None for value in review_fields)
            or result.evidence_gap is not None
            or result.accepted
            or result.applied
        ):
            _fail("invalid-artifact metric has inconsistent fields")
    elif result.terminal_status != (
        "waiting_human" if result.review_status == "proposed" else "succeeded"
    ):
        _fail("metric terminal status disagrees with validated outcome")
    if _canonical_bytes(_metric_payload(result), _MAX_METRIC_BYTES) != encoded:
        _fail("metric record must use exact canonical JSON encoding")
    expected = (
        "metric_" + hashlib.sha256(result.outcome_id.encode("ascii")).hexdigest()[:56]
    )
    if result.metric_id != expected:
        _fail("metric_id does not match outcome_id")
    return result


def render_metric_record(value: MetricRecord) -> bytes:
    checked = parse_metric_record(
        _canonical_bytes(_metric_payload(value), _MAX_METRIC_BYTES)
    )
    if checked != value:
        _fail("metric record cannot be rendered canonically")
    return _canonical_bytes(_metric_payload(checked), _MAX_METRIC_BYTES)


class _AppendOnlyPublisher:
    def __init__(self, resolver: VaultPathResolver) -> None:
        self._resolver = resolver

    def _directory(self, child: str) -> tuple[int, Path, tuple[int, int]]:
        if child not in {"finalize", "metrics"}:
            _fail("append-only directory is invalid")
        try:
            base = self._resolver.resolve("agent/logs", for_write=True, must_exist=True)
            base_fd = os.open(
                base,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
            opened_base = os.fstat(base_fd)
            named_base = os.stat(base, follow_symlinks=False)
            if not stat.S_ISDIR(opened_base.st_mode) or (
                opened_base.st_dev,
                opened_base.st_ino,
            ) != (named_base.st_dev, named_base.st_ino):
                _fail("agent logs changed while opening")
            try:
                os.mkdir(child, mode=0o700, dir_fd=base_fd)
                os.fsync(base_fd)
            except FileExistsError:
                pass
            child_fd = os.open(
                child,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=base_fd,
            )
            opened = os.fstat(child_fd)
            named = os.stat(child, dir_fd=base_fd, follow_symlinks=False)
            if not stat.S_ISDIR(opened.st_mode) or (opened.st_dev, opened.st_ino) != (
                named.st_dev,
                named.st_ino,
            ):
                _fail("append-only directory changed while opening")
            self._resolver.revalidate(
                base / child,
                "agent/logs",
                child,
                for_write=True,
                must_exist=True,
            )
            return child_fd, base / child, (opened.st_dev, opened.st_ino)
        except (OSError, VaultSchemaError, FinalizeError):
            if "child_fd" in locals():
                os.close(child_fd)
            raise FinalizeError(
                "append-only directory cannot be anchored safely"
            ) from None
        finally:
            if "base_fd" in locals():
                os.close(base_fd)

    @staticmethod
    def _read(directory_fd: int, name: str, maximum: int) -> bytes:
        fd: int | None = None
        try:
            fd = os.open(
                name,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=directory_fd,
            )
            opened = os.fstat(fd)
            named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_size > maximum
                or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
            ):
                _fail("append-only record is not a bounded regular file")
            chunks: list[bytes] = []
            remaining = maximum + 1
            while remaining:
                block = os.read(fd, min(64 * 1024, remaining))
                if not block:
                    break
                chunks.append(block)
                remaining -= len(block)
            if remaining == 0:
                _fail("append-only record is too large")
            if (os.fstat(fd).st_dev, os.fstat(fd).st_ino) != (
                opened.st_dev,
                opened.st_ino,
            ):
                _fail("append-only record changed while read")
            return b"".join(chunks)
        except OSError:
            raise FinalizeError("append-only record cannot be read safely") from None
        finally:
            if fd is not None:
                os.close(fd)

    def read_if_exists(self, child: str, name: str, maximum: int) -> bytes | None:
        directory_fd, path, identity = self._directory(child)
        try:
            try:
                raw = self._read(directory_fd, name, maximum)
            except FinalizeError:
                try:
                    os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                except FileNotFoundError:
                    raw = None
                else:
                    raise
            named = os.stat(path, follow_symlinks=False)
            if (named.st_dev, named.st_ino) != identity:
                _fail("append-only directory changed during read")
            return raw
        finally:
            os.close(directory_fd)

    def publish(
        self,
        child: str,
        name: str,
        data: bytes,
        maximum: int,
        *,
        after_prepare: Callable[[], None] | None = None,
        after_publish: Callable[[], None] | None = None,
    ) -> bytes:
        if not isinstance(data, bytes) or not data or len(data) > maximum:
            _fail("append-only publication bytes are invalid")
        directory_fd, path, identity = self._directory(child)
        digest = hashlib.sha256(data).hexdigest()
        stage = f".{name}.{digest[:16]}.pending"
        stage_identity: tuple[int, int] | None = None
        try:
            try:
                existing = self._read(directory_fd, name, maximum)
            except FinalizeError:
                try:
                    os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                except FileNotFoundError:
                    existing = None
                else:
                    raise
            if existing is not None:
                if existing != data:
                    _fail("append-only semantic ID belongs to different bytes")
                try:
                    staged = self._read(directory_fd, stage, maximum)
                except FinalizeError:
                    try:
                        os.stat(stage, dir_fd=directory_fd, follow_symlinks=False)
                    except FileNotFoundError:
                        staged = None
                    else:
                        raise
                if staged is not None:
                    if staged != data:
                        _fail("append-only stage contains foreign bytes")
                    staged_named = os.stat(
                        stage, dir_fd=directory_fd, follow_symlinks=False
                    )
                    published_named = os.stat(
                        name, dir_fd=directory_fd, follow_symlinks=False
                    )
                    if (staged_named.st_dev, staged_named.st_ino) != (
                        published_named.st_dev,
                        published_named.st_ino,
                    ):
                        _fail("append-only foreign stage cannot be cleaned")
                    os.unlink(stage, dir_fd=directory_fd)
                    os.fsync(directory_fd)
                return existing

            try:
                stage_fd = os.open(
                    stage,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                    0o600,
                    dir_fd=directory_fd,
                )
            except FileExistsError:
                staged = self._read(directory_fd, stage, maximum)
                if staged != data:
                    _fail("append-only stage contains foreign bytes")
                stage_metadata = os.stat(
                    stage, dir_fd=directory_fd, follow_symlinks=False
                )
                stage_identity = (stage_metadata.st_dev, stage_metadata.st_ino)
            else:
                try:
                    remaining = memoryview(data)
                    while remaining:
                        written = os.write(stage_fd, remaining)
                        if written <= 0:
                            _fail("append-only stage write was incomplete")
                        remaining = remaining[written:]
                    os.fsync(stage_fd)
                    metadata = os.fstat(stage_fd)
                    stage_identity = (metadata.st_dev, metadata.st_ino)
                finally:
                    os.close(stage_fd)
                os.fsync(directory_fd)
            if after_prepare is not None:
                after_prepare()
            staged_named = os.stat(stage, dir_fd=directory_fd, follow_symlinks=False)
            if stage_identity != (staged_named.st_dev, staged_named.st_ino):
                _fail("append-only stage was replaced before publication")
            if self._read(directory_fd, stage, maximum) != data:
                _fail("append-only stage changed before publication")
            linked_by_us = False
            try:
                os.link(
                    stage,
                    name,
                    src_dir_fd=directory_fd,
                    dst_dir_fd=directory_fd,
                    follow_symlinks=False,
                )
                linked_by_us = True
                os.fsync(directory_fd)
            except FileExistsError:
                existing = self._read(directory_fd, name, maximum)
                if existing != data:
                    _fail("append-only semantic ID belongs to different bytes")
            if after_publish is not None:
                after_publish()
            published = self._read(directory_fd, name, maximum)
            staged_named = os.stat(stage, dir_fd=directory_fd, follow_symlinks=False)
            if stage_identity != (staged_named.st_dev, staged_named.st_ino):
                _fail("append-only stage was replaced before cleanup")
            if linked_by_us:
                published_named = os.stat(
                    name, dir_fd=directory_fd, follow_symlinks=False
                )
                if stage_identity != (
                    published_named.st_dev,
                    published_named.st_ino,
                ):
                    _fail("append-only publication was replaced before cleanup")
            os.unlink(stage, dir_fd=directory_fd)
            os.fsync(directory_fd)
            named = os.stat(path, follow_symlinks=False)
            if (named.st_dev, named.st_ino) != identity or published != data:
                _fail("append-only publication changed during commit")
            return published
        except OSError:
            raise FinalizeError("append-only publication failed safely") from None
        finally:
            os.close(directory_fd)


class FinalizeFlow:
    def __init__(
        self,
        resolver: VaultPathResolver,
        run_store: RunStore,
        outbox_store: OutboxStore,
        *,
        policy: AuthorityPolicy,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if (
            not isinstance(run_store, RunStore)
            or not isinstance(outbox_store, OutboxStore)
            or not isinstance(policy, AuthorityPolicy)
            or getattr(run_store, "_resolver", None) is not resolver
            or getattr(outbox_store, "_resolver", None) is not resolver
            or getattr(outbox_store, "_run_store", None) is not run_store
            or getattr(outbox_store, "_policy", None) is not policy
        ):
            _fail("finalize stores must share one resolver and authority policy")
        self._resolver = resolver
        self._runs = run_store
        self._outbox = outbox_store
        self._policy = policy
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._publisher = _AppendOnlyPublisher(resolver)
        self._capture_ref_anchors()

    def _capture_ref_anchors(self) -> None:
        try:
            runs = self._resolver.resolve("agent/runs", must_exist=True)
            root = runs
            for _ in self._resolver.config.zone("runs").parts:
                root = root.parent
            zone_paths = {
                "agent/logs": PurePosixPath("agent/logs"),
                "agent/memory": self._resolver.config.zone("memory"),
                "review": self._resolver.config.zone("review"),
                "projects": self._resolver.config.zone("projects"),
                "tasks": self._resolver.config.zone("tasks"),
            }
            root_stat = os.stat(root, follow_symlinks=False)
            if not stat.S_ISDIR(root_stat.st_mode):
                _fail("finalize vault root is not a directory")
            anchors: dict[tuple[str, ...], tuple[int, int]] = {}
            for zone, physical in zone_paths.items():
                expected = self._resolver.resolve(zone, must_exist=True)
                if expected != root.joinpath(*physical.parts):
                    _fail("finalize zone disagrees with configured physical path")
                current = root
                prefix: list[str] = []
                for part in physical.parts:
                    prefix.append(part)
                    current = current / part
                    metadata = os.stat(current, follow_symlinks=False)
                    if not stat.S_ISDIR(metadata.st_mode):
                        _fail("finalize ref parent is not a directory")
                    identity = (metadata.st_dev, metadata.st_ino)
                    key = tuple(prefix)
                    previous = anchors.get(key)
                    if previous is not None and previous != identity:
                        _fail("finalize ref parents have conflicting identities")
                    anchors[key] = identity
        except (OSError, ValueError, VaultSchemaError, FinalizeError):
            raise FinalizeError(
                "finalize ref roots cannot be anchored safely"
            ) from None
        self._ref_root = root
        self._ref_root_identity = (root_stat.st_dev, root_stat.st_ino)
        self._ref_zone_paths = zone_paths
        self._ref_parent_anchors = anchors

    def _now(self) -> str:
        value = self._clock()
        if not isinstance(value, datetime) or value.tzinfo is None:
            _fail("finalize clock must return an aware datetime")
        return (
            value.astimezone(timezone.utc)
            .isoformat(timespec="microseconds")
            .replace("+00:00", "Z")
        )

    def _grant(self, capability: ActionCapability, action_id: str) -> ActionCapability:
        try:
            grant = self._policy.require(capability)
        except AuthorityError as error:
            raise FinalizeError(str(error)) from None
        expected = _FINALIZE_GRANTS[action_id]
        if (
            grant.flow_id != "finalize"
            or grant.action_id != action_id
            or any(getattr(grant, field) != value for field, value in expected.items())
        ):
            _fail(f"capability does not authorize finalize action {action_id}")
        return grant

    def _capabilities(
        self, roles: FinalizeArtifactRoles, capabilities: FinalizeCapabilities
    ) -> dict[str, ActionCapability]:
        if not isinstance(roles, FinalizeArtifactRoles) or not isinstance(
            capabilities, FinalizeCapabilities
        ):
            _fail("finalize input has invalid type")
        values = [value for value in roles.__dict__.values() if value is not None]
        if len(values) != len(set(values)) or any(
            not isinstance(value, str)
            or _ID.fullmatch(value) is None
            or value in _SIDECAR_NAMES
            for value in values
        ):
            _fail("finalize artifact role names are invalid or duplicated")
        grants = {
            "validate-run-artifacts": self._grant(
                capabilities.validate_run_artifacts, "validate-run-artifacts"
            ),
            "append-domain-log": self._grant(
                capabilities.append_domain_log, "append-domain-log"
            ),
            "append-run-trace": self._grant(
                capabilities.append_run_trace, "append-run-trace"
            ),
            "commit-bounded-metrics": self._grant(
                capabilities.commit_bounded_metrics, "commit-bounded-metrics"
            ),
            "emit-semantic-outbox-event": self._grant(
                capabilities.emit_semantic_outbox_event,
                "emit-semantic-outbox-event",
            ),
            "finalize-run-state": self._grant(
                capabilities.finalize_run_state, "finalize-run-state"
            ),
        }
        if capabilities.read_review_outcome is None:
            _fail("finalize requires the canonical read-review-outcome capability")
        grants["read-review-outcome"] = self._grant(
            capabilities.read_review_outcome, "read-review-outcome"
        )
        return grants

    def _read_committed(self, artifact: CommittedArtifact) -> bytes:
        checked = PurePosixPath(artifact.relative)
        try:
            base = self._resolver.resolve(artifact.zone, must_exist=True)
            expected = self._resolver.resolve(artifact.zone, checked, must_exist=True)
            current_fd = os.open(
                base,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
            base_fd = current_fd
            for part in checked.parts[:-1]:
                child_fd = os.open(
                    part,
                    os.O_RDONLY
                    | getattr(os, "O_DIRECTORY", 0)
                    | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=current_fd,
                )
                if current_fd != base_fd:
                    os.close(current_fd)
                current_fd = child_fd
            file_fd = os.open(
                checked.parts[-1],
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=current_fd,
            )
            opened = os.fstat(file_fd)
            named = os.stat(checked.parts[-1], dir_fd=current_fd, follow_symlinks=False)
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_size > _MAX_ARTIFACT_BYTES
                or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
            ):
                _fail("committed artifact is not a bounded regular file")
            chunks: list[bytes] = []
            remaining = _MAX_ARTIFACT_BYTES + 1
            while remaining:
                block = os.read(file_fd, min(64 * 1024, remaining))
                if not block:
                    break
                chunks.append(block)
                remaining -= len(block)
            raw = b"".join(chunks)
            if remaining == 0 or hashlib.sha256(raw).hexdigest() != artifact.sha256:
                _fail("committed artifact bytes changed after run snapshot")
            final = os.fstat(file_fd)
            if (final.st_dev, final.st_ino, final.st_size, final.st_mtime_ns) != (
                opened.st_dev,
                opened.st_ino,
                opened.st_size,
                opened.st_mtime_ns,
            ):
                _fail("committed artifact changed while read")
            self._resolver.revalidate(expected, artifact.zone, checked, must_exist=True)
            return raw
        except (OSError, VaultSchemaError, FinalizeError):
            raise FinalizeError("committed artifact cannot be read safely") from None
        finally:
            if "file_fd" in locals():
                os.close(file_fd)
            if "current_fd" in locals() and current_fd != base_fd:
                os.close(current_fd)
            if "base_fd" in locals():
                os.close(base_fd)

    @staticmethod
    def _state_hash(state: Mapping[str, object]) -> str:
        return hashlib.sha256(
            json.dumps(
                state,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
        ).hexdigest()

    @staticmethod
    def _artifact_map(snapshot: RunSnapshot) -> dict[str, CommittedArtifact]:
        return {item.name: item for item in snapshot.artifacts}

    def _artifact(
        self, artifacts: Mapping[str, CommittedArtifact], name: str | None, role: str
    ) -> tuple[CommittedArtifact, bytes]:
        if name is None or name not in artifacts:
            _fail(f"finalize requires committed {role} artifact evidence")
        artifact = artifacts[name]
        return artifact, self._read_committed(artifact)

    def _physical_ref(self, zone: str, relative: str) -> str:
        physical = self._ref_zone_paths.get(zone)
        if physical is None:
            _fail("finalize ref zone is unsupported")
        checked = PurePosixPath(_safe_ref(relative, "producer output relative"))
        return (physical / checked).as_posix()

    def _read_ref(self, ref: str, maximum: int = _MAX_ARTIFACT_BYTES) -> bytes:
        checked_ref = _safe_ref(ref, "producer output reference")
        ref_path = PurePosixPath(checked_ref)
        matches = [
            (zone, physical)
            for zone, physical in self._ref_zone_paths.items()
            if ref_path.parts[: len(physical.parts)] == physical.parts
            and len(ref_path.parts) > len(physical.parts)
        ]
        if len(matches) != 1:
            _fail("producer output reference is outside finalizable zones")
        zone, physical = matches[0]
        checked = PurePosixPath(*ref_path.parts[len(physical.parts) :])
        file_fd: int | None = None
        directory_fds: list[int] = []
        edges: list[tuple[int, str, int, tuple[int, int]]] = []
        try:
            expected = self._resolver.resolve(zone, checked, must_exist=True)
            if expected != self._ref_root.joinpath(*ref_path.parts):
                _fail("producer output reference is not its configured physical path")
            root_fd = os.open(
                self._ref_root,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
            directory_fds.append(root_fd)
            opened_root = os.fstat(root_fd)
            named_root = os.stat(self._ref_root, follow_symlinks=False)
            if (
                not stat.S_ISDIR(opened_root.st_mode)
                or (opened_root.st_dev, opened_root.st_ino) != self._ref_root_identity
                or (named_root.st_dev, named_root.st_ino) != self._ref_root_identity
            ):
                _fail("producer output vault root identity changed")
            current_fd = root_fd
            prefix: list[str] = []
            for part in ref_path.parts[:-1]:
                prefix.append(part)
                child_fd = os.open(
                    part,
                    os.O_RDONLY
                    | getattr(os, "O_DIRECTORY", 0)
                    | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=current_fd,
                )
                directory_fds.append(child_fd)
                opened_parent = os.fstat(child_fd)
                named_parent = os.stat(part, dir_fd=current_fd, follow_symlinks=False)
                identity = (opened_parent.st_dev, opened_parent.st_ino)
                if not stat.S_ISDIR(opened_parent.st_mode) or identity != (
                    named_parent.st_dev,
                    named_parent.st_ino,
                ):
                    _fail("producer output parent identity changed while opening")
                anchored = self._ref_parent_anchors.get(tuple(prefix))
                if anchored is not None and identity != anchored:
                    _fail("producer output anchored parent identity changed")
                edges.append((current_fd, part, child_fd, identity))
                current_fd = child_fd
            file_fd = os.open(
                ref_path.parts[-1],
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=current_fd,
            )
            opened = os.fstat(file_fd)
            named = os.stat(
                ref_path.parts[-1], dir_fd=current_fd, follow_symlinks=False
            )
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_size > maximum
                or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
            ):
                _fail("producer output is not a bounded regular file")
            chunks: list[bytes] = []
            remaining = maximum + 1
            while remaining:
                block = os.read(file_fd, min(64 * 1024, remaining))
                if not block:
                    break
                chunks.append(block)
                remaining -= len(block)
            if remaining == 0:
                _fail("producer output is too large")
            final = os.fstat(file_fd)
            if (
                final.st_dev,
                final.st_ino,
                final.st_size,
                final.st_mtime_ns,
                final.st_ctime_ns,
            ) != (
                opened.st_dev,
                opened.st_ino,
                opened.st_size,
                opened.st_mtime_ns,
                opened.st_ctime_ns,
            ):
                _fail("producer output changed while read")
            final_named = os.stat(
                ref_path.parts[-1], dir_fd=current_fd, follow_symlinks=False
            )
            if (final_named.st_dev, final_named.st_ino) != (
                opened.st_dev,
                opened.st_ino,
            ):
                _fail("producer output leaf identity changed while read")
            for parent_fd, name, child_fd, identity in edges:
                final_child = os.fstat(child_fd)
                final_edge = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                if (final_child.st_dev, final_child.st_ino) != identity or (
                    final_edge.st_dev,
                    final_edge.st_ino,
                ) != identity:
                    _fail("producer output parent identity changed while read")
            final_root = os.fstat(root_fd)
            final_named_root = os.stat(self._ref_root, follow_symlinks=False)
            if (final_root.st_dev, final_root.st_ino) != self._ref_root_identity or (
                final_named_root.st_dev,
                final_named_root.st_ino,
            ) != self._ref_root_identity:
                _fail("producer output vault root identity changed while read")
            self._resolver.revalidate(expected, zone, checked, must_exist=True)
            return b"".join(chunks)
        except (OSError, VaultSchemaError, FinalizeError):
            raise FinalizeError("producer output cannot be read safely") from None
        finally:
            if file_fd is not None:
                os.close(file_fd)
            for directory_fd in reversed(directory_fds):
                os.close(directory_fd)

    def _producer_trace(
        self, snapshot: RunSnapshot, artifact: CommittedArtifact
    ) -> Mapping[str, object]:
        try:
            matches = tuple(
                event
                for event in self._runs.trace_events(str(snapshot.state["run_id"]))
                if event.get("step_id") == artifact.step_id
            )
        except RunError as error:
            raise FinalizeError("producer trace cannot be validated") from error
        if len(matches) != 1:
            _fail("producer evidence lacks one exact trace step")
        return matches[0]

    @staticmethod
    def _require_trace_binding(
        trace: Mapping[str, object], *, input_hash: str, output_hash: str
    ) -> None:
        if (
            trace.get("input_hash") != input_hash
            or trace.get("output_hash") != output_hash
        ):
            _fail("producer evidence disagrees with its exact trace binding")

    @staticmethod
    def _require_exact_producer_trace(
        snapshot: RunSnapshot,
        trace: Mapping[str, object],
        *,
        step_id: str,
        authority: str,
        input_hash: str,
        output_hash: str,
        action_ids: Sequence[str],
    ) -> None:
        if (
            trace.get("schema_version") != 2
            or trace.get("run_id") != snapshot.state.get("run_id")
            or trace.get("step_id") != step_id
            or trace.get("authority") != authority
            or trace.get("input_hash") != input_hash
            or trace.get("output_hash") != output_hash
            or trace.get("executor_profile") != snapshot.state.get("executor")
            or trace.get("tool_outcomes") != []
        ):
            _fail("producer evidence lacks its exact committed trace")
        actions = trace.get("actions")
        if not isinstance(actions, list) or len(actions) != len(action_ids):
            _fail("producer evidence action trace is incomplete")
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
            (sequence, str(snapshot.state["flow"]), action_id, "succeeded")
            for sequence, action_id in enumerate(action_ids, start=1)
        )
        if actual != expected:
            _fail("producer evidence action trace is not exact")

    @staticmethod
    def _artifact_by_ref(
        artifacts: Mapping[str, CommittedArtifact],
        *,
        state_ref: str,
        sha256: str,
        name: str,
    ) -> CommittedArtifact:
        matches = tuple(
            item for item in artifacts.values() if item.state_ref == state_ref
        )
        if len(matches) != 1 or matches[0].name != name or matches[0].sha256 != sha256:
            _fail("producer bundle artifact binding is invalid")
        return matches[0]

    def _producer_base(
        self, snapshot: RunSnapshot, evidence_name: str
    ) -> tuple[
        CommittedArtifact, bytes, Mapping[str, CommittedArtifact], Mapping[str, object]
    ]:
        artifacts = self._artifact_map(snapshot)
        evidence, raw = self._artifact(artifacts, evidence_name, "producer evidence")
        if any(item.step_id != evidence.step_id for item in snapshot.artifacts):
            _fail("producer bundle mixes semantic steps")
        trace = self._producer_trace(snapshot, evidence)
        return evidence, raw, artifacts, trace

    def _project_outcome(
        self, snapshot: RunSnapshot, evidence_name: str
    ) -> _ProducerOutcome:
        evidence, raw, artifacts, trace = self._producer_base(snapshot, evidence_name)
        keys = frozenset(
            {
                "schema_version",
                "transition_id",
                "operation",
                "request_sha256",
                "location",
                "snapshot_sha256",
                "archived_children",
                "child_policy",
                "schedule_observation",
                "schedule_receipt",
            }
        )
        item = _exact_json(raw, "project producer evidence", keys)
        transition = _identifier(item["transition_id"], "project transition_id")
        operation = _text(item["operation"], "project operation", maximum=16)
        if operation not in {"create", "advance", "hold", "resume", "archive"}:
            _fail("project producer operation is unsupported")
        if (
            item["schema_version"] != 1
            or type(item["schema_version"]) is not int
            or evidence.name != "project_transition"
            or evidence.zone != "projects"
            or evidence.relative != f".lifeos-project-evidence/{transition}.json"
            or evidence.state_ref != f"projects/{evidence.relative}"
            or evidence.step_id != transition
        ):
            _fail("project producer artifact binding is invalid")
        _safe_ref(item["location"], "project location")
        request_hash = _hash(item["request_sha256"], "project request_sha256")
        _hash(item["snapshot_sha256"], "project snapshot_sha256")
        if not isinstance(item["archived_children"], list) or not isinstance(
            item["schedule_observation"], list
        ):
            _fail("project producer evidence lists are invalid")
        if item["child_policy"] is not None and not isinstance(
            item["child_policy"], str
        ):
            _fail("project child policy is invalid")
        if item["schedule_receipt"] is not None and not isinstance(
            item["schedule_receipt"], Mapping
        ):
            _fail("project schedule receipt is invalid")
        self._require_trace_binding(
            trace, input_hash=request_hash, output_hash=evidence.sha256
        )
        return _ProducerOutcome(
            operation,
            "domain-updated",
            "succeeded",
            tuple(artifacts.values()),
            evidence.step_id,
            _bundle_sha256(snapshot.artifacts),
            self._resolver.config.surface,
        )

    def _entities_outcome(
        self, snapshot: RunSnapshot, evidence_name: str
    ) -> _ProducerOutcome:
        evidence, raw, artifacts, trace = self._producer_base(snapshot, evidence_name)
        keys = frozenset(
            {
                "schema_version",
                "flow",
                "family",
                "operation_id",
                "request_sha256",
                "expected_output_sha256",
                "request",
            }
        )
        item = _exact_json(raw, "entities producer evidence", keys)
        family = _text(item["family"], "entities family", maximum=16)
        operation = _identifier(item["operation_id"], "entities operation_id")
        if family not in {"entity", "done", "trail"} or not isinstance(
            item["request"], Mapping
        ):
            _fail("entities producer evidence is invalid")
        if family == "entity":
            producer_operation = "entity-" + _text(
                item["request"].get("operation"),
                "entity operation",
                maximum=24,
            )
        else:
            producer_operation = f"{family}-append"
        request_raw = _canonical_bytes(dict(item["request"]), _MAX_ARTIFACT_BYTES)
        request_hash = _hash(item["request_sha256"], "entities request_sha256")
        output_hash = _hash(
            item["expected_output_sha256"], "entities expected_output_sha256"
        )
        token = hashlib.sha256((family + ":" + operation).encode()).hexdigest()
        if (
            item["schema_version"] != 1
            or type(item["schema_version"]) is not int
            or item["flow"] != "entities"
            or request_hash != hashlib.sha256(request_raw).hexdigest()
            or evidence.name != f"entities-{token[:24]}"
            or evidence.zone != "agent/runs"
            or PurePosixPath(evidence.relative).name != f"{evidence.name}.json"
            or evidence.step_id
            != f"{family}-{hashlib.sha256(operation.encode()).hexdigest()[:32]}"
        ):
            _fail("entities producer artifact binding is invalid")
        self._require_trace_binding(
            trace, input_hash=request_hash, output_hash=output_hash
        )
        return _ProducerOutcome(
            producer_operation,
            "domain-updated",
            "succeeded",
            tuple(artifacts.values()),
            evidence.step_id,
            _bundle_sha256(snapshot.artifacts),
            self._resolver.config.surface,
        )

    def _plan_outcome(
        self, snapshot: RunSnapshot, evidence_name: str
    ) -> _ProducerOutcome:
        evidence, raw, artifacts, trace = self._producer_base(snapshot, evidence_name)
        keys = frozenset(
            {
                "schema_version",
                "flow",
                "operation",
                "operation_id",
                "request",
                "packet",
                "targets",
                "preimages",
                "skipped_events",
                "feedback_proposal",
                "result_kind",
                "result_period",
                "output_sha256",
            }
        )
        item = _exact_json(raw, "plan producer evidence", keys)
        operation = _text(item["operation"], "plan operation", maximum=32)
        operation_id = _identifier(item["operation_id"], "plan operation_id")
        if operation not in {"commit-day", "commit-week", "skip-task", "rollover-day"}:
            _fail("plan producer operation is unsupported")
        if (
            item["schema_version"] != 1
            or type(item["schema_version"]) is not int
            or item["flow"] != "plan"
            or not isinstance(item["request"], Mapping)
            or not isinstance(item["targets"], list)
            or not isinstance(item["skipped_events"], list)
        ):
            _fail("plan producer evidence is invalid")
        targets: list[dict[str, str]] = []
        for raw_target in item["targets"]:
            if not isinstance(raw_target, Mapping) or set(raw_target) != {
                "relative",
                "maximum",
                "sha256",
                "bytes_base64",
            }:
                _fail("plan target evidence is invalid")
            relative = _safe_ref(raw_target["relative"], "plan target relative")
            target_hash = _hash(raw_target["sha256"], "plan target sha256")
            if (
                type(raw_target["maximum"]) is not int
                or not 1 <= raw_target["maximum"] <= 4 * 1024 * 1024
            ):
                _fail("plan target bound is invalid")
            try:
                decoded = base64.b64decode(raw_target["bytes_base64"], validate=True)
            except (TypeError, ValueError):
                _fail("plan target bytes are invalid")
            if (
                base64.b64encode(decoded).decode("ascii") != raw_target["bytes_base64"]
                or len(decoded) > raw_target["maximum"]
                or hashlib.sha256(decoded).hexdigest() != target_hash
            ):
                _fail("plan target bytes disagree with their binding")
            targets.append({"relative": relative, "sha256": target_hash})
        output_binding = {
            "targets": targets,
            "skipped_events": item["skipped_events"],
            "feedback_proposal": item["feedback_proposal"],
        }
        output_hash = _hash(item["output_sha256"], "plan output_sha256")
        request_hash = hashlib.sha256(
            _canonical_bytes(dict(item["request"]), _MAX_ARTIFACT_BYTES)
        ).hexdigest()
        token = hashlib.sha256(operation_id.encode()).hexdigest()[:32]
        if (
            output_hash
            != hashlib.sha256(
                _canonical_bytes(output_binding, _MAX_ARTIFACT_BYTES)
            ).hexdigest()
            or evidence.name != f"plan-evidence-{token}"
            or evidence.zone != "agent/runs"
            or PurePosixPath(evidence.relative).name != f"{evidence.name}.json"
            or evidence.step_id != f"plan-{token}"
        ):
            _fail("plan producer artifact binding is invalid")
        self._require_trace_binding(
            trace, input_hash=request_hash, output_hash=output_hash
        )
        return _ProducerOutcome(
            operation,
            "domain-updated",
            "succeeded",
            tuple(artifacts.values()),
            evidence.step_id,
            _bundle_sha256(snapshot.artifacts),
            self._resolver.config.surface,
        )

    @staticmethod
    def _proposal_state(
        *,
        status: str,
        sequence: int | None,
        decision_sha256: str,
        pending_kind: str,
        pending_id: str,
    ) -> tuple[str, str, str | None, str | None, str, int | None, str]:
        if status == "proposed":
            if sequence is not None:
                _fail("proposed artifact cannot have a decision sequence")
            return (
                "proposal-ready",
                "waiting_human",
                pending_kind,
                pending_id,
                status,
                None,
                decision_sha256,
            )
        if status not in {"approved", "rejected", "superseded", "applied"}:
            _fail("producer proposal status is invalid")
        if sequence is None or sequence < 1:
            _fail("decided producer proposal lacks decision sequence")
        return (
            _decision_kind(status),
            "succeeded",
            None,
            None,
            status,
            sequence,
            decision_sha256,
        )

    def _book_outcome(
        self, snapshot: RunSnapshot, evidence_name: str
    ) -> _ProducerOutcome:
        evidence, raw, artifacts, trace = self._producer_base(snapshot, evidence_name)
        keys = frozenset(
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
        item = _exact_json(raw, "book producer evidence", keys)
        request = item["request"]
        if not isinstance(request, Mapping) or set(request) != {
            "command",
            "source_manifest",
        }:
            _fail("book request evidence is invalid")
        if not isinstance(request["command"], Mapping) or not isinstance(
            request["source_manifest"], Mapping
        ):
            _fail("book request evidence is invalid")
        try:
            command = parse_book_command(
                _canonical_bytes(dict(request["command"]), _MAX_ARTIFACT_BYTES)
            )
            parse_book_source_manifest(
                _canonical_bytes(dict(request["source_manifest"]), _MAX_ARTIFACT_BYTES)
            )
            target = parse_reading_state(
                _canonical_bytes(dict(item["target_state"]), _MAX_ARTIFACT_BYTES)
            )
            if item["base_state"] is not None:
                if not isinstance(item["base_state"], Mapping):
                    _fail("book base state evidence is invalid")
                base_raw = _canonical_bytes(
                    dict(item["base_state"]), _MAX_ARTIFACT_BYTES
                )
                parse_reading_state(base_raw)
                if hashlib.sha256(base_raw).hexdigest() != _hash(
                    item["base_state_sha256"], "book base_state_sha256"
                ):
                    _fail("book base state hash is invalid")
            elif item["base_state_sha256"] is not None:
                _fail("book base state evidence is incomplete")
        except BookFlowError as error:
            raise FinalizeError(
                "book producer evidence violates its public schema"
            ) from error
        request_hash = _hash(item["request_sha256"], "book request_sha256")
        if (
            request_hash
            != hashlib.sha256(
                _canonical_bytes(dict(request), _MAX_ARTIFACT_BYTES)
            ).hexdigest()
        ):
            _fail("book request hash is invalid")
        if not isinstance(item["log_block"], str) or hashlib.sha256(
            item["log_block"].encode("utf-8")
        ).hexdigest() != _hash(item["log_block_sha256"], "book log_block_sha256"):
            _fail("book log block binding is invalid")
        token = hashlib.sha256(command.mutation_id.encode("ascii")).hexdigest()[:40]
        if (
            item["schema_version"] != 1
            or type(item["schema_version"]) is not int
            or item["flow"] != "book"
            or command.run_id != snapshot.state["run_id"]
            or target.last_mutation_id != command.mutation_id
            or target.last_mutation_sha256 != request_hash
            or evidence.name != f"book-{token}"
            or evidence.zone != "agent/runs"
            or PurePosixPath(evidence.relative).name != f"{evidence.name}.json"
            or evidence.step_id != evidence.name
        ):
            _fail("book producer artifact binding is invalid")
        self._require_trace_binding(
            trace, input_hash=request_hash, output_hash=evidence.sha256
        )
        source = tuple(artifacts.values())
        bundle_hash = _bundle_sha256(snapshot.artifacts)
        if command.operation != "anchor":
            if item["review_sha256"] is not None or item["plan_sha256"] is not None:
                _fail("non-anchor book evidence contains a proposal")
            if set(artifacts) != {evidence.name}:
                _fail("non-anchor book producer bundle has extra artifacts")
            return _ProducerOutcome(
                command.operation,
                "domain-updated",
                "succeeded",
                source,
                evidence.step_id,
                bundle_hash,
                self._resolver.config.surface,
            )

        review_name = f"book-review-{token}"
        plan_name = f"book-plan-{token}"
        if set(artifacts) != {evidence.name, review_name, plan_name}:
            _fail("book anchor producer bundle is incomplete")
        review_evidence, review_raw = self._artifact(
            artifacts, review_name, "book review"
        )
        plan_evidence, plan_raw = self._artifact(artifacts, plan_name, "book plan")
        original_review_hash = _hash(item["review_sha256"], "book review_sha256")
        original_plan_hash = _hash(item["plan_sha256"], "book plan_sha256")
        if plan_evidence.sha256 != original_plan_hash:
            _fail("book plan changed after producer commit")
        try:
            current_review = parse_review_artifact(review_raw)
            current_plan = parse_mutation_plan(plan_raw)
            validate_artifact_plan(current_review, current_plan)
            if len(current_review.decisions) > 1:
                _fail("book review decision is stale relative to its producer proposal")
            proposed = replace(
                current_review,
                status="proposed",
                decisions=(),
                application=None,
            )
            proposed_raw = render_review_artifact(proposed).encode("utf-8")
        except ReviewArtifactError as error:
            raise FinalizeError(
                "book review decision violates the review contract"
            ) from error
        if (
            current_review.flow != "book"
            or current_review.provenance.run_id != snapshot.state["run_id"]
            or hashlib.sha256(proposed_raw).hexdigest() != original_review_hash
            or hashlib.sha256(review_raw).hexdigest() != review_evidence.sha256
            or current_review.plan_path != plan_evidence.state_ref
        ):
            _fail("book review decision does not derive from the producer proposal")
        sequence = (
            None
            if not current_review.decisions
            else current_review.decisions[-1].sequence
        )
        decision_hash = hashlib.sha256(review_raw).hexdigest()
        (
            kind,
            terminal,
            pending_kind,
            pending_id,
            decision_status,
            decision_sequence,
            decision_sha,
        ) = self._proposal_state(
            status=current_review.status,
            sequence=sequence,
            decision_sha256=decision_hash,
            pending_kind="review",
            pending_id=current_review.review_id,
        )
        return _ProducerOutcome(
            command.operation,
            kind,
            terminal,
            source,
            evidence.step_id,
            bundle_hash,
            current_review.surface,
            pending_kind,
            pending_id,
            decision_status,
            decision_sequence,
            decision_sha,
        )

    def _memory_proposal_state(
        self,
        *,
        raw: bytes,
        original_sha256: str,
        producer_flow: str,
        run_id: str,
        operation_id: str,
    ) -> tuple[str, str, str | None, str | None, str, int | None, str]:
        try:
            from tool_life_os_runtime.ext.flows.memory import (
                MemoryFlowError,
                parse_memory_proposal,
                render_memory_proposal,
            )
        except ImportError as error:
            raise FinalizeError("memory proposal inspector is unavailable") from error
        try:
            proposal = parse_memory_proposal(raw)
            proposed = replace(
                proposal,
                status="proposed",
                human_decision=None,
            )
            proposed_raw = render_memory_proposal(proposed)
        except MemoryFlowError as error:
            raise FinalizeError(
                "memory proposal violates its accepted schema"
            ) from error
        if (
            proposal.producer_flow != producer_flow
            or proposal.run_id != run_id
            or proposal.operation_id != operation_id
            or hashlib.sha256(proposed_raw).hexdigest() != original_sha256
        ):
            _fail("memory proposal does not derive from producer evidence")
        sequence = (
            None
            if proposal.human_decision is None
            else proposal.human_decision.sequence
        )
        return self._proposal_state(
            status=proposal.status,
            sequence=sequence,
            decision_sha256=hashlib.sha256(raw).hexdigest(),
            pending_kind="memory-proposal",
            pending_id=proposal.proposal_id,
        )

    def _report_outcome(
        self, snapshot: RunSnapshot, evidence_name: str
    ) -> _ProducerOutcome:
        evidence, raw, artifacts, trace = self._producer_base(snapshot, evidence_name)
        try:
            from tool_life_os_runtime.ext.flows.report import (
                ReportFlowError,
                inspect_report_run_evidence,
            )
        except ImportError as error:
            raise FinalizeError("report evidence inspector is unavailable") from error
        try:
            record = inspect_report_run_evidence(evidence, raw)
        except ReportFlowError as error:
            raise FinalizeError(
                "report evidence violates its accepted inspector"
            ) from error
        # Report trace input is its request hash; run_state_sha256 is an
        # independent snapshot precondition retained in the evidence.
        if record.request_sha256 != trace.get("input_hash"):
            _fail("report evidence disagrees with its producer trace")
        if trace.get("output_hash") != evidence.sha256:
            _fail("report evidence output hash is invalid")
        if set(artifacts) != {evidence.name}:
            _fail("report producer bundle has extra artifacts")
        source = tuple(artifacts.values())
        bundle_hash = _bundle_sha256(snapshot.artifacts)
        if record.operation in {"daily", "weekly"}:
            output = self._read_ref(record.output_ref, 4 * 1024 * 1024)
            if not any(
                hashlib.sha256(line + b"\n").hexdigest() == record.log_line_sha256
                for line in output.splitlines()
            ):
                _fail("report log no longer contains its exact committed line")
            return _ProducerOutcome(
                record.operation,
                "report-ready",
                "succeeded",
                source,
                evidence.step_id,
                bundle_hash,
                self._resolver.config.surface,
            )
        if (
            record.operation != "extract"
            or record.proposal_ref is None
            or record.proposal_sha256 is None
        ):
            _fail("report extraction evidence is incomplete")
        proposal_raw = self._read_ref(record.proposal_ref)
        decision = self._memory_proposal_state(
            raw=proposal_raw,
            original_sha256=record.proposal_sha256,
            producer_flow="report",
            run_id=str(snapshot.state["run_id"]),
            operation_id=record.operation_id,
        )
        return _ProducerOutcome(
            record.operation,
            decision[0],
            decision[1],
            source,
            evidence.step_id,
            bundle_hash,
            self._resolver.config.surface,
            *decision[2:],
        )

    def _memory_outcome(
        self, snapshot: RunSnapshot, evidence_name: str
    ) -> _ProducerOutcome:
        evidence, raw, artifacts, trace = self._producer_base(snapshot, evidence_name)
        try:
            from tool_life_os_runtime.ext.flows.memory import (
                MemoryFlowError,
                inspect_memory_run_evidence,
                parse_forget_outcome,
                parse_memory_metadata,
            )
        except ImportError as error:
            raise FinalizeError("memory evidence inspector is unavailable") from error
        try:
            record = inspect_memory_run_evidence(evidence, raw)
        except MemoryFlowError as error:
            raise FinalizeError(
                "memory evidence violates its accepted inspector"
            ) from error
        self._require_trace_binding(
            trace, input_hash=record.request_sha256, output_hash=evidence.sha256
        )
        if set(artifacts) != {evidence.name}:
            _fail("memory producer bundle has extra artifacts")
        output = self._read_ref(record.output_ref)
        source = tuple(artifacts.values())
        bundle_hash = _bundle_sha256(snapshot.artifacts)
        if record.operation == "propose":
            decision = self._memory_proposal_state(
                raw=output,
                original_sha256=record.target_sha256,
                producer_flow="memory",
                run_id=str(snapshot.state["run_id"]),
                operation_id=record.operation_id,
            )
            return _ProducerOutcome(
                record.operation,
                decision[0],
                decision[1],
                source,
                evidence.step_id,
                bundle_hash,
                self._resolver.config.surface,
                *decision[2:],
            )
        if hashlib.sha256(output).hexdigest() != record.target_sha256:
            _fail("memory output changed after producer commit")
        try:
            if record.operation == "commit-metadata":
                parse_memory_metadata(output)
            elif record.operation == "forget":
                parse_forget_outcome(output)
            else:
                _fail("memory producer operation is unsupported")
        except MemoryFlowError as error:
            raise FinalizeError("memory output violates its accepted schema") from error
        return _ProducerOutcome(
            record.operation,
            "domain-updated",
            "succeeded",
            source,
            evidence.step_id,
            bundle_hash,
            self._resolver.config.surface,
        )

    def _mentor_outcome(
        self, snapshot: RunSnapshot, evidence_name: str
    ) -> _ProducerOutcome:
        evidence, raw, artifacts, trace = self._producer_base(snapshot, evidence_name)
        try:
            from tool_life_os_runtime.ext.flows.mentor import (
                MentorFlowError,
                inspect_mentor_run_evidence,
                mentor_task_artifact_name,
                parse_mentor_proposal,
                parse_mentor_task_packet,
            )
        except ImportError as error:
            raise FinalizeError("mentor evidence inspector is unavailable") from error
        try:
            record = inspect_mentor_run_evidence(evidence, raw)
            task_name = mentor_task_artifact_name(record.operation_id)
            task_artifact = artifacts[task_name]
            packet = parse_mentor_task_packet(self._read_committed(task_artifact))
            proposal_name = "mentor-review-" + record.output_sha256[:32]
            proposal_artifact = self._artifact_by_ref(
                artifacts,
                state_ref=record.output_ref,
                sha256=record.output_sha256,
                name=proposal_name,
            )
            proposal_raw = self._read_committed(proposal_artifact)
            proposal = parse_mentor_proposal(proposal_raw)
        except (KeyError, MentorFlowError) as error:
            raise FinalizeError(
                "mentor producer bundle violates its accepted schema"
            ) from error
        request = packet.request
        request_raw = _canonical_bytes(
            {
                "schema_version": request.schema_version,
                "run_id": request.run_id,
                "operation_id": request.operation_id,
                "proposal_id": request.proposal_id,
                "created_at": request.created_at,
                "focus": request.focus,
                "question": request.question,
                "project_refs": list(request.project_refs),
                "knowledge_refs": list(request.knowledge_refs),
                "memory_refs": list(request.memory_refs),
            },
            _MAX_ARTIFACT_BYTES,
        )
        anchors = tuple(
            (item.block_id, item.logical_ref, item.source_sha256)
            for item in proposal.evidence
        )
        blocks = tuple(
            (item.block_id, item.logical_ref, item.source_sha256)
            for item in packet.blocks
        )
        expected_names = {evidence.name, task_name, proposal_name}
        if (
            set(artifacts) != expected_names
            or task_artifact.sha256 != record.task_packet_sha256
            or hashlib.sha256(request_raw).hexdigest() != record.request_sha256
            or hashlib.sha256(proposal_raw).hexdigest() != record.output_sha256
            or request.run_id != snapshot.state["run_id"]
            or request.operation_id != record.operation_id
            or proposal.status != "proposed"
            or proposal.actor != "runtime"
            or proposal.run_id != request.run_id
            or proposal.operation_id != request.operation_id
            or proposal.proposal_id != request.proposal_id
            or proposal.created_at != request.created_at
            or proposal.focus != request.focus
            or proposal.question != request.question
            or proposal.task_packet_sha256 != record.task_packet_sha256
            or proposal.context != packet.manifest
            or anchors != blocks
        ):
            _fail("mentor proposal, task, and evidence bindings are inconsistent")
        step_id = (
            "mentor-" + hashlib.sha256(record.operation_id.encode()).hexdigest()[:32]
        )
        self._require_exact_producer_trace(
            snapshot,
            trace,
            step_id=step_id,
            authority="proposal",
            input_hash=record.request_sha256,
            output_hash=record.output_sha256,
            action_ids=(
                "collect-bounded-mentor-context",
                "read-mentor-knowledge",
                "read-mentor-memory",
                "commit-mentor-proposal",
                "record-run-state",
            ),
        )
        return _ProducerOutcome(
            "proposal",
            "proposal-ready",
            "waiting_human",
            tuple(artifacts.values()),
            evidence.step_id,
            _bundle_sha256(snapshot.artifacts),
            self._resolver.config.surface,
            "mentor-proposal",
            proposal.proposal_id,
            "proposed",
            None,
            record.output_sha256,
        )

    def _grill_outcome(
        self, snapshot: RunSnapshot, evidence_name: str
    ) -> _ProducerOutcome:
        evidence, raw, artifacts, trace = self._producer_base(snapshot, evidence_name)
        try:
            from tool_life_os_runtime.ext.flows.grill_me import (
                GrillFlowError,
                inspect_grill_run_evidence,
                parse_grill_decision_record,
                parse_grill_session,
            )
        except ImportError as error:
            raise FinalizeError("grill evidence inspector is unavailable") from error
        try:
            record = inspect_grill_run_evidence(evidence, raw)
            session_artifact = next(
                item
                for item in artifacts.values()
                if item.state_ref == record.session_ref
            )
            if session_artifact.sha256 != record.session_sha256:
                _fail("grill session hash disagrees with producer evidence")
            session = parse_grill_session(self._read_committed(session_artifact))
            proposal_name = "grill-review-" + record.output_sha256[:32]
            proposal_artifact = self._artifact_by_ref(
                artifacts,
                state_ref=record.output_ref,
                sha256=record.output_sha256,
                name=proposal_name,
            )
            proposal_raw = self._read_committed(proposal_artifact)
            proposal = parse_grill_decision_record(proposal_raw)
        except (StopIteration, GrillFlowError) as error:
            raise FinalizeError(
                "grill producer bundle violates its accepted schema"
            ) from error
        expected_names = {evidence.name, session_artifact.name, proposal_name}
        if (
            set(artifacts) != expected_names
            or session.status != "complete"
            or proposal.status != "proposed"
            or proposal.actor != "human"
            or proposal.run_id != session.run_id
            or proposal.operation_id != session.operation_id
            or proposal.record_id != session.record_id
            or proposal.created_at != session.created_at
            or proposal.topic != session.topic
            or proposal.request_sha256 != session.request_sha256
            or proposal.context != session.context
            or proposal.evidence != session.blocks
            or proposal.turns != session.turns
            or proposal.resolution != session.resolution
            or proposal.explicit_decision != session.explicit_decision
            or session.run_id != snapshot.state["run_id"]
            or session.operation_id != record.operation_id
            or session.request_sha256 != record.request_sha256
            or hashlib.sha256(proposal_raw).hexdigest() != record.output_sha256
        ):
            _fail("grill session, proposal, and evidence bindings are inconsistent")
        if session.explicit_decision is None:
            trace_input = hashlib.sha256(b"unresolved").hexdigest()
        else:
            decision = session.explicit_decision
            trace_input = hashlib.sha256(
                _canonical_bytes(
                    {
                        "schema_version": decision.schema_version,
                        "decision_id": decision.decision_id,
                        "actor": decision.actor,
                        "decided_at": decision.decided_at,
                        "exact_text": decision.exact_text,
                    },
                    _MAX_ARTIFACT_BYTES,
                )
            ).hexdigest()
        step_id = (
            "grill-finish-"
            + hashlib.sha256(record.operation_id.encode()).hexdigest()[:27]
        )
        self._require_exact_producer_trace(
            snapshot,
            trace,
            step_id=step_id,
            authority="proposal",
            input_hash=trace_input,
            output_hash=record.output_sha256,
            action_ids=("commit-question-answer-record", "record-run-state"),
        )
        return _ProducerOutcome(
            "finish",
            "proposal-ready",
            "waiting_human",
            tuple(artifacts.values()),
            evidence.step_id,
            _bundle_sha256(snapshot.artifacts),
            self._resolver.config.surface,
            "grill-decision",
            proposal.record_id,
            "proposed",
            None,
            record.output_sha256,
        )

    def _lint_outcome(
        self, snapshot: RunSnapshot, evidence_name: str
    ) -> _ProducerOutcome:
        evidence, raw, artifacts, trace = self._producer_base(snapshot, evidence_name)
        try:
            from tool_life_os_runtime.ext.flows.lint import (
                LINT_ZONE_ORDER,
                LintFlowError,
                LintRequest,
                inspect_lint_run_evidence,
                parse_lint_review,
                render_lint_report,
                render_lint_request,
                render_lint_review,
            )
        except ImportError as error:
            raise FinalizeError("lint evidence inspector is unavailable") from error
        try:
            record = inspect_lint_run_evidence(evidence, raw)
            state_input = snapshot.state.get("input")
            if not isinstance(state_input, Mapping) or set(state_input) != {
                "apply_fixes",
                "mode",
                "zones",
            }:
                _fail("lint current run request is incomplete")
            zones = state_input["zones"]
            if not isinstance(zones, list):
                _fail("lint current run zones are invalid")
            request = LintRequest(
                schema_version=1,
                run_id=str(snapshot.state["run_id"]),
                mode=str(state_input["mode"]),
                zones=tuple(zones),
                apply_fixes=state_input["apply_fixes"],
            )
            request_raw = render_lint_request(request)
        except LintFlowError as error:
            raise FinalizeError(
                "lint producer bundle violates its accepted schema"
            ) from error
        if (
            set(artifacts) != {evidence.name}
            or request.zones != LINT_ZONE_ORDER
            or hashlib.sha256(request_raw).hexdigest() != record.request_sha256
            or record.report.run_id != snapshot.state["run_id"]
            or record.report.mode != request.mode
            or record.report.operation_id != record.operation_id
            or record.report.request_sha256 != record.request_sha256
        ):
            _fail("lint report and current request bindings are inconsistent")
        has_proposal = record.proposal_ref is not None
        if has_proposal != (record.proposal_sha256 is not None):
            _fail("lint proposal evidence is incomplete")
        action_ids = (
            "scan-inbox-zone",
            "scan-non-archive-zones",
            "scan-task-zone",
            "scan-project-zone",
            "scan-memory-zone",
        )
        if has_proposal:
            action_ids += ("commit-semantic-lint-findings",)
        action_ids += ("record-run-state",)
        self._require_exact_producer_trace(
            snapshot,
            trace,
            step_id=evidence.step_id,
            authority="proposal" if has_proposal else "internal-write",
            input_hash=record.request_sha256,
            output_hash=evidence.sha256,
            action_ids=action_ids,
        )
        source = tuple(artifacts.values())
        bundle_hash = _bundle_sha256(snapshot.artifacts)
        operation = "lint-" + record.report.mode
        if not has_proposal:
            return _ProducerOutcome(
                operation,
                "report-ready",
                "succeeded",
                source,
                evidence.step_id,
                bundle_hash,
                self._resolver.config.surface,
            )
        assert record.proposal_ref is not None and record.proposal_sha256 is not None
        proposal_relative = record.proposal_ref.removeprefix("review/")
        proposal_ref = self._physical_ref("review", proposal_relative)
        try:
            proposal_raw = self._read_ref(proposal_ref)
            proposal = parse_lint_review(proposal_raw)
        except LintFlowError as error:
            raise FinalizeError("lint proposal violates its accepted schema") from error
        expected_findings = tuple(
            item.finding_id
            for item in record.report.findings
            if item.resolution == "review"
        )
        proposed_view = replace(proposal, status="proposed", human_decision=None)
        proposed_sha = hashlib.sha256(render_lint_review(proposed_view)).hexdigest()
        if (
            proposal.run_id != snapshot.state["run_id"]
            or proposal.operation_id != record.operation_id
            or proposal.mode != record.report.mode
            or record.proposal_ref != f"review/{proposal.proposal_id}.lint.json"
            or proposal.report_ref != evidence.state_ref
            or proposal.report_sha256
            != hashlib.sha256(render_lint_report(record.report)).hexdigest()
            or proposal.finding_ids != expected_findings
            or proposed_sha != record.proposal_sha256
        ):
            _fail("lint proposal disagrees with final producer evidence")
        sequence = (
            None
            if proposal.human_decision is None
            else proposal.human_decision.sequence
        )
        decision = self._proposal_state(
            status=proposal.status,
            sequence=sequence,
            decision_sha256=hashlib.sha256(proposal_raw).hexdigest(),
            pending_kind="lint-proposal",
            pending_id=proposal.proposal_id,
        )
        decision_artifact = PreparedArtifact(
            "finalize-decision",
            "review",
            proposal_relative,
            proposal_ref,
            hashlib.sha256(proposal_raw).hexdigest(),
        )
        return _ProducerOutcome(
            operation,
            decision[0],
            decision[1],
            source,
            evidence.step_id,
            bundle_hash,
            self._resolver.config.surface,
            *decision[2:],
            decision_artifact=decision_artifact,
        )

    def _source_event(
        self,
        snapshot: RunSnapshot,
        artifact: CommittedArtifact,
        *,
        event_id: str,
        flow_id: str,
        action_id: str,
        actor: str,
        event_type: str,
        semantic_key: str,
        summary: str,
        payload_ref: str,
        payload_sha256: str,
        urgency: str,
        surface: str,
    ) -> Mapping[str, object]:
        event_raw, event_item = _decode(
            self._read_committed(artifact), "producer outbox event", _MAX_OUTCOME_BYTES
        )
        try:
            event = validate_event(event_item)
        except OutboxError as error:
            raise FinalizeError(
                "producer outbox event violates its accepted schema"
            ) from error
        expected_dedupe = semantic_dedupe_key(
            flow_id=flow_id,
            event_type=event_type,
            semantic_key=semantic_key,
            artifact_ref=payload_ref,
        )
        if (
            _canonical_bytes(event, _MAX_OUTCOME_BYTES) != event_raw
            or artifact.state_ref != f"agent/outbox/{event_id}.json"
            or event.get("event_id") != event_id
            or event.get("run_id") != snapshot.state["run_id"]
            or event.get("flow_id") != flow_id
            or event.get("action")
            != {
                "action_id": action_id,
                "actor": actor,
                "authority": "internal-write",
                "target": "vault:agent/outbox",
            }
            or event.get("type") != event_type
            or event.get("summary") != summary
            or event.get("artifact_ref") != payload_ref
            or event.get("artifact_sha256") != payload_sha256
            or event.get("urgency") != urgency
            or event.get("dedupe_key") != expected_dedupe
            or event.get("delivery_policy")
            != {"surface": surface, "requires_receipt": True}
            or event.get("status") != "pending"
        ):
            _fail("producer outbox event disagrees with its exact source binding")
        return event

    def _ambient_outcome(
        self, snapshot: RunSnapshot, evidence_name: str
    ) -> _ProducerOutcome:
        evidence, raw, artifacts, trace = self._producer_base(snapshot, evidence_name)
        try:
            from tool_life_os_runtime.ext.flows.ambient import (
                AmbientFlowError,
                inspect_ambient_run_evidence,
            )
        except ImportError as error:
            raise FinalizeError("ambient evidence inspector is unavailable") from error
        try:
            record = inspect_ambient_run_evidence(evidence, raw)
        except AmbientFlowError as error:
            raise FinalizeError(
                "ambient evidence violates its accepted inspector"
            ) from error
        if record.run_id != snapshot.state["run_id"] or record.outcome not in {
            "emitted",
            "zero",
        }:
            _fail("ambient outcome is not finalizable")
        action_ids = (
            "scan-eligible-signals",
            "read-ambient-projects",
            "read-ambient-review",
            "read-ambient-memory",
        )
        if record.outcome == "emitted":
            action_ids += ("commit-nudge-outbox-event",)
        action_ids += ("record-run-state",)
        self._require_exact_producer_trace(
            snapshot,
            trace,
            step_id=evidence.step_id,
            authority="internal-write",
            input_hash=record.request_sha256,
            output_hash=evidence.sha256,
            action_ids=action_ids,
        )
        if record.outcome == "zero":
            if set(artifacts) != {evidence.name}:
                _fail("zero ambient bundle contains non-evidence artifacts")
            return _ProducerOutcome(
                "zero",
                "domain-updated",
                "succeeded",
                tuple(artifacts.values()),
                evidence.step_id,
                _bundle_sha256(snapshot.artifacts),
                "silent",
            )
        assert record.selected is not None
        assert record.marker_ref is not None and record.marker_sha256 is not None
        assert record.payload_ref is not None and record.payload_sha256 is not None
        assert record.event_ref is not None and record.event_sha256 is not None
        assert record.event_id is not None
        token = hashlib.sha256(record.operation_id.encode()).hexdigest()
        marker_name = "ambient-marker-" + token[:24]
        payload_name = "ambient-payload-" + record.payload_sha256[:24]
        event_name = "ambient-event-" + record.event_id.removeprefix("event_")[:24]
        marker = self._artifact_by_ref(
            artifacts,
            state_ref=record.marker_ref,
            sha256=record.marker_sha256,
            name=marker_name,
        )
        payload = self._artifact_by_ref(
            artifacts,
            state_ref=record.payload_ref,
            sha256=record.payload_sha256,
            name=payload_name,
        )
        event = self._artifact_by_ref(
            artifacts,
            state_ref=record.event_ref,
            sha256=record.event_sha256,
            name=event_name,
        )
        expected_names = {evidence.name, marker_name, payload_name, event_name}
        selected = record.selected
        selected_payload = {
            "schema_version": selected.schema_version,
            "candidate_id": selected.candidate_id,
            "kind": selected.kind,
            "semantic_slot": selected.semantic_slot,
            "source_ref": selected.source_ref,
            "source_sha256": selected.source_sha256,
            "source_revision": selected.source_revision,
            "priority": selected.priority,
            "eligible_at": selected.eligible_at,
            "expires_at": selected.expires_at,
            "supersedes": selected.supersedes,
            "surface": selected.surface,
            "summary": selected.summary,
        }
        dispositions = [
            {
                "schema_version": item.schema_version,
                "candidate_id": item.candidate_id,
                "reason": item.reason,
            }
            for item in record.dispositions
        ]
        marker_item = _exact_unterminated_json(
            self._read_committed(marker),
            "ambient operation marker",
            frozenset(
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
                }
            ),
        )
        expected_marker = {
            "schema_version": 1,
            "kind": "ambient-operation",
            "request_sha256": record.request_sha256,
            "outcome": "emitted",
            "candidate_count": record.candidate_count,
            "review_debt": record.review_debt,
            "candidates_sha256": record.candidates_sha256,
            "selected": selected_payload,
            "dispositions": dispositions,
            "payload_ref": record.payload_ref,
            "payload_sha256": record.payload_sha256,
        }
        payload_item = _exact_unterminated_json(
            self._read_committed(payload),
            "ambient nudge payload",
            frozenset(
                {
                    "schema_version",
                    "kind",
                    "candidate_id",
                    "candidate_kind",
                    "priority",
                    "eligible_at",
                    "surface",
                    "summary",
                }
            ),
        )
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
        if (
            set(artifacts) != expected_names
            or dict(marker_item) != expected_marker
            or dict(payload_item) != expected_payload
        ):
            _fail("ambient marker and payload disagree with producer evidence")
        urgency = {
            "low": "low",
            "medium": "normal",
            "high": "high",
            "critical": "critical",
        }[selected.priority]
        self._source_event(
            snapshot,
            event,
            event_id=record.event_id,
            flow_id="ambient",
            action_id="commit-nudge-outbox-event",
            actor="system",
            event_type="ambient_nudge",
            semantic_key=f"ambient:v1:{selected.candidate_id}",
            summary=selected.summary,
            payload_ref=record.payload_ref,
            payload_sha256=record.payload_sha256,
            urgency=urgency,
            surface=selected.surface,
        )
        return _ProducerOutcome(
            "emitted",
            "domain-updated",
            "succeeded",
            tuple(artifacts.values()),
            evidence.step_id,
            _bundle_sha256(snapshot.artifacts),
            "silent",
        )

    def _bundle_outcome(
        self, snapshot: RunSnapshot, evidence_name: str
    ) -> _ProducerOutcome:
        evidence, raw, artifacts, trace = self._producer_base(snapshot, evidence_name)
        try:
            from tool_life_os_runtime.ext.flows.bundle import (
                BundleFlowError,
                inspect_bundle_run_evidence,
                parse_bundle_manifest,
            )
        except ImportError as error:
            raise FinalizeError("bundle evidence inspector is unavailable") from error
        try:
            record = inspect_bundle_run_evidence(evidence, raw)
        except BundleFlowError as error:
            raise FinalizeError(
                "bundle evidence violates its accepted inspector"
            ) from error
        if record.run_id != snapshot.state["run_id"] or record.outcome not in {
            "emitted",
            "empty",
        }:
            _fail("bundle outcome is not finalizable")
        action_ids = ("collect-batched-items", "read-pending-outbox")
        if record.outcome == "emitted":
            action_ids += ("commit-bundle-outbox-event",)
        action_ids += ("record-run-state",)
        self._require_exact_producer_trace(
            snapshot,
            trace,
            step_id=evidence.step_id,
            authority="internal-write",
            input_hash=record.request_sha256,
            output_hash=evidence.sha256,
            action_ids=action_ids,
        )
        if record.outcome == "empty":
            if set(artifacts) != {evidence.name}:
                _fail("empty bundle contains non-evidence artifacts")
            return _ProducerOutcome(
                "empty",
                "domain-updated",
                "succeeded",
                tuple(artifacts.values()),
                evidence.step_id,
                _bundle_sha256(snapshot.artifacts),
                "silent",
            )
        assert record.marker_ref is not None and record.marker_sha256 is not None
        assert record.payload_ref is not None and record.payload_sha256 is not None
        assert record.event_ref is not None and record.event_sha256 is not None
        assert record.event_id is not None
        token = hashlib.sha256(record.operation_id.encode()).hexdigest()
        marker_name = "bundle-marker-" + token[:24]
        payload_name = "bundle-payload-" + record.payload_sha256[:24]
        event_name = "bundle-event-" + record.event_id.removeprefix("event_")[:24]
        marker = self._artifact_by_ref(
            artifacts,
            state_ref=record.marker_ref,
            sha256=record.marker_sha256,
            name=marker_name,
        )
        payload = self._artifact_by_ref(
            artifacts,
            state_ref=record.payload_ref,
            sha256=record.payload_sha256,
            name=payload_name,
        )
        event = self._artifact_by_ref(
            artifacts,
            state_ref=record.event_ref,
            sha256=record.event_sha256,
            name=event_name,
        )
        expected_names = {evidence.name, marker_name, payload_name, event_name}
        try:
            manifest = parse_bundle_manifest(self._read_committed(payload))
        except BundleFlowError as error:
            raise FinalizeError(
                "bundle manifest violates its accepted schema"
            ) from error
        marker_item = _exact_unterminated_json(
            self._read_committed(marker),
            "bundle operation marker",
            frozenset(
                {
                    "schema_version",
                    "kind",
                    "request_sha256",
                    "item_count",
                    "batch_digest",
                    "payload_ref",
                    "payload_sha256",
                }
            ),
        )
        expected_marker = {
            "schema_version": 1,
            "kind": "bundle-operation",
            "request_sha256": record.request_sha256,
            "item_count": record.item_count,
            "batch_digest": record.batch_digest,
            "payload_ref": record.payload_ref,
            "payload_sha256": record.payload_sha256,
        }
        if (
            set(artifacts) != expected_names
            or dict(marker_item) != expected_marker
            or manifest.batch_digest != record.batch_digest
            or len(manifest.items) != record.item_count
        ):
            _fail("bundle marker and payload disagree with producer evidence")
        self._source_event(
            snapshot,
            event,
            event_id=record.event_id,
            flow_id="bundle",
            action_id="commit-bundle-outbox-event",
            actor="system",
            event_type="batched_digest",
            semantic_key=(
                f"bundle:v1:{manifest.window.start}:{manifest.window.end}:"
                f"{manifest.batch_digest}"
            ),
            summary=f"{len(manifest.items)} batched Life OS items are ready.",
            payload_ref=record.payload_ref,
            payload_sha256=record.payload_sha256,
            urgency="normal",
            surface="gated",
        )
        return _ProducerOutcome(
            "emitted",
            "domain-updated",
            "succeeded",
            tuple(artifacts.values()),
            evidence.step_id,
            _bundle_sha256(snapshot.artifacts),
            "silent",
        )

    def _derive_p3(
        self, snapshot: RunSnapshot, evidence_name: str, observed_at: str
    ) -> tuple[
        OutcomeRecord,
        MetricRecord,
        tuple[CommittedArtifact, ...],
        str,
        PreparedArtifact | None,
    ]:
        flow_id = str(snapshot.state["flow"])
        adapter = {
            "project": self._project_outcome,
            "entities": self._entities_outcome,
            "plan": self._plan_outcome,
            "book": self._book_outcome,
            "report": self._report_outcome,
            "memory": self._memory_outcome,
            "mentor": self._mentor_outcome,
            "grill-me": self._grill_outcome,
            "lint": self._lint_outcome,
            "ambient": self._ambient_outcome,
            "bundle": self._bundle_outcome,
        }.get(flow_id)
        if adapter is None:
            _fail("finalize producer flow is unsupported")
        producer = adapter(snapshot, evidence_name)
        accepted = producer.decision_status in {"approved", "applied"}
        applied = producer.decision_status == "applied"
        base = {
            "schema_version": FINALIZE_P3_SCHEMA_VERSION,
            "run_id": snapshot.state["run_id"],
            "flow_id": flow_id,
            "terminal_status": producer.terminal_status,
            "outcome_kind": producer.outcome_kind,
            "artifact_valid": True,
            "review_id": None,
            "review_status": None,
            "plan_sha256": None,
            "journal_sha256": None,
            "ask_result_sha256": None,
            "accepted": accepted,
            "applied": applied,
            "evidence_gap": None,
            "citation_count": None,
            "source_step_id": producer.source_step_id,
            "source_bundle_sha256": producer.source_bundle_sha256,
            "producer_operation": producer.operation,
            "pending_kind": producer.pending_kind,
            "pending_id": producer.pending_id,
            "decision_status": producer.decision_status,
            "decision_sequence": producer.decision_sequence,
            "decision_sha256": producer.decision_sha256,
        }
        identity = dict(base)
        outcome_id = (
            "outcome_"
            + hashlib.sha256(
                _canonical_bytes(identity, _MAX_OUTCOME_BYTES)
            ).hexdigest()[:56]
        )
        outcome = OutcomeRecord(outcome_id=outcome_id, observed_at=observed_at, **base)
        metric = MetricRecord(
            schema_version=FINALIZE_P3_SCHEMA_VERSION,
            metric_id="metric_"
            + hashlib.sha256(outcome_id.encode("ascii")).hexdigest()[:56],
            outcome_id=outcome_id,
            run_id=str(snapshot.state["run_id"]),
            flow_id=flow_id,
            terminal_status=producer.terminal_status,
            artifact_valid=True,
            review_id=None,
            review_status=None,
            plan_sha256=None,
            decision_sequence=producer.decision_sequence,
            accepted=accepted,
            applied=applied,
            review_queue_open=None,
            review_queue_age_seconds=None,
            evidence_gap=None,
            citation_count=None,
            observed_at=observed_at,
            source_step_id=producer.source_step_id,
            source_bundle_sha256=producer.source_bundle_sha256,
            producer_operation=producer.operation,
            pending_kind=producer.pending_kind,
            pending_id=producer.pending_id,
            decision_status=producer.decision_status,
            decision_sha256=producer.decision_sha256,
        )
        _validate_outcome_semantics(outcome)
        parse_metric_record(render_metric_record(metric))
        return (
            outcome,
            metric,
            producer.source_artifacts,
            producer.surface,
            producer.decision_artifact,
        )

    def _derive(
        self,
        snapshot: RunSnapshot,
        roles: FinalizeArtifactRoles,
        observed_at: str,
    ) -> tuple[OutcomeRecord, MetricRecord, tuple[CommittedArtifact, ...], str]:
        state = snapshot.state
        flow_id = str(state["flow"])
        if flow_id not in {"distill", "apply", "ask"}:
            _fail("finalize supports only P2 knowledge flows")
        artifacts = self._artifact_map(snapshot)
        used: list[CommittedArtifact] = []
        review = None
        plan = None
        journal = None
        ask = None
        plan_hash: str | None = None
        journal_hash: str | None = None
        ask_hash: str | None = None
        if roles.review is not None or roles.plan is not None:
            review_evidence, review_raw = self._artifact(
                artifacts, roles.review, "review"
            )
            plan_evidence, plan_raw = self._artifact(artifacts, roles.plan, "plan")
            used.extend((review_evidence, plan_evidence))
            try:
                review = parse_review_artifact(review_raw)
                plan = parse_mutation_plan(plan_raw)
            except ReviewArtifactError as error:
                raise FinalizeError(
                    "review artifacts violate their exact schema"
                ) from error
            if review.status == "applied":
                journal_evidence, journal_raw = self._artifact(
                    artifacts, roles.apply_journal, "apply journal"
                )
                used.append(journal_evidence)
                try:
                    journal = parse_apply_journal(journal_raw)
                    plan_hash = validate_artifact_plan(
                        review, plan, apply_journal=journal_raw
                    )
                except ReviewArtifactError as error:
                    raise FinalizeError(
                        "applied review lacks exact committed journal evidence"
                    ) from error
                journal_hash = journal_evidence.sha256
            else:
                if roles.apply_journal is not None:
                    _fail("non-applied review cannot name apply journal evidence")
                try:
                    plan_hash = validate_artifact_plan(review, plan)
                except ReviewArtifactError as error:
                    raise FinalizeError("review and plan binding is invalid") from error
        elif roles.plan is not None or roles.apply_journal is not None:
            _fail("plan and journal roles require a review artifact")

        if roles.ask_result is not None:
            ask_evidence, ask_raw = self._artifact(
                artifacts, roles.ask_result, "ask result"
            )
            used.append(ask_evidence)
            try:
                ask = parse_ask_result(ask_raw)
            except AskError as error:
                raise FinalizeError("ask result violates its exact schema") from error
            if ask.run_id != state["run_id"]:
                _fail("ask result belongs to a different run")
            ask_hash = ask_evidence.sha256

        if flow_id == "distill" and (review is None or ask is not None):
            _fail("distill finalize requires review and plan only")
        if flow_id == "apply" and (
            review is None
            or review.status != "applied"
            or journal is None
            or ask is not None
        ):
            _fail("apply finalize requires an exact applied review and journal")
        if flow_id == "ask" and ask is None:
            _fail("ask finalize requires a durable ask result")
        if flow_id == "ask" and ask is not None:
            if ask.proposal is None and review is not None:
                _fail("ask result without file-back cannot name review artifacts")
            if ask.proposal is not None:
                if review is None or plan is None:
                    _fail("ask file-back requires committed review and plan artifacts")
                if (
                    ask.proposal.artifact.review_id != review.review_id
                    or mutation_plan_sha256(ask.proposal.plan) != plan_hash
                ):
                    _fail("ask file-back artifacts disagree with durable ask result")

        if flow_id in {"distill", "ask"} and review is not None:
            if review.provenance.run_id != state["run_id"]:
                _fail("review provenance belongs to a different producer run")
        if flow_id == "apply" and review is not None:
            run_input = state["input"]
            if not isinstance(run_input, Mapping) or (
                run_input.get("review_id") != review.review_id
                or run_input.get("plan_sha256") != plan_hash
            ):
                _fail("apply run input does not bind the exact review and plan")

        accepted = bool(
            review is not None
            and review.status in {"approved", "applied"}
            and review.decisions
            and review.decisions[-1].action == "approve"
        )
        applied = bool(review is not None and review.status == "applied" and journal)
        terminal = "succeeded"
        if review is not None:
            if review.status == "proposed":
                kind = "review-ready"
                terminal = "waiting_human"
            elif flow_id == "apply":
                kind = "knowledge-applied"
            else:
                kind = {
                    "approved": "review-approved",
                    "rejected": "review-rejected",
                    "superseded": "review-superseded",
                    "applied": "review-applied",
                }[review.status]
        elif ask is not None:
            kind = "evidence-gap" if ask.evidence_gap else "answer-ready"
        else:  # pragma: no cover - flow requirements above
            _fail("finalize found no outcome artifact")

        base = {
            "schema_version": FINALIZE_SCHEMA_VERSION,
            "run_id": state["run_id"],
            "flow_id": flow_id,
            "terminal_status": terminal,
            "outcome_kind": kind,
            "artifact_valid": True,
            "review_id": None if review is None else review.review_id,
            "review_status": None if review is None else review.status,
            "plan_sha256": plan_hash,
            "journal_sha256": journal_hash,
            "ask_result_sha256": ask_hash,
            "accepted": accepted,
            "applied": applied,
            "evidence_gap": None if ask is None else ask.evidence_gap,
            "citation_count": None if ask is None else len(ask.citations),
        }
        outcome_id = (
            "outcome_"
            + hashlib.sha256(_canonical_bytes(base, _MAX_OUTCOME_BYTES)).hexdigest()[
                :56
            ]
        )
        outcome = OutcomeRecord(outcome_id=outcome_id, observed_at=observed_at, **base)
        decision_sequence = (
            None
            if review is None or not review.decisions
            else review.decisions[-1].sequence
        )
        if review is None:
            queue_open = None
            queue_age = None
        else:
            start = datetime.fromisoformat(review.created_at[:-1] + "+00:00")
            end = (
                datetime.fromisoformat(review.decisions[0].at[:-1] + "+00:00")
                if review.decisions
                else datetime.fromisoformat(observed_at[:-1] + "+00:00")
            )
            queue_open = not review.decisions
            queue_age = max(0, int((end - start).total_seconds()))
        metric_id = (
            "metric_" + hashlib.sha256(outcome_id.encode("ascii")).hexdigest()[:56]
        )
        metric = MetricRecord(
            schema_version=FINALIZE_SCHEMA_VERSION,
            metric_id=metric_id,
            outcome_id=outcome_id,
            run_id=str(state["run_id"]),
            flow_id=flow_id,
            terminal_status=terminal,
            artifact_valid=True,
            review_id=None if review is None else review.review_id,
            review_status=None if review is None else review.status,
            plan_sha256=plan_hash,
            decision_sequence=decision_sequence,
            accepted=accepted,
            applied=applied,
            review_queue_open=queue_open,
            review_queue_age_seconds=queue_age,
            evidence_gap=None if ask is None else ask.evidence_gap,
            citation_count=None if ask is None else len(ask.citations),
            observed_at=observed_at,
        )
        surface = (
            review.surface if review is not None else self._resolver.config.surface
        )
        return outcome, metric, tuple(used), surface

    def _failure_records(
        self, state: Mapping[str, object], observed_at: str
    ) -> tuple[OutcomeRecord, MetricRecord]:
        version = (
            FINALIZE_P3_SCHEMA_VERSION
            if state["flow"] in _P3_FINALIZE_FLOWS
            else FINALIZE_SCHEMA_VERSION
        )
        base = {
            "schema_version": version,
            "run_id": state["run_id"],
            "flow_id": state["flow"],
            "terminal_status": "failed",
            "outcome_kind": "validation-failed",
            "artifact_valid": False,
            "review_id": None,
            "review_status": None,
            "plan_sha256": None,
            "journal_sha256": None,
            "ask_result_sha256": None,
            "accepted": False,
            "applied": False,
            "evidence_gap": None,
            "citation_count": None,
        }
        if version == FINALIZE_P3_SCHEMA_VERSION:
            base.update(
                {
                    "source_step_id": None,
                    "source_bundle_sha256": None,
                    "producer_operation": None,
                    "pending_kind": None,
                    "pending_id": None,
                    "decision_status": None,
                    "decision_sequence": None,
                    "decision_sha256": None,
                }
            )
        outcome_id = (
            "outcome_"
            + hashlib.sha256(_canonical_bytes(base, _MAX_OUTCOME_BYTES)).hexdigest()[
                :56
            ]
        )
        outcome = OutcomeRecord(outcome_id=outcome_id, observed_at=observed_at, **base)
        metric = MetricRecord(
            schema_version=version,
            metric_id="metric_"
            + hashlib.sha256(outcome_id.encode("ascii")).hexdigest()[:56],
            outcome_id=outcome_id,
            run_id=str(state["run_id"]),
            flow_id=str(state["flow"]),
            terminal_status="failed",
            artifact_valid=False,
            review_id=None,
            review_status=None,
            plan_sha256=None,
            decision_sequence=None,
            accepted=False,
            applied=False,
            review_queue_open=None,
            review_queue_age_seconds=None,
            evidence_gap=None,
            citation_count=None,
            observed_at=observed_at,
            source_step_id=None,
            source_bundle_sha256=None,
            producer_operation=None,
            pending_kind=None,
            pending_id=None,
            decision_status=None,
            decision_sha256=None,
        )
        return outcome, metric

    def _publish_records(
        self,
        outcome: OutcomeRecord,
        metric: MetricRecord,
        hooks: FinalizeCrashHooks,
        revalidate_decision: Callable[[], None],
    ) -> tuple[OutcomeRecord, bytes, MetricRecord, bytes]:
        outcome_name = f"{outcome.outcome_id}.json"
        existing = self._publisher.read_if_exists(
            "finalize", outcome_name, _MAX_OUTCOME_BYTES
        )
        if existing is not None:
            durable_outcome = parse_outcome_record(existing)
            expected = _outcome_payload(outcome)
            observed = _outcome_payload(durable_outcome)
            expected.pop("observed_at")
            observed.pop("observed_at")
            if expected != observed:
                _fail("durable outcome conflicts with current validated result")
            outcome = durable_outcome
        outcome_raw = render_outcome_record(outcome)
        revalidate_decision()
        self._publisher.publish(
            "finalize",
            outcome_name,
            outcome_raw,
            _MAX_OUTCOME_BYTES,
            after_publish=hooks.after_domain_log,
        )
        revalidate_decision()
        queue_age = metric.review_queue_age_seconds
        if metric.review_queue_open and queue_age is not None:
            requested_time = datetime.fromisoformat(metric.observed_at[:-1] + "+00:00")
            durable_time = datetime.fromisoformat(outcome.observed_at[:-1] + "+00:00")
            queue_age = max(
                0, queue_age - int((requested_time - durable_time).total_seconds())
            )
        metric = MetricRecord(
            **{
                **metric.__dict__,
                "observed_at": outcome.observed_at,
                "review_queue_age_seconds": queue_age,
            }
        )
        metric_raw = render_metric_record(metric)
        self._publisher.publish(
            "metrics",
            f"{metric.metric_id}.json",
            metric_raw,
            _MAX_METRIC_BYTES,
            after_publish=hooks.after_metric,
        )
        return outcome, outcome_raw, metric, metric_raw

    def _revalidate_decision(self, decision: PreparedArtifact | None) -> None:
        if decision is None:
            return
        if (
            decision.name != "finalize-decision"
            or decision.zone != "review"
            or decision.state_ref != self._physical_ref("review", decision.relative)
            or not decision.relative.startswith("lintprop-")
            or not decision.relative.endswith(".lint.json")
        ):
            _fail("current lint decision anchor is invalid")
        raw = self._read_ref(decision.state_ref)
        if hashlib.sha256(raw).hexdigest() != decision.sha256:
            _fail("current lint decision changed during finalize")

    @staticmethod
    def _summary(kind: str) -> str:
        return {
            "review-ready": "Review is ready for a human decision.",
            "review-approved": "Review was approved.",
            "review-rejected": "Review was rejected.",
            "review-superseded": "Review was superseded.",
            "review-applied": "Reviewed knowledge was applied.",
            "knowledge-applied": "Approved knowledge changes were applied.",
            "answer-ready": "A cited answer is ready.",
            "evidence-gap": "The answer has an explicit evidence gap.",
            "domain-updated": "A validated domain update is complete.",
            "proposal-ready": "A proposal is ready for a human decision.",
            "report-ready": "A validated report is ready.",
        }[kind]

    def _prepared_sidecars(
        self,
        outcome: OutcomeRecord,
        outcome_raw: bytes,
        metric: MetricRecord,
        metric_raw: bytes,
        event: Mapping[str, object] | None,
    ) -> list[PreparedArtifact]:
        prepared = [
            PreparedArtifact(
                "finalize-log",
                "agent/logs",
                f"finalize/{outcome.outcome_id}.json",
                f"agent/logs/finalize/{outcome.outcome_id}.json",
                hashlib.sha256(outcome_raw).hexdigest(),
            ),
            PreparedArtifact(
                "finalize-metric",
                "agent/logs",
                f"metrics/{metric.metric_id}.json",
                f"agent/logs/metrics/{metric.metric_id}.json",
                hashlib.sha256(metric_raw).hexdigest(),
            ),
        ]
        if event is not None:
            event_raw = (
                json.dumps(
                    event,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                    allow_nan=False,
                ).encode("utf-8")
                + b"\n"
            )
            event_id = str(event["event_id"])
            outbox_ref = str(self._resolver.config.zone("outbox") / f"{event_id}.json")
            prepared.append(
                PreparedArtifact(
                    "finalize-event",
                    "agent/outbox",
                    f"{event_id}.json",
                    outbox_ref,
                    hashlib.sha256(event_raw).hexdigest(),
                )
            )
        return prepared

    def _validate_existing_p3_source(
        self,
        snapshot: RunSnapshot,
        outcome: OutcomeRecord,
        log: CommittedArtifact,
    ) -> None:
        if (
            outcome.flow_id not in _P3_COMPLETE_BUNDLE_FLOWS
            or outcome.source_step_id is None
            or outcome.source_bundle_sha256 is None
        ):
            return
        evidence_prefix = {
            "mentor": "mentor-evidence-",
            "grill-me": "grill-evidence-",
            "lint": "lint-evidence-",
            "ambient": "ambient-evidence-",
            "bundle": "bundle-evidence-",
        }[outcome.flow_id]
        candidates = tuple(
            item.name
            for item in snapshot.artifacts
            if item.name.startswith(evidence_prefix)
        )
        if len(candidates) != 1:
            _fail("terminal finalize source bundle is not exact")
        try:
            source_snapshot = self._runs.producer_snapshot(
                outcome.run_id, producer_evidence=candidates[0]
            )
        except RunError as error:
            raise FinalizeError(
                "terminal finalize source bundle is not exact"
            ) from error
        if (
            not source_snapshot.artifacts
            or {item.step_id for item in source_snapshot.artifacts}
            != {outcome.source_step_id}
            or _bundle_sha256(source_snapshot.artifacts) != outcome.source_bundle_sha256
        ):
            _fail("terminal finalize source bundle is not exact")
        try:
            traces = self._runs.trace_events(outcome.run_id)
        except RunError as error:
            raise FinalizeError(
                "terminal finalize trace cannot be validated"
            ) from error
        expected_step = (
            "finalize-review-ready"
            if outcome.terminal_status == "waiting_human"
            else "finalize-complete"
        )
        producer_traces = tuple(
            trace
            for trace in traces[:-1]
            if not str(trace.get("step_id", "")).startswith("finalize-")
        )
        if (
            not producer_traces
            or producer_traces[-1].get("step_id") != outcome.source_step_id
            or traces[-1].get("step_id") != expected_step
        ):
            _fail("terminal finalize does not follow its exact latest producer step")
        trace = traces[-1]
        actions = trace.get("actions")
        actual = (
            tuple(
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
            if isinstance(actions, list)
            else ()
        )
        expected = tuple(
            (sequence, "finalize", action_id, "succeeded")
            for sequence, action_id in enumerate(_FINALIZE_GRANTS, start=1)
        )
        if (
            trace.get("schema_version") != 2
            or trace.get("run_id") != outcome.run_id
            or trace.get("authority") != "internal-write"
            or trace.get("output_hash") != log.sha256
            or trace.get("executor_profile") != snapshot.state.get("executor")
            or trace.get("tool_outcomes") != []
            or actual != expected
        ):
            _fail("terminal finalize action trace is not exact")

    def _existing_result(self, snapshot: RunSnapshot) -> FinalizeResult | None:
        artifacts = self._artifact_map(snapshot)
        log = artifacts.get("finalize-log")
        metric = artifacts.get("finalize-metric")
        if log is None and metric is None:
            return None
        if log is None or metric is None:
            _fail("terminal run has incomplete finalize sidecar evidence")
        outcome = parse_outcome_record(self._read_committed(log))
        metric_record = parse_metric_record(self._read_committed(metric))
        shared = {
            "outcome_id",
            "run_id",
            "flow_id",
            "terminal_status",
            "artifact_valid",
            "review_id",
            "review_status",
            "plan_sha256",
            "accepted",
            "applied",
            "evidence_gap",
            "citation_count",
            "observed_at",
        }
        if outcome.schema_version == FINALIZE_P3_SCHEMA_VERSION:
            shared.update(_P3_FIELDS)
        if outcome.terminal_status != snapshot.state["status"] or any(
            getattr(outcome, field) != getattr(metric_record, field) for field in shared
        ):
            _fail("terminal run disagrees with finalize sidecar evidence")
        event = artifacts.get("finalize-event")
        event_id = None
        if event is not None:
            event_raw, event_payload = _decode(
                self._read_committed(event), "finalize event", _MAX_OUTCOME_BYTES
            )
            try:
                checked_event = validate_event(event_payload)
            except OutboxError as error:
                raise FinalizeError("terminal finalize event is invalid") from error
            if _canonical_bytes(checked_event, _MAX_OUTCOME_BYTES) != event_raw:
                _fail("terminal finalize event must use exact canonical JSON")
            event_id = PurePosixPath(event.relative).stem
            if (
                checked_event["event_id"] != event_id
                or checked_event["run_id"] != outcome.run_id
                or checked_event["flow_id"] != "finalize"
                or checked_event["type"] != outcome.outcome_kind
                or checked_event["artifact_ref"] != log.state_ref
                or checked_event["artifact_sha256"] != log.sha256
            ):
                _fail("terminal finalize event disagrees with exact outcome evidence")
        if outcome.artifact_valid != (event is not None):
            _fail("terminal finalize event presence disagrees with outcome validity")
        self._validate_existing_p3_source(snapshot, outcome, log)
        return FinalizeResult(
            schema_version=outcome.schema_version,
            run_id=outcome.run_id,
            source_flow=outcome.flow_id,
            terminal_status=outcome.terminal_status,
            outcome_id=outcome.outcome_id,
            outcome_kind=outcome.outcome_kind,
            domain_log_ref=log.state_ref,
            metric_ref=metric.state_ref,
            outbox_event_id=event_id,
        )

    def finalize(
        self,
        run_id: str,
        *,
        artifacts: FinalizeArtifactRoles,
        capabilities: FinalizeCapabilities,
        crash_hooks: FinalizeCrashHooks | None = None,
    ) -> FinalizeResult:
        checked_run_id = _identifier(run_id, "run_id", _RUN_ID)
        hooks = crash_hooks or FinalizeCrashHooks()
        if not isinstance(hooks, FinalizeCrashHooks):
            _fail("finalize crash hooks have invalid type")
        grants = self._capabilities(artifacts, capabilities)
        try:
            state = self._runs.status(checked_run_id)
        except RunError as error:
            raise FinalizeError("finalize requires an existing valid run") from error
        supported = {"distill", "apply", "ask"} | set(_P3_FINALIZE_FLOWS)
        if state["flow"] not in supported:
            _fail("finalize source flow is unsupported")
        if not authority_at_most("internal-write", str(state["authority"])):
            _fail("run authority is too low for durable finalization")
        if state["status"] != "running":
            try:
                snapshot = self._runs.snapshot(
                    checked_run_id,
                    artifact_names=("finalize-log", "finalize-metric")
                    if state["status"] == "failed"
                    else None,
                )
            except RunError as error:
                raise FinalizeError("terminal run evidence is invalid") from error
            existing = self._existing_result(snapshot)
            if existing is None:
                _fail("non-running run has no completed finalize evidence")
            return existing

        expected_state_hash = self._state_hash(state)
        observed_at = self._now()
        validation_error: FinalizeError | RunError | None = None
        decision_artifact: PreparedArtifact | None = None
        try:
            if state["flow"] in _P3_FINALIZE_FLOWS:
                if artifacts.producer_evidence is None or any(
                    value is not None
                    for name, value in artifacts.__dict__.items()
                    if name != "producer_evidence"
                ):
                    _fail("P3 finalize requires only one producer_evidence selector")
                snapshot = self._runs.producer_snapshot(
                    checked_run_id,
                    producer_evidence=artifacts.producer_evidence,
                )
            else:
                if artifacts.producer_evidence is not None:
                    _fail("P2 finalize cannot select P3 producer evidence")
                snapshot = self._runs.snapshot(checked_run_id)
            if snapshot.state["status"] != "running":
                # P3 producer_snapshot intentionally projects only the latest
                # producer bundle. Reconciliation may just have committed a
                # prepared terminal finalize intent, so reload the full
                # terminal projection before reconstructing its result.
                snapshot = self._runs.snapshot(
                    checked_run_id,
                    artifact_names=("finalize-log", "finalize-metric")
                    if snapshot.state["status"] == "failed"
                    else None,
                )
                existing = self._existing_result(snapshot)
                if existing is None:
                    _fail("reconciled run has no completed finalize evidence")
                return existing
            expected_state_hash = snapshot.state_sha256
            if state["flow"] in _P3_FINALIZE_FLOWS:
                assert artifacts.producer_evidence is not None
                (
                    outcome,
                    metric,
                    source_artifacts,
                    surface,
                    decision_artifact,
                ) = self._derive_p3(snapshot, artifacts.producer_evidence, observed_at)
            else:
                outcome, metric, source_artifacts, surface = self._derive(
                    snapshot, artifacts, observed_at
                )
        except (FinalizeError, RunError) as error:
            if state["flow"] in _P3_COMPLETE_BUNDLE_FLOWS:
                raise FinalizeError(
                    "finalize source bundle is not an exact accepted producer result"
                ) from error
            validation_error = error
            outcome, metric = self._failure_records(state, observed_at)
            source_artifacts = ()
            surface = self._resolver.config.surface
            decision_artifact = None

        def revalidate_decision() -> None:
            self._revalidate_decision(decision_artifact)

        outcome, outcome_raw, metric, metric_raw = self._publish_records(
            outcome, metric, hooks, revalidate_decision
        )
        revalidate_decision()
        event: Mapping[str, object] | None = None
        if validation_error is None:
            try:
                event = self._outbox.enqueue(
                    grants["emit-semantic-outbox-event"],
                    run_id=checked_run_id,
                    event_type=outcome.outcome_kind,
                    semantic_key=f"finalize:{outcome.outcome_id}",
                    summary=self._summary(outcome.outcome_kind),
                    artifact_zone="agent/logs",
                    artifact_relative=f"finalize/{outcome.outcome_id}.json",
                    surface=surface,
                    requires_receipt=True,
                )
            except OutboxError as error:
                raise FinalizeError(
                    "semantic finalize event could not be committed"
                ) from error
            if hooks.after_outbox is not None:
                hooks.after_outbox()
            revalidate_decision()

        prepared = [
            PreparedArtifact(
                item.name,
                item.zone,
                item.relative,
                item.state_ref,
                item.sha256,
            )
            for item in source_artifacts
        ]
        prepared.extend(
            self._prepared_sidecars(outcome, outcome_raw, metric, metric_raw, event)
        )
        if decision_artifact is not None:
            prepared.append(decision_artifact)
        if validation_error is None:
            ordered_actions = [
                ActionUse(grants["validate-run-artifacts"]),
                ActionUse(grants["read-review-outcome"]),
            ]
            ordered_actions.extend(
                (
                    ActionUse(grants["append-domain-log"]),
                    ActionUse(grants["append-run-trace"]),
                    ActionUse(grants["commit-bounded-metrics"]),
                    ActionUse(grants["emit-semantic-outbox-event"]),
                    ActionUse(grants["finalize-run-state"]),
                )
            )
            step_id = (
                "finalize-review-ready"
                if outcome.terminal_status == "waiting_human"
                else "finalize-complete"
            )
            error_kind = None
            error_detail = ""
        else:
            ordered_actions = [
                ActionUse(grants["validate-run-artifacts"], "failed"),
                ActionUse(grants["read-review-outcome"], "failed"),
            ]
            ordered_actions.extend(
                (
                    ActionUse(grants["append-domain-log"]),
                    ActionUse(grants["append-run-trace"]),
                    ActionUse(grants["commit-bounded-metrics"]),
                    ActionUse(grants["emit-semantic-outbox-event"], "failed"),
                    ActionUse(grants["finalize-run-state"]),
                )
            )
            step_id = "finalize-failed"
            error_kind = "artifact-invalid"
            error_detail = str(validation_error)
        try:
            revalidate_decision()
            final_state = self._runs.commit_step(
                checked_run_id,
                step_id=step_id,
                authority="internal-write",
                input_hash=expected_state_hash,
                output_hash=hashlib.sha256(outcome_raw).hexdigest(),
                next_phase="finalized"
                if outcome.terminal_status != "waiting_human"
                else "review",
                next_status=outcome.terminal_status,
                waiting_for=(
                    "review-decision"
                    if outcome.terminal_status == "waiting_human"
                    else None
                ),
                prepared_artifacts=prepared,
                expected_state_sha256=expected_state_hash,
                error_kind=error_kind,
                error_detail=error_detail,
                action_uses=ordered_actions,
                authority_policy=self._policy,
                after_prepare=hooks.after_run_prepare,
                after_state=hooks.after_run_state,
                after_trace=hooks.after_run_trace,
            )
        except RunError as error:
            raise FinalizeError("finalize run commit failed safely") from error
        if final_state["status"] != outcome.terminal_status:
            _fail("finalize run state disagrees with durable outcome")
        event_id = None if event is None else str(event["event_id"])
        return FinalizeResult(
            schema_version=outcome.schema_version,
            run_id=checked_run_id,
            source_flow=str(state["flow"]),
            terminal_status=outcome.terminal_status,
            outcome_id=outcome.outcome_id,
            outcome_kind=outcome.outcome_kind,
            domain_log_ref=f"agent/logs/finalize/{outcome.outcome_id}.json",
            metric_ref=f"agent/logs/metrics/{metric.metric_id}.json",
            outbox_event_id=event_id,
        )
