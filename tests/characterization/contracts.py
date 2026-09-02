"""Public characterization oracle derived from observable legacy behavior.

This module contains no private imports or prose.  It records the behavior to
preserve, plus explicit v2 authority deltas, before production flows exist.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any, Mapping


AUTHORITY_CLASSES = frozenset(
    {
        "read",
        "internal-write",
        "proposal",
        "domain-write",
        "protected-write",
        "external-send",
    }
)


@dataclass(frozen=True)
class ReliabilityExpectation:
    stage: str
    cohort_size: int
    k: int
    assumed_single_pass: float
    minimum_pass_k: float
    models_executed: bool = False


@dataclass(frozen=True)
class CharacterizationCase:
    group: str
    fixture_evidence: tuple[str, ...]
    artifacts: tuple[str, ...]
    trajectory: tuple[str, ...]
    authority: Mapping[str, str]
    allowed_writes: tuple[str, ...]
    forbidden_effects: tuple[str, ...]
    observations: Mapping[str, Any]
    legacy_symbols: tuple[str, ...]
    reliability: ReliabilityExpectation | None = None


@dataclass(frozen=True)
class KnownLegacyFailure:
    failure_id: str
    cause_class: str
    expected_count: int
    accepted_behavior: bool = False


CASES: Mapping[str, CharacterizationCase] = {
    "review_apply": CharacterizationCase(
        group="review_apply",
        fixture_evidence=(
            "review/rev_fixture-001.md",
            ".lifeos/review-plans/rev_fixture-001.json",
            "knowledge/domains/ai/portable-workflow.md",
        ),
        artifacts=(
            "review/<review-id>.md",
            ".lifeos/review-plans/<review-id>.json",
            "knowledge/<approved-target>.md",
            "agent/runs/<run-id>/trace.jsonl",
        ),
        trajectory=(
            "proposal-created",
            "approval-recorded",
            "preconditions-verified",
            "protected-commit",
            "review-finalized",
        ),
        authority={
            "proposal-created": "proposal",
            "approval-recorded": "domain-write",
            "preconditions-verified": "read",
            "protected-commit": "protected-write",
            "review-finalized": "internal-write",
        },
        allowed_writes=("review/", ".lifeos/review-plans/", "knowledge/", "agent/runs/"),
        forbidden_effects=("direct-knowledge-write-before-approval", "external-send"),
        observations={
            "approval_evidence": ("approved_by", "approved_at", "approved_plan_sha256"),
            "plan_hashes": "pre-and-post",
            "prose_plan_drift": "fail-closed",
            "idempotent_replay": True,
            "legacy_evidence_warning_only": True,
            "target_requires_apply_evidence": True,
        },
        legacy_symbols=("tools.finalize.cmd_begin", "tools.finalize.cmd_apply"),
        reliability=ReliabilityExpectation(
            stage="proposal-synthesis",
            cohort_size=20,
            k=3,
            assumed_single_pass=0.90,
            minimum_pass_k=0.70,
        ),
    ),
    "project_transitions": CharacterizationCase(
        group="project_transitions",
        fixture_evidence=(
            "projects/portable-fixture/project.json",
            "projects/portable-fixture/state.json",
            "projects/portable-fixture/log.md",
        ),
        artifacts=(
            "projects/<slug>/project.json",
            "projects/<slug>/state.json",
            "projects/<slug>/log.md",
        ),
        trajectory=("active", "on-hold", "active", "archived"),
        authority={
            "active": "domain-write",
            "on-hold": "domain-write",
            "archived": "domain-write",
        },
        allowed_writes=("projects/", "agent/runs/"),
        forbidden_effects=(
            "hard-delete",
            "auto-resume-schedule",
            "direct-agent-schedule-write",
        ),
        observations={
            "locations": {
                "active": "projects/<slug>/",
                "on-hold": "projects/_on_hold/<slug>/",
                "archived": "projects/_archive/<slug>-<date>/",
            },
            "log_append_only": True,
            "archive_terminal": True,
            "hold_pauses_linked_schedules": True,
            "resume_does_not_auto_resume_schedules": True,
            "archive_children_requires_explicit_policy": True,
            "schedule_transition_owner": "connector:scheduler",
        },
        legacy_symbols=(
            "tools.project.cmd_hold",
            "tools.project.cmd_resume",
            "tools.project.cmd_archive",
        ),
    ),
    "task_rollover": CharacterizationCase(
        group="task_rollover",
        fixture_evidence=("tasks/2026-01-15.md",),
        artifacts=(
            "tasks/<period>.md",
            "agent/logs/tasks/<date>.md",
            "review/tasks-feedback-<date>.md",
        ),
        trajectory=(
            "read-current",
            "snapshot-before-replace",
            "extract-feedback",
            "proposal-created",
        ),
        authority={
            "read-current": "read",
            "snapshot-before-replace": "domain-write",
            "extract-feedback": "read",
            "proposal-created": "proposal",
        },
        allowed_writes=("agent/logs/tasks/", "review/", "tasks/"),
        forbidden_effects=("drop-incomplete-history", "external-send"),
        observations={
            "snapshot_before_replace": True,
            "feedback_requires_marker": True,
            "missing_source_is_noop": True,
            "evidence_verdicts": (
                "done-verified",
                "done-claimed",
                "ambiguous",
                "not-done",
            ),
            "strict_quota_excludes_uncertain": True,
            "file_existence_is_signal_not_verdict": True,
        },
        legacy_symbols=(
            "tools.task_rollover.snapshot_today",
            "tools.task_rollover.parse_feedback_blocks",
        ),
    ),
    "entity_done_trails": CharacterizationCase(
        group="entity_done_trails",
        fixture_evidence=(
            "knowledge/domains/ai/entities.json",
            "agent/logs/done-events.jsonl",
        ),
        artifacts=(
            "agent/memory/entities/<domain>.json",
            "agent/logs/done-events.jsonl",
            "agent/memory/trails/<entity-id>.jsonl",
        ),
        trajectory=(
            "entity-mutated",
            "human-confirms-event",
            "done-event-appended",
            "trail-appended",
        ),
        authority={
            "entity-mutated": "domain-write",
            "human-confirms-event": "read",
            "done-event-appended": "domain-write",
            "trail-appended": "domain-write",
        },
        allowed_writes=(
            "agent/memory/entities/",
            "agent/logs/",
            "agent/memory/trails/",
        ),
        forbidden_effects=("auto-confirm-real-life-event", "collapse-into-task"),
        observations={
            "distinct_records": True,
            "done_requires_human_confirmation": True,
            "trail_append_only": True,
            "done_followup_requires_sent_before_answer": True,
            "trail_actions": ("ping", "done", "skip", "silent"),
            "legacy_bridge_is_non_atomic": True,
            "legacy_entity_path": "knowledge/domains/<domain>/entities.json",
            "target_entity_path": "agent/memory/entities/<domain>.json",
        },
        legacy_symbols=(
            "tools.entity.Entity",
            "tools.done_log.cmd_add",
            "tools.trails.log_action",
        ),
    ),
    "reading": CharacterizationCase(
        group="reading",
        fixture_evidence=(
            "agent/reading/portable-handbook.json",
            "agent/reading/portable-handbook-log.md",
        ),
        artifacts=(
            "agent/reading/<slug>.json",
            "agent/reading/<slug>-log.md",
            "review/<anchors-review>.md",
        ),
        trajectory=("reading-started", "chapter-advanced", "anchor-appended", "reading-closed"),
        authority={
            "reading-started": "domain-write",
            "chapter-advanced": "domain-write",
            "anchor-appended": "domain-write",
            "reading-closed": "domain-write",
        },
        allowed_writes=("agent/reading/", "review/"),
        forbidden_effects=("copy-raw-book-into-vault", "direct-anchor-to-knowledge"),
        observations={
            "close_removes_state": True,
            "close_retains_log": True,
            "anchor_knowledge_path": "review-first",
            "raw_owned_externally": True,
            "terminal_decisions": ("finished", "dropped"),
            "legacy_close_retry_is_not_idempotent": True,
        },
        legacy_symbols=(
            "tools.reading_state.cmd_advance",
            "tools.reading_state.cmd_anchor",
            "tools.reading_state.cmd_close",
        ),
    ),
    "surface": CharacterizationCase(
        group="surface",
        fixture_evidence=("agent/outbox/event_fixture-001.json",),
        artifacts=(
            "agent/outbox/<event-id>.json",
            "agent/outbox/receipts/<event-id>.json",
        ),
        trajectory=(
            "semantic-selection",
            "outbox-commit",
            "surface-gate",
            "connector-send",
            "receipt-commit",
        ),
        authority={
            "semantic-selection": "internal-write",
            "outbox-commit": "internal-write",
            "surface-gate": "read",
            "connector-send": "external-send",
            "receipt-commit": "internal-write",
        },
        allowed_writes=("agent/outbox/",),
        forbidden_effects=("transport-token-in-event", "direct-transport-before-outbox"),
        observations={
            "semantic_event_only": True,
            "gated_requires_policy": True,
            "receipt_after_send": True,
            "silent_and_batched_do_not_transport": True,
            "force_requires_reason": True,
            "legacy_missing_surface_is_permissive": True,
        },
        legacy_symbols=("tools.notify.read_surface", "tools.notify.defer_notify"),
        reliability=ReliabilityExpectation(
            stage="semantic-selection",
            cohort_size=24,
            k=3,
            assumed_single_pass=0.95,
            minimum_pass_k=0.85,
        ),
    ),
    "finalize": CharacterizationCase(
        group="finalize",
        fixture_evidence=(
            "agent/runs/run_fixture-001/state.json",
            "agent/runs/run_fixture-001/trace.jsonl",
            "agent/logs/done-events.jsonl",
        ),
        artifacts=(
            "agent/runs/<run-id>/state.json",
            "agent/runs/<run-id>/trace.jsonl",
            "agent/logs/<event-log>.jsonl",
        ),
        trajectory=(
            "validate-artifact",
            "commit-allowed-zone",
            "append-trace",
            "append-metrics",
            "mark-succeeded",
        ),
        authority={
            "validate-artifact": "read",
            "commit-allowed-zone": "internal-write",
            "append-trace": "internal-write",
            "append-metrics": "internal-write",
            "mark-succeeded": "internal-write",
        },
        allowed_writes=("agent/runs/", "agent/logs/"),
        forbidden_effects=("protected-write", "external-send", "success-before-validation"),
        observations={
            "validator_before_success": True,
            "trace_append_only": True,
            "retry_does_not_duplicate_metrics": True,
            "failure_artifact_before_failure_surface": True,
            "session_end_is_adapter_not_oracle": True,
        },
        legacy_symbols=("tools.finalize.validate_critical_files", "tools.finalize.cmd_stateful"),
    ),
}


KNOWN_LEGACY_FAILURES = (
    KnownLegacyFailure(
        "test_f129_real_schedule_files_pass", "invalid-production-schedule", 1
    ),
    KnownLegacyFailure(
        "test_a010_production_schedule_contract_no_high_or_medium",
        "invalid-production-schedule",
        1,
    ),
    KnownLegacyFailure(
        "test_f086_raw_normalize_idempotent", "stale-test-expectation", 1
    ),
    KnownLegacyFailure(
        "test_f124_apply_evidence_in_strict", "time-window-expired", 1
    ),
)

# Fresh read-only audit on 2026-08-20 found one failure beyond the dated
# inventory. It is deterministic read-only coupling: JSON mode writes its
# report before stdout, so a denied buffer write yields empty stdout. This is
# neither accepted behavior nor folded into the four documented failures.
UNRESOLVED_LEGACY_DRIFT = (
    KnownLegacyFailure(
        "test_f130_system_audit_json_format",
        "read-only-side-effect-coupling",
        1,
    ),
)


def _relative_artifact(path: str) -> bool:
    normalized = path.replace("<", "fixture-").replace(">", "")
    value = PurePosixPath(normalized)
    return not value.is_absolute() and ".." not in value.parts


def validate_case(case: CharacterizationCase) -> set[str]:
    rules: set[str] = set()
    if not case.artifacts or not all(_relative_artifact(path) for path in case.artifacts):
        rules.add("artifact.relative-and-present")
    if not case.trajectory or any(not step for step in case.trajectory):
        rules.add("trajectory.steps-present")
    if not set(case.authority.values()) <= AUTHORITY_CLASSES:
        rules.add("authority.class-known")
    if not set(case.authority) <= set(case.trajectory):
        rules.add("authority.action-in-trajectory")
    if any(not _relative_artifact(path) for path in case.fixture_evidence):
        rules.add("fixture.relative")

    if case.group == "review_apply":
        if case.authority.get("protected-commit") != "protected-write":
            rules.add("authority.knowledge-protected-write")
        if case.observations.get("plan_hashes") != "pre-and-post":
            rules.add("artifact.review-plan-hashes")
        if case.observations.get("target_requires_apply_evidence") is not True:
            rules.add("artifact.apply-evidence-required")
    elif case.group == "project_transitions":
        locations = case.observations.get("locations", {})
        if locations.get("archived") != "projects/_archive/<slug>-<date>/":
            rules.add("artifact.project-archive-location")
        if case.observations.get("hold_pauses_linked_schedules") is not True:
            rules.add("side-effect.project-hold-pauses-schedules")
        if case.observations.get("schedule_transition_owner") != "connector:scheduler":
            rules.add("authority.project-schedule-owned-by-connector")
    elif case.group == "task_rollover":
        if case.observations.get("snapshot_before_replace") is not True:
            rules.add("side-effect.snapshot-before-replace")
        if case.observations.get("strict_quota_excludes_uncertain") is not True:
            rules.add("artifact.strict-quota-excludes-uncertain")
    elif case.group == "entity_done_trails":
        if case.observations.get("distinct_records") is not True:
            rules.add("artifact.distinct-entity-done-trail")
        if case.observations.get("done_requires_human_confirmation") is not True:
            rules.add("authority.done-human-confirmation")
        if case.observations.get("trail_append_only") is not True:
            rules.add("side-effect.trail-append-only")
        if case.observations.get("target_entity_path") != (
            "agent/memory/entities/<domain>.json"
        ):
            rules.add("authority.entity-outside-protected-knowledge")
    elif case.group == "reading":
        if case.observations.get("close_retains_log") is not True:
            rules.add("side-effect.reading-log-retained")
        if case.observations.get("anchor_knowledge_path") != "review-first":
            rules.add("authority.reading-anchor-review-first")
        if case.observations.get("raw_owned_externally") is not True:
            rules.add("side-effect.reading-raw-external")
    elif case.group == "surface":
        if case.trajectory.index("outbox-commit") > case.trajectory.index("connector-send"):
            rules.add("trajectory.outbox-before-send")
        if case.observations.get("silent_and_batched_do_not_transport") is not True:
            rules.add("side-effect.surface-silent-no-transport")
    elif case.group == "finalize":
        if case.trajectory.index("validate-artifact") > case.trajectory.index("mark-succeeded"):
            rules.add("trajectory.validation-before-success")
        if case.observations.get("retry_does_not_duplicate_metrics") is not True:
            rules.add("side-effect.finalize-metrics-idempotent")

    if case.reliability is not None:
        expectation = case.reliability
        if expectation.models_executed:
            rules.add("reliability.models-not-run-in-characterization")
        if expectation.cohort_size < 10 or expectation.k < 2:
            rules.add("reliability.cohort-and-k-bounded")
        pass_k = expectation.assumed_single_pass**expectation.k
        if not 0 < expectation.minimum_pass_k <= pass_k <= 1:
            rules.add("reliability.pass-k-expectation")
    return rules
