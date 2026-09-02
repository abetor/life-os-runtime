"""Canonical Gate P3 state and acceptance coverage.

The failure-authority catalog remains the authority for actions and ceilings.
This registry adds the state carrier and concrete regression evidence that the
phase gate needs without treating a migration target as an executable route.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Mapping, Sequence

from ....failure_authority import canonical_matrix, validate_matrix


P3_GATE_SCHEMA_VERSION = 1
P3_FLOW_IDS = (
    "obsidian",
    "ingest",
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
)

_ID = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")
_TEST_NODE = re.compile(r"^tests/test_[a-z0-9_]+\.py::test_[a-z0-9_]+$")
_INSPECTOR = re.compile(
    r"^tool_life_os_runtime(?:\.[a-z][a-z0-9_]*)+\.[A-Za-z_][A-Za-z0-9_]*$"
)
_STATE_KINDS = frozenset({"direct-receipt", "request-result", "run-store"})
_INTEGRATION_STATUSES = frozenset({"accepted", "integration_required"})


class P3GateRegistryError(ValueError):
    """The Gate P3 coverage registry is incomplete or inconsistent."""


@dataclass(frozen=True)
class StateContract:
    """Persisted or replayable state observed at the public flow boundary."""

    kind: str
    carrier: str
    producer_statuses: tuple[str, ...]
    finalized_statuses: tuple[str, ...]
    replay_key: str


@dataclass(frozen=True)
class FlowGateContract:
    """One P3 flow joined to authority, state, failure, and acceptance evidence."""

    schema_version: int
    flow_id: str
    authority_ceiling: str
    action_ids: tuple[str, ...]
    state: StateContract
    inspector: str
    acceptance_test_nodes: tuple[str, ...]
    failure_test_nodes: tuple[str, ...]
    integration_status: str


_COVERAGE: Mapping[
    str,
    tuple[
        StateContract,
        str,
        tuple[str, ...],
        tuple[str, ...],
        str,
    ],
] = {
    "obsidian": (
        StateContract(
            "direct-receipt",
            "validated-note-and-note-edit-receipt",
            ("validated", "committed"),
            ("succeeded",),
            "operation-id-and-precondition-sha256",
        ),
        "tool_life_os_runtime.ext.flows.obsidian.parse_note_edit_receipt",
        (
            "tests/test_obsidian_flow.py::test_create_update_receipt_round_trip_and_replay",
        ),
        (
            "tests/test_obsidian_flow.py::test_toxic_note_paths_fail_before_filesystem_access",
            "tests/test_obsidian_flow.py::test_foreign_target_after_prepare_is_preserved",
        ),
        "accepted",
    ),
    "ingest": (
        StateContract(
            "request-result",
            "canonical-result-and-injected-dedupe-state",
            ("classified", "proposal", "fallback"),
            ("proposal-ready", "explicit-fallback"),
            "request-sha256-and-review-id",
        ),
        "tool_life_os_runtime.ext.flows.ingest.parse_ingest_result",
        (
            "tests/test_ingest_flow.py::test_heavy_inputs_use_only_injected_connector_and_return_review",
            "tests/test_ingest_flow.py::test_unknown_returns_bounded_explicit_fallback_without_connector_or_proposal",
        ),
        (
            "tests/test_ingest_flow.py::test_same_review_id_with_changed_route_conflicts_before_connector",
            "tests/test_ingest_flow.py::test_temporary_clean_vault_has_no_configured_or_legacy_source_access",
        ),
        "integration_required",
    ),
    "project": (
        StateContract(
            "run-store",
            "project-state-log-and-run-store",
            ("running",),
            ("succeeded",),
            "transition-id-and-request-sha256",
        ),
        "tool_life_os_runtime.ext.flows.project.ProjectFlow",
        (
            "tests/test_project_flow.py::test_create_list_status_and_run_evidence_are_exact",
            "tests/test_finalize_flow.py::test_project_latest_producer_bundle_finalizes_to_schema_v2_domain_success",
        ),
        (
            "tests/test_project_flow.py::test_missing_scheduler_leaves_durable_pending_then_replays_once",
            "tests/test_project_flow.py::test_parent_vault_swap_during_publish_rolls_back_detached_domain_effects",
        ),
        "integration_required",
    ),
    "entities": (
        StateContract(
            "run-store",
            "entity-done-trail-artifacts-and-run-store",
            ("running",),
            ("succeeded",),
            "operation-family-and-operation-id",
        ),
        "tool_life_os_runtime.ext.flows.entities.EntitiesFlow",
        (
            "tests/test_entities_flow.py::test_entity_lifecycle_steps_paths_schema_and_action_order",
            "tests/test_finalize_flow.py::test_entities_and_plan_explicit_adapters_accept_exact_producer_evidence",
        ),
        (
            "tests/test_entities_flow.py::test_speculative_text_never_writes_done_and_confirmed_created_is_exact_once",
            "tests/test_entities_flow.py::test_retry_before_entity_replace_and_after_trail_append",
        ),
        "accepted",
    ),
    "plan": (
        StateContract(
            "run-store",
            "plan-preimage-plan-artifacts-and-run-store",
            ("running",),
            ("succeeded", "waiting_human"),
            "mutation-id-and-request-sha256",
        ),
        "tool_life_os_runtime.ext.flows.plan.parse_day_plan",
        (
            "tests/test_plan_flow.py::test_day_schema_markdown_paths_context_and_exact_action_order",
            "tests/test_finalize_flow.py::test_entities_and_plan_explicit_adapters_accept_exact_producer_evidence",
        ),
        (
            "tests/test_plan_flow.py::test_physical_quota_and_max_focus_are_code_invariants",
            "tests/test_plan_flow.py::test_partial_immutable_stage_never_appears_under_final_name_and_retries",
        ),
        "accepted",
    ),
    "book": (
        StateContract(
            "run-store",
            "reading-state-log-review-and-run-store",
            ("running",),
            ("succeeded", "waiting_human"),
            "mutation-id-and-source-identity",
        ),
        "tool_life_os_runtime.ext.flows.book.parse_book_result",
        (
            "tests/test_book_flow.py::test_full_lifecycle_retains_log_and_anchor_is_review_only",
            "tests/test_finalize_flow.py::test_book_proposal_finalize_decision_resume_rebinds_only_canonical_review",
        ),
        (
            "tests/test_book_flow.py::test_restart_after_log_commit_recovers_once_without_duplicate",
            "tests/test_book_flow.py::test_moved_source_resumes_by_identity_and_stale_source_is_rejected",
        ),
        "accepted",
    ),
    "report": (
        StateContract(
            "run-store",
            "append-only-report-memory-proposal-and-run-store",
            ("running",),
            ("succeeded", "waiting_human"),
            "operation-id-and-primary-evidence-sha256",
        ),
        "tool_life_os_runtime.ext.flows.report.inspect_report_run_evidence",
        (
            "tests/test_report_memory_flow.py::test_daily_weekly_and_extract_are_replay_safe_and_proposal_only",
            "tests/test_finalize_flow.py::test_report_and_memory_provisional_inspectors_finalize_exact_v2_outputs",
        ),
        (
            "tests/test_report_memory_flow.py::test_primary_evidence_anchor_cannot_relabel_summary_text",
            "tests/test_report_memory_flow.py::test_report_crash_after_log_recovers_exactly",
        ),
        "accepted",
    ),
    "memory": (
        StateContract(
            "run-store",
            "memory-proposal-metadata-outcome-and-run-store",
            ("running",),
            ("succeeded", "waiting_human"),
            "operation-id-and-evidence-sha256",
        ),
        "tool_life_os_runtime.ext.flows.memory.inspect_memory_run_evidence",
        (
            "tests/test_report_memory_flow.py::test_memory_proposal_crash_replay_and_evidence_inspection",
            "tests/test_finalize_flow.py::test_report_and_memory_provisional_inspectors_finalize_exact_v2_outputs",
        ),
        (
            "tests/test_report_memory_flow.py::test_stale_boundary_creates_review_not_shared_text",
            "tests/test_report_memory_flow.py::test_memory_proposal_parent_change_after_link_rolls_back_owned_publication",
        ),
        "accepted",
    ),
    "mentor": (
        StateContract(
            "run-store",
            "bounded-task-proposal-evidence-and-run-store",
            ("running",),
            ("waiting_human",),
            "operation-id-and-task-packet-sha256",
        ),
        "tool_life_os_runtime.ext.flows.mentor.inspect_mentor_run_evidence",
        (
            "tests/test_mentor_grill_flow.py::test_mentor_produces_only_strict_review_and_exact_run_evidence",
            "tests/test_p3_e2e.py::test_clean_vault_p3_trajectory_does_not_access_legacy",
        ),
        (
            "tests/test_mentor_grill_flow.py::test_mentor_strict_output_bounds_refs_and_crash_replay",
            "tests/test_mentor_grill_flow.py::test_mentor_parent_replacement_retires_only_owned_review",
        ),
        "accepted",
    ),
    "grill-me": (
        StateContract(
            "run-store",
            "question-answer-session-decision-record-and-run-store",
            ("waiting_human", "running"),
            ("waiting_human",),
            "operation-id-session-revision-and-explicit-human-input",
        ),
        "tool_life_os_runtime.ext.flows.grill_me.inspect_grill_run_evidence",
        (
            "tests/test_mentor_grill_flow.py::test_grill_persists_questions_answers_and_only_explicit_decision",
            "tests/test_p3_e2e.py::test_clean_vault_p3_trajectory_does_not_access_legacy",
        ),
        (
            "tests/test_mentor_grill_flow.py::test_grill_strict_question_and_unresolved_is_not_inferred",
            "tests/test_mentor_grill_flow.py::test_grill_parent_replacement_retires_only_owned_review",
        ),
        "accepted",
    ),
    "lint": (
        StateContract(
            "run-store",
            "infra-fix-batch-final-evidence-and-run-store",
            ("running",),
            ("succeeded", "waiting_human"),
            "request-sha256-and-latest-final-producer-step",
        ),
        "tool_life_os_runtime.ext.flows.lint.inspect_lint_run_evidence",
        (
            "tests/test_lint_flow.py::test_infra_scans_exact_five_zones_and_only_normalizes_allowlisted_notes",
            "tests/test_p3_e2e.py::test_clean_vault_p3_trajectory_does_not_access_legacy",
        ),
        (
            "tests/test_lint_flow.py::test_pending_fix_record_mismatch_fails_without_changes",
            "tests/test_lint_flow.py::test_replay_requires_exact_action_trace_for_each_committed_source_step",
        ),
        "accepted",
    ),
    "ambient": (
        StateContract(
            "run-store",
            "candidate-dispositions-outbox-evidence-and-run-store",
            ("running",),
            ("succeeded",),
            "operation-id-candidate-digest-and-semantic-dedupe-key",
        ),
        "tool_life_os_runtime.ext.flows.ambient.inspect_ambient_run_evidence",
        (
            "tests/test_ambient_bundle_flow.py::test_ambient_emits_one_content_addressed_event_and_exact_evidence",
            "tests/test_p3_e2e.py::test_clean_vault_p3_trajectory_does_not_access_legacy",
        ),
        (
            "tests/test_ambient_bundle_flow.py::test_ambient_zero_is_silent_semantic_success_and_stays_running",
            "tests/test_ambient_bundle_flow.py::test_all_crash_seams_preserve_exact_replay_and_one_event",
        ),
        "accepted",
    ),
    "bundle": (
        StateContract(
            "run-store",
            "closed-window-manifest-outbox-evidence-and-run-store",
            ("running",),
            ("succeeded",),
            "operation-id-window-digest-and-semantic-dedupe-key",
        ),
        "tool_life_os_runtime.ext.flows.bundle.inspect_bundle_run_evidence",
        (
            "tests/test_ambient_bundle_flow.py::test_bundle_closed_window_exact_digest_duplicate_and_no_recursive_item",
            "tests/test_p3_e2e.py::test_clean_vault_p3_trajectory_does_not_access_legacy",
        ),
        (
            "tests/test_ambient_bundle_flow.py::test_uncommitted_bundle_empty_evidence_cannot_hide_pending_event",
            "tests/test_ambient_bundle_flow.py::test_all_crash_seams_preserve_exact_replay_and_one_event",
        ),
        "accepted",
    ),
}


def _matrix_flows() -> dict[str, Mapping[str, object]]:
    matrix = canonical_matrix()
    validate_matrix(matrix)
    return {str(flow["flow_id"]): flow for flow in matrix["flows"]}


def canonical_p3_registry() -> tuple[FlowGateContract, ...]:
    """Return the exact P3 flow inventory in stable dependency order."""

    matrix = _matrix_flows()
    records = tuple(
        FlowGateContract(
            schema_version=P3_GATE_SCHEMA_VERSION,
            flow_id=flow_id,
            authority_ceiling=str(matrix[flow_id]["authority_ceiling"]),
            action_ids=tuple(
                str(action["action_id"])
                for action in matrix[flow_id]["actions"]  # type: ignore[index]
            ),
            state=_COVERAGE[flow_id][0],
            inspector=_COVERAGE[flow_id][1],
            acceptance_test_nodes=_COVERAGE[flow_id][2],
            failure_test_nodes=_COVERAGE[flow_id][3],
            integration_status=_COVERAGE[flow_id][4],
        )
        for flow_id in P3_FLOW_IDS
    )
    return validate_p3_registry(records)


def _unique_texts(values: object, label: str) -> tuple[str, ...]:
    if not isinstance(values, tuple) or not values:
        raise P3GateRegistryError(f"{label} must be a non-empty tuple")
    if any(not isinstance(value, str) or not value for value in values):
        raise P3GateRegistryError(f"{label} contains invalid text")
    if len(set(values)) != len(values):
        raise P3GateRegistryError(f"{label} contains duplicates")
    return values


def validate_p3_registry(
    records: Sequence[FlowGateContract],
) -> tuple[FlowGateContract, ...]:
    """Validate exact coverage and its live binding to the authority matrix."""

    if not isinstance(records, (tuple, list)):
        raise P3GateRegistryError("P3 registry must be an ordered sequence")
    checked = tuple(records)
    if any(not isinstance(record, FlowGateContract) for record in checked):
        raise P3GateRegistryError("P3 flow contract is invalid")
    if any(not isinstance(record.flow_id, str) for record in checked):
        raise P3GateRegistryError("P3 flow contract is invalid")
    if tuple(record.flow_id for record in checked) != P3_FLOW_IDS:
        raise P3GateRegistryError("P3 registry must cover the exact ordered flow set")
    matrix = _matrix_flows()
    for record in checked:
        if (
            type(record.schema_version) is not int
            or record.schema_version != P3_GATE_SCHEMA_VERSION
            or _ID.fullmatch(record.flow_id) is None
        ):
            raise P3GateRegistryError("P3 flow contract is invalid")
        flow = matrix[record.flow_id]
        exact_actions = tuple(
            str(action["action_id"])
            for action in flow["actions"]  # type: ignore[index]
        )
        if (
            record.authority_ceiling != flow["authority_ceiling"]
            or record.action_ids != exact_actions
        ):
            raise P3GateRegistryError(
                "P3 authority binding drifted from canonical matrix"
            )
        state = record.state
        if (
            not isinstance(state, StateContract)
            or not isinstance(state.kind, str)
            or state.kind not in _STATE_KINDS
            or not isinstance(state.carrier, str)
            or not state.carrier
            or not isinstance(state.replay_key, str)
            or not state.replay_key
        ):
            raise P3GateRegistryError("P3 state contract is invalid")
        _unique_texts(state.producer_statuses, "producer statuses")
        _unique_texts(state.finalized_statuses, "finalized statuses")
        if (
            not isinstance(record.inspector, str)
            or _INSPECTOR.fullmatch(record.inspector) is None
        ):
            raise P3GateRegistryError("P3 inspector reference is invalid")
        acceptance = _unique_texts(record.acceptance_test_nodes, "acceptance nodes")
        failures = _unique_texts(record.failure_test_nodes, "failure nodes")
        if any(_TEST_NODE.fullmatch(node) is None for node in (*acceptance, *failures)):
            raise P3GateRegistryError("P3 test node reference is invalid")
        if (
            not isinstance(record.integration_status, str)
            or record.integration_status not in _INTEGRATION_STATUSES
        ):
            raise P3GateRegistryError("P3 integration status is invalid")
        expected = _COVERAGE[record.flow_id]
        if (
            state != expected[0]
            or record.inspector != expected[1]
            or acceptance != expected[2]
            or failures != expected[3]
            or record.integration_status != expected[4]
        ):
            raise P3GateRegistryError(
                "P3 coverage binding drifted from canonical registry"
            )
    return checked


__all__ = [
    "P3_FLOW_IDS",
    "P3_GATE_SCHEMA_VERSION",
    "FlowGateContract",
    "P3GateRegistryError",
    "StateContract",
    "canonical_p3_registry",
    "validate_p3_registry",
]
