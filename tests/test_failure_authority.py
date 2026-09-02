"""P0-06 acceptance and main failure-mode regressions."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from tool_life_os_runtime.failure_authority import (
    REQUIRED_ACTION_IDS,
    REQUIRED_ACTION_SECURITY_DIGESTS,
    REQUIRED_ACTION_TARGETS,
    ACTION_SECURITY_FIELDS,
    REQUIRED_FLOW_IDS,
    FailureAuthorityError,
    authority_at_most,
    authorize_action,
    canonical_matrix,
    check_artifacts,
    load_matrix,
    render_pair,
    validate_matrix,
)


ROOT = Path(__file__).resolve().parents[1]
JSON_ARTIFACT = ROOT / "docs" / "failure-authority-matrix.json"
MARKDOWN_ARTIFACT = ROOT / "docs" / "failure-authority-matrix.md"

LEGACY_SKILL_TARGETS = {
    "ingest",
    "apply",
    "ask",
    "research",
    "engine",
    "project",
    "plan",
    "book",
    "mentor",
    "report",
    "lint",
    "ambient",
    "bundle",
    "grill-me",
    "obsidian",
}


@pytest.mark.parametrize(
    ("authority", "ceiling", "allowed"),
    [
        ("read", "read", True),
        ("internal-write", "proposal", True),
        ("proposal", "internal-write", False),
        ("domain-write", "protected-write", True),
        ("protected-write", "domain-write", False),
    ],
)
def test_canonical_authority_rank_contract(authority, ceiling, allowed):
    assert authority_at_most(authority, ceiling) is allowed


def test_canonical_authority_rank_rejects_unknown_values():
    with pytest.raises(FailureAuthorityError, match="unknown authority rank"):
        authority_at_most("unknown", "proposal")


def _flow(payload: dict[str, object], flow_id: str) -> dict[str, object]:
    return next(flow for flow in payload["flows"] if flow["flow_id"] == flow_id)


def _action(flow: dict[str, object], action_id: str) -> dict[str, object]:
    return next(action for action in flow["actions"] if action["action_id"] == action_id)


def _security_digest(record: dict[str, object], fields: tuple[str, ...]) -> str:
    payload = {field: record[field] for field in fields}
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def test_canonical_matrix_covers_target_flows_and_actions():
    payload = canonical_matrix()

    validate_matrix(payload)

    assert set(payload["flow_inventory"]) == REQUIRED_FLOW_IDS
    assert LEGACY_SKILL_TARGETS <= REQUIRED_FLOW_IDS
    assert {flow["flow_id"] for flow in payload["flows"]} == REQUIRED_FLOW_IDS
    for flow in payload["flows"]:
        assert {action["action_id"] for action in flow["actions"]} == REQUIRED_ACTION_IDS[flow["flow_id"]]
        assert {
            action["action_id"]: (action["access"], action["target"])
            for action in flow["actions"]
        } == REQUIRED_ACTION_TARGETS[flow["flow_id"]]
        assert {
            action["action_id"]: _security_digest(action, ACTION_SECURITY_FIELDS)
            for action in flow["actions"]
        } == REQUIRED_ACTION_SECURITY_DIGESTS[flow["flow_id"]]
        assert set(flow["allowed_reads"]) == {
            action["target"] for action in flow["actions"] if action["access"] == "read"
        }
        assert flow["eval_class"] in {"objective", "bounded-subjective", "owner-judgment"}
        assert flow["crash_points"]
        assert flow["retry_owner"]
        assert flow["rollback"]


def test_generated_artifacts_are_canonical_and_match_catalog():
    checked = load_matrix(JSON_ARTIFACT)
    check_artifacts(JSON_ARTIFACT, MARKDOWN_ARTIFACT)

    assert checked == canonical_matrix()
    json_text, markdown_text = render_pair(checked)
    assert JSON_ARTIFACT.read_text("utf-8") == json_text
    assert MARKDOWN_ARTIFACT.read_text("utf-8") == markdown_text
    assert hashlib.sha256(json_text.encode()).hexdigest() in markdown_text


def test_render_is_byte_deterministic():
    payload = canonical_matrix()
    assert render_pair(payload) == render_pair(copy.deepcopy(payload))


def test_artifacts_are_privacy_safe_symbolic_contracts():
    combined = JSON_ARTIFACT.read_text("utf-8") + MARKDOWN_ARTIFACT.read_text("utf-8")
    private_home_markers = ("/" + "Users" + "/", "/" + "home" + "/")

    assert all(marker not in combined for marker in private_home_markers)
    assert "file:" not in combined
    assert "legacy-vault/" not in combined
    assert "legacy-corpora" not in combined


@pytest.mark.parametrize("missing", ["flow", "action"])
def test_validator_fails_closed_when_required_item_is_missing(missing):
    payload = canonical_matrix()
    if missing == "flow":
        payload["flows"] = payload["flows"][1:]
        payload["flow_inventory"] = payload["flow_inventory"][1:]
    else:
        flow = _flow(payload, "apply")
        flow["actions"] = [
            action for action in flow["actions"] if action["action_id"] != "commit-approved-knowledge"
        ]
        flow["allowed_writes"] = ["vault:agent/runs"]
        flow["crash_points"] = sorted(
            {point for action in flow["actions"] for point in action["crash_points"]}
        )

    with pytest.raises(FailureAuthorityError, match="required"):
        validate_matrix(payload)


def test_action_authorization_is_exact_and_unknowns_fail_closed():
    payload = canonical_matrix()
    action = authorize_action(
        payload,
        flow_id="apply",
        action_id="commit-approved-knowledge",
        actor="runtime-human-approved",
        authority="protected-write",
        target="vault:knowledge",
    )
    assert action["effect_kind"] == "protected-artifact-commit"

    requests = (
        {"flow_id": "missing", "action_id": "x", "actor": "runtime", "authority": "read", "target": "vault:knowledge"},
        {"flow_id": "apply", "action_id": "missing", "actor": "runtime", "authority": "read", "target": "vault:review"},
        {"flow_id": "apply", "action_id": "commit-approved-knowledge", "actor": "runtime", "authority": "protected-write", "target": "vault:knowledge"},
        {"flow_id": "apply", "action_id": "commit-approved-knowledge", "actor": "runtime-human-approved", "authority": "domain-write", "target": "vault:knowledge"},
        {"flow_id": "apply", "action_id": "commit-approved-knowledge", "actor": "runtime-human-approved", "authority": "protected-write", "target": "vault:projects"},
    )
    for request in requests:
        with pytest.raises(FailureAuthorityError):
            authorize_action(payload, **request)


def test_knowledge_write_is_only_protected_apply():
    payload = canonical_matrix()
    knowledge_writes = [
        (flow["flow_id"], action)
        for flow in payload["flows"]
        for action in flow["actions"]
        if action["access"] == "write" and action["target"] == "vault:knowledge"
    ]

    assert [(flow_id, action["action_id"], action["authority"]) for flow_id, action in knowledge_writes] == [
        ("apply", "commit-approved-knowledge", "protected-write")
    ]


@pytest.mark.parametrize(
    ("flow_id", "action_id", "field", "value", "message"),
    [
        ("ask", "optional-file-back-proposal", "target", "vault:knowledge", "knowledge"),
        ("apply", "commit-approved-knowledge", "authority", "domain-write", "knowledge"),
        ("apply", "commit-approved-knowledge", "target", "vault:projects", "protected-write"),
        ("project", "commit-project-transition", "target", "legacy:vault", "legacy"),
    ],
)
def test_authority_mutations_are_rejected(flow_id, action_id, field, value, message):
    payload = canonical_matrix()
    flow = _flow(payload, flow_id)
    action = _action(flow, action_id)
    old_target = action["target"]
    action[field] = value
    if field == "target" and action["access"] == "write":
        flow["allowed_writes"] = sorted(
            value if item == old_target else item for item in flow["allowed_writes"]
        )

    with pytest.raises(FailureAuthorityError, match=message):
        validate_matrix(payload)


def test_gateway_and_scheduler_are_separate_from_artifact_commit():
    payload = canonical_matrix()
    ambient = _flow(payload, "ambient")
    bundle = _flow(payload, "bundle")
    connector = _flow(payload, "gateway-delivery")
    transport = _flow(payload, "gateway-transport")
    scheduler = _flow(payload, "scheduler-execution")

    assert "gateway:normalized-event-stdin" not in ambient["allowed_invocations"]
    assert "gateway:normalized-event-stdin" not in bundle["allowed_invocations"]
    assert "runtime:flow-entry" not in connector["allowed_invocations"]
    assert all(not action["artifact_commit"] for action in scheduler["actions"])
    assert _action(ambient, "commit-nudge-outbox-event")["artifact_commit"] is True
    assert _action(bundle, "commit-bundle-outbox-event")["artifact_commit"] is True
    assert transport["irreversible_effects"] == ["gateway-transport/deliver-channel-event"]

    assert connector["actor"] == "runtime"
    assert _action(connector, "read-semantic-outbox-event")["actor"] == "runtime"
    assert _action(connector, "invoke-normalized-gateway-event")["effect_kind"] == "gateway-connector-invocation"
    assert _action(connector, "reconcile-outbox-receipt")["effect_kind"] == "gateway-receipt-reconciliation"
    assert _action(connector, "reconcile-outbox-receipt")["artifact_commit"] is True

    assert transport["actor"] == "gateway"
    assert "vault:agent/outbox" not in transport["allowed_reads"]
    assert _action(transport, "deliver-channel-event")["effect_kind"] == "gateway-transport"
    assert _action(transport, "deliver-channel-event")["artifact_commit"] is False
    assert _action(transport, "commit-delivery-receipt")["effect_kind"] == "gateway-receipt-commit"
    assert _action(transport, "commit-delivery-receipt")["artifact_commit"] is True


@pytest.mark.parametrize("flow_id", ["ambient", "bundle"])
def test_scheduled_domain_actions_use_system_actor(flow_id):
    flow = _flow(canonical_matrix(), flow_id)
    assert flow["actor"] == "system"
    assert {action["actor"] for action in flow["actions"]} == {"system"}


def test_transport_or_scheduler_artifact_commit_mutation_fails():
    for flow_id, action_id in (
        ("gateway-transport", "deliver-channel-event"),
        ("scheduler-execution", "record-job-attempt"),
    ):
        payload = canonical_matrix()
        action = _action(_flow(payload, flow_id), action_id)
        action["artifact_commit"] = True
        with pytest.raises(FailureAuthorityError, match="mixed with artifact commit"):
            validate_matrix(payload)


@pytest.mark.parametrize("access", ["read", "write"])
def test_arbitrary_target_fails_even_if_allowed_targets_are_changed_too(access):
    payload = canonical_matrix()
    flow = _flow(payload, "obsidian")
    action_id = "read-safe-note" if access == "read" else "edit-projects"
    action = _action(flow, action_id)
    old_target = action["target"]
    action["target"] = "vault:arbitrary-zone"
    field = "allowed_reads" if access == "read" else "allowed_writes"
    flow[field] = sorted(
        "vault:arbitrary-zone" if target == old_target else target
        for target in flow[field]
    )

    with pytest.raises(FailureAuthorityError, match="required target registry"):
        validate_matrix(payload)


def test_allowed_read_without_authorized_read_action_fails():
    payload = canonical_matrix()
    _flow(payload, "ask")["allowed_reads"].append("vault:inbox")

    with pytest.raises(FailureAuthorityError, match="allowed_reads"):
        validate_matrix(payload)


def test_scheduler_invocation_is_internal_and_downstream_system_is_reauthorized():
    payload = canonical_matrix()
    invocation = _action(_flow(payload, "scheduler-execution"), "invoke-runtime-flow")

    assert invocation["authority"] == "internal-write"
    assert invocation["retry_owner"] == "scheduler"
    authorize_action(
        payload,
        flow_id="scheduler-execution",
        action_id="invoke-runtime-flow",
        actor="scheduler",
        authority="internal-write",
        target="runtime:flow-entry",
    )
    authorize_action(
        payload,
        flow_id="ambient",
        action_id="scan-eligible-signals",
        actor="system",
        authority="read",
        target="vault:tasks",
    )
    with pytest.raises(FailureAuthorityError, match="actor mismatch"):
        authorize_action(
            payload,
            flow_id="ambient",
            action_id="scan-eligible-signals",
            actor="scheduler",
            authority="read",
            target="vault:tasks",
        )


def test_infrastructure_read_retry_owners_match_service_boundary():
    payload = canonical_matrix()
    scheduler = _flow(payload, "scheduler-execution")
    transport = _flow(payload, "gateway-transport")

    assert {action["retry_owner"] for action in scheduler["actions"]} == {"scheduler"}
    assert {action["retry_owner"] for action in transport["actions"]} == {"gateway"}


@pytest.mark.parametrize(
    "flow_id",
    ["gateway-delivery", "gateway-transport", "scheduler-execution"],
)
def test_infrastructure_action_order_is_fail_closed(flow_id):
    payload = canonical_matrix()
    flow = _flow(payload, flow_id)
    flow["actions"] = list(reversed(flow["actions"]))

    with pytest.raises(FailureAuthorityError, match="canonical execution order"):
        validate_matrix(payload)


def test_canonical_entity_and_reading_targets_are_exact():
    payload = canonical_matrix()
    entities = _flow(payload, "entities")
    book = _flow(payload, "book")

    assert _action(entities, "read-entity-state")["target"] == "vault:agent/memory/entities"
    assert _action(entities, "commit-entity-state")["target"] == "vault:agent/memory/entities"
    assert _action(book, "read-reading-state")["target"] == "vault:agent/reading"
    assert _action(book, "commit-reading-state")["target"] == "vault:agent/reading"


def test_book_owns_reading_lifecycle_but_not_extraction():
    book = _flow(canonical_matrix(), "book")

    assert book["allowed_invocations"] == []
    assert _action(book, "read-source-manifest")["access"] == "read"
    assert all(action["target"] != "tool:coursedump" for action in book["actions"])


def test_entity_done_and_trail_records_are_distinct_actions_and_zones():
    entities = _flow(canonical_matrix(), "entities")
    done = _action(entities, "append-confirmed-done-event")
    trail = _action(entities, "append-entity-trail")

    assert done["target"] == "vault:agent/logs/done-events"
    assert trail["target"] == "vault:agent/memory/trails"
    assert done["target"] != trail["target"]
    assert done["effect_kind"] == "done-event-append"
    assert trail["effect_kind"] == "trail-append"
    assert done["actor"] == trail["actor"] == "runtime-human-confirmed"


def test_project_schedule_cascade_uses_scheduler_connector_action():
    project = _flow(canonical_matrix(), "project")
    transition = _action(project, "commit-project-transition")
    schedule = _action(project, "apply-linked-schedule-transition")
    order = [action["action_id"] for action in project["actions"]]

    assert transition["artifact_commit"] is True
    assert schedule["access"] == "invoke"
    assert schedule["target"] == "tool:scheduler"
    assert schedule["authority"] == "domain-write"
    assert schedule["effect_kind"] == "scheduler-connector-invocation"
    assert schedule["artifact_commit"] is False
    assert schedule["retry_owner"] == "scheduler"
    assert order.index("commit-project-transition") < order.index("apply-linked-schedule-transition")


def test_plan_rollover_snapshots_and_routes_feedback_to_review():
    plan = _flow(canonical_matrix(), "plan")
    snapshot = _action(plan, "snapshot-task-preimage")
    feedback = _action(plan, "commit-feedback-proposal")
    order = [action["action_id"] for action in plan["actions"]]

    assert snapshot["target"] == "vault:agent/logs/tasks"
    assert snapshot["effect_kind"] == "task-snapshot-commit"
    assert feedback["target"] == "vault:review"
    assert feedback["authority"] == "proposal"
    assert order.index("snapshot-task-preimage") < order.index("commit-plan-or-rollover")
    assert order.index("extract-feedback-markers") < order.index("commit-feedback-proposal")


def test_apply_finalizes_review_after_protected_commit():
    apply = _flow(canonical_matrix(), "apply")
    finalized = _action(apply, "finalize-applied-review")
    order = [action["action_id"] for action in apply["actions"]]

    assert finalized["target"] == "vault:review"
    assert finalized["authority"] == "internal-write"
    assert finalized["effect_kind"] == "review-finalization-commit"
    assert order.index("commit-approved-knowledge") < order.index("finalize-applied-review")


def test_finalize_separates_trace_metrics_log_outbox_and_state():
    finalize = _flow(canonical_matrix(), "finalize")
    trace = _action(finalize, "append-run-trace")
    metrics = _action(finalize, "commit-bounded-metrics")
    log = _action(finalize, "append-domain-log")
    outbox = _action(finalize, "emit-semantic-outbox-event")
    state = _action(finalize, "finalize-run-state")

    assert trace["target"] == "vault:agent/runs/trace"
    assert trace["effect_kind"] == "append-only-trace"
    assert metrics["target"] == "vault:agent/logs/metrics"
    assert metrics["effect_kind"] == "bounded-metrics-commit"
    assert len({trace["target"], metrics["target"], log["target"], outbox["target"], state["target"]}) == 5


def test_llmwiki_validation_belongs_to_distill_not_human_knowledge_ask():
    payload = canonical_matrix()
    distill = _flow(payload, "distill")
    ask = _flow(payload, "ask")

    assert _action(distill, "validate-machine-topic")["target"] == "tool:llmwiki"
    assert "tool:llmwiki" in distill["allowed_invocations"]
    assert "tool:llmwiki" not in ask["allowed_invocations"]


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("actor", "untrusted-executor", "invalid actor"),
        ("effect_kind", "implicit-side-effect", "invalid effect kind"),
        ("authority", "internal-write", "read action has non-read authority"),
    ],
)
def test_unknown_or_inconsistent_action_security_fields_fail_closed(field, value, message):
    payload = canonical_matrix()
    action = _action(_flow(payload, "ask"), "retrieve-cited-evidence")
    action[field] = value

    with pytest.raises(FailureAuthorityError, match=message):
        validate_matrix(payload)


@pytest.mark.parametrize(
    ("flow_id", "action_id", "field", "value"),
    [
        ("ask", "optional-file-back-proposal", "actor", "human"),
        ("ask", "optional-file-back-proposal", "effect_kind", "artifact-commit"),
        ("ask", "optional-file-back-proposal", "retry_owner", "human"),
        ("ask", "optional-file-back-proposal", "artifact_commit", False),
        ("gateway-transport", "deliver-channel-event", "irreversible", False),
        ("ask", "optional-file-back-proposal", "rollback", "discard-without-reconciliation"),
        ("ask", "optional-file-back-proposal", "crash_points", ["arbitrary-crash-boundary"]),
    ],
)
def test_exact_security_registry_rejects_valid_but_wrong_action_values(flow_id, action_id, field, value):
    payload = canonical_matrix()
    _action(_flow(payload, flow_id), action_id)[field] = value
    flow = _flow(payload, flow_id)
    if field == "irreversible":
        flow["irreversible_effects"] = []
    if field == "crash_points":
        flow["crash_points"] = sorted(
            {point for action in flow["actions"] for point in action["crash_points"]}
        )

    with pytest.raises(FailureAuthorityError, match="exact security registry"):
        validate_matrix(payload)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("eval_class", "objective"),
        ("authority_ceiling", "domain-write"),
        ("retry_owner", "human"),
        ("rollback", "discard-valid-state-and-restart"),
    ],
)
def test_exact_flow_registry_rejects_valid_but_wrong_failure_policy(field, value):
    payload = canonical_matrix()
    _flow(payload, "ask")[field] = value

    with pytest.raises(FailureAuthorityError, match="exact flow security registry"):
        validate_matrix(payload)


def test_scheduled_actor_mutation_is_rejected_by_public_validator():
    payload = canonical_matrix()
    _action(_flow(payload, "ambient"), "record-run-state")["actor"] = "runtime"

    with pytest.raises(FailureAuthorityError, match="exact security registry|system actor"):
        validate_matrix(payload)


def test_private_path_and_unknown_schema_field_fail_closed(tmp_path):
    payload = canonical_matrix()
    _flow(payload, "ask")["allowed_reads"][0] = "/" + "Users" + "/private/notes"
    with pytest.raises(FailureAuthorityError, match="private or absolute"):
        validate_matrix(payload)

    payload = canonical_matrix()
    payload["unexpected"] = True
    path = tmp_path / "matrix.json"
    path.write_text(json.dumps(payload), "utf-8")
    with pytest.raises(FailureAuthorityError, match="top-level"):
        load_matrix(path)


@pytest.mark.parametrize("schema_version", [True, 1.0, "1"])
def test_schema_version_requires_exact_integer_type(schema_version):
    payload = canonical_matrix()
    payload["schema_version"] = schema_version

    with pytest.raises(FailureAuthorityError, match="schema_version"):
        validate_matrix(payload)
