"""P3-10 ambient and bundle deterministic recovery acceptance."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil

import pytest

from tool_life_os_runtime.ext.flows.ambient import (
    AmbientAvailability,
    AmbientCandidate,
    AmbientCapabilities,
    AmbientCrashHooks,
    AmbientDisposition,
    AmbientFlow,
    AmbientFlowError,
    AmbientRequest,
    AmbientReviewBudget,
    AmbientRunEvidence,
    ambient_evidence_artifact_name,
    inspect_ambient_run_evidence,
    parse_ambient_run_evidence,
    render_ambient_run_evidence,
)
from tool_life_os_runtime.ext.flows.memory import (
    DecayPolicy,
    DeletionPolicy,
    MemoryEvidence,
    MemoryProposalRecord,
    RetentionPolicy,
    render_memory_proposal,
)
from tool_life_os_runtime.ext.flows.bundle import (
    BundleCapabilities,
    BundleCrashHooks,
    BundleFlow,
    BundleFlowError,
    BundleItem,
    BundleManifest,
    BundleReceiptVerificationPort,
    BundleRequest,
    BundleRunEvidence,
    BundleWindow,
    bundle_evidence_artifact_name,
    inspect_bundle_run_evidence,
    parse_bundle_manifest,
    parse_bundle_run_evidence,
    render_bundle_manifest,
    render_bundle_run_evidence,
)
from tool_life_os_runtime.ext.flows.plan import (
    DayPlan,
    PlanPolicy,
    PlanTask,
    render_day_plan,
)
from tool_life_os_runtime.ext.review.authority import AuthorityPolicy
from tool_life_os_runtime.ext.runs import OutboxStore, RunStore
from tool_life_os_runtime.ext.vault.config import load_vault_config
from tool_life_os_runtime.ext.vault.schema import VaultPathResolver


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/vault-minimal"
AT = "2026-01-15T09:00:00Z"


class _Clock:
    def __init__(self, value: datetime | None = None) -> None:
        self.value = value or datetime(2026, 1, 15, 9, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        current = self.value
        self.value += timedelta(microseconds=1)
        return current


class _ExactReceiptVerifier(BundleReceiptVerificationPort):
    def __init__(self, *, receipt_sha256: str, event_sha256: str) -> None:
        self._receipt_sha256 = receipt_sha256
        self._event_sha256 = event_sha256

    def verify_delivered(
        self,
        *,
        receipt,
        receipt_raw: bytes,
        event,
        event_raw: bytes,
    ) -> bool:
        return (
            receipt["event_id"] == event["event_id"]
            and hashlib.sha256(receipt_raw).hexdigest() == self._receipt_sha256
            and hashlib.sha256(event_raw).hexdigest() == self._event_sha256
        )


def _ambient_caps(policy: AuthorityPolicy) -> AmbientCapabilities:
    def issue(action: str, authority: str, target: str):
        return policy.issue(
            flow_id="ambient",
            action_id=action,
            actor="system",
            authority=authority,
            target=target,
        )

    return AmbientCapabilities(
        issue("scan-eligible-signals", "read", "vault:tasks"),
        issue("read-ambient-projects", "read", "vault:projects"),
        issue("read-ambient-review", "read", "vault:review"),
        issue("read-ambient-memory", "read", "vault:agent/memory"),
        issue("commit-nudge-outbox-event", "internal-write", "vault:agent/outbox"),
        issue("record-run-state", "internal-write", "vault:agent/runs"),
    )


def _bundle_caps(policy: AuthorityPolicy) -> BundleCapabilities:
    def issue(action: str, authority: str, target: str):
        return policy.issue(
            flow_id="bundle",
            action_id=action,
            actor="system",
            authority=authority,
            target=target,
        )

    return BundleCapabilities(
        issue("collect-batched-items", "read", "vault:review"),
        issue("read-pending-outbox", "read", "vault:agent/outbox"),
        issue("commit-bundle-outbox-event", "internal-write", "vault:agent/outbox"),
        issue("record-run-state", "internal-write", "vault:agent/runs"),
    )


def _setup(tmp_path: Path, *, surface: str = "gated"):
    vault = tmp_path / "vault"
    shutil.copytree(FIXTURE, vault)
    if surface != "gated":
        config_path = vault / "lifeos.toml"
        config_path.write_text(
            config_path.read_text("utf-8").replace(
                'default = "gated"', f'default = "{surface}"'
            ),
            "utf-8",
        )
    config = load_vault_config(vault / "lifeos.toml")
    resolver = VaultPathResolver(vault, config)
    clock = _Clock()
    runs = RunStore(resolver, clock=clock)
    policy = AuthorityPolicy()
    return vault, resolver, runs, policy, clock


def _run(runs: RunStore, run_id: str, flow: str) -> None:
    runs.create(
        run_id=run_id,
        flow=flow,
        phase="scan",
        authority="internal-write",
        executor="test",
        input_data={"fixture": "synthetic"},
    )
    runs.resume(run_id, executor="test")


def _request(operation_id: str = "ambient_scan") -> AmbientRequest:
    return AmbientRequest(
        operation_id,
        AT,
        AmbientAvailability(
            "available",
            "2026-01-15T08:00:00Z",
            "2026-01-15T10:00:00Z",
        ),
        AmbientReviewBudget(10, 20),
    )


def _bundle_request(operation_id: str = "bundle_scan") -> BundleRequest:
    return BundleRequest(
        operation_id,
        "2026-01-15T10:00:00Z",
        BundleWindow("2026-01-15T08:00:00Z", "2026-01-15T10:00:00Z"),
    )


def _request_sha256(request: AmbientRequest | BundleRequest) -> str:
    if isinstance(request, AmbientRequest):
        payload = {
            "schema_version": 1,
            "operation_id": request.operation_id,
            "observed_at": request.observed_at,
            "availability": {
                "schema_version": 1,
                "status": request.availability.status,
                "valid_from": request.availability.valid_from,
                "valid_until": request.availability.valid_until,
            },
            "review_budget": {
                "schema_version": 1,
                "soft_limit": request.review_budget.soft_limit,
                "hard_limit": request.review_budget.hard_limit,
            },
        }
    else:
        payload = {
            "schema_version": 1,
            "operation_id": request.operation_id,
            "observed_at": request.observed_at,
            "window": {
                "schema_version": 1,
                "start": request.window.start,
                "end": request.window.end,
            },
        }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(raw).hexdigest()


def _write_day(
    vault: Path, *, priority: str = "high", text: str = "Synthetic task"
) -> None:
    plan = DayPlan(
        "2026-01-15",
        "active",
        1,
        PlanPolicy(10, 3),
        (PlanTask("task-alpha", text, "2026-01-15", priority=priority),),
        "2026-01-15T08:00:00Z",
        "2026-01-15T08:00:00Z",
        "plan_seed",
        "0" * 64,
    )
    directory = vault / "tasks/days"
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "2026-01-15.json").write_bytes(render_day_plan(plan))


def _canonical_file(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(
        json.dumps(
            payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        + b"\n"
    )


def _tree_bytes(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def _tamper_committed_trace(
    vault: Path,
    *,
    run_id: str,
    step_id: str,
    corruption: str,
) -> None:
    run_root = vault / "agent/runs" / run_id
    trace_path = run_root / "trace.jsonl"
    events = [
        json.loads(line) for line in trace_path.read_text("utf-8").splitlines() if line
    ]
    matches = [event for event in events if event["step_id"] == step_id]
    assert len(matches) == 1
    event = matches[0]
    if corruption == "duplicate":
        events.append(dict(event))
    else:
        if corruption == "legacy":
            event["schema_version"] = 1
            event.pop("actions")
        elif corruption == "order":
            event["actions"][0], event["actions"][1] = (
                event["actions"][1],
                event["actions"][0],
            )
            for sequence, action in enumerate(event["actions"], start=1):
                action["sequence"] = sequence
        else:
            event["actions"][0]["status"] = "failed"
        intent_path = run_root / "intents" / f"{step_id}.json"
        intent = json.loads(intent_path.read_text("utf-8"))
        intent["trace_event"] = event
        intent_path.write_text(
            json.dumps(intent, sort_keys=True, separators=(",", ":")) + "\n",
            "utf-8",
        )
    trace_path.write_text(
        "".join(
            json.dumps(item, sort_keys=True, separators=(",", ":")) + "\n"
            for item in events
        ),
        "utf-8",
    )


def _write_bool_schema_source(vault: Path, source: str) -> None:
    if source.startswith("project-"):
        _write_project(vault)
        filename = "project.json" if source == "project-record" else "state.json"
        path = vault / "projects/portable-project" / filename
        payload = json.loads(path.read_text("utf-8"))
        payload["schema_version"] = True
        _canonical_file(path, payload)
        return

    if source.startswith("entity-"):
        _write_entity(vault)
        path = vault / "agent/memory/entities/systems.json"
        payload = json.loads(path.read_text("utf-8"))
        entity = payload["entities"][0]
        if source == "entity-collection":
            payload["schema_version"] = True
        elif source == "entity-record":
            entity["schema_version"] = True
        elif source == "entity-step":
            entity["steps"] = [
                {
                    "schema_version": True,
                    "id": "step-bool-schema",
                    "text": "Synthetic step.",
                    "status": "open",
                    "checked_at": None,
                }
            ]
        else:
            entity["next_check"] = {
                "schema_version": True,
                "kind": "at",
                "due_at": "2026-01-15T08:30:00Z",
                "interval_days": None,
            }
        _canonical_file(path, payload)
        return

    _canonical_file(
        vault / "review/tasks-feedback-bool-schema.json",
        {
            "schema_version": True,
            "proposal_id": "feedback_bool_schema",
            "operation_id": "feedback_bool_source",
            "status": "proposed",
            "created_at": "2026-01-15T08:00:00Z",
            "items": [
                {
                    "task_id": "task-alpha",
                    "task_text": "Synthetic task.",
                    "feedback": "Synthetic feedback.",
                    "source_date": "2026-01-15",
                }
            ],
        },
    )


def _write_project(vault: Path) -> None:
    root = vault / "projects/portable-project"
    _canonical_file(
        root / "project.json",
        {
            "schema_version": 1,
            "slug": "portable-project",
            "name": "Portable project",
            "goal": "Synthetic goal.",
            "domains": ["systems"],
            "kind": "general",
            "status": "active",
            "created_at": "2026-01-15T07:00:00Z",
            "updated_at": "2026-01-15T08:00:00Z",
            "on_hold_since": None,
            "on_hold_reason": None,
            "archived_at": None,
            "revision": 1,
            "last_transition_id": "project_seed",
            "schedule_ids": [],
        },
    )
    _canonical_file(
        root / "state.json",
        {
            "schema_version": 1,
            "project_slug": "portable-project",
            "revision": 1,
            "next_steps": [
                {
                    "id": "step_next",
                    "text": "Next",
                    "status": "open",
                    "priority": "medium",
                }
            ],
            "blockers": [{"id": "blocker_open", "text": "Blocked", "status": "open"}],
            "open_questions": [],
            "milestones": [],
            "last_session": None,
        },
    )


def _write_entity(vault: Path) -> None:
    entity = {
        "schema_version": 1,
        "id": "ent-alpha",
        "domain": "systems",
        "title": "Synthetic entity",
        "description": "Fixture.",
        "status": "active",
        "priority": "high",
        "steps": [],
        "deadline": None,
        "next_review_at": "2026-01-15T08:00:00Z",
        "next_check": None,
        "escalation_paused_until": None,
        "created_at": "2026-01-14T08:00:00Z",
        "updated_at": "2026-01-14T08:00:00Z",
        "closed_at": None,
        "revision": 1,
        "last_mutation_id": "entity_seed",
        "last_mutation_sha256": "3" * 64,
    }
    _canonical_file(
        vault / "agent/memory/entities/systems.json",
        {"schema_version": 1, "domain": "systems", "revision": 1, "entities": [entity]},
    )


def _write_memory_proposal(
    vault: Path,
    *,
    expires_at: str,
    created_at: str = "2026-01-15T08:30:00Z",
) -> None:
    proposal = MemoryProposalRecord(
        proposal_id="memprop-ambient",
        status="proposed",
        operation="create",
        memory_id="mem-ambient",
        memory_kind="feedback",
        scope="workday",
        candidate_text="Synthetic candidate.",
        evidence=(
            MemoryEvidence(
                "evidence_ambient",
                "task-feedback",
                "agent/logs/tasks/skipped.jsonl",
                "4" * 64,
                "anchor_ambient",
                "human",
                "2026-01-15T08:00:00Z",
                "Synthetic feedback.",
            ),
        ),
        current_memory_ref=None,
        current_memory_sha256=None,
        precondition_sha256=None,
        retention=RetentionPolicy("manual"),
        decay=DecayPolicy("expires", expires_at=expires_at),
        deletion=DeletionPolicy("forget"),
        producer_flow="report",
        run_id="run_report_ambient",
        operation_id="extract_ambient",
        created_at=created_at,
    )
    target = vault / "review/memprop-ambient.memory.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(render_memory_proposal(proposal))


def _event_files(vault: Path) -> list[Path]:
    return sorted(
        path for path in (vault / "agent/outbox").glob("event_*.json") if path.is_file()
    )


def _replace_file_with_same_bytes(target: Path, held: Path) -> None:
    raw = target.read_bytes()
    held.parent.mkdir(parents=True, exist_ok=True)
    target.rename(held)
    target.write_bytes(raw)


def _replace_tree_with_same_bytes(target: Path, held: Path) -> None:
    held.parent.mkdir(parents=True, exist_ok=True)
    target.rename(held)
    shutil.copytree(held, target)


def _has_flow_event(root: Path, flow_id: str) -> bool:
    for path in _event_files(root):
        try:
            if json.loads(path.read_text("utf-8"))["flow_id"] == flow_id:
                return True
        except (KeyError, UnicodeError, json.JSONDecodeError):
            continue
    return False


def _prepare_bundle_identity_sources(tmp_path: Path):
    vault, resolver, runs, policy, clock = _setup(tmp_path, surface="batched")
    _write_day(vault)
    _write_memory_proposal(vault, expires_at="2026-01-16T09:00:00Z")
    _run(runs, "run_ambient_identity_source", "ambient")
    with AmbientFlow(resolver, runs, policy, clock) as ambient_flow:
        ambient = ambient_flow.scan(
            _ambient_caps(policy),
            run_id="run_ambient_identity_source",
            request=_request("ambient_identity_source"),
        )
    receipt_cap = policy.issue(
        flow_id="gateway-delivery",
        action_id="reconcile-outbox-receipt",
        actor="runtime",
        authority="internal-write",
        target="vault:agent/outbox",
    )
    with OutboxStore(resolver, runs, policy=policy, clock=clock) as outbox:
        receipt = outbox.record_delivery_receipt(
            receipt_cap,
            event_id=str(ambient.event_id),
            attempt_id="attempt_identity_source",
            status="delivered",
            effect_hash="1" * 64,
        )
    event_path = next(
        path
        for path in _event_files(vault)
        if json.loads(path.read_text("utf-8"))["flow_id"] == "ambient"
    )
    receipt_path = vault / "agent/outbox/receipts" / f"{receipt['receipt_id']}.json"
    return vault, resolver, runs, policy, clock, event_path, receipt_path


def _trace_actions(runs: RunStore, run_id: str) -> list[str]:
    return [str(item["action_id"]) for item in runs.trace_events(run_id)[-1]["actions"]]


def test_ambient_emits_one_content_addressed_event_and_exact_evidence(
    tmp_path: Path,
) -> None:
    vault, resolver, runs, policy, clock = _setup(tmp_path)
    _write_day(vault)
    _run(runs, "run_ambient", "ambient")
    flow = AmbientFlow(resolver, runs, policy, clock)

    result = flow.scan(_ambient_caps(policy), run_id="run_ambient", request=_request())

    assert result.outcome == "emitted"
    assert len(_event_files(vault)) == 1
    assert runs.status("run_ambient")["status"] == "running"
    assert _trace_actions(runs, "run_ambient") == [
        "scan-eligible-signals",
        "read-ambient-projects",
        "read-ambient-review",
        "read-ambient-memory",
        "commit-nudge-outbox-event",
        "record-run-state",
    ]
    bundle = runs.producer_snapshot(
        "run_ambient", producer_evidence=result.evidence_artifact
    )
    assert len(bundle.artifacts) == 4
    evidence_artifact = next(
        item for item in bundle.artifacts if item.name == result.evidence_artifact
    )
    evidence = inspect_ambient_run_evidence(
        evidence_artifact, vault.joinpath(evidence_artifact.state_ref).read_bytes()
    )
    assert evidence.outcome == "emitted"
    assert evidence.selected is not None
    assert evidence.dispositions[0].reason == "emitted"
    assert evidence.payload_ref is not None
    delivered = vault.joinpath(evidence.payload_ref).read_text("utf-8")
    assert "Synthetic task" not in delivered
    assert "tasks/days" not in delivered


def test_ambient_duplicate_across_runs_is_one_event_and_replays_before_sources(
    tmp_path: Path,
) -> None:
    vault, resolver, runs, policy, clock = _setup(tmp_path)
    _write_day(vault)
    caps = _ambient_caps(policy)
    _run(runs, "run_ambient_a", "ambient")
    first = AmbientFlow(resolver, runs, policy, clock).scan(
        caps, run_id="run_ambient_a", request=_request()
    )
    (vault / "tasks/days/2026-01-15.json").write_bytes(b"not-json")
    _run(runs, "run_ambient_b", "ambient")

    second = AmbientFlow(resolver, runs, policy, clock).scan(
        caps, run_id="run_ambient_b", request=_request()
    )

    assert second.replayed is True
    assert second.event_id == first.event_id
    assert len(_event_files(vault)) == 1


def test_ambient_semantic_dedupe_across_distinct_operations_is_one_event(
    tmp_path: Path,
) -> None:
    vault, resolver, runs, policy, clock = _setup(tmp_path)
    _write_day(vault)
    _run(runs, "run_ambient_semantic_a", "ambient")
    first = AmbientFlow(resolver, runs, policy, clock).scan(
        _ambient_caps(policy),
        run_id="run_ambient_semantic_a",
        request=_request("ambient_semantic_a"),
    )
    _run(runs, "run_ambient_semantic_b", "ambient")
    second = AmbientFlow(resolver, runs, policy, clock).scan(
        _ambient_caps(policy),
        run_id="run_ambient_semantic_b",
        request=_request("ambient_semantic_b"),
    )
    assert second.event_id == first.event_id
    assert len(_event_files(vault)) == 1


def test_ambient_zero_is_silent_semantic_success_and_stays_running(
    tmp_path: Path,
) -> None:
    vault, resolver, runs, policy, clock = _setup(tmp_path)
    _run(runs, "run_ambient_zero", "ambient")

    result = AmbientFlow(resolver, runs, policy, clock).scan(
        _ambient_caps(policy),
        run_id="run_ambient_zero",
        request=_request("ambient_zero"),
    )

    assert result.outcome == "zero"
    assert result.event_id is None
    assert _event_files(vault) == []
    assert runs.status("run_ambient_zero")["status"] == "running"
    assert _trace_actions(runs, "run_ambient_zero") == [
        "scan-eligible-signals",
        "read-ambient-projects",
        "read-ambient-review",
        "read-ambient-memory",
        "record-run-state",
    ]


def test_uncommitted_ambient_zero_evidence_cannot_hide_due_task(
    tmp_path: Path,
) -> None:
    vault, resolver, runs, policy, clock = _setup(tmp_path)
    _write_day(vault)
    run_id = "run_ambient_uncommitted_zero"
    request = _request("ambient_uncommitted_zero")
    _run(runs, run_id, "ambient")
    snapshot = runs.snapshot(run_id)
    empty_candidates_sha = hashlib.sha256(
        json.dumps(
            {"schema_version": 1, "candidates": []},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    evidence = AmbientRunEvidence(
        run_id,
        request.operation_id,
        _request_sha256(request),
        snapshot.state_sha256,
        "zero",
        0,
        0,
        empty_candidates_sha,
        None,
        (),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    )
    runs.prepare_run_artifact(
        run_id,
        name=ambient_evidence_artifact_name(request.operation_id),
        data=render_ambient_run_evidence(evidence),
    )
    before_run = _tree_bytes(vault / "agent/runs" / run_id)
    before_outbox = _tree_bytes(vault / "agent/outbox")

    with AmbientFlow(resolver, runs, policy, clock) as flow:
        with pytest.raises(AmbientFlowError, match="recomputed sources"):
            flow.scan(_ambient_caps(policy), run_id=run_id, request=request)

    assert _tree_bytes(vault / "agent/runs" / run_id) == before_run
    assert _tree_bytes(vault / "agent/outbox") == before_outbox


def test_uncommitted_bundle_empty_evidence_cannot_hide_pending_event(
    tmp_path: Path,
) -> None:
    vault, resolver, runs, policy, clock = _setup(tmp_path, surface="batched")
    _write_day(vault)
    _run(runs, "run_ambient_bundle_pending", "ambient")
    ambient = AmbientFlow(resolver, runs, policy, clock).scan(
        _ambient_caps(policy),
        run_id="run_ambient_bundle_pending",
        request=_request("ambient_bundle_pending"),
    )
    assert ambient.event_id is not None
    run_id = "run_bundle_uncommitted_empty"
    request = _bundle_request("bundle_uncommitted_empty")
    _run(runs, run_id, "bundle")
    snapshot = runs.snapshot(run_id)
    empty_core = {
        "schema_version": 1,
        "kind": "batched-digest",
        "window": {
            "schema_version": 1,
            "start": request.window.start,
            "end": request.window.end,
        },
        "items": [],
    }
    evidence = BundleRunEvidence(
        run_id,
        request.operation_id,
        _request_sha256(request),
        snapshot.state_sha256,
        "empty",
        0,
        hashlib.sha256(
            json.dumps(empty_core, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    )
    runs.prepare_run_artifact(
        run_id,
        name=bundle_evidence_artifact_name(request.operation_id),
        data=render_bundle_run_evidence(evidence),
    )
    before_run = _tree_bytes(vault / "agent/runs" / run_id)
    before_outbox = _tree_bytes(vault / "agent/outbox")

    with BundleFlow(resolver, runs, policy, clock) as flow:
        with pytest.raises(BundleFlowError, match="recomputed sources"):
            flow.collect(_bundle_caps(policy), run_id=run_id, request=request)

    assert _tree_bytes(vault / "agent/runs" / run_id) == before_run
    assert _tree_bytes(vault / "agent/outbox") == before_outbox


@pytest.mark.parametrize("flow_name", ["ambient", "bundle"])
def test_empty_prepared_evidence_retry_recomputes_sources(
    tmp_path: Path, flow_name: str
) -> None:
    vault, resolver, runs, policy, clock = _setup(tmp_path)
    run_id = f"run_{flow_name}_empty_retry"
    operation_id = f"{flow_name}_empty_retry"
    _run(runs, run_id, flow_name)

    def crash() -> None:
        raise RuntimeError("prepared-evidence-crash")

    if flow_name == "ambient":
        request = _request(operation_id)
        with AmbientFlow(resolver, runs, policy, clock) as flow:
            with pytest.raises(RuntimeError, match="prepared-evidence-crash"):
                flow.scan(
                    _ambient_caps(policy),
                    run_id=run_id,
                    request=request,
                    crash_hooks=AmbientCrashHooks(after_evidence_prepare=crash),
                )
        with AmbientFlow(resolver, runs, policy, clock) as flow:
            result = flow.scan(_ambient_caps(policy), run_id=run_id, request=request)
        assert result.outcome == "zero"
    else:
        request = _bundle_request(operation_id)
        with BundleFlow(resolver, runs, policy, clock) as flow:
            with pytest.raises(RuntimeError, match="prepared-evidence-crash"):
                flow.collect(
                    _bundle_caps(policy),
                    run_id=run_id,
                    request=request,
                    crash_hooks=BundleCrashHooks(after_evidence_prepare=crash),
                )
        with BundleFlow(resolver, runs, policy, clock) as flow:
            result = flow.collect(_bundle_caps(policy), run_id=run_id, request=request)
        assert result.outcome == "empty"

    assert result.replayed is True
    assert _event_files(vault) == []
    assert runs.status(run_id)["status"] == "running"


@pytest.mark.parametrize(
    ("flow_name", "stage", "corruption"),
    [
        (flow_name, "final", corruption)
        for flow_name in ("ambient", "bundle")
        for corruption in ("legacy", "order", "status", "duplicate")
    ]
    + [
        (flow_name, "anchor", corruption)
        for flow_name in ("ambient", "bundle")
        for corruption in ("legacy", "status", "duplicate")
    ],
)
def test_committed_replay_requires_exact_final_and_anchor_trace_without_effect(
    tmp_path: Path, flow_name: str, stage: str, corruption: str
) -> None:
    if flow_name == "ambient":
        vault, resolver, runs, policy, clock = _setup(tmp_path)
        _write_day(vault)
    else:
        vault, resolver, runs, policy, clock, _event, _receipt = (
            _prepare_bundle_identity_sources(tmp_path)
        )
    run_id = f"run_{flow_name}_{stage}_{corruption}"
    operation_id = f"{flow_name}_{stage}_{corruption}"
    _run(runs, run_id, flow_name)

    if flow_name == "ambient":
        request = _request(operation_id)
        if stage == "final":
            AmbientFlow(resolver, runs, policy, clock).scan(
                _ambient_caps(policy), run_id=run_id, request=request
            )
            step_id = (
                "ambient-" + hashlib.sha256(operation_id.encode()).hexdigest()[:32]
            )
        else:
            with pytest.raises(RuntimeError, match="anchor-trace-crash"):
                AmbientFlow(resolver, runs, policy, clock).scan(
                    _ambient_caps(policy),
                    run_id=run_id,
                    request=request,
                    crash_hooks=AmbientCrashHooks(
                        after_payload_prepare=lambda: (_ for _ in ()).throw(
                            RuntimeError("anchor-trace-crash")
                        )
                    ),
                )
            step_id = (
                "ambient-anchor-"
                + hashlib.sha256(operation_id.encode()).hexdigest()[:32]
            )
        expected_error = AmbientFlowError
    else:
        request = _bundle_request(operation_id)
        if stage == "final":
            BundleFlow(resolver, runs, policy, clock).collect(
                _bundle_caps(policy), run_id=run_id, request=request
            )
            step_id = "bundle-" + hashlib.sha256(operation_id.encode()).hexdigest()[:32]
        else:
            with pytest.raises(RuntimeError, match="anchor-trace-crash"):
                BundleFlow(resolver, runs, policy, clock).collect(
                    _bundle_caps(policy),
                    run_id=run_id,
                    request=request,
                    crash_hooks=BundleCrashHooks(
                        after_payload_prepare=lambda: (_ for _ in ()).throw(
                            RuntimeError("anchor-trace-crash")
                        )
                    ),
                )
            step_id = (
                "bundle-anchor-"
                + hashlib.sha256(operation_id.encode()).hexdigest()[:32]
            )
        expected_error = BundleFlowError

    _tamper_committed_trace(
        vault,
        run_id=run_id,
        step_id=step_id,
        corruption=corruption,
    )
    before_run = _tree_bytes(vault / "agent/runs" / run_id)
    before_outbox = _tree_bytes(vault / "agent/outbox")
    if flow_name == "ambient":
        with pytest.raises(expected_error):
            AmbientFlow(resolver, runs, policy, clock).scan(
                _ambient_caps(policy), run_id=run_id, request=request
            )
    else:
        with pytest.raises(expected_error):
            BundleFlow(resolver, runs, policy, clock).collect(
                _bundle_caps(policy), run_id=run_id, request=request
            )
    assert _tree_bytes(vault / "agent/runs" / run_id) == before_run
    assert _tree_bytes(vault / "agent/outbox") == before_outbox


@pytest.mark.parametrize("flow_name", ["ambient", "bundle"])
@pytest.mark.parametrize("stage", ["final", "anchor"])
def test_exact_final_and_anchor_trace_replay_is_consistent(
    tmp_path: Path, flow_name: str, stage: str
) -> None:
    if flow_name == "ambient":
        vault, resolver, runs, policy, clock = _setup(tmp_path)
        _write_day(vault)
    else:
        vault, resolver, runs, policy, clock, _event, _receipt = (
            _prepare_bundle_identity_sources(tmp_path)
        )
    run_id = f"run_{flow_name}_{stage}_trace_positive"
    operation_id = f"{flow_name}_{stage}_trace_positive"
    _run(runs, run_id, flow_name)

    if flow_name == "ambient":
        request = _request(operation_id)
        if stage == "anchor":
            with pytest.raises(RuntimeError, match="positive-anchor-crash"):
                AmbientFlow(resolver, runs, policy, clock).scan(
                    _ambient_caps(policy),
                    run_id=run_id,
                    request=request,
                    crash_hooks=AmbientCrashHooks(
                        after_payload_prepare=lambda: (_ for _ in ()).throw(
                            RuntimeError("positive-anchor-crash")
                        )
                    ),
                )
        else:
            AmbientFlow(resolver, runs, policy, clock).scan(
                _ambient_caps(policy), run_id=run_id, request=request
            )
        result = AmbientFlow(resolver, runs, policy, clock).scan(
            _ambient_caps(policy), run_id=run_id, request=request
        )
    else:
        request = _bundle_request(operation_id)
        if stage == "anchor":
            with pytest.raises(RuntimeError, match="positive-anchor-crash"):
                BundleFlow(resolver, runs, policy, clock).collect(
                    _bundle_caps(policy),
                    run_id=run_id,
                    request=request,
                    crash_hooks=BundleCrashHooks(
                        after_payload_prepare=lambda: (_ for _ in ()).throw(
                            RuntimeError("positive-anchor-crash")
                        )
                    ),
                )
        else:
            BundleFlow(resolver, runs, policy, clock).collect(
                _bundle_caps(policy), run_id=run_id, request=request
            )
        result = BundleFlow(resolver, runs, policy, clock).collect(
            _bundle_caps(policy), run_id=run_id, request=request
        )

    assert result.outcome == "emitted"
    assert result.replayed is True
    assert (
        sum(
            json.loads(path.read_text("utf-8"))["flow_id"] == flow_name
            for path in _event_files(vault)
        )
        == 1
    )


@pytest.mark.parametrize("flow_name", ["ambient", "bundle"])
def test_exact_empty_final_trace_replay_is_consistent(
    tmp_path: Path, flow_name: str
) -> None:
    vault, resolver, runs, policy, clock = _setup(tmp_path)
    run_id = f"run_{flow_name}_empty_trace_positive"
    operation_id = f"{flow_name}_empty_trace_positive"
    _run(runs, run_id, flow_name)
    if flow_name == "ambient":
        request = _request(operation_id)
        AmbientFlow(resolver, runs, policy, clock).scan(
            _ambient_caps(policy), run_id=run_id, request=request
        )
        result = AmbientFlow(resolver, runs, policy, clock).scan(
            _ambient_caps(policy), run_id=run_id, request=request
        )
        assert result.outcome == "zero"
    else:
        request = _bundle_request(operation_id)
        BundleFlow(resolver, runs, policy, clock).collect(
            _bundle_caps(policy), run_id=run_id, request=request
        )
        result = BundleFlow(resolver, runs, policy, clock).collect(
            _bundle_caps(policy), run_id=run_id, request=request
        )
        assert result.outcome == "empty"
    assert result.replayed is True
    assert _event_files(vault) == []


def test_project_and_entity_candidates_are_strict_bounded_and_prioritized(
    tmp_path: Path,
) -> None:
    vault, resolver, runs, policy, clock = _setup(tmp_path)
    _write_project(vault)
    _write_entity(vault)
    _run(runs, "run_ambient_context", "ambient")
    result = AmbientFlow(resolver, runs, policy, clock).scan(
        _ambient_caps(policy),
        run_id="run_ambient_context",
        request=_request("ambient_context"),
    )
    evidence = parse_ambient_run_evidence(
        (
            vault
            / "agent/runs/run_ambient_context"
            / f"{result.evidence_artifact}.json"
        ).read_bytes()
    )
    assert evidence.candidate_count == 3
    assert evidence.selected is not None
    assert evidence.selected.kind == "entity-due"
    assert evidence.selected.priority == "critical"
    assert sorted(item.reason for item in evidence.dispositions) == [
        "emitted",
        "lower-ranked",
        "lower-ranked",
    ]


def test_ambient_backpressure_and_unavailable_disposition_every_candidate(
    tmp_path: Path,
) -> None:
    vault, resolver, runs, policy, clock = _setup(tmp_path)
    _write_day(vault, priority="low")
    (vault / "review/unsupported.proposal").write_text(
        "bounded unknown review", "utf-8"
    )
    _run(runs, "run_ambient_debt", "ambient")
    request = replace(_request("ambient_debt"), review_budget=AmbientReviewBudget(1, 1))
    result = AmbientFlow(resolver, runs, policy, clock).scan(
        _ambient_caps(policy), run_id="run_ambient_debt", request=request
    )
    evidence_path = (
        vault / "agent/runs/run_ambient_debt" / f"{result.evidence_artifact}.json"
    )
    evidence = parse_ambient_run_evidence(evidence_path.read_bytes())
    assert result.outcome == "review-backpressure"
    assert [item.reason for item in evidence.dispositions] == ["review-backpressure"]
    assert _event_files(vault) == []

    (vault / "review/unsupported.proposal").unlink()
    _run(runs, "run_ambient_unavailable", "ambient")
    unavailable = replace(
        _request("ambient_unavailable"),
        availability=AmbientAvailability(
            "unavailable", "2026-01-15T08:00:00Z", "2026-01-15T10:00:00Z"
        ),
    )
    result = AmbientFlow(resolver, runs, policy, clock).scan(
        _ambient_caps(policy), run_id="run_ambient_unavailable", request=unavailable
    )
    evidence = parse_ambient_run_evidence(
        (
            vault
            / "agent/runs/run_ambient_unavailable"
            / f"{result.evidence_artifact}.json"
        ).read_bytes()
    )
    assert result.outcome == "availability-deferred"
    assert all(item.reason == "availability-deferred" for item in evidence.dispositions)


def test_silent_surface_records_disposition_without_event(tmp_path: Path) -> None:
    vault, resolver, runs, policy, clock = _setup(tmp_path, surface="silent")
    _write_day(vault)
    _run(runs, "run_ambient_silent", "ambient")
    result = AmbientFlow(resolver, runs, policy, clock).scan(
        _ambient_caps(policy),
        run_id="run_ambient_silent",
        request=_request("ambient_silent"),
    )
    evidence = parse_ambient_run_evidence(
        (
            vault / "agent/runs/run_ambient_silent" / f"{result.evidence_artifact}.json"
        ).read_bytes()
    )
    assert result.outcome == "intentional-silent"
    assert evidence.selected is not None
    assert any(item.reason == "intentional-silent" for item in evidence.dispositions)
    assert _event_files(vault) == []


def test_expired_review_item_is_dispositioned_but_not_review_debt_or_bundle_item(
    tmp_path: Path,
) -> None:
    vault, resolver, runs, policy, clock = _setup(tmp_path, surface="batched")
    _write_memory_proposal(vault, expires_at=AT)
    _run(runs, "run_ambient_expired", "ambient")
    ambient = AmbientFlow(resolver, runs, policy, clock).scan(
        _ambient_caps(policy),
        run_id="run_ambient_expired",
        request=_request("ambient_expired"),
    )
    evidence = parse_ambient_run_evidence(
        (
            vault
            / "agent/runs/run_ambient_expired"
            / f"{ambient.evidence_artifact}.json"
        ).read_bytes()
    )
    assert ambient.outcome == "suppressed"
    assert evidence.review_debt == 0
    assert [item.reason for item in evidence.dispositions] == ["expired"]

    _run(runs, "run_bundle_expired", "bundle")
    bundle = BundleFlow(resolver, runs, policy, clock).collect(
        _bundle_caps(policy),
        run_id="run_bundle_expired",
        request=_bundle_request("bundle_expired"),
    )
    assert bundle.outcome == "empty"


def test_ambient_payload_crash_recovers_before_mutable_reread(tmp_path: Path) -> None:
    vault, resolver, runs, policy, clock = _setup(tmp_path)
    _write_day(vault)
    _run(runs, "run_ambient_crash", "ambient")
    caps = _ambient_caps(policy)

    with pytest.raises(RuntimeError, match="payload-crash"):
        AmbientFlow(resolver, runs, policy, clock).scan(
            caps,
            run_id="run_ambient_crash",
            request=_request("ambient_crash"),
            crash_hooks=AmbientCrashHooks(
                after_payload_prepare=lambda: (_ for _ in ()).throw(
                    RuntimeError("payload-crash")
                )
            ),
        )
    (vault / "tasks/days/2026-01-15.json").write_bytes(
        b"malformed after durable marker"
    )

    result = AmbientFlow(resolver, runs, policy, clock).scan(
        caps, run_id="run_ambient_crash", request=_request("ambient_crash")
    )
    assert result.outcome == "emitted"
    assert result.replayed is True
    assert len(_event_files(vault)) == 1


def test_ambient_event_crash_recovers_without_source_reread(tmp_path: Path) -> None:
    vault, resolver, runs, policy, clock = _setup(tmp_path)
    _write_day(vault)
    _run(runs, "run_ambient_event_crash", "ambient")
    caps = _ambient_caps(policy)
    request = _request("ambient_event_crash")
    with pytest.raises(RuntimeError, match="event-crash"):
        AmbientFlow(resolver, runs, policy, clock).scan(
            caps,
            run_id="run_ambient_event_crash",
            request=request,
            crash_hooks=AmbientCrashHooks(
                after_event_publish=lambda: (_ for _ in ()).throw(
                    RuntimeError("event-crash")
                )
            ),
        )
    (vault / "tasks/days/2026-01-15.json").write_bytes(b"not-json")

    result = AmbientFlow(resolver, runs, policy, clock).scan(
        caps, run_id="run_ambient_event_crash", request=request
    )
    assert result.replayed is True
    assert len(_event_files(vault)) == 1


@pytest.mark.parametrize(
    "seam", ["after_run_intent", "after_run_state", "after_run_trace"]
)
def test_ambient_run_commit_seams_reconcile_exactly(tmp_path: Path, seam: str) -> None:
    vault, resolver, runs, policy, clock = _setup(tmp_path)
    _write_day(vault)
    run_id = f"run_ambient_{seam}"
    operation_id = f"ambient_{seam}"
    _run(runs, run_id, "ambient")

    def crash() -> None:
        raise RuntimeError("run-crash")

    hooks = AmbientCrashHooks(**{seam: crash})
    with pytest.raises(RuntimeError, match="run-crash"):
        AmbientFlow(resolver, runs, policy, clock).scan(
            _ambient_caps(policy),
            run_id=run_id,
            request=_request(operation_id),
            crash_hooks=hooks,
        )

    result = AmbientFlow(resolver, runs, policy, clock).scan(
        _ambient_caps(policy), run_id=run_id, request=_request(operation_id)
    )
    assert result.replayed is True
    assert len(_event_files(vault)) == 1


def test_bundle_closed_window_exact_digest_duplicate_and_no_recursive_item(
    tmp_path: Path,
) -> None:
    vault, resolver, runs, policy, clock = _setup(tmp_path)
    _write_day(vault)
    _run(runs, "run_ambient_quiet", "ambient")
    quiet = replace(
        _request("ambient_quiet"),
        availability=AmbientAvailability(
            "quiet", "2026-01-15T08:00:00Z", "2026-01-15T10:00:00Z"
        ),
    )
    ambient = AmbientFlow(resolver, runs, policy, clock).scan(
        _ambient_caps(policy), run_id="run_ambient_quiet", request=quiet
    )
    assert ambient.outcome == "emitted"
    ambient_event = json.loads(_event_files(vault)[0].read_text("utf-8"))
    assert ambient_event["delivery_policy"]["surface"] == "batched"

    _run(runs, "run_bundle_a", "bundle")
    first = BundleFlow(resolver, runs, policy, clock).collect(
        _bundle_caps(policy), run_id="run_bundle_a", request=_bundle_request()
    )
    manifest_path = (
        vault / "agent/outbox/artifacts" / f"bundle-{first.batch_digest}.json"
    )
    manifest = parse_bundle_manifest(manifest_path.read_bytes())
    assert [item.source_id for item in manifest.items] == [ambient.event_id]
    assert render_bundle_manifest(manifest) == manifest_path.read_bytes()
    assert first.outcome == "emitted"
    assert _trace_actions(runs, "run_bundle_a") == [
        "collect-batched-items",
        "read-pending-outbox",
        "commit-bundle-outbox-event",
        "record-run-state",
    ]

    _run(runs, "run_bundle_b", "bundle")
    second = BundleFlow(resolver, runs, policy, clock).collect(
        _bundle_caps(policy),
        run_id="run_bundle_b",
        request=_bundle_request("bundle_scan_b"),
    )
    assert second.event_id == first.event_id
    assert second.replayed is False
    assert len(_event_files(vault)) == 2

    producer = runs.producer_snapshot(
        "run_bundle_a", producer_evidence=first.evidence_artifact
    )
    evidence_artifact = next(
        item for item in producer.artifacts if item.name == first.evidence_artifact
    )
    inspected = inspect_bundle_run_evidence(
        evidence_artifact, vault.joinpath(evidence_artifact.state_ref).read_bytes()
    )
    assert inspected.batch_digest == first.batch_digest


def test_bundle_same_operation_across_runs_uses_exact_prior_producer(
    tmp_path: Path,
) -> None:
    vault, resolver, runs, policy, clock, _event, _receipt = (
        _prepare_bundle_identity_sources(tmp_path)
    )
    request = _bundle_request("bundle_cross_run")
    _run(runs, "run_bundle_cross_a", "bundle")
    first = BundleFlow(resolver, runs, policy, clock).collect(
        _bundle_caps(policy), run_id="run_bundle_cross_a", request=request
    )
    (vault / "review/memprop-ambient.memory.json").write_bytes(b"not-json")
    _run(runs, "run_bundle_cross_b", "bundle")
    second = BundleFlow(resolver, runs, policy, clock).collect(
        _bundle_caps(policy), run_id="run_bundle_cross_b", request=request
    )
    assert second.replayed is True
    assert second.event_id == first.event_id
    assert second.batch_digest == first.batch_digest


def test_bundle_empty_window_is_silent_and_future_window_excludes_bundle_event(
    tmp_path: Path,
) -> None:
    vault, resolver, runs, policy, clock = _setup(tmp_path)
    _run(runs, "run_bundle_empty", "bundle")
    result = BundleFlow(resolver, runs, policy, clock).collect(
        _bundle_caps(policy),
        run_id="run_bundle_empty",
        request=_bundle_request("bundle_empty"),
    )
    assert result.outcome == "empty"
    assert result.event_id is None
    assert _event_files(vault) == []
    assert runs.status("run_bundle_empty")["status"] == "running"


def test_bundle_delivered_source_is_excluded(tmp_path: Path) -> None:
    vault, resolver, runs, policy, clock = _setup(tmp_path)
    _write_day(vault)
    _run(runs, "run_ambient_delivered", "ambient")
    quiet = replace(
        _request("ambient_delivered"),
        availability=AmbientAvailability(
            "quiet", "2026-01-15T08:00:00Z", "2026-01-15T10:00:00Z"
        ),
    )
    ambient = AmbientFlow(resolver, runs, policy, clock).scan(
        _ambient_caps(policy), run_id="run_ambient_delivered", request=quiet
    )
    receipt_cap = policy.issue(
        flow_id="gateway-delivery",
        action_id="reconcile-outbox-receipt",
        actor="runtime",
        authority="internal-write",
        target="vault:agent/outbox",
    )
    with OutboxStore(resolver, runs, policy=policy, clock=clock) as outbox:
        receipt = outbox.record_delivery_receipt(
            receipt_cap,
            event_id=str(ambient.event_id),
            attempt_id="attempt_delivered",
            status="delivered",
            effect_hash="1" * 64,
        )
    event_path = next(
        path
        for path in _event_files(vault)
        if json.loads(path.read_text("utf-8"))["event_id"] == ambient.event_id
    )
    receipt_path = vault / "agent/outbox/receipts" / f"{receipt['receipt_id']}.json"
    verifier = _ExactReceiptVerifier(
        receipt_sha256=hashlib.sha256(receipt_path.read_bytes()).hexdigest(),
        event_sha256=hashlib.sha256(event_path.read_bytes()).hexdigest(),
    )
    _run(runs, "run_bundle_delivered", "bundle")
    result = BundleFlow(
        resolver, runs, policy, clock, receipt_verifier=verifier
    ).collect(
        _bundle_caps(policy),
        run_id="run_bundle_delivered",
        request=_bundle_request("bundle_delivered"),
    )
    assert result.outcome == "empty"
    receipt_path.write_bytes(b"corrupt after committed empty evidence")
    replay = BundleFlow(
        resolver, runs, policy, clock, receipt_verifier=verifier
    ).collect(
        _bundle_caps(policy),
        run_id="run_bundle_delivered",
        request=_bundle_request("bundle_delivered"),
    )
    assert replay.outcome == "empty"
    assert replay.replayed is True


def test_forged_canonical_receipt_cannot_suppress_pending_event(
    tmp_path: Path,
) -> None:
    vault, resolver, runs, policy, clock = _setup(tmp_path, surface="batched")
    _write_day(vault)
    _run(runs, "run_ambient_forged_receipt", "ambient")
    ambient = AmbientFlow(resolver, runs, policy, clock).scan(
        _ambient_caps(policy),
        run_id="run_ambient_forged_receipt",
        request=_request("ambient_forged_receipt"),
    )
    forged = {
        "schema_version": 1,
        "receipt_id": "receipt_" + "a" * 56,
        "run_id": "run_ambient_forged_receipt",
        "event_id": ambient.event_id,
        "status": "delivered",
        "effect_hash": "f" * 64,
        "at": "2026-01-15T09:00:01Z",
    }
    receipts = vault / "agent/outbox/receipts"
    receipts.mkdir(exist_ok=True)
    (receipts / f"{forged['receipt_id']}.json").write_bytes(
        json.dumps(forged, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    )
    _run(runs, "run_bundle_forged_receipt", "bundle")
    result = BundleFlow(resolver, runs, policy, clock).collect(
        _bundle_caps(policy),
        run_id="run_bundle_forged_receipt",
        request=_bundle_request("bundle_forged_receipt"),
    )
    assert result.outcome == "emitted"
    manifest = parse_bundle_manifest(
        (
            vault / "agent/outbox/artifacts" / f"bundle-{result.batch_digest}.json"
        ).read_bytes()
    )
    assert [item.source_id for item in manifest.items] == [ambient.event_id]


def test_bundle_payload_crash_recovers_before_outbox_reread(tmp_path: Path) -> None:
    vault, resolver, runs, policy, clock = _setup(tmp_path)
    _write_day(vault)
    _run(runs, "run_ambient_for_crash", "ambient")
    quiet = replace(
        _request("ambient_for_crash"),
        availability=AmbientAvailability(
            "quiet", "2026-01-15T08:00:00Z", "2026-01-15T10:00:00Z"
        ),
    )
    AmbientFlow(resolver, runs, policy, clock).scan(
        _ambient_caps(policy), run_id="run_ambient_for_crash", request=quiet
    )
    _run(runs, "run_bundle_crash", "bundle")
    caps = _bundle_caps(policy)
    with pytest.raises(RuntimeError, match="bundle-payload-crash"):
        BundleFlow(resolver, runs, policy, clock).collect(
            caps,
            run_id="run_bundle_crash",
            request=_bundle_request("bundle_crash"),
            crash_hooks=BundleCrashHooks(
                after_payload_prepare=lambda: (_ for _ in ()).throw(
                    RuntimeError("bundle-payload-crash")
                )
            ),
        )
    source_event = next(
        path
        for path in _event_files(vault)
        if json.loads(path.read_text("utf-8"))["flow_id"] == "ambient"
    )
    source_event.write_bytes(b"mutated after durable bundle marker")
    result = BundleFlow(resolver, runs, policy, clock).collect(
        caps,
        run_id="run_bundle_crash",
        request=_bundle_request("bundle_crash"),
    )
    assert result.outcome == "emitted"
    assert result.replayed is True


def test_bundle_second_snapshot_detects_outbox_mutation(tmp_path: Path) -> None:
    vault, resolver, runs, policy, clock = _setup(tmp_path)
    _write_day(vault)
    _run(runs, "run_ambient_bundle_mutation", "ambient")
    quiet = replace(
        _request("ambient_bundle_mutation"),
        availability=AmbientAvailability(
            "quiet", "2026-01-15T08:00:00Z", "2026-01-15T10:00:00Z"
        ),
    )
    AmbientFlow(resolver, runs, policy, clock).scan(
        _ambient_caps(policy), run_id="run_ambient_bundle_mutation", request=quiet
    )
    source_event = next(
        path
        for path in _event_files(vault)
        if json.loads(path.read_text("utf-8"))["flow_id"] == "ambient"
    )
    _run(runs, "run_bundle_mutation", "bundle")

    def mutate() -> None:
        source_event.write_bytes(b"not-json")

    with pytest.raises(BundleFlowError):
        BundleFlow(resolver, runs, policy, clock).collect(
            _bundle_caps(policy),
            run_id="run_bundle_mutation",
            request=_bundle_request("bundle_mutation"),
            crash_hooks=BundleCrashHooks(after_source_read=mutate),
        )
    assert all(
        json.loads(path.read_text("utf-8"))["flow_id"] != "bundle"
        for path in _event_files(vault)
        if path != source_event
    )


def test_second_snapshot_detects_source_mutation_before_publish(tmp_path: Path) -> None:
    vault, resolver, runs, policy, clock = _setup(tmp_path)
    _write_day(vault)
    _run(runs, "run_ambient_mutation", "ambient")

    def mutate() -> None:
        _write_day(vault, text="Changed between snapshots")

    with pytest.raises(AmbientFlowError, match="changed"):
        AmbientFlow(resolver, runs, policy, clock).scan(
            _ambient_caps(policy),
            run_id="run_ambient_mutation",
            request=_request("ambient_mutation"),
            crash_hooks=AmbientCrashHooks(after_source_read=mutate),
        )
    assert _event_files(vault) == []


def test_bundle_priority_expiry_supersede_and_cycle_schema() -> None:
    window = BundleWindow("2026-01-15T08:00:00Z", "2026-01-15T10:00:00Z")
    older = BundleItem(
        "review",
        "review_old",
        "review/old.json",
        "1" * 64,
        "2026-01-15T08:10:00Z",
        "low",
    )
    newer = BundleItem(
        "review",
        "review_new",
        "review/new.json",
        "2" * 64,
        "2026-01-15T08:20:00Z",
        "critical",
        None,
        "review_old",
    )
    ordered = (newer, older)
    core = {
        "schema_version": 1,
        "kind": "batched-digest",
        "window": {"schema_version": 1, "start": window.start, "end": window.end},
        "items": [
            {
                "schema_version": item.schema_version,
                "kind": item.kind,
                "source_id": item.source_id,
                "source_ref": item.source_ref,
                "source_sha256": item.source_sha256,
                "created_at": item.created_at,
                "priority": item.priority,
                "expires_at": item.expires_at,
                "supersedes": item.supersedes,
            }
            for item in ordered
        ],
    }
    digest = hashlib.sha256(
        json.dumps(core, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    manifest = BundleManifest(window, ordered, digest)
    assert parse_bundle_manifest(render_bundle_manifest(manifest)) == manifest

    cycle_a = replace(older, supersedes="review_new")
    cycle_b = replace(newer, supersedes="review_old")
    with pytest.raises(BundleFlowError, match="cycle"):
        render_bundle_manifest(BundleManifest(window, (cycle_b, cycle_a), "0" * 64))


def test_ambient_explicit_supersede_is_deterministic_and_missing_target_fails(
    tmp_path: Path,
) -> None:
    _vault, resolver, runs, policy, clock = _setup(tmp_path)
    flow = AmbientFlow(resolver, runs, policy, clock)
    older = flow._make_candidate(
        kind="task-due",
        slot="task:old",
        source_ref="tasks/days/old.json",
        source_hash="1" * 64,
        revision=1,
        priority="high",
        eligible="2026-01-15T08:00:00Z",
        expires=None,
        supersedes=None,
        surface="gated",
    )
    newer = flow._make_candidate(
        kind="task-due",
        slot="task:new",
        source_ref="tasks/days/new.json",
        source_hash="2" * 64,
        revision=1,
        priority="high",
        eligible="2026-01-15T08:30:00Z",
        expires=None,
        supersedes=older.candidate_id,
        surface="gated",
    )
    outcome, selected, dispositions, _digest = flow._select(
        (older, newer),
        observed_at=AT,
        availability="available",
        debt=0,
        budget=AmbientReviewBudget(10, 20),
    )
    assert outcome == "emitted"
    assert selected == newer
    assert {item.candidate_id: item.reason for item in dispositions} == {
        older.candidate_id: "superseded",
        newer.candidate_id: "emitted",
    }

    missing = flow._make_candidate(
        kind="task-due",
        slot="task:missing",
        source_ref="tasks/days/missing.json",
        source_hash="3" * 64,
        revision=1,
        priority="high",
        eligible="2026-01-15T08:45:00Z",
        expires=None,
        supersedes="cand_unknown",
        surface="gated",
    )
    with pytest.raises(AmbientFlowError, match="unknown"):
        flow._select(
            (missing,),
            observed_at=AT,
            availability="available",
            debt=0,
            budget=AmbientReviewBudget(10, 20),
        )


def test_bundle_manifest_and_evidence_reject_tampering() -> None:
    with pytest.raises(BundleFlowError):
        parse_bundle_manifest(b'{"schema_version":1,"schema_version":1}')
    with pytest.raises(BundleFlowError):
        parse_bundle_run_evidence(b'{"schema_version":1}')
    with pytest.raises(AmbientFlowError):
        parse_ambient_run_evidence(b'{"schema_version":1}')


@pytest.mark.parametrize("corruption", ["unknown", "missing", "duplicate", "type"])
def test_ambient_nested_disposition_raw_schema_fails_without_effect(
    tmp_path: Path, corruption: str
) -> None:
    vault, resolver, runs, policy, clock = _setup(tmp_path)
    _write_day(vault)
    run_id = "run_ambient_nested_schema"
    _run(runs, run_id, "ambient")
    result = AmbientFlow(resolver, runs, policy, clock).scan(
        _ambient_caps(policy),
        run_id=run_id,
        request=_request("ambient_nested_schema"),
    )
    evidence_path = vault / "agent/runs" / run_id / f"{result.evidence_artifact}.json"
    evidence_raw = evidence_path.read_bytes()
    evidence = parse_ambient_run_evidence(evidence_raw)
    assert evidence.marker_ref is not None
    marker_raw = (vault / evidence.marker_ref).read_bytes()

    def corrupt(raw: bytes) -> bytes:
        if corruption == "duplicate":
            needle = b'"reason":"emitted"'
            assert needle in raw
            return raw.replace(
                needle,
                b'"reason":"emitted","reason":"emitted"',
                1,
            )
        payload = json.loads(raw)
        disposition = payload["dispositions"][0]
        if corruption == "unknown":
            disposition["unknown"] = "rejected"
        elif corruption == "missing":
            disposition.pop("reason")
        else:
            disposition["reason"] = True
        return json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    before_run = _tree_bytes(vault / "agent/runs" / run_id)
    before_outbox = _tree_bytes(vault / "agent/outbox")
    with pytest.raises(AmbientFlowError):
        parse_ambient_run_evidence(corrupt(evidence_raw))
    with AmbientFlow(resolver, runs, policy, clock) as flow:
        marker = json.loads(marker_raw)
        with pytest.raises(AmbientFlowError):
            flow._parse_marker(corrupt(marker_raw), str(marker["request_sha256"]))
    assert _tree_bytes(vault / "agent/runs" / run_id) == before_run
    assert _tree_bytes(vault / "agent/outbox") == before_outbox


def test_malformed_typed_public_and_source_fields_are_domain_errors(
    tmp_path: Path,
) -> None:
    vault, resolver, runs, policy, clock = _setup(tmp_path)
    _run(runs, "run_ambient_bad_availability", "ambient")
    malformed_availability = AmbientAvailability(
        ["available"],  # type: ignore[arg-type]
        "2026-01-15T08:00:00Z",
        "2026-01-15T10:00:00Z",
    )
    with pytest.raises(AmbientFlowError):
        AmbientFlow(resolver, runs, policy, clock).scan(
            _ambient_caps(policy),
            run_id="run_ambient_bad_availability",
            request=replace(_request(), availability=malformed_availability),
        )

    malformed_item = BundleItem(
        ["review"],  # type: ignore[arg-type]
        "review_bad",
        "review/bad.json",
        "1" * 64,
        "2026-01-15T08:00:00Z",
        "medium",
    )
    with pytest.raises(BundleFlowError):
        BundleFlow._normalize_items((malformed_item,), AT)

    _write_project(vault)
    project_path = vault / "projects/portable-project/project.json"
    project = json.loads(project_path.read_text("utf-8"))
    project["status"] = ["active"]
    _canonical_file(project_path, project)
    _run(runs, "run_ambient_bad_project", "ambient")
    with pytest.raises(AmbientFlowError):
        AmbientFlow(resolver, runs, policy, clock).scan(
            _ambient_caps(policy),
            run_id="run_ambient_bad_project",
            request=_request("ambient_bad_project"),
        )


@pytest.mark.parametrize(
    "source",
    [
        "project-record",
        "project-state",
        "entity-collection",
        "entity-record",
        "entity-step",
        "entity-next-check",
        "plan-feedback",
    ],
)
def test_untrusted_source_json_bool_schema_fails_without_effect(
    tmp_path: Path, source: str
) -> None:
    vault, resolver, runs, policy, clock = _setup(tmp_path)
    _write_bool_schema_source(vault, source)
    run_id = "run_ambient_bool_source"
    _run(runs, run_id, "ambient")
    run_root = vault / "agent/runs" / run_id
    before_run = _tree_bytes(run_root)

    with AmbientFlow(resolver, runs, policy, clock) as flow:
        with pytest.raises(AmbientFlowError):
            flow.scan(
                _ambient_caps(policy),
                run_id=run_id,
                request=_request("ambient_bool_source"),
            )

    assert _tree_bytes(run_root) == before_run
    assert _event_files(vault) == []
    assert not list((vault / "agent/outbox/artifacts").glob("ambient-*"))


@pytest.mark.parametrize("flow_name", ["ambient", "bundle"])
@pytest.mark.parametrize("corruption", ["marker", "payload"])
def test_bool_recovery_schema_fails_before_event_state_or_trace_change(
    tmp_path: Path, flow_name: str, corruption: str
) -> None:
    if flow_name == "ambient":
        vault, resolver, runs, policy, clock = _setup(tmp_path)
        _write_day(vault)
        run_id = "run_ambient_bool_marker"
        operation_id = "ambient_bool_marker"
        _run(runs, run_id, "ambient")
        hooks = AmbientCrashHooks(
            after_payload_prepare=lambda: (_ for _ in ()).throw(
                RuntimeError("ambient-marker-crash")
            )
        )
        with AmbientFlow(resolver, runs, policy, clock) as flow:
            with pytest.raises(RuntimeError, match="ambient-marker-crash"):
                flow.scan(
                    _ambient_caps(policy),
                    run_id=run_id,
                    request=_request(operation_id),
                    crash_hooks=hooks,
                )
        marker_prefix = "ambient-op-"
        expected_error = AmbientFlowError
    else:
        vault, resolver, runs, policy, clock, _event, _receipt = (
            _prepare_bundle_identity_sources(tmp_path)
        )
        run_id = "run_bundle_bool_marker"
        operation_id = "bundle_bool_marker"
        _run(runs, run_id, "bundle")
        hooks = BundleCrashHooks(
            after_payload_prepare=lambda: (_ for _ in ()).throw(
                RuntimeError("bundle-marker-crash")
            )
        )
        with BundleFlow(resolver, runs, policy, clock) as flow:
            with pytest.raises(RuntimeError, match="bundle-marker-crash"):
                flow.collect(
                    _bundle_caps(policy),
                    run_id=run_id,
                    request=_bundle_request(operation_id),
                    crash_hooks=hooks,
                )
        marker_prefix = "bundle-op-"
        expected_error = BundleFlowError

    marker = next((vault / "agent/outbox/artifacts").glob(f"{marker_prefix}*.json"))
    marker_payload = json.loads(marker.read_text("utf-8"))
    if corruption == "marker":
        marker_payload["schema_version"] = True
    else:
        payload_path = vault / str(marker_payload["payload_ref"])
        payload = json.loads(payload_path.read_text("utf-8"))
        payload["schema_version"] = True
        payload_raw = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        payload_path.write_bytes(payload_raw)
        marker_payload["payload_sha256"] = hashlib.sha256(payload_raw).hexdigest()
    marker.write_bytes(
        json.dumps(
            marker_payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    )
    run_root = vault / "agent/runs" / run_id
    before_run = _tree_bytes(run_root)
    before_events = {path.name: path.read_bytes() for path in _event_files(vault)}

    if flow_name == "ambient":
        with AmbientFlow(resolver, runs, policy, clock) as flow:
            with pytest.raises(expected_error):
                flow.scan(
                    _ambient_caps(policy),
                    run_id=run_id,
                    request=_request(operation_id),
                )
    else:
        with BundleFlow(resolver, runs, policy, clock) as flow:
            with pytest.raises(expected_error):
                flow.collect(
                    _bundle_caps(policy),
                    run_id=run_id,
                    request=_bundle_request(operation_id),
                )

    assert _tree_bytes(run_root) == before_run
    assert {
        path.name: path.read_bytes() for path in _event_files(vault)
    } == before_events
    assert not _has_flow_event(vault, flow_name)


def test_ambient_coherent_marker_payload_tamper_is_rejected_before_event(
    tmp_path: Path,
) -> None:
    vault, resolver, runs, policy, clock = _setup(tmp_path)
    _write_day(vault)
    run_id = "run_ambient_coherent_tamper"
    operation_id = "ambient_coherent_tamper"
    _run(runs, run_id, "ambient")
    with AmbientFlow(resolver, runs, policy, clock) as flow:
        with pytest.raises(RuntimeError, match="anchor-crash"):
            flow.scan(
                _ambient_caps(policy),
                run_id=run_id,
                request=_request(operation_id),
                crash_hooks=AmbientCrashHooks(
                    after_payload_prepare=lambda: (_ for _ in ()).throw(
                        RuntimeError("anchor-crash")
                    )
                ),
            )
    marker = next((vault / "agent/outbox/artifacts").glob("ambient-op-*.json"))
    marker_data = json.loads(marker.read_text("utf-8"))
    with AmbientFlow(resolver, runs, policy, clock) as flow:
        forged = flow._make_candidate(
            kind="project-next-step",
            slot="project:forged:step:forged",
            source_ref="projects/forged",
            source_hash="f" * 64,
            revision=999,
            priority="critical",
            eligible=AT,
            expires=None,
            supersedes=None,
            surface="gated",
        )
    selected = {
        "schema_version": 1,
        "candidate_id": forged.candidate_id,
        "kind": forged.kind,
        "semantic_slot": forged.semantic_slot,
        "source_ref": forged.source_ref,
        "source_sha256": forged.source_sha256,
        "source_revision": forged.source_revision,
        "priority": forged.priority,
        "eligible_at": forged.eligible_at,
        "expires_at": forged.expires_at,
        "supersedes": forged.supersedes,
        "surface": forged.surface,
        "summary": forged.summary,
    }
    payload_path = vault / str(marker_data["payload_ref"])
    payload_raw = json.dumps(
        {
            "schema_version": 1,
            "kind": "ambient-nudge",
            "candidate_id": forged.candidate_id,
            "candidate_kind": forged.kind,
            "priority": forged.priority,
            "eligible_at": forged.eligible_at,
            "surface": forged.surface,
            "summary": forged.summary,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    payload_path.write_bytes(payload_raw)
    marker_data.update(
        {
            "selected": selected,
            "dispositions": [
                {
                    "schema_version": 1,
                    "candidate_id": forged.candidate_id,
                    "reason": "emitted",
                }
            ],
            "candidate_count": 1,
            "candidates_sha256": "e" * 64,
            "payload_sha256": hashlib.sha256(payload_raw).hexdigest(),
        }
    )
    marker.write_bytes(
        json.dumps(marker_data, sort_keys=True, separators=(",", ":")).encode()
    )
    before_run = _tree_bytes(vault / "agent/runs" / run_id)
    with AmbientFlow(resolver, runs, policy, clock) as flow:
        with pytest.raises(AmbientFlowError):
            flow.scan(
                _ambient_caps(policy),
                run_id=run_id,
                request=_request(operation_id),
            )
    assert _tree_bytes(vault / "agent/runs" / run_id) == before_run
    assert not _has_flow_event(vault, "ambient")


def test_bundle_coherent_marker_payload_tamper_is_rejected_before_event(
    tmp_path: Path,
) -> None:
    vault, resolver, runs, policy, clock, _event, _receipt = (
        _prepare_bundle_identity_sources(tmp_path)
    )
    run_id = "run_bundle_coherent_tamper"
    operation_id = "bundle_coherent_tamper"
    request = _bundle_request(operation_id)
    _run(runs, run_id, "bundle")
    with BundleFlow(resolver, runs, policy, clock) as flow:
        with pytest.raises(RuntimeError, match="anchor-crash"):
            flow.collect(
                _bundle_caps(policy),
                run_id=run_id,
                request=request,
                crash_hooks=BundleCrashHooks(
                    after_payload_prepare=lambda: (_ for _ in ()).throw(
                        RuntimeError("anchor-crash")
                    )
                ),
            )
    marker = next((vault / "agent/outbox/artifacts").glob("bundle-op-*.json"))
    marker_data = json.loads(marker.read_text("utf-8"))
    forged = BundleItem(
        "review",
        "review_forged",
        "review/forged.memory.json",
        "f" * 64,
        AT,
        "critical",
    )
    core = {
        "schema_version": 1,
        "kind": "batched-digest",
        "window": {
            "schema_version": 1,
            "start": request.window.start,
            "end": request.window.end,
        },
        "items": [
            {
                "schema_version": 1,
                "kind": forged.kind,
                "source_id": forged.source_id,
                "source_ref": forged.source_ref,
                "source_sha256": forged.source_sha256,
                "created_at": forged.created_at,
                "priority": forged.priority,
                "expires_at": None,
                "supersedes": None,
            }
        ],
    }
    digest = hashlib.sha256(
        json.dumps(core, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    payload_raw = render_bundle_manifest(
        BundleManifest(request.window, (forged,), digest)
    )
    payload_path = vault / str(marker_data["payload_ref"])
    payload_path.write_bytes(payload_raw)
    marker_data.update(
        {
            "batch_digest": digest,
            "item_count": 1,
            "payload_sha256": hashlib.sha256(payload_raw).hexdigest(),
        }
    )
    marker.write_bytes(
        json.dumps(marker_data, sort_keys=True, separators=(",", ":")).encode()
    )
    before_run = _tree_bytes(vault / "agent/runs" / run_id)
    with BundleFlow(resolver, runs, policy, clock) as flow:
        with pytest.raises(BundleFlowError):
            flow.collect(_bundle_caps(policy), run_id=run_id, request=request)
    assert _tree_bytes(vault / "agent/runs" / run_id) == before_run
    assert not _has_flow_event(vault, "bundle")


def test_all_typed_schema_versions_and_adjacent_bool_fields_are_rejected(
    tmp_path: Path,
) -> None:
    vault, resolver, runs, policy, clock = _setup(tmp_path, surface="batched")
    _write_day(vault)
    _run(runs, "run_ambient_bool_seed", "ambient")
    with AmbientFlow(resolver, runs, policy, clock) as flow:
        ambient_result = flow.scan(
            _ambient_caps(policy),
            run_id="run_ambient_bool_seed",
            request=_request("ambient_bool_seed"),
        )
    ambient_raw = (
        vault
        / "agent/runs/run_ambient_bool_seed"
        / f"{ambient_result.evidence_artifact}.json"
    ).read_bytes()
    ambient_evidence = parse_ambient_run_evidence(ambient_raw)
    assert isinstance(ambient_evidence, AmbientRunEvidence)
    assert isinstance(ambient_evidence.selected, AmbientCandidate)
    assert isinstance(ambient_evidence.dispositions[0], AmbientDisposition)

    bad_ambient_requests = (
        replace(_request("ambient_bool_request"), schema_version=True),
        replace(
            _request("ambient_bool_availability_schema"),
            availability=replace(_request().availability, schema_version=True),
        ),
        replace(
            _request("ambient_bool_budget_schema"),
            review_budget=replace(_request().review_budget, schema_version=True),
        ),
        replace(
            _request("ambient_bool_availability_status"),
            availability=replace(
                _request().availability,
                status=True,  # type: ignore[arg-type]
            ),
        ),
        replace(
            _request("ambient_bool_budget_bound"),
            review_budget=replace(
                _request().review_budget,
                soft_limit=True,  # type: ignore[arg-type]
            ),
        ),
    )
    for index, request in enumerate(bad_ambient_requests):
        run_id = f"run_ambient_bool_request_{index}"
        _run(runs, run_id, "ambient")
        with pytest.raises(AmbientFlowError):
            AmbientFlow(resolver, runs, policy, clock).scan(
                _ambient_caps(policy), run_id=run_id, request=request
            )

    assert ambient_evidence.selected is not None
    with pytest.raises(AmbientFlowError):
        render_ambient_run_evidence(
            replace(
                ambient_evidence,
                selected=replace(ambient_evidence.selected, schema_version=True),
            )
        )
    with pytest.raises(AmbientFlowError):
        render_ambient_run_evidence(
            replace(
                ambient_evidence,
                selected=replace(
                    ambient_evidence.selected,
                    source_revision=True,  # type: ignore[arg-type]
                ),
            )
        )
    with pytest.raises(AmbientFlowError):
        render_ambient_run_evidence(
            replace(
                ambient_evidence,
                selected=replace(
                    ambient_evidence.selected,
                    priority=True,  # type: ignore[arg-type]
                ),
            )
        )
    with pytest.raises(AmbientFlowError):
        render_ambient_run_evidence(
            replace(
                ambient_evidence,
                dispositions=(
                    replace(ambient_evidence.dispositions[0], schema_version=True),
                ),
            )
        )
    with pytest.raises(AmbientFlowError):
        render_ambient_run_evidence(replace(ambient_evidence, schema_version=True))
    with pytest.raises(AmbientFlowError):
        render_ambient_run_evidence(
            replace(
                ambient_evidence,
                candidate_count=True,  # type: ignore[arg-type]
            )
        )

    _run(runs, "run_bundle_bool_seed", "bundle")
    with BundleFlow(resolver, runs, policy, clock) as flow:
        bundle_result = flow.collect(
            _bundle_caps(policy),
            run_id="run_bundle_bool_seed",
            request=_bundle_request("bundle_bool_seed"),
        )
    bundle_raw = (
        vault
        / "agent/runs/run_bundle_bool_seed"
        / f"{bundle_result.evidence_artifact}.json"
    ).read_bytes()
    bundle_evidence = parse_bundle_run_evidence(bundle_raw)
    assert isinstance(bundle_evidence, BundleRunEvidence)
    manifest = parse_bundle_manifest(
        (
            vault
            / "agent/outbox/artifacts"
            / f"bundle-{bundle_result.batch_digest}.json"
        ).read_bytes()
    )

    bad_bundle_requests = (
        replace(_bundle_request("bundle_bool_request"), schema_version=True),
        replace(
            _bundle_request("bundle_bool_window"),
            window=replace(_bundle_request().window, schema_version=True),
        ),
    )
    for index, request in enumerate(bad_bundle_requests):
        run_id = f"run_bundle_bool_request_{index}"
        _run(runs, run_id, "bundle")
        with pytest.raises(BundleFlowError):
            BundleFlow(resolver, runs, policy, clock).collect(
                _bundle_caps(policy), run_id=run_id, request=request
            )

    with pytest.raises(BundleFlowError):
        render_bundle_manifest(replace(manifest, schema_version=True))
    with pytest.raises(BundleFlowError):
        render_bundle_manifest(
            replace(manifest, window=replace(manifest.window, schema_version=True))
        )
    with pytest.raises(BundleFlowError):
        render_bundle_manifest(
            replace(
                manifest,
                items=(replace(manifest.items[0], schema_version=True),),
            )
        )
    with pytest.raises(BundleFlowError):
        render_bundle_manifest(
            replace(
                manifest,
                items=(
                    replace(
                        manifest.items[0],
                        priority=True,  # type: ignore[arg-type]
                    ),
                ),
            )
        )
    with pytest.raises(BundleFlowError):
        render_bundle_run_evidence(replace(bundle_evidence, schema_version=True))
    with pytest.raises(BundleFlowError):
        render_bundle_run_evidence(
            replace(
                bundle_evidence,
                item_count=True,  # type: ignore[arg-type]
            )
        )


@pytest.mark.parametrize(
    "operation",
    ["/" + "Users/private", "C:\\Users\\private", "file:///private", "bad\ud800"],
)
def test_private_or_malformed_request_text_is_rejected(
    tmp_path: Path, operation: str
) -> None:
    _vault, resolver, runs, policy, clock = _setup(tmp_path)
    _run(runs, "run_ambient_private", "ambient")
    with pytest.raises(AmbientFlowError):
        AmbientFlow(resolver, runs, policy, clock).scan(
            _ambient_caps(policy),
            run_id="run_ambient_private",
            request=replace(_request(), operation_id=operation),
        )


def test_root_and_leaf_rebinding_fail_closed_without_foreign_write(
    tmp_path: Path,
) -> None:
    vault, resolver, runs, policy, clock = _setup(tmp_path)
    _write_day(vault)
    _run(runs, "run_ambient_root", "ambient")
    flow = AmbientFlow(resolver, runs, policy, clock)
    moved = tmp_path / "moved-vault"
    vault.rename(moved)
    shutil.copytree(FIXTURE, vault)
    with pytest.raises(AmbientFlowError, match="root"):
        flow.scan(
            _ambient_caps(policy),
            run_id="run_ambient_root",
            request=_request("ambient_root"),
        )
    assert _event_files(vault) == []


def test_parent_rebinding_between_snapshots_fails_before_write(tmp_path: Path) -> None:
    vault, resolver, runs, policy, clock = _setup(tmp_path)
    _write_day(vault)
    _run(runs, "run_ambient_parent", "ambient")

    def rebind_parent() -> None:
        (vault / "tasks/days").rename(vault / "tasks/days-old")
        (vault / "tasks/days").mkdir()

    with pytest.raises(AmbientFlowError, match="changed"):
        AmbientFlow(resolver, runs, policy, clock).scan(
            _ambient_caps(policy),
            run_id="run_ambient_parent",
            request=_request("ambient_parent"),
            crash_hooks=AmbientCrashHooks(after_source_read=rebind_parent),
        )
    assert _event_files(vault) == []


@pytest.mark.parametrize("replacement", ["leaf", "parent", "root"])
def test_ambient_same_byte_source_identity_replacement_fails_before_write(
    tmp_path: Path, replacement: str
) -> None:
    vault, resolver, runs, policy, clock = _setup(tmp_path)
    _write_day(vault)
    _run(runs, "run_ambient_same_bytes", "ambient")
    held = tmp_path / f"held-ambient-{replacement}"

    def replace_source() -> None:
        if replacement == "leaf":
            _replace_file_with_same_bytes(vault / "tasks/days/2026-01-15.json", held)
        elif replacement == "parent":
            _replace_tree_with_same_bytes(vault / "tasks/days", held)
        else:
            _replace_tree_with_same_bytes(vault, held)

    flow = AmbientFlow(resolver, runs, policy, clock)
    try:
        with pytest.raises(AmbientFlowError, match="changed"):
            flow.scan(
                _ambient_caps(policy),
                run_id="run_ambient_same_bytes",
                request=_request("ambient_same_bytes"),
                crash_hooks=AmbientCrashHooks(after_source_read=replace_source),
            )
    finally:
        flow.close()

    assert not _has_flow_event(vault, "ambient")
    assert not list((vault / "agent/outbox/artifacts").glob("ambient-*"))
    if replacement == "root":
        assert not _has_flow_event(held, "ambient")
        assert not list((held / "agent/outbox/artifacts").glob("ambient-*"))


@pytest.mark.parametrize(
    "replacement",
    [
        "review-leaf",
        "outbox-leaf",
        "receipt-leaf",
        "review-parent",
        "outbox-parent",
        "receipt-parent",
        "root",
    ],
)
def test_bundle_same_byte_source_identity_replacement_fails_before_write(
    tmp_path: Path, replacement: str
) -> None:
    (
        vault,
        resolver,
        runs,
        policy,
        clock,
        event_path,
        receipt_path,
    ) = _prepare_bundle_identity_sources(tmp_path)
    _run(runs, "run_bundle_same_bytes", "bundle")
    targets = {
        "review-leaf": vault / "review/memprop-ambient.memory.json",
        "outbox-leaf": event_path,
        "receipt-leaf": receipt_path,
        "review-parent": vault / "review",
        "outbox-parent": vault / "agent/outbox",
        "receipt-parent": vault / "agent/outbox/receipts",
        "root": vault,
    }
    target = targets[replacement]
    held = tmp_path / f"held-bundle-{replacement}"

    def replace_source() -> None:
        if replacement.endswith("leaf"):
            _replace_file_with_same_bytes(target, held)
        else:
            _replace_tree_with_same_bytes(target, held)

    flow = BundleFlow(resolver, runs, policy, clock)
    try:
        with pytest.raises(BundleFlowError, match="changed"):
            flow.collect(
                _bundle_caps(policy),
                run_id="run_bundle_same_bytes",
                request=_bundle_request("bundle_same_bytes"),
                crash_hooks=BundleCrashHooks(after_source_read=replace_source),
            )
    finally:
        flow.close()

    assert not _has_flow_event(vault, "bundle")
    assert not list((vault / "agent/outbox/artifacts").glob("bundle-*"))
    if replacement == "root":
        assert not _has_flow_event(held, "bundle")
        assert not list((held / "agent/outbox/artifacts").glob("bundle-*"))


@pytest.mark.parametrize("flow_name", ["ambient", "bundle"])
def test_same_byte_identity_failures_do_not_leak_file_descriptors(
    tmp_path: Path, flow_name: str
) -> None:
    baseline = len(os.listdir("/dev/fd"))
    for index in range(6):
        case = tmp_path / f"{flow_name}-{index}"
        if flow_name == "ambient":
            vault, resolver, runs, policy, clock = _setup(case)
            _write_day(vault)
            _run(runs, f"run_ambient_identity_fd_{index}", "ambient")
            target = vault / "tasks/days/2026-01-15.json"
            flow = AmbientFlow(resolver, runs, policy, clock)
            with pytest.raises(AmbientFlowError, match="changed"):
                flow.scan(
                    _ambient_caps(policy),
                    run_id=f"run_ambient_identity_fd_{index}",
                    request=_request(f"ambient_identity_fd_{index}"),
                    crash_hooks=AmbientCrashHooks(
                        after_source_read=lambda: _replace_file_with_same_bytes(
                            target, case / "held-source"
                        )
                    ),
                )
        else:
            (
                _vault,
                resolver,
                runs,
                policy,
                clock,
                target,
                _receipt,
            ) = _prepare_bundle_identity_sources(case)
            _run(runs, f"run_bundle_identity_fd_{index}", "bundle")
            flow = BundleFlow(resolver, runs, policy, clock)
            with pytest.raises(BundleFlowError, match="changed"):
                flow.collect(
                    _bundle_caps(policy),
                    run_id=f"run_bundle_identity_fd_{index}",
                    request=_bundle_request(f"bundle_identity_fd_{index}"),
                    crash_hooks=BundleCrashHooks(
                        after_source_read=lambda: _replace_file_with_same_bytes(
                            target, case / "held-source"
                        )
                    ),
                )
        flow.close()
    assert len(os.listdir("/dev/fd")) <= baseline + 2


@pytest.mark.parametrize("flow_name", ["ambient", "bundle"])
@pytest.mark.parametrize(
    "seam",
    [
        "after_source_read",
        "after_payload_prepare",
        "after_event_publish",
        "after_evidence_prepare",
        "after_run_intent",
        "after_run_state",
        "after_run_trace",
    ],
)
def test_all_crash_seams_preserve_exact_replay_and_one_event(
    tmp_path: Path, flow_name: str, seam: str
) -> None:
    if flow_name == "ambient":
        vault, resolver, runs, policy, clock = _setup(tmp_path)
        _write_day(vault)
        run_id = "run_ambient_all_seams"
        request = _request("ambient_all_seams")
        _run(runs, run_id, "ambient")
        hooks = AmbientCrashHooks(
            **{seam: lambda: (_ for _ in ()).throw(RuntimeError("ambient-seam-crash"))}
        )
        with AmbientFlow(resolver, runs, policy, clock) as flow:
            with pytest.raises(RuntimeError, match="ambient-seam-crash"):
                flow.scan(
                    _ambient_caps(policy),
                    run_id=run_id,
                    request=request,
                    crash_hooks=hooks,
                )
        with AmbientFlow(resolver, runs, policy, clock) as flow:
            result = flow.scan(_ambient_caps(policy), run_id=run_id, request=request)
        assert result.replayed is (seam != "after_source_read")
    else:
        vault, resolver, runs, policy, clock, _event, _receipt = (
            _prepare_bundle_identity_sources(tmp_path)
        )
        run_id = "run_bundle_all_seams"
        request = _bundle_request("bundle_all_seams")
        _run(runs, run_id, "bundle")
        hooks = BundleCrashHooks(
            **{seam: lambda: (_ for _ in ()).throw(RuntimeError("bundle-seam-crash"))}
        )
        with BundleFlow(resolver, runs, policy, clock) as flow:
            with pytest.raises(RuntimeError, match="bundle-seam-crash"):
                flow.collect(
                    _bundle_caps(policy),
                    run_id=run_id,
                    request=request,
                    crash_hooks=hooks,
                )
        with BundleFlow(resolver, runs, policy, clock) as flow:
            result = flow.collect(_bundle_caps(policy), run_id=run_id, request=request)
        assert result.replayed is (seam != "after_source_read")

    events = [json.loads(path.read_text("utf-8")) for path in _event_files(vault)]
    assert sum(event["flow_id"] == flow_name for event in events) == 1


def test_flow_failures_do_not_leak_file_descriptors(tmp_path: Path) -> None:
    vault, resolver, runs, policy, clock = _setup(tmp_path)
    _write_day(vault)
    (vault / "tasks/days/2026-01-15.json").unlink()
    (vault / "tasks/days/2026-01-15.json").symlink_to(vault / "lifeos.toml")
    baseline = len(os.listdir("/dev/fd"))
    for index in range(20):
        run_id = f"run_ambient_fd_{index}"
        _run(runs, run_id, "ambient")
        flow = AmbientFlow(resolver, runs, policy, clock)
        with pytest.raises(AmbientFlowError):
            flow.scan(
                _ambient_caps(policy),
                run_id=run_id,
                request=_request(f"ambient_fd_{index}"),
            )
        flow.close()
    assert len(os.listdir("/dev/fd")) <= baseline + 2


def test_public_renderers_round_trip_committed_evidence(tmp_path: Path) -> None:
    vault, resolver, runs, policy, clock = _setup(tmp_path)
    _run(runs, "run_ambient_roundtrip", "ambient")
    ambient = AmbientFlow(resolver, runs, policy, clock).scan(
        _ambient_caps(policy),
        run_id="run_ambient_roundtrip",
        request=_request("ambient_roundtrip"),
    )
    raw = (
        vault / "agent/runs/run_ambient_roundtrip" / f"{ambient.evidence_artifact}.json"
    ).read_bytes()
    assert render_ambient_run_evidence(parse_ambient_run_evidence(raw)) == raw

    _run(runs, "run_bundle_roundtrip", "bundle")
    bundle = BundleFlow(resolver, runs, policy, clock).collect(
        _bundle_caps(policy),
        run_id="run_bundle_roundtrip",
        request=_bundle_request("bundle_roundtrip"),
    )
    raw = (
        vault / "agent/runs/run_bundle_roundtrip" / f"{bundle.evidence_artifact}.json"
    ).read_bytes()
    assert render_bundle_run_evidence(parse_bundle_run_evidence(raw)) == raw
