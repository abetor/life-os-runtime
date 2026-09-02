"""P3-07 report and proposal-only memory acceptance."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil

import pytest

import tool_life_os_runtime.ext.flows.memory.flow as memory_flow_module
import tool_life_os_runtime.ext.flows.report.flow as report_flow_module

from tool_life_os_runtime.ext.flows.memory import (
    MEMORY_SCHEMA_VERSION,
    DecayPolicy,
    DeletionPolicy,
    EvidenceBinding,
    ForgetRequest,
    HumanProposalDecision,
    MemoryCapabilities,
    MemoryCrashHooks,
    MemoryEvidence,
    MemoryFlow,
    MemoryFlowError,
    MemoryHygieneQuery,
    MemoryMetadataRecord,
    MemoryProposalRecord,
    RetentionPolicy,
    inspect_memory_run_evidence,
    memory_evidence_artifact_name,
    parse_forget_outcome,
    parse_memory_metadata,
    parse_memory_proposal,
    parse_memory_run_evidence,
    render_memory_proposal,
)
from tool_life_os_runtime.ext.flows.report import (
    REPORT_SCHEMA_VERSION,
    DailyLogRecord,
    HumanMaterial,
    ReportCapabilities,
    ReportContext,
    ReportContextItem,
    ReportCrashHooks,
    ReportFlow,
    ReportFlowError,
    WeeklyReflection,
    daily_memory_evidence,
    inspect_report_run_evidence,
    parse_daily_log,
    parse_report_run_evidence,
    parse_weekly_reflection,
    render_daily_log,
    render_weekly_reflection,
    report_evidence_artifact_name,
)
from tool_life_os_runtime.ext.review.authority import AuthorityPolicy
from tool_life_os_runtime.ext.runs import RunStore
from tool_life_os_runtime.ext.vault.config import load_vault_config
from tool_life_os_runtime.ext.vault.schema import VaultPathResolver


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/vault-minimal"

REPORT_ACTIONS = {
    "read-report-projects": ("read", "vault:projects"),
    "read-report-tasks": ("read", "vault:tasks"),
    "collect-primary-evidence": ("read", "vault:agent/logs"),
    "read-report-memory": ("read", "vault:agent/memory"),
    "commit-memory-proposal": ("proposal", "vault:review"),
    "append-report-log": ("internal-write", "vault:agent/logs"),
    "record-run-state": ("internal-write", "vault:agent/runs"),
}
MEMORY_ACTIONS = {
    "read-current-memory": ("read", "vault:agent/memory"),
    "check-evidence-and-retention": ("read", "vault:agent/logs"),
    "read-memory-review-state": ("read", "vault:review"),
    "commit-semantic-memory-proposal": ("proposal", "vault:review"),
    "commit-deterministic-memory-metadata": (
        "domain-write",
        "vault:agent/memory-metadata",
    ),
    "record-run-state": ("internal-write", "vault:agent/runs"),
}


def _issue(policy: AuthorityPolicy, flow: str, action: str):
    authority, target = (REPORT_ACTIONS if flow == "report" else MEMORY_ACTIONS)[
        action
    ]
    return policy.issue(
        flow_id=flow,
        action_id=action,
        actor="runtime",
        authority=authority,
        target=target,
    )


def _setup(tmp_path: Path):
    vault = tmp_path / "vault"
    shutil.copytree(FIXTURE, vault)
    resolver = VaultPathResolver(vault, load_vault_config(vault))
    policy = AuthorityPolicy()
    runs = RunStore(
        resolver, clock=lambda: datetime(2026, 8, 20, 9, tzinfo=timezone.utc)
    )
    runs.create(
        run_id="run_report_one",
        flow="report",
        phase="report",
        authority="proposal",
        executor="fixture",
        input_data={"period": "2026-08-20"},
    )
    runs.resume("run_report_one", executor="fixture")
    runs.create(
        run_id="run_memory_one",
        flow="memory",
        phase="memory",
        authority="domain-write",
        executor="fixture",
        input_data={"scope": "personal"},
    )
    runs.resume("run_memory_one", executor="fixture")
    report_caps = ReportCapabilities(
        *(_issue(policy, "report", action) for action in REPORT_ACTIONS)
    )
    memory_caps = MemoryCapabilities(
        *(_issue(policy, "memory", action) for action in MEMORY_ACTIONS)
    )
    return (
        vault,
        resolver,
        policy,
        runs,
        report_caps,
        memory_caps,
        ReportFlow(resolver, runs, policy),
        MemoryFlow(resolver, runs, policy),
    )


def _snapshot(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file() and not path.is_symlink()
    }


def _context(vault: Path) -> ReportContext:
    project = vault / "projects/context/state.json"
    project.parent.mkdir()
    project.write_bytes(b'{"schema_version":1,"status":"active"}\n')
    entity = vault / "agent/memory/entities/people.json"
    entity.parent.mkdir()
    entity.write_bytes(b'{"domain":"people","entities":[],"schema_version":1}\n')
    return ReportContext(
        (
            ReportContextItem(
                "entity",
                "agent/memory/entities/people.json",
                hashlib.sha256(entity.read_bytes()).hexdigest(),
            ),
            ReportContextItem(
                "project",
                "projects/context/state.json",
                hashlib.sha256(project.read_bytes()).hexdigest(),
            ),
        )
    )


def _daily(vault: Path, operation: str = "daily_one") -> DailyLogRecord:
    return DailyLogRecord(
        "rpt-daily-one",
        "2026-08-20",
        "run_report_one",
        operation,
        "2026-08-20T10:00:00Z",
        (
            HumanMaterial(
                "human_walk",
                "daily-human-entry",
                "human",
                "2026-08-20T09:55:00Z",
                "A short walk restored my focus.",
            ),
        ),
        _context(vault),
        "The report model grouped the retained input into a daily reflection.",
    )


def _proposal(
    evidence: MemoryEvidence,
    *,
    producer: str = "report",
    run_id: str = "run_report_one",
    operation_id: str = "extract_one",
    proposal_id: str = "memprop-walk",
    operation: str = "create",
    current_ref: str | None = None,
    current_hash: str | None = None,
) -> MemoryProposalRecord:
    return MemoryProposalRecord(
        proposal_id=proposal_id,
        status="proposed",
        operation=operation,
        memory_id="mem-walk",
        memory_kind="feedback",
        scope="workday",
        candidate_text="A short walk restored my focus.",
        evidence=(evidence,),
        current_memory_ref=current_ref,
        current_memory_sha256=current_hash,
        precondition_sha256=current_hash,
        retention=RetentionPolicy("review", review_at="2026-09-20T00:00:00Z"),
        decay=DecayPolicy("stale-after", stale_after_days=30),
        deletion=DeletionPolicy("forget"),
        producer_flow=producer,
        run_id=run_id,
        operation_id=operation_id,
        created_at="2026-08-20T10:05:00Z",
    )


def _record_daily(setup):
    vault, _, _, _, report_caps, _, report, _ = setup
    daily = _daily(vault)
    result = report.record_daily(daily, capabilities=report_caps)
    return daily, result


def _approved_metadata_input(setup) -> MemoryMetadataRecord:
    vault, _, _, _, _, memory_caps, _, memory = setup
    daily = _daily(vault)
    source = vault / "agent/logs/reports/daily/2026-08-20.jsonl"
    source.parent.mkdir(parents=True)
    source.write_bytes(render_daily_log(daily))
    evidence = daily_memory_evidence(daily, "human_walk")
    proposal = _proposal(
        evidence,
        producer="memory",
        run_id="run_memory_one",
        operation_id="parent_setup_proposal",
        proposal_id="memprop-parent-setup",
    )
    memory.propose(memory_caps, proposal)
    approved = replace(
        proposal,
        status="approved",
        human_decision=HumanProposalDecision(
            "approve", "human", "2026-08-20T12:00:00Z"
        ),
    )
    (vault / "review/memprop-parent-setup.memory.json").write_bytes(
        render_memory_proposal(approved)
    )
    semantic = vault / "agent/memory/feedback/walk.txt"
    semantic.parent.mkdir()
    semantic.write_text(approved.candidate_text)
    digest = hashlib.sha256(semantic.read_bytes()).hexdigest()
    return MemoryMetadataRecord(
        "mem-walk",
        "agent/memory/feedback/walk.txt",
        digest,
        "feedback",
        "workday",
        (EvidenceBinding(evidence.evidence_id, evidence.source_sha256),),
        approved.proposal_id,
        "2026-08-20T12:00:00Z",
        "2026-08-20T12:00:00Z",
        approved.retention,
        approved.decay,
        approved.deletion,
        "active",
        1,
        "placeholder",
        "0" * 64,
    )


def test_strict_v1_schemas_and_primary_human_boundary(tmp_path: Path):
    assert MEMORY_SCHEMA_VERSION == REPORT_SCHEMA_VERSION == 1
    setup = _setup(tmp_path)
    daily, _ = _record_daily(setup)
    evidence = daily_memory_evidence(daily, "human_walk")
    weekly = WeeklyReflection(
        "refl-week-one",
        "2026-08-17",
        "run_report_one",
        "weekly_one",
        "2026-08-20T11:00:00Z",
        (evidence,),
        daily.context,
        "A weekly model reflection grounded in the retained daily human line.",
    )
    assert parse_daily_log(render_daily_log(daily)) == daily
    assert parse_weekly_reflection(render_weekly_reflection(weekly)) == weekly

    payload = json.loads(render_daily_log(daily))
    payload["unknown"] = True
    with pytest.raises(ReportFlowError, match="unknown fields"):
        parse_daily_log(
            (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode()
        )
    with pytest.raises(ReportFlowError, match="duplicate"):
        parse_daily_log(b'{"schema_version":1,"schema_version":1}\n')
    false_retention = replace(evidence, source_kind="weekly-reflection")
    with pytest.raises(ReportFlowError, match="primary human"):
        render_weekly_reflection(replace(weekly, primary_evidence=(false_retention,)))
    with pytest.raises(MemoryFlowError, match="primary evidence"):
        render_memory_proposal(replace(_proposal(evidence), evidence=()))


def test_primary_evidence_anchor_cannot_relabel_summary_text(tmp_path: Path):
    setup = _setup(tmp_path)
    vault, _, _, _, report_caps, memory_caps, report, memory = setup
    daily, _ = _record_daily(setup)
    evidence = daily_memory_evidence(daily, "human_walk")
    relabeled = replace(evidence, exact_text=daily.reflection_text)
    weekly = WeeklyReflection(
        "refl-summary-counterexample",
        "2026-08-17",
        "run_report_one",
        "weekly_summary_counterexample",
        "2026-08-20T11:00:00Z",
        (relabeled,),
        daily.context,
        "A model summary cannot become primary evidence.",
    )
    with pytest.raises(ReportFlowError, match="exact human material"):
        report.record_weekly(weekly, capabilities=report_caps)
    proposal = _proposal(
        relabeled,
        producer="memory",
        run_id="run_memory_one",
        operation_id="summary_counterexample",
        proposal_id="memprop-summary-counterexample",
    )
    with pytest.raises(MemoryFlowError, match="exact human material"):
        memory.propose(memory_caps, proposal)
    assert not (vault / "review/memprop-summary-counterexample.memory.json").exists()


def test_daily_weekly_and_extract_are_replay_safe_and_proposal_only(tmp_path: Path):
    setup = _setup(tmp_path)
    vault, _, _, runs, report_caps, _, report, _ = setup
    daily, daily_result = _record_daily(setup)
    assert daily_result.log_ref == "agent/logs/reports/daily/2026-08-20.jsonl"
    assert not (vault / "agent/memory/feedback").exists()
    assert report.record_daily(daily, capabilities=report_caps).replayed

    evidence = daily_memory_evidence(daily, "human_walk")
    weekly = WeeklyReflection(
        "refl-week-one",
        "2026-08-17",
        "run_report_one",
        "weekly_one",
        "2026-08-20T11:00:00Z",
        (evidence,),
        daily.context,
        "The weekly reflection uses primary human material, not daily prose.",
    )
    report.record_weekly(weekly, capabilities=report_caps)
    proposal = _proposal(evidence)
    extracted = report.extract_memory(
        proposal,
        event_id="rpt-extract-one",
        recorded_at="2026-08-20T12:00:00Z",
        context=daily.context,
        capabilities=report_caps,
    )
    assert extracted.proposal_ref == "review/memprop-walk.memory.json"
    assert parse_memory_proposal(
        (vault / "review/memprop-walk.memory.json").read_bytes()
    ) == proposal
    assert report.extract_memory(
        proposal,
        event_id="rpt-extract-one",
        recorded_at="2026-08-20T12:00:00Z",
        context=daily.context,
        capabilities=report_caps,
    ).replayed
    extraction_snapshot = runs.snapshot(
        "run_report_one",
        artifact_names=(report_evidence_artifact_name("extract_one"),),
    )
    extraction_artifact = extraction_snapshot.artifacts[0]
    extraction_raw = (vault / extraction_artifact.state_ref).read_bytes()
    extraction_evidence = inspect_report_run_evidence(
        extraction_artifact, extraction_raw
    )
    assert extraction_evidence.outcome_class == "proposal-pending"
    assert extraction_evidence.proposal_ref == "review/memprop-walk.memory.json"
    assert hashlib.sha256(
        (vault / extraction_evidence.proposal_ref).read_bytes()
    ).hexdigest() == extraction_evidence.proposal_sha256
    assert runs.status("run_report_one")["status"] == "running"

    action_ids = [
        action["action_id"]
        for action in runs.trace_events("run_report_one")[-1]["actions"]
    ]
    assert action_ids == [
        "read-report-projects",
        "read-report-tasks",
        "collect-primary-evidence",
        "read-report-memory",
        "commit-memory-proposal",
        "append-report-log",
        "record-run-state",
    ]


def test_report_crash_after_log_recovers_exactly(tmp_path: Path):
    setup = _setup(tmp_path)
    vault, _, _, _, report_caps, _, report, _ = setup
    daily = _daily(vault)

    def stop() -> None:
        raise RuntimeError("stop-after-log")

    with pytest.raises(RuntimeError, match="stop-after-log"):
        report.record_daily(
            daily,
            capabilities=report_caps,
            crash_hooks=ReportCrashHooks(after_log_publish=stop),
        )
    before = (vault / "agent/logs/reports/daily/2026-08-20.jsonl").read_bytes()
    assert report.record_daily(daily, capabilities=report_caps).replayed
    assert (vault / "agent/logs/reports/daily/2026-08-20.jsonl").read_bytes() == before


def test_memory_proposal_crash_replay_and_evidence_inspection(tmp_path: Path):
    setup = _setup(tmp_path)
    vault, _, _, runs, _, memory_caps, _, memory = setup
    daily = _daily(vault)
    # Retain the primary source without consuming the report run.
    source = vault / "agent/logs/reports/daily/2026-08-20.jsonl"
    source.parent.mkdir(parents=True)
    source.write_bytes(render_daily_log(daily))
    proposal = _proposal(
        daily_memory_evidence(daily, "human_walk"),
        producer="memory",
        run_id="run_memory_one",
        operation_id="memory_propose_one",
        proposal_id="memprop-memory-walk",
    )

    def stop() -> None:
        raise RuntimeError("stop-after-proposal")

    with pytest.raises(RuntimeError, match="stop-after-proposal"):
        memory.propose(
            memory_caps,
            proposal,
            crash_hooks=MemoryCrashHooks(after_domain_publish=stop),
        )
    assert memory.propose(memory_caps, proposal).replayed
    snapshot = runs.snapshot(
        "run_memory_one",
        artifact_names=(memory_evidence_artifact_name("memory_propose_one"),),
    )
    artifact = snapshot.artifacts[0]
    raw = (vault / artifact.state_ref).read_bytes()
    inspected = inspect_memory_run_evidence(artifact, raw)
    assert inspected.operation == "propose"
    assert inspected.outcome_class == "proposal-pending"
    assert hashlib.sha256((vault / inspected.output_ref).read_bytes()).hexdigest() == (
        inspected.target_sha256
    )
    assert parse_memory_run_evidence(raw).output_ref.endswith(
        "memprop-memory-walk.memory.json"
    )
    tampered = json.loads(raw)
    tampered["target_sha256"] = "0" * 64
    tampered_raw = (
        json.dumps(tampered, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()
    with pytest.raises(MemoryFlowError, match="artifact binding"):
        inspect_memory_run_evidence(artifact, tampered_raw)


def test_approved_semantic_application_only_commits_metadata(tmp_path: Path):
    setup = _setup(tmp_path)
    vault, _, _, runs, _, memory_caps, _, memory = setup
    daily = _daily(vault)
    source = vault / "agent/logs/reports/daily/2026-08-20.jsonl"
    source.parent.mkdir(parents=True)
    source.write_bytes(render_daily_log(daily))
    evidence = daily_memory_evidence(daily, "human_walk")
    proposed = _proposal(
        evidence,
        producer="memory",
        run_id="run_memory_one",
        operation_id="memory_propose_one",
        proposal_id="memprop-memory-walk",
    )
    memory.propose(memory_caps, proposed)
    approved = replace(
        proposed,
        status="approved",
        human_decision=HumanProposalDecision(
            "approve", "human", "2026-08-20T12:00:00Z"
        ),
    )
    (vault / "review/memprop-memory-walk.memory.json").write_bytes(
        render_memory_proposal(approved)
    )
    semantic = vault / "agent/memory/feedback/walk.txt"
    semantic.parent.mkdir()
    semantic.write_text(approved.candidate_text)
    semantic_hash = hashlib.sha256(semantic.read_bytes()).hexdigest()
    requested = MemoryMetadataRecord(
        "mem-walk",
        "agent/memory/feedback/walk.txt",
        semantic_hash,
        "feedback",
        "workday",
        (EvidenceBinding(evidence.evidence_id, evidence.source_sha256),),
        approved.proposal_id,
        "2026-08-20T12:00:00Z",
        "2026-08-20T12:00:00Z",
        approved.retention,
        approved.decay,
        approved.deletion,
        "active",
        1,
        "placeholder",
        "0" * 64,
    )
    result = memory.commit_metadata(
        memory_caps,
        run_id="run_memory_one",
        operation_id="metadata_one",
        record=requested,
    )
    assert result.metadata is not None
    metadata_path = vault / "agent/memory/metadata/records/mem-walk.json"
    assert parse_memory_metadata(metadata_path.read_bytes()) == result.metadata
    assert approved.candidate_text.encode() not in metadata_path.read_bytes()
    assert runs.status("run_memory_one")["status"] == "running"
    assert [
        action["action_id"]
        for action in runs.trace_events("run_memory_one")[-1]["actions"]
    ] == [
        "read-current-memory",
        "check-evidence-and-retention",
        "read-memory-review-state",
        "commit-deterministic-memory-metadata",
        "record-run-state",
    ]


def test_stale_boundary_creates_review_not_shared_text(tmp_path: Path):
    setup = _setup(tmp_path)
    vault, _, _, _, _, memory_caps, _, memory = setup
    source_daily = _daily(vault)
    source = vault / "agent/logs/reports/daily/2026-08-20.jsonl"
    source.parent.mkdir(parents=True)
    source.write_bytes(render_daily_log(source_daily))
    evidence = daily_memory_evidence(source_daily, "human_walk")
    proposed = _proposal(
        evidence,
        producer="memory",
        run_id="run_memory_one",
        operation_id="memory_propose_one",
        proposal_id="memprop-memory-walk",
    )
    memory.propose(memory_caps, proposed)
    approved = replace(
        proposed,
        status="approved",
        human_decision=HumanProposalDecision(
            "approve", "human", "2026-08-20T12:00:00Z"
        ),
    )
    (vault / "review/memprop-memory-walk.memory.json").write_bytes(
        render_memory_proposal(approved)
    )
    semantic = vault / "agent/memory/feedback/walk.txt"
    semantic.parent.mkdir()
    semantic.write_text(approved.candidate_text)
    digest = hashlib.sha256(semantic.read_bytes()).hexdigest()
    record = MemoryMetadataRecord(
        "mem-walk",
        "agent/memory/feedback/walk.txt",
        digest,
        "feedback",
        "workday",
        (EvidenceBinding(evidence.evidence_id, evidence.source_sha256),),
        approved.proposal_id,
        "2026-08-20T12:00:00Z",
        "2026-08-20T12:00:00Z",
        approved.retention,
        approved.decay,
        approved.deletion,
        "active",
        1,
        "placeholder",
        "0" * 64,
    )
    metadata = memory.commit_metadata(
        memory_caps,
        run_id="run_memory_one",
        operation_id="metadata_one",
        record=record,
    ).metadata
    assert metadata is not None
    assert memory.stale(
        memory_caps.read_current_memory,
        MemoryHygieneQuery("2026-09-19T11:59:59Z", 30),
    ) == ()
    stale = memory.stale(
        memory_caps.read_current_memory,
        MemoryHygieneQuery("2026-09-19T12:00:00Z", 30),
    )
    assert stale[0].reasons == ("decayed", "threshold")
    review = _proposal(
        evidence,
        producer="memory",
        run_id="run_memory_one",
        operation_id="stale_review_one",
        proposal_id="memprop-stale-walk",
        operation="retain",
        current_ref=metadata.semantic_ref,
        current_hash=metadata.semantic_sha256,
    )
    memory.propose_stale_review(memory_caps, stale[0], review)
    assert (vault / "review/memprop-stale-walk.memory.json").exists()
    assert semantic.read_text() == approved.candidate_text


def test_never_shared_forget_has_verifiable_outcome(tmp_path: Path):
    setup = _setup(tmp_path)
    vault, _, _, _, _, memory_caps, _, memory = setup
    daily = _daily(vault)
    source = vault / "agent/logs/reports/daily/2026-08-20.jsonl"
    source.parent.mkdir(parents=True)
    source.write_bytes(render_daily_log(daily))
    proposal = _proposal(
        daily_memory_evidence(daily, "human_walk"),
        producer="memory",
        run_id="run_memory_one",
        operation_id="rejected_create",
        proposal_id="memprop-rejected-walk",
    )
    rejected = replace(
        proposal,
        status="rejected",
        human_decision=HumanProposalDecision(
            "reject", "human", "2026-08-20T11:00:00Z"
        ),
    )
    (vault / "review/memprop-rejected-walk.memory.json").write_bytes(
        render_memory_proposal(rejected)
    )
    result = memory.forget(
        memory_caps,
        run_id="run_memory_one",
        operation_id="forget_never_shared",
        request=ForgetRequest(
            "forget-walk",
            "mem-walk",
            "memprop-rejected-walk",
            "2026-08-20T12:00:00Z",
        ),
    )
    outcome_path = vault / "agent/memory/metadata/outcomes/forget-walk.json"
    assert parse_forget_outcome(outcome_path.read_bytes()) == result.forget_outcome
    assert result.forget_outcome is not None
    assert result.forget_outcome.verification == "proposal-never-shared"
    assert not (vault / "agent/memory/feedback/walk.txt").exists()


def test_run_evidence_contract_and_fd_stability(tmp_path: Path):
    setup = _setup(tmp_path)
    vault, _, _, runs, report_caps, memory_caps, report, memory = setup
    daily, _ = _record_daily(setup)
    snapshot = runs.snapshot(
        "run_report_one",
        artifact_names=(report_evidence_artifact_name(daily.operation_id),),
    )
    artifact = snapshot.artifacts[0]
    raw = (vault / artifact.state_ref).read_bytes()
    evidence = inspect_report_run_evidence(artifact, raw)
    assert evidence.operation == "daily"
    assert evidence.outcome_class == "report-log"
    assert parse_report_run_evidence(raw) == evidence

    omitted = json.loads(raw)
    del omitted["outcome_class"]
    with pytest.raises(ReportFlowError, match="unknown fields"):
        parse_report_run_evidence(
            (json.dumps(omitted, sort_keys=True, separators=(",", ":")) + "\n").encode()
        )

    before = len(os.listdir("/dev/fd"))
    for _ in range(40):
        assert memory.stale(
            memory_caps.read_current_memory,
            MemoryHygieneQuery("2026-08-20T12:00:00Z", 30),
        ) == ()
    assert len(os.listdir("/dev/fd")) == before
    assert report.record_daily(daily, capabilities=report_caps).replayed


def test_capability_failure_and_whole_vault_boundary(tmp_path: Path):
    setup = _setup(tmp_path)
    vault, _, policy, _, report_caps, _, report, _ = setup
    tasks_before = _snapshot(vault / "tasks")
    knowledge_before = _snapshot(vault / "knowledge")
    daily = _daily(vault)
    wrong = _issue(policy, "memory", "read-current-memory")
    with pytest.raises(ReportFlowError, match="capability"):
        report.record_daily(
            daily,
            capabilities=replace(report_caps, read_report_projects=wrong),
        )
    assert not (vault / "agent/logs/reports").exists()
    report.record_daily(daily, capabilities=report_caps)
    assert _snapshot(vault / "tasks") == tasks_before
    assert _snapshot(vault / "knowledge") == knowledge_before
    assert not any(path.name.endswith(".md") for path in (vault / "agent/memory").rglob("*"))


def test_invalid_hooks_fail_before_capability_or_io(tmp_path: Path):
    setup = _setup(tmp_path)
    vault, _, _, _, report_caps, memory_caps, report, memory = setup
    daily = _daily(vault)
    before = _snapshot(vault)
    with pytest.raises(ReportFlowError, match="hooks"):
        report.record_daily(
            daily,
            capabilities=report_caps,
            crash_hooks=ReportCrashHooks(after_prepare=object()),  # type: ignore[arg-type]
        )
    proposal = _proposal(
        MemoryEvidence(
            "evidence",
            "daily-human-entry",
            "agent/logs/missing.jsonl",
            "0" * 64,
            "anchor",
            "human",
            "2026-08-20T10:00:00Z",
            "text",
        ),
        producer="memory",
        run_id="run_memory_one",
    )
    with pytest.raises(MemoryFlowError, match="hooks"):
        memory.propose(
            memory_caps,
            proposal,
            crash_hooks=MemoryCrashHooks(after_prepare=object()),  # type: ignore[arg-type]
        )
    assert _snapshot(vault) == before


def test_report_parent_replacement_fails_before_detached_publish(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    setup = _setup(tmp_path)
    vault, _, _, _, report_caps, _, report, _ = setup
    daily = _daily(vault)
    original = report_flow_module._atomic_replace
    foreign = b"foreign replacement bytes\n"

    def replace_parent(
        fd,
        name,
        data,
        expected_identity,
        validate_parent,
        recovery_fd,
        recovery_kind,
    ):
        reports = vault / "agent/logs/reports"
        reports.rename(vault / "agent/logs/reports-detached")
        (reports / "daily").mkdir(parents=True)
        (reports / "daily/2026-08-20.jsonl").write_bytes(foreign)
        return original(
            fd,
            name,
            data,
            expected_identity,
            validate_parent,
            recovery_fd,
            recovery_kind,
        )

    monkeypatch.setattr(report_flow_module, "_atomic_replace", replace_parent)
    with pytest.raises(ReportFlowError, match="namespace changed"):
        report.record_daily(daily, capabilities=report_caps)
    assert (vault / "agent/logs/reports/daily/2026-08-20.jsonl").read_bytes() == foreign
    assert not (
        vault / "agent/logs/reports-detached/daily/2026-08-20.jsonl"
    ).exists()


def test_report_foreign_leaf_collision_after_prepare_is_preserved(tmp_path: Path):
    setup = _setup(tmp_path)
    vault, _, _, _, report_caps, _, report, _ = setup
    daily = _daily(vault)
    foreign = b"foreign leaf bytes\n"

    def collide() -> None:
        leaf = vault / "agent/logs/reports/daily/2026-08-20.jsonl"
        leaf.parent.mkdir(parents=True)
        leaf.write_bytes(foreign)

    with pytest.raises(ReportFlowError, match="canonical JSON|invalid"):
        report.record_daily(
            daily,
            capabilities=report_caps,
            crash_hooks=ReportCrashHooks(after_prepare=collide),
        )
    assert (vault / "agent/logs/reports/daily/2026-08-20.jsonl").read_bytes() == foreign


@pytest.mark.parametrize(
    "module,error_type",
    (
        (report_flow_module, ReportFlowError),
        (memory_flow_module, MemoryFlowError),
    ),
)
def test_identity_bound_retirement_preserves_substituted_named_leaf(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    module,
    error_type,
):
    source = tmp_path / "source"
    recovery = tmp_path / "recovery"
    source.mkdir()
    recovery.mkdir()
    owned = source / "owned.tmp"
    owned.write_bytes(b"owned bytes\n")
    expected_stat = owned.stat()
    expected = expected_stat.st_dev, expected_stat.st_ino
    original = module._rename_noreplace_between
    substituted = False

    def substitute(source_fd, source_name, recovery_fd, recovery_name):
        nonlocal substituted
        if source_name == "owned.tmp" and not substituted:
            substituted = True
            original(
                source_fd,
                source_name,
                recovery_fd,
                recovery_name,
            )
            foreign_fd = os.open(
                source_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=source_fd,
            )
            try:
                os.write(foreign_fd, b"foreign rebound bytes\n")
                os.fsync(foreign_fd)
            finally:
                os.close(foreign_fd)
        return original(source_fd, source_name, recovery_fd, recovery_name)

    monkeypatch.setattr(module, "_rename_noreplace_between", substitute)
    source_fd = os.open(source, os.O_RDONLY | os.O_DIRECTORY)
    recovery_fd = os.open(recovery, os.O_RDONLY | os.O_DIRECTORY)
    try:
        assert not module._retire_exact(
            source_fd, "owned.tmp", expected, recovery_fd, "exact-seam"
        )
        for _ in range(20):
            assert not module._retire_exact(
                source_fd, "owned.tmp", expected, recovery_fd, "exact-seam"
            )
    except error_type:
        pytest.fail("retirement seam leaked a flow error")
    finally:
        os.close(recovery_fd)
        os.close(source_fd)
    assert owned.read_bytes() == b"foreign rebound bytes\n"
    retained = tuple(recovery.iterdir())
    assert len(retained) == 1
    assert retained[0].read_bytes() == b"owned bytes\n"


def test_memory_proposal_parent_change_after_link_rolls_back_owned_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    setup = _setup(tmp_path)
    vault, _, _, _, _, memory_caps, _, memory = setup
    daily = _daily(vault)
    source = vault / "agent/logs/reports/daily/2026-08-20.jsonl"
    source.parent.mkdir(parents=True)
    source.write_bytes(render_daily_log(daily))
    proposal = _proposal(
        daily_memory_evidence(daily, "human_walk"),
        producer="memory",
        run_id="run_memory_one",
        operation_id="proposal_parent_change",
        proposal_id="memprop-parent-change",
    )
    original = memory_flow_module.os.link
    swapped = False

    def swap_after_link(source_name, target_name, *args, **kwargs):
        nonlocal swapped
        result = original(source_name, target_name, *args, **kwargs)
        if target_name == "memprop-parent-change.memory.json" and not swapped:
            swapped = True
            review = vault / "review"
            review.rename(vault / "review-detached")
            review.mkdir()
            (review / "foreign.marker").write_bytes(b"foreign\n")
        return result

    monkeypatch.setattr(memory_flow_module.os, "link", swap_after_link)
    with pytest.raises(MemoryFlowError, match="zone changed"):
        memory.propose(memory_caps, proposal)
    detached = vault / "review-detached"
    assert not (detached / "memprop-parent-change.memory.json").exists()
    assert not tuple(detached.glob("*.tmp"))
    assert (vault / "review/foreign.marker").read_bytes() == b"foreign\n"
    assert memory.propose(memory_caps, proposal).proposal_ref == (
        "review/memprop-parent-change.memory.json"
    )


def test_memory_new_metadata_parent_change_after_link_has_no_detached_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    setup = _setup(tmp_path)
    vault, _, _, _, _, memory_caps, _, memory = setup
    record = _approved_metadata_input(setup)
    original = memory_flow_module.os.link
    swapped = False

    def swap_after_link(source_name, target_name, *args, **kwargs):
        nonlocal swapped
        result = original(source_name, target_name, *args, **kwargs)
        if target_name == "mem-walk.json" and not swapped:
            swapped = True
            records = vault / "agent/memory/metadata/records"
            records.rename(records.with_name("records-detached"))
            records.mkdir()
        return result

    monkeypatch.setattr(memory_flow_module.os, "link", swap_after_link)
    with pytest.raises(MemoryFlowError, match="namespace changed"):
        memory.commit_metadata(
            memory_caps,
            run_id="run_memory_one",
            operation_id="metadata_parent_change",
            record=record,
        )
    metadata = vault / "agent/memory/metadata"
    detached = metadata / "records-detached"
    replacement_identity = (metadata / "records").stat()
    assert not (detached / "mem-walk.json").exists()
    assert not tuple(detached.glob("*.tmp"))
    assert memory.commit_metadata(
        memory_caps,
        run_id="run_memory_one",
        operation_id="metadata_parent_change",
        record=record,
    ).metadata is not None
    after_retry = (metadata / "records").stat()
    assert (after_retry.st_dev, after_retry.st_ino) == (
        replacement_identity.st_dev,
        replacement_identity.st_ino,
    )


def test_memory_outcome_parent_change_after_link_has_no_detached_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    setup = _setup(tmp_path)
    vault, _, _, _, _, memory_caps, _, memory = setup
    daily = _daily(vault)
    source = vault / "agent/logs/reports/daily/2026-08-20.jsonl"
    source.parent.mkdir(parents=True)
    source.write_bytes(render_daily_log(daily))
    proposal = _proposal(
        daily_memory_evidence(daily, "human_walk"),
        producer="memory",
        run_id="run_memory_one",
        operation_id="outcome_setup",
        proposal_id="memprop-outcome-parent",
    )
    rejected = replace(
        proposal,
        status="rejected",
        human_decision=HumanProposalDecision(
            "reject", "human", "2026-08-20T11:00:00Z"
        ),
    )
    (vault / "review/memprop-outcome-parent.memory.json").write_bytes(
        render_memory_proposal(rejected)
    )
    request = ForgetRequest(
        "forget-parent-change",
        "mem-walk",
        "memprop-outcome-parent",
        "2026-08-20T12:00:00Z",
    )
    original = memory_flow_module.os.link
    swapped = False

    def swap_after_link(source_name, target_name, *args, **kwargs):
        nonlocal swapped
        result = original(source_name, target_name, *args, **kwargs)
        if target_name == "forget-parent-change.json" and not swapped:
            swapped = True
            outcomes = vault / "agent/memory/metadata/outcomes"
            outcomes.rename(outcomes.with_name("outcomes-detached"))
            outcomes.mkdir()
        return result

    monkeypatch.setattr(memory_flow_module.os, "link", swap_after_link)
    with pytest.raises(MemoryFlowError, match="namespace changed"):
        memory.forget(
            memory_caps,
            run_id="run_memory_one",
            operation_id="outcome_parent_change",
            request=request,
        )
    metadata = vault / "agent/memory/metadata"
    detached = metadata / "outcomes-detached"
    replacement_identity = (metadata / "outcomes").stat()
    assert not (detached / "forget-parent-change.json").exists()
    assert not tuple(detached.glob("*.tmp"))
    assert memory.forget(
        memory_caps,
        run_id="run_memory_one",
        operation_id="outcome_parent_change",
        request=request,
    ).forget_outcome is not None
    after_retry = (metadata / "outcomes").stat()
    assert (after_retry.st_dev, after_retry.st_ino) == (
        replacement_identity.st_dev,
        replacement_identity.st_ino,
    )


def test_exact_replays_leave_recovery_residue_bounded(tmp_path: Path):
    setup = _setup(tmp_path)
    vault, _, _, _, report_caps, _, report, _ = setup
    daily = _daily(vault)
    report.record_daily(daily, capabilities=report_caps)
    rollback = vault / "agent/runs/run_report_one/rollback"
    before = tuple(sorted(path.name for path in rollback.iterdir()))
    for _ in range(20):
        assert report.record_daily(daily, capabilities=report_caps).replayed
    assert tuple(sorted(path.name for path in rollback.iterdir())) == before
