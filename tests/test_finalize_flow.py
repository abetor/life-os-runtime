"""P2-07 unified finalize acceptance and crash replay."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
from typing import Mapping

import pytest

from tool_life_os_runtime.ext.flows.finalize import (
    FinalizeArtifactRoles,
    FinalizeCapabilities,
    FinalizeCrashHooks,
    FinalizeError,
    FinalizeFlow,
    parse_metric_record,
    parse_outcome_record,
)
from tool_life_os_runtime.ext.flows.ask import AskFileBack, AskFlow, publish_ask_result
from tool_life_os_runtime.ext.flows.book import (
    BOOK_SCHEMA_VERSION,
    BookCapabilities,
    BookCommand,
    BookFlow,
    BookSourceManifest,
)
from tool_life_os_runtime.ext.flows.ambient import (
    AmbientAvailability,
    AmbientCapabilities,
    AmbientFlow,
    AmbientRequest,
    AmbientReviewBudget,
)
from tool_life_os_runtime.ext.flows.bundle import (
    BundleCapabilities,
    BundleFlow,
    BundleRequest,
    BundleWindow,
)
from tool_life_os_runtime.ext.flows.grill_me import (
    GrillCapabilities,
    GrillExplicitDecision,
    GrillHumanAnswer,
    GrillMeFlow,
    GrillQuestionOutput,
    GrillRequest,
)
from tool_life_os_runtime.ext.flows.lint import (
    LINT_ZONE_ORDER,
    LintCapabilities,
    LintFlow,
    LintRequest,
    LintReviewDecision,
    render_lint_review,
)
from tool_life_os_runtime.ext.flows.mentor import (
    MentorCapabilities,
    MentorExecutorOutput,
    MentorFlow,
    MentorObservation,
    MentorRecommendation,
    MentorRequest,
)
from tool_life_os_runtime.ext.flows.plan import (
    DayPlan,
    PlanPolicy,
    PlanTask,
    render_day_plan,
)
from tool_life_os_runtime.ext.flows.memory import (
    ForgetOutcome,
    MemoryRunEvidence,
    memory_evidence_artifact_name,
    render_forget_outcome,
    render_memory_run_evidence,
)
from tool_life_os_runtime.ext.flows.report import (
    ReportRunEvidence,
    render_report_run_evidence,
    report_evidence_artifact_name,
)
from tool_life_os_runtime.ext.review.artifact import (
    APPLICATION_SCHEMA_VERSION,
    APPLY_JOURNAL_SCHEMA_VERSION,
    DECISION_SCHEMA_VERSION,
    ApplicationEvidence,
    ApplyJournalEvidence,
    ApplyJournalOperation,
    MutationOperation,
    MutationPlan,
    Provenance,
    ReviewArtifact,
    ReviewDecision,
    SourceRef,
    apply_journal_sha256,
    mutation_plan_sha256,
    provenance_sha256,
    render_mutation_plan,
    render_apply_journal,
    render_review_artifact,
    review_body_sha256,
)
from tool_life_os_runtime.ext.review.authority import AuthorityPolicy
from tool_life_os_runtime.ext.runs import (
    OutboxError,
    OutboxStore,
    PreparedArtifact,
    RunError,
    RunStore,
)
from tool_life_os_runtime.ext.runs import store as runs_store
from tool_life_os_runtime.ext.runs.store import FINALIZE_ACTION_ORDER
from tool_life_os_runtime.ext.vault.config import load_vault_config
from tool_life_os_runtime.ext.vault.schema import VaultPathResolver


FIXTURE = Path(__file__).parent / "fixtures/vault-minimal"
ZERO_HASH = "0" * 64


class _Clock:
    def __init__(self) -> None:
        self.value = datetime(2026, 1, 15, 12, 0, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        current = self.value
        self.value += timedelta(seconds=1)
        return current


class _Crash(RuntimeError):
    pass


def _stores(tmp_path: Path, *, review_zone: str = "review"):
    vault = tmp_path / "vault"
    shutil.copytree(FIXTURE, vault)
    if review_zone != "review":
        config_path = vault / "lifeos.toml"
        config_path.write_text(
            config_path.read_text("utf-8").replace(
                'review = "review"', f'review = "{review_zone}"'
            ),
            "utf-8",
        )
        (vault / review_zone).mkdir(parents=True)
    resolver = VaultPathResolver(vault, load_vault_config(vault))
    clock = _Clock()
    runs = RunStore(resolver, clock=clock)
    policy = AuthorityPolicy()
    outbox = OutboxStore(resolver, runs, policy=policy, clock=clock)
    finalize = FinalizeFlow(resolver, runs, outbox, policy=policy, clock=clock)
    return vault, resolver, runs, outbox, policy, finalize


def _capabilities(policy: AuthorityPolicy):
    def issue(action_id: str, authority: str, target: str):
        return policy.issue(
            flow_id="finalize",
            action_id=action_id,
            actor="runtime",
            authority=authority,
            target=target,
        )

    return FinalizeCapabilities(
        validate_run_artifacts=issue(
            "validate-run-artifacts", "read", "vault:agent/runs"
        ),
        read_review_outcome=issue("read-review-outcome", "read", "vault:review"),
        append_domain_log=issue(
            "append-domain-log", "internal-write", "vault:agent/logs"
        ),
        append_run_trace=issue(
            "append-run-trace", "internal-write", "vault:agent/runs/trace"
        ),
        commit_bounded_metrics=issue(
            "commit-bounded-metrics",
            "internal-write",
            "vault:agent/logs/metrics",
        ),
        emit_semantic_outbox_event=issue(
            "emit-semantic-outbox-event",
            "internal-write",
            "vault:agent/outbox",
        ),
        finalize_run_state=issue(
            "finalize-run-state", "internal-write", "vault:agent/runs"
        ),
    )


def _mentor_capabilities(policy: AuthorityPolicy) -> MentorCapabilities:
    specs = (
        ("collect-bounded-mentor-context", "read", "vault:projects"),
        ("read-mentor-knowledge", "read", "vault:knowledge"),
        ("read-mentor-memory", "read", "vault:agent/memory"),
        ("commit-mentor-proposal", "proposal", "vault:review"),
        ("record-run-state", "internal-write", "vault:agent/runs"),
    )
    return MentorCapabilities(
        *(
            policy.issue(
                flow_id="mentor",
                action_id=action,
                actor="runtime",
                authority=authority,
                target=target,
            )
            for action, authority, target in specs
        )
    )


def _grill_capabilities(policy: AuthorityPolicy) -> GrillCapabilities:
    specs = (
        ("collect-decision-context", "human", "read", "vault:projects"),
        ("read-decision-memory", "human", "read", "vault:agent/memory"),
        ("commit-question-answer-record", "human", "proposal", "vault:review"),
        ("record-run-state", "runtime", "internal-write", "vault:agent/runs"),
    )
    return GrillCapabilities(
        *(
            policy.issue(
                flow_id="grill-me",
                action_id=action,
                actor=actor,
                authority=authority,
                target=target,
            )
            for action, actor, authority, target in specs
        )
    )


def _lint_capabilities(policy: AuthorityPolicy) -> LintCapabilities:
    specs = (
        ("scan-inbox-zone", "read", "vault:inbox"),
        ("scan-non-archive-zones", "read", "vault:knowledge"),
        ("scan-task-zone", "read", "vault:tasks"),
        ("scan-project-zone", "read", "vault:projects"),
        ("scan-memory-zone", "read", "vault:agent/memory"),
        ("apply-allowlisted-inbox-fix", "domain-write", "vault:inbox"),
        ("apply-allowlisted-task-fix", "domain-write", "vault:tasks"),
        ("apply-allowlisted-project-fix", "domain-write", "vault:projects"),
        ("commit-semantic-lint-findings", "proposal", "vault:review"),
        ("record-run-state", "internal-write", "vault:agent/runs"),
    )
    return LintCapabilities(
        *(
            policy.issue(
                flow_id="lint",
                action_id=action,
                actor="runtime",
                authority=authority,
                target=target,
            )
            for action, authority, target in specs
        )
    )


def _ambient_capabilities(policy: AuthorityPolicy) -> AmbientCapabilities:
    specs = (
        ("scan-eligible-signals", "read", "vault:tasks"),
        ("read-ambient-projects", "read", "vault:projects"),
        ("read-ambient-review", "read", "vault:review"),
        ("read-ambient-memory", "read", "vault:agent/memory"),
        ("commit-nudge-outbox-event", "internal-write", "vault:agent/outbox"),
        ("record-run-state", "internal-write", "vault:agent/runs"),
    )
    return AmbientCapabilities(
        *(
            policy.issue(
                flow_id="ambient",
                action_id=action,
                actor="system",
                authority=authority,
                target=target,
            )
            for action, authority, target in specs
        )
    )


def _bundle_capabilities(policy: AuthorityPolicy) -> BundleCapabilities:
    specs = (
        ("collect-batched-items", "read", "vault:review"),
        ("read-pending-outbox", "read", "vault:agent/outbox"),
        ("commit-bundle-outbox-event", "internal-write", "vault:agent/outbox"),
        ("record-run-state", "internal-write", "vault:agent/runs"),
    )
    return BundleCapabilities(
        *(
            policy.issue(
                flow_id="bundle",
                action_id=action,
                actor="system",
                authority=authority,
                target=target,
            )
            for action, authority, target in specs
        )
    )


def _create_source_run(
    runs: RunStore,
    *,
    run_id: str,
    flow: str,
    authority: str,
    input_data: Mapping[str, object],
) -> None:
    runs.create(
        run_id=run_id,
        flow=flow,
        phase="producer",
        authority=authority,
        executor="fixture",
        input_data=input_data,
    )
    runs.resume(run_id, executor="fixture")


def _proposal(run_id: str = "run_distill") -> tuple[ReviewArtifact, MutationPlan]:
    source = SourceRef(kind="machine-topic", ref="topic/source")
    provenance = Provenance(run_id=run_id, source_hashes=((source.ref, ZERO_HASH),))
    body = "# Synthetic proposal\n\nEvidence-bound useful synthesis.\n"
    artifact = ReviewArtifact(
        schema_version=1,
        review_id="rev_finalize-001",
        status="proposed",
        flow="distill",
        created_at="2026-01-15T11:00:00Z",
        surface="gated",
        sources=(source,),
        provenance=provenance,
        plan_path=".lifeos/review-plans/rev_finalize-001.json",
        body=body,
    )
    content = "# Applied fact\n\nEvidence-bound useful synthesis.\n"
    plan = MutationPlan(
        schema_version=1,
        review_id=artifact.review_id,
        review_body_sha256=review_body_sha256(body),
        provenance_sha256=provenance_sha256(provenance),
        operations=(
            MutationOperation(
                op="create",
                path="knowledge/domains/finalize.md",
                destination_path=None,
                source_refs=(source.ref,),
                precondition_sha256=None,
                postcondition_sha256=hashlib.sha256(content.encode()).hexdigest(),
                content=content,
            ),
        ),
    )
    return artifact, plan


def _running_distill(tmp_path: Path):
    vault, resolver, runs, outbox, policy, finalize = _stores(tmp_path)
    artifact, plan = _proposal()
    review_raw = render_review_artifact(artifact).encode("utf-8")
    plan_raw = render_mutation_plan(plan)
    review_path = vault / "review/rev_finalize-001.md"
    plan_path = vault / ".lifeos/review-plans/rev_finalize-001.json"
    review_path.write_bytes(review_raw)
    plan_path.write_bytes(plan_raw)
    runs.create(
        run_id="run_distill",
        flow="distill",
        phase="collect",
        authority="proposal",
        executor="fake",
        input_data={"topic_snapshot_sha256": ZERO_HASH},
    )
    runs.resume("run_distill", executor="fake")
    runs.commit_step(
        "run_distill",
        step_id="commit-proposal",
        authority="proposal",
        input_hash=ZERO_HASH,
        output_hash=hashlib.sha256(review_raw + plan_raw).hexdigest(),
        next_phase="validate",
        prepared_artifacts=(
            PreparedArtifact(
                "review",
                "review",
                review_path.name,
                "review/rev_finalize-001.md",
                hashlib.sha256(review_raw).hexdigest(),
            ),
            PreparedArtifact(
                "plan",
                ".lifeos/review-plans",
                plan_path.name,
                ".lifeos/review-plans/rev_finalize-001.json",
                hashlib.sha256(plan_raw).hexdigest(),
            ),
        ),
    )
    return vault, runs, outbox, policy, finalize, artifact, plan


def _roles() -> FinalizeArtifactRoles:
    return FinalizeArtifactRoles(review="review", plan="plan")


def test_proposed_review_finalizes_to_waiting_with_bounded_outputs_and_exact_trace(
    tmp_path: Path,
) -> None:
    vault, runs, outbox, policy, finalize, _artifact, _plan = _running_distill(tmp_path)
    caps = _capabilities(policy)

    first = finalize.finalize("run_distill", artifacts=_roles(), capabilities=caps)
    second = finalize.finalize("run_distill", artifacts=_roles(), capabilities=caps)

    assert first == second
    assert first.terminal_status == "waiting_human"
    assert first.outcome_kind == "review-ready"
    state = runs.status("run_distill")
    assert state["status"] == "waiting_human"
    assert state["waiting_for"] == "review-decision"
    outcome = parse_outcome_record((vault / first.domain_log_ref).read_bytes())
    metric = parse_metric_record((vault / first.metric_ref).read_bytes())
    assert outcome.artifact_valid is True
    assert outcome.accepted is False
    assert metric.review_queue_open is True
    assert metric.review_queue_age_seconds >= 0
    assert len(list((vault / "agent/logs/finalize").glob("*.json"))) == 1
    assert len(list((vault / "agent/logs/metrics").glob("*.json"))) == 1
    assert len(list((vault / "agent/outbox").glob("event_*.json"))) == 1
    trace = runs.trace_events("run_distill")[-1]
    assert trace["schema_version"] == 2
    assert (
        trace["output_hash"]
        == hashlib.sha256((vault / first.domain_log_ref).read_bytes()).hexdigest()
    )
    assert [item["action_id"] for item in trace["actions"]] == [
        "validate-run-artifacts",
        "read-review-outcome",
        "append-domain-log",
        "append-run-trace",
        "commit-bounded-metrics",
        "emit-semantic-outbox-event",
        "finalize-run-state",
    ]
    gateway_read = policy.issue(
        flow_id="gateway-delivery",
        action_id="read-semantic-outbox-event",
        actor="runtime",
        authority="read",
        target="vault:agent/outbox",
    )
    assert (
        outbox.read_for_delivery(gateway_read, first.outbox_event_id)["event_id"]
        == first.outbox_event_id
    )


def test_corrupted_committed_review_fails_without_success_event(tmp_path: Path) -> None:
    vault, runs, _outbox, policy, finalize, _artifact, _plan = _running_distill(
        tmp_path
    )
    private = "/" + "Users" + "/private/full source text"
    (vault / "review/rev_finalize-001.md").write_text(private, "utf-8")

    result = finalize.finalize(
        "run_distill", artifacts=_roles(), capabilities=_capabilities(policy)
    )
    replay = finalize.finalize(
        "run_distill", artifacts=_roles(), capabilities=_capabilities(policy)
    )

    assert replay == result
    assert result.terminal_status == "failed"
    assert result.outcome_kind == "validation-failed"
    assert result.outbox_event_id is None
    assert runs.status("run_distill")["status"] == "failed"
    assert not list((vault / "agent/outbox").glob("event_*.json"))
    metric_raw = (vault / result.metric_ref).read_text("utf-8")
    outcome_raw = (vault / result.domain_log_ref).read_text("utf-8")
    assert private not in metric_raw + outcome_raw
    assert parse_metric_record(metric_raw).artifact_valid is False
    trace = runs.trace_events("run_distill")[-1]
    assert trace["actions"][0]["status"] == "failed"
    assert trace["actions"][0]["action_id"] == "validate-run-artifacts"


def test_corrupt_artifact_crash_after_metrics_replays_one_failed_finalize(
    tmp_path: Path,
) -> None:
    vault, runs, _outbox, policy, finalize, _artifact, _plan = _running_distill(
        tmp_path
    )
    (vault / "review/rev_finalize-001.md").write_text("corrupt\n", "utf-8")

    def crash() -> None:
        raise _Crash("failed-after-metric")

    with pytest.raises(_Crash):
        finalize.finalize(
            "run_distill",
            artifacts=_roles(),
            capabilities=_capabilities(policy),
            crash_hooks=FinalizeCrashHooks(after_metric=crash),
        )

    result = finalize.finalize(
        "run_distill", artifacts=_roles(), capabilities=_capabilities(policy)
    )
    assert result.terminal_status == "failed"
    assert (
        finalize.finalize(
            "run_distill", artifacts=_roles(), capabilities=_capabilities(policy)
        )
        == result
    )
    assert len(list((vault / "agent/logs/finalize").glob("*.json"))) == 1
    assert len(list((vault / "agent/logs/metrics").glob("*.json"))) == 1
    assert not list((vault / "agent/outbox").glob("event_*.json"))


@pytest.mark.parametrize(
    "seam",
    [
        "after_domain_log",
        "after_metric",
        "after_outbox",
        "after_run_prepare",
        "after_run_state",
        "after_run_trace",
    ],
)
def test_every_finalize_crash_seam_replays_to_one_exact_result(
    tmp_path: Path, seam: str
) -> None:
    vault, runs, _outbox, policy, finalize, _artifact, _plan = _running_distill(
        tmp_path
    )
    caps = _capabilities(policy)

    def crash() -> None:
        raise _Crash(seam)

    with pytest.raises(_Crash):
        finalize.finalize(
            "run_distill",
            artifacts=_roles(),
            capabilities=caps,
            crash_hooks=FinalizeCrashHooks(**{seam: crash}),
        )

    result = finalize.finalize("run_distill", artifacts=_roles(), capabilities=caps)

    assert result.terminal_status == "waiting_human"
    assert len(list((vault / "agent/logs/finalize").glob("*.json"))) == 1
    assert len(list((vault / "agent/logs/metrics").glob("*.json"))) == 1
    assert len(list((vault / "agent/outbox").glob("event_*.json"))) == 1
    assert not list((vault / "agent/logs/finalize").glob("*.pending"))
    assert not list((vault / "agent/logs/metrics").glob("*.pending"))
    assert [item["step_id"] for item in runs.trace_events("run_distill")] == [
        "commit-proposal",
        "finalize-review-ready",
    ]


def test_finalize_stage_replacement_fails_before_cleanup_and_preserves_foreign_leaf(
    tmp_path: Path,
) -> None:
    vault, runs, _outbox, policy, finalize, _artifact, _plan = _running_distill(
        tmp_path
    )
    replaced: list[Path] = []

    def replace_stage() -> None:
        stage = next((vault / "agent/logs/finalize").glob("*.pending"))
        raw = stage.read_bytes()
        stage.unlink()
        stage.write_bytes(raw)
        replaced.append(stage)

    with pytest.raises(FinalizeError, match="stage was replaced"):
        finalize.finalize(
            "run_distill",
            artifacts=_roles(),
            capabilities=_capabilities(policy),
            crash_hooks=FinalizeCrashHooks(after_domain_log=replace_stage),
        )

    assert replaced and replaced[0].is_file()
    assert replaced[0].read_bytes() in {
        path.read_bytes()
        for path in (vault / "agent/logs/finalize").glob("outcome_*.json")
    }
    assert runs.status("run_distill")["status"] == "running"
    assert not list((vault / "agent/logs/metrics").glob("*.json"))
    assert not list((vault / "agent/outbox").glob("event_*.json"))


def test_metric_and_outcome_records_exclude_review_prose_and_source_refs(
    tmp_path: Path,
) -> None:
    vault, _runs, _outbox, policy, finalize, artifact, _plan = _running_distill(
        tmp_path
    )
    result = finalize.finalize(
        "run_distill", artifacts=_roles(), capabilities=_capabilities(policy)
    )
    combined = (vault / result.domain_log_ref).read_text("utf-8") + (
        vault / result.metric_ref
    ).read_text("utf-8")

    assert artifact.body not in combined
    assert artifact.sources[0].ref not in combined
    assert "Evidence-bound useful synthesis" not in combined
    assert mutation_plan_sha256(_proposal()[1]) in combined


def test_applied_review_requires_exact_journal_and_counts_accepted_applied(
    tmp_path: Path,
) -> None:
    vault, _resolver, runs, _outbox, policy, finalize = _stores(tmp_path)
    proposed, plan = _proposal("run_distill-origin")
    plan_hash = mutation_plan_sha256(plan)
    approval = ReviewDecision(
        schema_version=DECISION_SCHEMA_VERSION,
        sequence=1,
        action="approve",
        actor="human",
        at="2026-01-15T11:10:00Z",
        plan_sha256=plan_hash,
    )
    operation = plan.operations[0]
    journal = ApplyJournalEvidence(
        schema_version=APPLY_JOURNAL_SCHEMA_VERSION,
        journal_id="apply_finalize-001",
        review_id=proposed.review_id,
        plan_sha256=plan_hash,
        status="committed",
        committed_at="2026-01-15T11:20:00Z",
        operations=(
            ApplyJournalOperation(
                sequence=1,
                op=operation.op,
                path=operation.path,
                destination_path=operation.destination_path,
                precondition_sha256=operation.precondition_sha256,
                postcondition_sha256=operation.postcondition_sha256,
                status="committed",
            ),
        ),
    )
    applied = replace(
        proposed,
        status="applied",
        decisions=(approval,),
        application=ApplicationEvidence(
            schema_version=APPLICATION_SCHEMA_VERSION,
            applied_at=journal.committed_at,
            plan_sha256=plan_hash,
            journal_id=journal.journal_id,
            journal_sha256=apply_journal_sha256(journal),
        ),
    )
    review_raw = render_review_artifact(applied).encode("utf-8")
    plan_raw = render_mutation_plan(plan)
    journal_raw = render_apply_journal(journal)
    review_path = vault / "review/rev_finalize-001.md"
    plan_path = vault / ".lifeos/review-plans/rev_finalize-001.json"
    review_path.write_bytes(review_raw)
    plan_path.write_bytes(plan_raw)
    runs.create(
        run_id="run_apply",
        flow="apply",
        phase="commit",
        authority="protected-write",
        executor="fake",
        input_data={"review_id": applied.review_id, "plan_sha256": plan_hash},
    )
    runs.resume("run_apply", executor="fake")
    journal_prepared = runs.prepare_run_artifact(
        "run_apply", name="apply-journal", data=journal_raw
    )
    runs.commit_step(
        "run_apply",
        step_id="commit-applied-review",
        authority="protected-write",
        input_hash=plan_hash,
        output_hash=journal_prepared.sha256,
        next_phase="validate",
        prepared_artifacts=(
            PreparedArtifact(
                "review",
                "review",
                review_path.name,
                "review/rev_finalize-001.md",
                hashlib.sha256(review_raw).hexdigest(),
            ),
            PreparedArtifact(
                "plan",
                ".lifeos/review-plans",
                plan_path.name,
                ".lifeos/review-plans/rev_finalize-001.json",
                hashlib.sha256(plan_raw).hexdigest(),
            ),
            journal_prepared,
        ),
    )

    result = finalize.finalize(
        "run_apply",
        artifacts=FinalizeArtifactRoles(
            review="review", plan="plan", apply_journal="apply-journal"
        ),
        capabilities=_capabilities(policy),
    )

    assert result.terminal_status == "succeeded"
    assert result.outcome_kind == "knowledge-applied"
    outcome = parse_outcome_record((vault / result.domain_log_ref).read_bytes())
    metric = parse_metric_record((vault / result.metric_ref).read_bytes())
    assert outcome.accepted is True and outcome.applied is True
    assert metric.accepted is True and metric.applied is True
    assert outcome.journal_sha256 == hashlib.sha256(journal_raw).hexdigest()


def test_cited_ask_result_finalizes_without_leaking_answer_or_citation_path(
    tmp_path: Path,
) -> None:
    vault, resolver, runs, _outbox, policy, finalize = _stores(tmp_path)
    note = vault / "knowledge/source.md"
    note.write_text("A deterministic-finalize fact is grounded here.\n", "utf-8")
    runs.create(
        run_id="run_ask",
        flow="ask",
        phase="retrieve",
        authority="internal-write",
        executor="fake",
        input_data={},
    )
    runs.resume("run_ask", executor="fake")
    ask = AskFlow(resolver, policy=policy)
    read = policy.issue(
        flow_id="ask",
        action_id="retrieve-cited-evidence",
        actor="runtime",
        authority="read",
        target="vault:knowledge",
    )
    answer = ask.ask(
        "deterministic finalize",
        run_id="run_ask",
        read_capability=read,
    )
    prepared = publish_ask_result(runs, answer)
    runs.commit_step(
        "run_ask",
        step_id="commit-ask-result",
        authority="internal-write",
        input_hash=answer.query_sha256,
        output_hash=prepared.sha256,
        next_phase="validate",
        prepared_artifacts=(prepared,),
    )

    result = finalize.finalize(
        "run_ask",
        artifacts=FinalizeArtifactRoles(ask_result="ask-result"),
        capabilities=_capabilities(policy),
    )

    assert result.terminal_status == "succeeded"
    assert result.outcome_kind == "answer-ready"
    metric = parse_metric_record((vault / result.metric_ref).read_bytes())
    assert metric.citation_count == 1
    combined = (vault / result.domain_log_ref).read_text("utf-8") + (
        vault / result.metric_ref
    ).read_text("utf-8")
    assert answer.answer not in combined
    assert answer.citations[0].path not in combined
    assert "deterministic-finalize fact" not in combined


def test_ask_file_back_finalizes_answer_and_exact_proposal_as_waiting_human(
    tmp_path: Path,
) -> None:
    vault, resolver, runs, _outbox, policy, finalize = _stores(tmp_path)
    (vault / "knowledge/source.md").write_text(
        "A proposal-source fact uses a deterministic gate.\n", "utf-8"
    )
    runs.create(
        run_id="run_ask-proposal",
        flow="ask",
        phase="retrieve",
        authority="proposal",
        executor="fake",
        input_data={},
    )
    runs.resume("run_ask-proposal", executor="fake")
    ask_flow = AskFlow(resolver, policy=policy)
    read = policy.issue(
        flow_id="ask",
        action_id="retrieve-cited-evidence",
        actor="runtime",
        authority="read",
        target="vault:knowledge",
    )
    propose = policy.issue(
        flow_id="ask",
        action_id="optional-file-back-proposal",
        actor="runtime",
        authority="proposal",
        target="vault:review",
    )
    ask = ask_flow.ask(
        "deterministic gate",
        run_id="run_ask-proposal",
        read_capability=read,
        file_back=AskFileBack(
            review_id="rev_ask-finalize",
            created_at="2026-01-15T11:30:00Z",
            operation="create",
            path="knowledge/domains/ask-finalize.md",
            content="# Reviewed answer\n\nA deterministic gate protects this proposal.\n",
        ),
        proposal_capability=propose,
    )
    assert ask.proposal is not None
    review_raw = render_review_artifact(ask.proposal.artifact).encode("utf-8")
    plan_raw = render_mutation_plan(ask.proposal.plan)
    review_path = vault / "review/rev_ask-finalize.md"
    plan_path = vault / ".lifeos/review-plans/rev_ask-finalize.json"
    review_path.write_bytes(review_raw)
    plan_path.write_bytes(plan_raw)
    ask_prepared = publish_ask_result(runs, ask)
    runs.commit_step(
        "run_ask-proposal",
        step_id="commit-ask-proposal",
        authority="proposal",
        input_hash=ask.query_sha256,
        output_hash=ask_prepared.sha256,
        next_phase="validate",
        prepared_artifacts=(
            ask_prepared,
            PreparedArtifact(
                "review",
                "review",
                review_path.name,
                "review/rev_ask-finalize.md",
                hashlib.sha256(review_raw).hexdigest(),
            ),
            PreparedArtifact(
                "plan",
                ".lifeos/review-plans",
                plan_path.name,
                ".lifeos/review-plans/rev_ask-finalize.json",
                hashlib.sha256(plan_raw).hexdigest(),
            ),
        ),
    )

    result = finalize.finalize(
        "run_ask-proposal",
        artifacts=FinalizeArtifactRoles(
            review="review", plan="plan", ask_result="ask-result"
        ),
        capabilities=_capabilities(policy),
    )

    assert result.terminal_status == "waiting_human"
    assert result.outcome_kind == "review-ready"
    outcome = parse_outcome_record((vault / result.domain_log_ref).read_bytes())
    assert outcome.ask_result_sha256 == ask_prepared.sha256
    assert outcome.review_id == "rev_ask-finalize"
    assert outcome.citation_count == 1
    assert not (vault / "knowledge/domains/ask-finalize.md").exists()


def test_finalize_record_parsers_reject_semantically_inconsistent_exact_json(
    tmp_path: Path,
) -> None:
    vault, _runs, _outbox, policy, finalize, _artifact, _plan = _running_distill(
        tmp_path
    )
    result = finalize.finalize(
        "run_distill", artifacts=_roles(), capabilities=_capabilities(policy)
    )
    outcome_payload = json.loads((vault / result.domain_log_ref).read_bytes())
    outcome_payload["accepted"] = True
    forged_outcome = (
        json.dumps(
            outcome_payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )
    with pytest.raises(FinalizeError, match="acceptance flags"):
        parse_outcome_record(forged_outcome)

    metric_payload = json.loads((vault / result.metric_ref).read_bytes())
    metric_payload["decision_sequence"] = 1
    forged_metric = (
        json.dumps(
            metric_payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )
    with pytest.raises(FinalizeError, match="open queue"):
        parse_metric_record(forged_metric)

    for parser, payload in (
        (
            parse_outcome_record,
            json.loads((vault / result.domain_log_ref).read_bytes()),
        ),
        (parse_metric_record, json.loads((vault / result.metric_ref).read_bytes())),
    ):
        payload["terminal_status"] = []
        malformed = (
            json.dumps(
                payload,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            + b"\n"
        )
        with pytest.raises(FinalizeError):
            parser(malformed)


@pytest.mark.parametrize(
    ("parser", "ref_attribute", "id_field"),
    [
        (parse_outcome_record, "domain_log_ref", "outcome_id"),
        (parse_metric_record, "metric_ref", "metric_id"),
    ],
)
@pytest.mark.parametrize("field_kind", ["id", "flow_id", "observed_at"])
def test_finalize_record_escaped_lone_surrogates_are_domain_errors(
    tmp_path: Path,
    parser,
    ref_attribute: str,
    id_field: str,
    field_kind: str,
) -> None:
    vault, _runs, _outbox, policy, finalize, _artifact, _plan = _running_distill(
        tmp_path
    )
    result = finalize.finalize(
        "run_distill", artifacts=_roles(), capabilities=_capabilities(policy)
    )
    payload = json.loads((vault / getattr(result, ref_attribute)).read_bytes())
    field = id_field if field_kind == "id" else field_kind
    payload[field] = "\ud800"
    malformed = (
        json.dumps(
            payload,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        + b"\n"
    )

    with pytest.raises(FinalizeError):
        parser(malformed)


def test_stale_state_after_outbox_cannot_finalize_or_deliver_until_retry(
    tmp_path: Path,
) -> None:
    vault, runs, outbox, policy, finalize, _artifact, _plan = _running_distill(tmp_path)
    caps = _capabilities(policy)

    def concurrent_step() -> None:
        runs.commit_step(
            "run_distill",
            step_id="concurrent-step",
            authority="internal-write",
            input_hash=ZERO_HASH,
            output_hash=ZERO_HASH,
            next_phase="changed",
        )

    with pytest.raises(FinalizeError, match="commit failed safely"):
        finalize.finalize(
            "run_distill",
            artifacts=_roles(),
            capabilities=caps,
            crash_hooks=FinalizeCrashHooks(after_outbox=concurrent_step),
        )

    assert runs.status("run_distill")["phase"] == "changed"
    event_path = next((vault / "agent/outbox").glob("event_*.json"))
    event_id = event_path.stem
    gateway_read = policy.issue(
        flow_id="gateway-delivery",
        action_id="read-semantic-outbox-event",
        actor="runtime",
        authority="read",
        target="vault:agent/outbox",
    )
    with pytest.raises(OutboxError, match="not yet bound"):
        outbox.read_for_delivery(gateway_read, event_id)

    result = finalize.finalize("run_distill", artifacts=_roles(), capabilities=caps)

    assert result.outbox_event_id == event_id
    assert outbox.read_for_delivery(gateway_read, event_id)["event_id"] == event_id
    assert len(list((vault / "agent/outbox").glob("event_*.json"))) == 1


def test_capabilities_from_another_policy_fail_before_any_finalize_mutation(
    tmp_path: Path,
) -> None:
    vault, runs, _outbox, _policy, finalize, _artifact, _plan = _running_distill(
        tmp_path
    )
    before = {
        path.relative_to(vault).as_posix(): path.read_bytes()
        for path in vault.rglob("*")
        if path.is_file()
    }

    with pytest.raises(FinalizeError, match="not issued"):
        finalize.finalize(
            "run_distill",
            artifacts=_roles(),
            capabilities=_capabilities(AuthorityPolicy()),
        )

    after = {
        path.relative_to(vault).as_posix(): path.read_bytes()
        for path in vault.rglob("*")
        if path.is_file()
    }
    assert after == before
    assert runs.status("run_distill")["status"] == "running"


def test_terminal_finalize_replay_does_not_leak_file_descriptors(
    tmp_path: Path,
) -> None:
    if not Path("/dev/fd").exists():
        pytest.skip("descriptor projection is unavailable")
    _vault, _runs, _outbox, policy, finalize, _artifact, _plan = _running_distill(
        tmp_path
    )
    caps = _capabilities(policy)
    finalize.finalize("run_distill", artifacts=_roles(), capabilities=caps)
    baseline = len(list(Path("/dev/fd").iterdir()))

    for _ in range(25):
        finalize.finalize("run_distill", artifacts=_roles(), capabilities=caps)

    assert len(list(Path("/dev/fd").iterdir())) <= baseline


def _book_capabilities(policy: AuthorityPolicy) -> BookCapabilities:
    contracts = {
        "read-source-manifest": ("read", "tool:source-manifest"),
        "read-reading-state": ("read", "vault:agent/reading"),
        "read-reading-knowledge": ("read", "vault:knowledge"),
        "commit-reading-state": ("domain-write", "vault:agent/reading"),
        "commit-reading-knowledge-proposal": ("proposal", "vault:review"),
        "record-run-state": ("internal-write", "vault:agent/runs"),
    }

    def issue(action_id: str):
        authority, target = contracts[action_id]
        return policy.issue(
            flow_id="book",
            action_id=action_id,
            actor="runtime",
            authority=authority,
            target=target,
        )

    return BookCapabilities(
        read_source_manifest=issue("read-source-manifest"),
        read_reading_state=issue("read-reading-state"),
        read_reading_knowledge=issue("read-reading-knowledge"),
        commit_reading_state=issue("commit-reading-state"),
        commit_knowledge_proposal=issue("commit-reading-knowledge-proposal"),
        record_run_state=issue("record-run-state"),
    )


def _running_book_anchor(tmp_path: Path):
    vault, resolver, runs, _outbox, policy, finalize = _stores(tmp_path)
    runs.create(
        run_id="run_book_finalize",
        flow="book",
        phase="reading",
        authority="domain-write",
        executor="fixture",
        input_data={"slug": "finalize-book"},
    )
    runs.resume("run_book_finalize", executor="fixture")
    book = BookFlow(resolver, runs, policy)
    book_caps = _book_capabilities(policy)
    manifest = BookSourceManifest(
        BOOK_SCHEMA_VERSION,
        "source_finalize_book",
        "coursedump/manifests/finalize-book.json",
        "1" * 64,
        "2" * 64,
        "Finalize Book",
        8,
    )
    book.execute(
        BookCommand(
            BOOK_SCHEMA_VERSION,
            "run_book_finalize",
            "mut_active",
            "active",
            "finalize-book",
            "2026-08-20T10:00:00Z",
        ),
        manifest,
        capabilities=book_caps,
    )
    anchor = book.execute(
        BookCommand(
            BOOK_SCHEMA_VERSION,
            "run_book_finalize",
            "mut_anchor",
            "anchor",
            "finalize-book",
            "2026-08-20T11:00:00Z",
            chapter=2,
            text="A bounded anchor for central finalize.",
            anchor_id="anchor_finalize_one",
            review_id="rev_book_finalize_one",
            target_path="knowledge/book-finalize.md",
            surface="gated",
        ),
        manifest,
        capabilities=book_caps,
    )
    assert anchor.review_artifact_name is not None
    roles = FinalizeArtifactRoles(
        producer_evidence="book-" + hashlib.sha256(b"mut_anchor").hexdigest()[:40]
    )
    return vault, runs, policy, finalize, anchor, roles


def test_book_proposal_finalize_decision_resume_rebinds_only_canonical_review(
    tmp_path: Path,
) -> None:
    vault, runs, policy, finalize, anchor, roles = _running_book_anchor(tmp_path)
    first = finalize.finalize(
        "run_book_finalize", artifacts=roles, capabilities=_capabilities(policy)
    )
    assert first.schema_version == 2
    assert first.terminal_status == "waiting_human"
    first_outcome = parse_outcome_record((vault / first.domain_log_ref).read_bytes())
    assert first_outcome.outcome_kind == "proposal-ready"
    assert first_outcome.pending_id == "rev_book_finalize_one"
    assert first_outcome.source_step_id == roles.producer_evidence

    proposed = anchor.review_artifact
    plan = anchor.mutation_plan
    assert proposed is not None and plan is not None
    plan_hash = mutation_plan_sha256(plan)
    approved = replace(
        proposed,
        status="approved",
        decisions=(
            ReviewDecision(
                schema_version=DECISION_SCHEMA_VERSION,
                sequence=1,
                action="approve",
                actor="human",
                at="2026-08-20T12:00:00Z",
                plan_sha256=plan_hash,
            ),
        ),
    )
    review_path = vault / "review/rev_book_finalize_one.md"
    review_path.write_text(render_review_artifact(approved), "utf-8")
    runs.resume("run_book_finalize", executor="fixture")

    second = finalize.finalize(
        "run_book_finalize", artifacts=roles, capabilities=_capabilities(policy)
    )
    assert second.terminal_status == "succeeded"
    assert second.outcome_kind == "review-approved"
    decided = parse_outcome_record((vault / second.domain_log_ref).read_bytes())
    assert decided.decision_status == "approved"
    assert decided.decision_sequence == 1
    assert (
        decided.decision_sha256 == hashlib.sha256(review_path.read_bytes()).hexdigest()
    )
    assert decided.source_bundle_sha256 != first_outcome.source_bundle_sha256
    assert (
        finalize.finalize(
            "run_book_finalize", artifacts=roles, capabilities=_capabilities(policy)
        )
        == second
    )


@pytest.mark.parametrize(
    "seam",
    [
        "after_domain_log",
        "after_metric",
        "after_outbox",
        "after_run_prepare",
        "after_run_state",
        "after_run_trace",
    ],
)
def test_p3_proposal_finalize_replays_after_every_documented_seam(
    tmp_path: Path, seam: str
) -> None:
    vault, runs, policy, finalize, _anchor, roles = _running_book_anchor(tmp_path)

    def crash() -> None:
        raise _Crash(seam)

    with pytest.raises(_Crash):
        finalize.finalize(
            "run_book_finalize",
            artifacts=roles,
            capabilities=_capabilities(policy),
            crash_hooks=FinalizeCrashHooks(**{seam: crash}),
        )
    result = finalize.finalize(
        "run_book_finalize", artifacts=roles, capabilities=_capabilities(policy)
    )

    assert result.schema_version == 2
    assert result.terminal_status == "waiting_human"
    assert result.outcome_kind == "proposal-ready"
    assert len(list((vault / "agent/logs/finalize").glob("*.json"))) == 1
    assert len(list((vault / "agent/logs/metrics").glob("*.json"))) == 1
    assert len(list((vault / "agent/outbox").glob("event_*.json"))) == 1
    assert not list((vault / "agent/logs/finalize").glob("*.pending"))
    assert not list((vault / "agent/logs/metrics").glob("*.pending"))
    trace = runs.trace_events("run_book_finalize")
    assert trace[-1]["step_id"] == "finalize-review-ready"
    assert (
        tuple(action["action_id"] for action in trace[-1]["actions"])
        == FINALIZE_ACTION_ORDER
    )


@pytest.mark.parametrize("mutation", ["body", "second-decision"])
def test_book_resume_rejects_non_decision_mutation_and_stale_second_decision(
    tmp_path: Path, mutation: str
) -> None:
    vault, resolver, runs, _outbox, policy, finalize = _stores(tmp_path)
    runs.create(
        run_id="run_book_tampered",
        flow="book",
        phase="reading",
        authority="domain-write",
        executor="fixture",
        input_data={"slug": "tampered-book"},
    )
    runs.resume("run_book_tampered", executor="fixture")
    book = BookFlow(resolver, runs, policy)
    caps = _book_capabilities(policy)
    manifest = BookSourceManifest(
        1,
        "source_tampered_book",
        "coursedump/manifests/tampered-book.json",
        "1" * 64,
        "2" * 64,
        "Tampered Book",
        4,
    )
    book.execute(
        BookCommand(
            1,
            "run_book_tampered",
            "mut_active",
            "active",
            "tampered-book",
            "2026-08-20T10:00:00Z",
        ),
        manifest,
        capabilities=caps,
    )
    anchor = book.execute(
        BookCommand(
            1,
            "run_book_tampered",
            "mut_anchor",
            "anchor",
            "tampered-book",
            "2026-08-20T11:00:00Z",
            chapter=1,
            text="Original bounded anchor.",
            anchor_id="anchor_tampered_one",
            review_id="rev_book_tampered_one",
            target_path="knowledge/tampered-book.md",
            surface="gated",
        ),
        manifest,
        capabilities=caps,
    )
    roles = FinalizeArtifactRoles(
        producer_evidence="book-" + hashlib.sha256(b"mut_anchor").hexdigest()[:40]
    )
    finalize.finalize(
        "run_book_tampered", artifacts=roles, capabilities=_capabilities(policy)
    )
    assert anchor.review_artifact is not None and anchor.mutation_plan is not None
    path = vault / "review/rev_book_tampered_one.md"
    if mutation == "body":
        changed = replace(anchor.review_artifact, body="# Mutated semantic body\n")
    else:
        plan_hash = mutation_plan_sha256(anchor.mutation_plan)
        changed = replace(
            anchor.review_artifact,
            status="rejected",
            decisions=(
                ReviewDecision(
                    schema_version=DECISION_SCHEMA_VERSION,
                    sequence=1,
                    action="approve",
                    actor="human",
                    at="2026-08-20T12:00:00Z",
                    plan_sha256=plan_hash,
                ),
                ReviewDecision(
                    schema_version=DECISION_SCHEMA_VERSION,
                    sequence=2,
                    action="reject",
                    actor="human",
                    at="2026-08-20T13:00:00Z",
                    plan_sha256=plan_hash,
                ),
            ),
        )
    path.write_text(render_review_artifact(changed), "utf-8")
    runs.resume("run_book_tampered", executor="fixture")
    failed = finalize.finalize(
        "run_book_tampered", artifacts=roles, capabilities=_capabilities(policy)
    )
    assert failed.terminal_status == "failed"
    assert failed.outbox_event_id is None


def _commit_project_evidence(
    vault: Path,
    runs: RunStore,
    *,
    run_id: str,
    transition_id: str,
) -> PreparedArtifact:
    payload = {
        "schema_version": 1,
        "transition_id": transition_id,
        "operation": "create",
        "request_sha256": ZERO_HASH,
        "location": "active/synthetic-project",
        "snapshot_sha256": "3" * 64,
        "archived_children": [],
        "child_policy": None,
        "schedule_observation": [],
        "schedule_receipt": None,
    }
    raw = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode()
    evidence_dir = vault / "projects/.lifeos-project-evidence"
    evidence_dir.mkdir(exist_ok=True)
    path = evidence_dir / f"{transition_id}.json"
    path.write_bytes(raw)
    prepared = PreparedArtifact(
        "project_transition",
        "projects",
        f".lifeos-project-evidence/{transition_id}.json",
        f"projects/.lifeos-project-evidence/{transition_id}.json",
        hashlib.sha256(raw).hexdigest(),
    )
    runs.commit_step(
        run_id,
        step_id=transition_id,
        authority="domain-write",
        input_hash=ZERO_HASH,
        output_hash=prepared.sha256,
        next_phase="project-committed",
        prepared_artifacts=(prepared,),
    )
    return prepared


def test_project_latest_producer_bundle_finalizes_to_schema_v2_domain_success(
    tmp_path: Path,
) -> None:
    vault, _resolver, runs, _outbox, policy, finalize = _stores(tmp_path)
    runs.create(
        run_id="run_project_finalize",
        flow="project",
        phase="project",
        authority="domain-write",
        executor="fixture",
        input_data={"slug": "synthetic-project"},
    )
    runs.resume("run_project_finalize", executor="fixture")
    _commit_project_evidence(
        vault,
        runs,
        run_id="run_project_finalize",
        transition_id="create-project",
    )

    result = finalize.finalize(
        "run_project_finalize",
        artifacts=FinalizeArtifactRoles(producer_evidence="project_transition"),
        capabilities=_capabilities(policy),
    )

    assert result.schema_version == 2
    assert result.terminal_status == "succeeded"
    assert result.outcome_kind == "domain-updated"
    outcome = parse_outcome_record((vault / result.domain_log_ref).read_bytes())
    metric = parse_metric_record((vault / result.metric_ref).read_bytes())
    assert outcome.source_step_id == "create-project"
    assert outcome.producer_operation == "create"
    assert outcome.source_bundle_sha256 == metric.source_bundle_sha256
    assert outcome.pending_kind is None and outcome.decision_status is None


def test_p3_stale_producer_selector_fails_without_success_event(tmp_path: Path) -> None:
    vault, _resolver, runs, _outbox, policy, finalize = _stores(tmp_path)
    runs.create(
        run_id="run_project_stale",
        flow="project",
        phase="project",
        authority="domain-write",
        executor="fixture",
        input_data={"slug": "synthetic-project"},
    )
    runs.resume("run_project_stale", executor="fixture")
    first = _commit_project_evidence(
        vault,
        runs,
        run_id="run_project_stale",
        transition_id="create-project",
    )
    extra = runs.prepare_run_artifact(
        "run_project_stale", name="later-evidence", data=b'{"later":true}\n'
    )
    runs.commit_step(
        "run_project_stale",
        step_id="later-step",
        authority="domain-write",
        input_hash=first.sha256,
        output_hash=extra.sha256,
        next_phase="project-committed",
        prepared_artifacts=(extra,),
    )

    result = finalize.finalize(
        "run_project_stale",
        artifacts=FinalizeArtifactRoles(producer_evidence="project_transition"),
        capabilities=_capabilities(policy),
    )

    assert result.terminal_status == "failed"
    assert result.outbox_event_id is None
    assert not list((vault / "agent/outbox").glob("event_*.json"))


def test_entities_and_plan_explicit_adapters_accept_exact_producer_evidence(
    tmp_path: Path,
) -> None:
    for flow_id, run_id in (
        ("entities", "run_entities_finalize"),
        ("plan", "run_plan_finalize"),
    ):
        lane = tmp_path / flow_id
        vault, _resolver, runs, _outbox, policy, finalize = _stores(lane)
        runs.create(
            run_id=run_id,
            flow=flow_id,
            phase=flow_id,
            authority="domain-write",
            executor="fixture",
            input_data={"fixture": flow_id},
        )
        runs.resume(run_id, executor="fixture")
        if flow_id == "entities":
            operation_id = "create-entity"
            family = "entity"
            request = {"schema_version": 1, "operation": "create"}
            request_raw = (
                json.dumps(request, sort_keys=True, separators=(",", ":")) + "\n"
            ).encode()
            request_hash = hashlib.sha256(request_raw).hexdigest()
            output_hash = "4" * 64
            payload = {
                "schema_version": 1,
                "flow": "entities",
                "family": family,
                "operation_id": operation_id,
                "request_sha256": request_hash,
                "expected_output_sha256": output_hash,
                "request": request,
            }
            name = (
                "entities-"
                + hashlib.sha256(f"{family}:{operation_id}".encode()).hexdigest()[:24]
            )
            step_id = "entity-" + hashlib.sha256(operation_id.encode()).hexdigest()[:32]
        else:
            operation_id = "commit-day-one"
            request = {"schema_version": 1, "operation": "commit-day"}
            target_raw = b'{"day":"2026-08-20"}\n'
            target = {
                "relative": "plans/day-2026-08-20.json",
                "maximum": 4096,
                "sha256": hashlib.sha256(target_raw).hexdigest(),
                "bytes_base64": base64.b64encode(target_raw).decode("ascii"),
            }
            output_binding = {
                "targets": [
                    {"relative": target["relative"], "sha256": target["sha256"]}
                ],
                "skipped_events": [],
                "feedback_proposal": None,
            }
            output_hash = hashlib.sha256(
                (
                    json.dumps(output_binding, sort_keys=True, separators=(",", ":"))
                    + "\n"
                ).encode()
            ).hexdigest()
            payload = {
                "schema_version": 1,
                "flow": "plan",
                "operation": "commit-day",
                "operation_id": operation_id,
                "request": request,
                "packet": {},
                "targets": [target],
                "preimages": [],
                "skipped_events": [],
                "feedback_proposal": None,
                "result_kind": "day",
                "result_period": "2026-08-20",
                "output_sha256": output_hash,
            }
            token = hashlib.sha256(operation_id.encode()).hexdigest()[:32]
            name = f"plan-evidence-{token}"
            step_id = f"plan-{token}"
            request_hash = hashlib.sha256(
                (
                    json.dumps(request, sort_keys=True, separators=(",", ":")) + "\n"
                ).encode()
            ).hexdigest()
        raw = (
            json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode()
        prepared = runs.prepare_run_artifact(run_id, name=name, data=raw)
        runs.commit_step(
            run_id,
            step_id=step_id,
            authority="domain-write",
            input_hash=request_hash,
            output_hash=output_hash,
            next_phase=f"{flow_id}-committed",
            prepared_artifacts=(prepared,),
        )

        result = finalize.finalize(
            run_id,
            artifacts=FinalizeArtifactRoles(producer_evidence=name),
            capabilities=_capabilities(policy),
        )
        outcome = parse_outcome_record((vault / result.domain_log_ref).read_bytes())
        assert result.terminal_status == "succeeded"
        assert outcome.source_step_id == step_id
        assert outcome.outcome_kind == "domain-updated"


def test_report_and_memory_provisional_inspectors_finalize_exact_v2_outputs(
    tmp_path: Path,
) -> None:
    cases: list[tuple[str, str]] = [
        ("report", "run_report_finalize"),
        ("memory", "run_memory_finalize"),
    ]
    for flow_id, run_id in cases:
        lane = tmp_path / flow_id
        vault, _resolver, runs, _outbox, policy, finalize = _stores(lane)
        runs.create(
            run_id=run_id,
            flow=flow_id,
            phase=flow_id,
            authority="domain-write" if flow_id == "memory" else "proposal",
            executor="fixture",
            input_data={"fixture": flow_id},
        )
        runs.resume(run_id, executor="fixture")
        if flow_id == "report":
            operation_id = "daily-one"
            line = b'{"report":"synthetic"}\n'
            output = vault / "agent/logs/reports/daily/2026-08-20.jsonl"
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(line)
            record = ReportRunEvidence(
                operation_id=operation_id,
                operation="daily",
                output_ref="agent/logs/reports/daily/2026-08-20.jsonl",
                request_sha256="5" * 64,
                run_state_sha256="6" * 64,
                log_preimage_sha256="7" * 64,
                log_line_sha256=hashlib.sha256(line).hexdigest(),
                proposal_ref=None,
                proposal_sha256=None,
                outcome_class="report-log",
            )
            name = report_evidence_artifact_name(operation_id)
            raw = render_report_run_evidence(record)
            step_id = (
                "report-"
                + hashlib.sha256(f"daily:{operation_id}".encode()).hexdigest()[:32]
            )
            request_hash = record.request_sha256
            expected_kind = "report-ready"
        else:
            operation_id = "forget-one"
            outcome = ForgetOutcome(
                "forget-synthetic",
                "mem-synthetic",
                "memprop-synthetic",
                "proposal-never-shared",
                None,
                None,
                "2026-08-20T12:00:00Z",
                None,
            )
            output_raw = render_forget_outcome(outcome)
            output = vault / "agent/memory/metadata/outcomes/forget-synthetic.json"
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(output_raw)
            record = MemoryRunEvidence(
                operation_id=operation_id,
                operation="forget",
                output_ref="agent/memory/metadata/outcomes/forget-synthetic.json",
                request_sha256="5" * 64,
                run_state_sha256="6" * 64,
                preimage_sha256=None,
                target_sha256=hashlib.sha256(output_raw).hexdigest(),
                outcome_class="deterministic-metadata",
            )
            name = memory_evidence_artifact_name(operation_id)
            raw = render_memory_run_evidence(record)
            step_id = (
                "memory-"
                + hashlib.sha256(f"forget:{operation_id}".encode()).hexdigest()[:32]
            )
            request_hash = record.request_sha256
            expected_kind = "domain-updated"
        prepared = runs.prepare_run_artifact(run_id, name=name, data=raw)
        runs.commit_step(
            run_id,
            step_id=step_id,
            authority="domain-write" if flow_id == "memory" else "proposal",
            input_hash=request_hash,
            output_hash=prepared.sha256,
            next_phase=f"{flow_id}-committed",
            prepared_artifacts=(prepared,),
        )
        result = finalize.finalize(
            run_id,
            artifacts=FinalizeArtifactRoles(producer_evidence=name),
            capabilities=_capabilities(policy),
        )
        parsed = parse_outcome_record((vault / result.domain_log_ref).read_bytes())
        assert result.terminal_status == "succeeded"
        assert parsed.outcome_kind == expected_kind
        assert parsed.source_step_id == step_id


@pytest.mark.parametrize(
    "seam",
    [
        "after_domain_log",
        "after_metric",
        "after_outbox",
        "after_run_prepare",
        "after_run_state",
        "after_run_trace",
    ],
)
def test_p3_direct_finalize_replays_after_every_documented_seam(
    tmp_path: Path, seam: str
) -> None:
    vault, _resolver, runs, _outbox, policy, finalize = _stores(tmp_path)
    runs.create(
        run_id="run_project_crash",
        flow="project",
        phase="project",
        authority="domain-write",
        executor="fixture",
        input_data={"slug": "synthetic-project"},
    )
    runs.resume("run_project_crash", executor="fixture")
    _commit_project_evidence(
        vault,
        runs,
        run_id="run_project_crash",
        transition_id="create-project",
    )

    def crash() -> None:
        raise _Crash(seam)

    with pytest.raises(_Crash):
        finalize.finalize(
            "run_project_crash",
            artifacts=FinalizeArtifactRoles(producer_evidence="project_transition"),
            capabilities=_capabilities(policy),
            crash_hooks=FinalizeCrashHooks(**{seam: crash}),
        )
    result = finalize.finalize(
        "run_project_crash",
        artifacts=FinalizeArtifactRoles(producer_evidence="project_transition"),
        capabilities=_capabilities(policy),
    )
    assert result.terminal_status == "succeeded"
    assert len(list((vault / "agent/logs/finalize").glob("*.json"))) == 1
    assert len(list((vault / "agent/logs/metrics").glob("*.json"))) == 1
    assert len(list((vault / "agent/outbox").glob("event_*.json"))) == 1
    assert not list((vault / "agent/logs/finalize").glob("*.pending"))
    assert not list((vault / "agent/logs/metrics").glob("*.pending"))
    trace = runs.trace_events("run_project_crash")
    assert [item["step_id"] for item in trace] == [
        "create-project",
        "finalize-complete",
    ]
    assert (
        tuple(action["action_id"] for action in trace[-1]["actions"])
        == FINALIZE_ACTION_ORDER
    )


def test_p3_invalid_private_evidence_fails_without_leaking_or_event(
    tmp_path: Path,
) -> None:
    vault, _resolver, runs, _outbox, policy, finalize = _stores(tmp_path)
    runs.create(
        run_id="run_project_private",
        flow="project",
        phase="project",
        authority="domain-write",
        executor="fixture",
        input_data={"slug": "synthetic-project"},
    )
    runs.resume("run_project_private", executor="fixture")
    private = "/" + "Users" + "/private/project"
    payload = {
        "schema_version": 1,
        "transition_id": "create-project",
        "operation": "create",
        "request_sha256": ZERO_HASH,
        "location": private,
        "snapshot_sha256": "3" * 64,
        "archived_children": [],
        "child_policy": None,
        "schedule_observation": [],
        "schedule_receipt": None,
    }
    raw = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode()
    evidence_dir = vault / "projects/.lifeos-project-evidence"
    evidence_dir.mkdir(exist_ok=True)
    path = evidence_dir / "create-project.json"
    path.write_bytes(raw)
    prepared = PreparedArtifact(
        "project_transition",
        "projects",
        ".lifeos-project-evidence/create-project.json",
        "projects/.lifeos-project-evidence/create-project.json",
        hashlib.sha256(raw).hexdigest(),
    )
    runs.commit_step(
        "run_project_private",
        step_id="create-project",
        authority="domain-write",
        input_hash=ZERO_HASH,
        output_hash=prepared.sha256,
        next_phase="project-committed",
        prepared_artifacts=(prepared,),
    )

    result = finalize.finalize(
        "run_project_private",
        artifacts=FinalizeArtifactRoles(producer_evidence="project_transition"),
        capabilities=_capabilities(policy),
    )
    combined = (vault / result.domain_log_ref).read_text() + (
        vault / result.metric_ref
    ).read_text()
    assert result.terminal_status == "failed"
    assert result.outbox_event_id is None
    assert private not in combined


def _prepare_mentor_finalize(tmp_path: Path):
    vault, resolver, runs, _outbox, policy, finalize = _stores(tmp_path)
    (vault / "projects/alpha").mkdir(parents=True)
    (vault / "projects/alpha/state.json").write_text(
        '{"schema_version":1,"status":"active"}\n', "utf-8"
    )
    (vault / "knowledge/domain").mkdir(parents=True)
    (vault / "knowledge/domain/guide.md").write_text(
        "Keep the next step bounded.\n", "utf-8"
    )
    (vault / "agent/memory/decisions.jsonl").write_text(
        '{"decision":"pilot"}\n', "utf-8"
    )
    _create_source_run(
        runs,
        run_id="run_mentor_finalize",
        flow="mentor",
        authority="proposal",
        input_data={"scope": "alpha"},
    )
    mentor = MentorFlow(resolver, runs, policy)
    caps = _mentor_capabilities(policy)
    request = MentorRequest(
        "run_mentor_finalize",
        "mentor_finalize",
        "mentor-finalize",
        "2026-01-15T11:00:00Z",
        "Choose a bounded next step.",
        "What should a human review?",
        ("alpha/state.json",),
        ("domain/guide.md",),
        ("decisions.jsonl",),
    )
    packet = mentor.prepare_task_packet(request, capabilities=caps)
    block_ids = packet.manifest.block_ids
    result = mentor.commit_proposal(
        packet,
        MentorExecutorOutput(
            "Review one bounded checkpoint.",
            (
                MentorObservation(
                    "obs-finalize", "The project is active.", block_ids[:1]
                ),
            ),
            (
                MentorRecommendation(
                    "rec-finalize",
                    "Review the pilot checkpoint.",
                    "The action remains bounded.",
                    block_ids,
                ),
            ),
        ),
        capabilities=caps,
    )
    return vault, runs, policy, finalize, result.evidence_artifact


def _prepare_grill_finalize(tmp_path: Path):
    vault, resolver, runs, _outbox, policy, finalize = _stores(tmp_path)
    (vault / "projects/alpha").mkdir(parents=True)
    (vault / "projects/alpha/state.json").write_text(
        '{"schema_version":1,"status":"active"}\n', "utf-8"
    )
    (vault / "agent/memory/decisions.jsonl").write_text(
        '{"decision":"pilot"}\n', "utf-8"
    )
    _create_source_run(
        runs,
        run_id="run_grill_finalize",
        flow="grill-me",
        authority="proposal",
        input_data={"scope": "alpha"},
    )
    caps = _grill_capabilities(policy)
    grill = GrillMeFlow(resolver, runs, policy)
    block_ids = (
        "ctx-" + hashlib.sha256(b"agent/memory\0decisions.jsonl").hexdigest()[:24],
        "ctx-" + hashlib.sha256(b"projects\0alpha/state.json").hexdigest()[:24],
    )
    request = GrillRequest(
        "run_grill_finalize",
        "grill_finalize",
        "grill-finalize",
        "2026-01-15T11:00:00Z",
        "Clarify the pilot decision.",
        ("alpha/state.json",),
        ("decisions.jsonl",),
    )
    question = GrillQuestionOutput(
        "question-finalize",
        "2026-01-15T11:01:00Z",
        "What exact condition must hold?",
        block_ids,
    )
    grill.begin(request, question, capabilities=caps)
    runs.resume(request.run_id, executor="fixture")
    grill.answer(
        request.run_id,
        GrillHumanAnswer(
            question.question_id,
            "human",
            "2026-01-15T11:10:00Z",
            "The checkpoint remains reversible.",
        ),
        capabilities=caps,
    )
    runs.resume(request.run_id, executor="fixture")
    result = grill.finish(
        request.run_id,
        GrillExplicitDecision(
            "decision-finalize",
            "human",
            "2026-01-15T11:20:00Z",
            "Proceed with one reversible checkpoint.",
        ),
        capabilities=caps,
    )
    assert result.evidence_artifact is not None
    return vault, runs, policy, finalize, result.evidence_artifact


@pytest.mark.parametrize("producer", ["mentor", "grill-me"])
def test_interactive_producer_bundles_finalize_to_exact_waiting_result(
    tmp_path: Path, producer: str
) -> None:
    prepared = (
        _prepare_mentor_finalize(tmp_path)
        if producer == "mentor"
        else _prepare_grill_finalize(tmp_path)
    )
    vault, runs, policy, finalize, evidence_name = prepared
    run_id = f"run_{'grill' if producer == 'grill-me' else producer}_finalize"
    roles = FinalizeArtifactRoles(producer_evidence=evidence_name)

    first = finalize.finalize(
        run_id, artifacts=roles, capabilities=_capabilities(policy)
    )
    replay = finalize.finalize(
        run_id, artifacts=roles, capabilities=_capabilities(policy)
    )

    assert replay == first
    assert first.terminal_status == "waiting_human"
    outcome = parse_outcome_record((vault / first.domain_log_ref).read_bytes())
    assert outcome.source_step_id.startswith(
        "mentor-" if producer == "mentor" else "grill-finish-"
    )
    assert outcome.pending_kind == (
        "mentor-proposal" if producer == "mentor" else "grill-decision"
    )
    assert outcome.decision_status == "proposed"
    assert (
        tuple(
            action["action_id"] for action in runs.trace_events(run_id)[-1]["actions"]
        )
        == FINALIZE_ACTION_ORDER
    )


def _prepare_lint_finalize(
    tmp_path: Path, *, proposal: bool, review_zone: str = "review"
):
    vault, resolver, runs, _outbox, policy, finalize = _stores(
        tmp_path, review_zone=review_zone
    )
    request = LintRequest(
        1,
        "run_lint_finalize",
        "infra",
        zones=LINT_ZONE_ORDER,
        apply_fixes=False,
    )
    _create_source_run(
        runs,
        run_id=request.run_id,
        flow="lint",
        authority="domain-write",
        input_data={
            "apply_fixes": request.apply_fixes,
            "mode": request.mode,
            "zones": list(request.zones),
        },
    )
    if proposal:
        (vault / "knowledge/finalize.md").write_bytes(b"\xef\xbb\xbf# Review\r\n")
    result = LintFlow(resolver, runs, policy).execute(
        request, capabilities=_lint_capabilities(policy)
    )
    assert (result.proposal is not None) == proposal
    return vault, runs, policy, finalize, result


def _replace_lint_decision(
    proposal_path: Path,
    proposal,
    *,
    action: str | None,
    sequence: int = 1,
) -> None:
    status = {
        None: "proposed",
        "approve": "approved",
        "reject": "rejected",
        "supersede": "superseded",
    }[action]
    decision = (
        None
        if action is None
        else LintReviewDecision(
            action,
            "human",
            f"2026-01-15T12:{30 + sequence:02d}:00Z",
            sequence,
            f"lintprop-replacement-{sequence}" if action == "supersede" else None,
        )
    )
    replacement = proposal_path.with_name(f".{proposal_path.name}.{sequence}.next")
    replacement.write_bytes(
        render_lint_review(replace(proposal, status=status, human_decision=decision))
    )
    replacement.replace(proposal_path)


def test_lint_direct_and_proposal_finalize_without_caller_outcome_flags(
    tmp_path: Path,
) -> None:
    direct_lane = tmp_path / "direct"
    proposal_lane = tmp_path / "proposal"
    direct = _prepare_lint_finalize(direct_lane, proposal=False)
    proposal = _prepare_lint_finalize(proposal_lane, proposal=True)

    for expected, prepared in (("succeeded", direct), ("waiting_human", proposal)):
        vault, runs, policy, finalize, lint_result = prepared
        result = finalize.finalize(
            "run_lint_finalize",
            artifacts=FinalizeArtifactRoles(
                producer_evidence=lint_result.prepared_artifact.name
            ),
            capabilities=_capabilities(policy),
        )
        assert result.terminal_status == expected
        assert (
            tuple(
                action["action_id"]
                for action in runs.trace_events("run_lint_finalize")[-1]["actions"]
            )
            == FINALIZE_ACTION_ORDER
        )
        outcome = parse_outcome_record((vault / result.domain_log_ref).read_bytes())
        assert outcome.producer_operation == "lint-infra"
        assert outcome.decision_status == (
            None if expected == "succeeded" else "proposed"
        )


@pytest.mark.parametrize(
    ("action", "expected_status", "expected_kind"),
    [
        ("approve", "approved", "review-approved"),
        ("reject", "rejected", "review-rejected"),
        ("supersede", "superseded", "review-superseded"),
    ],
)
def test_lint_current_decision_is_rederived_before_terminal_mapping(
    tmp_path: Path,
    action: str,
    expected_status: str,
    expected_kind: str,
) -> None:
    vault, runs, policy, finalize, lint_result = _prepare_lint_finalize(
        tmp_path, proposal=True
    )
    assert lint_result.proposal is not None
    roles = FinalizeArtifactRoles(producer_evidence=lint_result.prepared_artifact.name)
    waiting = finalize.finalize(
        "run_lint_finalize", artifacts=roles, capabilities=_capabilities(policy)
    )
    assert waiting.terminal_status == "waiting_human"
    decision = LintReviewDecision(
        action,
        "human",
        "2026-01-15T12:30:00Z",
        1,
        "lintprop-next" if action == "supersede" else None,
    )
    proposal = replace(
        lint_result.proposal,
        status=expected_status,
        human_decision=decision,
    )
    proposal_path = vault / f"review/{proposal.proposal_id}.lint.json"
    proposal_path.write_bytes(render_lint_review(proposal))
    runs.resume("run_lint_finalize", executor="fixture")

    result = finalize.finalize(
        "run_lint_finalize", artifacts=roles, capabilities=_capabilities(policy)
    )
    outcome = parse_outcome_record((vault / result.domain_log_ref).read_bytes())
    assert result.terminal_status == "succeeded"
    assert result.outcome_kind == expected_kind
    assert outcome.decision_status == expected_status
    assert outcome.decision_sequence == 1
    assert (
        finalize.finalize(
            "run_lint_finalize", artifacts=roles, capabilities=_capabilities(policy)
        )
        == result
    )


@pytest.mark.parametrize(
    ("replacement_action", "replacement_status", "replacement_terminal"),
    [
        (None, "proposed", "waiting_human"),
        ("reject", "rejected", "succeeded"),
        ("supersede", "superseded", "succeeded"),
    ],
)
def test_lint_decision_change_after_domain_log_has_no_later_stale_effect(
    tmp_path: Path,
    replacement_action: str | None,
    replacement_status: str,
    replacement_terminal: str,
) -> None:
    vault, runs, policy, finalize, lint_result = _prepare_lint_finalize(
        tmp_path, proposal=True
    )
    assert lint_result.proposal is not None
    roles = FinalizeArtifactRoles(producer_evidence=lint_result.prepared_artifact.name)
    finalize.finalize(
        "run_lint_finalize", artifacts=roles, capabilities=_capabilities(policy)
    )
    runs.resume("run_lint_finalize", executor="fixture")
    proposal_path = vault / f"review/{lint_result.proposal.proposal_id}.lint.json"
    _replace_lint_decision(
        proposal_path, lint_result.proposal, action="approve", sequence=1
    )
    metrics_before = {
        path.name for path in (vault / "agent/logs/metrics").glob("*.json")
    }
    outbox_before = {
        path.name for path in (vault / "agent/outbox").glob("event_*.json")
    }
    trace_before = runs.trace_events("run_lint_finalize")

    def replace_current_decision() -> None:
        _replace_lint_decision(
            proposal_path,
            lint_result.proposal,
            action=replacement_action,
            sequence=2,
        )

    with pytest.raises(FinalizeError, match="current lint decision changed"):
        finalize.finalize(
            "run_lint_finalize",
            artifacts=roles,
            capabilities=_capabilities(policy),
            crash_hooks=FinalizeCrashHooks(after_domain_log=replace_current_decision),
        )

    assert runs.status("run_lint_finalize")["status"] == "running"
    assert runs.trace_events("run_lint_finalize") == trace_before
    assert {
        path.name for path in (vault / "agent/logs/metrics").glob("*.json")
    } == metrics_before
    assert {
        path.name for path in (vault / "agent/outbox").glob("event_*.json")
    } == outbox_before
    if replacement_action is not None:
        current = finalize.finalize(
            "run_lint_finalize",
            artifacts=roles,
            capabilities=_capabilities(policy),
        )
        current_outcome = parse_outcome_record(
            (vault / current.domain_log_ref).read_bytes()
        )
        assert current.terminal_status == replacement_terminal
        assert current_outcome.decision_status == replacement_status


def test_lint_terminal_replay_revalidates_the_exact_current_decision(
    tmp_path: Path,
) -> None:
    vault, runs, policy, finalize, lint_result = _prepare_lint_finalize(
        tmp_path, proposal=True
    )
    assert lint_result.proposal is not None
    roles = FinalizeArtifactRoles(producer_evidence=lint_result.prepared_artifact.name)
    finalize.finalize(
        "run_lint_finalize", artifacts=roles, capabilities=_capabilities(policy)
    )
    runs.resume("run_lint_finalize", executor="fixture")
    proposal_path = vault / f"review/{lint_result.proposal.proposal_id}.lint.json"
    _replace_lint_decision(
        proposal_path, lint_result.proposal, action="approve", sequence=1
    )
    base_state = runs.status("run_lint_finalize")
    base_trace = runs.trace_events("run_lint_finalize")
    result = finalize.finalize(
        "run_lint_finalize", artifacts=roles, capabilities=_capabilities(policy)
    )
    snapshot = runs.snapshot("run_lint_finalize")
    anchor = next(
        item for item in snapshot.artifacts if item.name == "finalize-decision"
    )
    assert anchor.state_ref == f"review/{proposal_path.name}"
    assert anchor.sha256 == hashlib.sha256(proposal_path.read_bytes()).hexdigest()
    _replace_lint_decision(
        proposal_path, lint_result.proposal, action="reject", sequence=2
    )

    with pytest.raises(FinalizeError, match="terminal run evidence is invalid"):
        finalize.finalize(
            "run_lint_finalize",
            artifacts=roles,
            capabilities=_capabilities(policy),
        )

    assert result.outcome_kind == "review-approved"
    assert runs.status("run_lint_finalize") == base_state
    assert runs.trace_events("run_lint_finalize") == base_trace
    current = finalize.finalize(
        "run_lint_finalize", artifacts=roles, capabilities=_capabilities(policy)
    )
    current_outcome = parse_outcome_record(
        (vault / current.domain_log_ref).read_bytes()
    )
    assert current_outcome.decision_status == "rejected"
    assert (
        finalize.finalize(
            "run_lint_finalize", artifacts=roles, capabilities=_capabilities(policy)
        )
        == current
    )


@pytest.mark.parametrize(
    "seam",
    [
        "after_metric",
        "after_outbox",
        "after_run_prepare",
        "after_run_state",
        "after_run_trace",
    ],
)
def test_lint_decision_change_at_later_seam_never_commits_stale_run_state(
    tmp_path: Path, seam: str
) -> None:
    vault, runs, policy, finalize, lint_result = _prepare_lint_finalize(
        tmp_path, proposal=True
    )
    assert lint_result.proposal is not None
    roles = FinalizeArtifactRoles(producer_evidence=lint_result.prepared_artifact.name)
    finalize.finalize(
        "run_lint_finalize", artifacts=roles, capabilities=_capabilities(policy)
    )
    runs.resume("run_lint_finalize", executor="fixture")
    proposal_path = vault / f"review/{lint_result.proposal.proposal_id}.lint.json"
    _replace_lint_decision(
        proposal_path, lint_result.proposal, action="approve", sequence=1
    )
    state_before = runs.status("run_lint_finalize")
    trace_before = runs.trace_events("run_lint_finalize")

    def replace_current_decision() -> None:
        _replace_lint_decision(
            proposal_path, lint_result.proposal, action="reject", sequence=2
        )

    with pytest.raises(FinalizeError):
        finalize.finalize(
            "run_lint_finalize",
            artifacts=roles,
            capabilities=_capabilities(policy),
            crash_hooks=FinalizeCrashHooks(**{seam: replace_current_decision}),
        )

    assert runs.status("run_lint_finalize") == state_before
    assert runs.trace_events("run_lint_finalize") == trace_before
    recovered = finalize.finalize(
        "run_lint_finalize", artifacts=roles, capabilities=_capabilities(policy)
    )
    recovered_outcome = parse_outcome_record(
        (vault / recovered.domain_log_ref).read_bytes()
    )
    assert recovered.terminal_status == "succeeded"
    assert recovered_outcome.decision_status == "rejected"


def test_lint_decision_change_and_crash_after_run_trace_rolls_back_on_recovery(
    tmp_path: Path,
) -> None:
    vault, runs, policy, finalize, lint_result = _prepare_lint_finalize(
        tmp_path, proposal=True
    )
    assert lint_result.proposal is not None
    roles = FinalizeArtifactRoles(producer_evidence=lint_result.prepared_artifact.name)
    finalize.finalize(
        "run_lint_finalize", artifacts=roles, capabilities=_capabilities(policy)
    )
    runs.resume("run_lint_finalize", executor="fixture")
    proposal_path = vault / f"review/{lint_result.proposal.proposal_id}.lint.json"
    _replace_lint_decision(
        proposal_path, lint_result.proposal, action="approve", sequence=1
    )
    state_before = runs.status("run_lint_finalize")
    trace_before = runs.trace_events("run_lint_finalize")

    def replace_and_crash() -> None:
        _replace_lint_decision(
            proposal_path, lint_result.proposal, action="reject", sequence=2
        )
        raise _Crash("after_run_trace")

    with pytest.raises(_Crash, match="after_run_trace"):
        finalize.finalize(
            "run_lint_finalize",
            artifacts=roles,
            capabilities=_capabilities(policy),
            crash_hooks=FinalizeCrashHooks(after_run_trace=replace_and_crash),
        )

    with pytest.raises(FinalizeError, match="terminal run evidence is invalid"):
        finalize.finalize(
            "run_lint_finalize", artifacts=roles, capabilities=_capabilities(policy)
        )
    assert runs.status("run_lint_finalize") == state_before
    assert runs.trace_events("run_lint_finalize") == trace_before
    recovered = finalize.finalize(
        "run_lint_finalize", artifacts=roles, capabilities=_capabilities(policy)
    )
    recovered_outcome = parse_outcome_record(
        (vault / recovered.domain_log_ref).read_bytes()
    )
    assert recovered.terminal_status == "succeeded"
    assert recovered_outcome.decision_status == "rejected"


@pytest.mark.parametrize("crash_after_publication", [False, True])
def test_lint_decision_change_during_committed_intent_publication_is_recovered(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    crash_after_publication: bool,
) -> None:
    vault, runs, policy, finalize, lint_result = _prepare_lint_finalize(
        tmp_path, proposal=True
    )
    assert lint_result.proposal is not None
    roles = FinalizeArtifactRoles(producer_evidence=lint_result.prepared_artifact.name)
    finalize.finalize(
        "run_lint_finalize", artifacts=roles, capabilities=_capabilities(policy)
    )
    runs.resume("run_lint_finalize", executor="fixture")
    proposal_path = vault / f"review/{lint_result.proposal.proposal_id}.lint.json"
    _replace_lint_decision(
        proposal_path, lint_result.proposal, action="approve", sequence=1
    )
    state_before = runs.status("run_lint_finalize")
    trace_before = runs.trace_events("run_lint_finalize")
    real_atomic = runs_store._atomic_json_at
    replaced = False

    def replace_during_committed_intent(directory_fd, name, payload):
        nonlocal replaced
        identity = real_atomic(directory_fd, name, payload)
        if (
            not replaced
            and name == "finalize-complete.json"
            and payload.get("status") == "committed"
        ):
            replaced = True
            _replace_lint_decision(
                proposal_path, lint_result.proposal, action="reject", sequence=2
            )
            if crash_after_publication:
                raise _Crash("after-committed-intent-publication")
        return identity

    monkeypatch.setattr(runs_store, "_atomic_json_at", replace_during_committed_intent)
    expected_error = _Crash if crash_after_publication else FinalizeError
    with pytest.raises(expected_error):
        finalize.finalize(
            "run_lint_finalize", artifacts=roles, capabilities=_capabilities(policy)
        )
    monkeypatch.setattr(runs_store, "_atomic_json_at", real_atomic)

    if crash_after_publication:
        with pytest.raises(FinalizeError, match="terminal run evidence is invalid"):
            finalize.finalize(
                "run_lint_finalize",
                artifacts=roles,
                capabilities=_capabilities(policy),
            )
    assert replaced
    assert runs.status("run_lint_finalize") == state_before
    assert runs.trace_events("run_lint_finalize") == trace_before
    assert not (
        vault / "agent/runs/run_lint_finalize/intents/finalize-complete.json"
    ).exists()

    recovered = finalize.finalize(
        "run_lint_finalize", artifacts=roles, capabilities=_capabilities(policy)
    )
    recovered_outcome = parse_outcome_record(
        (vault / recovered.domain_log_ref).read_bytes()
    )
    assert recovered_outcome.decision_status == "rejected"
    assert (
        finalize.finalize(
            "run_lint_finalize", artifacts=roles, capabilities=_capabilities(policy)
        )
        == recovered
    )


def test_lint_committed_intent_left_after_projection_rollback_is_retired_on_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    vault, runs, policy, finalize, lint_result = _prepare_lint_finalize(
        tmp_path, proposal=True
    )
    assert lint_result.proposal is not None
    roles = FinalizeArtifactRoles(producer_evidence=lint_result.prepared_artifact.name)
    finalize.finalize(
        "run_lint_finalize", artifacts=roles, capabilities=_capabilities(policy)
    )
    runs.resume("run_lint_finalize", executor="fixture")
    proposal_path = vault / f"review/{lint_result.proposal.proposal_id}.lint.json"
    _replace_lint_decision(
        proposal_path, lint_result.proposal, action="approve", sequence=1
    )
    state_before = runs.status("run_lint_finalize")
    trace_before = runs.trace_events("run_lint_finalize")
    run_dir = vault / "agent/runs/run_lint_finalize"
    intent_path = run_dir / "intents/finalize-complete.json"
    real_atomic = runs_store._atomic_json_at
    real_discard = runs._discard_invalid_lint_finalize_intent
    replaced = False

    def replace_during_committed_intent(directory_fd, name, payload):
        nonlocal replaced
        identity = real_atomic(directory_fd, name, payload)
        if (
            not replaced
            and name == intent_path.name
            and payload.get("status") == "committed"
        ):
            replaced = True
            _replace_lint_decision(
                proposal_path, lint_result.proposal, action="reject", sequence=2
            )
        return identity

    def crash_before_invalid_intent_retirement(*args, **kwargs):
        assert json.loads((run_dir / "state.json").read_text("utf-8")) == state_before
        assert (
            tuple(
                json.loads(line)
                for line in (run_dir / "trace.jsonl").read_text("utf-8").splitlines()
            )
            == trace_before
        )
        raise _Crash("after-projection-rollback")

    monkeypatch.setattr(runs_store, "_atomic_json_at", replace_during_committed_intent)
    monkeypatch.setattr(
        runs,
        "_discard_invalid_lint_finalize_intent",
        crash_before_invalid_intent_retirement,
    )
    with pytest.raises(_Crash, match="after-projection-rollback"):
        finalize.finalize(
            "run_lint_finalize", artifacts=roles, capabilities=_capabilities(policy)
        )
    monkeypatch.setattr(runs_store, "_atomic_json_at", real_atomic)
    monkeypatch.setattr(runs, "_discard_invalid_lint_finalize_intent", real_discard)

    assert replaced
    assert json.loads((run_dir / "state.json").read_text("utf-8")) == state_before
    assert json.loads(intent_path.read_text("utf-8"))["status"] == "committed"

    with pytest.raises(FinalizeError, match="exact accepted producer result"):
        finalize.finalize(
            "run_lint_finalize", artifacts=roles, capabilities=_capabilities(policy)
        )
    assert not intent_path.exists()
    assert runs.status("run_lint_finalize") == state_before
    assert runs.trace_events("run_lint_finalize") == trace_before

    recovered = finalize.finalize(
        "run_lint_finalize", artifacts=roles, capabilities=_capabilities(policy)
    )
    recovered_outcome = parse_outcome_record(
        (vault / recovered.domain_log_ref).read_bytes()
    )
    assert recovered_outcome.decision_status == "rejected"
    assert (
        finalize.finalize(
            "run_lint_finalize", artifacts=roles, capabilities=_capabilities(policy)
        )
        == recovered
    )


def test_lint_intent_retirement_does_not_delete_a_foreign_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    vault, runs, policy, finalize, lint_result = _prepare_lint_finalize(
        tmp_path, proposal=True
    )
    assert lint_result.proposal is not None
    roles = FinalizeArtifactRoles(producer_evidence=lint_result.prepared_artifact.name)
    finalize.finalize(
        "run_lint_finalize", artifacts=roles, capabilities=_capabilities(policy)
    )
    runs.resume("run_lint_finalize", executor="fixture")
    proposal_path = vault / f"review/{lint_result.proposal.proposal_id}.lint.json"
    _replace_lint_decision(
        proposal_path, lint_result.proposal, action="approve", sequence=1
    )
    state_before = runs.status("run_lint_finalize")
    trace_before = runs.trace_events("run_lint_finalize")
    intent_path = vault / "agent/runs/run_lint_finalize/intents/finalize-complete.json"
    foreign_raw = b'{"foreign":"intent replacement"}\n'
    real_atomic = runs_store._atomic_json_at

    def substitute_foreign_intent(directory_fd, name, payload):
        identity = real_atomic(directory_fd, name, payload)
        if name == intent_path.name and payload.get("status") == "committed":
            _replace_lint_decision(
                proposal_path, lint_result.proposal, action="reject", sequence=2
            )
            replacement = intent_path.with_name(".foreign-intent.next")
            replacement.write_bytes(foreign_raw)
            replacement.replace(intent_path)
        return identity

    monkeypatch.setattr(runs_store, "_atomic_json_at", substitute_foreign_intent)
    with pytest.raises(FinalizeError, match="finalize run commit failed safely"):
        finalize.finalize(
            "run_lint_finalize", artifacts=roles, capabilities=_capabilities(policy)
        )

    assert intent_path.read_bytes() == foreign_raw
    assert runs.status("run_lint_finalize") == state_before
    assert runs.trace_events("run_lint_finalize") == trace_before


def test_lint_finalize_uses_configured_physical_review_reference(
    tmp_path: Path,
) -> None:
    review_zone = "custom/reviews"
    vault, runs, policy, finalize, lint_result = _prepare_lint_finalize(
        tmp_path, proposal=True, review_zone=review_zone
    )
    assert lint_result.proposal is not None
    result = finalize.finalize(
        "run_lint_finalize",
        artifacts=FinalizeArtifactRoles(
            producer_evidence=lint_result.prepared_artifact.name
        ),
        capabilities=_capabilities(policy),
    )

    decision = next(
        item
        for item in runs.snapshot("run_lint_finalize").artifacts
        if item.name == "finalize-decision"
    )
    expected = f"{review_zone}/{lint_result.proposal.proposal_id}.lint.json"
    assert result.terminal_status == "waiting_human"
    assert decision.state_ref == expected
    assert (vault / expected).is_file()


def test_public_run_commit_rejects_rebound_lint_decision_against_finalize_log(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    vault, runs, policy, finalize, lint_result = _prepare_lint_finalize(
        tmp_path, proposal=True
    )
    assert lint_result.proposal is not None
    roles = FinalizeArtifactRoles(producer_evidence=lint_result.prepared_artifact.name)
    finalize.finalize(
        "run_lint_finalize", artifacts=roles, capabilities=_capabilities(policy)
    )
    runs.resume("run_lint_finalize", executor="fixture")
    proposal_path = vault / f"review/{lint_result.proposal.proposal_id}.lint.json"
    _replace_lint_decision(
        proposal_path, lint_result.proposal, action="approve", sequence=1
    )
    state_before = runs.status("run_lint_finalize")
    trace_before = runs.trace_events("run_lint_finalize")
    original_commit = runs.commit_step
    captured: dict[str, object] = {}

    def capture_commit(*args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs
        raise _Crash("before-public-run-commit")

    monkeypatch.setattr(runs, "commit_step", capture_commit)
    with pytest.raises(_Crash, match="before-public-run-commit"):
        finalize.finalize(
            "run_lint_finalize",
            artifacts=roles,
            capabilities=_capabilities(policy),
        )
    monkeypatch.setattr(runs, "commit_step", original_commit)

    _replace_lint_decision(
        proposal_path, lint_result.proposal, action="reject", sequence=2
    )
    kwargs = dict(captured["kwargs"])
    current_sha = hashlib.sha256(proposal_path.read_bytes()).hexdigest()
    kwargs["prepared_artifacts"] = [
        replace(item, sha256=current_sha) if item.name == "finalize-decision" else item
        for item in kwargs["prepared_artifacts"]
    ]
    with pytest.raises(RunError, match="decision, producer, and outcome"):
        original_commit(*captured["args"], **kwargs)

    assert runs.status("run_lint_finalize") == state_before
    assert runs.trace_events("run_lint_finalize") == trace_before
    assert not (
        vault / "agent/runs/run_lint_finalize/intents/finalize-complete.json"
    ).exists()


@pytest.mark.parametrize("substitution", ["leaf", "parent", "zone", "root"])
def test_read_ref_rejects_same_byte_identity_substitution_without_fd_leak(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    substitution: str,
) -> None:
    vault, _resolver, _runs, _outbox, _policy, finalize = _stores(tmp_path)
    source = vault / "review/nested/value.json"
    source.parent.mkdir()
    raw = b'{"value":"same bytes"}\n'
    source.write_bytes(raw)
    before_fds = len(os.listdir("/dev/fd"))
    real_read = os.read
    swapped = False

    def swapping_read(fd: int, size: int) -> bytes:
        nonlocal swapped
        if not swapped:
            swapped = True
            if substitution == "leaf":
                replacement = source.with_name(".value.next")
                replacement.write_bytes(raw)
                replacement.replace(source)
            elif substitution == "parent":
                saved = source.parent.with_name("nested-old")
                source.parent.rename(saved)
                source.parent.mkdir()
                source.write_bytes(raw)
            elif substitution == "zone":
                review = vault / "review"
                saved = vault / "review-old"
                review.rename(saved)
                source.parent.mkdir(parents=True)
                source.write_bytes(raw)
            else:
                saved = tmp_path / "vault-old"
                vault.rename(saved)
                shutil.copytree(saved, vault)
        return real_read(fd, size)

    monkeypatch.setattr(os, "read", swapping_read)
    with pytest.raises(FinalizeError, match="cannot be read safely"):
        finalize._read_ref("review/nested/value.json")

    assert swapped
    assert len(os.listdir("/dev/fd")) == before_fds


@pytest.mark.parametrize("replace_after_prepare", [False, True])
def test_lint_decision_precondition_is_rechecked_during_crash_reconciliation(
    tmp_path: Path, replace_after_prepare: bool
) -> None:
    vault, runs, policy, finalize, lint_result = _prepare_lint_finalize(
        tmp_path, proposal=True
    )
    assert lint_result.proposal is not None
    roles = FinalizeArtifactRoles(producer_evidence=lint_result.prepared_artifact.name)
    finalize.finalize(
        "run_lint_finalize", artifacts=roles, capabilities=_capabilities(policy)
    )
    runs.resume("run_lint_finalize", executor="fixture")
    proposal_path = vault / f"review/{lint_result.proposal.proposal_id}.lint.json"
    _replace_lint_decision(
        proposal_path, lint_result.proposal, action="approve", sequence=1
    )

    def crash_after_prepare() -> None:
        if replace_after_prepare:
            _replace_lint_decision(
                proposal_path, lint_result.proposal, action="reject", sequence=2
            )
        raise _Crash("after_run_prepare")

    with pytest.raises(_Crash):
        finalize.finalize(
            "run_lint_finalize",
            artifacts=roles,
            capabilities=_capabilities(policy),
            crash_hooks=FinalizeCrashHooks(after_run_prepare=crash_after_prepare),
        )

    if replace_after_prepare:
        with pytest.raises(FinalizeError, match="exact accepted producer result"):
            finalize.finalize(
                "run_lint_finalize",
                artifacts=roles,
                capabilities=_capabilities(policy),
            )
        assert runs.status("run_lint_finalize")["status"] == "running"
        assert runs.trace_events("run_lint_finalize")[-1]["step_id"] != (
            "finalize-complete"
        )
    else:
        result = finalize.finalize(
            "run_lint_finalize",
            artifacts=roles,
            capabilities=_capabilities(policy),
        )
        assert result.outcome_kind == "review-approved"
        assert runs.status("run_lint_finalize")["status"] == "succeeded"


def test_invalid_lint_current_proposal_is_rejected_before_finalize_effects(
    tmp_path: Path,
) -> None:
    vault, runs, policy, finalize, lint_result = _prepare_lint_finalize(
        tmp_path, proposal=True
    )
    assert lint_result.proposal is not None
    proposal_path = vault / f"review/{lint_result.proposal.proposal_id}.lint.json"
    proposal_path.write_bytes(
        render_lint_review(
            replace(lint_result.proposal, created_at="2026-01-15T12:00:00Z")
        )
    )
    before_state = runs.status("run_lint_finalize")

    with pytest.raises(FinalizeError, match="exact accepted producer result"):
        finalize.finalize(
            "run_lint_finalize",
            artifacts=FinalizeArtifactRoles(
                producer_evidence=lint_result.prepared_artifact.name
            ),
            capabilities=_capabilities(policy),
        )

    assert runs.status("run_lint_finalize") == before_state
    assert not list((vault / "agent/logs/finalize").glob("*.json"))
    assert not list((vault / "agent/logs/metrics").glob("*.json"))
    assert not list((vault / "agent/outbox").glob("event_*.json"))


def _stores_with_surface(tmp_path: Path, surface: str):
    vault = tmp_path / "vault"
    shutil.copytree(FIXTURE, vault)
    config_path = vault / "lifeos.toml"
    config_path.write_text(
        config_path.read_text("utf-8").replace(
            'default = "gated"', f'default = "{surface}"'
        ),
        "utf-8",
    )
    resolver = VaultPathResolver(vault, load_vault_config(vault))
    clock = _Clock()
    runs = RunStore(resolver, clock=clock)
    policy = AuthorityPolicy()
    outbox = OutboxStore(resolver, runs, policy=policy, clock=clock)
    finalize = FinalizeFlow(resolver, runs, outbox, policy=policy, clock=clock)
    return vault, resolver, runs, policy, finalize, clock


def _ambient_request(operation_id: str) -> AmbientRequest:
    return AmbientRequest(
        operation_id,
        "2026-01-15T12:10:00Z",
        AmbientAvailability(
            "available",
            "2026-01-15T11:00:00Z",
            "2026-01-15T13:00:00Z",
        ),
        AmbientReviewBudget(10, 20),
    )


def _write_finalize_day(vault: Path) -> None:
    plan = DayPlan(
        "2026-01-15",
        "active",
        1,
        PlanPolicy(10, 3),
        (
            PlanTask(
                "task-finalize",
                "Review the central finalize checkpoint",
                "2026-01-15",
                priority="high",
            ),
        ),
        "2026-01-15T08:00:00Z",
        "2026-01-15T08:00:00Z",
        "plan_finalize",
        ZERO_HASH,
    )
    directory = vault / "tasks/days"
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "2026-01-15.json").write_bytes(render_day_plan(plan))


def _finalize_event_surface(vault: Path, event_id: str | None) -> str:
    assert event_id is not None
    event = json.loads((vault / f"agent/outbox/{event_id}.json").read_bytes())
    return str(event["delivery_policy"]["surface"])


def test_ambient_and_bundle_emitted_bundles_finalize_with_silent_events(
    tmp_path: Path,
) -> None:
    vault, resolver, runs, policy, finalize, clock = _stores_with_surface(
        tmp_path, "batched"
    )
    _write_finalize_day(vault)
    _create_source_run(
        runs,
        run_id="run_ambient_finalize",
        flow="ambient",
        authority="internal-write",
        input_data={"fixture": "ambient"},
    )
    with AmbientFlow(resolver, runs, policy, clock) as ambient:
        ambient_result = ambient.scan(
            _ambient_capabilities(policy),
            run_id="run_ambient_finalize",
            request=_ambient_request("ambient_finalize"),
        )
    assert ambient_result.outcome == "emitted"
    _create_source_run(
        runs,
        run_id="run_bundle_finalize",
        flow="bundle",
        authority="internal-write",
        input_data={"fixture": "bundle"},
    )
    with BundleFlow(resolver, runs, policy, clock) as bundle:
        bundle_result = bundle.collect(
            _bundle_capabilities(policy),
            run_id="run_bundle_finalize",
            request=BundleRequest(
                "bundle_finalize",
                "2026-01-15T13:00:00Z",
                BundleWindow("2026-01-15T11:00:00Z", "2026-01-15T12:30:00Z"),
            ),
        )
    assert bundle_result.outcome == "emitted"

    ambient_final = finalize.finalize(
        "run_ambient_finalize",
        artifacts=FinalizeArtifactRoles(
            producer_evidence=ambient_result.evidence_artifact
        ),
        capabilities=_capabilities(policy),
    )
    bundle_final = finalize.finalize(
        "run_bundle_finalize",
        artifacts=FinalizeArtifactRoles(
            producer_evidence=bundle_result.evidence_artifact
        ),
        capabilities=_capabilities(policy),
    )

    assert ambient_final.terminal_status == "succeeded"
    assert bundle_final.terminal_status == "succeeded"
    assert _finalize_event_surface(vault, ambient_final.outbox_event_id) == "silent"
    assert _finalize_event_surface(vault, bundle_final.outbox_event_id) == "silent"
    for run_id in ("run_ambient_finalize", "run_bundle_finalize"):
        assert (
            tuple(
                action["action_id"]
                for action in runs.trace_events(run_id)[-1]["actions"]
            )
            == FINALIZE_ACTION_ORDER
        )


def test_ambient_zero_and_bundle_empty_finalize_from_singleton_latest_bundles(
    tmp_path: Path,
) -> None:
    vault, resolver, runs, _outbox, policy, finalize = _stores(tmp_path)
    producer_clock = _Clock()
    _create_source_run(
        runs,
        run_id="run_ambient_zero_finalize",
        flow="ambient",
        authority="internal-write",
        input_data={"fixture": "ambient-zero"},
    )
    with AmbientFlow(resolver, runs, policy, producer_clock) as ambient:
        ambient_result = ambient.scan(
            _ambient_capabilities(policy),
            run_id="run_ambient_zero_finalize",
            request=_ambient_request("ambient_zero_finalize"),
        )
    assert ambient_result.outcome == "zero"
    _create_source_run(
        runs,
        run_id="run_bundle_empty_finalize",
        flow="bundle",
        authority="internal-write",
        input_data={"fixture": "bundle-empty"},
    )
    with BundleFlow(resolver, runs, policy, producer_clock) as bundle:
        bundle_result = bundle.collect(
            _bundle_capabilities(policy),
            run_id="run_bundle_empty_finalize",
            request=BundleRequest(
                "bundle_empty_finalize",
                "2026-01-15T13:00:00Z",
                BundleWindow("2026-01-15T11:00:00Z", "2026-01-15T12:30:00Z"),
            ),
        )
    assert bundle_result.outcome == "empty"

    for run_id, evidence_name in (
        ("run_ambient_zero_finalize", ambient_result.evidence_artifact),
        ("run_bundle_empty_finalize", bundle_result.evidence_artifact),
    ):
        result = finalize.finalize(
            run_id,
            artifacts=FinalizeArtifactRoles(producer_evidence=evidence_name),
            capabilities=_capabilities(policy),
        )
        assert result.terminal_status == "succeeded"
        assert _finalize_event_surface(vault, result.outbox_event_id) == "silent"
        assert (
            finalize.finalize(
                run_id,
                artifacts=FinalizeArtifactRoles(producer_evidence=evidence_name),
                capabilities=_capabilities(policy),
            )
            == result
        )


@pytest.mark.parametrize(
    "corruption",
    ["artifact-bytes", "newer-step", "trace-action", "trace-input", "trace-output"],
)
def test_new_producer_source_mismatch_is_rejected_without_finalize_effect(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, corruption: str
) -> None:
    vault, runs, policy, finalize, evidence_name = _prepare_mentor_finalize(tmp_path)
    before_state = runs.status("run_mentor_finalize")
    if corruption == "artifact-bytes":
        snapshot = runs.producer_snapshot(
            "run_mentor_finalize", producer_evidence=evidence_name
        )
        task = next(
            item for item in snapshot.artifacts if item.name.startswith("mentor-task-")
        )
        (vault / task.state_ref).write_bytes(b'{"changed":true}\n')
    elif corruption == "newer-step":
        newer = runs.prepare_run_artifact(
            "run_mentor_finalize", name="newer-evidence", data=b'{"newer":true}\n'
        )
        runs.commit_step(
            "run_mentor_finalize",
            step_id="mentor-newer",
            authority="internal-write",
            input_hash=ZERO_HASH,
            output_hash=newer.sha256,
            next_phase="mentor-newer",
            prepared_artifacts=(newer,),
        )
        before_state = runs.status("run_mentor_finalize")
    else:
        real_trace_events = runs.trace_events

        def altered_trace_events(run_id: str):
            events = json.loads(json.dumps(real_trace_events(run_id)))
            event = events[-1]
            if corruption == "trace-action":
                event["actions"][0]["status"] = "failed"
            elif corruption == "trace-input":
                event["input_hash"] = ZERO_HASH
            else:
                event["output_hash"] = ZERO_HASH
            return events

        monkeypatch.setattr(runs, "trace_events", altered_trace_events)

    with pytest.raises(FinalizeError, match="exact accepted producer result"):
        finalize.finalize(
            "run_mentor_finalize",
            artifacts=FinalizeArtifactRoles(producer_evidence=evidence_name),
            capabilities=_capabilities(policy),
        )

    assert runs.status("run_mentor_finalize") == before_state
    assert not list((vault / "agent/logs/finalize").glob("*.json"))
    assert not list((vault / "agent/logs/metrics").glob("*.json"))
    assert not list((vault / "agent/outbox").glob("event_*.json"))


@pytest.mark.parametrize("producer", ["direct", "proposal"])
@pytest.mark.parametrize(
    "seam",
    [
        "after_domain_log",
        "after_metric",
        "after_outbox",
        "after_run_prepare",
        "after_run_state",
        "after_run_trace",
    ],
)
def test_new_direct_and_proposal_finalize_replay_every_crash_seam(
    tmp_path: Path, producer: str, seam: str
) -> None:
    if producer == "direct":
        vault, runs, policy, finalize, lint_result = _prepare_lint_finalize(
            tmp_path, proposal=False
        )
        run_id = "run_lint_finalize"
        evidence_name = lint_result.prepared_artifact.name
        terminal = "succeeded"
    else:
        vault, runs, policy, finalize, evidence_name = _prepare_mentor_finalize(
            tmp_path
        )
        run_id = "run_mentor_finalize"
        terminal = "waiting_human"

    def crash() -> None:
        raise _Crash(seam)

    roles = FinalizeArtifactRoles(producer_evidence=evidence_name)
    with pytest.raises(_Crash):
        finalize.finalize(
            run_id,
            artifacts=roles,
            capabilities=_capabilities(policy),
            crash_hooks=FinalizeCrashHooks(**{seam: crash}),
        )
    result = finalize.finalize(
        run_id, artifacts=roles, capabilities=_capabilities(policy)
    )

    assert result.terminal_status == terminal
    assert len(list((vault / "agent/logs/finalize").glob("*.json"))) == 1
    assert len(list((vault / "agent/logs/metrics").glob("*.json"))) == 1
    assert (
        tuple(
            action["action_id"] for action in runs.trace_events(run_id)[-1]["actions"]
        )
        == FINALIZE_ACTION_ORDER
    )
    assert (
        finalize.finalize(run_id, artifacts=roles, capabilities=_capabilities(policy))
        == result
    )
