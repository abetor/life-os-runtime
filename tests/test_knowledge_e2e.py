"""P2-08 clean-vault knowledge vertical acceptance.

The corpus and vault are synthetic.  No configured or legacy data root is read.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import unicodedata

import pytest

from tool_life_os_runtime.ext.connectors.llmwiki import LlmWikiConnector
from tool_life_os_runtime.ext.flows.ask import AskFlow, publish_ask_result
from tool_life_os_runtime.ext.flows.distill import (
    DISTILL_OUTPUT_SCHEMA_VERSION,
    DistillFlow,
)
from tool_life_os_runtime.ext.flows.finalize import (
    FinalizeArtifactRoles,
    FinalizeCapabilities,
    FinalizeFlow,
)
from tool_life_os_runtime.ext.review.apply import ApplyCrash, AtomicApply
from tool_life_os_runtime.ext.review.artifact import (
    mutation_plan_sha256,
    parse_mutation_plan,
    parse_review_artifact,
    render_apply_journal,
    render_mutation_plan,
    render_review_artifact,
)
from tool_life_os_runtime.ext.review.authority import AuthorityPolicy
from tool_life_os_runtime.ext.review.decision import record_decision
from tool_life_os_runtime.ext.runs import (
    ActionUse,
    OutboxStore,
    PreparedArtifact,
    RunStore,
)
from tool_life_os_runtime.ext.vault.config import load_vault_config
from tool_life_os_runtime.ext.vault.schema import VaultPathResolver


FIXTURE = Path(__file__).parent / "fixtures/vault-minimal"
FINALIZE_ACTIONS = (
    "validate-run-artifacts",
    "read-review-outcome",
    "append-domain-log",
    "append-run-trace",
    "commit-bounded-metrics",
    "emit-semantic-outbox-event",
    "finalize-run-state",
)


class _Clock:
    def __init__(self) -> None:
        self.value = datetime(2026, 8, 20, 10, 0, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        current = self.value
        self.value += timedelta(seconds=1)
        return current


class _Executor:
    def __init__(self) -> None:
        self.calls: list[bytes] = []

    def execute(self, packet_raw: bytes) -> dict[str, object]:
        self.calls.append(packet_raw)
        packet = json.loads(packet_raw)
        statements = []
        for sequence, claim in enumerate(packet["claims"], start=1):
            statements.append(
                {
                    "statement_id": f"stmt_{sequence}",
                    "text": (
                        f"{claim['text']} This retained rule connects the exact "
                        "source evidence to a repeatable retrieval practice."
                    ),
                    "claim_ids": [claim["claim_id"]],
                    "block_refs": [claim["evidence"]["block_ref"]],
                }
            )
        return {
            "schema_version": DISTILL_OUTPUT_SCHEMA_VERSION,
            "task_packet_sha256": hashlib.sha256(packet_raw).hexdigest(),
            "target_path": "knowledge/domains/learning/retrieval-practice.md",
            "title": "Evidence-bound retrieval practice",
            "statements": statements,
        }


class _LiveExecutor:
    def __init__(
        self, argv: tuple[str, ...], *, cwd: Path, timeout: float = 180.0
    ) -> None:
        self.argv = argv
        self.cwd = cwd
        self.timeout = timeout
        self.outputs: list[bytes] = []

    def execute(self, packet_raw: bytes) -> bytes:
        packet_hash = hashlib.sha256(packet_raw).hexdigest()
        prompt = (
            "Return only one JSON object, with no Markdown fence or commentary. "
            "You are the bounded synthesis executor for this synthetic test packet. "
            "Use schema_version 1 and task_packet_sha256 exactly "
            f"{packet_hash}. Set target_path to "
            "knowledge/domains/learning/retrieval-practice-live.md. "
            "Return a concise title and one grounded statement for every claim. "
            "Each statement must have statement_id, text of at least 80 characters, "
            "claim_ids containing exactly that claim_id, and block_refs containing "
            "exactly its evidence.block_ref. Use all claims and no outside facts. "
            "Input packet follows:\n"
        ).encode("utf-8") + packet_raw
        try:
            completed = subprocess.run(
                [*self.argv, prompt.decode("utf-8")],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=self.cwd,
                check=False,
                timeout=self.timeout,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise RuntimeError("live executor did not complete") from error
        if completed.returncode != 0 or not completed.stdout:
            raise RuntimeError("live executor returned no valid candidate")
        self.outputs.append(completed.stdout)
        return completed.stdout


def _jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    path.write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows),
        "utf-8",
    )


def _topic(tmp_path: Path) -> Path:
    topic = tmp_path / "machine-topics/e2e"
    (topic / "sources/content").mkdir(parents=True)
    (topic / "staging").mkdir()
    (topic / "final/wiki").mkdir(parents=True)
    (topic / "work").mkdir()
    (topic / "topic.json").write_text(
        json.dumps(
            {
                "spec_version": "0.1.0",
                "topic": "Retrieval practice",
                "slug": "e2e",
                "created_at": "2026-08-20T09:00:00+00:00",
            }
        )
        + "\n",
        "utf-8",
    )
    source_id = "src_aaaaaaaaaaaa"
    source_ref = "sources/content/lesson.md"
    (topic / source_ref).write_text(
        "Retrieve an existing note before adding a new one.\n"
        "Keep a citation beside every durable synthesis statement.\n",
        "utf-8",
    )
    _jsonl(
        topic / "sources/sources.jsonl",
        [
            {
                "id": source_id,
                "kind": "local",
                "title": "Synthetic lesson",
                "content_path": source_ref,
                "meta": {"lesson": 1},
            }
        ],
    )
    _jsonl(
        topic / "final/claims.jsonl",
        [
            {
                "id": "clm_111111111111",
                "text": "Retrieval should precede capture.",
                "confidence": "high",
                "status": "verified",
                "evidence": [
                    {
                        "source_id": source_id,
                        "quote": "Retrieve an existing note before adding a new one.",
                        "stance": "supports",
                        "locator": {"type": "line", "value": "1"},
                    }
                ],
                "created_at": "2026-08-20T09:01:00+00:00",
            },
            {
                "id": "clm_222222222222",
                "text": "Durable synthesis should retain exact citations.",
                "confidence": "high",
                "status": "final",
                "evidence": [
                    {
                        "source_id": source_id,
                        "quote": "Keep a citation beside every durable synthesis statement.",
                        "stance": "supports",
                        "locator": {"type": "line", "value": "2"},
                    }
                ],
                "created_at": "2026-08-20T09:02:00+00:00",
            },
        ],
    )
    (topic / "staging/claims.jsonl").write_text("", "utf-8")
    (topic / "final/wiki/retrieval.md").write_text(
        "---\n"
        "id: wik_cccccccccccc\n"
        "title: Retrieval practice\n"
        "claims:\n"
        "  - clm_111111111111\n"
        "  - clm_222222222222\n"
        "updated_at: 2026-08-20T09:03:00+00:00\n"
        "---\n\n"
        "# Retrieval practice\n",
        "utf-8",
    )
    return topic


def _validator_command(tmp_path: Path) -> tuple[str, ...]:
    program = tmp_path / "llmwiki-validator.py"
    program.write_text(
        "import sys\n"
        "if len(sys.argv) == 3 and sys.argv[1] == 'validate':\n"
        "    raise SystemExit(0)\n"
        "raise SystemExit(2)\n",
        "utf-8",
    )
    return sys.executable, str(program)


def _action_uses(
    policy: AuthorityPolicy, flow_id: str, action_ids: tuple[str, ...]
) -> tuple[ActionUse, ...]:
    from tool_life_os_runtime.failure_authority import canonical_matrix

    flow = next(row for row in canonical_matrix()["flows"] if row["flow_id"] == flow_id)
    actions = {row["action_id"]: row for row in flow["actions"]}
    assert set(action_ids).issubset(actions)
    return tuple(
        ActionUse(
            policy.issue(
                flow_id=flow_id,
                action_id=action_id,
                actor=str(actions[action_id]["actor"]),
                authority=str(actions[action_id]["authority"]),
                target=str(actions[action_id]["target"]),
            )
        )
        for action_id in action_ids
    )


def _finalize_capabilities(policy: AuthorityPolicy) -> FinalizeCapabilities:
    def issue(action: str, authority: str, target: str):
        return policy.issue(
            flow_id="finalize",
            action_id=action,
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
            "commit-bounded-metrics", "internal-write", "vault:agent/logs/metrics"
        ),
        emit_semantic_outbox_event=issue(
            "emit-semantic-outbox-event", "internal-write", "vault:agent/outbox"
        ),
        finalize_run_state=issue(
            "finalize-run-state", "internal-write", "vault:agent/runs"
        ),
    )


def _external_artifact(
    name: str, zone: str, relative: str, raw: bytes
) -> PreparedArtifact:
    return PreparedArtifact(
        name=name,
        zone=zone,
        relative=relative.removeprefix(f"{zone}/"),
        state_ref=relative,
        sha256=hashlib.sha256(raw).hexdigest(),
    )


def _assert_finalize_trace(runs: RunStore, run_id: str) -> None:
    trace = runs.trace_events(run_id)[-1]
    assert trace["schema_version"] == 2
    assert tuple(row["action_id"] for row in trace["actions"]) == FINALIZE_ACTIONS
    assert all(row["status"] == "succeeded" for row in trace["actions"])


def _assert_flow_trace(
    runs: RunStore, run_id: str, action_ids: tuple[str, ...]
) -> None:
    trace = runs.trace_events(run_id)[-1]
    assert trace["schema_version"] == 2
    assert tuple(row["action_id"] for row in trace["actions"]) == action_ids
    assert all(row["status"] == "succeeded" for row in trace["actions"])


def test_clean_vault_corpus_distill_approve_crash_resume_apply_and_cited_ask(
    tmp_path: Path,
) -> None:
    vault = tmp_path / "vault"
    shutil.copytree(FIXTURE, vault)
    (vault / "knowledge/domains/learning").mkdir(parents=True)
    resolver = VaultPathResolver(vault, load_vault_config(vault))
    clock = _Clock()
    policy = AuthorityPolicy()
    runs = RunStore(resolver, clock=clock)
    outbox = OutboxStore(resolver, runs, policy=policy, clock=clock)
    finalize = FinalizeFlow(resolver, runs, outbox, policy=policy, clock=clock)
    finalize_caps = _finalize_capabilities(policy)

    topic = _topic(tmp_path)
    connector = LlmWikiConnector(
        topics_root=topic.parent,
        command=_validator_command(tmp_path),
        cwd=tmp_path,
        env={},
    )
    snapshot = connector.load_topic(topic)
    runs.create(
        run_id="run_e2e_distill",
        flow="distill",
        phase="synthesize",
        authority="proposal",
        executor="fake-e2e",
        input_data={"topic_snapshot_sha256": snapshot.snapshot_sha256},
    )
    runs.resume("run_e2e_distill", executor="fake-e2e")
    executor = _Executor()
    distill = DistillFlow(policy=policy, executor=executor, run_store=runs)
    proposal_capability = policy.issue(
        flow_id="distill",
        action_id="commit-review-proposal",
        actor="runtime",
        authority="proposal",
        target="vault:review",
    )
    distilled = distill.distill(
        snapshot,
        run_id="run_e2e_distill",
        review_id="rev_e2e_knowledge",
        created_at="2026-08-20T10:00:00Z",
        surface="gated",
        proposal_capability=proposal_capability,
    )
    review_path = vault / "review/rev_e2e_knowledge.md"
    plan_path = vault / ".lifeos/review-plans/rev_e2e_knowledge.json"
    review_raw = render_review_artifact(distilled.proposal.artifact).encode("utf-8")
    plan_raw = render_mutation_plan(distilled.proposal.plan)
    review_path.write_bytes(review_raw)
    plan_path.write_bytes(plan_raw)
    runs.commit_step(
        "run_e2e_distill",
        step_id="commit-proposal",
        authority="proposal",
        input_hash=snapshot.snapshot_sha256,
        output_hash=hashlib.sha256(review_raw + plan_raw).hexdigest(),
        next_phase="validate",
        prepared_artifacts=(
            _external_artifact(
                "review", "review", "review/rev_e2e_knowledge.md", review_raw
            ),
            _external_artifact(
                "plan",
                ".lifeos/review-plans",
                ".lifeos/review-plans/rev_e2e_knowledge.json",
                plan_raw,
            ),
        ),
        action_uses=_action_uses(
            policy,
            "distill",
            (
                "read-validated-claims",
                "read-source-manifests",
                "validate-machine-topic",
                "commit-review-proposal",
                "record-run-state",
            ),
        ),
        authority_policy=policy,
    )
    _assert_flow_trace(
        runs,
        "run_e2e_distill",
        (
            "read-validated-claims",
            "read-source-manifests",
            "validate-machine-topic",
            "commit-review-proposal",
            "record-run-state",
        ),
    )
    waiting = finalize.finalize(
        "run_e2e_distill",
        artifacts=FinalizeArtifactRoles(review="review", plan="plan"),
        capabilities=finalize_caps,
    )
    assert waiting.terminal_status == "waiting_human"
    _assert_finalize_trace(runs, "run_e2e_distill")

    decision_capability = policy.issue(
        flow_id="review-decision",
        action_id="record-approve-reject-or-supersede",
        actor="human",
        authority="domain-write",
        target="vault:review",
    )
    approved = record_decision(
        distilled.proposal.artifact,
        distilled.proposal.plan,
        action="approve",
        actor="human-owner",
        at="2026-08-20T10:05:00Z",
        capability=decision_capability,
        policy=policy,
    )
    approved_path = vault / "review/rev_e2e_knowledge-approved.md"
    approved_path.write_text(render_review_artifact(approved), "utf-8")
    plan_hash = mutation_plan_sha256(distilled.proposal.plan)
    runs.create(
        run_id="run_e2e_apply",
        flow="apply",
        phase="commit",
        authority="protected-write",
        executor="runtime",
        input_data={"review_id": approved.review_id, "plan_sha256": plan_hash},
    )
    runs.resume("run_e2e_apply", executor="runtime")
    apply_capability = policy.issue(
        flow_id="apply",
        action_id="commit-approved-knowledge",
        actor="runtime-human-approved",
        authority="protected-write",
        target="vault:knowledge",
    )
    apply = AtomicApply(resolver, policy)
    apply.prepare(
        approved,
        distilled.proposal.plan,
        journal_id="apply_e2e_knowledge",
        committed_at="2026-08-20T10:06:00Z",
        capability=apply_capability,
    )
    with pytest.raises(ApplyCrash):
        apply.commit(
            approved,
            distilled.proposal.plan,
            journal_id="apply_e2e_knowledge",
            capability=apply_capability,
            crash_at="after-journal-before-review-finalization",
        )
    recovered_artifact = parse_review_artifact(approved_path.read_text("utf-8"))
    recovered_plan = parse_mutation_plan(plan_path.read_bytes())
    recovered_apply = AtomicApply(resolver, policy)
    journal = recovered_apply.reconcile(
        recovered_artifact,
        recovered_plan,
        journal_id="apply_e2e_knowledge",
        capability=apply_capability,
        strategy="commit",
    )
    applied = recovered_apply.finalize(
        recovered_artifact,
        recovered_plan,
        journal,
        capability=apply_capability,
    )
    target = vault / distilled.proposal.plan.operations[0].path
    assert target.read_text("utf-8") == distilled.proposal.plan.operations[0].content

    applied_raw = render_review_artifact(applied).encode("utf-8")
    journal_raw = render_apply_journal(journal)
    applied_path = vault / "review/rev_e2e_knowledge-applied.md"
    applied_path.write_bytes(applied_raw)
    journal_artifact = runs.prepare_run_artifact(
        "run_e2e_apply", name="apply-journal", data=journal_raw
    )
    runs.commit_step(
        "run_e2e_apply",
        step_id="commit-applied-review",
        authority="protected-write",
        input_hash=plan_hash,
        output_hash=journal_artifact.sha256,
        next_phase="validate",
        prepared_artifacts=(
            _external_artifact(
                "review",
                "review",
                "review/rev_e2e_knowledge-applied.md",
                applied_raw,
            ),
            _external_artifact(
                "plan",
                ".lifeos/review-plans",
                ".lifeos/review-plans/rev_e2e_knowledge.json",
                plan_raw,
            ),
            journal_artifact,
        ),
        action_uses=_action_uses(
            policy,
            "apply",
            (
                "verify-approved-plan",
                "read-knowledge-preconditions",
                "commit-approved-knowledge",
                "finalize-applied-review",
                "record-run-state",
            ),
        ),
        authority_policy=policy,
    )
    _assert_flow_trace(
        runs,
        "run_e2e_apply",
        (
            "verify-approved-plan",
            "read-knowledge-preconditions",
            "commit-approved-knowledge",
            "finalize-applied-review",
            "record-run-state",
        ),
    )
    applied_result = finalize.finalize(
        "run_e2e_apply",
        artifacts=FinalizeArtifactRoles(
            review="review", plan="plan", apply_journal="apply-journal"
        ),
        capabilities=finalize_caps,
    )
    assert applied_result.terminal_status == "succeeded"
    assert applied_result.outcome_kind == "knowledge-applied"
    _assert_finalize_trace(runs, "run_e2e_apply")

    runs.create(
        run_id="run_e2e_ask",
        flow="ask",
        phase="retrieve",
        authority="internal-write",
        executor="deterministic",
        input_data={},
    )
    runs.resume("run_e2e_ask", executor="deterministic")
    ask = AskFlow(resolver, policy=policy)
    ask_result = ask.ask(
        "retrieval practice",
        run_id="run_e2e_ask",
        read_capability=policy.issue(
            flow_id="ask",
            action_id="retrieve-cited-evidence",
            actor="runtime",
            authority="read",
            target="vault:knowledge",
        ),
    )
    assert not ask_result.evidence_gap
    assert ask_result.citations
    assert ask_result.citations[0].path == distilled.proposal.plan.operations[0].path
    assert (vault / ask_result.citations[0].path).is_file()
    prepared_ask = publish_ask_result(runs, ask_result)
    runs.commit_step(
        "run_e2e_ask",
        step_id="commit-ask-result",
        authority="internal-write",
        input_hash=ask_result.query_sha256,
        output_hash=prepared_ask.sha256,
        next_phase="validate",
        prepared_artifacts=(prepared_ask,),
        action_uses=_action_uses(
            policy,
            "ask",
            ("retrieve-cited-evidence", "record-run-state"),
        ),
        authority_policy=policy,
    )
    _assert_flow_trace(
        runs,
        "run_e2e_ask",
        ("retrieve-cited-evidence", "record-run-state"),
    )
    answer = finalize.finalize(
        "run_e2e_ask",
        artifacts=FinalizeArtifactRoles(ask_result="ask-result"),
        capabilities=finalize_caps,
    )
    assert answer.terminal_status == "succeeded"
    assert answer.outcome_kind == "answer-ready"
    _assert_finalize_trace(runs, "run_e2e_ask")
    assert len(executor.calls) == 1
    assert not list(vault.rglob(".lifeos-apply-*"))


def test_opt_in_live_executor_semantic_cohort_on_synthetic_topic(
    tmp_path: Path,
) -> None:
    encoded_argv = os.environ.get("LIFEOS_E2E_LIVE_ARGV_JSON")
    if encoded_argv is None:
        pytest.skip("set LIFEOS_E2E_LIVE_ARGV_JSON for the opt-in live cohort")
    if os.environ.get("LIFEOS_E2E_CONFIRM_SYNTHETIC") != "1":
        pytest.skip("set LIFEOS_E2E_CONFIRM_SYNTHETIC=1 for synthetic-only input")
    try:
        encoded_argv_bytes = encoded_argv.encode("utf-8")
    except UnicodeError:
        pytest.fail("live executor argv must be valid UTF-8")
    if len(encoded_argv_bytes) > 16 * 1024:
        pytest.fail("live executor argv JSON exceeds its byte limit")
    try:
        decoded = json.loads(encoded_argv)
    except (ValueError, RecursionError):
        pytest.fail("live executor argv must be a JSON string array")
    if (
        not isinstance(decoded, list)
        or not decoded
        or len(decoded) > 16
        or any(
            not isinstance(item, str)
            or not item
            or len(item.encode("utf-8")) > 4096
            or any(
                unicodedata.category(character).startswith("C")
                or unicodedata.category(character) in {"Zl", "Zp"}
                for character in item
            )
            for item in decoded
        )
    ):
        pytest.fail("live executor argv must be a bounded non-empty string array")
    cohort_raw = os.environ.get("LIFEOS_E2E_LIVE_COHORT", "3")
    try:
        cohort = int(cohort_raw)
    except ValueError:
        pytest.fail("live cohort size must be an integer")
    if cohort < 1 or cohort > 5:
        pytest.fail("live cohort size must be between one and five")

    topic = _topic(tmp_path)
    connector = LlmWikiConnector(
        topics_root=topic.parent,
        command=_validator_command(tmp_path),
        cwd=tmp_path,
        env={},
    )
    snapshot = connector.load_topic(topic)
    policy = AuthorityPolicy()
    capability = policy.issue(
        flow_id="distill",
        action_id="commit-review-proposal",
        actor="runtime",
        authority="proposal",
        target="vault:review",
    )
    executor = _LiveExecutor(tuple(decoded), cwd=tmp_path)
    results = []
    for sequence in range(1, cohort + 1):
        result = DistillFlow(policy=policy, executor=executor).distill(
            snapshot,
            run_id=f"run_live_{sequence}",
            review_id=f"rev_live_{sequence}",
            created_at=f"2026-08-20T11:00:0{sequence}Z",
            surface="gated",
            proposal_capability=capability,
        )
        content = result.proposal.plan.operations[0].content
        assert content is not None
        results.append(
            {
                "sequence": sequence,
                "packet_sha256": result.task_packet_sha256,
                "proposal_sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(),
                "proposal_bytes": len(content.encode("utf-8")),
                "content": content,
            }
        )
    print(json.dumps({"cohort": results}, ensure_ascii=False, indent=2))
    assert len(executor.outputs) == cohort
