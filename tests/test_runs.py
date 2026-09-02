"""P1-05 run envelope, lock, and crash-reconciliation acceptance."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
import multiprocessing
import os
from pathlib import Path
import shutil

import pytest

from tool_life_os_runtime.ext.runs import store as runs_store
from tool_life_os_runtime.ext.runs import (
    ActionUse,
    PreparedArtifact,
    RunError,
    RunLockBusy,
    RunStore,
    ToolOutcome,
    validate_receipt,
    validate_state,
    validate_trace_event,
)
from tool_life_os_runtime.ext.review.authority import AuthorityPolicy
from tool_life_os_runtime.ext.review.artifact import (
    DECISION_SCHEMA_VERSION,
    MutationOperation,
    MutationPlan,
    Provenance,
    ReviewArtifact,
    ReviewDecision,
    SourceRef,
    mutation_plan_sha256,
    provenance_sha256,
    render_mutation_plan,
    render_review_artifact,
    review_body_sha256,
)
from tool_life_os_runtime.ext.vault.config import load_vault_config
from tool_life_os_runtime.ext.vault.schema import VaultPathResolver


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "vault-minimal"
ZERO_HASH = "0" * 64
ONE_HASH = "1" * 64


class _Clock:
    def __init__(self) -> None:
        self.value = datetime(2026, 1, 15, 9, 0, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        current = self.value
        self.value += timedelta(seconds=1)
        return current


class _InjectedCrash(RuntimeError):
    pass


def _vault(tmp_path: Path) -> tuple[Path, VaultPathResolver]:
    vault = tmp_path / "vault"
    shutil.copytree(FIXTURE, vault)
    config = load_vault_config(vault / "lifeos.toml")
    return vault, VaultPathResolver(vault, config)


def _store(tmp_path: Path) -> tuple[Path, RunStore]:
    vault, resolver = _vault(tmp_path)
    return vault, RunStore(resolver, clock=_Clock())


def _create_running(store: RunStore, run_id: str = "run_fixture") -> dict[str, object]:
    store.create(
        run_id=run_id,
        flow="distill",
        phase="collect",
        authority="proposal",
        executor="codex",
        input_data={"source_ref": "inbox/fixture.md", "source_sha256": ZERO_HASH},
    )
    return store.resume(run_id, executor="codex")


def _finalize_actions(policy: AuthorityPolicy) -> tuple[ActionUse, ...]:
    action_specs = (
        ("validate-run-artifacts", "read", "vault:agent/runs"),
        ("read-review-outcome", "read", "vault:review"),
        ("append-domain-log", "internal-write", "vault:agent/logs"),
        ("append-run-trace", "internal-write", "vault:agent/runs/trace"),
        ("commit-bounded-metrics", "internal-write", "vault:agent/logs/metrics"),
        ("emit-semantic-outbox-event", "internal-write", "vault:agent/outbox"),
        ("finalize-run-state", "internal-write", "vault:agent/runs"),
    )
    return tuple(
        ActionUse(
            policy.issue(
                flow_id="finalize",
                action_id=action_id,
                actor="runtime",
                authority=authority,
                target=target,
            )
        )
        for action_id, authority, target in action_specs
    )


def _finalize_sidecars(vault: Path, label: str) -> tuple[PreparedArtifact, ...]:
    specs = (
        (
            "finalize-log",
            "agent/logs",
            f"finalize/outcome_{label}.json",
            f"agent/logs/finalize/outcome_{label}.json",
        ),
        (
            "finalize-metric",
            "agent/logs",
            f"metrics/metric_{label}.json",
            f"agent/logs/metrics/metric_{label}.json",
        ),
        (
            "finalize-event",
            "agent/outbox",
            f"event_{label}.json",
            f"agent/outbox/event_{label}.json",
        ),
    )
    result: list[PreparedArtifact] = []
    for name, zone, relative, state_ref in specs:
        path = vault / state_ref
        path.parent.mkdir(parents=True, exist_ok=True)
        raw = (json.dumps({"sidecar": name}, sort_keys=True) + "\n").encode()
        path.write_bytes(raw)
        result.append(
            PreparedArtifact(
                name, zone, relative, state_ref, hashlib.sha256(raw).hexdigest()
            )
        )
    return tuple(result)


def _book_rebind_bundle(tmp_path: Path):
    vault, store = _store(tmp_path)
    run_id = "run_book_rebind"
    store.create(
        run_id=run_id,
        flow="book",
        phase="reading",
        authority="domain-write",
        executor="codex",
        input_data={"slug": "rebind"},
    )
    store.resume(run_id, executor="codex")
    source = SourceRef("book-anchor", "source/rebind")
    provenance = Provenance(run_id, ((source.ref, ZERO_HASH),))
    body = "# Original bounded anchor\n"
    review = ReviewArtifact(
        schema_version=1,
        review_id="rev_book_rebind_one",
        status="proposed",
        flow="book",
        created_at="2026-01-15T08:00:00Z",
        surface="gated",
        sources=(source,),
        provenance=provenance,
        plan_path=".lifeos/review-plans/rev_book_rebind_one.json",
        body=body,
    )
    content = "# Accepted anchor\n"
    plan = MutationPlan(
        schema_version=1,
        review_id=review.review_id,
        review_body_sha256=review_body_sha256(body),
        provenance_sha256=provenance_sha256(provenance),
        operations=(
            MutationOperation(
                op="create",
                path="knowledge/book-rebind.md",
                destination_path=None,
                source_refs=(source.ref,),
                precondition_sha256=None,
                postcondition_sha256=hashlib.sha256(content.encode()).hexdigest(),
                content=content,
            ),
        ),
    )
    token = "rebindtoken"
    review_raw = render_review_artifact(review).encode()
    plan_raw = render_mutation_plan(plan)
    review_path = vault / f"review/{review.review_id}.md"
    plan_path = vault / review.plan_path
    review_path.write_bytes(review_raw)
    plan_path.parent.mkdir(parents=True, exist_ok=True)
    plan_path.write_bytes(plan_raw)
    evidence = store.prepare_run_artifact(
        run_id, name=f"book-{token}", data=b'{"book":"evidence"}\n'
    )
    review_evidence = PreparedArtifact(
        f"book-review-{token}",
        "review",
        review_path.name,
        f"review/{review_path.name}",
        hashlib.sha256(review_raw).hexdigest(),
    )
    plan_evidence = PreparedArtifact(
        f"book-plan-{token}",
        ".lifeos/review-plans",
        plan_path.name,
        review.plan_path,
        hashlib.sha256(plan_raw).hexdigest(),
    )
    store.commit_step(
        run_id,
        step_id=evidence.name,
        authority="domain-write",
        input_hash=ZERO_HASH,
        output_hash=evidence.sha256,
        next_phase="review",
        prepared_artifacts=(evidence, review_evidence, plan_evidence),
    )
    return (
        vault,
        store,
        run_id,
        review,
        plan,
        review_path,
        plan_path,
        evidence,
        review_evidence,
        plan_evidence,
    )


def _trace(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in path.read_text("utf-8").splitlines()]


def _lock_contender(vault_text: str, queue: multiprocessing.Queue) -> None:
    vault = Path(vault_text)
    config = load_vault_config(vault / "lifeos.toml")
    store = RunStore(VaultPathResolver(vault, config))
    try:
        with store._locked("run_fixture"):  # exact cross-process lock boundary
            queue.put("acquired")
    except RunLockBusy:
        queue.put("busy")


def _crash_after_prepare(vault_text: str, artifact_hash: str) -> None:
    vault = Path(vault_text)
    config = load_vault_config(vault / "lifeos.toml")
    store = RunStore(VaultPathResolver(vault, config), clock=_Clock())
    store.commit_step(
        "run_fixture",
        step_id="child-prepare",
        authority="proposal",
        input_hash=ZERO_HASH,
        output_hash=artifact_hash,
        next_phase="validate",
        prepared_artifacts=[
            PreparedArtifact(
                "review", "review", "proposal.md", "review/proposal.md", artifact_hash
            )
        ],
        after_prepare=lambda: os._exit(79),
    )


def test_create_resume_status_transition_and_cancel(tmp_path):
    _, store = _store(tmp_path)
    created = store.create(
        run_id="run_fixture",
        flow="distill",
        phase="collect",
        authority="proposal",
        executor="codex",
        input_data={"source_ref": "inbox/fixture.md", "source_sha256": ZERO_HASH},
    )
    assert created["status"] == "created"
    assert created["attempt"] == 1

    running = store.resume("run_fixture", executor="claude")
    assert running["status"] == "running"
    assert running["executor"] == "claude"
    assert running["attempt"] == 1

    waiting = store.transition(
        "run_fixture",
        status="waiting_human",
        phase="review",
        waiting_for="review-decision",
    )
    assert waiting["waiting_for"] == "review-decision"
    resumed = store.resume("run_fixture", executor="codex")
    assert resumed["attempt"] == 2
    assert resumed["waiting_for"] is None

    cancelled = store.cancel("run_fixture")
    assert cancelled["status"] == "cancelled"
    assert store.cancel("run_fixture") == cancelled
    assert store.status("run_fixture") == cancelled
    with pytest.raises(RunError, match="terminal"):
        store.resume("run_fixture", executor="codex")


def test_create_is_anchored_when_runs_zone_is_swapped_before_child_mkdir(
    tmp_path, monkeypatch
):
    vault, resolver = _vault(tmp_path)
    store = RunStore(resolver, clock=_Clock())
    runs = vault / "agent/runs"
    saved = vault / "agent/runs-saved"
    outside = tmp_path / "outside-runs"
    outside.mkdir()
    real_mkdir = runs_store.os.mkdir
    swapped = False

    def swap_then_mkdir(path, mode=0o777, *, dir_fd=None):
        nonlocal swapped
        if path == "run_fixture" and dir_fd is not None and not swapped:
            swapped = True
            runs.rename(saved)
            os.symlink(outside, runs, target_is_directory=True)
        return real_mkdir(path, mode, dir_fd=dir_fd)

    monkeypatch.setattr(runs_store.os, "mkdir", swap_then_mkdir)
    with pytest.raises(RunError, match="anchored safely"):
        store.create(
            run_id="run_fixture",
            flow="distill",
            phase="collect",
            authority="proposal",
            executor="codex",
            input_data={},
        )
    assert list(outside.iterdir()) == []
    assert (saved / "run_fixture").is_dir()


def test_create_resumes_empty_pre_state_scaffolding_without_clobber(
    tmp_path, monkeypatch
):
    vault, resolver = _vault(tmp_path)
    store = RunStore(resolver, clock=_Clock())
    real_create = runs_store._create_json_once_at
    crashed = False

    def crash_before_state(directory_fd, name, payload):
        nonlocal crashed
        if name == "state.json" and not crashed:
            crashed = True
            raise _InjectedCrash()
        return real_create(directory_fd, name, payload)

    monkeypatch.setattr(runs_store, "_create_json_once_at", crash_before_state)
    with pytest.raises(_InjectedCrash):
        store.create(
            run_id="run_fixture",
            flow="distill",
            phase="collect",
            authority="proposal",
            executor="codex",
            input_data={},
        )
    run_dir = vault / "agent/runs/run_fixture"
    assert set(path.name for path in run_dir.iterdir()) == {
        ".run-lock",
        "intents",
        "trace.jsonl",
    }

    created = store.create(
        run_id="run_fixture",
        flow="distill",
        phase="collect",
        authority="proposal",
        executor="codex",
        input_data={},
    )
    assert created["status"] == "created"
    assert store.status("run_fixture") == created


def test_terminal_and_waiting_transitions_fail_closed(tmp_path):
    _, store = _store(tmp_path)
    _create_running(store)
    succeeded = store.transition("run_fixture", status="succeeded", phase="complete")
    assert succeeded["status"] == "succeeded"
    with pytest.raises(RunError, match="completed"):
        store.cancel("run_fixture")
    with pytest.raises(RunError, match="transition"):
        store.transition("run_fixture", status="running", phase="again")

    _, second = _store(tmp_path / "second")
    _create_running(second)
    with pytest.raises(RunError, match="waiting_for"):
        second.transition("run_fixture", status="waiting_human", phase="review")


def test_error_detail_is_hashed_and_never_persisted(tmp_path):
    vault, store = _store(tmp_path)
    _create_running(store)
    detail = "private transient diagnostic"
    state = store.transition(
        "run_fixture",
        status="transient_wait",
        phase="retry",
        error_kind="connector-timeout",
        error_detail=detail,
    )
    serialized = (vault / "agent/runs/run_fixture/state.json").read_text("utf-8")
    assert detail not in serialized
    assert (
        state["last_error"]["detail_hash"]
        == hashlib.sha256(detail.encode()).hexdigest()
    )
    assert (
        store.transition(
            "run_fixture",
            status="transient_wait",
            phase="retry",
            error_kind="connector-timeout",
            error_detail=detail,
        )
        == state
    )
    with pytest.raises(RunError, match="same-status replay"):
        store.transition(
            "run_fixture",
            status="transient_wait",
            phase="different",
            error_kind="connector-timeout",
            error_detail=detail,
        )


@pytest.mark.parametrize(
    "mutation",
    [
        lambda state: state.update(schema_version=True),
        lambda state: state.update(attempt=True),
        lambda state: state.update(status="unknown"),
        lambda state: state.update(run_id="../escape"),
        lambda state: state.update(flow="missing"),
        lambda state: state.update(authority="external-send"),
        lambda state: state.update(waiting_for="unexpected"),
        lambda state: state.update(extra=True),
    ],
)
def test_state_schema_is_exact_and_type_sensitive(tmp_path, mutation):
    _, store = _store(tmp_path)
    state = store.create(
        run_id="run_fixture",
        flow="distill",
        phase="collect",
        authority="proposal",
        executor="codex",
        input_data={},
    )
    mutation(state)
    with pytest.raises(RunError):
        validate_state(state)


def test_error_retryability_is_derived_from_status(tmp_path):
    _, store = _store(tmp_path)
    state = store.create(
        run_id="run_fixture",
        flow="distill",
        phase="collect",
        authority="proposal",
        executor="codex",
        input_data={},
    )
    state["status"] = "quota_wait"
    state["last_error"] = {
        "kind": "quota",
        "retryable": False,
        "detail_hash": ZERO_HASH,
    }
    with pytest.raises(RunError, match="retryable disagrees"):
        validate_state(state)


@pytest.mark.parametrize(
    "input_data",
    [
        {"api_token": "fixture-value"},
        {"nested": {"password": "fixture-value"}},
        {"source": "/" + "Users" + "/private/note.md"},
        {"source": "line\x00break"},
        {"source": "line\u0085break"},
        {"source": "line\u2028break"},
    ],
)
def test_state_rejects_secret_fields_private_paths_and_controls(tmp_path, input_data):
    _, store = _store(tmp_path)
    with pytest.raises(RunError):
        store.create(
            run_id="run_fixture",
            flow="distill",
            phase="collect",
            authority="proposal",
            executor="codex",
            input_data=input_data,
        )


def test_crash_after_prepare_reconciles_once_across_executor_change(tmp_path):
    vault, store = _store(tmp_path)
    _create_running(store)
    artifact = vault / "review" / "proposal.md"
    artifact.write_text("portable proposal\n", encoding="utf-8")
    artifact_hash = hashlib.sha256(artifact.read_bytes()).hexdigest()
    prepared = PreparedArtifact(
        "review",
        "review",
        "proposal.md",
        "review/proposal.md",
        artifact_hash,
    )
    outcome = ToolOutcome("llmwiki", "compatible", 0, "private tool detail")

    with pytest.raises(_InjectedCrash):
        store.commit_step(
            "run_fixture",
            step_id="create-review",
            authority="proposal",
            input_hash=ZERO_HASH,
            output_hash=artifact_hash,
            next_phase="review",
            next_status="waiting_human",
            waiting_for="review-decision",
            prepared_artifacts=[prepared],
            tool_outcomes=[outcome],
            after_prepare=lambda: (_ for _ in ()).throw(_InjectedCrash()),
        )

    before = store.status("run_fixture")
    assert before["phase"] == "collect"
    assert before["artifacts"] == {}
    intent = json.loads(
        (vault / "agent/runs/run_fixture/intents/create-review.json").read_text("utf-8")
    )
    assert intent["status"] == "prepared"

    resumed = store.resume("run_fixture", executor="claude")
    assert resumed["phase"] == "review"
    assert resumed["status"] == "running"
    assert resumed["executor"] == "claude"
    assert resumed["attempt"] == 2
    assert resumed["artifacts"] == {"review": "review/proposal.md"}

    trace_path = vault / "agent/runs/run_fixture/trace.jsonl"
    events = _trace(trace_path)
    assert [event["step_id"] for event in events] == ["create-review"]
    serialized = trace_path.read_text("utf-8")
    assert "private tool detail" not in serialized
    assert hashlib.sha256(b"private tool detail").hexdigest() in serialized
    assert events[0]["executor_profile"] == "codex"

    replayed = store.commit_step(
        "run_fixture",
        step_id="create-review",
        authority="proposal",
        input_hash=ZERO_HASH,
        output_hash=artifact_hash,
        next_phase="review",
        next_status="waiting_human",
        waiting_for="review-decision",
        prepared_artifacts=[prepared],
        tool_outcomes=[outcome],
    )
    assert replayed == resumed
    assert len(_trace(trace_path)) == 1


def test_snapshot_binds_current_state_to_exact_committed_artifact_bytes(tmp_path):
    vault, store = _store(tmp_path)
    _create_running(store)
    artifact = vault / "review/proposal.md"
    artifact.write_text("portable proposal\n", encoding="utf-8")
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    store.commit_step(
        "run_fixture",
        step_id="commit-review",
        authority="proposal",
        input_hash=ZERO_HASH,
        output_hash=digest,
        next_phase="validate",
        prepared_artifacts=[
            PreparedArtifact(
                "review", "review", "proposal.md", "review/proposal.md", digest
            )
        ],
    )

    snapshot = store.snapshot("run_fixture")

    assert (
        snapshot.state_sha256
        == hashlib.sha256(
            json.dumps(
                snapshot.state,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
    )
    assert snapshot.artifacts[0].name == "review"
    assert snapshot.artifacts[0].sha256 == digest
    assert snapshot.artifacts[0].step_id == "commit-review"

    artifact.write_text("changed after commit\n", encoding="utf-8")
    with pytest.raises(RunError, match="hash changed"):
        store.snapshot("run_fixture")


def test_commit_step_state_precondition_rejects_stale_finalize_without_residue(
    tmp_path,
):
    vault, store = _store(tmp_path)
    _create_running(store)
    stale = store.snapshot("run_fixture")
    store.commit_step(
        "run_fixture",
        step_id="concurrent-step",
        authority="proposal",
        input_hash=ZERO_HASH,
        output_hash=ONE_HASH,
        next_phase="changed",
    )
    before = store.status("run_fixture")

    with pytest.raises(RunError, match="caller snapshot"):
        store.commit_step(
            "run_fixture",
            step_id="stale-finalize",
            authority="internal-write",
            input_hash=stale.state_sha256,
            output_hash=ONE_HASH,
            next_phase="finalized",
            next_status="succeeded",
            expected_state_sha256=stale.state_sha256,
        )

    assert store.status("run_fixture") == before
    assert [item["step_id"] for item in store.trace_events("run_fixture")] == [
        "concurrent-step"
    ]
    assert not (vault / "agent/runs/run_fixture/intents/stale-finalize.json").exists()


def test_commit_step_replay_keeps_the_original_state_precondition(tmp_path):
    _vault, store = _store(tmp_path)
    _create_running(store)
    original = store.snapshot("run_fixture")
    store.commit_step(
        "run_fixture",
        step_id="preconditioned-step",
        authority="proposal",
        input_hash=ZERO_HASH,
        output_hash=ONE_HASH,
        next_phase="validated",
        expected_state_sha256=original.state_sha256,
    )

    with pytest.raises(RunError, match="caller state precondition"):
        store.commit_step(
            "run_fixture",
            step_id="preconditioned-step",
            authority="proposal",
            input_hash=ZERO_HASH,
            output_hash=ONE_HASH,
            next_phase="validated",
            expected_state_sha256=ZERO_HASH,
        )


def test_finalize_decision_artifact_requires_exact_cross_flow_finalize_trace(
    tmp_path: Path,
) -> None:
    vault, store = _store(tmp_path)
    store.create(
        run_id="run_lint_decision",
        flow="lint",
        phase="scan",
        authority="domain-write",
        executor="codex",
        input_data={"mode": "infra"},
    )
    store.resume("run_lint_decision", executor="codex")
    before = store.snapshot("run_lint_decision")
    decision_path = vault / "review/lintprop-forged.lint.json"
    decision_raw = b'{"canonical":"but-unbound"}\n'
    decision_path.write_bytes(decision_raw)

    with pytest.raises(RunError, match="exact cross-flow finalize trace"):
        store.commit_step(
            "run_lint_decision",
            step_id="forged-decision",
            authority="internal-write",
            input_hash=before.state_sha256,
            output_hash=hashlib.sha256(decision_raw).hexdigest(),
            next_phase="scan-complete",
            prepared_artifacts=(
                PreparedArtifact(
                    "finalize-decision",
                    "review",
                    decision_path.name,
                    f"review/{decision_path.name}",
                    hashlib.sha256(decision_raw).hexdigest(),
                ),
            ),
            expected_state_sha256=before.state_sha256,
        )

    assert store.status("run_lint_decision") == before.state
    assert store.trace_events("run_lint_decision") == ()
    assert not (
        vault / "agent/runs/run_lint_decision/intents/forged-decision.json"
    ).exists()


@pytest.mark.parametrize("source_mode", ["omitted", "recomputed", "original"])
def test_cross_flow_finalize_cannot_replace_committed_source_evidence(
    tmp_path: Path, source_mode: str
) -> None:
    vault, store = _store(tmp_path)
    _create_running(store)
    review = vault / "review/proposal.md"
    plan = vault / ".lifeos/review-plans/proposal.json"
    review_raw = b"original committed review\n"
    plan_raw = b'{"original":"committed plan"}\n'
    review.write_bytes(review_raw)
    plan.write_bytes(plan_raw)
    review_evidence = PreparedArtifact(
        "review",
        "review",
        review.name,
        "review/proposal.md",
        hashlib.sha256(review_raw).hexdigest(),
    )
    plan_evidence = PreparedArtifact(
        "plan",
        ".lifeos/review-plans",
        plan.name,
        ".lifeos/review-plans/proposal.json",
        hashlib.sha256(plan_raw).hexdigest(),
    )
    store.commit_step(
        "run_fixture",
        step_id="commit-proposal",
        authority="proposal",
        input_hash=ZERO_HASH,
        output_hash=hashlib.sha256(review_raw + plan_raw).hexdigest(),
        next_phase="validate",
        prepared_artifacts=(review_evidence, plan_evidence),
    )
    base = store.snapshot("run_fixture")

    corrupt_raw = b"caller-recomputed corrupt review\n"
    review.write_bytes(corrupt_raw)
    log_dir = vault / "agent/logs/finalize"
    metric_dir = vault / "agent/logs/metrics"
    log_dir.mkdir(parents=True, exist_ok=True)
    metric_dir.mkdir(parents=True, exist_ok=True)
    log = log_dir / "outcome_exploit.json"
    metric = metric_dir / "metric_exploit.json"
    event = vault / "agent/outbox/event_exploit.json"
    log.write_bytes(b'{"valid":"shaped log"}\n')
    metric.write_bytes(b'{"valid":"shaped metric"}\n')
    event.write_bytes(b'{"valid":"shaped event"}\n')
    sidecars = [
        PreparedArtifact(
            "finalize-log",
            "agent/logs",
            "finalize/outcome_exploit.json",
            "agent/logs/finalize/outcome_exploit.json",
            hashlib.sha256(log.read_bytes()).hexdigest(),
        ),
        PreparedArtifact(
            "finalize-metric",
            "agent/logs",
            "metrics/metric_exploit.json",
            "agent/logs/metrics/metric_exploit.json",
            hashlib.sha256(metric.read_bytes()).hexdigest(),
        ),
        PreparedArtifact(
            "finalize-event",
            "agent/outbox",
            event.name,
            f"agent/outbox/{event.name}",
            hashlib.sha256(event.read_bytes()).hexdigest(),
        ),
    ]
    if source_mode == "recomputed":
        sidecars.extend(
            (
                PreparedArtifact(
                    "review",
                    "review",
                    review.name,
                    "review/proposal.md",
                    hashlib.sha256(corrupt_raw).hexdigest(),
                ),
                plan_evidence,
            )
        )
    elif source_mode == "original":
        sidecars.extend((review_evidence, plan_evidence))
    policy = AuthorityPolicy()
    action_specs = (
        ("validate-run-artifacts", "read", "vault:agent/runs"),
        ("read-review-outcome", "read", "vault:review"),
        ("append-domain-log", "internal-write", "vault:agent/logs"),
        ("append-run-trace", "internal-write", "vault:agent/runs/trace"),
        (
            "commit-bounded-metrics",
            "internal-write",
            "vault:agent/logs/metrics",
        ),
        (
            "emit-semantic-outbox-event",
            "internal-write",
            "vault:agent/outbox",
        ),
        ("finalize-run-state", "internal-write", "vault:agent/runs"),
    )
    actions = tuple(
        ActionUse(
            policy.issue(
                flow_id="finalize",
                action_id=action_id,
                actor="runtime",
                authority=authority,
                target=target,
            )
        )
        for action_id, authority, target in action_specs
    )

    with pytest.raises(
        RunError,
        match=(
            "source artifact roles|committed base artifact|"
            "hash changed before state commit"
        ),
    ):
        store.commit_step(
            "run_fixture",
            step_id="finalize-complete",
            authority="internal-write",
            input_hash=base.state_sha256,
            output_hash=sidecars[0].sha256,
            next_phase="finalized",
            next_status="succeeded",
            prepared_artifacts=sidecars,
            expected_state_sha256=base.state_sha256,
            action_uses=actions,
            authority_policy=policy,
        )

    assert store.status("run_fixture")["status"] == "running"
    assert not (
        vault / "agent/runs/run_fixture/intents/finalize-complete.json"
    ).exists()


@pytest.mark.parametrize(
    "source_flow",
    ["book", "mentor", "grill-me", "lint", "ambient", "bundle"],
)
def test_p3_cross_flow_finalize_requires_complete_latest_producer_bundle(
    tmp_path: Path,
    source_flow: str,
) -> None:
    vault, store = _store(tmp_path)
    authority = {
        "book": "domain-write",
        "mentor": "proposal",
        "grill-me": "proposal",
        "lint": "domain-write",
        "ambient": "internal-write",
        "bundle": "internal-write",
    }[source_flow]
    store.create(
        run_id="run_book_bundle",
        flow=source_flow,
        phase="reading",
        authority=authority,
        executor="codex",
        input_data={"slug": "bundle"},
    )
    store.resume("run_book_bundle", executor="codex")
    evidence = store.prepare_run_artifact(
        "run_book_bundle", name="book-evidence", data=b'{"evidence":true}\n'
    )
    companion = store.prepare_run_artifact(
        "run_book_bundle", name="book-plan", data=b'{"plan":true}\n'
    )
    store.commit_step(
        "run_book_bundle",
        step_id="book-producer",
        authority=authority,
        input_hash=ZERO_HASH,
        output_hash=evidence.sha256,
        next_phase="review",
        prepared_artifacts=(evidence, companion),
    )
    base = store.snapshot("run_book_bundle")

    sidecar_specs = (
        (
            "finalize-log",
            "agent/logs",
            "finalize/outcome_bundle.json",
            "agent/logs/finalize/outcome_bundle.json",
        ),
        (
            "finalize-metric",
            "agent/logs",
            "metrics/metric_bundle.json",
            "agent/logs/metrics/metric_bundle.json",
        ),
        (
            "finalize-event",
            "agent/outbox",
            "event_bundle.json",
            "agent/outbox/event_bundle.json",
        ),
    )
    sidecars = []
    for name, zone, relative, state_ref in sidecar_specs:
        path = vault / state_ref
        path.parent.mkdir(parents=True, exist_ok=True)
        raw = (json.dumps({"sidecar": name}, sort_keys=True) + "\n").encode()
        path.write_bytes(raw)
        sidecars.append(
            PreparedArtifact(
                name, zone, relative, state_ref, hashlib.sha256(raw).hexdigest()
            )
        )

    policy = AuthorityPolicy()
    action_specs = (
        ("validate-run-artifacts", "read", "vault:agent/runs"),
        ("read-review-outcome", "read", "vault:review"),
        ("append-domain-log", "internal-write", "vault:agent/logs"),
        ("append-run-trace", "internal-write", "vault:agent/runs/trace"),
        ("commit-bounded-metrics", "internal-write", "vault:agent/logs/metrics"),
        ("emit-semantic-outbox-event", "internal-write", "vault:agent/outbox"),
        ("finalize-run-state", "internal-write", "vault:agent/runs"),
    )
    actions = tuple(
        ActionUse(
            policy.issue(
                flow_id="finalize",
                action_id=action_id,
                actor="runtime",
                authority=authority,
                target=target,
            )
        )
        for action_id, authority, target in action_specs
    )

    with pytest.raises(RunError, match="complete latest producer step"):
        store.commit_step(
            "run_book_bundle",
            step_id="finalize-complete",
            authority="internal-write",
            input_hash=base.state_sha256,
            output_hash=sidecars[0].sha256,
            next_phase="finalized",
            next_status="succeeded",
            prepared_artifacts=(evidence, *sidecars),
            expected_state_sha256=base.state_sha256,
            action_uses=actions,
            authority_policy=policy,
        )

    assert store.status("run_book_bundle")["status"] == "running"
    assert not (
        vault / "agent/runs/run_book_bundle/intents/finalize-complete.json"
    ).exists()


@pytest.mark.parametrize("terminal", ["succeeded", "waiting_human"])
def test_direct_book_finalize_accepts_one_strict_reconstructed_decision(
    tmp_path: Path, terminal: str
) -> None:
    (
        vault,
        store,
        run_id,
        review,
        plan,
        review_path,
        _plan_path,
        evidence,
        review_evidence,
        plan_evidence,
    ) = _book_rebind_bundle(tmp_path)
    base = store.snapshot(run_id)
    decision = ReviewDecision(
        DECISION_SCHEMA_VERSION,
        1,
        "approve",
        "human",
        "2026-01-15T10:00:00Z",
        mutation_plan_sha256(plan),
    )
    decided = replace(review, status="approved", decisions=(decision,))
    decided_raw = render_review_artifact(decided).encode()
    review_path.write_bytes(decided_raw)
    current_review = replace(
        review_evidence, sha256=hashlib.sha256(decided_raw).hexdigest()
    )
    sidecars = _finalize_sidecars(vault, terminal)
    policy = AuthorityPolicy()
    step_id = (
        "finalize-complete" if terminal == "succeeded" else "finalize-review-ready"
    )
    state = store.commit_step(
        run_id,
        step_id=step_id,
        authority="internal-write",
        input_hash=base.state_sha256,
        output_hash=sidecars[0].sha256,
        next_phase="finalized" if terminal == "succeeded" else "review",
        next_status=terminal,
        waiting_for=None if terminal == "succeeded" else "review-decision",
        prepared_artifacts=(
            evidence,
            current_review,
            plan_evidence,
            *sidecars,
        ),
        expected_state_sha256=base.state_sha256,
        action_uses=_finalize_actions(policy),
        authority_policy=policy,
    )

    assert state["status"] == terminal
    assert state["artifacts"][review_evidence.name] == review_evidence.state_ref
    assert store.trace_events(run_id)[-1]["step_id"] == step_id


@pytest.mark.parametrize("terminal", ["succeeded", "waiting_human"])
@pytest.mark.parametrize(
    "mutation", ["body", "provenance", "plan", "status", "stale-decision"]
)
def test_direct_book_finalize_rejects_non_decision_rebind_before_intent_or_state(
    tmp_path: Path, terminal: str, mutation: str
) -> None:
    (
        vault,
        store,
        run_id,
        review,
        plan,
        review_path,
        plan_path,
        evidence,
        review_evidence,
        plan_evidence,
    ) = _book_rebind_bundle(tmp_path)
    base = store.snapshot(run_id)
    before_state = store.status(run_id)
    before_state_raw = (vault / f"agent/runs/{run_id}/state.json").read_bytes()
    before_trace = store.trace_events(run_id)
    plan_hash = mutation_plan_sha256(plan)
    first = ReviewDecision(
        DECISION_SCHEMA_VERSION,
        1,
        "approve",
        "human",
        "2026-01-15T10:00:00Z",
        plan_hash,
    )
    decided = replace(review, status="approved", decisions=(first,))
    current_plan = plan
    if mutation == "body":
        current_review_raw = render_review_artifact(
            replace(decided, body="# Mutated bounded anchor\n")
        ).encode()
    elif mutation == "provenance":
        current_review_raw = render_review_artifact(
            replace(
                decided,
                provenance=Provenance(
                    review.provenance.run_id,
                    ((review.sources[0].ref, ONE_HASH),),
                ),
            )
        ).encode()
    elif mutation == "plan":
        changed_content = "# Different accepted anchor\n"
        changed_operation = replace(
            plan.operations[0],
            content=changed_content,
            postcondition_sha256=hashlib.sha256(changed_content.encode()).hexdigest(),
        )
        current_plan = replace(plan, operations=(changed_operation,))
        current_review_raw = render_review_artifact(
            replace(
                decided,
                decisions=(
                    replace(first, plan_sha256=mutation_plan_sha256(current_plan)),
                ),
            )
        ).encode()
    elif mutation == "status":
        current_review_raw = (
            render_review_artifact(review)
            .replace('status: "proposed"', 'status: "approved"')
            .encode()
        )
    else:
        second = ReviewDecision(
            DECISION_SCHEMA_VERSION,
            2,
            "reject",
            "human",
            "2026-01-15T11:00:00Z",
            plan_hash,
        )
        current_review_raw = render_review_artifact(
            replace(decided, status="rejected", decisions=(first, second))
        ).encode()
    current_plan_raw = render_mutation_plan(current_plan)
    review_path.write_bytes(current_review_raw)
    plan_path.write_bytes(current_plan_raw)
    current_review = replace(
        review_evidence,
        sha256=hashlib.sha256(current_review_raw).hexdigest(),
    )
    current_plan_evidence = replace(
        plan_evidence,
        sha256=hashlib.sha256(current_plan_raw).hexdigest(),
    )
    sidecars = _finalize_sidecars(vault, f"{mutation}_{terminal}")
    policy = AuthorityPolicy()
    step_id = (
        "finalize-complete" if terminal == "succeeded" else "finalize-review-ready"
    )

    with pytest.raises(RunError):
        store.commit_step(
            run_id,
            step_id=step_id,
            authority="internal-write",
            input_hash=base.state_sha256,
            output_hash=sidecars[0].sha256,
            next_phase="finalized" if terminal == "succeeded" else "review",
            next_status=terminal,
            waiting_for=None if terminal == "succeeded" else "review-decision",
            prepared_artifacts=(
                evidence,
                current_review,
                current_plan_evidence,
                *sidecars,
            ),
            expected_state_sha256=base.state_sha256,
            action_uses=_finalize_actions(policy),
            authority_policy=policy,
        )

    assert store.status(run_id) == before_state
    assert (vault / f"agent/runs/{run_id}/state.json").read_bytes() == before_state_raw
    assert store.trace_events(run_id) == before_trace
    assert not (vault / f"agent/runs/{run_id}/intents/{step_id}.json").exists()


def test_failed_step_and_trace_v2_bind_only_policy_issued_actions(tmp_path):
    vault, store = _store(tmp_path)
    _create_running(store)
    policy = AuthorityPolicy()
    validate = policy.issue(
        flow_id="distill",
        action_id="read-validated-claims",
        actor="runtime",
        authority="read",
        target="machine-topic:validated-claims",
    )
    finalize = policy.issue(
        flow_id="distill",
        action_id="commit-review-proposal",
        actor="runtime",
        authority="proposal",
        target="vault:review",
    )
    detail = "/" + "Users" + "/private/corrupt artifact"

    state = store.commit_step(
        "run_fixture",
        step_id="finalize-failed",
        authority="proposal",
        input_hash=ZERO_HASH,
        output_hash=ONE_HASH,
        next_phase="finalized",
        next_status="failed",
        error_kind="artifact-invalid",
        error_detail=detail,
        action_uses=(ActionUse(validate, "failed"), ActionUse(finalize)),
        authority_policy=policy,
    )

    assert state["status"] == "failed"
    assert state["last_error"] == {
        "kind": "artifact-invalid",
        "retryable": False,
        "detail_hash": hashlib.sha256(detail.encode("utf-8")).hexdigest(),
    }
    trace = store.trace_events("run_fixture")[0]
    assert trace["schema_version"] == 2
    assert [item["action_id"] for item in trace["actions"]] == [
        "read-validated-claims",
        "commit-review-proposal",
    ]
    assert [item["status"] for item in trace["actions"]] == [
        "failed",
        "succeeded",
    ]
    assert detail not in (vault / "agent/runs/run_fixture/trace.jsonl").read_text(
        "utf-8"
    )

    other_policy = AuthorityPolicy()
    with pytest.raises(RunError, match="not issued"):
        # A fresh run is unnecessary: capability validation occurs before locking.
        store.commit_step(
            "run_fixture",
            step_id="forged-action",
            authority="proposal",
            input_hash=ZERO_HASH,
            output_hash=ONE_HASH,
            next_phase="finalized",
            action_uses=(ActionUse(validate),),
            authority_policy=other_policy,
        )


def test_crash_after_state_update_recovers_missing_trace_without_duplicate(tmp_path):
    vault, store = _store(tmp_path)
    _create_running(store)
    artifact = vault / "review" / "proposal.md"
    artifact.write_text("proposal\n", encoding="utf-8")
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()

    with pytest.raises(_InjectedCrash):
        store.commit_step(
            "run_fixture",
            step_id="commit-proposal",
            authority="proposal",
            input_hash=ZERO_HASH,
            output_hash=digest,
            next_phase="validate",
            prepared_artifacts=[
                PreparedArtifact(
                    "review", "review", "proposal.md", "review/proposal.md", digest
                )
            ],
            after_state=lambda: (_ for _ in ()).throw(_InjectedCrash()),
        )

    assert store.status("run_fixture")["phase"] == "validate"
    assert _trace(vault / "agent/runs/run_fixture/trace.jsonl") == []
    assert store.reconcile("run_fixture") == 1
    assert [
        event["step_id"]
        for event in _trace(vault / "agent/runs/run_fixture/trace.jsonl")
    ] == ["commit-proposal"]
    assert store.reconcile("run_fixture") == 0
    assert len(_trace(vault / "agent/runs/run_fixture/trace.jsonl")) == 1


def test_commit_step_cannot_exceed_immutable_run_authority(tmp_path):
    vault, store = _store(tmp_path)
    store.create(
        run_id="run_read_only",
        flow="distill",
        phase="collect",
        authority="read",
        executor="codex",
        input_data={},
    )
    store.resume("run_read_only", executor="codex")

    with pytest.raises(RunError, match="exceeds the immutable run authority"):
        store.commit_step(
            "run_read_only",
            step_id="elevated-proposal",
            authority="proposal",
            input_hash=ZERO_HASH,
            output_hash=ONE_HASH,
            next_phase="review",
        )

    assert store.status("run_read_only")["phase"] == "collect"
    assert _trace(vault / "agent/runs/run_read_only/trace.jsonl") == []
    assert not list((vault / "agent/runs/run_read_only/intents").glob("*.json"))


def test_real_process_exit_after_prepare_is_reconciled(tmp_path):
    vault, store = _store(tmp_path)
    _create_running(store)
    artifact = vault / "review" / "proposal.md"
    artifact.write_text("proposal\n", encoding="utf-8")
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    context = multiprocessing.get_context("fork")
    child = context.Process(target=_crash_after_prepare, args=(str(vault), digest))
    child.start()
    child.join(timeout=5)
    assert child.exitcode == 79
    assert store.status("run_fixture")["phase"] == "collect"

    resumed = store.resume("run_fixture", executor="claude")
    assert resumed["phase"] == "validate"
    assert resumed["executor"] == "claude"
    assert resumed["attempt"] == 2
    assert [
        event["step_id"]
        for event in _trace(vault / "agent/runs/run_fixture/trace.jsonl")
    ] == ["child-prepare"]


def test_crash_after_trace_before_intent_commit_does_not_duplicate_trace(tmp_path):
    vault, store = _store(tmp_path)
    _create_running(store)
    artifact = vault / "review" / "proposal.md"
    artifact.write_text("proposal\n", encoding="utf-8")
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    with pytest.raises(_InjectedCrash):
        store.commit_step(
            "run_fixture",
            step_id="commit-proposal",
            authority="proposal",
            input_hash=ZERO_HASH,
            output_hash=digest,
            next_phase="validate",
            prepared_artifacts=[
                PreparedArtifact(
                    "review", "review", "proposal.md", "review/proposal.md", digest
                )
            ],
            after_trace=lambda: (_ for _ in ()).throw(_InjectedCrash()),
        )
    intent_path = vault / "agent/runs/run_fixture/intents/commit-proposal.json"
    assert json.loads(intent_path.read_text("utf-8"))["status"] == "prepared"
    assert len(_trace(vault / "agent/runs/run_fixture/trace.jsonl")) == 1
    assert store.reconcile("run_fixture") == 1
    assert json.loads(intent_path.read_text("utf-8"))["status"] == "committed"
    assert len(_trace(vault / "agent/runs/run_fixture/trace.jsonl")) == 1


def test_new_step_first_reconciles_the_only_prepared_intent(tmp_path):
    vault, store = _store(tmp_path)
    _create_running(store)
    with pytest.raises(_InjectedCrash):
        store.commit_step(
            "run_fixture",
            step_id="first",
            authority="proposal",
            input_hash=ZERO_HASH,
            output_hash=ONE_HASH,
            next_phase="validate",
            after_prepare=lambda: (_ for _ in ()).throw(_InjectedCrash()),
        )

    state = store.commit_step(
        "run_fixture",
        step_id="second",
        authority="proposal",
        input_hash=ONE_HASH,
        output_hash=ZERO_HASH,
        next_phase="review",
    )
    assert state["phase"] == "review"
    assert [
        event["step_id"]
        for event in _trace(vault / "agent/runs/run_fixture/trace.jsonl")
    ] == ["first", "second"]
    intents = vault / "agent/runs/run_fixture/intents"
    assert {
        path.stem: json.loads(path.read_text("utf-8"))["status"]
        for path in intents.glob("*.json")
    } == {"first": "committed", "second": "committed"}


def test_torn_trace_tail_after_state_commit_is_preserved_and_reconciled(tmp_path):
    vault, store = _store(tmp_path)
    _create_running(store)
    trace_path = vault / "agent/runs/run_fixture/trace.jsonl"
    torn = b'{"incomplete":'

    def write_torn_tail() -> None:
        descriptor = os.open(trace_path, os.O_WRONLY | os.O_APPEND)
        try:
            os.write(descriptor, torn)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        raise _InjectedCrash()

    with pytest.raises(_InjectedCrash):
        store.commit_step(
            "run_fixture",
            step_id="torn-step",
            authority="proposal",
            input_hash=ZERO_HASH,
            output_hash=ONE_HASH,
            next_phase="validate",
            after_state=write_torn_tail,
        )

    assert store.status("run_fixture")["phase"] == "validate"
    assert trace_path.read_bytes() == torn
    assert store.reconcile("run_fixture") == 1
    assert [event["step_id"] for event in _trace(trace_path)] == ["torn-step"]
    evidence = list((trace_path.parent / "trace-recovery").glob("torn-*.bin"))
    assert len(evidence) == 1
    assert evidence[0].read_bytes() == torn
    assert store.reconcile("run_fixture") == 0


def test_complete_trace_event_missing_only_newline_is_kept_during_reconcile(tmp_path):
    vault, store = _store(tmp_path)
    _create_running(store)
    with pytest.raises(_InjectedCrash):
        store.commit_step(
            "run_fixture",
            step_id="complete-tail",
            authority="proposal",
            input_hash=ZERO_HASH,
            output_hash=ONE_HASH,
            next_phase="validate",
            after_prepare=lambda: (_ for _ in ()).throw(_InjectedCrash()),
        )
    intent = json.loads(
        (vault / "agent/runs/run_fixture/intents/complete-tail.json").read_text("utf-8")
    )
    trace_path = vault / "agent/runs/run_fixture/trace.jsonl"
    trace_path.write_text(
        json.dumps(intent["trace_event"], sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )

    assert store.reconcile("run_fixture") == 1
    assert [event["step_id"] for event in _trace(trace_path)] == ["complete-tail"]
    assert trace_path.read_bytes().endswith(b"\n")
    assert not (trace_path.parent / "trace-recovery").exists()


def test_changed_prepared_artifact_blocks_state_commit(tmp_path):
    vault, store = _store(tmp_path)
    _create_running(store)
    artifact = vault / "review" / "proposal.md"
    artifact.write_text("before\n", encoding="utf-8")
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    with pytest.raises(_InjectedCrash):
        store.commit_step(
            "run_fixture",
            step_id="commit-proposal",
            authority="proposal",
            input_hash=ZERO_HASH,
            output_hash=digest,
            next_phase="validate",
            prepared_artifacts=[
                PreparedArtifact(
                    "review", "review", "proposal.md", "review/proposal.md", digest
                )
            ],
            after_prepare=lambda: (_ for _ in ()).throw(_InjectedCrash()),
        )
    artifact.write_text("tampered\n", encoding="utf-8")
    with pytest.raises(RunError, match="hash changed"):
        store.reconcile("run_fixture")
    assert store.status("run_fixture")["phase"] == "collect"


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("authority", "authority is outside"),
        ("timestamp", "timestamp disagrees"),
        ("executor", "immutable run state"),
        ("artifact", "artifacts disagree"),
    ],
)
def test_forged_intent_cross_fields_fail_closed(tmp_path, mutation, message):
    vault, store = _store(tmp_path)
    _create_running(store)
    with pytest.raises(_InjectedCrash):
        store.commit_step(
            "run_fixture",
            step_id="forged-intent",
            authority="proposal",
            input_hash=ZERO_HASH,
            output_hash=ONE_HASH,
            next_phase="validate",
            after_prepare=lambda: (_ for _ in ()).throw(_InjectedCrash()),
        )
    path = vault / "agent/runs/run_fixture/intents/forged-intent.json"
    intent = json.loads(path.read_text("utf-8"))
    if mutation == "authority":
        intent["trace_event"]["authority"] = "external-send"
    elif mutation == "timestamp":
        intent["trace_event"]["at"] = "2026-01-15T10:00:00Z"
    elif mutation == "executor":
        intent["target_state"]["executor"] = "claude"
        intent["trace_event"]["executor_profile"] = "claude"
    else:
        intent["target_state"]["artifacts"] = {"injected": "review/foreign.md"}
    path.write_text(json.dumps(intent, sort_keys=True) + "\n", encoding="utf-8")

    with pytest.raises(RunError, match=message):
        store.reconcile("run_fixture")
    assert store.status("run_fixture")["phase"] == "collect"


def test_run_directory_symlink_swap_after_prepare_is_rejected_before_state_write(
    tmp_path,
):
    vault, store = _store(tmp_path)
    _create_running(store)
    artifact = vault / "review" / "proposal.md"
    artifact.write_text("proposal\n", encoding="utf-8")
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    run_dir = vault / "agent/runs/run_fixture"
    saved = vault / "agent/runs/run_fixture-saved"
    outside = tmp_path / "outside-run"
    outside.mkdir()

    def swap() -> None:
        run_dir.rename(saved)
        run_dir.symlink_to(outside, target_is_directory=True)

    with pytest.raises(RunError, match="changed during"):
        store.commit_step(
            "run_fixture",
            step_id="commit-proposal",
            authority="proposal",
            input_hash=ZERO_HASH,
            output_hash=digest,
            next_phase="validate",
            prepared_artifacts=[
                PreparedArtifact(
                    "review", "review", "proposal.md", "review/proposal.md", digest
                )
            ],
            after_prepare=swap,
        )
    assert list(outside.iterdir()) == []
    run_dir.unlink()
    saved.rename(run_dir)
    assert store.status("run_fixture")["phase"] == "collect"
    assert store.reconcile("run_fixture") == 1


def test_prepared_hash_uses_anchored_zone_parent_during_temporary_swap(
    tmp_path, monkeypatch
):
    vault, store = _store(tmp_path)
    _create_running(store)
    artifact = vault / "review/proposal.md"
    artifact.write_text("authoritative\n", encoding="utf-8")
    saved_review = vault / "review-saved"
    outside_review = tmp_path / "outside-review"
    outside_review.mkdir()
    foreign = outside_review / "proposal.md"
    foreign.write_text("foreign\n", encoding="utf-8")
    foreign_hash = hashlib.sha256(foreign.read_bytes()).hexdigest()
    real_open = runs_store.os.open
    swapped = False

    def temporary_swap(path, flags, mode=0o777, *, dir_fd=None):
        nonlocal swapped
        if path == "proposal.md" and dir_fd is not None and not swapped:
            swapped = True
            (vault / "review").rename(saved_review)
            (vault / "review").symlink_to(outside_review, target_is_directory=True)
            try:
                return real_open(path, flags, mode, dir_fd=dir_fd)
            finally:
                (vault / "review").unlink()
                saved_review.rename(vault / "review")
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(runs_store.os, "open", temporary_swap)
    with pytest.raises(RunError, match="hash changed"):
        store.commit_step(
            "run_fixture",
            step_id="swapped-artifact",
            authority="proposal",
            input_hash=ZERO_HASH,
            output_hash=foreign_hash,
            next_phase="validate",
            prepared_artifacts=[
                PreparedArtifact(
                    "review",
                    "review",
                    "proposal.md",
                    "review/proposal.md",
                    foreign_hash,
                )
            ],
        )
    assert store.status("run_fixture")["phase"] == "collect"


def test_prepared_artifact_reference_must_match_resolved_zone_path(tmp_path):
    vault, store = _store(tmp_path)
    _create_running(store)
    artifact = vault / "review" / "proposal.md"
    artifact.write_text("proposal\n", encoding="utf-8")
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    with pytest.raises(RunError, match="state reference disagrees"):
        store.commit_step(
            "run_fixture",
            step_id="commit-proposal",
            authority="proposal",
            input_hash=ZERO_HASH,
            output_hash=digest,
            next_phase="validate",
            prepared_artifacts=[
                PreparedArtifact(
                    "review", "review", "proposal.md", "projects/unrelated.md", digest
                )
            ],
        )
    assert not (vault / "agent/runs/run_fixture/intents/commit-proposal.json").exists()
    assert store.status("run_fixture")["phase"] == "collect"


def test_replay_with_same_step_id_but_different_evidence_fails(tmp_path):
    vault, store = _store(tmp_path)
    _create_running(store)
    artifact = vault / "review" / "proposal.md"
    artifact.write_text("proposal\n", encoding="utf-8")
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    prepared = [
        PreparedArtifact(
            "review", "review", "proposal.md", "review/proposal.md", digest
        )
    ]
    store.commit_step(
        "run_fixture",
        step_id="commit-proposal",
        authority="proposal",
        input_hash=ZERO_HASH,
        output_hash=digest,
        next_phase="validate",
        prepared_artifacts=prepared,
    )
    with pytest.raises(RunError, match="disagrees"):
        store.commit_step(
            "run_fixture",
            step_id="commit-proposal",
            authority="proposal",
            input_hash=ONE_HASH,
            output_hash=digest,
            next_phase="validate",
            prepared_artifacts=prepared,
        )


def test_status_ignores_trace_and_projection_because_state_is_authoritative(tmp_path):
    vault, store = _store(tmp_path)
    expected = _create_running(store)
    (vault / "agent/runs/run_fixture/trace.jsonl").write_text("{torn", encoding="utf-8")
    projection = vault / "agent/dashboard/runs/run_fixture.md"
    projection.parent.mkdir()
    projection.write_text("manually edited", encoding="utf-8")

    assert store.status("run_fixture") == expected
    with pytest.raises(RunError, match="trace contains invalid"):
        store.trace_events("run_fixture")


def test_status_is_read_only_for_run_files(tmp_path):
    vault, store = _store(tmp_path)
    expected = _create_running(store)
    run_dir = vault / "agent/runs/run_fixture"
    before = {
        path.name: (path.stat().st_mtime_ns, path.stat().st_size)
        for path in run_dir.iterdir()
        if path.is_file()
    }
    assert store.status("run_fixture") == expected
    after = {
        path.name: (path.stat().st_mtime_ns, path.stat().st_size)
        for path in run_dir.iterdir()
        if path.is_file()
    }
    assert after == before


def test_resume_does_not_depend_on_missing_trace_after_committed_step(tmp_path):
    vault, store = _store(tmp_path)
    _create_running(store)
    artifact = vault / "review" / "proposal.md"
    artifact.write_text("proposal\n", encoding="utf-8")
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    store.commit_step(
        "run_fixture",
        step_id="commit-proposal",
        authority="proposal",
        input_hash=ZERO_HASH,
        output_hash=digest,
        next_phase="validate",
        prepared_artifacts=[
            PreparedArtifact(
                "review", "review", "proposal.md", "review/proposal.md", digest
            )
        ],
    )
    store.transition(
        "run_fixture",
        status="transient_wait",
        phase="retry",
        error_kind="executor-interrupted",
    )
    (vault / "agent/runs/run_fixture/trace.jsonl").unlink()

    resumed = store.resume("run_fixture", executor="claude")
    assert resumed["status"] == "running"
    assert resumed["phase"] == "retry"
    assert resumed["artifacts"] == {"review": "review/proposal.md"}
    with pytest.raises(RunError, match="trace cannot be read"):
        store.trace_events("run_fixture")


def test_torn_or_duplicate_state_fails_closed(tmp_path):
    vault, store = _store(tmp_path)
    _create_running(store)
    state_path = vault / "agent/runs/run_fixture/state.json"
    state_path.write_text('{"schema_version":1', encoding="utf-8")
    with pytest.raises(RunError, match="valid JSON"):
        store.status("run_fixture")

    state_path.write_text('{"schema_version":1,"schema_version":1}', encoding="utf-8")
    with pytest.raises(RunError, match="duplicate"):
        store.status("run_fixture")


@pytest.mark.parametrize(
    "malformed",
    [
        '{"schema_version":' + "9" * 5000 + "}",
        "[" * 10000 + "]" * 10000,
    ],
)
def test_state_decoder_normalizes_huge_integer_and_deep_json(tmp_path, malformed):
    vault, store = _store(tmp_path)
    _create_running(store)
    (vault / "agent/runs/run_fixture/state.json").write_text(
        malformed, encoding="utf-8"
    )
    with pytest.raises(RunError, match="not valid JSON|must be an object"):
        store.status("run_fixture")


def test_trace_decoder_normalizes_deep_json(tmp_path):
    vault, store = _store(tmp_path)
    _create_running(store)
    (vault / "agent/runs/run_fixture/trace.jsonl").write_text(
        "[" * 5000 + "]" * 5000 + "\n", encoding="utf-8"
    )
    with pytest.raises(RunError, match="invalid JSON|must be an object"):
        store.trace_events("run_fixture")


def test_two_process_writers_have_one_winning_lock(tmp_path):
    vault, store = _store(tmp_path)
    _create_running(store)
    context = multiprocessing.get_context("fork")
    queue = context.Queue()
    with store._locked("run_fixture"):
        contender = context.Process(target=_lock_contender, args=(str(vault), queue))
        contender.start()
        contender.join(timeout=5)
        assert contender.exitcode == 0
        assert queue.get(timeout=1) == "busy"

    winner = context.Process(target=_lock_contender, args=(str(vault), queue))
    winner.start()
    winner.join(timeout=5)
    assert winner.exitcode == 0
    assert queue.get(timeout=1) == "acquired"


def test_named_run_directory_replacement_cannot_create_a_second_lock_owner(tmp_path):
    vault, store = _store(tmp_path)
    _create_running(store)
    run_dir = vault / "agent/runs/run_fixture"
    saved = vault / "agent/runs/run_fixture-saved"
    context = multiprocessing.get_context("fork")
    queue = context.Queue()
    with store._locked("run_fixture"):
        run_dir.rename(saved)
        run_dir.mkdir()
        with pytest.raises(RunLockBusy):
            with store._locked("run_fixture"):
                pytest.fail("same-process replacement acquired a second lock")
        contender = context.Process(target=_lock_contender, args=(str(vault), queue))
        contender.start()
        contender.join(timeout=5)
        assert contender.exitcode == 0
        assert queue.get(timeout=1) == "busy"
    run_dir.rmdir()
    saved.rename(run_dir)


def test_replacing_both_lock_evidence_leaves_cannot_bypass_namespace_guard(tmp_path):
    vault, store = _store(tmp_path)
    _create_running(store)
    run_dir = vault / "agent/runs/run_fixture"
    lock_name = hashlib.sha256(b"run_fixture").hexdigest() + ".lock"
    stable = vault / "agent/runs/.locks" / lock_name
    local = run_dir / ".run-lock"
    context = multiprocessing.get_context("fork")
    queue = context.Queue()
    with store._locked("run_fixture"):
        stable.unlink()
        local.unlink()
        stable.write_bytes(b"")
        os.link(stable, local)
        with pytest.raises(RunLockBusy):
            with store._locked("run_fixture"):
                pytest.fail("replacement evidence bypassed the namespace guard")
        contender = context.Process(target=_lock_contender, args=(str(vault), queue))
        contender.start()
        contender.join(timeout=5)
        assert contender.exitcode == 0
        assert queue.get(timeout=1) == "busy"


def test_unlinking_a_legacy_named_lock_cannot_bypass_directory_lock(tmp_path):
    vault, store = _store(tmp_path)
    _create_running(store)
    context = multiprocessing.get_context("fork")
    queue = context.Queue()
    legacy_lock = vault / "agent/runs/run_fixture/writer.lock"
    legacy_lock.write_text("not-authoritative\n", encoding="utf-8")
    with store._locked("run_fixture"):
        legacy_lock.unlink()
        contender = context.Process(target=_lock_contender, args=(str(vault), queue))
        contender.start()
        contender.join(timeout=5)
        assert contender.exitcode == 0
        assert queue.get(timeout=1) == "busy"


def test_same_process_second_file_description_cannot_reenter_lock(tmp_path):
    _, store = _store(tmp_path)
    _create_running(store)
    with store._locked("run_fixture"):
        with pytest.raises(RunLockBusy):
            with store._locked("run_fixture"):
                pytest.fail("second writer entered the same run")
        store._revalidate_run_path(
            tmp_path / "vault/agent/runs/run_fixture", "run_fixture"
        )


def test_receipt_projection_state_and_trace_are_separate_schemas(tmp_path):
    vault, store = _store(tmp_path)
    state = _create_running(store)
    receipt = store.record_receipt(
        "run_fixture",
        receipt_id="receipt_fixture",
        event_id="event_fixture",
        status="delivered",
        effect_hash=ONE_HASH,
    )
    projection = store.write_projection("run_fixture")

    receipt_path = vault / "agent/outbox/receipts/receipt_fixture.json"
    assert json.loads(receipt_path.read_text("utf-8")) == receipt
    assert validate_receipt(receipt) == receipt
    assert projection == vault / "agent/dashboard/runs/run_fixture.md"
    assert "lifeos-run-projection-schema: 1" in projection.read_text("utf-8")
    assert "source-state-sha256" in projection.read_text("utf-8")
    assert store.status("run_fixture") == state
    assert "receipt_id" not in state
    assert "source-state-sha256" not in json.dumps(state)
    assert set(receipt) != set(state)

    again = store.record_receipt(
        "run_fixture",
        receipt_id="receipt_fixture",
        event_id="event_fixture",
        status="delivered",
        effect_hash=ONE_HASH,
    )
    assert again == receipt
    with pytest.raises(RunError, match="different evidence"):
        store.record_receipt(
            "run_fixture",
            receipt_id="receipt_fixture",
            event_id="event_other",
            status="delivered",
            effect_hash=ONE_HASH,
        )


def test_immutable_receipt_stage_cleanup_preserves_substituted_foreign_leaf(
    tmp_path, monkeypatch
):
    vault, store = _store(tmp_path)
    _create_running(store)
    foreign = b"foreign receipt stage\n"

    def substitute_then_collide(directory_fd, source, destination):
        os.unlink(source, dir_fd=directory_fd)
        fd = os.open(
            source,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
            dir_fd=directory_fd,
        )
        with os.fdopen(fd, "wb") as handle:
            handle.write(foreign)
            handle.flush()
            os.fsync(handle.fileno())
        return False

    monkeypatch.setattr(runs_store, "_rename_noreplace_at", substitute_then_collide)
    with pytest.raises(RunError, match="foreign leaf"):
        store.record_receipt(
            "run_fixture",
            receipt_id="receipt_cleanup",
            event_id="event_cleanup",
            status="failed",
            effect_hash=ZERO_HASH,
        )

    receipts = vault / "agent/outbox/receipts"
    stages = list(receipts.glob(".receipt_cleanup.json.*.tmp"))
    assert len(stages) == 1
    assert stages[0].read_bytes() == foreign
    assert any(
        path.read_bytes() == foreign
        for path in (receipts / ".recovery").glob("stage-*.recovery")
    )
    assert not (receipts / "receipt_cleanup.json").exists()


def test_lifecycle_state_write_is_anchored_and_rejects_run_directory_swap(
    tmp_path, monkeypatch
):
    vault, store = _store(tmp_path)
    before = _create_running(store)
    run_dir = vault / "agent/runs/run_fixture"
    original = vault / "agent/runs/run_fixture-original"
    real_atomic = runs_store._atomic_json_at
    swapped = False

    def swap_before_write(directory_fd, name, payload):
        nonlocal swapped
        if name == "state.json" and not swapped:
            swapped = True
            run_dir.rename(original)
            run_dir.mkdir()
            (run_dir / "state.json").write_text(
                json.dumps(before, sort_keys=True) + "\n", encoding="utf-8"
            )
        return real_atomic(directory_fd, name, payload)

    monkeypatch.setattr(runs_store, "_atomic_json_at", swap_before_write)
    with pytest.raises(RunError, match="changed during"):
        store.transition(
            "run_fixture",
            status="waiting_human",
            phase="review",
            waiting_for="decision",
        )

    assert json.loads((run_dir / "state.json").read_text("utf-8"))["phase"] == "collect"
    assert json.loads((original / "state.json").read_text("utf-8"))["phase"] == "review"


def test_receipt_and_projection_writes_reject_managed_directory_swaps(
    tmp_path, monkeypatch
):
    vault, store = _store(tmp_path)
    _create_running(store)

    real_create = runs_store._create_json_once_at
    receipt_dir = vault / "agent/outbox/receipts"
    saved_receipts = vault / "agent/outbox/receipts-saved"

    def swap_receipts(directory_fd, name, payload):
        receipt_dir.rename(saved_receipts)
        receipt_dir.mkdir()
        return real_create(directory_fd, name, payload)

    monkeypatch.setattr(runs_store, "_create_json_once_at", swap_receipts)
    with pytest.raises(RunError, match="managed directory changed"):
        store.record_receipt(
            "run_fixture",
            receipt_id="receipt_swap",
            event_id="event_swap",
            status="delivered",
            effect_hash=ONE_HASH,
        )
    assert list(receipt_dir.iterdir()) == []
    assert not (saved_receipts / "receipt_swap.json").exists()

    real_bytes = runs_store._atomic_bytes_at
    projection_dir = vault / "agent/dashboard/runs"
    saved_projection = vault / "agent/dashboard/runs-saved"

    def swap_projection(directory_fd, name, data):
        projection_dir.rename(saved_projection)
        projection_dir.mkdir()
        return real_bytes(directory_fd, name, data)

    monkeypatch.setattr(runs_store, "_atomic_bytes_at", swap_projection)
    with pytest.raises(RunError, match="managed directory changed"):
        store.write_projection("run_fixture")
    assert list(projection_dir.iterdir()) == []
    assert not (saved_projection / "run_fixture.md").exists()


def test_intent_and_trace_replacements_cannot_return_a_committed_step(
    tmp_path, monkeypatch
):
    vault, store = _store(tmp_path)
    _create_running(store)
    run_dir = vault / "agent/runs/run_fixture"
    intents = run_dir / "intents"
    saved_intents = run_dir / "intents-saved"
    real_atomic = runs_store._atomic_json_at
    swapped_intents = False

    def swap_intents(directory_fd, name, payload):
        nonlocal swapped_intents
        if name == "intent-swap.json" and not swapped_intents:
            swapped_intents = True
            intents.rename(saved_intents)
            intents.mkdir()
        return real_atomic(directory_fd, name, payload)

    monkeypatch.setattr(runs_store, "_atomic_json_at", swap_intents)
    with pytest.raises(RunError, match="intent directory changed"):
        store.commit_step(
            "run_fixture",
            step_id="intent-swap",
            authority="proposal",
            input_hash=ZERO_HASH,
            output_hash=ONE_HASH,
            next_phase="validate",
        )
    assert store.status("run_fixture")["phase"] == "collect"
    assert list(intents.iterdir()) == []
    assert (saved_intents / "intent-swap.json").is_file()

    intents.rmdir()
    saved_intents.rename(intents)
    monkeypatch.setattr(runs_store, "_atomic_json_at", real_atomic)
    store.commit_step(
        "run_fixture",
        step_id="first-trace",
        authority="proposal",
        input_hash=ZERO_HASH,
        output_hash=ONE_HASH,
        next_phase="validate",
    )
    trace = run_dir / "trace.jsonl"
    saved_trace = run_dir / "trace-saved.jsonl"
    real_open = runs_store.os.open
    swapped_trace = False

    def swap_trace(path, flags, mode=0o777, *, dir_fd=None):
        nonlocal swapped_trace
        if (
            path == "trace.jsonl"
            and dir_fd is not None
            and flags & os.O_RDWR
            and not swapped_trace
        ):
            swapped_trace = True
            trace.rename(saved_trace)
            trace.write_text("", encoding="utf-8")
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(runs_store.os, "open", swap_trace)
    with pytest.raises(RunError, match="trace changed"):
        store.commit_step(
            "run_fixture",
            step_id="second-trace",
            authority="proposal",
            input_hash=ONE_HASH,
            output_hash=ZERO_HASH,
            next_phase="review",
        )
    assert [event["step_id"] for event in _trace(saved_trace)] == [
        "intent-swap",
        "first-trace",
    ]
    assert trace.read_text("utf-8") == ""


@pytest.mark.parametrize("kind", ["receipt", "projection"])
def test_run_swap_during_downstream_publish_rolls_back_new_artifact(
    tmp_path, monkeypatch, kind
):
    vault, store = _store(tmp_path)
    _create_running(store)
    run_dir = vault / "agent/runs/run_fixture"
    saved_run = vault / "agent/runs/run_fixture-saved"
    swapped = False

    def swap_run() -> None:
        nonlocal swapped
        if not swapped:
            swapped = True
            run_dir.rename(saved_run)
            run_dir.mkdir()

    if kind == "receipt":
        real_create = runs_store._create_json_once_at

        def create_after_swap(directory_fd, name, payload):
            swap_run()
            return real_create(directory_fd, name, payload)

        monkeypatch.setattr(runs_store, "_create_json_once_at", create_after_swap)
        with pytest.raises(RunError, match="changed during"):
            store.record_receipt(
                "run_fixture",
                receipt_id="receipt_run_swap",
                event_id="event_run_swap",
                status="delivered",
                effect_hash=ONE_HASH,
            )
        assert not (vault / "agent/outbox/receipts/receipt_run_swap.json").exists()
    else:
        real_bytes = runs_store._atomic_bytes_at

        def write_after_swap(directory_fd, name, data):
            swap_run()
            return real_bytes(directory_fd, name, data)

        monkeypatch.setattr(runs_store, "_atomic_bytes_at", write_after_swap)
        with pytest.raises(RunError, match="changed during"):
            store.write_projection("run_fixture")
        assert not (vault / "agent/dashboard/runs/run_fixture.md").exists()


def test_receipt_rollback_never_deletes_a_replacement_at_the_rename_seam(
    tmp_path, monkeypatch
):
    vault, store = _store(tmp_path)
    _create_running(store)
    run_dir = vault / "agent/runs/run_fixture"
    saved_run = vault / "agent/runs/run_fixture-saved"
    real_create = runs_store._create_json_once_at
    real_rename = runs_store.os.rename
    foreign = b"foreign receipt collision\n"

    def create_then_swap_run(directory_fd, name, payload):
        created = real_create(directory_fd, name, payload)
        run_dir.rename(saved_run)
        run_dir.mkdir()
        return created

    def replace_before_quarantine(
        source,
        destination,
        *,
        src_dir_fd=None,
        dst_dir_fd=None,
    ):
        if source == "receipt_seam.json" and str(destination).endswith(".recovery"):
            os.unlink(source, dir_fd=src_dir_fd)
            descriptor = os.open(
                source,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=src_dir_fd,
            )
            try:
                os.write(descriptor, foreign)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        return real_rename(
            source,
            destination,
            src_dir_fd=src_dir_fd,
            dst_dir_fd=dst_dir_fd,
        )

    monkeypatch.setattr(runs_store, "_create_json_once_at", create_then_swap_run)
    monkeypatch.setattr(runs_store.os, "rename", replace_before_quarantine)
    with pytest.raises(RunError, match="could not be rolled back"):
        store.record_receipt(
            "run_fixture",
            receipt_id="receipt_seam",
            event_id="event_seam",
            status="delivered",
            effect_hash=ONE_HASH,
        )
    assert (vault / "agent/outbox/receipts/receipt_seam.json").read_bytes() == foreign


def test_projection_rollback_restores_existing_view_without_replace(
    tmp_path, monkeypatch
):
    vault, store = _store(tmp_path)
    _create_running(store)
    projection = store.write_projection("run_fixture")
    previous = projection.read_bytes()
    store.transition(
        "run_fixture",
        status="waiting_human",
        phase="review",
        waiting_for="decision",
    )
    run_dir = vault / "agent/runs/run_fixture"
    saved_run = vault / "agent/runs/run_fixture-saved"
    real_bytes = runs_store._atomic_bytes_at
    swapped = False

    def write_then_swap(directory_fd, name, data):
        nonlocal swapped
        published_identity = real_bytes(directory_fd, name, data)
        if name == "run_fixture.md" and not swapped:
            swapped = True
            run_dir.rename(saved_run)
            run_dir.mkdir()
        return published_identity

    monkeypatch.setattr(runs_store, "_atomic_bytes_at", write_then_swap)
    with pytest.raises(RunError, match="changed during"):
        store.write_projection("run_fixture")
    assert projection.read_bytes() == previous
    recovery = list((saved_run / "rollback").glob("projection-*.recovery"))
    assert len(recovery) == 1
    assert b"Status: `waiting_human`" in recovery[0].read_bytes()


def test_trace_schema_is_bounded_exact_and_bool_exit_is_rejected():
    event = {
        "schema_version": 1,
        "at": "2026-01-15T09:00:00Z",
        "run_id": "run_fixture",
        "step_id": "validate",
        "authority": "read",
        "input_hash": ZERO_HASH,
        "output_hash": ONE_HASH,
        "executor_profile": "codex",
        "tool_outcomes": [
            {
                "tool": "llmwiki",
                "status": "compatible",
                "exit_code": 0,
                "detail_hash": ZERO_HASH,
            }
        ],
    }
    assert validate_trace_event(event) == event
    event["tool_outcomes"][0]["exit_code"] = True
    with pytest.raises(RunError, match="integer"):
        validate_trace_event(event)


def test_trace_cannot_claim_a_different_run(tmp_path):
    vault, store = _store(tmp_path)
    _create_running(store)
    trace_path = vault / "agent/runs/run_fixture/trace.jsonl"
    event = {
        "schema_version": 1,
        "at": "2026-01-15T09:00:00Z",
        "run_id": "run_other",
        "step_id": "validate",
        "authority": "read",
        "input_hash": ZERO_HASH,
        "output_hash": ONE_HASH,
        "executor_profile": "codex",
        "tool_outcomes": [],
    }
    trace_path.write_text(json.dumps(event) + "\n", encoding="utf-8")
    with pytest.raises(RunError, match="different run"):
        store.trace_events("run_fixture")


def test_trace_size_bound_blocks_append_without_changing_state(tmp_path):
    vault, resolver = _vault(tmp_path)
    store = RunStore(resolver, clock=_Clock(), max_trace_bytes=16 * 1024)
    state = _create_running(store)
    trace_path = vault / "agent/runs/run_fixture/trace.jsonl"
    trace_path.write_bytes(b" " * (16 * 1024))
    with pytest.raises(RunError, match="invalid JSON|too large|empty record"):
        store.trace_events("run_fixture")
    assert store.status("run_fixture") == state


def test_symlinked_state_trace_and_intent_paths_fail_closed(tmp_path):
    vault, store = _store(tmp_path)
    _create_running(store)
    outside = tmp_path / "outside"
    outside.mkdir()

    trace = vault / "agent/runs/run_fixture/trace.jsonl"
    trace.unlink()
    trace.symlink_to(outside / "trace.jsonl")
    with pytest.raises(RunError):
        store.trace_events("run_fixture")

    trace.unlink()
    trace.write_text("", encoding="utf-8")
    intents = vault / "agent/runs/run_fixture/intents"
    intents.rmdir()
    intents.symlink_to(outside)
    with pytest.raises(RunError, match="intent directory"):
        store.reconcile("run_fixture")


def test_atomic_writes_leave_no_temp_files(tmp_path):
    vault, store = _store(tmp_path)
    _create_running(store)
    store.transition(
        "run_fixture",
        status="transient_wait",
        phase="retry",
        error_kind="connector-timeout",
    )
    store.resume("run_fixture", executor="claude")
    assert not list(vault.rglob("*.tmp"))
    assert not [path for path in vault.rglob(".*.tmp")]
