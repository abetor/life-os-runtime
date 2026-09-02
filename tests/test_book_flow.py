"""P3-06 reading lifecycle, proposal, and restart/recovery acceptance."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil

import pytest

import tool_life_os_runtime.ext.flows.book.flow as book_flow_module

from tool_life_os_runtime.ext.flows.book import (
    BOOK_SCHEMA_VERSION,
    BookCapabilities,
    BookCommand,
    BookCrashHooks,
    BookFlow,
    BookFlowError,
    BookSourceManifest,
    StaleReadingQuery,
    parse_book_command,
    parse_book_result,
    parse_book_source_manifest,
    parse_reading_state,
    render_book_command,
    render_book_result,
    render_book_source_manifest,
    render_reading_state,
)
from tool_life_os_runtime.ext.review.artifact import (
    render_mutation_plan,
    render_review_artifact,
    validate_artifact_plan,
)
from tool_life_os_runtime.ext.review.authority import AuthorityPolicy
from tool_life_os_runtime.ext.runs import RunStore
from tool_life_os_runtime.ext.vault.config import load_vault_config
from tool_life_os_runtime.ext.vault.schema import VaultPathResolver
from tool_life_os_runtime.failure_authority import canonical_matrix


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/vault-minimal"

BOOK_ACTIONS = {
    "read-source-manifest": ("read", "tool:source-manifest"),
    "read-reading-state": ("read", "vault:agent/reading"),
    "read-reading-knowledge": ("read", "vault:knowledge"),
    "commit-reading-state": ("domain-write", "vault:agent/reading"),
    "commit-reading-knowledge-proposal": ("proposal", "vault:review"),
    "record-run-state": ("internal-write", "vault:agent/runs"),
}


def _issue(policy: AuthorityPolicy, action_id: str):
    authority, target = BOOK_ACTIONS[action_id]
    return policy.issue(
        flow_id="book",
        action_id=action_id,
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
        resolver,
        clock=lambda: datetime(2026, 8, 20, 9, tzinfo=timezone.utc),
    )
    runs.create(
        run_id="run_book_one",
        flow="book",
        phase="reading",
        authority="domain-write",
        executor="fixture",
        input_data={"slug": "portable-book"},
    )
    runs.resume("run_book_one", executor="fixture")
    capabilities = BookCapabilities(
        read_source_manifest=_issue(policy, "read-source-manifest"),
        read_reading_state=_issue(policy, "read-reading-state"),
        read_reading_knowledge=_issue(policy, "read-reading-knowledge"),
        commit_reading_state=_issue(policy, "commit-reading-state"),
        commit_knowledge_proposal=_issue(policy, "commit-reading-knowledge-proposal"),
        record_run_state=_issue(policy, "record-run-state"),
    )
    return vault, resolver, policy, runs, capabilities, BookFlow(resolver, runs, policy)


def _manifest(ref: str = "coursedump/manifests/portable-book.json"):
    return BookSourceManifest(
        BOOK_SCHEMA_VERSION,
        "source_portable_book",
        ref,
        "1" * 64,
        "2" * 64,
        "Portable Systems Handbook",
        12,
    )


def _command(operation: str, mutation: str, at: str, **values) -> BookCommand:
    return BookCommand(
        BOOK_SCHEMA_VERSION,
        "run_book_one",
        mutation,
        operation,
        "portable-book",
        at,
        **values,
    )


def _active():
    return _command("active", "mut_active", "2026-08-20T10:00:00Z")


def _snapshot(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file() and not path.is_symlink()
    }


def _evidence_path(vault: Path, mutation_id: str) -> Path:
    token = hashlib.sha256(mutation_id.encode("ascii")).hexdigest()[:40]
    return vault / f"agent/runs/run_book_one/book-{token}.json"


def _canonical_json(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        + b"\n"
    )


def _memory_evidence_chain(
    flow: BookFlow, length: int
) -> tuple[
    dict[str, object],
    dict[str, dict[str, object]],
    frozenset[str],
    BookCommand,
    BookSourceManifest,
]:
    assert length >= 1
    manifest = _manifest()
    current = None
    evidence: dict[str, dict[str, object]] = {}
    committed: set[str] = set()
    command = _active()
    for index in range(length):
        mutation_id = f"mut_chain_{index:04d}"
        command = _command(
            "active" if index == 0 else "progress",
            mutation_id,
            "2026-08-20T10:00:00Z",
            **({} if index == 0 else {"chapter": 1}),
        )
        request = flow._request_payload(command, manifest)
        request_hash = flow._request_hash(request)
        target = flow._derive_target(command, manifest, current, request_hash)
        block = flow._event_block(command, manifest, target, request_hash)
        payload: dict[str, object] = {
            "schema_version": BOOK_SCHEMA_VERSION,
            "flow": "book",
            "request": request,
            "request_sha256": request_hash,
            "run_state_sha256": "0" * 64,
            "base_state": (
                None if current is None else json.loads(render_reading_state(current))
            ),
            "base_state_sha256": (
                None
                if current is None
                else hashlib.sha256(render_reading_state(current)).hexdigest()
            ),
            "target_state": json.loads(render_reading_state(target)),
            "log_block": block,
            "log_block_sha256": hashlib.sha256(block.encode("utf-8")).hexdigest(),
            "review_sha256": None,
            "plan_sha256": None,
        }
        evidence[mutation_id] = payload
        committed.add(book_flow_module._artifact_names(mutation_id)[0])
        current = target
    return (
        evidence[command.mutation_id],
        evidence,
        frozenset(committed),
        command,
        manifest,
    )


def test_versioned_manifest_command_state_and_result_are_canonical(tmp_path: Path):
    vault, _, _, _, caps, flow = _setup(tmp_path)
    manifest = _manifest()
    command = _active()

    assert parse_book_source_manifest(render_book_source_manifest(manifest)) == manifest
    assert parse_book_command(render_book_command(command)) == command
    result = flow.execute(command, manifest, capabilities=caps)
    assert parse_reading_state(render_reading_state(result.state)) == result.state
    assert parse_book_result(render_book_result(result)) == result

    payload = json.loads(render_book_command(command))
    payload["unknown"] = True
    malformed = (
        json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode()
    with pytest.raises(BookFlowError, match="unknown fields"):
        parse_book_command(malformed)
    with pytest.raises(BookFlowError, match="duplicate"):
        parse_book_command(b'{"schema_version":1,"schema_version":1}\n')
    with pytest.raises(BookFlowError, match="canonical JSON"):
        parse_book_command(
            render_book_command(command).replace(
                b'"operation":"active"', b'"operation": "active"'
            )
        )
    assert not (vault / "knowledge/portable-book.md").exists()


def test_full_lifecycle_retains_log_and_anchor_is_review_only(tmp_path: Path):
    vault, _, _, runs, caps, flow = _setup(tmp_path)
    knowledge_before = _snapshot(vault / "knowledge")

    active = flow.execute(_active(), _manifest(), capabilities=caps)
    discussed = flow.execute(
        _command(
            "discuss",
            "mut_discuss",
            "2026-08-20T11:00:00Z",
            text="A bounded discussion note.",
        ),
        _manifest(),
        capabilities=caps,
    )
    progressed = flow.execute(
        _command(
            "progress",
            "mut_progress",
            "2026-08-20T12:00:00Z",
            chapter=4,
            text="Reached the consistency chapter.",
        ),
        _manifest(),
        capabilities=caps,
    )
    anchored = flow.execute(
        _command(
            "anchor",
            "mut_anchor",
            "2026-08-20T13:00:00Z",
            chapter=4,
            text="State should survive an executor change.",
            anchor_id="anchor_portable_one",
            review_id="rev_book_anchor_one",
            target_path="knowledge/portable-book-anchor.md",
            surface="gated",
        ),
        _manifest(),
        capabilities=caps,
    )

    assert active.state.revision == 1
    assert discussed.state.revision == 2
    assert progressed.state.current_chapter == 4
    assert anchored.review_artifact is not None
    assert anchored.mutation_plan is not None
    assert anchored.review_artifact.flow == "book"
    assert validate_artifact_plan(anchored.review_artifact, anchored.mutation_plan)
    assert _snapshot(vault / "knowledge") == knowledge_before
    assert (vault / "review/rev_book_anchor_one.md").read_text(
        "utf-8"
    ) == render_review_artifact(anchored.review_artifact)
    assert (vault / ".lifeos/review-plans/rev_book_anchor_one.json").read_bytes() == (
        render_mutation_plan(anchored.mutation_plan)
    )

    log_path = vault / "agent/reading/portable-book-log.md"
    before_close = log_path.read_bytes()
    closed = flow.execute(
        _command(
            "close",
            "mut_close",
            "2026-08-20T14:00:00Z",
            decision="finished",
            reason="Completed the intended chapters.",
        ),
        _manifest(),
        capabilities=caps,
    )

    assert closed.state.status == "closed"
    assert not (vault / "agent/reading/portable-book.json").exists()
    assert log_path.read_bytes().startswith(before_close)
    assert "closed: finished" in log_path.read_text("utf-8")
    assert runs.status("run_book_one")["status"] == "running"
    committed = {item.name for item in runs.snapshot("run_book_one").artifacts}
    assert anchored.review_artifact_name in committed
    assert anchored.mutation_plan_name in committed

    anchor_trace = next(
        event
        for event in runs.trace_events("run_book_one")
        if any(
            action["action_id"] == "commit-reading-knowledge-proposal"
            for action in event.get("actions", ())
        )
    )
    assert [item["action_id"] for item in anchor_trace["actions"]] == [
        "read-source-manifest",
        "read-reading-state",
        "read-reading-knowledge",
        "commit-reading-state",
        "commit-reading-knowledge-proposal",
        "record-run-state",
    ]


def test_restart_after_log_commit_recovers_once_without_duplicate(tmp_path: Path):
    vault, resolver, policy, runs, caps, flow = _setup(tmp_path)
    flow.execute(_active(), _manifest(), capabilities=caps)
    command = _command(
        "progress",
        "mut_progress_crash",
        "2026-08-20T12:00:00Z",
        chapter=3,
        text="Recover this exact progress.",
    )

    with pytest.raises(RuntimeError, match="stop after log"):
        flow.execute(
            command,
            _manifest(),
            capabilities=caps,
            crash_hooks=BookCrashHooks(
                after_log=lambda: (_ for _ in ()).throw(RuntimeError("stop after log"))
            ),
        )

    restarted = BookFlow(resolver, runs, policy)
    result = restarted.execute(command, _manifest(), capabilities=caps)
    log = (vault / "agent/reading/portable-book-log.md").read_text("utf-8")

    assert result.replayed
    assert result.state.current_chapter == 3
    assert log.count("lifeos-book-event:mut_progress_crash:") == 1
    assert runs.status("run_book_one")["status"] == "running"
    with pytest.raises(BookFlowError, match="conflicts with durable evidence"):
        restarted.execute(
            replace(command, text="A conflicting retry."),
            _manifest(),
            capabilities=caps,
        )


@pytest.mark.parametrize("tamper", ["base", "target", "log"])
def test_replay_semantically_rederives_durable_evidence(tmp_path: Path, tamper: str):
    vault, resolver, policy, runs, caps, flow = _setup(tmp_path)
    flow.execute(_active(), _manifest(), capabilities=caps)
    command = _command(
        "progress",
        "mut_semantic_evidence",
        "2026-08-20T12:00:00Z",
        chapter=3,
        text="Exact semantic recovery.",
    )
    with pytest.raises(RuntimeError, match="stop after evidence"):
        flow.execute(
            command,
            _manifest(),
            capabilities=caps,
            crash_hooks=BookCrashHooks(
                after_evidence=lambda: (_ for _ in ()).throw(
                    RuntimeError("stop after evidence")
                )
            ),
        )
    evidence = _evidence_path(vault, command.mutation_id)
    payload = json.loads(evidence.read_bytes())
    if tamper == "base":
        payload["base_state"]["current_chapter"] = 2
        base_raw = (
            json.dumps(
                payload["base_state"],
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            + b"\n"
        )
        payload["base_state_sha256"] = hashlib.sha256(base_raw).hexdigest()
    elif tamper == "target":
        payload["target_state"]["current_chapter"] = 4
        payload["log_block"] = payload["log_block"].replace(
            "- Chapter: 3", "- Chapter: 4"
        )
        payload["log_block_sha256"] = hashlib.sha256(
            payload["log_block"].encode("utf-8")
        ).hexdigest()
    else:
        payload["log_block"] += '- Detail: "altered but rehashed"\n'
        payload["log_block_sha256"] = hashlib.sha256(
            payload["log_block"].encode("utf-8")
        ).hexdigest()
    evidence.write_bytes(
        json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )

    with pytest.raises(BookFlowError, match="replay"):
        BookFlow(resolver, runs, policy).execute(
            command, _manifest(), capabilities=caps
        )


def test_replay_recursively_rederives_coordinated_committed_chain(
    tmp_path: Path,
):
    vault, resolver, policy, runs, caps, flow = _setup(tmp_path)
    flow.execute(_active(), _manifest(), capabilities=caps)
    command = _command(
        "progress",
        "mut_recursive_evidence",
        "2026-08-20T12:00:00Z",
        chapter=3,
    )
    with pytest.raises(RuntimeError, match="stop after evidence"):
        flow.execute(
            command,
            _manifest(),
            capabilities=caps,
            crash_hooks=BookCrashHooks(
                after_evidence=lambda: (_ for _ in ()).throw(
                    RuntimeError("stop after evidence")
                )
            ),
        )

    active_evidence = _evidence_path(vault, "mut_active")
    active_payload = json.loads(active_evidence.read_bytes())
    active_payload["target_state"]["current_chapter"] = 2
    active_payload["log_block"] = active_payload["log_block"].replace(
        "- Chapter: 1", "- Chapter: 2"
    )
    active_payload["log_block_sha256"] = hashlib.sha256(
        active_payload["log_block"].encode("utf-8")
    ).hexdigest()
    active_raw = _canonical_json(active_payload)
    active_evidence.write_bytes(active_raw)

    state_raw = _canonical_json(active_payload["target_state"])
    (vault / "agent/reading/portable-book.json").write_bytes(state_raw)
    progress_evidence = _evidence_path(vault, command.mutation_id)
    progress_payload = json.loads(progress_evidence.read_bytes())
    progress_payload["base_state"] = active_payload["target_state"]
    progress_payload["base_state_sha256"] = hashlib.sha256(state_raw).hexdigest()
    progress_evidence.write_bytes(_canonical_json(progress_payload))

    trace_path = vault / "agent/runs/run_book_one/trace.jsonl"
    trace = [json.loads(line) for line in trace_path.read_text("utf-8").splitlines()]
    trace[0]["output_hash"] = hashlib.sha256(active_raw).hexdigest()
    trace_path.write_bytes(b"".join(_canonical_json(event) for event in trace))

    intent_path = next((trace_path.parent / "intents").glob("*.json"))
    intent = json.loads(intent_path.read_bytes())
    intent["prepared_artifacts"][0]["sha256"] = hashlib.sha256(active_raw).hexdigest()
    intent["trace_event"]["output_hash"] = hashlib.sha256(active_raw).hexdigest()
    intent_path.write_bytes(_canonical_json(intent))

    with pytest.raises(BookFlowError, match="exact preimage"):
        BookFlow(resolver, runs, policy).execute(
            command, _manifest(), capabilities=caps
        )


def test_prior_chain_accepts_its_exact_iterative_bound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    _vault, _resolver, _policy, _runs, _caps, flow = _setup(tmp_path)
    assert book_flow_module._MAX_PRIOR_CHAIN == 256
    root, evidence, committed, command, manifest = _memory_evidence_chain(flow, 256)
    loads: list[str] = []

    def load(run_id: str, mutation_id: str):
        assert run_id == command.run_id
        loads.append(mutation_id)
        return evidence[mutation_id]

    monkeypatch.setattr(flow, "_load_evidence", load)
    derived = flow._derive_evidence_chain(
        root, run_id=command.run_id, committed_names=committed
    )

    assert derived[0] == command
    assert derived[1] == manifest
    assert derived[2].revision == 256
    assert len(loads) == 255


@pytest.mark.parametrize(
    "length",
    [257, 1100],
)
def test_prior_chain_rejects_over_bound_before_loading_another_item(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, length: int
):
    _vault, _resolver, _policy, _runs, _caps, flow = _setup(tmp_path)
    root, evidence, committed, command, _manifest_item = _memory_evidence_chain(
        flow, length
    )
    loads: list[str] = []

    def load(run_id: str, mutation_id: str):
        assert run_id == command.run_id
        loads.append(mutation_id)
        return evidence[mutation_id]

    monkeypatch.setattr(flow, "_load_evidence", load)
    with pytest.raises(BookFlowError, match="exceeds its bound"):
        flow._derive_evidence_chain(
            root, run_id=command.run_id, committed_names=committed
        )
    assert len(loads) == 255


def test_prior_chain_cycle_remains_a_normalized_book_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    _vault, _resolver, _policy, _runs, _caps, flow = _setup(tmp_path)
    root, evidence, committed, command, _manifest_item = _memory_evidence_chain(flow, 2)
    cyclic = json.loads(_canonical_json(root))
    cyclic["base_state"]["last_mutation_id"] = command.mutation_id
    cyclic["base_state"]["last_mutation_sha256"] = cyclic["request_sha256"]
    cyclic["base_state_sha256"] = hashlib.sha256(
        _canonical_json(cyclic["base_state"])
    ).hexdigest()
    evidence[command.mutation_id] = cyclic
    monkeypatch.setattr(
        flow,
        "_load_evidence",
        lambda _run_id, mutation_id: evidence[mutation_id],
    )

    with pytest.raises(BookFlowError, match="contains a cycle"):
        flow._derive_evidence_chain(
            cyclic, run_id=command.run_id, committed_names=committed
        )


def test_prior_chain_normalizes_unexpected_recursion_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    _vault, _resolver, _policy, _runs, _caps, flow = _setup(tmp_path)
    monkeypatch.setattr(
        flow,
        "_derive_evidence_chain_iterative",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RecursionError()),
    )

    with pytest.raises(BookFlowError, match="exceeds its bound"):
        flow._derive_evidence_chain(
            {}, run_id="run_book_one", committed_names=frozenset()
        )


def test_new_mutation_cannot_skip_an_uncommitted_lifecycle_event(tmp_path: Path):
    vault, _, _, runs, caps, flow = _setup(tmp_path)
    flow.execute(_active(), _manifest(), capabilities=caps)
    interrupted = _command(
        "progress",
        "mut_interrupted_state",
        "2026-08-20T11:00:00Z",
        chapter=2,
    )
    with pytest.raises(RuntimeError, match="stop after state"):
        flow.execute(
            interrupted,
            _manifest(),
            capabilities=caps,
            crash_hooks=BookCrashHooks(
                after_state=lambda: (_ for _ in ()).throw(
                    RuntimeError("stop after state")
                )
            ),
        )
    state_before = (vault / "agent/reading/portable-book.json").read_bytes()
    log_before = (vault / "agent/reading/portable-book-log.md").read_bytes()
    run_before = runs.snapshot("run_book_one")

    with pytest.raises(BookFlowError, match="uncommitted lifecycle event"):
        flow.execute(
            _command(
                "discuss",
                "mut_skip_interrupted",
                "2026-08-20T12:00:00Z",
                text="This must wait for exact recovery.",
            ),
            _manifest(),
            capabilities=caps,
        )

    assert (vault / "agent/reading/portable-book.json").read_bytes() == state_before
    assert (vault / "agent/reading/portable-book-log.md").read_bytes() == log_before
    assert runs.snapshot("run_book_one").state_sha256 == run_before.state_sha256
    recovered = flow.execute(interrupted, _manifest(), capabilities=caps)
    assert recovered.replayed and recovered.state.current_chapter == 2


def test_anchor_recovery_rebuilds_exact_review_without_knowledge_write(
    tmp_path: Path,
):
    vault, resolver, policy, runs, caps, flow = _setup(tmp_path)
    flow.execute(_active(), _manifest(), capabilities=caps)
    command = _command(
        "anchor",
        "mut_anchor_recovery",
        "2026-08-20T12:00:00Z",
        chapter=2,
        text="Recover the exact proposed anchor.",
        anchor_id="anchor_recovery",
        review_id="rev_book_recovery",
        target_path="knowledge/recovered-book-anchor.md",
        surface="gated",
    )
    with pytest.raises(RuntimeError, match="stop after anchor state"):
        flow.execute(
            command,
            _manifest(),
            capabilities=caps,
            crash_hooks=BookCrashHooks(
                after_state=lambda: (_ for _ in ()).throw(
                    RuntimeError("stop after anchor state")
                )
            ),
        )
    assert not (vault / "knowledge/recovered-book-anchor.md").exists()
    assert not (vault / "review/rev_book_recovery.md").exists()
    assert not (vault / ".lifeos/review-plans/rev_book_recovery.json").exists()

    result = BookFlow(resolver, runs, policy).execute(
        command, _manifest(), capabilities=caps
    )
    assert result.replayed
    assert result.review_artifact is not None and result.mutation_plan is not None
    assert validate_artifact_plan(result.review_artifact, result.mutation_plan)
    assert (vault / "review/rev_book_recovery.md").read_text(
        "utf-8"
    ) == render_review_artifact(result.review_artifact)
    assert (vault / ".lifeos/review-plans/rev_book_recovery.json").read_bytes() == (
        render_mutation_plan(result.mutation_plan)
    )
    assert not (vault / "knowledge/recovered-book-anchor.md").exists()
    assert (vault / "agent/reading/portable-book-log.md").read_text("utf-8").count(
        "lifeos-book-event:mut_anchor_recovery:"
    ) == 1


def test_anchor_recovery_after_proposal_publish_is_exact_and_single(
    tmp_path: Path,
):
    vault, resolver, policy, runs, caps, flow = _setup(tmp_path)
    flow.execute(_active(), _manifest(), capabilities=caps)
    command = _command(
        "anchor",
        "mut_anchor_published",
        "2026-08-20T12:30:00Z",
        chapter=3,
        text="Keep one exact proposal across the run commit boundary.",
        anchor_id="anchor_published",
        review_id="rev_book_published",
        target_path="knowledge/published-book-anchor.md",
        surface="gated",
    )

    with pytest.raises(RuntimeError, match="stop after proposal"):
        flow.execute(
            command,
            _manifest(),
            capabilities=caps,
            crash_hooks=BookCrashHooks(
                after_proposal=lambda: (_ for _ in ()).throw(
                    RuntimeError("stop after proposal")
                )
            ),
        )

    review_before = (vault / "review/rev_book_published.md").read_bytes()
    plan_before = (vault / ".lifeos/review-plans/rev_book_published.json").read_bytes()
    result = BookFlow(resolver, runs, policy).execute(
        command, _manifest(), capabilities=caps
    )

    assert result.replayed
    assert (vault / "review/rev_book_published.md").read_bytes() == review_before
    assert (
        vault / ".lifeos/review-plans/rev_book_published.json"
    ).read_bytes() == plan_before
    assert not (vault / "knowledge/published-book-anchor.md").exists()
    assert (vault / "agent/reading/portable-book-log.md").read_text("utf-8").count(
        "lifeos-book-event:mut_anchor_published:"
    ) == 1
    assert runs.status("run_book_one")["status"] == "running"


def test_close_recovery_is_idempotent_but_close_not_reading_fails(tmp_path: Path):
    vault, resolver, policy, runs, caps, flow = _setup(tmp_path)
    close = _command(
        "close",
        "mut_close_once",
        "2026-08-20T12:00:00Z",
        decision="dropped",
        reason="The source is outside the current focus.",
    )
    assert not (vault / "agent/reading").exists()
    with pytest.raises(BookFlowError, match="not currently being read"):
        flow.execute(close, _manifest(), capabilities=caps)
    assert not (vault / "agent/reading").exists()

    flow.execute(_active(), _manifest(), capabilities=caps)
    with pytest.raises(RuntimeError, match="stop after state"):
        flow.execute(
            close,
            _manifest(),
            capabilities=caps,
            crash_hooks=BookCrashHooks(
                after_state=lambda: (_ for _ in ()).throw(
                    RuntimeError("stop after state")
                )
            ),
        )
    assert not (vault / "agent/reading/portable-book.json").exists()

    restarted = BookFlow(resolver, runs, policy)
    recovered = restarted.execute(close, _manifest(), capabilities=caps)
    repeated = restarted.execute(close, _manifest(), capabilities=caps)
    assert recovered.replayed and repeated.replayed
    assert (vault / "agent/reading/portable-book-log.md").read_text("utf-8").count(
        "lifeos-book-event:mut_close_once:"
    ) == 1
    with pytest.raises(BookFlowError, match="not currently being read"):
        restarted.execute(
            replace(close, mutation_id="mut_close_other"),
            _manifest(),
            capabilities=caps,
        )


def test_moved_source_resumes_by_identity_and_stale_source_is_rejected(tmp_path: Path):
    vault, _, _, _, caps, flow = _setup(tmp_path)
    original = _manifest()
    flow.execute(_active(), original, capabilities=caps)
    moved = _manifest("coursedump/moved/portable-book.json")
    result = flow.execute(
        _command(
            "progress",
            "mut_source_moved",
            "2026-08-21T10:00:00Z",
            chapter=2,
        ),
        moved,
        capabilities=caps,
    )
    assert result.state.source.manifest_ref == moved.manifest_ref

    query_manifest = _manifest("coursedump/relocated/portable-book.json")
    before = _snapshot(vault / "agent/reading")
    not_stale = flow.stale(
        StaleReadingQuery(
            BOOK_SCHEMA_VERSION, "portable-book", "2026-08-27T09:59:59Z", 6
        ),
        query_manifest,
        capabilities=caps,
    )
    stale = flow.stale(
        StaleReadingQuery(
            BOOK_SCHEMA_VERSION, "portable-book", "2026-08-27T10:00:00Z", 6
        ),
        query_manifest,
        capabilities=caps,
    )
    assert not not_stale.stale
    assert stale.stale and stale.source_moved
    assert _snapshot(vault / "agent/reading") == before

    changed = replace(moved, manifest_sha256="3" * 64)
    with pytest.raises(BookFlowError, match="stale"):
        flow.execute(
            _command(
                "progress",
                "mut_stale_manifest",
                "2026-08-28T10:00:00Z",
                chapter=3,
            ),
            changed,
            capabilities=caps,
        )
    assert _snapshot(vault / "agent/reading") == before


def test_anchor_requires_empty_knowledge_target_before_any_mutation(tmp_path: Path):
    vault, _, _, runs, caps, flow = _setup(tmp_path)
    flow.execute(_active(), _manifest(), capabilities=caps)
    target = vault / "knowledge/existing-anchor.md"
    target.write_text("existing\n", "utf-8")
    before_reading = _snapshot(vault / "agent/reading")
    before_run = runs.snapshot("run_book_one")

    with pytest.raises(BookFlowError, match="already exists"):
        flow.execute(
            _command(
                "anchor",
                "mut_existing_target",
                "2026-08-20T12:00:00Z",
                chapter=1,
                text="Do not overwrite existing knowledge.",
                anchor_id="anchor_existing",
                review_id="rev_book_existing",
                target_path="knowledge/existing-anchor.md",
                surface="gated",
            ),
            _manifest(),
            capabilities=caps,
        )

    assert target.read_text("utf-8") == "existing\n"
    assert _snapshot(vault / "agent/reading") == before_reading
    assert runs.snapshot("run_book_one").state_sha256 == before_run.state_sha256


def test_anchor_review_identity_conflict_precedes_reading_mutation(tmp_path: Path):
    vault, _, _, runs, caps, flow = _setup(tmp_path)
    flow.execute(_active(), _manifest(), capabilities=caps)
    collision = vault / "review/rev_book_collision.md"
    collision.write_text("different durable review\n", "utf-8")
    before_reading = _snapshot(vault / "agent/reading")
    before_run = runs.snapshot("run_book_one")

    with pytest.raises(BookFlowError, match="different bytes"):
        flow.execute(
            _command(
                "anchor",
                "mut_review_collision",
                "2026-08-20T12:00:00Z",
                chapter=1,
                text="Do not reuse a conflicting review identity.",
                anchor_id="anchor_collision",
                review_id="rev_book_collision",
                target_path="knowledge/collision-book-anchor.md",
                surface="gated",
            ),
            _manifest(),
            capabilities=caps,
        )

    assert collision.read_text("utf-8") == "different durable review\n"
    assert _snapshot(vault / "agent/reading") == before_reading
    assert runs.snapshot("run_book_one").state_sha256 == before_run.state_sha256
    assert not (vault / ".lifeos/review-plans/rev_book_collision.json").exists()


def test_invalid_capability_has_no_reading_or_connector_effect(tmp_path: Path):
    vault, _, policy, runs, caps, flow = _setup(tmp_path)
    before = runs.snapshot("run_book_one")
    foreign = policy.issue(
        flow_id="book",
        action_id="read-reading-state",
        actor="runtime",
        authority="read",
        target="vault:agent/reading",
    )
    with pytest.raises(BookFlowError, match="exact book action"):
        flow.execute(
            _active(),
            _manifest(),
            capabilities=replace(caps, read_source_manifest=foreign),
        )
    assert not (vault / "agent/reading").exists()
    assert runs.snapshot("run_book_one").state_sha256 == before.state_sha256

    fields = set(BookCapabilities.__dataclass_fields__)
    assert not fields.intersection({"extract", "connector", "coursedump"})
    book = next(
        item for item in canonical_matrix()["flows"] if item["flow_id"] == "book"
    )
    assert book["allowed_invocations"] == []


@pytest.mark.parametrize(
    "field",
    [
        "after_evidence",
        "after_log",
        "after_state",
        "after_proposal",
        "before_run_commit",
    ],
)
def test_crash_hook_fields_are_callable_or_none_at_public_boundary(
    tmp_path: Path, field: str
):
    vault, _, _, runs, caps, flow = _setup(tmp_path)
    before = _snapshot(vault)
    run_before = runs.snapshot("run_book_one")
    hooks = replace(BookCrashHooks(), **{field: "not-callable"})

    with pytest.raises(BookFlowError, match="callables or null"):
        flow.execute(_active(), _manifest(), capabilities=caps, crash_hooks=hooks)

    assert _snapshot(vault) == before
    assert runs.snapshot("run_book_one").state_sha256 == run_before.state_sha256


def test_reading_symlink_and_zone_swap_do_not_redirect_writes(tmp_path: Path):
    vault, _, _, _, caps, flow = _setup(tmp_path)
    flow.execute(_active(), _manifest(), capabilities=caps)
    reading = vault / "agent/reading"
    outside = tmp_path / "outside"
    outside.mkdir()
    state = reading / "portable-book.json"
    state.unlink()
    state.symlink_to(outside / "state.json")
    with pytest.raises(BookFlowError):
        flow.execute(
            _command(
                "progress",
                "mut_symlink_state",
                "2026-08-20T11:00:00Z",
                chapter=2,
            ),
            _manifest(),
            capabilities=caps,
        )
    assert not (outside / "state.json").exists()


def test_progress_exchange_restores_substituted_foreign_named_leaf(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    vault, _, _, _, caps, flow = _setup(tmp_path)
    flow.execute(_active(), _manifest(), capabilities=caps)
    reading = vault / "agent/reading"
    state = reading / "portable-book.json"
    held = reading / "expected-held.json"
    original = state.read_bytes()
    foreign = b"foreign-state-must-be-preserved\n"
    exchange = book_flow_module._rename_exchange_at
    substituted = False

    def substitute(directory_fd: int, source: str, target: str) -> None:
        nonlocal substituted
        if target == "portable-book.json" and not substituted:
            substituted = True
            os.rename(
                target, held.name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd
            )
            fd = os.open(
                target,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=directory_fd,
            )
            try:
                os.write(fd, foreign)
                os.fsync(fd)
            finally:
                os.close(fd)
        exchange(directory_fd, source, target)

    monkeypatch.setattr(book_flow_module, "_rename_exchange_at", substitute)
    with pytest.raises(BookFlowError, match="changed before publish"):
        flow.execute(
            _command(
                "progress",
                "mut_progress_substitution",
                "2026-08-20T12:00:00Z",
                chapter=2,
            ),
            _manifest(),
            capabilities=caps,
        )

    assert substituted
    assert state.read_bytes() == foreign
    assert held.read_bytes() == original


def test_close_quarantine_restores_substituted_foreign_named_leaf(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    vault, _, _, _, caps, flow = _setup(tmp_path)
    flow.execute(_active(), _manifest(), capabilities=caps)
    reading = vault / "agent/reading"
    state = reading / "portable-book.json"
    held = reading / "expected-held.json"
    original = state.read_bytes()
    foreign = b"foreign-close-state-must-be-preserved\n"
    rename_noreplace = book_flow_module._rename_noreplace_at
    substituted = False

    def substitute(directory_fd: int, source: str, target: str) -> None:
        nonlocal substituted
        if source == "portable-book.json" and target.endswith(".close-quarantine"):
            substituted = True
            os.rename(
                source, held.name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd
            )
            fd = os.open(
                source,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=directory_fd,
            )
            try:
                os.write(fd, foreign)
                os.fsync(fd)
            finally:
                os.close(fd)
        rename_noreplace(directory_fd, source, target)

    monkeypatch.setattr(book_flow_module, "_rename_noreplace_at", substitute)
    with pytest.raises(BookFlowError, match="changed before close"):
        flow.execute(
            _command(
                "close",
                "mut_close_substitution",
                "2026-08-20T12:00:00Z",
                decision="dropped",
                reason="Substitution seam.",
            ),
            _manifest(),
            capabilities=caps,
        )

    assert substituted
    assert state.read_bytes() == foreign
    assert held.read_bytes() == original


def test_close_retains_original_quarantine_until_absence_decision_and_retries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    vault, resolver, policy, runs, caps, flow = _setup(tmp_path)
    flow.execute(_active(), _manifest(), capabilities=caps)
    reading = vault / "agent/reading"
    state = reading / "portable-book.json"
    quarantine = reading / ".portable-book.json.close-quarantine"
    retire = reading / ".portable-book.json.close-retire"
    original = state.read_bytes()
    foreign = b"foreign-created-after-quarantine\n"
    link = book_flow_module.os.link
    injected = False

    def inject_before_retirement(source: str, target: str, **kwargs) -> None:
        nonlocal injected
        if target == "portable-book.json" and not injected:
            injected = True
            directory_fd = kwargs["dst_dir_fd"]
            fd = os.open(
                target,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=directory_fd,
            )
            try:
                os.write(fd, foreign)
                os.fsync(fd)
            finally:
                os.close(fd)
        link(source, target, **kwargs)

    monkeypatch.setattr(book_flow_module.os, "link", inject_before_retirement)
    command = _command(
        "close",
        "mut_close_retained",
        "2026-08-20T12:00:00Z",
        decision="dropped",
        reason="Retain the exact recovery preimage.",
    )
    with pytest.raises(BookFlowError, match="before close retirement"):
        flow.execute(command, _manifest(), capabilities=caps)

    assert injected
    assert state.read_bytes() == foreign
    assert quarantine.read_bytes() == original
    assert not retire.exists()
    state.unlink()

    recovered = BookFlow(resolver, runs, policy).execute(
        command, _manifest(), capabilities=caps
    )

    assert recovered.replayed and recovered.state.status == "closed"
    assert not state.exists()
    assert not quarantine.exists()
    assert not retire.exists()
    assert runs.status("run_book_one")["status"] == "running"


def test_zone_identity_is_rechecked_after_durable_evidence(tmp_path: Path):
    vault, resolver, policy, runs, caps, flow = _setup(tmp_path)
    flow.execute(_active(), _manifest(), capabilities=caps)
    reading = vault / "agent/reading"
    held = vault / "agent/reading-held"
    outside = tmp_path / "outside"
    outside.mkdir()

    def swap_zone() -> None:
        reading.rename(held)
        reading.symlink_to(outside, target_is_directory=True)

    command = _command(
        "progress",
        "mut_zone_swap",
        "2026-08-20T11:00:00Z",
        chapter=2,
    )
    with pytest.raises(BookFlowError, match="zone changed"):
        flow.execute(
            command,
            _manifest(),
            capabilities=caps,
            crash_hooks=BookCrashHooks(after_evidence=swap_zone),
        )
    assert list(outside.iterdir()) == []

    reading.unlink()
    held.rename(reading)
    recovered = BookFlow(resolver, runs, policy).execute(
        command, _manifest(), capabilities=caps
    )
    assert recovered.replayed and recovered.state.current_chapter == 2


def test_repeated_malformed_state_failures_do_not_leak_descriptors(tmp_path: Path):
    vault, _, _, _, caps, flow = _setup(tmp_path)
    flow.execute(_active(), _manifest(), capabilities=caps)
    state = vault / "agent/reading/portable-book.json"
    state.write_text('{"schema_version":1}\n', "utf-8")
    before = len(os.listdir("/dev/fd"))
    for _ in range(50):
        with pytest.raises(BookFlowError):
            flow.stale(
                StaleReadingQuery(
                    BOOK_SCHEMA_VERSION,
                    "portable-book",
                    "2026-08-30T10:00:00Z",
                    7,
                ),
                _manifest(),
                capabilities=caps,
            )
    assert len(os.listdir("/dev/fd")) == before


@pytest.mark.parametrize(
    "command",
    [
        replace(_active(), schema_version=True),
        replace(_active(), slug="Portable-Book"),
        replace(_active(), occurred_at="2026-08-20"),
        _command(
            "discuss",
            "mut_private_text",
            "2026-08-20T11:00:00Z",
            text="FILE:/HOME/private/reading.md",
        ),
        _command(
            "progress",
            "mut_bad_chapter",
            "2026-08-20T11:00:00Z",
            chapter=0,
        ),
        _command(
            "anchor",
            "mut_bad_target",
            "2026-08-20T11:00:00Z",
            chapter=1,
            text="Portable text.",
            anchor_id="anchor_bad_target",
            review_id="rev_book_bad_target",
            target_path="knowledge/_archive/anchor.md",
            surface="gated",
        ),
    ],
)
def test_malformed_commands_are_normalized(command: BookCommand) -> None:
    with pytest.raises(BookFlowError):
        render_book_command(command)
