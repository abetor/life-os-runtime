"""P2-06 bounded cited ask retrieval and proposal-only file-back."""

from dataclasses import replace
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil

import pytest

from tool_life_os_runtime.ext.flows.ask import (
    AskError,
    AskFileBack,
    AskFlow,
    AskLimits,
    parse_ask_result,
    publish_ask_result,
    render_ask_context,
    render_ask_result,
)
from tool_life_os_runtime.ext.flows.ask import flow as ask_module
from tool_life_os_runtime.ext.review.artifact import validate_artifact_plan
from tool_life_os_runtime.ext.review.authority import AuthorityPolicy
from tool_life_os_runtime.ext.runs import RunStore
from tool_life_os_runtime.ext.vault.config import load_vault_config
from tool_life_os_runtime.ext.vault.schema import VaultPathResolver


FIXTURES = Path(__file__).parent / "fixtures"


def _vault(tmp_path: Path, fixture: str = "vault-populated") -> Path:
    target = tmp_path / "vault"
    shutil.copytree(FIXTURES / fixture, target)
    return target


def _flow(vault: Path, *, limits: AskLimits | None = None):
    policy = AuthorityPolicy()
    resolver = VaultPathResolver(vault, load_vault_config(vault))
    flow = AskFlow(resolver, policy=policy, limits=limits)
    read = policy.issue(
        flow_id="ask",
        action_id="retrieve-cited-evidence",
        actor="runtime",
        authority="read",
        target="vault:knowledge",
    )
    proposal = policy.issue(
        flow_id="ask",
        action_id="optional-file-back-proposal",
        actor="runtime",
        authority="proposal",
        target="vault:review",
    )
    return flow, policy, read, proposal


def _snapshot(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file() and not path.is_symlink()
    }


def _empty_knowledge(vault: Path) -> Path:
    knowledge = vault / "knowledge"
    for path in sorted(knowledge.rglob("*"), reverse=True):
        if path.is_symlink() or path.is_file():
            path.unlink()
        elif path.is_dir():
            path.rmdir()
    return knowledge


def test_retrieval_is_deterministic_cited_and_read_only(tmp_path: Path) -> None:
    vault = _vault(tmp_path)
    flow, _, read, _ = _flow(vault)
    before = _snapshot(vault)

    first = flow.ask(
        "deterministic gate",
        run_id="run_ask-001",
        read_capability=read,
    )
    second = flow.ask(
        "deterministic gate",
        run_id="run_ask-001",
        read_capability=read,
    )

    assert first == second
    assert not first.evidence_gap
    assert first.citations
    assert first.context_bytes == len(render_ask_context(first))
    assert first.context_bytes <= AskLimits().max_context_bytes
    for citation in first.citations:
        source = vault / citation.path
        assert source.is_file()
        assert not source.is_symlink()
        assert hashlib.sha256(source.read_bytes()).hexdigest() == citation.sha256
        assert citation.path in first.answer
        assert citation.sha256 in first.answer
    assert _snapshot(vault) == before


def test_gap_is_explicit_and_does_not_invent_a_citation(tmp_path: Path) -> None:
    vault = _vault(tmp_path)
    flow, _, read, _ = _flow(vault)

    result = flow.ask(
        "term-that-does-not-exist",
        run_id="run_ask-gap",
        read_capability=read,
    )

    assert result.evidence_gap is True
    assert result.citations == ()
    assert result.context_bytes == len(render_ask_context(result))
    assert result.context_bytes > 0
    assert "does not contain enough evidence" in result.answer


def test_ask_result_canonical_round_trip_and_privacy_rejection(tmp_path: Path) -> None:
    vault = _vault(tmp_path)
    flow, _, read, _ = _flow(vault)
    result = flow.ask(
        "deterministic gate",
        run_id="run_ask-result",
        read_capability=read,
    )

    rendered = render_ask_result(result)

    assert parse_ask_result(rendered) == result
    assert rendered.endswith(b"\n")
    pretty = json.dumps(json.loads(rendered), ensure_ascii=False, indent=2) + "\n"
    with pytest.raises(AskError, match="canonical JSON"):
        parse_ask_result(pretty)
    with pytest.raises(AskError, match="privacy-safe"):
        render_ask_result(
            replace(
                result,
                answer="authorization=private-value",
                context_bytes=len(
                    render_ask_context(
                        replace(result, answer="authorization=private-value")
                    )
                ),
            )
        )


def test_ask_result_publisher_is_replay_safe_and_committed_by_run_store(
    tmp_path: Path,
) -> None:
    vault = _vault(tmp_path)
    flow, _, read, _ = _flow(vault)
    result = flow.ask(
        "deterministic gate",
        run_id="run_ask-result",
        read_capability=read,
    )
    resolver = VaultPathResolver(vault, load_vault_config(vault))
    store = RunStore(resolver)
    store.create(
        run_id=result.run_id,
        flow="ask",
        phase="retrieve",
        authority="internal-write",
        executor="codex",
        input_data={"query_sha256": result.query_sha256},
    )
    store.resume(result.run_id, executor="codex")

    first = publish_ask_result(store, result)
    second = publish_ask_result(store, result)
    assert first == second
    state = store.commit_step(
        result.run_id,
        step_id="commit-ask-result",
        authority="internal-write",
        input_hash=result.query_sha256,
        output_hash=first.sha256,
        next_phase="validate",
        prepared_artifacts=(first,),
    )

    assert state["artifacts"] == {
        "ask-result": f"agent/runs/{result.run_id}/ask-result.json"
    }
    raw = vault.joinpath(first.state_ref).read_bytes()
    assert parse_ask_result(raw) == result
    assert store.snapshot(result.run_id).artifacts[0].sha256 == first.sha256


def test_ask_result_publisher_rejects_a_different_owning_flow_without_mutation(
    tmp_path: Path,
) -> None:
    vault = _vault(tmp_path)
    flow, _, read, _ = _flow(vault)
    result = flow.ask(
        "deterministic gate",
        run_id="run_ask-owner",
        read_capability=read,
    )
    resolver = VaultPathResolver(vault, load_vault_config(vault))
    store = RunStore(resolver)
    store.create(
        run_id=result.run_id,
        flow="distill",
        phase="collect",
        authority="proposal",
        executor="codex",
        input_data={},
    )
    store.resume(result.run_id, executor="codex")
    before = _snapshot(vault / "agent/runs" / result.run_id)

    with pytest.raises(AskError, match="owning ask run"):
        publish_ask_result(store, result)

    assert _snapshot(vault / "agent/runs" / result.run_id) == before
    assert not (vault / f"agent/runs/{result.run_id}/ask-result.json").exists()


def test_only_the_configured_human_knowledge_zone_is_searched(tmp_path: Path) -> None:
    vault = _vault(tmp_path, "vault-minimal")
    (vault / "knowledge/trap.md").write_text("configured-only-term trap\n", "utf-8")
    configured_root = vault / "human-notes"
    configured_root.mkdir()
    (configured_root / "source.md").write_text("configured-only-term source\n", "utf-8")
    profile = load_vault_config(vault)
    configured = replace(
        profile,
        zones=tuple(
            (name, PurePosixPath("human-notes") if name == "knowledge" else path)
            for name, path in profile.zones
        ),
    )
    policy = AuthorityPolicy()
    flow = AskFlow(VaultPathResolver(vault, configured), policy=policy)
    read = policy.issue(
        flow_id="ask",
        action_id="retrieve-cited-evidence",
        actor="runtime",
        authority="read",
        target="vault:knowledge",
    )

    result = flow.ask(
        "configured-only-term",
        run_id="run_ask-configured",
        read_capability=read,
    )

    assert [item.path for item in result.citations] == ["knowledge/source.md"]


def test_exact_read_authority_is_required(tmp_path: Path) -> None:
    vault = _vault(tmp_path)
    flow, policy, _, proposal = _flow(vault)
    memory_read = policy.issue(
        flow_id="ask",
        action_id="read-memory-retrieval-scope",
        actor="runtime",
        authority="read",
        target="vault:agent/memory",
    )

    for wrong in (memory_read, proposal):
        with pytest.raises(AskError, match="exact ask action"):
            flow.ask(
                "deterministic gate",
                run_id="run_ask-authority",
                read_capability=wrong,
            )


@pytest.mark.parametrize("operation", ["create", "update"])
def test_file_back_returns_bound_proposal_without_writing(
    tmp_path: Path, operation: str
) -> None:
    vault = _vault(tmp_path)
    flow, _, read, proposal = _flow(vault)
    path = (
        "knowledge/domains/ai/new-note.md"
        if operation == "create"
        else "knowledge/domains/ai/portable-workflow.md"
    )
    before = _snapshot(vault)
    request = AskFileBack(
        review_id=f"rev_ask-{operation}",
        created_at="2026-01-15T12:00:00Z",
        operation=operation,
        path=path,
        content="# Reviewed answer\n\nA deterministic gate protects the update.\n",
    )

    first = flow.ask(
        "deterministic gate",
        run_id="run_ask-file-back",
        read_capability=read,
        file_back=request,
        proposal_capability=proposal,
    )
    second = flow.ask(
        "deterministic gate",
        run_id="run_ask-file-back",
        read_capability=read,
        file_back=request,
        proposal_capability=proposal,
    )

    assert first == second
    assert first.proposal is not None
    assert first.proposal.artifact.flow == "ask"
    assert first.proposal.artifact.status == "proposed"
    assert first.proposal.plan.operations[0].path == path
    assert first.proposal.plan.operations[0].op == operation
    validate_artifact_plan(first.proposal.artifact, first.proposal.plan)
    if operation == "create":
        assert first.proposal.plan.operations[0].precondition_sha256 is None
        assert not (vault / path).exists()
    else:
        assert first.proposal.plan.operations[0].precondition_sha256 == hashlib.sha256(
            (vault / path).read_bytes()
        ).hexdigest()
    assert _snapshot(vault) == before


def test_file_back_requires_evidence_and_exact_proposal_authority(tmp_path: Path) -> None:
    vault = _vault(tmp_path)
    flow, _, read, proposal = _flow(vault)
    request = AskFileBack(
        review_id="rev_ask-gap",
        created_at="2026-01-15T12:00:00Z",
        operation="create",
        path="knowledge/new.md",
        content="# Proposed\n",
    )

    with pytest.raises(AskError, match="proposal authority"):
        flow.ask(
            "deterministic gate",
            run_id="run_ask-proposal",
            read_capability=read,
            file_back=request,
        )
    with pytest.raises(AskError, match="exact ask action"):
        flow.ask(
            "deterministic gate",
            run_id="run_ask-proposal",
            read_capability=read,
            file_back=request,
            proposal_capability=read,
        )
    with pytest.raises(AskError, match="requires cited evidence"):
        flow.ask(
            "absent-evidence-term",
            run_id="run_ask-proposal",
            read_capability=read,
            file_back=request,
            proposal_capability=proposal,
        )


@pytest.mark.parametrize(
    "path",
    [
        "../escape.md",
        "knowledge/../escape.md",
        "knowledge//escape.md",
        "knowledge/./escape.md",
        "/knowledge/escape.md",
        "knowledge/_archive/escape.md",
        "knowledge/.hidden/escape.md",
        "knowledge/re\u0301sume\u0301.md",
        "knowledge/escape.json",
    ],
)
def test_file_back_path_cannot_traverse_or_enter_excluded_trees(
    tmp_path: Path, path: str
) -> None:
    vault = _vault(tmp_path)
    flow, _, read, proposal = _flow(vault)
    request = AskFileBack(
        review_id="rev_ask-path",
        created_at="2026-01-15T12:00:00Z",
        operation="create",
        path=path,
        content="# Proposed\n",
    )

    with pytest.raises(AskError, match="path"):
        flow.ask(
            "deterministic gate",
            run_id="run_ask-path",
            read_capability=read,
            file_back=request,
            proposal_capability=proposal,
        )


@pytest.mark.parametrize(
    "path",
    [
        "knowledge/token=synthetic-value.md",
        "knowledge/secret-labelled.md",
        "knowledge/domains/password-note.md",
    ],
)
def test_file_back_path_cannot_expose_credential_or_private_markers(
    tmp_path: Path, path: str
) -> None:
    vault = _vault(tmp_path)
    flow, _, read, proposal = _flow(vault)
    before = _snapshot(vault)
    request = AskFileBack(
        review_id="rev_ask-sensitive-path",
        created_at="2026-01-15T12:00:00Z",
        operation="create",
        path=path,
        content="# Safe proposed content\n",
    )

    with pytest.raises(AskError, match="path") as caught:
        flow.ask(
            "deterministic gate",
            run_id="run_ask-sensitive-path",
            read_capability=read,
            file_back=request,
            proposal_capability=proposal,
        )

    assert path not in str(caught.value)
    assert _snapshot(vault) == before


@pytest.mark.parametrize("operation", ["create", "update"])
def test_file_back_rejects_portable_casefold_dirent_collision_without_writes(
    tmp_path: Path, operation: str
) -> None:
    vault = _vault(tmp_path)
    existing = vault / "knowledge/domains/ai/Case.md"
    existing.write_text("existing portable namespace entry\n", "utf-8")
    flow, _, read, proposal = _flow(vault)
    before = _snapshot(vault)
    request = AskFileBack(
        review_id=f"rev_ask-case-{operation}",
        created_at="2026-01-15T12:00:00Z",
        operation=operation,
        path="knowledge/domains/ai/case.md",
        content="# Safe proposed content\n",
    )

    with pytest.raises(AskError, match="portable namespace"):
        flow.ask(
            "deterministic gate",
            run_id="run_ask-casefold",
            read_capability=read,
            file_back=request,
            proposal_capability=proposal,
        )

    assert _snapshot(vault) == before


def test_archive_is_excluded_and_any_active_symlink_fails_closed(tmp_path: Path) -> None:
    vault = _vault(tmp_path, "vault-minimal")
    knowledge = _empty_knowledge(vault)
    archive = knowledge / "_archive"
    archive.mkdir()
    (archive / "old.md").write_text("archive-only-term\n", "utf-8")
    flow, _, read, _ = _flow(vault)

    result = flow.ask(
        "archive-only-term",
        run_id="run_ask-archive",
        read_capability=read,
    )
    assert result.evidence_gap

    outside = tmp_path / "outside.md"
    outside.write_text("outside-only-term\n", "utf-8")
    (knowledge / "linked.md").symlink_to(outside)
    with pytest.raises(AskError, match="symlink"):
        flow.ask(
            "outside-only-term",
            run_id="run_ask-symlink",
            read_capability=read,
        )


def test_citation_race_is_detected_before_result(monkeypatch, tmp_path: Path) -> None:
    vault = _vault(tmp_path, "vault-minimal")
    knowledge = _empty_knowledge(vault)
    target = knowledge / "source.md"
    target.write_text("race-term original\n", "utf-8")
    flow, _, read, _ = _flow(vault)
    original = ask_module._read_regular_at
    swapped = False

    def swap_after_first_read(parent_fd: int, name: str, maximum: int):
        nonlocal swapped
        result = original(parent_fd, name, maximum)
        if name == "source.md" and not swapped:
            swapped = True
            target.write_text("race-term replacement\n", "utf-8")
        return result

    monkeypatch.setattr(ask_module, "_read_regular_at", swap_after_first_read)

    with pytest.raises(AskError, match="changed"):
        flow.ask(
            "race-term",
            run_id="run_ask-race",
            read_capability=read,
        )


def test_knowledge_root_swap_is_detected_before_result(monkeypatch, tmp_path: Path) -> None:
    vault = _vault(tmp_path, "vault-minimal")
    knowledge = _empty_knowledge(vault)
    (knowledge / "source.md").write_text("root-race-term original\n", "utf-8")
    flow, _, read, _ = _flow(vault)
    original = AskFlow._collect

    def swap_after_collect(self, root_fd: int, query: str, terms: tuple[str, ...]):
        result = original(self, root_fd, query, terms)
        knowledge.rename(vault / "detached-knowledge")
        knowledge.mkdir()
        (knowledge / "source.md").write_text("root-race-term replacement\n", "utf-8")
        return result

    monkeypatch.setattr(AskFlow, "_collect", swap_after_collect)

    with pytest.raises(AskError, match="changed"):
        flow.ask(
            "root-race-term",
            run_id="run_ask-root-race",
            read_capability=read,
        )


def test_file_back_target_swap_is_detected(monkeypatch, tmp_path: Path) -> None:
    vault = _vault(tmp_path)
    flow, _, read, proposal = _flow(vault)
    request = AskFileBack(
        review_id="rev_ask-target-race",
        created_at="2026-01-15T12:00:00Z",
        operation="update",
        path="knowledge/domains/ai/portable-workflow.md",
        content="# Reviewed answer\n",
    )
    original = AskFlow._proposal
    target_parent = vault / "knowledge/domains/ai"

    def swap_after_proposal(self, *args, **kwargs):
        result = original(self, *args, **kwargs)
        target_parent.rename(vault / "knowledge/domains/ai-detached")
        target_parent.mkdir()
        (target_parent / "portable-workflow.md").write_text(
            "replacement target\n", "utf-8"
        )
        return result

    monkeypatch.setattr(AskFlow, "_proposal", swap_after_proposal)

    with pytest.raises(AskError, match="changed"):
        flow.ask(
            "deterministic gate",
            run_id="run_ask-target-race",
            read_capability=read,
            file_back=request,
            proposal_capability=proposal,
        )


def test_noncanonical_unicode_citation_path_fails_closed(tmp_path: Path) -> None:
    vault = _vault(tmp_path, "vault-minimal")
    knowledge = _empty_knowledge(vault)
    (knowledge / "re\u0301sume\u0301.md").write_text("unicode-term\n", "utf-8")
    flow, _, read, _ = _flow(vault)

    with pytest.raises(AskError, match="unsafe path component"):
        flow.ask(
            "unicode-term",
            run_id="run_ask-unicode",
            read_capability=read,
        )


@pytest.mark.parametrize(
    "name,raw,error",
    [
        ("invalid.md", b"term \xff", "UTF-8"),
        ("malformed.json", b'{"term":', "malformed"),
        ("deep.json", (b'[' * 40) + b'"term"' + (b']' * 40), "deep"),
    ],
)
def test_malformed_or_deep_content_fails_closed(
    tmp_path: Path, name: str, raw: bytes, error: str
) -> None:
    vault = _vault(tmp_path, "vault-minimal")
    knowledge = _empty_knowledge(vault)
    (knowledge / name).write_bytes(raw)
    flow, _, read, _ = _flow(vault)

    with pytest.raises(AskError, match=error):
        flow.ask("term", run_id="run_ask-malformed", read_capability=read)


def test_file_count_content_and_context_budgets_are_enforced(tmp_path: Path) -> None:
    vault = _vault(tmp_path, "vault-minimal")
    knowledge = _empty_knowledge(vault)
    (knowledge / "a.md").write_text("bounded term one\n", "utf-8")
    (knowledge / "b.md").write_text("bounded term two\n", "utf-8")
    flow, _, read, _ = _flow(
        vault,
        limits=AskLimits(
            max_files=1,
            max_file_bytes=128,
            max_total_bytes=128,
            max_context_bytes=64,
            max_citations=1,
            max_excerpt_bytes=64,
            max_depth=4,
        ),
    )
    with pytest.raises(AskError, match="file-count"):
        flow.ask("bounded", run_id="run_ask-bounds", read_capability=read)

    (knowledge / "b.md").unlink()
    (knowledge / "a.md").write_bytes(b"x" * 129)
    with pytest.raises(AskError, match="per-file"):
        flow.ask("bounded", run_id="run_ask-bounds", read_capability=read)


def test_long_citation_path_cannot_escape_tiny_total_context_budget(
    tmp_path: Path,
) -> None:
    vault = _vault(tmp_path, "vault-minimal")
    knowledge = _empty_knowledge(vault)
    long_name = "x" * 180 + "-needle.md"
    (knowledge / long_name).write_text("needle bounded excerpt\n", "utf-8")
    baseline, _, baseline_read, _ = _flow(vault)
    gap = baseline.ask(
        "absent-context-term",
        run_id="run_ask-context-gap",
        read_capability=baseline_read,
    )
    flow, _, read, _ = _flow(
        vault,
        limits=AskLimits(
            max_files=8,
            max_entries=16,
            max_file_bytes=1024,
            max_total_bytes=2048,
            max_context_bytes=gap.context_bytes,
            max_citations=2,
            max_excerpt_bytes=32,
            max_depth=4,
        ),
    )

    result = flow.ask(
        "needle",
        run_id="run_ask-context-long",
        read_capability=read,
    )

    assert result.evidence_gap
    assert result.citations == ()
    assert result.context_bytes == len(render_ask_context(result))
    assert result.context_bytes == gap.context_bytes
    assert result.context_bytes <= gap.context_bytes


@pytest.mark.parametrize(
    "unsafe",
    [
        "token: synthetic-secret-value",
        '{"topic":"needle","token":"synthetic-secret-value"}',
        "/" + "Users" + "/person/private-note",
        '{"topic":"needle","path":"\\/Users\\/person\\/private-note"}',
        "/" + "home" + "/person/private-note",
        "file:private-note",
    ],
)
def test_secret_or_private_evidence_is_never_returned(
    tmp_path: Path, unsafe: str
) -> None:
    vault = _vault(tmp_path, "vault-minimal")
    knowledge = _empty_knowledge(vault)
    (knowledge / "unsafe.md").write_text(f"needle {unsafe}\n", "utf-8")
    flow, _, read, _ = _flow(vault)

    result = flow.ask(
        "needle", run_id="run_ask-private", read_capability=read
    )

    assert result.evidence_gap
    assert unsafe not in result.answer


def test_secret_file_back_content_is_rejected_without_mutation(tmp_path: Path) -> None:
    vault = _vault(tmp_path)
    flow, _, read, proposal = _flow(vault)
    before = _snapshot(vault)
    request = AskFileBack(
        review_id="rev_ask-secret",
        created_at="2026-01-15T12:00:00Z",
        operation="create",
        path="knowledge/new.md",
        content="# Proposed\n\ntoken: synthetic-secret-value\n",
    )

    with pytest.raises(AskError, match="privacy-safe"):
        flow.ask(
            "deterministic gate",
            run_id="run_ask-secret",
            read_capability=read,
            file_back=request,
            proposal_capability=proposal,
        )
    assert _snapshot(vault) == before


@pytest.mark.parametrize(
    "query",
    ["", "   ", "../", "bad\nquery", "/" + "Users" + "/person/private"],
)
def test_query_is_bounded_and_privacy_safe(tmp_path: Path, query: str) -> None:
    vault = _vault(tmp_path)
    flow, _, read, _ = _flow(vault)

    with pytest.raises(AskError, match="query"):
        flow.ask(query, run_id="run_ask-query", read_capability=read)
