"""P2-05 evidence-bound distill flow acceptance."""

from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path
import shutil
import sys
from typing import Callable

import pytest

from tool_life_os_runtime.ext.connectors.llmwiki import (
    HashedRecord,
    LlmWikiConnector,
    TopicSnapshot,
)
from tool_life_os_runtime.ext.flows.distill import (
    DISTILL_OUTPUT_SCHEMA_VERSION,
    DISTILL_TASK_SCHEMA_VERSION,
    DistillError,
    DistillFlow,
    DistillLimits,
    render_distill_task_packet,
)
from tool_life_os_runtime.ext.review.artifact import validate_artifact_plan
from tool_life_os_runtime.ext.review.authority import AuthorityPolicy
from tool_life_os_runtime.ext.runs import RunStore
from tool_life_os_runtime.ext.vault.config import load_vault_config
from tool_life_os_runtime.ext.vault.schema import VaultPathResolver


SOURCE_IDS = (
    "src_aaaaaaaaaaaa",
    "src_bbbbbbbbbbbb",
    "src_cccccccccccc",
)
CLAIM_IDS = (
    "clm_111111111111",
    "clm_222222222222",
    "clm_333333333333",
    "clm_444444444444",
)
WIKI_ID = "wik_dddddddddddd"
ROOT = Path(__file__).resolve().parents[1]
VAULT_FIXTURE = ROOT / "tests" / "fixtures" / "vault-minimal"


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _write_jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    path.write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows),
        "utf-8",
    )


def _render_wiki(frontmatter: dict[str, object], body: str) -> str:
    lines = ["---\n"]
    for key, value in frontmatter.items():
        if isinstance(value, list):
            lines.append(f"{key}:\n")
            lines.extend(f"  - {item}\n" for item in value)
        else:
            lines.append(f"{key}: {value}\n")
    lines.append("---\n")
    body = body.strip("\n")
    if body:
        lines.extend(("\n", body, "\n"))
    return "".join(lines)


def _course_topic(tmp_path: Path) -> Path:
    root = tmp_path / "topics" / "course-pilot"
    (root / "sources/content").mkdir(parents=True)
    (root / "staging").mkdir()
    (root / "final/wiki").mkdir(parents=True)
    (root / "work").mkdir()
    manifest = {
        "spec_version": "0.1.0",
        "topic": "Practical course synthesis",
        "slug": "course-pilot",
        "created_at": "2026-08-20T09:00:00+00:00",
    }
    sources = [
        {
            "id": SOURCE_IDS[0],
            "kind": "local",
            "title": "Lesson one transcript",
            "content_path": "sources/content/lesson-one.md",
            "meta": {"lesson": 1},
        },
        {
            "id": SOURCE_IDS[1],
            "kind": "local",
            "title": "Lesson two exercises",
            "content_path": "sources/content/lesson-two.md",
            "meta": {"lesson": 2},
        },
        {
            "id": SOURCE_IDS[2],
            "kind": "local",
            "title": "Lesson three retrospective",
            "content_path": "sources/content/lesson-three.md",
            "meta": {"lesson": 3},
        },
    ]
    claims = [
        {
            "id": CLAIM_IDS[0],
            "text": "A short retrieval attempt should precede adding new notes.",
            "confidence": "high",
            "status": "verified",
            "evidence": [
                {
                    "source_id": SOURCE_IDS[0],
                    "quote": "retrieve a related note before capturing",
                    "stance": "supports",
                    "locator": {"type": "line", "value": "1"},
                }
            ],
            "created_at": "2026-08-20T09:01:00+00:00",
        },
        {
            "id": CLAIM_IDS[1],
            "text": "An atomic note should express one reusable decision.",
            "confidence": "high",
            "status": "final",
            "evidence": [
                {
                    "source_id": SOURCE_IDS[0],
                    "quote": "one reusable decision per atomic note",
                    "stance": "supports",
                    "locator": {"type": "line", "value": "2"},
                }
            ],
            "created_at": "2026-08-20T09:02:00+00:00",
        },
        {
            "id": CLAIM_IDS[2],
            "text": "Reviewing retrieval failures reveals missing vocabulary.",
            "confidence": "medium",
            "status": "verified",
            "evidence": [
                {
                    "source_id": SOURCE_IDS[1],
                    "quote": "retrieval failures exposes missing vocabulary",
                    "stance": "supports",
                    "locator": {"type": "line", "value": "1"},
                }
            ],
            "created_at": "2026-08-20T09:03:00+00:00",
        },
        {
            "id": CLAIM_IDS[3],
            "text": "A weekly synthesis should preserve links to exact evidence.",
            "confidence": "high",
            "status": "final",
            "evidence": [
                {
                    "source_id": SOURCE_IDS[2],
                    "quote": "weekly synthesis keeps exact evidence links",
                    "stance": "supports",
                    "locator": {"type": "line", "value": "1"},
                }
            ],
            "created_at": "2026-08-20T09:04:00+00:00",
        },
    ]
    (root / "topic.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", "utf-8"
    )
    (root / "sources/content/lesson-one.md").write_text(
        "First retrieve a related note before capturing a new observation.\n"
        "Keep one reusable decision per atomic note to make later synthesis dense.\n",
        "utf-8",
    )
    (root / "sources/content/lesson-two.md").write_text(
        "A log of retrieval failures exposes missing vocabulary and weak links.\n",
        "utf-8",
    )
    (root / "sources/content/lesson-three.md").write_text(
        "The weekly synthesis keeps exact evidence links beside each conclusion.\n",
        "utf-8",
    )
    _write_jsonl(root / "sources/sources.jsonl", sources)
    _write_jsonl(root / "final/claims.jsonl", claims)
    (root / "staging/claims.jsonl").write_text("", "utf-8")
    (root / "final/wiki/course.md").write_text(
        _render_wiki(
            {
                "id": WIKI_ID,
                "title": "Course synthesis",
                "claims": list(CLAIM_IDS),
                "updated_at": "2026-08-20T09:05:00+00:00",
            },
            "# Course synthesis\n\nA compact machine-topic overview.",
        ),
        "utf-8",
    )
    return root


def _snapshot(tmp_path: Path) -> tuple[Path, TopicSnapshot]:
    topic = _course_topic(tmp_path)
    connector = LlmWikiConnector(
        topics_root=topic.parent,
        command=(sys.executable,),
        cwd=tmp_path,
        env={},
    )
    return topic, connector.read_topic(topic)


def _capability(policy: AuthorityPolicy):
    return policy.issue(
        flow_id="distill",
        action_id="commit-review-proposal",
        actor="runtime",
        authority="proposal",
        target="vault:review",
    )


def _valid_output(packet_bytes: bytes) -> dict[str, object]:
    packet = json.loads(packet_bytes)
    statements = []
    for index, claim in enumerate(packet["claims"], start=1):
        statements.append(
            {
                "statement_id": f"stmt_{index}",
                "text": (
                    claim["text"]
                    + " This operational rule remains useful because it names both "
                    "the decision and the observable practice that supports it."
                ),
                "claim_ids": [claim["claim_id"]],
                "block_refs": [claim["evidence"]["block_ref"]],
            }
        )
    return {
        "schema_version": DISTILL_OUTPUT_SCHEMA_VERSION,
        "task_packet_sha256": hashlib.sha256(packet_bytes).hexdigest(),
        "target_path": "knowledge/domains/learning/course-distilled.md",
        "title": "Course distillation",
        "statements": statements,
    }


class FakeExecutor:
    def __init__(
        self,
        mutate: Callable[[dict[str, object], bytes], object] | None = None,
    ) -> None:
        self.calls: list[bytes] = []
        self._mutate = mutate

    def execute(self, packet_bytes: bytes) -> object:
        self.calls.append(packet_bytes)
        output = _valid_output(packet_bytes)
        if self._mutate is None:
            return output
        return self._mutate(output, packet_bytes)


def _flow(
    executor: FakeExecutor,
    *,
    limits: DistillLimits | None = None,
) -> tuple[DistillFlow, object]:
    policy = AuthorityPolicy()
    return (
        DistillFlow(policy=policy, executor=executor, limits=limits),
        _capability(policy),
    )


def _tree_bytes(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def _running_store(tmp_path: Path, snapshot: TopicSnapshot) -> tuple[Path, RunStore]:
    vault = tmp_path / "vault"
    shutil.copytree(VAULT_FIXTURE, vault)
    resolver = VaultPathResolver(vault, load_vault_config(vault / "lifeos.toml"))
    store = RunStore(resolver)
    store.create(
        run_id="run_bound_distill",
        flow="distill",
        phase="synthesize",
        authority="proposal",
        executor="fake",
        input_data={"topic_snapshot_sha256": snapshot.snapshot_sha256},
    )
    store.resume("run_bound_distill", executor="fake")
    return vault, store


def _rehash_claim(snapshot: TopicSnapshot, index: int, payload: dict[str, object]) -> TopicSnapshot:
    claim_hash = _digest(payload)
    record = replace(
        snapshot.final_claims[index],
        payload=payload,
        sha256=claim_hash,
        payload_sha256=claim_hash,
    )
    claims = list(snapshot.final_claims)
    claims[index] = record
    snapshot_hash = _digest(
        {
            "schema_version": 1,
            "spec_version": snapshot.spec_version,
            "manifest_sha256": snapshot.manifest_sha256,
            "sources": list(snapshot.source_hashes),
            "final_claims": [(item.record_id, item.sha256) for item in claims],
            "wiki_pages": [(item.relative_ref, item.sha256) for item in snapshot.wiki_pages],
        }
    )
    return replace(snapshot, final_claims=tuple(claims), snapshot_sha256=snapshot_hash)


def test_course_pilot_returns_dense_evidence_bound_in_memory_proposal(
    tmp_path: Path,
) -> None:
    topic, snapshot = _snapshot(tmp_path)
    before = _tree_bytes(topic)
    executor = FakeExecutor()
    flow, capability = _flow(executor)

    result = flow.distill(
        snapshot,
        run_id="run_course_pilot",
        review_id="rev_course_pilot",
        created_at="2026-08-20T10:00:00Z",
        surface="gated",
        proposal_capability=capability,
    )

    packet = result.task_packet
    assert packet.schema_version == DISTILL_TASK_SCHEMA_VERSION
    assert packet.context.used_bytes == len(executor.calls[0])
    assert packet.context.used_bytes <= packet.context.budget_bytes
    assert packet.context.source_text_bytes == sum(block.byte_length for block in packet.blocks)
    assert len(packet.claims) == len(CLAIM_IDS)
    assert {claim.claim_id for claim in packet.claims} == set(CLAIM_IDS)
    assert packet.context.claim_ids == tuple(claim.claim_id for claim in packet.claims)
    assert packet.context.block_refs == tuple(block.block_ref for block in packet.blocks)
    assert all(
        block.sha256 == hashlib.sha256(block.text.encode("utf-8")).hexdigest()
        and block.byte_length == len(block.text.encode("utf-8"))
        for block in packet.blocks
    )
    assert result.task_packet_sha256 == hashlib.sha256(executor.calls[0]).hexdigest()

    artifact = result.proposal.artifact
    plan = result.proposal.plan
    validate_artifact_plan(artifact, plan)
    assert artifact.status == "proposed"
    assert artifact.flow == "distill"
    assert len(plan.operations) == 1
    operation = plan.operations[0]
    assert operation.op == "create"
    assert operation.precondition_sha256 is None
    assert operation.content is not None
    assert len(operation.content.encode("utf-8")) > 900
    for claim in packet.claims:
        assert claim.claim_id in operation.content
    for block in packet.blocks:
        assert block.block_ref in operation.content
        assert block.sha256 in operation.content
    assert set(operation.source_refs) == {source.ref for source in artifact.sources}
    assert _tree_bytes(topic) == before
    assert not list(tmp_path.rglob("rev_course_pilot*"))


def test_task_packet_is_deterministic_and_capability_is_exact(tmp_path: Path) -> None:
    _, snapshot = _snapshot(tmp_path)
    executor = FakeExecutor()
    flow, capability = _flow(executor)

    one = flow.prepare_task_packet(
        snapshot,
        run_id="run_deterministic",
        proposal_capability=capability,
    )
    two = flow.prepare_task_packet(
        snapshot,
        run_id="run_deterministic",
        proposal_capability=capability,
    )
    assert render_distill_task_packet(one) == render_distill_task_packet(two)
    assert one.context.used_bytes == len(render_distill_task_packet(one))

    other_policy = AuthorityPolicy()
    wrong = other_policy.issue(
        flow_id="distill",
        action_id="read-validated-claims",
        actor="runtime",
        authority="read",
        target="machine-topic:validated-claims",
    )
    with pytest.raises(DistillError):
        flow.prepare_task_packet(
            snapshot,
            run_id="run_deterministic",
            proposal_capability=wrong,
        )


def test_run_store_binding_is_read_only_and_leaves_run_running(tmp_path: Path) -> None:
    _, snapshot = _snapshot(tmp_path)
    vault, store = _running_store(tmp_path, snapshot)
    executor = FakeExecutor()
    policy = AuthorityPolicy()
    flow = DistillFlow(policy=policy, executor=executor, run_store=store)
    capability = _capability(policy)
    run_dir = vault / "agent/runs/run_bound_distill"
    before = _tree_bytes(run_dir)

    result = flow.distill(
        snapshot,
        run_id="run_bound_distill",
        review_id="rev_bound_distill",
        created_at="2026-08-20T10:00:00Z",
        surface="gated",
        proposal_capability=capability,
    )

    assert result.run_state_sha256 == result.task_packet.run_state_sha256
    assert result.run_state_sha256 is not None
    assert store.status("run_bound_distill")["status"] == "running"
    assert _tree_bytes(run_dir) == before


def test_run_state_change_during_execution_rejects_proposal(tmp_path: Path) -> None:
    _, snapshot = _snapshot(tmp_path)
    _, store = _running_store(tmp_path, snapshot)

    def change_run(output: dict[str, object], _packet_bytes: bytes) -> object:
        store.transition(
            "run_bound_distill",
            status="transient_wait",
            phase="synthesize",
            error_kind="executor-unavailable",
            error_detail="synthetic",
        )
        return output

    policy = AuthorityPolicy()
    flow = DistillFlow(
        policy=policy,
        executor=FakeExecutor(change_run),
        run_store=store,
    )
    with pytest.raises(DistillError, match="active topic snapshot"):
        flow.distill(
            snapshot,
            run_id="run_bound_distill",
            review_id="rev_stale_run",
            created_at="2026-08-20T10:00:00Z",
            surface="gated",
            proposal_capability=_capability(policy),
        )
    assert store.status("run_bound_distill")["status"] == "transient_wait"


@pytest.mark.parametrize("fault", ["missing-evidence", "missing-source", "missing-quote"])
def test_malformed_or_missing_claim_evidence_fails_closed(
    tmp_path: Path,
    fault: str,
) -> None:
    _, snapshot = _snapshot(tmp_path)
    payload = dict(snapshot.final_claims[0].payload)
    if fault == "missing-evidence":
        payload["evidence"] = []
    else:
        evidence = [dict(item) for item in payload["evidence"]]
        if fault == "missing-source":
            evidence[0]["source_id"] = "src_ffffffffffff"
        else:
            evidence[0]["quote"] = "evidence text which is not in the source"
        payload["evidence"] = evidence
    changed = _rehash_claim(snapshot, 0, payload)
    flow, capability = _flow(FakeExecutor())

    with pytest.raises(DistillError):
        flow.prepare_task_packet(
            changed,
            run_id="run_bad_evidence",
            proposal_capability=capability,
        )


@pytest.mark.parametrize(
    "fault",
    [
        "wrong-version",
        "wrong-packet",
        "unknown-claim",
        "unknown-block",
        "wrong-exact-block",
        "unrelated-extra-block",
        "missing-coverage",
        "skeleton",
        "private-target",
        "archive-target",
        "archive-case-target",
        "secret-text",
        "uppercase-file-text",
        "windows-users-text",
        "windows-home-text",
        "mixed-credential-text",
        "credential-path-text",
        "duplicate-json",
    ],
)
def test_untrusted_executor_output_is_strictly_evidence_bound(
    tmp_path: Path,
    fault: str,
) -> None:
    _, snapshot = _snapshot(tmp_path)

    def break_output(output: dict[str, object], packet_bytes: bytes) -> object:
        statements = output["statements"]
        assert isinstance(statements, list)
        if fault == "wrong-version":
            output["schema_version"] = 2
        elif fault == "wrong-packet":
            output["task_packet_sha256"] = "0" * 64
        elif fault == "unknown-claim":
            statements[0]["claim_ids"] = ["clm_ffffffffffff"]
        elif fault == "unknown-block":
            statements[0]["block_refs"] = ["sources/src_ffffffffffff/lines/1"]
        elif fault == "wrong-exact-block":
            statements[0]["block_refs"] = statements[1]["block_refs"]
        elif fault == "unrelated-extra-block":
            statements[0]["block_refs"].append(statements[2]["block_refs"][0])
        elif fault == "missing-coverage":
            statements.pop()
        elif fault == "skeleton":
            for statement in statements:
                statement["text"] = "A bounded summary."
        elif fault == "private-target":
            output["target_path"] = "knowledge/" + "/" + "Users/example/private.md"
        elif fault == "archive-target":
            output["target_path"] = "knowledge/_on_hold/course.md"
        elif fault == "archive-case-target":
            output["target_path"] = "knowledge/_ARCHIVE/course.md"
        elif fault == "secret-text":
            statements[0]["text"] = "Author" + "ization: synthetic-token-value"
        elif fault == "uppercase-file-text":
            statements[0]["text"] = "Read FILE:/private/topic before continuing."
        elif fault == "windows-users-text":
            statements[0]["text"] = r"Read C:\UsErS\Person\topic before continuing."
        elif fault == "windows-home-text":
            statements[0]["text"] = r"Read C:\HoMe\Person\topic before continuing."
        elif fault == "mixed-credential-text":
            statements[0]["text"] = "CrEdEnTiAl = synthetic-value"
        elif fault == "credential-path-text":
            statements[0]["text"] = "Read docs/CrEdEnTiAl/current before continuing."
        else:
            digest = hashlib.sha256(packet_bytes).hexdigest()
            return (
                '{"schema_version":1,"schema_version":1,'
                f'"task_packet_sha256":"{digest}",'
                '"target_path":"knowledge/a.md","title":"A","statements":[]}'
            )
        return output

    limits = None
    if fault == "skeleton":
        limits = DistillLimits(min_synthesis_bytes=100)
    flow, capability = _flow(FakeExecutor(break_output), limits=limits)

    with pytest.raises(DistillError) as raised:
        flow.distill(
            snapshot,
            run_id="run_bad_output",
            review_id="rev_bad_output",
            created_at="2026-08-20T10:00:00Z",
            surface="gated",
            proposal_capability=capability,
        )
    assert "synthetic-token-value" not in str(raised.value)


def test_context_budget_counts_exact_packet_bytes_at_every_boundary(tmp_path: Path) -> None:
    _, snapshot = _snapshot(tmp_path)
    reference_flow, reference_capability = _flow(FakeExecutor())
    reference = reference_flow.prepare_task_packet(
        snapshot,
        run_id="run_budget_boundary",
        proposal_capability=reference_capability,
    )
    full_size = reference.context.used_bytes
    accepted_sizes: list[int] = []
    accepted_claim_counts: list[int] = []
    policy = AuthorityPolicy()
    capability = _capability(policy)

    for budget in range(1, full_size + 2):
        limits = DistillLimits(
            max_context_bytes=budget,
            max_block_bytes=min(256, budget),
        )
        flow = DistillFlow(policy=policy, executor=FakeExecutor(), limits=limits)
        try:
            packet = flow.prepare_task_packet(
                snapshot,
                run_id="run_budget_boundary",
                proposal_capability=capability,
            )
        except DistillError:
            continue
        rendered = render_distill_task_packet(packet)
        assert packet.context.used_bytes == len(rendered)
        assert len(rendered) <= budget
        assert packet.context.source_text_bytes == sum(
            block.byte_length for block in packet.blocks
        )
        accepted_sizes.append(len(rendered))
        accepted_claim_counts.append(len(packet.claims))

    assert accepted_sizes
    assert max(accepted_claim_counts) == len(reference.claims)


def test_private_or_secret_machine_context_is_suppressed(tmp_path: Path) -> None:
    _, snapshot = _snapshot(tmp_path)
    source = snapshot.sources[0]
    secret_line = (
        "Author" + "ization: synthetic-secret-value retrieve a related note before capturing"
    )
    payload = dict(source.payload)
    content_hash = hashlib.sha256(secret_line.encode("utf-8")).hexdigest()
    payload_hash = _digest(payload)
    stable_hash = _digest(
        {"content_sha256": content_hash, "payload_sha256": payload_hash}
    )
    changed_source = replace(
        source,
        content=secret_line,
        content_sha256=content_hash,
        payload_sha256=payload_hash,
        sha256=stable_hash,
    )
    sources = (changed_source, *snapshot.sources[1:])
    source_hashes = ((changed_source.record_id, stable_hash), *snapshot.source_hashes[1:])
    snapshot_hash = _digest(
        {
            "schema_version": 1,
            "spec_version": snapshot.spec_version,
            "manifest_sha256": snapshot.manifest_sha256,
            "sources": list(source_hashes),
            "final_claims": [
                (item.record_id, item.sha256) for item in snapshot.final_claims
            ],
            "wiki_pages": [(item.relative_ref, item.sha256) for item in snapshot.wiki_pages],
        }
    )
    changed = replace(
        snapshot,
        sources=sources,
        source_hashes=source_hashes,
        snapshot_sha256=snapshot_hash,
    )
    flow, capability = _flow(FakeExecutor())

    with pytest.raises(DistillError) as raised:
        flow.prepare_task_packet(
            changed,
            run_id="run_private_context",
            proposal_capability=capability,
        )
    assert "synthetic-secret-value" not in str(raised.value)


def test_snapshot_mutation_during_execution_is_detected(tmp_path: Path) -> None:
    _, snapshot = _snapshot(tmp_path)

    def mutate_snapshot(output: dict[str, object], _packet_bytes: bytes) -> object:
        snapshot.final_claims[0].payload["text"] = "Changed after packet creation"
        return output

    flow, capability = _flow(FakeExecutor(mutate_snapshot))
    with pytest.raises(DistillError, match="stale"):
        flow.distill(
            snapshot,
            run_id="run_stale_snapshot",
            review_id="rev_stale_snapshot",
            created_at="2026-08-20T10:00:00Z",
            surface="gated",
            proposal_capability=capability,
        )


@pytest.mark.parametrize("field", ["frontmatter", "body"])
def test_mutable_wiki_page_content_is_bound_to_its_snapshot_hash(
    tmp_path: Path,
    field: str,
) -> None:
    _, snapshot = _snapshot(tmp_path)
    assert snapshot.wiki_pages

    def mutate_wiki(output: dict[str, object], _packet_bytes: bytes) -> object:
        if field == "frontmatter":
            snapshot.wiki_pages[0].frontmatter["title"] = "Changed after packet creation"
        else:
            object.__setattr__(snapshot.wiki_pages[0], "body", "Changed body")
        return output

    flow, capability = _flow(FakeExecutor(mutate_wiki))
    with pytest.raises(DistillError, match="wiki page hash is stale"):
        flow.distill(
            snapshot,
            run_id="run_stale_wiki",
            review_id="rev_stale_wiki",
            created_at="2026-08-20T10:00:00Z",
            surface="gated",
            proposal_capability=capability,
        )


def test_noncanonical_snapshot_and_executor_unicode_fail_as_domain_errors(
    tmp_path: Path,
) -> None:
    _, snapshot = _snapshot(tmp_path)
    malformed = HashedRecord(
        record_id=snapshot.final_claims[0].record_id,
        payload={**snapshot.final_claims[0].payload, "text": "\ud800"},
        sha256=snapshot.final_claims[0].sha256,
        payload_sha256=snapshot.final_claims[0].payload_sha256,
    )
    changed = replace(
        snapshot,
        final_claims=(malformed, *snapshot.final_claims[1:]),
    )
    flow, capability = _flow(FakeExecutor())
    with pytest.raises(DistillError):
        flow.prepare_task_packet(
            changed,
            run_id="run_bad_unicode",
            proposal_capability=capability,
        )

    malformed_source = replace(snapshot.sources[0], content="\ud800")
    source_changed = replace(
        snapshot,
        sources=(malformed_source, *snapshot.sources[1:]),
    )
    with pytest.raises(DistillError):
        flow.prepare_task_packet(
            source_changed,
            run_id="run_bad_unicode",
            proposal_capability=capability,
        )

    unicode_flow, unicode_capability = _flow(
        FakeExecutor(lambda _output, _packet: "\ud800")
    )
    with pytest.raises(DistillError):
        unicode_flow.distill(
            snapshot,
            run_id="run_bad_unicode",
            review_id="rev_bad_unicode",
            created_at="2026-08-20T10:00:00Z",
            surface="gated",
            proposal_capability=unicode_capability,
        )
