"""P3-08 bounded mentor and explicit-human grill-me acceptance."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil

import pytest

from tool_life_os_runtime.ext.flows.grill_me import (
    GrillCapabilities,
    GrillContextBlock,
    GrillContextManifest,
    GrillCrashHooks,
    GrillDecisionRecord,
    GrillExplicitDecision,
    GrillFlowError,
    GrillHumanAnswer,
    GrillMeFlow,
    GrillQuestionOutput,
    GrillRequest,
    GrillRunEvidence,
    GrillSession,
    GrillTurn,
    grill_evidence_artifact_name,
    inspect_grill_run_evidence,
    parse_grill_decision_record,
    parse_grill_question_output,
    parse_grill_run_evidence,
    parse_grill_session,
    render_grill_decision_record,
    render_grill_question_output,
    render_grill_run_evidence,
    render_grill_session,
)
from tool_life_os_runtime.ext.flows.mentor import (
    MentorCapabilities,
    MentorContextBlock,
    MentorContextManifest,
    MentorCrashHooks,
    MentorEvidenceAnchor,
    MentorExecutorOutput,
    MentorFlow,
    MentorFlowError,
    MentorObservation,
    MentorProposalRecord,
    MentorRecommendation,
    MentorRequest,
    MentorRunEvidence,
    MentorTaskPacket,
    inspect_mentor_run_evidence,
    mentor_evidence_artifact_name,
    parse_mentor_executor_output,
    parse_mentor_proposal,
    parse_mentor_run_evidence,
    parse_mentor_task_packet,
    render_mentor_executor_output,
    render_mentor_proposal,
    render_mentor_run_evidence,
    render_mentor_task_packet,
)
import tool_life_os_runtime.ext.flows.grill_me.flow as grill_module
import tool_life_os_runtime.ext.flows.mentor.flow as mentor_module
from tool_life_os_runtime.ext.review.authority import AuthorityPolicy
from tool_life_os_runtime.ext.runs import RunStore
from tool_life_os_runtime.ext.vault.config import load_vault_config
from tool_life_os_runtime.ext.vault.schema import VaultPathResolver


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/vault-minimal"

MENTOR_ACTIONS = {
    "collect-bounded-mentor-context": ("runtime", "read", "vault:projects"),
    "read-mentor-knowledge": ("runtime", "read", "vault:knowledge"),
    "read-mentor-memory": ("runtime", "read", "vault:agent/memory"),
    "commit-mentor-proposal": ("runtime", "proposal", "vault:review"),
    "record-run-state": ("runtime", "internal-write", "vault:agent/runs"),
}
GRILL_ACTIONS = {
    "collect-decision-context": ("human", "read", "vault:projects"),
    "read-decision-memory": ("human", "read", "vault:agent/memory"),
    "commit-question-answer-record": ("human", "proposal", "vault:review"),
    "record-run-state": ("runtime", "internal-write", "vault:agent/runs"),
}


def _issue(policy: AuthorityPolicy, flow: str, action: str):
    actor, authority, target = (MENTOR_ACTIONS if flow == "mentor" else GRILL_ACTIONS)[
        action
    ]
    return policy.issue(
        flow_id=flow,
        action_id=action,
        actor=actor,
        authority=authority,
        target=target,
    )


def _setup(tmp_path: Path, review_zone: str = "review"):
    vault = tmp_path / "vault"
    shutil.copytree(FIXTURE, vault)
    if review_zone != "review":
        profile = vault / "lifeos.toml"
        profile.write_text(
            profile.read_text().replace(
                'review = "review"', f'review = "{review_zone}"'
            )
        )
        (vault / review_zone).mkdir(parents=True)
    project = vault / "projects/alpha/state.json"
    project.parent.mkdir(parents=True)
    project.write_text('{"schema_version":1,"status":"active"}\n')
    knowledge = vault / "knowledge/domain/guide.md"
    knowledge.parent.mkdir(parents=True)
    knowledge.write_text("Keep the next step small and observable.\n")
    memory = vault / "agent/memory/decisions.jsonl"
    memory.parent.mkdir(parents=True, exist_ok=True)
    memory.write_text('{"actor":"human","decision":"ship a pilot"}\n')
    resolver = VaultPathResolver(vault, load_vault_config(vault))
    policy = AuthorityPolicy()
    runs = RunStore(
        resolver, clock=lambda: datetime(2026, 8, 20, 9, tzinfo=timezone.utc)
    )
    for run_id, flow in (("run_mentor_one", "mentor"), ("run_grill_one", "grill-me")):
        runs.create(
            run_id=run_id,
            flow=flow,
            phase=flow,
            authority="proposal",
            executor="fixture",
            input_data={"scope": "alpha"},
        )
        runs.resume(run_id, executor="fixture")
    mentor_caps = MentorCapabilities(
        *(_issue(policy, "mentor", action) for action in MENTOR_ACTIONS)
    )
    grill_caps = GrillCapabilities(
        *(_issue(policy, "grill-me", action) for action in GRILL_ACTIONS)
    )
    return (
        vault,
        resolver,
        policy,
        runs,
        mentor_caps,
        grill_caps,
        MentorFlow(resolver, runs, policy),
        GrillMeFlow(resolver, runs, policy),
    )


def _domain_snapshot(vault: Path) -> dict[str, bytes]:
    result = {}
    for zone in ("projects", "knowledge", "agent/memory"):
        root = vault / zone
        result.update(
            {
                path.relative_to(vault).as_posix(): path.read_bytes()
                for path in sorted(root.rglob("*"))
                if path.is_file() and not path.is_symlink()
            }
        )
    return result


def _mentor_request() -> MentorRequest:
    return MentorRequest(
        "run_mentor_one",
        "mentor_one",
        "mentor-alpha",
        "2026-08-20T10:00:00Z",
        "Choose a bounded next step.",
        "What should be reviewed before the pilot?",
        ("alpha/state.json",),
        ("domain/guide.md",),
        ("decisions.jsonl",),
    )


def _mentor_output(packet) -> MentorExecutorOutput:
    ids = packet.manifest.block_ids
    return MentorExecutorOutput(
        "A pilot is reviewable without changing the project.",
        (MentorObservation("obs-one", "The project is active.", (ids[1],)),),
        (
            MentorRecommendation(
                "rec-one",
                "Review one pilot checkpoint.",
                "It keeps the next action bounded.",
                ids,
            ),
        ),
        ("Which checkpoint should the human approve?",),
    )


def _artifact_raw(vault: Path, artifact) -> bytes:
    return (vault / artifact.state_ref).read_bytes()


def _review_ref(review_zone: str, filename: str) -> str:
    return f"{review_zone}/{filename}"


@pytest.mark.parametrize("review_zone", ["review", "custom/reviews"])
def test_mentor_produces_only_strict_review_and_exact_run_evidence(
    tmp_path: Path, review_zone: str
):
    vault, _, _, runs, caps, _, mentor, _ = _setup(tmp_path, review_zone)
    before = _domain_snapshot(vault)
    packet = mentor.prepare_task_packet(_mentor_request(), capabilities=caps)
    assert packet == mentor.prepare_task_packet(_mentor_request(), capabilities=caps)
    assert packet.manifest.used_bytes == sum(
        len(block.text.encode()) for block in packet.blocks
    )
    assert packet == parse_mentor_task_packet(render_mentor_task_packet(packet))

    result = mentor.commit_proposal(packet, _mentor_output(packet), capabilities=caps)
    assert result.proposal_ref == _review_ref(review_zone, "mentor-alpha.mentor.json")
    proposal = parse_mentor_proposal((vault / result.proposal_ref).read_bytes())
    assert proposal.status == "proposed"
    assert proposal.actor == "runtime"
    assert _domain_snapshot(vault) == before
    assert [path.name for path in (vault / ".lifeos/review-plans").iterdir()] == [
        ".gitkeep"
    ]

    snapshot = runs.snapshot("run_mentor_one")
    evidence_artifact = next(
        item
        for item in snapshot.artifacts
        if item.name == mentor_evidence_artifact_name("mentor_one")
    )
    evidence = inspect_mentor_run_evidence(
        evidence_artifact, _artifact_raw(vault, evidence_artifact)
    )
    assert evidence.output_ref == result.proposal_ref
    assert evidence.output_sha256 == result.proposal_sha256
    actions = runs.trace_events("run_mentor_one")[0]["actions"]
    assert [item["action_id"] for item in actions] == list(MENTOR_ACTIONS)
    assert [item["actor"] for item in actions] == [
        MENTOR_ACTIONS[action][0] for action in MENTOR_ACTIONS
    ]
    assert [item["authority"] for item in actions] == [
        MENTOR_ACTIONS[action][1] for action in MENTOR_ACTIONS
    ]
    assert [item["target"] for item in actions] == [
        MENTOR_ACTIONS[action][2] for action in MENTOR_ACTIONS
    ]

    replay = mentor.commit_proposal(packet, _mentor_output(packet), capabilities=caps)
    assert replay.replayed is True
    changed = replace(_mentor_output(packet), summary="A different proposal.")
    with pytest.raises(MentorFlowError, match="replay changes"):
        mentor.commit_proposal(packet, changed, capabilities=caps)


def test_mentor_strict_output_bounds_refs_and_crash_replay(tmp_path: Path):
    vault, resolver, policy, runs, caps, _, mentor, _ = _setup(tmp_path)
    packet = mentor.prepare_task_packet(_mentor_request(), capabilities=caps)
    raw = render_mentor_executor_output(_mentor_output(packet))
    payload = json.loads(raw)
    payload["project_mutation"] = {"status": "done"}
    with pytest.raises(MentorFlowError, match="unknown fields"):
        parse_mentor_executor_output(
            json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"
        )
    with pytest.raises(MentorFlowError, match="duplicate"):
        parse_mentor_executor_output(
            '{"observations":[],"observations":[],"questions":[],"recommendations":[],"schema_version":1,"summary":"x"}\n'
        )
    bad = replace(
        _mentor_output(packet),
        observations=(MentorObservation("obs-bad", "Unsupported.", ("ctx-missing",)),),
    )
    with pytest.raises(MentorFlowError, match="outside the packet"):
        mentor.commit_proposal(packet, bad, capabilities=caps)

    project = vault / "projects/alpha/state.json"
    original_project = project.read_bytes()
    project.write_text('{"schema_version":1,"status":"changed"}\n')
    with pytest.raises(MentorFlowError, match="current exact sources"):
        mentor.commit_proposal(packet, _mentor_output(packet), capabilities=caps)
    project.write_bytes(original_project)

    with pytest.raises(RuntimeError, match="stop after publish"):
        mentor.commit_proposal(
            packet,
            _mentor_output(packet),
            capabilities=caps,
            hooks=MentorCrashHooks(
                after_proposal_publish=lambda: (_ for _ in ()).throw(
                    RuntimeError("stop after publish")
                )
            ),
        )
    assert not (vault / "review/mentor-alpha.mentor.json").exists()
    result = MentorFlow(resolver, runs, policy).commit_proposal(
        packet, _mentor_output(packet), capabilities=caps
    )
    assert result.replayed is False
    assert len(list((vault / "review").glob("mentor-alpha.mentor.json"))) == 1

    escaped = replace(
        _mentor_request(), proposal_id="mentor-escape", project_refs=("../lifeos.toml",)
    )
    with pytest.raises(MentorFlowError):
        mentor.prepare_task_packet(escaped, capabilities=caps)
    linked = vault / "projects/linked.json"
    linked.symlink_to(vault / "projects/alpha/state.json")
    linked_request = replace(
        _mentor_request(), proposal_id="mentor-link", project_refs=("linked.json",)
    )
    with pytest.raises(MentorFlowError):
        mentor.prepare_task_packet(linked_request, capabilities=caps)


def _grill_request() -> GrillRequest:
    return GrillRequest(
        "run_grill_one",
        "grill_one",
        "grill-alpha",
        "2026-08-20T11:00:00Z",
        "Clarify the pilot decision.",
        ("alpha/state.json",),
        ("decisions.jsonl",),
    )


def _question(number: int, block_ids: tuple[str, ...]) -> GrillQuestionOutput:
    return GrillQuestionOutput(
        f"question-{number}",
        f"2026-08-20T11:0{number}:00Z",
        f"What exact condition {number} must hold?",
        block_ids,
    )


@pytest.mark.parametrize("review_zone", ["review", "custom/reviews"])
def test_grill_persists_questions_answers_and_only_explicit_decision(
    tmp_path: Path, review_zone: str
):
    vault, resolver, policy, runs, _, caps, _, grill = _setup(tmp_path, review_zone)
    before = _domain_snapshot(vault)
    # Context block ids are deterministic from exact zone/ref pairs.
    block_ids = (
        "ctx-" + hashlib.sha256(b"agent/memory\0decisions.jsonl").hexdigest()[:24],
        "ctx-" + hashlib.sha256(b"projects\0alpha/state.json").hexdigest()[:24],
    )
    begin = grill.begin(_grill_request(), _question(1, block_ids), capabilities=caps)
    assert (begin.status, begin.waiting_for) == ("waiting_human", "grill-answer")
    assert runs.status("run_grill_one")["waiting_for"] == "grill-answer"

    runs.resume("run_grill_one", executor="fixture")
    answer_one = GrillHumanAnswer(
        "question-1",
        "human",
        "2026-08-20T11:10:00Z",
        "A human can inspect the checkpoint.",
    )
    middle = GrillMeFlow(resolver, runs, policy).answer(
        "run_grill_one",
        answer_one,
        capabilities=caps,
        next_question=_question(2, block_ids),
    )
    assert middle.waiting_for == "grill-answer"

    runs.resume("run_grill_one", executor="fixture")
    answer_two = GrillHumanAnswer(
        "question-2", "human", "2026-08-20T11:20:00Z", "The pilot remains reversible."
    )
    ready = GrillMeFlow(resolver, runs, policy).answer(
        "run_grill_one", answer_two, capabilities=caps
    )
    assert ready.waiting_for == "grill-decision"
    assert runs.status("run_grill_one")["waiting_for"] == "grill-decision"

    runs.resume("run_grill_one", executor="fixture")
    decision = GrillExplicitDecision(
        "decision-pilot",
        "human",
        "2026-08-20T11:30:00Z",
        "Proceed with the reversible pilot.",
    )
    result = GrillMeFlow(resolver, runs, policy).finish(
        "run_grill_one", decision, capabilities=caps
    )
    assert (result.status, result.waiting_for) == ("running", None)
    assert result.record_ref == _review_ref(review_zone, "grill-alpha.grill.json")
    record = parse_grill_decision_record((vault / result.record_ref).read_bytes())
    assert record.resolution == "explicit-human-decision"
    assert record.explicit_decision == decision
    assert tuple(turn.answer.exact_text for turn in record.turns) == (
        answer_one.exact_text,
        answer_two.exact_text,
    )
    assert _domain_snapshot(vault) == before
    assert [path.name for path in (vault / ".lifeos/review-plans").iterdir()] == [
        ".gitkeep"
    ]

    snapshot = runs.snapshot("run_grill_one")
    final_session_artifact = next(
        item for item in snapshot.artifacts if item.name == result.session_artifact
    )
    final_session = parse_grill_session(_artifact_raw(vault, final_session_artifact))
    assert final_session.explicit_decision == decision
    evidence_artifact = next(
        item
        for item in snapshot.artifacts
        if item.name == grill_evidence_artifact_name("grill_one")
    )
    evidence = inspect_grill_run_evidence(
        evidence_artifact, _artifact_raw(vault, evidence_artifact)
    )
    assert evidence.session_ref == final_session_artifact.state_ref
    assert evidence.output_ref == result.record_ref
    bundle = runs.producer_snapshot(
        "run_grill_one", producer_evidence=result.evidence_artifact
    )
    assert len(bundle.artifacts) == 3
    assert len({item.step_id for item in bundle.artifacts}) == 1
    assert {item.state_ref for item in bundle.artifacts} == {
        evidence.session_ref,
        evidence.output_ref,
        evidence_artifact.state_ref,
    }
    assert [
        [action["action_id"] for action in event["actions"]]
        for event in runs.trace_events("run_grill_one")
    ] == [
        [
            "collect-decision-context",
            "read-decision-memory",
            "record-run-state",
        ],
        ["record-run-state"],
        ["record-run-state"],
        ["commit-question-answer-record", "record-run-state"],
    ]
    assert (
        GrillMeFlow(resolver, runs, policy)
        .finish("run_grill_one", decision, capabilities=caps)
        .replayed
    )
    with pytest.raises(GrillFlowError, match="changes explicit human input"):
        GrillMeFlow(resolver, runs, policy).finish(
            "run_grill_one",
            replace(decision, exact_text="Do not proceed."),
            capabilities=caps,
        )


def test_grill_strict_question_and_unresolved_is_not_inferred(tmp_path: Path):
    vault, _, _, runs, _, caps, _, grill = _setup(tmp_path)
    block_ids = (
        "ctx-" + hashlib.sha256(b"agent/memory\0decisions.jsonl").hexdigest()[:24],
        "ctx-" + hashlib.sha256(b"projects\0alpha/state.json").hexdigest()[:24],
    )
    raw = render_grill_question_output(_question(1, block_ids))
    payload = json.loads(raw)
    payload["answer"] = "invented"
    with pytest.raises(GrillFlowError, match="unknown fields"):
        parse_grill_question_output(
            json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"
        )
    with pytest.raises(GrillFlowError, match="duplicate"):
        parse_grill_question_output(
            '{"asked_at":"2026-08-20T11:01:00Z","evidence_block_ids":["ctx-a"],"question":"x","question":"y","question_id":"question-1","schema_version":1}\n'
        )

    grill.begin(_grill_request(), _question(1, block_ids), capabilities=caps)
    runs.resume("run_grill_one", executor="fixture")
    with pytest.raises(GrillFlowError, match="pending question"):
        grill.answer(
            "run_grill_one",
            GrillHumanAnswer("question-other", "human", "2026-08-20T11:10:00Z", "No."),
            capabilities=caps,
        )
    grill.answer(
        "run_grill_one",
        GrillHumanAnswer(
            "question-1", "human", "2026-08-20T11:10:00Z", "No decision yet."
        ),
        capabilities=caps,
    )
    with pytest.raises(GrillFlowError, match="resumed"):
        grill.finish("run_grill_one", None, capabilities=caps)
    runs.resume("run_grill_one", executor="fixture")
    result = grill.finish("run_grill_one", None, capabilities=caps)
    record = parse_grill_decision_record((vault / result.record_ref).read_bytes())
    assert record.resolution == "unresolved"
    assert record.explicit_decision is None


def test_exact_grill_action_order_and_wrong_actor_capability(tmp_path: Path):
    _, _, policy, runs, _, caps, _, grill = _setup(tmp_path)
    block_ids = (
        "ctx-" + hashlib.sha256(b"agent/memory\0decisions.jsonl").hexdigest()[:24],
        "ctx-" + hashlib.sha256(b"projects\0alpha/state.json").hexdigest()[:24],
    )
    grill.begin(_grill_request(), _question(1, block_ids), capabilities=caps)
    assert [
        action["action_id"]
        for action in runs.trace_events("run_grill_one")[0]["actions"]
    ] == [
        "collect-decision-context",
        "read-decision-memory",
        "record-run-state",
    ]
    wrong = policy.issue(
        flow_id="mentor",
        action_id="record-run-state",
        actor="runtime",
        authority="internal-write",
        target="vault:agent/runs",
    )
    runs.resume("run_grill_one", executor="fixture")
    with pytest.raises(GrillFlowError, match="not exact"):
        grill.answer(
            "run_grill_one",
            GrillHumanAnswer(
                "question-1", "human", "2026-08-20T11:10:00Z", "Exact answer."
            ),
            capabilities=replace(caps, record_run_state=wrong),
        )


@pytest.mark.parametrize("review_zone", ["review", "custom/reviews"])
def test_mentor_committed_evidence_replays_before_mutable_context(
    tmp_path: Path, review_zone: str
):
    vault, _, _, runs, caps, _, mentor, _ = _setup(tmp_path, review_zone)
    packet = mentor.prepare_task_packet(_mentor_request(), capabilities=caps)
    output = _mentor_output(packet)
    first = mentor.commit_proposal(packet, output, capabilities=caps)
    (vault / "projects/alpha/state.json").write_text(
        '{"schema_version":1,"status":"changed-after-commit"}\n'
    )
    (vault / "knowledge/domain/guide.md").write_text("Changed knowledge.\n")
    (vault / "agent/memory/decisions.jsonl").write_text(
        '{"actor":"human","decision":"changed memory"}\n'
    )

    replay = mentor.commit_proposal(packet, output, capabilities=caps)
    assert replay.replayed is True
    assert replay.proposal_sha256 == first.proposal_sha256
    assert replay.proposal_ref == _review_ref(review_zone, "mentor-alpha.mentor.json")
    bundle = runs.producer_snapshot(
        "run_mentor_one", producer_evidence=replay.evidence_artifact
    )
    assert {item.name.split("-", 2)[1] for item in bundle.artifacts} == {
        "evidence",
        "review",
        "task",
    }


def test_grill_next_question_sees_answered_session_and_answer_replays(tmp_path: Path):
    _, resolver, policy, runs, _, caps, _, grill = _setup(tmp_path)
    block_ids = (
        "ctx-" + hashlib.sha256(b"agent/memory\0decisions.jsonl").hexdigest()[:24],
        "ctx-" + hashlib.sha256(b"projects\0alpha/state.json").hexdigest()[:24],
    )
    grill.begin(_grill_request(), _question(1, block_ids), capabilities=caps)
    runs.resume("run_grill_one", executor="fixture")
    answer = GrillHumanAnswer(
        "question-1",
        "human",
        "2026-08-20T11:10:00Z",
        "This exact answer must inform the next question.",
    )
    seen = []

    class Probe:
        def ask(self, session, context):
            seen.append((session, context))
            return _question(2, block_ids)

    first = grill.answer(
        "run_grill_one", answer, capabilities=caps, next_question=Probe()
    )
    assert seen[0][0].turns[-1].answer == answer
    assert seen[0][0].status == "ready-decision"
    assert seen[0][1] == seen[0][0].blocks
    runs.resume("run_grill_one", executor="fixture")
    replay = GrillMeFlow(resolver, runs, policy).answer(
        "run_grill_one",
        answer,
        capabilities=caps,
        next_question=_question(2, block_ids),
    )
    assert replay.replayed is True
    assert replay.session_artifact == first.session_artifact
    with pytest.raises(GrillFlowError, match="changes committed human input"):
        GrillMeFlow(resolver, runs, policy).answer(
            "run_grill_one",
            replace(answer, exact_text="Different answer."),
            capabilities=caps,
            next_question=_question(2, block_ids),
        )


def test_grill_begin_exact_replay_does_not_reread_context(tmp_path: Path):
    vault, resolver, policy, runs, _, caps, _, grill = _setup(tmp_path)
    block_ids = (
        "ctx-" + hashlib.sha256(b"agent/memory\0decisions.jsonl").hexdigest()[:24],
        "ctx-" + hashlib.sha256(b"projects\0alpha/state.json").hexdigest()[:24],
    )
    first = grill.begin(_grill_request(), _question(1, block_ids), capabilities=caps)
    (vault / "projects/alpha/state.json").write_text("changed after begin\n")
    runs.resume("run_grill_one", executor="fixture")
    replay = GrillMeFlow(resolver, runs, policy).begin(
        _grill_request(), _question(1, block_ids), capabilities=caps
    )
    assert replay.replayed is True
    assert replay.session_artifact == first.session_artifact
    with pytest.raises(GrillFlowError, match="changes the committed question"):
        GrillMeFlow(resolver, runs, policy).begin(
            _grill_request(),
            replace(_question(1, block_ids), question="Different question."),
            capabilities=caps,
        )


@pytest.mark.parametrize("flow_name", ["mentor", "grill"])
@pytest.mark.parametrize("seam", ["content", "leaf", "parent", "root"])
def test_context_read_pins_root_parents_leaf_and_content(
    tmp_path: Path, monkeypatch, flow_name: str, seam: str
):
    lane = tmp_path / f"{flow_name}-{seam}"
    vault, _, _, _, mentor_caps, _, mentor, grill = _setup(lane)
    source = vault / "projects/alpha/state.json"
    source_inode = source.stat().st_ino
    original = source.read_bytes()
    module = mentor_module if flow_name == "mentor" else grill_module
    real_read = module.os.read
    changed = False

    def racing_read(fd: int, count: int) -> bytes:
        nonlocal changed
        data = real_read(fd, count)
        if data and not changed and os.fstat(fd).st_ino == source_inode:
            changed = True
            if seam == "content":
                source.write_bytes(b"X" * len(original))
            elif seam == "leaf":
                source.unlink()
                source.write_bytes(original)
            elif seam == "parent":
                parent = source.parent
                detached = parent.with_name("alpha-detached")
                parent.rename(detached)
                parent.mkdir()
                os.link(detached / "state.json", parent / "state.json")
            else:
                detached = vault.with_name("vault-detached")
                vault.rename(detached)
                shutil.copytree(detached, vault, copy_function=os.link)
        return data

    monkeypatch.setattr(module.os, "read", racing_read)
    if flow_name == "mentor":
        request = replace(_mentor_request(), knowledge_refs=(), memory_refs=())

        def invoke():
            return mentor.prepare_task_packet(request, capabilities=mentor_caps)

        error = MentorFlowError
    else:
        request = replace(_grill_request(), memory_refs=())

        def invoke():
            return grill._context(request)

        error = GrillFlowError
    with pytest.raises(error, match="changed|identity"):
        invoke()
    assert changed is True


def test_context_failures_have_bounded_fds(tmp_path: Path):
    descriptor_root = Path("/dev/fd")
    if not descriptor_root.is_dir():
        descriptor_root = Path("/proc/self/fd")
    if not descriptor_root.is_dir():
        pytest.skip("no descriptor projection")
    vault, _, _, _, mentor_caps, _, mentor, grill = _setup(tmp_path)
    linked = vault / "projects/linked.json"
    linked.symlink_to(vault / "projects/alpha/state.json")
    mentor_request = replace(
        _mentor_request(),
        project_refs=("linked.json",),
        knowledge_refs=(),
        memory_refs=(),
    )
    grill_request = replace(
        _grill_request(), project_refs=("linked.json",), memory_refs=()
    )
    baseline = len(list(descriptor_root.iterdir()))
    for _ in range(40):
        with pytest.raises(MentorFlowError):
            mentor.prepare_task_packet(mentor_request, capabilities=mentor_caps)
        with pytest.raises(GrillFlowError):
            grill._context(grill_request)
    assert len(list(descriptor_root.iterdir())) == baseline


@pytest.mark.parametrize("review_zone", ["review", "custom/reviews"])
def test_review_failure_cleanup_has_bounded_fds(tmp_path: Path, review_zone: str):
    descriptor_root = Path("/dev/fd")
    if not descriptor_root.is_dir():
        descriptor_root = Path("/proc/self/fd")
    if not descriptor_root.is_dir():
        pytest.skip("no descriptor projection")

    mentor_lane = tmp_path / "mentor"
    mentor_vault, _, _, _, mentor_caps, _, mentor, _ = _setup(mentor_lane, review_zone)
    packet = mentor.prepare_task_packet(_mentor_request(), capabilities=mentor_caps)

    grill_lane = tmp_path / "grill"
    grill_vault, _, _, grill_runs, _, grill_caps, _, grill = _setup(
        grill_lane, review_zone
    )
    block_ids = (
        "ctx-" + hashlib.sha256(b"agent/memory\0decisions.jsonl").hexdigest()[:24],
        "ctx-" + hashlib.sha256(b"projects\0alpha/state.json").hexdigest()[:24],
    )
    grill.begin(_grill_request(), _question(1, block_ids), capabilities=grill_caps)
    grill_runs.resume("run_grill_one", executor="fixture")
    grill.answer(
        "run_grill_one",
        GrillHumanAnswer(
            "question-1", "human", "2026-08-20T11:10:00Z", "Exact answer."
        ),
        capabilities=grill_caps,
    )
    grill_runs.resume("run_grill_one", executor="fixture")

    def boom():
        raise RuntimeError("post-publish crash")

    baseline = len(list(descriptor_root.iterdir()))
    for _ in range(20):
        with pytest.raises(RuntimeError, match="post-publish crash"):
            mentor.commit_proposal(
                packet,
                _mentor_output(packet),
                capabilities=mentor_caps,
                hooks=MentorCrashHooks(after_proposal_publish=boom),
            )
        with pytest.raises(RuntimeError, match="post-publish crash"):
            grill.finish(
                "run_grill_one",
                None,
                capabilities=grill_caps,
                hooks=GrillCrashHooks(after_record_publish=boom),
            )
    assert len(list(descriptor_root.iterdir())) == baseline
    assert not (
        mentor_vault / _review_ref(review_zone, "mentor-alpha.mentor.json")
    ).exists()
    assert not (
        grill_vault / _review_ref(review_zone, "grill-alpha.grill.json")
    ).exists()


@pytest.mark.parametrize("review_zone", ["review", "custom/reviews"])
def test_mentor_parent_replacement_retires_only_owned_review(
    tmp_path: Path, review_zone: str
):
    vault, resolver, policy, runs, caps, _, mentor, _ = _setup(tmp_path, review_zone)
    packet = mentor.prepare_task_packet(_mentor_request(), capabilities=caps)
    review = vault / review_zone
    detached = review.with_name(review.name + "-detached")

    def replace_parent():
        review.rename(detached)
        review.mkdir()
        (review / "replacement-sentinel.txt").write_text("preserve replacement\n")
        (review / "mentor-alpha.mentor.json").write_text("foreign replacement\n")

    with pytest.raises(MentorFlowError):
        mentor.commit_proposal(
            packet,
            _mentor_output(packet),
            capabilities=caps,
            hooks=MentorCrashHooks(after_proposal_publish=replace_parent),
        )
    assert (review / "replacement-sentinel.txt").read_text() == (
        "preserve replacement\n"
    )
    assert (review / "mentor-alpha.mentor.json").read_text() == (
        "foreign replacement\n"
    )
    assert not (detached / "mentor-alpha.mentor.json").exists()
    assert not list(detached.glob(".mentor-retire-*.tmp"))

    (review / "mentor-alpha.mentor.json").unlink()
    result = MentorFlow(resolver, runs, policy).commit_proposal(
        packet, _mentor_output(packet), capabilities=caps
    )
    assert result.proposal_ref == _review_ref(review_zone, "mentor-alpha.mentor.json")
    assert (review / "mentor-alpha.mentor.json").is_file()


@pytest.mark.parametrize("review_zone", ["review", "custom/reviews"])
def test_grill_parent_replacement_retires_only_owned_review(
    tmp_path: Path, review_zone: str
):
    vault, resolver, policy, runs, _, caps, _, grill = _setup(tmp_path, review_zone)
    block_ids = (
        "ctx-" + hashlib.sha256(b"agent/memory\0decisions.jsonl").hexdigest()[:24],
        "ctx-" + hashlib.sha256(b"projects\0alpha/state.json").hexdigest()[:24],
    )
    grill.begin(_grill_request(), _question(1, block_ids), capabilities=caps)
    runs.resume("run_grill_one", executor="fixture")
    grill.answer(
        "run_grill_one",
        GrillHumanAnswer(
            "question-1", "human", "2026-08-20T11:10:00Z", "Exact answer."
        ),
        capabilities=caps,
    )
    runs.resume("run_grill_one", executor="fixture")
    review = vault / review_zone
    detached = review.with_name(review.name + "-detached")

    def replace_parent():
        review.rename(detached)
        review.mkdir()
        (review / "replacement-sentinel.txt").write_text("preserve replacement\n")
        (review / "grill-alpha.grill.json").write_text("foreign replacement\n")

    with pytest.raises(GrillFlowError):
        grill.finish(
            "run_grill_one",
            None,
            capabilities=caps,
            hooks=GrillCrashHooks(after_record_publish=replace_parent),
        )
    assert (review / "replacement-sentinel.txt").read_text() == (
        "preserve replacement\n"
    )
    assert (review / "grill-alpha.grill.json").read_text() == ("foreign replacement\n")
    assert not (detached / "grill-alpha.grill.json").exists()
    assert not list(detached.glob(".grill-retire-*.tmp"))

    (review / "grill-alpha.grill.json").unlink()
    result = GrillMeFlow(resolver, runs, policy).finish(
        "run_grill_one", None, capabilities=caps
    )
    assert result.record_ref == _review_ref(review_zone, "grill-alpha.grill.json")
    assert (review / "grill-alpha.grill.json").is_file()


def test_private_path_filter_is_casefolded_and_file_scheme_aware(tmp_path: Path):
    _, _, _, _, caps, _, mentor, _ = _setup(tmp_path)
    packet = mentor.prepare_task_packet(_mentor_request(), capabilities=caps)
    profile = replace(
        _mentor_output(packet),
        summary="Profile: preserve the explicit human boundary.",
    )
    assert (
        parse_mentor_executor_output(render_mentor_executor_output(profile)) == profile
    )
    for private in (
        r"C:\Users\PrivateOwner\secret.txt",
        "c:/HOME/PrivateOwner/secret.txt",
        "/HoMe/PrivateOwner/secret.txt",
        "Open FILE:///private/source",
    ):
        with pytest.raises(MentorFlowError, match="private path"):
            render_mentor_executor_output(replace(profile, summary=private))
        with pytest.raises(GrillFlowError, match="private path"):
            render_grill_question_output(
                GrillQuestionOutput(
                    "question-private",
                    "2026-08-20T11:01:00Z",
                    private,
                    ("ctx-a",),
                )
            )
    assert parse_grill_question_output(
        render_grill_question_output(
            GrillQuestionOutput(
                "question-profile",
                "2026-08-20T11:01:00Z",
                "Profile: which boundary matters?",
                ("ctx-a",),
            )
        )
    ).question.startswith("Profile:")


def _public_contract_samples():
    sha = "0" * 64
    mentor_block = MentorContextBlock(
        "ctx-a", "projects", "projects/a.txt", sha, 1, "x", False
    )
    mentor_manifest = MentorContextManifest(1024, 1, 1, ("ctx-a",), ())
    mentor_request = MentorRequest(
        "run_probe",
        "probe",
        "mentor-probe",
        "2026-08-20T00:00:00Z",
        "focus",
        "question",
        ("a.txt",),
    )
    mentor_packet = MentorTaskPacket(mentor_request, mentor_manifest, (mentor_block,))
    observation = MentorObservation("obs-a", "observation", ("ctx-a",))
    recommendation = MentorRecommendation(
        "rec-a", "recommendation", "rationale", ("ctx-a",)
    )
    mentor_output = MentorExecutorOutput(
        "summary", (observation,), (recommendation,), ("question",)
    )
    mentor_proposal = MentorProposalRecord(
        "mentor-probe",
        "proposed",
        "runtime",
        "run_probe",
        "probe",
        "2026-08-20T00:00:00Z",
        "focus",
        "question",
        sha,
        mentor_manifest,
        (MentorEvidenceAnchor("ctx-a", "projects/a.txt", sha),),
        "summary",
        (observation,),
        (recommendation,),
        ("question",),
    )
    mentor_evidence = MentorRunEvidence(
        "probe", "review/mentor-probe.mentor.json", sha, sha, sha, sha
    )

    grill_block = GrillContextBlock(
        "ctx-a", "projects", "projects/a.txt", sha, 1, "x", False
    )
    grill_manifest = GrillContextManifest(1024, 1, 1, ("ctx-a",), ())
    grill_question = GrillQuestionOutput(
        "question-a", "2026-08-20T00:00:00Z", "question", ("ctx-a",)
    )
    grill_answer = GrillHumanAnswer(
        "question-a", "human", "2026-08-20T00:01:00Z", "answer"
    )
    grill_turn = GrillTurn(0, grill_question, grill_answer)
    grill_decision = GrillExplicitDecision(
        "decision-a", "human", "2026-08-20T00:02:00Z", "decision"
    )
    grill_session = GrillSession(
        "run_probe",
        "probe",
        "grill-probe",
        "2026-08-20T00:00:00Z",
        "topic",
        sha,
        grill_manifest,
        (grill_block,),
        (grill_turn,),
        1,
        "ready-decision",
    )
    grill_record = GrillDecisionRecord(
        "grill-probe",
        "proposed",
        "human",
        "run_probe",
        "probe",
        "2026-08-20T00:00:00Z",
        "topic",
        sha,
        grill_manifest,
        (grill_block,),
        (grill_turn,),
        "explicit-human-decision",
        grill_decision,
    )
    grill_evidence = GrillRunEvidence(
        "probe",
        "review/grill-probe.grill.json",
        sha,
        "agent/runs/run_probe/session.json",
        sha,
        sha,
        sha,
    )
    return {
        "mentor-output": (
            mentor_output,
            render_mentor_executor_output,
            parse_mentor_executor_output,
            MentorFlowError,
        ),
        "mentor-packet": (
            mentor_packet,
            render_mentor_task_packet,
            parse_mentor_task_packet,
            MentorFlowError,
        ),
        "mentor-proposal": (
            mentor_proposal,
            render_mentor_proposal,
            parse_mentor_proposal,
            MentorFlowError,
        ),
        "mentor-evidence": (
            mentor_evidence,
            render_mentor_run_evidence,
            parse_mentor_run_evidence,
            MentorFlowError,
        ),
        "grill-question": (
            grill_question,
            render_grill_question_output,
            parse_grill_question_output,
            GrillFlowError,
        ),
        "grill-session": (
            grill_session,
            render_grill_session,
            parse_grill_session,
            GrillFlowError,
        ),
        "grill-record": (
            grill_record,
            render_grill_decision_record,
            parse_grill_decision_record,
            GrillFlowError,
        ),
        "grill-evidence": (
            grill_evidence,
            render_grill_run_evidence,
            parse_grill_run_evidence,
            GrillFlowError,
        ),
    }


def _replace_typed_path(value, path, replacement):
    if not path:
        return replacement
    field, *remaining = path
    if isinstance(field, int):
        items = list(value)
        items[field] = _replace_typed_path(items[field], remaining, replacement)
        return tuple(items) if isinstance(value, tuple) else items
    return replace(
        value,
        **{field: _replace_typed_path(getattr(value, field), remaining, replacement)},
    )


def _malformed_case(contract, path, value, label):
    rendered_path = "-".join(str(item) for item in path)
    return pytest.param(contract, path, value, id=f"{contract}-{rendered_path}-{label}")


_PUBLIC_CONTRACTS = tuple(_public_contract_samples())
_TYPED_MALFORMED_CASES = [
    *(
        _malformed_case(contract, ("schema_version",), value, label)
        for contract in _PUBLIC_CONTRACTS
        for value, label in ((True, "schema-bool"), (2, "schema-wrong-int"))
    ),
    _malformed_case("mentor-output", ("observations",), None, "none"),
    _malformed_case("mentor-output", ("observations", 0), object(), "object"),
    _malformed_case("mentor-output", ("recommendations",), None, "none"),
    _malformed_case("mentor-output", ("recommendations", 0), object(), "object"),
    _malformed_case("mentor-output", ("questions",), None, "none"),
    _malformed_case("mentor-output", ("questions", 0), object(), "object"),
    _malformed_case("mentor-output", ("summary",), "\ud800", "surrogate"),
    _malformed_case("mentor-packet", ("request",), None, "none"),
    _malformed_case("mentor-packet", ("request", "project_refs"), None, "none"),
    _malformed_case("mentor-packet", ("manifest",), None, "none"),
    _malformed_case("mentor-packet", ("manifest", "block_ids"), None, "none"),
    _malformed_case("mentor-packet", ("blocks",), None, "none"),
    _malformed_case("mentor-packet", ("blocks",), object(), "object"),
    _malformed_case("mentor-packet", ("blocks", 0), object(), "element-object"),
    _malformed_case("mentor-packet", ("blocks", 0, "zone"), [], "list"),
    _malformed_case("mentor-packet", ("blocks", 0, "zone"), {}, "dict"),
    _malformed_case("mentor-packet", ("blocks", 0, "text"), None, "none"),
    _malformed_case("mentor-packet", ("blocks", 0, "text"), 1, "int"),
    _malformed_case("mentor-packet", ("blocks", 0, "text"), "\ud800", "surrogate"),
    _malformed_case("mentor-packet", ("blocks", 0, "source_bytes"), None, "none"),
    _malformed_case("mentor-packet", ("blocks", 0, "source_bytes"), "1", "string"),
    _malformed_case(
        "mentor-packet", ("blocks", 0, "schema_version"), True, "schema-bool"
    ),
    _malformed_case("mentor-proposal", ("evidence",), None, "none"),
    _malformed_case("mentor-proposal", ("evidence", 0), object(), "object"),
    _malformed_case("mentor-proposal", ("observations",), None, "none"),
    _malformed_case("mentor-proposal", ("recommendations",), None, "none"),
    _malformed_case("grill-question", ("evidence_block_ids",), None, "none"),
    _malformed_case("grill-question", ("evidence_block_ids", 0), object(), "object"),
    _malformed_case("grill-question", ("question",), "\ud800", "surrogate"),
    _malformed_case("grill-session", ("context",), None, "none"),
    _malformed_case("grill-session", ("context", "block_ids"), None, "none"),
    _malformed_case("grill-session", ("blocks",), None, "none"),
    _malformed_case("grill-session", ("blocks",), object(), "object"),
    _malformed_case("grill-session", ("blocks", 0), object(), "element-object"),
    _malformed_case("grill-session", ("blocks", 0, "zone"), [], "list"),
    _malformed_case("grill-session", ("blocks", 0, "zone"), {}, "dict"),
    _malformed_case("grill-session", ("blocks", 0, "text"), None, "none"),
    _malformed_case("grill-session", ("blocks", 0, "text"), 1, "int"),
    _malformed_case("grill-session", ("blocks", 0, "text"), "\ud800", "surrogate"),
    _malformed_case("grill-session", ("blocks", 0, "source_bytes"), None, "none"),
    _malformed_case("grill-session", ("blocks", 0, "source_bytes"), "1", "string"),
    _malformed_case("grill-session", ("turns",), None, "none"),
    _malformed_case("grill-session", ("turns",), object(), "object"),
    _malformed_case("grill-session", ("turns", 0), object(), "element-object"),
    _malformed_case("grill-session", ("turns", 0, "question"), None, "none"),
    _malformed_case(
        "grill-session", ("turns", 0, "question", "question_id"), [], "list"
    ),
    _malformed_case(
        "grill-session",
        ("turns", 0, "question", "evidence_block_ids"),
        None,
        "none",
    ),
    _malformed_case(
        "grill-session",
        ("turns", 0, "question", "evidence_block_ids", 0),
        [],
        "element-list",
    ),
    _malformed_case("grill-session", ("status",), [], "list"),
    _malformed_case("grill-session", ("status",), {}, "dict"),
    _malformed_case("grill-session", ("status",), None, "none"),
    _malformed_case("grill-record", ("context",), None, "none"),
    _malformed_case("grill-record", ("evidence",), None, "none"),
    _malformed_case("grill-record", ("evidence",), object(), "object"),
    _malformed_case("grill-record", ("evidence", 0), object(), "element-object"),
    _malformed_case("grill-record", ("evidence", 0, "zone"), [], "list"),
    _malformed_case("grill-record", ("evidence", 0, "zone"), {}, "dict"),
    _malformed_case("grill-record", ("evidence", 0, "text"), None, "none"),
    _malformed_case("grill-record", ("evidence", 0, "source_bytes"), None, "none"),
    _malformed_case("grill-record", ("turns",), None, "none"),
    _malformed_case("grill-record", ("turns", 0), object(), "element-object"),
    _malformed_case("grill-record", ("resolution",), [], "list"),
    _malformed_case("grill-record", ("resolution",), {}, "dict"),
    _malformed_case("grill-record", ("resolution",), None, "none"),
]


@pytest.mark.parametrize(("contract", "path", "malformed"), _TYPED_MALFORMED_CASES)
def test_malformed_typed_fields_raise_only_domain_errors(contract, path, malformed):
    sample, render, _, error = _public_contract_samples()[contract]
    with pytest.raises(error):
        render(_replace_typed_path(sample, path, malformed))


_JSON_MALFORMED_CASES = [
    *(
        _malformed_case(contract, ("schema_version",), value, label)
        for contract in _PUBLIC_CONTRACTS
        for value, label in ((True, "schema-bool"), (2, "schema-wrong-int"))
    ),
    _malformed_case("mentor-output", ("observations",), None, "none"),
    _malformed_case("mentor-output", ("observations", 0), None, "element-none"),
    _malformed_case("mentor-output", ("recommendations",), {}, "dict"),
    _malformed_case("mentor-output", ("questions",), None, "none"),
    _malformed_case("mentor-packet", ("request",), None, "none"),
    _malformed_case("mentor-packet", ("request", "project_refs"), None, "none"),
    _malformed_case("mentor-packet", ("manifest",), None, "none"),
    _malformed_case("mentor-packet", ("manifest", "block_ids"), None, "none"),
    _malformed_case("mentor-packet", ("blocks",), None, "none"),
    _malformed_case("mentor-packet", ("blocks", 0), None, "element-none"),
    _malformed_case("mentor-packet", ("blocks", 0, "zone"), [], "list"),
    _malformed_case("mentor-packet", ("blocks", 0, "zone"), {}, "dict"),
    _malformed_case("mentor-packet", ("blocks", 0, "text"), None, "none"),
    _malformed_case("mentor-packet", ("blocks", 0, "source_bytes"), None, "none"),
    _malformed_case("mentor-proposal", ("evidence",), None, "none"),
    _malformed_case("mentor-proposal", ("evidence", 0), None, "element-none"),
    _malformed_case("mentor-proposal", ("observations",), None, "none"),
    _malformed_case("mentor-proposal", ("recommendations",), None, "none"),
    _malformed_case("grill-question", ("evidence_block_ids",), None, "none"),
    _malformed_case("grill-question", ("evidence_block_ids", 0), [], "element-list"),
    _malformed_case("grill-session", ("context",), None, "none"),
    _malformed_case("grill-session", ("context", "block_ids"), None, "none"),
    _malformed_case("grill-session", ("blocks",), None, "none"),
    _malformed_case("grill-session", ("blocks", 0), None, "element-none"),
    _malformed_case("grill-session", ("blocks", 0, "zone"), [], "list"),
    _malformed_case("grill-session", ("blocks", 0, "zone"), {}, "dict"),
    _malformed_case("grill-session", ("blocks", 0, "text"), None, "none"),
    _malformed_case("grill-session", ("blocks", 0, "source_bytes"), None, "none"),
    _malformed_case("grill-session", ("turns",), None, "none"),
    _malformed_case("grill-session", ("turns", 0), None, "element-none"),
    _malformed_case("grill-session", ("turns", 0, "question"), None, "none"),
    _malformed_case(
        "grill-session", ("turns", 0, "question", "question_id"), [], "list"
    ),
    _malformed_case(
        "grill-session",
        ("turns", 0, "question", "evidence_block_ids"),
        None,
        "none",
    ),
    _malformed_case(
        "grill-session",
        ("turns", 0, "question", "evidence_block_ids", 0),
        [],
        "element-list",
    ),
    _malformed_case("grill-session", ("status",), [], "list"),
    _malformed_case("grill-session", ("status",), {}, "dict"),
    _malformed_case("grill-record", ("context",), None, "none"),
    _malformed_case("grill-record", ("evidence",), None, "none"),
    _malformed_case("grill-record", ("evidence", 0), None, "element-none"),
    _malformed_case("grill-record", ("evidence", 0, "zone"), [], "list"),
    _malformed_case("grill-record", ("evidence", 0, "zone"), {}, "dict"),
    _malformed_case("grill-record", ("evidence", 0, "text"), None, "none"),
    _malformed_case("grill-record", ("evidence", 0, "source_bytes"), None, "none"),
    _malformed_case("grill-record", ("turns",), None, "none"),
    _malformed_case("grill-record", ("turns", 0), None, "element-none"),
    _malformed_case("grill-record", ("resolution",), [], "list"),
    _malformed_case("grill-record", ("resolution",), {}, "dict"),
    _malformed_case("grill-record", ("resolution",), None, "none"),
]


def _replace_json_path(value, path, replacement):
    field, *remaining = path
    if remaining:
        value[field] = _replace_json_path(value[field], remaining, replacement)
    else:
        value[field] = replacement
    return value


@pytest.mark.parametrize(("contract", "path", "malformed"), _JSON_MALFORMED_CASES)
def test_malformed_json_bytes_raise_only_domain_errors(contract, path, malformed):
    sample, render, parse, error = _public_contract_samples()[contract]
    payload = json.loads(render(sample))
    _replace_json_path(payload, path, malformed)
    raw = (
        json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")
    with pytest.raises(error):
        parse(raw)


@pytest.mark.parametrize("contract", _PUBLIC_CONTRACTS)
def test_invalid_utf8_bytes_raise_only_domain_errors(contract):
    _, _, parse, error = _public_contract_samples()[contract]
    with pytest.raises(error):
        parse(b"\xff")


@pytest.mark.parametrize("review_zone", ["review", "custom/reviews"])
def test_all_precommit_crash_seams_resume_without_duplicates(
    tmp_path: Path, review_zone: str
):
    def boom(label: str):
        return lambda: (_ for _ in ()).throw(RuntimeError(label))

    for seam in ("after_prepare", "after_proposal_publish", "before_run_commit"):
        lane = tmp_path / f"{review_zone.replace('/', '-')}-mentor-{seam}"
        vault, resolver, policy, runs, caps, _, mentor, _ = _setup(lane, review_zone)
        packet = mentor.prepare_task_packet(_mentor_request(), capabilities=caps)
        hooks = MentorCrashHooks(**{seam: boom(seam)})
        with pytest.raises(RuntimeError, match=seam):
            mentor.commit_proposal(
                packet, _mentor_output(packet), capabilities=caps, hooks=hooks
            )
        proposal = vault / _review_ref(review_zone, "mentor-alpha.mentor.json")
        assert not proposal.exists()
        result = MentorFlow(resolver, runs, policy).commit_proposal(
            packet, _mentor_output(packet), capabilities=caps
        )
        assert proposal.is_file()
        assert result.proposal_ref == _review_ref(
            review_zone, "mentor-alpha.mentor.json"
        )

    block_ids = (
        "ctx-" + hashlib.sha256(b"agent/memory\0decisions.jsonl").hexdigest()[:24],
        "ctx-" + hashlib.sha256(b"projects\0alpha/state.json").hexdigest()[:24],
    )
    for seam in ("after_prepare", "before_run_commit"):
        lane = tmp_path / f"{review_zone.replace('/', '-')}-grill-begin-{seam}"
        _, resolver, policy, runs, _, caps, _, grill = _setup(lane, review_zone)
        hooks = GrillCrashHooks(**{seam: boom(seam)})
        with pytest.raises(RuntimeError, match=seam):
            grill.begin(
                _grill_request(),
                _question(1, block_ids),
                capabilities=caps,
                hooks=hooks,
            )
        assert (
            GrillMeFlow(resolver, runs, policy)
            .begin(_grill_request(), _question(1, block_ids), capabilities=caps)
            .waiting_for
            == "grill-answer"
        )

    for seam in ("after_prepare", "before_run_commit"):
        lane = tmp_path / f"{review_zone.replace('/', '-')}-grill-answer-{seam}"
        _, resolver, policy, runs, _, caps, _, grill = _setup(lane, review_zone)
        grill.begin(_grill_request(), _question(1, block_ids), capabilities=caps)
        runs.resume("run_grill_one", executor="fixture")
        answer = GrillHumanAnswer(
            "question-1", "human", "2026-08-20T11:10:00Z", "Exact answer."
        )
        hooks = GrillCrashHooks(**{seam: boom(seam)})
        with pytest.raises(RuntimeError, match=seam):
            grill.answer("run_grill_one", answer, capabilities=caps, hooks=hooks)
        assert (
            GrillMeFlow(resolver, runs, policy)
            .answer("run_grill_one", answer, capabilities=caps)
            .waiting_for
            == "grill-decision"
        )

    for seam in ("after_prepare", "after_record_publish", "before_run_commit"):
        lane = tmp_path / f"{review_zone.replace('/', '-')}-grill-finish-{seam}"
        vault, resolver, policy, runs, _, caps, _, grill = _setup(lane, review_zone)
        grill.begin(_grill_request(), _question(1, block_ids), capabilities=caps)
        runs.resume("run_grill_one", executor="fixture")
        grill.answer(
            "run_grill_one",
            GrillHumanAnswer(
                "question-1", "human", "2026-08-20T11:10:00Z", "Exact answer."
            ),
            capabilities=caps,
        )
        runs.resume("run_grill_one", executor="fixture")
        hooks = GrillCrashHooks(**{seam: boom(seam)})
        with pytest.raises(RuntimeError, match=seam):
            grill.finish("run_grill_one", None, capabilities=caps, hooks=hooks)
        record = vault / _review_ref(review_zone, "grill-alpha.grill.json")
        assert not record.exists()
        result = GrillMeFlow(resolver, runs, policy).finish(
            "run_grill_one", None, capabilities=caps
        )
        assert record.is_file()
        assert result.record_ref == _review_ref(review_zone, "grill-alpha.grill.json")
