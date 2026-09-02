"""P3-05 day/week plan, context, quota, rollover, and recovery acceptance."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil

import pytest

from tool_life_os_runtime.ext.flows.entities import EntitiesCapabilities, EntitiesFlow
from tool_life_os_runtime.ext.flows.plan import (
    DayPlan,
    PlanCapabilities,
    PlanContextQuery,
    PlanFlow,
    PlanFlowError,
    PlanPolicy,
    PlanTask,
    parse_day_plan,
    render_day_markdown,
    render_day_plan,
    render_planning_packet,
)
from tool_life_os_runtime.ext.flows.plan import flow as plan_module
from tool_life_os_runtime.ext.flows.project import ProjectCapabilities, ProjectFlow
from tool_life_os_runtime.ext.review.authority import AuthorityPolicy
from tool_life_os_runtime.ext.runs import RunStore
from tool_life_os_runtime.ext.vault.config import load_vault_config
from tool_life_os_runtime.ext.vault.schema import VaultPathResolver, VaultSchemaError


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/vault-minimal"


class _Clock:
    def __init__(self) -> None:
        self.value = datetime(2026, 1, 19, 9, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        value = self.value
        self.value += timedelta(seconds=1)
        return value


def _capabilities(policy: AuthorityPolicy) -> PlanCapabilities:
    def issue(action_id, actor, authority, target):
        return policy.issue(
            flow_id="plan",
            action_id=action_id,
            actor=actor,
            authority=authority,
            target=target,
        )

    return PlanCapabilities(
        collect_plan_context=issue(
            "collect-plan-context", "runtime", "read", "vault:tasks"
        ),
        read_plan_project_context=issue(
            "read-plan-project-context", "runtime", "read", "vault:projects"
        ),
        read_plan_entity_context=issue(
            "read-plan-entity-context", "runtime", "read", "vault:agent/memory"
        ),
        snapshot_task_preimage=issue(
            "snapshot-task-preimage",
            "runtime",
            "domain-write",
            "vault:agent/logs/tasks",
        ),
        extract_feedback_markers=issue(
            "extract-feedback-markers", "runtime", "read", "vault:tasks"
        ),
        commit_feedback_proposal=issue(
            "commit-feedback-proposal", "runtime", "proposal", "vault:review"
        ),
        commit_plan_or_rollover=issue(
            "commit-plan-or-rollover", "runtime", "domain-write", "vault:tasks"
        ),
        record_run_state=issue(
            "record-run-state", "runtime", "internal-write", "vault:agent/runs"
        ),
    )


def _setup(tmp_path: Path):
    vault = tmp_path / "vault"
    shutil.copytree(FIXTURE, vault)
    config = load_vault_config(vault / "lifeos.toml")
    resolver = VaultPathResolver(vault, config)
    clock = _Clock()
    store = RunStore(resolver, clock=clock)
    policy = AuthorityPolicy()
    caps = _capabilities(policy)
    flow = PlanFlow(resolver, store, policy, clock=clock)
    return vault, resolver, store, policy, caps, flow, clock


def _run(store: RunStore, run_id: str = "run_plan") -> None:
    store.create(
        run_id=run_id,
        flow="plan",
        phase="plan",
        authority="domain-write",
        executor="test",
        input_data={"scope": "synthetic"},
    )
    store.resume(run_id, executor="test")


def _policy() -> PlanPolicy:
    return PlanPolicy(physical_quota=5, max_focus=2)


def _tasks(period: str = "2026-01-19") -> tuple[PlanTask, ...]:
    return (
        PlanTask(
            "task-alpha",
            "Review the synthetic proposal.",
            period,
            priority="high",
            physical_units=2,
            focus=True,
        ),
        PlanTask(
            "task-beta",
            "Prepare a bounded follow-up.",
            period,
            physical_units=1,
        ),
    )


def _commit_day(flow, caps, **overrides):
    values = {
        "run_id": "run_plan",
        "operation_id": "commit_day_one",
        "period": "2026-01-19",
        "tasks": _tasks(),
        "policy": _policy(),
    }
    values.update(overrides)
    return flow.commit_day(caps, **values)


def _tree(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file()
    }


def _create_context(resolver, store, policy, clock):
    project_caps = ProjectCapabilities(
        read=policy.issue(
            flow_id="project",
            action_id="read-project-state",
            actor="runtime",
            authority="read",
            target="vault:projects",
        ),
        commit=policy.issue(
            flow_id="project",
            action_id="commit-project-transition",
            actor="runtime",
            authority="domain-write",
            target="vault:projects",
        ),
        run=policy.issue(
            flow_id="project",
            action_id="record-run-state",
            actor="runtime",
            authority="internal-write",
            target="vault:agent/runs",
        ),
    )
    store.create(
        run_id="run_project_context",
        flow="project",
        phase="project",
        authority="domain-write",
        executor="test",
        input_data={},
    )
    store.resume("run_project_context", executor="test")
    project_result = ProjectFlow(resolver, store, policy, clock=clock).create(
        project_caps,
        run_id="run_project_context",
        transition_id="create_context_project",
        slug="context-project",
        name="Context project",
        goal="Provide synthetic planning context.",
        domains=("systems",),
    )

    entity_caps = EntitiesCapabilities(
        read_entity_state=policy.issue(
            flow_id="entities",
            action_id="read-entity-state",
            actor="runtime-human-confirmed",
            authority="read",
            target="vault:agent/memory/entities",
        ),
        read_done_events=policy.issue(
            flow_id="entities",
            action_id="read-done-events",
            actor="runtime-human-confirmed",
            authority="read",
            target="vault:agent/logs/done-events",
        ),
        read_trail_events=policy.issue(
            flow_id="entities",
            action_id="read-trail-events",
            actor="runtime-human-confirmed",
            authority="read",
            target="vault:agent/memory/trails",
        ),
        commit_entity_state=policy.issue(
            flow_id="entities",
            action_id="commit-entity-state",
            actor="runtime-human-confirmed",
            authority="domain-write",
            target="vault:agent/memory/entities",
        ),
        append_confirmed_done_event=policy.issue(
            flow_id="entities",
            action_id="append-confirmed-done-event",
            actor="runtime-human-confirmed",
            authority="domain-write",
            target="vault:agent/logs/done-events",
        ),
        append_entity_trail=policy.issue(
            flow_id="entities",
            action_id="append-entity-trail",
            actor="runtime-human-confirmed",
            authority="domain-write",
            target="vault:agent/memory/trails",
        ),
        record_run_state=policy.issue(
            flow_id="entities",
            action_id="record-run-state",
            actor="runtime",
            authority="internal-write",
            target="vault:agent/runs",
        ),
    )
    store.create(
        run_id="run_entities_context",
        flow="entities",
        phase="entities",
        authority="domain-write",
        executor="test",
        input_data={},
    )
    store.resume("run_entities_context", executor="test")
    EntitiesFlow(resolver, store, policy, clock).create(
        entity_caps,
        run_id="run_entities_context",
        mutation_id="create_context_entity",
        entity_id="ent-context",
        domain="systems",
        title="Context entity",
        description="Synthetic planning context.",
        deadline="2026-01-21",
        next_review_at="2026-01-20T15:00:00Z",
    )
    return project_result.snapshot.snapshot_sha256


def test_day_schema_markdown_paths_context_and_exact_action_order(tmp_path):
    vault, resolver, store, policy, caps, flow, clock = _setup(tmp_path)
    project_snapshot = _create_context(resolver, store, policy, clock)
    _run(store)
    tasks = (
        replace_task(
            _tasks()[0], project_slug="context-project", entity_id="ent-context"
        ),
        _tasks()[1],
    )

    packet = flow.planning_packet(
        caps, PlanContextQuery("day", "2026-01-19", "2026-01-19T08:00:00Z")
    )
    assert packet.projects[0].snapshot_sha256 == project_snapshot
    assert packet.entities[0].next_review_at == "2026-01-20T15:00:00Z"
    result = _commit_day(flow, caps, tasks=tasks)

    assert isinstance(result.day_plan, DayPlan)
    assert result.day_plan.revision == 1
    json_path = vault / "tasks/days/2026-01-19.json"
    markdown_path = vault / "tasks/days/2026-01-19.md"
    assert parse_day_plan(json_path.read_bytes()) == result.day_plan
    assert json_path.read_bytes() == render_day_plan(result.day_plan)
    assert markdown_path.read_bytes() == render_day_markdown(result.day_plan)
    assert "Review the synthetic proposal." in markdown_path.read_text("utf-8")
    assert list((vault / "agent/logs/tasks/preimages").glob("*.json"))
    assert store.status("run_plan")["status"] == "running"
    assert [
        item["action_id"] for item in store.trace_events("run_plan")[0]["actions"]
    ] == [
        "collect-plan-context",
        "read-plan-project-context",
        "read-plan-entity-context",
        "snapshot-task-preimage",
        "extract-feedback-markers",
        "commit-plan-or-rollover",
        "record-run-state",
    ]


def replace_task(task: PlanTask, **changes) -> PlanTask:
    values = dict(task.__dict__)
    values.update(changes)
    return PlanTask(**values)


@pytest.mark.parametrize(
    "tasks,policy,error",
    [
        (
            (
                PlanTask("task-a", "A", "2026-01-19", physical_units=3),
                PlanTask("task-b", "B", "2026-01-19", physical_units=3),
            ),
            PlanPolicy(5, 2),
            "physical quota",
        ),
        (
            (
                PlanTask("task-a", "A", "2026-01-19", focus=True),
                PlanTask("task-b", "B", "2026-01-19", focus=True),
            ),
            PlanPolicy(5, 1),
            "max-focus",
        ),
    ],
)
def test_physical_quota_and_max_focus_are_code_invariants(
    tmp_path, tasks, policy, error
):
    vault, _, store, _, caps, flow, _ = _setup(tmp_path)
    _run(store)
    before = _tree(vault / "tasks")
    with pytest.raises(PlanFlowError, match=error):
        _commit_day(flow, caps, tasks=tasks, policy=policy)
    assert _tree(vault / "tasks") == before


def test_exact_replay_is_noop_and_conflicting_request_fails(tmp_path):
    vault, _, store, _, caps, flow, _ = _setup(tmp_path)
    _run(store)
    first = _commit_day(flow, caps)
    replay = _commit_day(flow, caps)
    assert replay.replayed is True
    assert replay.day_plan == first.day_plan
    assert len(store.trace_events("run_plan")) == 1
    before = _tree(vault)
    with pytest.raises(PlanFlowError, match="conflicts"):
        _commit_day(
            flow,
            caps,
            tasks=(replace_task(_tasks()[0], text="Changed request."), _tasks()[1]),
        )
    assert _tree(vault) == before


def test_skip_is_append_only_exactly_once_and_feedback_is_proposal(tmp_path):
    vault, _, store, _, caps, flow, _ = _setup(tmp_path)
    _run(store)
    _commit_day(flow, caps)
    result = flow.skip_task(
        caps,
        run_id="run_plan",
        operation_id="skip_alpha",
        period="2026-01-19",
        task_id="task-alpha",
        expected_revision=1,
        reason="Explicitly deprioritized.",
        skipped_at="2026-01-19T10:00:00Z",
        feedback="The focus estimate was too optimistic.",
    )
    replay = flow.skip_task(
        caps,
        run_id="run_plan",
        operation_id="skip_alpha",
        period="2026-01-19",
        task_id="task-alpha",
        expected_revision=1,
        reason="Explicitly deprioritized.",
        skipped_at="2026-01-19T10:00:00Z",
        feedback="The focus estimate was too optimistic.",
    )

    assert replay.replayed is True
    assert result.day_plan.tasks[0].status == "skipped"
    lines = (vault / "agent/logs/tasks/skipped.jsonl").read_text().splitlines()
    assert len(lines) == 1 and json.loads(lines[0])["id"].startswith("skip-")
    assert result.feedback_proposal_ref is not None
    assert (vault / result.feedback_proposal_ref).is_file()
    actions = store.trace_events("run_plan")[-1]["actions"]
    assert [item["action_id"] for item in actions] == [
        "collect-plan-context",
        "read-plan-project-context",
        "read-plan-entity-context",
        "snapshot-task-preimage",
        "extract-feedback-markers",
        "commit-feedback-proposal",
        "commit-plan-or-rollover",
        "record-run-state",
    ]


def test_rollover_carries_only_open_tasks_and_replays_partial_pair(
    tmp_path, monkeypatch
):
    vault, _, store, _, caps, flow, _ = _setup(tmp_path)
    _run(store)
    done = PlanTask(
        "task-done",
        "Already completed.",
        "2026-01-19",
        status="done",
        completed_at="2026-01-19T08:00:00Z",
    )
    _commit_day(flow, caps, tasks=(_tasks()[0], done))
    crashed = False

    def crash_once(relative):
        nonlocal crashed
        if not crashed:
            crashed = True
            raise RuntimeError(f"injected after {relative}")

    monkeypatch.setattr(flow, "_after_task_replace", crash_once)
    with pytest.raises(RuntimeError, match="injected"):
        flow.rollover_day(
            caps,
            run_id="run_plan",
            operation_id="roll_day_two",
            source_date="2026-01-19",
            target_date="2026-01-20",
            expected_revision=1,
        )
    monkeypatch.setattr(flow, "_after_task_replace", lambda _relative: None)
    result = flow.rollover_day(
        caps,
        run_id="run_plan",
        operation_id="roll_day_two",
        source_date="2026-01-19",
        target_date="2026-01-20",
        expected_revision=1,
    )

    assert result.replayed is True
    assert [item.task_id for item in result.day_plan.tasks] == ["task-alpha"]
    assert result.day_plan.tasks[0].scheduled_for == "2026-01-20"
    assert result.day_plan.tasks[0].rollover_count == 1
    source = parse_day_plan((vault / "tasks/days/2026-01-19.json").read_bytes())
    assert source.status == "rolled-over"
    assert [item.status for item in source.tasks] == ["rolled-over", "done"]


def test_rollover_does_not_repropose_feedback_from_an_existing_skip(tmp_path):
    _, _, store, _, caps, flow, _ = _setup(tmp_path)
    _run(store)
    _commit_day(flow, caps)
    flow.skip_task(
        caps,
        run_id="run_plan",
        operation_id="skip_before_rollover",
        period="2026-01-19",
        task_id="task-alpha",
        expected_revision=1,
        reason="Explicitly defer this task.",
        skipped_at="2026-01-19T10:00:00Z",
        feedback="The estimate needs review.",
    )

    result = flow.rollover_day(
        caps,
        run_id="run_plan",
        operation_id="roll_after_skip",
        source_date="2026-01-19",
        target_date="2026-01-20",
        expected_revision=2,
    )
    assert result.feedback_proposal_ref is None
    assert [item.task_id for item in result.day_plan.tasks] == ["task-beta"]
    assert [
        item["action_id"] for item in store.trace_events("run_plan")[-1]["actions"]
    ] == [
        "collect-plan-context",
        "read-plan-project-context",
        "read-plan-entity-context",
        "snapshot-task-preimage",
        "extract-feedback-markers",
        "commit-plan-or-rollover",
        "record-run-state",
    ]


def test_skip_retry_before_target_write_does_not_duplicate_event(tmp_path, monkeypatch):
    vault, _, store, _, caps, flow, _ = _setup(tmp_path)
    _run(store)
    _commit_day(flow, caps)
    crashed = False

    def crash_once(_relative):
        nonlocal crashed
        if not crashed:
            crashed = True
            raise RuntimeError("after skip append")

    monkeypatch.setattr(flow, "_before_task_replace", crash_once)
    kwargs = {
        "run_id": "run_plan",
        "operation_id": "skip_retry",
        "period": "2026-01-19",
        "task_id": "task-beta",
        "expected_revision": 1,
        "reason": "Explicit skip for recovery.",
        "skipped_at": "2026-01-19T11:00:00Z",
    }
    with pytest.raises(RuntimeError, match="after skip"):
        flow.skip_task(caps, **kwargs)
    monkeypatch.setattr(flow, "_before_task_replace", lambda _relative: None)
    assert flow.skip_task(caps, **kwargs).replayed is True
    assert len((vault / "agent/logs/tasks/skipped.jsonl").read_text().splitlines()) == 1


def test_skip_retry_after_target_write_appends_trace_exactly_once(
    tmp_path, monkeypatch
):
    vault, _, store, _, caps, flow, _ = _setup(tmp_path)
    _run(store)
    _commit_day(flow, caps)
    crashed = False

    def crash_once():
        nonlocal crashed
        if not crashed:
            crashed = True
            raise RuntimeError("after plan before skipped trace")

    monkeypatch.setattr(flow, "_before_skip_append", crash_once)
    kwargs = {
        "run_id": "run_plan",
        "operation_id": "skip_after_target",
        "period": "2026-01-19",
        "task_id": "task-beta",
        "expected_revision": 1,
        "reason": "Explicit skip after a recoverable boundary.",
        "skipped_at": "2026-01-19T11:30:00Z",
    }
    with pytest.raises(RuntimeError, match="after plan"):
        flow.skip_task(caps, **kwargs)
    assert not (vault / "agent/logs/tasks/skipped.jsonl").exists()
    assert (
        parse_day_plan((vault / "tasks/days/2026-01-19.json").read_bytes()).revision
        == 2
    )

    monkeypatch.setattr(flow, "_before_skip_append", lambda: None)
    result = flow.skip_task(caps, **kwargs)
    assert result.replayed is True
    assert result.day_plan.revision == 2
    assert len((vault / "agent/logs/tasks/skipped.jsonl").read_text().splitlines()) == 1


def test_week_plan_packet_is_deterministic_and_bounded(tmp_path):
    _, _, store, _, caps, flow, _ = _setup(tmp_path)
    _run(store)
    week_tasks = (
        PlanTask("task-monday", "Monday task.", "2026-01-19", focus=True),
        PlanTask("task-tuesday", "Tuesday task.", "2026-01-20", physical_units=2),
    )
    result = flow.commit_week(
        caps,
        run_id="run_plan",
        operation_id="commit_week_one",
        week_start="2026-01-19",
        tasks=week_tasks,
        policy=_policy(),
    )
    assert result.week_plan.week_start == "2026-01-19"
    query = PlanContextQuery(
        "week", "2026-01-19", "2026-01-19T12:00:00Z", maximum_bytes=65536
    )
    first = flow.planning_packet(caps, query)
    second = flow.planning_packet(caps, query)
    assert first == second
    assert len(render_planning_packet(first)) <= 65536


def test_wrong_capability_and_private_text_fail_before_plan_write(tmp_path):
    vault, _, store, policy, caps, flow, _ = _setup(tmp_path)
    _run(store)
    wrong = PlanCapabilities(
        caps.commit_plan_or_rollover,
        caps.read_plan_project_context,
        caps.read_plan_entity_context,
        caps.snapshot_task_preimage,
        caps.extract_feedback_markers,
        caps.commit_feedback_proposal,
        caps.commit_plan_or_rollover,
        caps.record_run_state,
    )
    with pytest.raises(PlanFlowError, match="not exact"):
        _commit_day(flow, wrong)
    with pytest.raises(PlanFlowError):
        _commit_day(
            flow,
            caps,
            operation_id="private_text",
            tasks=(PlanTask("task-private", "FILE:/" + "Users/private/task", "2026-01-19"),),
        )
    foreign = _capabilities(AuthorityPolicy())
    with pytest.raises(PlanFlowError, match="not issued"):
        flow.planning_packet(
            foreign, PlanContextQuery("day", "2026-01-19", "2026-01-19T12:00:00Z")
        )
    assert [path.name for path in (vault / "tasks").iterdir()] == [".gitkeep"]
    assert policy.matrix_sha256 == caps.record_run_state.matrix_sha256


def test_open_zone_revalidation_failures_do_not_leak_descriptors(tmp_path, monkeypatch):
    _, resolver, store, _, caps, flow, _ = _setup(tmp_path)
    _run(store)
    real_revalidate = resolver.revalidate

    def fail_tasks(path, symbolic, *parts, **kwargs):
        if symbolic == "tasks":
            raise VaultSchemaError("injected")
        return real_revalidate(path, symbolic, *parts, **kwargs)

    monkeypatch.setattr(resolver, "revalidate", fail_tasks)
    descriptor_root = "/dev/fd" if Path("/dev/fd").is_dir() else "/proc/self/fd"
    before = len(os.listdir(descriptor_root))
    for _ in range(40):
        with pytest.raises(PlanFlowError):
            flow.read_day(caps.collect_plan_context, "2026-01-19")
    assert len(os.listdir(descriptor_root)) - before == 0


def test_publish_rejects_substituted_inode_and_exact_retry_recovers(
    tmp_path, monkeypatch
):
    vault, _, store, _, caps, flow, _ = _setup(tmp_path)
    _run(store)
    real_replace = plan_module.os.replace
    substituted = False

    def substitute(source, target, *args, **kwargs):
        nonlocal substituted
        real_replace(source, target, *args, **kwargs)
        if target != "2026-01-19.json" or substituted:
            return
        substituted = True
        directory_fd = kwargs["dst_dir_fd"]
        source_fd = os.open(target, os.O_RDONLY, dir_fd=directory_fd)
        try:
            raw = os.read(source_fd, 1_048_577)
        finally:
            os.close(source_fd)
        replacement = ".substituted-plan.json"
        target_fd = os.open(
            replacement,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
            dir_fd=directory_fd,
        )
        try:
            offset = 0
            while offset < len(raw):
                offset += os.write(target_fd, raw[offset:])
            os.fsync(target_fd)
        finally:
            os.close(target_fd)
        real_replace(
            replacement,
            target,
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
        )

    monkeypatch.setattr(plan_module.os, "replace", substitute)
    with pytest.raises(PlanFlowError, match="changed during publish"):
        _commit_day(flow, caps)
    result = _commit_day(flow, caps)
    assert result.replayed is True
    assert parse_day_plan((vault / "tasks/days/2026-01-19.json").read_bytes())


def test_tasks_zone_swap_before_publish_leaves_detached_and_replacement_untouched(
    tmp_path, monkeypatch
):
    vault, _, store, _, caps, flow, _ = _setup(tmp_path)
    _run(store)
    held = vault / "tasks-held"
    replacement = vault / "tasks"
    swapped = False

    def swap_zone(_relative):
        nonlocal swapped
        if swapped:
            return
        swapped = True
        replacement.rename(held)
        replacement.mkdir()
        (replacement / "foreign.txt").write_bytes(b"foreign replacement\n")

    monkeypatch.setattr(flow, "_before_task_replace", swap_zone)
    with pytest.raises(PlanFlowError, match="zone changed"):
        _commit_day(flow, caps)

    assert not list((held / "days").glob("*.json"))
    assert not list((held / "days").glob("*.md"))
    assert (replacement / "foreign.txt").read_bytes() == b"foreign replacement\n"

    moved_replacement = vault / "tasks-replacement"
    replacement.rename(moved_replacement)
    held.rename(replacement)
    monkeypatch.setattr(flow, "_before_task_replace", lambda _relative: None)
    result = _commit_day(flow, caps)
    assert result.replayed is True
    assert (moved_replacement / "foreign.txt").read_bytes() == b"foreign replacement\n"


def test_period_parent_swap_after_publish_rolls_back_only_owned_leaf(
    tmp_path, monkeypatch
):
    vault, _, store, _, caps, flow, _ = _setup(tmp_path)
    _run(store)
    days = vault / "tasks/days"
    held = vault / "tasks/days-held"
    swapped = False

    def swap_parent(_relative):
        nonlocal swapped
        if swapped:
            return
        swapped = True
        days.rename(held)
        days.mkdir()
        (days / "foreign.txt").write_bytes(b"foreign period replacement\n")

    monkeypatch.setattr(flow, "_after_task_replace", swap_parent)
    with pytest.raises(PlanFlowError, match="period namespace changed"):
        _commit_day(flow, caps)

    assert not list(held.glob("*.json"))
    assert not list(held.glob("*.md"))
    assert (days / "foreign.txt").read_bytes() == b"foreign period replacement\n"

    moved_replacement = vault / "tasks/days-replacement"
    days.rename(moved_replacement)
    held.rename(days)
    monkeypatch.setattr(flow, "_after_task_replace", lambda _relative: None)
    result = _commit_day(flow, caps)
    assert result.replayed is True
    assert (moved_replacement / "foreign.txt").read_bytes() == (
        b"foreign period replacement\n"
    )


def test_partial_immutable_stage_never_appears_under_final_name_and_retries(
    tmp_path, monkeypatch
):
    directory = tmp_path / "immutable"
    directory.mkdir()
    directory_fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    real_write = plan_module.os.write
    interrupted = False
    raw = b'{"schema_version":1}\n'

    def interrupt_stage(fd, data):
        nonlocal interrupted
        if not interrupted:
            interrupted = True
            real_write(fd, data[:7])
            raise RuntimeError("injected partial immutable stage")
        return real_write(fd, data)

    try:
        monkeypatch.setattr(plan_module.os, "write", interrupt_stage)
        with pytest.raises(RuntimeError, match="partial immutable stage"):
            plan_module._create_once_at(
                directory_fd, "preimage.json", raw, maximum=1024
            )
        assert not (directory / "preimage.json").exists()
        assert not list(directory.glob(".*.tmp"))

        monkeypatch.setattr(plan_module.os, "write", real_write)
        assert plan_module._create_once_at(
            directory_fd, "preimage.json", raw, maximum=1024
        )
        assert not plan_module._create_once_at(
            directory_fd, "preimage.json", raw, maximum=1024
        )
        assert (directory / "preimage.json").read_bytes() == raw
    finally:
        os.close(directory_fd)


def test_foreign_feedback_collision_is_preserved_and_exact_retry_recovers(tmp_path):
    vault, _, store, _, caps, flow, _ = _setup(tmp_path)
    _run(store)
    _commit_day(flow, caps)
    operation_id = "skip_feedback_collision"
    token = hashlib.sha256(operation_id.encode("utf-8")).hexdigest()[:32]
    proposal = vault / f"review/tasks-feedback-{token}.json"
    proposal.write_bytes(b"foreign proposal\n")
    kwargs = {
        "run_id": "run_plan",
        "operation_id": operation_id,
        "period": "2026-01-19",
        "task_id": "task-alpha",
        "expected_revision": 1,
        "reason": "Exercise immutable collision recovery.",
        "skipped_at": "2026-01-19T12:00:00Z",
        "feedback": "Review the physical estimate.",
    }

    with pytest.raises(PlanFlowError, match="immutable replay conflicts"):
        flow.skip_task(caps, **kwargs)
    assert proposal.read_bytes() == b"foreign proposal\n"
    assert (
        parse_day_plan((vault / "tasks/days/2026-01-19.json").read_bytes()).revision
        == 1
    )
    assert not (vault / "agent/logs/tasks/skipped.jsonl").exists()

    proposal.unlink()
    result = flow.skip_task(caps, **kwargs)
    assert result.replayed is True
    assert result.day_plan.revision == 2
    assert proposal.is_file()


@pytest.mark.parametrize(
    "malformed",
    ["task-status", "query-kind", "project-intent-status", "entity-next-check-kind"],
)
def test_unhashable_public_fields_are_normalized_and_do_not_write_plan_state(
    tmp_path, malformed
):
    vault, resolver, store, policy, caps, flow, clock = _setup(tmp_path)
    if malformed in {"project-intent-status", "entity-next-check-kind"}:
        _create_context(resolver, store, policy, clock)
    _run(store)
    before = _tree(vault / "tasks")

    if malformed == "task-status":

        def action():
            return _commit_day(
                flow,
                caps,
                tasks=(
                    PlanTask(
                        "task-invalid",
                        "Invalid status.",
                        "2026-01-19",
                        status=[],
                    ),
                ),
            )

    elif malformed == "query-kind":

        def action():
            return flow.planning_packet(
                caps,
                PlanContextQuery([], "2026-01-19", "2026-01-19T12:00:00Z"),
            )

    elif malformed == "project-intent-status":
        intent = next((vault / "projects/.lifeos-project-intents").glob("*.json"))
        payload = json.loads(intent.read_bytes())
        payload["status"] = []
        intent.write_bytes(
            json.dumps(
                payload,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            + b"\n"
        )

        def action():
            return flow.planning_packet(
                caps,
                PlanContextQuery("day", "2026-01-19", "2026-01-19T12:00:00Z"),
            )

    else:
        collection = vault / "agent/memory/entities/systems.json"
        payload = json.loads(collection.read_bytes())
        payload["entities"][0]["next_check"] = {
            "schema_version": 1,
            "kind": [],
            "due_at": "2026-01-20T12:00:00Z",
            "interval_days": None,
        }
        collection.write_bytes(
            json.dumps(
                payload,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            + b"\n"
        )

        def action():
            return flow.planning_packet(
                caps,
                PlanContextQuery("day", "2026-01-19", "2026-01-19T12:00:00Z"),
            )

    with pytest.raises(PlanFlowError) as caught:
        action()
    assert type(caught.value) is PlanFlowError
    assert _tree(vault / "tasks") == before


def test_tampered_durable_request_is_generic_and_cannot_reach_plan_state(
    tmp_path, monkeypatch
):
    vault, _, store, _, caps, flow, _ = _setup(tmp_path)
    _run(store)

    def crash(_relative):
        raise RuntimeError("leave durable evidence")

    monkeypatch.setattr(flow, "_before_task_replace", crash)
    with pytest.raises(RuntimeError, match="durable evidence"):
        _commit_day(flow, caps)
    evidence_paths = list((vault / "agent/runs/run_plan").glob("plan-evidence-*.json"))
    assert len(evidence_paths) == 1
    payload = json.loads(evidence_paths[0].read_bytes())
    payload["request"]["expected_revision"] = True
    evidence_paths[0].write_bytes(
        json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )
    monkeypatch.setattr(flow, "_before_task_replace", lambda _relative: None)

    with pytest.raises(PlanFlowError) as caught:
        _commit_day(flow, caps)
    assert type(caught.value) is PlanFlowError
    assert not list((vault / "tasks/days").glob("*.json"))


def test_period_symlink_is_rejected_without_external_write(tmp_path):
    vault, _, store, _, caps, flow, _ = _setup(tmp_path)
    _run(store)
    external = tmp_path / "external-days"
    external.mkdir()
    (vault / "tasks/days").symlink_to(external, target_is_directory=True)

    with pytest.raises(PlanFlowError):
        _commit_day(flow, caps)
    assert list(external.iterdir()) == []


def test_project_pending_transition_blocks_context_without_writes(tmp_path):
    vault, resolver, store, policy, caps, flow, clock = _setup(tmp_path)
    _create_context(resolver, store, policy, clock)
    _run(store)
    intents = vault / "projects/.lifeos-project-intents"
    source = next(intents.glob("*.json"))
    payload = json.loads(source.read_bytes())
    payload["transition_id"] = "pending_context_transition"
    payload["request"]["transition_id"] = "pending_context_transition"
    request_raw = (
        json.dumps(
            payload["request"],
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )
    payload["request_sha256"] = hashlib.sha256(request_raw).hexdigest()
    payload["status"] = "prepared"
    (intents / "pending_context_transition.json").write_bytes(
        json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )
    before = _tree(vault)

    with pytest.raises(PlanFlowError, match="pending transition"):
        flow.planning_packet(
            caps, PlanContextQuery("day", "2026-01-19", "2026-01-19T12:00:00Z")
        )
    assert _tree(vault) == before


@pytest.mark.parametrize("context", ["project", "entity"])
def test_malformed_public_context_is_generic_and_read_only(tmp_path, context):
    vault, _, store, _, caps, flow, _ = _setup(tmp_path)
    _run(store)
    if context == "project":
        project = vault / "projects/broken"
        project.mkdir()
        (project / "project.json").write_text("[]\n", "utf-8")
        (project / "state.json").write_text("{}\n", "utf-8")
    else:
        entities = vault / "agent/memory/entities"
        entities.mkdir()
        (entities / "systems.json").write_text(
            '{"domain":"systems","entities":{},"revision":1,"schema_version":1}\n',
            "utf-8",
        )
    before = _tree(vault)

    with pytest.raises(PlanFlowError) as caught:
        flow.planning_packet(
            caps, PlanContextQuery("day", "2026-01-19", "2026-01-19T12:00:00Z")
        )
    assert type(caught.value) is PlanFlowError
    assert _tree(vault) == before


def test_malformed_plan_json_is_generic_and_unrelated_zones_are_preserved(tmp_path):
    vault, _, store, _, caps, flow, _ = _setup(tmp_path)
    _run(store)
    before = {
        key: value
        for key, value in _tree(vault).items()
        if key.startswith(("knowledge/", "projects/", "agent/memory/"))
    }
    _commit_day(flow, caps)
    path = vault / "tasks/days/2026-01-19.json"
    payload = json.loads(path.read_bytes())
    payload["unknown"] = True
    path.write_text(json.dumps(payload), "utf-8")
    with pytest.raises(PlanFlowError) as caught:
        flow.read_day(caps.collect_plan_context, "2026-01-19")
    assert type(caught.value) is PlanFlowError
    after = {
        key: value
        for key, value in _tree(vault).items()
        if key.startswith(("knowledge/", "projects/", "agent/memory/"))
    }
    assert after == before
