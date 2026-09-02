"""P3-03 project lifecycle, authority, and crash replay acceptance."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import shutil

import pytest

from tool_life_os_runtime.ext.flows.project import (
    PROJECT_SCHEDULE_SCHEMA_VERSION,
    ProjectAdvance,
    ProjectBlocker,
    ProjectCapabilities,
    ProjectFlow,
    ProjectFlowError,
    ProjectMilestone,
    ProjectQuestion,
    ProjectSession,
    ProjectStep,
    ScheduleReceipt,
    ScheduleSnapshot,
    expected_schedule_effect_hash,
    plan_legacy_project_migration,
)
from tool_life_os_runtime.ext.flows.project import flow as project_module
from tool_life_os_runtime.ext.review.authority import AuthorityPolicy
from tool_life_os_runtime.ext.runs import RunStore
from tool_life_os_runtime.ext.vault.config import load_vault_config
from tool_life_os_runtime.ext.vault.schema import VaultPathResolver


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/vault-minimal"
ZERO = "0" * 64


class _Clock:
    def __init__(self) -> None:
        self.value = datetime(2026, 1, 15, 9, 0, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        value = self.value
        self.value += timedelta(seconds=1)
        return value


class _Scheduler:
    def __init__(self, observations=()) -> None:
        self.calls = []
        self.observations = tuple(observations)

    def observe(self, project_slug, schedule_ids):
        assert {item.schedule_id for item in self.observations} == set(schedule_ids)
        return self.observations

    def apply(self, intent):
        self.calls.append(intent)
        return ScheduleReceipt(
            PROJECT_SCHEDULE_SCHEMA_VERSION,
            intent.transition_id,
            "succeeded",
            expected_schedule_effect_hash(intent),
        )


def _setup(tmp_path: Path, *, scheduler=None):
    vault = tmp_path / "vault"
    shutil.copytree(FIXTURE, vault)
    config = load_vault_config(vault / "lifeos.toml")
    resolver = VaultPathResolver(vault, config)
    clock = _Clock()
    store = RunStore(resolver, clock=clock)
    policy = AuthorityPolicy()
    caps = ProjectCapabilities(
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
        schedule=policy.issue(
            flow_id="project",
            action_id="apply-linked-schedule-transition",
            actor="runtime",
            authority="domain-write",
            target="tool:scheduler",
        ),
        run=policy.issue(
            flow_id="project",
            action_id="record-run-state",
            actor="runtime",
            authority="internal-write",
            target="vault:agent/runs",
        ),
    )
    flow = ProjectFlow(resolver, store, policy, clock=clock, schedule_port=scheduler)
    return vault, resolver, store, policy, caps, flow


def _run(store: RunStore, run_id: str = "run_project") -> None:
    store.create(
        run_id=run_id,
        flow="project",
        phase="project",
        authority="domain-write",
        executor="test",
        input_data={"project_slug": "portable-project"},
    )
    store.resume(run_id, executor="test")


def _create(
    flow, caps, *, run_id="run_project", transition_id="create_project", schedules=()
):
    return flow.create(
        caps,
        run_id=run_id,
        transition_id=transition_id,
        slug="portable-project",
        name="Portable project",
        goal="Exercise a synthetic lifecycle.",
        domains=("systems",),
        schedule_ids=schedules,
    )


def _advance(snapshot):
    return ProjectAdvance(
        next_steps=(
            ProjectStep("step_review", "Review the proposal.", priority="high"),
        ),
        blockers=(
            ProjectBlocker("blocker_none", "Synthetic blocker.", status="resolved"),
        ),
        open_questions=(ProjectQuestion("question_scope", "Is scope exact?"),),
        milestones=(ProjectMilestone("milestone_one", "First transition."),),
        session=ProjectSession(
            "2026-01-15T09:10:00Z", "Advanced the synthetic fixture."
        ),
        summary="Recorded a typed project advance.",
    )


def test_create_list_status_and_run_evidence_are_exact(tmp_path):
    vault, _, store, _, caps, flow = _setup(tmp_path)
    _run(store)

    result = _create(flow, caps)

    assert result.snapshot.record.status == "active"
    assert result.snapshot.state.revision == 1
    assert result.snapshot.location == "portable-project"
    assert flow.list(caps.read) == (flow.status(caps.read, "portable-project"),)
    assert store.status("run_project")["status"] == "running"
    assert store.status("run_project")["artifacts"] == {
        "project_transition": "projects/.lifeos-project-evidence/create_project.json"
    }
    assert [
        action["action_id"]
        for action in store.trace_events("run_project")[0]["actions"]
    ] == ["read-project-state", "commit-project-transition", "record-run-state"]
    assert not (vault / "agent/schedule").exists()
    assert (
        json.loads((vault / "projects/portable-project/project.json").read_text())[
            "last_transition_id"
        ]
        == "create_project"
    )


def test_advance_is_typed_revisioned_and_log_append_only(tmp_path):
    vault, _, store, _, caps, flow = _setup(tmp_path)
    _run(store)
    created = _create(flow, caps)
    log_path = vault / "projects/portable-project/log.md"
    prefix = log_path.read_bytes()

    advanced = flow.advance(
        caps,
        run_id="run_project",
        transition_id="advance_project",
        slug="portable-project",
        advance=_advance(created.snapshot),
        expected_revision=1,
        expected_snapshot_sha256=created.snapshot.snapshot_sha256,
    )

    assert advanced.snapshot.record.revision == 2
    assert advanced.snapshot.state.next_steps[0].step_id == "step_review"
    assert log_path.read_bytes().startswith(prefix)
    with pytest.raises(ProjectFlowError, match="stale"):
        flow.advance(
            caps,
            run_id="run_project",
            transition_id="stale_advance",
            slug="portable-project",
            advance=_advance(created.snapshot),
            expected_revision=1,
            expected_snapshot_sha256=created.snapshot.snapshot_sha256,
        )


def test_hold_pauses_linked_schedules_resume_never_invokes(tmp_path):
    scheduler = _Scheduler()
    vault, _, store, _, caps, flow = _setup(tmp_path, scheduler=scheduler)
    _run(store)
    created = _create(flow, caps, schedules=("daily_review",))

    held = flow.hold(
        caps,
        run_id="run_project",
        transition_id="hold_project",
        slug="portable-project",
        reason="Pause for a bounded review.",
        expected_revision=1,
        expected_snapshot_sha256=created.snapshot.snapshot_sha256,
    )

    assert held.snapshot.location == "_on_hold/portable-project"
    assert [call.schedule_ids for call in scheduler.calls] == [("daily_review",)]
    resumed = flow.resume(
        caps,
        run_id="run_project",
        transition_id="resume_project",
        slug="portable-project",
        expected_revision=2,
        expected_snapshot_sha256=held.snapshot.snapshot_sha256,
    )
    assert resumed.snapshot.location == "portable-project"
    assert len(scheduler.calls) == 1
    assert not (vault / "agent/schedule").exists()


def test_missing_scheduler_leaves_durable_pending_then_replays_once(tmp_path):
    vault, resolver, store, policy, caps, flow = _setup(tmp_path)
    _run(store)
    created = _create(flow, caps, schedules=("daily_review",))

    pending = flow.hold(
        caps,
        run_id="run_project",
        transition_id="hold_pending",
        slug="portable-project",
        reason="Connector temporarily unavailable.",
        expected_revision=1,
        expected_snapshot_sha256=created.snapshot.snapshot_sha256,
    )

    assert pending.schedule_pending is True
    assert pending.snapshot.record.status == "on-hold"
    scheduler = _Scheduler()
    replay_flow = ProjectFlow(
        resolver, store, policy, clock=_Clock(), schedule_port=scheduler
    )
    replay = replay_flow.hold(
        caps,
        run_id="run_project",
        transition_id="hold_pending",
        slug="portable-project",
        reason="Connector temporarily unavailable.",
        expected_revision=1,
        expected_snapshot_sha256=created.snapshot.snapshot_sha256,
    )
    assert replay.replayed and not replay.schedule_pending
    assert len(scheduler.calls) == 1
    assert store.status("run_project")["status"] == "running"
    assert not (vault / "agent/schedule").exists()


def test_scheduler_apply_exception_is_generic_and_retry_keeps_pending_intent(
    tmp_path,
):
    class _FailingScheduler(_Scheduler):
        def apply(self, intent):
            self.calls.append(intent)
            raise RuntimeError("connector credential detail must stay private")

    failing = _FailingScheduler()
    vault, resolver, store, policy, caps, flow = _setup(tmp_path, scheduler=failing)
    _run(store)
    created = _create(flow, caps, schedules=("daily_review",))

    with pytest.raises(ProjectFlowError) as raised:
        flow.hold(
            caps,
            run_id="run_project",
            transition_id="hold_connector_failure",
            slug="portable-project",
            reason="Retry connector delivery.",
            expected_revision=1,
            expected_snapshot_sha256=created.snapshot.snapshot_sha256,
        )

    assert str(raised.value) == "linked schedule transition failed"
    assert "credential" not in str(raised.value)
    intent_path = vault / "projects/.lifeos-project-intents/hold_connector_failure.json"
    pending = json.loads(intent_path.read_text("utf-8"))
    assert pending["status"] == "domain_committed"
    assert pending["schedule_receipt"] is None

    scheduler = _Scheduler()
    replay_flow = ProjectFlow(
        resolver, store, policy, clock=_Clock(), schedule_port=scheduler
    )
    replay = replay_flow.hold(
        caps,
        run_id="run_project",
        transition_id="hold_connector_failure",
        slug="portable-project",
        reason="Retry connector delivery.",
        expected_revision=1,
        expected_snapshot_sha256=created.snapshot.snapshot_sha256,
    )

    assert replay.replayed
    assert not replay.schedule_pending
    assert len(scheduler.calls) == 1


def test_missing_schedule_capability_fails_before_hold_domain_effect(tmp_path):
    vault, _, store, _, caps, flow = _setup(tmp_path, scheduler=_Scheduler())
    _run(store)
    created = _create(flow, caps, schedules=("daily_review",))
    no_schedule = ProjectCapabilities(caps.read, caps.commit, caps.run, None)

    with pytest.raises(ProjectFlowError, match="schedule capability"):
        flow.hold(
            no_schedule,
            run_id="run_project",
            transition_id="hold_without_schedule_capability",
            slug="portable-project",
            reason="Capability must precede the effect.",
            expected_revision=1,
            expected_snapshot_sha256=created.snapshot.snapshot_sha256,
        )

    assert (vault / "projects/portable-project").is_dir()
    assert not (vault / "projects/_on_hold/portable-project").exists()


def test_archive_refuse_cascade_and_terminal_location(tmp_path):
    schedule = ScheduleSnapshot("weekly_project", "active", ZERO)
    scheduler = _Scheduler((schedule,))
    vault, _, store, _, caps, flow = _setup(tmp_path, scheduler=scheduler)
    _run(store)
    created = _create(flow, caps, schedules=("weekly_project",))
    engine = vault / "projects/portable-project/research/engine_one"
    engine.mkdir(parents=True)
    (engine / "project.json").write_text(
        json.dumps({"slug": "engine_one", "status": "active"}), "utf-8"
    )
    with pytest.raises(ProjectFlowError, match="refuses"):
        flow.archive(
            caps,
            run_id="run_project",
            transition_id="archive_refuse",
            slug="portable-project",
            child_policy="refuse",
            expected_revision=1,
            expected_snapshot_sha256=created.snapshot.snapshot_sha256,
        )

    archived = flow.archive(
        caps,
        run_id="run_project",
        transition_id="archive_cascade",
        slug="portable-project",
        child_policy="cascade",
        expected_revision=1,
        expected_snapshot_sha256=created.snapshot.snapshot_sha256,
    )

    assert archived.snapshot.location == "_archive/portable-project-2026-01-15"
    assert archived.snapshot.record.status == "archived"
    assert archived.archived_children == ("engine_one",)
    child = json.loads(
        (
            vault
            / "projects/_archive/portable-project-2026-01-15/research/engine_one/project.json"
        ).read_text()
    )
    assert child["status"] == "archived"
    assert scheduler.calls[-1].reason == "project-archive-cascade"
    with pytest.raises(ProjectFlowError, match="terminal"):
        flow.archive(
            caps,
            run_id="run_project",
            transition_id="archive_again",
            slug="portable-project",
            child_policy="cascade",
            expected_revision=2,
            expected_snapshot_sha256=archived.snapshot.snapshot_sha256,
        )


def test_archive_keep_active_is_explicit_and_does_not_pause(tmp_path):
    scheduler = _Scheduler((ScheduleSnapshot("weekly_project", "active", ZERO),))
    vault, _, store, _, caps, flow = _setup(tmp_path, scheduler=scheduler)
    _run(store)
    created = _create(flow, caps, schedules=("weekly_project",))
    engine = vault / "projects/portable-project/research/engine_one"
    engine.mkdir(parents=True)
    (engine / "project.json").write_text(json.dumps({"status": "active"}), "utf-8")

    result = flow.archive(
        caps,
        run_id="run_project",
        transition_id="archive_keep",
        slug="portable-project",
        child_policy="keep-active",
        expected_revision=1,
        expected_snapshot_sha256=created.snapshot.snapshot_sha256,
    )

    assert result.child_policy == "keep-active"
    assert [call.action for call in scheduler.calls] == ["verify"]
    assert (
        json.loads(
            (
                vault
                / "projects/_archive/portable-project-2026-01-15/research/engine_one/project.json"
            ).read_text()
        )["status"]
        == "active"
    )


def test_archive_requires_authoritative_schedule_observation(tmp_path):
    vault, _, store, _, caps, flow = _setup(tmp_path)
    _run(store)
    created = _create(flow, caps, schedules=("weekly_project",))

    with pytest.raises(ProjectFlowError, match="authoritative linked schedule"):
        flow.archive(
            caps,
            run_id="run_project",
            transition_id="archive_without_observation",
            slug="portable-project",
            child_policy="refuse",
            expected_revision=1,
            expected_snapshot_sha256=created.snapshot.snapshot_sha256,
        )

    assert (vault / "projects/portable-project").is_dir()
    assert not (vault / "projects/_archive/portable-project-2026-01-15").exists()


def test_archive_refuse_uses_observed_paused_state_not_caller_data(tmp_path):
    scheduler = _Scheduler((ScheduleSnapshot("weekly_project", "paused", ZERO),))
    _, _, store, _, caps, flow = _setup(tmp_path, scheduler=scheduler)
    _run(store)
    created = _create(flow, caps, schedules=("weekly_project",))

    result = flow.archive(
        caps,
        run_id="run_project",
        transition_id="archive_paused",
        slug="portable-project",
        child_policy="refuse",
        expected_revision=1,
        expected_snapshot_sha256=created.snapshot.snapshot_sha256,
    )

    assert result.snapshot.record.status == "archived"
    assert [call.action for call in scheduler.calls] == ["verify"]
    actions = store.trace_events("run_project")[-1]["actions"]
    assert [item["action_id"] for item in actions] == [
        "read-project-state",
        "commit-project-transition",
        "apply-linked-schedule-transition",
        "record-run-state",
    ]


def test_scheduler_receipt_must_bind_exact_canonical_intent(tmp_path):
    class _BadScheduler(_Scheduler):
        def apply(self, intent):
            self.calls.append(intent)
            return ScheduleReceipt(
                PROJECT_SCHEDULE_SCHEMA_VERSION,
                intent.transition_id,
                "succeeded",
                "f" * 64,
            )

    observation = ScheduleSnapshot("weekly_project", "active", ZERO)
    bad = _BadScheduler((observation,))
    _, resolver, store, policy, caps, flow = _setup(tmp_path, scheduler=bad)
    _run(store)
    created = _create(flow, caps, schedules=("weekly_project",))

    with pytest.raises(ProjectFlowError, match="not bound"):
        flow.archive(
            caps,
            run_id="run_project",
            transition_id="archive_bound_receipt",
            slug="portable-project",
            child_policy="cascade",
            expected_revision=1,
            expected_snapshot_sha256=created.snapshot.snapshot_sha256,
        )
    with pytest.raises(ProjectFlowError, match="pending transition"):
        flow.status(caps.read, "portable-project")

    good = _Scheduler((observation,))
    replay_flow = ProjectFlow(
        resolver, store, policy, clock=_Clock(), schedule_port=good
    )
    replay = replay_flow.archive(
        caps,
        run_id="run_project",
        transition_id="archive_bound_receipt",
        slug="portable-project",
        child_policy="cascade",
        expected_revision=1,
        expected_snapshot_sha256=created.snapshot.snapshot_sha256,
    )
    assert replay.replayed
    assert replay.schedule_receipt.effect_hash == expected_schedule_effect_hash(
        good.calls[0]
    )


def test_crash_after_intent_and_after_move_are_reconciled(tmp_path, monkeypatch):
    _, _, store, _, caps, flow = _setup(tmp_path)
    _run(store)
    crashed = False

    def crash_once():
        nonlocal crashed
        if not crashed:
            crashed = True
            raise RuntimeError("injected before domain")

    monkeypatch.setattr(flow, "_before_domain_commit", crash_once)
    with pytest.raises(RuntimeError, match="injected"):
        _create(flow, caps)
    monkeypatch.setattr(flow, "_before_domain_commit", lambda: None)
    created = _create(flow, caps)
    assert created.replayed

    real_atomic = project_module._atomic_file_at
    moved_crash = False

    def crash_after_move(directory_fd, name, data):
        nonlocal moved_crash
        if name == "project.json" and not moved_crash:
            moved_crash = True
            raise RuntimeError("injected after move")
        return real_atomic(directory_fd, name, data)

    monkeypatch.setattr(project_module, "_atomic_file_at", crash_after_move)
    with pytest.raises(RuntimeError, match="after move"):
        flow.hold(
            caps,
            run_id="run_project",
            transition_id="hold_crash",
            slug="portable-project",
            reason="Crash exercise.",
            expected_revision=1,
            expected_snapshot_sha256=created.snapshot.snapshot_sha256,
        )
    monkeypatch.setattr(project_module, "_atomic_file_at", real_atomic)
    recovered = flow.hold(
        caps,
        run_id="run_project",
        transition_id="hold_crash",
        slug="portable-project",
        reason="Crash exercise.",
        expected_revision=1,
        expected_snapshot_sha256=created.snapshot.snapshot_sha256,
    )
    assert recovered.snapshot.location == "_on_hold/portable-project"
    assert recovered.snapshot.record.revision == 2


def test_public_status_rejects_mixed_bundle_until_pending_intent_replays(
    tmp_path, monkeypatch
):
    _, _, store, _, caps, flow = _setup(tmp_path)
    _run(store)
    created = _create(flow, caps)
    real_atomic = project_module._atomic_file_at
    crashed = False

    def crash_after_log(directory_fd, name, data):
        nonlocal crashed
        if name == "project.json" and not crashed:
            crashed = True
            raise RuntimeError("after log before record")
        return real_atomic(directory_fd, name, data)

    monkeypatch.setattr(project_module, "_atomic_file_at", crash_after_log)
    with pytest.raises(RuntimeError, match="after log"):
        flow.advance(
            caps,
            run_id="run_project",
            transition_id="advance_bundle_crash",
            slug="portable-project",
            advance=_advance(created.snapshot),
            expected_revision=1,
            expected_snapshot_sha256=created.snapshot.snapshot_sha256,
        )
    with pytest.raises(ProjectFlowError, match="pending transition"):
        flow.status(caps.read, "portable-project")

    monkeypatch.setattr(project_module, "_atomic_file_at", real_atomic)
    recovered = flow.advance(
        caps,
        run_id="run_project",
        transition_id="advance_bundle_crash",
        slug="portable-project",
        advance=_advance(created.snapshot),
        expected_revision=1,
        expected_snapshot_sha256=created.snapshot.snapshot_sha256,
    )
    assert flow.status(caps.read, "portable-project") == recovered.snapshot


def test_public_status_binds_log_to_exact_completed_bundle_hash(tmp_path):
    vault, _, store, _, caps, flow = _setup(tmp_path)
    _run(store)
    _create(flow, caps)
    with (vault / "projects/portable-project/log.md").open("ab") as stream:
        stream.write(b"\nexternal mixed revision\n")

    with pytest.raises(ProjectFlowError, match="bundle hashes"):
        flow.status(caps.read, "portable-project")


def test_atomic_publish_retains_staged_inode_and_preserves_substituted_foreign(
    tmp_path, monkeypatch
):
    directory = tmp_path / "atomic"
    directory.mkdir()
    target = directory / "record.json"
    target.write_bytes(b"original\n")
    directory_fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    real_replace = project_module.os.replace
    substituted = False

    def substitute_staged(source, destination, *, src_dir_fd=None, dst_dir_fd=None):
        nonlocal substituted
        if (
            not substituted
            and source.startswith(".record.json.")
            and source.endswith(".tmp")
            and destination == "record.json"
        ):
            substituted = True
            os.unlink(source, dir_fd=src_dir_fd)
            foreign_fd = os.open(
                source,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=src_dir_fd,
            )
            os.write(foreign_fd, b"foreign\n")
            os.close(foreign_fd)
        return real_replace(
            source,
            destination,
            src_dir_fd=src_dir_fd,
            dst_dir_fd=dst_dir_fd,
        )

    monkeypatch.setattr(project_module.os, "replace", substitute_staged)
    try:
        with pytest.raises(ProjectFlowError, match="cannot be committed"):
            project_module._atomic_file_at(directory_fd, "record.json", b"target\n")
    finally:
        os.close(directory_fd)

    assert target.read_bytes() == b"original\n"
    foreign = list(directory.glob(".project-flow-foreign-*"))
    assert len(foreign) == 1
    assert foreign[0].read_bytes() == b"foreign\n"


def test_atomic_publish_rechecks_named_entry_after_retained_hash(tmp_path, monkeypatch):
    directory = tmp_path / "atomic-after-hash"
    directory.mkdir()
    target = directory / "record.json"
    target.write_bytes(b"original\n")
    retained_name = directory / "retained-target.json"
    directory_fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    real_read = project_module.os.read
    substituted = False

    def substitute_named_after_hash(fd, count):
        nonlocal substituted
        chunk = real_read(fd, count)
        if not substituted and chunk and target.exists():
            opened = os.fstat(fd)
            named = target.stat()
            if (opened.st_dev, opened.st_ino) == (named.st_dev, named.st_ino):
                substituted = True
                target.rename(retained_name)
                target.write_bytes(b"unrelated\n")
        return chunk

    monkeypatch.setattr(project_module.os, "read", substitute_named_after_hash)
    try:
        with pytest.raises(ProjectFlowError, match="cannot be committed"):
            project_module._atomic_file_at(directory_fd, "record.json", b"target\n")
    finally:
        os.close(directory_fd)

    assert substituted
    assert target.read_bytes() == b"unrelated\n"
    assert retained_name.read_bytes() == b"target\n"


def test_parent_vault_swap_during_publish_rolls_back_detached_domain_effects(
    tmp_path, monkeypatch
):
    vault, _, store, _, caps, flow = _setup(tmp_path)
    _run(store)
    saved = tmp_path / "detached-vault"
    real_atomic = project_module._atomic_file_at
    swapped = False

    def swap_parent_then_publish(directory_fd, name, data):
        nonlocal swapped
        if name == "log.md" and not swapped:
            swapped = True
            vault.rename(saved)
            shutil.copytree(FIXTURE, vault)
        return real_atomic(directory_fd, name, data)

    monkeypatch.setattr(project_module, "_atomic_file_at", swap_parent_then_publish)
    with pytest.raises(ProjectFlowError, match="identity changed"):
        _create(flow, caps)

    assert [path.name for path in (saved / "projects").iterdir()] == [".gitkeep"]
    assert [path.name for path in (vault / "projects").iterdir()] == [".gitkeep"]


def test_project_directory_replacement_stops_writes_and_reconciles_on_retry(
    tmp_path, monkeypatch
):
    vault, _, store, _, caps, flow = _setup(tmp_path)
    _run(store)
    created = _create(flow, caps)
    project = vault / "projects/portable-project"
    detached = vault / "projects/portable-project-detached"
    real_atomic = project_module._atomic_file_at
    replaced = False

    def replace_project_directory(directory_fd, name, data):
        nonlocal replaced
        if name == "log.md" and not replaced:
            replaced = True
            project.rename(detached)
            shutil.copytree(detached, project)
        return real_atomic(directory_fd, name, data)

    monkeypatch.setattr(project_module, "_atomic_file_at", replace_project_directory)
    with pytest.raises(ProjectFlowError, match="directory changed"):
        flow.advance(
            caps,
            run_id="run_project",
            transition_id="advance_directory_replaced",
            slug="portable-project",
            advance=_advance(created.snapshot),
            expected_revision=1,
            expected_snapshot_sha256=created.snapshot.snapshot_sha256,
        )

    assert json.loads((project / "project.json").read_text("utf-8"))["revision"] == 1
    assert json.loads((detached / "project.json").read_text("utf-8"))["revision"] == 1

    monkeypatch.setattr(project_module, "_atomic_file_at", real_atomic)
    replay = flow.advance(
        caps,
        run_id="run_project",
        transition_id="advance_directory_replaced",
        slug="portable-project",
        advance=_advance(created.snapshot),
        expected_revision=1,
        expected_snapshot_sha256=created.snapshot.snapshot_sha256,
    )

    assert replay.replayed
    assert replay.snapshot.record.revision == 2
    assert not detached.exists()
    preserved = list((vault / "projects").glob(".project-flow-foreign-*"))
    assert len(preserved) == 1
    assert (
        json.loads((preserved[0] / "project.json").read_text("utf-8"))["revision"] == 1
    )


def test_transition_replay_is_exact_and_conflicting_request_fails(tmp_path):
    _, _, store, _, caps, flow = _setup(tmp_path)
    _run(store)
    first = _create(flow, caps)
    replay = _create(flow, caps)
    assert replay.replayed
    assert replay.snapshot.snapshot_sha256 == first.snapshot.snapshot_sha256
    with pytest.raises(ProjectFlowError, match="disagrees"):
        flow.create(
            caps,
            run_id="run_project",
            transition_id="create_project",
            slug="portable-project",
            name="Changed name",
            goal="Exercise a synthetic lifecycle.",
            domains=("systems",),
        )


def test_crash_after_run_commit_before_local_completion_replays(tmp_path, monkeypatch):
    _, _, store, _, caps, flow = _setup(tmp_path)
    _run(store)
    crashed = False

    def crash_once():
        nonlocal crashed
        if not crashed:
            crashed = True
            raise RuntimeError("after run commit")

    monkeypatch.setattr(flow, "_after_run_commit", crash_once)
    with pytest.raises(RuntimeError, match="after run"):
        _create(flow, caps)
    monkeypatch.setattr(flow, "_after_run_commit", lambda: None)

    replay = _create(flow, caps)

    assert replay.replayed
    assert replay.snapshot.record.status == "active"
    assert [event["step_id"] for event in store.trace_events("run_project")] == [
        "create_project"
    ]


def test_child_appearing_after_archive_prepare_fails_without_move(
    tmp_path, monkeypatch
):
    vault, _, store, _, caps, flow = _setup(tmp_path)
    _run(store)
    created = _create(flow, caps)
    injected = False

    def add_child():
        nonlocal injected
        if not injected:
            injected = True
            child = vault / "projects/portable-project/research/late_engine"
            child.mkdir(parents=True)
            (child / "project.json").write_text(
                json.dumps({"status": "active"}), "utf-8"
            )

    monkeypatch.setattr(flow, "_before_domain_commit", add_child)
    with pytest.raises(ProjectFlowError, match="set changed"):
        flow.archive(
            caps,
            run_id="run_project",
            transition_id="archive_race",
            slug="portable-project",
            child_policy="refuse",
            expected_revision=1,
            expected_snapshot_sha256=created.snapshot.snapshot_sha256,
        )

    assert (vault / "projects/portable-project").is_dir()
    assert not (vault / "projects/_archive/portable-project-2026-01-15").exists()


def test_tampered_durable_intent_cannot_redirect_project_write(tmp_path, monkeypatch):
    vault, _, store, _, caps, flow = _setup(tmp_path)
    _run(store)
    monkeypatch.setattr(
        flow,
        "_before_domain_commit",
        lambda: (_ for _ in ()).throw(RuntimeError("prepared")),
    )
    with pytest.raises(RuntimeError, match="prepared"):
        _create(flow, caps)
    intent_path = vault / "projects/.lifeos-project-intents/create_project.json"
    intent = json.loads(intent_path.read_text("utf-8"))
    intent["destination"] = "redirected-project"
    intent_path.write_text(json.dumps(intent), "utf-8")
    monkeypatch.setattr(flow, "_before_domain_commit", lambda: None)

    with pytest.raises(ProjectFlowError, match="location disagrees"):
        _create(flow, caps)

    assert not (vault / "projects/portable-project").exists()
    assert not (vault / "projects/redirected-project").exists()


def test_snapshot_retains_all_file_identities_until_bundle_is_read(
    tmp_path, monkeypatch
):
    vault, _, store, _, caps, flow = _setup(tmp_path)
    _run(store)
    _create(flow, caps)
    project_path = vault / "projects/portable-project/project.json"
    project_inode = project_path.stat().st_ino
    real_read = project_module.os.read
    mutated = False

    def mutate_after_project_read(fd, count):
        nonlocal mutated
        chunk = real_read(fd, count)
        if not mutated and os.fstat(fd).st_ino == project_inode and chunk:
            mutated = True
            payload = json.loads(project_path.read_text("utf-8"))
            payload["name"] = "Changed concurrently"
            project_path.write_text(json.dumps(payload), "utf-8")
        return chunk

    monkeypatch.setattr(project_module.os, "read", mutate_after_project_read)
    with pytest.raises(ProjectFlowError, match="bundle changed"):
        flow.status(caps.read, "portable-project")


def test_directory_and_bundle_open_failures_do_not_leak_descriptors(
    tmp_path, monkeypatch
):
    descriptor_root = Path("/dev/fd")
    if not descriptor_root.is_dir():
        descriptor_root = Path("/proc/self/fd")
    if not descriptor_root.is_dir():
        pytest.skip("descriptor namespace is unavailable")

    directory = tmp_path / "descriptor-failures"
    child = directory / "child"
    child.mkdir(parents=True)
    (directory / "one.json").write_bytes(b"{}")
    (directory / "two.json").write_bytes(b"{}")
    directory_fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    real_stat = project_module.os.stat

    def fail_child_named_stat(path, *args, dir_fd=None, **kwargs):
        if path == "child" and dir_fd is not None:
            raise OSError("named directory stat failure")
        return real_stat(path, *args, dir_fd=dir_fd, **kwargs)

    monkeypatch.setattr(project_module.os, "stat", fail_child_named_stat)
    before = len(os.listdir(descriptor_root))
    for _ in range(100):
        with pytest.raises(ProjectFlowError, match="opened safely"):
            project_module._open_dir_at(directory_fd, "child")
    assert len(os.listdir(descriptor_root)) == before

    def fail_bundle_named_stat(path, *args, dir_fd=None, **kwargs):
        if path == "two.json" and dir_fd is not None:
            raise OSError("named file stat failure")
        return real_stat(path, *args, dir_fd=dir_fd, **kwargs)

    monkeypatch.setattr(project_module.os, "stat", fail_bundle_named_stat)
    before = len(os.listdir(descriptor_root))
    try:
        for _ in range(100):
            with pytest.raises(ProjectFlowError, match="opened safely"):
                project_module._read_bundle_at(
                    directory_fd,
                    (("one.json", 1024), ("two.json", 1024)),
                )
        assert len(os.listdir(descriptor_root)) == before
    finally:
        os.close(directory_fd)


def test_corrupt_lifecycle_child_status_does_not_leak_descriptors(tmp_path):
    descriptor_root = Path("/dev/fd")
    if not descriptor_root.is_dir():
        descriptor_root = Path("/proc/self/fd")
    if not descriptor_root.is_dir():
        pytest.skip("descriptor namespace is unavailable")

    vault, _, store, _, caps, flow = _setup(tmp_path)
    _run(store)
    _create(flow, caps)
    (vault / "projects/_on_hold/corrupt").mkdir(parents=True)

    before = len(os.listdir(descriptor_root))
    for _ in range(40):
        with pytest.raises(ProjectFlowError, match="corrupt data"):
            flow.status(caps.read, "portable-project")
    assert len(os.listdir(descriptor_root)) == before


def test_corrupt_optional_lifecycle_namespace_is_not_treated_as_absent(tmp_path):
    vault, _, store, _, caps, flow = _setup(tmp_path)
    _run(store)
    _create(flow, caps)
    outside = tmp_path / "outside-held"
    outside.mkdir()
    os.symlink(outside, vault / "projects/_on_hold", target_is_directory=True)

    with pytest.raises(ProjectFlowError, match="unsafe"):
        flow.status(caps.read, "portable-project")
    assert not hasattr(flow, "delete")


def test_wrong_capability_and_fabricated_capability_fail_without_write(tmp_path):
    vault, _, store, policy, caps, flow = _setup(tmp_path)
    _run(store)
    with pytest.raises(ProjectFlowError, match="not exact"):
        flow.create(
            ProjectCapabilities(caps.read, caps.read, caps.run, caps.schedule),
            run_id="run_project",
            transition_id="wrong_capability",
            slug="portable-project",
            name="Portable project",
            goal="A safe goal.",
            domains=("systems",),
        )
    other_policy = AuthorityPolicy()
    foreign = other_policy.issue(
        flow_id="project",
        action_id="read-project-state",
        actor="runtime",
        authority="read",
        target="vault:projects",
    )
    with pytest.raises(ProjectFlowError, match="not issued"):
        flow.list(foreign)
    assert [path.name for path in (vault / "projects").iterdir()] == [".gitkeep"]
    assert policy.matrix_sha256 == caps.commit.matrix_sha256


def test_transition_requires_exact_read_capability_before_commit(tmp_path):
    vault, _, store, _, caps, flow = _setup(tmp_path)
    _run(store)
    wrong = ProjectCapabilities(caps.commit, caps.commit, caps.run, caps.schedule)

    with pytest.raises(ProjectFlowError, match="not exact"):
        _create(flow, wrong)

    assert [path.name for path in (vault / "projects").iterdir()] == [".gitkeep"]


@pytest.mark.parametrize(
    "field,value",
    [
        ("name", "FILE:/" + "Users/private/project"),
        ("goal", r"C:\Users\private\project"),
        ("goal", "API_KEY=synthetic-secret-value"),
        ("name", "bad\ud800"),
    ],
)
def test_private_secret_and_non_utf8_text_is_rejected(tmp_path, field, value):
    vault, _, store, _, caps, flow = _setup(tmp_path)
    _run(store)
    kwargs = {
        "run_id": "run_project",
        "transition_id": "private_project",
        "slug": "portable-project",
        "name": "Portable project",
        "goal": "A safe goal.",
        "domains": ("systems",),
    }
    kwargs[field] = value
    with pytest.raises(ProjectFlowError):
        flow.create(caps, **kwargs)
    assert [path.name for path in (vault / "projects").iterdir()] == [".gitkeep"]


def test_portable_alias_symlink_and_root_swap_do_not_escape(tmp_path, monkeypatch):
    vault, _, store, _, caps, flow = _setup(tmp_path)
    _run(store)
    (vault / "projects/Portable-Project").mkdir()
    with pytest.raises(ProjectFlowError, match="collides"):
        _create(flow, caps)
    (vault / "projects/Portable-Project").rmdir()

    outside = tmp_path / "outside"
    outside.mkdir()
    os.symlink(outside, vault / "projects/portable-project", target_is_directory=True)
    with pytest.raises(ProjectFlowError, match="collides"):
        _create(flow, caps)
    (vault / "projects/portable-project").unlink()

    saved = vault / "projects-saved"
    swapped = False

    def swap_root():
        nonlocal swapped
        if not swapped:
            swapped = True
            (vault / "projects").rename(saved)
            os.symlink(outside, vault / "projects", target_is_directory=True)

    monkeypatch.setattr(flow, "_before_domain_commit", swap_root)
    with pytest.raises(ProjectFlowError, match="changed"):
        _create(flow, caps)
    assert list(outside.iterdir()) == []


@pytest.mark.parametrize("reserved", ["_ON_HOLD", "_Archive", "_TRASH"])
def test_casefold_reserved_lifecycle_alias_is_rejected(tmp_path, reserved):
    vault, _, store, _, caps, flow = _setup(tmp_path)
    _run(store)
    (vault / "projects" / reserved).mkdir()

    with pytest.raises(ProjectFlowError, match="aliases a reserved"):
        _create(flow, caps)

    assert not (vault / "projects/portable-project").exists()


def test_legacy_migration_is_pure_deterministic_and_does_not_touch_source(tmp_path):
    source = tmp_path / "legacy"
    source.mkdir()
    project_path = source / "project.json"
    state_path = source / "state.json"
    log_path = source / "log.md"
    project_path.write_text(
        json.dumps(
            {
                "slug": "legacy-project",
                "name": "Legacy project",
                "goal": "Migrate synthetic state.",
                "domains": ["systems"],
                "kind": "general",
                "status": "active",
                "created_at": "2026-01-15T08:00:00Z",
                "updated_at": "2026-01-15T09:00:00Z",
            }
        ),
        "utf-8",
    )
    state_path.write_text(
        json.dumps(
            {
                "next_steps": [{"id": "step_one", "text": "Migrate."}],
                "blockers": [],
                "open_questions": [],
                "milestones": [],
                "last_session": "2026-01-15T09:00:00Z",
            }
        ),
        "utf-8",
    )
    log_path.write_text("# Legacy log\n", "utf-8")
    before = {path: path.read_bytes() for path in (project_path, state_path, log_path)}

    first = plan_legacy_project_migration(
        project_bytes=before[project_path],
        state_bytes=before[state_path],
        log_bytes=before[log_path],
    )
    second = plan_legacy_project_migration(
        project_bytes=before[project_path],
        state_bytes=before[state_path],
        log_bytes=before[log_path],
    )

    assert first == second
    assert first.target_relative == "legacy-project"
    assert json.loads(first.project_bytes)["schema_version"] == 1
    assert {path: path.read_bytes() for path in before} == before


@pytest.mark.parametrize("field", ["domains", "schedule_ids"])
def test_legacy_migration_requires_arrays_not_strings(field):
    project = {
        "slug": "legacy-project",
        "name": "Legacy project",
        "goal": "Migrate synthetic state.",
        "domains": ["systems"],
        "schedule_ids": [],
        "kind": "general",
        "status": "active",
        "created_at": "2026-01-15T08:00:00Z",
        "updated_at": "2026-01-15T09:00:00Z",
    }
    project[field] = "not-an-array"

    with pytest.raises(ProjectFlowError, match="arrays of strings"):
        plan_legacy_project_migration(
            project_bytes=json.dumps(project).encode(),
            state_bytes=json.dumps(
                {
                    "next_steps": [],
                    "blockers": [],
                    "open_questions": [],
                    "milestones": [],
                    "last_session": None,
                }
            ).encode(),
            log_bytes=b"# Legacy log\n",
        )


@pytest.mark.parametrize("error", [ValueError("decoder"), RecursionError("deep")])
def test_decoder_normalizes_value_and_recursion_errors(monkeypatch, error):
    monkeypatch.setattr(
        project_module.json,
        "loads",
        lambda _value: (_ for _ in ()).throw(error),
    )
    with pytest.raises(ProjectFlowError, match="invalid JSON"):
        plan_legacy_project_migration(
            project_bytes=b"{}",
            state_bytes=b"{}",
            log_bytes=b"# Legacy log\n",
        )
