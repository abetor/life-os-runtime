"""P3-04 entity, confirmed done-event, trail, and stale acceptance."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import shutil

import pytest

from tool_life_os_runtime.ext.flows.entities import flow as entities_module
from tool_life_os_runtime.ext.flows.entities import (
    DoneEventRecord,
    EntitiesCapabilities,
    EntitiesFlow,
    EntitiesFlowError,
    EntityStep,
    HumanConfirmation,
    NextCheckPolicy,
    StaleQuery,
    TrailEvent,
    migrate_legacy_entities,
)
from tool_life_os_runtime.ext.review.authority import AuthorityPolicy
from tool_life_os_runtime.ext.runs import RunStore
from tool_life_os_runtime.ext.vault.config import load_vault_config
from tool_life_os_runtime.ext.vault.schema import VaultPathResolver, VaultSchemaError


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/vault-minimal"


class _Clock:
    def __init__(self) -> None:
        self.value = datetime(2026, 1, 1, 9, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        value = self.value
        self.value += timedelta(seconds=1)
        return value


def _setup(tmp_path: Path):
    vault = tmp_path / "vault"
    shutil.copytree(FIXTURE, vault)
    config = load_vault_config(vault / "lifeos.toml")
    resolver = VaultPathResolver(vault, config)
    clock = _Clock()
    store = RunStore(resolver, clock=clock)
    policy = AuthorityPolicy()
    caps = EntitiesCapabilities(
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
    flow = EntitiesFlow(resolver, store, policy, clock)
    return vault, resolver, store, policy, caps, flow


def _run(store: RunStore, run_id: str = "run_entities") -> None:
    store.create(
        run_id=run_id,
        flow="entities",
        phase="entities",
        authority="domain-write",
        executor="test",
        input_data={"scope": "synthetic"},
    )
    store.resume(run_id, executor="test")


def _create(flow: EntitiesFlow, caps: EntitiesCapabilities, **overrides):
    values = {
        "run_id": "run_entities",
        "mutation_id": "mut_create",
        "entity_id": "ent-alpha",
        "domain": "systems",
        "title": "Portable initiative",
        "description": "Synthetic lifecycle fixture.",
    }
    values.update(overrides)
    return flow.create(caps, **values)


def _confirmation(text: str, identity: str, at: str) -> HumanConfirmation:
    return HumanConfirmation(identity, at, text)


def _tree_bytes(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file()
    }


def test_entity_lifecycle_steps_paths_schema_and_action_order(tmp_path):
    vault, _, store, _, caps, flow = _setup(tmp_path)
    _run(store)
    created = _create(flow, caps)
    assert created.entity.entity_id == "ent-alpha"
    assert created.entity.revision == 1
    path = vault / "agent/memory/entities/systems.json"
    assert path.is_file()
    payload = json.loads(path.read_bytes())
    assert set(payload) == {"schema_version", "domain", "revision", "entities"}
    assert payload["schema_version"] == 1
    assert payload["entities"][0]["id"].startswith("ent-")
    assert not (vault / "knowledge/systems/entities.json").exists()

    stepped = flow.add_step(
        caps,
        run_id="run_entities",
        mutation_id="mut_add_step",
        entity_id="ent-alpha",
        domain="systems",
        expected_revision=1,
        step=EntityStep("step_review", "Review the result."),
    )
    checked = flow.check_step(
        caps,
        run_id="run_entities",
        mutation_id="mut_check_step",
        entity_id="ent-alpha",
        domain="systems",
        expected_revision=2,
        step_id="step_review",
        checked_at="2026-01-02T09:00:00Z",
    )
    assert stepped.entity.steps[0].status == "open"
    assert checked.entity.steps[0].status == "done"
    assert checked.entity.steps[0].checked_at == "2026-01-02T09:00:00Z"
    assert store.status("run_entities")["status"] == "running"
    assert [
        action["action_id"]
        for action in store.trace_events("run_entities")[0]["actions"]
    ] == ["read-entity-state", "commit-entity-state", "record-run-state"]


def test_entity_mutations_are_revisioned_and_replay_conflicts_fail(tmp_path):
    _, _, store, _, caps, flow = _setup(tmp_path)
    _run(store)
    created = _create(flow, caps)
    replay = _create(flow, caps)
    assert replay.replayed is True
    assert replay.collection_sha256 == created.collection_sha256
    with pytest.raises(EntitiesFlowError, match="conflict"):
        _create(flow, caps, title="Different replay")
    with pytest.raises(EntitiesFlowError, match="stale"):
        flow.update(
            caps,
            run_id="run_entities",
            mutation_id="mut_stale",
            entity_id="ent-alpha",
            domain="systems",
            expected_revision=2,
            title="Stale update",
        )


def test_all_typed_policy_mutations_and_terminal_independence(tmp_path):
    vault, _, store, _, caps, flow = _setup(tmp_path)
    _run(store)
    result = _create(flow, caps)
    result = flow.set_deadline(
        caps,
        run_id="run_entities",
        mutation_id="mut_deadline",
        entity_id="ent-alpha",
        domain="systems",
        expected_revision=result.entity.revision,
        deadline="2026-01-10",
    )
    result = flow.set_next_review(
        caps,
        run_id="run_entities",
        mutation_id="mut_review",
        entity_id="ent-alpha",
        domain="systems",
        expected_revision=result.entity.revision,
        next_review_at="2026-01-11T00:00:00Z",
    )
    result = flow.set_next_check(
        caps,
        run_id="run_entities",
        mutation_id="mut_check",
        entity_id="ent-alpha",
        domain="systems",
        expected_revision=result.entity.revision,
        next_check=NextCheckPolicy("after-update", interval_days=3),
    )
    result = flow.pause_escalation(
        caps,
        run_id="run_entities",
        mutation_id="mut_pause",
        entity_id="ent-alpha",
        domain="systems",
        expected_revision=result.entity.revision,
        until="2026-01-20T00:00:00Z",
    )
    closed = flow.close(
        caps,
        run_id="run_entities",
        mutation_id="mut_close",
        entity_id="ent-alpha",
        domain="systems",
        expected_revision=result.entity.revision,
        closed_at="2026-01-21T00:00:00Z",
    )
    assert closed.entity.status == "closed"
    assert not (vault / "agent/logs/done-events/events.jsonl").exists()


def test_stale_boundary_matrix_has_explicit_as_of_threshold_and_pause(tmp_path):
    _, _, store, _, caps, flow = _setup(tmp_path)
    _run(store)
    result = _create(
        flow,
        caps,
        deadline="2026-01-10",
        next_review_at="2026-01-11T00:00:00Z",
        next_check=NextCheckPolicy("at", "2026-01-12T00:00:00Z"),
    )
    result = flow.pause_escalation(
        caps,
        run_id="run_entities",
        mutation_id="mut_pause",
        entity_id="ent-alpha",
        domain="systems",
        expected_revision=result.entity.revision,
        until="2026-01-20T00:00:00Z",
    )
    assert flow.stale(
        caps.read_entity_state,
        StaleQuery("2026-01-19T23:59:59Z", 5),
    ) == ()
    boundary = flow.stale(
        caps.read_entity_state,
        StaleQuery("2026-01-20T00:00:00Z", 5),
    )
    assert len(boundary) == 1
    assert boundary[0].reasons == ("deadline", "review", "check", "inactivity")
    with pytest.raises(EntitiesFlowError, match="threshold_days"):
        flow.stale(caps.read_entity_state, StaleQuery("2026-01-20T00:00:00Z", 0))


def test_speculative_text_never_writes_done_and_confirmed_created_is_exact_once(tmp_path):
    vault, _, store, _, caps, flow = _setup(tmp_path)
    _run(store)
    before = _tree_bytes(vault)
    with pytest.raises(EntitiesFlowError, match="exactly equal"):
        flow.create_done(
            caps,
            run_id="run_entities",
            event_id="done-alpha",
            summary="Maybe this happened.",
            occurred_at="2026-01-02T10:00:00Z",
            recorded_at="2026-01-02T10:01:00Z",
            confirmation=_confirmation(
                "This definitely happened.", "confirm_alpha", "2026-01-02T10:00:30Z"
            ),
        )
    assert _tree_bytes(vault) == before

    event = flow.create_done(
        caps,
        run_id="run_entities",
        event_id="done-alpha",
        summary="The synthetic outcome happened.",
        occurred_at="2026-01-02T10:00:00Z",
        recorded_at="2026-01-02T10:01:00Z",
        confirmation=_confirmation(
            "The synthetic outcome happened.", "confirm_alpha", "2026-01-02T10:00:30Z"
        ),
        followup_due_at="2026-01-05T00:00:00Z",
    )
    assert event.event_id.startswith("done-")
    assert flow.append_done_event(caps, run_id="run_entities", event=event) == event
    lines = (vault / "agent/logs/done-events/events.jsonl").read_text().splitlines()
    assert len(lines) == 1
    assert not (vault / "agent/logs/done-events.jsonl").exists()
    conflict = DoneEventRecord(
        **{**event.__dict__, "summary": "Different replay."}
    )
    with pytest.raises(EntitiesFlowError):
        flow.append_done_event(caps, run_id="run_entities", event=conflict)


def test_followup_requires_sent_before_answer_and_projection_reconciles(tmp_path):
    _, _, store, _, caps, flow = _setup(tmp_path)
    _run(store)
    flow.create_done(
        caps,
        run_id="run_entities",
        event_id="done-root",
        summary="A confirmed outcome.",
        occurred_at="2026-01-02T10:00:00Z",
        recorded_at="2026-01-02T10:01:00Z",
        confirmation=_confirmation("A confirmed outcome.", "confirm_root", "2026-01-02T10:00:30Z"),
        followup_due_at="2026-01-05T00:00:00Z",
    )
    assert [item.state for item in flow.followup_signals(
        caps.read_done_events, as_of="2026-01-05T00:00:00Z"
    )] == ["unsent"]
    with pytest.raises(EntitiesFlowError, match="sent event"):
        flow.record_followup_answered(
            caps,
            run_id="run_entities",
            event_id="done-answer-early",
            root_event_id="done-root",
            sent_event_id="done-missing",
            summary="An answer arrived.",
            confirmation=_confirmation("An answer arrived.", "confirm_early", "2026-01-06T09:00:00Z"),
            at="2026-01-06T09:00:00Z",
        )
    flow.record_followup_sent(
        caps,
        run_id="run_entities",
        event_id="done-sent",
        root_event_id="done-root",
        summary="Followup sent.",
        confirmation=_confirmation("Followup sent.", "confirm_sent", "2026-01-06T10:00:00Z"),
        at="2026-01-06T10:00:00Z",
    )
    signals = flow.followup_signals(
        caps.read_done_events, as_of="2026-01-06T10:00:00Z"
    )
    assert [(item.state, item.sent_event_id) for item in signals] == [("pending", "done-sent")]
    flow.record_followup_answered(
        caps,
        run_id="run_entities",
        event_id="done-answer",
        root_event_id="done-root",
        sent_event_id="done-sent",
        summary="An answer arrived.",
        confirmation=_confirmation("An answer arrived.", "confirm_answer", "2026-01-07T10:00:00Z"),
        at="2026-01-07T10:00:00Z",
    )
    assert flow.followup_signals(
        caps.read_done_events, as_of="2026-01-07T10:00:00Z"
    ) == ()


def test_trail_fk_dedupe_consecutive_silent_and_no_entity_transition(tmp_path):
    vault, _, store, _, caps, flow = _setup(tmp_path)
    _run(store)
    _create(flow, caps)
    first = TrailEvent("trail-ping", "ent-alpha", "ping", "2026-01-02T09:00:00Z")
    silent_one = TrailEvent("trail-silent-1", "ent-alpha", "silent", "2026-01-02T10:00:00Z")
    silent_two = TrailEvent("trail-silent-2", "ent-alpha", "silent", "2026-01-02T11:00:00Z")
    for event in (first, silent_one, silent_two):
        flow.append_trail(caps, run_id="run_entities", event=event)
    flow.append_trail(caps, run_id="run_entities", event=silent_two)
    assert flow.consecutive_silent(caps.read_trail_events, "ent-alpha") == 2
    assert len((vault / "agent/memory/trails/ent-alpha.jsonl").read_text().splitlines()) == 3
    assert flow.status(caps.read_entity_state, "ent-alpha").status == "active"
    with pytest.raises(EntitiesFlowError, match="does not exist"):
        flow.append_trail(
            caps,
            run_id="run_entities",
            event=TrailEvent("trail-orphan", "ent-missing", "ping", "2026-01-02T12:00:00Z"),
        )


def test_retry_before_entity_replace_and_after_trail_append(tmp_path, monkeypatch):
    _, _, store, _, caps, flow = _setup(tmp_path)
    _run(store)
    before_calls = 0

    def fail_entity_once():
        nonlocal before_calls
        before_calls += 1
        if before_calls == 1:
            raise RuntimeError("injected replace boundary")

    monkeypatch.setattr(flow, "_before_entity_replace", fail_entity_once)
    with pytest.raises(RuntimeError, match="injected"):
        _create(flow, caps)
    result = _create(flow, caps)
    assert result.entity.entity_id == "ent-alpha"

    after_calls = 0

    def fail_trail_once(kind):
        nonlocal after_calls
        if kind == "trail":
            after_calls += 1
            if after_calls == 1:
                raise RuntimeError("injected append boundary")

    monkeypatch.setattr(flow, "_after_domain_change", fail_trail_once)
    event = TrailEvent("trail-retry", "ent-alpha", "silent", "2026-01-03T09:00:00Z")
    with pytest.raises(RuntimeError, match="injected"):
        flow.append_trail(caps, run_id="run_entities", event=event)
    assert flow.append_trail(caps, run_id="run_entities", event=event) == event
    assert len(flow.list_trails(caps.read_trail_events, "ent-alpha")) == 1


def test_run_step_ids_are_namespaced_without_changing_public_ids(tmp_path):
    vault, _, store, _, caps, flow = _setup(tmp_path)
    _run(store)
    created = _create(flow, caps, mutation_id="done-collision")
    done = flow.create_done(
        caps,
        run_id="run_entities",
        event_id="done-collision",
        summary="Same public token in another operation family.",
        occurred_at="2026-01-03T09:00:00Z",
        recorded_at="2026-01-03T09:01:00Z",
        confirmation=_confirmation(
            "Same public token in another operation family.",
            "confirm_collision",
            "2026-01-03T09:00:30Z",
        ),
    )
    assert _create(flow, caps, mutation_id="done-collision").replayed is True
    assert flow.append_done_event(caps, run_id="run_entities", event=done) == done
    updated = flow.update(
        caps,
        run_id="run_entities",
        mutation_id="trail-collision",
        entity_id="ent-alpha",
        domain="systems",
        expected_revision=1,
        title="Updated before the trail collision.",
    )
    trail = TrailEvent(
        "trail-collision", "ent-alpha", "ping", "2026-01-03T10:00:00Z"
    )
    flow.append_trail(caps, run_id="run_entities", event=trail)

    assert created.entity.last_mutation_id == done.event_id == "done-collision"
    assert updated.entity.last_mutation_id == trail.event_id == "trail-collision"
    assert flow.append_trail(caps, run_id="run_entities", event=trail) == trail
    assert len((vault / "agent/logs/done-events/events.jsonl").read_text().splitlines()) == 1
    assert len((vault / "agent/memory/trails/ent-alpha.jsonl").read_text().splitlines()) == 1
    step_ids = [event["step_id"] for event in store.trace_events("run_entities")]
    assert len(step_ids) == len(set(step_ids)) == 4
    assert sum(step_id.startswith("entity-") for step_id in step_ids) == 2
    assert sum(step_id.startswith("done-") for step_id in step_ids) == 1
    assert sum(step_id.startswith("trail-") for step_id in step_ids) == 1


def test_open_zone_revalidation_failures_do_not_leak_fds(tmp_path, monkeypatch):
    _, resolver, store, _, caps, flow = _setup(tmp_path)
    _run(store)
    _create(flow, caps)
    real_revalidate = resolver.revalidate

    def fail_entity_zone(path, symbolic, *parts, **kwargs):
        if symbolic == "agent/memory/entities":
            raise VaultSchemaError("injected revalidation failure")
        return real_revalidate(path, symbolic, *parts, **kwargs)

    monkeypatch.setattr(resolver, "revalidate", fail_entity_zone)
    before = len(os.listdir("/dev/fd"))
    for _ in range(40):
        with pytest.raises(EntitiesFlowError, match="changed during operation"):
            flow.list_entities(caps.read_entity_state)
    after = len(os.listdir("/dev/fd"))
    assert after - before == 0


def test_entity_publish_rejects_substituted_inode_and_exact_retry_recovers(
    tmp_path, monkeypatch
):
    vault, _, store, _, caps, flow = _setup(tmp_path)
    _run(store)
    real_replace = entities_module.os.replace
    substituted = False

    def replace_with_same_bytes_on_new_inode(source, target, *args, **kwargs):
        nonlocal substituted
        real_replace(source, target, *args, **kwargs)
        if target != "systems.json" or substituted:
            return
        substituted = True
        directory_fd = kwargs["dst_dir_fd"]
        source_fd = os.open(target, os.O_RDONLY, dir_fd=directory_fd)
        try:
            data = os.read(source_fd, 1_048_577)
        finally:
            os.close(source_fd)
        replacement = ".systems.json.substituted"
        replacement_fd = os.open(
            replacement,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
            dir_fd=directory_fd,
        )
        try:
            assert os.write(replacement_fd, data) == len(data)
            os.fsync(replacement_fd)
        finally:
            os.close(replacement_fd)
        real_replace(
            replacement,
            target,
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
        )

    monkeypatch.setattr(entities_module.os, "replace", replace_with_same_bytes_on_new_inode)
    with pytest.raises(EntitiesFlowError, match="changed during publish"):
        _create(flow, caps)
    result = _create(flow, caps)
    assert result.replayed is True
    assert result.entity.entity_id == "ent-alpha"
    assert json.loads((vault / "agent/memory/entities/systems.json").read_bytes())[
        "entities"
    ][0]["id"] == "ent-alpha"
    assert len(store.trace_events("run_entities")) == 1


def test_pure_legacy_list_migration_splits_embedded_trails(tmp_path):
    source = json.dumps(
        [
            {
                "id": "ent-legacy",
                "name": "Legacy fixture",
                "domain": "systems",
                "status": "active",
                "created": "2026-01-01",
                "updated_at": "2026-01-02",
                "priority": 2,
                "steps": [{"text": "Inspect migration", "done": False}],
                "trail": [
                    {"at": "2026-01-01T10:00:00Z", "kind": "created", "note": "Created."},
                    {"at": "2026-01-02T10:00:00Z", "kind": "silent", "note": "No answer."},
                ],
            }
        ]
    ).encode()
    before = _tree_bytes(tmp_path)
    first = migrate_legacy_entities(source, domain="systems")
    second = migrate_legacy_entities(source, domain="systems")
    assert first == second
    assert first.collection.entities[0].steps[0].status == "open"
    assert [item.action for item in first.trails[0][1]] == ["ping", "silent"]
    assert b'"trail"' not in first.collection_bytes
    assert first.trail_files[0][0] == "ent-legacy.jsonl"
    assert _tree_bytes(tmp_path) == before


@pytest.mark.parametrize(
    "payload,error",
    [
        ([{"id": "ent-legacy", "name": "Legacy", "status": []}], "status"),
        (
            [
                {
                    "id": "ent-legacy",
                    "name": "Legacy",
                    "created": "2026-01-01",
                    "trail": [{"at": "2026-01-01T10:00:00Z", "action": []}],
                }
            ],
            "trail action",
        ),
    ],
)
def test_malformed_legacy_membership_types_raise_entities_error(payload, error):
    source = json.dumps(payload, separators=(",", ":")).encode()
    with pytest.raises(EntitiesFlowError, match=error) as caught:
        migrate_legacy_entities(source, domain="systems")
    assert type(caught.value) is EntitiesFlowError


def test_whole_vault_preserves_tasks_knowledge_and_legacy_paths(tmp_path):
    vault, _, store, _, caps, flow = _setup(tmp_path)
    legacy = vault / "legacy/entities.json"
    legacy.parent.mkdir()
    legacy.write_text('[{"id":"ent-old"}]\n')
    before = {
        key: value
        for key, value in _tree_bytes(vault).items()
        if key.startswith(("tasks/", "knowledge/", "legacy/"))
    }
    _run(store)
    _create(flow, caps)
    flow.create_done(
        caps,
        run_id="run_entities",
        event_id="done-independent",
        summary="Independent result.",
        occurred_at="2026-01-03T09:00:00Z",
        recorded_at="2026-01-03T09:01:00Z",
        confirmation=_confirmation("Independent result.", "confirm_independent", "2026-01-03T09:00:30Z"),
    )
    flow.append_trail(
        caps,
        run_id="run_entities",
        event=TrailEvent("trail-independent", "ent-alpha", "done", "2026-01-03T10:00:00Z"),
    )
    after = {
        key: value
        for key, value in _tree_bytes(vault).items()
        if key.startswith(("tasks/", "knowledge/", "legacy/"))
    }
    assert after == before


def test_strict_types_text_size_schema_and_capability_fail_before_domain_write(tmp_path):
    vault, _, store, _, caps, flow = _setup(tmp_path)
    _run(store)
    with pytest.raises(EntitiesFlowError, match="bounded text"):
        _create(flow, caps, title="x" * 513)
    with pytest.raises(EntitiesFlowError, match="after-update"):
        _create(
            flow,
            caps,
            mutation_id="mut_bad_check",
            next_check=NextCheckPolicy("after-update", interval_days=0),
        )
    wrong_caps = EntitiesCapabilities(
        caps.read_entity_state,
        caps.read_done_events,
        caps.read_trail_events,
        caps.append_entity_trail,
        caps.append_confirmed_done_event,
        caps.append_entity_trail,
        caps.record_run_state,
    )
    with pytest.raises(EntitiesFlowError, match="commit-entity-state"):
        _create(flow, wrong_caps, mutation_id="mut_wrong_cap")
    assert not (vault / "agent/memory/entities/systems.json").exists()

    entities = vault / "agent/memory/entities"
    entities.mkdir()
    (entities / "systems.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "domain": "systems",
                "revision": 0,
                "entities": [],
                "unknown": True,
            },
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    )
    with pytest.raises(EntitiesFlowError, match="unknown fields"):
        flow.list_entities(caps.read_entity_state)


def test_done_and_trail_trace_records_exact_capability_order(tmp_path):
    _, _, store, _, caps, flow = _setup(tmp_path)
    _run(store)
    _create(flow, caps)
    flow.create_done(
        caps,
        run_id="run_entities",
        event_id="done-actions",
        summary="Action evidence recorded.",
        occurred_at="2026-01-03T09:00:00Z",
        recorded_at="2026-01-03T09:01:00Z",
        confirmation=_confirmation(
            "Action evidence recorded.", "confirm_actions", "2026-01-03T09:00:30Z"
        ),
    )
    flow.append_trail(
        caps,
        run_id="run_entities",
        event=TrailEvent("trail-actions", "ent-alpha", "skip", "2026-01-03T10:00:00Z"),
    )
    traces = store.trace_events("run_entities")
    done_trace = next(
        event for event in traces if event["actions"][0]["action_id"] == "read-done-events"
    )
    trail_trace = next(
        event
        for event in traces
        if event["actions"][0]["action_id"] == "read-entity-state"
        and len(event["actions"]) == 4
    )
    assert done_trace["step_id"].startswith("done-")
    assert trail_trace["step_id"].startswith("trail-")
    assert done_trace["step_id"] != trail_trace["step_id"]
    assert [item["action_id"] for item in done_trace["actions"]] == [
        "read-done-events",
        "append-confirmed-done-event",
        "record-run-state",
    ]
    assert [item["action_id"] for item in trail_trace["actions"]] == [
        "read-entity-state",
        "read-trail-events",
        "append-entity-trail",
        "record-run-state",
    ]
    assert all(
        item["matrix_sha256"] == caps.record_run_state.matrix_sha256
        for event in traces
        for item in event["actions"]
    )
