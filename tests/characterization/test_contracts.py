"""Hermetic P0-04 characterization and mutation sensitivity matrix."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from tests.characterization.contracts import (
    CASES,
    KNOWN_LEGACY_FAILURES,
    UNRESOLVED_LEGACY_DRIFT,
    validate_case,
)
from tests.characterization.observations import (
    OBSERVERS,
    ObservationInput,
    comparison_failures,
)


POPULATED = Path(__file__).parents[1] / "fixtures" / "vault-populated"
GOLDEN_PATH = Path(__file__).with_name("golden_observations.json")

MUTATION_RULES = {
    "review_apply": "effect.apply-marker-removed",
    "project_transitions": "artifact.project-archive-location",
    "task_rollover": "trajectory.snapshot-before-replace",
    "entity_done_trails": "artifact.identifier-namespaces-distinct",
    "reading": "effect.reading-state-removed",
    "surface": "side-effect.surface-silent-no-transport",
    "finalize": "trajectory.validation-before-success",
}


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload) + "\n", "utf-8")


def _write_jsonl(path: Path, payloads: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(item) + "\n" for item in payloads), "utf-8")


def _golden() -> dict[str, dict[str, Any]]:
    return json.loads(GOLDEN_PATH.read_text("utf-8"))["observations"]


def _materialize_observation(group: str, root: Path, mutated: bool) -> ObservationInput:
    source = ObservationInput(root=root)
    if group == "review_apply":
        archived = root / "_trash" / source.review_name
        archived.parent.mkdir(parents=True)
        archived.write_text("# Synthetic applied review\n", "utf-8")
        if mutated:
            _write_json(
                root / "agent/_buffer/apply-in-progress/rev_fixture.json",
                {"review": f"review/{source.review_name}"},
            )
    elif group == "project_transitions":
        project_dir = (
            root / f"projects/{source.slug}"
            if mutated
            else root / f"projects/_archive/{source.slug}-2026-01-15"
        )
        _write_json(project_dir / "project.json", {"status": "archived"})
        _write_json(
            project_dir / "research/portable-engine/project.json",
            {"status": "archived"},
        )
        _write_json(
            root / "agent/schedule/portable-schedule.json",
            {"status": "paused"},
        )
    elif group == "task_rollover":
        preimage = "---\ndate: 2026-01-15\n---\n- [ ] Synthetic prior task\n"
        (root / "preimage.md").parent.mkdir(parents=True, exist_ok=True)
        (root / "preimage.md").write_text(preimage, "utf-8")
        snapshot = root / "agent/logs/tasks/2026-01-15.md"
        snapshot.parent.mkdir(parents=True)
        snapshot.write_text(preimage, "utf-8")
        trace = [{"event": "snapshot"}, {"event": "replace"}]
        if mutated:
            trace.reverse()
        _write_jsonl(root / "trace.jsonl", trace)
    elif group == "entity_done_trails":
        _write_json(
            root / "agent/memory/entities/ai.json",
            [{"id": source.entity_id, "name": "Synthetic initiative"}],
        )
        _write_jsonl(
            root / "agent/logs/done-events.jsonl",
            [{"id": source.entity_id if mutated else "done-001", "status": "active"}],
        )
        _write_jsonl(
            root / f"agent/memory/trails/{source.entity_id}.jsonl",
            [{"action": "ping"}, {"action": "silent"}],
        )
    elif group == "reading":
        log = root / f"agent/reading/{source.reading_slug}-log.md"
        log.parent.mkdir(parents=True)
        log.write_text("# Reading log\n\nclosed: finished\n", "utf-8")
        if mutated:
            _write_json(
                root / f"agent/reading/{source.reading_slug}.json",
                {"slug": source.reading_slug},
            )
    elif group == "surface":
        _write_jsonl(
            root / "trace.jsonl",
            [
                {"surface": "silent", "action": "send" if mutated else "suppress"},
                {"surface": "gated", "action": "send"},
            ],
        )
    elif group == "finalize":
        first = [
            {"attempt": 1, "event": "validate"},
            {"attempt": 1, "event": "metrics"},
            {"attempt": 1, "event": "success"},
        ]
        if mutated:
            first = [first[2], first[0], first[1]]
        _write_jsonl(
            root / "trace.jsonl",
            first
            + [
                {"attempt": 2, "event": "validate"},
                {"attempt": 2, "event": "metrics"},
                {"attempt": 2, "event": "success"},
            ],
        )
    else:
        raise AssertionError(f"unknown observation group: {group}")
    return source


@pytest.mark.parametrize("group", sorted(CASES))
def test_accepted_characterization_contract(group):
    case = CASES[group]
    assert validate_case(case) == set()
    assert case.artifacts
    assert case.trajectory
    assert case.authority
    assert case.allowed_writes
    assert case.forbidden_effects
    assert case.legacy_symbols
    for relative in case.fixture_evidence:
        assert (POPULATED / relative).is_file(), (group, relative)


@pytest.mark.parametrize("group", sorted(OBSERVERS))
def test_independent_observation_matches_captured_golden(group, tmp_path):
    source = _materialize_observation(group, tmp_path / group, mutated=False)
    actual = OBSERVERS[group](source)
    assert comparison_failures(group, actual, _golden()[group]) == set()


@pytest.mark.parametrize("group", sorted(OBSERVERS))
def test_targeted_input_mutation_sensitivity_matrix(group, tmp_path):
    source = _materialize_observation(group, tmp_path / group, mutated=True)
    actual = OBSERVERS[group](source)
    assert comparison_failures(group, actual, _golden()[group]) == {
        MUTATION_RULES[group]
    }


def test_golden_is_privacy_safe_and_names_capture_provenance():
    text = GOLDEN_PATH.read_text("utf-8")
    capture = json.loads(text)["capture"]
    assert capture["kind"] == "privacy-safe-exact-legacy-observations"
    assert "tmp-only" in capture["source"]
    assert "/Users/" not in text
    assert "@" not in text


def test_probabilistic_stages_encode_cohort_pass_k_without_model_execution():
    probabilistic = [case for case in CASES.values() if case.reliability is not None]
    assert {case.group for case in probabilistic} == {"review_apply", "surface"}
    for case in probabilistic:
        expectation = case.reliability
        assert expectation is not None
        assert expectation.models_executed is False
        assert expectation.cohort_size >= 10
        assert expectation.k >= 2
        assert expectation.assumed_single_pass**expectation.k >= expectation.minimum_pass_k


def test_four_known_legacy_failures_are_isolated_from_accepted_behavior():
    assert len(KNOWN_LEGACY_FAILURES) == 4
    assert sum(failure.expected_count for failure in KNOWN_LEGACY_FAILURES) == 4
    assert all(failure.accepted_behavior is False for failure in KNOWN_LEGACY_FAILURES)
    causes = [failure.cause_class for failure in KNOWN_LEGACY_FAILURES]
    assert causes.count("invalid-production-schedule") == 2
    assert causes.count("stale-test-expectation") == 1
    assert causes.count("time-window-expired") == 1


def test_fresh_unresolved_legacy_drift_is_not_mislabeled_as_accepted_or_known():
    known = {failure.failure_id for failure in KNOWN_LEGACY_FAILURES}
    assert len(UNRESOLVED_LEGACY_DRIFT) == 1
    drift = UNRESOLVED_LEGACY_DRIFT[0]
    assert drift.failure_id == "test_f130_system_audit_json_format"
    assert drift.cause_class == "read-only-side-effect-coupling"
    assert drift.accepted_behavior is False
    assert drift.failure_id not in known


def test_observable_fixture_artifacts_have_expected_machine_shapes():
    review_plan = json.loads(
        (POPULATED / ".lifeos/review-plans/rev_fixture-001.json").read_text("utf-8")
    )
    project_state = json.loads(
        (POPULATED / "projects/portable-fixture/state.json").read_text("utf-8")
    )
    reading = json.loads(
        (POPULATED / "agent/reading/portable-handbook.json").read_text("utf-8")
    )
    outbox = json.loads(
        (POPULATED / "agent/outbox/event_fixture-001.json").read_text("utf-8")
    )
    run_state = json.loads(
        (POPULATED / "agent/runs/run_fixture-001/state.json").read_text("utf-8")
    )

    operation = review_plan["operations"][0]
    assert operation["precondition_sha256"] != operation["postcondition_sha256"]
    assert {"next_steps", "blockers", "open_questions", "last_session"} <= set(project_state)
    assert isinstance(reading["anchors"], list)
    assert reading["log_path"].startswith("agent/reading/")
    assert outbox["delivery_policy"]["surface"] in {"silent", "batched", "gated"}
    assert run_state["authority"] == "proposal"
