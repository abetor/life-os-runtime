"""Machine acceptance for the technical Gate P3 evidence."""

from __future__ import annotations

import ast
from dataclasses import replace
import hashlib
import importlib
import json
from pathlib import Path

import pytest

from tool_life_os_runtime.ext.gates.p3 import (
    P3_FLOW_IDS,
    P3GateRegistryError,
    canonical_p3_registry,
    validate_p3_registry,
)
from tool_life_os_runtime.ext.skills import CANONICAL_SKILL_IDS, canonical_skills
from tool_life_os_runtime.failure_authority import canonical_matrix


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "tests/fixtures/migration-manifest.json"
EXPECTED_EXECUTABLE_GAPS = {
    "ingest",
    "apply",
    "ask",
    "research",
    "engine",
    "project",
}


def _legacy_skill_ref(skill_id: str) -> str:
    relative = f".claude/skills/{skill_id}/SKILL.md"
    return "source:sha256:" + hashlib.sha256(relative.encode("utf-8")).hexdigest()


def test_sanitized_manifest_accepts_all_15_skill_targets() -> None:
    manifest = json.loads(MANIFEST.read_text("utf-8"))
    reconciliation = manifest["reconciliation"]
    assert reconciliation["ok"] is True
    assert reconciliation["source_count"] == 15
    assert reconciliation["duplicates"] == []
    assert reconciliation["unclassified"] == []
    assert manifest["counts"]["inventory_entities"]["active_skills"] == 15

    by_ref: dict[str, list[dict[str, object]]] = {}
    for record in manifest["records"]:
        by_ref.setdefault(record["source_ref"], []).append(record)
    assert tuple(skill.skill_id for skill in canonical_skills()) == CANONICAL_SKILL_IDS
    for skill_id in CANONICAL_SKILL_IDS:
        matches = by_ref.get(_legacy_skill_ref(skill_id), [])
        assert len(matches) == 1, skill_id
        assert {key: matches[0][key] for key in ("kind", "target", "outcome")} == {
            "kind": "skill",
            "target": "runtime",
            "outcome": "runtime-capability",
        }


def test_skill_catalog_reports_exact_remaining_executable_gaps() -> None:
    skills = canonical_skills()
    assert {
        skill.skill_id for skill in skills if skill.integration_required
    } == EXPECTED_EXECUTABLE_GAPS
    assert all(
        (skill.status == "available") == (not skill.integration_requirements)
        for skill in skills
    )


def _test_functions(path: Path) -> frozenset[str]:
    tree = ast.parse(path.read_text("utf-8"), filename=str(path))
    return frozenset(
        node.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name.startswith("test_")
    )


def _resolve_public_inspector(reference: str) -> object:
    module_name, attribute = reference.rsplit(".", 1)
    module = importlib.import_module(module_name)
    return getattr(module, attribute)


def test_registry_exactly_binds_authority_state_failure_and_acceptance() -> None:
    records = canonical_p3_registry()
    matrix = {flow["flow_id"]: flow for flow in canonical_matrix()["flows"]}

    assert tuple(record.flow_id for record in records) == P3_FLOW_IDS
    assert len(records) == len(set(P3_FLOW_IDS)) == 13
    assert {
        record.flow_id for record in records if record.integration_status != "accepted"
    } == {
        "ingest",
        "project",
    }
    for record in records:
        flow = matrix[record.flow_id]
        assert record.authority_ceiling == flow["authority_ceiling"]
        assert record.action_ids == tuple(
            action["action_id"] for action in flow["actions"]
        )
        assert record.state.carrier
        assert record.state.producer_statuses
        assert record.state.finalized_statuses
        assert record.state.replay_key
        assert callable(_resolve_public_inspector(record.inspector))
        for node in (*record.acceptance_test_nodes, *record.failure_test_nodes):
            relative, function_name = node.split("::", 1)
            path = ROOT / relative
            assert path.is_file(), node
            assert function_name in _test_functions(path), node


def test_registry_rejects_missing_flow_authority_and_coverage_drift() -> None:
    records = canonical_p3_registry()
    with pytest.raises(P3GateRegistryError, match="flow contract is invalid"):
        validate_p3_registry([object()])  # type: ignore[list-item]
    with pytest.raises(P3GateRegistryError, match="inspector reference is invalid"):
        validate_p3_registry(
            (replace(records[0], inspector=object()), *records[1:])  # type: ignore[arg-type]
        )
    with pytest.raises(P3GateRegistryError, match="integration status is invalid"):
        validate_p3_registry(
            (
                replace(records[0], integration_status=[]),  # type: ignore[arg-type]
                *records[1:],
            )
        )
    with pytest.raises(P3GateRegistryError, match="exact ordered"):
        validate_p3_registry(records[:-1])
    with pytest.raises(P3GateRegistryError, match="authority binding"):
        validate_p3_registry(
            (replace(records[0], authority_ceiling="protected-write"), *records[1:])
        )
    with pytest.raises(P3GateRegistryError, match="non-empty tuple"):
        validate_p3_registry(
            (
                replace(records[0], acceptance_test_nodes=()),
                *records[1:],
            )
        )
    with pytest.raises(P3GateRegistryError, match="coverage binding"):
        validate_p3_registry(
            (
                replace(
                    records[0],
                    state=replace(records[0].state, replay_key="different-key"),
                ),
                *records[1:],
            )
        )
    with pytest.raises(P3GateRegistryError, match="coverage binding"):
        validate_p3_registry(
            (
                replace(
                    records[0],
                    acceptance_test_nodes=(records[0].failure_test_nodes[0],),
                ),
                *records[1:],
            )
        )


def test_human_behavior_acceptance_remains_an_external_gate() -> None:
    """Technical evidence cannot manufacture the literal human sign-off."""

    assert not hasattr(
        importlib.import_module("tool_life_os_runtime.ext.gates.p3.registry"),
        "human_behavior_accepted",
    )
