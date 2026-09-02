from __future__ import annotations

from dataclasses import fields, replace

import pytest

from tool_life_os_runtime.ext.skills import (
    CANONICAL_SKILL_IDS,
    EvalObservation,
    EvalResult,
    EvalResultIdentity,
    EvolutionProposal,
    SkillPackError,
    SteeringRetirementProposal,
    SteeringScaffold,
    ambiguity_pairs,
    canonical_resource,
    canonical_skills,
    check_skill_pack,
    evaluate_evolution_proposal,
    evaluate_routing,
    evaluate_steering_retirement,
    model_role_profile,
    routing_eval_cases,
    skill_eval_contract,
    validate_canonical_skill,
    validate_skill_pack,
)
from tool_life_os_runtime.ext.skills.resources.model import ModelRole
from tool_life_os_runtime.failure_authority import canonical_matrix


def test_inventory_is_exact_ordered_and_health_matches_installer_surface() -> None:
    skills = canonical_skills()

    assert tuple(skill.skill_id for skill in skills) == CANONICAL_SKILL_IDS
    assert len(skills) == 15
    assert len({skill.resource_id for skill in skills}) == 15
    assert len({skill.sha256 for skill in skills}) == 15
    assert check_skill_pack() == replace(
        check_skill_pack(), ok=True, skill_count=15, wrapper_count=30, issues=()
    )
    assert validate_skill_pack(skills, expected_ids=CANONICAL_SKILL_IDS) == skills


def test_resources_derive_exact_ordered_actions_and_artifacts_from_public_matrix() -> (
    None
):
    matrix = {flow["flow_id"]: flow for flow in canonical_matrix()["flows"]}

    for skill in canonical_skills():
        public_actions = matrix[skill.flow_id]["actions"]
        assert skill.action_ids == tuple(
            action["action_id"] for action in public_actions
        )
        assert [
            (
                action.action_id,
                action.actor,
                action.authority,
                action.access,
                action.target,
                action.effect_kind,
                action.artifact_commit,
                action.irreversible,
                action.crash_points,
                action.retry_owner,
                action.rollback,
            )
            for action in skill.actions
        ] == [
            (
                action["action_id"],
                action["actor"],
                action["authority"],
                action["access"],
                action["target"],
                action["effect_kind"],
                action["artifact_commit"],
                action["irreversible"],
                tuple(action["crash_points"]),
                action["retry_owner"],
                action["rollback"],
            )
            for action in public_actions
        ]
        assert tuple(
            commit.action_id for commit in skill.artifact_contract.commits
        ) == tuple(
            action["action_id"]
            for action in public_actions
            if action["artifact_commit"]
        )


def test_incomplete_surfaces_have_exact_typed_integration_requirements() -> None:
    required = {
        "ingest": ("flow-trajectory", "runtime-flow:ingest"),
        "apply": ("flow-trajectory", "runtime-flow:apply"),
        "ask": ("flow-trajectory", "runtime-flow:ask"),
        "research": ("connector-route", "connector:researcher"),
        "engine": ("connector-route", "connector:researcher"),
        "project": ("flow-trajectory", "runtime-flow:project"),
    }
    assert {
        skill.skill_id for skill in canonical_skills() if skill.integration_required
    } == set(required)
    for skill_id, expected in required.items():
        skill = canonical_resource(skill_id)
        assert skill.status == "integration_required"
        assert len(skill.integration_requirements) == 1
        requirement = skill.integration_requirements[0]
        assert (requirement.requirement_type, requirement.target) == expected
        assert requirement.action_ids
        assert set(requirement.action_ids) <= set(skill.action_ids)
        assert requirement.target in skill.body


def test_research_surfaces_are_connector_routes_without_legacy_fallback() -> None:
    for skill_id in ("research", "engine"):
        skill = canonical_resource(skill_id)
        assert skill.integration_required is True
        assert skill.integration_target == "connector:researcher"
        assert "connector:researcher" in skill.body
        assert "legacy" in skill.body.lower()
        assert "legacy code" not in skill.body.lower()

    assert {
        skill.skill_id for skill in canonical_skills() if skill.status == "available"
    } == {
        "plan",
        "book",
        "mentor",
        "report",
        "lint",
        "ambient",
        "bundle",
        "grill-me",
        "obsidian",
    }


def test_resources_are_bounded_versioned_and_privacy_safe() -> None:
    for skill in canonical_skills():
        assert skill.schema_version == 1
        assert skill.routing.schema_version == 1
        assert skill.context.schema_version == 1
        assert skill.artifact_contract.schema_version == 1
        assert 0 < len(skill.description) <= 240
        assert 0 < len(skill.body) <= 4_096
        assert 0 < skill.context.max_files <= 32
        assert 0 < skill.context.max_bytes <= 262_144
        assert 0 < skill.context.max_items <= 64
        public = "\n".join(
            (
                skill.description,
                skill.body,
                *skill.routing.choose_when,
                *skill.routing.reject_when,
            )
        )
        assert "/" + "Users" + "/" not in public
        assert "/" + "home" + "/" not in public
        assert "file:" not in public


@pytest.mark.parametrize(
    ("mutation", "match"),
    [
        (
            lambda skill: replace(skill, body="private /" + "Users" + "/person/note"),
            "private",
        ),
        (lambda skill: replace(skill, body="bad\ud800text"), "surrogate"),
        (
            lambda skill: replace(
                skill,
                context=replace(skill.context, max_files=True),
            ),
            "integer",
        ),
        (
            lambda skill: replace(skill, actions=(skill.actions[0], skill.actions[0])),
            "duplicates",
        ),
    ],
)
def test_resource_validation_rejects_privacy_surrogate_type_and_duplicates(
    mutation, match: str
) -> None:
    with pytest.raises(SkillPackError, match=match):
        validate_canonical_skill(mutation(canonical_resource("ingest")))


def test_pack_validation_rejects_duplicate_skill_identity() -> None:
    skills = canonical_skills()
    with pytest.raises(SkillPackError, match="duplicate"):
        validate_skill_pack((*skills, skills[0]))


def test_model_role_profile_is_versioned_logical_and_has_no_literal_model_field() -> (
    None
):
    profile = model_role_profile()

    assert profile.schema_version == 1
    assert profile.model_family_id == "default-family/v1"
    assert profile.profile_id == "standard/v1"
    assert tuple(role.role_id for role in profile.roles) == (
        "cheap_collect",
        "reason",
        "synthesize",
        "critic",
    )
    assert "model" not in {field.name for field in fields(ModelRole)}
    assert all(
        role.max_input_bytes > 0 and role.max_output_chars > 0 for role in profile.roles
    )


def test_ambiguity_eval_has_symmetric_pairs_and_a_held_out_side() -> None:
    cases = routing_eval_cases()
    pairs = ambiguity_pairs()

    assert pairs
    assert all(
        any(
            case.held_out
            and set(pair) == {case.expected_skill_id, case.confounder_skill_id}
            for case in cases
        )
        for pair in pairs
    )
    assert all(
        right in canonical_resource(left).routing.ambiguity_with
        and left in canonical_resource(right).routing.ambiguity_with
        for left, right in pairs
    )
    report = evaluate_routing({case.case_id: case.expected_skill_id for case in cases})
    assert report.ok is True
    assert report.passed == report.total == len(cases)
    assert report.held_out_passed == report.held_out_total > 0


def test_routing_eval_reports_ambiguity_misroute_without_guessing() -> None:
    cases = routing_eval_cases()
    selections = {case.case_id: case.expected_skill_id for case in cases}
    selections[cases[0].case_id] = cases[0].confounder_skill_id

    report = evaluate_routing(selections)

    assert report.ok is False
    assert report.failures == (cases[0].case_id,)


def _identity(
    skill_id: str,
    *,
    base_sha256: str,
    candidate_sha256: str,
    model_family_id: str = "default-family/v1",
    profile_id: str = "standard/v1",
    scaffold: SteeringScaffold | None = None,
    scaffold_absent: bool = True,
    contract_sha256: str | None = None,
    case_ids: tuple[str, ...] | None = None,
) -> EvalResultIdentity:
    contract = skill_eval_contract(skill_id)
    return EvalResultIdentity(
        1,
        skill_id,
        contract.sha256 if contract_sha256 is None else contract_sha256,
        base_sha256,
        candidate_sha256,
        model_family_id,
        profile_id,
        contract.case_ids if case_ids is None else case_ids,
        scaffold_absent,
        None if scaffold is None else scaffold.sha256,
    )


def _eval_result(
    identity: EvalResultIdentity,
    *,
    regress: bool = False,
    improve: bool = True,
) -> EvalResult:
    contract = skill_eval_contract(identity.skill_id)
    cases = {case.case_id: case for case in routing_eval_cases()}
    observations = []
    for index, case_id in enumerate(contract.case_ids):
        case = cases.get(case_id)
        baseline = 1.0 if case is None else 0.7
        candidate = baseline
        passed = True
        if case is None and regress:
            candidate = 0.0
            passed = False
        elif case is not None and improve and index == 1:
            candidate = 0.8
        observations.append(
            EvalObservation(
                case_id,
                (
                    "regression"
                    if case is None
                    else "held_out"
                    if case.held_out
                    else "held_in"
                ),
                baseline,
                candidate,
                passed,
                identity.sha256,
            )
        )
    return EvalResult(1, identity, tuple(observations))


def _evolution_proposal(
    *,
    candidate_sha256: str = "a" * 64,
    base_sha256: str | None = None,
    result: EvalResult | None = None,
) -> EvolutionProposal:
    skill = canonical_resource("ask")
    base = skill.sha256 if base_sha256 is None else base_sha256
    if result is None:
        result = _eval_result(
            _identity(
                "ask",
                base_sha256=base,
                candidate_sha256=candidate_sha256,
            )
        )
    return EvolutionProposal(
        1,
        "evolution-ask-001",
        "ask",
        base,
        candidate_sha256,
        "Clarify routing for existing knowledge.",
        result,
    )


def test_evolution_requires_regression_and_held_out_evidence_before_approval() -> None:
    accepted = _evolution_proposal()
    assert evaluate_evolution_proposal(accepted).approved is True

    regressed = replace(
        accepted,
        eval_result=_eval_result(accepted.eval_result.identity, regress=True),
    )
    assert "regression" in evaluate_evolution_proposal(regressed).reasons
    stale_base = _evolution_proposal(base_sha256="b" * 64)
    assert evaluate_evolution_proposal(stale_base).reasons == (
        "stale-or-foreign-base-resource",
    )
    unchanged = _evolution_proposal(candidate_sha256=canonical_resource("ask").sha256)
    assert evaluate_evolution_proposal(unchanged).reasons == ("candidate-is-unchanged",)


def test_evolution_rejects_caller_invented_eval_identity_or_cohort() -> None:
    proposal = _evolution_proposal()
    invented = replace(
        proposal.eval_result,
        observations=(
            *proposal.observations,
            EvalObservation(
                "invented-held-out",
                "held_out",
                0.0,
                1.0,
                True,
                proposal.eval_result.identity.sha256,
            ),
        ),
    )
    with pytest.raises(SkillPackError, match="exact declared"):
        evaluate_evolution_proposal(replace(proposal, eval_result=invented))

    held_out_id = skill_eval_contract("ask").held_out_case_ids[0]
    mislabeled = replace(
        proposal.eval_result,
        observations=tuple(
            replace(observation, cohort="held_in")
            if observation.case_id == held_out_id
            else observation
            for observation in proposal.observations
        ),
    )
    with pytest.raises(SkillPackError, match="cohort"):
        evaluate_evolution_proposal(replace(proposal, eval_result=mislabeled))


def test_evolution_result_identity_rejects_reuse_omission_and_wrong_contract() -> None:
    proposal = _evolution_proposal()
    with pytest.raises(SkillPackError, match="proposal-bound"):
        evaluate_evolution_proposal(
            replace(proposal, candidate_resource_sha256="b" * 64)
        )

    held_in_id = next(
        observation.case_id
        for observation in proposal.observations
        if observation.cohort == "held_in"
    )
    omitted = replace(
        proposal.eval_result,
        observations=tuple(
            observation
            for observation in proposal.observations
            if observation.case_id != held_in_id
        ),
    )
    with pytest.raises(SkillPackError, match="exact declared"):
        evaluate_evolution_proposal(replace(proposal, eval_result=omitted))

    wrong_contract_identity = replace(
        proposal.eval_result.identity,
        eval_contract_sha256="b" * 64,
    )
    wrong_contract = replace(proposal.eval_result, identity=wrong_contract_identity)
    with pytest.raises(SkillPackError, match="contract hash"):
        evaluate_evolution_proposal(replace(proposal, eval_result=wrong_contract))


def test_evolution_observations_reject_cross_profile_or_family_rebinding() -> None:
    proposal = _evolution_proposal()
    for field_name, value in (
        ("model_family_id", "candidate-family/v1"),
        ("profile_id", "candidate-profile/v1"),
    ):
        rebound_identity = replace(
            proposal.eval_result.identity,
            **{field_name: value},
        )
        rebound_result = replace(proposal.eval_result, identity=rebound_identity)
        with pytest.raises(SkillPackError, match="another result identity"):
            evaluate_evolution_proposal(replace(proposal, eval_result=rebound_result))


@pytest.mark.parametrize(
    ("mutation", "match"),
    [
        (lambda identity: replace(identity, schema_version=True), "schema_version"),
        (
            lambda identity: replace(identity, model_family_id="bad\ud800family/v1"),
            "versioned symbolic",
        ),
        (
            lambda identity: replace(identity, profile_id="unversioned-profile"),
            "versioned symbolic",
        ),
        (
            lambda identity: replace(
                identity,
                case_ids=(*identity.case_ids, identity.case_ids[-1]),
            ),
            "case inventory",
        ),
        (
            lambda identity: replace(identity, scaffold_absent=1),
            "scaffold flag",
        ),
    ],
)
def test_eval_result_identity_rejects_bool_surrogate_profile_and_case_drift(
    mutation, match: str
) -> None:
    proposal = _evolution_proposal()
    identity = mutation(proposal.eval_result.identity)
    result = replace(proposal.eval_result, identity=identity)
    with pytest.raises(SkillPackError, match=match):
        evaluate_evolution_proposal(replace(proposal, eval_result=result))


def _retirement_proposal() -> SteeringRetirementProposal:
    skill = canonical_resource("ask")
    scaffold = SteeringScaffold(
        1,
        "steering-ask-001",
        "ask",
        "Temporary ambiguity clarification for one executor-profile generation.",
    )
    baseline_identity = _identity(
        "ask",
        base_sha256=skill.sha256,
        candidate_sha256=skill.sha256,
        model_family_id="baseline-family/v1",
        profile_id="baseline-profile/v1",
        scaffold=scaffold,
        scaffold_absent=False,
    )
    candidate_identity = _identity(
        "ask",
        base_sha256=skill.sha256,
        candidate_sha256=skill.sha256,
        model_family_id="candidate-family/v1",
        profile_id="candidate-profile/v1",
    )
    return SteeringRetirementProposal(
        1,
        "retire-steering-ask-001",
        scaffold,
        _eval_result(baseline_identity, improve=False),
        _eval_result(candidate_identity, improve=False),
    )


def test_steering_retirement_requires_no_regression_and_held_out_invariants() -> None:
    accepted = _retirement_proposal()
    assert evaluate_steering_retirement(accepted).approved is True

    regressed = replace(
        accepted,
        candidate_result=_eval_result(
            accepted.candidate_result.identity,
            regress=True,
            improve=False,
        ),
    )
    assert evaluate_steering_retirement(regressed).approved is False


def test_retirement_rejects_present_scaffold_same_family_or_same_profile() -> None:
    proposal = _retirement_proposal()
    present_identity = replace(
        proposal.candidate_result.identity,
        scaffold_absent=False,
        scaffold_sha256=proposal.scaffold.sha256,
    )
    present_result = _eval_result(present_identity, improve=False)
    with pytest.raises(SkillPackError, match="without scaffold"):
        evaluate_steering_retirement(replace(proposal, candidate_result=present_result))

    for field_name, reason in (
        ("model_family_id", "candidate-model-family-is-not-new"),
        ("profile_id", "candidate-profile-is-not-new"),
    ):
        same_identity = replace(
            proposal.candidate_result.identity,
            **{field_name: getattr(proposal.baseline_result.identity, field_name)},
        )
        same_result = _eval_result(same_identity, improve=False)
        decision = evaluate_steering_retirement(
            replace(proposal, candidate_result=same_result)
        )
        assert reason in decision.reasons


@pytest.mark.parametrize("field_name", ["model_family_id", "profile_id"])
def test_retirement_rejects_reused_stale_omitted_or_wrong_family_evidence(
    field_name: str,
) -> None:
    proposal = _retirement_proposal()
    rebound_identity = replace(
        proposal.candidate_result.identity,
        profile_id="rebound-profile/v1",
    )
    with pytest.raises(SkillPackError, match="another result identity"):
        evaluate_steering_retirement(
            replace(
                proposal,
                candidate_result=replace(
                    proposal.candidate_result,
                    identity=rebound_identity,
                ),
            )
        )

    omitted = replace(
        proposal.candidate_result,
        observations=proposal.candidate_result.observations[:-1],
    )
    with pytest.raises(SkillPackError, match="exact declared"):
        evaluate_steering_retirement(replace(proposal, candidate_result=omitted))

    stale_identity = replace(
        proposal.candidate_result.identity,
        base_resource_sha256="b" * 64,
        candidate_resource_sha256="b" * 64,
    )
    stale_result = _eval_result(stale_identity, improve=False)
    stale = evaluate_steering_retirement(
        replace(proposal, candidate_result=stale_result)
    )
    assert "stale-or-foreign-retirement-resource" in stale.reasons

    invalid_identity = replace(
        proposal.candidate_result.identity,
        **{field_name: "literal-model-name"},
    )
    invalid_result = _eval_result(invalid_identity, improve=False)
    with pytest.raises(SkillPackError, match="versioned symbolic"):
        evaluate_steering_retirement(replace(proposal, candidate_result=invalid_result))
