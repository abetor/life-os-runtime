"""Deterministic routing, evolution, and steering-retirement gates."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from typing import Mapping

from .catalog import CANONICAL_SKILL_IDS, canonical_resource
from .model import (
    EVAL_SCHEMA_VERSION,
    MAX_ROUTING_RULE_CHARS,
    MAX_STEERING_CHARS,
    SkillPackError,
    _canonical_json,
    _text,
    validate_hash,
    validate_score,
    validate_versioned_symbolic_id,
)


@dataclass(frozen=True)
class RoutingEvalCase:
    schema_version: int
    case_id: str
    prompt: str
    expected_skill_id: str
    confounder_skill_id: str
    held_out: bool


@dataclass(frozen=True)
class RoutingEvalReport:
    ok: bool
    passed: int
    total: int
    held_out_passed: int
    held_out_total: int
    failures: tuple[str, ...]


@dataclass(frozen=True)
class SkillEvalContract:
    """Immutable eval identities required before evolution or retirement."""

    schema_version: int
    skill_id: str
    regression_case_id: str
    routing_case_ids: tuple[str, ...]
    held_out_case_ids: tuple[str, ...]

    @property
    def case_ids(self) -> tuple[str, ...]:
        return (self.regression_case_id, *self.routing_case_ids)

    @property
    def sha256(self) -> str:
        payload = {
            "schema_version": self.schema_version,
            "skill_id": self.skill_id,
            "regression_case_id": self.regression_case_id,
            "routing_case_ids": list(self.routing_case_ids),
            "held_out_case_ids": list(self.held_out_case_ids),
        }
        return hashlib.sha256(_canonical_json(payload)).hexdigest()


@dataclass(frozen=True)
class EvalResultIdentity:
    """Immutable identity of one exact, model-family-bound evaluation result."""

    schema_version: int
    skill_id: str
    eval_contract_sha256: str
    base_resource_sha256: str
    candidate_resource_sha256: str
    model_family_id: str
    profile_id: str
    case_ids: tuple[str, ...]
    scaffold_absent: bool
    scaffold_sha256: str | None

    @property
    def sha256(self) -> str:
        payload = {
            "schema_version": self.schema_version,
            "skill_id": self.skill_id,
            "eval_contract_sha256": self.eval_contract_sha256,
            "base_resource_sha256": self.base_resource_sha256,
            "candidate_resource_sha256": self.candidate_resource_sha256,
            "model_family_id": self.model_family_id,
            "profile_id": self.profile_id,
            "case_ids": list(self.case_ids),
            "scaffold_absent": self.scaffold_absent,
            "scaffold_sha256": self.scaffold_sha256,
        }
        return hashlib.sha256(_canonical_json(payload)).hexdigest()


@dataclass(frozen=True)
class EvalObservation:
    """Comparable baseline/candidate result for one immutable eval case."""

    case_id: str
    cohort: str
    baseline_score: float
    candidate_score: float
    passed: bool
    result_identity_sha256: str


@dataclass(frozen=True)
class EvalResult:
    """One complete declared eval result bound to its immutable identity."""

    schema_version: int
    identity: EvalResultIdentity
    observations: tuple[EvalObservation, ...]

    @property
    def sha256(self) -> str:
        payload = {
            "schema_version": self.schema_version,
            "identity_sha256": self.identity.sha256,
            "observations": [
                {
                    "case_id": observation.case_id,
                    "cohort": observation.cohort,
                    "baseline_score": observation.baseline_score,
                    "candidate_score": observation.candidate_score,
                    "passed": observation.passed,
                    "result_identity_sha256": observation.result_identity_sha256,
                }
                for observation in self.observations
            ],
        }
        return hashlib.sha256(_canonical_json(payload)).hexdigest()


@dataclass(frozen=True)
class EvolutionProposal:
    schema_version: int
    proposal_id: str
    skill_id: str
    base_resource_sha256: str
    candidate_resource_sha256: str
    change_summary: str
    eval_result: EvalResult

    @property
    def observations(self) -> tuple[EvalObservation, ...]:
        """Compatibility view of the identity-bound result observations."""

        return self.eval_result.observations


@dataclass(frozen=True)
class EvolutionDecision:
    approved: bool
    reasons: tuple[str, ...]


@dataclass(frozen=True)
class SteeringScaffold:
    schema_version: int
    scaffold_id: str
    skill_id: str
    text: str

    @property
    def sha256(self) -> str:
        payload = {
            "schema_version": self.schema_version,
            "scaffold_id": self.scaffold_id,
            "skill_id": self.skill_id,
            "text": self.text,
        }
        return hashlib.sha256(_canonical_json(payload)).hexdigest()


@dataclass(frozen=True)
class SteeringRetirementProposal:
    schema_version: int
    proposal_id: str
    scaffold: SteeringScaffold
    baseline_result: EvalResult
    candidate_result: EvalResult


@dataclass(frozen=True)
class SteeringRetirementDecision:
    approved: bool
    reasons: tuple[str, ...]


_ROUTING_EVALS = (
    RoutingEvalCase(
        1,
        "ask-vs-research-01",
        "Answer from my existing notes and provide citations.",
        "ask",
        "research",
        False,
    ),
    RoutingEvalCase(
        1,
        "research-vs-ask-01",
        "Collect new external sources and prepare a research proposal.",
        "research",
        "ask",
        True,
    ),
    RoutingEvalCase(
        1,
        "research-vs-engine-01",
        "Start a new research topic for the stated question.",
        "research",
        "engine",
        False,
    ),
    RoutingEvalCase(
        1,
        "engine-vs-research-01",
        "Continue the existing research checkpoint without a second run.",
        "engine",
        "research",
        True,
    ),
    RoutingEvalCase(
        1,
        "ingest-vs-book-01",
        "Accept a new book file and register the input.",
        "ingest",
        "book",
        False,
    ),
    RoutingEvalCase(
        1,
        "book-vs-ingest-01",
        "Record reading progress for an already registered book.",
        "book",
        "ingest",
        True,
    ),
    RoutingEvalCase(
        1,
        "project-vs-plan-01",
        "Put the active project on hold.",
        "project",
        "plan",
        False,
    ),
    RoutingEvalCase(
        1,
        "plan-vs-project-01",
        "Build a daily plan with quota from active projects.",
        "plan",
        "project",
        True,
    ),
    RoutingEvalCase(
        1,
        "plan-vs-report-01",
        "Roll unfinished tasks into next week's plan.",
        "plan",
        "report",
        False,
    ),
    RoutingEvalCase(
        1,
        "report-vs-plan-01",
        "Build a weekly retrospective from primary logs.",
        "report",
        "plan",
        True,
    ),
    RoutingEvalCase(
        1,
        "mentor-vs-grill-01",
        "Critique the project strategy using the available evidence.",
        "mentor",
        "grill-me",
        False,
    ),
    RoutingEvalCase(
        1,
        "grill-vs-mentor-01",
        "Ask questions until I explicitly record a decision.",
        "grill-me",
        "mentor",
        True,
    ),
    RoutingEvalCase(
        1,
        "ambient-vs-bundle-01",
        "Select one new proactive nudge from current signals.",
        "ambient",
        "bundle",
        False,
    ),
    RoutingEvalCase(
        1,
        "bundle-vs-ambient-01",
        "Combine accumulated batched review items into a digest.",
        "bundle",
        "ambient",
        True,
    ),
    RoutingEvalCase(
        1,
        "apply-vs-obsidian-01",
        "Apply the approved review plan after checking preconditions.",
        "apply",
        "obsidian",
        False,
    ),
    RoutingEvalCase(
        1,
        "obsidian-vs-apply-01",
        "Fix ordinary task-note metadata with validate-on-write.",
        "obsidian",
        "apply",
        True,
    ),
    RoutingEvalCase(
        1,
        "lint-vs-obsidian-01",
        "Inspect the entire vault in infra mode and emit findings.",
        "lint",
        "obsidian",
        False,
    ),
    RoutingEvalCase(
        1,
        "obsidian-vs-lint-01",
        "Safely read one project note.",
        "obsidian",
        "lint",
        True,
    ),
)


def _validate_routing_case(case: RoutingEvalCase) -> None:
    if not isinstance(case, RoutingEvalCase) or type(case.schema_version) is not int:
        raise SkillPackError("routing eval case has an invalid type")
    if case.schema_version != EVAL_SCHEMA_VERSION or type(case.held_out) is not bool:
        raise SkillPackError("routing eval case has an invalid version or cohort")
    _text(case.case_id, label="routing eval case id", maximum=96)
    _text(
        case.prompt,
        label=f"{case.case_id} prompt",
        maximum=MAX_ROUTING_RULE_CHARS,
    )
    if (
        case.expected_skill_id not in CANONICAL_SKILL_IDS
        or case.confounder_skill_id not in CANONICAL_SKILL_IDS
        or case.expected_skill_id == case.confounder_skill_id
    ):
        raise SkillPackError(f"{case.case_id} has invalid skill ids")
    expected = canonical_resource(case.expected_skill_id)
    if case.confounder_skill_id not in expected.routing.ambiguity_with:
        raise SkillPackError(f"{case.case_id} is not a declared ambiguity pair")


for _case in _ROUTING_EVALS:
    _validate_routing_case(_case)
if len({case.case_id for case in _ROUTING_EVALS}) != len(_ROUTING_EVALS):
    raise SkillPackError("routing eval ids contain duplicates")


def routing_eval_cases() -> tuple[RoutingEvalCase, ...]:
    return _ROUTING_EVALS


def ambiguity_pairs() -> tuple[tuple[str, str], ...]:
    return tuple(
        dict.fromkeys(
            tuple(sorted((case.expected_skill_id, case.confounder_skill_id)))
            for case in _ROUTING_EVALS
        )
    )


def skill_eval_contract(skill_id: str) -> SkillEvalContract:
    canonical_resource(skill_id)
    relevant = tuple(
        case
        for case in _ROUTING_EVALS
        if skill_id in {case.expected_skill_id, case.confounder_skill_id}
    )
    held_out = tuple(case.case_id for case in relevant if case.held_out)
    if not relevant or not held_out:
        raise SkillPackError(f"{skill_id} lacks a declared held-out routing eval")
    return SkillEvalContract(
        schema_version=EVAL_SCHEMA_VERSION,
        skill_id=skill_id,
        regression_case_id=f"{skill_id}-authority-artifact-regression-v1",
        routing_case_ids=tuple(case.case_id for case in relevant),
        held_out_case_ids=held_out,
    )


def evaluate_routing(
    selections: Mapping[str, str],
    *,
    cases: tuple[RoutingEvalCase, ...] | None = None,
) -> RoutingEvalReport:
    if not isinstance(selections, Mapping):
        raise SkillPackError("routing selections must be a mapping")
    selected_cases = _ROUTING_EVALS if cases is None else cases
    if not isinstance(selected_cases, tuple) or not selected_cases:
        raise SkillPackError("routing eval cases must be a non-empty tuple")
    failures: list[str] = []
    held_out_passed = 0
    held_out_total = 0
    passed = 0
    seen: set[str] = set()
    for case in selected_cases:
        _validate_routing_case(case)
        if case.case_id in seen:
            raise SkillPackError("routing eval ids contain duplicates")
        seen.add(case.case_id)
        if case.held_out:
            held_out_total += 1
        if selections.get(case.case_id) == case.expected_skill_id:
            passed += 1
            if case.held_out:
                held_out_passed += 1
        else:
            failures.append(case.case_id)
    unknown = set(selections) - seen
    if unknown:
        raise SkillPackError("routing selections contain unknown eval ids")
    return RoutingEvalReport(
        ok=passed == len(selected_cases),
        passed=passed,
        total=len(selected_cases),
        held_out_passed=held_out_passed,
        held_out_total=held_out_total,
        failures=tuple(failures),
    )


def _validate_result_identity(
    identity: EvalResultIdentity,
) -> SkillEvalContract:
    if not isinstance(identity, EvalResultIdentity):
        raise SkillPackError("eval result identity has an invalid type")
    if (
        type(identity.schema_version) is not int
        or identity.schema_version != EVAL_SCHEMA_VERSION
    ):
        raise SkillPackError("eval result identity schema_version is invalid")
    contract = skill_eval_contract(identity.skill_id)
    contract_sha256 = validate_hash(
        identity.eval_contract_sha256,
        label="eval contract hash",
    )
    if contract_sha256 != contract.sha256:
        raise SkillPackError("eval result identity contract hash is stale or foreign")
    validate_hash(identity.base_resource_sha256, label="eval base resource hash")
    validate_hash(
        identity.candidate_resource_sha256,
        label="eval candidate resource hash",
    )
    validate_versioned_symbolic_id(
        identity.model_family_id,
        label="eval model family id",
    )
    validate_versioned_symbolic_id(identity.profile_id, label="eval profile id")
    if (
        not isinstance(identity.case_ids, tuple)
        or identity.case_ids != contract.case_ids
    ):
        raise SkillPackError("eval result identity case inventory is not exact")
    if type(identity.scaffold_absent) is not bool:
        raise SkillPackError("eval result identity scaffold flag is invalid")
    if identity.scaffold_absent:
        if identity.scaffold_sha256 is not None:
            raise SkillPackError("scaffold-absent eval carries a scaffold hash")
    else:
        validate_hash(identity.scaffold_sha256, label="eval scaffold hash")
    return contract


def _validate_eval_result(result: EvalResult) -> tuple[EvalObservation, ...]:
    if not isinstance(result, EvalResult):
        raise SkillPackError("eval result has an invalid type")
    if (
        type(result.schema_version) is not int
        or result.schema_version != EVAL_SCHEMA_VERSION
    ):
        raise SkillPackError("eval result schema_version is invalid")
    contract = _validate_result_identity(result.identity)
    observations = result.observations
    if not isinstance(observations, tuple) or not observations:
        raise SkillPackError("eval observations must be a non-empty tuple")
    if tuple(
        observation.case_id
        for observation in observations
        if isinstance(observation, EvalObservation)
    ) != contract.case_ids or len(observations) != len(contract.case_ids):
        raise SkillPackError("eval observations do not cover the exact declared cases")
    declared_cohorts = {
        contract.regression_case_id: "regression",
        **{
            case.case_id: "held_out" if case.held_out else "held_in"
            for case in _ROUTING_EVALS
            if case.case_id in contract.routing_case_ids
        },
    }
    identity_sha256 = result.identity.sha256
    for observation in observations:
        if not isinstance(observation, EvalObservation):
            raise SkillPackError("eval observation has an invalid type")
        _text(observation.case_id, label="eval case id", maximum=96)
        if observation.cohort != declared_cohorts[observation.case_id]:
            raise SkillPackError(
                "eval observation cohort does not match its declared case"
            )
        validate_score(observation.baseline_score, label="baseline score")
        validate_score(observation.candidate_score, label="candidate score")
        if type(observation.passed) is not bool:
            raise SkillPackError("eval observation passed flag is invalid")
        binding = validate_hash(
            observation.result_identity_sha256,
            label="eval observation identity hash",
        )
        if binding != identity_sha256:
            raise SkillPackError("eval observation is bound to another result identity")
    return observations


def evaluate_evolution_proposal(proposal: EvolutionProposal) -> EvolutionDecision:
    if not isinstance(proposal, EvolutionProposal):
        raise SkillPackError("evolution proposal has an invalid type")
    if (
        type(proposal.schema_version) is not int
        or proposal.schema_version != EVAL_SCHEMA_VERSION
    ):
        raise SkillPackError("evolution proposal schema_version is invalid")
    _text(proposal.proposal_id, label="evolution proposal id", maximum=96)
    skill = canonical_resource(proposal.skill_id)
    base = validate_hash(proposal.base_resource_sha256, label="base resource hash")
    candidate = validate_hash(
        proposal.candidate_resource_sha256,
        label="candidate resource hash",
    )
    _text(proposal.change_summary, label="change summary", maximum=512)
    observations = _validate_eval_result(proposal.eval_result)
    identity = proposal.eval_result.identity
    if (
        identity.skill_id != proposal.skill_id
        or identity.base_resource_sha256 != base
        or identity.candidate_resource_sha256 != candidate
    ):
        raise SkillPackError("evolution eval result identity is not proposal-bound")
    if not identity.scaffold_absent or identity.scaffold_sha256 is not None:
        raise SkillPackError("evolution eval must not depend on a steering scaffold")
    reasons: list[str] = []
    if base != skill.sha256:
        reasons.append("stale-or-foreign-base-resource")
    if base == candidate:
        reasons.append("candidate-is-unchanged")
    if any(not observation.passed for observation in observations):
        reasons.append("eval-failure")
    if any(
        observation.candidate_score < observation.baseline_score
        for observation in observations
    ):
        reasons.append("regression")
    if not any(
        observation.cohort in {"held_in", "held_out"}
        and observation.candidate_score > observation.baseline_score
        for observation in observations
    ):
        reasons.append("no-held-in-or-held-out-improvement")
    return EvolutionDecision(not reasons, tuple(dict.fromkeys(reasons)))


def evaluate_steering_retirement(
    proposal: SteeringRetirementProposal,
) -> SteeringRetirementDecision:
    if not isinstance(proposal, SteeringRetirementProposal):
        raise SkillPackError("steering retirement proposal has an invalid type")
    if (
        type(proposal.schema_version) is not int
        or proposal.schema_version != EVAL_SCHEMA_VERSION
    ):
        raise SkillPackError("steering retirement schema_version is invalid")
    _text(proposal.proposal_id, label="steering retirement proposal id", maximum=96)
    scaffold = proposal.scaffold
    if not isinstance(scaffold, SteeringScaffold):
        raise SkillPackError("steering scaffold has an invalid type")
    if (
        type(scaffold.schema_version) is not int
        or scaffold.schema_version != EVAL_SCHEMA_VERSION
    ):
        raise SkillPackError("steering scaffold schema_version is invalid")
    _text(scaffold.scaffold_id, label="steering scaffold id", maximum=96)
    canonical_resource(scaffold.skill_id)
    _text(
        scaffold.text,
        label="steering scaffold text",
        maximum=MAX_STEERING_CHARS,
        allow_newlines=True,
    )
    baseline = _validate_eval_result(proposal.baseline_result)
    candidate = _validate_eval_result(proposal.candidate_result)
    baseline_identity = proposal.baseline_result.identity
    candidate_identity = proposal.candidate_result.identity
    if baseline_identity.skill_id != scaffold.skill_id:
        raise SkillPackError("retirement baseline result is bound to another skill")
    if candidate_identity.skill_id != scaffold.skill_id:
        raise SkillPackError("retirement candidate result is bound to another skill")
    if (
        baseline_identity.scaffold_absent
        or baseline_identity.scaffold_sha256 != scaffold.sha256
    ):
        raise SkillPackError("retirement baseline was not evaluated with this scaffold")
    if (
        not candidate_identity.scaffold_absent
        or candidate_identity.scaffold_sha256 is not None
    ):
        raise SkillPackError("retirement candidate was not evaluated without scaffold")
    baseline_by_id = {observation.case_id: observation for observation in baseline}
    if any(
        observation.baseline_score
        != baseline_by_id[observation.case_id].candidate_score
        for observation in candidate
    ):
        raise SkillPackError("retirement candidate is not score-bound to its baseline")
    skill = canonical_resource(scaffold.skill_id)
    reasons: list[str] = []
    if any(
        value != skill.sha256
        for value in (
            baseline_identity.base_resource_sha256,
            baseline_identity.candidate_resource_sha256,
            candidate_identity.base_resource_sha256,
            candidate_identity.candidate_resource_sha256,
        )
    ):
        reasons.append("stale-or-foreign-retirement-resource")
    if baseline_identity.model_family_id == candidate_identity.model_family_id:
        reasons.append("candidate-model-family-is-not-new")
    if baseline_identity.profile_id == candidate_identity.profile_id:
        reasons.append("candidate-profile-is-not-new")
    if any(not observation.passed for observation in baseline):
        reasons.append("baseline-invariant-failure-with-scaffold")
    if any(not observation.passed for observation in candidate):
        reasons.append("invariant-failure-without-scaffold")
    if any(
        observation.candidate_score < observation.baseline_score
        for observation in candidate
    ):
        reasons.append("invariant-regression-without-scaffold")
    return SteeringRetirementDecision(not reasons, tuple(dict.fromkeys(reasons)))


# Concise aliases for callers that treat both operations as gates.
evaluate_evolution = evaluate_evolution_proposal
evaluate_retirement = evaluate_steering_retirement


__all__ = [
    "EvalObservation",
    "EvalResult",
    "EvalResultIdentity",
    "EvolutionDecision",
    "EvolutionProposal",
    "RoutingEvalCase",
    "RoutingEvalReport",
    "SkillEvalContract",
    "SteeringRetirementDecision",
    "SteeringRetirementProposal",
    "SteeringScaffold",
    "ambiguity_pairs",
    "evaluate_evolution",
    "evaluate_evolution_proposal",
    "evaluate_retirement",
    "evaluate_routing",
    "evaluate_steering_retirement",
    "routing_eval_cases",
    "skill_eval_contract",
]
