"""Canonical ordered Life OS skill inventory and public routing contracts."""

from __future__ import annotations

from typing import Any

from ....failure_authority import canonical_matrix, validate_matrix
from .model import (
    ACTION_SCHEMA_VERSION,
    ARTIFACT_SCHEMA_VERSION,
    MODEL_PROFILE_SCHEMA_VERSION,
    RESOURCE_SCHEMA_VERSION,
    ROUTING_SCHEMA_VERSION,
    ActionContract,
    ArtifactCommit,
    ArtifactContract,
    CanonicalSkill,
    ContextBounds,
    IntegrationRequirement,
    ModelRole,
    ModelRoleProfile,
    RoutingContract,
    SkillPackError,
    SkillPackHealth,
    validate_model_role_profile,
    validate_skill_pack,
)


CANONICAL_SKILL_IDS = (
    "ingest",
    "apply",
    "ask",
    "research",
    "engine",
    "project",
    "plan",
    "book",
    "mentor",
    "report",
    "lint",
    "ambient",
    "bundle",
    "grill-me",
    "obsidian",
)

_ROUTING: dict[str, tuple[str, str, str, str, tuple[str, ...]]] = {
    "ingest": (
        "The user submits a new note, link, video, book, or course to the inbox.",
        "Classify and deduplicate the declared input, then create a review proposal.",
        "Do not select this for discussing an existing book or answering from existing knowledge.",
        "Do not promise extraction or research without an accepted connector contract.",
        ("book",),
    ),
    "apply": (
        "The user explicitly asks to apply an approved review plan to human knowledge.",
        "Verify the plan hash and preconditions before an atomic protected write.",
        "Do not select this for ordinary note editing or creation of a new proposal.",
        "Do not treat the existence of a review file as human approval.",
        ("obsidian",),
    ),
    "ask": (
        "Answer with citations from existing human knowledge and the allowed memory scope.",
        "Any allowed file-back must remain a proposal in review.",
        "Do not select this for new external research or adding material to the inbox.",
        "Do not invent an answer when bounded retrieval finds no evidence.",
        ("research",),
    ),
    "research": (
        "Start external research and obtain validated claims through the researcher connector.",
        "Return the result as a review proposal rather than a direct knowledge write.",
        "Do not select this for a vault-only answer or continuation of a known checkpoint.",
        "Do not invoke legacy research code or a second embedded engine.",
        ("ask", "engine"),
    ),
    "engine": (
        "Continue or extend a known stateful researcher checkpoint.",
        "The compatibility surface must resume the same researcher run.",
        "Do not select this to start a new research topic or manage a project lifecycle.",
        "Do not route to a legacy engine implementation.",
        ("research",),
    ),
    "project": (
        "Create or inspect a project, or move it among active, hold, and archive.",
        "Update project state, its physical lifecycle, and its append-only log.",
        "Do not select this for day or week planning or for performing research work.",
        "Do not hide a linked schedule transition as an internal project detail.",
        ("plan",),
    ),
    "plan": (
        "Create or roll over a day or week plan with quota and project/entity context.",
        "Handle rollover or feedback markers using the task preimage.",
        "Do not select this to change a project lifecycle or create a retrospective report.",
        "Do not plan beyond the declared quota and maximum-focus invariants.",
        ("project", "report"),
    ),
    "book": (
        "Discuss a registered reading item or record its progress, anchor, or closure.",
        "Bind reading state to the source manifest and proposal-only knowledge output.",
        "Do not select this for initial ingest, download, or extraction of a raw book.",
        "Do not copy the raw source into the vault or write knowledge directly.",
        ("ingest",),
    ),
    "mentor": (
        "Critique or advise on a domain or project using bounded private context.",
        "Produce a verifiable proposal rather than performing project work.",
        "Do not select this to interactively clarify a decision that has not been made.",
        "Do not substitute a mentor conclusion for an explicit user decision.",
        ("grill-me",),
    ),
    "report": (
        "Create a daily or weekly retrospective from primary logs, tasks, projects, and memory.",
        "Create a report log and an evidence-bound memory proposal.",
        "Do not select this for a future plan or an answer to one knowledge question.",
        "Do not consolidate one summary from another without primary evidence.",
        ("plan",),
    ),
    "lint": (
        "Inspect the vault in infra, content, or deep mode and emit findings.",
        "A deterministic fix is allowed only in allowlisted non-knowledge zones.",
        "Do not select this for ordinary reading or editing of one note.",
        "Do not repair protected knowledge directly, even when a defect is obvious.",
        ("obsidian",),
    ),
    "ambient": (
        "A system run must select one bounded proactive nudge from current signals.",
        "Apply availability, review-budget backpressure, and semantic deduplication.",
        "Do not select this to assemble an existing batched review queue.",
        "Do not create an event when no suitable candidate exists.",
        ("bundle",),
    ),
    "bundle": (
        "A system run must combine pending batched items into one digest event.",
        "Deduplicate by window and source hashes without losing source artifacts.",
        "Do not select this to find a new proactive signal or request an immediate gated decision.",
        "Do not treat delivery as part of artifact commit.",
        ("ambient",),
    ),
    "grill-me": (
        "Ask questions and record answers before costly or ambiguous work.",
        "Produce explicit decisions without inferred consent.",
        "Do not select this for mentor critique or direct execution of work.",
        "Do not infer consent from silence or an incomplete answer.",
        ("mentor",),
    ),
    "obsidian": (
        "Perform safe basic operations on an allowed vault note or its metadata.",
        "Apply path validation, bounded reads, and validate-on-write.",
        "Do not select this instead of the specialized apply or lint flow.",
        "Do not write protected knowledge or cross archive or private roots.",
        ("apply", "lint"),
    ),
}

_DESCRIPTIONS = {
    "ingest": "Accept new input and route it through a bounded review-first ingest flow.",
    "apply": "Atomically apply an explicitly approved review plan to knowledge.",
    "ask": "Answer from the existing vault with verifiable citations.",
    "research": "Commission new research through the researcher connector and review.",
    "engine": "Continue a stateful research checkpoint through the researcher connector.",
    "project": "Manage a verifiable project lifecycle and state.",
    "plan": "Build a day or week plan with quota, rollover, and evidence.",
    "book": "Manage the reading lifecycle of a registered source manifest.",
    "mentor": "Provide bounded critique of a project or domain through a proposal.",
    "report": "Create an evidence-bound report and memory proposal.",
    "lint": "Inspect the vault and apply only allowed deterministic fixes.",
    "ambient": "Choose one proactive semantic nudge with backpressure and deduplication.",
    "bundle": "Combine batched review items into one semantic digest event.",
    "grill-me": "Clarify a decision through questions without inventing consent.",
    "obsidian": "Safely read and change only allowed vault zones.",
}

_INTEGRATION_REQUIREMENTS = {
    "ingest": (
        (
            "ingest-full-trajectory",
            "flow-trajectory",
            "runtime-flow:ingest",
            ("store-inbox-item", "record-run-state"),
        ),
    ),
    "apply": (
        (
            "apply-public-orchestrator",
            "flow-trajectory",
            "runtime-flow:apply",
            ("record-run-state",),
        ),
    ),
    "ask": (
        (
            "ask-memory-run-trajectory",
            "flow-trajectory",
            "runtime-flow:ask",
            ("read-memory-retrieval-scope", "record-run-state"),
        ),
    ),
    "research": (
        (
            "research-researcher-route",
            "connector-route",
            "connector:researcher",
            (
                "start-or-resume-researcher",
                "commit-research-proposal",
                "record-run-state",
            ),
        ),
    ),
    "engine": (
        (
            "engine-researcher-route",
            "connector-route",
            "connector:researcher",
            (
                "compat-resume-researcher",
                "commit-engine-compat-proposal",
                "record-run-state",
            ),
        ),
    ),
    "project": (
        (
            "project-knowledge-proposal",
            "flow-trajectory",
            "runtime-flow:project",
            ("commit-project-knowledge-proposal",),
        ),
    ),
}


def _matrix_flows() -> dict[str, dict[str, Any]]:
    matrix = canonical_matrix()
    validate_matrix(matrix)
    return {flow["flow_id"]: flow for flow in matrix["flows"]}


def _actions(flow: dict[str, Any]) -> tuple[ActionContract, ...]:
    return tuple(
        ActionContract(
            schema_version=ACTION_SCHEMA_VERSION,
            action_id=action["action_id"],
            actor=action["actor"],
            authority=action["authority"],
            access=action["access"],
            target=action["target"],
            effect_kind=action["effect_kind"],
            artifact_commit=action["artifact_commit"],
            irreversible=action["irreversible"],
            crash_points=tuple(action["crash_points"]),
            retry_owner=action["retry_owner"],
            rollback=action["rollback"],
        )
        for action in flow["actions"]
    )


def _body(
    skill_id: str,
    routing: RoutingContract,
    context: ContextBounds,
    actions: tuple[ActionContract, ...],
    artifact: ArtifactContract,
    requirements: tuple[IntegrationRequirement, ...],
) -> str:
    choose = "\n".join(f"- {rule}" for rule in routing.choose_when)
    reject = "\n".join(f"- {rule}" for rule in routing.reject_when)
    action_ids = ", ".join(action.action_id for action in actions)
    commits = ", ".join(commit.action_id for commit in artifact.commits) or "none"
    integration = (
        "Integration required: "
        + "; ".join(
            f"{requirement.requirement_type} {requirement.target} "
            f"[{', '.join(requirement.action_ids)}]"
            for requirement in requirements
        )
        + "."
        if requirements
        else "Executable route covers the declared public action trajectory."
    )
    return (
        f"# lifeos-{skill_id}\n\n"
        "Routing schema: 1. Resource schema: 1.\n\n"
        "Choose when:\n"
        f"{choose}\n\n"
        "Do not choose when:\n"
        f"{reject}\n\n"
        f"Context bound: {context.max_files} files, {context.max_bytes} bytes, "
        f"{context.max_items} items.\n\n"
        f"Exact action IDs: {action_ids}.\n\n"
        f"Artifact contract: {artifact.contract_id}; commits: {commits}.\n\n"
        f"{integration}\n"
        "Executor output is untrusted until deterministic validation. Do not raise "
        "authority or change protected knowledge outside an approved apply."
    )


def _build_skills() -> tuple[CanonicalSkill, ...]:
    flows = _matrix_flows()
    skills: list[CanonicalSkill] = []
    for skill_id in CANONICAL_SKILL_IDS:
        flow = flows[skill_id]
        choose_a, choose_b, reject_a, reject_b, ambiguity = _ROUTING[skill_id]
        routing = RoutingContract(
            schema_version=ROUTING_SCHEMA_VERSION,
            choose_when=(choose_a, choose_b),
            reject_when=(reject_a, reject_b),
            ambiguity_with=ambiguity,
        )
        scopes = tuple(
            dict.fromkeys(
                [
                    *flow["allowed_reads"],
                    *flow["allowed_writes"],
                    *flow["allowed_invocations"],
                ]
            )
        )
        context = ContextBounds(
            schema_version=RESOURCE_SCHEMA_VERSION,
            max_files=12,
            max_bytes=65_536,
            max_items=24,
            allowed_scopes=scopes,
        )
        actions = _actions(flow)
        artifact = ArtifactContract(
            schema_version=ARTIFACT_SCHEMA_VERSION,
            contract_id=f"lifeos://artifacts/{skill_id}/v1",
            flow_id=skill_id,
            action_ids=tuple(action.action_id for action in actions),
            commits=tuple(
                ArtifactCommit(
                    action_id=action.action_id,
                    authority=action.authority,
                    target=action.target,
                    effect_kind=action.effect_kind,
                )
                for action in actions
                if action.artifact_commit
            ),
        )
        requirements = tuple(
            IntegrationRequirement(
                schema_version=RESOURCE_SCHEMA_VERSION,
                requirement_id=requirement_id,
                requirement_type=requirement_type,
                target=target,
                action_ids=action_ids,
            )
            for requirement_id, requirement_type, target, action_ids in (
                _INTEGRATION_REQUIREMENTS.get(skill_id, ())
            )
        )
        skill = CanonicalSkill(
            skill_id=skill_id,
            resource_id=f"lifeos://skills/{skill_id}/v1",
            name=f"lifeos-{skill_id}",
            description=_DESCRIPTIONS[skill_id],
            body=_body(
                skill_id,
                routing,
                context,
                actions,
                artifact,
                requirements,
            ),
            schema_version=RESOURCE_SCHEMA_VERSION,
            flow_id=skill_id,
            routing=routing,
            context=context,
            actions=actions,
            artifact_contract=artifact,
            status=("integration_required" if requirements else "available"),
            integration_requirements=requirements,
        )
        skills.append(skill)
    return validate_skill_pack(skills, expected_ids=CANONICAL_SKILL_IDS)


_SKILLS = _build_skills()
_BY_ID = {skill.skill_id: skill for skill in _SKILLS}

_MODEL_PROFILES = (
    ModelRoleProfile(
        schema_version=MODEL_PROFILE_SCHEMA_VERSION,
        model_family_id="default-family/v1",
        profile_id="standard/v1",
        roles=(
            ModelRole(
                "cheap_collect",
                "Collect bounded facts without making domain decisions.",
                65_536,
                4_096,
            ),
            ModelRole(
                "reason",
                "Check alternatives, evidence, and authority before synthesis.",
                131_072,
                8_192,
            ),
            ModelRole(
                "synthesize", "Produce an artifact under the accepted contract.", 131_072, 12_288
            ),
            ModelRole(
                "critic",
                "Independently check invariants, gaps, and acceptance.",
                65_536,
                8_192,
            ),
        ),
    ),
)
for _profile in _MODEL_PROFILES:
    validate_model_role_profile(_profile)


def canonical_skills() -> tuple[CanonicalSkill, ...]:
    """Return all 15 canonical resources in their stable public order."""

    return _SKILLS


def canonical_resource(skill_id: str) -> CanonicalSkill:
    """Resolve one canonical resource by its stable skill id."""

    try:
        return _BY_ID[skill_id]
    except (KeyError, TypeError) as exc:
        raise KeyError(skill_id) from exc


def model_role_profiles() -> tuple[ModelRoleProfile, ...]:
    return _MODEL_PROFILES


def model_role_profile(profile_id: str = "standard/v1") -> ModelRoleProfile:
    for profile in _MODEL_PROFILES:
        if profile.profile_id == profile_id:
            return profile
    raise KeyError(profile_id)


def check_skill_pack() -> SkillPackHealth:
    issues: list[str] = []
    try:
        validate_skill_pack(_SKILLS, expected_ids=CANONICAL_SKILL_IDS)
    except SkillPackError:
        issues.append("invalid-canonical-resources")
    try:
        for profile in _MODEL_PROFILES:
            validate_model_role_profile(profile)
    except SkillPackError:
        issues.append("invalid-model-role-profile")
    return SkillPackHealth(
        ok=not issues,
        skill_count=len(_SKILLS),
        wrapper_count=len(_SKILLS) * 2,
        issues=tuple(issues),
    )


__all__ = [
    "CANONICAL_SKILL_IDS",
    "canonical_resource",
    "canonical_skills",
    "check_skill_pack",
    "model_role_profile",
    "model_role_profiles",
]
