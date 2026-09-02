"""Strict public models for the canonical Life OS skill pack."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
import re
from typing import Iterable, Mapping


RESOURCE_SCHEMA_VERSION = 1
ROUTING_SCHEMA_VERSION = 1
ACTION_SCHEMA_VERSION = 1
ARTIFACT_SCHEMA_VERSION = 1
MODEL_PROFILE_SCHEMA_VERSION = 1
EVAL_SCHEMA_VERSION = 1

MAX_DESCRIPTION_CHARS = 240
MAX_BODY_CHARS = 4_096
MAX_ROUTING_RULES = 8
MAX_ROUTING_RULE_CHARS = 280
MAX_ACTIONS = 16
MAX_CONTEXT_FILES = 32
MAX_CONTEXT_BYTES = 262_144
MAX_CONTEXT_ITEMS = 64
MAX_STEERING_CHARS = 1_024

_ID = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")
_PROFILE_ID = re.compile(r"^[a-z][a-z0-9_-]{0,63}/v[1-9][0-9]*$")
_HASH = re.compile(r"^[0-9a-f]{64}$")
_PRIVATE_MARKERS = ("/" + "Users" + "/", "/" + "home" + "/")
_MODEL_ROLES = ("cheap_collect", "reason", "synthesize", "critic")


class SkillPackError(ValueError):
    """A public skill resource or evaluation contract is invalid."""


def _strict_int(value: object, *, label: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise SkillPackError(f"{label} must be an integer in [{minimum}, {maximum}]")
    return value


def _text(
    value: object,
    *,
    label: str,
    maximum: int,
    allow_newlines: bool = False,
) -> str:
    if not isinstance(value, str) or not value or value.strip() != value:
        raise SkillPackError(f"{label} must be a non-empty canonical string")
    if len(value) > maximum:
        raise SkillPackError(f"{label} exceeds its public bound")
    if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
        raise SkillPackError(f"{label} contains a Unicode surrogate")
    if any(
        (ord(character) < 32 and (not allow_newlines or character not in "\n\t"))
        or ord(character) == 127
        for character in value
    ):
        raise SkillPackError(f"{label} contains a control character")
    if (
        value.startswith(("/", "~", "file:"))
        or "\\" in value
        or any(marker in value for marker in _PRIVATE_MARKERS)
    ):
        raise SkillPackError(f"{label} contains a private or absolute path")
    return value


def _ordered_unique_texts(
    value: object,
    *,
    label: str,
    maximum_items: int,
    maximum_chars: int,
) -> tuple[str, ...]:
    if not isinstance(value, tuple):
        raise SkillPackError(f"{label} must be a tuple")
    if not 1 <= len(value) <= maximum_items:
        raise SkillPackError(f"{label} has an invalid item count")
    normalized = tuple(
        _text(item, label=f"{label} item", maximum=maximum_chars) for item in value
    )
    if len(set(normalized)) != len(normalized):
        raise SkillPackError(f"{label} contains duplicates")
    return normalized


def _canonical_json(value: Mapping[str, object]) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


@dataclass(frozen=True)
class ContextBounds:
    """Hard limits applied before a skill task packet reaches an executor."""

    schema_version: int
    max_files: int
    max_bytes: int
    max_items: int
    allowed_scopes: tuple[str, ...]


@dataclass(frozen=True)
class RoutingContract:
    """Versioned positive, negative, and ambiguity routing rules."""

    schema_version: int
    choose_when: tuple[str, ...]
    reject_when: tuple[str, ...]
    ambiguity_with: tuple[str, ...]


@dataclass(frozen=True)
class ActionContract:
    """One exact row from the public failure-authority matrix."""

    schema_version: int
    action_id: str
    actor: str
    authority: str
    access: str
    target: str
    effect_kind: str
    artifact_commit: bool
    irreversible: bool
    crash_points: tuple[str, ...]
    retry_owner: str
    rollback: str


@dataclass(frozen=True)
class ArtifactCommit:
    """The committed-artifact subset of one exact action contract."""

    action_id: str
    authority: str
    target: str
    effect_kind: str


@dataclass(frozen=True)
class ArtifactContract:
    """Harness-independent output contract derived from matrix actions."""

    schema_version: int
    contract_id: str
    flow_id: str
    action_ids: tuple[str, ...]
    commits: tuple[ArtifactCommit, ...]

    @property
    def sha256(self) -> str:
        payload = {
            "schema_version": self.schema_version,
            "contract_id": self.contract_id,
            "flow_id": self.flow_id,
            "action_ids": list(self.action_ids),
            "commits": [
                {
                    "action_id": commit.action_id,
                    "authority": commit.authority,
                    "target": commit.target,
                    "effect_kind": commit.effect_kind,
                }
                for commit in self.commits
            ],
        }
        return hashlib.sha256(_canonical_json(payload)).hexdigest()


@dataclass(frozen=True)
class IntegrationRequirement:
    """One explicit missing executable edge for an otherwise usable route."""

    schema_version: int
    requirement_id: str
    requirement_type: str
    target: str
    action_ids: tuple[str, ...]


@dataclass(frozen=True)
class CanonicalSkill:
    """One canonical, harness-independent, bounded skill resource."""

    skill_id: str
    resource_id: str
    name: str
    description: str
    body: str
    schema_version: int
    flow_id: str
    routing: RoutingContract
    context: ContextBounds
    actions: tuple[ActionContract, ...]
    artifact_contract: ArtifactContract
    status: str
    integration_requirements: tuple[IntegrationRequirement, ...]

    @property
    def action_ids(self) -> tuple[str, ...]:
        return tuple(action.action_id for action in self.actions)

    @property
    def integration_required(self) -> bool:
        return self.status == "integration_required"

    @property
    def integration_target(self) -> str | None:
        """Compatibility view for callers that only understood one target."""

        if not self.integration_requirements:
            return None
        return self.integration_requirements[0].target

    @property
    def sha256(self) -> str:
        """Digest the complete contract, not only its prose projection."""

        payload = {
            "schema_version": self.schema_version,
            "skill_id": self.skill_id,
            "resource_id": self.resource_id,
            "name": self.name,
            "description": self.description,
            "body": self.body,
            "flow_id": self.flow_id,
            "routing": {
                "schema_version": self.routing.schema_version,
                "choose_when": list(self.routing.choose_when),
                "reject_when": list(self.routing.reject_when),
                "ambiguity_with": list(self.routing.ambiguity_with),
            },
            "context": {
                "schema_version": self.context.schema_version,
                "max_files": self.context.max_files,
                "max_bytes": self.context.max_bytes,
                "max_items": self.context.max_items,
                "allowed_scopes": list(self.context.allowed_scopes),
            },
            "actions": [
                {
                    "schema_version": action.schema_version,
                    "action_id": action.action_id,
                    "actor": action.actor,
                    "authority": action.authority,
                    "access": action.access,
                    "target": action.target,
                    "effect_kind": action.effect_kind,
                    "artifact_commit": action.artifact_commit,
                    "irreversible": action.irreversible,
                    "crash_points": list(action.crash_points),
                    "retry_owner": action.retry_owner,
                    "rollback": action.rollback,
                }
                for action in self.actions
            ],
            "artifact_contract_sha256": self.artifact_contract.sha256,
            "status": self.status,
            "integration_requirements": [
                {
                    "schema_version": requirement.schema_version,
                    "requirement_id": requirement.requirement_id,
                    "requirement_type": requirement.requirement_type,
                    "target": requirement.target,
                    "action_ids": list(requirement.action_ids),
                }
                for requirement in self.integration_requirements
            ],
        }
        return hashlib.sha256(_canonical_json(payload)).hexdigest()


@dataclass(frozen=True)
class ModelRole:
    """Logical execution role with bounded input and output, never a model pin."""

    role_id: str
    purpose: str
    max_input_bytes: int
    max_output_chars: int


@dataclass(frozen=True)
class ModelRoleProfile:
    """Versioned logical routing profile shared by harness adapters."""

    schema_version: int
    model_family_id: str
    profile_id: str
    roles: tuple[ModelRole, ...]


@dataclass(frozen=True)
class SkillPackHealth:
    ok: bool
    skill_count: int
    wrapper_count: int
    issues: tuple[str, ...]


def validate_model_role_profile(profile: ModelRoleProfile) -> None:
    if not isinstance(profile, ModelRoleProfile):
        raise SkillPackError("model role profile has an invalid type")
    _strict_int(
        profile.schema_version,
        label="model role profile schema_version",
        minimum=MODEL_PROFILE_SCHEMA_VERSION,
        maximum=MODEL_PROFILE_SCHEMA_VERSION,
    )
    if not isinstance(profile.model_family_id, str) or not _PROFILE_ID.fullmatch(
        profile.model_family_id
    ):
        raise SkillPackError("model role family id is invalid")
    if not isinstance(profile.profile_id, str) or not _PROFILE_ID.fullmatch(
        profile.profile_id
    ):
        raise SkillPackError("model role profile id is invalid")
    if not isinstance(profile.roles, tuple):
        raise SkillPackError("model roles must be a tuple")
    role_ids = tuple(
        role.role_id for role in profile.roles if isinstance(role, ModelRole)
    )
    if len(role_ids) != len(profile.roles) or role_ids != _MODEL_ROLES:
        raise SkillPackError("model role profile must contain the four logical roles")
    for role in profile.roles:
        _text(role.purpose, label=f"{role.role_id} purpose", maximum=240)
        _strict_int(
            role.max_input_bytes,
            label=f"{role.role_id} max_input_bytes",
            minimum=1,
            maximum=MAX_CONTEXT_BYTES,
        )
        _strict_int(
            role.max_output_chars,
            label=f"{role.role_id} max_output_chars",
            minimum=1,
            maximum=MAX_BODY_CHARS * 4,
        )


def validate_canonical_skill(skill: CanonicalSkill) -> None:
    if not isinstance(skill, CanonicalSkill):
        raise SkillPackError("canonical skill has an invalid type")
    _strict_int(
        skill.schema_version,
        label="skill schema_version",
        minimum=RESOURCE_SCHEMA_VERSION,
        maximum=RESOURCE_SCHEMA_VERSION,
    )
    if not _ID.fullmatch(skill.skill_id):
        raise SkillPackError("skill id is invalid")
    if skill.flow_id != skill.skill_id or not _ID.fullmatch(skill.flow_id):
        raise SkillPackError(f"{skill.skill_id} has an invalid flow id")
    if skill.resource_id != f"lifeos://skills/{skill.skill_id}/v1":
        raise SkillPackError(f"{skill.skill_id} has an invalid resource id")
    if skill.name != f"lifeos-{skill.skill_id}":
        raise SkillPackError(f"{skill.skill_id} has an invalid public name")
    _text(
        skill.description,
        label=f"{skill.skill_id} description",
        maximum=MAX_DESCRIPTION_CHARS,
    )
    _text(
        skill.body,
        label=f"{skill.skill_id} body",
        maximum=MAX_BODY_CHARS,
        allow_newlines=True,
    )
    if not isinstance(skill.routing, RoutingContract):
        raise SkillPackError(f"{skill.skill_id} routing has an invalid type")
    _strict_int(
        skill.routing.schema_version,
        label=f"{skill.skill_id} routing schema_version",
        minimum=ROUTING_SCHEMA_VERSION,
        maximum=ROUTING_SCHEMA_VERSION,
    )
    _ordered_unique_texts(
        skill.routing.choose_when,
        label=f"{skill.skill_id} choose_when",
        maximum_items=MAX_ROUTING_RULES,
        maximum_chars=MAX_ROUTING_RULE_CHARS,
    )
    _ordered_unique_texts(
        skill.routing.reject_when,
        label=f"{skill.skill_id} reject_when",
        maximum_items=MAX_ROUTING_RULES,
        maximum_chars=MAX_ROUTING_RULE_CHARS,
    )
    if not isinstance(skill.routing.ambiguity_with, tuple):
        raise SkillPackError(f"{skill.skill_id} ambiguity list must be a tuple")
    if len(set(skill.routing.ambiguity_with)) != len(skill.routing.ambiguity_with):
        raise SkillPackError(f"{skill.skill_id} ambiguity list contains duplicates")
    for other in skill.routing.ambiguity_with:
        if (
            not isinstance(other, str)
            or not _ID.fullmatch(other)
            or other == skill.skill_id
        ):
            raise SkillPackError(f"{skill.skill_id} ambiguity target is invalid")
    if not isinstance(skill.context, ContextBounds):
        raise SkillPackError(f"{skill.skill_id} context has an invalid type")
    _strict_int(
        skill.context.schema_version,
        label=f"{skill.skill_id} context schema_version",
        minimum=RESOURCE_SCHEMA_VERSION,
        maximum=RESOURCE_SCHEMA_VERSION,
    )
    _strict_int(
        skill.context.max_files,
        label=f"{skill.skill_id} max_files",
        minimum=1,
        maximum=MAX_CONTEXT_FILES,
    )
    _strict_int(
        skill.context.max_bytes,
        label=f"{skill.skill_id} max_bytes",
        minimum=1,
        maximum=MAX_CONTEXT_BYTES,
    )
    _strict_int(
        skill.context.max_items,
        label=f"{skill.skill_id} max_items",
        minimum=1,
        maximum=MAX_CONTEXT_ITEMS,
    )
    _ordered_unique_texts(
        skill.context.allowed_scopes,
        label=f"{skill.skill_id} allowed_scopes",
        maximum_items=MAX_CONTEXT_ITEMS,
        maximum_chars=MAX_ROUTING_RULE_CHARS,
    )
    if (
        not isinstance(skill.actions, tuple)
        or not 1 <= len(skill.actions) <= MAX_ACTIONS
    ):
        raise SkillPackError(f"{skill.skill_id} actions have an invalid bound")
    action_ids: list[str] = []
    for action in skill.actions:
        if not isinstance(action, ActionContract):
            raise SkillPackError(f"{skill.skill_id} action has an invalid type")
        _strict_int(
            action.schema_version,
            label=f"{skill.skill_id}/{action.action_id} schema_version",
            minimum=ACTION_SCHEMA_VERSION,
            maximum=ACTION_SCHEMA_VERSION,
        )
        for label, value in (
            ("action_id", action.action_id),
            ("actor", action.actor),
            ("authority", action.authority),
            ("access", action.access),
            ("target", action.target),
            ("effect_kind", action.effect_kind),
            ("retry_owner", action.retry_owner),
            ("rollback", action.rollback),
        ):
            _text(value, label=f"{skill.skill_id} {label}", maximum=160)
        if (
            type(action.artifact_commit) is not bool
            or type(action.irreversible) is not bool
        ):
            raise SkillPackError(
                f"{skill.skill_id}/{action.action_id} flags are invalid"
            )
        if not isinstance(action.crash_points, tuple) or not action.crash_points:
            raise SkillPackError(
                f"{skill.skill_id}/{action.action_id} crash points are invalid"
            )
        if len(set(action.crash_points)) != len(action.crash_points):
            raise SkillPackError(
                f"{skill.skill_id}/{action.action_id} crash points duplicate"
            )
        for crash_point in action.crash_points:
            _text(
                crash_point,
                label=f"{skill.skill_id}/{action.action_id} crash point",
                maximum=160,
            )
        action_ids.append(action.action_id)
    if len(set(action_ids)) != len(action_ids):
        raise SkillPackError(f"{skill.skill_id} action ids contain duplicates")
    artifact = skill.artifact_contract
    if not isinstance(artifact, ArtifactContract):
        raise SkillPackError(f"{skill.skill_id} artifact contract has an invalid type")
    _strict_int(
        artifact.schema_version,
        label=f"{skill.skill_id} artifact schema_version",
        minimum=ARTIFACT_SCHEMA_VERSION,
        maximum=ARTIFACT_SCHEMA_VERSION,
    )
    if artifact.contract_id != f"lifeos://artifacts/{skill.skill_id}/v1":
        raise SkillPackError(f"{skill.skill_id} artifact contract id is invalid")
    if artifact.flow_id != skill.flow_id or artifact.action_ids != tuple(action_ids):
        raise SkillPackError(f"{skill.skill_id} artifact action inventory is invalid")
    expected_commits = tuple(
        ArtifactCommit(
            action_id=action.action_id,
            authority=action.authority,
            target=action.target,
            effect_kind=action.effect_kind,
        )
        for action in skill.actions
        if action.artifact_commit
    )
    if artifact.commits != expected_commits:
        raise SkillPackError(f"{skill.skill_id} artifact commits are invalid")
    if skill.status not in {"available", "integration_required"}:
        raise SkillPackError(f"{skill.skill_id} status is invalid")
    requirements = skill.integration_requirements
    if not isinstance(requirements, tuple):
        raise SkillPackError(
            f"{skill.skill_id} integration requirements must be a tuple"
        )
    if skill.status == "available" and requirements:
        raise SkillPackError(f"{skill.skill_id} has spurious integration requirements")
    if skill.status == "integration_required" and not requirements:
        raise SkillPackError(f"{skill.skill_id} lacks an integration requirement")
    requirement_ids: set[str] = set()
    for requirement in requirements:
        if not isinstance(requirement, IntegrationRequirement):
            raise SkillPackError(
                f"{skill.skill_id} integration requirement type is invalid"
            )
        _strict_int(
            requirement.schema_version,
            label=f"{skill.skill_id} integration schema_version",
            minimum=RESOURCE_SCHEMA_VERSION,
            maximum=RESOURCE_SCHEMA_VERSION,
        )
        _text(
            requirement.requirement_id,
            label=f"{skill.skill_id} integration requirement id",
            maximum=96,
        )
        if requirement.requirement_id in requirement_ids:
            raise SkillPackError(f"{skill.skill_id} integration requirements duplicate")
        requirement_ids.add(requirement.requirement_id)
        if requirement.requirement_type not in {
            "flow-trajectory",
            "connector-route",
            "finalize-registration",
        }:
            raise SkillPackError(
                f"{skill.skill_id} integration requirement kind is invalid"
            )
        _text(
            requirement.target,
            label=f"{skill.skill_id} integration target",
            maximum=160,
        )
        if not isinstance(requirement.action_ids, tuple) or not requirement.action_ids:
            raise SkillPackError(f"{skill.skill_id} integration actions are invalid")
        if len(set(requirement.action_ids)) != len(requirement.action_ids):
            raise SkillPackError(f"{skill.skill_id} integration actions duplicate")
        if any(action_id not in action_ids for action_id in requirement.action_ids):
            raise SkillPackError(f"{skill.skill_id} integration action is not public")


def validate_skill_pack(
    skills: Iterable[CanonicalSkill],
    *,
    expected_ids: tuple[str, ...] | None = None,
) -> tuple[CanonicalSkill, ...]:
    if isinstance(skills, (str, bytes)):
        raise SkillPackError("skill pack must be an iterable of resources")
    pack = tuple(skills)
    for skill in pack:
        validate_canonical_skill(skill)
    skill_ids = tuple(skill.skill_id for skill in pack)
    if len(set(skill_ids)) != len(skill_ids):
        raise SkillPackError("skill pack contains duplicate ids")
    if expected_ids is not None and skill_ids != expected_ids:
        raise SkillPackError("skill inventory or order is invalid")
    by_id = {skill.skill_id: skill for skill in pack}
    for skill in pack:
        for other_id in skill.routing.ambiguity_with:
            if other_id not in by_id:
                raise SkillPackError(f"{skill.skill_id} ambiguity target is unknown")
            if skill.skill_id not in by_id[other_id].routing.ambiguity_with:
                raise SkillPackError(
                    f"{skill.skill_id} ambiguity relation is not symmetric"
                )
    return pack


def validate_score(value: object, *, label: str) -> float:
    if type(value) not in {int, float}:
        raise SkillPackError(f"{label} must be a finite score")
    score = float(value)
    if not math.isfinite(score) or not 0.0 <= score <= 1.0:
        raise SkillPackError(f"{label} must be in [0, 1]")
    return score


def validate_hash(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not _HASH.fullmatch(value):
        raise SkillPackError(f"{label} must be a SHA-256 digest")
    return value


def validate_versioned_symbolic_id(value: object, *, label: str) -> str:
    """Validate a bounded symbolic family or profile id without model literals."""

    if not isinstance(value, str) or not _PROFILE_ID.fullmatch(value):
        raise SkillPackError(f"{label} must be a versioned symbolic id")
    return value


__all__ = [
    "ACTION_SCHEMA_VERSION",
    "ARTIFACT_SCHEMA_VERSION",
    "ActionContract",
    "ArtifactCommit",
    "ArtifactContract",
    "CanonicalSkill",
    "ContextBounds",
    "EVAL_SCHEMA_VERSION",
    "IntegrationRequirement",
    "MAX_ACTIONS",
    "MAX_BODY_CHARS",
    "MAX_CONTEXT_BYTES",
    "MAX_CONTEXT_FILES",
    "MAX_CONTEXT_ITEMS",
    "MAX_DESCRIPTION_CHARS",
    "MAX_ROUTING_RULE_CHARS",
    "MAX_ROUTING_RULES",
    "MAX_STEERING_CHARS",
    "MODEL_PROFILE_SCHEMA_VERSION",
    "ModelRole",
    "ModelRoleProfile",
    "RESOURCE_SCHEMA_VERSION",
    "ROUTING_SCHEMA_VERSION",
    "RoutingContract",
    "SkillPackError",
    "SkillPackHealth",
    "validate_canonical_skill",
    "validate_hash",
    "validate_model_role_profile",
    "validate_score",
    "validate_skill_pack",
    "validate_versioned_symbolic_id",
]
