"""Explicit human review decisions bound to the current canonical plan."""

from __future__ import annotations

from dataclasses import replace

from tool_life_os_runtime.ext.review.artifact import (
    DECISION_SCHEMA_VERSION,
    MutationPlan,
    ReviewArtifact,
    ReviewDecision,
    validate_artifact_plan,
    validate_plan_binding,
)
from tool_life_os_runtime.ext.review.authority import (
    ActionCapability,
    AuthorityError,
    AuthorityPolicy,
)


_DECISION_GRANT = {
    "flow_id": "review-decision",
    "action_id": "record-approve-reject-or-supersede",
    "actor": "human",
    "authority": "domain-write",
    "target": "vault:review",
}

_TRANSITIONS: dict[str, frozenset[str]] = {
    "proposed": frozenset({"approve", "reject", "supersede"}),
    "approved": frozenset({"approve", "reject", "supersede"}),
    "rejected": frozenset({"approve", "supersede"}),
    "applied": frozenset(),
    "superseded": frozenset(),
}

_STATUS_FOR_ACTION = {
    "approve": "approved",
    "reject": "rejected",
    "supersede": "superseded",
}


class ReviewDecisionError(ValueError):
    """A human decision is unauthorized, stale, or an invalid transition."""


def _fail(message: str) -> None:
    raise ReviewDecisionError(message)


def _require_decision_capability(
    capability: ActionCapability, policy: AuthorityPolicy
) -> None:
    if not isinstance(policy, AuthorityPolicy):
        _fail("review decision requires its issuing authority policy")
    try:
        grant = policy.require(capability)
    except AuthorityError as error:
        raise ReviewDecisionError(str(error)) from None
    for field, expected in _DECISION_GRANT.items():
        if getattr(grant, field) != expected:
            _fail("capability does not authorize a human review decision")
    if grant.access != "write" or not grant.artifact_commit:
        _fail("capability does not authorize a review artifact commit")


def record_decision(
    artifact: ReviewArtifact,
    plan: MutationPlan,
    *,
    action: str,
    actor: str,
    at: str,
    capability: ActionCapability,
    policy: AuthorityPolicy,
    superseded_by: str | None = None,
) -> ReviewArtifact:
    """Append one authorized decision against the exact current plan hash.

    An ``approved`` artifact may receive another ``approve`` only when the
    plan changed after the previous approval.  That explicit re-approval is
    what makes the changed plan eligible for apply again.
    """

    _require_decision_capability(capability, policy)
    if not isinstance(action, str):
        _fail("review decision action must be text")
    allowed = _TRANSITIONS.get(artifact.status)
    if allowed is None or action not in allowed:
        _fail("review decision transition is not allowed")
    plan_hash = validate_plan_binding(artifact, plan)
    if action != "supersede" and superseded_by is not None:
        _fail("only supersede may name a replacement review")
    if action == "supersede" and superseded_by is None:
        _fail("supersede requires an explicit replacement review id")
    if (
        action == "approve"
        and artifact.status == "approved"
        and artifact.decisions
        and artifact.decisions[-1].plan_sha256 == plan_hash
    ):
        _fail("current plan is already approved")

    decision = ReviewDecision(
        schema_version=DECISION_SCHEMA_VERSION,
        sequence=len(artifact.decisions) + 1,
        action=action,
        actor=actor,
        at=at,
        plan_sha256=plan_hash,
        superseded_by=superseded_by,
    )
    updated = replace(
        artifact,
        status=_STATUS_FOR_ACTION[action],
        decisions=artifact.decisions + (decision,),
    )
    # The artifact parser validates bounded actor/timestamp/replacement fields,
    # sequence, status and decision-history agreement.  The cross-validator
    # then proves that the just-recorded decision binds this exact plan.
    validate_artifact_plan(updated, plan)
    return updated


def require_current_approval(
    artifact: ReviewArtifact, plan: MutationPlan
) -> ReviewDecision:
    """Return approval evidence only for an explicitly approved current plan."""

    if artifact.status != "approved":
        _fail("review is not approved")
    validate_artifact_plan(artifact, plan)
    if not artifact.decisions or artifact.decisions[-1].action != "approve":
        _fail("review lacks explicit approval evidence")
    return artifact.decisions[-1]
