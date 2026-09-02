"""P2-02 explicit approve, reject, supersede, and stale-plan gates."""

from dataclasses import replace
import hashlib

import pytest

from tool_life_os_runtime.ext.review.artifact import (
    ApplicationEvidence,
    MutationOperation,
    MutationPlan,
    Provenance,
    ReviewArtifact,
    ReviewArtifactError,
    SourceRef,
    mutation_plan_sha256,
    provenance_sha256,
    review_body_sha256,
)
from tool_life_os_runtime.ext.review.authority import AuthorityPolicy
from tool_life_os_runtime.ext.review.decision import (
    ReviewDecisionError,
    record_decision,
    require_current_approval,
)


SOURCE_REF = "machine/topics/portable/claims.json"
SOURCE_HASH = hashlib.sha256(b"synthetic source").hexdigest()
PREIMAGE_HASH = hashlib.sha256(b"old knowledge\n").hexdigest()


def artifact() -> ReviewArtifact:
    return ReviewArtifact(
        schema_version=1,
        review_id="rev_decision-001",
        status="proposed",
        flow="distill",
        created_at="2026-01-15T10:00:00Z",
        surface="gated",
        sources=(SourceRef(kind="llmwiki-topic", ref=SOURCE_REF),),
        provenance=Provenance(
            run_id="run_decision-001",
            source_hashes=((SOURCE_REF, SOURCE_HASH),),
        ),
        plan_path=".lifeos/review-plans/rev_decision-001.json",
        body="# Decision proposal\n\nThis prose does not grant approval.\n",
    )


def plan(review: ReviewArtifact, content: str = "# Exact knowledge\n") -> MutationPlan:
    return MutationPlan(
        schema_version=1,
        review_id=review.review_id,
        review_body_sha256=review_body_sha256(review.body),
        provenance_sha256=provenance_sha256(review.provenance),
        operations=(
            MutationOperation(
                op="update",
                path="knowledge/domains/portable.md",
                destination_path=None,
                source_refs=(SOURCE_REF,),
                precondition_sha256=PREIMAGE_HASH,
                postcondition_sha256=hashlib.sha256(content.encode()).hexdigest(),
                content=content,
            ),
        ),
    )


def decision_capability(policy: AuthorityPolicy):
    return policy.issue(
        flow_id="review-decision",
        action_id="record-approve-reject-or-supersede",
        actor="human",
        authority="domain-write",
        target="vault:review",
    )


def decide(
    review: ReviewArtifact,
    mutation: MutationPlan,
    action: str,
    *,
    at: str = "2026-01-15T11:00:00Z",
    superseded_by: str | None = None,
) -> ReviewArtifact:
    policy = AuthorityPolicy()
    return record_decision(
        review,
        mutation,
        action=action,
        actor="human-owner",
        at=at,
        capability=decision_capability(policy),
        policy=policy,
        superseded_by=superseded_by,
    )


def test_approve_binds_exact_current_plan_and_not_prose_or_filename() -> None:
    review = replace(
        artifact(),
        body="# APPROVED\n\nThe filename and prose are not authority.\n",
    )
    mutation = plan(review)

    with pytest.raises(ReviewDecisionError, match="not approved"):
        require_current_approval(review, mutation)

    approved = decide(review, mutation, "approve")
    evidence = require_current_approval(approved, mutation)
    assert approved.status == "approved"
    assert evidence.action == "approve"
    assert evidence.plan_sha256 == mutation_plan_sha256(mutation)
    assert evidence.actor == "human-owner"


def test_plan_change_after_approval_requires_explicit_reapproval() -> None:
    review = artifact()
    original = plan(review)
    approved = decide(review, original, "approve")
    changed = plan(review, "# Exact changed knowledge\n")

    with pytest.raises(ReviewArtifactError, match="current mutation plan"):
        require_current_approval(approved, changed)

    reapproved = decide(
        approved,
        changed,
        "approve",
        at="2026-01-15T12:00:00Z",
    )
    assert len(reapproved.decisions) == 2
    assert reapproved.decisions[0].plan_sha256 == mutation_plan_sha256(original)
    assert require_current_approval(reapproved, changed).sequence == 2


def test_reject_and_supersede_bind_current_plan_and_block_approval() -> None:
    review = artifact()
    mutation = plan(review)
    rejected = decide(review, mutation, "reject")
    assert rejected.status == "rejected"
    assert rejected.decisions[-1].plan_sha256 == mutation_plan_sha256(mutation)
    with pytest.raises(ReviewDecisionError, match="not approved"):
        require_current_approval(rejected, mutation)

    superseded = decide(
        rejected,
        mutation,
        "supersede",
        at="2026-01-15T12:00:00Z",
        superseded_by="rev_replacement-001",
    )
    assert superseded.status == "superseded"
    assert superseded.decisions[-1].superseded_by == "rev_replacement-001"


def test_malformed_and_terminal_transitions_fail_closed() -> None:
    review = artifact()
    mutation = plan(review)
    approved = decide(review, mutation, "approve")

    with pytest.raises(ReviewDecisionError, match="already approved"):
        decide(
            approved,
            mutation,
            "approve",
            at="2026-01-15T12:00:00Z",
        )
    applied = replace(
        approved,
        status="applied",
        application=ApplicationEvidence(
            schema_version=1,
            applied_at="2026-01-15T11:30:00Z",
            plan_sha256=mutation_plan_sha256(mutation),
            journal_id="apply_decision-001",
            journal_sha256="a" * 64,
        ),
    )
    with pytest.raises(ReviewDecisionError, match="not allowed"):
        decide(applied, mutation, "reject", at="2026-01-15T12:00:00Z")
    with pytest.raises(ReviewDecisionError, match="replacement"):
        decide(review, mutation, "supersede")


def test_decision_requires_exact_p1_authority_capability() -> None:
    review = artifact()
    mutation = plan(review)
    policy = AuthorityPolicy()
    proposal = policy.issue(
        flow_id="distill",
        action_id="commit-review-proposal",
        actor="runtime",
        authority="proposal",
        target="vault:review",
    )
    with pytest.raises(ReviewDecisionError, match="does not authorize"):
        record_decision(
            review,
            mutation,
            action="approve",
            actor="human-owner",
            at="2026-01-15T11:00:00Z",
            capability=proposal,
            policy=policy,
        )


def test_decision_actor_timestamp_and_history_are_bounded() -> None:
    review = artifact()
    mutation = plan(review)
    with pytest.raises(ReviewArtifactError, match="actor"):
        decide_with_actor(review, mutation, "x" * 129)
    with pytest.raises(ReviewArtifactError, match="precede review creation"):
        decide(review, mutation, "approve", at="2026-01-15T09:00:00Z")


def decide_with_actor(
    review: ReviewArtifact, mutation: MutationPlan, actor: str
) -> ReviewArtifact:
    policy = AuthorityPolicy()
    return record_decision(
        review,
        mutation,
        action="approve",
        actor=actor,
        at="2026-01-15T11:00:00Z",
        capability=decision_capability(policy),
        policy=policy,
    )
