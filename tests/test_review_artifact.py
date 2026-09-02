"""P2-01 review artifact, mutation plan, and drift validation."""

from dataclasses import replace
import hashlib
import json
import unicodedata

import pytest

from tool_life_os_runtime.ext.review.artifact import (
    ApplicationEvidence,
    ApplyJournalEvidence,
    ApplyJournalOperation,
    MutationOperation,
    MutationPlan,
    Provenance,
    ReviewArtifact,
    ReviewArtifactError,
    ReviewDecision,
    SourceRef,
    apply_journal_sha256,
    mutation_plan_sha256,
    parse_mutation_plan,
    parse_review_artifact,
    provenance_sha256,
    render_mutation_plan,
    render_apply_journal,
    render_review_artifact,
    review_body_sha256,
    validate_artifact_plan,
    validate_apply_journal,
    validate_plan_binding,
)


SOURCE_REF = "machine/topics/portable/claims.json"
SOURCE_HASH = hashlib.sha256(b"synthetic source").hexdigest()
PREIMAGE_HASH = hashlib.sha256(b"old knowledge\n").hexdigest()
BODY = "# Portable proposal\n\nApply the evidence-backed update.\n"
CONTENT = "# Portable knowledge\n\nA deterministic gate protects mutation.\n"


def artifact(**changes: object) -> ReviewArtifact:
    value = ReviewArtifact(
        schema_version=1,
        review_id="rev_portable-001",
        status="proposed",
        flow="distill",
        created_at="2026-01-15T10:00:00Z",
        surface="gated",
        sources=(SourceRef(kind="llmwiki-topic", ref=SOURCE_REF),),
        provenance=Provenance(
            run_id="run_portable-001",
            source_hashes=((SOURCE_REF, SOURCE_HASH),),
        ),
        plan_path=".lifeos/review-plans/rev_portable-001.json",
        body=BODY,
    )
    return replace(value, **changes)


def plan(
    source: ReviewArtifact | None = None, *, content: str = CONTENT
) -> MutationPlan:
    source = source or artifact()
    return MutationPlan(
        schema_version=1,
        review_id=source.review_id,
        review_body_sha256=review_body_sha256(source.body),
        provenance_sha256=provenance_sha256(source.provenance),
        operations=(
            MutationOperation(
                op="update",
                path="knowledge/domains/ai/portable.md",
                destination_path=None,
                source_refs=(SOURCE_REF,),
                precondition_sha256=PREIMAGE_HASH,
                postcondition_sha256=hashlib.sha256(content.encode()).hexdigest(),
                content=content,
            ),
        ),
    )


def move_operation(path: str, destination: str, *, sequence: int = 0) -> MutationOperation:
    digest = hashlib.sha256(f"move-{sequence}".encode()).hexdigest()
    return MutationOperation(
        op="move",
        path=path,
        destination_path=destination,
        source_refs=(SOURCE_REF,),
        precondition_sha256=digest,
        postcondition_sha256=digest,
        content=None,
    )


def journal(
    review: ReviewArtifact, mutation: MutationPlan
) -> ApplyJournalEvidence:
    operation = mutation.operations[0]
    return ApplyJournalEvidence(
        schema_version=1,
        journal_id="apply_portable-001",
        review_id=review.review_id,
        plan_sha256=mutation_plan_sha256(mutation),
        status="committed",
        committed_at="2026-01-15T12:00:00Z",
        operations=(
            ApplyJournalOperation(
                sequence=1,
                op=operation.op,
                path=operation.path,
                destination_path=operation.destination_path,
                precondition_sha256=operation.precondition_sha256,
                postcondition_sha256=operation.postcondition_sha256,
                status="committed",
            ),
        ),
    )


def test_artifact_and_plan_round_trip_canonically() -> None:
    review = artifact()
    mutation = plan(review)

    artifact_raw = render_review_artifact(review)
    plan_raw = render_mutation_plan(mutation)

    assert parse_review_artifact(artifact_raw) == review
    assert parse_mutation_plan(plan_raw) == mutation
    assert plan_raw == render_mutation_plan(parse_mutation_plan(plan_raw))
    assert validate_artifact_plan(review, mutation) == mutation_plan_sha256(mutation)
    assert plan_raw.endswith(b"\n")
    assert b" \n" not in plan_raw


def test_plan_requires_exact_provenance_and_source_coverage() -> None:
    review = artifact()
    mutation = plan(review)
    changed_provenance = replace(
        review,
        provenance=Provenance(
            run_id=review.provenance.run_id,
            source_hashes=((SOURCE_REF, "0" * 64),),
        ),
    )
    with pytest.raises(ReviewArtifactError, match="provenance changed"):
        validate_plan_binding(changed_provenance, mutation)

    missing_ref = replace(
        mutation,
        operations=(replace(mutation.operations[0], source_refs=("other/source",)),),
    )
    with pytest.raises(ReviewArtifactError, match="exactly cover"):
        validate_plan_binding(review, missing_ref)


def test_prose_change_fails_closed_against_plan() -> None:
    review = artifact()
    mutation = plan(review)

    with pytest.raises(ReviewArtifactError, match="prose changed"):
        validate_plan_binding(replace(review, body=review.body + "Changed.\n"), mutation)


def test_operation_hash_and_status_evidence_fail_closed() -> None:
    mutation = plan()
    payload = json.loads(render_mutation_plan(mutation))
    payload["operations"][0]["postcondition_sha256"] = "0" * 64
    with pytest.raises(ReviewArtifactError, match="exact content"):
        parse_mutation_plan(json.dumps(payload))

    proposed = render_review_artifact(artifact())
    invalid = proposed.replace('status: "proposed"', 'status: "approved"')
    with pytest.raises(ReviewArtifactError, match="decision evidence"):
        parse_review_artifact(invalid)

    missing_provenance = "\n".join(
        line for line in proposed.splitlines() if not line.startswith("provenance: ")
    )
    with pytest.raises(ReviewArtifactError, match="missing or unknown"):
        parse_review_artifact(missing_provenance)


@pytest.mark.parametrize(
    "raw",
    [
        b"{\"schema_version\":1,\"schema_version\":1}",
        b"[" * 1500 + b"]" * 1500,
        b"\xff\xfe",
        b"x" * (512 * 1024 + 1),
        "\ud800",
    ],
)
def test_plan_decoder_is_bounded_and_adversarial_input_is_normalized(raw) -> None:
    with pytest.raises(ReviewArtifactError):
        parse_mutation_plan(raw)


def test_artifact_decoder_is_bounded_and_does_not_echo_secret_field() -> None:
    with pytest.raises(ReviewArtifactError, match="too large"):
        parse_review_artifact(b"x" * (256 * 1024 + 1))

    raw = render_review_artifact(artifact()).replace(
        'decisions: []', 'api_token: "sensitive-test-value"'
    )
    with pytest.raises(ReviewArtifactError) as captured:
        parse_review_artifact(raw)
    assert "sensitive-test-value" not in str(captured.value)
    assert "api_token" not in str(captured.value)


def test_private_absolute_source_refs_and_unsafe_plan_paths_are_rejected() -> None:
    private = "/" + "Users" + "/person/knowledge.md"
    review = artifact(
        sources=(SourceRef(kind="vault-note", ref=private),),
        provenance=Provenance(
            run_id="run_portable-001",
            source_hashes=((private, SOURCE_HASH),),
        ),
    )
    with pytest.raises(ReviewArtifactError, match="private path"):
        render_review_artifact(review)

    mutation = plan()
    escaped = replace(
        mutation,
        operations=(
            replace(mutation.operations[0], path="knowledge/../private.md"),
        ),
    )
    with pytest.raises(ReviewArtifactError, match="safe relative"):
        render_mutation_plan(escaped)


@pytest.mark.parametrize(
    "unsafe_ref",
    [
        "machine/./topics/portable.json",
        "machine//topics/portable.json",
        "machine/topics/portable.json/",
        unicodedata.normalize("NFD", "machine/topics/café.json"),
    ],
)
def test_logical_and_path_refs_require_canonical_posix_nfc(unsafe_ref) -> None:
    review = artifact(
        sources=(SourceRef(kind="llmwiki-topic", ref=unsafe_ref),),
        provenance=Provenance(
            run_id="run_portable-001",
            source_hashes=((unsafe_ref, SOURCE_HASH),),
        ),
    )
    with pytest.raises(ReviewArtifactError, match="canonical"):
        render_review_artifact(review)


def test_plan_rejects_dot_alias_and_parent_file_namespace_collisions() -> None:
    mutation = plan()
    dot_alias = replace(
        mutation,
        operations=(
            mutation.operations[0],
            replace(
                mutation.operations[0],
                path="knowledge/domains/ai/./portable.md",
            ),
        ),
    )
    with pytest.raises(ReviewArtifactError, match="canonical POSIX"):
        render_mutation_plan(dot_alias)

    parent_collision = replace(
        mutation,
        operations=(
            replace(mutation.operations[0], path="knowledge/collision.md"),
            replace(
                mutation.operations[0],
                path="knowledge/collision.md/child.md",
            ),
        ),
    )
    with pytest.raises(ReviewArtifactError, match="parent/file"):
        render_mutation_plan(parent_collision)

    nfd_path = unicodedata.normalize("NFD", "knowledge/domains/café.md")
    with pytest.raises(ReviewArtifactError, match="Unicode NFC"):
        render_mutation_plan(
            replace(
                mutation,
                operations=(replace(mutation.operations[0], path=nfd_path),),
            )
        )
    nfc_path = unicodedata.normalize("NFC", "knowledge/domains/café.md")
    assert parse_mutation_plan(
        render_mutation_plan(
            replace(
                mutation,
                operations=(replace(mutation.operations[0], path=nfc_path),),
            )
        )
    ).operations[0].path == nfc_path


def test_portable_namespace_rejects_casefold_source_source_aliases() -> None:
    mutation = plan()
    aliased = replace(
        mutation,
        operations=(
            replace(mutation.operations[0], path="knowledge/Case.md"),
            replace(mutation.operations[0], path="knowledge/case.md"),
        ),
    )
    with pytest.raises(ReviewArtifactError, match="case-insensitive"):
        render_mutation_plan(aliased)


def test_portable_namespace_rejects_destination_and_cross_aliases() -> None:
    mutation = plan()
    destination_alias = replace(
        mutation,
        operations=(
            move_operation(
                "knowledge/source-one.md", "knowledge/archive/Case.md", sequence=1
            ),
            move_operation(
                "knowledge/source-two.md", "knowledge/archive/case.md", sequence=2
            ),
        ),
    )
    with pytest.raises(ReviewArtifactError, match="case-insensitive"):
        render_mutation_plan(destination_alias)

    source_destination_alias = replace(
        mutation,
        operations=(
            replace(mutation.operations[0], path="knowledge/Case.md"),
            move_operation(
                "knowledge/other.md", "knowledge/case.md", sequence=3
            ),
        ),
    )
    with pytest.raises(ReviewArtifactError, match="case-insensitive"):
        render_mutation_plan(source_destination_alias)


def test_source_refs_reject_unicode_casefold_aliases_but_preserve_single_spelling() -> None:
    first = "machine/topics/Straße.json"
    second = "machine/topics/STRASSE.json"
    aliased = artifact(
        sources=(
            SourceRef(kind="llmwiki-topic", ref=first),
            SourceRef(kind="llmwiki-topic", ref=second),
        ),
        provenance=Provenance(
            run_id="run_portable-001",
            source_hashes=((first, SOURCE_HASH), (second, "1" * 64)),
        ),
    )
    with pytest.raises(ReviewArtifactError, match="case-insensitive"):
        render_review_artifact(aliased)
    with pytest.raises(ReviewArtifactError, match="case-insensitive"):
        provenance_sha256(aliased.provenance)

    mutation = plan()
    original = "knowledge/Domains/Case.md"
    round_trip = parse_mutation_plan(
        render_mutation_plan(
            replace(
                mutation,
                operations=(replace(mutation.operations[0], path=original),),
            )
        )
    )
    assert round_trip.operations[0].path == original


def test_apply_journal_rejects_casefold_namespace_aliases() -> None:
    review = artifact()
    mutation = plan(review)
    evidence = journal(review, mutation)
    first = replace(
        evidence.operations[0], sequence=1, path="knowledge/Journal.md"
    )
    second = replace(
        evidence.operations[0], sequence=2, path="knowledge/journal.md"
    )
    with pytest.raises(ReviewArtifactError, match="case-insensitive"):
        render_apply_journal(replace(evidence, operations=(first, second)))


@pytest.mark.parametrize("schema_version", [True, 1.0, "1"])
def test_schema_versions_require_exact_integer(schema_version) -> None:
    payload = json.loads(render_mutation_plan(plan()))
    payload["schema_version"] = schema_version
    with pytest.raises(ReviewArtifactError, match="schema_version"):
        parse_mutation_plan(json.dumps(payload))


def test_decision_history_rejects_transition_after_supersede() -> None:
    mutation = plan()
    first = ReviewDecision(
        schema_version=1,
        sequence=1,
        action="supersede",
        actor="human-owner",
        at="2026-01-15T11:00:00Z",
        plan_sha256=mutation_plan_sha256(mutation),
        superseded_by="rev_replacement-001",
    )
    impossible = ReviewDecision(
        schema_version=1,
        sequence=2,
        action="approve",
        actor="human-owner",
        at="2026-01-15T12:00:00Z",
        plan_sha256=mutation_plan_sha256(mutation),
    )
    with pytest.raises(ReviewArtifactError, match="invalid transition"):
        render_review_artifact(
            artifact(status="approved", decisions=(first, impossible))
        )


def test_applied_status_requires_plan_bound_journal_evidence() -> None:
    mutation = plan()
    approval = ReviewDecision(
        schema_version=1,
        sequence=1,
        action="approve",
        actor="human-owner",
        at="2026-01-15T11:00:00Z",
        plan_sha256=mutation_plan_sha256(mutation),
    )
    with pytest.raises(ReviewArtifactError, match="application evidence"):
        render_review_artifact(
            artifact(status="applied", decisions=(approval,))
        )

    review = artifact()
    evidence = journal(review, mutation)
    applied = artifact(
        status="applied",
        decisions=(approval,),
        application=ApplicationEvidence(
            schema_version=1,
            applied_at="2026-01-15T12:00:00Z",
            plan_sha256=mutation_plan_sha256(mutation),
            journal_id=evidence.journal_id,
            journal_sha256=apply_journal_sha256(evidence),
        ),
    )
    with pytest.raises(ReviewArtifactError, match="supplied apply journal"):
        validate_artifact_plan(applied, mutation)
    assert validate_artifact_plan(
        applied, mutation, apply_journal=render_apply_journal(evidence)
    ) == mutation_plan_sha256(mutation)
    assert validate_apply_journal(applied, mutation, evidence) == evidence


def test_forged_or_mismatched_journal_cannot_self_assert_application() -> None:
    review = artifact()
    mutation = plan(review)
    evidence = journal(review, mutation)
    approval = ReviewDecision(
        schema_version=1,
        sequence=1,
        action="approve",
        actor="human-owner",
        at="2026-01-15T11:00:00Z",
        plan_sha256=mutation_plan_sha256(mutation),
    )
    application = ApplicationEvidence(
        schema_version=1,
        applied_at=evidence.committed_at,
        plan_sha256=mutation_plan_sha256(mutation),
        journal_id=evidence.journal_id,
        journal_sha256=apply_journal_sha256(evidence),
    )
    applied = artifact(
        status="applied", decisions=(approval,), application=application
    )

    mismatched = replace(evidence, committed_at="2026-01-15T12:01:00Z")
    with pytest.raises(ReviewArtifactError, match="does not hash"):
        validate_artifact_plan(applied, mutation, apply_journal=mismatched)

    forged_operation = replace(
        evidence.operations[0], path="knowledge/domains/ai/forged.md"
    )
    forged = replace(evidence, operations=(forged_operation,))
    self_asserted = replace(
        applied,
        application=replace(
            application, journal_sha256=apply_journal_sha256(forged)
        ),
    )
    with pytest.raises(ReviewArtifactError, match="does not match the mutation plan"):
        validate_artifact_plan(self_asserted, mutation, apply_journal=forged)

    pretty = json.dumps(json.loads(render_apply_journal(evidence)), indent=2) + "\n"
    with pytest.raises(ReviewArtifactError, match="canonical JSON"):
        validate_artifact_plan(applied, mutation, apply_journal=pretty)

    changed = plan(review, content="# A changed approved target\n")
    changed_evidence = journal(review, changed)
    stale_approval = replace(
        applied,
        application=replace(
            application,
            journal_id=changed_evidence.journal_id,
            journal_sha256=apply_journal_sha256(changed_evidence),
        ),
    )
    with pytest.raises(ReviewArtifactError, match="approval do not bind"):
        validate_apply_journal(stale_approval, changed, changed_evidence)
