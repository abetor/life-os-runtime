"""P2-03 atomic approved knowledge apply and crash reconciliation."""

from __future__ import annotations

from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import shutil

import pytest

from tool_life_os_runtime.ext.review.apply import ApplyCrash, ApplyError, AtomicApply
from tool_life_os_runtime.ext.review.apply import transaction as apply_module
from tool_life_os_runtime.ext.review.artifact import (
    MutationOperation,
    MutationPlan,
    Provenance,
    ReviewArtifact,
    SourceRef,
    apply_journal_sha256,
    mutation_plan_sha256,
    provenance_sha256,
    review_body_sha256,
    validate_artifact_plan,
)
from tool_life_os_runtime.ext.review.authority import AuthorityPolicy
from tool_life_os_runtime.ext.review.decision import record_decision
from tool_life_os_runtime.ext.vault.config import load_vault_config
from tool_life_os_runtime.ext.vault.schema import VaultPathResolver


FIXTURE = Path(__file__).parent / "fixtures/vault-minimal"
SOURCE_REF = "machine/topics/apply/claims.json"
SOURCE_HASH = hashlib.sha256(b"synthetic apply source").hexdigest()
COMMITTED_AT = "2026-01-15T12:00:00Z"


def _digest(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def _vault(tmp_path: Path) -> tuple[Path, VaultPathResolver]:
    root = tmp_path / "vault"
    shutil.copytree(FIXTURE, root)
    (root / "knowledge/_archive").mkdir()
    return root, VaultPathResolver(root, load_vault_config(root))


def _artifact() -> ReviewArtifact:
    return ReviewArtifact(
        schema_version=1,
        review_id="rev_apply-001",
        status="proposed",
        flow="distill",
        created_at="2026-01-15T10:00:00Z",
        surface="gated",
        sources=(SourceRef(kind="llmwiki-topic", ref=SOURCE_REF),),
        provenance=Provenance(
            run_id="run_apply-001",
            source_hashes=((SOURCE_REF, SOURCE_HASH),),
        ),
        plan_path=".lifeos/review-plans/rev_apply-001.json",
        body="# Apply proposal\n\nExact protected changes.\n",
    )


def _operation(
    op: str,
    path: str,
    *,
    old: bytes | None = None,
    new: str | None = None,
    destination: str | None = None,
) -> MutationOperation:
    if op in {"move", "archive"}:
        assert old is not None
        post = _digest(old)
        content = None
    else:
        assert new is not None
        post = _digest(new)
        content = new
    return MutationOperation(
        op=op,
        path=path,
        destination_path=destination,
        source_refs=(SOURCE_REF,),
        precondition_sha256=None if op == "create" else _digest(old or b""),
        postcondition_sha256=post,
        content=content,
    )


def _plan(
    artifact: ReviewArtifact, operations: tuple[MutationOperation, ...]
) -> MutationPlan:
    return MutationPlan(
        schema_version=1,
        review_id=artifact.review_id,
        review_body_sha256=review_body_sha256(artifact.body),
        provenance_sha256=provenance_sha256(artifact.provenance),
        operations=operations,
    )


def _approved(
    artifact: ReviewArtifact, plan: MutationPlan, policy: AuthorityPolicy
) -> ReviewArtifact:
    capability = policy.issue(
        flow_id="review-decision",
        action_id="record-approve-reject-or-supersede",
        actor="human",
        authority="domain-write",
        target="vault:review",
    )
    return record_decision(
        artifact,
        plan,
        action="approve",
        actor="human-owner",
        at="2026-01-15T11:00:00Z",
        capability=capability,
        policy=policy,
    )


def _apply_capability(policy: AuthorityPolicy):
    return policy.issue(
        flow_id="apply",
        action_id="commit-approved-knowledge",
        actor="runtime-human-approved",
        authority="protected-write",
        target="vault:knowledge",
    )


def _service(
    resolver: VaultPathResolver,
) -> tuple[AtomicApply, AuthorityPolicy, object]:
    policy = AuthorityPolicy()
    service = AtomicApply(resolver, policy)
    return service, policy, _apply_capability(policy)


def _snapshot(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file() and not path.is_symlink()
    }


def _two_operation_case(
    tmp_path: Path,
) -> tuple[Path, AtomicApply, object, ReviewArtifact, MutationPlan]:
    root, resolver = _vault(tmp_path)
    old = b"old first\n"
    (root / "knowledge/first.md").write_bytes(old)
    service, policy, capability = _service(resolver)
    artifact = _artifact()
    plan = _plan(
        artifact,
        (
            _operation(
                "update",
                "knowledge/first.md",
                old=old,
                new="new first\n",
            ),
            _operation("create", "knowledge/second.md", new="new second\n"),
        ),
    )
    return root, service, capability, _approved(artifact, plan, policy), plan


def test_create_update_move_archive_commit_and_finalize(tmp_path: Path) -> None:
    root, resolver = _vault(tmp_path)
    update_old = b"update old\n"
    move_old = b"move old\n"
    archive_old = b"archive old\n"
    (root / "knowledge/update.md").write_bytes(update_old)
    (root / "knowledge/move.md").write_bytes(move_old)
    (root / "knowledge/archive.md").write_bytes(archive_old)
    service, policy, capability = _service(resolver)
    artifact = _artifact()
    plan = _plan(
        artifact,
        (
            _operation(
                "update",
                "knowledge/update.md",
                old=update_old,
                new="update new\n",
            ),
            _operation("create", "knowledge/create.md", new="create new\n"),
            _operation(
                "move",
                "knowledge/move.md",
                old=move_old,
                destination="knowledge/moved.md",
            ),
            _operation(
                "archive",
                "knowledge/archive.md",
                old=archive_old,
                destination="knowledge/_archive/archive.md",
            ),
        ),
    )
    approved = _approved(artifact, plan, policy)

    preview = service.dry_run(approved, plan, capability=capability)
    prepared = service.prepare(
        approved,
        plan,
        journal_id="apply_all-001",
        committed_at=COMMITTED_AT,
        capability=capability,
    )
    committed = service.commit(
        approved,
        plan,
        journal_id=prepared.journal_id,
        capability=capability,
    )
    applied = service.finalize(
        approved, plan, committed, capability=capability
    )

    assert preview.status == "ready"
    assert preview.plan_sha256 == mutation_plan_sha256(plan)
    assert prepared.status == "prepared"
    assert committed.status == "committed"
    assert all(operation.status == "committed" for operation in committed.operations)
    assert (root / "knowledge/update.md").read_bytes() == b"update new\n"
    assert (root / "knowledge/create.md").read_bytes() == b"create new\n"
    assert not (root / "knowledge/move.md").exists()
    assert (root / "knowledge/moved.md").read_bytes() == move_old
    assert not (root / "knowledge/archive.md").exists()
    assert (root / "knowledge/_archive/archive.md").read_bytes() == archive_old
    assert not list((root / "knowledge").rglob(".lifeos-apply-*"))
    assert applied.status == "applied"
    assert applied.application is not None
    assert applied.application.journal_sha256 == apply_journal_sha256(committed)
    assert validate_artifact_plan(applied, plan, apply_journal=committed)


@pytest.mark.parametrize(
    "seam",
    [
        "before-first-replace",
        "between-replaces",
        "after-all-replaces-before-journal-committed",
        "after-journal-before-review-finalization",
    ],
)
def test_every_commit_crash_seam_reconciles_to_exact_old_or_new(
    tmp_path: Path, seam: str
) -> None:
    root, service, capability, approved, plan = _two_operation_case(tmp_path)
    service.prepare(
        approved,
        plan,
        journal_id="apply_crash-001",
        committed_at=COMMITTED_AT,
        capability=capability,
    )

    with pytest.raises(ApplyCrash):
        service.commit(
            approved,
            plan,
            journal_id="apply_crash-001",
            capability=capability,
            crash_at=seam,
        )

    reconciled = service.reconcile(
        approved,
        plan,
        journal_id="apply_crash-001",
        capability=capability,
    )
    if seam == "after-journal-before-review-finalization":
        assert reconciled.status == "committed"
        assert (root / "knowledge/first.md").read_bytes() == b"new first\n"
        assert (root / "knowledge/second.md").read_bytes() == b"new second\n"
    else:
        assert reconciled.status == "rolled_back"
        assert (root / "knowledge/first.md").read_bytes() == b"old first\n"
        assert not (root / "knowledge/second.md").exists()
    assert not list((root / "knowledge").rglob(".lifeos-apply-*"))


def test_forward_retry_and_prepare_retry_are_byte_idempotent(tmp_path: Path) -> None:
    root, service, capability, approved, plan = _two_operation_case(tmp_path)
    prepared = service.prepare(
        approved,
        plan,
        journal_id="apply_retry-001",
        committed_at=COMMITTED_AT,
        capability=capability,
    )
    assert service.prepare(
        approved,
        plan,
        journal_id="apply_retry-001",
        committed_at=COMMITTED_AT,
        capability=capability,
    ) == prepared
    committed = service.commit(
        approved,
        plan,
        journal_id="apply_retry-001",
        capability=capability,
    )
    after = _snapshot(root)

    assert service.commit(
        approved,
        plan,
        journal_id="apply_retry-001",
        capability=capability,
    ) == committed
    assert service.prepare(
        approved,
        plan,
        journal_id="apply_retry-001",
        committed_at=COMMITTED_AT,
        capability=capability,
    ) == committed
    assert _snapshot(root) == after


def test_explicit_rollback_restores_exact_preimage_and_is_idempotent(
    tmp_path: Path,
) -> None:
    root, service, capability, approved, plan = _two_operation_case(tmp_path)
    service.prepare(
        approved,
        plan,
        journal_id="apply_rollback-001",
        committed_at=COMMITTED_AT,
        capability=capability,
    )
    service.commit(
        approved,
        plan,
        journal_id="apply_rollback-001",
        capability=capability,
    )

    rolled_back = service.rollback(
        approved,
        plan,
        journal_id="apply_rollback-001",
        capability=capability,
    )
    after = _snapshot(root)
    repeated = service.rollback(
        approved,
        plan,
        journal_id="apply_rollback-001",
        capability=capability,
    )

    assert rolled_back.status == repeated.status == "rolled_back"
    assert (root / "knowledge/first.md").read_bytes() == b"old first\n"
    assert not (root / "knowledge/second.md").exists()
    assert _snapshot(root) == after


def test_rejected_stale_or_wrong_capability_never_changes_vault_bytes(
    tmp_path: Path,
) -> None:
    root, resolver = _vault(tmp_path)
    old = b"old\n"
    (root / "knowledge/item.md").write_bytes(old)
    service, policy, capability = _service(resolver)
    artifact = _artifact()
    plan = _plan(
        artifact,
        (_operation("update", "knowledge/item.md", old=old, new="new\n"),),
    )
    approved = _approved(artifact, plan, policy)
    rejected = replace(approved, status="rejected")
    stale = replace(plan, operations=(replace(plan.operations[0], content="other\n", postcondition_sha256=_digest("other\n")),))
    wrong = policy.issue(
        flow_id="distill",
        action_id="commit-review-proposal",
        actor="runtime",
        authority="proposal",
        target="vault:review",
    )
    before = _snapshot(root)

    for current_artifact, current_plan, current_capability in (
        (rejected, plan, capability),
        (approved, stale, capability),
        (approved, plan, wrong),
    ):
        with pytest.raises(ApplyError):
            service.prepare(
                current_artifact,
                current_plan,
                journal_id="apply_denied-001",
                committed_at=COMMITTED_AT,
                capability=current_capability,
            )
        assert _snapshot(root) == before


@pytest.mark.parametrize("kind", ["case", "unicode", "symlink"])
def test_portable_namespace_and_nofollow_fail_before_write(
    tmp_path: Path, kind: str
) -> None:
    root, resolver = _vault(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    service, policy, capability = _service(resolver)
    artifact = _artifact()
    if kind == "case":
        (root / "knowledge/Case.md").write_text("foreign\n", "utf-8")
        target = "knowledge/case.md"
    elif kind == "unicode":
        (root / "knowledge/STRASSE.md").write_text("foreign\n", "utf-8")
        target = "knowledge/strasse.md"
    else:
        (root / "knowledge/link").symlink_to(outside, target_is_directory=True)
        target = "knowledge/link/item.md"
    plan = _plan(artifact, (_operation("create", target, new="new\n"),))
    approved = _approved(artifact, plan, policy)
    before = _snapshot(root)

    with pytest.raises(ApplyError):
        service.dry_run(approved, plan, capability=capability)

    assert _snapshot(root) == before
    assert not list(outside.iterdir())


def test_foreign_replacement_after_crash_is_preserved(tmp_path: Path) -> None:
    root, service, capability, approved, plan = _two_operation_case(tmp_path)
    service.prepare(
        approved,
        plan,
        journal_id="apply_foreign-001",
        committed_at=COMMITTED_AT,
        capability=capability,
    )
    with pytest.raises(ApplyCrash):
        service.commit(
            approved,
            plan,
            journal_id="apply_foreign-001",
            capability=capability,
            crash_at="before-first-replace",
        )
    (root / "knowledge/first.md").write_bytes(b"foreign replacement\n")

    with pytest.raises(ApplyError, match="foreign"):
        service.commit(
            approved,
            plan,
            journal_id="apply_foreign-001",
            capability=capability,
        )

    assert (root / "knowledge/first.md").read_bytes() == b"foreign replacement\n"
    assert not (root / "knowledge/second.md").exists()


def test_publish_race_does_not_overwrite_appearing_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, resolver = _vault(tmp_path)
    service, policy, capability = _service(resolver)
    artifact = _artifact()
    plan = _plan(
        artifact, (_operation("create", "knowledge/race.md", new="planned\n"),)
    )
    approved = _approved(artifact, plan, policy)
    service.prepare(
        approved,
        plan,
        journal_id="apply_race-001",
        committed_at=COMMITTED_AT,
        capability=capability,
    )
    real_link = apply_module.os.link
    injected = False

    def racing_link(source, destination, *args, **kwargs):
        nonlocal injected
        if destination == "race.md" and not injected:
            injected = True
            fd = os.open(
                destination,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=kwargs["dst_dir_fd"],
            )
            os.write(fd, b"foreign\n")
            os.close(fd)
        return real_link(source, destination, *args, **kwargs)

    monkeypatch.setattr(apply_module.os, "link", racing_link)

    with pytest.raises(ApplyError, match="appeared"):
        service.commit(
            approved,
            plan,
            journal_id="apply_race-001",
            capability=capability,
        )

    assert (root / "knowledge/race.md").read_bytes() == b"foreign\n"


def test_journal_decoder_is_bounded_canonical_and_nofollow(tmp_path: Path) -> None:
    root, service, capability, approved, plan = _two_operation_case(tmp_path)
    service.prepare(
        approved,
        plan,
        journal_id="apply_decode-001",
        committed_at=COMMITTED_AT,
        capability=capability,
    )
    journal_path = root / "agent/runs/apply-journals/apply_decode-001/journal.json"
    payload = json.loads(journal_path.read_bytes())
    payload["private_path"] = "/" + "Users/private/secret"
    journal_path.write_text(json.dumps(payload), "utf-8")
    with pytest.raises(ApplyError):
        service.read_journal("apply_decode-001")

    journal_path.write_bytes(b"{" + b"x" * (4 * 1024 * 1024 + 1))
    with pytest.raises(ApplyError, match="bounded"):
        service.read_journal("apply_decode-001")

    journal_path.unlink()
    journal_path.symlink_to(root / "lifeos.toml")
    with pytest.raises(ApplyError):
        service.read_journal("apply_decode-001")


def test_source_reads_and_file_descriptors_are_bounded(tmp_path: Path) -> None:
    root, resolver = _vault(tmp_path)
    oversized = b"x" * (4 * 1024 * 1024 + 1)
    (root / "knowledge/large.md").write_bytes(oversized)
    service, policy, capability = _service(resolver)
    artifact = _artifact()
    plan = _plan(
        artifact,
        (
            _operation(
                "update",
                "knowledge/large.md",
                old=oversized,
                new="bounded\n",
            ),
        ),
    )
    approved = _approved(artifact, plan, policy)
    baseline = len(os.listdir("/dev/fd"))

    for _ in range(8):
        with pytest.raises(ApplyError, match="bounded"):
            service.dry_run(approved, plan, capability=capability)

    assert len(os.listdir("/dev/fd")) == baseline
    assert (root / "knowledge/large.md").read_bytes() == oversized


def test_journal_time_before_exact_approval_fails_before_any_write(
    tmp_path: Path,
) -> None:
    root, service, capability, approved, plan = _two_operation_case(tmp_path)
    before = _snapshot(root)

    with pytest.raises(ApplyError, match="precede approval"):
        service.prepare(
            approved,
            plan,
            journal_id="apply_early-001",
            committed_at="2026-01-15T10:30:00Z",
            capability=capability,
        )

    assert _snapshot(root) == before


def test_finalize_requires_exact_durable_journal_and_all_new_bytes(
    tmp_path: Path,
) -> None:
    root, service, capability, approved, plan = _two_operation_case(tmp_path)
    prepared = service.prepare(
        approved,
        plan,
        journal_id="apply_finalize-001",
        committed_at=COMMITTED_AT,
        capability=capability,
    )
    forged = replace(
        prepared,
        status="committed",
        operations=tuple(
            replace(operation, status="committed")
            for operation in prepared.operations
        ),
    )
    before = _snapshot(root)

    with pytest.raises(ApplyError, match="durable evidence"):
        service.finalize(approved, plan, forged, capability=capability)
    assert _snapshot(root) == before

    committed = service.commit(
        approved,
        plan,
        journal_id="apply_finalize-001",
        capability=capability,
    )
    (root / "knowledge/first.md").write_bytes(b"foreign after commit\n")
    with pytest.raises(ApplyError, match="knowledge bytes"):
        service.finalize(approved, plan, committed, capability=capability)
    assert (root / "knowledge/first.md").read_bytes() == b"foreign after commit\n"


def test_bound_vault_or_zone_replacement_cannot_redirect_apply(
    tmp_path: Path,
) -> None:
    root, resolver = _vault(tmp_path)
    service, policy, capability = _service(resolver)
    artifact = _artifact()
    plan = _plan(
        artifact,
        (_operation("create", "knowledge/redirect.md", new="planned\n"),),
    )
    approved = _approved(artifact, plan, policy)
    original = tmp_path / "original-vault"
    root.rename(original)
    replacement = tmp_path / "vault"
    shutil.copytree(FIXTURE, replacement)
    before = _snapshot(replacement)

    with pytest.raises(ApplyError, match="identity changed"):
        service.prepare(
            approved,
            plan,
            journal_id="apply_redirect-001",
            committed_at=COMMITTED_AT,
            capability=capability,
        )

    assert _snapshot(replacement) == before
    assert not (replacement / "knowledge/redirect.md").exists()
    assert not (original / "knowledge/redirect.md").exists()
