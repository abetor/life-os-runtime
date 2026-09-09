"""P3-01 safe Obsidian note primitives and validate-on-write."""

from __future__ import annotations

from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import shutil
import unicodedata

import pytest

from tool_life_os_runtime.ext.flows.obsidian import (
    NoteEdit,
    NoteEditReceipt,
    NoteRef,
    ObsidianCrash,
    ObsidianError,
    ObsidianFlow,
    parse_feedback_blocks,
    parse_note,
    parse_note_edit_receipt,
    render_note_edit_receipt,
    validate_note,
)
from tool_life_os_runtime.ext.flows.obsidian import flow as obsidian_module
from tool_life_os_runtime.ext.review.authority import AuthorityPolicy
from tool_life_os_runtime.ext.vault.config import load_vault_config
from tool_life_os_runtime.ext.vault.schema import VaultPathResolver


FIXTURES = Path(__file__).parent / "fixtures"
READ_ACTIONS = {
    "inbox": ("read-inbox-note", "vault:inbox"),
    "knowledge": ("read-safe-note", "vault:knowledge"),
    "tasks": ("read-task-note", "vault:tasks"),
    "projects": ("read-project-note", "vault:projects"),
    "agent/memory": ("read-memory-note", "vault:agent/memory"),
}
WRITE_ACTIONS = {
    "inbox": ("edit-inbox", "vault:inbox"),
    "tasks": ("edit-tasks", "vault:tasks"),
    "projects": ("edit-projects", "vault:projects"),
    "agent/memory-metadata": (
        "edit-memory-metadata",
        "vault:agent/memory-metadata",
    ),
}


def _vault(tmp_path: Path, fixture: str = "vault-populated") -> Path:
    root = tmp_path / "vault"
    shutil.copytree(FIXTURES / fixture, root)
    return root


def _runtime(root: Path) -> tuple[ObsidianFlow, AuthorityPolicy]:
    policy = AuthorityPolicy()
    resolver = VaultPathResolver(root, load_vault_config(root))
    return ObsidianFlow(resolver, policy), policy


def _capability(policy: AuthorityPolicy, zone: str, *, write: bool):
    action, target = (WRITE_ACTIONS if write else READ_ACTIONS)[zone]
    return policy.issue(
        flow_id="obsidian",
        action_id=action,
        actor="runtime",
        authority="domain-write" if write else "read",
        target=target,
    )


def _note(
    body: str = "# Synthetic note\n\nPortable body.\n",
    *,
    date: str = "2026-01-15",
    tags: tuple[str, ...] = ("fixture",),
    extra: str = "",
) -> str:
    tag_lines = "".join(f"  - {tag}\n" for tag in tags)
    return f'---\ntags:\n{tag_lines}date: "{date}"\n{extra}---\n\n{body}'


def _digest(value: str | bytes) -> str:
    if isinstance(value, str):
        value = value.encode("utf-8")
    return hashlib.sha256(value).hexdigest()


def _snapshot(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file() and not path.is_symlink()
    }


@pytest.mark.parametrize(
    ("zone", "relative"),
    [
        ("inbox", "2026-01-15.md"),
        ("knowledge", "domains/ai/portable-workflow.md"),
        ("tasks", "2026-01-15.md"),
        ("projects", "portable-fixture/log.md"),
        ("agent/memory", "portable-memory.md"),
    ],
)
def test_exact_read_capability_mapping_for_every_allowed_zone(
    tmp_path: Path, zone: str, relative: str
) -> None:
    root = _vault(tmp_path)
    (root / "agent/memory/portable-memory.md").write_text(_note(), "utf-8")
    flow, policy = _runtime(root)
    capability = _capability(policy, zone, write=False)

    snapshot = flow.read_note(NoteRef(1, zone, relative), capability=capability)

    assert snapshot.zone == zone
    assert snapshot.relative == relative
    assert snapshot.path.endswith(relative)
    assert snapshot.sha256 == _digest(snapshot.content)
    assert validate_note(snapshot).valid


def test_wrong_zone_or_write_capability_cannot_authorize_read(tmp_path: Path) -> None:
    root = _vault(tmp_path)
    flow, policy = _runtime(root)
    wrong_zone = _capability(policy, "tasks", write=False)
    write = _capability(policy, "inbox", write=True)
    ref = NoteRef(1, "inbox", "2026-01-15.md")

    for capability in (wrong_zone, write):
        with pytest.raises(ObsidianError, match="exact obsidian action"):
            flow.read_note(ref, capability=capability)


def test_common_frontmatter_is_strict_but_preserves_bounded_domain_fields() -> None:
    content = _note(extra="source_type: synthesis\nconfidence: high\n")
    snapshot = parse_note(NoteRef(1, "knowledge", "item.md"), content)

    assert snapshot.metadata()["source_type"] == "synthesis"
    assert snapshot.metadata()["confidence"] == "high"
    assert validate_note(snapshot).valid


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ("---\ntags:\n  - fixture\n", "not terminated"),
        (
            '---\ntags:\n  - fixture\ntags:\n  - duplicate\ndate: "2026-01-15"\n---\n# H1\n',
            "duplicate key",
        ),
        (
            '---\ntags:\n    nested: value\ndate: "2026-01-15"\n---\n# H1\n',
            "flat scalar",
        ),
        (
            '---\ntags: &shared fixture\ndate: "2026-01-15"\n---\n# H1\n',
            "unsupported YAML",
        ),
        (_note().replace("\n", "\r\n"), "LF line endings"),
    ],
)
def test_toxic_frontmatter_and_text_are_rejected(content: str, message: str) -> None:
    with pytest.raises(ObsidianError, match=message):
        parse_note(NoteRef(1, "inbox", "item.md"), content)


@pytest.mark.parametrize(
    ("content", "rule"),
    [
        ("# Missing frontmatter\n", "note.frontmatter.required"),
        (_note(tags=()), "note.tags.required"),
        (_note(tags=("Same", "same")), "note.tags.duplicate"),
        (_note(date="2026-02-31"), "note.date.invalid"),
        (_note(body="No heading.\n"), "note.h1.required"),
        (_note(body="# First\n\n# Second\n"), "note.h1.invalid"),
    ],
)
def test_common_validation_rules_are_deterministic(content: str, rule: str) -> None:
    snapshot = parse_note(NoteRef(1, "inbox", "item.md"), content)

    first = validate_note(snapshot)
    second = validate_note(snapshot)

    assert first == second
    assert rule in {issue.rule_id for issue in first.issues}
    assert not first.valid


def test_wikilinks_parse_alias_heading_and_ignore_code() -> None:
    content = _note(
        body=(
            "# Links\n\n"
            "[[knowledge/domains/ai/portable-workflow#Gate|workflow]]\n"
            "`[[ignored/inline]]`\n"
            "```md\n[[ignored/fence]]\n```\n"
        )
    )
    snapshot = parse_note(NoteRef(1, "inbox", "links.md"), content)

    assert len(snapshot.wikilinks) == 1
    link = snapshot.wikilinks[0]
    assert link.target == "knowledge/domains/ai/portable-workflow"
    assert link.heading == "Gate"
    assert link.alias == "workflow"


def test_unmatched_inline_backtick_cannot_hide_a_toxic_wikilink() -> None:
    content = _note(body="# Links\n\n` unmatched [[../escape]]\n")

    with pytest.raises(ObsidianError, match="inline code span is not terminated"):
        parse_note(NoteRef(1, "inbox", "links.md"), content)


def test_mixed_backtick_widths_do_not_replace_the_open_inline_delimiter() -> None:
    ignored = _note(body="# Links\n\n`inside `` [[../ignored]] still inside`\n")
    snapshot = parse_note(NoteRef(1, "inbox", "links.md"), ignored)

    assert snapshot.wikilinks == ()

    exposed = _note(body="# Links\n\n`inside `` still inside` [[../escape]]\n")
    with pytest.raises(ObsidianError, match="canonical relative POSIX path"):
        parse_note(NoteRef(1, "inbox", "links.md"), exposed)

    unmatched = _note(body="# Links\n\n``inside ` never closes\n")
    with pytest.raises(ObsidianError, match="inline code span is not terminated"):
        parse_note(NoteRef(1, "inbox", "links.md"), unmatched)


@pytest.mark.parametrize(
    "link",
    [
        "[[../escape]]",
        "[[/absolute]]",
        "[[knowledge\\item]]",
        "[[knowledge/_archive/item]]",
        "[[knowledge/item|]]",
        "[[knowledge/item#]]",
        "[[knowledge/item|one|two]]",
        "[[knowledge/item",
        "]]",
    ],
)
def test_toxic_wikilinks_fail_closed(link: str) -> None:
    with pytest.raises(ObsidianError, match="wikilink"):
        parse_note(NoteRef(1, "inbox", "links.md"), _note(body=f"# Links\n\n{link}\n"))


def test_link_index_reports_missing_ambiguous_and_case_mismatch() -> None:
    snapshot = parse_note(
        NoteRef(1, "inbox", "links.md"),
        _note(body=("# Links\n\n[[knowledge/Exact]] [[shared]] [[missing]]\n")),
    )
    report = validate_note(
        snapshot,
        link_index=(
            "knowledge/exact.md",
            "knowledge/a/shared.md",
            "projects/b/shared.md",
        ),
    )

    assert {issue.rule_id for issue in report.issues} == {
        "wikilink.target.case-mismatch",
        "wikilink.target.ambiguous",
        "wikilink.target.missing",
    }


def test_feedback_parser_matches_captured_completed_task_contract() -> None:
    snapshot = parse_note(
        NoteRef(1, "tasks", "2026-01-15.md"),
        _note(
            body=(
                "# Plan\n\n"
                "- [x] Synthetic completed task\n"
                "> fb: deterministic fixture feedback\n"
                "> continuation without personal prose\n"
                "- [ ] Pending task\n"
                "> fb: must not be extracted\n"
                "```\n- [x] Code task\n> fb: ignored\n```\n"
            )
        ),
    )

    blocks = parse_feedback_blocks(snapshot)

    assert len(blocks) == 1
    assert blocks[0].task_line == "- [x] Synthetic completed task"
    assert blocks[0].feedback == (
        "deterministic fixture feedback continuation without personal prose"
    )
    assert blocks[0].start_line < blocks[0].end_line


@pytest.mark.parametrize(
    "relative",
    [
        "../escape.md",
        "/absolute.md",
        "nested//item.md",
        "nested/./item.md",
        "nested\\item.md",
        "_archive/item.md",
        "_ARCHIVE/item.md",
        "_Trash/item.md",
        "_ON_HOLD/item.md",
        "item.txt",
        ".lifeos-note-owned.md",
        ".LIFEOS-NOTE-owned.md",
        ".LIFEOS-RETIRED-owned.md",
        "nested/.lifeos-note-owned/item.md",
        "nested/.LiFeOs-ReTiReD-owned/item.md",
        unicodedata.normalize("NFD", "café.md"),
    ],
)
def test_toxic_note_paths_fail_before_filesystem_access(
    tmp_path: Path, relative: str
) -> None:
    root = _vault(tmp_path)
    flow, policy = _runtime(root)
    capability = _capability(policy, "inbox", write=False)

    with pytest.raises(ObsidianError):
        flow.read_note(NoteRef(1, "inbox", relative), capability=capability)


def test_casefold_collision_and_parent_symlink_fail_closed(tmp_path: Path) -> None:
    root = _vault(tmp_path)
    (root / "inbox/Case.md").write_text(_note(), "utf-8")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "item.md").write_text(_note(), "utf-8")
    (root / "inbox/link").symlink_to(outside, target_is_directory=True)
    flow, policy = _runtime(root)
    capability = _capability(policy, "inbox", write=False)

    with pytest.raises(ObsidianError, match="namespace collision"):
        flow.read_note(NoteRef(1, "inbox", "case.md"), capability=capability)
    with pytest.raises(ObsidianError):
        flow.read_note(NoteRef(1, "inbox", "link/item.md"), capability=capability)


def test_create_update_receipt_round_trip_and_replay(tmp_path: Path) -> None:
    root = _vault(tmp_path)
    flow, policy = _runtime(root)
    capability = _capability(policy, "inbox", write=True)
    created_content = _note(body="# Created\n\nFirst version.\n")
    create = NoteEdit(
        1,
        "create_item",
        NoteRef(1, "inbox", "created.md"),
        None,
        created_content,
    )

    created = flow.edit_note(create, capability=capability)
    repeated = flow.edit_note(create, capability=capability)
    updated_content = _note(body="# Created\n\nSecond version.\n")
    update = NoteEdit(
        1,
        "update_item",
        create.ref,
        _digest(created_content),
        updated_content,
    )
    updated = flow.edit_note(update, capability=capability)

    assert created.status == "applied"
    assert repeated.status == "already_applied"
    assert updated.before_sha256 == _digest(created_content)
    assert updated.after_sha256 == _digest(updated_content)
    assert (root / "inbox/created.md").read_text("utf-8") == updated_content
    assert parse_note_edit_receipt(render_note_edit_receipt(updated)) == updated
    assert not list((root / "inbox").glob(".lifeos-note-*"))
    retired = list((root / "inbox").glob(".lifeos-retired-*"))
    assert len(retired) == 1
    assert created_content.encode("utf-8") not in retired[0].read_bytes()


def test_sequential_updates_reuse_one_bounded_retirement_slot(tmp_path: Path) -> None:
    root = _vault(tmp_path)
    target = root / "inbox/sequential.md"
    initial = _note(body="# Sequential\n\nVersion 0 unique original bytes.\n")
    target.write_text(initial, "utf-8")
    flow, policy = _runtime(root)
    capability = _capability(policy, "inbox", write=True)
    previous = initial

    for version in range(1, 41):
        current = _note(body=f"# Sequential\n\nVersion {version}.\n")
        flow.edit_note(
            NoteEdit(
                1,
                f"sequential_{version}",
                NoteRef(1, "inbox", target.name),
                _digest(previous),
                current,
            ),
            capability=capability,
        )
        previous = current

    residues = list((root / "inbox").glob(".lifeos-retired-*"))
    assert target.read_text("utf-8") == previous
    assert len(residues) <= 1
    assert not list((root / "inbox").glob(".lifeos-note-*"))
    assert all(initial.encode("utf-8") not in path.read_bytes() for path in residues)


def test_retirement_reconciliation_preserves_unrelated_replacement_files(
    tmp_path: Path,
) -> None:
    root = _vault(tmp_path)
    unrelated = root / "inbox/.lifeos-retired-unrelated.slot"
    unrelated.write_bytes(b"unrelated replacement bytes")
    target = root / "inbox/reconcile.md"
    old = _note(body="# Old\n")
    target.write_text(old, "utf-8")
    flow, policy = _runtime(root)
    capability = _capability(policy, "inbox", write=True)

    flow.edit_note(
        NoteEdit(
            1,
            "reconcile_update",
            NoteRef(1, "inbox", target.name),
            _digest(old),
            _note(body="# New\n"),
        ),
        capability=capability,
    )

    assert unrelated.read_bytes() == b"unrelated replacement bytes"


def test_memory_metadata_uses_exact_canonical_write_action_and_zone(
    tmp_path: Path,
) -> None:
    root = _vault(tmp_path)
    (root / "agent/memory/metadata").mkdir()
    flow, policy = _runtime(root)
    capability = _capability(policy, "agent/memory-metadata", write=True)
    content = _note(body="# Memory metadata\n\nDeterministic metadata.\n")

    receipt = flow.edit_note(
        NoteEdit(
            1,
            "memory_metadata",
            NoteRef(1, "agent/memory-metadata", "index.md"),
            None,
            content,
        ),
        capability=capability,
    )

    assert receipt.path == "agent/memory/metadata/index.md"
    assert (root / receipt.path).read_text("utf-8") == content

    wrong = policy.issue(
        flow_id="obsidian",
        action_id="edit-projects",
        actor="runtime",
        authority="domain-write",
        target="vault:projects",
    )
    with pytest.raises(ObsidianError, match="exact obsidian action"):
        flow.edit_note(
            NoteEdit(
                1,
                "wrong_memory_metadata",
                NoteRef(1, "agent/memory-metadata", "other.md"),
                None,
                content,
            ),
            capability=wrong,
        )


def test_direct_knowledge_and_memory_edits_are_never_authorized(tmp_path: Path) -> None:
    root = _vault(tmp_path)
    flow, policy = _runtime(root)
    before = _snapshot(root)
    read_knowledge = _capability(policy, "knowledge", write=False)
    read_memory = _capability(policy, "agent/memory", write=False)

    for zone, capability in (
        ("knowledge", read_knowledge),
        ("agent/memory", read_memory),
    ):
        with pytest.raises(ObsidianError, match="direct edit is forbidden"):
            flow.edit_note(
                NoteEdit(
                    1, "forbidden_edit", NoteRef(1, zone, "item.md"), None, _note()
                ),
                capability=capability,
            )
    assert _snapshot(root) == before


def test_invalid_candidate_and_stale_hash_do_not_mutate(tmp_path: Path) -> None:
    root = _vault(tmp_path)
    target = root / "tasks/2026-01-15.md"
    original = target.read_bytes()
    flow, policy = _runtime(root)
    capability = _capability(policy, "tasks", write=True)

    with pytest.raises(ObsidianError, match="common validation"):
        flow.edit_note(
            NoteEdit(
                1,
                "invalid_candidate",
                NoteRef(1, "tasks", target.name),
                _digest(original),
                "# no frontmatter\n",
            ),
            capability=capability,
        )
    with pytest.raises(ObsidianError, match="precondition hash"):
        flow.edit_note(
            NoteEdit(
                1,
                "stale_candidate",
                NoteRef(1, "tasks", target.name),
                "0" * 64,
                _note(),
            ),
            capability=capability,
        )

    assert target.read_bytes() == original
    assert not list((root / "tasks").glob(".lifeos-note-*"))


@pytest.mark.parametrize(
    ("seam", "expected_status"),
    [
        ("after-prepare-before-replace", "applied"),
        ("after-replace-before-cleanup", "already_applied"),
    ],
)
def test_create_crash_retries_to_one_exact_note_without_temp(
    tmp_path: Path, seam: str, expected_status: str
) -> None:
    root = _vault(tmp_path)
    flow, policy = _runtime(root)
    capability = _capability(policy, "projects", write=True)
    request = NoteEdit(
        1,
        "crash_create",
        NoteRef(1, "projects", "portable-fixture/crash.md"),
        None,
        _note(),
    )

    with pytest.raises(ObsidianCrash):
        flow.edit_note(request, capability=capability, crash_at=seam)
    result = flow.edit_note(request, capability=capability)

    assert result.status == expected_status
    assert (root / "projects/portable-fixture/crash.md").read_text(
        "utf-8"
    ) == request.content
    assert not list((root / "projects").rglob(".lifeos-note-*"))


@pytest.mark.parametrize(
    ("seam", "expected_status"),
    [
        ("after-prepare-before-replace", "applied"),
        ("after-replace-before-cleanup", "already_applied"),
    ],
)
def test_update_crash_retries_to_one_exact_note_without_temp(
    tmp_path: Path, seam: str, expected_status: str
) -> None:
    root = _vault(tmp_path)
    target = root / "projects/portable-fixture/log.md"
    old = target.read_bytes()
    new = _note(body="# Portable fixture log\n\nUpdated.\n")
    flow, policy = _runtime(root)
    capability = _capability(policy, "projects", write=True)
    request = NoteEdit(
        1,
        "crash_update",
        NoteRef(1, "projects", "portable-fixture/log.md"),
        _digest(old),
        new,
    )

    with pytest.raises(ObsidianCrash):
        flow.edit_note(request, capability=capability, crash_at=seam)
    result = flow.edit_note(request, capability=capability)

    assert result.status == expected_status
    assert target.read_text("utf-8") == new
    assert not list((root / "projects").rglob(".lifeos-note-*"))


@pytest.mark.parametrize("operation", ["create", "update"])
def test_foreign_target_after_prepare_is_preserved(
    tmp_path: Path, operation: str
) -> None:
    root = _vault(tmp_path)
    flow, policy = _runtime(root)
    capability = _capability(policy, "inbox", write=True)
    relative = "foreign.md"
    target = root / "inbox" / relative
    expected = None
    if operation == "update":
        target.write_text(_note(body="# Old\n"), "utf-8")
        expected = _digest(target.read_bytes())
    request = NoteEdit(
        1,
        f"foreign_{operation}",
        NoteRef(1, "inbox", relative),
        expected,
        _note(body="# Planned\n"),
    )
    with pytest.raises(ObsidianCrash):
        flow.edit_note(
            request,
            capability=capability,
            crash_at="after-prepare-before-replace",
        )
    foreign = _note(body="# Foreign\n\nMust survive.\n")
    target.write_text(foreign, "utf-8")

    with pytest.raises(ObsidianError):
        flow.edit_note(request, capability=capability)

    assert target.read_text("utf-8") == foreign
    assert not list((root / "inbox").glob(".lifeos-note-*"))


def test_create_publish_race_preserves_appearing_foreign_note(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _vault(tmp_path)
    flow, policy = _runtime(root)
    capability = _capability(policy, "inbox", write=True)
    request = NoteEdit(
        1,
        "create_race",
        NoteRef(1, "inbox", "race.md"),
        None,
        _note(body="# Planned\n"),
    )
    real_rename = obsidian_module._rename_noreplace
    injected = False
    foreign = _note(body="# Foreign\n")

    def racing_rename(directory_fd: int, source: str, destination: str) -> None:
        nonlocal injected
        if destination == "race.md" and not injected:
            injected = True
            fd = os.open(
                destination,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=directory_fd,
            )
            os.write(fd, foreign.encode("utf-8"))
            os.close(fd)
        real_rename(directory_fd, source, destination)

    monkeypatch.setattr(obsidian_module, "_rename_noreplace", racing_rename)

    with pytest.raises(ObsidianError, match="appeared during create"):
        flow.edit_note(request, capability=capability)
    assert (root / "inbox/race.md").read_text("utf-8") == foreign
    assert not list((root / "inbox").glob(".lifeos-note-*"))


def test_update_in_place_race_is_swapped_back_and_preserved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _vault(tmp_path)
    target = root / "inbox/update-race.md"
    old = _note(body="# Old\n\nOriginal.\n")
    target.write_text(old, "utf-8")
    flow, policy = _runtime(root)
    capability = _capability(policy, "inbox", write=True)
    request = NoteEdit(
        1,
        "update_race",
        NoteRef(1, "inbox", target.name),
        _digest(old),
        _note(body="# New\n\nPlanned.\n"),
    )
    real_exchange = obsidian_module._rename_exchange
    foreign = _note(body="# Foreign\n\nMust survive.\n")
    injected = False

    def racing_exchange(directory_fd: int, first: str, second: str) -> None:
        nonlocal injected
        if not injected:
            injected = True
            fd = os.open(second, os.O_WRONLY | os.O_TRUNC, dir_fd=directory_fd)
            os.write(fd, foreign.encode("utf-8"))
            os.fsync(fd)
            os.close(fd)
        real_exchange(directory_fd, first, second)

    monkeypatch.setattr(obsidian_module, "_rename_exchange", racing_exchange)

    with pytest.raises(ObsidianError, match="preserved"):
        flow.edit_note(request, capability=capability)
    assert target.read_text("utf-8") == foreign


def test_cleanup_substitution_is_preserved_without_path_unlink(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _vault(tmp_path)
    target = root / "inbox/retire-race.md"
    old = _note(body="# Old\n")
    target.write_text(old, "utf-8")
    flow, policy = _runtime(root)
    capability = _capability(policy, "inbox", write=True)
    request = NoteEdit(
        1,
        "retire_race",
        NoteRef(1, "inbox", target.name),
        _digest(old),
        _note(body="# New\n"),
    )
    real_open = obsidian_module.os.open
    real_unlink = obsidian_module.os.unlink
    foreign = b"FOREIGN RETIREMENT ENTRY"
    injected: str | None = None

    def racing_open(path, flags, *args, **kwargs):
        nonlocal injected
        if (
            isinstance(path, str)
            and path.startswith(".lifeos-retired-")
            and flags & os.O_RDWR
            and injected is None
        ):
            injected = path
            real_unlink(path, dir_fd=kwargs["dir_fd"])
            fd = real_open(
                path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=kwargs["dir_fd"],
            )
            os.write(fd, foreign)
            os.fsync(fd)
            os.close(fd)
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(obsidian_module.os, "open", racing_open)

    with pytest.raises(ObsidianError, match="retirement entry was preserved"):
        flow.edit_note(request, capability=capability)

    assert injected is not None
    assert (root / "inbox" / injected).read_bytes() == foreign


def test_replay_revalidates_target_after_temp_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _vault(tmp_path)
    flow, policy = _runtime(root)
    capability = _capability(policy, "inbox", write=True)
    request = NoteEdit(
        1,
        "replay_race",
        NoteRef(1, "inbox", "replay-race.md"),
        None,
        _note(body="# Planned\n"),
    )
    flow.edit_note(request, capability=capability)
    real_cleanup = obsidian_module._remove_exact_temp
    foreign = _note(body="# Foreign\n\nMust survive.\n")

    def racing_cleanup(directory_fd: int, name: str, expected: str) -> None:
        real_cleanup(directory_fd, name, expected)
        fd = os.open("replay-race.md", os.O_WRONLY | os.O_TRUNC, dir_fd=directory_fd)
        os.write(fd, foreign.encode("utf-8"))
        os.fsync(fd)
        os.close(fd)

    monkeypatch.setattr(obsidian_module, "_remove_exact_temp", racing_cleanup)

    with pytest.raises(ObsidianError, match="changed before receipt"):
        flow.edit_note(request, capability=capability)
    assert (root / "inbox/replay-race.md").read_text("utf-8") == foreign


def test_flow_rejects_replacement_of_the_pinned_vault_root(tmp_path: Path) -> None:
    root = _vault(tmp_path)
    flow, policy = _runtime(root)
    capability = _capability(policy, "inbox", write=False)
    original = tmp_path / "vault-original"
    root.rename(original)
    shutil.copytree(FIXTURES / "vault-populated", root)
    replacement = root / "inbox/2026-01-15.md"
    replacement.write_text(_note(body="# Replacement vault\n"), "utf-8")

    with pytest.raises(ObsidianError, match="root identity changed"):
        flow.read_note(NoteRef(1, "inbox", "2026-01-15.md"), capability=capability)


@pytest.mark.parametrize("swap_call", [1, 2])
def test_parent_renamed_during_prepare_or_publish_is_retired_or_rolled_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, swap_call: int
) -> None:
    root = _vault(tmp_path)
    flow, policy = _runtime(root)
    capability = _capability(policy, "inbox", write=True)
    request = NoteEdit(
        1,
        "parent_swap",
        NoteRef(1, "inbox", "swapped.md"),
        None,
        _note(body="# Planned\n"),
    )
    real_revalidate = obsidian_module._revalidate_parent
    calls = 0

    def swap_after_precommit(*args, **kwargs) -> None:
        nonlocal calls
        real_revalidate(*args, **kwargs)
        calls += 1
        if calls == swap_call:
            (root / "inbox").rename(root / "inbox-detached")
            (root / "inbox").mkdir()

    monkeypatch.setattr(obsidian_module, "_revalidate_parent", swap_after_precommit)

    with pytest.raises(ObsidianError, match="parent identity changed"):
        flow.edit_note(request, capability=capability)

    assert not (root / "inbox/swapped.md").exists()
    assert not (root / "inbox-detached/swapped.md").exists()
    assert not list((root / "inbox-detached").glob(".lifeos-note-*"))
    assert all(
        path.read_bytes() == obsidian_module._RETIRED_MARKER
        for path in (root / "inbox-detached").glob(".lifeos-retired-*")
    )


@pytest.mark.fresh_inode
def test_same_byte_post_publish_inode_substitution_has_no_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _vault(tmp_path)
    target = root / "projects/portable-fixture/log.md"
    old = target.read_bytes()
    new = _note(body="# Portable fixture log\n\nUpdated.\n")
    flow, policy = _runtime(root)
    capability = _capability(policy, "projects", write=True)
    request = NoteEdit(
        1,
        "post_publish_substitute",
        NoteRef(1, "projects", "portable-fixture/log.md"),
        _digest(old),
        new,
    )
    real_cleanup = obsidian_module._remove_exact_temp
    identities: list[int] = []

    def substitute_after_cleanup(*args, **kwargs) -> None:
        directory_fd = args[0]
        real_cleanup(*args, **kwargs)
        identities.append(
            os.stat("log.md", dir_fd=directory_fd, follow_symlinks=False).st_ino
        )
        os.unlink("log.md", dir_fd=directory_fd)
        fd = os.open(
            "log.md",
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
            dir_fd=directory_fd,
        )
        os.write(fd, new.encode("utf-8"))
        os.fsync(fd)
        os.close(fd)
        identities.append(
            os.stat("log.md", dir_fd=directory_fd, follow_symlinks=False).st_ino
        )

    monkeypatch.setattr(obsidian_module, "_remove_exact_temp", substitute_after_cleanup)

    with pytest.raises(ObsidianError, match="postcondition hash"):
        flow.edit_note(request, capability=capability)

    assert identities[0] != identities[1]
    assert target.read_text("utf-8") == new


def test_symlink_leaf_and_oversized_note_fail_without_fd_leak(tmp_path: Path) -> None:
    root = _vault(tmp_path)
    outside = tmp_path / "outside.md"
    outside.write_text(_note(), "utf-8")
    (root / "inbox/symlink.md").symlink_to(outside)
    (root / "inbox/large.md").write_bytes(b"x" * (1024 * 1024 + 1))
    flow, policy = _runtime(root)
    capability = _capability(policy, "inbox", write=False)
    baseline = len(os.listdir("/dev/fd"))

    for relative in ("symlink.md", "large.md") * 4:
        with pytest.raises(ObsidianError):
            flow.read_note(NoteRef(1, "inbox", relative), capability=capability)

    assert len(os.listdir("/dev/fd")) == baseline
    assert outside.read_text("utf-8") == _note()


def test_receipt_parser_rejects_noncanonical_duplicate_and_unknown_fields() -> None:
    receipt = NoteEditReceipt(
        1,
        "receipt_test",
        "inbox/item.md",
        None,
        "a" * 64,
        "applied",
    )
    canonical = render_note_edit_receipt(receipt)
    payload = json.loads(canonical)

    for path in (
        "inbox/_ARCHIVE/item.md",
        "inbox/.LIFEOS-NOTE-owned.md",
        "inbox/.LIFEOS-RETIRED-owned.md",
        "inbox/.LiFeOs-NoTe-owned/item.md",
        "inbox/nested/.LiFeOs-ReTiReD-owned/item.md",
    ):
        with pytest.raises(ObsidianError):
            render_note_edit_receipt(replace(receipt, path=path))

    with pytest.raises(ObsidianError, match="canonical"):
        parse_note_edit_receipt(json.dumps(payload).encode("utf-8"))
    with pytest.raises(ObsidianError, match="duplicate"):
        parse_note_edit_receipt(canonical.replace(b"{", b'{"status":"applied",', 1))
    payload["unknown"] = True
    with pytest.raises(ObsidianError, match="unknown"):
        parse_note_edit_receipt(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        )

    for field, value in (
        ("operation_id", 1),
        ("path", ["inbox/item.md"]),
        ("before_sha256", 1),
        ("after_sha256", None),
        ("status", ["applied"]),
    ):
        malformed = json.loads(canonical)
        malformed[field] = value
        raw = (
            json.dumps(malformed, sort_keys=True, separators=(",", ":")).encode()
            + b"\n"
        )
        with pytest.raises(ObsidianError):
            parse_note_edit_receipt(raw)


def test_dataclass_field_mutations_fail_as_domain_errors(tmp_path: Path) -> None:
    root = _vault(tmp_path)
    flow, policy = _runtime(root)
    capability = _capability(policy, "inbox", write=True)
    base = NoteEdit(1, "valid_id", NoteRef(1, "inbox", "item.md"), None, _note())

    for request in (
        replace(base, schema_version=True),
        replace(base, operation_id="bad id"),
        replace(base, expected_sha256="bad"),
        replace(base, ref=replace(base.ref, schema_version=True)),
        replace(base, content=object()),
    ):
        with pytest.raises(ObsidianError):
            flow.edit_note(request, capability=capability)

    with pytest.raises(ObsidianError):
        parse_note(replace(base.ref, relative=1), _note())


def test_snapshot_consumers_normalize_malformed_fields_to_domain_errors() -> None:
    snapshot = parse_note(NoteRef(1, "tasks", "item.md"), _note())
    malformed = (
        replace(snapshot, schema_version=True),
        replace(snapshot, body=object()),
        replace(snapshot, frontmatter=("not-a-field",)),
        replace(
            snapshot,
            frontmatter=(
                ("tags", ("\ud800",)),
                ("date", "2026-01-15"),
            ),
        ),
        replace(snapshot, wikilinks=(object(),)),
    )

    for changed in malformed:
        with pytest.raises(ObsidianError):
            validate_note(changed)
        with pytest.raises(ObsidianError):
            parse_feedback_blocks(changed)

    for changed in malformed[2:4]:
        with pytest.raises(ObsidianError):
            changed.metadata()

    report = validate_note(snapshot)
    for changed in (
        replace(report, schema_version=True),
        replace(report, issues=(object(),)),
    ):
        with pytest.raises(ObsidianError):
            _ = changed.valid
