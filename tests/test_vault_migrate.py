from __future__ import annotations

from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path, PurePosixPath

import pytest

from tool_life_os_runtime.ext.vault.config import load_vault_config
from tool_life_os_runtime.ext.vault.migrate import (
    DEFAULT_VAULT_CONFIG,
    VaultMigrationError,
    build_migration_plan,
    init_vault,
    load_migration_plan,
    parse_vault_profile,
    render_migration_plan,
    render_vault_profile,
    scan_vault,
)
from tool_life_os_runtime.ext.vault.schema import validate_vault
import tool_life_os_runtime.ext.vault.migrate.core as migrate_core


FIXTURES = Path(__file__).parent / "fixtures"


def _tree_snapshot(root: Path) -> dict[str, tuple[str, int, int]]:
    if not root.exists():
        return {}
    result: dict[str, tuple[str, int, int]] = {}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            result[relative] = (f"symlink:{os.readlink(path)}", 0, path.lstat().st_mtime_ns)
        elif path.is_file():
            data = path.read_bytes()
            result[relative] = (hashlib.sha256(data).hexdigest(), len(data), path.stat().st_mtime_ns)
        elif path.is_dir():
            result[relative] = ("directory", 0, path.stat().st_mtime_ns)
    return result


def _staging_names(parent: Path, target_name: str) -> list[str]:
    return sorted(path.name for path in parent.iterdir() if path.name.startswith(f".{target_name}.lifeos-init-"))


def test_init_absent_target_creates_deterministic_minimal_vault(tmp_path: Path) -> None:
    target = tmp_path / "vault"

    result = init_vault(target)

    assert result.status == "initialized"
    assert result.root_ref.startswith("sha256:")
    profile = load_vault_config(target)
    report = validate_vault(target, profile)
    assert report.valid
    assert report.missing_optional == ("agent/reading",)
    assert [path.relative_to(target).as_posix() for path in target.rglob("*") if path.is_file()] == [
        "lifeos.toml"
    ]
    assert (target / "lifeos.toml").read_text("utf-8") == render_vault_profile(DEFAULT_VAULT_CONFIG)
    assert _staging_names(tmp_path, target.name) == []


def test_init_existing_empty_target_commits_atomically(tmp_path: Path) -> None:
    target = tmp_path / "vault"
    target.mkdir()

    result = init_vault(target)

    assert result.status == "initialized"
    assert validate_vault(target, load_vault_config(target)).valid


def test_second_init_is_read_only_idempotent_recognition(tmp_path: Path) -> None:
    target = tmp_path / "vault"
    first = init_vault(target)
    before = _tree_snapshot(target)

    second = init_vault(target)

    assert second.status == "already_initialized"
    assert second.root_ref == first.root_ref
    assert second.snapshot_sha256 == first.snapshot_sha256
    assert _tree_snapshot(target) == before


def test_nonempty_target_is_unchanged_and_gets_no_staging_artifact(tmp_path: Path) -> None:
    target = tmp_path / "vault"
    target.mkdir()
    (target / "owned.txt").write_bytes(b"owner data")
    before = _tree_snapshot(tmp_path)

    with pytest.raises(VaultMigrationError, match="non-empty"):
        init_vault(target)

    assert _tree_snapshot(tmp_path) == before
    assert _staging_names(tmp_path, target.name) == []


@pytest.mark.parametrize(
    "raw",
    [
        "relative-vault",
        "../vault",
        "/tmp/control\u0085vault",
        "/tmp/line\u2028vault",
        "/tmp/windows\\vault",
    ],
)
def test_init_rejects_nonexplicit_traversal_and_control_before_write(tmp_path: Path, raw: str) -> None:
    before = _tree_snapshot(tmp_path)

    with pytest.raises(VaultMigrationError):
        init_vault(raw)

    assert _tree_snapshot(tmp_path) == before


def test_init_accepts_printable_unicode_target(tmp_path: Path) -> None:
    target = tmp_path / "portable-分析-🙂"

    assert init_vault(target).status == "initialized"
    assert validate_vault(target, load_vault_config(target)).valid


def test_init_rejects_leaf_symlink_without_touching_destination(tmp_path: Path) -> None:
    destination = tmp_path / "destination"
    destination.mkdir()
    target = tmp_path / "vault"
    target.symlink_to(destination, target_is_directory=True)
    before = _tree_snapshot(tmp_path)

    with pytest.raises(VaultMigrationError, match="symlink"):
        init_vault(target)

    assert _tree_snapshot(tmp_path) == before


@pytest.mark.parametrize("relation", ["equal", "target_parent", "target_child"])
def test_init_rejects_read_only_root_overlap_before_first_write(tmp_path: Path, relation: str) -> None:
    base = tmp_path / "shared"
    if relation == "equal":
        target, protected = base, base
    elif relation == "target_parent":
        target, protected = base, base / "legacy"
    else:
        target, protected = base / "target", base
        base.mkdir()
    before = _tree_snapshot(tmp_path)

    with pytest.raises(VaultMigrationError, match="overlaps"):
        init_vault(target, read_only_roots=(protected,))

    assert _tree_snapshot(tmp_path) == before
    assert _staging_names(target.parent, target.name) == []


def test_invalid_or_unknown_profile_field_fails_before_first_write(tmp_path: Path) -> None:
    target = tmp_path / "vault"
    text = render_vault_profile(DEFAULT_VAULT_CONFIG).replace(
        'locale = "ru"', 'locale = "ru"\nwrite_legacy = true'
    )

    with pytest.raises(VaultMigrationError, match="unknown or missing"):
        init_vault(target, profile=text)

    assert not target.exists()
    assert _staging_names(tmp_path, target.name) == []


@pytest.mark.parametrize(
    "zone_value",
    ["/absolute", "../escape", "knowledge\u0085unsafe", "windows\\path"],
)
def test_invalid_profile_zone_fails_before_first_write(tmp_path: Path, zone_value: str) -> None:
    text = render_vault_profile(DEFAULT_VAULT_CONFIG).replace(
        'knowledge = "knowledge"', f"knowledge = {json.dumps(zone_value)}"
    )
    target = tmp_path / "vault"

    with pytest.raises(VaultMigrationError):
        init_vault(target, profile=text)

    assert not target.exists()


def test_invalid_profile_object_collision_fails_before_first_write(tmp_path: Path) -> None:
    zones = tuple(
        (name, PurePosixPath("agent/logs") if name == "knowledge" else path)
        for name, path in DEFAULT_VAULT_CONFIG.zones
    )
    target = tmp_path / "vault"

    with pytest.raises(VaultMigrationError):
        init_vault(target, profile=replace(DEFAULT_VAULT_CONFIG, zones=zones))

    assert not target.exists()


def test_invalid_profile_object_type_fails_before_first_write(tmp_path: Path) -> None:
    target = tmp_path / "vault"

    with pytest.raises(VaultMigrationError, match="profile object"):
        init_vault(target, profile=object())  # type: ignore[arg-type]

    assert not target.exists()


def test_init_failure_cleans_private_staging_and_never_recognizes_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "vault"

    def fail_write(_fd: int, _data: bytes) -> None:
        raise OSError("synthetic write failure")

    monkeypatch.setattr(migrate_core, "_write_all", fail_write)
    with pytest.raises(VaultMigrationError, match="transaction failed"):
        init_vault(target)

    assert not target.exists()
    assert _staging_names(tmp_path, target.name) == []


def test_staging_name_collision_never_deletes_preexisting_tree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "vault"
    collision = tmp_path / ".vault.lifeos-init-collision"
    collision.mkdir()
    (collision / "owned.txt").write_bytes(b"owned")
    tokens = iter(["collision", "fresh"])
    monkeypatch.setattr(migrate_core.secrets, "token_hex", lambda _size: next(tokens))

    assert init_vault(target).status == "initialized"

    assert (collision / "owned.txt").read_bytes() == b"owned"
    assert _staging_names(tmp_path, target.name) == [collision.name]


def test_target_appearing_during_init_is_not_overwritten(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "vault"

    def appear(path: Path) -> None:
        path.mkdir()
        (path / "owned.txt").write_bytes(b"appeared")

    monkeypatch.setattr(migrate_core, "_before_init_commit", appear)
    with pytest.raises(VaultMigrationError):
        init_vault(target)

    assert (target / "owned.txt").read_bytes() == b"appeared"
    assert _staging_names(tmp_path, target.name) == []


@pytest.mark.parametrize("target_appears", [False, True])
def test_same_inode_staging_content_change_is_never_committed_or_cleaned(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    target_appears: bool,
) -> None:
    target = tmp_path / "vault"
    observed_stage: Path | None = None

    def mutate(path: Path) -> None:
        nonlocal observed_stage
        stages = [
            item
            for item in tmp_path.iterdir()
            if item.name.startswith(".vault.lifeos-init-")
        ]
        assert len(stages) == 1
        observed_stage = stages[0]
        (observed_stage / "foreign.txt").write_bytes(b"foreign")
        if target_appears:
            path.mkdir()
            (path / "owner.txt").write_bytes(b"owner")

    monkeypatch.setattr(migrate_core, "_before_init_commit", mutate)
    with pytest.raises(VaultMigrationError, match="content changed"):
        init_vault(target)

    assert observed_stage is not None
    assert (observed_stage / "foreign.txt").read_bytes() == b"foreign"
    if target_appears:
        assert (target / "owner.txt").read_bytes() == b"owner"
    else:
        assert not target.exists()


@pytest.mark.parametrize("target_appears", [False, True])
def test_renamed_owned_stage_and_foreign_replacement_are_never_committed_or_deleted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    target_appears: bool,
) -> None:
    target = tmp_path / "vault"
    renamed_owned = tmp_path / "renamed-owned-stage"
    observed_stage_name = ""

    def replace_stage(path: Path) -> None:
        nonlocal observed_stage_name
        candidates = [
            item
            for item in path.parent.iterdir()
            if item.name.startswith(f".{path.name}.lifeos-init-")
        ]
        assert len(candidates) == 1
        owned = candidates[0]
        observed_stage_name = owned.name
        owned.rename(renamed_owned)
        owned.mkdir()
        (owned / "foreign.txt").write_bytes(b"foreign replacement")
        if target_appears:
            path.mkdir()
            (path / "appeared.txt").write_bytes(b"appeared target")

    monkeypatch.setattr(migrate_core, "_before_init_commit", replace_stage)
    with pytest.raises(VaultMigrationError, match="transaction changed"):
        init_vault(target)

    foreign_replacement = tmp_path / observed_stage_name
    assert (renamed_owned / "lifeos.toml").is_file()
    assert (foreign_replacement / "foreign.txt").read_bytes() == b"foreign replacement"
    if target_appears:
        assert (target / "appeared.txt").read_bytes() == b"appeared target"
    else:
        assert not target.exists()


def test_existing_target_inode_swap_during_init_is_not_overwritten(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "vault"
    target.mkdir()
    original = tmp_path / "original-empty"

    def swap(path: Path) -> None:
        path.rename(original)
        path.mkdir()

    monkeypatch.setattr(migrate_core, "_before_init_commit", swap)
    with pytest.raises(VaultMigrationError, match="changed"):
        init_vault(target)

    assert list(target.iterdir()) == []
    assert list(original.iterdir()) == []
    assert _staging_names(tmp_path, target.name) == []


def test_repeat_init_rejects_initialized_vault_swap_before_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "vault"
    moved_initialized = tmp_path / "moved-initialized"
    init_vault(target)

    def swap(path: Path) -> None:
        path.rename(moved_initialized)
        path.mkdir()
        (path / "foreign.txt").write_bytes(b"foreign")

    monkeypatch.setattr(migrate_core, "_before_repeat_scan", swap)
    with pytest.raises(VaultMigrationError, match="changed before scan"):
        init_vault(target)

    assert (moved_initialized / "lifeos.toml").is_file()
    assert (target / "foreign.txt").read_bytes() == b"foreign"


def test_repeat_init_rechecks_exact_contents_before_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "vault"
    init_vault(target)

    def mutate(path: Path) -> None:
        (path / "foreign.txt").write_bytes(b"foreign")

    monkeypatch.setattr(migrate_core, "_before_repeat_scan", mutate)
    with pytest.raises(VaultMigrationError, match="changed before scan"):
        init_vault(target)

    assert (target / "foreign.txt").read_bytes() == b"foreign"


def test_read_only_symlink_swap_is_rechecked_before_commit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "vault"
    unrelated = tmp_path / "unrelated"
    unrelated.mkdir()
    protected_link = tmp_path / "protected"
    protected_link.symlink_to(unrelated, target_is_directory=True)

    def swap(_path: Path) -> None:
        protected_link.unlink()
        protected_link.symlink_to(target, target_is_directory=True)

    monkeypatch.setattr(migrate_core, "_before_init_commit", swap)
    roots = (item for item in [protected_link])
    with pytest.raises(VaultMigrationError, match="overlaps"):
        init_vault(target, read_only_roots=roots)

    assert not target.exists()
    assert _staging_names(tmp_path, target.name) == []


@pytest.mark.parametrize("fixture", ["vault-minimal", "vault-populated"])
def test_scan_is_byte_and_mtime_preserving_on_canonical_fixture(fixture: str) -> None:
    root = FIXTURES / fixture
    before = _tree_snapshot(root)

    first = scan_vault(root)
    second = scan_vault(root)

    assert first == second
    assert first.schema_version == 1
    assert first.root_ref.startswith("sha256:")
    assert _tree_snapshot(root) == before


def test_scan_excludes_archive_hold_and_trash_but_reports_exact_counts(tmp_path: Path) -> None:
    root = tmp_path / "source"
    (root / "active/nested").mkdir(parents=True)
    (root / "active/nested/item.md").write_bytes(b"active")
    for name in ("_archive", "_trash", "_on_hold"):
        (root / f"active/{name}/nested").mkdir(parents=True)
        (root / f"active/{name}/hidden.md").write_bytes(name.encode())
        (root / f"active/{name}/nested/deep.md").write_bytes(b"deep")
    before = _tree_snapshot(root)

    scan = scan_vault(root)

    assert [item.relative_ref for item in scan.files] == ["active/nested/item.md"]
    assert [item.relative_ref for item in scan.excluded] == [
        "active/_archive",
        "active/_on_hold",
        "active/_trash",
    ]
    assert [item.entry_count for item in scan.excluded] == [4, 4, 4]
    assert scan.excluded_entry_count == 12
    assert _tree_snapshot(root) == before


def test_scan_rejects_active_symlink_without_following_it(tmp_path: Path) -> None:
    root = tmp_path / "source"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (outside / "private.md").write_bytes(b"outside")
    (root / "link").symlink_to(outside, target_is_directory=True)
    before = _tree_snapshot(tmp_path)

    with pytest.raises(VaultMigrationError, match="symlink"):
        scan_vault(root)

    assert _tree_snapshot(tmp_path) == before


def test_scan_rejects_control_filename(tmp_path: Path) -> None:
    root = tmp_path / "source"
    root.mkdir()
    (root / "unsafe\u0085name.md").write_bytes(b"content")

    with pytest.raises(VaultMigrationError, match="invalid"):
        scan_vault(root)


@pytest.mark.parametrize("root_value", ["relative", "../source"])
def test_scan_rejects_nonexplicit_or_traversing_root(root_value: str) -> None:
    with pytest.raises(VaultMigrationError):
        scan_vault(root_value)


def test_scan_rejects_leaf_root_symlink(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "source"
    link.symlink_to(real, target_is_directory=True)

    with pytest.raises(VaultMigrationError, match="symlink"):
        scan_vault(link)


def test_scan_detects_root_path_swap_without_scanning_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "source"
    replacement = tmp_path / "replacement"
    moved = tmp_path / "moved"
    root.mkdir()
    replacement.mkdir()
    (root / "item.md").write_bytes(b"original")
    (replacement / "item.md").write_bytes(b"replacement")
    original_hash = migrate_core._hash_file_at
    swapped = False

    def swap_after_hash(parent_fd: int, name: str, expected):
        nonlocal swapped
        result = original_hash(parent_fd, name, expected)
        if not swapped:
            root.rename(moved)
            replacement.rename(root)
            swapped = True
        return result

    monkeypatch.setattr(migrate_core, "_hash_file_at", swap_after_hash)
    with pytest.raises(VaultMigrationError, match="changed during scan"):
        scan_vault(root)

    assert (root / "item.md").read_bytes() == b"replacement"
    assert (moved / "item.md").read_bytes() == b"original"


def test_scan_normalizes_fd_race_error_without_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "source"
    root.mkdir()
    (root / "item.md").write_bytes(b"content")
    before = _tree_snapshot(root)

    def disappear(*_args, **_kwargs):
        raise FileNotFoundError("synthetic race")

    monkeypatch.setattr(migrate_core, "_hash_file_at", disappear)
    with pytest.raises(VaultMigrationError, match="changed or became unsafe"):
        scan_vault(root)

    assert _tree_snapshot(root) == before


def test_migration_plan_is_deterministic_hashed_and_explicit_only(tmp_path: Path) -> None:
    source = tmp_path / "source"
    target = tmp_path / "target"
    source.mkdir()
    target.mkdir()
    (source / "a-create.md").write_bytes(b"create")
    (source / "b-update.md").write_bytes(b"source")
    (source / "c-same.md").write_bytes(b"same")
    (target / "b-update.md").write_bytes(b"target")
    (target / "c-same.md").write_bytes(b"same")
    (target / "z-target-only.md").write_bytes(b"target only")
    source_scan = scan_vault(source)
    target_scan = scan_vault(target)

    first = build_migration_plan(source_scan, target_scan)
    second = build_migration_plan(scan_vault(source), scan_vault(target))
    rendered = render_migration_plan(first)

    assert first == second
    assert render_migration_plan(second) == rendered
    assert [item.action for item in first.operations] == ["create", "update"]
    assert [item.relative_ref for item in first.operations] == ["a-create.md", "b-update.md"]
    assert first.summary == {
        "create_count": 1,
        "update_count": 1,
        "unchanged_count": 1,
        "target_only_count": 1,
    }
    assert first.operations[0].target_precondition_sha256 is None
    assert first.operations[1].target_precondition_sha256 == hashlib.sha256(b"target").hexdigest()
    assert first.source["root_ref"] != first.target["root_ref"]
    assert str(source) not in rendered
    assert str(target) not in rendered
    assert "apply" not in json.loads(rendered)
    assert load_migration_plan(rendered) == first


def test_migration_plan_rejects_overlapping_roots(tmp_path: Path) -> None:
    source = tmp_path / "source"
    target = source / "target"
    target.mkdir(parents=True)

    with pytest.raises(VaultMigrationError, match="overlap"):
        build_migration_plan(scan_vault(source), scan_vault(target))


def test_migration_plan_rejects_forged_scan_object(tmp_path: Path) -> None:
    source = tmp_path / "source"
    target = tmp_path / "target"
    source.mkdir()
    target.mkdir()
    (source / "item.md").write_bytes(b"source")
    source_scan = scan_vault(source)
    forged_file = replace(source_scan.files[0], relative_ref="../escape")
    forged = replace(source_scan, files=(forged_file,))

    with pytest.raises(VaultMigrationError, match="unsafe"):
        build_migration_plan(forged, scan_vault(target))


@pytest.mark.parametrize(
    "mutate",
    [
        lambda payload: payload.update({"unknown_security_field": True}),
        lambda payload: payload["source"].update({"path": "/private/source"}),
        lambda payload: payload["operations"][0].update({"relative_ref": "../escape"}),
        lambda payload: payload["operations"][0].update({"relative_ref": "/absolute"}),
        lambda payload: payload["operations"][0].update({"relative_ref": "_archive/item.md"}),
        lambda payload: payload["operations"][0].update({"relative_ref": "bad\u2028name"}),
        lambda payload: payload["operations"][0].update({"source_sha256": "0" * 64}),
        lambda payload: payload["operations"][0].update({"operation_id": "op_" + "0" * 24}),
        lambda payload: payload.update({"plan_id": "mig_" + "0" * 24}),
    ],
)
def test_plan_loader_fails_closed_on_unknown_toxic_or_tampered_fields(
    tmp_path: Path, mutate
) -> None:
    source = tmp_path / "source"
    target = tmp_path / "target"
    source.mkdir()
    target.mkdir()
    (source / "item.md").write_bytes(b"source")
    payload = build_migration_plan(scan_vault(source), scan_vault(target)).to_dict()
    mutate(payload)

    with pytest.raises(VaultMigrationError):
        load_migration_plan(json.dumps(payload))


def test_profile_round_trip_is_canonical_and_rejects_unknown_nested_field() -> None:
    rendered = render_vault_profile(DEFAULT_VAULT_CONFIG)
    assert parse_vault_profile(rendered) == DEFAULT_VAULT_CONFIG

    invalid = rendered.replace('default = "gated"', 'default = "gated"\nforce = true')
    with pytest.raises(VaultMigrationError, match="unknown or missing"):
        parse_vault_profile(invalid)


@pytest.mark.parametrize(
    "payload",
    [
        "value = " + "[" * 500 + "0" + "]" * 500,
        "schema_version = " + "9" * 5000,
    ],
)
def test_public_profile_parser_normalizes_bounded_toml_decoder_failures(
    payload: str,
) -> None:
    with pytest.raises(VaultMigrationError, match="vault profile is invalid"):
        parse_vault_profile(payload)


def test_public_migrate_api_has_no_apply_operation() -> None:
    import tool_life_os_runtime.ext.vault.migrate as migrate

    assert not hasattr(migrate, "apply_migration")
    assert all("apply" not in name for name in migrate.__all__)
