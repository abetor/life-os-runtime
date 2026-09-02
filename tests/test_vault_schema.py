from __future__ import annotations

from dataclasses import replace
import os
from pathlib import Path, PurePosixPath
import shutil

import pytest

from tool_life_os_runtime.ext.vault.config import VaultConfig, load_vault_config
from tool_life_os_runtime.ext.vault.schema import (
    ARCHIVE_COMPONENTS,
    VaultPathResolver,
    VaultSchemaError,
    ZoneState,
    is_archive_path,
    iter_active_paths,
    validate_vault,
)


FIXTURES = Path(__file__).parent / "fixtures"


def _profile(root: Path) -> VaultConfig:
    return load_vault_config(root)


def _copy_fixture(tmp_path: Path, name: str = "vault-minimal") -> Path:
    target = tmp_path / name
    shutil.copytree(FIXTURES / name, target)
    return target


def _snapshot(root: Path) -> dict[str, tuple[int, int]]:
    return {
        path.relative_to(root).as_posix(): (path.stat().st_size, path.stat().st_mtime_ns)
        for path in root.rglob("*")
        if path.is_file()
    }


@pytest.mark.parametrize("fixture", ["vault-minimal", "vault-populated"])
def test_canonical_fixtures_match_versioned_schema_without_mutation(fixture: str) -> None:
    root = FIXTURES / fixture
    before = _snapshot(root)

    report = validate_vault(root, _profile(root))

    assert report.schema_version == 1
    assert report.valid
    assert report.corrupt_required == ()
    assert _snapshot(root) == before


def test_minimal_fixture_reports_missing_optional_reading_separately() -> None:
    root = FIXTURES / "vault-minimal"

    report = validate_vault(root, _profile(root))

    assert report.valid
    assert report.missing_optional == ("agent/reading",)
    assert next(check for check in report.checks if check.name == "agent/reading").state is ZoneState.MISSING_OPTIONAL


def test_populated_fixture_has_optional_reading_zone() -> None:
    root = FIXTURES / "vault-populated"
    report = validate_vault(root, _profile(root))

    assert report.missing_optional == ()
    assert next(check for check in report.checks if check.name == "agent/reading").state is ZoneState.PRESENT


@pytest.mark.parametrize("required", ["knowledge", "agent/runs", ".lifeos/review-plans"])
def test_missing_required_zone_is_corrupt_not_optional(tmp_path: Path, required: str) -> None:
    root = _copy_fixture(tmp_path)
    path = root.joinpath(*PurePosixPath(required).parts)
    for child in path.iterdir():
        child.unlink()
    path.rmdir()

    report = validate_vault(root, _profile(root))

    assert not report.valid
    assert required in report.corrupt_required
    assert required not in report.missing_optional
    with pytest.raises(VaultSchemaError, match="schema is corrupt"):
        report.require_valid()


def test_required_zone_file_is_corrupt(tmp_path: Path) -> None:
    root = _copy_fixture(tmp_path)
    knowledge = root / "knowledge"
    (knowledge / ".gitkeep").unlink()
    knowledge.rmdir()
    knowledge.write_text("not a directory", "utf-8")

    report = validate_vault(root, _profile(root))

    check = next(check for check in report.checks if check.name == "knowledge")
    assert check.state is ZoneState.CORRUPT_REQUIRED
    assert not report.valid


def test_present_optional_zone_with_wrong_type_is_corrupt_not_missing(tmp_path: Path) -> None:
    root = _copy_fixture(tmp_path)
    reading = root / "agent/reading"
    reading.write_text("not a directory", "utf-8")

    report = validate_vault(root, _profile(root))

    check = next(check for check in report.checks if check.name == "agent/reading")
    assert check.state is ZoneState.CORRUPT_OPTIONAL
    assert not report.valid
    assert report.missing_optional == ()
    assert report.corrupt_optional == ("agent/reading",)


def test_missing_or_symlinked_lifeos_profile_is_corrupt(tmp_path: Path) -> None:
    root = _copy_fixture(tmp_path)
    external = tmp_path / "outside.toml"
    (root / "lifeos.toml").replace(external)
    (root / "lifeos.toml").symlink_to(external)

    report = VaultPathResolver(root, _profile(external)).validate()

    assert "lifeos.toml" in report.corrupt_required


@pytest.mark.parametrize(
    "relative",
    [
        "../escape",
        "nested/../../escape",
        "/absolute",
        "nul\0name",
        "line\nname",
        "windows\\path",
        "next\u0085line",
        "control\u009fname",
        "line\u2028separator",
        "paragraph\u2029separator",
        "direction\u200emark",
    ],
)
def test_toxic_relative_paths_are_rejected(relative: str) -> None:
    root = FIXTURES / "vault-minimal"
    resolver = VaultPathResolver(root, _profile(root))

    with pytest.raises(VaultSchemaError):
        resolver.resolve("knowledge", relative, for_write=True)


@pytest.mark.parametrize(
    "relative",
    ["σημείωση.md", "résumé/分析.md", "symbol-λ-🙂.md", "space allowed.md"],
)
def test_printable_unicode_paths_are_not_false_positives(relative: str) -> None:
    root = FIXTURES / "vault-minimal"
    resolver = VaultPathResolver(root, _profile(root))

    assert resolver.resolve("knowledge", relative) == root / "knowledge" / relative


def test_unknown_symbolic_zone_is_rejected_instead_of_broadening_authority() -> None:
    root = FIXTURES / "vault-minimal"
    resolver = VaultPathResolver(root, _profile(root))

    with pytest.raises(VaultSchemaError, match="unknown symbolic"):
        resolver.resolve("agent/arbitrary", for_write=True)


def test_p0_symbolic_subzones_have_exact_non_knowledge_ownership() -> None:
    root = FIXTURES / "vault-minimal"
    profile = _profile(root)
    resolver = VaultPathResolver(root, profile)

    memory = resolver.resolve("agent/memory")
    knowledge = resolver.resolve("knowledge")
    assert resolver.resolve("agent/memory-metadata") == memory / "metadata"
    assert resolver.resolve("agent/memory/entities") == memory / "entities"
    assert resolver.resolve("agent/memory/trails") == memory / "trails"
    assert resolver.resolve("agent/logs") == root / "agent/logs"
    assert resolver.resolve("agent/dashboard") == root / "agent/dashboard"
    assert resolver.resolve("agent/reading") == root / "agent/reading"
    for zone in ("agent/memory-metadata", "agent/logs", "agent/dashboard", "agent/reading"):
        resolved = resolver.resolve(zone)
        assert resolved != knowledge
        assert knowledge not in resolved.parents


def test_memory_metadata_follows_configured_memory_zone_not_agent_sibling(tmp_path: Path) -> None:
    root = _copy_fixture(tmp_path)
    profile = _profile(root)
    zones = tuple(
        (name, PurePosixPath("portable/memory") if name == "memory" else path)
        for name, path in profile.zones
    )
    configured = replace(profile, zones=zones)
    (root / "portable/memory").mkdir(parents=True)
    resolver = VaultPathResolver(root, configured)

    assert resolver.resolve("agent/memory-metadata") == root / "portable/memory/metadata"
    assert resolver.resolve("agent/memory-metadata") != root / "agent/memory-metadata"


def test_fixed_service_zone_cannot_collide_with_configured_zone() -> None:
    root = FIXTURES / "vault-minimal"
    profile = _profile(root)
    zones = tuple(
        (name, PurePosixPath("agent/logs") if name == "knowledge" else path)
        for name, path in profile.zones
    )

    with pytest.raises(VaultSchemaError, match="overlap"):
        VaultPathResolver(root, replace(profile, zones=zones))


@pytest.mark.parametrize("relation", ["equal", "parent", "child"])
def test_parent_child_configured_zones_fail_closed(relation: str) -> None:
    root = FIXTURES / "vault-minimal"
    profile = _profile(root)
    replacements = {
        "equal": (PurePosixPath("shared"), PurePosixPath("shared")),
        "parent": (PurePosixPath("shared"), PurePosixPath("shared/child")),
        "child": (PurePosixPath("shared/child"), PurePosixPath("shared")),
    }
    first, second = replacements[relation]
    zones = tuple(
        (name, first if name == "tasks" else second if name == "projects" else path)
        for name, path in profile.zones
    )

    with pytest.raises(VaultSchemaError, match="overlap"):
        VaultPathResolver(root, replace(profile, zones=zones))


def test_symlink_escape_is_rejected_for_read_and_write(tmp_path: Path) -> None:
    root = _copy_fixture(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (root / "knowledge/escape").symlink_to(outside, target_is_directory=True)
    resolver = VaultPathResolver(root, _profile(root))

    for for_write in (False, True):
        with pytest.raises(VaultSchemaError, match="escapes"):
            resolver.resolve("knowledge", "escape/item.md", for_write=for_write)


def test_zone_symlink_swap_is_rechecked_after_config_load(tmp_path: Path) -> None:
    root = _copy_fixture(tmp_path)
    inside = root / "inside-knowledge"
    outside = tmp_path / "outside-knowledge"
    inside.mkdir()
    outside.mkdir()
    configured_link = root / "configured-knowledge"
    configured_link.symlink_to(inside, target_is_directory=True)
    profile = _profile(root)
    zones = tuple(
        (name, PurePosixPath("configured-knowledge") if name == "knowledge" else path)
        for name, path in profile.zones
    )
    resolver = VaultPathResolver(root, replace(profile, zones=zones))
    assert resolver.resolve("knowledge", "note.md", for_write=True) == inside / "note.md"

    configured_link.unlink()
    configured_link.symlink_to(outside, target_is_directory=True)

    with pytest.raises(VaultSchemaError, match="escapes"):
        resolver.resolve("knowledge", "note.md", for_write=True)


def test_symlink_swap_cannot_alias_two_authority_zones(tmp_path: Path) -> None:
    root = _copy_fixture(tmp_path)
    original = root / "knowledge"
    moved = root / "knowledge-original"
    original.rename(moved)
    original.symlink_to(moved, target_is_directory=True)
    resolver = VaultPathResolver(root, _profile(root))
    assert resolver.resolve("knowledge", "note.md", for_write=True) == moved / "note.md"

    original.unlink()
    original.symlink_to(root / "agent/logs", target_is_directory=True)

    with pytest.raises(VaultSchemaError, match="physical vault zones overlap"):
        resolver.resolve("knowledge", "note.md", for_write=True)


def test_revalidate_detects_root_symlink_swap(tmp_path: Path) -> None:
    first = shutil.copytree(FIXTURES / "vault-minimal", tmp_path / "first")
    second = shutil.copytree(FIXTURES / "vault-minimal", tmp_path / "second")
    link = tmp_path / "current-vault"
    link.symlink_to(first, target_is_directory=True)
    resolver = VaultPathResolver(link, _profile(first))
    original = resolver.resolve("knowledge", "note.md", for_write=True)

    link.unlink()
    link.symlink_to(second, target_is_directory=True)

    with pytest.raises(VaultSchemaError, match="changed"):
        resolver.revalidate(original, "knowledge", "note.md", for_write=True)


@pytest.mark.parametrize("relation", ["equal", "write_parent", "write_child"])
def test_resolved_write_path_cannot_overlap_read_only_root(tmp_path: Path, relation: str) -> None:
    root = _copy_fixture(tmp_path)
    write_path = root / "knowledge/branch"
    if relation == "equal":
        protected = write_path
    elif relation == "write_parent":
        protected = write_path / "legacy"
    else:
        protected = root / "knowledge"
    resolver = VaultPathResolver(root, _profile(root), read_only_roots=(protected,))

    with pytest.raises(VaultSchemaError, match="read-only"):
        resolver.resolve("knowledge", "branch", for_write=True)
    assert resolver.resolve("knowledge", "branch", for_write=False) == write_path


def test_read_only_root_symlink_swap_is_rechecked(tmp_path: Path) -> None:
    root = _copy_fixture(tmp_path)
    unrelated = tmp_path / "unrelated"
    unrelated.mkdir()
    protected_link = tmp_path / "protected"
    protected_link.symlink_to(unrelated, target_is_directory=True)
    resolver = VaultPathResolver(root, _profile(root), read_only_roots=(protected_link,))
    assert resolver.resolve("knowledge", "branch", for_write=True) == root / "knowledge/branch"

    protected_link.unlink()
    protected_link.symlink_to(root / "knowledge/branch", target_is_directory=True)

    with pytest.raises(VaultSchemaError, match="read-only"):
        resolver.resolve("knowledge", "branch", for_write=True)


@pytest.mark.parametrize("name", sorted(ARCHIVE_COMPONENTS))
def test_archive_conventions_are_excluded_by_default_and_explicit_when_needed(name: str) -> None:
    root = FIXTURES / "vault-minimal"
    resolver = VaultPathResolver(root, _profile(root))

    assert is_archive_path(f"active/{name}/old.md")
    with pytest.raises(VaultSchemaError, match="excluded"):
        resolver.resolve("projects", f"{name}/old.md")
    assert resolver.resolve("projects", f"{name}/old.md", allow_archive=True) == root / "projects" / name / "old.md"


@pytest.mark.parametrize("name", sorted(ARCHIVE_COMPONENTS))
def test_directory_symlink_cannot_hide_physical_archive_tree(tmp_path: Path, name: str) -> None:
    root = _copy_fixture(tmp_path)
    archive = root / "projects" / name
    archive.mkdir()
    (root / "projects/active-link").symlink_to(archive, target_is_directory=True)
    resolver = VaultPathResolver(root, _profile(root))

    with pytest.raises(VaultSchemaError, match="physically enters"):
        resolver.resolve("projects", "active-link/item.md", for_write=True)
    assert resolver.resolve(
        "projects", "active-link/item.md", for_write=True, allow_archive=True
    ) == archive / "item.md"


@pytest.mark.parametrize("name", sorted(ARCHIVE_COMPONENTS))
def test_file_symlink_cannot_hide_physical_archive_tree(tmp_path: Path, name: str) -> None:
    root = _copy_fixture(tmp_path)
    archive = root / "projects" / name
    archive.mkdir()
    hidden = archive / "hidden.md"
    hidden.write_text("archived", "utf-8")
    (root / "projects/active.md").symlink_to(hidden)
    resolver = VaultPathResolver(root, _profile(root))

    with pytest.raises(VaultSchemaError, match="physically enters"):
        resolver.resolve("projects", "active.md", must_exist=True)


def test_archive_symlink_swap_is_rejected_by_resolve_and_revalidate(tmp_path: Path) -> None:
    root = _copy_fixture(tmp_path)
    live = root / "projects/live"
    held = root / "projects/_on_hold"
    live.mkdir()
    held.mkdir()
    link = root / "projects/current"
    link.symlink_to(live, target_is_directory=True)
    resolver = VaultPathResolver(root, _profile(root))
    original = resolver.resolve("projects", "current/item.md", for_write=True)
    assert original == live / "item.md"

    link.unlink()
    link.symlink_to(held, target_is_directory=True)

    with pytest.raises(VaultSchemaError, match="physically enters"):
        resolver.resolve("projects", "current/item.md", for_write=True)
    with pytest.raises(VaultSchemaError, match="physically enters"):
        resolver.revalidate(original, "projects", "current/item.md", for_write=True)


def test_active_walk_does_not_descend_into_archive_trees(tmp_path: Path) -> None:
    root = tmp_path / "tree"
    (root / "active").mkdir(parents=True)
    (root / "active/item.md").write_text("active", "utf-8")
    outside = tmp_path / "outside.md"
    outside.write_text("outside", "utf-8")
    (root / "active/external.md").symlink_to(outside)
    for name in ARCHIVE_COMPONENTS:
        (root / name).mkdir()
        (root / name / "hidden.md").write_text("hidden", "utf-8")

    paths = [path.relative_to(root).as_posix() for path in iter_active_paths(root)]

    assert paths == ["active/item.md"]
