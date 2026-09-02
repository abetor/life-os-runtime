from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

import pytest

from tool_life_os_runtime.ext.skills import (
    CANONICAL_SKILL_IDS,
    SkillInstallError,
    canonical_resource,
    canonical_skills,
    check,
    install,
    manifest_path,
    uninstall,
)
from tool_life_os_runtime.ext.skills import installer as installer_module


CLAUDE = Path(".claude/skills/lifeos-ingest/SKILL.md")
CODEX = Path(".agents/skills/lifeos-ingest/SKILL.md")
ALL_WRAPPERS = tuple(
    Path(root) / f"lifeos-{skill_id}" / "SKILL.md"
    for root in (".claude/skills", ".agents/skills")
    for skill_id in CANONICAL_SKILL_IDS
)
FIRST_SORTED_WRAPPER = min(ALL_WRAPPERS, key=lambda path: path.as_posix())


def _roots(tmp_path: Path) -> tuple[Path, Path]:
    target = tmp_path / "portable-vault"
    manifests = tmp_path / "runtime-home" / "install"
    target.mkdir()
    manifests.mkdir(parents=True)
    return target, manifests


def _snapshot(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def test_pack_has_all_harness_independent_canonical_resources() -> None:
    skills = canonical_skills()
    assert tuple(skill.skill_id for skill in skills) == CANONICAL_SKILL_IDS
    assert len(skills) == 15
    assert skills[0] == canonical_resource("ingest")
    assert skills[0].resource_id == "lifeos://skills/ingest/v1"
    assert all("/" + "Users" + "/" not in skill.body for skill in skills)
    with pytest.raises(KeyError):
        canonical_resource("unknown")


def test_install_is_byte_deterministic_and_second_install_is_noop(
    tmp_path: Path,
) -> None:
    target, manifests = _roots(tmp_path)
    first = install(target, manifests)
    first_snapshot = _snapshot(tmp_path)
    first_mtimes = {
        path: (tmp_path / path).stat().st_mtime_ns for path in first_snapshot
    }

    second = install(target, manifests)
    second_snapshot = _snapshot(tmp_path)

    assert first.changed is True
    assert second.changed is False
    assert first_snapshot == second_snapshot
    assert first_mtimes == {
        path: (tmp_path / path).stat().st_mtime_ns for path in second_snapshot
    }
    assert first.installed == tuple(path.as_posix() for path in ALL_WRAPPERS)
    assert check(target, manifests).ok is True


def test_wrappers_are_thin_harness_specific_routes_with_source_hash(
    tmp_path: Path,
) -> None:
    target, manifests = _roots(tmp_path)
    install(target, manifests)
    source = canonical_resource("ingest")

    claude = (target / CLAUDE).read_text("utf-8")
    codex = (target / CODEX).read_text("utf-8")
    assert "GENERATED tool-life-os-runtime skills" in claude
    assert f"Canonical resource: `{source.resource_id}`" in claude
    assert source.sha256 in claude
    assert "Harness: `claude`" in claude
    assert "Harness: `codex`" in codex
    assert source.body not in claude
    assert source.body not in codex
    assert "lifeos doctor" not in claude
    assert "/Users/" not in claude + codex

    payload = json.loads(manifest_path(manifests).read_text("utf-8"))
    assert payload["state"] == "installed"
    assert len(payload["canonical_resources"]) == 15
    assert payload["canonical_resources"][0] == {
        "resource_id": source.resource_id,
        "sha256": source.sha256,
        "skill_id": "ingest",
    }
    assert len(payload["records"]) == 30
    assert {record["harness"] for record in payload["records"]} == {"claude", "codex"}
    assert all(
        record["source_sha256"] == canonical_resource(record["skill_id"]).sha256
        for record in payload["records"]
    )
    assert all(
        "/" not in value
        for key, value in payload.items()
        if key == "target_root_sha256"
    )
    assert str(tmp_path) not in manifest_path(manifests).read_text("utf-8")


@pytest.mark.parametrize("relative", [CLAUDE, CODEX])
def test_check_detects_manual_wrapper_drift_and_missing(
    tmp_path: Path, relative: Path
) -> None:
    target, manifests = _roots(tmp_path)
    install(target, manifests)
    (target / relative).write_text("manual replacement\n", encoding="utf-8")
    result = check(target, manifests)
    assert result.ok is False
    assert ("wrapper-drift", relative.as_posix()) in {
        (issue.code, issue.path) for issue in result.issues
    }

    (target / relative).unlink()
    result = check(target, manifests)
    assert ("missing-wrapper", relative.as_posix()) in {
        (issue.code, issue.path) for issue in result.issues
    }


def test_install_refuses_foreign_collision_even_when_bytes_match(
    tmp_path: Path,
) -> None:
    target, manifests = _roots(tmp_path)
    install(target, manifests)
    owned_body = (target / CLAUDE).read_bytes()
    uninstall(target, manifests)
    (target / CLAUDE).parent.mkdir(parents=True, exist_ok=True)
    (target / CLAUDE).write_bytes(owned_body)

    with pytest.raises(SkillInstallError, match="another source"):
        install(target, manifests)
    assert not manifest_path(manifests).exists()


def test_install_preflights_all_collisions_before_any_write(tmp_path: Path) -> None:
    target, manifests = _roots(tmp_path)
    foreign = target / CLAUDE
    foreign.parent.mkdir(parents=True)
    foreign.write_text("foreign\n", encoding="utf-8")

    with pytest.raises(SkillInstallError, match="another source"):
        install(target, manifests)
    assert foreign.read_text("utf-8") == "foreign\n"
    assert not (target / CODEX).exists()
    assert not manifest_path(manifests).exists()


def test_uninstall_removes_only_exact_owned_hash_and_preserves_modified_file(
    tmp_path: Path,
) -> None:
    target, manifests = _roots(tmp_path)
    install(target, manifests)
    (target / CLAUDE).write_text("foreign manual content\n", encoding="utf-8")

    result = uninstall(target, manifests)

    assert len(result.removed) == 29
    assert CODEX.as_posix() in result.removed
    assert result.preserved == (CLAUDE.as_posix(),)
    assert (target / CLAUDE).read_text("utf-8") == "foreign manual content\n"
    assert not (target / CODEX).exists()
    assert not manifest_path(manifests).exists()


def test_uninstall_reconciles_an_already_missing_owned_file(tmp_path: Path) -> None:
    target, manifests = _roots(tmp_path)
    install(target, manifests)
    (target / CODEX).unlink()
    result = uninstall(target, manifests)
    assert result.missing == (CODEX.as_posix(),)
    assert len(result.removed) == 29
    assert CLAUDE.as_posix() in result.removed


def test_partial_install_resumes_from_installing_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target, manifests = _roots(tmp_path)
    real_link = installer_module._link_staged_at
    wrapper_writes = 0

    def fail_on_second_wrapper(
        target_fd: int,
        parent_fd: int,
        name: str,
        staging: str,
        *,
        label: str,
        verify_parent,
    ) -> None:
        nonlocal wrapper_writes
        if name == "SKILL.md":
            wrapper_writes += 1
            if wrapper_writes == 2:
                raise SkillInstallError("injected crash")
        real_link(
            target_fd,
            parent_fd,
            name,
            staging,
            label=label,
            verify_parent=verify_parent,
        )

    monkeypatch.setattr(installer_module, "_link_staged_at", fail_on_second_wrapper)
    with pytest.raises(SkillInstallError, match="injected crash"):
        install(target, manifests)
    payload = json.loads(manifest_path(manifests).read_text("utf-8"))
    assert payload["state"] == "installing"
    assert sum(path.exists() for path in (target / CLAUDE, target / CODEX)) == 1

    monkeypatch.setattr(installer_module, "_link_staged_at", real_link)
    result = install(target, manifests)
    assert result.changed is True
    assert check(target, manifests).ok is True


def test_installing_manifest_never_adopts_manually_inserted_exact_wrapper(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    donor_base = tmp_path / "donor"
    target_base = tmp_path / "target"
    donor_base.mkdir()
    target_base.mkdir()
    donor_target, donor_manifests = _roots(donor_base)
    target, manifests = _roots(target_base)
    install(donor_target, donor_manifests)
    exact_foreign = (donor_target / CLAUDE).read_bytes()

    real_stage = installer_module._create_stage_at

    def crash_before_publish(*args, **kwargs) -> None:
        raise SkillInstallError("injected before first publish")

    monkeypatch.setattr(installer_module, "_create_stage_at", crash_before_publish)
    with pytest.raises(SkillInstallError, match="before first publish"):
        install(target, manifests)
    payload = json.loads(manifest_path(manifests).read_text("utf-8"))
    assert payload["state"] == "installing"
    assert all(record["file_identity"] is None for record in payload["records"])

    (target / CLAUDE).parent.mkdir(parents=True, exist_ok=True)
    (target / CLAUDE).write_bytes(exact_foreign)
    monkeypatch.setattr(installer_module, "_create_stage_at", real_stage)
    with pytest.raises(SkillInstallError, match="collides|cannot adopt"):
        install(target, manifests)
    assert (target / CLAUDE).read_bytes() == exact_foreign


def test_no_clobber_publish_preserves_leaf_appearing_after_observe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target, manifests = _roots(tmp_path)
    foreign = b"appeared after preflight\n"

    def insert_leaf(label: str) -> None:
        if label == CLAUDE.as_posix() and not (target / CLAUDE).exists():
            (target / CLAUDE).write_bytes(foreign)

    monkeypatch.setattr(installer_module, "_before_atomic_publish", insert_leaf)
    with pytest.raises(SkillInstallError, match="appeared before publish"):
        install(target, manifests)
    assert (target / CLAUDE).read_bytes() == foreign
    assert (
        len(json.loads(manifest_path(manifests).read_text("utf-8"))["publications"])
        == 1
    )
    assert (
        len(
            [
                path
                for path in target.iterdir()
                if path.name.startswith(".lifeos-publish-")
            ]
        )
        == 1
    )


def test_process_exit_after_publish_link_reconciles_only_the_proven_staged_inode(
    tmp_path: Path,
) -> None:
    target, manifests = _roots(tmp_path)
    script = """
import os
import sys
from pathlib import Path
from tool_life_os_runtime.ext.skills import install
from tool_life_os_runtime.ext.skills import installer

def crash(_label):
    os._exit(87)

installer._after_publish_link = crash
install(Path(sys.argv[1]), Path(sys.argv[2]))
"""
    crashed = subprocess.run(
        [sys.executable, "-c", script, str(target), str(manifests)],
        check=False,
        capture_output=True,
        text=True,
        cwd=Path(__file__).resolve().parents[1],
    )
    assert crashed.returncode == 87
    interrupted = json.loads(manifest_path(manifests).read_text("utf-8"))
    assert interrupted["state"] == "installing"
    assert len(interrupted["publications"]) == 1
    publication = interrupted["publications"][0]
    interrupted_record = next(
        record
        for record in interrupted["records"]
        if record["path"] == publication["path"]
    )
    assert interrupted_record["file_identity"] is None
    staged = target / publication["staging"]
    published = target / publication["path"]
    assert staged.exists() and published.exists()
    assert staged.stat().st_ino == published.stat().st_ino
    assert "publication-unresolved" in {
        issue.code for issue in check(target, manifests).issues
    }

    resumed = install(target, manifests)
    assert resumed.changed is True
    assert check(target, manifests).ok is True
    assert install(target, manifests).changed is False
    assert not [
        path for path in target.iterdir() if path.name.startswith(".lifeos-publish-")
    ]

    removed = uninstall(target, manifests)
    assert len(removed.removed) == 30
    assert not (target / CLAUDE).exists()
    assert not (target / CODEX).exists()


def test_process_exit_after_staging_cleanup_rename_reconciles_deterministic_leaf(
    tmp_path: Path,
) -> None:
    target, manifests = _roots(tmp_path)
    script = """
import os
import sys
from pathlib import Path
from tool_life_os_runtime.ext.skills import install
from tool_life_os_runtime.ext.skills import installer

def crash(_staging):
    os._exit(92)

installer._after_staging_cleanup_rename = crash
install(Path(sys.argv[1]), Path(sys.argv[2]))
"""
    crashed = subprocess.run(
        [sys.executable, "-c", script, str(target), str(manifests)],
        check=False,
        capture_output=True,
        text=True,
        cwd=Path(__file__).resolve().parents[1],
    )
    assert crashed.returncode == 92
    interrupted = json.loads(manifest_path(manifests).read_text("utf-8"))
    publication = interrupted["publications"][0]
    cleanup = target / f".lifeos-publish-clean-{publication['expected_sha256']}"
    assert not (target / publication["staging"]).exists()
    assert cleanup.is_file()
    assert cleanup.stat().st_ino == publication["staged_identity"]["inode"]
    assert (target / publication["path"]).stat().st_ino == cleanup.stat().st_ino
    assert "publication-unresolved" in {
        issue.code for issue in check(target, manifests).issues
    }

    assert install(target, manifests).changed is True
    assert install(target, manifests).changed is False
    assert check(target, manifests).ok is True
    assert not [
        path
        for path in target.iterdir()
        if path.name.startswith((".lifeos-publish-clean-", ".lifeos-publish-verify-"))
    ]
    assert len(uninstall(target, manifests).removed) == 30
    assert not [
        path
        for path in target.iterdir()
        if path.name.startswith((".lifeos-publish-clean-", ".lifeos-publish-verify-"))
    ]


def test_staging_cleanup_hash_unlink_seam_preserves_foreign_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target, manifests = _roots(tmp_path)
    foreign = b"foreign replacement after exact cleanup hash\n"
    replaced: list[Path] = []

    def replace_after_hash(cleanup_name: str) -> None:
        if replaced:
            return
        cleanup = target / cleanup_name
        cleanup.unlink()
        cleanup.write_bytes(foreign)
        replaced.append(cleanup)

    monkeypatch.setattr(
        installer_module,
        "_after_staging_cleanup_hash",
        replace_after_hash,
    )
    with pytest.raises(SkillInstallError, match="cleanup has foreign drift"):
        install(target, manifests)

    assert len(replaced) == 1
    cleanup = replaced[0]
    assert cleanup.read_bytes() == foreign
    assert not [
        path
        for path in target.iterdir()
        if path.name.startswith(".lifeos-publish-verify-")
    ]
    payload = json.loads(manifest_path(manifests).read_text("utf-8"))
    publication = payload["publications"][0]
    assert (target / publication["path"]).exists()

    monkeypatch.setattr(
        installer_module, "_after_staging_cleanup_hash", lambda _name: None
    )
    cleanup.unlink()
    assert install(target, manifests).changed is True
    assert install(target, manifests).changed is False
    assert check(target, manifests).ok is True
    assert not [
        path
        for path in target.iterdir()
        if path.name.startswith((".lifeos-publish-clean-", ".lifeos-publish-verify-"))
    ]
    assert len(uninstall(target, manifests).removed) == 30


def test_process_exit_after_complete_stage_before_link_reconciles_without_orphan(
    tmp_path: Path,
) -> None:
    target, manifests = _roots(tmp_path)
    script = """
import os
import sys
from pathlib import Path
from tool_life_os_runtime.ext.skills import install
from tool_life_os_runtime.ext.skills import installer

def crash(_label):
    os._exit(88)

installer._after_publish_stage = crash
install(Path(sys.argv[1]), Path(sys.argv[2]))
"""
    crashed = subprocess.run(
        [sys.executable, "-c", script, str(target), str(manifests)],
        check=False,
        capture_output=True,
        text=True,
        cwd=Path(__file__).resolve().parents[1],
    )
    assert crashed.returncode == 88
    interrupted = json.loads(manifest_path(manifests).read_text("utf-8"))
    assert interrupted["state"] == "installing"
    assert interrupted["publications"] == []
    stages = [
        path for path in target.iterdir() if path.name.startswith(".lifeos-publish-")
    ]
    assert len(stages) == 1
    assert hashlib.sha256(stages[0].read_bytes()).hexdigest() == stages[
        0
    ].name.removeprefix(".lifeos-publish-")
    assert not (target / CLAUDE).exists()

    assert install(target, manifests).changed is True
    assert install(target, manifests).changed is False
    assert check(target, manifests).ok is True
    assert not [
        path for path in target.iterdir() if path.name.startswith(".lifeos-publish-")
    ]
    removed = uninstall(target, manifests)
    assert len(removed.removed) == 30
    assert not [
        path for path in target.iterdir() if path.name.startswith(".lifeos-publish-")
    ]


def test_process_exit_after_canonical_stage_completion_reconciles_by_name_and_bytes(
    tmp_path: Path,
) -> None:
    target, manifests = _roots(tmp_path)
    script = """
import os
import sys
from pathlib import Path
from tool_life_os_runtime.ext.skills import install
from tool_life_os_runtime.ext.skills import installer

real_create = installer._create_stage_at

def crash(*args, **kwargs):
    result = real_create(*args, **kwargs)
    os._exit(90)

installer._create_stage_at = crash
install(Path(sys.argv[1]), Path(sys.argv[2]))
"""
    crashed = subprocess.run(
        [sys.executable, "-c", script, str(target), str(manifests)],
        check=False,
        capture_output=True,
        text=True,
        cwd=Path(__file__).resolve().parents[1],
    )
    assert crashed.returncode == 90
    interrupted = json.loads(manifest_path(manifests).read_text("utf-8"))
    assert interrupted["publications"] == []
    stages = [
        path for path in target.iterdir() if path.name.startswith(".lifeos-publish-")
    ]
    assert len(stages) == 1
    staged = stages[0]
    assert hashlib.sha256(staged.read_bytes()).hexdigest() == staged.name.removeprefix(
        ".lifeos-publish-"
    )

    assert install(target, manifests).changed is True
    assert install(target, manifests).changed is False
    assert check(target, manifests).ok is True
    assert not [
        path for path in target.iterdir() if path.name.startswith(".lifeos-publish-")
    ]
    assert len(uninstall(target, manifests).removed) == 30
    assert not [
        path for path in target.iterdir() if path.name.startswith(".lifeos-publish-")
    ]


def test_process_exit_during_unjournaled_stage_body_preserves_partial_inode(
    tmp_path: Path,
) -> None:
    target, manifests = _roots(tmp_path)
    script = """
import os
import sys
from pathlib import Path
from tool_life_os_runtime.ext.skills import install
from tool_life_os_runtime.ext.skills import installer

def crash(_label):
    os._exit(89)

installer._after_partial_stage_write = crash
install(Path(sys.argv[1]), Path(sys.argv[2]))
"""
    crashed = subprocess.run(
        [sys.executable, "-c", script, str(target), str(manifests)],
        check=False,
        capture_output=True,
        text=True,
        cwd=Path(__file__).resolve().parents[1],
    )
    assert crashed.returncode == 89
    interrupted = json.loads(manifest_path(manifests).read_text("utf-8"))
    assert interrupted["publications"] == []
    stages = [
        path for path in target.iterdir() if path.name.startswith(".lifeos-publish-")
    ]
    assert len(stages) == 1
    staged = stages[0]
    assert (
        0
        < staged.stat().st_size
        < len(
            installer_module._wrapper(
                canonical_resource("ingest"), "claude", interrupted["runtime_version"]
            )
        )
    )
    partial = staged.read_bytes()

    with pytest.raises(
        SkillInstallError, match="canonical publication staging has foreign drift"
    ):
        install(target, manifests)
    assert staged.read_bytes() == partial
    uninstall(target, manifests)
    assert staged.read_bytes() == partial


def test_process_exit_immediately_after_stage_inode_create_preserves_unknown_empty_leaf(
    tmp_path: Path,
) -> None:
    target, manifests = _roots(tmp_path)
    script = """
import os
import sys
from pathlib import Path
from tool_life_os_runtime.ext.skills import install
from tool_life_os_runtime.ext.skills import installer

def crash(_label):
    os._exit(91)

installer._after_stage_create = crash
install(Path(sys.argv[1]), Path(sys.argv[2]))
"""
    crashed = subprocess.run(
        [sys.executable, "-c", script, str(target), str(manifests)],
        check=False,
        capture_output=True,
        text=True,
        cwd=Path(__file__).resolve().parents[1],
    )
    assert crashed.returncode == 91
    interrupted = json.loads(manifest_path(manifests).read_text("utf-8"))
    assert interrupted["publications"] == []
    stages = [
        path for path in target.iterdir() if path.name.startswith(".lifeos-publish-")
    ]
    assert len(stages) == 1
    staged = stages[0]
    assert staged.stat().st_size == 0

    with pytest.raises(
        SkillInstallError, match="canonical publication staging has foreign drift"
    ):
        install(target, manifests)
    assert staged.exists() and staged.stat().st_size == 0
    uninstall(target, manifests)
    assert staged.exists() and staged.stat().st_size == 0


def test_partial_stage_with_replaced_inode_is_never_deleted_or_adopted(
    tmp_path: Path,
) -> None:
    target, manifests = _roots(tmp_path)
    script = """
import os
import sys
from pathlib import Path
from tool_life_os_runtime.ext.skills import install
from tool_life_os_runtime.ext.skills import installer

def crash(_label):
    os._exit(89)

installer._after_partial_stage_write = crash
install(Path(sys.argv[1]), Path(sys.argv[2]))
"""
    crashed = subprocess.run(
        [sys.executable, "-c", script, str(target), str(manifests)],
        check=False,
        capture_output=True,
        text=True,
        cwd=Path(__file__).resolve().parents[1],
    )
    assert crashed.returncode == 89
    staged = next(
        path for path in target.iterdir() if path.name.startswith(".lifeos-publish-")
    )
    staged.unlink()
    foreign = b"foreign replacement stage\n"
    staged.write_bytes(foreign)

    with pytest.raises(
        SkillInstallError, match="canonical publication staging has foreign drift"
    ):
        install(target, manifests)
    assert staged.read_bytes() == foreign


def test_installed_missing_wrapper_is_reconciled_but_manual_drift_blocks_all_writes(
    tmp_path: Path,
) -> None:
    target, manifests = _roots(tmp_path)
    install(target, manifests)
    (target / CODEX).unlink()
    assert install(target, manifests).changed is True
    assert check(target, manifests).ok is True

    (target / CLAUDE).write_text("manual\n", encoding="utf-8")
    codex_before = (target / CODEX).read_bytes()
    manifest_before = manifest_path(manifests).read_bytes()
    with pytest.raises(SkillInstallError, match="manual drift"):
        install(target, manifests)
    assert (target / CODEX).read_bytes() == codex_before
    assert manifest_path(manifests).read_bytes() == manifest_before


def test_target_binding_prevents_manifest_reuse_for_another_root(
    tmp_path: Path,
) -> None:
    first, manifests = _roots(tmp_path)
    second = tmp_path / "another-vault"
    second.mkdir()
    install(first, manifests)
    with pytest.raises(SkillInstallError, match="another target"):
        install(second, manifests)
    with pytest.raises(SkillInstallError, match="another target"):
        uninstall(second, manifests)


def test_copied_manifest_and_identical_wrappers_do_not_transfer_delete_ownership(
    tmp_path: Path,
) -> None:
    source_base = tmp_path / "source-install"
    destination_base = tmp_path / "destination-install"
    source_base.mkdir()
    destination_base.mkdir()
    source_target, source_manifests = _roots(source_base)
    destination_target, destination_manifests = _roots(destination_base)
    install(source_target, source_manifests)

    copied: dict[Path, bytes] = {}
    for relative in (CLAUDE, CODEX):
        body = (source_target / relative).read_bytes()
        copied[relative] = body
        (destination_target / relative).parent.mkdir(parents=True, exist_ok=True)
        (destination_target / relative).write_bytes(body)
    payload = json.loads(manifest_path(source_manifests).read_text("utf-8"))
    payload["target_root_sha256"] = hashlib.sha256(
        os.fsencode(destination_target.resolve())
    ).hexdigest()
    manifest_path(destination_manifests).write_text(
        json.dumps(payload), encoding="utf-8"
    )

    with pytest.raises(SkillInstallError, match="local evidence"):
        uninstall(destination_target, destination_manifests)
    assert all(
        (destination_target / relative).read_bytes() == body
        for relative, body in copied.items()
    )
    assert check(destination_target, destination_manifests).state == "unsafe"


def test_manifest_root_cannot_overlap_target_root(tmp_path: Path) -> None:
    target = tmp_path / "portable-vault"
    target.mkdir()
    nested = target / "agent" / "install"
    nested.mkdir(parents=True)
    with pytest.raises(SkillInstallError, match="must not overlap"):
        install(target, nested)
    assert not manifest_path(nested).exists()


@pytest.mark.parametrize(
    ("root_kind", "expected_label"),
    [("target", "target root"), ("manifest", "manifest root")],
)
def test_root_swap_to_symlink_between_anchor_and_resolve_never_writes_outside(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    root_kind: str,
    expected_label: str,
) -> None:
    target, manifests = _roots(tmp_path)
    selected = target if root_kind == "target" else manifests
    detached = selected.with_name(f"{selected.name}-detached")
    outside = tmp_path / f"outside-{root_kind}"
    outside.mkdir()
    swapped = False

    def swap(label: str) -> None:
        nonlocal swapped
        if label == expected_label and not swapped:
            selected.rename(detached)
            selected.symlink_to(outside, target_is_directory=True)
            swapped = True

    monkeypatch.setattr(installer_module, "_before_root_resolve", swap)
    with pytest.raises(SkillInstallError, match="changed while it was resolved"):
        install(target, manifests)

    assert swapped is True
    assert list(outside.iterdir()) == []
    assert list(detached.iterdir()) == []
    untouched = manifests if root_kind == "target" else target
    assert list(untouched.iterdir()) == []


def test_target_swap_between_joint_root_opens_fails_before_any_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target, manifests = _roots(tmp_path)
    detached = tmp_path / "portable-vault-detached"
    replacement = tmp_path / "portable-vault-replacement"
    replacement.mkdir()
    real_open_root_anchor = installer_module._open_root_anchor
    swapped = False

    def swap_before_manifest_parent(path, *, label):
        nonlocal swapped
        if label == "manifest root parent" and not swapped:
            target.rename(detached)
            replacement.rename(target)
            swapped = True
        return real_open_root_anchor(path, label=label)

    monkeypatch.setattr(
        installer_module, "_open_root_anchor", swap_before_manifest_parent
    )
    with pytest.raises(SkillInstallError, match="target root changed"):
        install(target, manifests)

    assert swapped is True
    assert list(target.iterdir()) == []
    assert list(detached.iterdir()) == []
    assert list(manifests.iterdir()) == []


def test_symlink_target_and_wrapper_fail_closed(tmp_path: Path) -> None:
    target, manifests = _roots(tmp_path)
    linked_root = tmp_path / "linked-vault"
    linked_root.symlink_to(target, target_is_directory=True)
    with pytest.raises(SkillInstallError, match="real directory"):
        install(linked_root, manifests)

    install(target, manifests)
    original = (target / CLAUDE).read_bytes()
    (target / CLAUDE).unlink()
    (target / CLAUDE).symlink_to(target / CODEX)
    with pytest.raises(SkillInstallError, match="regular file"):
        uninstall(target, manifests)
    assert (target / CODEX).read_bytes() != b""
    assert (target / CLAUDE).is_symlink()
    assert original != b""


def test_symlink_path_component_fails_without_writing_outside_target(
    tmp_path: Path,
) -> None:
    target, manifests = _roots(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (target / ".claude").symlink_to(outside, target_is_directory=True)

    with pytest.raises(SkillInstallError, match="unsafe component"):
        install(target, manifests)
    assert list(outside.iterdir()) == []
    assert not manifest_path(manifests).exists()


def test_install_parent_swap_before_replace_cannot_write_outside_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target, manifests = _roots(tmp_path)
    outside = tmp_path / "outside-install"
    outside.mkdir()
    outside_file = outside / "SKILL.md"
    foreign = b"outside file must not be replaced\n"
    outside_file.write_bytes(foreign)
    original_parent = target / CLAUDE.parent
    detached_parent = target / ".claude/skills/lifeos-ingest-detached"
    swapped = False

    def swap_parent(label: str) -> None:
        nonlocal swapped
        if label != CLAUDE.as_posix() or swapped:
            return
        original_parent.rename(detached_parent)
        original_parent.symlink_to(outside, target_is_directory=True)
        swapped = True

    monkeypatch.setattr(installer_module, "_before_atomic_publish", swap_parent)
    with pytest.raises(SkillInstallError, match="unsafe component|parent changed"):
        install(target, manifests)

    assert swapped is True
    assert outside_file.read_bytes() == foreign
    assert not (detached_parent / "SKILL.md").exists()
    assert (
        len(json.loads(manifest_path(manifests).read_text("utf-8"))["publications"])
        == 1
    )
    assert (
        len(
            [
                path
                for path in target.iterdir()
                if path.name.startswith(".lifeos-publish-")
            ]
        )
        == 1
    )
    assert (
        json.loads(manifest_path(manifests).read_text("utf-8"))["state"] == "installing"
    )


def test_unsafe_or_tampered_manifest_fails_closed(tmp_path: Path) -> None:
    target, manifests = _roots(tmp_path)
    install(target, manifests)
    payload = json.loads(manifest_path(manifests).read_text("utf-8"))
    payload["records"][0]["path"] = "../outside/SKILL.md"
    manifest_path(manifests).write_text(json.dumps(payload), encoding="utf-8")

    assert check(target, manifests).state == "unsafe"
    with pytest.raises(SkillInstallError, match="wrapper path"):
        uninstall(target, manifests)


@pytest.mark.parametrize("operation", ["install", "uninstall"])
def test_forged_manifest_hash_cannot_authorize_foreign_wrapper_mutation(
    tmp_path: Path, operation: str
) -> None:
    target, manifests = _roots(tmp_path)
    install(target, manifests)
    foreign = b"foreign wrapper that must survive\n"
    (target / CLAUDE).write_bytes(foreign)
    codex_before = (target / CODEX).read_bytes()
    payload = json.loads(manifest_path(manifests).read_text("utf-8"))
    claude_record = next(
        record for record in payload["records"] if record["harness"] == "claude"
    )
    claude_record["sha256"] = hashlib.sha256(foreign).hexdigest()
    manifest_path(manifests).write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(SkillInstallError, match="ownership claim"):
        (install if operation == "install" else uninstall)(target, manifests)
    assert (target / CLAUDE).read_bytes() == foreign
    assert (target / CODEX).read_bytes() == codex_before


def test_forged_source_and_canonical_hashes_are_not_trusted(tmp_path: Path) -> None:
    target, manifests = _roots(tmp_path)
    install(target, manifests)
    payload = json.loads(manifest_path(manifests).read_text("utf-8"))
    forged = "0" * 64
    payload["canonical_resources"][0]["sha256"] = forged
    payload["records"][0]["source_sha256"] = forged
    manifest_path(manifests).write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(SkillInstallError, match="canonical resource"):
        uninstall(target, manifests)
    assert (target / CLAUDE).exists()
    assert (target / CODEX).exists()


def test_boolean_schema_version_is_rejected(tmp_path: Path) -> None:
    target, manifests = _roots(tmp_path)
    install(target, manifests)
    payload = json.loads(manifest_path(manifests).read_text("utf-8"))
    payload["schema_version"] = True
    manifest_path(manifests).write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(SkillInstallError, match="identity"):
        uninstall(target, manifests)
    assert (target / CLAUDE).exists()
    assert (target / CODEX).exists()


def test_uninstall_parent_swap_cannot_redirect_unlink_outside_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target, manifests = _roots(tmp_path)
    install(target, manifests)
    outside = tmp_path / "outside-skill"
    outside.mkdir()
    outside_file = outside / "SKILL.md"
    outside_file.write_bytes((target / CLAUDE).read_bytes())
    original_parent = target / CLAUDE.parent
    detached_parent = target / ".claude/skills/lifeos-ingest-detached"
    swapped = False

    def swap_parent(relative: str) -> None:
        nonlocal swapped
        if relative != CLAUDE.as_posix() or swapped:
            return
        original_parent.rename(detached_parent)
        original_parent.symlink_to(outside, target_is_directory=True)
        swapped = True

    monkeypatch.setattr(installer_module, "_before_unlink", swap_parent)
    result = uninstall(target, manifests)

    assert swapped is True
    assert outside_file.exists()
    assert outside_file.read_bytes() != b""
    assert not (detached_parent / "SKILL.md").exists()
    assert CLAUDE.as_posix() in result.removed


def test_uninstall_preserves_same_inode_drift_in_final_unlink_window(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target, manifests = _roots(tmp_path)
    install(target, manifests)
    modified = b"modified after uninstall preflight\n"

    def mutate_before_unlink(relative: str) -> None:
        if relative == CLAUDE.as_posix():
            (target / CLAUDE).write_bytes(modified)

    monkeypatch.setattr(installer_module, "_before_unlink", mutate_before_unlink)
    result = uninstall(target, manifests)

    assert (target / CLAUDE).read_bytes() == modified
    assert CLAUDE.as_posix() in result.preserved
    assert not [
        path for path in target.rglob("*") if path.name.startswith(".lifeos-remove-")
    ]


def test_process_exit_after_quarantine_rename_is_reconciled_without_losing_ownership(
    tmp_path: Path,
) -> None:
    target, manifests = _roots(tmp_path)
    install(target, manifests)
    script = """
import os
import sys
from pathlib import Path
from tool_life_os_runtime.ext.skills import uninstall
from tool_life_os_runtime.ext.skills import installer

def crash(_relative):
    os._exit(86)

installer._after_quarantine_rename = crash
uninstall(Path(sys.argv[1]), Path(sys.argv[2]))
"""
    crashed = subprocess.run(
        [sys.executable, "-c", script, str(target), str(manifests)],
        check=False,
        capture_output=True,
        text=True,
        cwd=Path(__file__).resolve().parents[1],
    )
    assert crashed.returncode == 86
    payload = json.loads(manifest_path(manifests).read_text("utf-8"))
    assert len(payload["quarantines"]) == 1
    entry = payload["quarantines"][0]
    quarantined = target / Path(entry["path"]).parent / entry["quarantine"]
    assert quarantined.is_file()
    assert quarantined.stat().st_ino == entry["file_identity"]["inode"]
    assert "quarantine-unresolved" in {
        issue.code for issue in check(target, manifests).issues
    }

    result = uninstall(target, manifests)

    assert len(result.missing) == 1
    assert len(result.removed) == 29
    assert not manifest_path(manifests).exists()
    assert not [
        path for path in target.rglob("*") if path.name.startswith(".lifeos-remove-")
    ]


def test_process_exit_after_foreign_inode_quarantine_restores_foreign_to_public_path(
    tmp_path: Path,
) -> None:
    target, manifests = _roots(tmp_path)
    install(target, manifests)
    foreign = b"foreign replacement before quarantine rename\n"
    script = """
import os
import sys
from pathlib import Path
from tool_life_os_runtime.ext.skills import uninstall
from tool_life_os_runtime.ext.skills import installer

target = Path(sys.argv[1])

def replace(relative):
    wrapper = target / relative
    wrapper.unlink()
    wrapper.write_bytes(b"foreign replacement before quarantine rename\\n")

def crash(_relative):
    os._exit(93)

installer._before_unlink = replace
installer._after_quarantine_rename = crash
uninstall(target, Path(sys.argv[2]))
"""
    crashed = subprocess.run(
        [sys.executable, "-c", script, str(target), str(manifests)],
        check=False,
        capture_output=True,
        text=True,
        cwd=Path(__file__).resolve().parents[1],
    )
    assert crashed.returncode == 93
    payload = json.loads(manifest_path(manifests).read_text("utf-8"))
    entry = payload["quarantines"][0]
    original = target / entry["path"]
    quarantined = original.parent / entry["quarantine"]
    assert not original.exists()
    assert quarantined.read_bytes() == foreign
    assert quarantined.stat().st_ino != entry["file_identity"]["inode"]

    result = uninstall(target, manifests)
    assert entry["path"] in result.preserved
    assert len(result.removed) == 29
    assert original.read_bytes() == foreign
    assert not quarantined.exists()
    assert not manifest_path(manifests).exists()


def test_foreign_quarantine_recovery_never_overwrites_new_live_wrapper(
    tmp_path: Path,
) -> None:
    target, manifests = _roots(tmp_path)
    install(target, manifests)
    quarantined_foreign = b"foreign replacement before quarantine rename\n"
    live_foreign = b"new live wrapper after process exit\n"
    script = """
import os
import sys
from pathlib import Path
from tool_life_os_runtime.ext.skills import uninstall
from tool_life_os_runtime.ext.skills import installer

target = Path(sys.argv[1])

def replace(relative):
    wrapper = target / relative
    wrapper.unlink()
    wrapper.write_bytes(b"foreign replacement before quarantine rename\\n")

def crash(_relative):
    os._exit(93)

installer._before_unlink = replace
installer._after_quarantine_rename = crash
uninstall(target, Path(sys.argv[2]))
"""
    crashed = subprocess.run(
        [sys.executable, "-c", script, str(target), str(manifests)],
        check=False,
        capture_output=True,
        text=True,
        cwd=Path(__file__).resolve().parents[1],
    )
    assert crashed.returncode == 93
    payload = json.loads(manifest_path(manifests).read_text("utf-8"))
    entry = payload["quarantines"][0]
    original = target / entry["path"]
    quarantined = original.parent / entry["quarantine"]
    assert quarantined.read_bytes() == quarantined_foreign
    original.write_bytes(live_foreign)

    with pytest.raises(SkillInstallError, match="without overwriting a live wrapper"):
        uninstall(target, manifests)
    assert original.read_bytes() == live_foreign
    assert quarantined.read_bytes() == quarantined_foreign
    assert manifest_path(manifests).exists()


def test_process_exit_before_quarantine_rename_retries_without_orphan(
    tmp_path: Path,
) -> None:
    target, manifests = _roots(tmp_path)
    install(target, manifests)
    script = """
import os
import sys
from pathlib import Path
from tool_life_os_runtime.ext.skills import uninstall
from tool_life_os_runtime.ext.skills import installer

def crash(_relative):
    os._exit(84)

installer._before_unlink = crash
uninstall(Path(sys.argv[1]), Path(sys.argv[2]))
"""
    crashed = subprocess.run(
        [sys.executable, "-c", script, str(target), str(manifests)],
        check=False,
        capture_output=True,
        text=True,
        cwd=Path(__file__).resolve().parents[1],
    )
    assert crashed.returncode == 84
    payload = json.loads(manifest_path(manifests).read_text("utf-8"))
    entry = payload["quarantines"][0]
    quarantine = target / Path(entry["path"]).parent / entry["quarantine"]
    assert not quarantine.exists()
    assert (target / entry["path"]).stat().st_ino == entry["file_identity"]["inode"]

    result = uninstall(target, manifests)
    assert len(result.removed) == 29
    assert len(result.missing) == 1
    assert not manifest_path(manifests).exists()
    assert not [
        path for path in target.rglob("*") if path.name.startswith(".lifeos-remove-")
    ]


def test_foreign_quarantine_leaf_after_process_exit_is_never_adopted_or_deleted(
    tmp_path: Path,
) -> None:
    target, manifests = _roots(tmp_path)
    install(target, manifests)
    script = """
import os
import sys
from pathlib import Path
from tool_life_os_runtime.ext.skills import uninstall
from tool_life_os_runtime.ext.skills import installer

def crash(_relative):
    os._exit(84)

installer._before_unlink = crash
uninstall(Path(sys.argv[1]), Path(sys.argv[2]))
"""
    crashed = subprocess.run(
        [sys.executable, "-c", script, str(target), str(manifests)],
        check=False,
        capture_output=True,
        text=True,
        cwd=Path(__file__).resolve().parents[1],
    )
    assert crashed.returncode == 84
    payload = json.loads(manifest_path(manifests).read_text("utf-8"))
    entry = payload["quarantines"][0]
    foreign = target / Path(entry["path"]).parent / entry["quarantine"]
    foreign_bytes = b"foreign quarantine leaf\n"
    foreign.write_bytes(foreign_bytes)

    with pytest.raises(SkillInstallError, match="without overwriting a live wrapper"):
        uninstall(target, manifests)
    assert foreign.read_bytes() == foreign_bytes
    assert manifest_path(manifests).exists()
    assert (target / CLAUDE).exists()
    assert (target / CODEX).exists()


def test_quarantine_rename_never_replaces_leaf_appearing_at_publish_seam(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target, manifests = _roots(tmp_path)
    install(target, manifests)
    real_rename = installer_module._rename_noreplace_at
    foreign_bytes = b"foreign leaf at rename seam\n"
    foreign_paths: list[Path] = []

    def insert_then_rename(parent_fd: int, source: str, destination: str) -> None:
        if destination.startswith(".lifeos-remove-") and not foreign_paths:
            descriptor = os.open(
                destination,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=parent_fd,
            )
            try:
                os.write(descriptor, foreign_bytes)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            foreign_paths.append(target / FIRST_SORTED_WRAPPER.parent / destination)
        real_rename(parent_fd, source, destination)

    monkeypatch.setattr(installer_module, "_rename_noreplace_at", insert_then_rename)
    with pytest.raises(SkillInstallError, match="appeared before rename"):
        uninstall(target, manifests)

    assert len(foreign_paths) == 1
    assert foreign_paths[0].read_bytes() == foreign_bytes
    assert (target / CODEX).exists()
    assert manifest_path(manifests).exists()


def test_manifest_parent_swap_cannot_redirect_unlink_to_external_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target, manifests = _roots(tmp_path)
    install(target, manifests)
    outside = tmp_path / "outside-manifests"
    outside.mkdir()
    outside_manifest = outside / manifest_path(manifests).name
    foreign = b"external manifest must survive\n"
    outside_manifest.write_bytes(foreign)
    detached = manifests.with_name("install-detached")

    def swap_manifest_parent() -> None:
        manifests.rename(detached)
        manifests.symlink_to(outside, target_is_directory=True)

    monkeypatch.setattr(
        installer_module, "_before_manifest_unlink", swap_manifest_parent
    )
    result = uninstall(target, manifests)

    assert len(result.removed) == 30
    assert outside_manifest.read_bytes() == foreign
    assert not (detached / outside_manifest.name).exists()


def test_atomic_write_fsyncs_file_after_mode_and_parent_after_replace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = tmp_path / "artifact.json"
    events: list[str] = []
    real_fchmod = os.fchmod
    real_fsync = os.fsync
    real_replace = os.replace

    def observed_fchmod(fd: int, mode: int) -> None:
        events.append("fchmod")
        real_fchmod(fd, mode)

    def observed_fsync(fd: int) -> None:
        mode = os.fstat(fd).st_mode
        events.append("fsync-dir" if stat.S_ISDIR(mode) else "fsync-file")
        real_fsync(fd)

    def observed_replace(source: str, target: str, **kwargs: int) -> None:
        events.append("replace")
        real_replace(source, target, **kwargs)

    monkeypatch.setattr(os, "fchmod", observed_fchmod)
    monkeypatch.setattr(os, "fsync", observed_fsync)
    monkeypatch.setattr(os, "replace", observed_replace)
    parent_fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        installer_module._atomic_write_at(
            parent_fd, destination.name, b"{}\n", label="test"
        )
    finally:
        os.close(parent_fd)

    assert events == ["fchmod", "fsync-file", "replace", "fsync-dir"]
    assert destination.read_bytes() == b"{}\n"


def test_install_fsyncs_each_parent_immediately_after_mkdir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target, manifests = _roots(tmp_path)
    events: list[str] = []
    real_mkdir = os.mkdir
    real_fsync = os.fsync

    def observed_mkdir(
        path: str, mode: int = 0o777, *, dir_fd: int | None = None
    ) -> None:
        events.append(f"mkdir:{path}")
        real_mkdir(path, mode, dir_fd=dir_fd)

    def observed_fsync(fd: int) -> None:
        events.append(
            "fsync-dir" if stat.S_ISDIR(os.fstat(fd).st_mode) else "fsync-file"
        )
        real_fsync(fd)

    monkeypatch.setattr(os, "mkdir", observed_mkdir)
    monkeypatch.setattr(os, "fsync", observed_fsync)
    install(target, manifests)

    mkdir_indexes = [
        index for index, event in enumerate(events) if event.startswith("mkdir:")
    ]
    assert mkdir_indexes
    assert all(events[index + 1] == "fsync-dir" for index in mkdir_indexes)


def test_manifest_symlink_is_never_followed(tmp_path: Path) -> None:
    target, manifests = _roots(tmp_path)
    outside = tmp_path / "foreign-state.json"
    outside.write_text("foreign\n", encoding="utf-8")
    manifest_path(manifests).symlink_to(outside)

    with pytest.raises(SkillInstallError, match="regular file"):
        install(target, manifests)
    assert outside.read_text("utf-8") == "foreign\n"


def test_atomic_output_has_exact_manifest_hashes_and_no_temporary_residue(
    tmp_path: Path,
) -> None:
    target, manifests = _roots(tmp_path)
    install(target, manifests)
    payload = json.loads(manifest_path(manifests).read_text("utf-8"))
    for record in payload["records"]:
        body = (target / record["path"]).read_bytes()
        assert hashlib.sha256(body).hexdigest() == record["sha256"]
    assert not [
        path for path in tmp_path.rglob("*") if path.name.startswith(".SKILL.md.")
    ]
    assert not [
        path
        for path in tmp_path.rglob("*")
        if path.name.startswith(".lifeos-skills-v1.json.")
    ]
    assert not [
        path for path in tmp_path.rglob("*") if path.name.startswith(".lifeos-write-")
    ]


def test_explicit_roots_only_and_generated_artifacts_are_privacy_safe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target, manifests = _roots(tmp_path)
    fake_home = tmp_path / "must-remain-empty"
    fake_home.mkdir()
    monkeypatch.setenv("HOME", str(fake_home))
    install(target, manifests)

    assert list(fake_home.iterdir()) == []
    combined = b"\n".join(_snapshot(tmp_path).values()).decode("utf-8")
    assert str(tmp_path) not in combined
    assert "PRIVATE " + "KEY" not in combined
    assert "to" + "ken=" not in combined.lower()


def test_direct_traversal_helper_rejected() -> None:
    with pytest.raises(SkillInstallError, match="unsafe relative path"):
        installer_module._validate_relative("../foreign")
    with pytest.raises(SkillInstallError, match="unsupported harness"):
        installer_module._wrapper(
            canonical_resource("ingest"), "../../foreign", "0.1.0"
        )
