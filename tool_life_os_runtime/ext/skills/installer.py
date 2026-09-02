"""Deterministic and fail-closed installation of harness skill wrappers."""

from __future__ import annotations

from dataclasses import dataclass
import ctypes
import errno
import hashlib
from importlib import metadata
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
from typing import Any, Callable, Mapping
import uuid

from .resources import (
    CANONICAL_SKILL_IDS,
    CanonicalSkill,
    SkillPackError,
    canonical_resource,
    canonical_skills,
    validate_skill_pack,
)


class SkillInstallError(ValueError):
    """A skill pack operation is unsafe or its ownership is ambiguous."""


@dataclass(frozen=True)
class InstallResult:
    changed: bool
    installed: tuple[str, ...]
    manifest: str


@dataclass(frozen=True)
class CheckIssue:
    code: str
    path: str | None = None


@dataclass(frozen=True)
class CheckResult:
    ok: bool
    state: str
    issues: tuple[CheckIssue, ...]


@dataclass(frozen=True)
class UninstallResult:
    removed: tuple[str, ...]
    preserved: tuple[str, ...]
    missing: tuple[str, ...]


_SCHEMA_VERSION = 1
_MANIFEST_NAME = "lifeos-skills-v1.json"
_GENERATED_BY = "tool_life_os_runtime.ext.skills"
_GENERATED_NOTICE = "<!-- GENERATED tool-life-os-runtime skills; do not edit -->"
_HASH = re.compile(r"^[0-9a-f]{64}$")
_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$")
_HARNESS_ROOTS = {
    "claude": PurePosixPath(".claude/skills"),
    "codex": PurePosixPath(".agents/skills"),
}


def _wrapper_path(skill: CanonicalSkill, harness: str) -> PurePosixPath:
    try:
        root = _HARNESS_ROOTS[harness]
    except KeyError as exc:
        raise SkillInstallError("unsupported harness") from exc
    return root / skill.name / "SKILL.md"


def _runtime_version() -> str:
    try:
        value = metadata.version("tool-life-os-runtime")
    except metadata.PackageNotFoundError:
        value = "0.1.0"
    if not _VERSION.fullmatch(value):
        raise SkillInstallError("runtime version is not safe to render")
    return value


def _sha256_bytes(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def _root_fingerprint(root: Path) -> str:
    return hashlib.sha256(os.fsencode(root)).hexdigest()


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


def _before_root_resolve(_label: str) -> None:
    """Test seam after fd anchoring and before canonical path resolution."""


def _open_root_anchor(path: str | Path, *, label: str) -> tuple[Path, int]:
    root = Path(path)
    descriptor = -1
    try:
        descriptor = os.open(root, _directory_flags())
        opened = os.fstat(descriptor)
        named = os.stat(root, follow_symlinks=False)
    except OSError as exc:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            rejected = os.stat(root, follow_symlinks=False)
        except OSError:
            rejected = None
        if rejected is not None and stat.S_ISLNK(rejected.st_mode):
            raise SkillInstallError(f"{label} must be a real directory") from exc
        raise SkillInstallError(f"{label} must be an existing directory") from exc
    try:
        identity = (opened.st_dev, opened.st_ino)
        if not stat.S_ISDIR(opened.st_mode) or identity != (named.st_dev, named.st_ino):
            raise SkillInstallError(f"{label} changed while it was anchored")
        _before_root_resolve(label)
        resolved = root.resolve(strict=True)
        resolved_named = os.stat(resolved, follow_symlinks=False)
        current_named = os.stat(root, follow_symlinks=False)
        if (
            identity != (resolved_named.st_dev, resolved_named.st_ino)
            or identity != (current_named.st_dev, current_named.st_ino)
            or not stat.S_ISDIR(current_named.st_mode)
        ):
            raise SkillInstallError(f"{label} changed while it was resolved")
        return resolved, descriptor
    except (OSError, RuntimeError) as exc:
        os.close(descriptor)
        raise SkillInstallError(f"{label} cannot be resolved") from exc
    except Exception:
        os.close(descriptor)
        raise


def _validate_root(path: str | Path, *, label: str) -> Path:
    root, descriptor = _open_root_anchor(path, label=label)
    os.close(descriptor)
    return root


def _validate_relative(value: str | PurePosixPath) -> PurePosixPath:
    relative = PurePosixPath(value)
    if (
        relative.is_absolute()
        or not relative.parts
        or any(part in {"", ".", ".."} for part in relative.parts)
        or any(
            any(ord(character) < 32 or ord(character) == 127 for character in part)
            for part in relative.parts
        )
    ):
        raise SkillInstallError("manifest contains an unsafe relative path")
    return relative


def manifest_path(manifest_root: str | Path) -> Path:
    """Return the fixed manifest path below an explicit runtime-home directory."""

    return _validate_root(manifest_root, label="manifest root") / _MANIFEST_NAME


def _open_operation_roots(
    target_root: str | Path,
    manifest_root: str | Path,
    *,
    expected_target_identity: tuple[int, int] | None = None,
    expected_manifest_identity: tuple[int, int] | None = None,
    expected_manifest_parent_identity: tuple[int, int] | None = None,
) -> tuple[Path, Path, int, int, int]:
    target, target_fd = _open_root_anchor(target_root, label="target root")
    manifest_parent_fd = -1
    manifest_fd = -1
    try:
        manifest_input = Path(manifest_root)
        if manifest_input.name in {"", ".", ".."}:
            raise SkillInstallError("manifest root must have a parent directory")
        manifest_parent, manifest_parent_fd = _open_root_anchor(
            manifest_input.parent, label="manifest root parent"
        )
        if expected_manifest_parent_identity is not None and (
            type(expected_manifest_parent_identity) is not tuple
            or len(expected_manifest_parent_identity) != 2
            or any(
                type(item) is not int or item < 0
                for item in expected_manifest_parent_identity
            )
            or (
                os.fstat(manifest_parent_fd).st_dev,
                os.fstat(manifest_parent_fd).st_ino,
            )
            != expected_manifest_parent_identity
        ):
            raise SkillInstallError(
                "manifest root parent does not match caller evidence"
            )
        _before_root_resolve("manifest root")
        try:
            manifest_fd = os.open(
                manifest_input.name,
                _directory_flags(),
                dir_fd=manifest_parent_fd,
            )
        except OSError as exc:
            raise SkillInstallError(
                "manifest root changed while it was resolved"
            ) from exc
        manifest_opened = os.fstat(manifest_fd)
        manifest_named = os.stat(
            manifest_input.name,
            dir_fd=manifest_parent_fd,
            follow_symlinks=False,
        )
        if not stat.S_ISDIR(manifest_opened.st_mode) or (
            manifest_opened.st_dev,
            manifest_opened.st_ino,
        ) != (manifest_named.st_dev, manifest_named.st_ino):
            raise SkillInstallError("manifest root changed while it was anchored")
        manifests = manifest_parent / manifest_input.name
        for label, descriptor, expected in (
            ("target root", target_fd, expected_target_identity),
            ("manifest root", manifest_fd, expected_manifest_identity),
        ):
            if expected is not None:
                if (
                    type(expected) is not tuple
                    or len(expected) != 2
                    or any(type(item) is not int or item < 0 for item in expected)
                    or (os.fstat(descriptor).st_dev, os.fstat(descriptor).st_ino)
                    != expected
                ):
                    raise SkillInstallError(f"{label} does not match caller evidence")
        target_current = os.stat(target_root, follow_symlinks=False)
        manifest_parent_current = os.stat(manifest_input.parent, follow_symlinks=False)
        manifest_current = os.stat(manifest_root, follow_symlinks=False)
        if (target_current.st_dev, target_current.st_ino) != (
            os.fstat(target_fd).st_dev,
            os.fstat(target_fd).st_ino,
        ):
            raise SkillInstallError("target root changed while roots were bound")
        if (manifest_current.st_dev, manifest_current.st_ino) != (
            os.fstat(manifest_fd).st_dev,
            os.fstat(manifest_fd).st_ino,
        ):
            raise SkillInstallError("manifest root changed while roots were bound")
        if (
            manifest_parent_current.st_dev,
            manifest_parent_current.st_ino,
        ) != (
            os.fstat(manifest_parent_fd).st_dev,
            os.fstat(manifest_parent_fd).st_ino,
        ):
            raise SkillInstallError(
                "manifest root parent changed while roots were bound"
            )
        if (
            target == manifests
            or target in manifests.parents
            or manifests in target.parents
        ):
            raise SkillInstallError("target root and manifest root must not overlap")
        return target, manifests, target_fd, manifest_fd, manifest_parent_fd
    except Exception:
        os.close(target_fd)
        if manifest_fd >= 0:
            os.close(manifest_fd)
        if manifest_parent_fd >= 0:
            os.close(manifest_parent_fd)
        raise


def _directory_flags() -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return flags


def _file_flags() -> int:
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return flags


def _open_parent_at(
    root_fd: int,
    relative: str | PurePosixPath,
    *,
    create: bool,
) -> tuple[int, str] | None:
    parts = _validate_relative(relative).parts
    current = os.dup(root_fd)
    try:
        for index, part in enumerate(parts[:-1]):
            try:
                following = os.open(part, _directory_flags(), dir_fd=current)
            except FileNotFoundError:
                if not create:
                    os.close(current)
                    return None
                _assert_fd_at_parts(root_fd, parts[:index], current)
                try:
                    os.mkdir(part, mode=0o755, dir_fd=current)
                except FileExistsError:
                    pass
                os.fsync(current)
                following = os.open(part, _directory_flags(), dir_fd=current)
            os.close(current)
            current = following
        return current, parts[-1]
    except OSError as exc:
        os.close(current)
        raise SkillInstallError("wrapper path crosses an unsafe component") from exc


def _assert_fd_at_parts(root_fd: int, parts: tuple[str, ...], expected_fd: int) -> None:
    current = os.dup(root_fd)
    try:
        for part in parts:
            following = os.open(part, _directory_flags(), dir_fd=current)
            os.close(current)
            current = following
        if _fd_identity(current) != _fd_identity(expected_fd):
            raise SkillInstallError("wrapper parent moved outside target root")
    except OSError as exc:
        raise SkillInstallError("wrapper parent moved outside target root") from exc
    finally:
        os.close(current)


def _identity_from_stat(info: os.stat_result) -> dict[str, int]:
    return {"device": info.st_dev, "inode": info.st_ino}


def _fd_identity(descriptor: int) -> dict[str, int]:
    try:
        return _identity_from_stat(os.fstat(descriptor))
    except OSError as exc:
        raise SkillInstallError("cannot read local install identity") from exc


def _valid_identity(value: object) -> bool:
    return (
        isinstance(value, dict)
        and set(value) == {"device", "inode"}
        and type(value["device"]) is int
        and type(value["inode"]) is int
        and value["device"] >= 0
        and value["inode"] > 0
    )


def _hash_regular_at(parent_fd: int, name: str) -> tuple[str, dict[str, int]] | None:
    try:
        descriptor = os.open(name, _file_flags(), dir_fd=parent_fd)
    except FileNotFoundError:
        return None
    except OSError as exc:
        if exc.errno in {errno.ELOOP, errno.EISDIR}:
            raise SkillInstallError("installed wrapper must be a regular file") from exc
        raise SkillInstallError("cannot open installed wrapper") from exc
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise SkillInstallError("installed wrapper must be a regular file")
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
        return digest.hexdigest(), _identity_from_stat(info)
    except OSError as exc:
        raise SkillInstallError("cannot read installed wrapper") from exc
    finally:
        os.close(descriptor)


def _read_regular_at(parent_fd: int, name: str, *, label: str) -> bytes | None:
    try:
        descriptor = os.open(name, _file_flags(), dir_fd=parent_fd)
    except FileNotFoundError:
        return None
    except OSError as exc:
        if exc.errno in {errno.ELOOP, errno.EISDIR}:
            raise SkillInstallError(f"{label} must be a regular file") from exc
        raise SkillInstallError(f"cannot open {label}") from exc
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise SkillInstallError(f"{label} must be a regular file")
        if info.st_size > 1024 * 1024:
            raise SkillInstallError(f"{label} is too large")
        chunks: list[bytes] = []
        size = 0
        while chunk := os.read(descriptor, 64 * 1024):
            size += len(chunk)
            if size > 1024 * 1024:
                raise SkillInstallError(f"{label} is too large")
            chunks.append(chunk)
        return b"".join(chunks)
    except OSError as exc:
        raise SkillInstallError(f"cannot read {label}") from exc
    finally:
        os.close(descriptor)


def _before_atomic_replace(_label: str) -> None:
    """Test seam immediately before an anchored replace."""


def _before_atomic_publish(_label: str) -> None:
    """Test seam before binding and no-clobber wrapper publication."""


def _atomic_write_at(parent_fd: int, name: str, body: bytes, *, label: str) -> None:
    """Create, sync and replace a leaf through one anchored parent descriptor."""

    _validate_relative(name)
    if "/" in name:
        raise SkillInstallError("atomic write name must be one path component")
    temporary = f".lifeos-write-{uuid.uuid4().hex}"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = -1
    try:
        descriptor = os.open(temporary, flags, 0o600, dir_fd=parent_fd)
        view = memoryview(body)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short atomic write")
            view = view[written:]
        os.fchmod(descriptor, 0o644)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        _before_atomic_replace(label)
        os.replace(temporary, name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        os.fsync(parent_fd)
    except OSError as exc:
        raise SkillInstallError("atomic skill write failed") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary, dir_fd=parent_fd)
        except FileNotFoundError:
            pass
        except OSError:
            pass


def _after_publish_stage(_label: str) -> None:
    """Test seam after a complete stage and before publication."""


def _after_partial_stage_write(_label: str) -> None:
    """Test seam after a partial body write with durable inode evidence."""


def _after_stage_create(_label: str) -> None:
    """Test seam after canonical stage creation and before its body write."""


def _create_stage_at(
    target_fd: int,
    staging: str,
    body: bytes,
    *,
    expected_hash: str,
    label: str,
) -> tuple[str, dict[str, int]]:
    """Create or verify one content-addressed canonical publication stage."""

    if staging != f".lifeos-publish-{expected_hash}" or not _HASH.fullmatch(
        expected_hash
    ):
        raise SkillInstallError("publication staging name is invalid")
    if _sha256_bytes(body) != expected_hash:
        raise SkillInstallError("publication staging body does not match its name")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = -1
    try:
        try:
            descriptor = os.open(staging, flags, 0o600, dir_fd=target_fd)
        except FileExistsError:
            observed = _hash_regular_at(target_fd, staging)
            if observed is None or observed[0] != expected_hash:
                raise SkillInstallError(
                    "canonical publication staging has foreign drift"
                )
            return observed
        _after_stage_create(label)
        _write_stage_body(descriptor, body, label=label)
        os.close(descriptor)
        descriptor = -1
        os.fsync(target_fd)
    except Exception as exc:
        if descriptor >= 0:
            os.close(descriptor)
        if isinstance(exc, OSError):
            raise SkillInstallError("atomic wrapper staging failed") from exc
        raise
    observed = _hash_regular_at(target_fd, staging)
    if observed is None or observed[0] != expected_hash:
        raise SkillInstallError("canonical publication staging did not verify")
    return observed


def _write_all(descriptor: int, body: memoryview) -> None:
    while body:
        written = os.write(descriptor, body)
        if written <= 0:
            raise OSError("short atomic publish write")
        body = body[written:]


def _write_stage_body(descriptor: int, body: bytes, *, label: str) -> None:
    """Write stage bytes only after its inode evidence is durable."""

    split = max(1, len(body) // 2)
    try:
        _write_all(descriptor, memoryview(body)[:split])
        _after_partial_stage_write(label)
        _write_all(descriptor, memoryview(body)[split:])
        os.fchmod(descriptor, 0o644)
        os.fsync(descriptor)
    except OSError as exc:
        raise SkillInstallError("atomic wrapper staging failed") from exc


def _after_publish_link(_label: str) -> None:
    """Test seam for process exit after link and before identity evidence."""


def _link_staged_at(
    target_fd: int,
    parent_fd: int,
    name: str,
    staging: str,
    *,
    label: str,
    verify_parent: Callable[[], None],
) -> None:
    """Publish a durable staged inode without replacing an existing leaf."""

    _validate_relative(name)
    if "/" in name:
        raise SkillInstallError("atomic publish name must be one path component")
    _before_atomic_publish(label)
    verify_parent()
    try:
        os.link(
            staging,
            name,
            src_dir_fd=target_fd,
            dst_dir_fd=parent_fd,
            follow_symlinks=False,
        )
        os.fsync(parent_fd)
        _after_publish_link(label)
    except FileExistsError as exc:
        raise SkillInstallError("wrapper destination appeared before publish") from exc
    except OSError as exc:
        raise SkillInstallError("atomic wrapper publish failed") from exc


def _after_staging_cleanup_rename(_staging: str) -> None:
    """Test seam after durable cleanup rename and before verified unlink."""


def _after_staging_cleanup_hash(_cleanup: str) -> None:
    """Test seam after exact cleanup hash and before conditional quarantine."""


def _after_staging_verify_rename(_verification: str) -> None:
    """Test seam after cleanup quarantine and before its final verification."""


def _cleanup_staging(
    target_fd: int,
    staging: str,
    *,
    expected_hash: str,
    expected_identity: Mapping[str, int],
) -> None:
    cleanup = f".lifeos-publish-clean-{expected_hash}"
    verification = f".lifeos-publish-verify-{expected_hash}"
    staged = _hash_regular_at(target_fd, staging)
    quarantined = _hash_regular_at(target_fd, cleanup)
    verifying = _hash_regular_at(target_fd, verification)
    if sum(item is not None for item in (staged, quarantined, verifying)) > 1:
        raise SkillInstallError("publication staging cleanup collides")
    if quarantined is None and staged is None and verifying is None:
        return
    if quarantined is None and verifying is None:
        if (
            staged is None
            or staged[0] != expected_hash
            or staged[1] != expected_identity
        ):
            raise SkillInstallError("publication staging cleanup lacks exact evidence")
        try:
            _rename_noreplace_at(target_fd, staging, cleanup)
            os.fsync(target_fd)
            _after_staging_cleanup_rename(staging)
        except FileExistsError as exc:
            raise SkillInstallError(
                "publication staging cleanup appeared concurrently"
            ) from exc
        except OSError as exc:
            raise SkillInstallError("cannot quarantine publication staging") from exc
        quarantined = _hash_regular_at(target_fd, cleanup)
    if verifying is None:
        if (
            quarantined is None
            or quarantined[0] != expected_hash
            or quarantined[1] != expected_identity
        ):
            raise SkillInstallError("publication staging cleanup has foreign drift")
        _after_staging_cleanup_hash(cleanup)
        try:
            _rename_noreplace_at(target_fd, cleanup, verification)
            os.fsync(target_fd)
            _after_staging_verify_rename(verification)
        except FileExistsError as exc:
            raise SkillInstallError(
                "publication staging verification appeared concurrently"
            ) from exc
        except OSError as exc:
            raise SkillInstallError(
                "cannot verify publication staging removal"
            ) from exc
        verifying = _hash_regular_at(target_fd, verification)
    if (
        verifying is None
        or verifying[0] != expected_hash
        or verifying[1] != expected_identity
    ):
        try:
            _rename_noreplace_at(target_fd, verification, cleanup)
            os.fsync(target_fd)
        except (FileExistsError, FileNotFoundError, OSError) as exc:
            raise SkillInstallError(
                "publication staging foreign replacement could not be restored"
            ) from exc
        raise SkillInstallError("publication staging cleanup has foreign drift")
    try:
        os.unlink(verification, dir_fd=target_fd)
        os.fsync(target_fd)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise SkillInstallError("cannot remove publication staging") from exc


def _wrapper(skill: CanonicalSkill, harness: str, runtime_version: str) -> bytes:
    if harness not in _HARNESS_ROOTS:
        raise SkillInstallError("unsupported harness")
    body = (
        "---\n"
        f"name: {skill.name}\n"
        f"description: {skill.description}\n"
        "---\n"
        f"{_GENERATED_NOTICE}\n"
        f"# {skill.name}\n\n"
        f"Harness: `{harness}`\n\n"
        f"Canonical resource: `{skill.resource_id}`\n\n"
        f"Canonical SHA-256: `{skill.sha256}`\n\n"
        f"Artifact contract: `{skill.artifact_contract.contract_id}`\n\n"
        f"Artifact SHA-256: `{skill.artifact_contract.sha256}`\n\n"
        f"Route status: `{skill.status}`\n\n"
        + (
            "Integration requirements: `"
            + "; ".join(
                f"{requirement.requirement_type}:{requirement.target}"
                f"[{','.join(requirement.action_ids)}]"
                for requirement in skill.integration_requirements
            )
            + "`\n\n"
            if skill.integration_requirements
            else ""
        )
        + f"Runtime version: `{runtime_version}`\n\n"
        "Load the canonical resource through the Life OS runtime skills surface. "
        "This wrapper contains routing metadata only. Artifact and authority "
        "contracts are identical across adapters; executor behavior is not promised "
        "to be identical.\n"
    )
    return body.encode("utf-8")


def _expected_records(
    runtime_version: str,
    file_identities: Mapping[str, Mapping[str, int]] | None = None,
) -> tuple[tuple[dict[str, Any], bytes], ...]:
    try:
        skills = validate_skill_pack(
            canonical_skills(), expected_ids=CANONICAL_SKILL_IDS
        )
    except SkillPackError as exc:
        raise SkillInstallError("canonical skill pack is invalid") from exc
    records: list[tuple[dict[str, Any], bytes]] = []
    for harness in _HARNESS_ROOTS:
        for skill in skills:
            body = _wrapper(skill, harness, runtime_version)
            relative = _wrapper_path(skill, harness).as_posix()
            records.append(
                (
                    {
                        "file_identity": (
                            None
                            if file_identities is None
                            or relative not in file_identities
                            else dict(file_identities[relative])
                        ),
                        "harness": harness,
                        "path": relative,
                        "sha256": _sha256_bytes(body),
                        "skill_id": skill.skill_id,
                        "source_sha256": skill.sha256,
                    },
                    body,
                )
            )
    return tuple(records)


def _manifest(
    target_root: Path,
    target_fd: int,
    manifest_fd: int,
    runtime_version: str,
    records: tuple[tuple[dict[str, Any], bytes], ...],
    *,
    state: str,
    publications: list[dict[str, Any]] | None = None,
    quarantines: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    skills = canonical_skills()
    return {
        "canonical_resources": [
            {
                "resource_id": skill.resource_id,
                "sha256": skill.sha256,
                "skill_id": skill.skill_id,
            }
            for skill in skills
        ],
        "generated_by": _GENERATED_BY,
        "local_install_evidence": {
            "manifest_root": _fd_identity(manifest_fd),
            "target_root": _fd_identity(target_fd),
        },
        "publications": [] if publications is None else publications,
        "quarantines": [] if quarantines is None else quarantines,
        "records": [record for record, _body in records],
        "runtime_version": runtime_version,
        "schema_version": _SCHEMA_VERSION,
        "state": state,
        "target_root_sha256": _root_fingerprint(target_root),
    }


def _load_manifest_at(manifest_fd: int) -> dict[str, Any] | None:
    raw = _read_regular_at(manifest_fd, _MANIFEST_NAME, label="skills manifest")
    if raw is None:
        return None
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise SkillInstallError("skills manifest is not readable JSON") from exc
    return _validate_manifest(value)


def _validate_manifest(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise SkillInstallError("skills manifest must be an object")
    expected_keys = {
        "canonical_resources",
        "generated_by",
        "local_install_evidence",
        "publications",
        "quarantines",
        "records",
        "runtime_version",
        "schema_version",
        "state",
        "target_root_sha256",
    }
    if set(value) != expected_keys:
        raise SkillInstallError("skills manifest fields are invalid")
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"] != _SCHEMA_VERSION
        or value["generated_by"] != _GENERATED_BY
    ):
        raise SkillInstallError("skills manifest identity is invalid")
    state = value["state"]
    if state not in {"installing", "installed"}:
        raise SkillInstallError("skills manifest state is invalid")
    runtime_version = value["runtime_version"]
    if not isinstance(runtime_version, str) or not _VERSION.fullmatch(runtime_version):
        raise SkillInstallError("skills manifest runtime version is invalid")
    if not isinstance(value["target_root_sha256"], str) or not _HASH.fullmatch(
        value["target_root_sha256"]
    ):
        raise SkillInstallError("skills manifest root binding is invalid")
    evidence = value["local_install_evidence"]
    if (
        not isinstance(evidence, dict)
        or set(evidence) != {"manifest_root", "target_root"}
        or not _valid_identity(evidence["manifest_root"])
        or not _valid_identity(evidence["target_root"])
    ):
        raise SkillInstallError("skills manifest local evidence is invalid")

    resources = value["canonical_resources"]
    skills = canonical_skills()
    expected_resources = [
        {
            "resource_id": skill.resource_id,
            "sha256": skill.sha256,
            "skill_id": skill.skill_id,
        }
        for skill in skills
    ]
    if not isinstance(resources, list) or resources != expected_resources:
        raise SkillInstallError(
            "skills manifest canonical resource does not match this runtime"
        )

    records = value["records"]
    expected_record_count = len(skills) * len(_HARNESS_ROOTS)
    if not isinstance(records, list) or len(records) != expected_record_count:
        raise SkillInstallError("skills manifest record set is invalid")
    by_skill_id = {skill.skill_id: skill for skill in skills}
    expected_paths = {
        _wrapper_path(skill, harness).as_posix(): (skill, harness)
        for harness in _HARNESS_ROOTS
        for skill in skills
    }
    seen: set[str] = set()
    for record in records:
        expected_fields = {
            "file_identity",
            "harness",
            "path",
            "sha256",
            "skill_id",
            "source_sha256",
        }
        if not isinstance(record, dict) or set(record) != expected_fields:
            raise SkillInstallError("skills manifest record fields are invalid")
        harness = record["harness"]
        path = record["path"]
        expected = expected_paths.get(path)
        if harness not in _HARNESS_ROOTS or expected is None or expected[1] != harness:
            raise SkillInstallError("skills manifest wrapper path is invalid")
        _validate_relative(path)
        skill = by_skill_id.get(record["skill_id"])
        if skill is None or expected[0] != skill or path in seen:
            raise SkillInstallError("skills manifest record identity is invalid")
        seen.add(path)
        if any(
            not isinstance(record[key], str) or not _HASH.fullmatch(record[key])
            for key in ("sha256", "source_sha256")
        ):
            raise SkillInstallError("skills manifest record hash is invalid")
        rendered = _wrapper(skill, harness, runtime_version)
        if record["source_sha256"] != skill.sha256 or record["sha256"] != _sha256_bytes(
            rendered
        ):
            raise SkillInstallError(
                "skills manifest wrapper ownership claim is invalid"
            )
        if state == "installed" and not _valid_identity(record["file_identity"]):
            raise SkillInstallError("installed wrapper local evidence is invalid")
        if (
            state == "installing"
            and record["file_identity"] is not None
            and not _valid_identity(record["file_identity"])
        ):
            raise SkillInstallError("installing wrapper local evidence is invalid")
    if seen != set(expected_paths):
        raise SkillInstallError("skills manifest does not cover both harnesses")
    publications = value["publications"]
    if not isinstance(publications, list) or len(publications) > 1:
        raise SkillInstallError("skills manifest publication journal is invalid")
    records_by_path = {record["path"]: record for record in records}
    for entry in publications:
        if not isinstance(entry, dict) or set(entry) != {
            "expected_sha256",
            "parent_identity",
            "path",
            "staged_identity",
            "staging",
        }:
            raise SkillInstallError("skills manifest publication entry is invalid")
        path = entry["path"]
        staging = entry["staging"]
        if (
            state != "installing"
            or path not in records_by_path
            or entry["expected_sha256"] != records_by_path[path]["sha256"]
            or not isinstance(staging, str)
            or staging != f".lifeos-publish-{entry['expected_sha256']}"
            or not _valid_identity(entry["parent_identity"])
            or not _valid_identity(entry["staged_identity"])
            or records_by_path[path]["file_identity"]
            not in (None, entry["staged_identity"])
        ):
            raise SkillInstallError("skills manifest publication evidence is invalid")
    quarantines = value["quarantines"]
    if not isinstance(quarantines, list) or len(quarantines) > expected_record_count:
        raise SkillInstallError("skills manifest quarantine journal is invalid")
    quarantine_paths: set[str] = set()
    for entry in quarantines:
        if not isinstance(entry, dict) or set(entry) != {
            "expected_sha256",
            "file_identity",
            "path",
            "quarantine",
        }:
            raise SkillInstallError("skills manifest quarantine entry is invalid")
        path = entry["path"]
        if path not in records_by_path or path in quarantine_paths:
            raise SkillInstallError("skills manifest quarantine path is invalid")
        quarantine_paths.add(path)
        quarantine = entry["quarantine"]
        if (
            not isinstance(quarantine, str)
            or not re.fullmatch(r"\.lifeos-remove-[0-9a-f]{32}", quarantine)
            or entry["expected_sha256"] != records_by_path[path]["sha256"]
            or entry["file_identity"] != records_by_path[path]["file_identity"]
            or not _valid_identity(entry["file_identity"])
        ):
            raise SkillInstallError("skills manifest quarantine evidence is invalid")
    return value


def _record_map(manifest: Mapping[str, Any] | None) -> dict[str, Mapping[str, Any]]:
    if manifest is None:
        return {}
    return {record["path"]: record for record in manifest["records"]}


def _claim_map(
    records: tuple[tuple[dict[str, Any], bytes], ...],
) -> dict[str, dict[str, Any]]:
    return {
        record["path"]: {
            key: value for key, value in record.items() if key != "file_identity"
        }
        for record, _body in records
    }


def _assert_local_binding(
    manifest: Mapping[str, Any],
    target_root: Path,
    target_fd: int,
    manifest_fd: int,
) -> None:
    if manifest["target_root_sha256"] != _root_fingerprint(target_root):
        raise SkillInstallError("skills manifest belongs to another target root")
    expected = {
        "manifest_root": _fd_identity(manifest_fd),
        "target_root": _fd_identity(target_fd),
    }
    if manifest["local_install_evidence"] != expected:
        raise SkillInstallError("skills manifest is not local evidence for these roots")


def _observe_at(
    target_fd: int,
    relative: str,
    *,
    create: bool,
) -> tuple[int, str, tuple[str, dict[str, int]] | None] | None:
    opened = _open_parent_at(target_fd, relative, create=create)
    if opened is None:
        return None
    parent_fd, name = opened
    try:
        observed = _hash_regular_at(parent_fd, name)
    except Exception:
        os.close(parent_fd)
        raise
    return parent_fd, name, observed


def _write_manifest_snapshot(manifest_fd: int, manifest: dict[str, Any]) -> None:
    _validate_manifest(manifest)
    _atomic_write_at(
        manifest_fd,
        _MANIFEST_NAME,
        _canonical_json(manifest),
        label="skills manifest",
    )


def _with_record_identity(
    manifest: dict[str, Any], path: str, identity: Mapping[str, int]
) -> dict[str, Any]:
    updated = dict(manifest)
    updated["records"] = [
        {**record, "file_identity": dict(identity)}
        if record["path"] == path
        else dict(record)
        for record in manifest["records"]
    ]
    return updated


def _create_and_fill_intent_stage(
    manifest: dict[str, Any],
    entry: dict[str, Any],
    target_fd: int,
    manifest_fd: int,
    body: bytes,
) -> tuple[dict[str, Any], dict[str, Any], tuple[str, dict[str, int]]]:
    staged = _create_stage_at(
        target_fd,
        entry["staging"],
        body,
        expected_hash=entry["expected_sha256"],
        label=entry["path"],
    )
    _after_publish_stage(entry["path"])
    updated_entry = {**entry, "staged_identity": staged[1]}
    updated = dict(manifest)
    updated["publications"] = [updated_entry]
    _write_manifest_snapshot(manifest_fd, updated)
    return updated, updated_entry, staged


def _reconcile_publications(
    manifest: dict[str, Any],
    target_fd: int,
    manifest_fd: int,
    *,
    mutate: bool,
) -> dict[str, Any]:
    if not manifest["publications"] or not mutate:
        return manifest
    entry = manifest["publications"][0]
    opened = _open_parent_at(target_fd, entry["path"], create=False)
    if opened is None:
        raise SkillInstallError("owned publication parent is unresolved")
    parent_fd, name = opened
    try:
        if _fd_identity(parent_fd) != entry["parent_identity"]:
            raise SkillInstallError("owned publication parent has moved")
        staged = _hash_regular_at(target_fd, entry["staging"])
        target = _hash_regular_at(parent_fd, name)
        record = _record_map(manifest)[entry["path"]]
        try:
            skill = canonical_resource(record["skill_id"])
        except KeyError as exc:
            raise SkillInstallError("publication references an unknown skill") from exc
        body = _wrapper(skill, record["harness"], manifest["runtime_version"])
        if staged is not None and staged[1] != entry["staged_identity"]:
            raise SkillInstallError("owned publication staging identity has drifted")
        elif staged is not None and staged[0] != entry["expected_sha256"]:
            raise SkillInstallError("owned publication staging has content drift")
        elif staged is None and target is None:
            cleared = dict(manifest)
            cleared["publications"] = []
            _write_manifest_snapshot(manifest_fd, cleared)
            manifest, entry, staged = _create_and_fill_intent_stage(
                cleared, entry, target_fd, manifest_fd, body
            )
        if staged is not None:
            if (
                staged[0] != entry["expected_sha256"]
                or staged[1] != entry["staged_identity"]
            ):
                raise SkillInstallError("owned publication staging has drifted")
            if target is None:
                _link_staged_at(
                    target_fd,
                    parent_fd,
                    name,
                    entry["staging"],
                    label=entry["path"],
                    verify_parent=lambda: _assert_parent_still_bound(
                        target_fd, entry["path"], parent_fd
                    ),
                )
                target = _hash_regular_at(parent_fd, name)
            if target is None or target[0] != staged[0] or target[1] != staged[1]:
                raise SkillInstallError(
                    "owned publication collides with another wrapper"
                )
        elif (
            target is None
            or target[0] != entry["expected_sha256"]
            or target[1] != entry["staged_identity"]
        ):
            raise SkillInstallError("owned publication lost its staged evidence")

        evidenced = _with_record_identity(
            manifest, entry["path"], entry["staged_identity"]
        )
        _write_manifest_snapshot(manifest_fd, evidenced)
        _cleanup_staging(
            target_fd,
            entry["staging"],
            expected_hash=entry["expected_sha256"],
            expected_identity=entry["staged_identity"],
        )
        cleared = dict(evidenced)
        cleared["publications"] = []
        _write_manifest_snapshot(manifest_fd, cleared)
        return cleared
    finally:
        os.close(parent_fd)


def _reconcile_quarantines(
    manifest: dict[str, Any],
    target_fd: int,
    manifest_fd: int,
    *,
    mutate: bool,
) -> dict[str, Any]:
    if not manifest["quarantines"] or not mutate:
        return manifest
    remaining = list(manifest["quarantines"])
    for entry in list(remaining):
        opened = _open_parent_at(target_fd, entry["path"], create=False)
        if opened is None:
            raise SkillInstallError("owned quarantine parent is unresolved")
        parent_fd, name = opened
        try:
            quarantined = _hash_regular_at(parent_fd, entry["quarantine"])
            original = _hash_regular_at(parent_fd, name)
            if quarantined is None:
                if (
                    original is not None
                    and original[0] == entry["expected_sha256"]
                    and original[1] == entry["file_identity"]
                ):
                    _quarantine_unlink_exact(
                        parent_fd,
                        name,
                        entry["path"],
                        entry["expected_sha256"],
                        entry["file_identity"],
                        entry["quarantine"],
                    )
                remaining.remove(entry)
                continue
            if quarantined[1] != entry["file_identity"]:
                if original is not None:
                    raise SkillInstallError(
                        "foreign quarantine cannot be restored without overwriting a live wrapper"
                    )
                _restore_quarantined(parent_fd, entry["quarantine"], name)
                remaining.remove(entry)
                continue
            if original is not None:
                if original != quarantined:
                    raise SkillInstallError(
                        "owned quarantine collides with a live wrapper"
                    )
                os.unlink(entry["quarantine"], dir_fd=parent_fd)
                os.fsync(parent_fd)
                remaining.remove(entry)
                continue
            if quarantined[0] == entry["expected_sha256"]:
                os.unlink(entry["quarantine"], dir_fd=parent_fd)
                os.fsync(parent_fd)
                remaining.remove(entry)
                continue
            _restore_quarantined(parent_fd, entry["quarantine"], name)
            remaining.remove(entry)
        except OSError as exc:
            raise SkillInstallError("owned quarantine reconciliation failed") from exc
        finally:
            os.close(parent_fd)
    reconciled = dict(manifest)
    reconciled["quarantines"] = remaining
    _write_manifest_snapshot(manifest_fd, reconciled)
    return reconciled


def _assert_parent_still_bound(
    target_fd: int, relative: str, anchored_parent_fd: int
) -> None:
    reopened = _open_parent_at(target_fd, relative, create=False)
    if reopened is None:
        raise SkillInstallError("wrapper parent changed during install")
    current_fd, _name = reopened
    try:
        if _fd_identity(current_fd) != _fd_identity(anchored_parent_fd):
            raise SkillInstallError("wrapper parent changed during install")
    finally:
        os.close(current_fd)


def install(
    target_root: str | Path,
    manifest_root: str | Path,
    *,
    expected_target_identity: tuple[int, int] | None = None,
    expected_manifest_identity: tuple[int, int] | None = None,
    expected_manifest_parent_identity: tuple[int, int] | None = None,
) -> InstallResult:
    """Install both wrappers and return only privacy-safe relative paths."""

    target, manifests, target_fd, manifest_fd, manifest_parent_fd = (
        _open_operation_roots(
            target_root,
            manifest_root,
            expected_target_identity=expected_target_identity,
            expected_manifest_identity=expected_manifest_identity,
            expected_manifest_parent_identity=expected_manifest_parent_identity,
        )
    )
    try:
        existing = _load_manifest_at(manifest_fd)
        if existing is not None:
            _assert_local_binding(existing, target, target_fd, manifest_fd)
            existing = _reconcile_publications(
                existing, target_fd, manifest_fd, mutate=True
            )
            existing = _reconcile_quarantines(
                existing, target_fd, manifest_fd, mutate=True
            )
        runtime_version = _runtime_version()
        planned = _expected_records(runtime_version)
        existing_records = _record_map(existing)
        if existing is not None:
            existing_claims = {
                path: {
                    key: value
                    for key, value in record.items()
                    if key != "file_identity"
                }
                for path, record in existing_records.items()
            }
            if existing[
                "runtime_version"
            ] != runtime_version or existing_claims != _claim_map(planned):
                raise SkillInstallError(
                    "existing install does not match the current skill pack"
                )

        identities: dict[str, Mapping[str, int]] = {}
        for record, _body in planned:
            opened = _observe_at(target_fd, record["path"], create=False)
            if opened is None:
                observed = None
            else:
                parent_fd, _name, observed = opened
                os.close(parent_fd)
            if existing is None:
                if observed is not None:
                    raise SkillInstallError(
                        "wrapper destination is owned by another source"
                    )
                continue
            evidence = existing_records[record["path"]]["file_identity"]
            if existing["state"] == "installing" and evidence is None:
                if observed is not None:
                    raise SkillInstallError(
                        "installing manifest cannot adopt an unowned wrapper"
                    )
                continue
            if observed is None:
                continue
            if observed[0] != record["sha256"]:
                raise SkillInstallError("owned wrapper has manual drift")
            if observed[1] != evidence:
                raise SkillInstallError("owned wrapper local evidence has drifted")
            identities[record["path"]] = observed[1]

        if (
            existing is not None
            and existing["state"] == "installed"
            and len(identities) == len(planned)
        ):
            final_records = _expected_records(runtime_version, identities)
            final_manifest = _manifest(
                target,
                target_fd,
                manifest_fd,
                runtime_version,
                final_records,
                state="installed",
            )
            if existing == final_manifest:
                return InstallResult(
                    False,
                    tuple(record["path"] for record, _ in planned),
                    _MANIFEST_NAME,
                )

        installing_records = _expected_records(runtime_version, identities)
        installing_manifest = _manifest(
            target,
            target_fd,
            manifest_fd,
            runtime_version,
            installing_records,
            state="installing",
        )
        _write_manifest_snapshot(manifest_fd, installing_manifest)
        changed = True
        for record, body in planned:
            if record["path"] in identities:
                continue
            opened = _observe_at(target_fd, record["path"], create=True)
            assert opened is not None
            parent_fd, name, observed = opened
            try:
                if observed is not None:
                    raise SkillInstallError(
                        "wrapper destination appeared before publish"
                    )
                staging = f".lifeos-publish-{record['sha256']}"
                staged = _create_stage_at(
                    target_fd,
                    staging,
                    body,
                    expected_hash=record["sha256"],
                    label=record["path"],
                )
                _after_publish_stage(record["path"])
                staged_identity = staged[1]
                publication = {
                    "expected_sha256": record["sha256"],
                    "parent_identity": _fd_identity(parent_fd),
                    "path": record["path"],
                    "staged_identity": staged_identity,
                    "staging": staging,
                }
                journaled = dict(installing_manifest)
                journaled["publications"] = [publication]
                _write_manifest_snapshot(manifest_fd, journaled)
                installing_manifest = journaled
                _link_staged_at(
                    target_fd,
                    parent_fd,
                    name,
                    staging,
                    label=record["path"],
                    verify_parent=lambda relative=record["path"], anchored=parent_fd: (
                        _assert_parent_still_bound(target_fd, relative, anchored)
                    ),
                )
                verified = _hash_regular_at(parent_fd, name)
                if (
                    verified is None
                    or verified[0] != record["sha256"]
                    or verified[1] != staged_identity
                ):
                    raise SkillInstallError("published wrapper did not verify")
                identities[record["path"]] = verified[1]
            finally:
                os.close(parent_fd)
            installing_records = _expected_records(runtime_version, identities)
            installing_manifest = _manifest(
                target,
                target_fd,
                manifest_fd,
                runtime_version,
                installing_records,
                state="installing",
                publications=[publication],
            )
            _write_manifest_snapshot(manifest_fd, installing_manifest)
            _cleanup_staging(
                target_fd,
                staging,
                expected_hash=record["sha256"],
                expected_identity=staged_identity,
            )
            installing_manifest = _manifest(
                target,
                target_fd,
                manifest_fd,
                runtime_version,
                installing_records,
                state="installing",
            )
            _write_manifest_snapshot(manifest_fd, installing_manifest)

        final_records = _expected_records(runtime_version, identities)
        final_manifest = _manifest(
            target,
            target_fd,
            manifest_fd,
            runtime_version,
            final_records,
            state="installed",
        )
        _write_manifest_snapshot(manifest_fd, final_manifest)
        return InstallResult(
            changed, tuple(record["path"] for record, _ in planned), _MANIFEST_NAME
        )
    finally:
        os.close(manifest_fd)
        os.close(manifest_parent_fd)
        os.close(target_fd)


def check(
    target_root: str | Path,
    manifest_root: str | Path,
    *,
    expected_target_identity: tuple[int, int] | None = None,
    expected_manifest_identity: tuple[int, int] | None = None,
    expected_manifest_parent_identity: tuple[int, int] | None = None,
) -> CheckResult:
    """Check local ownership, package source version, missing files, and drift."""

    try:
        target, manifests, target_fd, manifest_fd, manifest_parent_fd = (
            _open_operation_roots(
                target_root,
                manifest_root,
                expected_target_identity=expected_target_identity,
                expected_manifest_identity=expected_manifest_identity,
                expected_manifest_parent_identity=expected_manifest_parent_identity,
            )
        )
    except SkillInstallError:
        return CheckResult(False, "unsafe", (CheckIssue("unsafe-install-state"),))
    try:
        try:
            existing = _load_manifest_at(manifest_fd)
            if existing is not None:
                _assert_local_binding(existing, target, target_fd, manifest_fd)
        except SkillInstallError:
            return CheckResult(False, "unsafe", (CheckIssue("unsafe-install-state"),))
        if existing is None:
            return CheckResult(
                False, "uninstalled", (CheckIssue("missing-manifest", _MANIFEST_NAME),)
            )
        issues: list[CheckIssue] = []
        if existing["publications"]:
            issues.append(CheckIssue("publication-unresolved"))
        if existing["quarantines"]:
            issues.append(CheckIssue("quarantine-unresolved"))
        if existing["state"] != "installed":
            issues.append(CheckIssue("incomplete-install"))
        runtime_version = _runtime_version()
        try:
            planned = _expected_records(runtime_version)
        except SkillInstallError:
            issues.append(CheckIssue("invalid-skill-pack"))
            return CheckResult(False, "unsafe", tuple(issues))
        if existing["runtime_version"] != runtime_version:
            issues.append(CheckIssue("runtime-version-drift"))
        existing_claims = {
            path: {
                key: value for key, value in record.items() if key != "file_identity"
            }
            for path, record in _record_map(existing).items()
        }
        if existing_claims != _claim_map(planned):
            issues.append(CheckIssue("manifest-drift"))
        for relative, record in sorted(_record_map(existing).items()):
            try:
                opened = _observe_at(target_fd, relative, create=False)
            except SkillInstallError:
                issues.append(CheckIssue("unsafe-wrapper", relative))
                continue
            if opened is None:
                issues.append(CheckIssue("missing-wrapper", relative))
                continue
            parent_fd, _name, observed = opened
            os.close(parent_fd)
            if observed is None:
                issues.append(CheckIssue("missing-wrapper", relative))
            else:
                if observed[0] != record["sha256"]:
                    issues.append(CheckIssue("wrapper-drift", relative))
                if (
                    record["file_identity"] is not None
                    and observed[1] != record["file_identity"]
                ):
                    issues.append(CheckIssue("wrapper-ownership-drift", relative))
        return CheckResult(not issues, existing["state"], tuple(issues))
    finally:
        os.close(manifest_fd)
        os.close(manifest_parent_fd)
        os.close(target_fd)


def _before_unlink(_relative: str) -> None:
    """Test seam before atomic quarantine rename."""


def _after_quarantine_rename(_relative: str) -> None:
    """Test seam for a real process exit with the candidate isolated."""


def _rename_noreplace_at(parent_fd: int, source: str, destination: str) -> None:
    """Atomically rename one leaf without replacing a concurrent destination."""

    library = ctypes.CDLL(None, use_errno=True)
    source_bytes = os.fsencode(source)
    destination_bytes = os.fsencode(destination)
    if sys.platform == "darwin":
        rename = library.renameatx_np
        rename.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        rename.restype = ctypes.c_int
        result = rename(
            parent_fd, source_bytes, parent_fd, destination_bytes, 0x00000004
        )
    elif sys.platform.startswith("linux") and hasattr(library, "renameat2"):
        rename = library.renameat2
        rename.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        rename.restype = ctypes.c_int
        result = rename(
            parent_fd, source_bytes, parent_fd, destination_bytes, 0x00000001
        )
    else:
        raise SkillInstallError("atomic no-replace quarantine rename is unavailable")
    if result == 0:
        return
    error = ctypes.get_errno()
    if error == errno.EEXIST:
        raise FileExistsError(error, os.strerror(error), destination)
    if error == errno.ENOENT:
        raise FileNotFoundError(error, os.strerror(error), source)
    raise OSError(error, os.strerror(error), source)


def _restore_quarantined(parent_fd: int, quarantine_name: str, name: str) -> None:
    try:
        os.link(
            quarantine_name,
            name,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
            follow_symlinks=False,
        )
    except FileExistsError as exc:
        raise SkillInstallError(
            "cannot restore changed wrapper without overwrite"
        ) from exc
    except OSError as exc:
        raise SkillInstallError("cannot restore changed wrapper") from exc
    try:
        os.unlink(quarantine_name, dir_fd=parent_fd)
        os.fsync(parent_fd)
    except OSError as exc:
        raise SkillInstallError("cannot finalize changed wrapper restore") from exc


def _quarantine_unlink_exact(
    parent_fd: int,
    name: str,
    relative: str,
    expected_hash: str,
    expected_identity: Mapping[str, int],
    quarantine_name: str,
) -> str:
    _before_unlink(relative)
    collision = _hash_regular_at(parent_fd, quarantine_name)
    if collision is not None:
        raise SkillInstallError("wrapper quarantine leaf already exists")
    try:
        try:
            _rename_noreplace_at(parent_fd, name, quarantine_name)
            os.fsync(parent_fd)
            _after_quarantine_rename(relative)
        except FileExistsError as exc:
            raise SkillInstallError(
                "wrapper quarantine leaf appeared before rename"
            ) from exc
        except FileNotFoundError:
            if _hash_regular_at(parent_fd, quarantine_name) is not None:
                raise SkillInstallError("wrapper quarantine raced with another leaf")
            return "missing"
        except OSError as exc:
            raise SkillInstallError("cannot quarantine owned wrapper") from exc
        try:
            observed = _hash_regular_at(parent_fd, quarantine_name)
        except SkillInstallError:
            _restore_quarantined(parent_fd, quarantine_name, name)
            return "preserve"
        if observed is None:
            raise SkillInstallError("quarantined wrapper disappeared")
        if observed[0] != expected_hash or observed[1] != expected_identity:
            _restore_quarantined(parent_fd, quarantine_name, name)
            return "preserve"
        os.unlink(quarantine_name, dir_fd=parent_fd)
        os.fsync(parent_fd)
        return "remove"
    except OSError as exc:
        raise SkillInstallError("cannot remove quarantined wrapper") from exc


def _before_manifest_unlink() -> None:
    """Test seam after manifest load and before anchored unlink."""


def uninstall(
    target_root: str | Path,
    manifest_root: str | Path,
    *,
    expected_target_identity: tuple[int, int] | None = None,
    expected_manifest_identity: tuple[int, int] | None = None,
    expected_manifest_parent_identity: tuple[int, int] | None = None,
) -> UninstallResult:
    """Remove only locally evidenced wrappers after atomic quarantine verify."""

    target, manifests, target_fd, manifest_fd, manifest_parent_fd = (
        _open_operation_roots(
            target_root,
            manifest_root,
            expected_target_identity=expected_target_identity,
            expected_manifest_identity=expected_manifest_identity,
            expected_manifest_parent_identity=expected_manifest_parent_identity,
        )
    )
    anchored: list[tuple[str, Mapping[str, Any], int, str, str]] = []
    try:
        existing = _load_manifest_at(manifest_fd)
        if existing is None:
            return UninstallResult((), (), ())
        _assert_local_binding(existing, target, target_fd, manifest_fd)
        existing = _reconcile_publications(
            existing, target_fd, manifest_fd, mutate=True
        )
        existing = _reconcile_quarantines(existing, target_fd, manifest_fd, mutate=True)
        for relative, record in sorted(_record_map(existing).items()):
            opened = _observe_at(target_fd, relative, create=False)
            if opened is None:
                anchored.append((relative, record, -1, "", "missing"))
                continue
            parent_fd, name, observed = opened
            if observed is None:
                action = "missing"
            elif existing["state"] != "installed":
                action = "preserve"
            elif (
                observed[1] != record["file_identity"]
                or observed[0] != record["sha256"]
            ):
                action = "preserve"
            else:
                action = "remove"
            anchored.append((relative, record, parent_fd, name, action))
        removed: list[str] = []
        preserved: list[str] = []
        missing: list[str] = []
        for relative, record, parent_fd, name, action in anchored:
            if action == "remove":
                quarantine_name = f".lifeos-remove-{uuid.uuid4().hex}"
                entry = {
                    "expected_sha256": record["sha256"],
                    "file_identity": record["file_identity"],
                    "path": relative,
                    "quarantine": quarantine_name,
                }
                journaled = dict(existing)
                journaled["quarantines"] = [*existing["quarantines"], entry]
                _write_manifest_snapshot(manifest_fd, journaled)
                existing = journaled
                action = _quarantine_unlink_exact(
                    parent_fd,
                    name,
                    relative,
                    record["sha256"],
                    record["file_identity"],
                    quarantine_name,
                )
                cleared = dict(existing)
                cleared["quarantines"] = [
                    item
                    for item in existing["quarantines"]
                    if not (
                        item["path"] == relative
                        and item["quarantine"] == quarantine_name
                    )
                ]
                _write_manifest_snapshot(manifest_fd, cleared)
                existing = cleared
            if action == "remove":
                removed.append(relative)
            elif action == "preserve":
                preserved.append(relative)
            else:
                missing.append(relative)
        if existing["publications"] or existing["quarantines"]:
            raise SkillInstallError("owned install journal remains unresolved")
        _before_manifest_unlink()
        try:
            os.unlink(_MANIFEST_NAME, dir_fd=manifest_fd)
            os.fsync(manifest_fd)
        except OSError as exc:
            raise SkillInstallError("cannot remove skills manifest") from exc
        return UninstallResult(tuple(removed), tuple(preserved), tuple(missing))
    finally:
        for _relative, _record, parent_fd, _name, _action in anchored:
            if parent_fd >= 0:
                os.close(parent_fd)
        os.close(manifest_fd)
        os.close(manifest_parent_fd)
        os.close(target_fd)
