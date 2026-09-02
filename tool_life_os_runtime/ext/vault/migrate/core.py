"""Deterministic vault init, read-only scan, and migration planning.

This module deliberately has no migration apply operation.  A plan is a
versioned, hashed precondition artifact, not permission to mutate either tree.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import stat
import tomllib
from typing import Iterable, Mapping
import unicodedata

from ..config import MigrationRoot, VaultConfig
from ..schema import ARCHIVE_COMPONENTS, VaultPathResolver, VaultSchemaError, ZONE_SPECS


SCHEMA_VERSION = 1
PLAN_KIND = "lifeos-migration-plan"
_FLOW = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ROOT_REF = re.compile(r"^sha256:[0-9a-f]{64}$")
_PLAN_ID = re.compile(r"^mig_[0-9a-f]{24}$")
_OP_ID = re.compile(r"^op_[0-9a-f]{24}$")
_SURFACES = frozenset({"silent", "batched", "gated"})
_ZONE_NAMES = frozenset(
    {"inbox", "review", "tasks", "projects", "knowledge", "memory", "runs", "outbox"}
)
_DEFAULT_ZONE_PATHS = {
    "inbox": PurePosixPath("inbox"),
    "review": PurePosixPath("review"),
    "tasks": PurePosixPath("tasks"),
    "projects": PurePosixPath("projects"),
    "knowledge": PurePosixPath("knowledge"),
    "memory": PurePosixPath("agent/memory"),
    "runs": PurePosixPath("agent/runs"),
    "outbox": PurePosixPath("agent/outbox"),
}

DEFAULT_VAULT_CONFIG = VaultConfig(
    schema_version=SCHEMA_VERSION,
    locale="ru",
    timezone="UTC",
    enabled_flows=(),
    zones=tuple(sorted(_DEFAULT_ZONE_PATHS.items())),
    surface="gated",
)


class VaultMigrationError(ValueError):
    """Init, scan, or plan input is invalid or changed during the operation."""


@dataclass(frozen=True)
class InitResult:
    status: str
    root_ref: str
    snapshot_sha256: str


@dataclass(frozen=True)
class ScannedFile:
    relative_ref: str
    sha256: str
    size: int

    def to_dict(self) -> dict[str, object]:
        return {
            "relative_ref": self.relative_ref,
            "sha256": self.sha256,
            "size": self.size,
        }


@dataclass(frozen=True)
class ExcludedTree:
    relative_ref: str
    reason: str
    entry_count: int

    def to_dict(self) -> dict[str, object]:
        return {
            "relative_ref": self.relative_ref,
            "reason": self.reason,
            "entry_count": self.entry_count,
        }


@dataclass(frozen=True)
class VaultScan:
    schema_version: int
    root_ref: str
    snapshot_sha256: str
    files: tuple[ScannedFile, ...]
    directory_count: int
    total_bytes: int
    excluded: tuple[ExcludedTree, ...]
    _root: Path = field(repr=False, compare=False)

    @property
    def excluded_entry_count(self) -> int:
        return sum(item.entry_count for item in self.excluded)

    def summary_dict(self) -> dict[str, object]:
        return {
            "root_ref": self.root_ref,
            "snapshot_sha256": self.snapshot_sha256,
            "file_count": len(self.files),
            "directory_count": self.directory_count,
            "total_bytes": self.total_bytes,
            "excluded_root_count": len(self.excluded),
            "excluded_entry_count": self.excluded_entry_count,
        }


@dataclass(frozen=True)
class MigrationOperation:
    operation_id: str
    action: str
    relative_ref: str
    source_sha256: str
    size: int
    target_precondition_sha256: str | None
    rollback: str

    def to_dict(self) -> dict[str, object]:
        return {
            "operation_id": self.operation_id,
            "action": self.action,
            "relative_ref": self.relative_ref,
            "source_sha256": self.source_sha256,
            "size": self.size,
            "target_precondition_sha256": self.target_precondition_sha256,
            "rollback": self.rollback,
        }


@dataclass(frozen=True)
class MigrationPlan:
    schema_version: int
    kind: str
    plan_id: str
    source: Mapping[str, object]
    target: Mapping[str, object]
    operations: tuple[MigrationOperation, ...]
    summary: Mapping[str, int]

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "kind": self.kind,
            "plan_id": self.plan_id,
            "source": dict(self.source),
            "target": dict(self.target),
            "operations": [item.to_dict() for item in self.operations],
            "summary": dict(self.summary),
        }


def _has_unsafe_unicode(text: str) -> bool:
    return any(
        unicodedata.category(character).startswith("C")
        or unicodedata.category(character) in {"Zl", "Zp"}
        for character in text
    )


def _safe_relative(value: str) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value or _has_unsafe_unicode(value):
        raise VaultMigrationError("relative reference is invalid")
    path = PurePosixPath(value)
    if path.is_absolute() or path == PurePosixPath(".") or ".." in path.parts:
        raise VaultMigrationError("relative reference is unsafe")
    return path


def _safe_component(value: str) -> None:
    path = _safe_relative(value)
    if len(path.parts) != 1:
        raise VaultMigrationError("filesystem entry name is unsafe")


def _overlaps(first: Path, second: Path) -> bool:
    return first == second or first in second.parents or second in first.parents


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _root_ref(path: Path) -> str:
    return f"sha256:{hashlib.sha256(os.fsencode(path)).hexdigest()}"


def _absolute_explicit(path: str | os.PathLike[str], *, label: str) -> Path:
    try:
        raw = os.fspath(path)
    except TypeError as error:
        raise VaultMigrationError(f"{label} must be an absolute path") from error
    if not isinstance(raw, str) or not raw or "\\" in raw or _has_unsafe_unicode(raw):
        raise VaultMigrationError(f"{label} path is invalid")
    candidate = Path(raw)
    if not candidate.is_absolute() or ".." in candidate.parts:
        raise VaultMigrationError(f"{label} must be an explicit absolute path")
    return candidate


def _canonical_without_leaf_symlink(path: Path, *, label: str) -> Path:
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError:
        mode = None
    except OSError as error:
        raise VaultMigrationError(f"{label} cannot be inspected") from error
    if mode is not None and stat.S_ISLNK(mode):
        raise VaultMigrationError(f"{label} symlink is forbidden")
    try:
        return path.resolve(strict=False)
    except (OSError, RuntimeError) as error:
        raise VaultMigrationError(f"{label} cannot be resolved") from error


def _reject_symlink_ancestors(
    path: Path, *, include_leaf: bool, leaf_may_be_missing: bool = False
) -> None:
    limit = len(path.parts) if include_leaf else len(path.parts) - 1
    current = Path(path.anchor)
    selected = path.parts[1:limit]
    for index, part in enumerate(selected):
        current /= part
        try:
            mode = current.lstat().st_mode
        except FileNotFoundError:
            if leaf_may_be_missing and index == len(selected) - 1:
                return
            raise VaultMigrationError("target parent must already exist") from None
        except OSError as error:
            raise VaultMigrationError("target ancestry cannot be inspected") from error
        if stat.S_ISLNK(mode):
            raise VaultMigrationError("symlink target ancestry is forbidden")
        if not stat.S_ISDIR(mode):
            raise VaultMigrationError("target ancestry is not a directory")


def _protected_paths(
    roots: Iterable[str | os.PathLike[str] | MigrationRoot],
) -> tuple[Path, ...]:
    protected: list[Path] = []
    for item in roots:
        if isinstance(item, MigrationRoot):
            if not item.read_only:
                raise VaultMigrationError("migration root must be read-only")
            path = item.path
            if not path.is_absolute():
                raise VaultMigrationError("migration root must be absolute")
        else:
            path = _absolute_explicit(item, label="migration root")
        try:
            protected.append(path.resolve(strict=False))
        except (OSError, RuntimeError) as error:
            raise VaultMigrationError("migration root cannot be resolved") from error
    return tuple(protected)


def _validate_target(
    target: Path,
    protected_inputs: Iterable[str | os.PathLike[str] | MigrationRoot],
) -> tuple[Path, tuple[Path, ...]]:
    _reject_symlink_ancestors(target, include_leaf=True, leaf_may_be_missing=True)
    try:
        resolved = target.resolve(strict=False)
    except (OSError, RuntimeError) as error:
        raise VaultMigrationError("target cannot be resolved") from error
    protected = _protected_paths(protected_inputs)
    if any(_overlaps(resolved, item) for item in protected):
        raise VaultMigrationError("target overlaps a read-only migration root")
    return resolved, protected


def _strict_table(
    value: object,
    *,
    allowed: set[str] | frozenset[str],
    required: set[str] | frozenset[str],
    label: str,
) -> dict[str, object]:
    if not isinstance(value, dict):
        raise VaultMigrationError(f"{label} must be an object")
    unknown = set(value) - set(allowed)
    missing = set(required) - set(value)
    if unknown or missing:
        raise VaultMigrationError(f"{label} has unknown or missing fields")
    return value


def _bounded_text(value: object, *, label: str, limit: int) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > limit
        or _has_unsafe_unicode(value)
    ):
        raise VaultMigrationError(f"{label} is invalid")
    return value


def parse_vault_profile(text: str) -> VaultConfig:
    """Parse init profile without writing untrusted TOML into the target."""

    if not isinstance(text, str) or len(text.encode("utf-8")) > 64 * 1024:
        raise VaultMigrationError("vault profile is invalid")
    try:
        raw = tomllib.loads(text)
    except (
        tomllib.TOMLDecodeError,
        UnicodeError,
        ValueError,
        RecursionError,
    ) as error:
        raise VaultMigrationError("vault profile is invalid") from error
    table = _strict_table(
        raw,
        allowed={"schema_version", "locale", "timezone", "enabled_flows", "zones", "surface"},
        required={"schema_version", "zones", "surface"},
        label="vault profile",
    )
    if type(table["schema_version"]) is not int or table["schema_version"] != SCHEMA_VERSION:
        raise VaultMigrationError("vault profile schema_version is unsupported")
    locale = _bounded_text(table.get("locale", "ru"), label="locale", limit=64)
    timezone = _bounded_text(table.get("timezone", "UTC"), label="timezone", limit=128)
    raw_flows = table.get("enabled_flows", [])
    if not isinstance(raw_flows, list) or any(
        not isinstance(flow, str) or not _FLOW.fullmatch(flow) for flow in raw_flows
    ):
        raise VaultMigrationError("enabled_flows is invalid")
    if len(set(raw_flows)) != len(raw_flows):
        raise VaultMigrationError("enabled_flows must be unique")
    zones_raw = _strict_table(
        table["zones"], allowed=_ZONE_NAMES, required=_ZONE_NAMES, label="zones"
    )
    zones: list[tuple[str, PurePosixPath]] = []
    for name in sorted(_ZONE_NAMES):
        value = zones_raw[name]
        if not isinstance(value, str):
            raise VaultMigrationError("zone path is invalid")
        path = _safe_relative(value)
        zones.append((name, path))
    surface_raw = _strict_table(
        table["surface"], allowed={"default"}, required={"default"}, label="surface"
    )
    surface = _bounded_text(surface_raw["default"], label="surface.default", limit=32)
    if surface not in _SURFACES:
        raise VaultMigrationError("surface.default is unsupported")
    profile = VaultConfig(
        SCHEMA_VERSION, locale, timezone, tuple(raw_flows), tuple(zones), surface
    )
    # Constructor validates relative and fixed-zone authority collisions without
    # touching the not-yet-created target.
    try:
        VaultPathResolver(Path.cwd() / ".lifeos-profile-validation", profile)
    except VaultSchemaError as error:
        raise VaultMigrationError("vault profile zone schema is unsafe") from error
    return profile


def render_vault_profile(profile: VaultConfig) -> str:
    """Render one canonical TOML representation and validate it by round-trip."""

    if not isinstance(profile, VaultConfig):
        raise VaultMigrationError("vault profile object is invalid")
    try:
        zones = dict(profile.zones)
        lines = [
            f"schema_version = {profile.schema_version}",
            f"locale = {json.dumps(profile.locale, ensure_ascii=False)}",
            f"timezone = {json.dumps(profile.timezone, ensure_ascii=False)}",
            "enabled_flows = ["
            + ", ".join(json.dumps(flow, ensure_ascii=False) for flow in profile.enabled_flows)
            + "]",
            "",
            "[zones]",
        ]
        for name in (
            "inbox",
            "review",
            "tasks",
            "projects",
            "knowledge",
            "memory",
            "runs",
            "outbox",
        ):
            value = zones.get(name)
            if value is None:
                raise VaultMigrationError("vault profile misses a zone")
            lines.append(f"{name} = {json.dumps(value.as_posix(), ensure_ascii=False)}")
    except (AttributeError, TypeError, ValueError) as error:
        raise VaultMigrationError("vault profile object is invalid") from error
    lines.extend(
        ["", "[surface]", f"default = {json.dumps(profile.surface, ensure_ascii=False)}", ""]
    )
    rendered = "\n".join(lines)
    if parse_vault_profile(rendered) != profile:
        raise VaultMigrationError("vault profile is not canonicalizable")
    return rendered


def _minimal_directories(profile: VaultConfig) -> tuple[str, ...]:
    directories: set[PurePosixPath] = set()
    for spec in ZONE_SPECS:
        if not spec.required:
            continue
        path = spec.relative_path(profile)
        directories.add(path)
        directories.update(parent for parent in path.parents if parent != PurePosixPath("."))
    return tuple(path.as_posix() for path in sorted(directories, key=lambda item: (len(item.parts), item.as_posix())))


def _directory_flags() -> int:
    return os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)


def _remove_tree_at(
    parent_fd: int,
    name: str,
    *,
    expected_identity: os.stat_result | None = None,
) -> None:
    """Remove a tree only while its directory entry retains expected ownership."""

    try:
        named_identity = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if expected_identity is not None and not _same_identity(
            expected_identity, named_identity
        ):
            return
        if not stat.S_ISDIR(named_identity.st_mode):
            return
        child_fd = os.open(name, _directory_flags(), dir_fd=parent_fd)
    except FileNotFoundError:
        return
    try:
        opened_identity = os.fstat(child_fd)
        if not _same_identity(named_identity, opened_identity):
            return
        with os.scandir(child_fd) as entries:
            for entry in entries:
                entry_identity = entry.stat(follow_symlinks=False)
                if stat.S_ISDIR(entry_identity.st_mode):
                    _remove_tree_at(
                        child_fd,
                        entry.name,
                        expected_identity=entry_identity,
                    )
                else:
                    os.unlink(entry.name, dir_fd=child_fd)
    finally:
        os.close(child_fd)
    try:
        final_identity = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    if _same_identity(named_identity, final_identity):
        os.rmdir(name, dir_fd=parent_fd)


def _write_all(fd: int, data: bytes) -> None:
    offset = 0
    while offset < len(data):
        written = os.write(fd, data[offset:])
        if written <= 0:  # pragma: no cover - OS contract
            raise VaultMigrationError("profile write made no progress")
        offset += written


def _populate_staging(stage_fd: int, profile: VaultConfig, config_bytes: bytes) -> None:
    for relative in _minimal_directories(profile):
        try:
            os.mkdir(relative, mode=0o700, dir_fd=stage_fd)
        except FileExistsError:
            pass
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    config_fd = os.open("lifeos.toml", flags, 0o600, dir_fd=stage_fd)
    try:
        _write_all(config_fd, config_bytes)
        os.fsync(config_fd)
    finally:
        os.close(config_fd)
    os.fsync(stage_fd)


def _entry_names(fd: int) -> tuple[str, ...]:
    with os.scandir(fd) as entries:
        return tuple(sorted(entry.name for entry in entries))


def _is_exact_initialized(root_fd: int, profile_bytes: bytes, profile: VaultConfig) -> bool:
    expected_dirs = set(_minimal_directories(profile))
    seen_dirs: set[str] = set()
    stack: list[tuple[int, PurePosixPath]] = [(os.dup(root_fd), PurePosixPath("."))]
    try:
        seen_files: dict[str, bytes] = {}
        while stack:
            directory_fd, relative = stack.pop()
            try:
                with os.scandir(directory_fd) as entries:
                    for entry in entries:
                        _safe_component(entry.name)
                        child = PurePosixPath(entry.name) if relative == PurePosixPath(".") else relative / entry.name
                        mode = entry.stat(follow_symlinks=False).st_mode
                        if stat.S_ISLNK(mode):
                            return False
                        if stat.S_ISDIR(mode):
                            seen_dirs.add(child.as_posix())
                            stack.append((os.open(entry.name, _directory_flags(), dir_fd=directory_fd), child))
                        elif stat.S_ISREG(mode):
                            file_fd = os.open(
                                entry.name,
                                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                                dir_fd=directory_fd,
                            )
                            try:
                                chunks: list[bytes] = []
                                while chunk := os.read(file_fd, 1024 * 1024):
                                    chunks.append(chunk)
                                seen_files[child.as_posix()] = b"".join(chunks)
                            finally:
                                os.close(file_fd)
                        else:
                            return False
            finally:
                os.close(directory_fd)
        return seen_dirs == expected_dirs and seen_files == {"lifeos.toml": profile_bytes}
    except (OSError, VaultMigrationError):
        return False
    finally:
        for pending_fd, _ in stack:
            os.close(pending_fd)


# Tests replace this no-op to force deterministic path-swap races before the
# final recheck.  Production callers do not receive a hook.
def _before_init_commit(_target: Path) -> None:
    return None


def _before_repeat_scan(_target: Path) -> None:
    return None


def init_vault(
    target: str | os.PathLike[str],
    *,
    profile: VaultConfig | str = DEFAULT_VAULT_CONFIG,
    read_only_roots: Iterable[str | os.PathLike[str] | MigrationRoot] = (),
) -> InitResult:
    """Atomically initialize only an explicit absent or empty target."""

    target_path = _canonical_without_leaf_symlink(
        _absolute_explicit(target, label="target"), label="target"
    )
    protected_inputs = tuple(read_only_roots)
    parsed_profile = parse_vault_profile(profile) if isinstance(profile, str) else profile
    config_text = render_vault_profile(parsed_profile)
    config_bytes = config_text.encode("utf-8")
    resolved_target, _ = _validate_target(target_path, protected_inputs)

    initial: os.stat_result | None
    try:
        initial = target_path.lstat()
    except FileNotFoundError:
        initial = None
    except OSError as error:
        raise VaultMigrationError("target cannot be inspected") from error
    if initial is not None:
        if stat.S_ISLNK(initial.st_mode) or not stat.S_ISDIR(initial.st_mode):
            raise VaultMigrationError("target must be an absent or empty directory")
        try:
            target_fd = os.open(target_path, _directory_flags())
        except OSError as error:
            raise VaultMigrationError("target changed or became unsafe") from error
        try:
            opened_target = os.fstat(target_fd)
            if not _same_identity(initial, opened_target):
                raise VaultMigrationError("target changed before init inspection")
            is_empty = not _entry_names(target_fd)
            if not is_empty and _is_exact_initialized(
                target_fd, config_bytes, parsed_profile
            ):
                _before_repeat_scan(target_path)
                current_before_scan = os.stat(target_path, follow_symlinks=False)
                if not _same_identity(
                    opened_target, current_before_scan
                ) or not _is_exact_initialized(
                    target_fd, config_bytes, parsed_profile
                ):
                    raise VaultMigrationError("initialized target changed before scan")
                scan = scan_vault(target_path)
                current_after_scan = os.stat(target_path, follow_symlinks=False)
                if (
                    not _same_identity(opened_target, os.fstat(target_fd))
                    or not _same_identity(opened_target, current_after_scan)
                    or not _is_exact_initialized(
                        target_fd, config_bytes, parsed_profile
                    )
                ):
                    raise VaultMigrationError("initialized target changed during scan")
                return InitResult("already_initialized", scan.root_ref, scan.snapshot_sha256)
        finally:
            os.close(target_fd)
        if not is_empty:
            raise VaultMigrationError("target is non-empty")

    parent = target_path.parent
    try:
        parent_fd = os.open(parent, _directory_flags())
    except OSError as error:
        raise VaultMigrationError("target parent cannot be opened safely") from error
    parent_identity = os.fstat(parent_fd)
    stage_name = ""
    stage_created = False
    stage_fd: int | None = None
    stage_identity: os.stat_result | None = None
    stage_cleanup_allowed = True
    try:
        for _attempt in range(16):
            candidate = f".{target_path.name}.lifeos-init-{secrets.token_hex(12)}"
            try:
                os.mkdir(candidate, mode=0o700, dir_fd=parent_fd)
            except FileExistsError:
                continue
            stage_name = candidate
            stage_created = True
            break
        if not stage_created:
            raise VaultMigrationError("cannot allocate a private init transaction")
        named_stage = os.stat(stage_name, dir_fd=parent_fd, follow_symlinks=False)
        stage_fd = os.open(stage_name, _directory_flags(), dir_fd=parent_fd)
        stage_identity = os.fstat(stage_fd)
        if (
            not stat.S_ISDIR(stage_identity.st_mode)
            or not _same_identity(named_stage, stage_identity)
        ):
            raise VaultMigrationError("private init transaction changed during creation")
        _populate_staging(stage_fd, parsed_profile, config_bytes)
        _before_init_commit(target_path)

        # The held directory inode is not enough ownership evidence: another
        # writer can add or change a leaf without replacing that inode.  Only
        # the exact generated profile may be committed or recursively cleaned.
        if not _is_exact_initialized(stage_fd, config_bytes, parsed_profile):
            stage_cleanup_allowed = False
            raise VaultMigrationError("private init transaction content changed")

        current_stage = os.stat(stage_name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            not _same_identity(stage_identity, os.fstat(stage_fd))
            or not _same_identity(stage_identity, current_stage)
            or not stat.S_ISDIR(current_stage.st_mode)
        ):
            raise VaultMigrationError("private init transaction changed before commit")

        # Re-resolve security boundaries and compare path identity immediately
        # before the only operation that makes the vault visible.
        current_target, _ = _validate_target(target_path, protected_inputs)
        if current_target != resolved_target:
            raise VaultMigrationError("target path changed during init")
        current_parent = parent.resolve(strict=True)
        current_parent_stat = current_parent.stat()
        if (current_parent_stat.st_dev, current_parent_stat.st_ino) != (
            parent_identity.st_dev,
            parent_identity.st_ino,
        ):
            raise VaultMigrationError("target parent changed during init")
        try:
            current = os.stat(target_path.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            current = None
        if initial is None:
            if current is not None:
                raise VaultMigrationError("target appeared during init")
        elif current is None or (current.st_dev, current.st_ino) != (initial.st_dev, initial.st_ino):
            raise VaultMigrationError("target changed during init")
        else:
            current_fd = os.open(target_path.name, _directory_flags(), dir_fd=parent_fd)
            try:
                if _entry_names(current_fd):
                    raise VaultMigrationError("target became non-empty during init")
            finally:
                os.close(current_fd)

        os.replace(stage_name, target_path.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        stage_created = False
        os.fsync(parent_fd)
    except (OSError, RuntimeError) as error:
        if isinstance(error, VaultMigrationError):
            raise
        raise VaultMigrationError("vault init transaction failed") from error
    finally:
        if stage_fd is not None:
            os.close(stage_fd)
        if stage_created and stage_identity is not None and stage_cleanup_allowed:
            _remove_tree_at(
                parent_fd,
                stage_name,
                expected_identity=stage_identity,
            )
        os.close(parent_fd)

    scan = scan_vault(target_path)
    return InitResult("initialized", scan.root_ref, scan.snapshot_sha256)


def _same_identity(first: os.stat_result, second: os.stat_result) -> bool:
    return (first.st_dev, first.st_ino, first.st_mode) == (
        second.st_dev,
        second.st_ino,
        second.st_mode,
    )


def _count_excluded_at(parent_fd: int, name: str, expected: os.stat_result) -> int:
    if not stat.S_ISDIR(expected.st_mode):
        current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if not _same_identity(expected, current):
            raise VaultMigrationError("excluded entry changed during scan")
        return 1
    child_fd = os.open(name, _directory_flags(), dir_fd=parent_fd)
    count = 1
    try:
        before = os.fstat(child_fd)
        if not _same_identity(expected, before):
            raise VaultMigrationError("excluded directory changed during scan")
        with os.scandir(child_fd) as entries:
            for entry in entries:
                entry_stat = entry.stat(follow_symlinks=False)
                count += _count_excluded_at(child_fd, entry.name, entry_stat)
        after = os.fstat(child_fd)
        if not _same_identity(before, after) or (
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (after.st_mtime_ns, after.st_ctime_ns):
            raise VaultMigrationError("excluded directory changed during scan")
    finally:
        os.close(child_fd)
    return count


def _hash_file_at(parent_fd: int, name: str, expected: os.stat_result) -> tuple[str, int]:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(name, flags, dir_fd=parent_fd)
    digest = hashlib.sha256()
    try:
        before = os.fstat(fd)
        if not _same_identity(expected, before) or not stat.S_ISREG(before.st_mode):
            raise VaultMigrationError("file changed during scan")
        while chunk := os.read(fd, 1024 * 1024):
            digest.update(chunk)
        after = os.fstat(fd)
        if not _same_identity(before, after) or (
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise VaultMigrationError("file changed during scan")
        return digest.hexdigest(), after.st_size
    finally:
        os.close(fd)


def _scan_directory(
    directory_fd: int,
    relative: PurePosixPath,
    files: list[ScannedFile],
    excluded: list[ExcludedTree],
) -> int:
    before = os.fstat(directory_fd)
    directory_count = 1
    with os.scandir(directory_fd) as iterator:
        entries = sorted(iterator, key=lambda entry: entry.name)
    for entry in entries:
        _safe_component(entry.name)
        child = PurePosixPath(entry.name) if relative == PurePosixPath(".") else relative / entry.name
        entry_stat = entry.stat(follow_symlinks=False)
        if entry.name in ARCHIVE_COMPONENTS:
            excluded.append(
                ExcludedTree(
                    child.as_posix(),
                    "archive-convention",
                    _count_excluded_at(directory_fd, entry.name, entry_stat),
                )
            )
            continue
        if stat.S_ISLNK(entry_stat.st_mode):
            raise VaultMigrationError("active scan tree contains a symlink")
        if stat.S_ISDIR(entry_stat.st_mode):
            child_fd = os.open(entry.name, _directory_flags(), dir_fd=directory_fd)
            try:
                if not _same_identity(entry_stat, os.fstat(child_fd)):
                    raise VaultMigrationError("directory changed during scan")
                directory_count += _scan_directory(child_fd, child, files, excluded)
            finally:
                os.close(child_fd)
        elif stat.S_ISREG(entry_stat.st_mode):
            digest, size = _hash_file_at(directory_fd, entry.name, entry_stat)
            files.append(ScannedFile(child.as_posix(), digest, size))
        else:
            raise VaultMigrationError("active scan tree contains a special file")
    after = os.fstat(directory_fd)
    if not _same_identity(before, after) or (
        before.st_mtime_ns,
        before.st_ctime_ns,
    ) != (after.st_mtime_ns, after.st_ctime_ns):
        raise VaultMigrationError("directory changed during scan")
    return directory_count


def scan_vault(root: str | os.PathLike[str]) -> VaultScan:
    """Take a deterministic, byte-preserving snapshot without following links."""

    root_path = _canonical_without_leaf_symlink(
        _absolute_explicit(root, label="scan root"), label="scan root"
    )
    _reject_symlink_ancestors(root_path, include_leaf=True)
    try:
        resolved = root_path.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise VaultMigrationError("scan root cannot be resolved") from error
    try:
        root_fd = os.open(root_path, _directory_flags())
    except OSError as error:
        raise VaultMigrationError("scan root is not a safe directory") from error
    files: list[ScannedFile] = []
    excluded: list[ExcludedTree] = []
    try:
        try:
            directory_count = _scan_directory(
                root_fd, PurePosixPath("."), files, excluded
            )
            path_after = root_path.resolve(strict=True)
            if path_after != resolved or not _same_identity(os.fstat(root_fd), path_after.stat()):
                raise VaultMigrationError("scan root changed during scan")
        except VaultMigrationError:
            raise
        except (OSError, RuntimeError) as error:
            raise VaultMigrationError("scan tree changed or became unsafe") from error
    finally:
        os.close(root_fd)
    ordered_files = tuple(sorted(files, key=lambda item: item.relative_ref))
    ordered_excluded = tuple(sorted(excluded, key=lambda item: item.relative_ref))
    snapshot_payload = {
        "schema_version": SCHEMA_VERSION,
        "files": [item.to_dict() for item in ordered_files],
        "excluded": [item.to_dict() for item in ordered_excluded],
        "directory_count": directory_count,
    }
    return VaultScan(
        SCHEMA_VERSION,
        _root_ref(resolved),
        _sha256_bytes(_canonical_json(snapshot_payload)),
        ordered_files,
        directory_count,
        sum(item.size for item in ordered_files),
        ordered_excluded,
        resolved,
    )


def _operation_payload(
    action: str,
    source: ScannedFile,
    target_sha256: str | None,
) -> dict[str, object]:
    rollback = "remove-created-file" if action == "create" else "restore-target-preimage"
    return {
        "action": action,
        "relative_ref": source.relative_ref,
        "source_sha256": source.sha256,
        "size": source.size,
        "target_precondition_sha256": target_sha256,
        "rollback": rollback,
    }


def _validate_scan_object(scan: VaultScan, *, label: str) -> None:
    if not isinstance(scan, VaultScan) or scan.schema_version != SCHEMA_VERSION:
        raise VaultMigrationError(f"{label} scan schema version is unsupported")
    if (
        not isinstance(scan._root, Path)
        or not scan._root.is_absolute()
        or scan.root_ref != _root_ref(scan._root)
    ):
        raise VaultMigrationError(f"{label} scan root fingerprint is invalid")
    if type(scan.directory_count) is not int or scan.directory_count < 1:
        raise VaultMigrationError(f"{label} scan directory count is invalid")
    refs: set[str] = set()
    for item in scan.files:
        if not isinstance(item, ScannedFile):
            raise VaultMigrationError(f"{label} scan file is invalid")
        relative = _safe_relative(item.relative_ref)
        if any(part in ARCHIVE_COMPONENTS for part in relative.parts) or item.relative_ref in refs:
            raise VaultMigrationError(f"{label} scan file reference is unsafe")
        if (
            not isinstance(item.sha256, str)
            or not _SHA256.fullmatch(item.sha256)
            or type(item.size) is not int
            or item.size < 0
        ):
            raise VaultMigrationError(f"{label} scan file metadata is invalid")
        refs.add(item.relative_ref)
    if [item.relative_ref for item in scan.files] != sorted(refs):
        raise VaultMigrationError(f"{label} scan files are not canonical")
    excluded_refs: set[str] = set()
    for item in scan.excluded:
        if not isinstance(item, ExcludedTree):
            raise VaultMigrationError(f"{label} excluded tree is invalid")
        relative = _safe_relative(item.relative_ref)
        if (
            relative.name not in ARCHIVE_COMPONENTS
            or item.relative_ref in excluded_refs
            or item.reason != "archive-convention"
            or type(item.entry_count) is not int
            or item.entry_count < 1
        ):
            raise VaultMigrationError(f"{label} excluded tree metadata is invalid")
        excluded_refs.add(item.relative_ref)
    if [item.relative_ref for item in scan.excluded] != sorted(excluded_refs):
        raise VaultMigrationError(f"{label} excluded trees are not canonical")
    if scan.total_bytes != sum(item.size for item in scan.files):
        raise VaultMigrationError(f"{label} scan byte count is invalid")
    snapshot_payload = {
        "schema_version": SCHEMA_VERSION,
        "files": [item.to_dict() for item in scan.files],
        "excluded": [item.to_dict() for item in scan.excluded],
        "directory_count": scan.directory_count,
    }
    if scan.snapshot_sha256 != _sha256_bytes(_canonical_json(snapshot_payload)):
        raise VaultMigrationError(f"{label} scan fingerprint is invalid")


def build_migration_plan(source: VaultScan, target: VaultScan) -> MigrationPlan:
    """Build a deterministic explicit plan.  It cannot apply itself."""

    _validate_scan_object(source, label="source")
    _validate_scan_object(target, label="target")
    if _overlaps(source._root, target._root):
        raise VaultMigrationError("source and target roots overlap")
    target_files = {item.relative_ref: item for item in target.files}
    operations: list[MigrationOperation] = []
    unchanged = 0
    for item in source.files:
        existing = target_files.get(item.relative_ref)
        if existing is not None and existing.sha256 == item.sha256:
            unchanged += 1
            continue
        action = "create" if existing is None else "update"
        payload = _operation_payload(action, item, None if existing is None else existing.sha256)
        operation_id = f"op_{_sha256_bytes(_canonical_json(payload))[:24]}"
        operations.append(MigrationOperation(operation_id=operation_id, **payload))
    source_summary = source.summary_dict()
    target_summary = target.summary_dict()
    summary = {
        "create_count": sum(item.action == "create" for item in operations),
        "update_count": sum(item.action == "update" for item in operations),
        "unchanged_count": unchanged,
        "target_only_count": len(set(target_files) - {item.relative_ref for item in source.files}),
    }
    identity_payload = {
        "schema_version": SCHEMA_VERSION,
        "kind": PLAN_KIND,
        "source": source_summary,
        "target": target_summary,
        "operations": [item.to_dict() for item in operations],
        "summary": summary,
    }
    plan_id = f"mig_{_sha256_bytes(_canonical_json(identity_payload))[:24]}"
    return MigrationPlan(
        SCHEMA_VERSION,
        PLAN_KIND,
        plan_id,
        source_summary,
        target_summary,
        tuple(operations),
        summary,
    )


def render_migration_plan(plan: MigrationPlan) -> str:
    validated = load_migration_plan(
        json.dumps(plan.to_dict(), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    )
    return json.dumps(
        validated.to_dict(), ensure_ascii=False, sort_keys=True, indent=2
    ) + "\n"


def _require_int(value: object, *, label: str) -> int:
    if type(value) is not int or value < 0:
        raise VaultMigrationError(f"{label} must be a non-negative integer")
    return value


def _validate_scan_summary(value: object, *, label: str) -> dict[str, object]:
    table = _strict_table(
        value,
        allowed={
            "root_ref",
            "snapshot_sha256",
            "file_count",
            "directory_count",
            "total_bytes",
            "excluded_root_count",
            "excluded_entry_count",
        },
        required={
            "root_ref",
            "snapshot_sha256",
            "file_count",
            "directory_count",
            "total_bytes",
            "excluded_root_count",
            "excluded_entry_count",
        },
        label=label,
    )
    if not isinstance(table["root_ref"], str) or not _ROOT_REF.fullmatch(table["root_ref"]):
        raise VaultMigrationError(f"{label}.root_ref is invalid")
    if not isinstance(table["snapshot_sha256"], str) or not _SHA256.fullmatch(table["snapshot_sha256"]):
        raise VaultMigrationError(f"{label}.snapshot_sha256 is invalid")
    for field_name in (
        "file_count",
        "directory_count",
        "total_bytes",
        "excluded_root_count",
        "excluded_entry_count",
    ):
        _require_int(table[field_name], label=f"{label}.{field_name}")
    return table


def load_migration_plan(text: str) -> MigrationPlan:
    """Load an exact plan schema and recompute all deterministic identifiers."""

    if not isinstance(text, str) or len(text.encode("utf-8")) > 16 * 1024 * 1024:
        raise VaultMigrationError("migration plan is invalid")
    try:
        raw = json.loads(text)
    except (json.JSONDecodeError, UnicodeError) as error:
        raise VaultMigrationError("migration plan is invalid JSON") from error
    table = _strict_table(
        raw,
        allowed={"schema_version", "kind", "plan_id", "source", "target", "operations", "summary"},
        required={"schema_version", "kind", "plan_id", "source", "target", "operations", "summary"},
        label="migration plan",
    )
    if type(table["schema_version"]) is not int or table["schema_version"] != SCHEMA_VERSION:
        raise VaultMigrationError("migration plan schema version is unsupported")
    if table["kind"] != PLAN_KIND:
        raise VaultMigrationError("migration plan kind is invalid")
    if not isinstance(table["plan_id"], str) or not _PLAN_ID.fullmatch(table["plan_id"]):
        raise VaultMigrationError("migration plan id is invalid")
    source = _validate_scan_summary(table["source"], label="source")
    target = _validate_scan_summary(table["target"], label="target")
    if source["root_ref"] == target["root_ref"]:
        raise VaultMigrationError("source and target root fingerprints must differ")
    raw_operations = table["operations"]
    if not isinstance(raw_operations, list):
        raise VaultMigrationError("operations must be an array")
    operations: list[MigrationOperation] = []
    refs: set[str] = set()
    for raw_operation in raw_operations:
        operation = _strict_table(
            raw_operation,
            allowed={
                "operation_id",
                "action",
                "relative_ref",
                "source_sha256",
                "size",
                "target_precondition_sha256",
                "rollback",
            },
            required={
                "operation_id",
                "action",
                "relative_ref",
                "source_sha256",
                "size",
                "target_precondition_sha256",
                "rollback",
            },
            label="operation",
        )
        if not isinstance(operation["operation_id"], str) or not _OP_ID.fullmatch(operation["operation_id"]):
            raise VaultMigrationError("operation id is invalid")
        action = operation["action"]
        if action not in {"create", "update"}:
            raise VaultMigrationError("operation action is invalid")
        relative_ref = operation["relative_ref"]
        if not isinstance(relative_ref, str):
            raise VaultMigrationError("operation relative_ref is invalid")
        relative = _safe_relative(relative_ref)
        if any(part in ARCHIVE_COMPONENTS for part in relative.parts) or relative_ref in refs:
            raise VaultMigrationError("operation relative_ref is excluded or duplicate")
        refs.add(relative_ref)
        source_sha = operation["source_sha256"]
        if not isinstance(source_sha, str) or not _SHA256.fullmatch(source_sha):
            raise VaultMigrationError("operation source hash is invalid")
        size = _require_int(operation["size"], label="operation.size")
        target_sha = operation["target_precondition_sha256"]
        if target_sha is not None and (not isinstance(target_sha, str) or not _SHA256.fullmatch(target_sha)):
            raise VaultMigrationError("operation target precondition is invalid")
        expected_rollback = "remove-created-file" if action == "create" else "restore-target-preimage"
        if operation["rollback"] != expected_rollback:
            raise VaultMigrationError("operation rollback is invalid")
        if (action == "create") != (target_sha is None):
            raise VaultMigrationError("operation precondition does not match action")
        if action == "update" and target_sha == source_sha:
            raise VaultMigrationError("unchanged file must not be an update operation")
        identity = _operation_payload(action, ScannedFile(relative_ref, source_sha, size), target_sha)
        expected_id = f"op_{_sha256_bytes(_canonical_json(identity))[:24]}"
        if operation["operation_id"] != expected_id:
            raise VaultMigrationError("operation id does not match its contents")
        operations.append(MigrationOperation(operation_id=expected_id, **identity))
    if [item.relative_ref for item in operations] != sorted(refs):
        raise VaultMigrationError("operations are not in canonical order")
    summary_table = _strict_table(
        table["summary"],
        allowed={"create_count", "update_count", "unchanged_count", "target_only_count"},
        required={"create_count", "update_count", "unchanged_count", "target_only_count"},
        label="summary",
    )
    summary = {
        name: _require_int(summary_table[name], label=f"summary.{name}")
        for name in ("create_count", "update_count", "unchanged_count", "target_only_count")
    }
    if summary["create_count"] != sum(item.action == "create" for item in operations) or summary[
        "update_count"
    ] != sum(item.action == "update" for item in operations):
        raise VaultMigrationError("summary does not match operations")
    if (
        summary["create_count"]
        + summary["update_count"]
        + summary["unchanged_count"]
        != source["file_count"]
        or summary["update_count"]
        + summary["unchanged_count"]
        + summary["target_only_count"]
        != target["file_count"]
    ):
        raise VaultMigrationError("summary does not match scan fingerprints")
    identity_payload = {
        "schema_version": SCHEMA_VERSION,
        "kind": PLAN_KIND,
        "source": source,
        "target": target,
        "operations": [item.to_dict() for item in operations],
        "summary": summary,
    }
    expected_plan_id = f"mig_{_sha256_bytes(_canonical_json(identity_payload))[:24]}"
    if table["plan_id"] != expected_plan_id:
        raise VaultMigrationError("plan id does not match its contents")
    return MigrationPlan(
        SCHEMA_VERSION,
        PLAN_KIND,
        expected_plan_id,
        source,
        target,
        tuple(operations),
        summary,
    )
