"""Versioned vault layout and fail-closed path resolution.

The schema owns only the portable runtime zones.  It does not interpret note
contents and it never turns an arbitrary symbolic target into a filesystem
path.  Callers must select one of the explicit contract zones below.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import os
from pathlib import Path, PurePosixPath
from typing import Iterable, Iterator
import unicodedata

from ..config import MigrationRoot, VaultConfig


SCHEMA_VERSION = 1
ARCHIVE_COMPONENTS = frozenset({"_archive", "_trash", "_on_hold"})


class VaultSchemaError(ValueError):
    """A vault layout or requested path is invalid or unsafe."""


class ZoneState(str, Enum):
    PRESENT = "present"
    MISSING_OPTIONAL = "missing_optional"
    CORRUPT_OPTIONAL = "corrupt_optional"
    CORRUPT_REQUIRED = "corrupt_required"


@dataclass(frozen=True)
class ZoneSpec:
    """One schema-owned directory.

    ``config_name`` selects a path from ``lifeos.toml``.  A fixed path is used
    only for runtime zones that are intentionally not human knowledge zones.
    """

    name: str
    required: bool
    config_name: str | None = None
    fixed_path: PurePosixPath | None = None

    def relative_path(self, config: VaultConfig) -> PurePosixPath:
        if self.config_name is not None:
            return config.zone(self.config_name)
        if self.fixed_path is None:  # pragma: no cover - module invariant
            raise VaultSchemaError("zone has no configured path")
        return self.fixed_path


# The target names are the exact P0 symbolic authority zones.  Derived targets
# remain inside the owning base zone instead of creating new authority roots.
ZONE_SPECS: tuple[ZoneSpec, ...] = (
    ZoneSpec("inbox", True, config_name="inbox"),
    ZoneSpec("review", True, config_name="review"),
    ZoneSpec("tasks", True, config_name="tasks"),
    ZoneSpec("projects", True, config_name="projects"),
    ZoneSpec("knowledge", True, config_name="knowledge"),
    ZoneSpec("agent/memory", True, config_name="memory"),
    ZoneSpec("agent/runs", True, config_name="runs"),
    ZoneSpec("agent/outbox", True, config_name="outbox"),
    ZoneSpec("agent/logs", True, fixed_path=PurePosixPath("agent/logs")),
    ZoneSpec("agent/dashboard", True, fixed_path=PurePosixPath("agent/dashboard")),
    ZoneSpec(".lifeos/review-plans", True, fixed_path=PurePosixPath(".lifeos/review-plans")),
    ZoneSpec("agent/reading", False, fixed_path=PurePosixPath("agent/reading")),
)

_SPECS_BY_NAME = {spec.name: spec for spec in ZONE_SPECS}
_DERIVED_ZONES: dict[str, tuple[str, PurePosixPath]] = {
    "agent/memory-metadata": ("agent/memory", PurePosixPath("metadata")),
    "agent/memory/entities": ("agent/memory", PurePosixPath("entities")),
    "agent/memory/trails": ("agent/memory", PurePosixPath("trails")),
    "agent/logs/done-events": ("agent/logs", PurePosixPath("done-events")),
    "agent/logs/metrics": ("agent/logs", PurePosixPath("metrics")),
    "agent/logs/tasks": ("agent/logs", PurePosixPath("tasks")),
    "agent/runs/trace": ("agent/runs", PurePosixPath("trace")),
}


@dataclass(frozen=True)
class ZoneCheck:
    name: str
    state: ZoneState
    required: bool
    detail: str


@dataclass(frozen=True)
class VaultSchemaReport:
    schema_version: int
    checks: tuple[ZoneCheck, ...]

    @property
    def valid(self) -> bool:
        return not any(
            check.state in {ZoneState.CORRUPT_REQUIRED, ZoneState.CORRUPT_OPTIONAL}
            for check in self.checks
        )

    @property
    def missing_optional(self) -> tuple[str, ...]:
        return tuple(
            check.name for check in self.checks if check.state is ZoneState.MISSING_OPTIONAL
        )

    @property
    def corrupt_required(self) -> tuple[str, ...]:
        return tuple(
            check.name for check in self.checks if check.state is ZoneState.CORRUPT_REQUIRED
        )

    @property
    def corrupt_optional(self) -> tuple[str, ...]:
        return tuple(
            check.name for check in self.checks if check.state is ZoneState.CORRUPT_OPTIONAL
        )

    def require_valid(self) -> None:
        if not self.valid:
            raise VaultSchemaError("vault schema is corrupt")


def _has_control(text: str) -> bool:
    return any(
        unicodedata.category(character).startswith("C")
        or unicodedata.category(character) in {"Zl", "Zp"}
        for character in text
    )


def _safe_relative(
    value: str | os.PathLike[str] | PurePosixPath, *, allow_root: bool
) -> PurePosixPath:
    try:
        text = os.fspath(value)
    except TypeError as error:
        raise VaultSchemaError("path must be text") from error
    if not isinstance(text, str):
        raise VaultSchemaError("path must be text")
    if not text:
        if allow_root:
            return PurePosixPath(".")
        raise VaultSchemaError("path must not be empty")
    if "\\" in text or _has_control(text):
        raise VaultSchemaError("path contains non-portable or control characters")
    path = PurePosixPath(text)
    if path.is_absolute() or ".." in path.parts:
        raise VaultSchemaError("path must be relative and must not traverse")
    if path == PurePosixPath(".") and not allow_root:
        raise VaultSchemaError("path must name a child")
    return path


def _overlaps(first: Path, second: Path) -> bool:
    return first == second or first in second.parents or second in first.parents


def _contained(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def is_archive_path(value: str | os.PathLike[str] | PurePosixPath) -> bool:
    """Return whether a safe relative path enters an excluded archive tree."""

    relative = _safe_relative(value, allow_root=True)
    return any(part in ARCHIVE_COMPONENTS for part in relative.parts)


def iter_active_paths(root: str | os.PathLike[str]) -> Iterator[Path]:
    """Walk a tree without descending into archive, trash, or hold dirs."""

    root_path = Path(root)
    for current, dirs, files in os.walk(root_path, followlinks=False):
        dirs[:] = sorted(name for name in dirs if name not in ARCHIVE_COMPONENTS)
        current_path = Path(current)
        for name in sorted(files):
            path = current_path / name
            if not path.is_symlink():
                yield path


class VaultPathResolver:
    """Resolve allowlisted symbolic vault paths with fresh containment checks.

    Inputs are intentionally retained unresolved.  Every call resolves the
    vault root, the selected zone, and read-only roots again, so a symlink swap
    after config loading cannot reuse a stale containment decision.
    """

    def __init__(
        self,
        root: str | os.PathLike[str],
        config: VaultConfig,
        *,
        read_only_roots: Iterable[str | os.PathLike[str] | MigrationRoot] = (),
    ) -> None:
        if config.schema_version != SCHEMA_VERSION:
            raise VaultSchemaError("unsupported vault schema version")
        self._root_input = Path(root).absolute()
        self.config = config
        protected: list[Path] = []
        for entry in read_only_roots:
            if isinstance(entry, MigrationRoot):
                if not entry.read_only:
                    raise VaultSchemaError("migration root must be read-only")
                path = entry.path
            else:
                path = Path(entry)
            if not path.is_absolute():
                raise VaultSchemaError("read-only migration root must be absolute")
            protected.append(path)
        self._protected_inputs = tuple(protected)
        # Validate static namespace collisions now, then repeat physical checks
        # on each resolution because symlinks may change later.
        self._validate_relative_namespace()

    def _validate_relative_namespace(self) -> None:
        bases: list[tuple[str, PurePosixPath]] = [
            (spec.name, spec.relative_path(self.config)) for spec in ZONE_SPECS
        ]
        for index, (name, first) in enumerate(bases):
            for other_name, second in bases[index + 1 :]:
                if first == second or first in second.parents or second in first.parents:
                    raise VaultSchemaError(f"vault zones overlap: {name}, {other_name}")

    def _root(self, *, must_exist: bool) -> Path:
        try:
            root = self._root_input.resolve(strict=must_exist)
        except (OSError, RuntimeError) as error:
            raise VaultSchemaError("vault root cannot be resolved") from error
        if must_exist and not root.is_dir():
            raise VaultSchemaError("vault root is not a directory")
        return root

    def _protected_roots(self) -> tuple[Path, ...]:
        try:
            return tuple(path.resolve(strict=False) for path in self._protected_inputs)
        except (OSError, RuntimeError) as error:
            raise VaultSchemaError("read-only migration root cannot be resolved") from error

    def _validate_physical_namespace(self, root: Path) -> None:
        bases: list[tuple[str, Path]] = []
        try:
            for spec in ZONE_SPECS:
                path = (root / spec.relative_path(self.config)).resolve(strict=False)
                if not _contained(path, root):
                    raise VaultSchemaError("vault zone escapes the vault root")
                bases.append((spec.name, path))
        except (OSError, RuntimeError) as error:
            raise VaultSchemaError("vault zone cannot be resolved") from error
        for index, (name, first) in enumerate(bases):
            for other_name, second in bases[index + 1 :]:
                if _overlaps(first, second):
                    raise VaultSchemaError(f"physical vault zones overlap: {name}, {other_name}")

    def _zone_relative(self, symbolic_zone: str) -> PurePosixPath:
        if not isinstance(symbolic_zone, str) or _has_control(symbolic_zone):
            raise VaultSchemaError("symbolic zone is invalid")
        spec = _SPECS_BY_NAME.get(symbolic_zone)
        if spec is not None:
            return spec.relative_path(self.config)
        derived = _DERIVED_ZONES.get(symbolic_zone)
        if derived is None:
            raise VaultSchemaError("unknown symbolic vault zone")
        parent, suffix = derived
        return self._zone_relative(parent) / suffix

    def _resolve_candidate(
        self,
        symbolic_zone: str,
        relative: str | os.PathLike[str] | PurePosixPath,
        *,
        for_write: bool,
        allow_archive: bool,
        must_exist: bool,
    ) -> Path:
        root = self._root(must_exist=must_exist)
        self._validate_physical_namespace(root)
        zone_relative = self._zone_relative(symbolic_zone)
        leaf = _safe_relative(relative, allow_root=True)
        combined = zone_relative if leaf == PurePosixPath(".") else zone_relative / leaf
        if not allow_archive and is_archive_path(combined):
            raise VaultSchemaError("archive, trash, and hold paths are excluded")
        try:
            zone = (root / zone_relative).resolve(strict=False)
            candidate = (root / combined).resolve(strict=must_exist)
        except (OSError, RuntimeError) as error:
            raise VaultSchemaError("vault path cannot be resolved") from error
        if not _contained(zone, root) or not _contained(candidate, zone):
            raise VaultSchemaError("vault path escapes its allowlisted zone")
        if not allow_archive:
            physical_from_root = candidate.relative_to(root)
            physical_from_zone = candidate.relative_to(zone)
            if is_archive_path(physical_from_root) or is_archive_path(physical_from_zone):
                raise VaultSchemaError("vault path physically enters an excluded archive tree")

        protected = self._protected_roots()
        if for_write and any(_overlaps(candidate, item) for item in protected):
            raise VaultSchemaError("resolved write path overlaps a read-only migration root")
        # Reject a vault whose physical root changed into a protected tree even
        # for a missing leaf.  This is deliberately repeated on every call.
        if for_write and any(_overlaps(root, item) for item in protected):
            raise VaultSchemaError("vault root overlaps a read-only migration root")
        return candidate

    def resolve(
        self,
        symbolic_zone: str,
        relative: str | os.PathLike[str] | PurePosixPath = ".",
        *,
        for_write: bool = False,
        allow_archive: bool = False,
        must_exist: bool = False,
    ) -> Path:
        """Resolve a path and repeat every security-relevant check."""

        return self._resolve_candidate(
            symbolic_zone,
            relative,
            for_write=for_write,
            allow_archive=allow_archive,
            must_exist=must_exist,
        )

    def revalidate(
        self,
        expected: str | os.PathLike[str],
        symbolic_zone: str,
        relative: str | os.PathLike[str] | PurePosixPath = ".",
        *,
        for_write: bool = False,
        allow_archive: bool = False,
        must_exist: bool = False,
    ) -> Path:
        """Resolve again immediately before I/O and reject a changed target."""

        actual = self.resolve(
            symbolic_zone,
            relative,
            for_write=for_write,
            allow_archive=allow_archive,
            must_exist=must_exist,
        )
        try:
            expected_path = Path(expected).resolve(strict=must_exist)
        except (OSError, RuntimeError) as error:
            raise VaultSchemaError("expected vault path cannot be resolved") from error
        if actual != expected_path:
            raise VaultSchemaError("vault path changed since it was resolved")
        return actual

    def validate(self) -> VaultSchemaReport:
        """Inspect structure only; do not create, touch, or repair anything."""

        checks: list[ZoneCheck] = []
        try:
            root = self._root(must_exist=True)
        except VaultSchemaError:
            return VaultSchemaReport(
                SCHEMA_VERSION,
                (ZoneCheck("vault", ZoneState.CORRUPT_REQUIRED, True, "root is missing or invalid"),),
            )

        config_path = root / "lifeos.toml"
        if not config_path.is_file() or config_path.is_symlink():
            checks.append(
                ZoneCheck("lifeos.toml", ZoneState.CORRUPT_REQUIRED, True, "required regular file is missing")
            )
        else:
            checks.append(ZoneCheck("lifeos.toml", ZoneState.PRESENT, True, "regular file"))

        resolved_bases: list[tuple[str, Path]] = []
        for spec in ZONE_SPECS:
            try:
                path = self.resolve(spec.name, must_exist=False)
            except VaultSchemaError:
                state = ZoneState.CORRUPT_REQUIRED if spec.required else ZoneState.CORRUPT_OPTIONAL
                checks.append(ZoneCheck(spec.name, state, spec.required, "unsafe path"))
                continue
            if not path.exists():
                state = ZoneState.CORRUPT_REQUIRED if spec.required else ZoneState.MISSING_OPTIONAL
                detail = "required directory is missing" if spec.required else "optional directory is absent"
                checks.append(ZoneCheck(spec.name, state, spec.required, detail))
                continue
            if not path.is_dir():
                state = ZoneState.CORRUPT_REQUIRED if spec.required else ZoneState.CORRUPT_OPTIONAL
                detail = "required path is not a directory" if spec.required else "optional path is not a directory"
                checks.append(ZoneCheck(spec.name, state, spec.required, detail))
                continue
            if any(path == other or path in other.parents or other in path.parents for _, other in resolved_bases):
                state = ZoneState.CORRUPT_REQUIRED if spec.required else ZoneState.CORRUPT_OPTIONAL
                checks.append(ZoneCheck(spec.name, state, spec.required, "physical zone overlaps another zone"))
                continue
            resolved_bases.append((spec.name, path))
            checks.append(ZoneCheck(spec.name, ZoneState.PRESENT, spec.required, "directory"))
        return VaultSchemaReport(SCHEMA_VERSION, tuple(checks))


def validate_vault(
    root: str | os.PathLike[str],
    config: VaultConfig,
    *,
    read_only_roots: Iterable[str | os.PathLike[str] | MigrationRoot] = (),
) -> VaultSchemaReport:
    return VaultPathResolver(root, config, read_only_roots=read_only_roots).validate()
