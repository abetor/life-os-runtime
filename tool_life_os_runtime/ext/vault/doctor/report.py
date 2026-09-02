"""Bounded doctor/status report for explicit runtime paths.

The doctor never discovers paths through ``HOME`` and never emits configured
paths, subprocess output, or parser diagnostics.  Callers supply the repo and
runtime-home roots explicitly and inject the connector probe boundary.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import threading
from typing import Callable, Mapping, Sequence
import unicodedata

from tool_life_os_runtime.ext.connectors.probes import (
    CapabilityContract,
    DEFAULT_SPECS,
    MachineOutputContract,
    ProbeRecord,
    ProbeSpec,
)
from tool_life_os_runtime.ext.vault.config import (
    ConfigError,
    RuntimeConfig,
    VaultConfig,
    load_runtime_config,
    load_vault_config,
)
from tool_life_os_runtime.ext.vault.schema import (
    ZONE_SPECS,
    VaultPathResolver,
    VaultSchemaError,
    VaultSchemaReport,
    ZoneCheck,
    ZoneState,
)


STATUS_SCHEMA_VERSION = 1
STATUS_KIND = "lifeos-doctor-status"
SECTION_ORDER = ("repo", "runtime_home", "vault", "connectors")
MAX_CONFIG_BYTES = 256 * 1024
MAX_STATUS_BYTES = 128 * 1024
MAX_CHECKS_PER_SECTION = 128
_PROBE_OUTPUT_LIMIT = 64 * 1024 + 1

_LEVELS = frozenset({"ok", "warning", "failure"})
_IDENTIFIER = re.compile(r"^[a-z][a-z0-9._-]{0,127}$")
_HASH_REF = re.compile(r"^sha256:[0-9a-f]{64}$")
_PROBE_STATUSES = frozenset(
    {"compatible", "unavailable", "quota", "transient", "contract_error"}
)
_IDEMPOTENCY = frozenset({"deduplicated", "idempotent", "read-only"})
_MAX_CAPABILITIES = 64
_MAX_ARGV_ITEMS = 64
_MAX_ARG_BYTES = 4096
_MAX_EXIT_CODES = 32
_MAX_REQUIRED_FIELDS = 64


class DoctorError(ValueError):
    """A status payload or doctor input violates the bounded contract."""


@dataclass(frozen=True)
class DoctorCheck:
    id: str
    status: str
    required: bool
    code: str
    ref: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "status": self.status,
            "required": self.required,
            "code": self.code,
            "ref": self.ref,
        }


@dataclass(frozen=True)
class DoctorSection:
    name: str
    status: str
    checks: tuple[DoctorCheck, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "status": self.status,
            "checks": [check.to_dict() for check in self.checks],
        }


@dataclass(frozen=True)
class DoctorReport:
    schema_version: int
    kind: str
    status: str
    warning_count: int
    failure_count: int
    sections: tuple[DoctorSection, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "kind": self.kind,
            "status": self.status,
            "summary": {
                "warning_count": self.warning_count,
                "failure_count": self.failure_count,
            },
            "sections": [section.to_dict() for section in self.sections],
        }


ConnectorProbe = Callable[[], Sequence[ProbeRecord]]
ConfiguredConnectorProbe = Callable[[RuntimeConfig | None], Sequence[ProbeRecord]]


def _level(checks: Sequence[DoctorCheck]) -> str:
    if any(check.status == "failure" for check in checks):
        return "failure"
    if any(check.status == "warning" for check in checks):
        return "warning"
    return "ok"


def _section(name: str, checks: Sequence[DoctorCheck]) -> DoctorSection:
    ordered = tuple(sorted(checks, key=lambda check: check.id))
    return DoctorSection(name, _level(ordered), ordered)


def _report(sections: Sequence[DoctorSection]) -> DoctorReport:
    ordered = tuple(sections)
    all_checks = [check for section in ordered for check in section.checks]
    failures = sum(check.status == "failure" for check in all_checks)
    warnings = sum(check.status == "warning" for check in all_checks)
    return DoctorReport(
        STATUS_SCHEMA_VERSION,
        STATUS_KIND,
        "failure" if failures else "warning" if warnings else "ok",
        warnings,
        failures,
        ordered,
    )


def _has_control(value: str) -> bool:
    return any(
        unicodedata.category(character).startswith("C")
        or unicodedata.category(character) in {"Zl", "Zp"}
        for character in value
    )


def _explicit_path(value: str | os.PathLike[str]) -> Path:
    try:
        raw = os.fspath(value)
    except TypeError as error:
        raise DoctorError("path must be explicit") from error
    if not isinstance(raw, str) or not raw or _has_control(raw) or "\\" in raw:
        raise DoctorError("path must be explicit")
    path = Path(raw)
    if not path.is_absolute() or ".." in path.parts:
        raise DoctorError("path must be explicit")
    return path


def _ref(path: Path) -> str:
    return "sha256:" + hashlib.sha256(os.fsencode(path)).hexdigest()


@dataclass(frozen=True)
class _BoundRoot:
    path: Path
    fd: int
    identity: tuple[int, int]


@dataclass(frozen=True)
class _RuntimeConfigStamp:
    root_path: Path
    root_identity: tuple[int, int]
    file_identity: tuple[int, int, int, int, int]
    sha256: str


@dataclass(frozen=True)
class _RootStamp:
    path: Path
    identity: tuple[int, int]


def _directory_identity(metadata: os.stat_result) -> tuple[int, int]:
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise DoctorError("root must be a directory")
    return metadata.st_dev, metadata.st_ino


def _root_check(
    check_id: str, value: str | os.PathLike[str]
) -> tuple[DoctorCheck, _BoundRoot | None]:
    supplied: Path | None = None
    try:
        supplied = _explicit_path(value)
        flags = (
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        fd = os.open(supplied, flags)
        try:
            identity = _directory_identity(os.fstat(fd))
        except Exception:
            os.close(fd)
            raise
    except (DoctorError, OSError, RuntimeError):
        return (
            DoctorCheck(
                check_id,
                "failure",
                True,
                "root_invalid",
                None if supplied is None else _ref(supplied),
            ),
            None,
        )
    return (
        DoctorCheck(check_id, "ok", True, "root_valid", _ref(supplied)),
        _BoundRoot(supplied, fd, identity),
    )


def _root_revalidated_check(check_id: str, root: _BoundRoot) -> DoctorCheck:
    try:
        current = _directory_identity(os.stat(root.path, follow_symlinks=False))
        held = _directory_identity(os.fstat(root.fd))
    except (DoctorError, OSError):
        current = None
        held = root.identity
    if current != root.identity or held != root.identity:
        return DoctorCheck(check_id, "failure", True, "root_changed", _ref(root.path))
    return DoctorCheck(check_id, "ok", True, "root_valid", _ref(root.path))


def _safe_relative_parts(value: str | os.PathLike[str]) -> tuple[str, ...]:
    try:
        raw = os.fspath(value)
    except TypeError as error:
        raise DoctorError("entry path is invalid") from error
    if not isinstance(raw, str) or not raw or _has_control(raw) or "\\" in raw:
        raise DoctorError("entry path is invalid")
    parts = tuple(part for part in raw.split("/") if part)
    if raw.startswith("/") or not parts or any(part in {".", ".."} for part in parts):
        raise DoctorError("entry path is invalid")
    return parts


def _entry_state_at(
    root_fd: int, relative: str | os.PathLike[str], *, directory: bool
) -> str:
    """Return present/missing/invalid without following any path component."""

    opened: list[int] = []
    current_fd = root_fd
    try:
        parts = _safe_relative_parts(relative)
        flags = (
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        for component in parts[:-1]:
            try:
                child_fd = os.open(component, flags, dir_fd=current_fd)
            except FileNotFoundError:
                return "missing"
            except OSError:
                return "invalid"
            opened.append(child_fd)
            current_fd = child_fd
        try:
            metadata = os.stat(parts[-1], dir_fd=current_fd, follow_symlinks=False)
        except FileNotFoundError:
            return "missing"
        except OSError:
            return "invalid"
        expected = (
            stat.S_ISDIR(metadata.st_mode)
            if directory
            else stat.S_ISREG(metadata.st_mode)
        )
        if stat.S_ISLNK(metadata.st_mode) or not expected:
            return "invalid"
        return "present"
    except DoctorError:
        return "invalid"
    finally:
        for fd in reversed(opened):
            os.close(fd)


def _entry_check_at(
    check_id: str,
    root: _BoundRoot,
    relative: str,
    *,
    directory: bool,
) -> DoctorCheck:
    state = _entry_state_at(root.fd, relative, directory=directory)
    ref = _ref(root.path / relative)
    if state == "missing":
        return DoctorCheck(check_id, "failure", True, "required_entry_missing", ref)
    if state == "invalid":
        return DoctorCheck(check_id, "failure", True, "required_entry_invalid", ref)
    return DoctorCheck(check_id, "ok", True, "required_entry_valid", ref)


def _metadata_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise DoctorError("config must be a regular file")
    if metadata.st_size > MAX_CONFIG_BYTES:
        raise DoctorError("config is too large")
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _read_config_snapshot_at(
    root_fd: int, name: str
) -> tuple[bytes, tuple[int, int, int, int, int]]:
    parts = _safe_relative_parts(name)
    if len(parts) != 1:
        raise DoctorError("config must be a direct root child")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(parts[0], flags, dir_fd=root_fd)
    except OSError as error:
        raise DoctorError("config cannot be opened safely") from error
    try:
        before = _metadata_identity(os.fstat(fd))
        chunks: list[bytes] = []
        remaining = MAX_CONFIG_BYTES + 1
        while remaining:
            chunk = os.read(fd, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > MAX_CONFIG_BYTES:
            raise DoctorError("config is too large")
        after = _metadata_identity(os.fstat(fd))
        if after != before or len(raw) != before[2]:
            raise DoctorError("config changed while inspected")
        return raw, before
    except OSError as error:
        raise DoctorError("config cannot be read safely") from error
    finally:
        os.close(fd)


def _parse_snapshot(raw: bytes, loader: Callable[[Path], object]) -> object:
    """Feed exact captured bytes through the canonical path-based parser."""

    read_fd, write_fd = os.pipe()
    alias: Path | None = None
    for candidate in (Path(f"/dev/fd/{read_fd}"), Path(f"/proc/self/fd/{read_fd}")):
        if candidate.exists():
            alias = candidate
            break
    if alias is None:
        os.close(read_fd)
        os.close(write_fd)
        raise DoctorError("bounded config parser is unavailable")

    write_failed = False

    def feed() -> None:
        nonlocal write_failed
        view = memoryview(raw)
        try:
            while view:
                written = os.write(write_fd, view)
                if written <= 0:
                    write_failed = True
                    break
                view = view[written:]
        except OSError:
            write_failed = True
        finally:
            os.close(write_fd)

    feeder = threading.Thread(
        target=feed, name="lifeos-doctor-config-feed", daemon=True
    )
    try:
        feeder.start()
    except Exception as error:
        os.close(read_fd)
        os.close(write_fd)
        if feeder.is_alive():
            feeder.join(timeout=1.0)
        raise DoctorError("bounded config parser failed") from error
    try:
        value = loader(alias)
    finally:
        os.close(read_fd)
        feeder.join(timeout=1.0)
    if feeder.is_alive() or write_failed:
        raise DoctorError("bounded config parser failed")
    return value


def _guarded_load_at(
    root: _BoundRoot,
    name: str,
    loader: Callable[[Path], object],
) -> object:
    value, _, _ = _guarded_load_snapshot_at(root, name, loader)
    return value


def _guarded_load_snapshot_at(
    root: _BoundRoot,
    name: str,
    loader: Callable[[Path], object],
) -> tuple[object, tuple[int, int, int, int, int], str]:
    raw, before = _read_config_snapshot_at(root.fd, name)
    try:
        value = _parse_snapshot(raw, loader)
    except (ConfigError, OSError, UnicodeError, ValueError, RecursionError) as error:
        raise DoctorError("config is invalid") from error
    try:
        after = _metadata_identity(os.stat(name, dir_fd=root.fd, follow_symlinks=False))
    except (DoctorError, OSError, TypeError, ValueError) as error:
        raise DoctorError("config changed while inspected") from error
    if after != before:
        raise DoctorError("config changed while inspected")
    return value, before, hashlib.sha256(raw).hexdigest()


def _repo_section(
    repo_value: str | os.PathLike[str],
) -> tuple[DoctorSection, _RootStamp | None]:
    root_check, root = _root_check("repo.root", repo_value)
    checks = [root_check]
    stamp: _RootStamp | None = None
    if root is not None:
        try:
            checks.extend(
                [
                    _entry_check_at(
                        "repo.package", root, "tool_life_os_runtime", directory=True
                    ),
                    _entry_check_at(
                        "repo.pyproject", root, "pyproject.toml", directory=False
                    ),
                ]
            )
            checks[0] = _root_revalidated_check("repo.root", root)
            if checks[0].status != "failure":
                stamp = _RootStamp(root.path, root.identity)
        finally:
            os.close(root.fd)
    return _section("repo", checks), stamp


def _runtime_section(
    runtime_value: str | os.PathLike[str],
) -> tuple[DoctorSection, RuntimeConfig | None, _RuntimeConfigStamp | None]:
    root_check, root = _root_check("runtime_home.root", runtime_value)
    checks = [root_check]
    config: RuntimeConfig | None = None
    stamp: _RuntimeConfigStamp | None = None
    if root is not None:
        try:
            config_path = root.path / "config.toml"
            try:
                loaded, file_identity, digest = _guarded_load_snapshot_at(
                    root,
                    "config.toml",
                    load_runtime_config,
                )
                if type(loaded) is not RuntimeConfig:
                    raise DoctorError("runtime config has wrong type")
                config = loaded
                stamp = _RuntimeConfigStamp(
                    root.path,
                    root.identity,
                    file_identity,
                    digest,
                )
                checks.append(
                    DoctorCheck(
                        "runtime_home.config",
                        "ok",
                        True,
                        "config_valid",
                        _ref(config_path),
                    )
                )
            except DoctorError:
                checks.append(
                    DoctorCheck(
                        "runtime_home.config",
                        "failure",
                        True,
                        "config_invalid",
                        _ref(config_path),
                    )
                )
            checks[0] = _root_revalidated_check("runtime_home.root", root)
            if checks[0].status == "failure":
                config = None
                stamp = None
        finally:
            os.close(root.fd)
    return _section("runtime_home", checks), config, stamp


def _replace_runtime_check(
    section: DoctorSection, check_id: str, code: str
) -> DoctorSection:
    checks = [
        DoctorCheck(check.id, "failure", True, code, check.ref)
        if check.id == check_id
        else check
        for check in section.checks
    ]
    return _section("runtime_home", checks)


def _revalidate_runtime_section(
    section: DoctorSection, stamp: _RuntimeConfigStamp | None
) -> DoctorSection:
    if stamp is None:
        return section
    root: _BoundRoot | None = None
    try:
        _, root = _root_check("runtime_home.root", stamp.root_path)
        if root is None or root.identity != stamp.root_identity:
            return _replace_runtime_check(
                section,
                "runtime_home.root",
                "root_changed",
            )
        raw, file_identity = _read_config_snapshot_at(root.fd, "config.toml")
        named_identity = _metadata_identity(
            os.stat("config.toml", dir_fd=root.fd, follow_symlinks=False)
        )
        if (
            file_identity != stamp.file_identity
            or named_identity != file_identity
            or hashlib.sha256(raw).hexdigest() != stamp.sha256
        ):
            return _replace_runtime_check(
                section,
                "runtime_home.config",
                "config_invalid",
            )
        if _root_revalidated_check("runtime_home.root", root).status == "failure":
            return _replace_runtime_check(
                section,
                "runtime_home.root",
                "root_changed",
            )
    except (DoctorError, OSError, TypeError, ValueError):
        return _replace_runtime_check(
            section,
            "runtime_home.config",
            "config_invalid",
        )
    finally:
        if root is not None:
            os.close(root.fd)
    return section


def _zone_check(name: str, state: ZoneState, required: bool) -> DoctorCheck:
    check_id = "vault.zone." + name.replace("/", ".")
    if state is ZoneState.PRESENT:
        return DoctorCheck(check_id, "ok", required, "zone_present")
    if state is ZoneState.MISSING_OPTIONAL:
        return DoctorCheck(check_id, "warning", False, "optional_zone_missing")
    if state is ZoneState.CORRUPT_OPTIONAL:
        return DoctorCheck(check_id, "failure", False, "optional_zone_corrupt")
    return DoctorCheck(check_id, "failure", True, "required_zone_corrupt")


def _vault_schema_at(root: _BoundRoot, profile: VaultConfig) -> VaultSchemaReport:
    checks = [ZoneCheck("lifeos.toml", ZoneState.PRESENT, True, "regular file")]
    for spec in ZONE_SPECS:
        relative = spec.relative_path(profile).as_posix()
        state = _entry_state_at(root.fd, relative, directory=True)
        if state == "present":
            zone_state = ZoneState.PRESENT
        elif state == "missing" and not spec.required:
            zone_state = ZoneState.MISSING_OPTIONAL
        elif spec.required:
            zone_state = ZoneState.CORRUPT_REQUIRED
        else:
            zone_state = ZoneState.CORRUPT_OPTIONAL
        checks.append(ZoneCheck(spec.name, zone_state, spec.required, state))
    return VaultSchemaReport(1, tuple(checks))


def _vault_section(
    config: RuntimeConfig | None,
) -> tuple[DoctorSection, _RootStamp | None]:
    if config is None:
        return (
            _section(
                "vault",
                [
                    DoctorCheck(
                        "vault.config",
                        "failure",
                        True,
                        "runtime_config_unavailable",
                    )
                ],
            ),
            None,
        )
    try:
        alias = config.vault(config.default_vault)
        root = alias.path
    except (ConfigError, ValueError):
        return (
            _section(
                "vault",
                [DoctorCheck("vault.root", "failure", True, "vault_alias_invalid")],
            ),
            None,
        )
    root_check, checked_root = _root_check("vault.root", root)
    checks = [root_check]
    if checked_root is None:
        return _section("vault", checks), None
    stamp: _RootStamp | None = None
    try:
        profile_path = checked_root.path / "lifeos.toml"
        try:
            profile = _guarded_load_at(checked_root, "lifeos.toml", load_vault_config)
            if type(profile) is not VaultConfig:
                raise DoctorError("vault config has wrong type")
            # Constructor validates the static configured namespace without
            # resolving or reading the named root. All filesystem inspection
            # below remains anchored to the held root descriptor.
            VaultPathResolver(
                checked_root.path,
                profile,
                read_only_roots=config.migration,
            )
            schema_report = _vault_schema_at(checked_root, profile)
        except (DoctorError, VaultSchemaError, ConfigError, TypeError, ValueError):
            checks.append(
                DoctorCheck(
                    "vault.config",
                    "failure",
                    True,
                    "vault_config_invalid",
                    _ref(profile_path),
                )
            )
        else:
            checks.append(
                DoctorCheck(
                    "vault.config", "ok", True, "vault_config_valid", _ref(profile_path)
                )
            )
            checks.extend(
                _zone_check(check.name, check.state, check.required)
                for check in schema_report.checks
            )
        checks[0] = _root_revalidated_check("vault.root", checked_root)
        if checks[0].status != "failure":
            stamp = _RootStamp(checked_root.path, checked_root.identity)
    finally:
        os.close(checked_root.fd)
    return _section("vault", checks), stamp


def _invalidate_root_snapshot(section: DoctorSection) -> DoctorSection:
    return _section(
        section.name,
        [
            DoctorCheck(
                check.id,
                "failure",
                check.required,
                "root_changed",
                check.ref,
            )
            for check in section.checks
        ],
    )


def _revalidate_repo_section(
    original: DoctorSection,
    stamp: _RootStamp | None,
) -> DoctorSection:
    if stamp is None:
        return original
    current, current_stamp = _repo_section(stamp.path)
    if current_stamp is None or current_stamp.identity != stamp.identity:
        return _invalidate_root_snapshot(original)
    return current


def _revalidate_vault_section(
    original: DoctorSection,
    config: RuntimeConfig | None,
    stamp: _RootStamp | None,
) -> DoctorSection:
    if stamp is None:
        return original
    current, current_stamp = _vault_section(config)
    if current_stamp is None or current_stamp.identity != stamp.identity:
        return _invalidate_root_snapshot(original)
    return current


def _machine_output_valid(value: object) -> bool:
    if type(value) is not MachineOutputContract:
        return False
    fields = value.required_fields
    return (
        type(value.format) is str
        and value.format == "json"
        and type(value.schema_version) is int
        and value.schema_version == 1
        and type(fields) is tuple
        and 0 < len(fields) <= _MAX_REQUIRED_FIELDS
        and all(type(item) is str and _IDENTIFIER.fullmatch(item) for item in fields)
        and len(set(fields)) == len(fields)
    )


def _capability_valid(value: object, *, executable: str) -> bool:
    if type(value) is not CapabilityContract:
        return False
    argv = value.argv
    exits = value.exit_codes
    if (
        type(value.name) is not str
        or _IDENTIFIER.fullmatch(value.name) is None
        or type(argv) is not tuple
        or not 0 < len(argv) <= _MAX_ARGV_ITEMS
        or any(
            type(item) is not str
            or not item
            or len(item.encode("utf-8")) > _MAX_ARG_BYTES
            or _has_control(item)
            for item in argv
        )
        or argv[0] != executable
        or not _machine_output_valid(value.machine_output)
        or type(exits) is not tuple
        or not 0 < len(exits) <= _MAX_EXIT_CODES
        or type(value.idempotency) is not str
        or value.idempotency not in _IDEMPOTENCY
    ):
        return False
    codes: list[int] = []
    for entry in exits:
        if (
            type(entry) is not tuple
            or len(entry) != 2
            or type(entry[0]) is not int
            or not 0 <= entry[0] <= 255
            or type(entry[1]) is not str
            or _IDENTIFIER.fullmatch(entry[1]) is None
        ):
            return False
        codes.append(entry[0])
    return len(set(codes)) == len(codes) and 0 in codes


def _probe_spec_valid(spec: object) -> bool:
    try:
        if type(spec) is not ProbeSpec:
            return False
        capabilities = spec.expected_capabilities
        if (
            type(spec.tool) is not str
            or _IDENTIFIER.fullmatch(spec.tool) is None
            or type(spec.executable) is not str
            or not spec.executable
            or len(spec.executable.encode("utf-8")) > 256
            or _has_control(spec.executable)
            or type(spec.optional) is not bool
            or type(spec.machine_contract_available) is not bool
            or type(capabilities) is not tuple
            or not 0 <= len(capabilities) <= _MAX_CAPABILITIES
            or type(spec.minimum_version) is not tuple
            or len(spec.minimum_version) != 3
            or type(spec.maximum_version_exclusive) is not tuple
            or len(spec.maximum_version_exclusive) != 3
            or spec.argv
            != (
                (spec.executable, "capabilities", "--json")
                if spec.machine_contract_available
                else ()
            )
            or (spec.machine_contract_available and not capabilities)
            or (not spec.machine_contract_available and capabilities)
            or any(
                type(item) is not int or not 0 <= item <= 999_999_999
                for item in spec.minimum_version
            )
            or any(
                type(item) is not int or not 0 <= item <= 999_999_999
                for item in spec.maximum_version_exclusive
            )
            or spec.minimum_version >= spec.maximum_version_exclusive
            or any(
                not _capability_valid(capability, executable=spec.executable)
                for capability in capabilities
            )
        ):
            return False
        names = tuple(capability.name for capability in capabilities)
        return len(set(names)) == len(names)
    except Exception:
        return False


def _probe_record_valid(record: object, spec: ProbeSpec) -> bool:
    try:
        if type(record) is not ProbeRecord or not _probe_spec_valid(spec):
            return False
        if not spec.machine_contract_available and (
            record.status != "unavailable"
            or record.error != "machine_contract_unavailable"
        ):
            return False
        required_capabilities = tuple(
            capability.name for capability in spec.expected_capabilities
        )
        if (
            type(record.tool) is not str
            or record.tool != spec.tool
            or type(record.optional) is not bool
            or record.optional is not spec.optional
            or type(record.probe_argv) is not tuple
            or any(type(item) is not str for item in record.probe_argv)
            or record.probe_argv != spec.argv
            or type(record.expected_capabilities) is not tuple
            or any(
                not _capability_valid(capability, executable=spec.executable)
                for capability in record.expected_capabilities
            )
            or record.expected_capabilities != spec.expected_capabilities
            or type(record.minimum_supported_tool_version) is not str
            or record.minimum_supported_tool_version
            != ".".join(str(item) for item in spec.minimum_version)
            or type(record.maximum_supported_tool_version_exclusive) is not str
            or record.maximum_supported_tool_version_exclusive
            != ".".join(str(item) for item in spec.maximum_version_exclusive)
            or type(record.status) is not str
            or record.status not in _PROBE_STATUSES
        ):
            return False
        for count in (record.stdout_bytes, record.stderr_bytes):
            if type(count) is not int or not 0 <= count <= _PROBE_OUTPUT_LIMIT:
                return False
        if record.returncode is not None and (
            type(record.returncode) is not int or not -1024 <= record.returncode <= 1024
        ):
            return False
        if record.protocol_version is not None and (
            type(record.protocol_version) is not int or record.protocol_version != 1
        ):
            return False
        if (
            type(record.missing_machine_modes) is not tuple
            or len(record.missing_machine_modes) > _MAX_CAPABILITIES
            or any(
                type(item) is not str or _IDENTIFIER.fullmatch(item) is None
                for item in record.missing_machine_modes
            )
            or len(set(record.missing_machine_modes))
            != len(record.missing_machine_modes)
            or not set(record.missing_machine_modes).issubset(required_capabilities)
        ):
            return False
        if record.error is not None and (
            type(record.error) is not str or _IDENTIFIER.fullmatch(record.error) is None
        ):
            return False
        if record.status == "compatible" and (
            record.returncode != 0
            or record.protocol_version != 1
            or record.error is not None
            or record.missing_machine_modes
        ):
            return False
        if record.status == "unavailable" and (
            record.returncode is not None
            or record.protocol_version is not None
            or record.missing_machine_modes != required_capabilities
            or record.error
            != (
                "machine_contract_unavailable"
                if not spec.machine_contract_available
                else (
                    "executable_not_found"
                    if spec.optional
                    else "required_executable_not_found"
                )
            )
        ):
            return False
        if record.status == "quota" and (
            record.returncode != 75
            or record.protocol_version is not None
            or record.error != "probe_quota"
            or record.missing_machine_modes
        ):
            return False
        if record.status == "transient" and (
            record.protocol_version is not None
            or record.missing_machine_modes
            or (record.returncode, record.error)
            not in {(111, "probe_transient"), (None, "probe_timeout")}
        ):
            return False
        if record.status == "contract_error" and (
            record.protocol_version is not None or record.error is None
        ):
            return False
        return True
    except Exception:
        return False


def _connector_check(spec: ProbeSpec, record: ProbeRecord | None) -> DoctorCheck:
    check_id = f"connectors.{spec.tool}"
    if record is None:
        status = "warning" if spec.optional else "failure"
        return DoctorCheck(
            check_id, status, not spec.optional, "connector_probe_missing"
        )
    if not _probe_record_valid(record, spec):
        return DoctorCheck(
            check_id, "failure", not spec.optional, "connector_probe_malformed"
        )
    if record.status == "compatible":
        return DoctorCheck(check_id, "ok", not spec.optional, "connector_compatible")
    if record.status == "unavailable":
        status = "warning" if spec.optional else "failure"
        if record.error == "machine_contract_unavailable":
            code = "connector_machine_contract_unavailable"
        else:
            code = (
                "optional_connector_unavailable"
                if spec.optional
                else "required_connector_unavailable"
            )
        return DoctorCheck(check_id, status, not spec.optional, code)
    if record.status in {"quota", "transient"}:
        status = "warning" if spec.optional else "failure"
        return DoctorCheck(
            check_id, status, not spec.optional, "connector_probe_transient"
        )
    return DoctorCheck(
        check_id, "failure", not spec.optional, "connector_contract_error"
    )


def _connectors_section(
    connector_probe: ConnectorProbe | None,
    configured_connector_probe: ConfiguredConnectorProbe | None,
    config: RuntimeConfig | None,
    expected_specs: Sequence[ProbeSpec],
) -> DoctorSection:
    try:
        if (
            type(expected_specs) not in (tuple, list)
            or not 0 < len(expected_specs) <= 32
        ):
            raise TypeError
        specs = tuple(expected_specs)
        if any(not _probe_spec_valid(spec) for spec in specs) or len(
            {spec.tool for spec in specs}
        ) != len(specs):
            raise TypeError
    except Exception:
        return _section(
            "connectors",
            [
                DoctorCheck(
                    "connectors.probe", "failure", True, "connector_specs_invalid"
                )
            ],
        )
    records: Sequence[ProbeRecord] = ()
    malformed_set = False
    if connector_probe is not None and configured_connector_probe is not None:
        malformed_set = True
    elif connector_probe is not None:
        try:
            candidate = connector_probe()
            if type(candidate) not in (tuple, list) or len(candidate) > 32:
                raise TypeError
            records = candidate
        except Exception:
            malformed_set = True
    elif configured_connector_probe is not None:
        try:
            candidate = configured_connector_probe(config)
            if type(candidate) not in (tuple, list) or len(candidate) > 32:
                raise TypeError
            records = candidate
        except Exception:
            malformed_set = True
    by_tool: dict[str, ProbeRecord] = {}
    if not malformed_set:
        for record in records:
            if (
                type(record) is not ProbeRecord
                or type(record.tool) is not str
                or _IDENTIFIER.fullmatch(record.tool) is None
                or record.tool in by_tool
            ):
                malformed_set = True
                break
            by_tool[record.tool] = record
        if set(by_tool) - {spec.tool for spec in specs}:
            malformed_set = True
    if malformed_set:
        return _section(
            "connectors",
            [
                DoctorCheck(
                    "connectors.probe", "failure", True, "connector_probe_malformed"
                )
            ],
        )
    return _section(
        "connectors",
        [_connector_check(spec, by_tool.get(spec.tool)) for spec in specs],
    )


def run_doctor(
    *,
    repo_root: str | os.PathLike[str],
    runtime_home: str | os.PathLike[str],
    connector_probe: ConnectorProbe | None = None,
    configured_connector_probe: ConfiguredConnectorProbe | None = None,
    expected_specs: Sequence[ProbeSpec] = DEFAULT_SPECS,
) -> DoctorReport:
    """Inspect only explicit roots and return a bounded, redacted report."""

    repo, repo_stamp = _repo_section(repo_root)
    runtime, config, runtime_stamp = _runtime_section(runtime_home)
    vault, vault_stamp = _vault_section(config)
    connectors = _connectors_section(
        connector_probe,
        configured_connector_probe,
        config,
        expected_specs,
    )
    repo = _revalidate_repo_section(repo, repo_stamp)
    runtime = _revalidate_runtime_section(runtime, runtime_stamp)
    vault = _revalidate_vault_section(vault, config, vault_stamp)
    report = _report((repo, runtime, vault, connectors))
    validate_status(report.to_dict())
    return report


def _plain(value: object, label: str, *, pattern: re.Pattern[str]) -> str:
    if (
        not isinstance(value, str)
        or len(value) > 128
        or _has_control(value)
        or pattern.fullmatch(value) is None
    ):
        raise DoctorError(f"{label} is invalid")
    return value


def _canonical_bytes(payload: Mapping[str, object]) -> bytes:
    try:
        raw = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as error:
        raise DoctorError("status is not canonical JSON") from error
    if len(raw) > MAX_STATUS_BYTES:
        raise DoctorError("status is too large")
    return raw


def validate_status(payload: Mapping[str, object]) -> dict[str, object]:
    """Validate exact status schema, derived levels, counts, and ordering."""

    if not isinstance(payload, Mapping) or set(payload) != {
        "schema_version",
        "kind",
        "status",
        "summary",
        "sections",
    }:
        raise DoctorError("status has missing or unknown fields")
    if type(payload["schema_version"]) is not int or payload["schema_version"] != 1:
        raise DoctorError("unsupported status schema_version")
    if (
        payload["kind"] != STATUS_KIND
        or not isinstance(payload["status"], str)
        or payload["status"] not in _LEVELS
    ):
        raise DoctorError("status identity is invalid")
    summary = payload["summary"]
    if not isinstance(summary, Mapping) or set(summary) != {
        "warning_count",
        "failure_count",
    }:
        raise DoctorError("status summary is invalid")
    for value in summary.values():
        if type(value) is not int or value < 0:
            raise DoctorError("status summary count is invalid")
    sections = payload["sections"]
    if not isinstance(sections, list) or len(sections) != len(SECTION_ORDER):
        raise DoctorError("status sections are invalid")
    checked_sections: list[dict[str, object]] = []
    warning_count = 0
    failure_count = 0
    for expected_name, raw_section in zip(SECTION_ORDER, sections, strict=True):
        if not isinstance(raw_section, Mapping) or set(raw_section) != {
            "name",
            "status",
            "checks",
        }:
            raise DoctorError("status section has missing or unknown fields")
        if (
            raw_section["name"] != expected_name
            or not isinstance(raw_section["status"], str)
            or raw_section["status"] not in _LEVELS
        ):
            raise DoctorError("status section identity is invalid")
        raw_checks = raw_section["checks"]
        if (
            not isinstance(raw_checks, list)
            or not raw_checks
            or len(raw_checks) > MAX_CHECKS_PER_SECTION
        ):
            raise DoctorError("status section checks are invalid")
        checks: list[dict[str, object]] = []
        ids: list[str] = []
        for raw_check in raw_checks:
            if not isinstance(raw_check, Mapping) or set(raw_check) != {
                "id",
                "status",
                "required",
                "code",
                "ref",
            }:
                raise DoctorError("status check has missing or unknown fields")
            check_id = _plain(raw_check["id"], "check id", pattern=_IDENTIFIER)
            code = _plain(raw_check["code"], "check code", pattern=_IDENTIFIER)
            level = raw_check["status"]
            if (
                not isinstance(level, str)
                or level not in _LEVELS
                or type(raw_check["required"]) is not bool
            ):
                raise DoctorError("status check type is invalid")
            reference = raw_check["ref"]
            if reference is not None and (
                not isinstance(reference, str) or _HASH_REF.fullmatch(reference) is None
            ):
                raise DoctorError("status check reference is invalid")
            ids.append(check_id)
            warning_count += level == "warning"
            failure_count += level == "failure"
            checks.append(
                {
                    "id": check_id,
                    "status": level,
                    "required": raw_check["required"],
                    "code": code,
                    "ref": reference,
                }
            )
        if ids != sorted(ids) or len(ids) != len(set(ids)):
            raise DoctorError("status checks are not canonical")
        expected_level = (
            "failure"
            if any(c["status"] == "failure" for c in checks)
            else ("warning" if any(c["status"] == "warning" for c in checks) else "ok")
        )
        if raw_section["status"] != expected_level:
            raise DoctorError("status section level disagrees with checks")
        checked_sections.append(
            {"name": expected_name, "status": expected_level, "checks": checks}
        )
    if (
        summary["warning_count"] != warning_count
        or summary["failure_count"] != failure_count
    ):
        raise DoctorError("status summary disagrees with checks")
    expected_status = (
        "failure" if failure_count else "warning" if warning_count else "ok"
    )
    if payload["status"] != expected_status:
        raise DoctorError("status level disagrees with checks")
    checked = {
        "schema_version": 1,
        "kind": STATUS_KIND,
        "status": expected_status,
        "summary": {"warning_count": warning_count, "failure_count": failure_count},
        "sections": checked_sections,
    }
    _canonical_bytes(checked)
    return checked


def _no_duplicate_fields(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise DoctorError("status JSON has duplicate fields")
        result[key] = value
    return result


def load_status(text: str) -> dict[str, object]:
    if not isinstance(text, str):
        raise DoctorError("status JSON must be text")
    try:
        raw = text.encode("utf-8")
    except UnicodeError as error:
        raise DoctorError("status JSON is invalid") from error
    if len(raw) > MAX_STATUS_BYTES:
        raise DoctorError("status JSON is too large")
    try:
        payload = json.loads(text, object_pairs_hook=_no_duplicate_fields)
    except DoctorError:
        raise
    except (ValueError, UnicodeError, RecursionError) as error:
        raise DoctorError("status JSON is invalid") from error
    if not isinstance(payload, dict):
        raise DoctorError("status JSON must be an object")
    return validate_status(payload)


def render_status(report: DoctorReport | Mapping[str, object]) -> str:
    payload = report.to_dict() if isinstance(report, DoctorReport) else report
    checked = validate_status(payload)
    rendered = json.dumps(checked, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    if len(rendered.encode("utf-8")) > MAX_STATUS_BYTES:
        raise DoctorError("rendered status is too large")
    return rendered
