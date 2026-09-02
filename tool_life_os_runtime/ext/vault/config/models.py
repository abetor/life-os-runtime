"""Fail-closed schemas for runtime-home config and vault ``lifeos.toml``.

The models deliberately do not resolve secret values. A tool config contains
only environment variable names; the caller may pass the selected names to a
subprocess at the last possible boundary.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import tomllib
from typing import Callable, Mapping, TypeVar


class ConfigError(ValueError):
    """Configuration is invalid or unsafe to use."""


_NAME = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
_ENV_NAME = re.compile(r"^[A-Z_][A-Z0-9_]{0,127}$")
_FLOW_NAME = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
_SURFACES = frozenset({"silent", "batched", "gated"})
_ZONE_NAMES = frozenset(
    {"inbox", "review", "tasks", "projects", "knowledge", "memory", "runs", "outbox"}
)
_SAFE_LOCALE = "ru"
_SAFE_TIMEZONE = "UTC"
_T = TypeVar("_T")


@dataclass(frozen=True)
class VaultAlias:
    name: str
    path: Path


@dataclass(frozen=True)
class MachineKnowledgeConfig:
    topics_root: Path


@dataclass(frozen=True)
class MigrationRoot:
    name: str
    path: Path
    read_only: bool


@dataclass(frozen=True)
class ToolCommand:
    name: str
    argv: tuple[str, ...]
    cwd: Path | None
    env_names: tuple[str, ...]


@dataclass(frozen=True)
class RuntimeConfig:
    schema_version: int
    default_vault: str
    vaults: tuple[VaultAlias, ...]
    machine_knowledge: MachineKnowledgeConfig
    migration: tuple[MigrationRoot, ...]
    tools: tuple[ToolCommand, ...]

    def vault(self, alias: str) -> VaultAlias:
        for vault in self.vaults:
            if vault.name == alias:
                return vault
        raise ConfigError("unknown vault alias")


@dataclass(frozen=True)
class VaultConfig:
    schema_version: int
    locale: str
    timezone: str
    enabled_flows: tuple[str, ...]
    zones: tuple[tuple[str, PurePosixPath], ...]
    surface: str

    def zone(self, name: str) -> PurePosixPath:
        for zone_name, zone_path in self.zones:
            if zone_name == name:
                return zone_path
        raise ConfigError("unknown vault zone")


@dataclass(frozen=True)
class ResolvedValue:
    value: object
    source: str


def _read_toml(path: str | Path, *, label: str) -> dict[str, object]:
    read_failed = False
    try:
        data = tomllib.loads(Path(path).read_text("utf-8"))
    except (
        OSError,
        UnicodeError,
        tomllib.TOMLDecodeError,
        ValueError,
        RecursionError,
    ):
        read_failed = True
        data = {}
    if read_failed:
        raise ConfigError(f"cannot read {label}")
    if not isinstance(data, dict):  # pragma: no cover - guaranteed by tomllib
        raise ConfigError(f"invalid {label}")
    return data


def _exact_table(
    value: object,
    *,
    label: str,
    allowed: frozenset[str] | set[str],
    required: frozenset[str] | set[str] = frozenset(),
) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ConfigError(f"{label} must be a table")
    unknown = set(value) - set(allowed)
    if unknown:
        raise ConfigError(f"{label} has unknown fields: {', '.join(sorted(unknown))}")
    missing = set(required) - set(value)
    if missing:
        raise ConfigError(f"{label} misses required fields: {', '.join(sorted(missing))}")
    return value


def _dynamic_table(value: object, *, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ConfigError(f"{label} must be a table")
    return value


def _schema_one(value: object, *, label: str) -> int:
    if type(value) is not int or value != 1:
        raise ConfigError(f"{label} must equal 1")
    return value


def _string(value: object, *, label: str, max_length: int = 256) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > max_length
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ConfigError(f"{label} must be a non-empty bounded string")
    return value


def _name(value: object, *, label: str) -> str:
    text = _string(value, label=label, max_length=64)
    if not _NAME.fullmatch(text):
        raise ConfigError(f"{label} has invalid syntax")
    return text


def _absolute_path(value: object, *, label: str) -> Path:
    text = _string(value, label=label, max_length=4096)
    path = Path(text)
    if not path.is_absolute():
        raise ConfigError(f"{label} must be absolute")
    resolve_failed = False
    try:
        resolved = path.resolve(strict=False)
    except (OSError, RuntimeError):
        resolve_failed = True
        resolved = path
    if resolve_failed:
        raise ConfigError(f"{label} cannot be resolved")
    return resolved


def _paths_overlap(first: Path, second: Path) -> bool:
    return first == second or first in second.parents or second in first.parents


def _string_list(
    value: object,
    *,
    label: str,
    allow_empty: bool,
    item_max_length: int = 4096,
) -> tuple[str, ...]:
    if not isinstance(value, list) or (not allow_empty and not value):
        raise ConfigError(f"{label} must be an array of strings")
    result: list[str] = []
    for item in value:
        result.append(_string(item, label=label, max_length=item_max_length))
    return tuple(result)


def load_runtime_config(path: str | Path) -> RuntimeConfig:
    """Load runtime-home ``config.toml`` without reading process secrets."""

    raw = _exact_table(
        _read_toml(path, label="runtime config"),
        label="runtime config",
        allowed={"schema_version", "default_vault", "vaults", "machine_knowledge", "migration", "tools"},
        required={"schema_version", "default_vault", "vaults", "machine_knowledge", "migration"},
    )
    schema_version = _schema_one(raw["schema_version"], label="runtime schema_version")
    default_vault = _name(raw["default_vault"], label="default_vault")

    raw_vaults = _dynamic_table(raw["vaults"], label="vaults")
    if not raw_vaults:
        raise ConfigError("vaults must not be empty")
    vaults: list[VaultAlias] = []
    for alias, value in sorted(raw_vaults.items()):
        alias = _name(alias, label="vault alias")
        table = _exact_table(value, label=f"vaults.{alias}", allowed={"path"}, required={"path"})
        vaults.append(VaultAlias(alias, _absolute_path(table["path"], label=f"vaults.{alias}.path")))
    if default_vault not in {entry.name for entry in vaults}:
        raise ConfigError("default_vault does not name a configured vault")

    machine = _exact_table(
        raw["machine_knowledge"],
        label="machine_knowledge",
        allowed={"topics_root"},
        required={"topics_root"},
    )
    machine_knowledge = MachineKnowledgeConfig(
        _absolute_path(machine["topics_root"], label="machine_knowledge.topics_root")
    )

    raw_migration = _dynamic_table(raw["migration"], label="migration")
    migration: list[MigrationRoot] = []
    for root_name, value in sorted(raw_migration.items()):
        root_name = _name(root_name, label="migration root name")
        table = _exact_table(
            value,
            label=f"migration.{root_name}",
            allowed={"path", "read_only"},
            required={"path", "read_only"},
        )
        if table["read_only"] is not True:
            raise ConfigError(f"migration.{root_name}.read_only must be true")
        migration.append(
            MigrationRoot(
                root_name,
                _absolute_path(table["path"], label=f"migration.{root_name}.path"),
                True,
            )
        )

    tools: list[ToolCommand] = []
    raw_tools = _dynamic_table(raw.get("tools", {}), label="tools")
    for tool_name, value in sorted(raw_tools.items()):
        tool_name = _name(tool_name, label="tool name")
        table = _exact_table(
            value,
            label=f"tools.{tool_name}",
            allowed={"argv", "cwd", "env"},
            required={"argv"},
        )
        argv = _string_list(table["argv"], label=f"tools.{tool_name}.argv", allow_empty=False)
        if not argv[0].strip() or argv[0] != argv[0].strip():
            raise ConfigError(f"tools.{tool_name}.argv executable is invalid")
        cwd = None
        if "cwd" in table:
            cwd = _absolute_path(table["cwd"], label=f"tools.{tool_name}.cwd")
        env_names = _string_list(
            table.get("env", []), label=f"tools.{tool_name}.env", allow_empty=True, item_max_length=128
        )
        if len(set(env_names)) != len(env_names) or any(not _ENV_NAME.fullmatch(name) for name in env_names):
            raise ConfigError(f"tools.{tool_name}.env must contain unique environment names")
        tools.append(ToolCommand(tool_name, argv, cwd, env_names))

    protected_roots = tuple(entry.path for entry in migration)
    write_targets = (
        tuple(entry.path for entry in vaults)
        + (machine_knowledge.topics_root,)
        + tuple(tool.cwd for tool in tools if tool.cwd is not None)
    )
    for target in write_targets:
        if any(_paths_overlap(target, protected) for protected in protected_roots):
            raise ConfigError("a write target overlaps a read-only migration root")

    return RuntimeConfig(
        schema_version=schema_version,
        default_vault=default_vault,
        vaults=tuple(vaults),
        machine_knowledge=machine_knowledge,
        migration=tuple(migration),
        tools=tuple(tools),
    )


def _zone_path(value: object, *, label: str) -> PurePosixPath:
    text = _string(value, label=label, max_length=256)
    if "\\" in text:
        raise ConfigError(f"{label} must use portable separators")
    path = PurePosixPath(text)
    if path.is_absolute() or path == PurePosixPath(".") or ".." in path.parts:
        raise ConfigError(f"{label} must be a safe relative path")
    return path


def load_vault_config(path: str | Path) -> VaultConfig:
    """Load a portable vault ``lifeos.toml`` profile."""

    source = Path(path)
    if source.name != "lifeos.toml" and source.is_dir():
        source = source / "lifeos.toml"
    raw = _exact_table(
        _read_toml(source, label="vault config"),
        label="vault config",
        allowed={"schema_version", "locale", "timezone", "enabled_flows", "zones", "surface"},
        required={"schema_version", "zones", "surface"},
    )
    schema_version = _schema_one(raw["schema_version"], label="vault schema_version")
    locale = _string(raw.get("locale", _SAFE_LOCALE), label="locale", max_length=64)
    timezone = _string(raw.get("timezone", _SAFE_TIMEZONE), label="timezone", max_length=128)

    flows = _string_list(raw.get("enabled_flows", []), label="enabled_flows", allow_empty=True, item_max_length=64)
    if len(set(flows)) != len(flows) or any(not _FLOW_NAME.fullmatch(flow) for flow in flows):
        raise ConfigError("enabled_flows must contain unique flow names")

    zones_raw = _exact_table(raw["zones"], label="zones", allowed=_ZONE_NAMES, required=_ZONE_NAMES)
    zones = tuple(
        (name, _zone_path(zones_raw[name], label=f"zones.{name}")) for name in sorted(_ZONE_NAMES)
    )
    zone_paths = tuple(path for _, path in zones)
    for index, first in enumerate(zone_paths):
        for second in zone_paths[index + 1 :]:
            if first == second or first in second.parents or second in first.parents:
                raise ConfigError("vault zone paths must not overlap")

    surface_raw = _exact_table(raw["surface"], label="surface", allowed={"default"}, required={"default"})
    surface = _string(surface_raw["default"], label="surface.default", max_length=32)
    if surface not in _SURFACES:
        raise ConfigError("surface.default is unsupported")
    return VaultConfig(schema_version, locale, timezone, flows, zones, surface)


def resolve_precedence(
    *,
    cli: _T | None,
    profile: _T | None,
    env_name: str,
    environ: Mapping[str, str] | None,
    default: _T,
    parse_env: Callable[[str], _T] | None = None,
) -> ResolvedValue:
    """Resolve one value as CLI -> selected profile -> env -> safe default."""

    if not _ENV_NAME.fullmatch(env_name):
        raise ConfigError("environment name is invalid")
    if cli is not None:
        return ResolvedValue(cli, "cli")
    if profile is not None:
        return ResolvedValue(profile, "profile")
    source_env = os.environ if environ is None else environ
    if env_name in source_env:
        raw_value = source_env[env_name]
        if not isinstance(raw_value, str):
            raise ConfigError(f"environment value for {env_name} is invalid")
        parse_failed = False
        try:
            value = parse_env(raw_value) if parse_env else raw_value
        except Exception:
            parse_failed = True
            value = default
        if parse_failed:
            raise ConfigError(f"environment value for {env_name} is invalid")
        return ResolvedValue(value, "env")
    return ResolvedValue(default, "default")


def resolve_vault(
    config: RuntimeConfig,
    *,
    cli_alias: str | None = None,
    profile_alias: str | None = None,
    environ: Mapping[str, str] | None = None,
    env_name: str = "LIFE_OS_VAULT",
) -> VaultAlias:
    """Select a configured write vault while preserving fail-closed routing."""

    selected = resolve_precedence(
        cli=cli_alias,
        profile=profile_alias,
        env_name=env_name,
        environ=environ,
        default=config.default_vault,
    )
    if not isinstance(selected.value, str) or not _NAME.fullmatch(selected.value):
        raise ConfigError("selected vault alias is invalid")
    return config.vault(selected.value)


def _path_fingerprint(path: Path) -> str:
    return hashlib.sha256(os.fsencode(path)).hexdigest()[:16]


def render_redacted(config: RuntimeConfig) -> str:
    """Return deterministic JSON without paths, secret values, or env contents."""

    payload = {
        "schema_version": config.schema_version,
        "default_vault": config.default_vault,
        "vaults": [
            {"alias": vault.name, "path": f"sha256:{_path_fingerprint(vault.path)}"}
            for vault in config.vaults
        ],
        "machine_knowledge": {
            "topics_root": f"sha256:{_path_fingerprint(config.machine_knowledge.topics_root)}"
        },
        "migration": [
            {
                "name": root.name,
                "path": f"sha256:{_path_fingerprint(root.path)}",
                "read_only": root.read_only,
            }
            for root in config.migration
        ],
        "tools": [
            {
                "name": tool.name,
                "argv": ["<configured>"] * len(tool.argv),
                "cwd": None if tool.cwd is None else f"sha256:{_path_fingerprint(tool.cwd)}",
                "env_names": list(tool.env_names),
            }
            for tool in config.tools
        ],
    }
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
