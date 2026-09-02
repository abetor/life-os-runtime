"""P1 integration CLI for the portable Life OS runtime."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import threading
from typing import Callable, TypeVar
import unicodedata

from .ext.connectors.probes import DEFAULT_SPECS, ProbeRecord, probe_tool
from .ext.runs.store import RunError, RunStore
from .ext.skills import SkillInstallError, check, install, uninstall
from .ext.vault.config import (
    ConfigError,
    RuntimeConfig,
    VaultConfig,
    load_runtime_config,
    resolve_vault,
)
from .ext.vault.doctor import DoctorError, DoctorReport, render_status, run_doctor
from .ext.vault.migrate import (
    DEFAULT_VAULT_CONFIG,
    VaultMigrationError,
    init_vault,
    parse_vault_profile,
    scan_vault,
)
from .ext.vault.schema import VaultPathResolver, VaultSchemaError
from .shared.cliargs import ArgumentParser


EXIT_OK = 0
EXIT_QUOTA = 75
EXIT_TRANSIENT = 111
EXIT_FAIL = 1

DATA_ENV = "LIFE_OS_RUNTIME_DATA"
DATA_DIR = "life-os-runtime-data"
VAULT_ENV = "LIFE_OS_VAULT"
STATUS_SCHEMA_VERSION = 1
MAX_CONFIG_BYTES = 256 * 1024
MAX_OUTPUT_BYTES = 256 * 1024

_T = TypeVar("_T")


class CliError(ValueError):
    """A CLI input or local snapshot cannot be used safely."""


@dataclass(frozen=True)
class _RuntimeSnapshot:
    config: RuntimeConfig
    root_identity: tuple[int, int]
    file_identity: tuple[int, int, int, int, int]
    sha256: str


@dataclass(frozen=True)
class _ProfileSnapshot:
    profile: VaultConfig
    root_identity: tuple[int, int]
    file_identity: tuple[int, int, int, int, int]
    sha256: str


def resolve_home(cli_home: str | None = None) -> Path:
    """Resolve CLI -> tool env -> canonical tools-data without a cwd default."""

    raw = cli_home if cli_home is not None else os.environ.get(DATA_ENV)
    if raw is None:
        return Path.home() / "tools-data" / DATA_DIR
    if (
        not isinstance(raw, str)
        or not raw
        or any(
            unicodedata.category(character).startswith("C")
            or unicodedata.category(character) in {"Zl", "Zp"}
            for character in raw
        )
    ):
        raise CliError("runtime home is invalid")
    path = Path(raw)
    if not path.is_absolute():
        raise CliError("runtime home must be an absolute path")
    return path


def _directory_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )


def _identity(metadata: os.stat_result) -> tuple[int, int]:
    return metadata.st_dev, metadata.st_ino


def _file_snapshot_identity(
    metadata: os.stat_result,
) -> tuple[int, int, int, int, int]:
    if not stat.S_ISREG(metadata.st_mode):
        raise CliError("configuration must be a regular file")
    if metadata.st_size > MAX_CONFIG_BYTES:
        raise CliError("configuration is too large")
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _read_direct_snapshot(
    root: Path, name: str, *, maximum: int = MAX_CONFIG_BYTES
) -> tuple[bytes, tuple[int, int], tuple[int, int, int, int, int]]:
    """Read one direct child through a held no-follow directory descriptor."""

    if not root.is_absolute() or not name or "/" in name or "\\" in name:
        raise CliError("configuration location is invalid")
    root_fd = -1
    file_fd = -1
    try:
        root_fd = os.open(root, _directory_flags())
        root_opened = os.fstat(root_fd)
        root_named = os.stat(root, follow_symlinks=False)
        root_identity = _identity(root_opened)
        if not stat.S_ISDIR(root_opened.st_mode) or root_identity != _identity(
            root_named
        ):
            raise CliError("configuration root changed while opening")
        file_fd = os.open(
            name,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
            dir_fd=root_fd,
        )
        before = _file_snapshot_identity(os.fstat(file_fd))
        if before[2] > maximum:
            raise CliError("configuration is too large")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            block = os.read(file_fd, min(64 * 1024, remaining))
            if not block:
                break
            chunks.append(block)
            remaining -= len(block)
        raw = b"".join(chunks)
        if len(raw) > maximum:
            raise CliError("configuration is too large")
        after = _file_snapshot_identity(os.fstat(file_fd))
        named_after = _file_snapshot_identity(
            os.stat(name, dir_fd=root_fd, follow_symlinks=False)
        )
        root_after = os.stat(root, follow_symlinks=False)
        if (
            before != after
            or before != named_after
            or len(raw) != before[2]
            or root_identity != _identity(root_after)
        ):
            raise CliError("configuration changed while it was read")
        return raw, root_identity, before
    except CliError:
        raise
    except OSError as error:
        raise CliError("configuration cannot be read safely") from error
    finally:
        if file_fd >= 0:
            os.close(file_fd)
        if root_fd >= 0:
            os.close(root_fd)


def _parse_snapshot(raw: bytes, loader: Callable[[Path], _T]) -> _T:
    """Feed exact captured bytes into an existing canonical path parser."""

    read_fd, write_fd = os.pipe()
    alias: Path | None = None
    for candidate in (Path(f"/dev/fd/{read_fd}"), Path(f"/proc/self/fd/{read_fd}")):
        if candidate.exists():
            alias = candidate
            break
    if alias is None:
        os.close(read_fd)
        os.close(write_fd)
        raise CliError("bounded configuration parser is unavailable")
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

    feeder = threading.Thread(target=feed, name="lifeos-config-feed", daemon=True)
    try:
        feeder.start()
    except Exception as error:
        os.close(read_fd)
        os.close(write_fd)
        if feeder.is_alive():
            feeder.join(timeout=1.0)
        raise CliError("bounded configuration parser failed") from error
    try:
        try:
            value = loader(alias)
        except ConfigError:
            raise
        except (UnicodeError, ValueError, RecursionError) as error:
            raise CliError("configuration is invalid") from error
    finally:
        os.close(read_fd)
        feeder.join(timeout=1.0)
    if feeder.is_alive() or write_failed:
        raise CliError("bounded configuration parser failed")
    return value


def _runtime_snapshot(home: Path) -> _RuntimeSnapshot:
    raw, root_identity, file_identity = _read_direct_snapshot(home, "config.toml")
    config = _parse_snapshot(raw, load_runtime_config)
    snapshot = _RuntimeSnapshot(
        config,
        root_identity,
        file_identity,
        hashlib.sha256(raw).hexdigest(),
    )
    _revalidate_runtime(home, snapshot)
    return snapshot


def _load_runtime(home: Path) -> RuntimeConfig:
    return _runtime_snapshot(home).config


def _revalidate_runtime(home: Path, snapshot: _RuntimeSnapshot) -> None:
    raw, root_identity, file_identity = _read_direct_snapshot(home, "config.toml")
    if (
        root_identity != snapshot.root_identity
        or file_identity != snapshot.file_identity
        or hashlib.sha256(raw).hexdigest() != snapshot.sha256
    ):
        raise CliError("configuration changed while it was parsed")


def _load_profile(vault: Path) -> _ProfileSnapshot:
    raw, root_identity, file_identity = _read_direct_snapshot(
        vault, "lifeos.toml", maximum=64 * 1024
    )
    try:
        text = raw.decode("utf-8")
    except UnicodeError as error:
        raise CliError("vault profile is invalid") from error
    try:
        profile = parse_vault_profile(text)
    except (UnicodeError, ValueError, RecursionError) as error:
        raise CliError("vault profile is invalid") from error
    second, second_root, second_file = _read_direct_snapshot(
        vault, "lifeos.toml", maximum=64 * 1024
    )
    if second != raw or second_root != root_identity or second_file != file_identity:
        raise CliError("vault profile changed while it was parsed")
    return _ProfileSnapshot(
        profile,
        root_identity,
        file_identity,
        hashlib.sha256(raw).hexdigest(),
    )


def _revalidate_profile(vault: Path, snapshot: _ProfileSnapshot) -> None:
    raw, root_identity, file_identity = _read_direct_snapshot(
        vault, "lifeos.toml", maximum=64 * 1024
    )
    if (
        root_identity != snapshot.root_identity
        or file_identity != snapshot.file_identity
        or hashlib.sha256(raw).hexdigest() != snapshot.sha256
    ):
        raise CliError("vault profile changed while it was parsed")


def _canonical_json(payload: object) -> str:
    try:
        rendered = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError, RecursionError) as error:
        raise CliError("command result is not valid JSON") from error
    if len(rendered.encode("utf-8")) > MAX_OUTPUT_BYTES:
        raise CliError("command result is too large")
    return rendered


def _emit_json(payload: object) -> None:
    print(_canonical_json(payload))


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _probe_connectors(
    repo_root: Path, config: RuntimeConfig | None = None
) -> tuple[ProbeRecord, ...]:
    configured = {} if config is None else {tool.name: tool for tool in config.tools}
    supported = {spec.tool for spec in DEFAULT_SPECS}
    if set(configured) - supported:
        raise CliError("configured connector is unsupported")
    records: list[ProbeRecord] = []
    for spec in DEFAULT_SPECS:
        tool = configured.get(spec.tool)
        if tool is None and spec.machine_contract_available:
            continue
        cwd = repo_root if tool is None or tool.cwd is None else tool.cwd
        env = (
            {}
            if tool is None
            else {
                name: os.environ[name] for name in tool.env_names if name in os.environ
            }
        )
        records.append(
            probe_tool(
                spec,
                cwd=cwd,
                env=env,
                command=None if tool is None else tool.argv,
            )
        )
    return tuple(records)


def _doctor_report(home: Path) -> DoctorReport:
    repo = _repo_root()
    return run_doctor(
        repo_root=repo,
        runtime_home=home,
        configured_connector_probe=lambda config: _probe_connectors(repo, config),
    )


def _render_doctor(report: DoctorReport) -> str:
    lines = [f"lifeos doctor: {report.status}"]
    for section in report.sections:
        lines.append(f"  {section.name}: {section.status}")
        for item in section.checks:
            lines.append(f"    {item.id}: {item.status} ({item.code})")
    return "\n".join(lines)


def _manifest_root(
    home: Path, *, create: bool, expected_home_identity: tuple[int, int]
) -> tuple[Path, tuple[int, int]]:
    root_fd = -1
    install_fd = -1
    try:
        root_fd = os.open(home, _directory_flags())
        root_identity = _identity(os.fstat(root_fd))
        if root_identity != expected_home_identity or root_identity != _identity(
            os.stat(home, follow_symlinks=False)
        ):
            raise CliError("runtime home changed while opening install state")
        if create:
            try:
                os.mkdir("install", mode=0o700, dir_fd=root_fd)
                os.fsync(root_fd)
            except FileExistsError:
                pass
        install_fd = os.open("install", _directory_flags(), dir_fd=root_fd)
        install_identity = _identity(os.fstat(install_fd))
        if install_identity != _identity(
            os.stat("install", dir_fd=root_fd, follow_symlinks=False)
        ):
            raise CliError("skills manifest root changed while opening")
        if root_identity != _identity(os.stat(home, follow_symlinks=False)):
            raise CliError("runtime home changed while opening install state")
        return home / "install", install_identity
    except CliError:
        raise
    except OSError as error:
        raise CliError("skills manifest root is unavailable") from error
    finally:
        if install_fd >= 0:
            os.close(install_fd)
        if root_fd >= 0:
            os.close(root_fd)


def _directory_identity(path: Path, *, label: str) -> tuple[int, int]:
    descriptor = -1
    try:
        descriptor = os.open(path, _directory_flags())
        opened = os.fstat(descriptor)
        named = os.stat(path, follow_symlinks=False)
        identity = _identity(opened)
        if not stat.S_ISDIR(opened.st_mode) or identity != _identity(named):
            raise CliError(f"{label} changed while it was opened")
        return identity
    except CliError:
        raise
    except OSError as error:
        raise CliError(f"{label} is unavailable") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _selected_vault(config: RuntimeConfig, alias: str | None):
    return resolve_vault(
        config,
        cli_alias=alias,
        environ=os.environ,
        env_name=VAULT_ENV,
    )


def _command_init(home: Path, alias: str | None) -> int:
    runtime = _runtime_snapshot(home)
    vault = _selected_vault(runtime.config, alias)
    _revalidate_runtime(home, runtime)
    result = init_vault(
        vault.path,
        profile=DEFAULT_VAULT_CONFIG,
        read_only_roots=runtime.config.migration,
    )
    _revalidate_runtime(home, runtime)
    _emit_json(
        {
            "schema_version": STATUS_SCHEMA_VERSION,
            "kind": "vault-init",
            **asdict(result),
        }
    )
    return EXIT_OK


def _command_scan(home: Path, alias: str | None) -> int:
    runtime = _runtime_snapshot(home)
    vault = _selected_vault(runtime.config, alias)
    _revalidate_runtime(home, runtime)
    scan = scan_vault(vault.path)
    _revalidate_runtime(home, runtime)
    _emit_json(
        {
            "schema_version": STATUS_SCHEMA_VERSION,
            "kind": "vault-scan",
            **scan.summary_dict(),
        }
    )
    return EXIT_OK


def _command_doctor(home: Path, *, machine: bool) -> int:
    report = _doctor_report(home)
    if machine:
        rendered = render_status(report)
        if len(rendered.encode("utf-8")) > MAX_OUTPUT_BYTES:
            raise CliError("doctor result is too large")
        print(rendered, end="" if rendered.endswith("\n") else "\n")
    else:
        print(_render_doctor(report))
    return EXIT_FAIL if report.status == "failure" else EXIT_OK


def _command_run_status(home: Path, alias: str | None, run_id: str) -> int:
    runtime = _runtime_snapshot(home)
    vault = _selected_vault(runtime.config, alias)
    profile = _load_profile(vault.path)
    _revalidate_runtime(home, runtime)
    _revalidate_profile(vault.path, profile)
    resolver = VaultPathResolver(
        vault.path,
        profile.profile,
        read_only_roots=runtime.config.migration,
    )
    state = RunStore(resolver).status(run_id)
    _revalidate_profile(vault.path, profile)
    _revalidate_runtime(home, runtime)
    _emit_json(state)
    return EXIT_OK


def _command_skills(home: Path, alias: str | None, operation: str) -> int:
    runtime = _runtime_snapshot(home)
    vault = _selected_vault(runtime.config, alias)
    profile = _load_profile(vault.path)
    target_identity = _directory_identity(vault.path, label="vault root")
    if target_identity != profile.root_identity:
        raise CliError("vault root changed before skills operation")
    resolver = VaultPathResolver(
        vault.path,
        profile.profile,
        read_only_roots=runtime.config.migration,
    )
    resolver.validate().require_valid()
    _revalidate_runtime(home, runtime)
    _revalidate_profile(vault.path, profile)
    manifests, manifest_identity = _manifest_root(
        home,
        create=operation == "install",
        expected_home_identity=runtime.root_identity,
    )
    _revalidate_runtime(home, runtime)
    _revalidate_profile(vault.path, profile)
    if operation == "install":
        result = install(
            vault.path,
            manifests,
            expected_target_identity=target_identity,
            expected_manifest_identity=manifest_identity,
            expected_manifest_parent_identity=runtime.root_identity,
        )
        payload = {
            "schema_version": STATUS_SCHEMA_VERSION,
            "kind": "skills-install",
            **asdict(result),
        }
        code = EXIT_OK
    elif operation == "check":
        result = check(
            vault.path,
            manifests,
            expected_target_identity=target_identity,
            expected_manifest_identity=manifest_identity,
            expected_manifest_parent_identity=runtime.root_identity,
        )
        payload = {
            "schema_version": STATUS_SCHEMA_VERSION,
            "kind": "skills-check",
            **asdict(result),
        }
        code = EXIT_OK if result.ok else EXIT_FAIL
    elif operation == "uninstall":
        result = uninstall(
            vault.path,
            manifests,
            expected_target_identity=target_identity,
            expected_manifest_identity=manifest_identity,
            expected_manifest_parent_identity=runtime.root_identity,
        )
        payload = {
            "schema_version": STATUS_SCHEMA_VERSION,
            "kind": "skills-uninstall",
            **asdict(result),
        }
        code = EXIT_OK
    else:  # pragma: no cover - argparse keeps this unreachable
        raise CliError("unknown skills operation")
    _revalidate_profile(vault.path, profile)
    _revalidate_runtime(home, runtime)
    _emit_json(payload)
    return code


def _parser() -> ArgumentParser:
    parser = ArgumentParser(
        prog="lifeos",
        description="Portable runtime for a file-based personal Life OS",
    )
    parser.add_argument(
        "--home",
        help=f"absolute runtime-home; overrides {DATA_ENV}",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    init_parser = commands.add_parser(
        "init", help="initialize a configured empty vault"
    )
    init_parser.add_argument("--vault", metavar="ALIAS")

    scan_parser = commands.add_parser("scan", help="scan a configured vault read-only")
    scan_parser.add_argument("--vault", metavar="ALIAS")

    commands.add_parser("doctor", help="render read-only diagnostics")
    status_parser = commands.add_parser("status", help="render machine diagnostics")
    status_parser.add_argument("--json", action="store_true", required=True)

    run_parser = commands.add_parser("run-status", help="read authoritative run state")
    run_parser.add_argument("run_id")
    run_parser.add_argument("--vault", metavar="ALIAS")

    skills_parser = commands.add_parser(
        "skills", help="manage generated skill wrappers"
    )
    skill_commands = skills_parser.add_subparsers(
        dest="skills_operation", required=True
    )
    for operation in ("install", "check", "uninstall"):
        operation_parser = skill_commands.add_parser(operation)
        operation_parser.add_argument("--vault", metavar="ALIAS")
    return parser


def _error_text(error: Exception) -> str:
    """Render only integrator-owned text; parser inputs never reach stderr."""

    if isinstance(error, CliError):
        return str(error)
    if isinstance(error, ConfigError):
        return "runtime configuration is invalid"
    if isinstance(error, DoctorError):
        return "diagnostics failed"
    if isinstance(error, RunError):
        return "run state is unavailable"
    if isinstance(error, SkillInstallError):
        return "skills operation failed"
    if isinstance(error, VaultMigrationError):
        return "vault operation failed"
    if isinstance(error, VaultSchemaError):
        return "vault schema is invalid"
    return "operation failed"


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        home = resolve_home(args.home)
        if args.command == "init":
            return _command_init(home, args.vault)
        if args.command == "scan":
            return _command_scan(home, args.vault)
        if args.command == "doctor":
            return _command_doctor(home, machine=False)
        if args.command == "status":
            return _command_doctor(home, machine=True)
        if args.command == "run-status":
            return _command_run_status(home, args.vault, args.run_id)
        if args.command == "skills":
            return _command_skills(home, args.vault, args.skills_operation)
        raise CliError("unknown command")
    except (
        CliError,
        ConfigError,
        DoctorError,
        RunError,
        SkillInstallError,
        VaultMigrationError,
        VaultSchemaError,
    ) as error:
        print(f"lifeos: {_error_text(error)}", file=sys.stderr)
        return EXIT_FAIL


if __name__ == "__main__":
    sys.exit(main())
