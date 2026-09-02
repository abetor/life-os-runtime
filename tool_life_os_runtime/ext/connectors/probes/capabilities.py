"""Fail-closed, read-only capability probes for neighboring CLI tools.

Each neighbor may expose ``capabilities --json``, but its response is only a
claim. Runtime owns the expected contracts below and accepts the response only
when it matches them exactly. Probe output is bounded and never copied into the
returned record.
"""

from __future__ import annotations

import json
import os
import shutil
import signal
import stat
import subprocess
import threading
import time
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, BinaryIO, Mapping, Sequence

PROBE_SCHEMA_VERSION = 1
MAX_PROBE_OUTPUT_BYTES = 64 * 1024
MAX_SEMVER_COMPONENT_DIGITS = 9
_PROCESS_CLEANUP_SECONDS = 0.25
_MAX_COMMAND_ITEMS = 32
_MAX_COMMAND_ITEM_BYTES = 4096
_MAX_COMMAND_BYTES = 16 * 1024

_STATUS_COMPATIBLE = "compatible"
_STATUS_UNAVAILABLE = "unavailable"
_STATUS_QUOTA = "quota"
_STATUS_TRANSIENT = "transient"
_STATUS_CONTRACT_ERROR = "contract_error"


@dataclass(frozen=True)
class MachineOutputContract:
    format: str
    schema_version: int
    required_fields: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "format": self.format,
            "schema_version": self.schema_version,
            "required_fields": list(self.required_fields),
        }


@dataclass(frozen=True)
class CapabilityContract:
    """Integrator-owned contract for one neighboring operation."""

    name: str
    argv: tuple[str, ...]
    machine_output: MachineOutputContract
    exit_codes: tuple[tuple[int, str], ...]
    idempotency: str

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "argv": list(self.argv),
            "machine_output": self.machine_output.to_dict(),
            "exit_codes": {str(code): outcome for code, outcome in self.exit_codes},
            "idempotency": self.idempotency,
        }


@dataclass(frozen=True)
class ProbeSpec:
    tool: str
    executable: str
    expected_capabilities: tuple[CapabilityContract, ...]
    minimum_version: tuple[int, int, int] = (0, 1, 0)
    maximum_version_exclusive: tuple[int, int, int] = (0, 2, 0)
    optional: bool = True
    machine_contract_available: bool = True

    @property
    def argv(self) -> tuple[str, ...]:
        if not self.machine_contract_available:
            return ()
        return (self.executable, "capabilities", "--json")

    @property
    def required_capabilities(self) -> tuple[str, ...]:
        return tuple(capability.name for capability in self.expected_capabilities)


def _machine_output(*required_fields: str) -> MachineOutputContract:
    return MachineOutputContract("json", 1, tuple(required_fields))


def _capability(
    name: str,
    argv: tuple[str, ...],
    required_fields: tuple[str, ...],
    exit_codes: tuple[tuple[int, str], ...],
    idempotency: str,
) -> CapabilityContract:
    return CapabilityContract(
        name=name,
        argv=argv,
        machine_output=_machine_output(*required_fields),
        exit_codes=exit_codes,
        idempotency=idempotency,
    )


_LOCAL_EXITS = ((0, "success"), (1, "failure"))
_REMOTE_EXITS = _LOCAL_EXITS + ((75, "quota"), (111, "transient"))
_RESEARCH_START_EXITS = _REMOTE_EXITS + ((76, "waiting_human"),)
_GATEWAY_EXITS = _LOCAL_EXITS + ((111, "transient"),)


DEFAULT_SPECS: tuple[ProbeSpec, ...] = (
    ProbeSpec(
        tool="researcher",
        executable="research",
        expected_capabilities=(
            _capability(
                "start",
                ("research", "start", "<topic>", "--base", "<topics-root>", "--json"),
                ("schema_version", "status", "topic_dir"),
                _RESEARCH_START_EXITS,
                "deduplicated",
            ),
            _capability(
                "status",
                ("research", "status", "<topic-dir>"),
                ("schema_version", "status", "phase"),
                _LOCAL_EXITS,
                "read-only",
            ),
            _capability(
                "resume",
                ("research", "resume", "<topic-dir>", "--json"),
                ("schema_version", "status", "topic_dir"),
                _RESEARCH_START_EXITS,
                "idempotent",
            ),
            _capability(
                "extend",
                ("research", "extend", "<topic-dir>", "--json"),
                ("schema_version", "status", "topic_dir"),
                _RESEARCH_START_EXITS,
                "deduplicated",
            ),
            _capability(
                "doctor",
                ("research", "doctor", "--json"),
                ("schema_version", "status", "checks"),
                _LOCAL_EXITS,
                "read-only",
            ),
        ),
    ),
    ProbeSpec(
        tool="llm-wiki",
        executable="llmwiki",
        expected_capabilities=(),
        machine_contract_available=False,
    ),
    ProbeSpec(
        tool="coursedump",
        executable="coursedump",
        expected_capabilities=(
            _capability(
                "plan",
                ("coursedump", "plan", "<source>", "--data", "<data-home>", "--json"),
                ("schema_version", "source", "items", "estimate"),
                _REMOTE_EXITS,
                "read-only",
            ),
            _capability(
                "run",
                ("coursedump", "run", "<source>", "--data", "<data-home>", "--json"),
                ("schema_version", "status", "artifact"),
                _REMOTE_EXITS,
                "idempotent",
            ),
            _capability(
                "status",
                ("coursedump", "status", "--data", "<data-home>", "--json"),
                ("schema_version", "runs"),
                _LOCAL_EXITS,
                "read-only",
            ),
        ),
    ),
    ProbeSpec(
        tool="scheduler",
        executable="tool-scheduler",
        expected_capabilities=(
            _capability(
                "list",
                ("tool-scheduler", "--home", "<home>", "list", "--json"),
                ("schema_version", "jobs"),
                _LOCAL_EXITS,
                "read-only",
            ),
            _capability(
                "doctor",
                ("tool-scheduler", "--home", "<home>", "doctor", "--json"),
                ("schema_version", "status", "problems"),
                _LOCAL_EXITS,
                "read-only",
            ),
            _capability(
                "job-schema",
                ("tool-scheduler", "job-schema", "--json"),
                ("schema_version", "job_schema"),
                _LOCAL_EXITS,
                "read-only",
            ),
        ),
    ),
    ProbeSpec(
        tool="gateway",
        executable="tool-gateway",
        expected_capabilities=(
            _capability(
                "dispatch-event",
                ("tool-gateway", "--home", "<home>", "dispatch-event", "--json"),
                ("schema_version", "event_id", "status", "receipt"),
                _GATEWAY_EXITS,
                "deduplicated",
            ),
            _capability(
                "delivery-receipt",
                ("tool-gateway", "--home", "<home>", "receipt", "<event-id>", "--json"),
                ("schema_version", "event_id", "status", "dedupe_key"),
                _LOCAL_EXITS,
                "read-only",
            ),
        ),
    ),
)


@dataclass(frozen=True)
class ProbeRecord:
    """Bounded record containing only integrator-owned or numeric fields."""

    tool: str
    status: str
    optional: bool
    probe_argv: tuple[str, ...]
    minimum_supported_tool_version: str
    maximum_supported_tool_version_exclusive: str
    expected_capabilities: tuple[CapabilityContract, ...]
    returncode: int | None = None
    protocol_version: int | None = None
    missing_machine_modes: tuple[str, ...] = ()
    error: str | None = None
    stdout_bytes: int = 0
    stderr_bytes: int = 0

    def to_dict(self) -> dict[str, object]:
        return {
            "tool": self.tool,
            "status": self.status,
            "optional": self.optional,
            "probe_argv": list(self.probe_argv),
            "supported_tool_versions": {
                "minimum_inclusive": self.minimum_supported_tool_version,
                "maximum_exclusive": self.maximum_supported_tool_version_exclusive,
            },
            "returncode": self.returncode,
            "protocol_version": self.protocol_version,
            "expected_capabilities": [
                capability.to_dict() for capability in self.expected_capabilities
            ],
            "missing_machine_modes": list(self.missing_machine_modes),
            "error": self.error,
            "stdout_bytes": self.stdout_bytes,
            "stderr_bytes": self.stderr_bytes,
        }


class _ContractViolation(ValueError):
    pass


def _object_no_duplicates(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise _ContractViolation("duplicate_machine_output_field")
        value[key] = item
    return value


@dataclass
class _BoundedCapture:
    data: bytearray = field(default_factory=bytearray)
    size: int = 0

    def drain(self, stream: BinaryIO) -> None:
        try:
            while chunk := stream.read(8192):
                self.size = min(MAX_PROBE_OUTPUT_BYTES + 1, self.size + len(chunk))
                room = MAX_PROBE_OUTPUT_BYTES + 1 - len(self.data)
                if room > 0:
                    self.data.extend(chunk[:room])
        except (OSError, ValueError):
            # The owner may close a still-blocked pipe after the bounded cleanup
            # window. Captured bytes remain usable; diagnostics are never emitted.
            pass
        finally:
            try:
                stream.close()
            except (OSError, ValueError):
                pass


@dataclass(frozen=True)
class _ProcessOutput:
    returncode: int
    stdout: bytes
    stdout_bytes: int
    stderr_bytes: int
    timed_out: bool


@dataclass(frozen=True)
class _ConfiguredTarget:
    cwd: Path
    cwd_identity: tuple[int, int]
    executable: Path
    executable_identity: tuple[int, int, int, int, int]


def probe_tool(
    spec: ProbeSpec,
    *,
    cwd: Path,
    env: Mapping[str, str],
    timeout: float = 5.0,
    command: Sequence[str] | None = None,
) -> ProbeRecord:
    """Probe one tool without stdin, shell expansion, or configured-home writes."""

    cwd = Path(cwd)
    try:
        command_prefix = _command_prefix(command, spec)
    except _ContractViolation:
        return _result(
            spec,
            _STATUS_CONTRACT_ERROR,
            error="configured_command_invalid",
            missing_machine_modes=spec.required_capabilities,
        )

    if not spec.machine_contract_available:
        return _result(
            spec,
            _STATUS_UNAVAILABLE,
            error="machine_contract_unavailable",
        )

    target: _ConfiguredTarget | None = None
    if command is None:
        if not cwd.is_dir():
            return _result(
                spec,
                _STATUS_CONTRACT_ERROR,
                error="probe_cwd_not_directory",
            )
        executable_available = _executable_available(
            command_prefix[0], cwd=cwd, env=env
        )
    else:
        try:
            target = _configured_target(command_prefix[0], cwd=cwd, env=env)
        except _ContractViolation as error:
            return _result(
                spec,
                _STATUS_CONTRACT_ERROR,
                error=str(error),
                missing_machine_modes=spec.required_capabilities,
            )
        executable_available = target is not None
        if target is not None:
            command_prefix = (os.fspath(target.executable), *command_prefix[1:])

    if not executable_available:
        status = _STATUS_UNAVAILABLE if spec.optional else _STATUS_CONTRACT_ERROR
        error = (
            "executable_not_found" if spec.optional else "required_executable_not_found"
        )
        return _result(
            spec,
            status,
            error=error,
            missing_machine_modes=spec.required_capabilities,
        )

    try:
        process_output = _run_bounded(
            [*command_prefix, "capabilities", "--json"],
            cwd=cwd,
            env=env,
            timeout=timeout,
        )
    except (OSError, TypeError):
        if target is not None and not _configured_target_stable(target):
            return _result(
                spec,
                _STATUS_CONTRACT_ERROR,
                error="configured_target_changed",
                missing_machine_modes=spec.required_capabilities,
            )
        return _result(spec, _STATUS_CONTRACT_ERROR, error="probe_execution_failed")

    if target is not None and not _configured_target_stable(target):
        return _result(
            spec,
            _STATUS_CONTRACT_ERROR,
            returncode=process_output.returncode,
            error="configured_target_changed",
            missing_machine_modes=spec.required_capabilities,
            stdout_bytes=process_output.stdout_bytes,
            stderr_bytes=process_output.stderr_bytes,
        )

    if process_output.timed_out:
        return _result(
            spec,
            _STATUS_TRANSIENT,
            error="probe_timeout",
            stdout_bytes=process_output.stdout_bytes,
            stderr_bytes=process_output.stderr_bytes,
        )
    if process_output.returncode == 75:
        return _result(
            spec,
            _STATUS_QUOTA,
            returncode=75,
            error="probe_quota",
            stdout_bytes=process_output.stdout_bytes,
            stderr_bytes=process_output.stderr_bytes,
        )
    if process_output.returncode == 111:
        return _result(
            spec,
            _STATUS_TRANSIENT,
            returncode=111,
            error="probe_transient",
            stdout_bytes=process_output.stdout_bytes,
            stderr_bytes=process_output.stderr_bytes,
        )
    if (
        process_output.stdout_bytes > MAX_PROBE_OUTPUT_BYTES
        or process_output.stderr_bytes > MAX_PROBE_OUTPUT_BYTES
    ):
        return _result(
            spec,
            _STATUS_CONTRACT_ERROR,
            returncode=process_output.returncode,
            error="probe_output_too_large",
            missing_machine_modes=spec.required_capabilities,
            stdout_bytes=process_output.stdout_bytes,
            stderr_bytes=process_output.stderr_bytes,
        )
    if process_output.returncode != 0:
        return _result(
            spec,
            _STATUS_CONTRACT_ERROR,
            returncode=process_output.returncode,
            error="machine_probe_nonzero_exit",
            missing_machine_modes=spec.required_capabilities,
            stdout_bytes=process_output.stdout_bytes,
            stderr_bytes=process_output.stderr_bytes,
        )

    try:
        stdout = process_output.stdout.decode("utf-8", errors="strict")
        payload = json.loads(stdout, object_pairs_hook=_object_no_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError, _ContractViolation):
        return _result(
            spec,
            _STATUS_CONTRACT_ERROR,
            returncode=0,
            error="invalid_machine_output",
            missing_machine_modes=spec.required_capabilities,
            stdout_bytes=process_output.stdout_bytes,
            stderr_bytes=process_output.stderr_bytes,
        )

    missing_modes = _missing_required_modes(payload, spec)
    try:
        _validate_exact_payload(payload, spec)
    except _ContractViolation as error:
        return _result(
            spec,
            _STATUS_CONTRACT_ERROR,
            returncode=0,
            error=str(error),
            missing_machine_modes=missing_modes,
            stdout_bytes=process_output.stdout_bytes,
            stderr_bytes=process_output.stderr_bytes,
        )

    return _result(
        spec,
        _STATUS_COMPATIBLE,
        returncode=0,
        protocol_version=PROBE_SCHEMA_VERSION,
        stdout_bytes=process_output.stdout_bytes,
        stderr_bytes=process_output.stderr_bytes,
    )


def probe_all(
    *,
    cwd: Path,
    env: Mapping[str, str],
    specs: Sequence[ProbeSpec] = DEFAULT_SPECS,
    timeout: float = 5.0,
) -> tuple[ProbeRecord, ...]:
    return tuple(probe_tool(spec, cwd=cwd, env=env, timeout=timeout) for spec in specs)


def _command_prefix(command: Sequence[str] | None, spec: ProbeSpec) -> tuple[str, ...]:
    candidate: object = (spec.executable,) if command is None else command
    if (
        type(candidate) not in {tuple, list}
        or not 0 < len(candidate) <= _MAX_COMMAND_ITEMS
    ):
        raise _ContractViolation("configured_command_invalid")
    checked: list[str] = []
    total = 0
    for item in candidate:
        if type(item) is not str or not item:
            raise _ContractViolation("configured_command_invalid")
        try:
            size = len(item.encode("utf-8"))
        except UnicodeError as error:
            raise _ContractViolation("configured_command_invalid") from error
        if (
            size > _MAX_COMMAND_ITEM_BYTES
            or item != unicodedata.normalize("NFC", item)
            or any(
                unicodedata.category(character).startswith("C")
                or unicodedata.category(character) in {"Zl", "Zp"}
                for character in item
            )
        ):
            raise _ContractViolation("configured_command_invalid")
        total += size
        checked.append(item)
    if total > _MAX_COMMAND_BYTES:
        raise _ContractViolation("configured_command_invalid")
    return tuple(checked)


def _executable_available(
    executable: str, *, cwd: Path, env: Mapping[str, str]
) -> bool:
    if "/" not in executable:
        return shutil.which(executable, path=env.get("PATH", "")) is not None
    candidate = Path(executable)
    if not candidate.is_absolute():
        candidate = cwd / candidate
    try:
        return candidate.is_file() and os.access(candidate, os.X_OK)
    except OSError:
        return False


def _directory_identity(path: Path) -> tuple[int, int]:
    try:
        metadata = os.stat(path, follow_symlinks=False)
    except OSError as error:
        raise _ContractViolation("probe_cwd_not_directory") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise _ContractViolation("configured_cwd_unsafe")
    return metadata.st_dev, metadata.st_ino


def _executable_identity(path: Path) -> tuple[int, int, int, int, int]:
    try:
        metadata = os.stat(path, follow_symlinks=False)
    except OSError as error:
        raise _ContractViolation("configured_executable_unavailable") from error
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_mode & 0o111 == 0
        or not os.access(path, os.X_OK)
    ):
        raise _ContractViolation("configured_executable_unsafe")
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _configured_target(
    executable: str, *, cwd: Path, env: Mapping[str, str]
) -> _ConfiguredTarget | None:
    if not cwd.is_absolute() or ".." in cwd.parts:
        raise _ContractViolation("configured_cwd_unsafe")
    cwd_identity = _directory_identity(cwd)
    if "/" in executable:
        executable_path = Path(executable)
        if not executable_path.is_absolute() or ".." in executable_path.parts:
            raise _ContractViolation("configured_executable_unsafe")
    else:
        located = shutil.which(executable, path=env.get("PATH", ""))
        if located is None:
            return None
        executable_path = Path(located)
        if not executable_path.is_absolute():
            raise _ContractViolation("configured_executable_unsafe")
    try:
        executable_identity = _executable_identity(executable_path)
    except _ContractViolation as error:
        if str(error) == "configured_executable_unavailable":
            return None
        raise
    return _ConfiguredTarget(
        cwd,
        cwd_identity,
        executable_path,
        executable_identity,
    )


def _configured_target_stable(target: _ConfiguredTarget) -> bool:
    try:
        return (
            _directory_identity(target.cwd) == target.cwd_identity
            and _executable_identity(target.executable) == target.executable_identity
        )
    except _ContractViolation:
        return False


def _result(
    spec: ProbeSpec,
    status: str,
    *,
    returncode: int | None = None,
    protocol_version: int | None = None,
    missing_machine_modes: tuple[str, ...] = (),
    error: str | None = None,
    stdout_bytes: int = 0,
    stderr_bytes: int = 0,
) -> ProbeRecord:
    return ProbeRecord(
        tool=spec.tool,
        status=status,
        optional=spec.optional,
        probe_argv=spec.argv,
        minimum_supported_tool_version=_format_version(spec.minimum_version),
        maximum_supported_tool_version_exclusive=_format_version(
            spec.maximum_version_exclusive
        ),
        expected_capabilities=spec.expected_capabilities,
        returncode=returncode,
        protocol_version=protocol_version,
        missing_machine_modes=missing_machine_modes,
        error=error,
        stdout_bytes=stdout_bytes,
        stderr_bytes=stderr_bytes,
    )


def _validate_exact_payload(payload: Any, spec: ProbeSpec) -> None:
    if not isinstance(payload, dict) or set(payload) != {
        "schema_version",
        "tool",
        "version",
        "capabilities",
    }:
        raise _ContractViolation("invalid_machine_output")
    if (
        type(payload["schema_version"]) is not int
        or payload["schema_version"] != PROBE_SCHEMA_VERSION
    ):
        raise _ContractViolation("unsupported_probe_schema")
    if payload["tool"] != spec.tool:
        raise _ContractViolation("tool_identity_mismatch")

    tool_version = payload["version"]
    if not isinstance(tool_version, str):
        raise _ContractViolation("invalid_machine_output")
    parsed_version = _semantic_version(tool_version)
    if not spec.minimum_version <= parsed_version < spec.maximum_version_exclusive:
        raise _ContractViolation("unsupported_tool_version")

    expected = [capability.to_dict() for capability in spec.expected_capabilities]
    if not _strict_equal(payload["capabilities"], expected):
        raise _ContractViolation("capability_contract_mismatch")


def _missing_required_modes(payload: Any, spec: ProbeSpec) -> tuple[str, ...]:
    if not isinstance(payload, dict) or not isinstance(
        payload.get("capabilities"), list
    ):
        return spec.required_capabilities
    claimed: set[str] = set()
    expected = set(spec.required_capabilities)
    for capability in payload["capabilities"]:
        if not isinstance(capability, dict):
            continue
        name = capability.get("name")
        if isinstance(name, str) and name in expected:
            claimed.add(name)
    return tuple(name for name in spec.required_capabilities if name not in claimed)


def _semantic_version(value: str) -> tuple[int, int, int]:
    parts = value.split(".")
    if len(parts) != 3 or any(
        not part.isascii()
        or not part.isdigit()
        or len(part) > MAX_SEMVER_COMPONENT_DIGITS
        for part in parts
    ):
        raise _ContractViolation("invalid_machine_output")
    return int(parts[0]), int(parts[1]), int(parts[2])


def _format_version(value: tuple[int, int, int]) -> str:
    return ".".join(str(part) for part in value)


def _strict_equal(value: Any, expected: Any) -> bool:
    if type(value) is not type(expected):
        return False
    if isinstance(expected, dict):
        return set(value) == set(expected) and all(
            _strict_equal(value[key], expected[key]) for key in expected
        )
    if isinstance(expected, list):
        return len(value) == len(expected) and all(
            _strict_equal(item, expected_item)
            for item, expected_item in zip(value, expected, strict=True)
        )
    return value == expected


def _run_bounded(
    argv: list[str],
    *,
    cwd: Path,
    env: Mapping[str, str],
    timeout: float,
) -> _ProcessOutput:
    deadline = time.monotonic() + max(timeout, 0.0)
    process = subprocess.Popen(
        argv,
        cwd=cwd,
        env=dict(env),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        start_new_session=True,
    )
    if process.stdout is None or process.stderr is None:  # pragma: no cover
        _kill_process_group(process)
        _bounded_wait(process, time.monotonic() + _PROCESS_CLEANUP_SECONDS)
        raise OSError("subprocess pipes unavailable")

    stdout = _BoundedCapture()
    stderr = _BoundedCapture()
    readers = (
        threading.Thread(target=stdout.drain, args=(process.stdout,), daemon=True),
        threading.Thread(target=stderr.drain, args=(process.stderr,), daemon=True),
    )
    started_readers: list[threading.Thread] = []
    try:
        for reader in readers:
            reader.start()
            started_readers.append(reader)
    except Exception as error:
        _kill_process_group(process)
        cleanup_deadline = time.monotonic() + _PROCESS_CLEANUP_SECONDS
        _bounded_wait(process, cleanup_deadline)
        for stream in (process.stdout, process.stderr):
            _close_pipe(stream)
        for reader in started_readers:
            reader.join(timeout=_remaining(cleanup_deadline))
        raise OSError("probe reader setup failed") from error

    timed_out = False
    try:
        returncode = process.wait(timeout=_remaining(deadline))
    except subprocess.TimeoutExpired:
        timed_out = True
        _kill_process_group(process)
        returncode = _bounded_wait(process, time.monotonic() + _PROCESS_CLEANUP_SECONDS)

    for reader in readers:
        reader.join(timeout=_remaining(deadline))

    if any(reader.is_alive() for reader in readers):
        # The direct process may already have exited while one of its descendants
        # still owns an inherited stdout/stderr descriptor. Kill the session's
        # process group, not only the reaped parent, and never join without a
        # deadline.
        timed_out = True
        _kill_process_group(process)
        cleanup_deadline = time.monotonic() + _PROCESS_CLEANUP_SECONDS
        for reader in readers:
            reader.join(timeout=_remaining(cleanup_deadline))
        if any(reader.is_alive() for reader in readers):
            for stream in (process.stdout, process.stderr):
                _close_pipe(stream)
            for reader in readers:
                reader.join(timeout=_remaining(cleanup_deadline))

    return _ProcessOutput(
        returncode=returncode,
        stdout=bytes(stdout.data),
        stdout_bytes=stdout.size,
        stderr_bytes=stderr.size,
        timed_out=timed_out,
    )


def _close_pipe(stream: BinaryIO) -> None:
    """Close one owned pipe without waiting for a blocked BufferedReader."""

    try:
        raw = stream.detach()
    except (AttributeError, OSError, ValueError):
        try:
            stream.close()
        except (OSError, ValueError):
            pass
        return
    try:
        raw.close()
    except (OSError, ValueError):
        pass


def _remaining(deadline: float) -> float:
    return max(0.0, deadline - time.monotonic())


def _kill_process_group(process: subprocess.Popen[bytes]) -> None:
    pid = getattr(process, "pid", None)
    if isinstance(pid, int):
        try:
            os.killpg(pid, signal.SIGKILL)
            return
        except OSError:
            pass
    try:
        process.kill()
    except ProcessLookupError:
        pass


def _bounded_wait(process: subprocess.Popen[bytes], deadline: float) -> int:
    try:
        return process.wait(timeout=_remaining(deadline))
    except subprocess.TimeoutExpired:
        returncode = getattr(process, "returncode", None)
        return returncode if isinstance(returncode, int) else -signal.SIGKILL
