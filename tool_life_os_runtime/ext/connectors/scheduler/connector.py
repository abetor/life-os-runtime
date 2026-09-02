"""Bounded read-only adapter for the scheduler v1 machine surface."""

from __future__ import annotations

from dataclasses import dataclass
import datetime
import json
import math
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import time
from typing import Mapping, Sequence
import unicodedata

from tool_life_os_runtime.ext.connectors.probes import DEFAULT_SPECS


SCHEDULER_CONNECTOR_SCHEMA_VERSION = 1
MAX_SCHEDULER_OUTPUT_BYTES = 64 * 1024

_MAX_JSON_DEPTH = 12
_MAX_JSON_INTEGER = 2**63 - 1
_MAX_ENV = 256
_MAX_JOBS = 512
_MAX_ERRORS = 512
_MAX_TEXT = 2048
_PROCESS_CLEANUP_SECONDS = 0.25
_SEMVER = re.compile(r"^(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})$")
_JOB_NAME = re.compile(r"^[a-z0-9][a-z0-9_-]{0,127}$")
_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_AT = re.compile(r"^(?:[01]\d|2[0-3]):[0-5]\d$")
_SPEC = next(spec for spec in DEFAULT_SPECS if spec.tool == "scheduler")

_LIST_ERROR_CODES = frozenset(
    {
        "filesystem_error",
        "invalid_job",
        "invalid_state",
        "missing_jobs_dir",
        "output_too_large",
    }
)
_DOCTOR_ERROR_CODES = frozenset(
    {
        "filesystem_error",
        "invalid_job",
        "invalid_state",
        "missing_home",
        "missing_jobs_dir",
        "output_too_large",
        "stale_state",
    }
)


class SchedulerConnectorError(ValueError):
    """Normalized scheduler process, contract, or filesystem failure."""

    def __init__(
        self,
        code: str,
        *,
        category: str = "contract",
        returncode: int | None = None,
        stdout_bytes: int = 0,
        stderr_bytes: int = 0,
    ) -> None:
        self.code = code
        self.category = category
        self.returncode = returncode
        self.runtime_exit_code = 111 if category == "transient" else 1
        self.stdout_bytes = stdout_bytes
        self.stderr_bytes = stderr_bytes
        super().__init__(code)


@dataclass(frozen=True)
class SchedulerProblem:
    code: str
    job: str | None = None


@dataclass(frozen=True)
class SchedulerJobSchedule:
    kind: str
    at: str | None = None
    every_seconds: int | None = None


@dataclass(frozen=True)
class SchedulerJobPolicy:
    retries: int
    retry_delay_seconds: int
    quota_wait_seconds: int
    timeout_seconds: int


@dataclass(frozen=True)
class SchedulerJobState:
    last_run: str | None
    last_status: str | None
    fails: int
    next_run: int | float | None
    next_run_iso: str | None
    next_run_reason: str | None


@dataclass(frozen=True)
class SchedulerJob:
    name: str
    enabled: bool
    schedule: SchedulerJobSchedule
    policy: SchedulerJobPolicy
    state: SchedulerJobState


@dataclass(frozen=True)
class SchedulerList:
    schema_version: int
    status: str
    enabled: bool
    jobs: tuple[SchedulerJob, ...]
    errors: tuple[SchedulerProblem, ...]


@dataclass(frozen=True)
class SchedulerDoctor:
    schema_version: int
    status: str
    enabled: bool
    problems: tuple[SchedulerProblem, ...]


@dataclass(frozen=True)
class SchedulerJobSchema:
    schema_version: int
    job_schema: Mapping[str, object]


@dataclass(frozen=True)
class _ProcessResult:
    returncode: int | None
    stdout: bytes
    stdout_bytes: int
    stderr_bytes: int
    timed_out: bool
    setup_failed: bool


def _fail(
    code: str,
    *,
    category: str = "contract",
    returncode: int | None = None,
    stdout_bytes: int = 0,
    stderr_bytes: int = 0,
) -> None:
    raise SchedulerConnectorError(
        code,
        category=category,
        returncode=returncode,
        stdout_bytes=stdout_bytes,
        stderr_bytes=stderr_bytes,
    )


def _control(value: str) -> bool:
    return any(
        unicodedata.category(character).startswith("C")
        or unicodedata.category(character) in {"Zl", "Zp"}
        for character in value
    )


def _text(value: object, label: str, maximum: int = _MAX_TEXT) -> str:
    if not isinstance(value, str) or not value:
        _fail(f"invalid-{label}")
    try:
        encoded = value.encode("utf-8")
    except UnicodeError:
        _fail(f"invalid-{label}")
    if (
        len(encoded) > maximum
        or value != unicodedata.normalize("NFC", value)
        or _control(value)
    ):
        _fail(f"invalid-{label}")
    return value


def _integer(value: object, label: str, maximum: int = _MAX_JSON_INTEGER) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        _fail(f"invalid-{label}")
    return value


def _mapping(value: object, label: str, keys: set[str]) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or set(value) != keys:
        _fail(f"invalid-{label}")
    return value


def _pairs(items: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in items:
        if key in result:
            _fail("duplicate-json-key")
        result[key] = value
    return result


def _json_safe(value: object, *, depth: int = 0) -> None:
    if depth > _MAX_JSON_DEPTH:
        _fail("machine-json-too-deep")
    if value is None or isinstance(value, bool):
        return
    if type(value) is int:
        if abs(value) > _MAX_JSON_INTEGER:
            _fail("machine-json-integer-out-of-range")
        return
    if isinstance(value, float):
        if not math.isfinite(value) or abs(value) > _MAX_JSON_INTEGER:
            _fail("machine-json-number-out-of-range")
        return
    if isinstance(value, str):
        _text(value, "machine-text", MAX_SCHEDULER_OUTPUT_BYTES)
        return
    if isinstance(value, list):
        if len(value) > 2048:
            _fail("machine-json-too-many-items")
        for item in value:
            _json_safe(item, depth=depth + 1)
        return
    if isinstance(value, Mapping):
        if len(value) > 2048:
            _fail("machine-json-too-many-fields")
        for key, item in value.items():
            _text(key, "machine-key", 256)
            _json_safe(item, depth=depth + 1)
        return
    _fail("machine-json-invalid-type")


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError):
        _fail("machine-json-invalid")


def _decode(raw: bytes, label: str) -> object:
    if not raw or len(raw) > MAX_SCHEDULER_OUTPUT_BYTES:
        _fail(f"invalid-{label}")
    try:
        text = raw.decode("utf-8")
        value = json.loads(text, object_pairs_hook=_pairs)
    except SchedulerConnectorError:
        raise
    except (UnicodeError, ValueError, RecursionError):
        _fail(f"invalid-{label}")
    _json_safe(value)
    if raw != _canonical(value) + b"\n":
        _fail(f"noncanonical-{label}")
    return value


def _problem(
    value: object,
    label: str,
    codes: frozenset[str],
    *,
    optional_job_codes: frozenset[str] = frozenset({"invalid_job"}),
    required_job_codes: frozenset[str] = frozenset(),
) -> SchedulerProblem:
    if not isinstance(value, Mapping) or set(value) not in (
        {"code"},
        {"code", "job"},
    ):
        _fail(f"invalid-{label}")
    code = _text(value["code"], f"{label}-code", 64)
    if code not in codes:
        _fail(f"invalid-{label}-code")
    has_job = "job" in value
    if (has_job and code not in optional_job_codes | required_job_codes) or (
        not has_job and code in required_job_codes
    ):
        _fail(f"invalid-{label}-shape")
    job = value.get("job")
    if has_job:
        checked = _text(job, f"{label}-job", 133)
        if code == "invalid_job":
            stem = checked.removesuffix(".toml")
            if checked != f"{stem}.toml":
                _fail(f"invalid-{label}-job")
        else:
            stem = checked
            if checked.endswith(".toml"):
                _fail(f"invalid-{label}-job")
        if _JOB_NAME.fullmatch(stem) is None:
            _fail(f"invalid-{label}-job")
        job = checked
    return SchedulerProblem(code, job if isinstance(job, str) else None)


def _nullable_text(
    value: object, label: str, allowed: frozenset[str] | None = None
) -> str | None:
    if value is None:
        return None
    checked = _text(value, label, 1024)
    if allowed is not None and checked not in allowed:
        _fail(f"invalid-{label}")
    return checked


def _nullable_iso(value: object, label: str) -> str | None:
    checked = _nullable_text(value, label)
    if checked is None:
        return None
    try:
        datetime.datetime.fromisoformat(checked)
    except (ValueError, OverflowError):
        _fail(f"invalid-{label}")
    return checked


def _job(value: object) -> SchedulerJob:
    item = _mapping(
        value,
        "scheduler-job",
        {"name", "enabled", "schedule", "policy", "state"},
    )
    name = _text(item["name"], "job-name", 128)
    if _JOB_NAME.fullmatch(name) is None or type(item["enabled"]) is not bool:
        _fail("invalid-scheduler-job")
    schedule_raw = item["schedule"]
    if not isinstance(schedule_raw, Mapping):
        _fail("invalid-job-schedule")
    kind = schedule_raw.get("kind")
    if kind == "at" and set(schedule_raw) == {"kind", "at"}:
        at = _text(schedule_raw["at"], "job-at", 5)
        if _AT.fullmatch(at) is None:
            _fail("invalid-job-at")
        schedule = SchedulerJobSchedule("at", at=at)
    elif kind == "every" and set(schedule_raw) == {"kind", "every_seconds"}:
        every = _integer(schedule_raw["every_seconds"], "job-every-seconds", 2**31 - 1)
        if every < 1:
            _fail("invalid-job-every-seconds")
        schedule = SchedulerJobSchedule("every", every_seconds=every)
    else:
        _fail("invalid-job-schedule")
    policy_raw = _mapping(
        item["policy"],
        "job-policy",
        {"retries", "retry_delay_seconds", "quota_wait_seconds", "timeout_seconds"},
    )
    retry_delay = _integer(
        policy_raw["retry_delay_seconds"], "job-retry-delay", 2**31 - 1
    )
    quota_wait = _integer(policy_raw["quota_wait_seconds"], "job-quota-wait", 2**31 - 1)
    if retry_delay < 1 or quota_wait < 1:
        _fail("invalid-job-policy-duration")
    policy = SchedulerJobPolicy(
        _integer(policy_raw["retries"], "job-retries", 1000),
        retry_delay,
        quota_wait,
        _integer(policy_raw["timeout_seconds"], "job-timeout", 30 * 24 * 60 * 60),
    )
    state_raw = _mapping(
        item["state"],
        "job-state",
        {
            "last_run",
            "last_status",
            "fails",
            "next_run",
            "next_run_iso",
            "next_run_reason",
        },
    )
    next_run = state_raw["next_run"]
    if next_run is not None and (
        isinstance(next_run, bool)
        or not isinstance(next_run, (int, float))
        or not math.isfinite(next_run)
        or not 0 <= next_run <= 253_402_300_799
    ):
        _fail("invalid-job-next-run")
    state = SchedulerJobState(
        _nullable_iso(state_raw["last_run"], "job-last-run"),
        _nullable_text(
            state_raw["last_status"],
            "job-last-status",
            frozenset({"ok", "quota", "transient", "fail"}),
        ),
        _integer(state_raw["fails"], "job-fails", 2**31 - 1),
        next_run
        if isinstance(next_run, (int, float)) and not isinstance(next_run, bool)
        else None,
        _nullable_iso(state_raw["next_run_iso"], "job-next-run-iso"),
        _nullable_text(
            state_raw["next_run_reason"],
            "job-next-run-reason",
            frozenset({"schedule", "retry", "quota"}),
        ),
    )
    return SchedulerJob(name, item["enabled"], schedule, policy, state)


def _parse_list(raw: bytes, returncode: int) -> SchedulerList:
    item = _mapping(
        _decode(raw, "scheduler-list"),
        "scheduler-list",
        {"schema_version", "status", "enabled", "jobs", "errors"},
    )
    if type(item["schema_version"]) is not int or item["schema_version"] != 1:
        _fail("invalid-scheduler-list-schema")
    status = _text(item["status"], "scheduler-list-status", 16)
    if status not in {"ok", "error"} or type(item["enabled"]) is not bool:
        _fail("invalid-scheduler-list-status")
    if not isinstance(item["jobs"], list) or len(item["jobs"]) > _MAX_JOBS:
        _fail("invalid-scheduler-jobs")
    if not isinstance(item["errors"], list) or len(item["errors"]) > _MAX_ERRORS:
        _fail("invalid-scheduler-list-errors")
    jobs = tuple(_job(value) for value in item["jobs"])
    errors = tuple(
        _problem(value, "scheduler-list-error", _LIST_ERROR_CODES)
        for value in item["errors"]
    )
    if tuple(job.name for job in jobs) != tuple(sorted((job.name for job in jobs))):
        _fail("scheduler-jobs-not-sorted")
    if len({job.name for job in jobs}) != len(jobs):
        _fail("scheduler-jobs-collide")
    if (returncode, status, bool(errors)) not in {(0, "ok", False), (1, "error", True)}:
        _fail("scheduler-list-exit-mismatch", returncode=returncode)
    if status == "error" and jobs:
        _fail("scheduler-error-list-has-jobs")
    return SchedulerList(1, status, item["enabled"], jobs, errors)


def _parse_doctor(raw: bytes, returncode: int) -> SchedulerDoctor:
    item = _mapping(
        _decode(raw, "scheduler-doctor"),
        "scheduler-doctor",
        {"schema_version", "status", "enabled", "problems"},
    )
    if type(item["schema_version"]) is not int or item["schema_version"] != 1:
        _fail("invalid-scheduler-doctor-schema")
    status = _text(item["status"], "scheduler-doctor-status", 16)
    if status not in {"ok", "error"} or type(item["enabled"]) is not bool:
        _fail("invalid-scheduler-doctor-status")
    if not isinstance(item["problems"], list) or len(item["problems"]) > _MAX_ERRORS:
        _fail("invalid-scheduler-doctor-problems")
    problems = tuple(
        _problem(
            value,
            "scheduler-doctor-problem",
            _DOCTOR_ERROR_CODES,
            required_job_codes=frozenset({"stale_state"}),
        )
        for value in item["problems"]
    )
    if (returncode, status, bool(problems)) not in {
        (0, "ok", False),
        (1, "error", True),
    }:
        _fail("scheduler-doctor-exit-mismatch", returncode=returncode)
    return SchedulerDoctor(1, status, item["enabled"], problems)


_JOB_SCHEMA: dict[str, object] = {
    "schema_version": 1,
    "format": "toml",
    "name": {
        "source": "filename_stem",
        "type": "string",
        "pattern": "^[a-z0-9][a-z0-9_-]{0,127}$",
    },
    "additional_properties": False,
    "required": ["command"],
    "schedule": {"exactly_one_of": ["every", "at"]},
    "fields": {
        "command": {
            "type": "string",
            "min_utf8_bytes": 1,
            "max_utf8_bytes": 65536,
            "sensitive": True,
        },
        "every": {
            "type": "string",
            "pattern": "^(\\d+)([smhd])$",
            "minimum_seconds": 1,
            "maximum_seconds": 2**31 - 1,
        },
        "at": {"type": "string", "pattern": "^(?:[01]\\d|2[0-3]):[0-5]\\d$"},
        "enabled": {"type": "boolean", "default": True},
        "retries": {"type": "integer", "minimum": 0, "maximum": 1000, "default": 0},
        "retry_delay": {
            "type": "string",
            "pattern": "^(\\d+)([smhd])$",
            "minimum_seconds": 1,
            "maximum_seconds": 2**31 - 1,
            "default": "5m",
        },
        "quota_wait": {
            "type": "string",
            "pattern": "^(\\d+)([smhd])$",
            "minimum_seconds": 1,
            "maximum_seconds": 2**31 - 1,
            "default": "60m",
        },
        "timeout": {
            "type": "integer",
            "minimum": 0,
            "maximum": 30 * 24 * 60 * 60,
            "default": 0,
        },
        "quota_patterns": {
            "type": "array",
            "items": {"type": "string", "max_utf8_bytes": 1024},
            "max_items": 64,
            "default": [],
            "sensitive": True,
        },
    },
}


def _parse_job_schema(raw: bytes, returncode: int) -> SchedulerJobSchema:
    if returncode != 0:
        _fail("scheduler-job-schema-failed", returncode=returncode)
    item = _mapping(
        _decode(raw, "scheduler-job-schema"),
        "scheduler-job-schema",
        {"schema_version", "job_schema"},
    )
    if type(item["schema_version"]) is not int or item["schema_version"] != 1:
        _fail("invalid-scheduler-job-schema-version")
    if item["job_schema"] != _JOB_SCHEMA:
        _fail("scheduler-job-schema-drift")
    return SchedulerJobSchema(1, _JOB_SCHEMA)


def _expected_capabilities() -> list[dict[str, object]]:
    return [capability.to_dict() for capability in _SPEC.expected_capabilities]


def _parse_capabilities(raw: bytes, returncode: int) -> None:
    if returncode != 0:
        _fail("scheduler-handshake-failed", category="transient", returncode=returncode)
    item = _mapping(
        _decode(raw, "scheduler-capabilities"),
        "scheduler-capabilities",
        {"schema_version", "tool", "version", "capabilities"},
    )
    if (
        type(item["schema_version"]) is not int
        or item["schema_version"] != 1
        or item["tool"] != "scheduler"
        or item["capabilities"] != _expected_capabilities()
    ):
        _fail("scheduler-capability-drift")
    version = _text(item["version"], "scheduler-version", 32)
    match = _SEMVER.fullmatch(version)
    if match is None:
        _fail("invalid-scheduler-version")
    parsed = tuple(int(part) for part in match.groups())
    if not _SPEC.minimum_version <= parsed < _SPEC.maximum_version_exclusive:
        _fail("unsupported-scheduler-version")


def _kill_and_reap(process: subprocess.Popen[bytes]) -> None:
    # The direct child may exit while a descendant in the same fresh session
    # still holds stdout/stderr open.  Killing only while the parent is alive
    # leaves that descendant running after a timeout.
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (OSError, ProcessLookupError):
        if process.poll() is None:
            try:
                process.kill()
            except (OSError, ProcessLookupError):
                pass
    end = time.monotonic() + _PROCESS_CLEANUP_SECONDS
    while process.poll() is None and time.monotonic() < end:
        try:
            process.wait(timeout=max(0.001, end - time.monotonic()))
        except subprocess.TimeoutExpired:
            break


def _run_process(
    argv: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str],
    deadline: float,
) -> _ProcessResult:
    process: subprocess.Popen[bytes] | None = None
    selector: selectors.BaseSelector | None = None
    streams: list[object] = []
    stdout = bytearray()
    counts = {"stdout": 0, "stderr": 0}
    setup_failed = False
    try:
        process = subprocess.Popen(
            list(argv),
            cwd=cwd,
            env=dict(env),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            start_new_session=True,
        )
        if process.stdout is None or process.stderr is None:
            raise OSError("missing process pipe")
        streams = [process.stdout, process.stderr]
        selector = selectors.DefaultSelector()
        for label, stream in (("stdout", process.stdout), ("stderr", process.stderr)):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, label)
    except Exception:
        setup_failed = True
        if process is not None:
            _kill_and_reap(process)
        for stream in streams:
            try:
                stream.close()  # type: ignore[union-attr]
            except (OSError, ValueError):
                pass
        if selector is not None:
            selector.close()
        return _ProcessResult(None, b"", 0, 0, False, True)

    timed_out = False
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            for key, _mask in selector.select(min(remaining, 0.05)):
                label = key.data
                try:
                    block = os.read(key.fileobj.fileno(), 8192)
                except BlockingIOError:
                    continue
                except OSError:
                    setup_failed = True
                    block = b""
                if not block:
                    try:
                        selector.unregister(key.fileobj)
                    except (KeyError, ValueError):
                        pass
                    continue
                counts[label] = min(
                    MAX_SCHEDULER_OUTPUT_BYTES + 1, counts[label] + len(block)
                )
                if label == "stdout" and len(stdout) <= MAX_SCHEDULER_OUTPUT_BYTES:
                    room = MAX_SCHEDULER_OUTPUT_BYTES + 1 - len(stdout)
                    stdout.extend(block[:room])
            if process.poll() is not None and not selector.get_map():
                break
        if timed_out or setup_failed:
            _kill_and_reap(process)
        elif process.poll() is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                _kill_and_reap(process)
            else:
                try:
                    process.wait(timeout=remaining)
                except subprocess.TimeoutExpired:
                    timed_out = True
                    _kill_and_reap(process)
        return _ProcessResult(
            process.returncode,
            bytes(stdout),
            counts["stdout"],
            counts["stderr"],
            timed_out,
            setup_failed,
        )
    finally:
        selector.close()
        for stream in streams:
            try:
                stream.close()  # type: ignore[union-attr]
            except (OSError, ValueError):
                pass


def _directory_signature(fd: int) -> tuple[int, int]:
    metadata = os.fstat(fd)
    if not stat.S_ISDIR(metadata.st_mode):
        _fail("scheduler-path-is-not-directory")
    return metadata.st_dev, metadata.st_ino


class SchedulerConnector:
    """Observe one configured external scheduler home without mutating it."""

    def __init__(
        self,
        *,
        command: Sequence[str],
        cwd: Path,
        env: Mapping[str, str],
        home: Path,
        timeout: float = 5.0,
    ) -> None:
        if (
            not isinstance(command, Sequence)
            or isinstance(command, (str, bytes))
            or not command
            or len(command) > 32
        ):
            _fail("invalid-scheduler-command")
        checked_command = tuple(
            _text(item, "scheduler-command", 4096) for item in command
        )
        if (
            not isinstance(cwd, Path)
            or not cwd.is_absolute()
            or not isinstance(home, Path)
            or not home.is_absolute()
            or isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout)
            or not 0 < timeout <= 300
            or not isinstance(env, Mapping)
            or len(env) > _MAX_ENV
        ):
            _fail("invalid-scheduler-configuration")
        checked_env: dict[str, str] = {}
        for key, value in env.items():
            if not isinstance(key, str) or _ENV_NAME.fullmatch(key) is None:
                _fail("invalid-scheduler-environment")
            checked_env[key] = _text(value, "scheduler-environment-value", 32 * 1024)
        self._command = checked_command
        self._cwd = cwd
        self._home = home
        self._env = checked_env
        self._timeout = float(timeout)
        self._fds: list[int] = []
        try:
            flags = (
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            self._cwd_fd = os.open(cwd, flags)
            self._fds.append(self._cwd_fd)
            self._home_fd = os.open(home, flags)
            self._fds.append(self._home_fd)
            self._jobs_fd = os.open("jobs", flags, dir_fd=self._home_fd)
            self._fds.append(self._jobs_fd)
            self._cwd_identity = _directory_signature(self._cwd_fd)
            self._home_identity = _directory_signature(self._home_fd)
            self._jobs_identity = _directory_signature(self._jobs_fd)
            self._revalidate()
        except SchedulerConnectorError:
            self.close()
            raise
        except OSError:
            self.close()
            _fail("scheduler-path-unavailable")

    def close(self) -> None:
        while getattr(self, "_fds", []):
            fd = self._fds.pop()
            try:
                os.close(fd)
            except OSError:
                pass

    def __enter__(self) -> SchedulerConnector:
        self._revalidate()
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def __del__(self) -> None:
        self.close()

    def _revalidate(self) -> None:
        try:
            cwd_named = os.stat(self._cwd, follow_symlinks=False)
            home_named = os.stat(self._home, follow_symlinks=False)
            jobs_named = os.stat("jobs", dir_fd=self._home_fd, follow_symlinks=False)
            if (
                _directory_signature(self._cwd_fd) != self._cwd_identity
                or _directory_signature(self._home_fd) != self._home_identity
                or _directory_signature(self._jobs_fd) != self._jobs_identity
                or (cwd_named.st_dev, cwd_named.st_ino) != self._cwd_identity
                or (home_named.st_dev, home_named.st_ino) != self._home_identity
                or (jobs_named.st_dev, jobs_named.st_ino) != self._jobs_identity
            ):
                _fail("scheduler-path-changed")
        except SchedulerConnectorError:
            raise
        except OSError:
            _fail("scheduler-path-changed")

    def _invoke(self, operation: str) -> _ProcessResult:
        deadline = time.monotonic() + self._timeout
        self._revalidate()
        handshake = _run_process(
            (*self._command, "capabilities", "--json"),
            cwd=self._cwd,
            env=self._env,
            deadline=deadline,
        )
        self._check_process(handshake, "scheduler-handshake")
        _parse_capabilities(handshake.stdout, int(handshake.returncode))
        self._revalidate()
        argv = (
            (*self._command, "job-schema", "--json")
            if operation == "job-schema"
            else (*self._command, "--home", str(self._home), operation, "--json")
        )
        result = _run_process(argv, cwd=self._cwd, env=self._env, deadline=deadline)
        self._check_process(result, f"scheduler-{operation}", allow_failure=True)
        self._revalidate()
        return result

    @staticmethod
    def _check_process(
        result: _ProcessResult, label: str, *, allow_failure: bool = False
    ) -> None:
        if result.setup_failed:
            _fail(f"{label}-setup-failed", category="transient")
        if result.timed_out:
            _fail(f"{label}-timeout", category="transient")
        if (
            result.stdout_bytes > MAX_SCHEDULER_OUTPUT_BYTES
            or result.stderr_bytes > MAX_SCHEDULER_OUTPUT_BYTES
        ):
            _fail(f"{label}-output-too-large", category="transient")
        if result.returncode is None or result.returncode not in (
            {0, 1} if allow_failure else {0}
        ):
            _fail(
                f"{label}-unexpected-exit",
                category="transient",
                returncode=result.returncode,
            )

    def list_jobs(self) -> SchedulerList:
        result = self._invoke("list")
        return _parse_list(result.stdout, int(result.returncode))

    def doctor(self) -> SchedulerDoctor:
        result = self._invoke("doctor")
        return _parse_doctor(result.stdout, int(result.returncode))

    def job_schema(self) -> SchedulerJobSchema:
        result = self._invoke("job-schema")
        return _parse_job_schema(result.stdout, int(result.returncode))
