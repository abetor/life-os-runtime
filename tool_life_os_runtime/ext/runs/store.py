"""Authoritative run state and replay-safe semantic step journal.

``state.json`` is the only resume state.  Intents make the short interval
between a prepared artifact and the state commit recoverable; trace and human
projections are deliberately downstream views and are never parsed by
``status`` or ``resume``.
"""

from __future__ import annotations

from contextlib import contextmanager
import ctypes
from dataclasses import dataclass, replace
from datetime import datetime, timezone
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
from typing import Callable, Iterator, Mapping, Sequence
import unicodedata
import uuid

from tool_life_os_runtime.ext.review.authority import (
    ActionCapability,
    AuthorityError,
    AuthorityPolicy,
)
from tool_life_os_runtime.ext.vault.schema import VaultPathResolver, VaultSchemaError
from tool_life_os_runtime.failure_authority import (
    FailureAuthorityError,
    REQUIRED_FLOW_IDS,
    authority_at_most,
    authorize_action,
    canonical_matrix,
)


STATE_SCHEMA_VERSION = 1
TRACE_SCHEMA_VERSION = 1
TRACE_ACTION_SCHEMA_VERSION = 2
INTENT_SCHEMA_VERSION = 2
RECEIPT_SCHEMA_VERSION = 1
PROJECTION_SCHEMA_VERSION = 1

# Cross-flow finalization is the sole action-evidence exception: a producer
# run may be closed by the objective finalize flow, but only as this complete
# P0 matrix sequence. Keep the order explicit so a matrix reorder is reviewed
# as a contract change instead of silently widening the exception.
FINALIZE_ACTION_ORDER = (
    "validate-run-artifacts",
    "read-review-outcome",
    "append-domain-log",
    "append-run-trace",
    "commit-bounded-metrics",
    "emit-semantic-outbox-event",
    "finalize-run-state",
)
_FINALIZE_SOURCE_FLOWS = frozenset(
    {
        "distill",
        "apply",
        "ask",
        "project",
        "entities",
        "plan",
        "book",
        "report",
        "memory",
        "mentor",
        "grill-me",
        "lint",
        "ambient",
        "bundle",
    }
)
_FINALIZE_SIDECARS = {
    "finalize-log": ("agent/logs", "finalize/"),
    "finalize-metric": ("agent/logs", "metrics/"),
    "finalize-event": ("agent/outbox", "event_"),
}
_FINALIZE_DECISION = "finalize-decision"
_FINALIZE_SOURCE_ROLES = {
    "distill": frozenset({"review", "plan"}),
    "apply": frozenset({"review", "plan", "apply-journal"}),
}

STATUSES = frozenset(
    {
        "created",
        "running",
        "waiting_human",
        "succeeded",
        "failed",
        "quota_wait",
        "transient_wait",
        "cancelled",
    }
)
TERMINAL_STATUSES = frozenset({"succeeded", "failed", "cancelled"})
RESUMABLE_STATUSES = frozenset(
    {"created", "running", "waiting_human", "quota_wait", "transient_wait"}
)
TRANSITIONS: dict[str, frozenset[str]] = {
    "created": frozenset({"running", "cancelled"}),
    "running": frozenset(
        {
            "waiting_human",
            "succeeded",
            "failed",
            "quota_wait",
            "transient_wait",
            "cancelled",
        }
    ),
    "waiting_human": frozenset({"running", "failed", "cancelled"}),
    "quota_wait": frozenset({"running", "failed", "cancelled"}),
    "transient_wait": frozenset({"running", "failed", "cancelled"}),
    "succeeded": frozenset(),
    "failed": frozenset(),
    "cancelled": frozenset(),
}

_RUN_ID = re.compile(r"^run_[a-z0-9][a-z0-9_-]{0,62}$")
_CANONICAL_ID = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$")
_PRIVATE_MARKERS = ("/" + "Users" + "/", "/" + "home" + "/", "file:")
_SECRET_KEYS = (
    "token",
    "secret",
    "password",
    "credential",
    "authorization",
    "cookie",
    "chat_id",
    "api_key",
)
_STATE_KEYS = frozenset(
    {
        "schema_version",
        "run_id",
        "flow",
        "status",
        "phase",
        "authority",
        "executor",
        "input",
        "artifacts",
        "attempt",
        "created_at",
        "updated_at",
        "waiting_for",
        "last_error",
    }
)
_TRACE_KEYS = frozenset(
    {
        "schema_version",
        "at",
        "run_id",
        "step_id",
        "authority",
        "input_hash",
        "output_hash",
        "executor_profile",
        "tool_outcomes",
    }
)
_TRACE_ACTION_KEYS = _TRACE_KEYS | {"actions"}
_ACTION_EVIDENCE_KEYS = frozenset(
    {
        "sequence",
        "flow_id",
        "action_id",
        "actor",
        "authority",
        "target",
        "access",
        "effect_kind",
        "artifact_commit",
        "matrix_sha256",
        "status",
    }
)
_OUTCOME_KEYS = frozenset({"tool", "status", "exit_code", "detail_hash"})
_INTENT_KEYS_V1 = frozenset(
    {
        "schema_version",
        "run_id",
        "step_id",
        "status",
        "base_state_sha256",
        "target_state",
        "prepared_artifacts",
        "trace_event",
    }
)
_INTENT_KEYS_V2 = _INTENT_KEYS_V1 | {"base_state"}
_PREPARED_KEYS = frozenset({"name", "zone", "relative", "state_ref", "sha256"})
_RECEIPT_KEYS = frozenset(
    {
        "schema_version",
        "receipt_id",
        "run_id",
        "event_id",
        "status",
        "effect_hash",
        "at",
    }
)
_MAX_JSON_BYTES = 256 * 1024
_MAX_TRACE_LINE_BYTES = 16 * 1024
_DEFAULT_MAX_TRACE_BYTES = 4 * 1024 * 1024


class RunError(ValueError):
    """Run state is invalid, unsafe, or conflicts with durable evidence."""


class RunLockBusy(RunError):
    """Another writer currently owns this run."""


@dataclass(frozen=True)
class PreparedArtifact:
    """One already-durable artifact which a state transition will expose."""

    name: str
    zone: str
    relative: str
    state_ref: str
    sha256: str


@dataclass(frozen=True)
class CommittedArtifact:
    """Exact durable evidence for one artifact exposed by current run state."""

    name: str
    zone: str
    relative: str
    state_ref: str
    sha256: str
    step_id: str


@dataclass(frozen=True)
class RunSnapshot:
    """One reconciled state precondition plus rechecked committed artifacts."""

    state: Mapping[str, object]
    state_sha256: str
    artifacts: tuple[CommittedArtifact, ...]


@dataclass(frozen=True)
class _CommittedIndex:
    artifacts: Mapping[str, Mapping[str, object]]
    steps: Mapping[str, str]
    latest_producer_step: str | None


@dataclass(frozen=True)
class ToolOutcome:
    """Bounded tool result; raw detail is hashed instead of persisted."""

    tool: str
    status: str
    exit_code: int | None
    detail: str = ""


@dataclass(frozen=True)
class ActionUse:
    """One policy-issued capability and its bounded execution result."""

    capability: ActionCapability
    status: str = "succeeded"


def _fail(message: str) -> None:
    raise RunError(message)


def _has_nonportable_text(value: str) -> bool:
    return any(
        unicodedata.category(character).startswith("C")
        or unicodedata.category(character) in {"Zl", "Zp"}
        for character in value
    )


def _plain_string(
    value: object, label: str, *, pattern: re.Pattern[str] | None = None
) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 4096
        or value.strip() != value
        or _has_nonportable_text(value)
        or any(marker in value for marker in _PRIVATE_MARKERS)
    ):
        _fail(f"{label} must be a bounded privacy-safe string")
    if pattern is not None and pattern.fullmatch(value) is None:
        _fail(f"{label} has invalid syntax")
    return value


def _exact_int(value: object, label: str, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        _fail(f"{label} must be an integer >= {minimum}")
    return value


def _hash(value: object, label: str) -> str:
    return _plain_string(value, label, pattern=_SHA256)


def _timestamp(value: object, label: str) -> str:
    text = _plain_string(value, label)
    if _UTC.fullmatch(text) is None:
        _fail(f"{label} must be a UTC timestamp")
    try:
        datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError:
        _fail(f"{label} must be a valid UTC timestamp")
    return text


def _timestamp_value(value: str) -> datetime:
    return datetime.fromisoformat(value[:-1] + "+00:00")


def _safe_ref(value: object, label: str) -> str:
    text = _plain_string(value, label)
    if "\\" in text:
        _fail(f"{label} must use portable separators")
    path = PurePosixPath(text)
    if path.is_absolute() or path == PurePosixPath(".") or ".." in path.parts:
        _fail(f"{label} must be a safe relative path")
    return text


def _safe_json(value: object, label: str, *, depth: int = 0) -> object:
    if depth > 8:
        _fail(f"{label} is too deeply nested")
    if value is None or isinstance(value, bool) or type(value) in {int, float}:
        return value
    if isinstance(value, str):
        if len(value) > 8192 or _has_nonportable_text(value):
            _fail(f"{label} contains an invalid string")
        if any(marker in value for marker in _PRIVATE_MARKERS):
            _fail(f"{label} contains a private path")
        return value
    if isinstance(value, list):
        if len(value) > 128:
            _fail(f"{label} has too many items")
        return [_safe_json(item, f"{label} item", depth=depth + 1) for item in value]
    if isinstance(value, Mapping):
        if len(value) > 128:
            _fail(f"{label} has too many fields")
        result: dict[str, object] = {}
        for key, item in value.items():
            key_text = _plain_string(key, f"{label} key")
            lowered = key_text.lower()
            if any(marker in lowered for marker in _SECRET_KEYS):
                _fail(f"{label} contains a forbidden secret field")
            result[key_text] = _safe_json(item, f"{label}.{key_text}", depth=depth + 1)
        return result
    _fail(f"{label} contains a non-JSON value")


def _canonical_bytes(payload: Mapping[str, object]) -> bytes:
    try:
        raw = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError):
        _fail("payload is not canonical JSON")
    if len(raw) > _MAX_JSON_BYTES:
        _fail("payload is too large")
    return raw


def _digest(payload: Mapping[str, object]) -> str:
    return hashlib.sha256(_canonical_bytes(payload)).hexdigest()


def _object_no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            _fail("JSON has duplicate fields")
        result[key] = value
    return result


def _read_regular_bounded_at(
    directory_fd: int, name: str, maximum: int, label: str
) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(name, flags, dir_fd=directory_fd)
    except OSError:
        _fail(f"{label} cannot be read")
    try:
        return _read_regular_bounded_fd(fd, maximum, label)
    finally:
        os.close(fd)


def _read_regular_bounded_fd(fd: int, maximum: int, label: str) -> bytes:
    metadata = os.fstat(fd)
    if not stat.S_ISREG(metadata.st_mode):
        _fail(f"{label} must be a regular file")
    if metadata.st_size > maximum:
        _fail(f"{label} is too large")
    try:
        os.lseek(fd, 0, os.SEEK_SET)
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(fd, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
    except OSError:
        _fail(f"{label} cannot be read")
    raw = b"".join(chunks)
    if len(raw) > maximum:
        _fail(f"{label} is too large")
    return raw


def _decode_json(raw: bytes, label: str) -> dict[str, object]:
    try:
        payload = json.loads(raw, object_pairs_hook=_object_no_duplicates)
    except RunError:
        raise
    except (UnicodeError, ValueError, RecursionError):
        _fail(f"{label} is not valid JSON")
    if not isinstance(payload, dict):
        _fail(f"{label} must be an object")
    return payload


def _read_json_at(
    directory_fd: int, name: str, label: str = "run state"
) -> dict[str, object]:
    return _decode_json(
        _read_regular_bounded_at(directory_fd, name, _MAX_JSON_BYTES, label), label
    )


def _atomic_bytes_at(directory_fd: int, name: str, data: bytes) -> tuple[int, int]:
    tmp = f".{name}.{os.getpid()}.{uuid.uuid4().hex}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd: int | None = None
    identity: tuple[int, int] | None = None
    try:
        fd = os.open(tmp, flags, 0o600, dir_fd=directory_fd)
        with os.fdopen(fd, "wb", closefd=True) as handle:
            fd = None
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
            metadata = os.fstat(handle.fileno())
            identity = (metadata.st_dev, metadata.st_ino)
        os.replace(
            tmp,
            name,
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
        )
        os.fsync(directory_fd)
        if identity is None:  # pragma: no cover - local invariant
            raise RunError("atomic run write lost its file identity")
        return identity
    except OSError:
        try:
            os.unlink(tmp, dir_fd=directory_fd)
        except OSError:
            pass
        raise RunError("atomic run write failed") from None
    finally:
        if fd is not None:
            os.close(fd)


def _atomic_json_at(
    directory_fd: int, name: str, payload: Mapping[str, object]
) -> tuple[int, int]:
    return _atomic_bytes_at(directory_fd, name, _canonical_bytes(payload) + b"\n")


def _rename_noreplace_at(directory_fd: int, source: str, destination: str) -> bool:
    """Atomically rename one directory entry without replacing destination."""

    libc = ctypes.CDLL(None, use_errno=True)
    source_bytes = os.fsencode(source)
    destination_bytes = os.fsencode(destination)
    if sys.platform == "darwin":
        function = libc.renameatx_np
        function.argtypes = (
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        )
        function.restype = ctypes.c_int
        result = function(
            directory_fd,
            source_bytes,
            directory_fd,
            destination_bytes,
            0x00000004,
        )
    elif sys.platform.startswith("linux") and hasattr(libc, "renameat2"):
        function = libc.renameat2
        function.argtypes = (
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        )
        function.restype = ctypes.c_int
        result = function(
            directory_fd,
            source_bytes,
            directory_fd,
            destination_bytes,
            1,
        )
    else:
        _fail("atomic no-replace run publication is unavailable")
    if result == 0:
        return True
    error = ctypes.get_errno()
    if error == errno.EEXIST:
        return False
    raise RunError("atomic no-replace run publication failed") from OSError(
        error, os.strerror(error)
    )


def _retire_temp_at(directory_fd: int, temp: str, identity: tuple[int, int]) -> bool:
    """Retain a temp safely and never unlink a substituted foreign leaf."""

    try:
        os.mkdir(".recovery", mode=0o700, dir_fd=directory_fd)
        os.fsync(directory_fd)
    except FileExistsError:
        pass
    except OSError:
        return False
    try:
        recovery_fd = os.open(
            ".recovery",
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory_fd,
        )
    except OSError:
        return False
    recovery_name = f"stage-{uuid.uuid4().hex}.recovery"
    try:
        os.rename(
            temp,
            recovery_name,
            src_dir_fd=directory_fd,
            dst_dir_fd=recovery_fd,
        )
        os.fsync(directory_fd)
        os.fsync(recovery_fd)
        moved = os.stat(recovery_name, dir_fd=recovery_fd, follow_symlinks=False)
        if (moved.st_dev, moved.st_ino) == identity:
            return True
        try:
            os.link(
                recovery_name,
                temp,
                src_dir_fd=recovery_fd,
                dst_dir_fd=directory_fd,
                follow_symlinks=False,
            )
            os.fsync(directory_fd)
        except OSError:
            pass
        return False
    except OSError:
        return False
    finally:
        os.close(recovery_fd)


def _create_json_once_at(
    directory_fd: int, name: str, payload: Mapping[str, object]
) -> tuple[int, int] | None:
    """Publish immutable JSON beneath an already anchored directory."""

    return _create_bytes_once_at(directory_fd, name, _canonical_bytes(payload) + b"\n")


def _create_bytes_once_at(
    directory_fd: int, name: str, data: bytes
) -> tuple[int, int] | None:
    """Publish immutable bytes without replacing an existing directory entry."""

    try:
        os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        return None
    except FileNotFoundError:
        pass
    except OSError:
        raise RunError("immutable run destination cannot be inspected") from None

    tmp = f".{name}.{os.getpid()}.{uuid.uuid4().hex}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd: int | None = None
    identity: tuple[int, int] | None = None
    retire_temp = False
    try:
        fd = os.open(tmp, flags, 0o600, dir_fd=directory_fd)
        retire_temp = True
        with os.fdopen(fd, "wb", closefd=True) as handle:
            fd = None
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
            metadata = os.fstat(handle.fileno())
            identity = (metadata.st_dev, metadata.st_ino)
        if not _rename_noreplace_at(directory_fd, tmp, name):
            return None
        retire_temp = False
        if identity is None:  # pragma: no cover - local invariant
            raise RunError("immutable run write lost its file identity")
        published = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        os.fsync(directory_fd)
        if (published.st_dev, published.st_ino) != identity:
            _fail("immutable run stage was replaced during publication")
        return identity
    except OSError:
        raise RunError("immutable run write failed") from None
    finally:
        if fd is not None:
            os.close(fd)
        if (
            retire_temp
            and identity is not None
            and not _retire_temp_at(directory_fd, tmp, identity)
        ):
            _fail("immutable run stage cleanup encountered a foreign leaf")


def _allowed_authorities(flow: str) -> frozenset[str]:
    for row in canonical_matrix()["flows"]:
        if row["flow_id"] == flow:
            return frozenset(action["authority"] for action in row["actions"])
    _fail("unknown run flow")


def validate_state(payload: Mapping[str, object]) -> dict[str, object]:
    """Validate and return a detached canonical run-state object."""

    if not isinstance(payload, Mapping) or set(payload) != _STATE_KEYS:
        _fail("state has missing or unknown fields")
    if (
        type(payload["schema_version"]) is not int
        or payload["schema_version"] != STATE_SCHEMA_VERSION
    ):
        _fail("unsupported state schema_version")
    run_id = _plain_string(payload["run_id"], "run_id", pattern=_RUN_ID)
    flow = _plain_string(payload["flow"], "flow", pattern=_CANONICAL_ID)
    if flow not in REQUIRED_FLOW_IDS:
        _fail("unknown run flow")
    status = payload["status"]
    if status not in STATUSES:
        _fail("invalid run status")
    _plain_string(payload["phase"], "phase", pattern=_CANONICAL_ID)
    authority = _plain_string(payload["authority"], "authority", pattern=_CANONICAL_ID)
    if authority not in _allowed_authorities(flow):
        _fail("authority is outside the flow contract")
    _plain_string(payload["executor"], "executor", pattern=_CANONICAL_ID)
    input_value = _safe_json(payload["input"], "input")
    if not isinstance(input_value, dict):
        _fail("input must be an object")
    artifacts = payload["artifacts"]
    if not isinstance(artifacts, Mapping):
        _fail("artifacts must be an object")
    checked_artifacts: dict[str, str] = {}
    for name, reference in artifacts.items():
        checked_name = _plain_string(name, "artifact name", pattern=_CANONICAL_ID)
        checked_artifacts[checked_name] = _safe_ref(
            reference, f"artifact {checked_name}"
        )
    _exact_int(payload["attempt"], "attempt", minimum=1)
    created_at = _timestamp(payload["created_at"], "created_at")
    updated_at = _timestamp(payload["updated_at"], "updated_at")
    if _timestamp_value(updated_at) < _timestamp_value(created_at):
        _fail("updated_at must not precede created_at")
    waiting_for = payload["waiting_for"]
    if status == "waiting_human":
        _plain_string(waiting_for, "waiting_for", pattern=_CANONICAL_ID)
    elif waiting_for is not None:
        _fail("waiting_for is only valid for waiting_human")
    last_error = payload["last_error"]
    error_statuses = {"failed", "quota_wait", "transient_wait"}
    if status in error_statuses and last_error is None:
        _fail("failed or waiting status requires last_error")
    if status not in error_statuses and last_error is not None:
        _fail("last_error is invalid for this status")
    if last_error is not None:
        if not isinstance(last_error, Mapping) or set(last_error) != {
            "kind",
            "retryable",
            "detail_hash",
        }:
            _fail("last_error has invalid fields")
        _plain_string(last_error["kind"], "last_error.kind", pattern=_CANONICAL_ID)
        if not isinstance(last_error["retryable"], bool):
            _fail("last_error.retryable must be boolean")
        if last_error["retryable"] != (status in {"quota_wait", "transient_wait"}):
            _fail("last_error.retryable disagrees with run status")
        _hash(last_error["detail_hash"], "last_error.detail_hash")
    checked = dict(payload)
    checked["input"] = input_value
    checked["artifacts"] = checked_artifacts
    _canonical_bytes(checked)
    if checked["run_id"] != run_id:
        _fail("run_id changed during validation")
    return checked


def validate_trace_event(payload: Mapping[str, object]) -> dict[str, object]:
    if not isinstance(payload, Mapping):
        _fail("trace event has missing or unknown fields")
    schema_version = payload.get("schema_version")
    expected_keys = (
        _TRACE_KEYS
        if schema_version == TRACE_SCHEMA_VERSION
        else _TRACE_ACTION_KEYS
        if schema_version == TRACE_ACTION_SCHEMA_VERSION
        else frozenset()
    )
    if set(payload) != expected_keys:
        _fail("trace event has missing or unknown fields")
    if type(schema_version) is not int or schema_version not in {
        TRACE_SCHEMA_VERSION,
        TRACE_ACTION_SCHEMA_VERSION,
    }:
        _fail("unsupported trace schema_version")
    _timestamp(payload["at"], "trace.at")
    _plain_string(payload["run_id"], "trace.run_id", pattern=_RUN_ID)
    _plain_string(payload["step_id"], "trace.step_id", pattern=_CANONICAL_ID)
    _plain_string(payload["authority"], "trace.authority", pattern=_CANONICAL_ID)
    _hash(payload["input_hash"], "trace.input_hash")
    _hash(payload["output_hash"], "trace.output_hash")
    _plain_string(
        payload["executor_profile"], "trace.executor_profile", pattern=_CANONICAL_ID
    )
    outcomes = payload["tool_outcomes"]
    if not isinstance(outcomes, list) or len(outcomes) > 16:
        _fail("trace.tool_outcomes must be a bounded list")
    for outcome in outcomes:
        if not isinstance(outcome, Mapping) or set(outcome) != _OUTCOME_KEYS:
            _fail("tool outcome has missing or unknown fields")
        _plain_string(outcome["tool"], "tool outcome tool", pattern=_CANONICAL_ID)
        _plain_string(outcome["status"], "tool outcome status", pattern=_CANONICAL_ID)
        if outcome["exit_code"] is not None:
            _exact_int(outcome["exit_code"], "tool outcome exit_code", minimum=0)
        _hash(outcome["detail_hash"], "tool outcome detail_hash")
    checked = dict(payload)
    if schema_version == TRACE_ACTION_SCHEMA_VERSION:
        actions = payload["actions"]
        if not isinstance(actions, list) or not actions or len(actions) > 16:
            _fail("trace.actions must be a bounded non-empty list")
        normalized_actions: list[dict[str, object]] = []
        matrix_hash = hashlib.sha256(_canonical_bytes(canonical_matrix())).hexdigest()
        for sequence, action in enumerate(actions, start=1):
            if not isinstance(action, Mapping) or set(action) != _ACTION_EVIDENCE_KEYS:
                _fail("trace action has missing or unknown fields")
            if (
                _exact_int(action["sequence"], "trace action sequence", minimum=1)
                != sequence
            ):
                _fail("trace action sequence must be contiguous and ordered")
            flow_id = _plain_string(
                action["flow_id"], "trace action flow_id", pattern=_CANONICAL_ID
            )
            action_id = _plain_string(
                action["action_id"], "trace action action_id", pattern=_CANONICAL_ID
            )
            actor = _plain_string(action["actor"], "trace action actor")
            action_authority = _plain_string(
                action["authority"], "trace action authority", pattern=_CANONICAL_ID
            )
            target = _plain_string(action["target"], "trace action target")
            try:
                canonical = authorize_action(
                    canonical_matrix(),
                    flow_id=flow_id,
                    action_id=action_id,
                    actor=actor,
                    authority=action_authority,
                    target=target,
                )
            except FailureAuthorityError:
                _fail("trace action is not canonical")
            if (
                action["access"],
                action["effect_kind"],
                action["artifact_commit"],
            ) != (
                canonical["access"],
                canonical["effect_kind"],
                canonical["artifact_commit"],
            ):
                _fail("trace action fields disagree with the canonical action")
            if action["matrix_sha256"] != matrix_hash:
                _fail("trace action matrix binding is invalid")
            if action["status"] not in {"succeeded", "failed"}:
                _fail("trace action status is invalid")
            normalized_actions.append(dict(action))
        if not all(
            authority_at_most(str(action["authority"]), str(payload["authority"]))
            for action in normalized_actions
        ) or not any(
            action["authority"] == payload["authority"] for action in normalized_actions
        ):
            _fail("trace actions disagree with the semantic step authority")
        checked["actions"] = normalized_actions
    raw = _canonical_bytes(checked)
    if len(raw) + 1 > _MAX_TRACE_LINE_BYTES:
        _fail("trace event is too large")
    return checked


def _validate_cross_flow_finalize_intent(
    *,
    base_state_sha256: object,
    target: Mapping[str, object],
    prepared: Sequence[Mapping[str, object]],
    trace: Mapping[str, object],
) -> None:
    actions = trace.get("actions", [])
    has_finalize_decision = any(
        isinstance(item, Mapping) and item.get("name") == _FINALIZE_DECISION
        for item in prepared
    )
    if not isinstance(actions, list) or not actions:
        if has_finalize_decision:
            _fail("finalize decision requires the exact cross-flow finalize trace")
        return
    source_flow = str(target["flow"])
    action_flows = tuple(str(action["flow_id"]) for action in actions)
    if all(flow_id == source_flow for flow_id in action_flows):
        if has_finalize_decision:
            _fail("finalize decision requires the exact cross-flow finalize trace")
        return
    finalize_rows = tuple(
        row for row in canonical_matrix()["flows"] if row["flow_id"] == "finalize"
    )
    matrix_order = (
        tuple(action["action_id"] for action in finalize_rows[0]["actions"])
        if len(finalize_rows) == 1
        else ()
    )
    if (
        matrix_order != FINALIZE_ACTION_ORDER
        or len(actions) != len(FINALIZE_ACTION_ORDER)
        or source_flow not in _FINALIZE_SOURCE_FLOWS
        or any(flow_id != "finalize" for flow_id in action_flows)
        or tuple(str(action["action_id"]) for action in actions)
        != FINALIZE_ACTION_ORDER
    ):
        _fail("cross-flow trace is not the exact canonical finalize sequence")

    status = str(target["status"])
    expected_binding = {
        "waiting_human": (
            "finalize-review-ready",
            "review",
            "review-decision",
            False,
        ),
        "succeeded": ("finalize-complete", "finalized", None, False),
        "failed": ("finalize-failed", "finalized", None, True),
    }.get(status)
    if expected_binding is None:
        _fail("cross-flow finalize must commit a supported terminal state")
    step_id, phase, waiting_for, has_error = expected_binding
    expected_statuses = (
        (
            "failed",
            "failed",
            "succeeded",
            "succeeded",
            "succeeded",
            "failed",
            "succeeded",
        )
        if status == "failed"
        else ("succeeded",) * len(FINALIZE_ACTION_ORDER)
    )
    if (
        trace["step_id"] != step_id
        or trace["authority"] != "internal-write"
        or target["phase"] != phase
        or target["waiting_for"] != waiting_for
        or (target["last_error"] is not None) != has_error
        or tuple(str(action["status"]) for action in actions) != expected_statuses
        or trace["input_hash"] != base_state_sha256
    ):
        _fail("cross-flow finalize trace and target state are not exactly bound")

    by_name = {str(item["name"]): item for item in prepared}
    required = {"finalize-log", "finalize-metric"}
    if status != "failed":
        required.add("finalize-event")
    if not required.issubset(by_name) or (
        status == "failed" and "finalize-event" in by_name
    ):
        _fail("cross-flow finalize sidecar evidence is incomplete")
    for name in required:
        item = by_name[name]
        zone, prefix = _FINALIZE_SIDECARS[name]
        relative = str(item["relative"])
        if item["zone"] != zone or not relative.startswith(prefix):
            _fail("cross-flow finalize sidecar has invalid binding")
    if trace["output_hash"] != by_name["finalize-log"]["sha256"]:
        _fail("cross-flow finalize output hash is not the exact domain log")
    decision = by_name.get(_FINALIZE_DECISION)
    if decision is not None:
        relative = str(decision["relative"])
        state_parts = PurePosixPath(str(decision["state_ref"])).parts
        relative_parts = PurePosixPath(relative).parts
        if (
            source_flow != "lint"
            or status == "failed"
            or decision["zone"] != "review"
            or state_parts[-len(relative_parts) :] != relative_parts
            or not relative.startswith("lintprop-")
            or not relative.endswith(".lint.json")
        ):
            _fail("cross-flow finalize decision precondition is invalid")


def _validate_cross_flow_finalize_sources(
    *,
    flow_id: str,
    base_state: Mapping[str, object],
    base_artifacts: Mapping[str, Mapping[str, object]],
    base_steps: Mapping[str, str],
    latest_producer_step: str | None,
    prepared: Sequence[Mapping[str, object]],
) -> None:
    provided = {
        str(item["name"]): item
        for item in prepared
        if str(item["name"]) not in _FINALIZE_SIDECARS
        and str(item["name"]) != _FINALIZE_DECISION
    }
    if flow_id in {
        "project",
        "entities",
        "plan",
        "book",
        "report",
        "memory",
        "mentor",
        "grill-me",
        "lint",
        "ambient",
        "bundle",
    }:
        if latest_producer_step is None:
            _fail("cross-flow finalize lacks a producer step")
        required = {
            name
            for name, step_id in base_steps.items()
            if step_id == latest_producer_step
        }
        if not required or set(provided) != required:
            _fail(
                "cross-flow finalize source bundle is not the complete latest producer step"
            )
        for name in sorted(required):
            expected = base_artifacts.get(name)
            current = provided[name]
            if expected is None:
                _fail("cross-flow finalize source bundle lacks committed evidence")
            if dict(current) == dict(expected):
                continue
            # A book review is intentionally mutable while the run waits for a
            # human decision. Finalize validates the semantic transition and
            # supplies the current canonical hash; RunStore permits that one
            # hash rebind while retaining the exact producer name/path.
            if flow_id != "book" or not name.startswith("book-review-"):
                _fail(
                    "cross-flow finalize source is not the exact latest producer artifact"
                )
            if {key: value for key, value in current.items() if key != "sha256"} != {
                key: value for key, value in expected.items() if key != "sha256"
            } or current.get("sha256") == expected.get("sha256"):
                _fail("book review decision rebind changes more than canonical bytes")
        return

    if flow_id == "ask":
        has_review = "review" in base_artifacts
        has_plan = "plan" in base_artifacts
        if has_review != has_plan:
            _fail("ask finalize base evidence has an incomplete file-back proposal")
        required = {"ask-result"}
        if has_review:
            required.update({"review", "plan"})
    else:
        required = set(_FINALIZE_SOURCE_ROLES.get(flow_id, ()))
    if not required:
        _fail("cross-flow finalize source flow is unsupported")

    state_refs = base_state.get("artifacts")
    if not isinstance(state_refs, Mapping) or set(provided) != required:
        _fail("cross-flow finalize source artifact roles are not exact")
    for name in sorted(required):
        expected = base_artifacts.get(name)
        if (
            expected is None
            or state_refs.get(name) != expected.get("state_ref")
            or dict(provided[name]) != dict(expected)
        ):
            _fail(
                "cross-flow finalize source evidence is not the committed base artifact"
            )


def validate_receipt(payload: Mapping[str, object]) -> dict[str, object]:
    if not isinstance(payload, Mapping) or set(payload) != _RECEIPT_KEYS:
        _fail("receipt has missing or unknown fields")
    if (
        type(payload["schema_version"]) is not int
        or payload["schema_version"] != RECEIPT_SCHEMA_VERSION
    ):
        _fail("unsupported receipt schema_version")
    _plain_string(payload["receipt_id"], "receipt_id", pattern=_CANONICAL_ID)
    _plain_string(payload["run_id"], "receipt.run_id", pattern=_RUN_ID)
    _plain_string(payload["event_id"], "receipt.event_id", pattern=_CANONICAL_ID)
    if payload["status"] not in {"delivered", "failed"}:
        _fail("receipt status is invalid")
    _hash(payload["effect_hash"], "receipt.effect_hash")
    _timestamp(payload["at"], "receipt.at")
    return dict(payload)


class RunStore:
    """Filesystem implementation of the portable run envelope."""

    def __init__(
        self,
        resolver: VaultPathResolver,
        *,
        clock: Callable[[], datetime] | None = None,
        max_trace_bytes: int = _DEFAULT_MAX_TRACE_BYTES,
    ) -> None:
        if type(max_trace_bytes) is not int or max_trace_bytes < _MAX_TRACE_LINE_BYTES:
            raise RunError("max_trace_bytes is invalid")
        self._resolver = resolver
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._max_trace_bytes = max_trace_bytes
        self._active_run_identities: dict[str, tuple[int, int]] = {}
        self._active_run_fds: dict[str, int] = {}
        self._active_trace_identities: dict[str, tuple[int, int]] = {}

    def _now(self) -> str:
        value = self._clock()
        if not isinstance(value, datetime) or value.tzinfo is None:
            _fail("clock must return an aware datetime")
        return (
            value.astimezone(timezone.utc)
            .isoformat(timespec="microseconds")
            .replace("+00:00", "Z")
        )

    def _run_dir(self, run_id: str, *, for_write: bool, must_exist: bool) -> Path:
        checked = _plain_string(run_id, "run_id", pattern=_RUN_ID)
        try:
            path = self._resolver.resolve(
                "agent/runs", checked, for_write=for_write, must_exist=must_exist
            )
        except VaultSchemaError:
            raise RunError("run path is unsafe") from None
        if path.exists() and (path.is_symlink() or not path.is_dir()):
            _fail("run path must be a real directory")
        return path

    def _open_run_dir(self, run_id: str, run_dir: Path, *, for_write: bool) -> int:
        flags = os.O_RDONLY
        if hasattr(os, "O_DIRECTORY"):
            flags |= os.O_DIRECTORY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            directory_fd = os.open(run_dir, flags)
            opened = os.fstat(directory_fd)
            named = os.stat(run_dir, follow_symlinks=False)
            if not stat.S_ISDIR(opened.st_mode) or (opened.st_dev, opened.st_ino) != (
                named.st_dev,
                named.st_ino,
            ):
                _fail("run directory changed while it was opened")
            self._resolver.revalidate(
                run_dir,
                "agent/runs",
                run_id,
                for_write=for_write,
                must_exist=True,
            )
            return directory_fd
        except (OSError, VaultSchemaError, RunError):
            if "directory_fd" in locals():
                os.close(directory_fd)
            raise RunError("run directory cannot be anchored safely") from None

    def _revalidate_open_run_dir(
        self, directory_fd: int, run_dir: Path, run_id: str, *, for_write: bool
    ) -> None:
        try:
            opened = os.fstat(directory_fd)
            named = os.stat(run_dir, follow_symlinks=False)
            self._resolver.revalidate(
                run_dir,
                "agent/runs",
                run_id,
                for_write=for_write,
                must_exist=True,
            )
        except (OSError, VaultSchemaError):
            raise RunError("run directory changed during the operation") from None
        if not stat.S_ISDIR(opened.st_mode) or (opened.st_dev, opened.st_ino) != (
            named.st_dev,
            named.st_ino,
        ):
            _fail("run directory changed during the operation")

    def _open_zone_directory(
        self, symbolic_zone: str, relative: str, *, create: bool
    ) -> tuple[int, Path, tuple[int, int]]:
        """Open a managed child directory without following mutable parents."""

        checked = PurePosixPath(_safe_ref(relative, "managed directory"))
        try:
            base = self._resolver.resolve(
                symbolic_zone, for_write=True, must_exist=True
            )
            base_fd = os.open(
                base,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
            opened_base = os.fstat(base_fd)
            named_base = os.stat(base, follow_symlinks=False)
            if not stat.S_ISDIR(opened_base.st_mode) or (
                opened_base.st_dev,
                opened_base.st_ino,
            ) != (named_base.st_dev, named_base.st_ino):
                _fail("managed zone changed while it was opened")
            self._resolver.revalidate(
                base,
                symbolic_zone,
                for_write=True,
                must_exist=True,
            )
        except (OSError, VaultSchemaError, RunError):
            if "base_fd" in locals():
                os.close(base_fd)
            raise RunError("managed zone cannot be anchored safely") from None

        current_fd = base_fd
        try:
            for part in checked.parts:
                if create:
                    try:
                        os.mkdir(part, mode=0o700, dir_fd=current_fd)
                        os.fsync(current_fd)
                    except FileExistsError:
                        pass
                    except OSError:
                        raise RunError("managed directory cannot be created") from None
                child_fd: int | None = None
                try:
                    child_fd = os.open(
                        part,
                        os.O_RDONLY
                        | getattr(os, "O_DIRECTORY", 0)
                        | getattr(os, "O_NOFOLLOW", 0),
                        dir_fd=current_fd,
                    )
                    named = os.stat(part, dir_fd=current_fd, follow_symlinks=False)
                    opened = os.fstat(child_fd)
                    if not stat.S_ISDIR(opened.st_mode) or (
                        opened.st_dev,
                        opened.st_ino,
                    ) != (named.st_dev, named.st_ino):
                        os.close(child_fd)
                        child_fd = None
                        _fail("managed directory changed while it was opened")
                except (OSError, RunError):
                    if child_fd is not None:
                        os.close(child_fd)
                    raise RunError(
                        "managed directory cannot be anchored safely"
                    ) from None
                if current_fd != base_fd:
                    os.close(current_fd)
                current_fd = child_fd

            path = self._resolver.resolve(
                symbolic_zone,
                checked,
                for_write=True,
                must_exist=True,
            )
            opened = os.fstat(current_fd)
            named = os.stat(path, follow_symlinks=False)
            identity = (opened.st_dev, opened.st_ino)
            if identity != (named.st_dev, named.st_ino):
                _fail("managed directory changed during traversal")
            return current_fd, path, identity
        except (OSError, VaultSchemaError, RunError):
            if current_fd != base_fd:
                os.close(current_fd)
            raise RunError("managed directory cannot be anchored safely") from None
        finally:
            os.close(base_fd)

    def _revalidate_zone_directory(
        self,
        directory_fd: int,
        path: Path,
        identity: tuple[int, int],
        symbolic_zone: str,
        relative: str,
    ) -> None:
        try:
            opened = os.fstat(directory_fd)
            named = os.stat(path, follow_symlinks=False)
            self._resolver.revalidate(
                path,
                symbolic_zone,
                relative,
                for_write=True,
                must_exist=True,
            )
        except (OSError, VaultSchemaError):
            raise RunError("managed directory changed during the write") from None
        if (
            not stat.S_ISDIR(opened.st_mode)
            or (opened.st_dev, opened.st_ino) != identity
            or (named.st_dev, named.st_ino) != identity
        ):
            _fail("managed directory changed during the write")

    def _open_stable_lock(
        self, run_id: str, *, create: bool
    ) -> tuple[int, int, str, tuple[int, int]]:
        locks_fd, _locks_path, _locks_identity = self._open_zone_directory(
            "agent/runs", ".locks", create=create
        )
        name = hashlib.sha256(run_id.encode("ascii")).hexdigest() + ".lock"
        try:
            if create:
                _create_bytes_once_at(locks_fd, name, b"")
            lock_fd = os.open(
                name,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=locks_fd,
            )
            opened = os.fstat(lock_fd)
            named = os.stat(name, dir_fd=locks_fd, follow_symlinks=False)
            identity = (opened.st_dev, opened.st_ino)
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_size != 0
                or identity != (named.st_dev, named.st_ino)
            ):
                _fail("run lock evidence is invalid")
            return locks_fd, lock_fd, name, identity
        except (OSError, RunError):
            if "lock_fd" in locals():
                os.close(lock_fd)
            os.close(locks_fd)
            raise RunError("run lock cannot be anchored safely") from None

    def _open_runs_namespace_guard(self) -> int:
        try:
            root = self._resolver.resolve("agent/runs", for_write=True, must_exist=True)
            guard_fd = os.open(
                root,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
            opened = os.fstat(guard_fd)
            named = os.stat(root, follow_symlinks=False)
            if not stat.S_ISDIR(opened.st_mode) or (opened.st_dev, opened.st_ino) != (
                named.st_dev,
                named.st_ino,
            ):
                _fail("runs namespace changed while opened")
            self._resolver.revalidate(
                root, "agent/runs", for_write=True, must_exist=True
            )
            return guard_fd
        except (OSError, VaultSchemaError, RunError):
            if "guard_fd" in locals():
                os.close(guard_fd)
            raise RunError("runs namespace cannot be anchored safely") from None

    @staticmethod
    def _bind_local_lock(
        run_fd: int,
        locks_fd: int,
        lock_name: str,
        lock_identity: tuple[int, int],
        *,
        create: bool,
    ) -> None:
        local_name = ".run-lock"
        try:
            local = os.stat(local_name, dir_fd=run_fd, follow_symlinks=False)
        except FileNotFoundError:
            if not create:
                _fail("run-local lock evidence is missing")
            try:
                os.link(
                    lock_name,
                    local_name,
                    src_dir_fd=locks_fd,
                    dst_dir_fd=run_fd,
                    follow_symlinks=False,
                )
                os.fsync(run_fd)
                local = os.stat(local_name, dir_fd=run_fd, follow_symlinks=False)
            except (FileExistsError, OSError):
                raise RunError("run-local lock evidence cannot be created") from None
        except OSError:
            raise RunError("run-local lock evidence cannot be inspected") from None
        if (
            not stat.S_ISREG(local.st_mode)
            or local.st_size != 0
            or (local.st_dev, local.st_ino) != lock_identity
        ):
            _fail("run-local lock evidence disagrees with the stable lock")

    @contextmanager
    def _locked(self, run_id: str, *, create: bool = False) -> Iterator[Path]:
        checked_run_id = _plain_string(run_id, "run_id", pattern=_RUN_ID)
        guard_fd = self._open_runs_namespace_guard()
        try:
            fcntl.flock(guard_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(guard_fd)
            raise RunLockBusy("run namespace already has an active writer") from None
        try:
            locks_fd, lock_fd, lock_name, lock_identity = self._open_stable_lock(
                checked_run_id, create=create
            )
        except BaseException:
            fcntl.flock(guard_fd, fcntl.LOCK_UN)
            os.close(guard_fd)
            raise
        registered = False
        identity: tuple[int, int] | None = None
        try:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise RunLockBusy("run already has an active writer") from None
            if create:
                directory_fd, run_dir, _ = self._open_zone_directory(
                    "agent/runs", checked_run_id, create=True
                )
            else:
                run_dir = self._run_dir(checked_run_id, for_write=True, must_exist=True)
                directory_fd = self._open_run_dir(
                    checked_run_id, run_dir, for_write=True
                )
            self._bind_local_lock(
                directory_fd,
                locks_fd,
                lock_name,
                lock_identity,
                create=create,
            )
            opened = os.fstat(directory_fd)
            identity = (opened.st_dev, opened.st_ino)
            self._active_run_identities[str(run_dir)] = identity
            self._active_run_fds[str(run_dir)] = directory_fd
            try:
                trace = os.stat(
                    "trace.jsonl", dir_fd=directory_fd, follow_symlinks=False
                )
            except FileNotFoundError:
                pass
            else:
                if not stat.S_ISREG(trace.st_mode):
                    _fail("trace must be a regular file")
                self._active_trace_identities[str(run_dir)] = (
                    trace.st_dev,
                    trace.st_ino,
                )
            registered = True
            yield run_dir
        finally:
            if registered and self._active_run_identities.get(str(run_dir)) == identity:
                self._active_run_identities.pop(str(run_dir), None)
                self._active_run_fds.pop(str(run_dir), None)
                self._active_trace_identities.pop(str(run_dir), None)
            try:
                if "directory_fd" in locals():
                    os.close(directory_fd)
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(lock_fd)
                os.close(locks_fd)
                fcntl.flock(guard_fd, fcntl.LOCK_UN)
                os.close(guard_fd)

    def _load_state(self, run_dir: Path) -> dict[str, object]:
        active_fd = self._active_run_fds.get(str(run_dir))
        if active_fd is None:
            _fail("state read requires an anchored run lock")
        return validate_state(_read_json_at(active_fd, "state.json"))

    def _write_state(self, run_dir: Path, state: Mapping[str, object]) -> None:
        active_fd = self._active_run_fds.get(str(run_dir))
        if active_fd is None:
            _fail("state write requires an anchored run lock")
        self._revalidate_run_path(run_dir, state["run_id"])
        _atomic_json_at(active_fd, "state.json", state)
        self._revalidate_run_path(run_dir, state["run_id"])

    def _open_intents(self, run_dir: Path) -> int:
        run_fd = self._active_run_fds.get(str(run_dir))
        if run_fd is None:
            _fail("intent access requires an anchored run lock")
        try:
            return os.open(
                "intents",
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=run_fd,
            )
        except OSError:
            raise RunError("intent directory is missing or unsafe") from None

    def _revalidate_intents(self, run_dir: Path, intents_fd: int) -> None:
        run_fd = self._active_run_fds.get(str(run_dir))
        if run_fd is None:
            _fail("intent validation requires an anchored run lock")
        try:
            opened = os.fstat(intents_fd)
            named = os.stat("intents", dir_fd=run_fd, follow_symlinks=False)
        except OSError:
            raise RunError("intent directory changed during the transaction") from None
        if not stat.S_ISDIR(opened.st_mode) or (opened.st_dev, opened.st_ino) != (
            named.st_dev,
            named.st_ino,
        ):
            _fail("intent directory changed during the transaction")

    def _revalidate_run_file(self, run_dir: Path, name: str, file_fd: int) -> None:
        run_fd = self._active_run_fds.get(str(run_dir))
        if run_fd is None:
            _fail("run file validation requires an anchored run lock")
        try:
            opened = os.fstat(file_fd)
            named = os.stat(name, dir_fd=run_fd, follow_symlinks=False)
        except OSError:
            raise RunError("run file changed during the transaction") from None
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (
            named.st_dev,
            named.st_ino,
        ):
            _fail("run file changed during the transaction")
        if name == "trace.jsonl":
            expected = self._active_trace_identities.get(str(run_dir))
            if expected is not None and (opened.st_dev, opened.st_ino) != expected:
                _fail("trace changed during the transaction")

    def _capture_trace_identity(self, run_dir: Path) -> None:
        run_fd = self._active_run_fds.get(str(run_dir))
        if run_fd is None:
            _fail("trace identity requires an anchored run lock")
        try:
            metadata = os.stat("trace.jsonl", dir_fd=run_fd, follow_symlinks=False)
        except OSError:
            raise RunError("trace identity cannot be captured") from None
        if not stat.S_ISREG(metadata.st_mode):
            _fail("trace must be a regular file")
        self._active_trace_identities[str(run_dir)] = (
            metadata.st_dev,
            metadata.st_ino,
        )

    def _quarantine_publication(
        self,
        run_dir: Path,
        source_fd: int,
        source_name: str,
        identity: tuple[int, int],
        *,
        kind: str,
    ) -> bool:
        """Move a late publication aside without a check-then-unlink race.

        Recovery files are intentionally retained under the authoritative run.
        Deleting a pathname after checking its inode cannot be made conditional
        with portable POSIX APIs; retained evidence is safer than deleting a
        concurrently substituted foreign leaf.
        """

        run_fd = self._active_run_fds.get(str(run_dir))
        if run_fd is None:
            _fail("publication quarantine requires an anchored run lock")
        try:
            os.mkdir("rollback", mode=0o700, dir_fd=run_fd)
            os.fsync(run_fd)
        except FileExistsError:
            pass
        except OSError:
            return False
        try:
            rollback_fd = os.open(
                "rollback",
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=run_fd,
            )
        except OSError:
            return False
        recovery_name = f"{kind}-{uuid.uuid4().hex}.recovery"
        try:
            os.rename(
                source_name,
                recovery_name,
                src_dir_fd=source_fd,
                dst_dir_fd=rollback_fd,
            )
            os.fsync(source_fd)
            os.fsync(rollback_fd)
            moved = os.stat(recovery_name, dir_fd=rollback_fd, follow_symlinks=False)
            if (moved.st_dev, moved.st_ino) == identity:
                return True
            try:
                os.link(
                    recovery_name,
                    source_name,
                    src_dir_fd=rollback_fd,
                    dst_dir_fd=source_fd,
                    follow_symlinks=False,
                )
                os.fsync(source_fd)
            except OSError:
                pass
            return False
        except OSError:
            return False
        finally:
            os.close(rollback_fd)

    def create(
        self,
        *,
        run_id: str,
        flow: str,
        phase: str,
        authority: str,
        executor: str,
        input_data: Mapping[str, object],
        artifacts: Mapping[str, str] | None = None,
    ) -> dict[str, object]:
        _plain_string(run_id, "run_id", pattern=_RUN_ID)
        now = self._now()
        state = validate_state(
            {
                "schema_version": STATE_SCHEMA_VERSION,
                "run_id": run_id,
                "flow": flow,
                "status": "created",
                "phase": phase,
                "authority": authority,
                "executor": executor,
                "input": dict(input_data),
                "artifacts": dict(artifacts or {}),
                "attempt": 1,
                "created_at": now,
                "updated_at": now,
                "waiting_for": None,
                "last_error": None,
            }
        )
        with self._locked(run_id, create=True) as run_dir:
            run_fd = self._active_run_fds[str(run_dir)]
            try:
                os.stat("state.json", dir_fd=run_fd, follow_symlinks=False)
                state_exists = True
            except FileNotFoundError:
                state_exists = False
            if state_exists:
                _fail("run already exists")
            unknown = {
                name
                for name in os.listdir(run_fd)
                if name not in {".run-lock", "intents", "trace.jsonl"}
            }
            if unknown:
                _fail("incomplete run directory contains unknown data")
            try:
                os.mkdir("intents", mode=0o700, dir_fd=run_fd)
                os.fsync(run_fd)
            except FileExistsError:
                pass
            except OSError:
                raise RunError("intent directory cannot be created") from None
            intents_fd = self._open_intents(run_dir)
            try:
                self._revalidate_intents(run_dir, intents_fd)
                if os.listdir(intents_fd):
                    _fail("incomplete run directory has non-empty intents")
            finally:
                os.close(intents_fd)
            if not _create_bytes_once_at(run_fd, "trace.jsonl", b""):
                trace_fd = os.open(
                    "trace.jsonl",
                    os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=run_fd,
                )
                try:
                    trace = os.fstat(trace_fd)
                    if not stat.S_ISREG(trace.st_mode) or trace.st_size != 0:
                        _fail("incomplete run trace is not empty")
                finally:
                    os.close(trace_fd)
            self._capture_trace_identity(run_dir)
            self._revalidate_run_path(run_dir, run_id)
            if not _create_json_once_at(run_fd, "state.json", state):
                _fail("run state appeared during create")
            self._revalidate_run_path(run_dir, run_id)
        return dict(state)

    def status(self, run_id: str) -> dict[str, object]:
        """Read only ``state.json``; trace/projection corruption is irrelevant."""

        run_dir = self._run_dir(run_id, for_write=False, must_exist=True)
        directory_fd = self._open_run_dir(run_id, run_dir, for_write=False)
        try:
            state = validate_state(_read_json_at(directory_fd, "state.json"))
            self._revalidate_open_run_dir(
                directory_fd, run_dir, run_id, for_write=False
            )
            return state
        finally:
            os.close(directory_fd)

    def snapshot(
        self,
        run_id: str,
        *,
        artifact_names: Sequence[str] | None = None,
    ) -> RunSnapshot:
        """Return a reconciled state hash and exact current committed artifacts.

        ``artifact_names`` is an explicit recovery projection. It is used when a
        terminal failed run must replay its finalize evidence while the corrupt
        producer artifact which caused that failure remains corrupt.
        """

        selected: frozenset[str] | None = None
        if artifact_names is not None:
            checked_names = tuple(
                _plain_string(name, "artifact name", pattern=_CANONICAL_ID)
                for name in artifact_names
            )
            if not checked_names or len(checked_names) != len(set(checked_names)):
                _fail("snapshot artifact selection is empty or duplicated")
            selected = frozenset(checked_names)

        with self._locked(run_id) as run_dir:
            self._reconcile_locked(run_dir)
            self._require_trace_matches_committed_intents(run_dir, run_id)
            state = self._load_state(run_dir)
            intents_fd = self._open_intents(run_dir)
            intents: dict[str, dict[str, object]] = {}
            try:
                self._revalidate_intents(run_dir, intents_fd)
                for name in sorted(os.listdir(intents_fd)):
                    if not name.endswith(".json"):
                        _fail("intent directory contains an unsafe entry")
                    intent = self._validate_intent(
                        _read_json_at(intents_fd, name, "intent")
                    )
                    if intent["status"] != "committed":
                        _fail("snapshot found an unreconciled intent")
                    intents[str(intent["step_id"])] = intent
                self._revalidate_intents(run_dir, intents_fd)
            finally:
                os.close(intents_fd)

            latest: dict[str, tuple[str, dict[str, object]]] = {}
            for trace in self._trace_events(run_dir, expected_run_id=run_id):
                step_id = str(trace["step_id"])
                intent = intents.get(step_id)
                if intent is None:
                    _fail("trace lacks committed artifact evidence")
                for item in intent["prepared_artifacts"]:
                    if not isinstance(item, Mapping):
                        _fail("committed artifact evidence is invalid")
                    latest[str(item["name"])] = (step_id, dict(item))

            current_refs = state["artifacts"]
            if not isinstance(current_refs, Mapping):
                _fail("state artifact evidence is invalid")
            if selected is not None and not selected.issubset(current_refs):
                _fail("snapshot artifact selection is not committed in state")
            checked_items: list[dict[str, object]] = []
            committed: list[CommittedArtifact] = []
            for name, state_ref in sorted(current_refs.items()):
                evidence = latest.get(str(name))
                if evidence is None:
                    _fail("state artifact lacks committed intent evidence")
                step_id, item = evidence
                if item["state_ref"] != state_ref:
                    _fail("state artifact disagrees with its latest committed evidence")
                if selected is not None and name not in selected:
                    continue
                checked_items.append(item)
                committed.append(
                    CommittedArtifact(
                        name=str(item["name"]),
                        zone=str(item["zone"]),
                        relative=str(item["relative"]),
                        state_ref=str(item["state_ref"]),
                        sha256=str(item["sha256"]),
                        step_id=step_id,
                    )
                )
            self._verify_prepared(checked_items)
            self._revalidate_run_path(run_dir, run_id)
            return RunSnapshot(
                state=dict(state),
                state_sha256=_digest(state),
                artifacts=tuple(committed),
            )

    def producer_snapshot(self, run_id: str, *, producer_evidence: str) -> RunSnapshot:
        """Return the complete latest non-finalize producer bundle.

        The named evidence selects the bundle, never an arbitrary subset. A
        resumed book review may have gained a canonical human decision; only
        that review hash is refreshed here and its semantic lineage is checked
        by the book adapter before a finalize commit is attempted.
        """

        checked_evidence = _plain_string(
            producer_evidence, "producer evidence", pattern=_CANONICAL_ID
        )
        with self._locked(run_id) as run_dir:
            self._reconcile_locked(run_dir)
            index = self._require_trace_matches_committed_intents(run_dir, run_id)
            state = self._load_state(run_dir)
            step_id = index.latest_producer_step
            if step_id is None or index.steps.get(checked_evidence) != step_id:
                _fail("producer evidence is not part of the latest producer step")
            names = tuple(
                sorted(
                    name
                    for name, item_step in index.steps.items()
                    if item_step == step_id
                )
            )
            if not names:
                _fail("latest producer step has no committed artifacts")
            state_refs = state.get("artifacts")
            if not isinstance(state_refs, Mapping):
                _fail("state artifact evidence is invalid")

            try:
                runs_root = self._resolver.resolve("agent/runs", must_exist=True)
                configured_runs = self._resolver.config.zone("runs")
            except (VaultSchemaError, ValueError):
                raise RunError("vault root cannot be derived safely") from None
            vault_root = runs_root
            for _ in configured_runs.parts:
                vault_root = vault_root.parent

            artifacts: list[CommittedArtifact] = []
            verified: list[Mapping[str, object]] = []
            changed_book_reviews = 0
            for name in names:
                source = index.artifacts[name]
                if state_refs.get(name) != source.get("state_ref"):
                    _fail("producer bundle disagrees with current run state")
                item = dict(source)
                digest, path = self._sha256_zone_file(
                    str(item["zone"]), str(item["relative"])
                )
                if digest != item["sha256"]:
                    if (
                        state.get("flow") != "book"
                        or state.get("status") != "running"
                        or state.get("phase") != "review"
                        or not name.startswith("book-review-")
                    ):
                        _fail("producer artifact bytes changed after commit")
                    item["sha256"] = digest
                    changed_book_reviews += 1
                try:
                    expected_ref = path.relative_to(vault_root).as_posix()
                except ValueError:
                    _fail("producer artifact is outside the vault")
                if expected_ref != item["state_ref"]:
                    _fail("producer artifact reference changed")
                verified.append(item)
                artifacts.append(
                    CommittedArtifact(
                        name=name,
                        zone=str(item["zone"]),
                        relative=str(item["relative"]),
                        state_ref=str(item["state_ref"]),
                        sha256=str(item["sha256"]),
                        step_id=step_id,
                    )
                )
            if changed_book_reviews > 1:
                _fail("book producer bundle has multiple mutable reviews")
            self._verify_prepared(verified)
            self._revalidate_run_path(run_dir, run_id)
            return RunSnapshot(
                state=dict(state),
                state_sha256=_digest(state),
                artifacts=tuple(artifacts),
            )

    def prepare_run_artifact(
        self,
        run_id: str,
        *,
        name: str,
        data: bytes,
        maximum_bytes: int = _MAX_JSON_BYTES,
    ) -> PreparedArtifact:
        """Publish one replay-safe run-local artifact for a later semantic step."""

        checked_name = _plain_string(name, "artifact name", pattern=_CANONICAL_ID)
        if (
            not isinstance(data, bytes)
            or not data
            or type(maximum_bytes) is not int
            or maximum_bytes < 1
            or maximum_bytes > 4 * 1024 * 1024
            or len(data) > maximum_bytes
        ):
            _fail("run artifact bytes are invalid or too large")
        filename = f"{checked_name}.json"
        with self._locked(run_id) as run_dir:
            self._reconcile_locked(run_dir)
            state = self._load_state(run_dir)
            if state["status"] != "running":
                _fail("run artifact preparation requires a running run")
            run_fd = self._active_run_fds.get(str(run_dir))
            if run_fd is None:
                _fail("run artifact preparation requires an anchored run")
            created = _create_bytes_once_at(run_fd, filename, data)
            if not created:
                existing = _read_regular_bounded_at(
                    run_fd, filename, maximum_bytes, "run artifact"
                )
                if existing != data:
                    _fail("run artifact replay disagrees with existing bytes")
            self._revalidate_run_path(run_dir, run_id)
        digest = hashlib.sha256(data).hexdigest()
        relative = f"{run_id}/{filename}"
        return PreparedArtifact(
            name=checked_name,
            zone="agent/runs",
            relative=relative,
            state_ref=f"agent/runs/{relative}",
            sha256=digest,
        )

    def trace_events(self, run_id: str) -> tuple[dict[str, object], ...]:
        """Validate the bounded trace for diagnostics, never for resume state."""

        run_dir = self._run_dir(run_id, for_write=False, must_exist=True)
        directory_fd = self._open_run_dir(run_id, run_dir, for_write=False)
        try:
            events = tuple(
                self._trace_events(
                    run_dir, expected_run_id=run_id, directory_fd=directory_fd
                )
            )
            self._revalidate_open_run_dir(
                directory_fd, run_dir, run_id, for_write=False
            )
            return events
        finally:
            os.close(directory_fd)

    def resume(self, run_id: str, *, executor: str) -> dict[str, object]:
        executor = _plain_string(executor, "executor", pattern=_CANONICAL_ID)
        with self._locked(run_id) as run_dir:
            self._reconcile_locked(run_dir)
            state = self._load_state(run_dir)
            if state["status"] not in RESUMABLE_STATUSES:
                _fail("terminal run cannot be resumed")
            was_created = state["status"] == "created"
            state["status"] = "running"
            state["executor"] = executor
            if not was_created:
                state["attempt"] = int(state["attempt"]) + 1
            state["waiting_for"] = None
            state["last_error"] = None
            state["updated_at"] = self._now()
            checked = validate_state(state)
            self._write_state(run_dir, checked)
            return checked

    def transition(
        self,
        run_id: str,
        *,
        status: str,
        phase: str,
        waiting_for: str | None = None,
        error_kind: str | None = None,
        error_detail: str = "",
    ) -> dict[str, object]:
        if status not in STATUSES:
            _fail("invalid run status")
        phase = _plain_string(phase, "phase", pattern=_CANONICAL_ID)
        requested_error: dict[str, object] | None = None
        if error_kind is not None:
            if (
                not isinstance(error_detail, str)
                or len(error_detail.encode("utf-8")) > 1024 * 1024
            ):
                _fail("error detail must be bounded text")
            requested_error = {
                "kind": _plain_string(error_kind, "error kind", pattern=_CANONICAL_ID),
                "retryable": status in {"quota_wait", "transient_wait"},
                "detail_hash": hashlib.sha256(error_detail.encode("utf-8")).hexdigest(),
            }
        with self._locked(run_id) as run_dir:
            self._reconcile_locked(run_dir)
            state = self._load_state(run_dir)
            current = str(state["status"])
            if status == current:
                if (
                    state["phase"] == phase
                    and state["waiting_for"] == waiting_for
                    and state["last_error"] == requested_error
                ):
                    return state
                _fail("same-status replay disagrees with authoritative state")
            if status not in TRANSITIONS[current]:
                _fail("invalid run status transition")
            state["status"] = status
            state["phase"] = phase
            state["waiting_for"] = waiting_for
            state["last_error"] = requested_error
            state["updated_at"] = self._now()
            checked = validate_state(state)
            self._write_state(run_dir, checked)
            return checked

    def cancel(self, run_id: str, *, phase: str = "cancelled") -> dict[str, object]:
        phase = _plain_string(phase, "phase", pattern=_CANONICAL_ID)
        with self._locked(run_id) as run_dir:
            self._reconcile_locked(run_dir)
            state = self._load_state(run_dir)
            if state["status"] == "cancelled":
                return state
            if state["status"] in {"succeeded", "failed"}:
                _fail("completed run cannot be cancelled")
            state["status"] = "cancelled"
            state["phase"] = phase
            state["waiting_for"] = None
            state["last_error"] = None
            state["updated_at"] = self._now()
            checked = validate_state(state)
            self._write_state(run_dir, checked)
            return checked

    @staticmethod
    def _outcome_payload(outcome: ToolOutcome) -> dict[str, object]:
        if not isinstance(outcome, ToolOutcome):
            _fail("tool outcome must use ToolOutcome")
        detail = outcome.detail
        if not isinstance(detail, str) or len(detail.encode("utf-8")) > 1024 * 1024:
            _fail("tool outcome detail must be bounded text")
        return {
            "tool": outcome.tool,
            "status": outcome.status,
            "exit_code": outcome.exit_code,
            "detail_hash": hashlib.sha256(detail.encode("utf-8")).hexdigest(),
        }

    @staticmethod
    def _prepared_payload(artifact: PreparedArtifact) -> dict[str, object]:
        if not isinstance(artifact, PreparedArtifact):
            _fail("prepared artifact has invalid type")
        payload = {
            "name": _plain_string(
                artifact.name, "artifact name", pattern=_CANONICAL_ID
            ),
            "zone": _plain_string(artifact.zone, "artifact zone"),
            "relative": _safe_ref(artifact.relative, "artifact relative path"),
            "state_ref": _safe_ref(artifact.state_ref, "artifact state reference"),
            "sha256": _hash(artifact.sha256, "artifact sha256"),
        }
        return payload

    @staticmethod
    def _action_payloads(
        action_uses: Sequence[ActionUse],
        authority_policy: AuthorityPolicy | None,
    ) -> list[dict[str, object]]:
        if not action_uses:
            if authority_policy is not None and not isinstance(
                authority_policy, AuthorityPolicy
            ):
                _fail("authority policy has invalid type")
            return []
        if not isinstance(authority_policy, AuthorityPolicy):
            _fail("trace action evidence requires its issuing authority policy")
        if len(action_uses) > 16:
            _fail("trace action evidence has too many items")
        actions: list[dict[str, object]] = []
        for sequence, use in enumerate(action_uses, start=1):
            if not isinstance(use, ActionUse) or use.status not in {
                "succeeded",
                "failed",
            }:
                _fail("trace action use is invalid")
            try:
                grant = authority_policy.require(use.capability)
            except AuthorityError as error:
                raise RunError(str(error)) from None
            actions.append(
                {
                    "sequence": sequence,
                    "flow_id": grant.flow_id,
                    "action_id": grant.action_id,
                    "actor": grant.actor,
                    "authority": grant.authority,
                    "target": grant.target,
                    "access": grant.access,
                    "effect_kind": grant.effect_kind,
                    "artifact_commit": grant.artifact_commit,
                    "matrix_sha256": grant.matrix_sha256,
                    "status": use.status,
                }
            )
        return actions

    @staticmethod
    def _error_payload(
        status: str, error_kind: str | None, error_detail: str
    ) -> dict[str, object] | None:
        error_statuses = {"failed", "quota_wait", "transient_wait"}
        if status not in error_statuses:
            if error_kind is not None or error_detail:
                _fail("error evidence is invalid for the target status")
            return None
        if error_kind is None:
            _fail("failed or waiting semantic step requires error_kind")
        if not isinstance(error_detail, str):
            _fail("error detail must be bounded text")
        try:
            encoded_detail = error_detail.encode("utf-8")
        except UnicodeError:
            _fail("error detail must be valid UTF-8 text")
        if len(encoded_detail) > 1024 * 1024:
            _fail("error detail must be bounded text")
        return {
            "kind": _plain_string(error_kind, "error kind", pattern=_CANONICAL_ID),
            "retryable": status in {"quota_wait", "transient_wait"},
            "detail_hash": hashlib.sha256(encoded_detail).hexdigest(),
        }

    def commit_step(
        self,
        run_id: str,
        *,
        step_id: str,
        authority: str,
        input_hash: str,
        output_hash: str,
        next_phase: str,
        next_status: str = "running",
        waiting_for: str | None = None,
        prepared_artifacts: Sequence[PreparedArtifact] = (),
        tool_outcomes: Sequence[ToolOutcome] = (),
        expected_state_sha256: str | None = None,
        error_kind: str | None = None,
        error_detail: str = "",
        action_uses: Sequence[ActionUse] = (),
        authority_policy: AuthorityPolicy | None = None,
        after_prepare: Callable[[], None] | None = None,
        after_state: Callable[[], None] | None = None,
        after_trace: Callable[[], None] | None = None,
    ) -> dict[str, object]:
        """Commit one semantic step, recoverably across either injected crash."""

        step_id = _plain_string(step_id, "step_id", pattern=_CANONICAL_ID)
        authority = _plain_string(authority, "authority", pattern=_CANONICAL_ID)
        input_hash = _hash(input_hash, "input_hash")
        output_hash = _hash(output_hash, "output_hash")
        next_phase = _plain_string(next_phase, "next_phase", pattern=_CANONICAL_ID)
        if next_status not in STATUSES:
            _fail("next_status is invalid")
        if expected_state_sha256 is not None:
            expected_state_sha256 = _hash(
                expected_state_sha256, "expected_state_sha256"
            )
        requested_error = self._error_payload(next_status, error_kind, error_detail)
        prepared = [self._prepared_payload(item) for item in prepared_artifacts]
        if len(prepared) != len({item["name"] for item in prepared}):
            _fail("prepared artifact names must be unique")
        outcomes = [self._outcome_payload(item) for item in tool_outcomes]
        actions = self._action_payloads(action_uses, authority_policy)

        with self._locked(run_id) as run_dir:
            self._reconcile_locked(run_dir)
            committed_index = self._require_trace_matches_committed_intents(
                run_dir, run_id
            )
            base_artifacts = committed_index.artifacts
            intent_name = f"{step_id}.json"
            intents_fd = self._open_intents(run_dir)
            try:
                self._revalidate_intents(run_dir, intents_fd)
                try:
                    os.stat(intent_name, dir_fd=intents_fd, follow_symlinks=False)
                    intent_exists = True
                except FileNotFoundError:
                    intent_exists = False
                state = self._load_state(run_dir)
                if intent_exists:
                    intent = self._validate_intent(
                        _read_json_at(intents_fd, intent_name, "intent")
                    )
                    self._revalidate_intents(run_dir, intents_fd)
                    if intent["target_state"]["authority"] != state["authority"]:
                        _fail("intent changes immutable run authority")
                    if not authority_at_most(authority, str(state["authority"])):
                        _fail("step authority exceeds the immutable run authority")
                    self._match_replay_request(
                        intent,
                        authority=authority,
                        input_hash=input_hash,
                        output_hash=output_hash,
                        next_phase=next_phase,
                        next_status=next_status,
                        waiting_for=waiting_for,
                        requested_error=requested_error,
                        prepared=prepared,
                        outcomes=outcomes,
                        actions=actions,
                        expected_state_sha256=expected_state_sha256,
                    )
                    self._apply_intent(run_dir, intents_fd, intent_name, intent)
                    return self._load_state(run_dir)

                if state["status"] != "running":
                    _fail("semantic step requires a running run")
                if (
                    expected_state_sha256 is not None
                    and _digest(state) != expected_state_sha256
                ):
                    _fail("run state changed after the caller snapshot")
                if authority not in _allowed_authorities(str(state["flow"])):
                    _fail("step authority is outside the flow contract")
                if not authority_at_most(authority, str(state["authority"])):
                    _fail("step authority exceeds the immutable run authority")
                if (
                    next_status != "running"
                    and next_status not in TRANSITIONS["running"]
                ):
                    _fail("semantic step has invalid target status")
                target = dict(state)
                target["phase"] = next_phase
                target["status"] = next_status
                target["waiting_for"] = waiting_for
                target["last_error"] = requested_error
                target["updated_at"] = self._now()
                target_artifacts = dict(target["artifacts"])
                for item in prepared:
                    target_artifacts[str(item["name"])] = str(item["state_ref"])
                target["artifacts"] = target_artifacts
                target = validate_state(target)
                trace_payload: dict[str, object] = {
                    "schema_version": (
                        TRACE_ACTION_SCHEMA_VERSION if actions else TRACE_SCHEMA_VERSION
                    ),
                    "at": target["updated_at"],
                    "run_id": run_id,
                    "step_id": step_id,
                    "authority": authority,
                    "input_hash": input_hash,
                    "output_hash": output_hash,
                    "executor_profile": state["executor"],
                    "tool_outcomes": outcomes,
                }
                if actions:
                    trace_payload["actions"] = actions
                trace = validate_trace_event(trace_payload)
                intent = self._validate_intent(
                    {
                        "schema_version": INTENT_SCHEMA_VERSION,
                        "run_id": run_id,
                        "step_id": step_id,
                        "status": "prepared",
                        "base_state_sha256": _digest(state),
                        "base_state": state,
                        "target_state": target,
                        "prepared_artifacts": prepared,
                        "trace_event": trace,
                    }
                )
                if (
                    next_status != "failed"
                    and actions
                    and any(action["flow_id"] != state["flow"] for action in actions)
                ):
                    _validate_cross_flow_finalize_sources(
                        flow_id=str(state["flow"]),
                        base_state=state,
                        base_artifacts=base_artifacts,
                        base_steps=committed_index.steps,
                        latest_producer_step=committed_index.latest_producer_step,
                        prepared=prepared,
                    )
                    if state["flow"] == "book":
                        self._validate_book_review_rebind(
                            base_artifacts=base_artifacts,
                            prepared=prepared,
                        )
                self._validate_lint_finalize_commit(intent)
                self._verify_prepared(prepared)
                self._revalidate_run_path(run_dir, run_id)
                self._revalidate_intents(run_dir, intents_fd)
                _atomic_json_at(intents_fd, intent_name, intent)
                self._revalidate_intents(run_dir, intents_fd)
                self._revalidate_run_path(run_dir, run_id)
                if after_prepare is not None:
                    after_prepare()
                self._apply_intent(
                    run_dir,
                    intents_fd,
                    intent_name,
                    intent,
                    after_state=after_state,
                    after_trace=after_trace,
                )
                return self._load_state(run_dir)
            finally:
                os.close(intents_fd)

    def _require_trace_matches_committed_intents(
        self, run_dir: Path, run_id: str
    ) -> _CommittedIndex:
        intents_fd = self._open_intents(run_dir)
        expected_intents: dict[str, dict[str, object]] = {}
        try:
            self._revalidate_intents(run_dir, intents_fd)
            for name in sorted(os.listdir(intents_fd)):
                if not name.endswith(".json"):
                    _fail("intent directory contains an unsafe entry")
                intent = self._validate_intent(
                    _read_json_at(intents_fd, name, "intent")
                )
                if intent["status"] != "committed":
                    _fail("prepared intent remained after reconciliation")
                trace = intent["trace_event"]
                if not isinstance(trace, dict):
                    _fail("committed intent trace is invalid")
                expected_intents[str(trace["step_id"])] = intent
            self._revalidate_intents(run_dir, intents_fd)
        finally:
            os.close(intents_fd)
        trace_events = self._trace_events(run_dir, expected_run_id=run_id)
        actual = {str(event["step_id"]): event for event in trace_events}
        expected = {
            step_id: intent["trace_event"]
            for step_id, intent in expected_intents.items()
        }
        if actual != expected:
            _fail("trace disagrees with committed semantic intents")
        latest: dict[str, dict[str, object]] = {}
        latest_steps: dict[str, str] = {}
        latest_producer_step: str | None = None
        for event in trace_events:
            step_id = str(event["step_id"])
            intent = expected_intents[str(event["step_id"])]
            target = intent["target_state"]
            prepared = intent["prepared_artifacts"]
            actions = event.get("actions", [])
            cross_flow = isinstance(actions, list) and any(
                action.get("flow_id") != target["flow"] for action in actions
            )
            if cross_flow:
                if target["status"] != "failed":
                    _validate_cross_flow_finalize_sources(
                        flow_id=str(target["flow"]),
                        base_state={
                            "artifacts": {
                                name: item["state_ref"] for name, item in latest.items()
                            }
                        },
                        base_artifacts=latest,
                        base_steps=latest_steps,
                        latest_producer_step=latest_producer_step,
                        prepared=prepared,
                    )
            else:
                latest_producer_step = step_id
            for item in prepared:
                name = str(item["name"])
                latest[name] = dict(item)
                if not cross_flow or name in _FINALIZE_SIDECARS:
                    latest_steps[name] = step_id
        return _CommittedIndex(latest, latest_steps, latest_producer_step)

    def _validate_intent(self, payload: Mapping[str, object]) -> dict[str, object]:
        if not isinstance(payload, Mapping):
            _fail("intent has missing or unknown fields")
        version = payload.get("schema_version")
        if type(version) is not int or version not in {1, INTENT_SCHEMA_VERSION}:
            _fail("unsupported intent schema_version")
        expected_keys = _INTENT_KEYS_V1 if version == 1 else _INTENT_KEYS_V2
        if set(payload) != expected_keys:
            _fail("intent has missing or unknown fields")
        _plain_string(payload["run_id"], "intent.run_id", pattern=_RUN_ID)
        _plain_string(payload["step_id"], "intent.step_id", pattern=_CANONICAL_ID)
        if payload["status"] not in {"prepared", "committed"}:
            _fail("intent status is invalid")
        _hash(payload["base_state_sha256"], "intent.base_state_sha256")
        base = None
        if version == INTENT_SCHEMA_VERSION:
            base = validate_state(payload["base_state"])
            if _digest(base) != payload["base_state_sha256"]:
                _fail("intent base state disagrees with its hash")
        target = validate_state(payload["target_state"])
        prepared = payload["prepared_artifacts"]
        if not isinstance(prepared, list) or len(prepared) > 64:
            _fail("intent prepared_artifacts must be a bounded list")
        names: list[str] = []
        for item in prepared:
            if not isinstance(item, Mapping) or set(item) != _PREPARED_KEYS:
                _fail("prepared artifact has missing or unknown fields")
            names.append(
                _plain_string(
                    item["name"], "prepared artifact name", pattern=_CANONICAL_ID
                )
            )
            _plain_string(item["zone"], "prepared artifact zone")
            _safe_ref(item["relative"], "prepared artifact relative")
            _safe_ref(item["state_ref"], "prepared artifact state_ref")
            _hash(item["sha256"], "prepared artifact sha256")
        if len(names) != len(set(names)):
            _fail("prepared artifact names must be unique")
        trace = validate_trace_event(payload["trace_event"])
        if (
            target["run_id"] != payload["run_id"]
            or trace["run_id"] != payload["run_id"]
        ):
            _fail("intent run IDs disagree")
        if base is not None:
            immutable = (
                "schema_version",
                "run_id",
                "flow",
                "authority",
                "executor",
                "input",
                "attempt",
                "created_at",
            )
            if any(base[field] != target[field] for field in immutable):
                _fail("intent target changes immutable run state from its base")
        if trace["step_id"] != payload["step_id"]:
            _fail("intent step IDs disagree")
        if trace["authority"] not in _allowed_authorities(str(target["flow"])):
            _fail("intent trace authority is outside the flow contract")
        if not authority_at_most(str(trace["authority"]), str(target["authority"])):
            _fail("intent trace authority exceeds the immutable run authority")
        if trace["at"] != target["updated_at"]:
            _fail("intent trace timestamp disagrees with target state")
        if trace["executor_profile"] != target["executor"]:
            _fail("intent trace executor disagrees with target state")
        _validate_cross_flow_finalize_intent(
            base_state_sha256=payload["base_state_sha256"],
            target=target,
            prepared=prepared,
            trace=trace,
        )
        checked = dict(payload)
        if base is not None:
            checked["base_state"] = base
        checked["target_state"] = target
        checked["prepared_artifacts"] = [dict(item) for item in prepared]
        checked["trace_event"] = trace
        _canonical_bytes(checked)
        return checked

    @staticmethod
    def _match_replay_request(
        intent: Mapping[str, object],
        *,
        authority: str,
        input_hash: str,
        output_hash: str,
        next_phase: str,
        next_status: str,
        waiting_for: str | None,
        requested_error: Mapping[str, object] | None,
        prepared: list[dict[str, object]],
        outcomes: list[dict[str, object]],
        actions: list[dict[str, object]],
        expected_state_sha256: str | None,
    ) -> None:
        trace = intent["trace_event"]
        target = intent["target_state"]
        if not isinstance(trace, Mapping) or not isinstance(target, Mapping):
            _fail("intent replay evidence is invalid")
        if (
            expected_state_sha256 is not None
            and intent["base_state_sha256"] != expected_state_sha256
        ):
            _fail("step replay disagrees with caller state precondition")
        expected = (
            trace["authority"],
            trace["input_hash"],
            trace["output_hash"],
            target["phase"],
            target["status"],
            target["waiting_for"],
            target["last_error"],
            intent["prepared_artifacts"],
            trace["tool_outcomes"],
            trace.get("actions", []),
        )
        actual = (
            authority,
            input_hash,
            output_hash,
            next_phase,
            next_status,
            waiting_for,
            requested_error,
            prepared,
            outcomes,
            actions,
        )
        if expected != actual:
            _fail("step replay disagrees with durable intent")

    def _sha256_zone_file(self, zone: str, relative: str) -> tuple[str, Path]:
        checked = PurePosixPath(_safe_ref(relative, "prepared artifact relative"))
        try:
            base = self._resolver.resolve(zone, must_exist=True)
            expected = self._resolver.resolve(zone, checked, must_exist=True)
            base_fd = os.open(
                base,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
            opened_base = os.fstat(base_fd)
            named_base = os.stat(base, follow_symlinks=False)
            if not stat.S_ISDIR(opened_base.st_mode) or (
                opened_base.st_dev,
                opened_base.st_ino,
            ) != (named_base.st_dev, named_base.st_ino):
                _fail("prepared artifact zone changed while opened")
            self._resolver.revalidate(base, zone, must_exist=True)
        except (OSError, VaultSchemaError, RunError):
            if "base_fd" in locals():
                os.close(base_fd)
            raise RunError("prepared artifact zone cannot be anchored safely") from None

        current_fd = base_fd
        file_fd: int | None = None
        try:
            for part in checked.parts[:-1]:
                child_fd = os.open(
                    part,
                    os.O_RDONLY
                    | getattr(os, "O_DIRECTORY", 0)
                    | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=current_fd,
                )
                opened = os.fstat(child_fd)
                named = os.stat(part, dir_fd=current_fd, follow_symlinks=False)
                if not stat.S_ISDIR(opened.st_mode) or (
                    opened.st_dev,
                    opened.st_ino,
                ) != (named.st_dev, named.st_ino):
                    os.close(child_fd)
                    _fail("prepared artifact parent changed while opened")
                if current_fd != base_fd:
                    os.close(current_fd)
                current_fd = child_fd
            file_fd = os.open(
                checked.parts[-1],
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=current_fd,
            )
            opened_file = os.fstat(file_fd)
            named_file = os.stat(
                checked.parts[-1], dir_fd=current_fd, follow_symlinks=False
            )
            if not stat.S_ISREG(opened_file.st_mode) or (
                opened_file.st_dev,
                opened_file.st_ino,
            ) != (named_file.st_dev, named_file.st_ino):
                _fail("prepared artifact changed while opened")
            digest = hashlib.sha256()
            while True:
                chunk = os.read(file_fd, 1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
            final_file = os.fstat(file_fd)
            final_named = os.stat(
                checked.parts[-1], dir_fd=current_fd, follow_symlinks=False
            )
            if (
                final_file.st_dev,
                final_file.st_ino,
                final_file.st_size,
                final_file.st_mtime_ns,
                final_file.st_ctime_ns,
            ) != (
                opened_file.st_dev,
                opened_file.st_ino,
                opened_file.st_size,
                opened_file.st_mtime_ns,
                opened_file.st_ctime_ns,
            ) or (final_file.st_dev, final_file.st_ino) != (
                final_named.st_dev,
                final_named.st_ino,
            ):
                _fail("prepared artifact changed while hashed")
            self._resolver.revalidate(expected, zone, checked, must_exist=True)
            return digest.hexdigest(), expected
        except (OSError, VaultSchemaError, RunError):
            raise RunError("prepared artifact cannot be read safely") from None
        finally:
            if file_fd is not None:
                os.close(file_fd)
            if current_fd != base_fd:
                os.close(current_fd)
            os.close(base_fd)

    def _read_zone_file_bounded(
        self,
        zone: str,
        relative: str,
        *,
        maximum: int = _MAX_JSON_BYTES,
    ) -> tuple[bytes, Path]:
        """Read one bounded zone file through an anchored traversal."""

        if type(maximum) is not int or maximum < 1 or maximum > 4 * 1024 * 1024:
            _fail("zone file read bound is invalid")
        checked = PurePosixPath(_safe_ref(relative, "prepared artifact relative"))
        try:
            base = self._resolver.resolve(zone, must_exist=True)
            expected = self._resolver.resolve(zone, checked, must_exist=True)
            base_fd = os.open(
                base,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
            opened_base = os.fstat(base_fd)
            named_base = os.stat(base, follow_symlinks=False)
            if not stat.S_ISDIR(opened_base.st_mode) or (
                opened_base.st_dev,
                opened_base.st_ino,
            ) != (named_base.st_dev, named_base.st_ino):
                _fail("prepared artifact zone changed while opened")
            self._resolver.revalidate(base, zone, must_exist=True)
        except (OSError, VaultSchemaError, RunError):
            if "base_fd" in locals():
                os.close(base_fd)
            raise RunError("prepared artifact zone cannot be anchored safely") from None

        current_fd = base_fd
        file_fd: int | None = None
        try:
            for part in checked.parts[:-1]:
                child_fd = os.open(
                    part,
                    os.O_RDONLY
                    | getattr(os, "O_DIRECTORY", 0)
                    | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=current_fd,
                )
                opened = os.fstat(child_fd)
                named = os.stat(part, dir_fd=current_fd, follow_symlinks=False)
                if not stat.S_ISDIR(opened.st_mode) or (
                    opened.st_dev,
                    opened.st_ino,
                ) != (named.st_dev, named.st_ino):
                    os.close(child_fd)
                    _fail("prepared artifact parent changed while opened")
                if current_fd != base_fd:
                    os.close(current_fd)
                current_fd = child_fd
            file_fd = os.open(
                checked.parts[-1],
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=current_fd,
            )
            opened_file = os.fstat(file_fd)
            named_file = os.stat(
                checked.parts[-1], dir_fd=current_fd, follow_symlinks=False
            )
            if (
                not stat.S_ISREG(opened_file.st_mode)
                or opened_file.st_size > maximum
                or (opened_file.st_dev, opened_file.st_ino)
                != (named_file.st_dev, named_file.st_ino)
            ):
                _fail("prepared artifact is not a bounded regular file")
            raw = _read_regular_bounded_fd(file_fd, maximum, "prepared artifact")
            final_file = os.fstat(file_fd)
            final_named = os.stat(
                checked.parts[-1], dir_fd=current_fd, follow_symlinks=False
            )
            if (
                final_file.st_dev,
                final_file.st_ino,
                final_file.st_size,
                final_file.st_mtime_ns,
                final_file.st_ctime_ns,
            ) != (
                opened_file.st_dev,
                opened_file.st_ino,
                opened_file.st_size,
                opened_file.st_mtime_ns,
                opened_file.st_ctime_ns,
            ) or (final_file.st_dev, final_file.st_ino) != (
                final_named.st_dev,
                final_named.st_ino,
            ):
                _fail("prepared artifact changed while read")
            self._resolver.revalidate(expected, zone, checked, must_exist=True)
            return raw, expected
        except (OSError, VaultSchemaError, RunError):
            raise RunError("prepared artifact cannot be read safely") from None
        finally:
            if file_fd is not None:
                os.close(file_fd)
            if current_fd != base_fd:
                os.close(current_fd)
            os.close(base_fd)

    def _validate_lint_finalize_commit(self, intent: Mapping[str, object]) -> None:
        """Bind a lint finalize intent to its exact public producer records."""

        target = intent.get("target_state")
        trace = intent.get("trace_event")
        prepared = intent.get("prepared_artifacts")
        if (
            not isinstance(target, Mapping)
            or target.get("flow") != "lint"
            or not isinstance(trace, Mapping)
            or not isinstance(prepared, list)
        ):
            return
        actions = trace.get("actions")
        if not isinstance(actions, list) or not any(
            isinstance(action, Mapping) and action.get("flow_id") == "finalize"
            for action in actions
        ):
            return

        by_name = {str(item["name"]): item for item in prepared}
        decision_item = by_name.get(_FINALIZE_DECISION)
        if target.get("status") == "failed":
            if decision_item is not None:
                _fail("failed lint finalize cannot carry a decision precondition")
            return
        log_item = by_name.get("finalize-log")
        source_items = [
            item
            for item in prepared
            if str(item["name"]) not in _FINALIZE_SIDECARS
            and str(item["name"]) != _FINALIZE_DECISION
        ]
        if not isinstance(log_item, Mapping) or len(source_items) != 1:
            _fail("lint finalize lacks one exact log and producer evidence record")
        source_item = source_items[0]
        if not isinstance(source_item, Mapping):
            _fail("lint finalize producer evidence is invalid")

        try:
            from tool_life_os_runtime.ext.flows.finalize.flow import (
                FinalizeError,
                parse_outcome_record,
                render_outcome_record,
            )
            from tool_life_os_runtime.ext.flows.lint import (
                LintFlowError,
                inspect_lint_run_evidence,
                parse_lint_review,
                render_lint_report,
                render_lint_review,
            )

            log_raw, _ = self._read_zone_file_bounded(
                str(log_item["zone"]), str(log_item["relative"])
            )
            if (
                hashlib.sha256(log_raw).hexdigest() != log_item["sha256"]
                or trace.get("output_hash") != log_item["sha256"]
            ):
                _fail("lint finalize log hash binding is invalid")
            outcome = parse_outcome_record(log_raw)
            if render_outcome_record(outcome) != log_raw:
                _fail("lint finalize log is not exact canonical bytes")

            evidence_raw, _ = self._read_zone_file_bounded(
                str(source_item["zone"]), str(source_item["relative"])
            )
            evidence_artifact = PreparedArtifact(
                str(source_item["name"]),
                str(source_item["zone"]),
                str(source_item["relative"]),
                str(source_item["state_ref"]),
                str(source_item["sha256"]),
            )
            evidence = inspect_lint_run_evidence(evidence_artifact, evidence_raw)
        except (ImportError, FinalizeError, LintFlowError) as error:
            raise RunError(
                "lint finalize records violate their strict public schemas"
            ) from error

        bundle_payload = {
            "artifacts": [
                {
                    "name": str(item["name"]),
                    "zone": str(item["zone"]),
                    "relative": str(item["relative"]),
                    "state_ref": str(item["state_ref"]),
                    "sha256": str(item["sha256"]),
                }
                for item in sorted(source_items, key=lambda value: str(value["name"]))
            ]
        }
        bundle_sha256 = hashlib.sha256(
            _canonical_bytes(bundle_payload) + b"\n"
        ).hexdigest()
        expected_step = (
            "lint-final-"
            + hashlib.sha256(evidence.operation_id.encode()).hexdigest()[:32]
        )
        if (
            outcome.run_id != target.get("run_id")
            or outcome.flow_id != "lint"
            or outcome.terminal_status != target.get("status")
            or outcome.source_step_id != expected_step
            or outcome.source_bundle_sha256 != bundle_sha256
            or outcome.producer_operation != f"lint-{evidence.report.mode}"
        ):
            _fail("lint finalize outcome disagrees with producer evidence")

        if evidence.proposal_ref is None:
            if decision_item is not None or any(
                value is not None
                for value in (
                    outcome.pending_kind,
                    outcome.pending_id,
                    outcome.decision_status,
                    outcome.decision_sequence,
                    outcome.decision_sha256,
                )
            ):
                _fail("direct lint finalize carries foreign decision evidence")
            return
        if not isinstance(decision_item, Mapping):
            _fail("lint proposal finalize lacks its exact decision precondition")

        try:
            decision_raw, decision_path = self._read_zone_file_bounded(
                str(decision_item["zone"]), str(decision_item["relative"])
            )
            review = parse_lint_review(decision_raw)
            if render_lint_review(review) != decision_raw:
                _fail("lint finalize decision is not exact canonical bytes")
        except LintFlowError as error:
            raise RunError(
                "lint finalize decision violates its strict schema"
            ) from error
        try:
            runs_root = self._resolver.resolve("agent/runs", must_exist=True)
            vault_root = runs_root
            for _ in self._resolver.config.zone("runs").parts:
                vault_root = vault_root.parent
            physical_ref = decision_path.relative_to(vault_root).as_posix()
        except (ValueError, VaultSchemaError):
            raise RunError("lint finalize decision is outside the vault") from None

        proposed = replace(review, status="proposed", human_decision=None)
        proposed_sha256 = hashlib.sha256(render_lint_review(proposed)).hexdigest()
        expected_findings = tuple(
            finding.finding_id
            for finding in evidence.report.findings
            if finding.resolution == "review"
        )
        sequence = (
            None if review.human_decision is None else review.human_decision.sequence
        )
        expected_pending = review.status == "proposed"
        if (
            decision_item["zone"] != "review"
            or decision_item["relative"] != f"{review.proposal_id}.lint.json"
            or decision_item["state_ref"] != physical_ref
            or decision_item["sha256"] != hashlib.sha256(decision_raw).hexdigest()
            or evidence.proposal_ref != f"review/{review.proposal_id}.lint.json"
            or evidence.proposal_sha256 != proposed_sha256
            or review.run_id != target.get("run_id")
            or review.operation_id != evidence.operation_id
            or review.mode != evidence.report.mode
            or review.report_ref != source_item["state_ref"]
            or review.report_sha256
            != hashlib.sha256(render_lint_report(evidence.report)).hexdigest()
            or review.finding_ids != expected_findings
            or outcome.decision_status != review.status
            or outcome.decision_sequence != sequence
            or outcome.decision_sha256 != decision_item["sha256"]
            or outcome.pending_kind != ("lint-proposal" if expected_pending else None)
            or outcome.pending_id != (review.proposal_id if expected_pending else None)
        ):
            _fail("lint finalize decision, producer, and outcome bindings disagree")

    def _validate_book_review_rebind(
        self,
        *,
        base_artifacts: Mapping[str, Mapping[str, object]],
        prepared: Sequence[Mapping[str, object]],
    ) -> None:
        """Allow only one strict human-decision rebind of a book proposal."""

        provided = {
            str(item["name"]): item
            for item in prepared
            if str(item["name"]) not in _FINALIZE_SIDECARS
            and str(item["name"]) != _FINALIZE_DECISION
        }
        changed = [
            name
            for name, current in provided.items()
            if name.startswith("book-review-")
            and name in base_artifacts
            and dict(current) != dict(base_artifacts[name])
        ]
        if not changed:
            return
        if len(changed) != 1:
            _fail("book finalize may rebind only one review decision")
        review_name = changed[0]
        token = review_name.removeprefix("book-review-")
        plan_name = f"book-plan-{token}"
        current_review = provided[review_name]
        original_review = base_artifacts[review_name]
        current_plan = provided.get(plan_name)
        original_plan = base_artifacts.get(plan_name)
        if (
            current_plan is None
            or original_plan is None
            or dict(current_plan) != dict(original_plan)
        ):
            _fail("book review decision requires the exact committed plan")

        review_raw, _ = self._read_zone_file_bounded(
            str(current_review["zone"]), str(current_review["relative"])
        )
        plan_raw, _ = self._read_zone_file_bounded(
            str(current_plan["zone"]), str(current_plan["relative"])
        )
        if (
            hashlib.sha256(review_raw).hexdigest() != current_review["sha256"]
            or hashlib.sha256(plan_raw).hexdigest() != current_plan["sha256"]
        ):
            _fail("book review decision bytes disagree with prepared evidence")

        try:
            from tool_life_os_runtime.ext.review.artifact import (
                ReviewArtifactError,
                parse_mutation_plan,
                parse_review_artifact,
                render_review_artifact,
                validate_artifact_plan,
            )

            review = parse_review_artifact(review_raw)
            plan = parse_mutation_plan(plan_raw)
            validate_artifact_plan(review, plan)
            if len(review.decisions) != 1 or review.application is not None:
                _fail("book review rebind requires one canonical human decision")
            proposed = replace(
                review,
                status="proposed",
                decisions=(),
                application=None,
            )
            proposed_raw = render_review_artifact(proposed).encode("utf-8")
            if render_review_artifact(review).encode("utf-8") != review_raw:
                _fail("book review decision is not canonical")
        except ReviewArtifactError as error:
            raise RunError("book review decision violates its strict schema") from error
        if hashlib.sha256(proposed_raw).hexdigest() != original_review["sha256"]:
            _fail("book review decision does not reconstruct the committed proposal")

    def _verify_prepared(self, items: Sequence[Mapping[str, object]]) -> None:
        try:
            runs_root = self._resolver.resolve("agent/runs", must_exist=True)
            configured_runs = self._resolver.config.zone("runs")
        except (VaultSchemaError, ValueError):
            raise RunError("vault root cannot be derived safely") from None
        vault_root = runs_root
        for _ in configured_runs.parts:
            vault_root = vault_root.parent
        for item in items:
            digest, path = self._sha256_zone_file(
                str(item["zone"]), str(item["relative"])
            )
            try:
                expected_ref = path.relative_to(vault_root).as_posix()
            except ValueError:
                _fail("prepared artifact is outside the vault")
            if expected_ref != item["state_ref"]:
                _fail(
                    "prepared artifact state reference disagrees with its resolved path"
                )
            if digest != item["sha256"]:
                _fail("prepared artifact hash changed before state commit")

    def _revalidate_run_path(self, run_dir: Path, run_id: object) -> None:
        try:
            current = os.stat(run_dir, follow_symlinks=False)
        except OSError:
            raise RunError("run directory changed during the transaction") from None
        expected_identity = self._active_run_identities.get(str(run_dir))
        if (
            expected_identity is None
            or not stat.S_ISDIR(current.st_mode)
            or (current.st_dev, current.st_ino) != expected_identity
        ):
            _fail("run directory changed during the transaction")
        try:
            self._resolver.revalidate(
                run_dir,
                "agent/runs",
                _plain_string(run_id, "run_id", pattern=_RUN_ID),
                for_write=True,
                must_exist=True,
            )
        except VaultSchemaError:
            raise RunError("run directory changed during the transaction") from None

    def _trace_events(
        self,
        run_dir: Path,
        *,
        expected_run_id: str,
        directory_fd: int | None = None,
    ) -> list[dict[str, object]]:
        active_fd = (
            directory_fd
            if directory_fd is not None
            else self._active_run_fds.get(str(run_dir))
        )
        if active_fd is None:
            _fail("trace read requires an anchored run directory")
        raw = _read_regular_bounded_at(
            active_fd, "trace.jsonl", self._max_trace_bytes, "trace"
        )
        return self._parse_trace_bytes(raw, expected_run_id=expected_run_id)

    @staticmethod
    def _parse_trace_bytes(
        raw: bytes, *, expected_run_id: str
    ) -> list[dict[str, object]]:
        events: list[dict[str, object]] = []
        for line in raw.splitlines():
            if not line:
                _fail("trace contains an empty record")
            try:
                item = json.loads(line, object_pairs_hook=_object_no_duplicates)
            except RunError:
                raise
            except (UnicodeError, ValueError, RecursionError):
                _fail("trace contains invalid JSON")
            if not isinstance(item, dict):
                _fail("trace event must be an object")
            checked = validate_trace_event(item)
            if checked["run_id"] != expected_run_id:
                _fail("trace event belongs to a different run")
            events.append(checked)
        step_ids = [str(item["step_id"]) for item in events]
        if len(step_ids) != len(set(step_ids)):
            _fail("trace contains duplicate semantic step IDs")
        return events

    def _repair_torn_trace_tail(self, run_dir: Path, *, expected_run_id: str) -> None:
        run_fd = self._active_run_fds.get(str(run_dir))
        if run_fd is None:
            _fail("trace recovery requires an anchored run lock")
        try:
            trace_fd = os.open(
                "trace.jsonl",
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=run_fd,
            )
        except OSError:
            raise RunError("trace cannot be opened safely") from None
        try:
            self._revalidate_run_file(run_dir, "trace.jsonl", trace_fd)
            raw = _read_regular_bounded_fd(trace_fd, self._max_trace_bytes, "trace")
            self._revalidate_run_file(run_dir, "trace.jsonl", trace_fd)
        finally:
            os.close(trace_fd)
        if not raw or raw.endswith(b"\n"):
            return
        boundary = raw.rfind(b"\n")
        prefix = raw[: boundary + 1] if boundary >= 0 else b""
        torn = raw[boundary + 1 :]
        self._parse_trace_bytes(prefix, expected_run_id=expected_run_id)
        try:
            self._parse_trace_bytes(
                prefix + torn + b"\n", expected_run_id=expected_run_id
            )
        except RunError:
            pass
        else:
            _atomic_bytes_at(run_fd, "trace.jsonl", prefix + torn + b"\n")
            self._capture_trace_identity(run_dir)
            self._revalidate_run_path(run_dir, expected_run_id)
            return
        try:
            os.mkdir("trace-recovery", mode=0o700, dir_fd=run_fd)
            os.fsync(run_fd)
        except FileExistsError:
            pass
        except OSError:
            raise RunError("trace recovery directory cannot be created") from None
        recovery_fd = os.open(
            "trace-recovery",
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=run_fd,
        )
        try:
            name = f"torn-{hashlib.sha256(torn).hexdigest()}.bin"
            try:
                os.stat(name, dir_fd=recovery_fd, follow_symlinks=False)
            except FileNotFoundError:
                _atomic_bytes_at(recovery_fd, name, torn)
            else:
                if (
                    _read_regular_bounded_at(
                        recovery_fd, name, self._max_trace_bytes, "torn trace evidence"
                    )
                    != torn
                ):
                    _fail("torn trace evidence conflicts with recovery record")
        finally:
            os.close(recovery_fd)
        _atomic_bytes_at(run_fd, "trace.jsonl", prefix)
        self._capture_trace_identity(run_dir)
        self._revalidate_run_path(run_dir, expected_run_id)

    def _append_trace_once(self, run_dir: Path, event: Mapping[str, object]) -> None:
        checked = validate_trace_event(event)
        self._repair_torn_trace_tail(run_dir, expected_run_id=str(checked["run_id"]))
        run_fd = self._active_run_fds.get(str(run_dir))
        if run_fd is None:
            _fail("trace append requires an anchored run lock")
        try:
            fd = os.open(
                "trace.jsonl",
                os.O_RDWR | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=run_fd,
            )
        except OSError:
            raise RunError("trace cannot be opened safely") from None
        try:
            self._revalidate_run_file(run_dir, "trace.jsonl", fd)
            raw = _read_regular_bounded_fd(fd, self._max_trace_bytes, "trace")
            existing = self._parse_trace_bytes(
                raw, expected_run_id=str(checked["run_id"])
            )
            self._revalidate_run_file(run_dir, "trace.jsonl", fd)
            for item in existing:
                if item["step_id"] == checked["step_id"]:
                    if item != checked:
                        _fail("semantic step ID has conflicting trace evidence")
                    return
            line = _canonical_bytes(checked) + b"\n"
            current_size = os.fstat(fd).st_size
            if current_size + len(line) > self._max_trace_bytes:
                _fail("trace append would exceed its configured bound")
            remaining = memoryview(line)
            while remaining:
                written = os.write(fd, remaining)
                if written <= 0:
                    _fail("trace append was incomplete")
                remaining = remaining[written:]
            os.fsync(fd)
            self._revalidate_run_file(run_dir, "trace.jsonl", fd)
        except OSError:
            raise RunError("trace append failed") from None
        finally:
            os.close(fd)

    def _remove_last_trace_once(
        self, run_dir: Path, event: Mapping[str, object]
    ) -> None:
        """Remove only this prepared intent's exact final trace projection."""

        checked = validate_trace_event(event)
        run_fd = self._active_run_fds.get(str(run_dir))
        if run_fd is None:
            _fail("trace rollback requires an anchored run lock")
        raw = _read_regular_bounded_at(
            run_fd, "trace.jsonl", self._max_trace_bytes, "trace"
        )
        line = _canonical_bytes(checked) + b"\n"
        if not raw.endswith(line):
            events = self._parse_trace_bytes(
                raw, expected_run_id=str(checked["run_id"])
            )
            if not any(item["step_id"] == checked["step_id"] for item in events):
                return
            _fail("prepared intent trace is not the exact final projection")
        prefix = raw[: -len(line)]
        self._parse_trace_bytes(prefix, expected_run_id=str(checked["run_id"]))
        _atomic_bytes_at(run_fd, "trace.jsonl", prefix)
        self._capture_trace_identity(run_dir)
        self._revalidate_run_path(run_dir, checked["run_id"])

    def _rollback_prepared_intent_projection(
        self,
        run_dir: Path,
        intent: Mapping[str, object],
        current: Mapping[str, object],
    ) -> None:
        base = intent.get("base_state")
        target = intent.get("target_state")
        trace = intent.get("trace_event")
        if (
            intent.get("schema_version") != INTENT_SCHEMA_VERSION
            or not isinstance(base, Mapping)
            or not isinstance(target, Mapping)
            or not isinstance(trace, Mapping)
            or _digest(base) != intent.get("base_state_sha256")
        ):
            _fail("prepared intent cannot restore its exact base state")
        if _digest(current) == _digest(base):
            return
        if _digest(current) != _digest(target):
            _fail("prepared intent rollback found a conflicting run state")
        self._remove_last_trace_once(run_dir, trace)
        self._write_state(run_dir, base)

    def _discard_invalid_lint_finalize_intent(
        self,
        run_dir: Path,
        intents_fd: int,
        intent_name: str,
        intent: Mapping[str, object],
    ) -> None:
        prepared = intent.get("prepared_artifacts")
        if (
            intent.get("schema_version") != INTENT_SCHEMA_VERSION
            or not isinstance(prepared, list)
            or not any(
                isinstance(item, Mapping) and item.get("name") == _FINALIZE_DECISION
                for item in prepared
            )
        ):
            return
        intent_fd: int | None = None
        try:
            intent_fd = os.open(
                intent_name,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=intents_fd,
            )
            opened = os.fstat(intent_fd)
            named = os.stat(intent_name, dir_fd=intents_fd, follow_symlinks=False)
            identity = (opened.st_dev, opened.st_ino)
            if not stat.S_ISREG(opened.st_mode) or identity != (
                named.st_dev,
                named.st_ino,
            ):
                _fail("invalid lint finalize intent changed before rollback")
            current = self._validate_intent(
                _decode_json(
                    _read_regular_bounded_fd(intent_fd, _MAX_JSON_BYTES, "intent"),
                    "intent",
                )
            )
            final_named = os.stat(intent_name, dir_fd=intents_fd, follow_symlinks=False)
            if current != intent or identity != (
                final_named.st_dev,
                final_named.st_ino,
            ):
                _fail("invalid lint finalize intent changed before rollback")
        except OSError:
            raise RunError("invalid lint finalize intent cannot be retired") from None
        finally:
            if intent_fd is not None:
                os.close(intent_fd)
        if not self._quarantine_publication(
            run_dir,
            intents_fd,
            intent_name,
            identity,
            kind="lint-finalize-intent",
        ):
            raise RunError("invalid lint finalize intent cannot be retired")
        self._revalidate_intents(run_dir, intents_fd)

    def _apply_intent(
        self,
        run_dir: Path,
        intents_fd: int,
        intent_name: str,
        intent: dict[str, object],
        *,
        after_state: Callable[[], None] | None = None,
        after_trace: Callable[[], None] | None = None,
    ) -> None:
        self._revalidate_run_path(run_dir, intent["run_id"])
        self._revalidate_intents(run_dir, intents_fd)
        try:
            self._verify_prepared(intent["prepared_artifacts"])
            self._validate_lint_finalize_commit(intent)
        except RunError:
            if intent["status"] == "prepared":
                current = self._load_state(run_dir)
                if _digest(current) == _digest(intent["target_state"]):
                    self._rollback_prepared_intent_projection(run_dir, intent, current)
                self._discard_invalid_lint_finalize_intent(
                    run_dir, intents_fd, intent_name, intent
                )
            raise
        if intent["status"] == "committed":
            return
        state = self._load_state(run_dir)
        target = intent["target_state"]
        if not isinstance(target, dict):
            _fail("intent target_state is invalid")
        current_hash = _digest(state)
        target_hash = _digest(target)
        state_written = False
        if current_hash == intent["base_state_sha256"]:
            immutable = (
                "schema_version",
                "run_id",
                "flow",
                "authority",
                "executor",
                "input",
                "attempt",
                "created_at",
            )
            if any(state[field] != target[field] for field in immutable):
                _fail("intent changes immutable run state")
            if state["status"] != "running" or (
                target["status"] != "running"
                and target["status"] not in TRANSITIONS["running"]
            ):
                _fail("intent has an invalid semantic state transition")
            expected_artifacts = dict(state["artifacts"])
            for item in intent["prepared_artifacts"]:
                expected_artifacts[str(item["name"])] = str(item["state_ref"])
            if target["artifacts"] != expected_artifacts:
                _fail("intent target artifacts disagree with prepared evidence")
            self._write_state(run_dir, target)
            state_written = True
            if after_state is not None:
                after_state()
        elif current_hash != target_hash:
            _fail("run state conflicts with prepared intent")
        try:
            self._verify_prepared(intent["prepared_artifacts"])
            self._validate_lint_finalize_commit(intent)
        except RunError:
            if state_written:
                self._write_state(run_dir, state)
            self._discard_invalid_lint_finalize_intent(
                run_dir, intents_fd, intent_name, intent
            )
            raise
        self._revalidate_run_path(run_dir, intent["run_id"])
        self._append_trace_once(run_dir, intent["trace_event"])
        if after_trace is not None:
            after_trace()
        try:
            self._verify_prepared(intent["prepared_artifacts"])
            self._validate_lint_finalize_commit(intent)
        except RunError:
            if state_written:
                self._remove_last_trace_once(run_dir, intent["trace_event"])
                self._write_state(run_dir, state)
            self._discard_invalid_lint_finalize_intent(
                run_dir, intents_fd, intent_name, intent
            )
            raise
        if intent["status"] != "committed":
            self._revalidate_run_path(run_dir, intent["run_id"])
            committed = dict(intent)
            committed["status"] = "committed"
            _atomic_json_at(intents_fd, intent_name, self._validate_intent(committed))
            self._revalidate_intents(run_dir, intents_fd)
            self._revalidate_run_path(run_dir, intent["run_id"])
            try:
                self._verify_prepared(committed["prepared_artifacts"])
                self._validate_lint_finalize_commit(committed)
            except RunError:
                current = self._load_state(run_dir)
                if _digest(current) == _digest(committed["target_state"]):
                    self._rollback_prepared_intent_projection(
                        run_dir, committed, current
                    )
                self._discard_invalid_lint_finalize_intent(
                    run_dir, intents_fd, intent_name, committed
                )
                raise

    def _reconcile_locked(self, run_dir: Path) -> int:
        intents_fd = self._open_intents(run_dir)
        try:
            self._revalidate_intents(run_dir, intents_fd)
            state = self._load_state(run_dir)
            count = 0
            prepared_names: list[str] = []
            intents: list[tuple[str, dict[str, object]]] = []
            for name in sorted(os.listdir(intents_fd)):
                if not name.endswith(".json"):
                    _fail("intent directory contains an unsafe entry")
                try:
                    metadata = os.stat(name, dir_fd=intents_fd, follow_symlinks=False)
                except OSError:
                    _fail("intent directory contains an unsafe entry")
                if not stat.S_ISREG(metadata.st_mode):
                    _fail("intent directory contains an unsafe entry")
                intent = self._validate_intent(
                    _read_json_at(intents_fd, name, "intent")
                )
                if intent["run_id"] != state["run_id"]:
                    _fail("intent belongs to a different run")
                if name != f"{intent['step_id']}.json":
                    _fail("intent filename disagrees with its semantic step ID")
                target = intent["target_state"]
                trace = intent["trace_event"]
                if (
                    not isinstance(target, Mapping)
                    or not isinstance(trace, Mapping)
                    or target["authority"] != state["authority"]
                ):
                    _fail("intent changes immutable run authority")
                if not authority_at_most(
                    str(trace["authority"]), str(state["authority"])
                ):
                    _fail("intent trace authority exceeds the immutable run authority")
                has_lint_decision = any(
                    isinstance(item, Mapping) and item.get("name") == _FINALIZE_DECISION
                    for item in intent["prepared_artifacts"]
                )
                is_committed_lint_success = (
                    intent["status"] == "committed"
                    and has_lint_decision
                    and intent["target_state"]["status"] == "succeeded"
                )
                if (
                    is_committed_lint_success
                    and intent["schema_version"] == INTENT_SCHEMA_VERSION
                    and _digest(state) == intent["base_state_sha256"]
                ):
                    try:
                        self._validate_lint_finalize_commit(intent)
                    except RunError:
                        if any(
                            event["step_id"] == trace["step_id"]
                            for event in self._trace_events(
                                run_dir, expected_run_id=str(state["run_id"])
                            )
                        ):
                            _fail(
                                "invalid lint finalize intent is not an exact "
                                "rolled-back projection"
                            )
                        self._discard_invalid_lint_finalize_intent(
                            run_dir, intents_fd, name, intent
                        )
                        raise
                if is_committed_lint_success and _digest(state) == _digest(
                    intent["target_state"]
                ):
                    try:
                        self._validate_lint_finalize_commit(intent)
                    except RunError:
                        current = self._load_state(run_dir)
                        if _digest(current) == _digest(intent["target_state"]):
                            self._rollback_prepared_intent_projection(
                                run_dir, intent, current
                            )
                        self._discard_invalid_lint_finalize_intent(
                            run_dir, intents_fd, name, intent
                        )
                        raise
                intents.append((name, intent))
                if intent["status"] == "prepared":
                    prepared_names.append(name)
            if len(prepared_names) > 1:
                _fail("run has more than one prepared semantic intent")
            for name, intent in intents:
                if intent["status"] == "prepared":
                    self._apply_intent(run_dir, intents_fd, name, intent)
                    count += 1
            self._revalidate_run_path(run_dir, state["run_id"])
            self._revalidate_intents(run_dir, intents_fd)
            return count
        finally:
            os.close(intents_fd)

    def reconcile(self, run_id: str) -> int:
        with self._locked(run_id) as run_dir:
            return self._reconcile_locked(run_dir)

    def record_receipt(
        self,
        run_id: str,
        *,
        receipt_id: str,
        event_id: str,
        status: str,
        effect_hash: str,
    ) -> dict[str, object]:
        """Store external-effect evidence outside run state and trace."""

        payload = validate_receipt(
            {
                "schema_version": RECEIPT_SCHEMA_VERSION,
                "receipt_id": receipt_id,
                "run_id": run_id,
                "event_id": event_id,
                "status": status,
                "effect_hash": effect_hash,
                "at": self._now(),
            }
        )
        with self._locked(run_id) as run_dir:
            self._revalidate_run_path(run_dir, run_id)
            receipt_fd, receipt_dir, identity = self._open_zone_directory(
                "agent/outbox", "receipts", create=True
            )
            try:
                name = f"{receipt_id}.json"
                created_identity = _create_json_once_at(receipt_fd, name, payload)
                if created_identity is not None:
                    try:
                        self._revalidate_zone_directory(
                            receipt_fd,
                            receipt_dir,
                            identity,
                            "agent/outbox",
                            "receipts",
                        )
                        self._revalidate_run_path(run_dir, run_id)
                    except RunError:
                        if not self._quarantine_publication(
                            run_dir,
                            receipt_fd,
                            name,
                            created_identity,
                            kind="receipt",
                        ):
                            raise RunError(
                                "receipt publication failed and could not be rolled back"
                            ) from None
                        raise
                    return payload
                existing = validate_receipt(_read_json_at(receipt_fd, name, "receipt"))
                comparable = (
                    "schema_version",
                    "receipt_id",
                    "run_id",
                    "event_id",
                    "status",
                    "effect_hash",
                )
                if any(existing[field] != payload[field] for field in comparable):
                    _fail("receipt ID already has different evidence")
                self._revalidate_zone_directory(
                    receipt_fd,
                    receipt_dir,
                    identity,
                    "agent/outbox",
                    "receipts",
                )
                self._revalidate_run_path(run_dir, run_id)
                return existing
            finally:
                os.close(receipt_fd)

    def write_projection(self, run_id: str) -> Path:
        """Render a rebuildable human view; no runtime method reads it back."""

        with self._locked(run_id) as run_dir:
            state = self._load_state(run_dir)
            state_hash = _digest(state)
            lines = [
                f"<!-- lifeos-run-projection-schema: {PROJECTION_SCHEMA_VERSION} -->",
                f"<!-- source-state-sha256: {state_hash} -->",
                "",
                f"# Run {state['run_id']}",
                "",
                f"- Flow: `{state['flow']}`",
                f"- Status: `{state['status']}`",
                f"- Phase: `{state['phase']}`",
                f"- Attempt: `{state['attempt']}`",
                "",
            ]
            directory_fd, directory, identity = self._open_zone_directory(
                "agent/dashboard", "runs", create=True
            )
            try:
                name = f"{run_id}.md"
                previous: bytes | None
                try:
                    previous_fd = os.open(
                        name,
                        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                        dir_fd=directory_fd,
                    )
                except FileNotFoundError:
                    previous = None
                except OSError:
                    raise RunError("projection cannot be inspected safely") from None
                else:
                    try:
                        previous = _read_regular_bounded_fd(
                            previous_fd, _MAX_JSON_BYTES, "projection"
                        )
                    finally:
                        os.close(previous_fd)
                published_identity = _atomic_bytes_at(
                    directory_fd,
                    name,
                    "\n".join(lines).encode("utf-8"),
                )
                try:
                    self._revalidate_zone_directory(
                        directory_fd,
                        directory,
                        identity,
                        "agent/dashboard",
                        "runs",
                    )
                    self._revalidate_run_path(run_dir, run_id)
                except RunError:
                    if not self._quarantine_publication(
                        run_dir,
                        directory_fd,
                        name,
                        published_identity,
                        kind="projection",
                    ):
                        raise RunError(
                            "projection publication could not be quarantined safely"
                        ) from None
                    if previous is not None and not _create_bytes_once_at(
                        directory_fd, name, previous
                    ):
                        raise RunError(
                            "projection publication could not restore the prior view"
                        ) from None
                    raise
                return directory / name
            finally:
                os.close(directory_fd)
