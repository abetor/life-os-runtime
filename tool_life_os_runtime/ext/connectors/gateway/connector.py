"""Exact, bounded subprocess connector for the tool-gateway v1 event surface.

The low-level connector accepts one already-authorized semantic outbox event,
normalizes only its public delivery fields, and sends canonical JSON to
``dispatch-event``.  The runtime service obtains that event from ``OutboxStore``
and reconciles evidence through its public receipt API; neither component
changes the immutable event or its source artifact.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
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
from tool_life_os_runtime.ext.review.authority import (
    ActionCapability,
    AuthorityError,
    AuthorityPolicy,
)
from tool_life_os_runtime.ext.runs import (
    OutboxError,
    OutboxStore,
    bound_receipt_effect_hash,
    validate_event,
    validate_receipt,
)


GATEWAY_CONNECTOR_SCHEMA_VERSION = 1
MAX_GATEWAY_MACHINE_BYTES = 64 * 1024
GATEWAY_DELIVERY_ACTION_ORDER = (
    "read-semantic-outbox-event",
    "invoke-normalized-gateway-event",
    "read-gateway-delivery-receipt",
    "reconcile-outbox-receipt",
)

_MAX_ENV = 256
_MAX_ARGV = 32
_MAX_ARG_BYTES = 4096
_MAX_TOTAL_ARG_BYTES = 16 * 1024
_MAX_ENV_NAME_BYTES = 256
_MAX_ENV_VALUE_BYTES = 32 * 1024
_MAX_SEMVER_COMPONENT_DIGITS = 9
_MAX_ATTEMPTS = 2**31 - 1
_ZERO_HASH = "0" * 64

_NAME = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
_EVENT_ID = re.compile(r"^event_[a-z0-9][a-z0-9_-]{0,57}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SEMVER = re.compile(
    rf"^(0|[1-9][0-9]{{0,{_MAX_SEMVER_COMPONENT_DIGITS - 1}}})\."
    rf"(0|[1-9][0-9]{{0,{_MAX_SEMVER_COMPONENT_DIGITS - 1}}})\."
    rf"(0|[1-9][0-9]{{0,{_MAX_SEMVER_COMPONENT_DIGITS - 1}}})$"
)
_ERROR_CODE = re.compile(r"^[a-z][a-z0-9_]{0,127}$")
_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_SECRET_ARG = re.compile(
    r"(?i)(?:^--?(?:api[-_]?key|authorization|password|secret|token)(?:=|$)|"
    r"\b(?:bearer|basic)\s+\S+|\bsk-[a-z0-9_-]{8,})"
)
_PRIVATE_MARKERS = ("/users/", "/home/", "file:", "c:\\users\\")
_CREDENTIAL_LABEL = re.compile(
    r"(?i)(?:^|[\s,;|{\[(])(?:authorization|api[_ -]?key|access[_ -]?token|"
    r"refresh[_ -]?token|client[_ -]?secret|token|secret|password|passwd|"
    r"cookie|credential|chat[_ -]?id)\s*[:=]"
)
_AUTH_VALUE = re.compile(r"(?i)\b(?:bearer|basic)\s+\S+")
_COMMON_SECRET = re.compile(r"(?i)\bsk-[a-z0-9_-]{8,}")

_GATEWAY_SPEC = next(spec for spec in DEFAULT_SPECS if spec.tool == "gateway")

_GATEWAY_EVENT_KEYS = frozenset(
    {
        "schema_version",
        "event_id",
        "dedupe_key",
        "target",
        "source",
        "kind",
        "text",
        "project",
        "ref",
    }
)
_RECEIPT_KEYS = frozenset(
    {
        "schema_version",
        "event_id",
        "dedupe_key",
        "status",
        "effect_sha256",
        "attempts",
    }
)
_DISPATCH_KEYS = frozenset(
    {"schema_version", "event_id", "status", "receipt", "replayed"}
)
_DISPATCH_ERROR_KEYS = _DISPATCH_KEYS | {"error"}
_LOOKUP_NOT_FOUND_KEYS = frozenset(
    {
        "schema_version",
        "event_id",
        "status",
        "dedupe_key",
        "effect_sha256",
        "attempts",
    }
)
_LOOKUP_ERROR_KEYS = _LOOKUP_NOT_FOUND_KEYS | {"error"}
_GATEWAY_DELIVERY_ACTION_SPECS = (
    (
        "read-semantic-outbox-event",
        "runtime",
        "read",
        "read",
        "vault:agent/outbox",
        "read-only",
        False,
    ),
    (
        "invoke-normalized-gateway-event",
        "runtime",
        "external-send",
        "invoke",
        "gateway:normalized-event-stdin",
        "gateway-connector-invocation",
        False,
    ),
    (
        "read-gateway-delivery-receipt",
        "runtime",
        "read",
        "read",
        "gateway:delivery-receipt",
        "read-only",
        False,
    ),
    (
        "reconcile-outbox-receipt",
        "runtime",
        "internal-write",
        "write",
        "vault:agent/outbox",
        "gateway-receipt-reconciliation",
        True,
    ),
)


class GatewayConnectorError(ValueError):
    """Configured process, event, response, or receipt is not safe to use."""

    def __init__(
        self,
        code: str,
        *,
        category: str = "contract",
        returncode: int | None = None,
        stdout_bytes: int = 0,
        stderr_bytes: int = 0,
        receipt: GatewayReceipt | None = None,
    ) -> None:
        self.code = code
        self.category = category
        self.returncode = returncode
        self.stdout_bytes = stdout_bytes
        self.stderr_bytes = stderr_bytes
        self.receipt = receipt
        super().__init__(code)

    @property
    def retryable(self) -> bool:
        return self.category in {"transient", "unavailable"}


@dataclass(frozen=True)
class GatewayEvent:
    schema_version: int
    event_id: str
    dedupe_key: str
    target: str
    source: str
    kind: str
    text: str
    project: None = None
    ref: None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "event_id": self.event_id,
            "dedupe_key": self.dedupe_key,
            "target": self.target,
            "source": self.source,
            "kind": self.kind,
            "text": self.text,
            "project": self.project,
            "ref": self.ref,
        }


@dataclass(frozen=True)
class GatewayReceipt:
    schema_version: int
    event_id: str
    dedupe_key: str
    status: str
    effect_sha256: str
    attempts: int

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "event_id": self.event_id,
            "dedupe_key": self.dedupe_key,
            "status": self.status,
            "effect_sha256": self.effect_sha256,
            "attempts": self.attempts,
        }


@dataclass(frozen=True)
class GatewayDelivery:
    schema_version: int
    event_id: str
    status: str
    receipt: GatewayReceipt
    replayed: bool
    source_event_sha256: str
    gateway_event_sha256: str


@dataclass(frozen=True)
class GatewayDeliveryCapabilities:
    """Exact P0-06 capabilities required by runtime gateway delivery."""

    read_semantic_outbox_event: ActionCapability
    invoke_normalized_gateway_event: ActionCapability
    read_gateway_delivery_receipt: ActionCapability
    reconcile_outbox_receipt: ActionCapability

    def ordered(self) -> tuple[ActionCapability, ...]:
        return (
            self.read_semantic_outbox_event,
            self.invoke_normalized_gateway_event,
            self.read_gateway_delivery_receipt,
            self.reconcile_outbox_receipt,
        )


@dataclass(frozen=True)
class GatewayDeliveryOutcome:
    """Runtime receipt reconciliation result for one immutable outbox event."""

    schema_version: int
    event_id: str
    status: str
    attempt_id: str
    gateway_receipt: GatewayReceipt
    outbox_receipt_id: str
    outbox_effect_hash: str
    replayed: bool
    source_event_sha256: str
    action_ids: tuple[str, ...] = GATEWAY_DELIVERY_ACTION_ORDER


@dataclass(frozen=True)
class _NormalizedEvent:
    gateway: GatewayEvent
    source_event_sha256: str
    gateway_event_sha256: str
    stdin: bytes


@dataclass(frozen=True)
class _ProcessResult:
    returncode: int | None
    stdout: bytes
    stdout_bytes: int
    stderr_bytes: int
    timed_out: bool
    output_too_large: bool


def _fail(
    code: str,
    *,
    category: str = "contract",
    returncode: int | None = None,
    stdout_bytes: int = 0,
    stderr_bytes: int = 0,
    receipt: GatewayReceipt | None = None,
) -> None:
    raise GatewayConnectorError(
        code,
        category=category,
        returncode=returncode,
        stdout_bytes=stdout_bytes,
        stderr_bytes=stderr_bytes,
        receipt=receipt,
    )


def _has_control(value: str) -> bool:
    return any(
        unicodedata.category(character).startswith("C")
        or unicodedata.category(character) in {"Zl", "Zp"}
        for character in value
    )


def _text(value: object, label: str, *, maximum: int) -> str:
    if not isinstance(value, str) or not value:
        _fail(f"invalid-{label}")
    try:
        encoded = value.encode("utf-8")
    except UnicodeError:
        _fail(f"invalid-{label}")
    if (
        len(encoded) > maximum
        or value != unicodedata.normalize("NFC", value)
        or _has_control(value)
    ):
        _fail(f"invalid-{label}")
    return value


def _name(value: object, label: str) -> str:
    checked = _text(value, label, maximum=64)
    if _NAME.fullmatch(checked) is None:
        _fail(f"invalid-{label}")
    return checked


def _safe_message(value: object) -> str:
    checked = _text(value, "gateway-text", maximum=4096)
    folded = checked.casefold()
    if (
        any(marker in folded for marker in _PRIVATE_MARKERS)
        or _CREDENTIAL_LABEL.search(checked)
        or _AUTH_VALUE.search(checked)
        or _COMMON_SECRET.search(checked)
    ):
        _fail("unsafe-gateway-text")
    return checked


def _event_id(value: object) -> str:
    checked = _text(value, "event-id", maximum=64)
    if _EVENT_ID.fullmatch(checked) is None:
        _fail("invalid-event-id")
    return checked


def _dedupe_key(value: object) -> str:
    checked = _text(value, "dedupe-key", maximum=71)
    if not checked.startswith("sha256:") or _SHA256.fullmatch(checked[7:]) is None:
        _fail("invalid-dedupe-key")
    return checked


def _hash(value: object, label: str) -> str:
    checked = _text(value, label, maximum=64)
    if _SHA256.fullmatch(checked) is None:
        _fail(f"invalid-{label}")
    return checked


def _canonical_bytes(
    payload: Mapping[str, object], *, maximum: int = MAX_GATEWAY_MACHINE_BYTES
) -> bytes:
    try:
        rendered = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError):
        _fail("invalid-canonical-json")
    if len(rendered) > maximum:
        _fail("machine-input-size")
    return rendered


def _object_no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            _fail("duplicate-json-field")
        result[key] = value
    return result


def _decode(raw: bytes) -> dict[str, object]:
    try:
        payload = json.loads(raw, object_pairs_hook=_object_no_duplicates)
    except GatewayConnectorError:
        raise
    except (UnicodeError, ValueError, RecursionError):
        _fail("invalid-machine-json")
    if not isinstance(payload, dict):
        _fail("invalid-machine-json")
    return payload


def _strict_equal(left: object, right: object) -> bool:
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return set(left) == set(right) and all(
            _strict_equal(left[key], right[key]) for key in left
        )
    if isinstance(left, list):
        return len(left) == len(right) and all(
            _strict_equal(first, second) for first, second in zip(left, right)
        )
    return left == right


def _semver(value: object) -> tuple[int, int, int]:
    if not isinstance(value, str) or (match := _SEMVER.fullmatch(value)) is None:
        _fail("invalid-tool-version")
    return tuple(int(match.group(index)) for index in (1, 2, 3))


def _error_code(value: object) -> str:
    checked = _text(value, "gateway-error-code", maximum=128)
    if _ERROR_CODE.fullmatch(checked) is None:
        _fail("invalid-gateway-error")
    return checked


def _error_mapping(value: object) -> str:
    if not isinstance(value, Mapping) or set(value) != {"code"}:
        _fail("invalid-gateway-error")
    return _error_code(value["code"])


def _receipt(payload: object) -> GatewayReceipt:
    if not isinstance(payload, Mapping) or set(payload) != _RECEIPT_KEYS:
        _fail("invalid-gateway-receipt")
    if type(payload["schema_version"]) is not int or payload["schema_version"] != 1:
        _fail("invalid-gateway-receipt")
    event_id = _event_id(payload["event_id"])
    dedupe_key = _dedupe_key(payload["dedupe_key"])
    if event_id != "event_" + dedupe_key[7:65]:
        _fail("gateway-receipt-identity-mismatch")
    status_value = payload["status"]
    if status_value not in {"delivered", "failed", "retryable"}:
        _fail("invalid-gateway-receipt")
    effect = _hash(payload["effect_sha256"], "gateway-effect-sha256")
    attempts = payload["attempts"]
    if type(attempts) is not int or not 0 <= attempts <= _MAX_ATTEMPTS:
        _fail("invalid-gateway-receipt")
    if status_value == "delivered" and effect == _ZERO_HASH:
        _fail("invalid-gateway-receipt")
    if status_value == "retryable" and effect != _ZERO_HASH:
        _fail("invalid-gateway-receipt")
    return GatewayReceipt(1, event_id, dedupe_key, status_value, effect, attempts)


def _normalize_outbox_event(
    payload: Mapping[str, object], *, target: str
) -> _NormalizedEvent:
    try:
        source = validate_event(payload)
    except (OutboxError, TypeError, ValueError, UnicodeError, RecursionError):
        _fail("invalid-outbox-event")
    policy = source["delivery_policy"]
    if not isinstance(policy, Mapping):  # pragma: no cover - validate_event invariant
        _fail("invalid-outbox-event")
    if policy["surface"] != "gated" or policy["requires_receipt"] is not True:
        _fail("outbox-event-not-deliverable")
    checked_target = _name(target, "gateway-target")
    gateway = GatewayEvent(
        GATEWAY_CONNECTOR_SCHEMA_VERSION,
        str(source["event_id"]),
        str(source["dedupe_key"]),
        checked_target,
        "runtime",
        str(source["type"]),
        _safe_message(source["summary"]),
    )
    gateway_payload = gateway.to_dict()
    if set(gateway_payload) != _GATEWAY_EVENT_KEYS:  # pragma: no cover
        _fail("invalid-gateway-event")
    gateway_raw = _canonical_bytes(gateway_payload)
    source_raw = _canonical_bytes(source) + b"\n"
    return _NormalizedEvent(
        gateway,
        hashlib.sha256(source_raw).hexdigest(),
        hashlib.sha256(gateway_raw).hexdigest(),
        gateway_raw + b"\n",
    )


def _remaining(deadline: float) -> float:
    return max(0.0, deadline - time.monotonic())


def _kill_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            process.kill()
        except (ProcessLookupError, OSError):
            pass


def _run_process(
    argv: Sequence[str],
    *,
    stdin: bytes,
    cwd: Path,
    env: Mapping[str, str],
    deadline: float,
    limit: int,
) -> _ProcessResult:
    remaining = _remaining(deadline)
    if remaining <= 0:
        return _ProcessResult(None, b"", 0, 0, True, False)
    try:
        process = subprocess.Popen(
            list(argv),
            cwd=cwd,
            env=dict(env),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            start_new_session=True,
            bufsize=0,
        )
    except (OSError, ValueError, subprocess.SubprocessError):
        _fail("gateway-unavailable", category="unavailable")

    assert process.stdin is not None
    assert process.stdout is not None
    assert process.stderr is not None
    streams = {
        "stdin": process.stdin,
        "stdout": process.stdout,
        "stderr": process.stderr,
    }
    selector: selectors.BaseSelector | None = None
    captured = bytearray()
    sizes = {"stdout": 0, "stderr": 0}
    stdin_offset = 0
    open_reads = {"stdout", "stderr"}
    stdin_open = True
    parent_exited_at: float | None = None
    timed_out = False
    output_too_large = False
    cleanup_reserve = min(0.05, remaining / 10)
    execution_deadline = deadline - cleanup_reserve

    def close_stream(name: str) -> None:
        nonlocal stdin_open
        stream = streams[name]
        if selector is not None:
            try:
                selector.unregister(stream)
            except (KeyError, OSError, ValueError):
                pass
        try:
            stream.close()
        except (OSError, ValueError):
            pass
        if name == "stdin":
            stdin_open = False
        else:
            open_reads.discard(name)

    try:
        selector = selectors.DefaultSelector()
        for stream in streams.values():
            os.set_blocking(stream.fileno(), False)
        selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        if stdin:
            selector.register(process.stdin, selectors.EVENT_WRITE, "stdin")
        else:
            close_stream("stdin")
    except Exception:
        _kill_group(process)
        for name in tuple(streams):
            close_stream(name)
        if selector is not None:
            try:
                selector.close()
            except (OSError, ValueError):
                pass
        while process.poll() is None and _remaining(deadline) > 0:
            time.sleep(min(0.005, _remaining(deadline)))
        _fail("connector-process-io", category="transient")

    assert selector is not None
    try:
        while True:
            now = time.monotonic()
            returncode = process.poll()
            if returncode is not None and parent_exited_at is None:
                parent_exited_at = now
                if stdin_open:
                    close_stream("stdin")
            if returncode is not None and not open_reads:
                break
            if output_too_large:
                _kill_group(process)
                if stdin_open:
                    close_stream("stdin")
            elif returncode is None and now >= execution_deadline:
                timed_out = True
                _kill_group(process)
                if stdin_open:
                    close_stream("stdin")
            elif (
                parent_exited_at is not None
                and open_reads
                and now >= min(parent_exited_at + 0.05, execution_deadline)
            ):
                timed_out = True
                _kill_group(process)
            if now >= deadline:
                timed_out = True
                _kill_group(process)
                break

            wake_at = deadline
            if returncode is None and not output_too_large:
                wake_at = min(wake_at, execution_deadline)
            if parent_exited_at is not None and open_reads:
                wake_at = min(wake_at, parent_exited_at + 0.05)
            try:
                ready = selector.select(max(0.0, min(0.05, wake_at - now)))
            except OSError:
                timed_out = True
                _kill_group(process)
                break
            for key, _mask in ready:
                name = key.data
                stream = key.fileobj
                if name == "stdin":
                    try:
                        written = os.write(stream.fileno(), stdin[stdin_offset:])
                    except (BlockingIOError, BrokenPipeError, OSError):
                        close_stream("stdin")
                    else:
                        stdin_offset += written
                        if stdin_offset >= len(stdin):
                            close_stream("stdin")
                    continue
                try:
                    chunk = os.read(stream.fileno(), 64 * 1024)
                except BlockingIOError:
                    continue
                except OSError:
                    close_stream(name)
                    continue
                if not chunk:
                    close_stream(name)
                    continue
                sizes[name] = min(limit + 1, sizes[name] + len(chunk))
                if name == "stdout":
                    room = limit + 1 - len(captured)
                    if room > 0:
                        captured.extend(chunk[:room])
                if sizes[name] > limit:
                    output_too_large = True
                    _kill_group(process)
                    if stdin_open:
                        close_stream("stdin")
    except Exception:
        _kill_group(process)
        _fail("connector-process-io", category="transient")
    finally:
        if process.poll() is None or open_reads:
            _kill_group(process)
        while process.poll() is None and _remaining(deadline) > 0:
            time.sleep(min(0.005, _remaining(deadline)))
        for name in tuple(streams):
            close_stream(name)
        try:
            selector.close()
        except (OSError, ValueError):
            pass

    return _ProcessResult(
        None if timed_out else process.returncode,
        bytes(captured),
        sizes["stdout"],
        sizes["stderr"],
        timed_out,
        output_too_large,
    )


class GatewayConnector:
    """Configured gateway v1 dispatch and durable-receipt adapter."""

    def __init__(
        self,
        *,
        gateway_home: str | os.PathLike[str],
        target: str,
        command: Sequence[str],
        cwd: str | os.PathLike[str],
        env: Mapping[str, str],
        timeout: float = 30.0,
        max_output_bytes: int = MAX_GATEWAY_MACHINE_BYTES,
    ) -> None:
        self._command = self._validate_command(command)
        self._cwd = self._absolute_directory(cwd, "connector-cwd")
        self._cwd_identity = self._directory_identity(self._cwd)
        self._gateway_home = self._absolute_directory(gateway_home, "gateway-home")
        self._gateway_home_identity = self._directory_identity(self._gateway_home)
        self._gateway_parent = self._absolute_directory(
            self._gateway_home.parent, "gateway-home-parent"
        )
        self._gateway_parent_identity = self._directory_identity(self._gateway_parent)
        self._target = _name(target, "gateway-target")
        self._env = self._validate_env(env)
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
            _fail("invalid-timeout")
        if not math.isfinite(float(timeout)) or not 0.05 <= float(timeout) <= 3600:
            _fail("invalid-timeout")
        if (
            type(max_output_bytes) is not int
            or not 1024 <= max_output_bytes <= MAX_GATEWAY_MACHINE_BYTES
        ):
            _fail("invalid-output-limit")
        self._timeout = float(timeout)
        self._max_output_bytes = max_output_bytes

    @staticmethod
    def _absolute_directory(value: str | os.PathLike[str], label: str) -> Path:
        try:
            raw = os.fspath(value)
        except TypeError:
            _fail(f"invalid-{label}")
        if not isinstance(raw, str) or not raw or _has_control(raw):
            _fail(f"invalid-{label}")
        path = Path(raw)
        if not path.is_absolute() or ".." in path.parts:
            _fail(f"invalid-{label}")
        try:
            metadata = os.stat(path, follow_symlinks=False)
        except OSError:
            _fail(f"invalid-{label}")
        if not stat.S_ISDIR(metadata.st_mode):
            _fail(f"invalid-{label}")
        return path

    @staticmethod
    def _directory_identity(path: Path) -> tuple[int, int]:
        metadata = os.stat(path, follow_symlinks=False)
        if not stat.S_ISDIR(metadata.st_mode):
            _fail("connector-directory-moved")
        return metadata.st_dev, metadata.st_ino

    @staticmethod
    def _validate_command(command: Sequence[str]) -> tuple[str, ...]:
        if type(command) not in {tuple, list} or not 0 < len(command) <= _MAX_ARGV:
            _fail("invalid-command")
        checked: list[str] = []
        total = 0
        for item in command:
            value = _text(item, "command", maximum=_MAX_ARG_BYTES)
            if _SECRET_ARG.search(value):
                _fail("invalid-command")
            total += len(value.encode("utf-8"))
            checked.append(value)
        if total > _MAX_TOTAL_ARG_BYTES:
            _fail("invalid-command")
        return tuple(checked)

    @staticmethod
    def _validate_env(env: Mapping[str, str]) -> dict[str, str]:
        if not isinstance(env, Mapping) or len(env) > _MAX_ENV:
            _fail("invalid-environment")
        checked: dict[str, str] = {}
        for key, value in env.items():
            if not isinstance(key, str) or not isinstance(value, str):
                _fail("invalid-environment")
            try:
                key_size = len(key.encode("utf-8"))
                value_size = len(value.encode("utf-8"))
            except UnicodeError:
                _fail("invalid-environment")
            if (
                not key
                or key_size > _MAX_ENV_NAME_BYTES
                or _ENV_NAME.fullmatch(key) is None
                or value_size > _MAX_ENV_VALUE_BYTES
                or "\x00" in value
            ):
                _fail("invalid-environment")
            checked[key] = value
        return checked

    def _revalidate_roots(self) -> None:
        try:
            cwd = self._directory_identity(self._cwd)
            home = self._directory_identity(self._gateway_home)
            parent = self._directory_identity(self._gateway_parent)
        except (OSError, GatewayConnectorError):
            _fail("connector-directory-moved")
        if (
            cwd != self._cwd_identity
            or home != self._gateway_home_identity
            or parent != self._gateway_parent_identity
        ):
            _fail("connector-directory-moved")

    def _execute(
        self, suffix: Sequence[str], *, stdin: bytes, deadline: float
    ) -> _ProcessResult:
        self._revalidate_roots()
        try:
            result = _run_process(
                (*self._command, *suffix),
                stdin=stdin,
                cwd=self._cwd,
                env=self._env,
                deadline=deadline,
                limit=self._max_output_bytes,
            )
        finally:
            self._revalidate_roots()
        if result.timed_out:
            _fail(
                "gateway-timeout",
                category="transient",
                returncode=result.returncode,
                stdout_bytes=result.stdout_bytes,
                stderr_bytes=result.stderr_bytes,
            )
        if result.output_too_large:
            _fail(
                "gateway-machine-output-size",
                returncode=result.returncode,
                stdout_bytes=result.stdout_bytes,
                stderr_bytes=result.stderr_bytes,
            )
        return result

    @staticmethod
    def _unexpected_exit(result: _ProcessResult) -> None:
        _fail(
            "gateway-transient",
            category="transient",
            returncode=result.returncode,
            stdout_bytes=result.stdout_bytes,
            stderr_bytes=result.stderr_bytes,
        )

    def _handshake(self, deadline: float) -> None:
        result = self._execute(("capabilities", "--json"), stdin=b"", deadline=deadline)
        if result.returncode != 0:
            if result.returncode not in {0, 1}:
                self._unexpected_exit(result)
            _fail(
                "gateway-capability-handshake-failed",
                category="fatal",
                returncode=result.returncode,
                stdout_bytes=result.stdout_bytes,
                stderr_bytes=result.stderr_bytes,
            )
        payload = _decode(result.stdout)
        if set(payload) != {"schema_version", "tool", "version", "capabilities"}:
            _fail("gateway-capability-contract-mismatch")
        version = _semver(payload["version"])
        expected = [item.to_dict() for item in _GATEWAY_SPEC.expected_capabilities]
        if (
            type(payload["schema_version"]) is not int
            or payload["schema_version"] != 1
            or payload["tool"] != "gateway"
            or not _GATEWAY_SPEC.minimum_version
            <= version
            < _GATEWAY_SPEC.maximum_version_exclusive
            or not _strict_equal(payload["capabilities"], expected)
        ):
            _fail("gateway-capability-contract-mismatch")

    @staticmethod
    def _check_receipt_binding(receipt: GatewayReceipt, event: GatewayEvent) -> None:
        if receipt.event_id != event.event_id or receipt.dedupe_key != event.dedupe_key:
            _fail("gateway-receipt-identity-mismatch")

    @staticmethod
    def _dispatch_error(payload: Mapping[str, object], *, event: GatewayEvent) -> None:
        if set(payload) != _DISPATCH_ERROR_KEYS:
            _fail("invalid-gateway-dispatch-response")
        if (
            type(payload["schema_version"]) is not int
            or payload["schema_version"] != 1
            or payload["status"] != "error"
            or payload["receipt"] is not None
            or payload["replayed"] is not False
            or payload["event_id"] != event.event_id
        ):
            _fail("invalid-gateway-dispatch-response")
        _error_mapping(payload["error"])
        _fail("gateway-dispatch-failed", category="fatal", returncode=1)

    @classmethod
    def _dispatch_response(
        cls,
        payload: Mapping[str, object],
        *,
        event: GatewayEvent,
        returncode: int | None,
    ) -> tuple[str, GatewayReceipt, bool]:
        if set(payload) == _DISPATCH_ERROR_KEYS:
            cls._dispatch_error(payload, event=event)
        if set(payload) != _DISPATCH_KEYS:
            _fail("invalid-gateway-dispatch-response")
        if type(payload["schema_version"]) is not int or payload["schema_version"] != 1:
            _fail("invalid-gateway-dispatch-response")
        if payload["event_id"] != event.event_id:
            _fail("gateway-dispatch-identity-mismatch")
        status_value = payload["status"]
        if status_value not in {"delivered", "failed", "retryable"}:
            _fail("invalid-gateway-dispatch-response")
        replayed = payload["replayed"]
        if type(replayed) is not bool or (replayed and status_value != "delivered"):
            _fail("invalid-gateway-dispatch-response")
        receipt = _receipt(payload["receipt"])
        cls._check_receipt_binding(receipt, event)
        expected_exit = {"delivered": 0, "failed": 1, "retryable": 111}[status_value]
        if returncode != expected_exit or receipt.status != status_value:
            _fail("gateway-dispatch-exit-status-mismatch")
        return status_value, receipt, replayed

    def _lookup_receipt(
        self, event: GatewayEvent, deadline: float
    ) -> GatewayReceipt | None:
        result = self._execute(
            (
                "--home",
                str(self._gateway_home),
                "receipt",
                event.event_id,
                "--json",
            ),
            stdin=b"",
            deadline=deadline,
        )
        if result.returncode not in {0, 1}:
            self._unexpected_exit(result)
        payload = _decode(result.stdout)
        if result.returncode == 0:
            receipt = _receipt(payload)
            self._check_receipt_binding(receipt, event)
            return receipt
        if set(payload) == _LOOKUP_NOT_FOUND_KEYS:
            if (
                type(payload["schema_version"]) is int
                and payload["schema_version"] == 1
                and payload["event_id"] == event.event_id
                and payload["status"] == "not_found"
                and payload["dedupe_key"] is None
                and payload["effect_sha256"] is None
                and type(payload["attempts"]) is int
                and payload["attempts"] == 0
            ):
                return None
        if set(payload) == _LOOKUP_ERROR_KEYS:
            if (
                type(payload["schema_version"]) is int
                and payload["schema_version"] == 1
                and payload["event_id"] is None
                and payload["status"] == "error"
                and payload["dedupe_key"] is None
                and payload["effect_sha256"] is None
                and type(payload["attempts"]) is int
                and payload["attempts"] == 0
            ):
                _error_mapping(payload["error"])
                _fail("gateway-receipt-read-failed", category="fatal", returncode=1)
        _fail("invalid-gateway-receipt-response", returncode=1)

    def receipt(self, event: Mapping[str, object]) -> GatewayReceipt | None:
        """Read persistent gateway evidence without mutating either tool."""

        normalized = _normalize_outbox_event(event, target=self._target)
        deadline = time.monotonic() + self._timeout
        self._handshake(deadline)
        return self._lookup_receipt(normalized.gateway, deadline)

    def deliver(self, event: Mapping[str, object]) -> GatewayDelivery:
        """Dispatch once and require the separately readable exact receipt."""

        normalized = _normalize_outbox_event(event, target=self._target)
        deadline = time.monotonic() + self._timeout
        self._handshake(deadline)
        result = self._execute(
            (
                "--home",
                str(self._gateway_home),
                "dispatch-event",
                "--json",
            ),
            stdin=normalized.stdin,
            deadline=deadline,
        )
        if result.returncode not in {0, 1, 111}:
            self._unexpected_exit(result)
        payload = _decode(result.stdout)
        status_value, embedded, replayed = self._dispatch_response(
            payload, event=normalized.gateway, returncode=result.returncode
        )
        persistent = self._lookup_receipt(normalized.gateway, deadline)
        if persistent is None or persistent != embedded:
            _fail("gateway-persistent-receipt-mismatch")
        if status_value == "retryable":
            _fail(
                "gateway-transient",
                category="transient",
                returncode=111,
                stdout_bytes=result.stdout_bytes,
                stderr_bytes=result.stderr_bytes,
                receipt=persistent,
            )
        return GatewayDelivery(
            GATEWAY_CONNECTOR_SCHEMA_VERSION,
            normalized.gateway.event_id,
            status_value,
            persistent,
            replayed,
            normalized.source_event_sha256,
            normalized.gateway_event_sha256,
        )


class GatewayDeliveryService:
    """Deliver one event obtained only through the authorized runtime outbox."""

    def __init__(
        self,
        *,
        outbox_store: OutboxStore,
        connector: GatewayConnector,
        policy: AuthorityPolicy,
    ) -> None:
        if (
            not isinstance(outbox_store, OutboxStore)
            or not isinstance(connector, GatewayConnector)
            or not isinstance(policy, AuthorityPolicy)
        ):
            _fail("invalid-gateway-delivery-service")
        self._outbox_store = outbox_store
        self._connector = connector
        self._policy = policy

    def _preflight(self, capabilities: GatewayDeliveryCapabilities) -> None:
        if not isinstance(capabilities, GatewayDeliveryCapabilities):
            _fail("invalid-gateway-delivery-capabilities")
        for capability, expected in zip(
            capabilities.ordered(), _GATEWAY_DELIVERY_ACTION_SPECS, strict=True
        ):
            try:
                grant = self._policy.require(capability)
            except AuthorityError:
                _fail("invalid-gateway-delivery-capabilities")
            actual = (
                grant.action_id,
                grant.actor,
                grant.authority,
                grant.access,
                grant.target,
                grant.effect_kind,
                grant.artifact_commit,
            )
            if grant.flow_id != "gateway-delivery" or actual != expected:
                _fail("invalid-gateway-delivery-capabilities")

    @staticmethod
    def _attempt_id(receipt: GatewayReceipt, source_event_sha256: str) -> str:
        material = {
            "schema_version": GATEWAY_CONNECTOR_SCHEMA_VERSION,
            "source_event_sha256": _hash(source_event_sha256, "source-event-sha256"),
            "gateway_receipt": receipt.to_dict(),
        }
        digest = hashlib.sha256(_canonical_bytes(material)).hexdigest()
        return "gateway_" + digest[:56]

    def deliver(
        self,
        event_id: str,
        capabilities: GatewayDeliveryCapabilities,
    ) -> GatewayDeliveryOutcome:
        """Execute the four authoritative delivery actions in canonical order."""

        self._preflight(capabilities)
        try:
            event, committed_event_sha256 = (
                self._outbox_store.read_committed_for_delivery(
                    capabilities.read_semantic_outbox_event,
                    event_id,
                )
            )
        except OutboxError:
            _fail("gateway-outbox-read-failed")
        checked_event = validate_event(event)
        source_event_sha256 = _hash(committed_event_sha256, "committed-event-sha256")

        delivery = self._connector.deliver(checked_event)
        if (
            not isinstance(delivery, GatewayDelivery)
            or delivery.schema_version != GATEWAY_CONNECTOR_SCHEMA_VERSION
            or delivery.event_id != checked_event["event_id"]
            or delivery.source_event_sha256 != source_event_sha256
            or delivery.status not in {"delivered", "failed"}
            or delivery.receipt.status != delivery.status
        ):
            _fail("gateway-delivery-binding-mismatch")

        persistent = self._connector.receipt(checked_event)
        if persistent is None or persistent != delivery.receipt:
            _fail("gateway-persistent-receipt-mismatch")
        attempt_id = self._attempt_id(persistent, source_event_sha256)
        try:
            recorded = self._outbox_store.record_delivery_receipt(
                capabilities.reconcile_outbox_receipt,
                event_id=str(checked_event["event_id"]),
                attempt_id=attempt_id,
                status=delivery.status,
                effect_hash=persistent.effect_sha256,
                expected_event_sha256=source_event_sha256,
            )
            checked_receipt = validate_receipt(recorded)
        except (OutboxError, ValueError):
            _fail("gateway-outbox-reconciliation-failed")
        expected_effect = bound_receipt_effect_hash(
            event_sha256=source_event_sha256,
            gateway_effect_sha256=persistent.effect_sha256,
        )
        if (
            checked_receipt["event_id"] != checked_event["event_id"]
            or checked_receipt["run_id"] != checked_event["run_id"]
            or checked_receipt["status"] != delivery.status
            or checked_receipt["effect_hash"] != expected_effect
        ):
            _fail("gateway-outbox-receipt-binding-mismatch")
        return GatewayDeliveryOutcome(
            GATEWAY_CONNECTOR_SCHEMA_VERSION,
            str(checked_event["event_id"]),
            delivery.status,
            attempt_id,
            persistent,
            str(checked_receipt["receipt_id"]),
            str(checked_receipt["effect_hash"]),
            delivery.replayed,
            source_event_sha256,
        )
