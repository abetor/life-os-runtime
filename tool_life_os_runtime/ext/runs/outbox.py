"""Replay-safe semantic outbox separated from gateway delivery effects."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import ctypes
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
from typing import Callable, Mapping
import unicodedata
import uuid

from tool_life_os_runtime.ext.review.authority import (
    ActionCapability,
    AuthorityError,
    AuthorityPolicy,
)
from tool_life_os_runtime.ext.vault.schema import (
    ZONE_SPECS,
    VaultPathResolver,
    VaultSchemaError,
)
from tool_life_os_runtime.failure_authority import (
    FailureAuthorityError,
    authority_at_most,
    authorize_action,
    canonical_matrix,
)

from .store import (
    FINALIZE_ACTION_ORDER,
    RunError,
    RunStore,
    _create_json_once_at,
    validate_receipt,
)


OUTBOX_SCHEMA_VERSION = 1
_ID = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
_RUN_ID = re.compile(r"^run_[a-z0-9][a-z0-9_-]{0,62}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$")
_SURFACES = frozenset({"silent", "batched", "gated"})
_URGENCIES = frozenset({"low", "normal", "high", "critical"})
_EVENT_KEYS = frozenset(
    {
        "schema_version",
        "event_id",
        "run_id",
        "flow_id",
        "action",
        "type",
        "summary",
        "artifact_ref",
        "artifact_sha256",
        "urgency",
        "dedupe_key",
        "delivery_policy",
        "status",
        "created_at",
    }
)
_ACTION_KEYS = frozenset({"action_id", "actor", "authority", "target"})
_DELIVERY_KEYS = frozenset({"surface", "requires_receipt"})
_PRIVATE_MARKERS = ("/" + "Users" + "/", "/" + "home" + "/", "file:")
_SECRET_KEYS = (
    "api_key",
    "authorization",
    "chat_id",
    "cookie",
    "credential",
    "password",
    "secret",
    "token",
)
_CREDENTIAL_LABEL = re.compile(
    r"(?i)(?:^|[\s,;|{\[(])"
    r"(?:authorization|proxy-authorization|api[_ -]?key|x-api-key|"
    r"access[_ -]?token|refresh[_ -]?token|private[_ -]?token|"
    r"client[_ -]?secret|token|secret|password|passwd|cookie|credential|"
    r"chat[_ -]?id)\s*[:=]"
)
_AUTH_VALUE = re.compile(r"(?i)\b(?:bearer|basic)\s+\S+")
_COMMON_SECRET = re.compile(r"(?i)\bsk-[a-z0-9_-]{8,}")
_MAX_EVENT_BYTES = 64 * 1024
_MAX_ARTIFACT_BYTES = 4 * 1024 * 1024
_ZONE_PATHS = {spec.name: spec for spec in ZONE_SPECS}


def _is_finalize_emit_action(grant: ActionCapability | Mapping[str, object]) -> bool:
    getter = (
        (lambda field: getattr(grant, field))
        if isinstance(grant, ActionCapability)
        else (lambda field: grant.get(field))
    )
    return (
        getter("flow_id") == "finalize"
        and getter("action_id") == "emit-semantic-outbox-event"
        and getter("actor") == "runtime"
        and getter("authority") == "internal-write"
        and getter("target") == "vault:agent/outbox"
    )


class OutboxError(ValueError):
    """Outbox data, authority, or filesystem evidence is unsafe."""


def _fail(message: str) -> None:
    raise OutboxError(message)


def _has_control(value: str) -> bool:
    return any(
        unicodedata.category(character).startswith("C")
        or unicodedata.category(character) in {"Zl", "Zp"}
        for character in value
    )


def _text(value: object, label: str, *, limit: int = 4096) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > limit
        or value.strip() != value
        or _has_control(value)
        or any(marker in value for marker in _PRIVATE_MARKERS)
    ):
        _fail(f"{label} must be bounded privacy-safe text")
    return value


def _identifier(value: object, label: str) -> str:
    checked = _text(value, label, limit=64)
    if _ID.fullmatch(checked) is None:
        _fail(f"{label} has invalid syntax")
    return checked


def _semantic_text(value: object, label: str, *, limit: int) -> str:
    checked = _text(value, label, limit=limit)
    if (
        _CREDENTIAL_LABEL.search(checked)
        or _AUTH_VALUE.search(checked)
        or _COMMON_SECRET.search(checked)
    ):
        _fail(f"{label} contains credential-labelled or sensitive text")
    return checked


def _run_id(value: object, label: str = "run_id") -> str:
    checked = _text(value, label, limit=64)
    if _RUN_ID.fullmatch(checked) is None:
        _fail(f"{label} has invalid syntax")
    return checked


def _hash(value: object, label: str) -> str:
    checked = _text(value, label, limit=64)
    if _SHA256.fullmatch(checked) is None:
        _fail(f"{label} must be sha256")
    return checked


def _timestamp(value: object, label: str) -> str:
    checked = _text(value, label, limit=64)
    if _UTC.fullmatch(checked) is None:
        _fail(f"{label} must be a UTC timestamp")
    try:
        datetime.fromisoformat(checked[:-1] + "+00:00")
    except ValueError:
        _fail(f"{label} must be a valid UTC timestamp")
    return checked


def _relative(value: object, label: str) -> str:
    checked = _text(value, label, limit=4096)
    if "\\" in checked:
        _fail(f"{label} must use portable separators")
    path = PurePosixPath(checked)
    if path.is_absolute() or path == PurePosixPath(".") or ".." in path.parts:
        _fail(f"{label} must be a safe relative path")
    return checked


def _canonical_bytes(payload: Mapping[str, object]) -> bytes:
    try:
        raw = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError):
        _fail("outbox payload is not canonical JSON")
    if len(raw) > _MAX_EVENT_BYTES:
        _fail("outbox payload is too large")
    return raw


def _object_no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            _fail("outbox JSON has duplicate fields")
        result[key] = value
    return result


def _decode_event(raw: bytes) -> dict[str, object]:
    try:
        payload = json.loads(raw, object_pairs_hook=_object_no_duplicates)
    except OutboxError:
        raise
    except (UnicodeError, ValueError, RecursionError):
        _fail("outbox event is not valid JSON")
    if not isinstance(payload, dict):
        _fail("outbox event must be an object")
    return validate_event(payload)


def _decode_receipt(raw: bytes) -> dict[str, object]:
    try:
        payload = json.loads(raw, object_pairs_hook=_object_no_duplicates)
    except OutboxError:
        raise
    except (UnicodeError, ValueError, RecursionError):
        _fail("delivery receipt is not valid JSON")
    if not isinstance(payload, dict):
        _fail("delivery receipt must be an object")
    try:
        return validate_receipt(payload)
    except RunError as error:
        raise OutboxError("delivery receipt schema is invalid") from error


def _rename_noreplace(directory_fd: int, source: str, destination: str) -> bool:
    """Atomically publish one name without replacing an existing leaf."""

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
            0x00000004,  # RENAME_EXCL
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
            1,  # RENAME_NOREPLACE
        )
    else:
        _fail("atomic no-replace publication is unavailable")
    if result == 0:
        return True
    error = ctypes.get_errno()
    if error == errno.EEXIST:
        return False
    raise OutboxError("atomic no-replace publication failed") from OSError(
        error, os.strerror(error)
    )


def semantic_dedupe_key(
    *, flow_id: str, event_type: str, semantic_key: str, artifact_ref: str
) -> str:
    """Return an opaque stable key; summaries and run attempts do not affect it."""

    identity = {
        "schema_version": OUTBOX_SCHEMA_VERSION,
        "flow_id": _identifier(flow_id, "flow_id"),
        "type": _identifier(event_type, "event type"),
        "semantic_key": _semantic_text(semantic_key, "semantic key", limit=1024),
        "artifact_ref": _relative(artifact_ref, "artifact_ref"),
    }
    return "sha256:" + hashlib.sha256(_canonical_bytes(identity)).hexdigest()


def bound_receipt_effect_hash(*, event_sha256: str, gateway_effect_sha256: str) -> str:
    """Bind the v1 receipt effect field to exact event and gateway evidence."""

    event_hash = _hash(event_sha256, "event_sha256")
    gateway_hash = _hash(gateway_effect_sha256, "gateway_effect_sha256")
    material = (
        b"lifeos-outbox-receipt-v1\0"
        + bytes.fromhex(event_hash)
        + bytes.fromhex(gateway_hash)
    )
    return hashlib.sha256(material).hexdigest()


def validate_event(payload: Mapping[str, object]) -> dict[str, object]:
    """Validate the exact bounded semantic event schema."""

    if not isinstance(payload, Mapping) or set(payload) != _EVENT_KEYS:
        _fail("outbox event has missing or unknown fields")
    if (
        type(payload["schema_version"]) is not int
        or payload["schema_version"] != OUTBOX_SCHEMA_VERSION
    ):
        _fail("unsupported outbox schema_version")
    event_id = _identifier(payload["event_id"], "event_id")
    _run_id(payload["run_id"])
    flow_id = _identifier(payload["flow_id"], "flow_id")
    action = payload["action"]
    if not isinstance(action, Mapping) or set(action) != _ACTION_KEYS:
        _fail("outbox action has missing or unknown fields")
    for field in sorted(_ACTION_KEYS):
        _text(action[field], f"outbox action.{field}", limit=256)
    try:
        canonical = authorize_action(
            canonical_matrix(),
            flow_id=flow_id,
            action_id=str(action["action_id"]),
            actor=str(action["actor"]),
            authority=str(action["authority"]),
            target=str(action["target"]),
        )
    except FailureAuthorityError as error:
        raise OutboxError("outbox action is not canonical") from error
    if (
        canonical["access"] != "write"
        or canonical["effect_kind"] != "outbox-artifact-commit"
        or not canonical["artifact_commit"]
    ):
        _fail("outbox action does not commit an outbox artifact")
    _identifier(payload["type"], "event type")
    _semantic_text(payload["summary"], "summary", limit=512)
    _relative(payload["artifact_ref"], "artifact_ref")
    _hash(payload["artifact_sha256"], "artifact_sha256")
    if payload["urgency"] not in _URGENCIES:
        _fail("outbox urgency is invalid")
    dedupe_key = _text(payload["dedupe_key"], "dedupe_key", limit=80)
    if (
        not dedupe_key.startswith("sha256:")
        or _SHA256.fullmatch(dedupe_key[7:]) is None
    ):
        _fail("outbox dedupe_key is invalid")
    if event_id != "event_" + dedupe_key[7:65]:
        _fail("event_id does not match dedupe_key")
    policy = payload["delivery_policy"]
    if not isinstance(policy, Mapping) or set(policy) != _DELIVERY_KEYS:
        _fail("delivery_policy has missing or unknown fields")
    if policy["surface"] not in _SURFACES:
        _fail("delivery_policy.surface is invalid")
    if not isinstance(policy["requires_receipt"], bool):
        _fail("delivery_policy.requires_receipt must be boolean")
    if payload["status"] != "pending":
        _fail("outbox event status must remain pending until separate receipt")
    _timestamp(payload["created_at"], "created_at")
    checked = dict(payload)
    checked["action"] = dict(action)
    checked["delivery_policy"] = dict(policy)
    _canonical_bytes(checked)
    return checked


@dataclass(frozen=True)
class _AnchoredDirectory:
    fd: int
    path: Path
    identity: tuple[int, int]
    relative: str


class OutboxStore:
    """Filesystem outbox with deterministic no-clobber publication."""

    def __init__(
        self,
        resolver: VaultPathResolver,
        run_store: RunStore,
        *,
        policy: AuthorityPolicy | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not isinstance(run_store, RunStore):
            raise OutboxError("run_store must be a RunStore")
        if getattr(run_store, "_resolver", None) is not resolver:
            raise OutboxError("outbox and run store must share one vault resolver")
        self._resolver = resolver
        self._run_store = run_store
        self._policy = policy or AuthorityPolicy()
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        root_input = getattr(resolver, "_root_input", None)
        if not isinstance(root_input, Path) or not root_input.is_absolute():
            raise OutboxError("vault resolver has no bindable root")
        self._root_path = root_input
        try:
            self._root_fd = os.open(
                root_input,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
            opened = os.fstat(self._root_fd)
            named = os.stat(root_input, follow_symlinks=False)
            if not stat.S_ISDIR(opened.st_mode) or (opened.st_dev, opened.st_ino) != (
                named.st_dev,
                named.st_ino,
            ):
                _fail("vault root changed while binding outbox")
            self._root_identity = (opened.st_dev, opened.st_ino)
        except (OSError, OutboxError):
            if hasattr(self, "_root_fd"):
                os.close(self._root_fd)
            raise OutboxError("vault root cannot be bound safely") from None

    def close(self) -> None:
        """Release the stable vault-root binding."""

        root_fd = getattr(self, "_root_fd", -1)
        if root_fd >= 0:
            os.close(root_fd)
            self._root_fd = -1

    def __enter__(self) -> OutboxStore:
        self._assert_root_binding()
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def __del__(self) -> None:  # pragma: no cover - best-effort resource release
        try:
            self.close()
        except OSError:
            pass

    def _assert_root_binding(self) -> None:
        try:
            opened = os.fstat(self._root_fd)
            named = os.stat(self._root_path, follow_symlinks=False)
        except OSError:
            _fail("vault root changed after outbox binding")
        if (
            not stat.S_ISDIR(opened.st_mode)
            or (opened.st_dev, opened.st_ino) != self._root_identity
            or (named.st_dev, named.st_ino) != self._root_identity
        ):
            _fail("vault root changed after outbox binding")

    def _now(self) -> str:
        value = self._clock()
        if not isinstance(value, datetime) or value.tzinfo is None:
            _fail("clock must return an aware datetime")
        return (
            value.astimezone(timezone.utc)
            .isoformat(timespec="microseconds")
            .replace("+00:00", "Z")
        )

    def _open_directory(
        self, relative: str = ".", *, create: bool = False
    ) -> _AnchoredDirectory:
        self._assert_root_binding()
        outbox_relative = self._resolver.config.zone("outbox")
        checked = PurePosixPath(
            "." if relative == "." else _relative(relative, "directory")
        )
        suffix = () if checked == PurePosixPath(".") else checked.parts
        parts = outbox_relative.parts + suffix
        try:
            current_fd = os.dup(self._root_fd)
        except OSError:
            raise OutboxError("outbox root binding cannot be duplicated") from None
        try:
            for index, part in enumerate(parts):
                if create and index >= len(outbox_relative.parts):
                    try:
                        os.mkdir(part, mode=0o700, dir_fd=current_fd)
                        os.fsync(current_fd)
                    except FileExistsError:
                        pass
                    except OSError:
                        _fail("outbox child directory cannot be created")
                child_fd: int | None = None
                try:
                    child_fd = os.open(
                        part,
                        os.O_RDONLY
                        | getattr(os, "O_DIRECTORY", 0)
                        | getattr(os, "O_NOFOLLOW", 0),
                        dir_fd=current_fd,
                    )
                    child_opened = os.fstat(child_fd)
                    child_named = os.stat(
                        part, dir_fd=current_fd, follow_symlinks=False
                    )
                    if not stat.S_ISDIR(child_opened.st_mode) or (
                        child_opened.st_dev,
                        child_opened.st_ino,
                    ) != (child_named.st_dev, child_named.st_ino):
                        _fail("outbox child directory changed while opening")
                except (OSError, OutboxError):
                    if child_fd is not None:
                        os.close(child_fd)
                    raise
                os.close(current_fd)
                if child_fd is None:  # pragma: no cover - local invariant
                    _fail("outbox child directory was not opened")
                current_fd = child_fd
            path = self._root_path.joinpath(*parts)
            opened = os.fstat(current_fd)
            named = os.stat(path, follow_symlinks=False)
            identity = (opened.st_dev, opened.st_ino)
            if not stat.S_ISDIR(opened.st_mode) or identity != (
                named.st_dev,
                named.st_ino,
            ):
                _fail("outbox child directory changed during traversal")
            self._assert_root_binding()
            self._resolver.revalidate(
                path,
                "agent/outbox",
                checked,
                for_write=True,
                must_exist=True,
            )
            return _AnchoredDirectory(current_fd, path, identity, relative)
        except (OSError, VaultSchemaError, OutboxError):
            os.close(current_fd)
            raise OutboxError("outbox directory cannot be anchored safely") from None

    def _revalidate_directory(self, directory: _AnchoredDirectory) -> None:
        try:
            self._assert_root_binding()
            opened = os.fstat(directory.fd)
            named = os.stat(directory.path, follow_symlinks=False)
            self._resolver.revalidate(
                directory.path,
                "agent/outbox",
                directory.relative,
                for_write=True,
                must_exist=True,
            )
        except (OSError, VaultSchemaError):
            _fail("outbox directory changed during operation")
        if (
            not stat.S_ISDIR(opened.st_mode)
            or (opened.st_dev, opened.st_ino) != directory.identity
            or (named.st_dev, named.st_ino) != directory.identity
        ):
            _fail("outbox directory changed during operation")

    @staticmethod
    def _read_regular_fd(fd: int, *, maximum: int) -> bytes:
        try:
            metadata = os.fstat(fd)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > maximum:
                _fail("outbox file is not a bounded regular file")
            os.lseek(fd, 0, os.SEEK_SET)
            chunks: list[bytes] = []
            remaining = maximum + 1
            while remaining:
                chunk = os.read(fd, min(64 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            if len(raw) > maximum:
                _fail("outbox file is too large")
            return raw
        except OSError:
            raise OutboxError("outbox file cannot be read safely") from None

    @staticmethod
    def _read_regular(directory_fd: int, name: str, *, maximum: int) -> bytes:
        try:
            fd = os.open(
                name,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=directory_fd,
            )
        except OSError:
            _fail("outbox file cannot be read safely")
        try:
            metadata = os.fstat(fd)
            named_before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            identity = (metadata.st_dev, metadata.st_ino)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_size > maximum
                or identity != (named_before.st_dev, named_before.st_ino)
            ):
                _fail("outbox file is not a bounded regular file")
            raw = OutboxStore._read_regular_fd(fd, maximum=maximum)
            metadata_after = os.fstat(fd)
            named_after = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if (
                not stat.S_ISREG(metadata_after.st_mode)
                or (metadata_after.st_dev, metadata_after.st_ino) != identity
                or (named_after.st_dev, named_after.st_ino) != identity
            ):
                _fail("outbox file changed while it was read")
            return raw
        except OSError:
            raise OutboxError("outbox file cannot be read safely") from None
        finally:
            os.close(fd)

    @staticmethod
    def _open_event_at(
        directory_fd: int, event_id: str
    ) -> tuple[int, tuple[int, int], bytes, dict[str, object]]:
        name = f"{event_id}.json"
        try:
            event_fd = os.open(
                name,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=directory_fd,
            )
            opened = os.fstat(event_fd)
            named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            identity = (opened.st_dev, opened.st_ino)
            if not stat.S_ISREG(opened.st_mode) or identity != (
                named.st_dev,
                named.st_ino,
            ):
                _fail("outbox event changed while opening")
            raw = OutboxStore._read_regular_fd(event_fd, maximum=_MAX_EVENT_BYTES)
            event = _decode_event(raw)
            if event["event_id"] != event_id:
                _fail("outbox event ID disagrees with its file name")
            return event_fd, identity, raw, event
        except OutboxError:
            if "event_fd" in locals():
                os.close(event_fd)
            raise
        except OSError:
            if "event_fd" in locals():
                os.close(event_fd)
            raise OutboxError("outbox event cannot be anchored safely") from None

    @staticmethod
    def _revalidate_event_at(
        directory_fd: int,
        event_id: str,
        event_fd: int,
        identity: tuple[int, int],
        expected: bytes,
    ) -> None:
        name = f"{event_id}.json"
        try:
            opened = os.fstat(event_fd)
            named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            current = OutboxStore._read_regular_fd(event_fd, maximum=_MAX_EVENT_BYTES)
        except (OSError, OutboxError):
            _fail("outbox event changed during receipt commit")
        if (
            not stat.S_ISREG(opened.st_mode)
            or (opened.st_dev, opened.st_ino) != identity
            or (named.st_dev, named.st_ino) != identity
            or current != expected
        ):
            _fail("outbox event changed during receipt commit")

    @staticmethod
    def _retire_temp(directory_fd: int, temp: str, identity: tuple[int, int]) -> bool:
        """Move a stage aside without ever unlinking a substituted leaf."""

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
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0),
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

    @staticmethod
    def _publish_once(
        directory_fd: int,
        name: str,
        data: bytes,
        *,
        after_prepare: Callable[[], None] | None,
        after_publish: Callable[[], None] | None,
    ) -> tuple[tuple[int, int], bytes] | None:
        temp = f".{name}.pending"
        fd: int | None = None
        identity: tuple[int, int] | None = None
        retire_stage = False
        try:
            try:
                fd = os.open(
                    temp,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                    0o600,
                    dir_fd=directory_fd,
                )
            except FileExistsError:
                existing = OutboxStore._read_regular(
                    directory_fd, temp, maximum=_MAX_EVENT_BYTES
                )
                staged_event = _decode_event(existing)
                requested_event = _decode_event(data)
                comparable = set(_EVENT_KEYS) - {"created_at"}
                if any(
                    staged_event[field] != requested_event[field]
                    for field in comparable
                ):
                    _fail("outbox pending stage has conflicting bytes")
                data = existing
                staged = os.stat(temp, dir_fd=directory_fd, follow_symlinks=False)
                identity = (staged.st_dev, staged.st_ino)
            else:
                with os.fdopen(fd, "wb", closefd=True) as handle:
                    fd = None
                    handle.write(data)
                    handle.flush()
                    os.fsync(handle.fileno())
                    metadata = os.fstat(handle.fileno())
                    identity = (metadata.st_dev, metadata.st_ino)
                if after_prepare is not None:
                    after_prepare()
            if identity is None:  # pragma: no cover - local invariant
                _fail("outbox publication lost stage identity")
            if not _rename_noreplace(directory_fd, temp, name):
                retire_stage = True
                return None
            os.fsync(directory_fd)
            published = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if (published.st_dev, published.st_ino) != identity:
                _fail("outbox stage was replaced during publication")
            if after_publish is not None:
                after_publish()
            return identity, data
        except OutboxError:
            raise
        except OSError:
            raise OutboxError("outbox publication failed") from None
        finally:
            if fd is not None:
                os.close(fd)
            if (
                retire_stage
                and identity is not None
                and not OutboxStore._retire_temp(directory_fd, temp, identity)
            ):
                _fail("outbox stage cleanup encountered a foreign leaf")

    @staticmethod
    def _quarantine(
        directory_fd: int,
        name: str,
        identity: tuple[int, int],
        *,
        kind: str = "event",
    ) -> bool:
        """Remove only our publication from the event namespace after a late race."""

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
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=directory_fd,
            )
        except OSError:
            return False
        recovery_name = f"{kind}-{uuid.uuid4().hex}.recovery"
        try:
            os.rename(
                name,
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
                    name,
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

    @classmethod
    def _revalidate_publication(
        cls,
        directory_fd: int,
        name: str,
        identity: tuple[int, int],
        expected: bytes,
    ) -> None:
        raw = cls._read_regular(directory_fd, name, maximum=_MAX_EVENT_BYTES)
        try:
            named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except OSError:
            _fail("outbox publication disappeared")
        if (named.st_dev, named.st_ino) != identity or raw != expected:
            _fail("outbox publication was replaced")

    def _artifact(
        self, zone: str, relative: str
    ) -> tuple[str, str, int, tuple[int, int]]:
        spec = _ZONE_PATHS.get(zone)
        if spec is None:
            _fail("artifact zone is not a base vault zone")
        checked_relative = _relative(relative, "artifact relative")
        zone_relative = spec.relative_path(self._resolver.config)
        parts = zone_relative.parts + PurePosixPath(checked_relative).parts
        self._assert_root_binding()
        try:
            current_fd = os.dup(self._root_fd)
            for part in parts[:-1]:
                child_fd: int | None = None
                try:
                    child_fd = os.open(
                        part,
                        os.O_RDONLY
                        | getattr(os, "O_DIRECTORY", 0)
                        | getattr(os, "O_NOFOLLOW", 0),
                        dir_fd=current_fd,
                    )
                    child_opened = os.fstat(child_fd)
                    child_named = os.stat(
                        part, dir_fd=current_fd, follow_symlinks=False
                    )
                    if not stat.S_ISDIR(child_opened.st_mode) or (
                        child_opened.st_dev,
                        child_opened.st_ino,
                    ) != (child_named.st_dev, child_named.st_ino):
                        _fail("artifact parent changed while opening")
                except (OSError, OutboxError):
                    if child_fd is not None:
                        os.close(child_fd)
                    raise
                os.close(current_fd)
                if child_fd is None:  # pragma: no cover - local invariant
                    _fail("artifact parent was not opened")
                current_fd = child_fd
            fd = os.open(
                parts[-1],
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=current_fd,
            )
            opened = os.fstat(fd)
            named = os.stat(parts[-1], dir_fd=current_fd, follow_symlinks=False)
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_size > _MAX_ARTIFACT_BYTES
                or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
            ):
                _fail("outbox artifact must be a bounded regular file")
            path = self._root_path.joinpath(*parts)
            resolved_named = os.stat(path, follow_symlinks=False)
            if (opened.st_dev, opened.st_ino) != (
                resolved_named.st_dev,
                resolved_named.st_ino,
            ):
                _fail("artifact path changed during traversal")
            self._assert_root_binding()
            self._resolver.revalidate(path, zone, checked_relative, must_exist=True)
            digest = hashlib.sha256()
            remaining = _MAX_ARTIFACT_BYTES + 1
            while remaining:
                block = os.read(fd, min(64 * 1024, remaining))
                if not block:
                    break
                digest.update(block)
                remaining -= len(block)
            if remaining == 0:
                _fail("outbox artifact is too large")
            vault_ref = spec.relative_path(self._resolver.config)
            artifact_ref = str(vault_ref / PurePosixPath(checked_relative))
            return (
                artifact_ref,
                digest.hexdigest(),
                fd,
                (
                    opened.st_dev,
                    opened.st_ino,
                ),
            )
        except (OSError, VaultSchemaError, OutboxError):
            if "fd" in locals():
                os.close(fd)
            raise OutboxError("outbox artifact cannot be anchored safely") from None
        finally:
            if "current_fd" in locals():
                os.close(current_fd)

    def _revalidate_artifact(
        self,
        *,
        zone: str,
        relative: str,
        fd: int,
        identity: tuple[int, int],
        expected_hash: str,
    ) -> None:
        try:
            opened = os.fstat(fd)
            _, current_hash, current_fd, current_identity = self._artifact(
                zone, relative
            )
        except (OSError, VaultSchemaError, OutboxError):
            _fail("outbox artifact changed during event commit")
        try:
            if (
                not stat.S_ISREG(opened.st_mode)
                or (opened.st_dev, opened.st_ino) != identity
                or current_identity != identity
                or current_hash != expected_hash
            ):
                _fail("outbox artifact changed during event commit")
        finally:
            os.close(current_fd)
        try:
            os.lseek(fd, 0, os.SEEK_SET)
            digest = hashlib.sha256()
            remaining = _MAX_ARTIFACT_BYTES + 1
            while remaining:
                block = os.read(fd, min(64 * 1024, remaining))
                if not block:
                    break
                digest.update(block)
                remaining -= len(block)
        except OSError:
            _fail("outbox artifact changed during event commit")
        if remaining == 0 or digest.hexdigest() != expected_hash:
            _fail("outbox artifact bytes changed during event commit")

    def enqueue(
        self,
        capability: ActionCapability,
        *,
        run_id: str,
        event_type: str,
        semantic_key: str,
        summary: str,
        artifact_zone: str,
        artifact_relative: str,
        urgency: str = "normal",
        surface: str = "gated",
        requires_receipt: bool = True,
        after_prepare: Callable[[], None] | None = None,
        after_publish: Callable[[], None] | None = None,
    ) -> dict[str, object]:
        """Commit one event before transport; replay returns the first exact item."""

        try:
            grant = self._policy.require(capability)
        except AuthorityError as error:
            raise OutboxError(str(error)) from None
        if (
            grant.target != "vault:agent/outbox"
            or grant.access != "write"
            or grant.effect_kind != "outbox-artifact-commit"
            or not grant.artifact_commit
        ):
            _fail("capability does not authorize an outbox artifact commit")
        checked_run_id = _run_id(run_id)
        try:
            run_state = self._run_store.status(checked_run_id)
        except RunError:
            raise OutboxError("outbox event requires an existing valid run") from None
        if run_state["flow"] != grant.flow_id and not _is_finalize_emit_action(grant):
            _fail("outbox capability flow does not match authoritative run flow")
        if not authority_at_most(grant.authority, str(run_state["authority"])):
            _fail("outbox capability exceeds the immutable run authority")
        checked_type = _identifier(event_type, "event type")
        checked_summary = _semantic_text(summary, "summary", limit=512)
        if urgency not in _URGENCIES:
            _fail("outbox urgency is invalid")
        if surface not in _SURFACES:
            _fail("outbox surface is invalid")
        if not isinstance(requires_receipt, bool):
            _fail("requires_receipt must be boolean")
        artifact_ref, artifact_hash, artifact_fd, artifact_identity = self._artifact(
            artifact_zone, artifact_relative
        )
        try:
            dedupe_key = semantic_dedupe_key(
                flow_id=grant.flow_id,
                event_type=checked_type,
                semantic_key=semantic_key,
                artifact_ref=artifact_ref,
            )
            event_id = "event_" + dedupe_key[7:65]
            event = validate_event(
                {
                    "schema_version": OUTBOX_SCHEMA_VERSION,
                    "event_id": event_id,
                    "run_id": checked_run_id,
                    "flow_id": grant.flow_id,
                    "action": {
                        "action_id": grant.action_id,
                        "actor": grant.actor,
                        "authority": grant.authority,
                        "target": grant.target,
                    },
                    "type": checked_type,
                    "summary": checked_summary,
                    "artifact_ref": artifact_ref,
                    "artifact_sha256": artifact_hash,
                    "urgency": urgency,
                    "dedupe_key": dedupe_key,
                    "delivery_policy": {
                        "surface": surface,
                        "requires_receipt": requires_receipt,
                    },
                    "status": "pending",
                    "created_at": self._now(),
                }
            )
            directory = self._open_directory()
            locked = False
            try:
                try:
                    fcntl.flock(directory.fd, fcntl.LOCK_EX)
                    locked = True
                except OSError:
                    _fail("outbox writer lock cannot be acquired")
                name = f"{event_id}.json"
                data = _canonical_bytes(event) + b"\n"
                try:
                    os.stat(name, dir_fd=directory.fd, follow_symlinks=False)
                    already_exists = True
                except FileNotFoundError:
                    already_exists = False
                except OSError:
                    _fail("outbox event cannot be inspected safely")
                published: tuple[tuple[int, int], bytes] | None = None
                if not already_exists:
                    published = self._publish_once(
                        directory.fd,
                        name,
                        data,
                        after_prepare=after_prepare,
                        after_publish=after_publish,
                    )
                if published is None:
                    existing = _decode_event(
                        self._read_regular(directory.fd, name, maximum=_MAX_EVENT_BYTES)
                    )
                    comparable = set(_EVENT_KEYS) - {"run_id", "created_at"}
                    if any(existing[field] != event[field] for field in comparable):
                        _fail("dedupe key already belongs to a different event")
                    self._revalidate_directory(directory)
                    self._revalidate_artifact(
                        zone=artifact_zone,
                        relative=artifact_relative,
                        fd=artifact_fd,
                        identity=artifact_identity,
                        expected_hash=artifact_hash,
                    )
                    return existing
                try:
                    published_identity, published_data = published
                    self._revalidate_publication(
                        directory.fd, name, published_identity, published_data
                    )
                    self._revalidate_directory(directory)
                    self._revalidate_artifact(
                        zone=artifact_zone,
                        relative=artifact_relative,
                        fd=artifact_fd,
                        identity=artifact_identity,
                        expected_hash=artifact_hash,
                    )
                except OutboxError:
                    if not self._quarantine(directory.fd, name, published_identity):
                        raise OutboxError(
                            "unsafe outbox publication could not be quarantined"
                        ) from None
                    raise
                return _decode_event(published_data)
            finally:
                if locked:
                    fcntl.flock(directory.fd, fcntl.LOCK_UN)
                os.close(directory.fd)
        finally:
            os.close(artifact_fd)

    def _require_committed_finalize_trace(
        self, event: Mapping[str, object], event_raw: bytes
    ) -> None:
        action = event.get("action")
        if not isinstance(action, Mapping) or not _is_finalize_emit_action(
            {"flow_id": event.get("flow_id"), **action}
        ):
            return
        try:
            snapshot = self._run_store.snapshot(str(event["run_id"]))
            trace = self._run_store.trace_events(str(event["run_id"]))
        except RunError:
            _fail("finalize event is not bound to a valid committed run trace")
        committed = {item.name: item for item in snapshot.artifacts}.get(
            "finalize-event"
        )
        committed_log = {item.name: item for item in snapshot.artifacts}.get(
            "finalize-log"
        )
        committed_metric = {item.name: item for item in snapshot.artifacts}.get(
            "finalize-metric"
        )
        event_hash = hashlib.sha256(event_raw).hexdigest()
        if (
            snapshot.state.get("status") not in {"waiting_human", "succeeded"}
            or committed is None
            or committed_log is None
            or committed_metric is None
            or committed.zone != "agent/outbox"
            or committed.relative != f"{event['event_id']}.json"
            or committed.sha256 != event_hash
            or committed_log.state_ref != event.get("artifact_ref")
            or committed_log.sha256 != event.get("artifact_sha256")
        ):
            _fail("finalize event is not yet bound to exact committed run evidence")
        item = trace[-1] if trace else {}
        actions = item.get("actions")
        expected_step = (
            "finalize-review-ready"
            if snapshot.state["status"] == "waiting_human"
            else "finalize-complete"
        )
        if (
            item.get("schema_version") != 2
            or item.get("step_id") != expected_step
            or item.get("at") != snapshot.state.get("updated_at")
            or item.get("authority") != "internal-write"
            or item.get("output_hash") != event.get("artifact_sha256")
            or snapshot.state.get("phase")
            != (
                "review" if snapshot.state["status"] == "waiting_human" else "finalized"
            )
            or snapshot.state.get("waiting_for")
            != (
                "review-decision"
                if snapshot.state["status"] == "waiting_human"
                else None
            )
            or not isinstance(actions, list)
            or tuple(action.get("action_id") for action in actions)
            != FINALIZE_ACTION_ORDER
            or any(
                action.get("flow_id") != "finalize"
                or action.get("status") != "succeeded"
                for action in actions
            )
        ):
            _fail("finalize event is not bound to the exact committed finalize trace")

    def _read_committed_artifact(self, artifact: object) -> bytes:
        zone = getattr(artifact, "zone", None)
        relative = getattr(artifact, "relative", None)
        state_ref = getattr(artifact, "state_ref", None)
        expected_hash = getattr(artifact, "sha256", None)
        if not all(
            isinstance(item, str) for item in (zone, relative, state_ref, expected_hash)
        ):
            _fail("gateway producer artifact binding is invalid")
        artifact_ref, actual_hash, artifact_fd, _identity = self._artifact(
            str(zone), str(relative)
        )
        try:
            raw = self._read_regular_fd(artifact_fd, maximum=_MAX_ARTIFACT_BYTES)
        finally:
            os.close(artifact_fd)
        if artifact_ref != state_ref or actual_hash != expected_hash:
            _fail("gateway producer artifact bytes are not exact")
        return raw

    def _require_committed_producer_event(
        self, event: Mapping[str, object], event_raw: bytes
    ) -> None:
        flow_id = str(event["flow_id"])
        run_id = str(event["run_id"])
        event_id = str(event["event_id"])
        if flow_id not in {"ambient", "bundle"}:
            _fail("gateway event has no supported committed producer")
        event_name = f"{flow_id}-event-{event_id.removeprefix('event_')[:24]}"
        try:
            producer = self._run_store.producer_snapshot(
                run_id, producer_evidence=event_name
            )
            traces = self._run_store.trace_events(run_id)
        except RunError:
            _fail("gateway event lacks exact committed producer evidence")
        if producer.state.get("flow") != flow_id:
            _fail("gateway event producer flow is invalid")
        artifacts = {item.name: item for item in producer.artifacts}
        event_artifact = artifacts.get(event_name)
        evidence_items = tuple(
            item
            for item in producer.artifacts
            if item.name.startswith(f"{flow_id}-evidence-")
        )
        if event_artifact is None or len(evidence_items) != 1:
            _fail("gateway event producer bundle is incomplete")
        evidence_artifact = evidence_items[0]
        evidence_raw = self._read_committed_artifact(evidence_artifact)
        try:
            if flow_id == "ambient":
                from tool_life_os_runtime.ext.flows.ambient import (
                    inspect_ambient_run_evidence,
                )

                evidence = inspect_ambient_run_evidence(evidence_artifact, evidence_raw)
                expected_actions = (
                    "scan-eligible-signals",
                    "read-ambient-projects",
                    "read-ambient-review",
                    "read-ambient-memory",
                    "commit-nudge-outbox-event",
                    "record-run-state",
                )
            else:
                from tool_life_os_runtime.ext.flows.bundle import (
                    inspect_bundle_run_evidence,
                )

                evidence = inspect_bundle_run_evidence(evidence_artifact, evidence_raw)
                expected_actions = (
                    "collect-batched-items",
                    "read-pending-outbox",
                    "commit-bundle-outbox-event",
                    "record-run-state",
                )
        except (ValueError, UnicodeError, RecursionError):
            _fail("gateway event producer evidence is invalid")
        if evidence.outcome != "emitted":
            _fail("gateway event producer did not emit an event")
        token = hashlib.sha256(evidence.operation_id.encode()).hexdigest()
        expected_names = {
            evidence_artifact.name,
            f"{flow_id}-marker-{token[:24]}",
            f"{flow_id}-payload-{str(evidence.payload_sha256)[:24]}",
            event_name,
        }
        if set(artifacts) != expected_names:
            _fail("gateway event producer bundle is not exact")
        bindings = (
            (
                artifacts[f"{flow_id}-marker-{token[:24]}"],
                evidence.marker_ref,
                evidence.marker_sha256,
                "agent/outbox",
            ),
            (
                artifacts[f"{flow_id}-payload-{str(evidence.payload_sha256)[:24]}"],
                evidence.payload_ref,
                evidence.payload_sha256,
                "agent/outbox",
            ),
            (
                event_artifact,
                evidence.event_ref,
                evidence.event_sha256,
                "agent/outbox",
            ),
        )
        for artifact, state_ref, digest, zone in bindings:
            if (
                artifact.zone != zone
                or artifact.state_ref != state_ref
                or artifact.sha256 != digest
            ):
                _fail("gateway event producer artifact binding is invalid")
        event_hash = hashlib.sha256(event_raw).hexdigest()
        if (
            evidence.run_id != run_id
            or evidence.event_id != event_id
            or evidence.event_sha256 != event_hash
            or event_artifact.relative != f"{event_id}.json"
            or event.get("artifact_ref") != evidence.payload_ref
            or event.get("artifact_sha256") != evidence.payload_sha256
        ):
            _fail("gateway event bytes disagree with committed producer evidence")
        matches = tuple(
            trace
            for trace in traces
            if trace.get("step_id") == evidence_artifact.step_id
        )
        if len(matches) != 1:
            _fail("gateway event producer trace is ambiguous")
        trace = matches[0]
        actions = trace.get("actions")
        if (
            trace.get("schema_version") != 2
            or trace.get("run_id") != run_id
            or trace.get("authority") != "internal-write"
            or trace.get("input_hash") != evidence.request_sha256
            or trace.get("output_hash") != evidence_artifact.sha256
            or trace.get("executor_profile") != producer.state.get("executor")
            or trace.get("tool_outcomes") != []
            or not isinstance(actions, list)
            or tuple(action.get("action_id") for action in actions) != expected_actions
            or any(
                action.get("sequence") != sequence
                or action.get("flow_id") != flow_id
                or action.get("status") != "succeeded"
                for sequence, action in enumerate(actions, start=1)
            )
        ):
            _fail("gateway event producer trace is not exact")

    def _require_committed_delivery_event(
        self, event: Mapping[str, object], event_raw: bytes
    ) -> str:
        if event_raw != _canonical_bytes(event) + b"\n":
            _fail("gateway event bytes are not canonical")
        action = event.get("action")
        if isinstance(action, Mapping) and _is_finalize_emit_action(
            {"flow_id": event.get("flow_id"), **action}
        ):
            self._require_committed_finalize_trace(event, event_raw)
        else:
            self._require_committed_producer_event(event, event_raw)
        return hashlib.sha256(event_raw).hexdigest()

    def _read_delivery_event(
        self, capability: ActionCapability, event_id: str, *, require_commit: bool
    ) -> tuple[dict[str, object], str | None]:
        """Read one event and optionally prove its exact producer commit."""

        try:
            grant = self._policy.require(capability)
        except AuthorityError as error:
            raise OutboxError(str(error)) from None
        if (
            grant.flow_id != "gateway-delivery"
            or grant.action_id != "read-semantic-outbox-event"
            or grant.actor != "runtime"
            or grant.authority != "read"
            or grant.target != "vault:agent/outbox"
            or grant.access != "read"
        ):
            _fail("capability does not authorize gateway outbox read")
        checked = _identifier(event_id, "event_id")
        directory = self._open_directory()
        event_fd: int | None = None
        locked = False
        try:
            fcntl.flock(directory.fd, fcntl.LOCK_SH)
            locked = True
            event_fd, identity, raw, event = self._open_event_at(directory.fd, checked)
            self._revalidate_event_at(directory.fd, checked, event_fd, identity, raw)
            if require_commit:
                event_sha256 = self._require_committed_delivery_event(event, raw)
            else:
                event_sha256 = None
                self._require_committed_finalize_trace(event, raw)
            self._revalidate_directory(directory)
            return event, event_sha256
        finally:
            if event_fd is not None:
                os.close(event_fd)
            if locked:
                fcntl.flock(directory.fd, fcntl.LOCK_UN)
            os.close(directory.fd)

    def read_for_delivery(
        self, capability: ActionCapability, event_id: str
    ) -> dict[str, object]:
        """Read one normalized event only with the exact gateway read action."""
        event, _event_sha256 = self._read_delivery_event(
            capability, event_id, require_commit=False
        )
        return event

    def read_committed_for_delivery(
        self, capability: ActionCapability, event_id: str
    ) -> tuple[dict[str, object], str]:
        """Return only an exact canonical event from its committed producer bundle."""

        event, event_sha256 = self._read_delivery_event(
            capability, event_id, require_commit=True
        )
        if event_sha256 is None:  # pragma: no cover - local invariant
            _fail("gateway event commit hash is missing")
        return event, event_sha256

    def record_delivery_receipt(
        self,
        capability: ActionCapability,
        *,
        event_id: str,
        attempt_id: str,
        status: str,
        effect_hash: str,
        expected_event_sha256: str | None = None,
    ) -> dict[str, object]:
        """Persist delivery evidence separately; the immutable event survives failure."""

        try:
            grant = self._policy.require(capability)
        except AuthorityError as error:
            raise OutboxError(str(error)) from None
        if (
            grant.flow_id != "gateway-delivery"
            or grant.action_id != "reconcile-outbox-receipt"
            or grant.actor != "runtime"
            or grant.authority != "internal-write"
            or grant.target != "vault:agent/outbox"
            or grant.access != "write"
            or grant.effect_kind != "gateway-receipt-reconciliation"
            or not grant.artifact_commit
        ):
            _fail("capability does not authorize receipt reconciliation")
        checked_event_id = _identifier(event_id, "event_id")
        checked_attempt = _identifier(attempt_id, "attempt_id")
        if status not in {"delivered", "failed"}:
            _fail("receipt status is invalid")
        gateway_effect = _hash(effect_hash, "effect_hash")
        expected_event_hash = (
            None
            if expected_event_sha256 is None
            else _hash(expected_event_sha256, "expected_event_sha256")
        )
        directory = self._open_directory()
        locked = False
        event_fd: int | None = None
        receipt_directory: _AnchoredDirectory | None = None
        created_identity: tuple[int, int] | None = None
        receipt_name: str | None = None
        try:
            fcntl.flock(directory.fd, fcntl.LOCK_EX)
            locked = True
            event_fd, event_identity, event_raw, event = self._open_event_at(
                directory.fd, checked_event_id
            )
            if expected_event_hash is None:
                self._require_committed_finalize_trace(event, event_raw)
            else:
                committed_hash = self._require_committed_delivery_event(
                    event, event_raw
                )
                if committed_hash != expected_event_hash:
                    _fail("gateway event changed after committed delivery read")
            event_sha256 = hashlib.sha256(event_raw).hexdigest()
            bound_effect = bound_receipt_effect_hash(
                event_sha256=event_sha256,
                gateway_effect_sha256=gateway_effect,
            )
            receipt_digest = hashlib.sha256(
                _canonical_bytes(
                    {
                        "schema_version": OUTBOX_SCHEMA_VERSION,
                        "event_id": event["event_id"],
                        "attempt_id": checked_attempt,
                    }
                )
            ).hexdigest()
            receipt_id = "receipt_" + receipt_digest[:56]
            receipt = validate_receipt(
                {
                    "schema_version": 1,
                    "receipt_id": receipt_id,
                    "run_id": event["run_id"],
                    "event_id": event["event_id"],
                    "status": status,
                    # P1-05 receipt schema remains v1.  Its effect_hash now
                    # commits to both exact event bytes and gateway evidence.
                    "effect_hash": bound_effect,
                    "at": self._now(),
                }
            )
            receipt_directory = self._open_directory("receipts", create=True)
            receipt_name = f"{receipt_id}.json"
            created_identity = _create_json_once_at(
                receipt_directory.fd, receipt_name, receipt
            )
            if created_identity is None:
                existing = _decode_receipt(
                    self._read_regular(
                        receipt_directory.fd,
                        receipt_name,
                        maximum=_MAX_EVENT_BYTES,
                    )
                )
                comparable = set(receipt) - {"at"}
                if any(existing[field] != receipt[field] for field in comparable):
                    _fail("receipt ID already has different event evidence")
                receipt = existing
            else:
                expected_receipt = _canonical_bytes(receipt) + b"\n"
                self._revalidate_publication(
                    receipt_directory.fd,
                    receipt_name,
                    created_identity,
                    expected_receipt,
                )
            self._revalidate_event_at(
                directory.fd,
                checked_event_id,
                event_fd,
                event_identity,
                event_raw,
            )
            self._revalidate_directory(receipt_directory)
            self._revalidate_directory(directory)
            return receipt
        except (RunError, OutboxError) as error:
            if (
                created_identity is not None
                and receipt_directory is not None
                and receipt_name is not None
            ):
                if not self._quarantine(
                    receipt_directory.fd,
                    receipt_name,
                    created_identity,
                    kind="receipt",
                ):
                    raise OutboxError(
                        "unsafe receipt could not be quarantined"
                    ) from None
            if isinstance(error, OutboxError):
                raise
            raise OutboxError(
                "delivery receipt could not be reconciled safely"
            ) from error
        finally:
            if receipt_directory is not None:
                os.close(receipt_directory.fd)
            if event_fd is not None:
                os.close(event_fd)
            if locked:
                fcntl.flock(directory.fd, fcntl.LOCK_UN)
            os.close(directory.fd)
