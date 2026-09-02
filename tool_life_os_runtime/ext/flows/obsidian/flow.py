"""Safe, short-lived Markdown primitives for the portable vault.

The module deliberately has no run state and no domain rewrite logic.  Every
read and edit is authorized as one exact P0 obsidian action, anchored to a
configured vault zone, and validated before any durable write.
"""

from __future__ import annotations

from contextlib import contextmanager
import ctypes
from dataclasses import dataclass
from datetime import date
import errno
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
from typing import Iterable, Iterator, Literal
import unicodedata

from tool_life_os_runtime.ext.review.authority import (
    ActionCapability,
    AuthorityError,
    AuthorityPolicy,
)
from tool_life_os_runtime.ext.vault.config import ConfigError
from tool_life_os_runtime.ext.vault.schema import VaultPathResolver, VaultSchemaError


OBSIDIAN_SCHEMA_VERSION = 1
EDIT_CRASH_SEAMS = frozenset(
    {"after-prepare-before-replace", "after-replace-before-cleanup"}
)

_MAX_NOTE_BYTES = 1024 * 1024
_MAX_FRONTMATTER_BYTES = 64 * 1024
_MAX_FIELDS = 64
_MAX_LIST_ITEMS = 128
_MAX_LINKS = 2048
_MAX_FEEDBACK_BLOCKS = 256
_MAX_DIRECTORY_ENTRIES = 4096
_MAX_RECEIPT_BYTES = 16 * 1024
_ID = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
_KEY = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_WINDOWS_FORBIDDEN = frozenset('<>:"|?*')
_ARCHIVE_COMPONENTS = frozenset({"_archive", "_trash", "_on_hold"})
_RUNTIME_PREFIXES = (".lifeos-note-", ".lifeos-retired-")
_RETIRED_MARKER = b"lifeos-retired-v1\n"
_RESERVED_COMPONENTS = frozenset(
    {"con", "prn", "aux", "nul"}
    | {f"com{number}" for number in range(1, 10)}
    | {f"lpt{number}" for number in range(1, 10)}
)
_READ_GRANTS = {
    "inbox": ("read-inbox-note", "vault:inbox"),
    "knowledge": ("read-safe-note", "vault:knowledge"),
    "tasks": ("read-task-note", "vault:tasks"),
    "projects": ("read-project-note", "vault:projects"),
    "agent/memory": ("read-memory-note", "vault:agent/memory"),
}
_WRITE_GRANTS = {
    "inbox": ("edit-inbox", "vault:inbox"),
    "tasks": ("edit-tasks", "vault:tasks"),
    "projects": ("edit-projects", "vault:projects"),
    "agent/memory-metadata": (
        "edit-memory-metadata",
        "vault:agent/memory-metadata",
    ),
}
_CONFIG_ZONE_PATHS = {
    "inbox": ("inbox", PurePosixPath(".")),
    "knowledge": ("knowledge", PurePosixPath(".")),
    "tasks": ("tasks", PurePosixPath(".")),
    "projects": ("projects", PurePosixPath(".")),
    "agent/memory": ("memory", PurePosixPath(".")),
    "agent/memory-metadata": ("memory", PurePosixPath("metadata")),
}
_MISSING = object()


class ObsidianError(ValueError):
    """A note, path, capability, or filesystem observation is unsafe."""


class ObsidianCrash(BaseException):
    """Deterministic test-only interruption at a documented edit seam."""


def _fail(message: str) -> None:
    raise ObsidianError(message)


@dataclass(frozen=True)
class NoteRef:
    schema_version: int
    zone: str
    relative: str


@dataclass(frozen=True)
class WikiLink:
    raw: str
    target: str
    alias: str | None
    heading: str | None
    line: int


@dataclass(frozen=True)
class FeedbackBlock:
    task_line: str
    feedback: str
    start_line: int
    end_line: int


@dataclass(frozen=True)
class NoteSnapshot:
    schema_version: int
    zone: str
    relative: str
    path: str
    sha256: str
    size_bytes: int
    content: str
    frontmatter: tuple[tuple[str, object], ...]
    body: str
    wikilinks: tuple[WikiLink, ...]

    def metadata(self) -> dict[str, object]:
        if (
            not isinstance(self.frontmatter, tuple)
            or len(self.frontmatter) > _MAX_FIELDS
        ):
            _fail("note snapshot frontmatter is invalid")
        result: dict[str, object] = {}
        for item in self.frontmatter:
            if not isinstance(item, tuple) or len(item) != 2:
                _fail("note snapshot frontmatter is invalid")
            key, value = item
            if not isinstance(key, str) or _KEY.fullmatch(key) is None or key in result:
                _fail("note snapshot frontmatter is invalid")
            if isinstance(value, tuple):
                if len(value) > _MAX_LIST_ITEMS:
                    _fail("note snapshot frontmatter value is invalid")
                checked: list[object] = []
                for entry in value:
                    _validate_frontmatter_value(entry)
                    checked.append(entry)
                result[key] = checked
            else:
                _validate_frontmatter_value(value)
                result[key] = value
        return result


@dataclass(frozen=True)
class NoteIssue:
    rule_id: str
    severity: str
    path: str
    line: int | None
    evidence_sha256: str


@dataclass(frozen=True)
class NoteValidation:
    schema_version: int
    path: str
    source_sha256: str
    issues: tuple[NoteIssue, ...]

    @property
    def valid(self) -> bool:
        if (
            type(self.schema_version) is not int
            or self.schema_version != OBSIDIAN_SCHEMA_VERSION
            or not isinstance(self.path, str)
            or not isinstance(self.source_sha256, str)
            or _SHA256.fullmatch(self.source_sha256) is None
            or not isinstance(self.issues, tuple)
        ):
            _fail("note validation fields are invalid")
        _canonical_relative(self.path, "note validation path", markdown=True)
        for issue in self.issues:
            if (
                not isinstance(issue, NoteIssue)
                or not isinstance(issue.rule_id, str)
                or not isinstance(issue.severity, str)
                or not isinstance(issue.path, str)
                or issue.path != self.path
                or (issue.line is not None and type(issue.line) is not int)
                or not isinstance(issue.evidence_sha256, str)
                or _SHA256.fullmatch(issue.evidence_sha256) is None
            ):
                _fail("note validation issue fields are invalid")
            _utf8(issue.rule_id, "note validation rule_id", maximum=128)
            _utf8(issue.severity, "note validation severity", maximum=32)
        return not any(issue.severity == "error" for issue in self.issues)


@dataclass(frozen=True)
class NoteEdit:
    schema_version: int
    operation_id: str
    ref: NoteRef
    expected_sha256: str | None
    content: str


@dataclass(frozen=True)
class NoteEditReceipt:
    schema_version: int
    operation_id: str
    path: str
    before_sha256: str | None
    after_sha256: str
    status: str


@dataclass(frozen=True)
class _ObservedFile:
    data: bytes
    digest: str
    identity: tuple[int, int, int, int, int, int]


def _identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _open_directory_path(path: Path, message: str) -> tuple[int, tuple[int, int]]:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd: int | None = None
    try:
        fd = os.open(path, flags)
        opened = os.fstat(fd)
        named = os.stat(path, follow_symlinks=False)
    except OSError:
        if fd is not None:
            os.close(fd)
        _fail(message)
    if (
        not stat.S_ISDIR(opened.st_mode)
        or _identity(opened)[:2] != _identity(named)[:2]
    ):
        os.close(fd)
        _fail(message)
    return fd, _identity(opened)[:2]


def _pin_authorized_root(resolver: VaultPathResolver) -> tuple[Path, tuple[int, int]]:
    """Capture the physical configured root without reaching into resolver internals."""

    try:
        zone = resolver.resolve("inbox", ".", must_exist=True)
        relative = resolver.config.zone(_CONFIG_ZONE_PATHS["inbox"][0])
    except (ConfigError, VaultSchemaError):
        _fail("configured vault root cannot be pinned")
    root = Path(zone)
    for _part in relative.parts:
        root = root.parent
    fd, identity = _open_directory_path(root, "configured vault root cannot be pinned")
    os.close(fd)
    return root, identity


def _require_pinned_root(path: Path, expected: tuple[int, int]) -> None:
    fd, current = _open_directory_path(path, "configured vault root identity changed")
    os.close(fd)
    if current != expected:
        _fail("configured vault root identity changed")


def _has_control(value: str, *, allow_layout: bool = False) -> bool:
    allowed = {"\n", "\t"} if allow_layout else set()
    return any(
        character not in allowed
        and (
            unicodedata.category(character).startswith("C")
            or unicodedata.category(character) in {"Zl", "Zp"}
        )
        for character in value
    )


def _utf8(value: object, label: str, *, maximum: int, layout: bool = False) -> str:
    if not isinstance(value, str):
        _fail(f"{label} must be text")
    try:
        raw = value.encode("utf-8")
    except UnicodeError:
        _fail(f"{label} must be valid UTF-8")
    if len(raw) > maximum or _has_control(value, allow_layout=layout):
        _fail(f"{label} is not bounded portable text")
    if unicodedata.normalize("NFC", value) != value:
        _fail(f"{label} must use Unicode NFC")
    return value


def _portable_component(value: str, label: str, *, allow_hidden: bool = True) -> str:
    _utf8(value, label, maximum=255)
    if (
        not value
        or value in {".", ".."}
        or value.strip() != value
        or value.endswith(".")
        or any(character in _WINDOWS_FORBIDDEN for character in value)
        or "/" in value
        or "\\" in value
        or (not allow_hidden and value.startswith("."))
        or value.split(".", 1)[0].casefold() in _RESERVED_COMPONENTS
    ):
        _fail(f"{label} contains a non-portable path component")
    return value


def _canonical_relative(value: object, label: str, *, markdown: bool) -> str:
    text = _utf8(value, label, maximum=4096)
    if (
        not text
        or text.startswith("/")
        or text.endswith("/")
        or "//" in text
        or "\\" in text
    ):
        _fail(f"{label} must be a canonical relative POSIX path")
    path = PurePosixPath(text)
    if path.as_posix() != text or any(part in {".", ".."} for part in path.parts):
        _fail(f"{label} must be a canonical relative POSIX path")
    for part in path.parts:
        _portable_component(part, label)
    if any(_portable_key(part) in _ARCHIVE_COMPONENTS for part in path.parts):
        _fail(f"{label} enters an excluded archive zone")
    if markdown and path.suffix.casefold() != ".md":
        _fail(f"{label} must name a Markdown file")
    for part in path.parts:
        key = unicodedata.normalize("NFC", part).casefold()
        if key.startswith(_RUNTIME_PREFIXES):
            _fail(f"{label} uses a reserved temporary namespace")
    return text


def _validate_ref(ref: NoteRef, *, write: bool | None) -> NoteRef:
    if not isinstance(ref, NoteRef) or type(ref.schema_version) is not int:
        _fail("note reference is invalid")
    if ref.schema_version != OBSIDIAN_SCHEMA_VERSION:
        _fail("unsupported note reference schema_version")
    if not isinstance(ref.zone, str):
        _fail("note reference zone is invalid")
    if write is None:
        allowed = {**_READ_GRANTS, **_WRITE_GRANTS}
    else:
        allowed = _WRITE_GRANTS if write else _READ_GRANTS
    if ref.zone not in allowed:
        if write is True and ref.zone in _READ_GRANTS:
            _fail("obsidian direct edit is forbidden for this zone")
        _fail("note reference names an unsupported zone")
    relative = _canonical_relative(ref.relative, "note relative path", markdown=True)
    return NoteRef(OBSIDIAN_SCHEMA_VERSION, ref.zone, relative)


def _root_relative_path(resolver: VaultPathResolver, ref: NoteRef) -> str:
    try:
        config_name, suffix = _CONFIG_ZONE_PATHS[ref.zone]
        base = resolver.config.zone(config_name)
    except ConfigError:
        _fail("configured note zone cannot be represented")
    path = base / suffix / PurePosixPath(ref.relative)
    text = path.as_posix()
    _canonical_relative(text, "configured note path", markdown=True)
    return text


def _require_capability(
    policy: AuthorityPolicy,
    capability: ActionCapability,
    *,
    zone: str,
    write: bool,
) -> None:
    if not isinstance(policy, AuthorityPolicy):
        _fail("obsidian requires an AuthorityPolicy")
    grants = _WRITE_GRANTS if write else _READ_GRANTS
    action_id, target = grants[zone]
    try:
        grant = policy.require(capability)
    except AuthorityError as error:
        raise ObsidianError(str(error)) from None
    expected = {
        "flow_id": "obsidian",
        "action_id": action_id,
        "actor": "runtime",
        "authority": "domain-write" if write else "read",
        "target": target,
        "access": "write" if write else "read",
        "effect_kind": "artifact-commit" if write else "read-only",
        "artifact_commit": write,
    }
    if any(getattr(grant, field) != value for field, value in expected.items()):
        _fail("capability does not authorize the exact obsidian action")


def _portable_key(value: str) -> str:
    _portable_component(value, "vault directory entry")
    return unicodedata.normalize("NFC", value).casefold()


def _list_directory(directory_fd: int) -> tuple[str, ...]:
    try:
        entries = os.listdir(directory_fd)
    except OSError:
        _fail("vault directory cannot be inspected")
    if len(entries) > _MAX_DIRECTORY_ENTRIES:
        _fail("vault directory has too many entries")
    for entry in entries:
        _portable_key(entry)
    return tuple(entries)


def _exact_entry(directory_fd: int, name: str) -> bool:
    wanted = _portable_key(name)
    matches = [
        entry
        for entry in _list_directory(directory_fd)
        if _portable_key(entry) == wanted
    ]
    if len(matches) > 1 or (matches and matches[0] != name):
        _fail("vault contains a portable namespace collision")
    return bool(matches)


def _open_directory_at(directory_fd: int, name: str) -> int:
    if not _exact_entry(directory_fd, name):
        _fail("required note parent directory is missing")
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    child_fd: int | None = None
    try:
        child_fd = os.open(name, flags, dir_fd=directory_fd)
        opened = os.fstat(child_fd)
        named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except OSError:
        if child_fd is not None:
            os.close(child_fd)
        _fail("note parent is not a safe directory")
    if not stat.S_ISDIR(opened.st_mode) or _identity(opened) != _identity(named):
        os.close(child_fd)
        _fail("note parent changed while it was opened")
    return child_fd


@contextmanager
def _open_zone(
    resolver: VaultPathResolver, zone: str, *, write: bool
) -> Iterator[tuple[int, os.PathLike[str]]]:
    try:
        resolved = resolver.resolve(
            zone,
            ".",
            for_write=write,
            allow_archive=False,
            must_exist=True,
        )
    except VaultSchemaError as error:
        raise ObsidianError(str(error)) from None
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd: int | None = None
    try:
        fd = os.open(resolved, flags)
        opened = os.fstat(fd)
        named = os.stat(resolved, follow_symlinks=False)
    except OSError:
        if fd is not None:
            os.close(fd)
        _fail("configured note zone is not a safe directory")
    if not stat.S_ISDIR(opened.st_mode) or _identity(opened) != _identity(named):
        os.close(fd)
        _fail("configured note zone changed while it was opened")
    try:
        yield fd, resolved
    finally:
        os.close(fd)


@contextmanager
def _open_parent(zone_fd: int, relative: str) -> Iterator[tuple[int, str]]:
    parts = PurePosixPath(relative).parts
    current_fd = os.dup(zone_fd)
    try:
        for part in parts[:-1]:
            child_fd = _open_directory_at(current_fd, part)
            os.close(current_fd)
            current_fd = child_fd
        yield current_fd, parts[-1]
    finally:
        os.close(current_fd)


def _revalidate_parent(
    resolver: VaultPathResolver,
    ref: NoteRef,
    resolved_zone: os.PathLike[str],
    parent_fd: int,
    *,
    write: bool,
) -> None:
    try:
        resolver.revalidate(
            resolved_zone,
            ref.zone,
            ".",
            for_write=write,
            allow_archive=False,
            must_exist=True,
        )
    except VaultSchemaError as error:
        raise ObsidianError(str(error)) from None
    with _open_zone(resolver, ref.zone, write=write) as (fresh_zone_fd, _fresh):
        with _open_parent(fresh_zone_fd, ref.relative) as (fresh_parent_fd, _leaf):
            try:
                held = _identity(os.fstat(parent_fd))[:2]
                fresh = _identity(os.fstat(fresh_parent_fd))[:2]
            except OSError:
                _fail("note parent cannot be revalidated")
            if held != fresh:
                _fail("note parent identity changed")


def _read_fd_bounded(fd: int) -> tuple[bytes, os.stat_result]:
    try:
        before = os.fstat(fd)
    except OSError:
        _fail("note cannot be inspected")
    if not stat.S_ISREG(before.st_mode) or before.st_size > _MAX_NOTE_BYTES:
        _fail("note must be a bounded regular file")
    chunks: list[bytes] = []
    remaining = _MAX_NOTE_BYTES + 1
    try:
        os.lseek(fd, 0, os.SEEK_SET)
        while remaining:
            chunk = os.read(fd, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(fd)
    except OSError:
        _fail("note cannot be read")
    data = b"".join(chunks)
    if len(data) > _MAX_NOTE_BYTES or _identity(before) != _identity(after):
        _fail("note changed during bounded read")
    return data, after


def _observe_at(directory_fd: int, name: str) -> _ObservedFile | None:
    if not _exact_entry(directory_fd, name):
        return None
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(name, flags, dir_fd=directory_fd)
    except OSError:
        _fail("note leaf is not a safe regular file")
    try:
        data, opened = _read_fd_bounded(fd)
        try:
            named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except OSError:
            _fail("note leaf changed during bounded read")
        if _identity(opened) != _identity(named):
            _fail("note leaf changed during bounded read")
        return _ObservedFile(data, hashlib.sha256(data).hexdigest(), _identity(opened))
    finally:
        os.close(fd)


def _write_exclusive_at(directory_fd: int, name: str, data: bytes) -> None:
    if len(data) > _MAX_NOTE_BYTES:
        _fail("note bytes are too large")
    if _exact_entry(directory_fd, name):
        _fail("note staging path already exists")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(name, flags, 0o600, dir_fd=directory_fd)
    except OSError:
        _fail("note staging file cannot be created")
    try:
        offset = 0
        while offset < len(data):
            written = os.write(fd, data[offset:])
            if written <= 0:
                _fail("note staging file cannot be written")
            offset += written
        os.fsync(fd)
    except OSError:
        _fail("note staging file cannot be written")
    finally:
        os.close(fd)
    _fsync_directory(directory_fd, "note staging directory cannot be synced")


def _rewrite_observed_at(
    directory_fd: int,
    name: str,
    observed: _ObservedFile,
    data: bytes,
    *,
    changed_message: str,
) -> _ObservedFile:
    """Rewrite only the inode already observed at one reserved runtime path."""

    if len(data) > _MAX_NOTE_BYTES:
        _fail("note bytes are too large")
    flags = os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
    fd: int | None = None
    try:
        fd = os.open(name, flags, dir_fd=directory_fd)
        opened = os.fstat(fd)
        named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if (
            _identity(opened) != observed.identity
            or _identity(named) != observed.identity
        ):
            _fail(changed_message)
        os.ftruncate(fd, 0)
        offset = 0
        while offset < len(data):
            written = os.write(fd, data[offset:])
            if written <= 0:
                _fail(changed_message)
            offset += written
        os.fsync(fd)
        rewritten = os.fstat(fd)
    except OSError:
        _fail(changed_message)
    finally:
        if fd is not None:
            os.close(fd)
    current = _observe_at(directory_fd, name)
    expected_digest = hashlib.sha256(data).hexdigest()
    if (
        current is None
        or current.identity[:3] != _identity(rewritten)[:3]
        or current.digest != expected_digest
    ):
        _fail(changed_message)
    return current


def _fsync_directory(directory_fd: int, message: str) -> None:
    try:
        os.fsync(directory_fd)
    except OSError:
        _fail(message)


def _rename_exchange(directory_fd: int, first: str, second: str) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    first_raw = os.fsencode(first)
    second_raw = os.fsencode(second)
    if hasattr(libc, "renameatx_np"):
        result = libc.renameatx_np(
            directory_fd,
            ctypes.c_char_p(first_raw),
            directory_fd,
            ctypes.c_char_p(second_raw),
            0x00000002,
        )
    elif hasattr(libc, "renameat2"):
        result = libc.renameat2(
            directory_fd,
            ctypes.c_char_p(first_raw),
            directory_fd,
            ctypes.c_char_p(second_raw),
            2,
        )
    else:
        raise OSError(errno.ENOSYS, "atomic exchange is unavailable")
    if result != 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))


def _rename_noreplace(directory_fd: int, source: str, destination: str) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    source_raw = os.fsencode(source)
    destination_raw = os.fsencode(destination)
    if hasattr(libc, "renameatx_np"):
        result = libc.renameatx_np(
            directory_fd,
            ctypes.c_char_p(source_raw),
            directory_fd,
            ctypes.c_char_p(destination_raw),
            0x00000004,
        )
        if result == 0:
            return
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))
    if hasattr(libc, "renameat2"):
        result = libc.renameat2(
            directory_fd,
            ctypes.c_char_p(source_raw),
            directory_fd,
            ctypes.c_char_p(destination_raw),
            1,
        )
        if result == 0:
            return
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))
    os.link(
        source,
        destination,
        src_dir_fd=directory_fd,
        dst_dir_fd=directory_fd,
        follow_symlinks=False,
    )
    os.unlink(source, dir_fd=directory_fd)


def _stage_exact(directory_fd: int, name: str, data: bytes) -> None:
    observed = _observe_at(directory_fd, name)
    if observed is None:
        _write_exclusive_at(directory_fd, name, data)
    elif observed.data == _RETIRED_MARKER:
        _rewrite_observed_at(
            directory_fd,
            name,
            observed,
            data,
            changed_message="note retirement marker changed during reuse",
        )
    elif observed.data != data:
        _fail("note staging path contains foreign bytes")


def _remove_exact_temp(
    directory_fd: int,
    name: str,
    expected_digest: str,
    expected_identity: tuple[int, int, int] | None = None,
) -> None:
    observed = _observe_at(directory_fd, name)
    if observed is None:
        return
    if observed.data == _RETIRED_MARKER:
        return
    if observed.digest != expected_digest or (
        expected_identity is not None and observed.identity[:3] != expected_identity
    ):
        _fail("note staging path contains foreign bytes")
    _rewrite_observed_at(
        directory_fd,
        name,
        observed,
        _RETIRED_MARKER,
        changed_message="foreign note retirement entry was preserved",
    )
    _fsync_directory(directory_fd, "note staging cleanup cannot be synced")


def _rollback_created_note(
    directory_fd: int,
    leaf: str,
    temporary: str,
    published: _ObservedFile,
) -> None:
    current = _observe_at(directory_fd, leaf)
    if (
        current is None
        or current.identity[:3] != published.identity[:3]
        or current.digest != published.digest
    ):
        _fail("published note changed before rollback")
    try:
        _rename_noreplace(directory_fd, leaf, temporary)
    except OSError:
        _fail("published note cannot be rolled back safely")
    restored = _observe_at(directory_fd, temporary)
    if (
        restored is None
        or restored.identity[:3] != published.identity[:3]
        or restored.digest != published.digest
    ):
        try:
            _rename_noreplace(directory_fd, temporary, leaf)
        except OSError:
            pass
        _fail("foreign note was preserved during rollback")
    _remove_exact_temp(
        directory_fd,
        temporary,
        published.digest,
        published.identity[:3],
    )


def _rollback_updated_note(
    directory_fd: int,
    leaf: str,
    temporary: str,
    *,
    published: _ObservedFile,
    previous: _ObservedFile,
) -> None:
    current = _observe_at(directory_fd, leaf)
    displaced = _observe_at(directory_fd, temporary)
    if (
        current is None
        or displaced is None
        or current.identity[:3] != published.identity[:3]
        or current.digest != published.digest
        or displaced.identity[:3] != previous.identity[:3]
        or displaced.digest != previous.digest
    ):
        _fail("updated note changed before rollback")
    try:
        _rename_exchange(directory_fd, temporary, leaf)
    except OSError:
        _fail("updated note cannot be rolled back safely")
    restored = _observe_at(directory_fd, leaf)
    staged = _observe_at(directory_fd, temporary)
    if (
        restored is None
        or staged is None
        or restored.identity[:3] != previous.identity[:3]
        or restored.digest != previous.digest
        or staged.identity[:3] != published.identity[:3]
        or staged.digest != published.digest
    ):
        _fail("updated note rollback could not be verified")
    _remove_exact_temp(
        directory_fd,
        temporary,
        published.digest,
        published.identity[:3],
    )


def _decode_note(raw: str | bytes) -> tuple[str, bytes]:
    if isinstance(raw, str):
        if "\r" in raw:
            _fail("note content must use LF line endings")
        text = _utf8(raw, "note content", maximum=_MAX_NOTE_BYTES, layout=True)
        data = text.encode("utf-8")
    elif isinstance(raw, bytes):
        if len(raw) > _MAX_NOTE_BYTES:
            _fail("note content is too large")
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            _fail("note content must be UTF-8")
        if "\r" in text:
            _fail("note content must use LF line endings")
        _utf8(text, "note content", maximum=_MAX_NOTE_BYTES, layout=True)
        data = raw
    else:
        _fail("note content must be text or bytes")
    return text, data


def _frontmatter_scalar(value: str, label: str) -> object:
    if not value or value.strip() != value:
        _fail(f"{label} must be a non-empty canonical scalar")
    _utf8(value, label, maximum=4096)
    if value.startswith(("&", "*", "!", "|", ">")) or value in {"{}", "[]"}:
        _fail(f"{label} uses unsupported YAML syntax")
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        parsed = value
    if isinstance(parsed, (dict, list)) or type(parsed) is float:
        _fail(f"{label} must be a scalar")
    if parsed is None:
        _fail(f"{label} must not be null")
    if isinstance(parsed, str):
        _utf8(parsed, label, maximum=4096)
    return parsed


def _validate_frontmatter_value(value: object) -> None:
    if isinstance(value, str):
        _utf8(value, "note snapshot frontmatter value", maximum=4096)
    elif type(value) not in {bool, int}:
        _fail("note snapshot frontmatter value is invalid")


def _parse_frontmatter(text: str) -> tuple[tuple[tuple[str, object], ...], str, int]:
    if not text.startswith("---\n"):
        return (), text, 0
    boundary = text.find("\n---\n", 4)
    if boundary < 0:
        _fail("note frontmatter is not terminated")
    raw = text[4:boundary]
    if len(raw.encode("utf-8")) > _MAX_FRONTMATTER_BYTES:
        _fail("note frontmatter is too large")
    fields: dict[str, object] = {}
    active_list: str | None = None
    for number, line in enumerate(raw.splitlines(), start=2):
        if not line:
            continue
        if line.startswith("  - "):
            if active_list is None:
                _fail("note frontmatter contains an orphan list item")
            current = fields[active_list]
            assert isinstance(current, list)
            if len(current) >= _MAX_LIST_ITEMS:
                _fail("note frontmatter list has too many items")
            current.append(_frontmatter_scalar(line[4:], f"frontmatter line {number}"))
            continue
        if line.startswith((" ", "\t", "- ")) or ":" not in line:
            _fail("note frontmatter must use flat scalar or string-list fields")
        key, encoded = line.split(":", 1)
        if _KEY.fullmatch(key) is None or key in fields:
            _fail("note frontmatter has an invalid or duplicate key")
        if len(fields) >= _MAX_FIELDS:
            _fail("note frontmatter has too many fields")
        if encoded == "":
            fields[key] = []
            active_list = key
        elif encoded.startswith(" ") and encoded[1:]:
            fields[key] = _frontmatter_scalar(encoded[1:], f"frontmatter field {key}")
            active_list = None
        else:
            _fail("note frontmatter field formatting is invalid")
    for key, value in fields.items():
        if isinstance(value, list):
            fields[key] = tuple(value)
    body = text[boundary + 5 :]
    body_line = text[: boundary + 5].count("\n")
    return tuple(fields.items()), body, body_line


def _canonical_link_target(value: str) -> str:
    target = _utf8(value, "wikilink target", maximum=4096)
    if target.strip() != target:
        _fail("wikilink target must not have surrounding whitespace")
    return _canonical_relative(target, "wikilink target", markdown=False)


def _parse_wikilinks(body: str, *, line_offset: int) -> tuple[WikiLink, ...]:
    result: list[WikiLink] = []
    fence: tuple[str, int] | None = None
    for body_line, line in enumerate(body.splitlines(), start=1):
        stripped = line.lstrip(" ")
        if stripped.startswith(("```", "~~~")):
            marker = stripped[0]
            length = len(stripped) - len(stripped.lstrip(marker))
            if length >= 3:
                if fence is None:
                    fence = (marker, length)
                elif fence[0] == marker and length >= fence[1]:
                    fence = None
                continue
        if fence is not None:
            continue
        index = 0
        code_ticks: int | None = None
        while index < len(line):
            if line[index] == "`":
                end = index
                while end < len(line) and line[end] == "`":
                    end += 1
                width = end - index
                if code_ticks is None:
                    code_ticks = width
                elif code_ticks == width:
                    code_ticks = None
                index = end
                continue
            if code_ticks is not None:
                index += 1
                continue
            if line.startswith("[[", index):
                close = line.find("]]", index + 2)
                if close < 0:
                    _fail("wikilink is not terminated")
                inner = line[index + 2 : close]
                if "[[" in inner or not inner:
                    _fail("wikilink syntax is invalid")
                if len(result) >= _MAX_LINKS:
                    _fail("note contains too many wikilinks")
                if inner.count("|") > 1 or inner.count("#") > 1:
                    _fail("wikilink syntax is invalid")
                target_with_heading, separator, alias_value = inner.partition("|")
                target_value, heading_separator, heading_value = (
                    target_with_heading.partition("#")
                )
                target = _canonical_link_target(target_value)
                alias = None
                if separator:
                    alias = _utf8(alias_value, "wikilink alias", maximum=1024)
                    if not alias or alias.strip() != alias:
                        _fail("wikilink alias is invalid")
                heading = None
                if heading_separator:
                    heading = _utf8(heading_value, "wikilink heading", maximum=1024)
                    if not heading or heading.strip() != heading:
                        _fail("wikilink heading is invalid")
                result.append(
                    WikiLink(
                        raw=line[index : close + 2],
                        target=target,
                        alias=alias,
                        heading=heading,
                        line=line_offset + body_line,
                    )
                )
                index = close + 2
                continue
            if line.startswith("]]", index):
                _fail("wikilink contains an unmatched closing delimiter")
            index += 1
        if code_ticks is not None:
            _fail("Markdown inline code span is not terminated")
    if fence is not None:
        _fail("Markdown code fence is not terminated")
    return tuple(result)


def parse_note(
    ref: NoteRef, raw: str | bytes, *, path: str | None = None
) -> NoteSnapshot:
    """Parse bounded Markdown without inferring domain-specific frontmatter."""

    checked = _validate_ref(ref, write=None)
    text, data = _decode_note(raw)
    frontmatter, body, line_offset = _parse_frontmatter(text)
    links = _parse_wikilinks(body, line_offset=line_offset)
    visible_path = path or f"{checked.zone}/{checked.relative}"
    _canonical_relative(visible_path, "note path", markdown=True)
    return NoteSnapshot(
        schema_version=OBSIDIAN_SCHEMA_VERSION,
        zone=checked.zone,
        relative=checked.relative,
        path=visible_path,
        sha256=hashlib.sha256(data).hexdigest(),
        size_bytes=len(data),
        content=text,
        frontmatter=frontmatter,
        body=body,
        wikilinks=links,
    )


def _validate_snapshot(snapshot: NoteSnapshot) -> NoteSnapshot:
    if not isinstance(snapshot, NoteSnapshot):
        _fail("note operation requires a NoteSnapshot")
    if type(snapshot.schema_version) is not int:
        _fail("note snapshot schema_version is invalid")
    if not isinstance(snapshot.zone, str) or not isinstance(snapshot.relative, str):
        _fail("note snapshot reference fields are invalid")
    if not isinstance(snapshot.path, str):
        _fail("note snapshot path is invalid")
    if (
        not isinstance(snapshot.sha256, str)
        or _SHA256.fullmatch(snapshot.sha256) is None
    ):
        _fail("note snapshot sha256 is invalid")
    if (
        type(snapshot.size_bytes) is not int
        or not 0 <= snapshot.size_bytes <= _MAX_NOTE_BYTES
    ):
        _fail("note snapshot size_bytes is invalid")
    if not isinstance(snapshot.content, str):
        _fail("note snapshot content must be text")
    if not isinstance(snapshot.frontmatter, tuple):
        _fail("note snapshot frontmatter is invalid")
    if not isinstance(snapshot.body, str):
        _fail("note snapshot body must be text")
    if not isinstance(snapshot.wikilinks, tuple) or not all(
        isinstance(link, WikiLink) for link in snapshot.wikilinks
    ):
        _fail("note snapshot wikilinks are invalid")
    snapshot.metadata()
    canonical = parse_note(
        NoteRef(snapshot.schema_version, snapshot.zone, snapshot.relative),
        snapshot.content,
        path=snapshot.path,
    )
    if snapshot != canonical:
        _fail("note snapshot fields do not match parsed content")
    return snapshot


def _issue(
    snapshot: NoteSnapshot,
    rule_id: str,
    *,
    line: int | None = None,
    evidence: str = "",
) -> NoteIssue:
    return NoteIssue(
        rule_id=rule_id,
        severity="error",
        path=snapshot.path,
        line=line,
        evidence_sha256=hashlib.sha256(evidence.encode("utf-8")).hexdigest(),
    )


def _normalize_link_index(paths: Iterable[str]) -> tuple[str, ...]:
    normalized: list[str] = []
    for value in paths:
        normalized.append(
            _canonical_relative(value, "wikilink index path", markdown=True)
        )
    keys: dict[str, str] = {}
    for value in normalized:
        key = unicodedata.normalize("NFC", value).casefold()
        previous = keys.get(key)
        if previous is not None and previous != value:
            _fail("wikilink index contains a portable namespace collision")
        keys[key] = value
    return tuple(sorted(set(normalized), key=lambda value: (value.casefold(), value)))


def validate_note(
    snapshot: NoteSnapshot, *, link_index: Iterable[str] | None = None
) -> NoteValidation:
    """Validate the common v1 envelope and optional exact active-link index."""

    snapshot = _validate_snapshot(snapshot)
    metadata = snapshot.metadata()
    issues: list[NoteIssue] = []
    if not snapshot.content.startswith("---\n"):
        issues.append(_issue(snapshot, "note.frontmatter.required"))
    tags = metadata.get("tags")
    if not isinstance(tags, list) or not tags:
        issues.append(_issue(snapshot, "note.tags.required"))
    else:
        checked_tags: list[str] = []
        for tag in tags:
            if (
                not isinstance(tag, str)
                or not tag
                or len(tag.encode("utf-8")) > 128
                or tag.strip() != tag
                or _has_control(tag)
                or unicodedata.normalize("NFC", tag) != tag
            ):
                issues.append(_issue(snapshot, "note.tags.invalid", evidence=str(tag)))
                break
            checked_tags.append(tag.casefold())
        if len(checked_tags) != len(set(checked_tags)):
            issues.append(_issue(snapshot, "note.tags.duplicate"))
    raw_date = metadata.get("date")
    try:
        if not isinstance(raw_date, str) or _DATE.fullmatch(raw_date) is None:
            raise ValueError
        date.fromisoformat(raw_date)
    except ValueError:
        issues.append(_issue(snapshot, "note.date.invalid", evidence=str(raw_date)))
    nonempty = [
        (index, line)
        for index, line in enumerate(snapshot.body.splitlines(), start=1)
        if line.strip()
    ]
    headings = [(index, line) for index, line in nonempty if line.startswith("# ")]
    if not nonempty or not headings:
        issues.append(_issue(snapshot, "note.h1.required"))
    elif nonempty[0] != headings[0] or len(headings) != 1:
        issues.append(_issue(snapshot, "note.h1.invalid", line=headings[0][0]))

    if link_index is not None:
        active = _normalize_link_index(link_index)
        by_key = {value.casefold(): value for value in active}
        for link in snapshot.wikilinks:
            raw_target = link.target
            target = (
                raw_target
                if raw_target.casefold().endswith(".md")
                else f"{raw_target}.md"
            )
            if "/" in raw_target:
                exact = by_key.get(target.casefold())
                if exact is None:
                    issues.append(
                        _issue(
                            snapshot,
                            "wikilink.target.missing",
                            line=link.line,
                            evidence=target,
                        )
                    )
                elif exact != target:
                    issues.append(
                        _issue(
                            snapshot,
                            "wikilink.target.case-mismatch",
                            line=link.line,
                            evidence=target,
                        )
                    )
                continue
            stem = PurePosixPath(target).stem.casefold()
            matches = [
                value
                for value in active
                if PurePosixPath(value).stem.casefold() == stem
            ]
            if not matches:
                issues.append(
                    _issue(
                        snapshot,
                        "wikilink.target.missing",
                        line=link.line,
                        evidence=target,
                    )
                )
            elif len(matches) > 1:
                issues.append(
                    _issue(
                        snapshot,
                        "wikilink.target.ambiguous",
                        line=link.line,
                        evidence=target,
                    )
                )
            elif PurePosixPath(matches[0]).stem != PurePosixPath(target).stem:
                issues.append(
                    _issue(
                        snapshot,
                        "wikilink.target.case-mismatch",
                        line=link.line,
                        evidence=target,
                    )
                )
    ordered = tuple(
        sorted(
            issues,
            key=lambda item: (item.line or 0, item.rule_id, item.evidence_sha256),
        )
    )
    return NoteValidation(
        schema_version=OBSIDIAN_SCHEMA_VERSION,
        path=snapshot.path,
        source_sha256=snapshot.sha256,
        issues=ordered,
    )


def parse_feedback_blocks(snapshot: NoteSnapshot) -> tuple[FeedbackBlock, ...]:
    """Extract exact completed-task ``fb:`` blockquotes outside code fences."""

    snapshot = _validate_snapshot(snapshot)
    lines = snapshot.body.splitlines()
    body_offset = snapshot.content[: len(snapshot.content) - len(snapshot.body)].count(
        "\n"
    )
    result: list[FeedbackBlock] = []
    fence: tuple[str, int] | None = None
    index = 0
    while index < len(lines):
        line = lines[index]
        stripped = line.lstrip(" ")
        if stripped.startswith(("```", "~~~")):
            marker = stripped[0]
            width = len(stripped) - len(stripped.lstrip(marker))
            if width >= 3:
                if fence is None:
                    fence = (marker, width)
                elif fence[0] == marker and width >= fence[1]:
                    fence = None
                index += 1
                continue
        if fence is not None:
            index += 1
            continue
        if re.match(r"^- \[[xX]\] \S", line) and index + 1 < len(lines):
            first = lines[index + 1]
            if first.startswith("> fb: ") and first[6:].strip():
                chunks = [first[6:].strip()]
                end = index + 1
                cursor = index + 2
                while cursor < len(lines) and lines[cursor].startswith("> "):
                    continuation = lines[cursor][2:].strip()
                    if continuation:
                        chunks.append(continuation)
                    end = cursor
                    cursor += 1
                feedback = " ".join(" ".join(chunks).split())
                _utf8(feedback, "feedback block", maximum=8192)
                if len(result) >= _MAX_FEEDBACK_BLOCKS:
                    _fail("note contains too many feedback blocks")
                result.append(
                    FeedbackBlock(
                        task_line=line,
                        feedback=feedback,
                        start_line=body_offset + index + 1,
                        end_line=body_offset + end + 1,
                    )
                )
                index = cursor
                continue
        index += 1
    return tuple(result)


class ObsidianFlow:
    """Capability-bound safe note reader and single-file editor."""

    def __init__(self, resolver: VaultPathResolver, policy: AuthorityPolicy) -> None:
        if not isinstance(resolver, VaultPathResolver):
            _fail("obsidian requires a VaultPathResolver")
        if not isinstance(policy, AuthorityPolicy):
            _fail("obsidian requires an AuthorityPolicy")
        self._resolver = resolver
        self._policy = policy
        self._root_path, self._root_identity = _pin_authorized_root(resolver)

    def _require_root(self) -> None:
        _require_pinned_root(self._root_path, self._root_identity)

    def _revalidate_parent_and_root(
        self,
        ref: NoteRef,
        resolved_zone: os.PathLike[str],
        parent_fd: int,
        *,
        write: bool,
    ) -> None:
        self._require_root()
        _revalidate_parent(
            self._resolver,
            ref,
            resolved_zone,
            parent_fd,
            write=write,
        )
        self._require_root()

    def read_note(self, ref: NoteRef, *, capability: ActionCapability) -> NoteSnapshot:
        checked = _validate_ref(ref, write=False)
        _require_capability(self._policy, capability, zone=checked.zone, write=False)
        self._require_root()
        path = _root_relative_path(self._resolver, checked)
        with _open_zone(self._resolver, checked.zone, write=False) as (
            zone_fd,
            resolved,
        ):
            self._require_root()
            with _open_parent(zone_fd, checked.relative) as (parent_fd, leaf):
                observed = _observe_at(parent_fd, leaf)
                if observed is None:
                    _fail("note is missing")
                self._revalidate_parent_and_root(
                    checked, resolved, parent_fd, write=False
                )
        snapshot = parse_note(checked, observed.data, path=path)
        report = validate_note(snapshot)
        if not report.valid:
            _fail("note failed common validation")
        return snapshot

    def edit_note(
        self,
        request: NoteEdit,
        *,
        capability: ActionCapability,
        crash_at: Literal[
            "after-prepare-before-replace", "after-replace-before-cleanup"
        ]
        | None = None,
    ) -> NoteEditReceipt:
        if not isinstance(request, NoteEdit) or type(request.schema_version) is not int:
            _fail("note edit request is invalid")
        if request.schema_version != OBSIDIAN_SCHEMA_VERSION:
            _fail("unsupported note edit schema_version")
        operation_id = _utf8(request.operation_id, "operation_id", maximum=64)
        if _ID.fullmatch(operation_id) is None:
            _fail("operation_id has invalid syntax")
        if crash_at is not None and crash_at not in EDIT_CRASH_SEAMS:
            _fail("unknown obsidian crash seam")
        checked = _validate_ref(request.ref, write=True)
        _require_capability(self._policy, capability, zone=checked.zone, write=True)
        if request.expected_sha256 is not None and (
            not isinstance(request.expected_sha256, str)
            or _SHA256.fullmatch(request.expected_sha256) is None
        ):
            _fail("expected_sha256 is invalid")
        self._require_root()
        path = _root_relative_path(self._resolver, checked)
        candidate = parse_note(checked, request.content, path=path)
        validation = validate_note(candidate)
        if not validation.valid:
            _fail("candidate note failed common validation")
        data = candidate.content.encode("utf-8")
        post = candidate.sha256
        token = hashlib.sha256(path.encode("utf-8")).hexdigest()[:24]
        temporary = f".lifeos-retired-{token}.slot"

        with _open_zone(self._resolver, checked.zone, write=True) as (
            zone_fd,
            resolved,
        ):
            self._require_root()
            with _open_parent(zone_fd, checked.relative) as (parent_fd, leaf):
                self._revalidate_parent_and_root(
                    checked, resolved, parent_fd, write=True
                )
                before = _observe_at(parent_fd, leaf)
                if before is not None and before.digest == post:
                    expected_temp = (
                        post
                        if request.expected_sha256 is None
                        else request.expected_sha256
                    )
                    _remove_exact_temp(parent_fd, temporary, expected_temp)
                    self._revalidate_parent_and_root(
                        checked, resolved, parent_fd, write=True
                    )
                    replayed = _observe_at(parent_fd, leaf)
                    if (
                        replayed is None
                        or replayed.digest != post
                        or replayed.identity[:3] != before.identity[:3]
                    ):
                        _fail("replayed note changed before receipt")
                    return NoteEditReceipt(
                        OBSIDIAN_SCHEMA_VERSION,
                        operation_id,
                        path,
                        request.expected_sha256,
                        post,
                        "already_applied",
                    )
                if request.expected_sha256 is None:
                    if before is not None:
                        _remove_exact_temp(parent_fd, temporary, post)
                        self._revalidate_parent_and_root(
                            checked, resolved, parent_fd, write=True
                        )
                        preserved = _observe_at(parent_fd, leaf)
                        if (
                            preserved is None
                            or preserved.identity != before.identity
                            or preserved.digest != before.digest
                        ):
                            _fail("foreign note changed during staged cleanup")
                        _fail("create requires an absent note")
                elif before is None or before.digest != request.expected_sha256:
                    _remove_exact_temp(parent_fd, temporary, post)
                    self._revalidate_parent_and_root(
                        checked, resolved, parent_fd, write=True
                    )
                    preserved = _observe_at(parent_fd, leaf)
                    if before is None:
                        if preserved is not None:
                            _fail("note changed during staged cleanup")
                    elif (
                        preserved is None
                        or preserved.identity != before.identity
                        or preserved.digest != before.digest
                    ):
                        _fail("foreign note changed during staged cleanup")
                    _fail("note precondition hash does not match")

                _stage_exact(parent_fd, temporary, data)
                staged = _observe_at(parent_fd, temporary)
                if staged is None or staged.digest != post:
                    _fail("note staging file cannot be verified")
                if crash_at == "after-prepare-before-replace":
                    raise ObsidianCrash(crash_at)
                try:
                    self._revalidate_parent_and_root(
                        checked, resolved, parent_fd, write=True
                    )
                except ObsidianError:
                    _remove_exact_temp(parent_fd, temporary, post, staged.identity[:3])
                    raise
                current = _observe_at(parent_fd, leaf)
                if request.expected_sha256 is None:
                    if current is not None:
                        _remove_exact_temp(
                            parent_fd, temporary, post, staged.identity[:3]
                        )
                        _fail("foreign note appeared before create")
                    try:
                        _rename_noreplace(parent_fd, temporary, leaf)
                    except OSError:
                        _remove_exact_temp(
                            parent_fd, temporary, post, staged.identity[:3]
                        )
                        _fail("foreign note appeared during create")
                    published = _observe_at(parent_fd, leaf)
                    if (
                        published is None
                        or published.identity[:3] != staged.identity[:3]
                        or published.digest != post
                    ):
                        _fail("created note publication cannot be verified")
                    before_hash: str | None = None
                else:
                    if (
                        current is None
                        or current.digest != request.expected_sha256
                        or current.identity != before.identity
                    ):
                        _fail("foreign note replaced the update precondition")
                    try:
                        _rename_exchange(parent_fd, temporary, leaf)
                    except OSError:
                        _fail("note update cannot be committed atomically")
                    displaced = _observe_at(parent_fd, temporary)
                    if (
                        displaced is None
                        or displaced.digest != request.expected_sha256
                        or displaced.identity[:3] != before.identity[:3]
                    ):
                        try:
                            _rename_exchange(parent_fd, temporary, leaf)
                            _fsync_directory(
                                parent_fd,
                                "restored note directory cannot be synced",
                            )
                        except OSError:
                            _fail(
                                "foreign note could not be restored after update race"
                            )
                        _fail("foreign note replacement was preserved")
                    published = _observe_at(parent_fd, leaf)
                    if (
                        published is None
                        or published.identity[:3] != staged.identity[:3]
                        or published.digest != post
                    ):
                        try:
                            _rename_exchange(parent_fd, temporary, leaf)
                            _fsync_directory(
                                parent_fd,
                                "restored note directory cannot be synced",
                            )
                        except OSError:
                            _fail(
                                "foreign note could not be restored after publication race"
                            )
                        _fail("updated note publication cannot be verified")
                    before_hash = request.expected_sha256
                _fsync_directory(parent_fd, "note directory cannot be synced")
                if crash_at == "after-replace-before-cleanup":
                    raise ObsidianCrash(crash_at)
                try:
                    self._revalidate_parent_and_root(
                        checked, resolved, parent_fd, write=True
                    )
                except ObsidianError:
                    if request.expected_sha256 is None:
                        _rollback_created_note(parent_fd, leaf, temporary, published)
                    else:
                        _rollback_updated_note(
                            parent_fd,
                            leaf,
                            temporary,
                            published=published,
                            previous=before,
                        )
                    _fsync_directory(
                        parent_fd, "rolled back note directory cannot be synced"
                    )
                    raise
                if request.expected_sha256 is not None:
                    _remove_exact_temp(
                        parent_fd,
                        temporary,
                        request.expected_sha256,
                        before.identity[:3],
                    )
                self._revalidate_parent_and_root(
                    checked, resolved, parent_fd, write=True
                )
                after = _observe_at(parent_fd, leaf)
                if (
                    after is None
                    or after.digest != post
                    or after.identity != published.identity
                ):
                    _fail("note postcondition hash does not match")
        return NoteEditReceipt(
            OBSIDIAN_SCHEMA_VERSION,
            operation_id,
            path,
            before_hash,
            post,
            "applied",
        )


def read_note(
    resolver: VaultPathResolver,
    ref: NoteRef,
    *,
    capability: ActionCapability,
    policy: AuthorityPolicy,
) -> NoteSnapshot:
    return ObsidianFlow(resolver, policy).read_note(ref, capability=capability)


def edit_note(
    resolver: VaultPathResolver,
    request: NoteEdit,
    *,
    capability: ActionCapability,
    policy: AuthorityPolicy,
    crash_at: Literal["after-prepare-before-replace", "after-replace-before-cleanup"]
    | None = None,
) -> NoteEditReceipt:
    return ObsidianFlow(resolver, policy).edit_note(
        request, capability=capability, crash_at=crash_at
    )


def _receipt_payload(receipt: NoteEditReceipt) -> dict[str, object]:
    if not isinstance(receipt, NoteEditReceipt):
        _fail("note edit receipt is invalid")
    if (
        type(receipt.schema_version) is not int
        or receipt.schema_version != OBSIDIAN_SCHEMA_VERSION
    ):
        _fail("unsupported note edit receipt schema_version")
    if (
        not isinstance(receipt.operation_id, str)
        or _ID.fullmatch(receipt.operation_id) is None
    ):
        _fail("receipt operation_id is invalid")
    path = _canonical_relative(receipt.path, "receipt path", markdown=True)
    if receipt.before_sha256 is not None and (
        not isinstance(receipt.before_sha256, str)
        or _SHA256.fullmatch(receipt.before_sha256) is None
    ):
        _fail("receipt before_sha256 is invalid")
    if (
        not isinstance(receipt.after_sha256, str)
        or _SHA256.fullmatch(receipt.after_sha256) is None
    ):
        _fail("receipt after_sha256 is invalid")
    if not isinstance(receipt.status, str) or receipt.status not in {
        "applied",
        "already_applied",
    }:
        _fail("receipt status is invalid")
    return {
        "after_sha256": receipt.after_sha256,
        "before_sha256": receipt.before_sha256,
        "operation_id": receipt.operation_id,
        "path": path,
        "schema_version": receipt.schema_version,
        "status": receipt.status,
    }


def render_note_edit_receipt(receipt: NoteEditReceipt) -> bytes:
    return (
        json.dumps(
            _receipt_payload(receipt),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )


def _json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            _fail("note edit receipt contains duplicate fields")
        result[key] = value
    return result


def parse_note_edit_receipt(raw: str | bytes) -> NoteEditReceipt:
    if isinstance(raw, str):
        try:
            data = raw.encode("utf-8")
        except UnicodeError:
            _fail("note edit receipt must be UTF-8")
    elif isinstance(raw, bytes):
        data = raw
    else:
        _fail("note edit receipt must be text or bytes")
    if not data or len(data) > _MAX_RECEIPT_BYTES:
        _fail("note edit receipt is not bounded")
    try:
        payload = json.loads(data, object_pairs_hook=_json_object)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        _fail("note edit receipt is malformed")
    required = {
        "schema_version",
        "operation_id",
        "path",
        "before_sha256",
        "after_sha256",
        "status",
    }
    if not isinstance(payload, dict) or set(payload) != required:
        _fail("note edit receipt has missing or unknown fields")
    receipt = NoteEditReceipt(
        schema_version=payload["schema_version"],
        operation_id=payload["operation_id"],
        path=payload["path"],
        before_sha256=payload["before_sha256"],
        after_sha256=payload["after_sha256"],
        status=payload["status"],
    )
    canonical = render_note_edit_receipt(receipt)
    if data != canonical:
        _fail("note edit receipt must use canonical JSON")
    return receipt
