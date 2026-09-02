"""Bounded subprocess validation and direct reads of public llm-wiki topics.

The neighboring package is deliberately never imported.  Validation uses its
documented CLI, while reads implement the published spec 0.1.0 contract over
an fd-anchored topic tree.  No mutation operation is exposed here.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import selectors
import signal
import stat
import subprocess
import time
from typing import Mapping, Sequence
import unicodedata


SUPPORTED_SPEC_VERSION = "0.1.0"
VALIDATE_ARGV_SUFFIX = ("validate", "<topic-dir>")
VALIDATE_EXIT_CODES = frozenset({0, 1})
MAX_CONNECTOR_OUTPUT_BYTES = 64 * 1024

_MAX_MANIFEST_BYTES = 256 * 1024
_MAX_JSONL_BYTES = 16 * 1024 * 1024
_MAX_WIKI_BYTES = 2 * 1024 * 1024
_MAX_SOURCE_CONTENT_BYTES = 4 * 1024 * 1024
_MAX_JSONL_RECORDS = 8192
_MAX_WIKI_PAGES = 2048
_MAX_ISSUES = 256
_MAX_JSON_DEPTH = 12

_TOPIC_SLUG = re.compile(r"^[a-z0-9][a-z0-9-]*$")
_SOURCE_ID = re.compile(r"^src_[0-9a-f]{12}$")
_CLAIM_ID = re.compile(r"^clm_[0-9a-f]{12}$")
_WIKI_ID = re.compile(r"^wik_[0-9a-f]{12}$")
_SPEC_VERSION = re.compile(r"^0\.1\.\d+$")
_KEY_SCALAR = re.compile(r"^([A-Za-z_][A-Za-z0-9_-]*):[ \t]+(.+?)[ \t]*$")
_KEY_LIST = re.compile(r"^([A-Za-z_][A-Za-z0-9_-]*):[ \t]*$")
_ITEM = re.compile(r"^[ \t]+-[ \t]+(.+?)[ \t]*$")

_SOURCE_KINDS = frozenset(
    {"web", "youtube", "telegram", "paper", "book", "repo", "dataset", "local", "other"}
)
_CONFIDENCES = frozenset({"high", "medium", "low"})
_CLAIM_STATUSES = frozenset({"candidate", "verified", "final", "retracted"})
_FINAL_STATUSES = frozenset({"verified", "final", "retracted"})
_STANCES = frozenset({"supports", "contradicts", "mentions"})
_LOCATOR_TYPES = frozenset({"block", "heading", "timestamp", "page", "line", "other"})


@dataclass(frozen=True)
class TopicIssue:
    """Privacy-safe machine finding from the direct public-spec reader."""

    code: str
    location: str | None = None
    reference: str | None = None


class LlmWikiConnectorError(ValueError):
    """The topic, subprocess contract, or direct-read contract is unsafe."""

    def __init__(self, code: str, issues: Sequence[TopicIssue] = ()) -> None:
        self.code = code
        self.issues = tuple(issues)
        super().__init__(code)


@dataclass(frozen=True)
class TopicValidation:
    schema_version: int
    status: str
    returncode: int | None
    stdout_bytes: int
    stderr_bytes: int
    issue_code: str | None


@dataclass(frozen=True)
class HashedRecord:
    record_id: str
    payload: dict[str, object]
    sha256: str
    payload_sha256: str
    content: str | None = None
    content_sha256: str | None = None


@dataclass(frozen=True)
class WikiPage:
    relative_ref: str
    frontmatter: dict[str, object]
    body: str
    sha256: str


@dataclass(frozen=True)
class TopicSnapshot:
    schema_version: int
    spec_version: str
    topic_ref: str
    manifest: dict[str, object]
    manifest_sha256: str
    sources: tuple[HashedRecord, ...]
    final_claims: tuple[HashedRecord, ...]
    wiki_pages: tuple[WikiPage, ...]
    source_hashes: tuple[tuple[str, str], ...]
    snapshot_sha256: str


@dataclass
class _BoundTopic:
    topics_fd: int
    topic_fd: int
    topics_identity: tuple[int, int]
    topic_identity: tuple[int, int]
    name: str
    path: Path


@dataclass(frozen=True)
class _ProcessResult:
    returncode: int | None
    stdout_bytes: int
    stderr_bytes: int
    timed_out: bool
    spawn_failed: bool
    setup_failed: bool


@dataclass(frozen=True)
class _LeafObservation:
    relative: str
    identity: tuple[int, int, int, int, int] | None
    content_sha256: str | None
    maximum: int


@dataclass(frozen=True)
class _WikiSetObservation:
    identity: tuple[int, int, int, int, int] | None
    names: tuple[str, ...]


class _ByteCounter:
    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.size = 0

    def add(self, size: int) -> None:
        self.size = min(self.limit + 1, self.size + size)


def _has_control(value: str) -> bool:
    return any(
        unicodedata.category(character).startswith("C")
        or unicodedata.category(character) in {"Zl", "Zp"}
        for character in value
    )


def _directory_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )


def _file_flags() -> int:
    return os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)


def _directory_identity(metadata: os.stat_result) -> tuple[int, int]:
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise LlmWikiConnectorError("unsafe-topic")
    return metadata.st_dev, metadata.st_ino


def _regular_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise LlmWikiConnectorError("unsafe-topic-entry")
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _directory_snapshot(
    metadata: os.stat_result,
) -> tuple[int, int, int, int, int]:
    device, inode = _directory_identity(metadata)
    return (
        device,
        inode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _canonical_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError) as error:
        raise LlmWikiConnectorError("noncanonical-topic-data") from error


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _utf8_size(value: str) -> int | None:
    try:
        return len(value.encode("utf-8"))
    except UnicodeEncodeError:
        return None


def _path_ref(path: Path) -> str:
    return "sha256:" + hashlib.sha256(os.fsencode(path)).hexdigest()


def _no_duplicate_fields(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def _safe_json(value: object, *, depth: int = 0) -> bool:
    if depth > _MAX_JSON_DEPTH:
        return False
    if value is None or isinstance(value, bool) or type(value) in {int, float}:
        if type(value) is float:
            try:
                _canonical_bytes(value)
            except LlmWikiConnectorError:
                return False
        return True
    if isinstance(value, str):
        size = _utf8_size(value)
        return size is not None and size <= _MAX_WIKI_BYTES
    if isinstance(value, list):
        return len(value) <= _MAX_JSONL_RECORDS and all(
            _safe_json(item, depth=depth + 1) for item in value
        )
    if isinstance(value, Mapping):
        return len(value) <= 512 and all(
            isinstance(key, str)
            and (key_size := _utf8_size(key)) is not None
            and key_size <= 256
            and _safe_json(item, depth=depth + 1)
            for key, item in value.items()
        )
    return False


def _string(value: object, *, nonempty: bool = False, pattern: re.Pattern[str] | None = None) -> bool:
    return (
        isinstance(value, str)
        and (not nonempty or bool(value))
        and (pattern is None or pattern.fullmatch(value) is not None)
    )


def _exact_object(
    value: object, *, required: set[str], allowed: set[str]
) -> dict[str, object] | None:
    if not isinstance(value, dict) or not required.issubset(value) or set(value) - allowed:
        return None
    return value


def _schema_issue(location: str) -> TopicIssue:
    return TopicIssue("schema-mismatch", location)


def _source_content_ref(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value or "\\" in value or _has_control(value):
        raise LlmWikiConnectorError("source-not-self-contained")
    relative = PurePosixPath(value)
    if (
        relative.is_absolute()
        or ".." in relative.parts
        or relative.parts[:2] != ("sources", "content")
        or len(relative.parts) < 3
    ):
        raise LlmWikiConnectorError("source-not-self-contained")
    return relative.as_posix()


def _validate_manifest(value: object, issues: list[TopicIssue]) -> dict[str, object] | None:
    table = _exact_object(
        value,
        required={"spec_version", "topic", "slug", "created_at"},
        allowed={"spec_version", "topic", "slug", "created_at", "description", "meta"},
    )
    if table is None:
        issues.append(_schema_issue("topic.json"))
        return None
    valid = (
        _string(table["spec_version"], nonempty=True, pattern=_SPEC_VERSION)
        and _string(table["topic"], nonempty=True)
        and _string(table["slug"], nonempty=True, pattern=_TOPIC_SLUG)
        and _string(table["created_at"], nonempty=True)
        and len(str(table["created_at"])) >= 10
        and ("description" not in table or _string(table["description"]))
        and ("meta" not in table or isinstance(table["meta"], dict))
        and _safe_json(table)
    )
    if not valid:
        issues.append(_schema_issue("topic.json"))
        return None
    return table


def _validate_source(value: object, location: str, issues: list[TopicIssue]) -> dict[str, object] | None:
    table = _exact_object(
        value,
        required={"id", "kind", "title"},
        allowed={"id", "kind", "title", "url", "fetched_at", "tool", "content_path", "meta"},
    )
    valid = table is not None and (
        _string(table["id"], nonempty=True, pattern=_SOURCE_ID)
        and isinstance(table["kind"], str)
        and table["kind"] in _SOURCE_KINDS
        and _string(table["title"], nonempty=True)
        and all(
            key not in table or _string(table[key], nonempty=(key == "url"))
            for key in ("url", "fetched_at", "tool", "content_path")
        )
        and ("meta" not in table or isinstance(table["meta"], dict))
        and _safe_json(table)
    )
    if not valid:
        issues.append(_schema_issue(location))
        return None
    return table


def _validate_evidence(value: object) -> bool:
    if not isinstance(value, list) or not value:
        return False
    for item in value:
        table = _exact_object(
            item,
            required={"source_id", "quote", "stance"},
            allowed={"source_id", "quote", "stance", "locator"},
        )
        if table is None or not (
            _string(table["source_id"], nonempty=True, pattern=_SOURCE_ID)
            and _string(table["quote"], nonempty=True)
            and isinstance(table["stance"], str)
            and table["stance"] in _STANCES
        ):
            return False
        if "locator" in table:
            locator = _exact_object(
                table["locator"], required={"type", "value"}, allowed={"type", "value"}
            )
            if locator is None or not (
                isinstance(locator["type"], str)
                and locator["type"] in _LOCATOR_TYPES
                and _string(locator["value"], nonempty=True)
            ):
                return False
    return True


def _validate_claim(value: object, location: str, issues: list[TopicIssue]) -> dict[str, object] | None:
    table = _exact_object(
        value,
        required={"id", "text", "confidence", "status", "evidence", "created_at"},
        allowed={"id", "text", "confidence", "status", "evidence", "tags", "created_at", "run_id", "meta"},
    )
    valid = table is not None and (
        _string(table["id"], nonempty=True, pattern=_CLAIM_ID)
        and _string(table["text"], nonempty=True)
        and isinstance(table["confidence"], str)
        and table["confidence"] in _CONFIDENCES
        and isinstance(table["status"], str)
        and table["status"] in _CLAIM_STATUSES
        and table["status"] in _FINAL_STATUSES
        and _validate_evidence(table["evidence"])
        and _string(table["created_at"], nonempty=True)
        and len(str(table["created_at"])) >= 10
        and (
            "tags" not in table
            or isinstance(table["tags"], list)
            and all(_string(item, nonempty=True) for item in table["tags"])
        )
        and ("run_id" not in table or _string(table["run_id"]))
        and ("meta" not in table or isinstance(table["meta"], dict))
        and _safe_json(table)
    )
    if not valid:
        issues.append(_schema_issue(location))
        return None
    return table


def _parse_scalar(raw: str) -> str:
    if not raw.startswith('"'):
        return raw
    value = json.loads(raw)
    if not isinstance(value, str):
        raise ValueError("frontmatter scalar is not text")
    return value


def _parse_frontmatter(text: str) -> tuple[dict[str, object], str]:
    lines = text.splitlines(keepends=True)
    if not lines or lines[0].rstrip("\r\n") != "---":
        raise ValueError("missing frontmatter")
    closing = next(
        (index for index in range(1, len(lines)) if lines[index].rstrip("\r\n") == "---"),
        None,
    )
    if closing is None:
        raise ValueError("missing frontmatter close")
    data: dict[str, object] = {}
    current_list: str | None = None
    for line in "".join(lines[1:closing]).splitlines():
        if not line.strip():
            continue
        item_match = _ITEM.match(line)
        if item_match is not None:
            if current_list is None:
                raise ValueError("orphan frontmatter item")
            current = data[current_list]
            if not isinstance(current, list):
                raise ValueError("frontmatter list is invalid")
            current.append(_parse_scalar(item_match.group(1)))
            continue
        scalar_match = _KEY_SCALAR.match(line)
        if scalar_match is not None:
            key = scalar_match.group(1)
            if key in data:
                raise ValueError("duplicate frontmatter key")
            data[key] = _parse_scalar(scalar_match.group(2))
            current_list = None
            continue
        list_match = _KEY_LIST.match(line)
        if list_match is not None:
            key = list_match.group(1)
            if key in data:
                raise ValueError("duplicate frontmatter key")
            data[key] = []
            current_list = key
            continue
        raise ValueError("invalid frontmatter")
    body = "".join(lines[closing + 1 :]).strip("\n")
    return data, body


def _validate_wiki(value: object, location: str, issues: list[TopicIssue]) -> dict[str, object] | None:
    table = _exact_object(
        value,
        required={"id", "title", "claims", "updated_at"},
        allowed={"id", "title", "claims", "updated_at"},
    )
    valid = table is not None and (
        _string(table["id"], nonempty=True, pattern=_WIKI_ID)
        and _string(table["title"], nonempty=True)
        and isinstance(table["claims"], list)
        and bool(table["claims"])
        and all(_string(item, nonempty=True, pattern=_CLAIM_ID) for item in table["claims"])
        and _string(table["updated_at"], nonempty=True)
        and len(str(table["updated_at"])) >= 10
        and _safe_json(table)
    )
    if not valid:
        issues.append(_schema_issue(location))
        return None
    return table


class LlmWikiConnector:
    """Exact read-only integration boundary for one configured topics root."""

    def __init__(
        self,
        *,
        topics_root: str | os.PathLike[str],
        command: Sequence[str],
        cwd: str | os.PathLike[str],
        env: Mapping[str, str],
        timeout: float = 10.0,
        max_output_bytes: int = MAX_CONNECTOR_OUTPUT_BYTES,
    ) -> None:
        root = Path(topics_root)
        working = Path(cwd)
        if not root.is_absolute() or not working.is_absolute():
            raise LlmWikiConnectorError("paths-must-be-absolute")
        if type(command) not in (tuple, list) or not 0 < len(command) <= 16:
            raise LlmWikiConnectorError("invalid-command")
        checked_command: list[str] = []
        for item in command:
            item_size = _utf8_size(item) if isinstance(item, str) else None
            if (
                not isinstance(item, str)
                or not item
                or item_size is None
                or item_size > 4096
                or _has_control(item)
            ):
                raise LlmWikiConnectorError("invalid-command")
            checked_command.append(item)
        if not isinstance(env, Mapping) or any(
            not isinstance(key, str)
            or not key
            or not isinstance(value, str)
            or _utf8_size(key) is None
            or _utf8_size(value) is None
            or "\x00" in key
            or "=" in key
            or "\x00" in value
            for key, value in env.items()
        ):
            raise LlmWikiConnectorError("invalid-environment")
        if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or not 0 < timeout <= 300:
            raise LlmWikiConnectorError("invalid-timeout")
        if type(max_output_bytes) is not int or not 1024 <= max_output_bytes <= 1024 * 1024:
            raise LlmWikiConnectorError("invalid-output-limit")
        self._topics_root = root
        self._command = tuple(checked_command)
        self._cwd = working
        self._env = dict(env)
        self._timeout = float(timeout)
        self._max_output_bytes = max_output_bytes

    def _topic_input(self, topic_dir: str | os.PathLike[str]) -> tuple[str, Path]:
        try:
            supplied = Path(topic_dir)
        except TypeError as error:
            raise LlmWikiConnectorError("unsafe-topic") from error
        raw = os.fspath(supplied)
        if (
            not isinstance(raw, str)
            or not supplied.is_absolute()
            or ".." in supplied.parts
            or _has_control(raw)
            or supplied.parent != self._topics_root
            or _TOPIC_SLUG.fullmatch(supplied.name) is None
        ):
            raise LlmWikiConnectorError("unsafe-topic")
        return supplied.name, supplied

    def _bind_topic(self, topic_dir: str | os.PathLike[str]) -> _BoundTopic:
        name, path = self._topic_input(topic_dir)
        topics_fd = -1
        topic_fd = -1
        try:
            topics_fd = os.open(self._topics_root, _directory_flags())
            topics_identity = _directory_identity(os.fstat(topics_fd))
            named_root = _directory_identity(os.stat(self._topics_root, follow_symlinks=False))
            if topics_identity != named_root:
                raise LlmWikiConnectorError("topics-root-moved")
            topic_fd = os.open(name, _directory_flags(), dir_fd=topics_fd)
            topic_identity = _directory_identity(os.fstat(topic_fd))
            named_topic = _directory_identity(os.stat(name, dir_fd=topics_fd, follow_symlinks=False))
            if topic_identity != named_topic:
                raise LlmWikiConnectorError("topic-moved")
            return _BoundTopic(
                topics_fd,
                topic_fd,
                topics_identity,
                topic_identity,
                name,
                path,
            )
        except (OSError, RuntimeError) as error:
            if topic_fd >= 0:
                os.close(topic_fd)
            if topics_fd >= 0:
                os.close(topics_fd)
            raise LlmWikiConnectorError("unsafe-topic") from error
        except Exception:
            if topic_fd >= 0:
                os.close(topic_fd)
            if topics_fd >= 0:
                os.close(topics_fd)
            raise

    @staticmethod
    def _close_bound(bound: _BoundTopic) -> None:
        os.close(bound.topic_fd)
        os.close(bound.topics_fd)

    def _revalidate_topic(self, bound: _BoundTopic) -> None:
        try:
            named_root = _directory_identity(os.stat(self._topics_root, follow_symlinks=False))
            held_root = _directory_identity(os.fstat(bound.topics_fd))
            named_topic = _directory_identity(
                os.stat(bound.name, dir_fd=bound.topics_fd, follow_symlinks=False)
            )
            held_topic = _directory_identity(os.fstat(bound.topic_fd))
        except (OSError, LlmWikiConnectorError) as error:
            raise LlmWikiConnectorError("topic-moved") from error
        if (
            named_root != bound.topics_identity
            or held_root != bound.topics_identity
            or named_topic != bound.topic_identity
            or held_topic != bound.topic_identity
        ):
            raise LlmWikiConnectorError("topic-moved")

    def _read_file(
        self,
        topic_fd: int,
        relative: str,
        *,
        maximum: int,
        missing_ok: bool,
        observations: list[_LeafObservation] | None = None,
    ) -> bytes | None:
        path = PurePosixPath(relative)
        if path.is_absolute() or ".." in path.parts or not path.parts:
            raise LlmWikiConnectorError("unsafe-topic-entry")
        opened: list[int] = []
        current_fd = topic_fd

        def observe_absence() -> None:
            if observations is not None:
                observations.append(_LeafObservation(relative, None, None, maximum))

        try:
            for component in path.parts[:-1]:
                try:
                    child_fd = os.open(component, _directory_flags(), dir_fd=current_fd)
                except FileNotFoundError:
                    if missing_ok:
                        observe_absence()
                        return None
                    raise
                named = _directory_identity(
                    os.stat(component, dir_fd=current_fd, follow_symlinks=False)
                )
                if _directory_identity(os.fstat(child_fd)) != named:
                    raise LlmWikiConnectorError("topic-changed")
                opened.append(child_fd)
                current_fd = child_fd
            name = path.parts[-1]
            try:
                descriptor = os.open(name, _file_flags(), dir_fd=current_fd)
            except FileNotFoundError:
                if missing_ok:
                    observe_absence()
                    return None
                raise
            try:
                before = _regular_identity(os.fstat(descriptor))
                if before[2] > maximum:
                    raise LlmWikiConnectorError("topic-entry-too-large")
                chunks: list[bytes] = []
                remaining = maximum + 1
                while remaining:
                    chunk = os.read(descriptor, min(64 * 1024, remaining))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    remaining -= len(chunk)
                raw = b"".join(chunks)
                after = _regular_identity(os.fstat(descriptor))
                named_after = _regular_identity(
                    os.stat(name, dir_fd=current_fd, follow_symlinks=False)
                )
                if len(raw) > maximum:
                    raise LlmWikiConnectorError("topic-entry-too-large")
                if before != after or before != named_after or len(raw) != before[2]:
                    raise LlmWikiConnectorError("topic-changed")
                if observations is not None:
                    observations.append(
                        _LeafObservation(relative, before, _sha256(raw), maximum)
                    )
                return raw
            finally:
                os.close(descriptor)
        except FileNotFoundError as error:
            raise LlmWikiConnectorError("topic-entry-missing") from error
        except OSError as error:
            raise LlmWikiConnectorError("unsafe-topic-entry") from error
        finally:
            for descriptor in reversed(opened):
                os.close(descriptor)

    def _revalidate_leaves(
        self, topic_fd: int, observations: Sequence[_LeafObservation]
    ) -> None:
        for expected in observations:
            current: list[_LeafObservation] = []
            try:
                self._read_file(
                    topic_fd,
                    expected.relative,
                    maximum=expected.maximum,
                    missing_ok=expected.identity is None,
                    observations=current,
                )
            except LlmWikiConnectorError as error:
                raise LlmWikiConnectorError("topic-moved") from error
            if len(current) != 1 or current[0] != expected:
                raise LlmWikiConnectorError("topic-moved")

    @staticmethod
    def _decode_object(raw: bytes, location: str, issues: list[TopicIssue]) -> dict[str, object] | None:
        try:
            value = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicate_fields)
        except (UnicodeError, ValueError, RecursionError):
            issues.append(TopicIssue("invalid-json", location))
            return None
        if not isinstance(value, dict):
            issues.append(TopicIssue("schema-mismatch", location))
            return None
        return value

    @staticmethod
    def _decode_jsonl(
        raw: bytes | None, location: str, issues: list[TopicIssue]
    ) -> list[tuple[int, dict[str, object]]]:
        if raw is None or raw == b"":
            return []
        try:
            text = raw.decode("utf-8")
        except UnicodeError:
            issues.append(TopicIssue("invalid-jsonl", location))
            return []
        lines = text.split("\n")
        if lines[-1:] == [""]:
            lines.pop()
        if len(lines) > _MAX_JSONL_RECORDS:
            issues.append(TopicIssue("too-many-records", location))
            return []
        result: list[tuple[int, dict[str, object]]] = []
        for index, line in enumerate(lines, 1):
            row_location = f"{location}:{index}"
            if line.endswith("\r"):
                line = line[:-1]
            if not line.strip():
                issues.append(TopicIssue("invalid-jsonl", row_location))
                continue
            try:
                value = json.loads(line, object_pairs_hook=_no_duplicate_fields)
            except (ValueError, UnicodeError, RecursionError):
                issues.append(TopicIssue("invalid-jsonl", row_location))
                continue
            if not isinstance(value, dict):
                issues.append(TopicIssue("schema-mismatch", row_location))
                continue
            result.append((index, value))
        return result

    def _wiki_names(self, topic_fd: int) -> _WikiSetObservation:
        opened: list[int] = []
        current = topic_fd
        try:
            for component in ("final", "wiki"):
                try:
                    descriptor = os.open(component, _directory_flags(), dir_fd=current)
                except FileNotFoundError:
                    return _WikiSetObservation(None, ())
                named = _directory_identity(
                    os.stat(component, dir_fd=current, follow_symlinks=False)
                )
                if _directory_identity(os.fstat(descriptor)) != named:
                    raise LlmWikiConnectorError("topic-changed")
                opened.append(descriptor)
                current = descriptor
            before = _directory_snapshot(os.fstat(current))
            names = tuple(sorted(name for name in os.listdir(current) if name.endswith(".md")))
            if len(names) > _MAX_WIKI_PAGES:
                raise LlmWikiConnectorError("too-many-wiki-pages")
            if any(
                not name
                or name in {".", ".."}
                or "/" in name
                or "\\" in name
                or _has_control(name)
                for name in names
            ):
                raise LlmWikiConnectorError("unsafe-wiki-name")
            after = _directory_snapshot(os.fstat(current))
            if before != after:
                raise LlmWikiConnectorError("topic-changed")
            return _WikiSetObservation(before, names)
        except OSError as error:
            raise LlmWikiConnectorError("unsafe-topic-entry") from error
        finally:
            for descriptor in reversed(opened):
                os.close(descriptor)

    def _read_bound(self, bound: _BoundTopic) -> TopicSnapshot:
        issues: list[TopicIssue] = []
        observations: list[_LeafObservation] = []
        manifest_raw = self._read_file(
            bound.topic_fd,
            "topic.json",
            maximum=_MAX_MANIFEST_BYTES,
            missing_ok=False,
            observations=observations,
        )
        assert manifest_raw is not None
        manifest_value = self._decode_object(manifest_raw, "topic.json", issues)
        manifest = _validate_manifest(manifest_value, issues) if manifest_value is not None else None

        sources_raw = self._read_file(
            bound.topic_fd,
            "sources/sources.jsonl",
            maximum=_MAX_JSONL_BYTES,
            missing_ok=True,
            observations=observations,
        )
        source_values = self._decode_jsonl(sources_raw, "sources/sources.jsonl", issues)
        sources: list[HashedRecord] = []
        source_ids: set[str] = set()
        for index, value in source_values:
            location = f"sources/sources.jsonl:{index}"
            source = _validate_source(value, location, issues)
            if source is None:
                continue
            source_id = str(source["id"])
            if source_id in source_ids:
                issues.append(TopicIssue("duplicate-source-id", location, source_id))
                continue
            source_ids.add(source_id)
            payload_hash = _sha256(_canonical_bytes(source))
            content: str | None = None
            content_hash: str | None = None
            try:
                content_ref = _source_content_ref(source.get("content_path"))
            except LlmWikiConnectorError:
                issues.append(TopicIssue("source-not-self-contained", location, source_id))
                content_ref = None
            if content_ref is not None:
                try:
                    content_raw = self._read_file(
                        bound.topic_fd,
                        content_ref,
                        maximum=_MAX_SOURCE_CONTENT_BYTES,
                        missing_ok=False,
                        observations=observations,
                    )
                    assert content_raw is not None
                    content = content_raw.decode("utf-8")
                    content_hash = _sha256(content_raw)
                except UnicodeError:
                    issues.append(TopicIssue("source-content-not-utf8", location, source_id))
                except LlmWikiConnectorError as error:
                    code = (
                        "source-content-missing"
                        if error.code == "topic-entry-missing"
                        else "source-content-unsafe"
                    )
                    issues.append(TopicIssue(code, location, source_id))
            stable_hash = _sha256(
                _canonical_bytes(
                    {
                        "payload_sha256": payload_hash,
                        "content_sha256": content_hash,
                    }
                )
            )
            sources.append(
                HashedRecord(
                    source_id,
                    dict(source),
                    stable_hash,
                    payload_hash,
                    content,
                    content_hash,
                )
            )

        claims_raw = self._read_file(
            bound.topic_fd,
            "final/claims.jsonl",
            maximum=_MAX_JSONL_BYTES,
            missing_ok=True,
            observations=observations,
        )
        claim_values = self._decode_jsonl(claims_raw, "final/claims.jsonl", issues)
        claims: list[HashedRecord] = []
        claim_ids: set[str] = set()
        for index, value in claim_values:
            location = f"final/claims.jsonl:{index}"
            claim = _validate_claim(value, location, issues)
            if claim is None:
                continue
            claim_id = str(claim["id"])
            if claim_id in claim_ids:
                issues.append(TopicIssue("duplicate-claim-id", location, claim_id))
                continue
            claim_ids.add(claim_id)
            for evidence in claim["evidence"]:
                source_id = str(evidence["source_id"])
                if source_id not in source_ids:
                    issues.append(TopicIssue("missing-source-fk", location, source_id))
            claim_hash = _sha256(_canonical_bytes(claim))
            claims.append(
                HashedRecord(claim_id, dict(claim), claim_hash, claim_hash)
            )

        first_wiki_set = self._wiki_names(bound.topic_fd)
        first_wiki_names = first_wiki_set.names
        pages: list[WikiPage] = []
        wiki_ids: set[str] = set()
        for name in first_wiki_names:
            relative = f"final/wiki/{name}"
            raw = self._read_file(
                bound.topic_fd,
                relative,
                maximum=_MAX_WIKI_BYTES,
                missing_ok=False,
                observations=observations,
            )
            assert raw is not None
            try:
                text = raw.decode("utf-8")
                page_value, body = _parse_frontmatter(text)
            except (UnicodeError, ValueError, RecursionError):
                issues.append(TopicIssue("invalid-wiki-page", relative))
                continue
            page = _validate_wiki(page_value, relative, issues)
            if page is None:
                continue
            wiki_id = str(page["id"])
            if wiki_id in wiki_ids:
                issues.append(TopicIssue("duplicate-wiki-id", relative, wiki_id))
                continue
            wiki_ids.add(wiki_id)
            for claim_id in page["claims"]:
                if claim_id not in claim_ids:
                    issues.append(TopicIssue("missing-claim-fk", relative, str(claim_id)))
            pages.append(WikiPage(relative, dict(page), body, _sha256(raw)))
        if self._wiki_names(bound.topic_fd) != first_wiki_set:
            raise LlmWikiConnectorError("topic-changed")

        self._before_topic_revalidate(bound.path)
        if self._wiki_names(bound.topic_fd) != first_wiki_set:
            raise LlmWikiConnectorError("topic-moved")
        self._revalidate_leaves(bound.topic_fd, observations)
        self._revalidate_topic(bound)
        if issues:
            bounded = tuple(issues[:_MAX_ISSUES])
            if len(issues) > _MAX_ISSUES:
                bounded += (TopicIssue("too-many-issues"),)
            raise LlmWikiConnectorError("topic-invalid", bounded)
        if manifest is None:  # guarded by issues above
            raise LlmWikiConnectorError("topic-invalid")

        manifest_spec_version = str(manifest["spec_version"])
        manifest_hash = _sha256(_canonical_bytes(manifest))
        source_hashes = tuple((entry.record_id, entry.sha256) for entry in sources)
        snapshot_payload = {
            "schema_version": 1,
            "spec_version": manifest_spec_version,
            "manifest_sha256": manifest_hash,
            "sources": list(source_hashes),
            "final_claims": [(entry.record_id, entry.sha256) for entry in claims],
            "wiki_pages": [(entry.relative_ref, entry.sha256) for entry in pages],
        }
        return TopicSnapshot(
            schema_version=1,
            spec_version=manifest_spec_version,
            topic_ref=_path_ref(bound.path),
            manifest=dict(manifest),
            manifest_sha256=manifest_hash,
            sources=tuple(sources),
            final_claims=tuple(claims),
            wiki_pages=tuple(pages),
            source_hashes=source_hashes,
            snapshot_sha256=_sha256(_canonical_bytes(snapshot_payload)),
        )

    @staticmethod
    def _before_topic_revalidate(_topic_path: Path) -> None:
        """Test seam immediately before the final held-root identity check."""

    @staticmethod
    def _drain_ready(
        selector: selectors.BaseSelector,
        counters: Mapping[int, _ByteCounter],
        *,
        deadline: float,
    ) -> bool:
        drained = False
        for key, _events in selector.select(timeout=0):
            for _ in range(16):
                if time.monotonic() >= deadline:
                    return drained
                try:
                    chunk = os.read(key.fd, 64 * 1024)
                except BlockingIOError:
                    break
                except OSError:
                    try:
                        selector.unregister(key.fd)
                    except KeyError:
                        pass
                    break
                if not chunk:
                    try:
                        selector.unregister(key.fd)
                    except KeyError:
                        pass
                    break
                counters[key.fd].add(len(chunk))
                drained = True
        return drained

    @staticmethod
    def _kill_process(process: subprocess.Popen[bytes]) -> None:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except OSError:
            try:
                process.kill()
            except OSError:
                pass

    @staticmethod
    def _reap_process_bounded(
        process: subprocess.Popen[bytes], *, timeout: float = 0.2
    ) -> int | None:
        deadline = time.monotonic() + timeout
        returncode = process.poll()
        while returncode is None and time.monotonic() < deadline:
            remaining = max(0.0, deadline - time.monotonic())
            time.sleep(min(0.005, remaining))
            returncode = process.poll()
        return returncode

    def _run_validate(self, topic_path: Path) -> _ProcessResult:
        argv = [*self._command, "validate", os.fspath(topic_path)]
        deadline = time.monotonic() + self._timeout
        try:
            process = subprocess.Popen(
                argv,
                cwd=self._cwd,
                env=self._env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                start_new_session=True,
            )
        except (OSError, TypeError, ValueError, UnicodeError):
            return _ProcessResult(None, 0, 0, False, True, False)
        stdout_stream = process.stdout
        stderr_stream = process.stderr
        stdout = _ByteCounter(self._max_output_bytes)
        stderr = _ByteCounter(self._max_output_bytes)
        selector: selectors.BaseSelector | None = None
        counters: dict[int, _ByteCounter] = {}
        timed_out = False
        setup_failed = False
        returncode: int | None = None
        try:
            try:
                if stdout_stream is None or stderr_stream is None:
                    raise RuntimeError("subprocess pipes unavailable")
                selector = selectors.DefaultSelector()
                counters = {
                    stdout_stream.fileno(): stdout,
                    stderr_stream.fileno(): stderr,
                }
                for descriptor in counters:
                    os.set_blocking(descriptor, False)
                    selector.register(descriptor, selectors.EVENT_READ)
            except Exception:
                setup_failed = True
                self._kill_process(process)

            if not setup_failed:
                assert selector is not None
                while True:
                    returncode = process.poll()
                    now = time.monotonic()
                    if returncode is not None:
                        drain_deadline = min(deadline, now + 0.02)
                        while time.monotonic() < drain_deadline and self._drain_ready(
                            selector, counters, deadline=drain_deadline
                        ):
                            pass
                        break
                    if now >= deadline:
                        timed_out = True
                        self._kill_process(process)
                        break
                    selector.select(timeout=min(0.02, deadline - now))
                    self._drain_ready(selector, counters, deadline=deadline)

                cleanup_deadline = time.monotonic() + 0.2
                while returncode is None and time.monotonic() < cleanup_deadline:
                    returncode = process.poll()
                    self._drain_ready(selector, counters, deadline=cleanup_deadline)
                    if returncode is None:
                        remaining = max(0.0, cleanup_deadline - time.monotonic())
                        selector.select(timeout=min(0.01, remaining))
                if returncode is None:
                    self._kill_process(process)
            if setup_failed or returncode is None:
                returncode = self._reap_process_bounded(process)
        finally:
            if selector is not None:
                try:
                    selector.close()
                except Exception:
                    pass
            for stream in (stdout_stream, stderr_stream):
                if stream is not None:
                    try:
                        stream.close()
                    except Exception:
                        pass
        return _ProcessResult(
            returncode,
            stdout.size,
            stderr.size,
            timed_out,
            False,
            setup_failed,
        )

    def _validate_bound(self, bound: _BoundTopic) -> TopicValidation:
        result = self._run_validate(bound.path)
        try:
            self._revalidate_topic(bound)
        except LlmWikiConnectorError:
            return TopicValidation(1, "contract_error", result.returncode, result.stdout_bytes, result.stderr_bytes, "topic-moved")
        if result.spawn_failed:
            return TopicValidation(1, "unavailable", None, 0, 0, "executable-unavailable")
        if result.setup_failed:
            return TopicValidation(1, "contract_error", result.returncode, 0, 0, "subprocess-setup-failed")
        if result.timed_out:
            return TopicValidation(1, "transient", result.returncode, result.stdout_bytes, result.stderr_bytes, "timeout")
        if (
            result.stdout_bytes > self._max_output_bytes
            or result.stderr_bytes > self._max_output_bytes
        ):
            return TopicValidation(1, "contract_error", result.returncode, result.stdout_bytes, result.stderr_bytes, "output-too-large")
        if result.returncode == 0:
            return TopicValidation(1, "valid", 0, result.stdout_bytes, result.stderr_bytes, None)
        if result.returncode == 1:
            return TopicValidation(1, "invalid", 1, result.stdout_bytes, result.stderr_bytes, "upstream-validation-failed")
        return TopicValidation(1, "transient", result.returncode, result.stdout_bytes, result.stderr_bytes, "unknown-exit")

    def validate_topic(self, topic_dir: str | os.PathLike[str]) -> TopicValidation:
        """Run exact public ``validate <topic-dir>`` without parsing human output."""

        try:
            bound = self._bind_topic(topic_dir)
        except LlmWikiConnectorError as error:
            return TopicValidation(1, "contract_error", None, 0, 0, error.code)
        try:
            return self._validate_bound(bound)
        finally:
            self._close_bound(bound)

    def read_topic(self, topic_dir: str | os.PathLike[str]) -> TopicSnapshot:
        """Read sources, final claims, and wiki directly through spec 0.1.0."""

        bound = self._bind_topic(topic_dir)
        try:
            return self._read_bound(bound)
        finally:
            self._close_bound(bound)

    def load_topic(self, topic_dir: str | os.PathLike[str]) -> TopicSnapshot:
        """Validate with llmwiki CLI, then read the same held topic inode."""

        bound = self._bind_topic(topic_dir)
        try:
            validation = self._validate_bound(bound)
            if validation.status != "valid":
                raise LlmWikiConnectorError(
                    validation.issue_code or "upstream-validation-failed",
                    (TopicIssue(validation.issue_code or "upstream-validation-failed"),),
                )
            return self._read_bound(bound)
        finally:
            self._close_bound(bound)
