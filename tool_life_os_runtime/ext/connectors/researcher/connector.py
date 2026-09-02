"""Bounded adapter for the researcher v1 machine and topic contracts."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import selectors
import signal
import stat
import subprocess
import time
from typing import Callable, Mapping, Protocol, Sequence
import unicodedata

from tool_life_os_runtime.ext.connectors.llmwiki import (
    HashedRecord,
    TopicSnapshot,
    WikiPage,
)
from tool_life_os_runtime.ext.connectors.probes import DEFAULT_SPECS


RESEARCHER_CONNECTOR_SCHEMA_VERSION = 1
MAX_CONNECTOR_OUTPUT_BYTES = 64 * 1024

_MAX_JSON_DEPTH = 12
_MAX_JSON_INTEGER = 2**63 - 1
_MAX_ENV = 256
_MAX_DOCUMENTS = 256
_MAX_DOCUMENT_BYTES = 2 * 1024 * 1024
_MAX_TOTAL_DOCUMENT_BYTES = 16 * 1024 * 1024
_MAX_WINDOWS_PER_DOCUMENT = 1 + _MAX_DOCUMENT_BYTES // (12_000 // 2 - 512)
_MAX_TOPIC_RECORDS = 8192
_MAX_WIKI_PAGES = 2048
_MAX_TOPIC_JSON_BYTES = 16 * 1024 * 1024
_MAX_SOURCE_CONTENT_BYTES = 4 * 1024 * 1024
_MAX_WIKI_BYTES = 2 * 1024 * 1024
_PHASES = frozenset({"planned", "collecting", "verifying", "synthesizing", "done"})
_KINDS = frozenset({"auto", "local-markdown", "coursedump-manifest"})
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_PLAN_ID = re.compile(r"^plan_[0-9a-f]{24}$")
_DOCUMENT_ID = re.compile(r"^doc_[0-9a-f]{24}$")
_SOURCE_ID = re.compile(r"^src_[0-9a-f]{12}$")
_CLAIM_ID = re.compile(r"^clm_[0-9a-f]{12}$")
_SEMVER = re.compile(r"^(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})$")
_TOPIC_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$")
_PRIVATE_PATH = re.compile(r"(?i)(?:/users/|/home/|[a-z]:\\users\\|[a-z]:\\home\\)")
_FILE_SCHEME = re.compile(r"(?i)(?:^|[^a-z0-9_])file:")
_SPEC = next(spec for spec in DEFAULT_SPECS if spec.tool == "researcher")


class ResearcherConnectorError(ValueError):
    """Normalized process, response, or artifact failure."""

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
        self.runtime_exit_code = (
            75 if category == "quota" else 111 if category == "transient" else 1
        )
        self.stdout_bytes = stdout_bytes
        self.stderr_bytes = stderr_bytes
        super().__init__(code)


@dataclass(frozen=True)
class ResearcherEvent:
    schema_version: int
    event_type: str
    semantic_key: str
    status: str
    phase: str
    topic_ref: str
    summary: str
    urgency: str
    surface: str
    requires_receipt: bool


@dataclass(frozen=True)
class ResearcherResult:
    schema_version: int
    operation: str
    status: str
    phase: str
    topic_ref: str
    topic_name: str
    upstream_exit_code: int
    runtime_exit_code: int
    event: ResearcherEvent | None = None


@dataclass(frozen=True)
class ResearcherSourceDocument:
    document_id: str
    relative_path: str
    title: str
    sha256: str
    size_bytes: int
    window_count: int


@dataclass(frozen=True)
class ResearcherSourcePlan:
    schema_version: int
    plan_id: str
    status: str
    source_kind: str
    corpus_sha256: str
    documents: tuple[ResearcherSourceDocument, ...]
    window_chars: int
    overlap_chars: int
    upstream_exit_code: int
    runtime_exit_code: int
    event: ResearcherEvent


@dataclass(frozen=True)
class ResearcherArtifactRef:
    logical_ref: str
    sha256: str


@dataclass(frozen=True)
class ResearcherArtifactRegistration:
    schema_version: int
    topic_ref: str
    topic_manifest: ResearcherArtifactRef
    topic_snapshot: ResearcherArtifactRef
    sources: tuple[ResearcherArtifactRef, ...]
    claims: tuple[ResearcherArtifactRef, ...]
    wiki: tuple[ResearcherArtifactRef, ...]
    registration_sha256: str


@dataclass(frozen=True)
class ResearcherReviewAdapter:
    schema_version: int
    source_kind: str
    source_ref: str
    source_sha256: str
    topic_snapshot: TopicSnapshot


@dataclass(frozen=True)
class ResearcherImportResult:
    schema_version: int
    status: str
    registration: ResearcherArtifactRegistration
    review: ResearcherReviewAdapter


@dataclass(frozen=True)
class _ProcessResult:
    returncode: int | None
    stdout: bytes
    stdout_bytes: int
    stderr_bytes: int
    timed_out: bool
    setup_failed: bool


class TopicBoundary(Protocol):
    def load_topic(self, topic_dir: str | os.PathLike[str]) -> TopicSnapshot: ...


def _fail(
    code: str,
    *,
    category: str = "contract",
    returncode: int | None = None,
    stdout_bytes: int = 0,
    stderr_bytes: int = 0,
) -> None:
    raise ResearcherConnectorError(
        code,
        category=category,
        returncode=returncode,
        stdout_bytes=stdout_bytes,
        stderr_bytes=stderr_bytes,
    )


def _has_control(value: str) -> bool:
    return any(
        unicodedata.category(character).startswith("C")
        or unicodedata.category(character) in {"Zl", "Zp"}
        for character in value
    )


def _text(value: object, label: str, maximum: int, *, portable: bool = True) -> str:
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
        or (portable and (_PRIVATE_PATH.search(value) or _FILE_SCHEME.search(value)))
    ):
        _fail(f"invalid-{label}")
    return value


def _integer(value: object, label: str, maximum: int = _MAX_JSON_INTEGER) -> int:
    if type(value) is not int or value < 0 or value > maximum:
        _fail(f"invalid-{label}")
    return value


def _hash(value: object, label: str) -> str:
    checked = _text(value, label, 64)
    if _SHA256.fullmatch(checked) is None:
        _fail(f"invalid-{label}")
    return checked


def _relative(value: object, label: str) -> str:
    checked = _text(value, label, 2048)
    if "\\" in checked:
        _fail(f"invalid-{label}")
    path = PurePosixPath(checked)
    if (
        path.is_absolute()
        or path.as_posix() != checked
        or not path.parts
        or len(path.parts) > 16
        or any(
            part in {"", ".", ".."} or len(part.encode("utf-8")) > 255
            for part in path.parts
        )
    ):
        _fail(f"invalid-{label}")
    return checked


def _source_relative(value: object) -> str:
    if not isinstance(value, str) or not value:
        _fail("invalid-document-path")
    try:
        encoded = value.encode("utf-8")
    except UnicodeError:
        _fail("invalid-document-path")
    path = PurePosixPath(value)
    if (
        len(encoded) > 1024
        or value != unicodedata.normalize("NFC", value)
        or _has_control(value)
        or "\\" in value
        or path.is_absolute()
        or path.as_posix() != value
        or not path.parts
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        _fail("invalid-document-path")
    return value


def _source_title(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 300:
        _fail("invalid-document-title")
    try:
        value.encode("utf-8")
    except UnicodeError:
        _fail("invalid-document-title")
    if _has_control(value):
        _fail("invalid-document-title")
    return value


def _canonical(value: object) -> bytes:
    try:
        return (
            json.dumps(
                value,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
            + b"\n"
        )
    except (TypeError, ValueError, UnicodeError, RecursionError):
        _fail("noncanonical-connector-data")


def _canonical_digest(value: object) -> str:
    return hashlib.sha256(_canonical(value)[:-1]).hexdigest()


def _bounded_text_bytes(value: object, label: str, maximum: int) -> bytes:
    if not isinstance(value, str):
        _fail(f"invalid-{label}")
    try:
        encoded = value.encode("utf-8")
    except UnicodeError:
        _fail(f"invalid-{label}")
    if len(encoded) > maximum:
        _fail(f"invalid-{label}")
    return encoded


def _bounded_canonical(value: object, label: str, maximum: int) -> bytes:
    encoded = _canonical(value)[:-1]
    if len(encoded) > maximum:
        _fail(f"invalid-{label}")
    return encoded


def _frontmatter_scalar(value: object) -> str:
    if not isinstance(value, str):
        _fail("invalid-wiki-frontmatter")
    _bounded_text_bytes(value, "wiki-frontmatter", _MAX_WIKI_BYTES)
    plain = (
        bool(value)
        and value == value.strip()
        and not value.startswith('"')
        and all(ord(character) >= 0x20 for character in value)
    )
    if plain:
        return value
    try:
        return json.dumps(value, ensure_ascii=False)
    except (TypeError, ValueError, UnicodeError, RecursionError):
        _fail("invalid-wiki-frontmatter")


def _wiki_digest(page: WikiPage) -> str:
    if not isinstance(page.frontmatter, dict):
        _fail("invalid-wiki-frontmatter")
    lines = ["---\n"]
    for key, value in page.frontmatter.items():
        if (
            not isinstance(key, str)
            or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]*", key) is None
        ):
            _fail("invalid-wiki-frontmatter")
        if isinstance(value, list):
            lines.append(f"{key}:\n")
            lines.extend(f"  - {_frontmatter_scalar(item)}\n" for item in value)
        else:
            lines.append(f"{key}: {_frontmatter_scalar(value)}\n")
    body = page.body
    body_bytes = _bounded_text_bytes(body, "wiki-body", _MAX_WIKI_BYTES)
    body = body.strip("\n")
    lines.append("---\n")
    if body:
        lines.extend(("\n", body, "\n"))
    rendered = "".join(lines).encode("utf-8")
    if len(rendered) > _MAX_WIKI_BYTES or len(body_bytes) > _MAX_WIKI_BYTES:
        _fail("invalid-wiki-page")
    return hashlib.sha256(rendered).hexdigest()


def _no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            _fail("duplicate-machine-field")
        result[key] = value
    return result


def _json_safe(value: object, depth: int = 0) -> bool:
    if depth > _MAX_JSON_DEPTH:
        return False
    if value is None or isinstance(value, bool):
        return True
    if type(value) is int:
        return -(_MAX_JSON_INTEGER + 1) <= value <= _MAX_JSON_INTEGER
    if type(value) is float:
        return math.isfinite(value)
    if isinstance(value, str):
        try:
            return len(value.encode("utf-8")) <= MAX_CONNECTOR_OUTPUT_BYTES
        except UnicodeError:
            return False
    if isinstance(value, list):
        return len(value) <= 4096 and all(_json_safe(item, depth + 1) for item in value)
    if isinstance(value, dict):
        if len(value) > 512:
            return False
        for key, item in value.items():
            if not isinstance(key, str):
                return False
            try:
                if len(key.encode("utf-8")) > 256:
                    return False
            except UnicodeError:
                return False
            if not _json_safe(item, depth + 1):
                return False
        return True
    return False


def _decode(raw: bytes, maximum: int) -> dict[str, object]:
    if not raw or len(raw) > maximum:
        _fail("machine-output-size")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicates)
    except ResearcherConnectorError:
        raise
    except (UnicodeError, ValueError, RecursionError):
        _fail("malformed-machine-output")
    if not isinstance(value, dict) or not _json_safe(value) or raw != _canonical(value):
        _fail("noncanonical-machine-output")
    return value


def _exact(value: object, keys: set[str], label: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        _fail(f"invalid-{label}")
    return value


def _strict_equal(value: object, expected: object) -> bool:
    if type(value) is not type(expected):
        return False
    if isinstance(expected, dict):
        return set(value) == set(expected) and all(
            _strict_equal(value[key], expected[key]) for key in expected
        )
    if isinstance(expected, list):
        return len(value) == len(expected) and all(
            _strict_equal(item, wanted)
            for item, wanted in zip(value, expected, strict=True)
        )
    return value == expected


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
    cwd: Path,
    env: Mapping[str, str],
    deadline: float,
    limit: int,
) -> _ProcessResult:
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
    except Exception:
        _fail("connector-executable-unavailable", category="unavailable")
    selector: selectors.BaseSelector | None = None
    stdout = bytearray()
    sizes = {"stdout": 0, "stderr": 0}
    timed_out = False
    setup_failed = False
    pipes_open = True
    try:
        if process.stdout is None or process.stderr is None:  # pragma: no cover
            setup_failed = True
            return _ProcessResult(None, b"", 0, 0, False, True)
        selector = selectors.DefaultSelector()
        for label, stream in (("stdout", process.stdout), ("stderr", process.stderr)):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, label)
        while selector.get_map():
            remaining = _remaining(deadline)
            if remaining <= 0:
                timed_out = True
                break
            events = selector.select(remaining)
            if not events:
                timed_out = True
                break
            for key, _mask in events:
                stream = key.fileobj
                label = key.data
                while True:
                    try:
                        chunk = os.read(stream.fileno(), 8192)
                    except BlockingIOError:
                        break
                    if not chunk:
                        selector.unregister(stream)
                        break
                    sizes[label] = min(limit + 1, sizes[label] + len(chunk))
                    if label == "stdout" and len(stdout) <= limit:
                        stdout.extend(chunk[: limit + 1 - len(stdout)])
                if _remaining(deadline) <= 0:
                    timed_out = True
                    break
            if timed_out:
                break
        pipes_open = bool(selector.get_map())
        if not timed_out:
            try:
                process.wait(timeout=_remaining(deadline))
            except subprocess.TimeoutExpired:
                timed_out = True
    except Exception:
        setup_failed = True
    finally:
        if setup_failed or timed_out or pipes_open or process.poll() is None:
            _kill_group(process)
        if process.poll() is None:
            try:
                process.wait(timeout=_remaining(deadline))
            except (subprocess.TimeoutExpired, OSError, ValueError):
                _kill_group(process)
        if selector is not None:
            try:
                selector.close()
            except (OSError, ValueError):
                pass
        for stream in (process.stdout, process.stderr):
            if stream is not None:
                try:
                    stream.close()
                except (OSError, ValueError):
                    pass
    return _ProcessResult(
        process.returncode,
        bytes(stdout),
        sizes["stdout"],
        sizes["stderr"],
        timed_out,
        setup_failed,
    )


def _semver(value: object) -> tuple[int, int, int]:
    if not isinstance(value, str) or (match := _SEMVER.fullmatch(value)) is None:
        _fail("invalid-tool-version")
    return tuple(int(match.group(index)) for index in (1, 2, 3))


def _directory_identity(path: Path, code: str) -> tuple[int, int]:
    try:
        metadata = os.stat(path, follow_symlinks=False)
    except OSError:
        _fail(code)
    if not stat.S_ISDIR(metadata.st_mode):
        _fail(code)
    return metadata.st_dev, metadata.st_ino


def _source_identity(path: Path, code: str) -> tuple[int, int, int, int, int, int]:
    try:
        metadata = os.stat(path, follow_symlinks=False)
    except (OSError, UnicodeError):
        _fail(code)
    if not (stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode)):
        _fail(code)
    return (
        metadata.st_dev,
        metadata.st_ino,
        stat.S_IFMT(metadata.st_mode),
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _topic_ref(name: str) -> str:
    digest = hashlib.sha256(
        b"lifeos-researcher-topic-v1\0" + name.encode("utf-8")
    ).hexdigest()
    return f"researcher/topics/topic_{digest[:24]}"


class ResearcherConnector:
    """Configured researcher machine client and llmwiki import adapter."""

    def __init__(
        self,
        *,
        topics_root: str | os.PathLike[str],
        command: Sequence[str],
        cwd: str | os.PathLike[str],
        env: Mapping[str, str],
        topic_boundary: TopicBoundary,
        timeout: float = 30.0,
        max_output_bytes: int = MAX_CONNECTOR_OUTPUT_BYTES,
    ) -> None:
        self._command = self._validate_command(command)
        self._cwd = self._absolute_directory(cwd, "connector-cwd")
        self._cwd_identity = _directory_identity(self._cwd, "connector-cwd-moved")
        self._topics_root = self._absolute_directory(topics_root, "topics-root")
        self._topics_identity = _directory_identity(
            self._topics_root, "topics-root-moved"
        )
        if not callable(getattr(topic_boundary, "load_topic", None)):
            _fail("invalid-topic-boundary")
        self._topic_boundary = topic_boundary
        if not isinstance(env, Mapping) or len(env) > _MAX_ENV:
            _fail("invalid-environment")
        checked_env: dict[str, str] = {}
        for key, value in env.items():
            try:
                key_size = len(key.encode("utf-8")) if isinstance(key, str) else -1
                value_size = (
                    len(value.encode("utf-8")) if isinstance(value, str) else -1
                )
            except UnicodeError:
                _fail("invalid-environment")
            if (
                not isinstance(key, str)
                or not key
                or key_size > 256
                or "=" in key
                or "\x00" in key
                or not isinstance(value, str)
                or value_size > 32 * 1024
                or "\x00" in value
            ):
                _fail("invalid-environment")
            checked_env[key] = value
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
            _fail("invalid-timeout")
        if not math.isfinite(float(timeout)) or not 0.05 <= float(timeout) <= 3600:
            _fail("invalid-timeout")
        if (
            type(max_output_bytes) is not int
            or not 1024 <= max_output_bytes <= MAX_CONNECTOR_OUTPUT_BYTES
        ):
            _fail("invalid-output-limit")
        self._env = checked_env
        self._timeout = float(timeout)
        self._max_output_bytes = max_output_bytes

    @staticmethod
    def _validate_command(command: Sequence[str]) -> tuple[str, ...]:
        if type(command) not in {list, tuple} or not 0 < len(command) <= 16:
            _fail("invalid-command")
        return tuple(_text(item, "command", 4096, portable=False) for item in command)

    @staticmethod
    def _absolute_directory(value: str | os.PathLike[str], label: str) -> Path:
        try:
            raw = os.fspath(value)
        except TypeError:
            _fail(f"invalid-{label}")
        if (
            not isinstance(raw, str)
            or not raw
            or raw != unicodedata.normalize("NFC", raw)
            or _has_control(raw)
        ):
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

    def _revalidate_roots(self) -> None:
        if _directory_identity(self._cwd, "connector-cwd-moved") != self._cwd_identity:
            _fail("connector-cwd-moved")
        if (
            _directory_identity(self._topics_root, "topics-root-moved")
            != self._topics_identity
        ):
            _fail("topics-root-moved")

    @staticmethod
    def _topic_name(value: object) -> str:
        checked = _text(value, "topic-name", 255)
        if (
            _TOPIC_NAME.fullmatch(checked) is None
            or checked in {".", ".."}
            or checked.casefold() in {"work", "final", "sources", "staging"}
        ):
            _fail("invalid-topic-name")
        return checked

    def _topic_identity(self, name: str) -> tuple[int, int]:
        flags = (
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        )
        root_fd: int | None = None
        topic_fd: int | None = None
        try:
            root_fd = os.open(self._topics_root, flags)
            root_meta = os.fstat(root_fd)
            named_root = os.stat(self._topics_root, follow_symlinks=False)
            root_identity = (root_meta.st_dev, root_meta.st_ino)
            if root_identity != self._topics_identity or root_identity != (
                named_root.st_dev,
                named_root.st_ino,
            ):
                _fail("topics-root-moved")
            topic_fd = os.open(name, flags, dir_fd=root_fd)
            topic_meta = os.fstat(topic_fd)
            named_topic = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
            topic_identity = (topic_meta.st_dev, topic_meta.st_ino)
            if topic_identity != (named_topic.st_dev, named_topic.st_ino):
                _fail("topic-artifact-moved")
            return topic_identity
        except ResearcherConnectorError:
            raise
        except OSError:
            _fail("topic-artifact-unavailable")
        finally:
            for descriptor in (topic_fd, root_fd):
                if descriptor is not None:
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass

    def _execute(self, suffix: Sequence[str], deadline: float) -> _ProcessResult:
        self._revalidate_roots()
        result = _run_process(
            (*self._command, *suffix),
            cwd=self._cwd,
            env=self._env,
            deadline=deadline,
            limit=self._max_output_bytes,
        )
        self._revalidate_roots()
        if result.setup_failed:
            _fail(
                "connector-process-io",
                category="transient",
                returncode=result.returncode,
                stdout_bytes=result.stdout_bytes,
                stderr_bytes=result.stderr_bytes,
            )
        if result.timed_out:
            _fail(
                "connector-timeout",
                category="transient",
                returncode=result.returncode,
                stdout_bytes=result.stdout_bytes,
                stderr_bytes=result.stderr_bytes,
            )
        return result

    def _handshake(self, deadline: float) -> None:
        result = self._execute(("capabilities", "--json"), deadline)
        if result.returncode != 0:
            self._raise_nonzero(result, "capabilities")
        self._check_sizes(result)
        payload = _decode(result.stdout, self._max_output_bytes)
        if set(payload) != {"schema_version", "tool", "version", "capabilities"}:
            _fail("capability-contract-mismatch")
        expected = [item.to_dict() for item in _SPEC.expected_capabilities]
        version = _semver(payload["version"])
        if (
            type(payload["schema_version"]) is not int
            or payload["schema_version"] != 1
            or payload["tool"] != "researcher"
            or not _SPEC.minimum_version <= version < _SPEC.maximum_version_exclusive
            or not _strict_equal(payload["capabilities"], expected)
        ):
            _fail("capability-contract-mismatch")

    def _check_sizes(self, result: _ProcessResult) -> None:
        if (
            result.stdout_bytes > self._max_output_bytes
            or result.stderr_bytes > self._max_output_bytes
        ):
            _fail(
                "machine-output-size",
                returncode=result.returncode,
                stdout_bytes=result.stdout_bytes,
                stderr_bytes=result.stderr_bytes,
            )

    def _raise_nonzero(self, result: _ProcessResult, operation: str) -> None:
        if result.returncode == 75:
            _fail(
                "researcher-quota",
                category="quota",
                returncode=75,
                stdout_bytes=result.stdout_bytes,
                stderr_bytes=result.stderr_bytes,
            )
        if result.returncode == 111 or result.returncode not in {0, 1, 75, 76, 111}:
            _fail(
                "researcher-transient",
                category="transient",
                returncode=result.returncode,
                stdout_bytes=result.stdout_bytes,
                stderr_bytes=result.stderr_bytes,
            )
        if result.returncode == 76:
            _fail("unexpected-waiting-human", returncode=76)
        self._check_sizes(result)
        try:
            payload = _decode(result.stdout, self._max_output_bytes)
        except ResearcherConnectorError:
            _fail("invalid-failure-envelope", returncode=1)
        error = payload.get("error")
        if (
            payload.get("schema_version") != 1
            or payload.get("status") != "error"
            or not isinstance(error, dict)
            or set(error) != {"code"}
            or not isinstance(error.get("code"), str)
        ):
            _fail("invalid-failure-envelope", returncode=1)
        _text(error["code"], "failure-code", 128)
        _fail(f"researcher-{operation}-failed", category="fatal", returncode=1)

    def _operation(
        self,
        operation: str,
        suffix: Sequence[str],
        deadline: float,
        *,
        before_operation: Callable[[], None] | None = None,
    ) -> _ProcessResult:
        self._handshake(deadline)
        if before_operation is not None:
            before_operation()
        result = self._execute(suffix, deadline)
        if result.returncode not in {0, 76}:
            self._raise_nonzero(result, operation)
        self._check_sizes(result)
        return result

    def start(self, topic: str) -> ResearcherResult:
        checked = _text(topic, "topic", 2048, portable=False)
        return self._run_operation(
            "start",
            ("start", checked, "--base", str(self._topics_root), "--json"),
            None,
        )

    def status(self, topic_name: str) -> ResearcherResult:
        name = self._topic_name(topic_name)
        return self._run_operation(
            "status", ("status", str(self._topics_root / name)), name
        )

    def resume(self, topic_name: str) -> ResearcherResult:
        name = self._topic_name(topic_name)
        return self._run_operation(
            "resume", ("resume", str(self._topics_root / name), "--json"), name
        )

    def extend(self, topic_name: str) -> ResearcherResult:
        name = self._topic_name(topic_name)
        return self._run_operation(
            "extend", ("extend", str(self._topics_root / name), "--json"), name
        )

    def _run_operation(
        self, operation: str, suffix: Sequence[str], expected_name: str | None
    ) -> ResearcherResult:
        before = self._topic_identity(expected_name) if expected_name else None
        deadline = time.monotonic() + self._timeout

        def revalidate_topic() -> None:
            assert expected_name is not None and before is not None
            if self._topic_identity(expected_name) != before:
                _fail("topic-artifact-moved")

        result = self._operation(
            operation,
            suffix,
            deadline,
            before_operation=revalidate_topic if expected_name is not None else None,
        )
        payload = _decode(result.stdout, self._max_output_bytes)
        required = {"schema_version", "status", "phase"}
        if operation != "status":
            required.add("topic_dir")
        if not required.issubset(payload):
            _fail("invalid-operation-result")
        if type(payload["schema_version"]) is not int or payload["schema_version"] != 1:
            _fail("unsupported-operation-schema")
        status_value = _text(payload["status"], "operation-status", 32)
        phase = _text(payload["phase"], "operation-phase", 32)
        if phase not in _PHASES:
            _fail("invalid-operation-phase")
        if operation == "status":
            name = expected_name
            if result.returncode != 0 or status_value not in {"running", "done"}:
                _fail("operation-exit-status-mismatch")
        else:
            topic_dir = payload["topic_dir"]
            if not isinstance(topic_dir, str):
                _fail("invalid-topic-artifact")
            path = Path(topic_dir)
            try:
                if path.parent != self._topics_root:
                    _fail("topic-artifact-outside-root")
                name = self._topic_name(path.name)
            except (OSError, ValueError, UnicodeError):
                _fail("invalid-topic-artifact")
            if expected_name is not None and name != expected_name:
                _fail("topic-artifact-mismatch")
            expected_status = "waiting_human" if result.returncode == 76 else None
            if expected_status is not None and status_value != expected_status:
                _fail("operation-exit-status-mismatch")
            if result.returncode == 0 and status_value not in {"running", "done"}:
                _fail("operation-exit-status-mismatch")
        assert name is not None
        after = self._topic_identity(name)
        if before is not None and after != before:
            _fail("topic-artifact-moved")
        ref = _topic_ref(name)
        event = None
        if result.returncode == 76:
            event = ResearcherEvent(
                RESEARCHER_CONNECTOR_SCHEMA_VERSION,
                "researcher-waiting-human",
                f"researcher:{operation}:{ref}:{phase}",
                "waiting_human",
                phase,
                ref,
                "Research plan requires review",
                "normal",
                "gated",
                True,
            )
        return ResearcherResult(
            RESEARCHER_CONNECTOR_SCHEMA_VERSION,
            operation,
            status_value,
            phase,
            ref,
            name,
            result.returncode or 0,
            0,
            event,
        )

    def source_plan(
        self, source: str | os.PathLike[str], *, kind: str = "auto"
    ) -> ResearcherSourcePlan:
        checked_kind = _text(kind, "source-kind", 32)
        if checked_kind not in _KINDS:
            _fail("invalid-source-kind")
        try:
            raw = os.fspath(source)
        except TypeError:
            _fail("invalid-source")
        if (
            not isinstance(raw, str)
            or not Path(raw).is_absolute()
            or ".." in Path(raw).parts
            or raw != unicodedata.normalize("NFC", raw)
            or _has_control(raw)
        ):
            _fail("invalid-source")
        path = Path(raw)
        before = _source_identity(path, "source-unavailable")

        def revalidate_source() -> None:
            if _source_identity(path, "source-moved") != before:
                _fail("source-moved")

        deadline = time.monotonic() + self._timeout
        result = self._operation(
            "source-plan",
            ("source-plan", raw, "--kind", checked_kind, "--json"),
            deadline,
            before_operation=revalidate_source,
        )
        revalidate_source()
        if result.returncode != 76:
            _fail("operation-exit-status-mismatch")
        payload = _exact(
            _decode(result.stdout, self._max_output_bytes),
            {
                "schema_version",
                "plan_id",
                "status",
                "source_kind",
                "corpus_sha256",
                "documents",
                "window",
            },
            "source-plan",
        )
        if (
            type(payload["schema_version"]) is not int
            or payload["schema_version"] != 1
            or payload["status"] != "waiting_human"
        ):
            _fail("invalid-source-plan")
        plan_id = _text(payload["plan_id"], "plan-id", 29)
        if _PLAN_ID.fullmatch(plan_id) is None:
            _fail("invalid-plan-id")
        source_kind = _text(payload["source_kind"], "source-kind", 32)
        if (
            source_kind not in _KINDS - {"auto"}
            or checked_kind != "auto"
            and source_kind != checked_kind
        ):
            _fail("invalid-source-kind")
        corpus_sha256 = _hash(payload["corpus_sha256"], "corpus-sha256")
        raw_documents = payload["documents"]
        if (
            not isinstance(raw_documents, list)
            or not raw_documents
            or len(raw_documents) > _MAX_DOCUMENTS
        ):
            _fail("invalid-source-documents")
        documents: list[ResearcherSourceDocument] = []
        for raw_document in raw_documents:
            item = _exact(
                raw_document,
                {
                    "document_id",
                    "relative_path",
                    "title",
                    "sha256",
                    "size_bytes",
                    "window_count",
                },
                "source-document",
            )
            document_id = _text(item["document_id"], "document-id", 28)
            relative_path = _source_relative(item["relative_path"])
            document_sha256 = _hash(item["sha256"], "document-sha256")
            expected_document_id = (
                "doc_"
                + hashlib.sha256(
                    (relative_path + "\0" + document_sha256).encode("utf-8")
                ).hexdigest()[:24]
            )
            if (
                _DOCUMENT_ID.fullmatch(document_id) is None
                or document_id != expected_document_id
            ):
                _fail("invalid-source-document")
            documents.append(
                ResearcherSourceDocument(
                    document_id,
                    relative_path,
                    _source_title(item["title"]),
                    document_sha256,
                    _integer(item["size_bytes"], "document-size", _MAX_DOCUMENT_BYTES),
                    _integer(
                        item["window_count"],
                        "document-window-count",
                        _MAX_WINDOWS_PER_DOCUMENT,
                    ),
                )
            )
        relative_paths = [document.relative_path for document in documents]
        document_ids = [document.document_id for document in documents]
        if (
            relative_paths != sorted(relative_paths, key=str.casefold)
            or len({relative.casefold() for relative in relative_paths})
            != len(relative_paths)
            or len(set(document_ids)) != len(document_ids)
            or sum(document.size_bytes for document in documents)
            > _MAX_TOTAL_DOCUMENT_BYTES
        ):
            _fail("invalid-source-documents")
        window = _exact(payload["window"], {"max_chars", "overlap_chars"}, "window")
        window_chars = _integer(window["max_chars"], "window-chars", 12_000)
        overlap_chars = _integer(window["overlap_chars"], "window-overlap", 512)
        if window_chars != 12_000 or overlap_chars != 512:
            _fail("unsupported-source-window")
        plan_body = {
            "schema_version": 1,
            "source_kind": source_kind,
            "documents": [
                {
                    "document_id": document.document_id,
                    "relative_path": document.relative_path,
                    "title": document.title,
                    "sha256": document.sha256,
                    "size_bytes": document.size_bytes,
                    "window_count": document.window_count,
                }
                for document in documents
            ],
            "window": {
                "max_chars": window_chars,
                "overlap_chars": overlap_chars,
            },
        }
        expected_corpus_sha256 = _canonical_digest(plan_body)
        expected_plan_id = (
            "plan_"
            + hashlib.sha256(
                ("source-import-v1:" + expected_corpus_sha256).encode("ascii")
            ).hexdigest()[:24]
        )
        if corpus_sha256 != expected_corpus_sha256 or plan_id != expected_plan_id:
            _fail("source-plan-binding")
        source_ref = f"researcher/source-plans/{plan_id}"
        event = ResearcherEvent(
            1,
            "researcher-source-plan",
            f"researcher:source-plan:{plan_id}:{corpus_sha256}",
            "waiting_human",
            "source_plan",
            source_ref,
            "Research source plan requires review",
            "normal",
            "gated",
            True,
        )
        return ResearcherSourcePlan(
            1,
            plan_id,
            "waiting_human",
            source_kind,
            corpus_sha256,
            tuple(documents),
            window_chars,
            overlap_chars,
            76,
            0,
            event,
        )

    def import_topic(self, topic_name: str) -> ResearcherImportResult:
        name = self._topic_name(topic_name)
        before = self._topic_identity(name)
        observed = self.status(name)
        if observed.status != "done" or observed.phase != "done":
            _fail("topic-not-final")
        self._revalidate_roots()
        if self._topic_identity(name) != before:
            _fail("topic-artifact-moved")
        path = self._topics_root / name
        try:
            snapshot = self._topic_boundary.load_topic(path)
        except ResearcherConnectorError:
            raise
        except Exception:
            _fail("topic-validation-failed")
        self._revalidate_roots()
        if self._topic_identity(name) != before:
            _fail("topic-artifact-moved")
        registration = self._registration(path, name, snapshot)
        return ResearcherImportResult(
            1,
            "proposed",
            registration,
            ResearcherReviewAdapter(
                1,
                "researcher-topic",
                registration.topic_ref,
                registration.topic_snapshot.sha256,
                snapshot,
            ),
        )

    @staticmethod
    def _registration(
        path: Path, name: str, snapshot: object
    ) -> ResearcherArtifactRegistration:
        if (
            not isinstance(snapshot, TopicSnapshot)
            or type(snapshot.schema_version) is not int
            or snapshot.schema_version != 1
            or snapshot.spec_version != "0.1.0"
        ):
            _fail("invalid-topic-snapshot")
        if (
            snapshot.topic_ref
            != "sha256:" + hashlib.sha256(os.fsencode(path)).hexdigest()
        ):
            _fail("topic-snapshot-binding")
        if (
            not isinstance(snapshot.manifest, dict)
            or not isinstance(snapshot.sources, tuple)
            or not isinstance(snapshot.final_claims, tuple)
            or not isinstance(snapshot.wiki_pages, tuple)
            or not all(isinstance(item, HashedRecord) for item in snapshot.sources)
            or not all(isinstance(item, HashedRecord) for item in snapshot.final_claims)
            or not all(isinstance(item, WikiPage) for item in snapshot.wiki_pages)
            or len(snapshot.sources) > _MAX_TOPIC_RECORDS
            or len(snapshot.final_claims) > _MAX_TOPIC_RECORDS
            or len(snapshot.wiki_pages) > _MAX_WIKI_PAGES
        ):
            _fail("invalid-topic-snapshot")
        manifest_hash = hashlib.sha256(
            _bounded_canonical(snapshot.manifest, "topic-manifest", 256 * 1024)
        ).hexdigest()
        if manifest_hash != snapshot.manifest_sha256:
            _fail("topic-manifest-hash-binding")

        source_hashes: list[tuple[str, str]] = []
        source_json_bytes = 0
        for record in snapshot.sources:
            if (
                not isinstance(record.payload, dict)
                or not isinstance(record.record_id, str)
                or _SOURCE_ID.fullmatch(record.record_id) is None
                or record.payload.get("id") != record.record_id
            ):
                _fail("invalid-topic-source")
            payload = _bounded_canonical(
                record.payload, "topic-source-payload", _MAX_TOPIC_JSON_BYTES
            )
            source_json_bytes += len(payload)
            if source_json_bytes > _MAX_TOPIC_JSON_BYTES:
                _fail("invalid-topic-source-payload")
            payload_hash = hashlib.sha256(payload).hexdigest()
            if record.payload_sha256 != payload_hash:
                _fail("topic-source-payload-hash-binding")
            if record.content is None:
                content_hash = None
                if record.content_sha256 is not None:
                    _fail("topic-source-content-hash-binding")
            else:
                content_hash = hashlib.sha256(
                    _bounded_text_bytes(
                        record.content,
                        "topic-source-content",
                        _MAX_SOURCE_CONTENT_BYTES,
                    )
                ).hexdigest()
                if record.content_sha256 != content_hash:
                    _fail("topic-source-content-hash-binding")
            stable_hash = _canonical_digest(
                {
                    "payload_sha256": payload_hash,
                    "content_sha256": content_hash,
                }
            )
            if record.sha256 != stable_hash:
                _fail("topic-source-stable-hash-binding")
            source_hashes.append((record.record_id, stable_hash))

        claim_hashes: list[tuple[str, str]] = []
        claim_json_bytes = 0
        for record in snapshot.final_claims:
            if (
                not isinstance(record.payload, dict)
                or not isinstance(record.record_id, str)
                or _CLAIM_ID.fullmatch(record.record_id) is None
                or record.payload.get("id") != record.record_id
                or record.content is not None
                or record.content_sha256 is not None
            ):
                _fail("invalid-topic-claim")
            payload = _bounded_canonical(
                record.payload, "topic-claim-payload", _MAX_TOPIC_JSON_BYTES
            )
            claim_json_bytes += len(payload)
            if claim_json_bytes > _MAX_TOPIC_JSON_BYTES:
                _fail("invalid-topic-claim-payload")
            claim_hash = hashlib.sha256(payload).hexdigest()
            if record.payload_sha256 != claim_hash or record.sha256 != claim_hash:
                _fail("topic-claim-hash-binding")
            claim_hashes.append((record.record_id, claim_hash))

        wiki_hashes: list[tuple[str, str]] = []
        for page in snapshot.wiki_pages:
            relative = _relative(page.relative_ref, "wiki-ref")
            page_hash = _wiki_digest(page)
            if page.sha256 != page_hash:
                _fail("topic-wiki-hash-binding")
            wiki_hashes.append((relative, page_hash))

        if snapshot.source_hashes != tuple(source_hashes):
            _fail("invalid-topic-source-hashes")
        snapshot_payload = {
            "schema_version": 1,
            "spec_version": snapshot.spec_version,
            "manifest_sha256": manifest_hash,
            "sources": source_hashes,
            "final_claims": claim_hashes,
            "wiki_pages": wiki_hashes,
        }
        snapshot_hash = _canonical_digest(snapshot_payload)
        if snapshot.snapshot_sha256 != snapshot_hash:
            _fail("topic-snapshot-hash-binding")

        ref = _topic_ref(name)
        sources = tuple(
            ResearcherArtifactRef(
                f"{ref}/sources/{_relative(record.record_id, 'source-id')}",
                _hash(record.sha256, "source-sha256"),
            )
            for record in snapshot.sources
        )
        claims = tuple(
            ResearcherArtifactRef(
                f"{ref}/claims/{_relative(record.record_id, 'claim-id')}",
                _hash(record.sha256, "claim-sha256"),
            )
            for record in snapshot.final_claims
        )
        wiki = tuple(
            ResearcherArtifactRef(
                f"{ref}/wiki/{_relative(page.relative_ref, 'wiki-ref')}",
                _hash(page.sha256, "wiki-sha256"),
            )
            for page in snapshot.wiki_pages
        )
        for rows in (sources, claims, wiki):
            if tuple(item.logical_ref for item in rows) != tuple(
                sorted(item.logical_ref for item in rows)
            ) or len({item.logical_ref for item in rows}) != len(rows):
                _fail("invalid-topic-snapshot-order")
        payload = {
            "schema_version": 1,
            "topic_ref": ref,
            "topic_manifest": {
                "logical_ref": f"{ref}/topic.json",
                "sha256": manifest_hash,
            },
            "topic_snapshot": {"logical_ref": ref, "sha256": snapshot_hash},
            "sources": [item.__dict__ for item in sources],
            "claims": [item.__dict__ for item in claims],
            "wiki": [item.__dict__ for item in wiki],
        }
        registration_hash = _canonical_digest(payload)
        return ResearcherArtifactRegistration(
            1,
            ref,
            ResearcherArtifactRef(f"{ref}/topic.json", manifest_hash),
            ResearcherArtifactRef(ref, snapshot_hash),
            sources,
            claims,
            wiki,
            registration_hash,
        )
