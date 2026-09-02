"""Exact, bounded integration with the coursedump v1 machine surface.

The connector invokes the configured executable as an argv list, validates its
capability claim before every operation, and converts absolute external paths
into content-addressed logical references. It hashes only the upstream
``manifest.jsonl`` and ``source.json`` metadata files. Raw files and extracted
text remain in the configured coursedump data-home.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
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
from typing import Mapping, Sequence
import unicodedata

from tool_life_os_runtime.ext.connectors.probes import DEFAULT_SPECS


COURSEDUMP_CONNECTOR_SCHEMA_VERSION = 1

_MAX_MACHINE_OUTPUT_BYTES = 64 * 1024
_MAX_EXTERNAL_MANIFEST_BYTES = 16 * 1024 * 1024
_MAX_SOURCE_MANIFEST_BYTES = 256 * 1024
_MAX_SOURCE_BYTES = 8192
_MAX_TITLE_BYTES = 2048
_MAX_RUNS = 512
_MAX_ITEMS = 128
_MAX_ENV = 256
_MAX_JSON_DEPTH = 12
_MAX_JSON_INTEGER = 2**63 - 1
_MAX_MANIFEST_ROWS = 100_000

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[a-z][a-z0-9_-]{0,127}$")
_KIND = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
_ADAPTER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_RUN_ID = re.compile(r"^run_[a-z0-9][a-z0-9_-]{0,62}$")
_ERROR_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$")
_SEMVER = re.compile(r"^(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})$")
_PRIVATE_PATH = re.compile(r"(?i)(?:/users/|/home/|[a-z]:\\users\\|[a-z]:\\home\\)")
_FILE_SCHEME = re.compile(r"(?i)(?:^|[^a-z0-9_])file:")

_ARTIFACT_KEYS = frozenset(
    {
        "schema_version",
        "artifact_id",
        "artifact_ref",
        "artifact_sha256",
        "manifest_id",
        "manifest_ref",
        "manifest_sha256",
        "source_ref",
        "source_manifest_sha256",
        "source_sha256",
        "status",
        "done",
        "total",
        "errors",
    }
)

_COURSEDUMP_SPEC = next(spec for spec in DEFAULT_SPECS if spec.tool == "coursedump")


class CoursedumpConnectorError(ValueError):
    """A configured process, machine response, or external artifact is invalid."""

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
        self.stdout_bytes = stdout_bytes
        self.stderr_bytes = stderr_bytes
        super().__init__(code)


@dataclass(frozen=True)
class CoursedumpPlanItem:
    kind: str
    count: int
    size_bytes: int
    work_items: int


@dataclass(frozen=True)
class CoursedumpEstimate:
    basis: str
    media_items: int
    media_bytes: int
    media_duration_seconds: float | None
    asr_seconds: float | None


@dataclass(frozen=True)
class CoursedumpPlan:
    schema_version: int
    source_sha256: str
    title: str
    adapter: str
    is_local: bool
    items: tuple[CoursedumpPlanItem, ...]
    estimate: CoursedumpEstimate


@dataclass(frozen=True)
class CoursedumpArtifactManifest:
    schema_version: int
    artifact_id: str
    artifact_ref: str
    artifact_sha256: str
    manifest_id: str
    manifest_ref: str
    manifest_sha256: str
    source_ref: str
    source_manifest_sha256: str
    source_sha256: str
    status: str
    done: int
    total: int
    errors: int

    def to_book_source_manifest(self, title: str):
        """Adapt registration metadata to the public BookFlow manifest shape."""

        checked = _artifact_manifest(self)
        checked_title = _portable_text(title, "book title", _MAX_TITLE_BYTES)
        if checked.total < 1:
            _fail("book-source-has-no-chapters")
        from tool_life_os_runtime.ext.flows.book import (
            BOOK_SCHEMA_VERSION,
            BookSourceManifest,
        )

        return BookSourceManifest(
            BOOK_SCHEMA_VERSION,
            checked.manifest_id,
            checked.manifest_ref,
            checked.manifest_sha256,
            checked.source_sha256,
            checked_title,
            checked.total,
        )


@dataclass(frozen=True)
class CoursedumpRun:
    schema_version: int
    status: str
    artifact: CoursedumpArtifactManifest


@dataclass(frozen=True)
class CoursedumpStatus:
    schema_version: int
    artifacts: tuple[CoursedumpArtifactManifest, ...]


@dataclass(frozen=True)
class _ProcessResult:
    returncode: int | None
    stdout: bytes
    stdout_bytes: int
    stderr_bytes: int
    timed_out: bool


def _fail(
    code: str,
    *,
    category: str = "contract",
    returncode: int | None = None,
    stdout_bytes: int = 0,
    stderr_bytes: int = 0,
) -> None:
    raise CoursedumpConnectorError(
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


def _text(value: object, label: str, maximum: int, *, portable: bool) -> str:
    if not isinstance(value, str) or not value:
        _fail(f"invalid-{label}")
    try:
        size = len(value.encode("utf-8"))
    except UnicodeError:
        _fail(f"invalid-{label}")
    if (
        size > maximum
        or value != unicodedata.normalize("NFC", value)
        or _has_control(value)
        or (portable and (_PRIVATE_PATH.search(value) or _FILE_SCHEME.search(value)))
    ):
        _fail(f"invalid-{label}")
    return value


def _portable_text(value: object, label: str, maximum: int) -> str:
    return _text(value, label.replace(" ", "-"), maximum, portable=True)


def _external_text(
    value: object, label: str, maximum: int, *, allow_empty: bool
) -> str:
    if not isinstance(value, str) or (not allow_empty and not value):
        _fail(f"invalid-{label}")
    try:
        size = len(value.encode("utf-8"))
    except UnicodeError:
        _fail(f"invalid-{label}")
    if (
        size > maximum
        or value != unicodedata.normalize("NFC", value)
        or _has_control(value)
    ):
        _fail(f"invalid-{label}")
    return value


def _external_layout_text(value: object, label: str, maximum: int) -> str:
    if not isinstance(value, str) or not value:
        _fail(f"invalid-{label}")
    try:
        size = len(value.encode("utf-8"))
    except UnicodeError:
        _fail(f"invalid-{label}")
    if (
        size > maximum
        or value != unicodedata.normalize("NFC", value)
        or any(
            character not in {"\n", "\t"}
            and (
                unicodedata.category(character).startswith("C")
                or unicodedata.category(character) in {"Zl", "Zp"}
            )
            for character in value
        )
    ):
        _fail(f"invalid-{label}")
    return value


def _identifier(value: object, label: str) -> str:
    checked = _portable_text(value, label, 128)
    if _IDENTIFIER.fullmatch(checked) is None:
        _fail(f"invalid-{label}")
    return checked


def _hash(value: object, label: str) -> str:
    checked = _portable_text(value, label, 64)
    if _SHA256.fullmatch(checked) is None:
        _fail(f"invalid-{label}")
    return checked


def _integer(value: object, label: str, *, maximum: int = 2**63 - 1) -> int:
    if type(value) is not int or value < 0 or value > maximum:
        _fail(f"invalid-{label}")
    return value


def _number(value: object, label: str) -> float | None:
    if value is None:
        return None
    if type(value) not in {int, float}:
        _fail(f"invalid-{label}")
    number = float(value)
    if not math.isfinite(number) or number < 0:
        _fail(f"invalid-{label}")
    return number


def _canonical(value: object) -> bytes:
    try:
        return (
            json.dumps(
                value,
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
            + b"\n"
        )
    except (TypeError, ValueError, UnicodeError, RecursionError):
        _fail("noncanonical-connector-data")


def _no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            _fail("duplicate-machine-field")
        result[key] = value
    return result


def _json_safe(value: object, *, depth: int = 0) -> bool:
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
            return len(value.encode("utf-8")) <= _MAX_MACHINE_OUTPUT_BYTES
        except UnicodeError:
            return False
    if isinstance(value, list):
        return len(value) <= 4096 and all(
            _json_safe(item, depth=depth + 1) for item in value
        )
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
            if not _json_safe(item, depth=depth + 1):
                return False
        return True
    return False


def _decode(raw: bytes) -> dict[str, object]:
    if not raw or len(raw) > _MAX_MACHINE_OUTPUT_BYTES:
        _fail("machine-output-size")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicates)
    except CoursedumpConnectorError:
        raise
    except (UnicodeError, ValueError, RecursionError):
        _fail("malformed-machine-output")
    if not isinstance(value, dict) or not _json_safe(value) or raw != _canonical(value):
        _fail("noncanonical-machine-output")
    return value


def _exact(
    value: object, keys: set[str] | frozenset[str], label: str
) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != set(keys):
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


def _source_digest(source: str) -> str:
    return hashlib.sha256(source.encode("utf-8")).hexdigest()


def _ingest_source_digest(classification: str, canonical_source: str) -> str:
    return hashlib.sha256(
        b"lifeos-ingest-source-v1\0"
        + classification.encode("ascii")
        + b"\0"
        + canonical_source.encode("utf-8")
    ).hexdigest()


def _artifact_payload(value: CoursedumpArtifactManifest) -> dict[str, object]:
    checked = _artifact_manifest(value)
    return {
        "schema_version": checked.schema_version,
        "artifact_id": checked.artifact_id,
        "artifact_ref": checked.artifact_ref,
        "artifact_sha256": checked.artifact_sha256,
        "manifest_id": checked.manifest_id,
        "manifest_ref": checked.manifest_ref,
        "manifest_sha256": checked.manifest_sha256,
        "source_ref": checked.source_ref,
        "source_manifest_sha256": checked.source_manifest_sha256,
        "source_sha256": checked.source_sha256,
        "status": checked.status,
        "done": checked.done,
        "total": checked.total,
        "errors": checked.errors,
    }


def _artifact_manifest(value: object) -> CoursedumpArtifactManifest:
    if (
        not isinstance(value, CoursedumpArtifactManifest)
        or type(value.schema_version) is not int
        or value.schema_version != COURSEDUMP_CONNECTOR_SCHEMA_VERSION
    ):
        _fail("invalid-artifact-manifest")
    artifact_id = _identifier(value.artifact_id, "artifact-id")
    manifest_id = _identifier(value.manifest_id, "manifest-id")
    artifact_ref = _logical_ref(value.artifact_ref, "artifact-ref")
    manifest_ref = _logical_ref(value.manifest_ref, "manifest-ref")
    source_ref = _logical_ref(value.source_ref, "source-ref")
    if (
        artifact_ref != f"coursedump/artifacts/{artifact_id}"
        or manifest_ref != f"{artifact_ref}/manifest.jsonl"
        or source_ref != f"{artifact_ref}/source.json"
        or manifest_id != f"source_{artifact_id.removeprefix('artifact_')}"
    ):
        _fail("artifact-reference-binding")
    status = _portable_text(value.status, "artifact-status", 32)
    if status not in {"succeeded", "completed-with-errors", "observed"}:
        _fail("invalid-artifact-status")
    done = _integer(value.done, "artifact-done")
    total = _integer(value.total, "artifact-total")
    errors = _integer(value.errors, "artifact-errors")
    if done > total:
        _fail("invalid-artifact-counts")
    checked = CoursedumpArtifactManifest(
        COURSEDUMP_CONNECTOR_SCHEMA_VERSION,
        artifact_id,
        artifact_ref,
        _hash(value.artifact_sha256, "artifact-sha256"),
        manifest_id,
        manifest_ref,
        _hash(value.manifest_sha256, "manifest-sha256"),
        source_ref,
        _hash(value.source_manifest_sha256, "source-manifest-sha256"),
        _hash(value.source_sha256, "source-sha256"),
        status,
        done,
        total,
        errors,
    )
    binding = {
        key: item
        for key, item in _artifact_payload_unchecked(checked).items()
        if key != "artifact_sha256"
    }
    if hashlib.sha256(_canonical(binding)).hexdigest() != checked.artifact_sha256:
        _fail("artifact-hash-binding")
    return checked


def _artifact_payload_unchecked(value: CoursedumpArtifactManifest) -> dict[str, object]:
    return {
        "schema_version": value.schema_version,
        "artifact_id": value.artifact_id,
        "artifact_ref": value.artifact_ref,
        "artifact_sha256": value.artifact_sha256,
        "manifest_id": value.manifest_id,
        "manifest_ref": value.manifest_ref,
        "manifest_sha256": value.manifest_sha256,
        "source_ref": value.source_ref,
        "source_manifest_sha256": value.source_manifest_sha256,
        "source_sha256": value.source_sha256,
        "status": value.status,
        "done": value.done,
        "total": value.total,
        "errors": value.errors,
    }


def render_artifact_manifest(value: CoursedumpArtifactManifest) -> bytes:
    return _canonical(_artifact_payload(value))


def parse_artifact_manifest(raw: str | bytes) -> CoursedumpArtifactManifest:
    if isinstance(raw, str):
        try:
            data = raw.encode("utf-8")
        except UnicodeError:
            _fail("invalid-artifact-manifest")
    elif isinstance(raw, bytes):
        data = raw
    else:
        _fail("invalid-artifact-manifest")
    payload = _decode(data)
    item = _exact(payload, _ARTIFACT_KEYS, "artifact-manifest")
    value = _artifact_manifest(
        CoursedumpArtifactManifest(
            item["schema_version"],
            item["artifact_id"],
            item["artifact_ref"],
            item["artifact_sha256"],
            item["manifest_id"],
            item["manifest_ref"],
            item["manifest_sha256"],
            item["source_ref"],
            item["source_manifest_sha256"],
            item["source_sha256"],
            item["status"],
            item["done"],
            item["total"],
            item["errors"],
        )
    )
    if data != render_artifact_manifest(value):
        _fail("noncanonical-artifact-manifest")
    return value


def _logical_ref(value: object, label: str) -> str:
    checked = _portable_text(value, label, 2048)
    if "\\" in checked:
        _fail(f"invalid-{label}")
    path = PurePosixPath(checked)
    if (
        path.is_absolute()
        or path.as_posix() != checked
        or ".." in path.parts
        or not path.parts
        or len(path.parts) > 12
        or any(
            part in {"", "."} or len(part.encode("utf-8")) > 255 for part in path.parts
        )
    ):
        _fail(f"invalid-{label}")
    return checked


def _paths_overlap(left: Path, right: Path) -> bool:
    return left == right or left in right.parents or right in left.parents


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
    stdout_data = bytearray()
    sizes = {"stdout": 0, "stderr": 0}
    timed_out = False
    completed = False
    try:
        if process.stdout is None or process.stderr is None:  # pragma: no cover
            _fail("connector-pipes-unavailable", category="transient")
        selector = selectors.DefaultSelector()
        for label, stream in (("stdout", process.stdout), ("stderr", process.stderr)):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, label)
        while selector.get_map():
            remaining = _remaining(deadline)
            if remaining <= 0:
                timed_out = True
                _kill_group(process)
                break
            events = selector.select(remaining)
            if not events:
                timed_out = True
                _kill_group(process)
                break
            for key, _mask in events:
                stream = key.fileobj
                label = key.data
                while True:
                    if _remaining(deadline) <= 0:
                        timed_out = True
                        _kill_group(process)
                        break
                    try:
                        chunk = os.read(stream.fileno(), 8192)
                    except BlockingIOError:
                        break
                    if not chunk:
                        selector.unregister(stream)
                        break
                    sizes[label] = min(limit + 1, sizes[label] + len(chunk))
                    if label == "stdout":
                        room = limit + 1 - len(stdout_data)
                        if room > 0:
                            stdout_data.extend(chunk[:room])
                if timed_out:
                    break
            if timed_out:
                break
        if not timed_out:
            remaining = _remaining(deadline)
            if remaining <= 0:
                timed_out = True
                _kill_group(process)
            else:
                try:
                    process.wait(timeout=remaining)
                except subprocess.TimeoutExpired:
                    timed_out = True
                    _kill_group(process)
        completed = not timed_out
    except CoursedumpConnectorError:
        raise
    except Exception:
        _fail("connector-process-io", category="transient")
    finally:
        if not completed and process.poll() is None:
            _kill_group(process)
        if process.poll() is None:
            try:
                process.wait(timeout=_remaining(deadline))
            except subprocess.TimeoutExpired:
                _kill_group(process)
        if process.poll() is None:
            try:
                process.wait()
            except (OSError, subprocess.SubprocessError):
                pass
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
        bytes(stdout_data),
        sizes["stdout"],
        sizes["stderr"],
        timed_out,
    )


def _semver(value: object) -> tuple[int, int, int]:
    if not isinstance(value, str) or (match := _SEMVER.fullmatch(value)) is None:
        _fail("invalid-tool-version")
    return tuple(int(match.group(index)) for index in (1, 2, 3))


class CoursedumpConnector:
    """Configured v1 plan/run/status adapter and IngestConnectorPort."""

    def __init__(
        self,
        *,
        data_home: str | os.PathLike[str],
        command: Sequence[str],
        cwd: str | os.PathLike[str],
        env: Mapping[str, str],
        forbidden_roots: Sequence[str | os.PathLike[str]] = (),
        timeout: float = 30.0,
        max_output_bytes: int = _MAX_MACHINE_OUTPUT_BYTES,
    ) -> None:
        self._command = self._validate_command(command)
        self._cwd = self._absolute_directory(cwd, "connector-cwd")
        self._cwd_identity = self._directory_identity(self._cwd)
        self._data_home = self._absolute_path(data_home, "data-home")
        self._data_parent = self._absolute_directory(
            self._data_home.parent, "data-home-parent"
        )
        self._data_parent_identity = self._directory_identity(self._data_parent)
        try:
            self._data_identity: tuple[int, int] | None = self._path_directory_identity(
                self._data_home
            )
        except FileNotFoundError:
            self._data_identity = None
        except OSError:
            _fail("invalid-data-home")
        roots = tuple(
            self._absolute_path(item, "forbidden-root") for item in forbidden_roots
        )
        if any(_paths_overlap(self._data_home, item) for item in roots):
            _fail("data-home-overlaps-forbidden-root")
        if not isinstance(env, Mapping) or not 0 < len(env) <= _MAX_ENV:
            _fail("invalid-environment")
        checked_env: dict[str, str] = {}
        for key, value in env.items():
            if (
                not isinstance(key, str)
                or not key
                or len(key.encode("utf-8")) > 256
                or "=" in key
                or "\x00" in key
                or not isinstance(value, str)
                or len(value.encode("utf-8")) > 32 * 1024
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
            or not 1024 <= max_output_bytes <= _MAX_MACHINE_OUTPUT_BYTES
        ):
            _fail("invalid-output-limit")
        self._env = checked_env
        self._timeout = float(timeout)
        self._max_output_bytes = max_output_bytes

    @staticmethod
    def _absolute_path(value: str | os.PathLike[str], label: str) -> Path:
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
            return path.resolve(strict=False)
        except OSError:
            _fail(f"invalid-{label}")

    @classmethod
    def _absolute_directory(cls, value: str | os.PathLike[str], label: str) -> Path:
        path = cls._absolute_path(value, label)
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
            _fail("connector-cwd-moved")
        return metadata.st_dev, metadata.st_ino

    @staticmethod
    def _validate_command(command: Sequence[str]) -> tuple[str, ...]:
        if type(command) not in {tuple, list} or not 0 < len(command) <= 16:
            _fail("invalid-command")
        checked: list[str] = []
        for item in command:
            checked.append(_text(item, "command", 4096, portable=False))
        return tuple(checked)

    def _revalidate_cwd(self) -> None:
        try:
            current = self._directory_identity(self._cwd)
        except (OSError, CoursedumpConnectorError):
            _fail("connector-cwd-moved")
        if current != self._cwd_identity:
            _fail("connector-cwd-moved")

    def _revalidate_data_home(self, *, allow_create: bool) -> tuple[int, int] | None:
        try:
            if (
                self._directory_identity(self._data_parent)
                != self._data_parent_identity
            ):
                _fail("data-home-parent-moved")
            current = self._path_directory_identity(self._data_home)
        except FileNotFoundError:
            if self._data_identity is not None:
                _fail("data-home-moved")
            return None
        except CoursedumpConnectorError:
            _fail("data-home-moved")
        except OSError:
            _fail("data-home-moved")
        if self._data_identity is None:
            if not allow_create:
                _fail("data-home-appeared-outside-run")
            self._data_identity = current
        elif current != self._data_identity:
            _fail("data-home-moved")
        return current

    def _execute(self, suffix: Sequence[str], deadline: float) -> _ProcessResult:
        self._revalidate_cwd()
        result = _run_process(
            (*self._command, *suffix),
            cwd=self._cwd,
            env=self._env,
            deadline=deadline,
            limit=self._max_output_bytes,
        )
        self._revalidate_cwd()
        if result.timed_out:
            _fail(
                "connector-timeout",
                category="transient",
                returncode=result.returncode,
                stdout_bytes=result.stdout_bytes,
                stderr_bytes=result.stderr_bytes,
            )
        return result

    @staticmethod
    def _map_nonzero(result: _ProcessResult, operation: str) -> None:
        if result.returncode == 75:
            _fail(
                "coursedump-quota",
                category="quota",
                returncode=75,
                stdout_bytes=result.stdout_bytes,
                stderr_bytes=result.stderr_bytes,
            )
        if result.returncode == 111 or result.returncode not in {0, 1, 75, 111}:
            _fail(
                "coursedump-transient",
                category="transient",
                returncode=result.returncode,
                stdout_bytes=result.stdout_bytes,
                stderr_bytes=result.stderr_bytes,
            )
        if result.returncode != 1:
            return
        if (
            result.stdout_bytes > _MAX_MACHINE_OUTPUT_BYTES
            or result.stderr_bytes > _MAX_MACHINE_OUTPUT_BYTES
        ):
            _fail(
                "machine-output-size",
                returncode=1,
                stdout_bytes=result.stdout_bytes,
                stderr_bytes=result.stderr_bytes,
            )
        try:
            payload = _decode(result.stdout)
        except CoursedumpConnectorError:
            _fail(
                "invalid-failure-envelope",
                returncode=1,
                stdout_bytes=result.stdout_bytes,
                stderr_bytes=result.stderr_bytes,
            )
        required = {
            "plan": {
                "schema_version",
                "source",
                "items",
                "estimate",
                "status",
                "error",
            },
            "run": {"schema_version", "status", "artifact", "error"},
            "status": {"schema_version", "runs", "status", "error"},
        }[operation]
        if (
            set(payload) != required
            or type(payload.get("schema_version")) is not int
            or payload["schema_version"] != 1
            or payload.get("status") != "failure"
            or not isinstance(payload.get("error"), str)
            or _KIND.fullmatch(str(payload["error"])) is None
        ):
            _fail("invalid-failure-envelope", returncode=1)
        _fail(
            f"coursedump-{operation}-failed",
            category="fatal",
            returncode=1,
            stdout_bytes=result.stdout_bytes,
            stderr_bytes=result.stderr_bytes,
        )

    def _handshake(self, deadline: float) -> None:
        result = self._execute(("capabilities", "--json"), deadline)
        if result.returncode != 0:
            if result.returncode in {75, 111}:
                self._map_nonzero(result, "status")
            if result.returncode not in {0, 1, 75, 111}:
                _fail(
                    "coursedump-transient",
                    category="transient",
                    returncode=result.returncode,
                    stdout_bytes=result.stdout_bytes,
                    stderr_bytes=result.stderr_bytes,
                )
            _fail(
                "capability-handshake-failed",
                returncode=result.returncode,
                stdout_bytes=result.stdout_bytes,
                stderr_bytes=result.stderr_bytes,
            )
        if (
            result.stdout_bytes > self._max_output_bytes
            or result.stderr_bytes > self._max_output_bytes
        ):
            _fail("capability-output-size")
        payload = _decode(result.stdout)
        if set(payload) != {"schema_version", "tool", "version", "capabilities"}:
            _fail("capability-contract-mismatch")
        version = _semver(payload["version"])
        expected = [item.to_dict() for item in _COURSEDUMP_SPEC.expected_capabilities]
        if (
            type(payload["schema_version"]) is not int
            or payload["schema_version"] != 1
            or payload["tool"] != "coursedump"
            or not _COURSEDUMP_SPEC.minimum_version
            <= version
            < _COURSEDUMP_SPEC.maximum_version_exclusive
            or not _strict_equal(payload["capabilities"], expected)
        ):
            _fail("capability-contract-mismatch")

    def _operation(
        self, operation: str, suffix: Sequence[str], deadline: float
    ) -> dict[str, object]:
        self._revalidate_data_home(allow_create=False)
        try:
            self._handshake(deadline)
        except BaseException:
            self._revalidate_data_home(allow_create=False)
            raise
        self._revalidate_data_home(allow_create=False)
        try:
            result = self._execute(suffix, deadline)
        except BaseException:
            self._revalidate_data_home(allow_create=operation == "run")
            raise
        self._revalidate_data_home(allow_create=operation == "run")
        if result.returncode != 0:
            self._map_nonzero(result, operation)
        if (
            result.stdout_bytes > self._max_output_bytes
            or result.stderr_bytes > self._max_output_bytes
        ):
            _fail(
                "machine-output-size",
                returncode=0,
                stdout_bytes=result.stdout_bytes,
                stderr_bytes=result.stderr_bytes,
            )
        return _decode(result.stdout)

    @staticmethod
    def _source(value: object) -> str:
        return _text(value, "source", _MAX_SOURCE_BYTES, portable=False)

    def plan(self, source: str) -> CoursedumpPlan:
        return self._plan(source, time.monotonic() + self._timeout)

    def _plan(self, source: str, deadline: float) -> CoursedumpPlan:
        checked_source = self._source(source)
        payload = self._operation(
            "plan",
            ("plan", checked_source, "--data", str(self._data_home), "--json"),
            deadline,
        )
        item = _exact(
            payload, {"schema_version", "source", "items", "estimate"}, "plan"
        )
        if type(item["schema_version"]) is not int or item["schema_version"] != 1:
            _fail("unsupported-plan-schema")
        source_model = _exact(
            item["source"], {"input", "title", "adapter", "is_local"}, "plan-source"
        )
        if (
            source_model["input"] != checked_source
            or type(source_model["is_local"]) is not bool
        ):
            _fail("plan-source-binding")
        title = _portable_text(source_model["title"], "plan-title", _MAX_TITLE_BYTES)
        adapter = _portable_text(source_model["adapter"], "plan-adapter", 128)
        if _ADAPTER.fullmatch(adapter) is None:
            _fail("invalid-plan-adapter")
        raw_items = item["items"]
        if not isinstance(raw_items, list) or len(raw_items) > _MAX_ITEMS:
            _fail("invalid-plan-items")
        groups: list[CoursedumpPlanItem] = []
        for raw in raw_items:
            group = _exact(
                raw, {"kind", "count", "size_bytes", "work_items"}, "plan-item"
            )
            kind = _identifier(group["kind"], "plan-kind")
            count = _integer(group["count"], "plan-count")
            size_bytes = _integer(group["size_bytes"], "plan-size")
            work_items = _integer(group["work_items"], "plan-work-items")
            if work_items > count:
                _fail("invalid-plan-work-items")
            groups.append(CoursedumpPlanItem(kind, count, size_bytes, work_items))
        if len({group.kind for group in groups}) != len(groups) or tuple(
            groups
        ) != tuple(sorted(groups, key=lambda value: value.kind)):
            _fail("plan-items-not-canonical")
        estimate_model = _exact(
            item["estimate"],
            {
                "basis",
                "media_items",
                "media_bytes",
                "media_duration_seconds",
                "asr_seconds",
            },
            "plan-estimate",
        )
        basis = _identifier(estimate_model["basis"], "estimate-basis")
        if basis not in {"none", "duration", "size"}:
            _fail("invalid-estimate-basis")
        estimate = CoursedumpEstimate(
            basis,
            _integer(estimate_model["media_items"], "estimate-media-items"),
            _integer(estimate_model["media_bytes"], "estimate-media-bytes"),
            _number(estimate_model["media_duration_seconds"], "estimate-duration"),
            _number(estimate_model["asr_seconds"], "estimate-asr"),
        )
        if (estimate.media_duration_seconds is None) != (estimate.asr_seconds is None):
            _fail("invalid-estimate-pair")
        return CoursedumpPlan(
            COURSEDUMP_CONNECTOR_SCHEMA_VERSION,
            _source_digest(checked_source),
            title,
            adapter,
            source_model["is_local"],
            tuple(groups),
            estimate,
        )

    def run(self, source: str) -> CoursedumpRun:
        return self._run(source, time.monotonic() + self._timeout)

    def _run(self, source: str, deadline: float) -> CoursedumpRun:
        checked_source = self._source(source)
        payload = self._operation(
            "run",
            ("run", checked_source, "--data", str(self._data_home), "--json"),
            deadline,
        )
        item = _exact(payload, {"schema_version", "status", "artifact"}, "run")
        if type(item["schema_version"]) is not int or item["schema_version"] != 1:
            _fail("unsupported-run-schema")
        status_name = _identifier(item["status"], "run-status")
        if status_name not in {"succeeded", "completed-with-errors"}:
            _fail("invalid-run-status")
        artifact = _exact(
            item["artifact"],
            {"source", "course_dir", "done", "total", "errors"},
            "run-artifact",
        )
        if artifact["source"] != checked_source:
            _fail("run-source-binding")
        done = _integer(artifact["done"], "run-done")
        total = _integer(artifact["total"], "run-total")
        errors = _integer(artifact["errors"], "run-errors")
        if done > total or (status_name == "succeeded" and errors != 0):
            _fail("invalid-run-counts")
        registered = self._register(
            artifact["course_dir"],
            checked_source,
            status_name,
            done,
            total,
            errors,
        )
        return CoursedumpRun(
            COURSEDUMP_CONNECTOR_SCHEMA_VERSION, status_name, registered
        )

    def status(self) -> CoursedumpStatus:
        return self._status(time.monotonic() + self._timeout)

    def _status(self, deadline: float) -> CoursedumpStatus:
        payload = self._operation(
            "status",
            ("status", "--data", str(self._data_home), "--json"),
            deadline,
        )
        item = _exact(payload, {"schema_version", "runs"}, "status")
        if type(item["schema_version"]) is not int or item["schema_version"] != 1:
            _fail("unsupported-status-schema")
        raw_runs = item["runs"]
        if not isinstance(raw_runs, list) or len(raw_runs) > _MAX_RUNS:
            _fail("invalid-status-runs")
        artifacts: list[CoursedumpArtifactManifest] = []
        for raw in raw_runs:
            row = _exact(
                raw,
                {"course", "source", "artifact", "done", "total", "errors"},
                "status-row",
            )
            source = self._source(row["source"])
            course = _text(row["course"], "status-course", 255, portable=False)
            supplied_path = self._external_course_path(row["artifact"])
            if supplied_path.name != course:
                _fail("status-artifact-binding")
            artifacts.append(
                self._register(
                    str(supplied_path),
                    source,
                    "observed",
                    _integer(row["done"], "status-done"),
                    _integer(row["total"], "status-total"),
                    _integer(row["errors"], "status-errors"),
                )
            )
        if len({item.artifact_id for item in artifacts}) != len(artifacts):
            _fail("duplicate-status-artifact")
        return CoursedumpStatus(
            COURSEDUMP_CONNECTOR_SCHEMA_VERSION,
            tuple(sorted(artifacts, key=lambda value: value.artifact_id)),
        )

    def collect(self, request):
        """Implement the narrow public IngestConnectorPort without raw copying."""

        from tool_life_os_runtime.ext.flows.ingest import (
            INGEST_CONNECTOR_SCHEMA_VERSION,
            IngestConnectorRequest,
            IngestConnectorResult,
        )

        if (
            not isinstance(request, IngestConnectorRequest)
            or type(request.schema_version) is not int
            or request.schema_version != INGEST_CONNECTOR_SCHEMA_VERSION
            or request.connector != "coursedump"
            or request.classification not in {"video", "book", "course"}
            or not isinstance(request.run_id, str)
            or _RUN_ID.fullmatch(request.run_id) is None
            or type(request.max_content_bytes) is not int
            or not 1 <= request.max_content_bytes <= 4 * 1024 * 1024
        ):
            _fail("invalid-ingest-request")
        source = self._source(request.canonical_source)
        request_hash = _hash(request.canonical_source_sha256, "ingest-source-sha256")
        if request_hash != _ingest_source_digest(request.classification, source):
            _fail("ingest-source-hash-binding")
        deadline = time.monotonic() + self._timeout
        plan = self._plan(source, deadline)
        completed = self._run(source, deadline)
        artifact = completed.artifact
        content = self._ingest_note(plan.title, artifact)
        raw = content.encode("utf-8")
        if len(raw) > request.max_content_bytes:
            _fail("ingest-content-limit")
        return IngestConnectorResult(
            INGEST_CONNECTOR_SCHEMA_VERSION,
            "coursedump",
            artifact.manifest_ref,
            request_hash,
            artifact.manifest_sha256,
            hashlib.sha256(raw).hexdigest(),
            content,
        )

    @staticmethod
    def _ingest_note(title: str, artifact: CoursedumpArtifactManifest) -> str:
        return (
            "---\n"
            "tags:\n"
            "  - ingest\n"
            "  - coursedump\n"
            "---\n\n"
            f"# {title}\n\n"
            "Coursedump registered an external text artifact. Raw source and "
            "extracted files remain in its configured data-home.\n\n"
            f"- Manifest ref: `{artifact.manifest_ref}`\n"
            f"- Manifest sha256: `{artifact.manifest_sha256}`\n"
            f"- Source sha256: `{artifact.source_sha256}`\n"
            f"- Extraction: {artifact.done}/{artifact.total}; errors: {artifact.errors}\n"
        )

    def _external_course_path(self, value: object) -> Path:
        raw = _text(value, "artifact-path", 4096, portable=False)
        path = Path(raw)
        expected_parent = self._data_home / "out"
        if (
            not path.is_absolute()
            or ".." in path.parts
            or path.parent != expected_parent
            or not path.name
        ):
            _fail("artifact-outside-data-home")
        return path

    def _register(
        self,
        course_dir: object,
        source: str,
        status_name: str,
        done: int,
        total: int,
        errors: int,
    ) -> CoursedumpArtifactManifest:
        path = self._external_course_path(course_dir)
        if done > total:
            _fail("invalid-artifact-counts")
        pinned_data_identity = self._revalidate_data_home(allow_create=False)
        if pinned_data_identity is None:
            _fail("external-data-home-is-absent")
        flags = (
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        data_fd = -1
        out_fd = -1
        course_fd = -1
        try:
            data_fd = os.open(self._data_home, flags)
            data_identity = self._fd_directory_identity(data_fd)
            if (
                data_identity != pinned_data_identity
                or self._path_directory_identity(self._data_home) != data_identity
            ):
                _fail("external-data-home-moved")
            out_fd = os.open("out", flags, dir_fd=data_fd)
            out_identity = self._fd_directory_identity(out_fd)
            named_out = self._entry_directory_identity(data_fd, "out")
            if out_identity != named_out:
                _fail("external-artifact-root-moved")
            course_fd = os.open(path.name, flags, dir_fd=out_fd)
            course_identity = self._fd_directory_identity(course_fd)
            named_course = self._entry_directory_identity(out_fd, path.name)
            if course_identity != named_course:
                _fail("external-artifact-moved")
            manifest_hash, manifest_raw = self._hash_file(
                course_fd,
                "manifest.jsonl",
                _MAX_EXTERNAL_MANIFEST_BYTES,
                retain=True,
            )
            source_manifest_hash, source_raw = self._hash_file(
                course_fd,
                "source.json",
                _MAX_SOURCE_MANIFEST_BYTES,
                retain=True,
            )
            source_payload = self._decode_source_manifest(source_raw)
            if source_payload.get("source") != source:
                _fail("source-manifest-binding")
            self._validate_external_manifest(
                course_fd,
                manifest_raw,
                status_name=status_name,
                done=done,
                total=total,
                errors=errors,
            )
            if (
                self._fd_directory_identity(data_fd) != data_identity
                or self._path_directory_identity(self._data_home) != data_identity
                or self._fd_directory_identity(out_fd) != out_identity
                or self._entry_directory_identity(data_fd, "out") != out_identity
                or self._fd_directory_identity(course_fd) != course_identity
                or self._entry_directory_identity(out_fd, path.name) != course_identity
                or self._revalidate_data_home(allow_create=False) != data_identity
            ):
                _fail("external-artifact-moved")
        except OSError:
            _fail("unsafe-external-artifact")
        finally:
            if course_fd >= 0:
                os.close(course_fd)
            if out_fd >= 0:
                os.close(out_fd)
            if data_fd >= 0:
                os.close(data_fd)
        source_hash = _source_digest(source)
        token = hashlib.sha256(
            _canonical(
                {
                    "manifest_sha256": manifest_hash,
                    "source_manifest_sha256": source_manifest_hash,
                    "source_sha256": source_hash,
                }
            )
        ).hexdigest()[:40]
        artifact_id = f"artifact_{token}"
        artifact_ref = f"coursedump/artifacts/{artifact_id}"
        candidate = CoursedumpArtifactManifest(
            COURSEDUMP_CONNECTOR_SCHEMA_VERSION,
            artifact_id,
            artifact_ref,
            "0" * 64,
            f"source_{token}",
            f"{artifact_ref}/manifest.jsonl",
            manifest_hash,
            f"{artifact_ref}/source.json",
            source_manifest_hash,
            source_hash,
            status_name,
            done,
            total,
            errors,
        )
        binding = {
            key: value
            for key, value in _artifact_payload_unchecked(candidate).items()
            if key != "artifact_sha256"
        }
        return _artifact_manifest(
            CoursedumpArtifactManifest(
                candidate.schema_version,
                candidate.artifact_id,
                candidate.artifact_ref,
                hashlib.sha256(_canonical(binding)).hexdigest(),
                candidate.manifest_id,
                candidate.manifest_ref,
                candidate.manifest_sha256,
                candidate.source_ref,
                candidate.source_manifest_sha256,
                candidate.source_sha256,
                candidate.status,
                candidate.done,
                candidate.total,
                candidate.errors,
            )
        )

    @staticmethod
    def _fd_directory_identity(fd: int) -> tuple[int, int]:
        metadata = os.fstat(fd)
        if not stat.S_ISDIR(metadata.st_mode):
            _fail("unsafe-external-artifact")
        return metadata.st_dev, metadata.st_ino

    @staticmethod
    def _path_directory_identity(path: Path) -> tuple[int, int]:
        metadata = os.stat(path, follow_symlinks=False)
        if not stat.S_ISDIR(metadata.st_mode):
            _fail("unsafe-external-artifact")
        return metadata.st_dev, metadata.st_ino

    @staticmethod
    def _entry_directory_identity(parent_fd: int, name: str) -> tuple[int, int]:
        metadata = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if not stat.S_ISDIR(metadata.st_mode):
            _fail("unsafe-external-artifact")
        return metadata.st_dev, metadata.st_ino

    @staticmethod
    def _hash_file(
        directory_fd: int,
        name: str,
        maximum: int,
        *,
        retain: bool,
    ) -> tuple[str, bytes]:
        try:
            fd = os.open(
                name,
                os.O_RDONLY
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
                dir_fd=directory_fd,
            )
        except OSError:
            _fail("unsafe-external-artifact-file")
        captured = bytearray()
        digest = hashlib.sha256()
        size = 0
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
                _fail("external-artifact-file-size")
            while chunk := os.read(fd, 64 * 1024):
                size += len(chunk)
                if size > maximum:
                    _fail("external-artifact-file-size")
                digest.update(chunk)
                if retain:
                    captured.extend(chunk)
            after = os.fstat(fd)
            named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            observed = (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            )
            final = (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            )
            named_final = (
                named.st_dev,
                named.st_ino,
                named.st_size,
                named.st_mtime_ns,
                named.st_ctime_ns,
            )
            if (
                observed != final
                or final != named_final
                or not stat.S_ISREG(named.st_mode)
            ):
                _fail("external-artifact-file-moved")
            return digest.hexdigest(), bytes(captured)
        finally:
            os.close(fd)

    @staticmethod
    def _manifest_target(value: object) -> str:
        target = _external_text(value, "manifest-target", 4096, allow_empty=True)
        if not target:
            return target
        if "\\" in target:
            _fail("invalid-manifest-target")
        path = PurePosixPath(target)
        if (
            path.is_absolute()
            or path.as_posix() != target
            or ".." in path.parts
            or not path.parts
            or len(path.parts) > 32
            or path.suffix != ".md"
            or any(part in {"", "."} for part in path.parts)
        ):
            _fail("invalid-manifest-target")
        return target

    @staticmethod
    def _target_exists(course_fd: int, target: str) -> bool:
        flags = (
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        owned: list[int] = []
        try:
            try:
                current = os.open("text", flags, dir_fd=course_fd)
            except FileNotFoundError:
                return False
            owned.append(current)
            parts = PurePosixPath(target).parts
            for part in parts[:-1]:
                try:
                    current = os.open(part, flags, dir_fd=current)
                except FileNotFoundError:
                    return False
                owned.append(current)
            try:
                item = os.stat(parts[-1], dir_fd=current, follow_symlinks=False)
            except FileNotFoundError:
                return False
            if not stat.S_ISREG(item.st_mode):
                _fail("manifest target is not a regular external file")
            return True
        except OSError:
            _fail("manifest target path is unsafe")
        finally:
            for fd in reversed(owned):
                os.close(fd)

    @staticmethod
    def _error_row_count(course_fd: int, manifest_rels: set[str]) -> int:
        try:
            fd = os.open(
                "errors.jsonl",
                os.O_RDONLY
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
                dir_fd=course_fd,
            )
        except FileNotFoundError:
            return 0
        except OSError:
            _fail("external errors log is unsafe")
        try:
            before = os.fstat(fd)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_size > _MAX_EXTERNAL_MANIFEST_BYTES
            ):
                _fail("external errors log is invalid")
            remaining = _MAX_EXTERNAL_MANIFEST_BYTES + 1
            chunks: list[bytes] = []
            while remaining:
                chunk = os.read(fd, min(64 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            if len(raw) > _MAX_EXTERNAL_MANIFEST_BYTES:
                _fail("external errors log is invalid")
            after = os.fstat(fd)
            named = os.stat("errors.jsonl", dir_fd=course_fd, follow_symlinks=False)
            if (
                (
                    before.st_dev,
                    before.st_ino,
                    before.st_size,
                    before.st_mtime_ns,
                    before.st_ctime_ns,
                )
                != (
                    after.st_dev,
                    after.st_ino,
                    after.st_size,
                    after.st_mtime_ns,
                    after.st_ctime_ns,
                )
                or (
                    after.st_dev,
                    after.st_ino,
                    after.st_size,
                    after.st_mtime_ns,
                    after.st_ctime_ns,
                )
                != (
                    named.st_dev,
                    named.st_ino,
                    named.st_size,
                    named.st_mtime_ns,
                    named.st_ctime_ns,
                )
                or not stat.S_ISREG(named.st_mode)
            ):
                _fail("external errors log changed during read")
            if not raw:
                return 0
            if not raw.endswith(b"\n"):
                _fail("external errors log is partial")
            try:
                lines = raw.decode("utf-8").splitlines()
            except UnicodeError:
                _fail("external errors log is not UTF-8")
            if (
                not lines
                or len(lines) > _MAX_MANIFEST_ROWS
                or any(not line for line in lines)
            ):
                _fail("external errors log row count is invalid")
            for line in lines:
                try:
                    row = json.loads(line, object_pairs_hook=_no_duplicates)
                except CoursedumpConnectorError:
                    raise
                except (UnicodeError, ValueError, RecursionError):
                    _fail("external errors log row is malformed")
                item = _exact(
                    row, {"ts", "rel", "error", "trace"}, "external-error-row"
                )
                timestamp = _external_text(
                    item["ts"], "error-timestamp", 32, allow_empty=False
                )
                if _ERROR_TIMESTAMP.fullmatch(timestamp) is None:
                    _fail("external error timestamp is invalid")
                try:
                    datetime.fromisoformat(timestamp)
                except ValueError:
                    _fail("external error timestamp is invalid")
                rel = _external_text(item["rel"], "error-rel", 4096, allow_empty=False)
                error = _external_layout_text(item["error"], "error-message", 16 * 1024)
                trace = _external_layout_text(item["trace"], "error-trace", 128 * 1024)
                checked_row = {
                    "ts": timestamp,
                    "rel": rel,
                    "error": error,
                    "trace": trace,
                }
                if rel not in manifest_rels:
                    _fail("external error row is not bound to the manifest")
                if json.dumps(checked_row, ensure_ascii=False) != line:
                    _fail("external errors log row is not canonical")
            return len(lines)
        finally:
            os.close(fd)

    @classmethod
    def _validate_external_manifest(
        cls,
        course_fd: int,
        raw: bytes,
        *,
        status_name: str,
        done: int,
        total: int,
        errors: int,
    ) -> None:
        if not raw or not raw.endswith(b"\n"):
            _fail("external manifest is empty or partial")
        try:
            lines = raw.decode("utf-8").splitlines()
        except UnicodeError:
            _fail("external manifest is not UTF-8")
        if (
            not lines
            or len(lines) > _MAX_MANIFEST_ROWS
            or any(not line for line in lines)
        ):
            _fail("external manifest row count is invalid")
        targets: list[str] = []
        rels: set[str] = set()
        for line in lines:
            try:
                row = json.loads(line, object_pairs_hook=_no_duplicates)
            except CoursedumpConnectorError:
                raise
            except (UnicodeError, ValueError, RecursionError):
                _fail("external manifest row is malformed")
            item = _exact(
                row,
                {
                    "rel",
                    "kind",
                    "size",
                    "remote",
                    "skip",
                    "target",
                    "index",
                    "vid",
                    "title",
                },
                "external-manifest-row",
            )
            rel = _external_text(item["rel"], "manifest-rel", 4096, allow_empty=False)
            kind = _external_text(item["kind"], "manifest-kind", 32, allow_empty=False)
            size = _integer(item["size"], "manifest-size")
            remote = _external_text(
                item["remote"], "manifest-remote", 8192, allow_empty=True
            )
            skip = _external_text(item["skip"], "manifest-skip", 32, allow_empty=True)
            target = cls._manifest_target(item["target"])
            index = _integer(item["index"], "manifest-index", maximum=2**31 - 1)
            vid = _external_text(item["vid"], "manifest-vid", 1024, allow_empty=True)
            title = _external_text(
                item["title"], "manifest-title", 4096, allow_empty=True
            )
            if kind not in {
                "video",
                "audio",
                "pdf",
                "office",
                "text",
                "subs",
                "html",
                "image",
                "other",
            } or skip not in {"", "blacklist", "image", "other", "sibling"}:
                _fail("external manifest kind or skip is invalid")
            if (target == "") != (skip != ""):
                _fail("external manifest target and skip disagree")
            checked_row = {
                "rel": rel,
                "kind": kind,
                "size": size,
                "remote": remote,
                "skip": skip,
                "target": target,
                "index": index,
                "vid": vid,
                "title": title,
            }
            if json.dumps(checked_row, ensure_ascii=False) != line:
                _fail("external manifest row is not canonical")
            if rel in rels:
                _fail("external manifest rel is duplicated")
            rels.add(rel)
            if target:
                targets.append(target)
        if not targets or len(set(targets)) != len(targets) or total != len(targets):
            _fail("external manifest total is inconsistent")
        actual_done = sum(cls._target_exists(course_fd, target) for target in targets)
        if done != actual_done:
            _fail("external manifest done count is inconsistent")
        if status_name == "succeeded" and (done != total or errors != 0):
            _fail("external manifest succeeded status is inconsistent")
        if status_name == "completed-with-errors" and (
            errors == 0 or errors > total - done
        ):
            _fail("external manifest error status is inconsistent")
        durable_errors = cls._error_row_count(course_fd, rels)
        if errors != durable_errors:
            _fail("external manifest durable error count is inconsistent")

    @staticmethod
    def _decode_source_manifest(raw: bytes) -> dict[str, object]:
        try:
            value = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicates)
        except CoursedumpConnectorError:
            raise
        except (UnicodeError, ValueError, RecursionError):
            _fail("invalid-source-manifest")
        if not isinstance(value, dict) or not _json_safe(value):
            _fail("invalid-source-manifest")
        return value
