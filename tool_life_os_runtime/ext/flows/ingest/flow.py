"""Deterministic ingest routing into bounded review proposals.

The router owns classification, authority checks, dedupe evidence, and the
review boundary. It does not fetch or extract heavy sources and never writes
the inbox, review, run, or knowledge zones directly.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime
import hashlib
import json
from pathlib import PurePosixPath
import re
import threading
from typing import Mapping, Protocol
import unicodedata
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlsplit, urlunsplit

from tool_life_os_runtime.ext.flows.obsidian import (
    OBSIDIAN_SCHEMA_VERSION,
    NoteRef,
    ObsidianError,
    ObsidianFlow,
    parse_note,
    validate_note,
)
from tool_life_os_runtime.ext.review.artifact import (
    ARTIFACT_SCHEMA_VERSION,
    PLAN_SCHEMA_VERSION,
    MutationOperation,
    MutationPlan,
    Provenance,
    ReviewArtifact,
    ReviewArtifactError,
    SourceRef,
    parse_mutation_plan,
    parse_review_artifact,
    provenance_sha256,
    render_mutation_plan,
    render_review_artifact,
    review_body_sha256,
    validate_artifact_plan,
)
from tool_life_os_runtime.ext.review.authority import (
    ActionCapability,
    AuthorityError,
    AuthorityPolicy,
)
from tool_life_os_runtime.ext.vault.schema import VaultPathResolver


INGEST_SCHEMA_VERSION = 1
INGEST_CONNECTOR_SCHEMA_VERSION = 1

_MAX_INPUT_BYTES = 32 * 1024
_MAX_RESULT_BYTES = 1024 * 1024
_MAX_SOURCE_BYTES = 16 * 1024
_MAX_CONTENT_BYTES = 192 * 1024
_MAX_FALLBACK_BYTES = 1024
_MAX_QUERY_ITEMS = 128
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_RUN_ID = re.compile(r"^run_[a-z0-9][a-z0-9_-]{0,62}$")
_REVIEW_ID = re.compile(r"^rev_[a-z0-9][a-z0-9_-]{0,62}$")
_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$")
_KINDS = frozenset({"auto", "note", "url", "video", "book", "course", "unknown"})
_CLASSIFICATIONS = frozenset({"note", "url", "video", "book", "course", "unknown"})
_SURFACES = frozenset({"silent", "batched", "gated"})
_ARCHIVE_COMPONENTS = frozenset({"_archive", "_trash", "_on_hold"})
_VIDEO_HOSTS = frozenset(
    {
        "youtube.com",
        "www.youtube.com",
        "m.youtube.com",
        "youtu.be",
        "vimeo.com",
        "www.vimeo.com",
    }
)
_VIDEO_SUFFIXES = frozenset({".mp4", ".mkv", ".mov", ".webm", ".avi"})
_BOOK_SUFFIXES = frozenset({".pdf", ".epub", ".mobi", ".azw", ".azw3", ".fb2"})
_PRIVATE_MARKERS = ("/" + "Users" + "/", "/" + "home" + "/", "file:")
_INPUT_KEYS = frozenset(
    {
        "schema_version",
        "run_id",
        "review_id",
        "created_at",
        "kind",
        "source",
        "target_path",
        "surface",
    }
)
_RESULT_KEYS = frozenset(
    {
        "schema_version",
        "classification",
        "route",
        "connector",
        "status",
        "canonical_source_sha256",
        "content_sha256",
        "source_ref",
        "provenance_sha256",
        "dedupe_key",
        "review_artifact",
        "mutation_plan",
        "fallback",
        "replayed",
    }
)
_FALLBACK_KEYS = frozenset({"schema_version", "code", "message", "accepted_kinds"})
_CONNECTOR_REQUESTS = {
    "url": ("researcher", "research-heavy-input"),
    "video": ("coursedump", "extract-heavy-input"),
    "book": ("coursedump", "extract-heavy-input"),
    "course": ("coursedump", "extract-heavy-input"),
}
_INGEST_ACTIONS = {
    "classify-declared-input": (
        "runtime",
        "read",
        "external:declared-input",
        "read",
        "read-only",
        False,
    ),
    "read-inbox-dedupe-state": (
        "runtime",
        "read",
        "vault:inbox",
        "read",
        "read-only",
        False,
    ),
    "read-source-manifest": (
        "runtime",
        "read",
        "tool:source-manifest",
        "read",
        "read-only",
        False,
    ),
    "extract-heavy-input": (
        "runtime",
        "internal-write",
        "tool:coursedump",
        "invoke",
        "connector-call",
        False,
    ),
    "research-heavy-input": (
        "runtime",
        "internal-write",
        "tool:researcher",
        "invoke",
        "connector-call",
        False,
    ),
    "commit-review-proposal": (
        "runtime",
        "proposal",
        "vault:review",
        "write",
        "proposal-commit",
        True,
    ),
}


class IngestError(ValueError):
    """An ingest input, capability, connector result, or proposal is invalid."""


def _fail(message: str) -> None:
    raise IngestError(message)


@dataclass(frozen=True)
class IngestInput:
    schema_version: int
    run_id: str
    review_id: str
    created_at: str
    kind: str
    source: str
    target_path: str
    surface: str = "gated"


@dataclass(frozen=True)
class IngestFallback:
    schema_version: int
    code: str
    message: str
    accepted_kinds: tuple[str, ...]


@dataclass(frozen=True)
class IngestConnectorRequest:
    schema_version: int
    run_id: str
    classification: str
    connector: str
    canonical_source: str
    canonical_source_sha256: str
    max_content_bytes: int


@dataclass(frozen=True)
class IngestConnectorResult:
    schema_version: int
    connector: str
    source_ref: str
    canonical_source_sha256: str
    manifest_sha256: str
    content_sha256: str
    content: str


class IngestConnectorPort(Protocol):
    """Narrow boundary implemented by connector adapters, never sibling imports."""

    def collect(self, request: IngestConnectorRequest) -> IngestConnectorResult: ...


@dataclass(frozen=True)
class IngestDedupeEntry:
    """Canonical replay evidence owned by an injected dedupe store."""

    schema_version: int
    run_id: str
    review_id: str
    created_at: str
    target_path: str
    surface: str
    classification: str
    route: str
    connector: str | None
    canonical_source_sha256: str
    content_sha256: str | None
    source_ref: str | None
    provenance_sha256: str | None
    dedupe_key: str
    result: IngestResult


class IngestDedupePort(Protocol):
    """Shared replay index supplied by the runtime composition boundary."""

    def find_by_review(self, review_id: str) -> IngestDedupeEntry | None: ...

    def find_by_source(
        self, canonical_source_sha256: str
    ) -> IngestDedupeEntry | None: ...

    def remember(self, entry: IngestDedupeEntry) -> IngestDedupeEntry: ...


@dataclass(frozen=True)
class IngestCapabilities:
    classify: ActionCapability
    read_dedupe: ActionCapability
    commit_review: ActionCapability | None = None
    note_read: ActionCapability | None = None
    read_manifest: ActionCapability | None = None
    extract: ActionCapability | None = None
    research: ActionCapability | None = None


@dataclass(frozen=True)
class IngestResult:
    schema_version: int
    classification: str
    route: str
    connector: str | None
    status: str
    canonical_source_sha256: str
    content_sha256: str | None
    source_ref: str | None
    provenance_sha256: str | None
    dedupe_key: str
    review_artifact: ReviewArtifact | None
    mutation_plan: MutationPlan | None
    fallback: IngestFallback | None
    replayed: bool


class InMemoryIngestDedupeStore:
    """Explicit shared store for one runtime process or deterministic tests."""

    def __init__(self) -> None:
        self._by_review: dict[str, IngestDedupeEntry] = {}
        self._by_source: dict[str, IngestDedupeEntry] = {}
        self._by_dedupe: dict[str, IngestDedupeEntry] = {}
        self._lock = threading.RLock()

    def find_by_review(self, review_id: str) -> IngestDedupeEntry | None:
        with self._lock:
            return self._by_review.get(review_id)

    def find_by_source(self, canonical_source_sha256: str) -> IngestDedupeEntry | None:
        with self._lock:
            return self._by_source.get(canonical_source_sha256)

    def remember(self, entry: IngestDedupeEntry) -> IngestDedupeEntry:
        with self._lock:
            matches = tuple(
                candidate
                for candidate in (
                    self._by_review.get(entry.review_id),
                    self._by_source.get(entry.canonical_source_sha256),
                    self._by_dedupe.get(entry.dedupe_key),
                )
                if candidate is not None
            )
            if matches:
                if any(candidate != entry for candidate in matches):
                    raise IngestError("ingest dedupe evidence conflicts")
                return matches[0]
            self._by_review[entry.review_id] = entry
            self._by_source[entry.canonical_source_sha256] = entry
            self._by_dedupe[entry.dedupe_key] = entry
            return entry


def _has_control(value: str, *, layout: bool = False) -> bool:
    allowed = {"\n", "\t"} if layout else set()
    return any(
        character not in allowed
        and (
            unicodedata.category(character).startswith("C")
            or unicodedata.category(character) in {"Zl", "Zp"}
        )
        for character in value
    )


def _text(
    value: object,
    label: str,
    *,
    maximum: int,
    allow_empty: bool = False,
    layout: bool = False,
    privacy_safe: bool = True,
) -> str:
    if not isinstance(value, str):
        _fail(f"{label} must be text")
    try:
        raw = value.encode("utf-8")
    except UnicodeError:
        _fail(f"{label} must be valid UTF-8")
    if (
        (not allow_empty and not value)
        or len(raw) > maximum
        or _has_control(value, layout=layout)
        or unicodedata.normalize("NFC", value) != value
    ):
        _fail(f"{label} must be bounded portable NFC text")
    if privacy_safe and any(marker in value for marker in _PRIVATE_MARKERS):
        _fail(f"{label} contains a private path")
    return value


def _hash(value: object, label: str) -> str:
    text = _text(value, label, maximum=64)
    if _SHA256.fullmatch(text) is None:
        _fail(f"{label} must be a sha256 digest")
    return text


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError):
        _fail("ingest value is not canonical JSON")


def _object_no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            _fail("ingest JSON contains duplicate fields")
        result[key] = value
    return result


def _decode_json(
    raw: str | bytes, *, label: str, maximum: int
) -> tuple[dict[str, object], bytes]:
    if isinstance(raw, str):
        try:
            data = raw.encode("utf-8")
        except UnicodeError:
            _fail(f"{label} must be UTF-8")
    elif isinstance(raw, bytes):
        data = raw
    else:
        _fail(f"{label} must be text or bytes")
    if not data or len(data) > maximum:
        _fail(f"{label} is not bounded")
    try:
        payload = json.loads(
            data.decode("utf-8"), object_pairs_hook=_object_no_duplicates
        )
    except IngestError:
        raise
    except (UnicodeError, ValueError, RecursionError):
        _fail(f"{label} is malformed")
    if not isinstance(payload, dict):
        _fail(f"{label} must be a JSON object")
    return payload, data


def _timestamp(value: object) -> str:
    text = _text(value, "created_at", maximum=40)
    if _UTC.fullmatch(text) is None:
        _fail("created_at must be a UTC timestamp")
    try:
        datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError:
        _fail("created_at must be a valid UTC timestamp")
    return text


def _knowledge_target(value: object) -> str:
    text = _text(value, "target_path", maximum=4096)
    if "\\" in text or text.startswith("/") or text.endswith("/") or "//" in text:
        _fail("target_path must be a canonical relative POSIX path")
    path = PurePosixPath(text)
    if (
        path.as_posix() != text
        or len(path.parts) < 2
        or len(path.parts) > 16
        or path.parts[0] != "knowledge"
        or path.suffix != ".md"
        or any(part in {".", ".."} for part in path.parts)
        or any(part.startswith(".") for part in path.parts)
        or any(part.casefold() in _ARCHIVE_COMPONENTS for part in path.parts)
    ):
        _fail("target_path must name active portable Markdown knowledge")
    for part in path.parts:
        if len(part.encode("utf-8")) > 255 or part.strip() != part:
            _fail("target_path contains a non-portable component")
    return text


def _validate_input(value: IngestInput) -> IngestInput:
    if not isinstance(value, IngestInput) or type(value.schema_version) is not int:
        _fail("ingest input is invalid")
    if value.schema_version != INGEST_SCHEMA_VERSION:
        _fail("unsupported ingest input schema_version")
    run_id = _text(value.run_id, "run_id", maximum=64)
    review_id = _text(value.review_id, "review_id", maximum=64)
    if _RUN_ID.fullmatch(run_id) is None or _REVIEW_ID.fullmatch(review_id) is None:
        _fail("ingest run_id or review_id has invalid syntax")
    kind = _text(value.kind, "kind", maximum=16)
    if kind not in _KINDS:
        _fail("ingest kind is unsupported")
    surface = _text(value.surface, "surface", maximum=16)
    if surface not in _SURFACES:
        _fail("ingest surface is unsupported")
    source = _text(value.source, "source", maximum=_MAX_SOURCE_BYTES)
    if kind == "note" or (kind == "auto" and source.startswith("inbox/")):
        source, _relative = _canonical_note_source(source)
    return IngestInput(
        INGEST_SCHEMA_VERSION,
        run_id,
        review_id,
        _timestamp(value.created_at),
        kind,
        source,
        _knowledge_target(value.target_path),
        surface,
    )


def _input_payload(value: IngestInput) -> dict[str, object]:
    checked = _validate_input(value)
    return {
        "schema_version": checked.schema_version,
        "run_id": checked.run_id,
        "review_id": checked.review_id,
        "created_at": checked.created_at,
        "kind": checked.kind,
        "source": checked.source,
        "target_path": checked.target_path,
        "surface": checked.surface,
    }


def render_ingest_input(value: IngestInput) -> bytes:
    """Render one validated canonical JSON input."""

    return _canonical_json(_input_payload(value)) + b"\n"


def parse_ingest_input(raw: str | bytes) -> IngestInput:
    """Parse exact bounded JSON without duplicate or unknown fields."""

    payload, data = _decode_json(raw, label="ingest input", maximum=_MAX_INPUT_BYTES)
    if set(payload) != _INPUT_KEYS:
        _fail("ingest input has missing or unknown fields")
    value = _validate_input(
        IngestInput(
            payload["schema_version"],
            payload["run_id"],
            payload["review_id"],
            payload["created_at"],
            payload["kind"],
            payload["source"],
            payload["target_path"],
            payload["surface"],
        )
    )
    if data != render_ingest_input(value):
        _fail("ingest input must use canonical JSON")
    return value


def _canonical_note_source(source: str) -> tuple[str, str]:
    if (
        "\\" in source
        or source.startswith("/")
        or source.endswith("/")
        or "//" in source
    ):
        _fail("note source must be a canonical inbox path")
    path = PurePosixPath(source)
    if (
        path.as_posix() != source
        or len(path.parts) < 2
        or path.parts[0] != "inbox"
        or path.suffix.casefold() != ".md"
        or any(part in {".", ".."} for part in path.parts)
        or any(part.startswith(".") for part in path.parts)
        or any(part.casefold() in _ARCHIVE_COMPONENTS for part in path.parts)
    ):
        _fail("note source must name active inbox Markdown")
    for part in path.parts:
        if len(part.encode("utf-8")) > 255 or part.strip() != part:
            _fail("note source contains a non-portable component")
    return source, PurePosixPath(*path.parts[1:]).as_posix()


def _canonical_url(source: str) -> str:
    try:
        parsed = urlsplit(source)
        port = parsed.port
    except ValueError:
        _fail("heavy ingest source is not a valid URL")
    if (
        parsed.scheme.casefold() not in {"http", "https"}
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
    ):
        _fail("heavy ingest source must be an HTTP URL without credentials")
    try:
        host = parsed.hostname.encode("idna").decode("ascii").casefold()
    except UnicodeError:
        _fail("heavy ingest URL host is invalid")
    if not host or _has_control(host):
        _fail("heavy ingest URL host is invalid")
    default_port = (parsed.scheme.casefold() == "http" and port == 80) or (
        parsed.scheme.casefold() == "https" and port == 443
    )
    authority = host if port is None or default_port else f"{host}:{port}"
    try:
        decoded_path = unicodedata.normalize("NFC", unquote(parsed.path or "/"))
        path = quote(decoded_path, safe="/-._~:@!$&'()*+,;=")
        pairs = parse_qsl(
            parsed.query, keep_blank_values=True, max_num_fields=_MAX_QUERY_ITEMS
        )
    except (UnicodeError, ValueError):
        _fail("heavy ingest URL path or query is invalid")
    checked_pairs: list[tuple[str, str]] = []
    for key, value in pairs:
        checked_key = _text(key, "URL query key", maximum=4096, privacy_safe=False)
        checked_value = _text(
            value, "URL query value", maximum=4096, allow_empty=True, privacy_safe=False
        )
        checked_pairs.append((checked_key, checked_value))
    query = urlencode(sorted(checked_pairs), doseq=True)
    canonical = urlunsplit((parsed.scheme.casefold(), authority, path, query, ""))
    return _text(canonical, "canonical source", maximum=_MAX_SOURCE_BYTES)


def classify_ingest_input(value: IngestInput) -> tuple[str, str]:
    """Return the deterministic classification and canonical source."""

    checked = _validate_input(value)
    if checked.kind == "note" or (
        checked.kind == "auto" and checked.source.startswith("inbox/")
    ):
        canonical, _relative = _canonical_note_source(checked.source)
        return "note", canonical
    if checked.kind == "unknown":
        return "unknown", checked.source
    try:
        canonical = _canonical_url(checked.source)
    except IngestError:
        if checked.kind == "auto":
            return "unknown", checked.source
        raise
    if checked.kind in _CLASSIFICATIONS - {"note", "unknown"}:
        return checked.kind, canonical
    parsed = urlsplit(canonical)
    suffix = PurePosixPath(unquote(parsed.path)).suffix.casefold()
    segments = {part.casefold() for part in PurePosixPath(unquote(parsed.path)).parts}
    if parsed.hostname in _VIDEO_HOSTS or suffix in _VIDEO_SUFFIXES:
        return "video", canonical
    if suffix in _BOOK_SUFFIXES or segments.intersection(
        {"book", "books", "ebook", "ebooks"}
    ):
        return "book", canonical
    if segments.intersection({"course", "courses", "curriculum"}):
        return "course", canonical
    return "url", canonical


def _source_digest(classification: str, canonical_source: str) -> str:
    return hashlib.sha256(
        b"lifeos-ingest-source-v1\0"
        + classification.encode("ascii")
        + b"\0"
        + canonical_source.encode("utf-8")
    ).hexdigest()


def _dedupe_key(
    classification: str, source_digest: str, content_digest: str | None
) -> str:
    return hashlib.sha256(
        b"lifeos-ingest-dedupe-v1\0"
        + classification.encode("ascii")
        + b"\0"
        + source_digest.encode("ascii")
        + b"\0"
        + (content_digest or "none").encode("ascii")
    ).hexdigest()


def _fallback() -> IngestFallback:
    return IngestFallback(
        INGEST_SCHEMA_VERSION,
        "unsupported-input",
        "Input was not classified. Declare note, url, video, book, or course.",
        ("note", "url", "video", "book", "course"),
    )


def _fallback_payload(value: IngestFallback) -> dict[str, object]:
    if (
        not isinstance(value, IngestFallback)
        or type(value.schema_version) is not int
        or value.schema_version != INGEST_SCHEMA_VERSION
    ):
        _fail("ingest fallback is invalid")
    code = _text(value.code, "fallback code", maximum=64)
    message = _text(value.message, "fallback message", maximum=_MAX_FALLBACK_BYTES)
    if code != "unsupported-input" or value.accepted_kinds != (
        "note",
        "url",
        "video",
        "book",
        "course",
    ):
        _fail("ingest fallback contract is invalid")
    return {
        "schema_version": value.schema_version,
        "code": code,
        "message": message,
        "accepted_kinds": list(value.accepted_kinds),
    }


def _require_action(
    policy: AuthorityPolicy, capability: ActionCapability | None, action_id: str
) -> ActionCapability:
    if capability is None:
        _fail(f"ingest action {action_id} requires a capability")
    try:
        grant = policy.require(capability)
    except AuthorityError as error:
        raise IngestError(str(error)) from None
    expected = _INGEST_ACTIONS.get(action_id)
    if expected is None:
        _fail("ingest action is unknown")
    actor, authority, target, access, effect_kind, artifact_commit = expected
    if (
        grant.flow_id != "ingest"
        or grant.action_id != action_id
        or grant.actor != actor
        or grant.authority != authority
        or grant.target != target
        or grant.access != access
        or grant.effect_kind != effect_kind
        or grant.artifact_commit is not artifact_commit
    ):
        _fail("capability does not authorize the exact ingest action")
    return grant


def _validated_candidate(content: str, target_path: str) -> tuple[str, str]:
    checked_content = _text(
        content,
        "ingest candidate content",
        maximum=_MAX_CONTENT_BYTES,
        layout=True,
        privacy_safe=False,
    )
    relative = PurePosixPath(*PurePosixPath(target_path).parts[1:]).as_posix()
    try:
        snapshot = parse_note(
            NoteRef(OBSIDIAN_SCHEMA_VERSION, "knowledge", relative),
            checked_content,
            path=target_path,
        )
        validation = validate_note(snapshot)
    except ObsidianError:
        _fail("ingest candidate is not a valid portable note")
    if not validation.valid:
        _fail("ingest candidate is not a valid portable note")
    return snapshot.content, snapshot.sha256


def _connector_result(
    value: object,
    *,
    request: IngestConnectorRequest,
    target_path: str,
) -> tuple[str, str, str, str]:
    if not isinstance(value, IngestConnectorResult):
        _fail("ingest connector returned an invalid result")
    if (
        type(value.schema_version) is not int
        or value.schema_version != INGEST_CONNECTOR_SCHEMA_VERSION
        or value.connector != request.connector
        or value.canonical_source_sha256 != request.canonical_source_sha256
    ):
        _fail("ingest connector result is not bound to the request")
    source_ref = _logical_source_ref(value.source_ref)
    manifest_sha256 = _hash(value.manifest_sha256, "connector manifest_sha256")
    content, content_sha256 = _validated_candidate(value.content, target_path)
    if _hash(value.content_sha256, "connector content_sha256") != content_sha256:
        _fail("ingest connector content hash is invalid")
    return source_ref, manifest_sha256, content, content_sha256


def _logical_source_ref(value: object) -> str:
    source_ref = _text(value, "source_ref", maximum=1024)
    if "\\" in source_ref:
        _fail("source_ref must be portable")
    source_path = PurePosixPath(source_ref)
    if (
        source_path.is_absolute()
        or source_path.as_posix() != source_ref
        or source_path == PurePosixPath(".")
        or ".." in source_path.parts
        or any(part.casefold() in _ARCHIVE_COMPONENTS for part in source_path.parts)
    ):
        _fail("source_ref must be a safe active logical reference")
    return source_ref


def _proposal_body(
    classification: str, route: str, canonical_source_sha256: str, target_path: str
) -> str:
    return (
        "# Ingest proposal\n\n"
        f"- Classification: `{classification}`\n"
        f"- Route: `{route}`\n"
        f"- Source: `sha256:{canonical_source_sha256}`\n"
        f"- Target: `{target_path}`\n"
    )


def _proposal(
    request: IngestInput,
    *,
    classification: str,
    route: str,
    source_ref: str,
    source_kind: str,
    provenance_digest: str,
    canonical_source_sha256: str,
    content: str,
    content_sha256: str,
) -> tuple[ReviewArtifact, MutationPlan]:
    body = _proposal_body(
        classification, route, canonical_source_sha256, request.target_path
    )
    provenance = Provenance(
        request.run_id,
        ((source_ref, provenance_digest),),
    )
    artifact = ReviewArtifact(
        ARTIFACT_SCHEMA_VERSION,
        request.review_id,
        "proposed",
        "ingest",
        request.created_at,
        request.surface,
        (SourceRef(source_kind, source_ref),),
        provenance,
        f".lifeos/review-plans/{request.review_id}.json",
        body,
    )
    plan = MutationPlan(
        PLAN_SCHEMA_VERSION,
        request.review_id,
        review_body_sha256(body),
        provenance_sha256(provenance),
        (
            MutationOperation(
                "create",
                request.target_path,
                None,
                (source_ref,),
                None,
                content_sha256,
                content,
            ),
        ),
    )
    try:
        checked_artifact = parse_review_artifact(render_review_artifact(artifact))
        checked_plan = parse_mutation_plan(render_mutation_plan(plan))
        validate_artifact_plan(checked_artifact, checked_plan)
    except ReviewArtifactError:
        _fail("ingest proposal violates the review contract")
    return checked_artifact, checked_plan


def _validate_result(value: IngestResult) -> IngestResult:
    if not isinstance(value, IngestResult) or type(value.schema_version) is not int:
        _fail("ingest result is invalid")
    if value.schema_version != INGEST_SCHEMA_VERSION:
        _fail("unsupported ingest result schema_version")
    classification = _text(value.classification, "classification", maximum=16)
    if classification not in _CLASSIFICATIONS:
        _fail("ingest result classification is invalid")
    route = _text(value.route, "route", maximum=32)
    connector = (
        None
        if value.connector is None
        else _text(value.connector, "connector", maximum=32)
    )
    status = _text(value.status, "status", maximum=16)
    source_digest = _hash(value.canonical_source_sha256, "canonical_source_sha256")
    content_digest = (
        None
        if value.content_sha256 is None
        else _hash(value.content_sha256, "content_sha256")
    )
    source_ref = (
        None if value.source_ref is None else _logical_source_ref(value.source_ref)
    )
    provenance_digest = (
        None
        if value.provenance_sha256 is None
        else _hash(value.provenance_sha256, "provenance_sha256")
    )
    dedupe = _hash(value.dedupe_key, "dedupe_key")
    if dedupe != _dedupe_key(classification, source_digest, content_digest):
        _fail("ingest result dedupe_key is not bound to its source and content")
    if type(value.replayed) is not bool:
        _fail("ingest result replayed flag is invalid")
    if classification == "unknown":
        if (
            route != "fallback"
            or connector is not None
            or status != "unsupported"
            or content_digest is not None
            or source_ref is not None
            or provenance_digest is not None
            or value.review_artifact is not None
            or value.mutation_plan is not None
            or value.fallback is None
        ):
            _fail("unknown ingest result has invalid fallback fields")
        _fallback_payload(value.fallback)
    else:
        expected_route = (
            "local-note"
            if classification == "note"
            else _CONNECTOR_REQUESTS[classification][0]
        )
        expected_connector = None if classification == "note" else expected_route
        if (
            route != expected_route
            or connector != expected_connector
            or status != "proposed"
            or content_digest is None
            or source_ref is None
            or provenance_digest is None
            or value.review_artifact is None
            or value.mutation_plan is None
            or value.fallback is not None
        ):
            _fail("proposed ingest result has invalid fields")
        try:
            artifact = parse_review_artifact(
                render_review_artifact(value.review_artifact)
            )
            plan = parse_mutation_plan(render_mutation_plan(value.mutation_plan))
            validate_artifact_plan(artifact, plan)
        except ReviewArtifactError:
            _fail("ingest result proposal is invalid")
        operation = plan.operations[0] if len(plan.operations) == 1 else None
        source_kind = (
            "vault_note" if classification == "note" else f"{connector}_manifest"
        )
        if (
            artifact.flow != "ingest"
            or artifact.status != "proposed"
            or artifact.sources != (SourceRef(source_kind, source_ref),)
            or artifact.provenance.source_hashes != ((source_ref, provenance_digest),)
            or operation is None
            or operation.op != "create"
            or operation.source_refs != (source_ref,)
            or operation.postcondition_sha256 != content_digest
            or artifact.body
            != _proposal_body(classification, route, source_digest, operation.path)
        ):
            _fail("ingest result proposal does not match result evidence")
        if classification == "note" and source_digest != _source_digest(
            classification, source_ref
        ):
            _fail("note ingest result source_ref does not match source identity")
    return value


def _result_payload(value: IngestResult) -> dict[str, object]:
    checked = _validate_result(value)
    return {
        "schema_version": checked.schema_version,
        "classification": checked.classification,
        "route": checked.route,
        "connector": checked.connector,
        "status": checked.status,
        "canonical_source_sha256": checked.canonical_source_sha256,
        "content_sha256": checked.content_sha256,
        "source_ref": checked.source_ref,
        "provenance_sha256": checked.provenance_sha256,
        "dedupe_key": checked.dedupe_key,
        "review_artifact": (
            None
            if checked.review_artifact is None
            else render_review_artifact(checked.review_artifact)
        ),
        "mutation_plan": (
            None
            if checked.mutation_plan is None
            else render_mutation_plan(checked.mutation_plan).decode("utf-8")
        ),
        "fallback": None
        if checked.fallback is None
        else _fallback_payload(checked.fallback),
        "replayed": checked.replayed,
    }


def render_ingest_result(value: IngestResult) -> bytes:
    """Render one strict result containing only review artifacts or fallback."""

    data = _canonical_json(_result_payload(value)) + b"\n"
    if len(data) > _MAX_RESULT_BYTES:
        _fail("ingest result exceeds its byte limit")
    return data


def parse_ingest_result(raw: str | bytes) -> IngestResult:
    """Parse and revalidate exact nested review contracts."""

    payload, data = _decode_json(raw, label="ingest result", maximum=_MAX_RESULT_BYTES)
    if set(payload) != _RESULT_KEYS:
        _fail("ingest result has missing or unknown fields")
    fallback_raw = payload["fallback"]
    fallback = None
    if fallback_raw is not None:
        if not isinstance(fallback_raw, Mapping) or set(fallback_raw) != _FALLBACK_KEYS:
            _fail("ingest fallback has missing or unknown fields")
        accepted = fallback_raw["accepted_kinds"]
        if not isinstance(accepted, list) or not all(
            isinstance(item, str) for item in accepted
        ):
            _fail("ingest fallback accepted_kinds is invalid")
        fallback = IngestFallback(
            fallback_raw["schema_version"],
            fallback_raw["code"],
            fallback_raw["message"],
            tuple(accepted),
        )
    artifact_raw = payload["review_artifact"]
    plan_raw = payload["mutation_plan"]
    try:
        artifact = None if artifact_raw is None else parse_review_artifact(artifact_raw)
        plan = None if plan_raw is None else parse_mutation_plan(plan_raw)
    except ReviewArtifactError:
        _fail("ingest result contains an invalid review proposal")
    result = _validate_result(
        IngestResult(
            payload["schema_version"],
            payload["classification"],
            payload["route"],
            payload["connector"],
            payload["status"],
            payload["canonical_source_sha256"],
            payload["content_sha256"],
            payload["source_ref"],
            payload["provenance_sha256"],
            payload["dedupe_key"],
            artifact,
            plan,
            fallback,
            payload["replayed"],
        )
    )
    if data != render_ingest_result(result):
        _fail("ingest result must use canonical JSON")
    return result


def _validate_dedupe_entry(value: object) -> IngestDedupeEntry:
    if (
        not isinstance(value, IngestDedupeEntry)
        or type(value.schema_version) is not int
        or value.schema_version != INGEST_SCHEMA_VERSION
    ):
        _fail("ingest dedupe evidence is invalid")
    run_id = _text(value.run_id, "dedupe run_id", maximum=64)
    review_id = _text(value.review_id, "dedupe review_id", maximum=64)
    if _RUN_ID.fullmatch(run_id) is None or _REVIEW_ID.fullmatch(review_id) is None:
        _fail("ingest dedupe identity is invalid")
    created_at = _timestamp(value.created_at)
    target_path = _knowledge_target(value.target_path)
    surface = _text(value.surface, "dedupe surface", maximum=16)
    if surface not in _SURFACES:
        _fail("ingest dedupe surface is invalid")
    classification = _text(value.classification, "dedupe classification", maximum=16)
    if classification not in _CLASSIFICATIONS:
        _fail("ingest dedupe classification is invalid")
    route = _text(value.route, "dedupe route", maximum=32)
    connector = (
        None
        if value.connector is None
        else _text(value.connector, "dedupe connector", maximum=32)
    )
    source_digest = _hash(
        value.canonical_source_sha256, "dedupe canonical_source_sha256"
    )
    content_digest = (
        None
        if value.content_sha256 is None
        else _hash(value.content_sha256, "dedupe content_sha256")
    )
    source_ref = (
        None if value.source_ref is None else _logical_source_ref(value.source_ref)
    )
    provenance_digest = (
        None
        if value.provenance_sha256 is None
        else _hash(value.provenance_sha256, "dedupe provenance_sha256")
    )
    dedupe = _hash(value.dedupe_key, "dedupe key")
    result = _validate_result(value.result)
    if result.replayed:
        _fail("stored ingest dedupe result cannot already be replayed")
    if (
        result.classification != classification
        or result.route != route
        or result.connector != connector
        or result.canonical_source_sha256 != source_digest
        or result.content_sha256 != content_digest
        or result.source_ref != source_ref
        or result.provenance_sha256 != provenance_digest
        or result.dedupe_key != dedupe
    ):
        _fail("ingest dedupe evidence does not match its result")
    if classification == "unknown":
        if route != "fallback" or connector is not None:
            _fail("unknown ingest dedupe route is invalid")
    else:
        expected_route = (
            "local-note"
            if classification == "note"
            else _CONNECTOR_REQUESTS[classification][0]
        )
        expected_connector = None if classification == "note" else expected_route
        artifact = result.review_artifact
        plan = result.mutation_plan
        if (
            route != expected_route
            or connector != expected_connector
            or artifact is None
            or plan is None
            or artifact.review_id != review_id
            or artifact.created_at != created_at
            or artifact.surface != surface
            or artifact.provenance.run_id != run_id
            or len(plan.operations) != 1
            or plan.operations[0].path != target_path
        ):
            _fail("ingest dedupe request envelope is not bound to its proposal")
    return value


def _dedupe_entry(
    request: IngestInput,
    *,
    result: IngestResult,
) -> IngestDedupeEntry:
    return _validate_dedupe_entry(
        IngestDedupeEntry(
            INGEST_SCHEMA_VERSION,
            request.run_id,
            request.review_id,
            request.created_at,
            request.target_path,
            request.surface,
            result.classification,
            result.route,
            result.connector,
            result.canonical_source_sha256,
            result.content_sha256,
            result.source_ref,
            result.provenance_sha256,
            result.dedupe_key,
            result,
        )
    )


def _require_replay_envelope(
    entry: IngestDedupeEntry,
    request: IngestInput,
    *,
    classification: str,
    route: str,
    connector: str | None,
    canonical_source_sha256: str,
    content_sha256: str | None | object = ...,
) -> IngestDedupeEntry:
    checked = _validate_dedupe_entry(entry)
    if (
        checked.run_id != request.run_id
        or checked.review_id != request.review_id
        or checked.created_at != request.created_at
        or checked.target_path != request.target_path
        or checked.surface != request.surface
        or checked.classification != classification
        or checked.route != route
        or checked.connector != connector
        or checked.canonical_source_sha256 != canonical_source_sha256
        or (content_sha256 is not ... and checked.content_sha256 != content_sha256)
    ):
        _fail("ingest replay request conflicts with stored evidence")
    return checked


class IngestFlow:
    """Classify one declared input and return a review proposal or exact replay."""

    def __init__(
        self,
        resolver: VaultPathResolver,
        policy: AuthorityPolicy,
        *,
        dedupe_store: IngestDedupePort,
        connector: IngestConnectorPort | None = None,
    ) -> None:
        if not isinstance(resolver, VaultPathResolver):
            _fail("ingest requires a VaultPathResolver")
        if not isinstance(policy, AuthorityPolicy):
            _fail("ingest requires an AuthorityPolicy")
        if connector is not None and not callable(getattr(connector, "collect", None)):
            _fail("ingest connector does not implement collect")
        if not all(
            callable(getattr(dedupe_store, name, None))
            for name in ("find_by_review", "find_by_source", "remember")
        ):
            _fail("ingest requires an explicit dedupe store")
        self._resolver = resolver
        self._policy = policy
        self._connector = connector
        self._dedupe_store = dedupe_store
        self._obsidian = ObsidianFlow(resolver, policy)

    def _lookup_replay(
        self,
        request: IngestInput,
        *,
        classification: str,
        route: str,
        connector: str | None,
        canonical_source_sha256: str,
        content_sha256: str | None | object = ...,
    ) -> IngestDedupeEntry | None:
        try:
            candidates = tuple(
                candidate
                for candidate in (
                    self._dedupe_store.find_by_review(request.review_id),
                    self._dedupe_store.find_by_source(canonical_source_sha256),
                )
                if candidate is not None
            )
        except IngestError:
            raise
        except Exception:
            _fail("ingest dedupe lookup failed")
        if not candidates:
            return None
        first = _require_replay_envelope(
            candidates[0],
            request,
            classification=classification,
            route=route,
            connector=connector,
            canonical_source_sha256=canonical_source_sha256,
            content_sha256=content_sha256,
        )
        if any(
            _validate_dedupe_entry(candidate) != first for candidate in candidates[1:]
        ):
            _fail("ingest dedupe indexes disagree")
        return first

    def _remember(
        self, request: IngestInput, result: IngestResult
    ) -> IngestDedupeEntry:
        candidate = _dedupe_entry(request, result=result)
        try:
            stored = self._dedupe_store.remember(candidate)
        except IngestError:
            raise
        except Exception:
            _fail("ingest dedupe publication failed")
        checked = _validate_dedupe_entry(stored)
        if checked != candidate:
            _fail("ingest dedupe publication conflicts with stored evidence")
        return checked

    def ingest(
        self, request: IngestInput, *, capabilities: IngestCapabilities
    ) -> IngestResult:
        checked = _validate_input(request)
        if not isinstance(capabilities, IngestCapabilities):
            _fail("ingest requires IngestCapabilities")
        _require_action(self._policy, capabilities.classify, "classify-declared-input")
        _require_action(
            self._policy, capabilities.read_dedupe, "read-inbox-dedupe-state"
        )
        classification, canonical_source = classify_ingest_input(checked)
        canonical_source_sha256 = _source_digest(classification, canonical_source)

        if classification == "unknown":
            route = "fallback"
            replay = self._lookup_replay(
                checked,
                classification=classification,
                route=route,
                connector=None,
                canonical_source_sha256=canonical_source_sha256,
                content_sha256=None,
            )
            if replay is not None:
                return _validate_result(replace(replay.result, replayed=True))
            dedupe = _dedupe_key(classification, canonical_source_sha256, None)
            result = _validate_result(
                IngestResult(
                    INGEST_SCHEMA_VERSION,
                    classification,
                    route,
                    None,
                    "unsupported",
                    canonical_source_sha256,
                    None,
                    None,
                    None,
                    dedupe,
                    None,
                    None,
                    _fallback(),
                    False,
                )
            )
            self._remember(checked, result)
            return result

        _require_action(
            self._policy, capabilities.commit_review, "commit-review-proposal"
        )
        if classification == "note":
            route = "local-note"
            connector_name = None
            if capabilities.note_read is None:
                _fail("note ingest requires the exact Obsidian read capability")
            _canonical, relative = _canonical_note_source(canonical_source)
            try:
                snapshot = self._obsidian.read_note(
                    NoteRef(OBSIDIAN_SCHEMA_VERSION, "inbox", relative),
                    capability=capabilities.note_read,
                )
            except ObsidianError:
                _fail("local note could not be read safely")
            content, content_sha256 = _validated_candidate(
                snapshot.content, checked.target_path
            )
            source_ref = canonical_source
            source_kind = "vault_note"
            provenance_digest = snapshot.sha256
        else:
            connector_name, action_id = _CONNECTOR_REQUESTS[classification]
            route = connector_name
            invoke = (
                capabilities.extract
                if connector_name == "coursedump"
                else capabilities.research
            )
            _require_action(self._policy, invoke, action_id)
            _require_action(
                self._policy, capabilities.read_manifest, "read-source-manifest"
            )
            replay = self._lookup_replay(
                checked,
                classification=classification,
                route=route,
                connector=connector_name,
                canonical_source_sha256=canonical_source_sha256,
            )
            if replay is not None:
                return _validate_result(replace(replay.result, replayed=True))
            if self._connector is None:
                _fail("heavy ingest connector is unavailable")
            connector_request = IngestConnectorRequest(
                INGEST_CONNECTOR_SCHEMA_VERSION,
                checked.run_id,
                classification,
                connector_name,
                canonical_source,
                canonical_source_sha256,
                _MAX_CONTENT_BYTES,
            )
            try:
                raw_result = self._connector.collect(connector_request)
            except Exception:
                _fail("heavy ingest connector failed")
            source_ref, provenance_digest, content, content_sha256 = _connector_result(
                raw_result,
                request=connector_request,
                target_path=checked.target_path,
            )
            source_kind = f"{connector_name}_manifest"

        dedupe = _dedupe_key(classification, canonical_source_sha256, content_sha256)
        replay = self._lookup_replay(
            checked,
            classification=classification,
            route=route,
            connector=connector_name,
            canonical_source_sha256=canonical_source_sha256,
            content_sha256=content_sha256,
        )
        if replay is not None:
            return _validate_result(replace(replay.result, replayed=True))
        artifact, plan = _proposal(
            checked,
            classification=classification,
            route=route,
            source_ref=source_ref,
            source_kind=source_kind,
            provenance_digest=provenance_digest,
            canonical_source_sha256=canonical_source_sha256,
            content=content,
            content_sha256=content_sha256,
        )
        result = _validate_result(
            IngestResult(
                INGEST_SCHEMA_VERSION,
                classification,
                route,
                connector_name,
                "proposed",
                canonical_source_sha256,
                content_sha256,
                source_ref,
                provenance_digest,
                dedupe,
                artifact,
                plan,
                None,
                False,
            )
        )
        self._remember(checked, result)
        return result
