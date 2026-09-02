"""Bounded filesystem retrieval for the ``ask`` flow.

The flow deliberately has no writer.  Optional file-back produces the same
review artifact and mutation-plan types consumed by the P2 review/apply path,
but leaves persistence to the phase integrator after an explicit review
commit.  Human knowledge is read through anchored directory descriptors so a
path swap cannot redirect retrieval to another tree.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import stat
from typing import Mapping
import unicodedata

from tool_life_os_runtime.ext.review.artifact import (
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
from tool_life_os_runtime.ext.vault.schema import (
    ARCHIVE_COMPONENTS,
    VaultPathResolver,
    VaultSchemaError,
)
from tool_life_os_runtime.ext.runs.store import PreparedArtifact, RunError, RunStore


ASK_SCHEMA_VERSION = 1
_TEXT_SUFFIXES = frozenset({".md", ".txt", ".json", ".jsonl"})
_WORD = re.compile(r"[^\W_]+", re.UNICODE)
_STOPWORDS = frozenset(
    {
        "a",
        "an",
        "and",
        "are",
        "as",
        "at",
        "be",
        "by",
        "do",
        "does",
        "for",
        "from",
        "how",
        "in",
        "is",
        "it",
        "no",
        "not",
        "of",
        "on",
        "or",
        "that",
        "the",
        "this",
        "to",
        "what",
        "when",
        "where",
        "who",
        "why",
        "with",
        # Unicode escapes preserve Russian stop-word behavior while keeping the
        # public source and its comments English-only.
        "\u0431\u0435\u0437",
        "\u0432",
        "\u0434\u043b\u044f",
        "\u0438",
        "\u0438\u0437",
        "\u043a\u0430\u043a",
        "\u043d\u0430",
        "\u043d\u0435",
        "\u043e",
        "\u043f\u043e",
        "\u0447\u0442\u043e",
        "\u044d\u0442\u043e",
    }
)
_REVIEW_ID = re.compile(r"^rev_[a-z0-9][a-z0-9_-]{0,62}$")
_RUN_ID = re.compile(r"^run_[a-z0-9][a-z0-9_-]{0,62}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$")
_PRIVATE_MARKERS = (
    "/" + "Users" + "/",
    "/" + "home" + "/",
    "\\/" + "Users" + "\\/",
    "\\/" + "home" + "\\/",
    "\\" + "Users" + "\\",
    "file:",
)
_SECRET = re.compile(
    r"(?i)(?:"
    r"(?:api[_ -]?key|authorization|bearer|cookie|credential|password|secret|token)[\"']?\s*[:=]"
    r"|sk-[a-z0-9_-]{12,}"
    r"|gh[pousr]_[a-z0-9]{20,}"
    r"|akia[a-z0-9]{16}"
    r"|eyj[a-z0-9_-]{12,}\.[a-z0-9_-]{12,}"
    r"|-----begin [a-z ]*private key-----"
    r")"
)
_SENSITIVE_PATH_COMPONENT = re.compile(
    r"(?i)(?:^|[^a-z0-9])(?:api[-_ ]?key|authorization|cookie|credential|password|secret|token)(?:$|[^a-z0-9])"
)
_MAX_QUERY_BYTES = 4096
_MAX_FILE_BACK_BYTES = 64 * 1024
_MAX_LINE_BYTES = 16 * 1024
_MAX_JSON_NODES = 16_384
_MAX_ASK_RESULT_BYTES = 1024 * 1024
_MAX_ASK_RESULT_CITATIONS = 64
_MAX_ASK_RESULT_ANSWER_BYTES = 128 * 1024
_MAX_ASK_RESULT_EXCERPT_BYTES = 8 * 1024
_ASK_RESULT_KEYS = frozenset(
    {
        "schema_version",
        "run_id",
        "query_sha256",
        "answer",
        "citations",
        "evidence_gap",
        "context_bytes",
        "proposal",
    }
)
_ASK_CITATION_KEYS = frozenset({"path", "sha256", "excerpt", "block"})
_ASK_PROPOSAL_KEYS = frozenset({"artifact", "plan"})

_READ_GRANT: Mapping[str, object] = {
    "flow_id": "ask",
    "action_id": "retrieve-cited-evidence",
    "actor": "runtime",
    "authority": "read",
    "target": "vault:knowledge",
    "access": "read",
    "effect_kind": "read-only",
    "artifact_commit": False,
}
_PROPOSAL_GRANT: Mapping[str, object] = {
    "flow_id": "ask",
    "action_id": "optional-file-back-proposal",
    "actor": "runtime",
    "authority": "proposal",
    "target": "vault:review",
    "access": "write",
    "effect_kind": "proposal-commit",
    "artifact_commit": True,
}


class AskError(ValueError):
    """The ask input, evidence tree, or authority is unsafe."""


def _fail(message: str) -> None:
    raise AskError(message)


@dataclass(frozen=True)
class AskLimits:
    """Explicit retrieval and context budgets."""

    max_files: int = 512
    max_entries: int = 2048
    max_file_bytes: int = 128 * 1024
    max_total_bytes: int = 2 * 1024 * 1024
    max_context_bytes: int = 32 * 1024
    max_citations: int = 8
    max_excerpt_bytes: int = 2048
    max_depth: int = 16

    def validate(self) -> None:
        fields = (
            self.max_files,
            self.max_entries,
            self.max_file_bytes,
            self.max_total_bytes,
            self.max_context_bytes,
            self.max_citations,
            self.max_excerpt_bytes,
            self.max_depth,
        )
        if any(type(value) is not int or value < 1 for value in fields):
            _fail("ask limits must be positive exact integers")
        if self.max_file_bytes > self.max_total_bytes:
            _fail("per-file budget cannot exceed the total retrieval budget")
        if self.max_excerpt_bytes > self.max_context_bytes:
            _fail("excerpt budget cannot exceed the context budget")
        if self.max_depth > 64:
            _fail("ask path depth is too large")


@dataclass(frozen=True)
class AskCitation:
    path: str
    sha256: str
    excerpt: str
    block: int


@dataclass(frozen=True)
class AskFileBack:
    """An explicit proposed create/update, never a write request."""

    review_id: str
    created_at: str
    operation: str
    path: str
    content: str


@dataclass(frozen=True)
class AskProposal:
    artifact: ReviewArtifact
    plan: MutationPlan


@dataclass(frozen=True)
class AskResult:
    schema_version: int
    run_id: str
    query_sha256: str
    answer: str
    citations: tuple[AskCitation, ...]
    evidence_gap: bool
    context_bytes: int
    proposal: AskProposal | None = None


def _canonical_context_bytes(
    answer: str, citations: tuple[AskCitation, ...]
) -> bytes:
    payload = {
        "schema_version": ASK_SCHEMA_VERSION,
        "answer": answer,
        "citations": [
            {
                "block": citation.block,
                "excerpt": citation.excerpt,
                "path": citation.path,
                "sha256": citation.sha256,
            }
            for citation in citations
        ],
    }
    try:
        return json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError):
        raise AskError("ask context is not canonical JSON") from None


def render_ask_context(result: AskResult) -> bytes:
    """Render the exact canonical context whose size is budgeted by ask."""

    if not isinstance(result, AskResult):
        _fail("ask context requires an AskResult")
    return _canonical_context_bytes(result.answer, result.citations)


def _ask_result_payload(result: AskResult) -> dict[str, object]:
    return {
        "schema_version": result.schema_version,
        "run_id": result.run_id,
        "query_sha256": result.query_sha256,
        "answer": result.answer,
        "citations": [
            {
                "path": item.path,
                "sha256": item.sha256,
                "excerpt": item.excerpt,
                "block": item.block,
            }
            for item in result.citations
        ],
        "evidence_gap": result.evidence_gap,
        "context_bytes": result.context_bytes,
        "proposal": (
            None
            if result.proposal is None
            else {
                "artifact": render_review_artifact(result.proposal.artifact),
                "plan": render_mutation_plan(result.proposal.plan).decode("utf-8"),
            }
        ),
    }


def _canonical_result_bytes(payload: Mapping[str, object]) -> bytes:
    try:
        raw = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError):
        _fail("ask result is not canonical JSON")
    if len(raw) + 1 > _MAX_ASK_RESULT_BYTES:
        _fail("ask result is too large")
    return raw + b"\n"


def _result_text(
    value: object,
    label: str,
    *,
    maximum: int,
    allow_layout: bool = False,
) -> str:
    if (
        not isinstance(value, str)
        or not value
        or _encoded_size(value, label) > maximum
        or _has_control(value, allow_layout=allow_layout)
        or _contains_private_or_secret(value)
    ):
        _fail(f"{label} must be bounded privacy-safe text")
    return value


def _citation_path(value: object) -> str:
    text = _result_text(value, "citation path", maximum=4096)
    if (
        not text
        or "\\" in text
        or unicodedata.normalize("NFC", text) != text
        or _contains_sensitive_path(text)
    ):
        _fail("citation path is invalid")
    path = PurePosixPath(text)
    if (
        path.is_absolute()
        or path.as_posix() != text
        or len(path.parts) < 2
        or path.parts[0] != "knowledge"
        or ".." in path.parts
        or path.suffix not in _TEXT_SUFFIXES
        or any(part in ARCHIVE_COMPONENTS or part.startswith(".") for part in path.parts)
    ):
        _fail("citation path must name human knowledge")
    for part in path.parts:
        _safe_name(part)
    return text


def parse_ask_result(raw: str | bytes) -> AskResult:
    """Parse exact canonical durable ask output without trusting caller objects."""

    if isinstance(raw, str):
        try:
            encoded = raw.encode("utf-8")
        except UnicodeError:
            _fail("ask result is not valid UTF-8")
    elif isinstance(raw, bytes):
        encoded = raw
    else:
        _fail("ask result must be bytes or text")
    if not encoded or len(encoded) > _MAX_ASK_RESULT_BYTES:
        _fail("ask result is empty or too large")
    try:
        text = encoded.decode("utf-8")
        payload = json.loads(text, object_pairs_hook=_json_object)
    except AskError:
        raise
    except (UnicodeError, ValueError, RecursionError):
        _fail("ask result is not valid JSON")
    if not isinstance(payload, Mapping) or set(payload) != _ASK_RESULT_KEYS:
        _fail("ask result has missing or unknown fields")
    if _canonical_result_bytes(payload) != encoded:
        _fail("ask result must use exact canonical JSON encoding")
    if type(payload["schema_version"]) is not int or payload["schema_version"] != ASK_SCHEMA_VERSION:
        _fail("unsupported ask result schema_version")
    run_id = payload["run_id"]
    if not isinstance(run_id, str) or _RUN_ID.fullmatch(run_id) is None:
        _fail("ask result run_id is invalid")
    query_hash = payload["query_sha256"]
    if not isinstance(query_hash, str) or _SHA256.fullmatch(query_hash) is None:
        _fail("ask result query_sha256 is invalid")
    answer = _result_text(
        payload["answer"],
        "ask result answer",
        maximum=_MAX_ASK_RESULT_ANSWER_BYTES,
        allow_layout=True,
    )
    citations_raw = payload["citations"]
    if (
        not isinstance(citations_raw, list)
        or len(citations_raw) > _MAX_ASK_RESULT_CITATIONS
    ):
        _fail("ask result citations must be a bounded list")
    citations: list[AskCitation] = []
    seen: set[tuple[str, int]] = set()
    for value in citations_raw:
        if not isinstance(value, Mapping) or set(value) != _ASK_CITATION_KEYS:
            _fail("ask result citation has missing or unknown fields")
        path = _citation_path(value["path"])
        digest = value["sha256"]
        if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
            _fail("ask result citation sha256 is invalid")
        excerpt = _result_text(
            value["excerpt"],
            "ask result citation excerpt",
            maximum=_MAX_ASK_RESULT_EXCERPT_BYTES,
        )
        block = value["block"]
        if type(block) is not int or block < 1:
            _fail("ask result citation block is invalid")
        if (path, block) in seen:
            _fail("ask result citations contain a duplicate block")
        seen.add((path, block))
        citations.append(AskCitation(path, digest, excerpt, block))
    evidence_gap = payload["evidence_gap"]
    if not isinstance(evidence_gap, bool) or evidence_gap != (not citations):
        _fail("ask result evidence_gap disagrees with citations")
    context_bytes = payload["context_bytes"]
    if type(context_bytes) is not int or context_bytes < 1:
        _fail("ask result context_bytes is invalid")
    checked_citations = tuple(citations)
    if context_bytes != len(_canonical_context_bytes(answer, checked_citations)):
        _fail("ask result context_bytes disagrees with exact context")

    proposal_raw = payload["proposal"]
    proposal: AskProposal | None = None
    if proposal_raw is not None:
        if not isinstance(proposal_raw, Mapping) or set(proposal_raw) != _ASK_PROPOSAL_KEYS:
            _fail("ask result proposal has missing or unknown fields")
        artifact_text = proposal_raw["artifact"]
        plan_text = proposal_raw["plan"]
        if not isinstance(artifact_text, str) or not isinstance(plan_text, str):
            _fail("ask result proposal must contain canonical text artifacts")
        try:
            artifact = parse_review_artifact(artifact_text)
            plan = parse_mutation_plan(plan_text.encode("utf-8"))
            validate_artifact_plan(artifact, plan)
        except ReviewArtifactError as error:
            raise AskError("ask result proposal violates the review contract") from error
        if artifact.provenance.run_id != run_id:
            _fail("ask result proposal belongs to a different run")
        if (
            render_review_artifact(artifact) != artifact_text
            or render_mutation_plan(plan).decode("utf-8") != plan_text
        ):
            _fail("ask result proposal must contain exact canonical artifacts")
        citation_hashes = tuple(sorted((item.path, item.sha256) for item in citations))
        if artifact.provenance.source_hashes != citation_hashes:
            _fail("ask result proposal provenance disagrees with citations")
        proposal = AskProposal(artifact=artifact, plan=plan)

    return AskResult(
        schema_version=ASK_SCHEMA_VERSION,
        run_id=run_id,
        query_sha256=query_hash,
        answer=answer,
        citations=checked_citations,
        evidence_gap=evidence_gap,
        context_bytes=context_bytes,
        proposal=proposal,
    )


def render_ask_result(result: AskResult) -> bytes:
    """Render one canonical durable ask result terminated by a newline."""

    if not isinstance(result, AskResult):
        _fail("ask result has invalid type")
    try:
        candidate = _canonical_result_bytes(_ask_result_payload(result))
    except ReviewArtifactError as error:
        raise AskError("ask result proposal violates the review contract") from error
    checked = parse_ask_result(candidate)
    if checked != result:
        _fail("ask result cannot be rendered canonically")
    return candidate


def publish_ask_result(run_store: RunStore, result: AskResult) -> PreparedArtifact:
    """Publish exact replay-safe bytes inside the owning run directory."""

    if not isinstance(run_store, RunStore):
        _fail("ask result publisher requires a RunStore")
    try:
        state = run_store.status(result.run_id)
    except RunError:
        raise AskError("ask result publisher requires an existing valid run") from None
    if state["flow"] != "ask":
        _fail("ask result publisher requires its owning ask run")
    raw = render_ask_result(result)
    try:
        return run_store.prepare_run_artifact(
            result.run_id,
            name="ask-result",
            data=raw,
            maximum_bytes=_MAX_ASK_RESULT_BYTES,
        )
    except RunError:
        raise AskError("ask result could not be published safely") from None


@dataclass(frozen=True)
class _Candidate:
    path: str
    sha256: str
    excerpt: str
    block: int
    phrase: int
    unique_terms: int
    occurrences: int


@dataclass(frozen=True)
class _ParentAnchor:
    fd: int
    leaf: str
    owned_fds: tuple[int, ...]
    links: tuple[tuple[int, str, int, tuple[int, int]], ...]


def _has_control(value: str, *, allow_layout: bool = False) -> bool:
    for character in value:
        if allow_layout and character in {"\n", "\r", "\t"}:
            continue
        category = unicodedata.category(character)
        if category.startswith("C") or category in {"Zl", "Zp"}:
            return True
    return False


def _encoded_size(value: str, label: str) -> int:
    try:
        return len(value.encode("utf-8"))
    except UnicodeError:
        _fail(f"{label} is not valid UTF-8 text")


def _contains_private_or_secret(value: str) -> bool:
    return any(marker in value for marker in _PRIVATE_MARKERS) or _SECRET.search(value) is not None


def _contains_sensitive_path(value: str) -> bool:
    return _contains_private_or_secret(value) or any(
        _SENSITIVE_PATH_COMPONENT.search(part) is not None
        for part in PurePosixPath(value).parts
    )


def _safe_query(query: object) -> tuple[str, tuple[str, ...]]:
    if (
        not isinstance(query, str)
        or not query
        or query.strip() != query
        or _encoded_size(query, "query") > _MAX_QUERY_BYTES
        or _has_control(query)
        or _contains_private_or_secret(query)
    ):
        _fail("query must be bounded privacy-safe text")
    terms = tuple(
        sorted(
            term
            for term in set(_WORD.findall(query.casefold()))
            if term not in _STOPWORDS
        )
    )
    if not terms:
        _fail("query must contain searchable terms")
    return query, terms


def _safe_name(name: str) -> None:
    if (
        not name
        or name in {".", ".."}
        or "/" in name
        or "\\" in name
        or _has_control(name)
        or unicodedata.normalize("NFC", name) != name
        or _encoded_size(name, "knowledge path component") > 255
    ):
        _fail("knowledge tree contains an unsafe path component")


def _open_directory_at(parent_fd: int, name: str) -> int:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        child_fd = os.open(name, flags, dir_fd=parent_fd)
        opened = os.fstat(child_fd)
        named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError:
        if "child_fd" in locals():
            os.close(child_fd)
        raise AskError("knowledge directory cannot be anchored safely") from None
    if not stat.S_ISDIR(opened.st_mode) or (
        opened.st_dev,
        opened.st_ino,
    ) != (named.st_dev, named.st_ino):
        os.close(child_fd)
        _fail("knowledge directory changed while it was opened")
    return child_fd


def _read_regular_at(parent_fd: int, name: str, maximum: int) -> tuple[bytes, tuple[int, int]]:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(name, flags, dir_fd=parent_fd)
        before = os.fstat(fd)
        named_before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if not stat.S_ISREG(before.st_mode) or (
            before.st_dev,
            before.st_ino,
        ) != (named_before.st_dev, named_before.st_ino):
            _fail("knowledge file changed while it was opened")
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
            _fail("knowledge file exceeds the per-file budget")
        after = os.fstat(fd)
        named_after = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        identity = (before.st_dev, before.st_ino)
        if (
            identity != (after.st_dev, after.st_ino)
            or identity != (named_after.st_dev, named_after.st_ino)
            or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
        ):
            _fail("knowledge file changed while it was read")
        return raw, identity
    except AskError:
        raise
    except OSError:
        raise AskError("knowledge file cannot be read safely") from None
    finally:
        if "fd" in locals():
            os.close(fd)


def _validate_json_shape(value: object, maximum_depth: int) -> None:
    stack: list[tuple[object, int]] = [(value, 0)]
    nodes = 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes > _MAX_JSON_NODES or depth > maximum_depth:
            _fail("structured knowledge is too deep or complex")
        if item is None or isinstance(item, bool) or type(item) is int:
            continue
        if type(item) is float:
            if not math.isfinite(item):
                _fail("structured knowledge contains a non-finite number")
            continue
        if isinstance(item, str):
            if _encoded_size(item, "structured knowledge string") > _MAX_LINE_BYTES:
                _fail("structured knowledge contains an oversized string")
            continue
        if isinstance(item, list):
            stack.extend((child, depth + 1) for child in reversed(item))
            continue
        if isinstance(item, dict):
            for key, child in reversed(tuple(item.items())):
                if not isinstance(key, str) or _has_control(key):
                    _fail("structured knowledge contains an unsafe field")
                stack.append((child, depth + 1))
            continue
        _fail("structured knowledge contains an unsupported value")


def _json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            _fail("structured knowledge contains a duplicate field")
        value[key] = item
    return value


def _decode_document(raw: bytes, suffix: str, maximum_depth: int) -> str:
    try:
        text = raw.decode("utf-8")
    except UnicodeError:
        raise AskError("knowledge file is not valid UTF-8") from None
    if "\x00" in text or _has_control(text, allow_layout=True):
        _fail("knowledge file contains invalid control characters")
    for line in text.splitlines():
        if _encoded_size(line, "knowledge line") > _MAX_LINE_BYTES:
            _fail("knowledge file contains an oversized line")
    if suffix == ".json":
        try:
            value = json.loads(text, object_pairs_hook=_json_object)
        except AskError:
            raise
        except (ValueError, RecursionError):
            raise AskError("structured knowledge is malformed") from None
        _validate_json_shape(value, maximum_depth)
    elif suffix == ".jsonl":
        for line in text.splitlines():
            if not line.strip():
                continue
            try:
                value = json.loads(line, object_pairs_hook=_json_object)
            except AskError:
                raise
            except (ValueError, RecursionError):
                raise AskError("structured knowledge is malformed") from None
            _validate_json_shape(value, maximum_depth)
    return text


def _excerpt(line: str, terms: tuple[str, ...], maximum: int) -> str:
    normalized = " ".join(line.split())
    raw = normalized.encode("utf-8")
    if len(raw) <= maximum:
        return normalized
    folded = normalized.casefold()
    positions = [folded.find(term) for term in terms if folded.find(term) >= 0]
    character_start = max(0, min(positions, default=0) - maximum // 4)
    candidate = normalized[character_start:]
    encoded = candidate.encode("utf-8")[:maximum]
    while True:
        try:
            bounded = encoded.decode("utf-8")
            break
        except UnicodeDecodeError:
            encoded = encoded[:-1]
    return bounded.strip()


def _best_candidate(
    text: str,
    path: str,
    digest: str,
    query: str,
    terms: tuple[str, ...],
    limits: AskLimits,
) -> _Candidate | None:
    best: _Candidate | None = None
    query_folded = query.casefold()
    for block, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        folded = stripped.casefold()
        word_counts = Counter(_WORD.findall(folded))
        matches = tuple(term for term in terms if term in word_counts)
        if not matches:
            continue
        excerpt = _excerpt(stripped, terms, limits.max_excerpt_bytes)
        if not excerpt or _contains_private_or_secret(excerpt):
            continue
        candidate = _Candidate(
            path=path,
            sha256=digest,
            excerpt=excerpt,
            block=block,
            phrase=int(query_folded in folded),
            unique_terms=len(matches),
            occurrences=sum(word_counts.get(term, 0) for term in terms),
        )
        if best is None or (
            -candidate.phrase,
            -candidate.unique_terms,
            -candidate.occurrences,
            candidate.block,
        ) < (
            -best.phrase,
            -best.unique_terms,
            -best.occurrences,
            best.block,
        ):
            best = candidate
    return best


def _verify_directory_entry(parent_fd: int, name: str, identity: tuple[int, int]) -> None:
    try:
        current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError:
        raise AskError("knowledge directory changed during retrieval") from None
    if not stat.S_ISDIR(current.st_mode) or (current.st_dev, current.st_ino) != identity:
        _fail("knowledge directory changed during retrieval")


class AskFlow:
    """Retrieve cited human evidence under one exact read capability."""

    def __init__(
        self,
        resolver: VaultPathResolver,
        *,
        policy: AuthorityPolicy,
        limits: AskLimits | None = None,
    ) -> None:
        if not isinstance(resolver, VaultPathResolver):
            _fail("ask requires a vault path resolver")
        if not isinstance(policy, AuthorityPolicy):
            _fail("ask requires an authority policy")
        self._resolver = resolver
        self._policy = policy
        self._limits = limits or AskLimits()
        self._limits.validate()

    def _require_capability(
        self, capability: ActionCapability, expected: Mapping[str, object]
    ) -> None:
        try:
            grant = self._policy.require(capability)
        except AuthorityError as error:
            raise AskError(str(error)) from None
        if any(getattr(grant, field) != value for field, value in expected.items()):
            _fail("capability does not authorize the exact ask action")

    def _open_knowledge(self) -> tuple[Path, int, tuple[int, int]]:
        try:
            path = self._resolver.resolve("knowledge", must_exist=True)
            flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(path, flags)
            opened = os.fstat(fd)
            named = os.stat(path, follow_symlinks=False)
            if not stat.S_ISDIR(opened.st_mode) or (
                opened.st_dev,
                opened.st_ino,
            ) != (named.st_dev, named.st_ino):
                _fail("knowledge root changed while it was opened")
            self._resolver.revalidate(path, "knowledge", must_exist=True)
            return path, fd, (opened.st_dev, opened.st_ino)
        except AskError:
            if "fd" in locals():
                os.close(fd)
            raise
        except (OSError, VaultSchemaError):
            if "fd" in locals():
                os.close(fd)
            raise AskError("knowledge root cannot be anchored safely") from None

    def _revalidate_root(self, path: Path, fd: int, identity: tuple[int, int]) -> None:
        try:
            opened = os.fstat(fd)
            named = os.stat(path, follow_symlinks=False)
            self._resolver.revalidate(path, "knowledge", must_exist=True)
        except (OSError, VaultSchemaError):
            raise AskError("knowledge root changed during retrieval") from None
        if (
            not stat.S_ISDIR(opened.st_mode)
            or identity != (opened.st_dev, opened.st_ino)
            or identity != (named.st_dev, named.st_ino)
        ):
            _fail("knowledge root changed during retrieval")

    def _collect(
        self,
        root_fd: int,
        query: str,
        terms: tuple[str, ...],
    ) -> tuple[list[_Candidate], int]:
        candidates: list[_Candidate] = []
        total_bytes = 0
        file_count = 0
        entry_count = 0

        def walk(directory_fd: int, parts: tuple[str, ...]) -> None:
            nonlocal total_bytes, file_count, entry_count
            if len(parts) > self._limits.max_depth:
                _fail("knowledge tree exceeds the path depth budget")
            try:
                names: list[str] = []
                with os.scandir(directory_fd) as entries:
                    for entry in entries:
                        names.append(entry.name)
                        entry_count += 1
                        if entry_count > self._limits.max_entries:
                            _fail("knowledge tree exceeds the entry-count budget")
                names.sort()
            except AskError:
                raise
            except OSError:
                raise AskError("knowledge directory cannot be listed safely") from None
            for name in names:
                _safe_name(name)
                try:
                    metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                except OSError:
                    raise AskError("knowledge entry changed during retrieval") from None
                if stat.S_ISLNK(metadata.st_mode):
                    _fail("knowledge tree contains a symlink")
                if stat.S_ISDIR(metadata.st_mode):
                    if name in ARCHIVE_COMPONENTS or name.startswith("."):
                        continue
                    child_fd = _open_directory_at(directory_fd, name)
                    identity = (metadata.st_dev, metadata.st_ino)
                    try:
                        walk(child_fd, parts + (name,))
                        _verify_directory_entry(directory_fd, name, identity)
                    finally:
                        os.close(child_fd)
                    continue
                if not stat.S_ISREG(metadata.st_mode):
                    _fail("knowledge tree contains an unsupported entry")
                suffix = PurePosixPath(name).suffix.casefold()
                if suffix not in _TEXT_SUFFIXES:
                    continue
                file_count += 1
                if file_count > self._limits.max_files:
                    _fail("knowledge tree exceeds the file-count budget")
                raw, _ = _read_regular_at(directory_fd, name, self._limits.max_file_bytes)
                total_bytes += len(raw)
                if total_bytes > self._limits.max_total_bytes:
                    _fail("knowledge tree exceeds the total retrieval budget")
                relative = PurePosixPath(*parts, name).as_posix()
                cited_path = f"knowledge/{relative}"
                text = _decode_document(raw, suffix, self._limits.max_depth)
                digest = hashlib.sha256(raw).hexdigest()
                candidate = _best_candidate(
                    text, cited_path, digest, query, terms, self._limits
                )
                if candidate is not None:
                    candidates.append(candidate)

        walk(root_fd, ())
        candidates.sort(
            key=lambda item: (
                -item.phrase,
                -item.unique_terms,
                -item.occurrences,
                item.path,
                item.block,
            )
        )
        return candidates, total_bytes

    def _portable_entry_exists(self, directory_fd: int, requested: str) -> bool:
        folded = unicodedata.normalize("NFC", requested).casefold()
        matches: list[str] = []
        try:
            with os.scandir(directory_fd) as entries:
                for index, entry in enumerate(entries, start=1):
                    if index > self._limits.max_entries:
                        _fail("knowledge directory exceeds the entry-count budget")
                    _safe_name(entry.name)
                    if unicodedata.normalize("NFC", entry.name).casefold() == folded:
                        matches.append(entry.name)
        except AskError:
            raise
        except OSError:
            raise AskError("knowledge directory cannot be compared safely") from None
        if not matches:
            return False
        if len(matches) != 1 or matches[0] != requested:
            _fail("file-back path collides in the portable namespace")
        return True

    def _open_parent(
        self,
        root_fd: int,
        relative: PurePosixPath,
        *,
        portable_namespace: bool = False,
    ) -> _ParentAnchor | None:
        current_fd = os.dup(root_fd)
        owned_fds = [current_fd]
        links: list[tuple[int, str, int, tuple[int, int]]] = []
        try:
            for part in relative.parts[:-1]:
                _safe_name(part)
                if portable_namespace and not self._portable_entry_exists(
                    current_fd, part
                ):
                    for owned in reversed(owned_fds):
                        os.close(owned)
                    return None
                try:
                    next_fd = _open_directory_at(current_fd, part)
                except AskError:
                    try:
                        os.stat(part, dir_fd=current_fd, follow_symlinks=False)
                    except FileNotFoundError:
                        for owned in reversed(owned_fds):
                            os.close(owned)
                        return None
                    raise
                metadata = os.fstat(next_fd)
                links.append(
                    (
                        current_fd,
                        part,
                        next_fd,
                        (metadata.st_dev, metadata.st_ino),
                    )
                )
                owned_fds.append(next_fd)
                current_fd = next_fd
            return _ParentAnchor(
                fd=current_fd,
                leaf=relative.parts[-1],
                owned_fds=tuple(owned_fds),
                links=tuple(links),
            )
        except Exception:
            for owned in reversed(owned_fds):
                os.close(owned)
            raise

    @staticmethod
    def _revalidate_parent(anchor: _ParentAnchor) -> None:
        for parent_fd, name, child_fd, identity in anchor.links:
            try:
                opened = os.fstat(child_fd)
                named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            except OSError:
                raise AskError("knowledge path changed during retrieval") from None
            if (
                not stat.S_ISDIR(opened.st_mode)
                or identity != (opened.st_dev, opened.st_ino)
                or identity != (named.st_dev, named.st_ino)
            ):
                _fail("knowledge path changed during retrieval")

    @staticmethod
    def _close_parent(anchor: _ParentAnchor) -> None:
        for fd in reversed(anchor.owned_fds):
            os.close(fd)

    def _read_relative(self, root_fd: int, cited_path: str) -> bytes:
        path = PurePosixPath(cited_path)
        if len(path.parts) < 2 or path.parts[0] != "knowledge" or ".." in path.parts:
            _fail("citation path is outside human knowledge")
        relative = PurePosixPath(*path.parts[1:])
        opened = self._open_parent(root_fd, relative)
        if opened is None:
            _fail("cited evidence no longer exists")
        try:
            raw, _ = _read_regular_at(opened.fd, opened.leaf, self._limits.max_file_bytes)
            self._revalidate_parent(opened)
            return raw
        finally:
            self._close_parent(opened)

    def _select(self, candidates: list[_Candidate]) -> tuple[AskCitation, ...]:
        selected: list[AskCitation] = []
        gap_size = len(_canonical_context_bytes(self._answer(()), ()))
        if gap_size > self._limits.max_context_bytes:
            _fail("context budget is too small for an honest gap result")
        for candidate in candidates:
            citation = AskCitation(
                path=candidate.path,
                sha256=candidate.sha256,
                excerpt=candidate.excerpt,
                block=candidate.block,
            )
            proposed = tuple((*selected, citation))
            proposed_size = len(
                _canonical_context_bytes(self._answer(proposed), proposed)
            )
            if proposed_size > self._limits.max_context_bytes:
                continue
            selected.append(citation)
            if len(selected) == self._limits.max_citations:
                break
        return tuple(selected)

    @staticmethod
    def _answer(citations: tuple[AskCitation, ...]) -> str:
        if not citations:
            return "Human knowledge does not contain enough evidence to answer."
        lines = ["Evidence from human knowledge:"]
        lines.extend(
            f"- {item.excerpt} [{item.path} sha256:{item.sha256}]"
            for item in citations
        )
        answer = "\n".join(lines)
        if _contains_private_or_secret(answer):
            _fail("retrieved answer is not privacy-safe")
        return answer

    @staticmethod
    def _file_back_path(value: object) -> PurePosixPath:
        if (
            not isinstance(value, str)
            or "\\" in value
            or _has_control(value)
            or unicodedata.normalize("NFC", value) != value
            or _contains_sensitive_path(value)
        ):
            _fail("file-back path is invalid")
        path = PurePosixPath(value)
        if (
            path.is_absolute()
            or path.as_posix() != value
            or len(path.parts) < 2
            or path.parts[0] != "knowledge"
            or ".." in path.parts
            or path.suffix != ".md"
            or any(part in ARCHIVE_COMPONENTS or part.startswith(".") for part in path.parts)
        ):
            _fail("file-back path must name active Markdown human knowledge")
        for part in path.parts:
            _safe_name(part)
        return PurePosixPath(*path.parts[1:])

    def _target_precondition(
        self, root_fd: int, request: AskFileBack, relative: PurePosixPath
    ) -> str | None:
        opened = self._open_parent(
            root_fd, relative, portable_namespace=True
        )
        if opened is None:
            if request.operation == "update":
                _fail("file-back update target does not exist")
            return None
        try:
            leaf_exists = self._portable_entry_exists(opened.fd, opened.leaf)
            if not leaf_exists:
                if request.operation == "update":
                    _fail("file-back update target does not exist")
                self._revalidate_parent(opened)
                return None
            try:
                metadata = os.stat(
                    opened.leaf, dir_fd=opened.fd, follow_symlinks=False
                )
            except FileNotFoundError:
                if request.operation == "update":
                    _fail("file-back update target does not exist")
                self._revalidate_parent(opened)
                return None
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
                _fail("file-back target is not a safe regular file")
            if request.operation == "create":
                _fail("file-back create target already exists")
            raw, _ = _read_regular_at(
                opened.fd, opened.leaf, self._limits.max_file_bytes
            )
            self._revalidate_parent(opened)
            return hashlib.sha256(raw).hexdigest()
        finally:
            self._close_parent(opened)

    def _proposal(
        self,
        root_fd: int,
        request: AskFileBack,
        *,
        run_id: str,
        query_sha256: str,
        citations: tuple[AskCitation, ...],
    ) -> AskProposal:
        if not isinstance(request, AskFileBack):
            _fail("file-back request has invalid type")
        if not citations:
            _fail("file-back proposal requires cited evidence")
        if request.operation not in {"create", "update"}:
            _fail("file-back operation must be create or update")
        if not isinstance(request.review_id, str) or _REVIEW_ID.fullmatch(request.review_id) is None:
            _fail("file-back review id is invalid")
        if not isinstance(request.created_at, str) or _UTC.fullmatch(request.created_at) is None:
            _fail("file-back timestamp is invalid")
        if (
            not isinstance(request.content, str)
            or _encoded_size(request.content, "file-back content") > _MAX_FILE_BACK_BYTES
            or "\x00" in request.content
            or _has_control(request.content, allow_layout=True)
            or _contains_private_or_secret(request.content)
        ):
            _fail("file-back content must be bounded privacy-safe text")
        relative = self._file_back_path(request.path)
        precondition = self._target_precondition(root_fd, request, relative)
        source_refs = tuple(item.path for item in citations)
        sources = tuple(SourceRef(kind="vault-note", ref=ref) for ref in source_refs)
        provenance = Provenance(
            run_id=run_id,
            source_hashes=tuple(sorted((item.path, item.sha256) for item in citations)),
        )
        evidence_lines = "\n".join(
            f"- `{item.path}` (`sha256:{item.sha256}`)" for item in citations
        )
        body = (
            "# Ask file-back proposal\n\n"
            f"Question hash: `sha256:{query_sha256}`\n\n"
            f"Target: `{request.path}`\n\n"
            "## Evidence\n\n"
            f"{evidence_lines}\n\n"
            "## Proposed content\n\n"
            f"{request.content}"
        )
        artifact = ReviewArtifact(
            schema_version=1,
            review_id=request.review_id,
            status="proposed",
            flow="ask",
            created_at=request.created_at,
            surface=self._resolver.config.surface,
            sources=sources,
            provenance=provenance,
            plan_path=f".lifeos/review-plans/{request.review_id}.json",
            body=body,
        )
        operation = MutationOperation(
            op=request.operation,
            path=request.path,
            destination_path=None,
            source_refs=source_refs,
            precondition_sha256=precondition,
            postcondition_sha256=hashlib.sha256(request.content.encode("utf-8")).hexdigest(),
            content=request.content,
        )
        plan = MutationPlan(
            schema_version=1,
            review_id=request.review_id,
            review_body_sha256=review_body_sha256(body),
            provenance_sha256=provenance_sha256(provenance),
            operations=(operation,),
        )
        try:
            validate_artifact_plan(artifact, plan)
        except ReviewArtifactError as error:
            raise AskError("file-back proposal violates the review contract") from error
        return AskProposal(artifact=artifact, plan=plan)

    def ask(
        self,
        query: str,
        *,
        run_id: str,
        read_capability: ActionCapability,
        file_back: AskFileBack | None = None,
        proposal_capability: ActionCapability | None = None,
    ) -> AskResult:
        """Return a deterministic cited answer and optional in-memory proposal."""

        self._require_capability(read_capability, _READ_GRANT)
        checked_query, terms = _safe_query(query)
        if not isinstance(run_id, str) or _RUN_ID.fullmatch(run_id) is None:
            _fail("run_id is invalid")
        if file_back is None and proposal_capability is not None:
            _fail("proposal capability is unused without file-back")
        if file_back is not None:
            if proposal_capability is None:
                _fail("file-back requires proposal authority")
            self._require_capability(proposal_capability, _PROPOSAL_GRANT)

        knowledge_path, root_fd, identity = self._open_knowledge()
        try:
            candidates, _ = self._collect(root_fd, checked_query, terms)
            citations = self._select(candidates)
            query_sha256 = hashlib.sha256(checked_query.encode("utf-8")).hexdigest()
            proposal = (
                self._proposal(
                    root_fd,
                    file_back,
                    run_id=run_id,
                    query_sha256=query_sha256,
                    citations=citations,
                )
                if file_back is not None
                else None
            )
            if file_back is not None and proposal is not None:
                relative = self._file_back_path(file_back.path)
                current_precondition = self._target_precondition(
                    root_fd, file_back, relative
                )
                if (
                    current_precondition
                    != proposal.plan.operations[0].precondition_sha256
                ):
                    _fail("file-back target changed while the proposal was built")
            for citation in citations:
                raw = self._read_relative(root_fd, citation.path)
                if hashlib.sha256(raw).hexdigest() != citation.sha256:
                    _fail("cited evidence changed during retrieval")
            self._revalidate_root(knowledge_path, root_fd, identity)
        finally:
            os.close(root_fd)

        answer = self._answer(citations)
        context_bytes = len(_canonical_context_bytes(answer, citations))
        if context_bytes > self._limits.max_context_bytes:  # pragma: no cover - invariant
            _fail("ask context exceeds its validated budget")
        return AskResult(
            schema_version=ASK_SCHEMA_VERSION,
            run_id=run_id,
            query_sha256=query_sha256,
            answer=answer,
            citations=citations,
            evidence_gap=not citations,
            context_bytes=context_bytes,
            proposal=proposal,
        )
