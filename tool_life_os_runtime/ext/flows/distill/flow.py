"""Evidence-bound distillation from an accepted llm-wiki topic snapshot.

The connector owns filesystem validation and stale topic detection.  This flow
accepts its detached ``TopicSnapshot``, rechecks all hashes it consumes, builds
one exact bounded task packet, and treats executor output as untrusted data.
It has no knowledge or review writer: the only result is an in-memory review
artifact and mutation plan for a later explicit persistence/review phase.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
import json
from pathlib import PurePosixPath
import re
from typing import Mapping, Protocol, Sequence
import unicodedata

from tool_life_os_runtime.ext.connectors.llmwiki import (
    HashedRecord,
    TopicSnapshot,
    WikiPage,
)
from tool_life_os_runtime.ext.review.artifact import (
    MutationOperation,
    MutationPlan,
    Provenance,
    ReviewArtifact,
    ReviewArtifactError,
    SourceRef,
    provenance_sha256,
    review_body_sha256,
    validate_artifact_plan,
)
from tool_life_os_runtime.ext.review.authority import (
    ActionCapability,
    AuthorityError,
    AuthorityPolicy,
)
from tool_life_os_runtime.ext.runs import RunError, RunStore
from tool_life_os_runtime.ext.vault.schema import ARCHIVE_COMPONENTS


DISTILL_TASK_SCHEMA_VERSION = 1
DISTILL_OUTPUT_SCHEMA_VERSION = 1

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_TOPIC_REF = re.compile(r"^sha256:[0-9a-f]{64}$")
_CLAIM_ID = re.compile(r"^clm_[0-9a-f]{12}$")
_SOURCE_ID = re.compile(r"^src_[0-9a-f]{12}$")
_REVIEW_ID = re.compile(r"^rev_[a-z0-9][a-z0-9_-]{0,62}$")
_RUN_ID = re.compile(r"^run_[a-z0-9][a-z0-9_-]{0,62}$")
_STATEMENT_ID = re.compile(r"^stmt_[a-z0-9][a-z0-9_-]{0,62}$")
_SPEC_VERSION = re.compile(r"^0\.1\.\d+$")
_CONFIDENCES = frozenset({"high", "medium", "low"})
_SOURCE_KINDS = frozenset(
    {"web", "youtube", "telegram", "paper", "book", "repo", "dataset", "local", "other"}
)
_STANCES = frozenset({"supports", "contradicts", "mentions"})
_LOCATOR_TYPES = frozenset({"block", "heading", "timestamp", "page", "line", "other"})
_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$")
_PRIVATE_MARKERS = ("/users/", "/home/")
_FILE_SCHEME = re.compile(r"(?:^|[^a-z0-9_])file:")
_SECRET = re.compile(
    r"(?i)(?:"
    r"(?:api[_ -]?key|authorization|bearer|cookie|credential|password|secret|token)"
    r"[\"']?\s*[:=]"
    r"|sk-[a-z0-9_-]{12,}"
    r"|gh[pousr]_[a-z0-9]{20,}"
    r"|akia[a-z0-9]{16}"
    r"|eyj[a-z0-9_-]{12,}\.[a-z0-9_-]{12,}"
    r"|-----begin [a-z ]*private key-----"
    r")"
)
_SENSITIVE_COMPONENT = re.compile(
    r"(?i)(?:^|[^a-z0-9])"
    r"(?:api[-_ ]?key|authorization|cookie|credential|password|secret|token)"
    r"(?:$|[^a-z0-9])"
)

_PROPOSAL_GRANT: Mapping[str, object] = {
    "flow_id": "distill",
    "action_id": "commit-review-proposal",
    "actor": "runtime",
    "authority": "proposal",
    "target": "vault:review",
    "access": "write",
    "effect_kind": "proposal-commit",
    "artifact_commit": True,
}
_ACCEPTANCE_CHECKS = (
    "output schema_version and task_packet_sha256 match this packet",
    "every statement names known claim_ids and their selected source block_refs",
    "all selected claims and blocks are covered by the proposal",
    "target is a create-only active Markdown path under knowledge",
    "no private path, credential, secret, or unbounded prose is returned",
)


class DistillError(ValueError):
    """The snapshot, context, executor output, or proposal is unsafe."""


def _fail(message: str) -> None:
    raise DistillError(message)


@dataclass(frozen=True)
class DistillLimits:
    """Exact context and output bounds, independent from any model."""

    max_context_bytes: int = 64 * 1024
    max_claims: int = 48
    max_blocks: int = 48
    max_block_bytes: int = 4096
    max_output_bytes: int = 128 * 1024
    max_statements: int = 48
    max_statement_bytes: int = 4096
    max_proposal_bytes: int = 128 * 1024
    min_synthesis_bytes: int = 96

    def validate(self) -> None:
        values = (
            self.max_context_bytes,
            self.max_claims,
            self.max_blocks,
            self.max_block_bytes,
            self.max_output_bytes,
            self.max_statements,
            self.max_statement_bytes,
            self.max_proposal_bytes,
            self.min_synthesis_bytes,
        )
        if any(type(value) is not int or value < 1 for value in values):
            _fail("distill limits must be positive exact integers")
        if self.max_block_bytes > self.max_context_bytes:
            _fail("source block bound cannot exceed the context budget")
        if self.max_statement_bytes > self.max_output_bytes:
            _fail("statement bound cannot exceed the output budget")
        if self.min_synthesis_bytes > self.max_proposal_bytes:
            _fail("minimum synthesis cannot exceed the proposal budget")
        if self.max_claims + self.max_blocks + 1 > 128:
            _fail("distill evidence count exceeds the review artifact contract")


@dataclass(frozen=True)
class DistillEvidenceAnchor:
    source_id: str
    block_ref: str
    quote_sha256: str
    stance: str


@dataclass(frozen=True)
class DistillClaimAnchor:
    claim_id: str
    text: str
    confidence: str
    record_sha256: str
    evidence: DistillEvidenceAnchor


@dataclass(frozen=True)
class DistillSourceManifest:
    source_id: str
    kind: str
    title: str
    record_sha256: str
    content_sha256: str


@dataclass(frozen=True)
class DistillContextBlock:
    block_ref: str
    source_id: str
    line: int
    text: str
    sha256: str
    byte_length: int


@dataclass(frozen=True)
class DistillContextManifest:
    schema_version: int
    budget_bytes: int
    used_bytes: int
    source_text_bytes: int
    claim_ids: tuple[str, ...]
    block_refs: tuple[str, ...]


@dataclass(frozen=True)
class DistillTaskPacket:
    schema_version: int
    output_schema_version: int
    flow_id: str
    run_id: str
    action_id: str
    authority: str
    target: str
    topic_ref: str
    topic_snapshot_sha256: str
    topic_manifest_sha256: str
    topic_title: str
    run_state_sha256: str | None
    claims: tuple[DistillClaimAnchor, ...]
    sources: tuple[DistillSourceManifest, ...]
    blocks: tuple[DistillContextBlock, ...]
    context: DistillContextManifest
    acceptance_checks: tuple[str, ...]


class DistillExecutor(Protocol):
    """Harness-neutral executor boundary; bytes in and versioned bytes out."""

    def execute(self, task_packet: bytes) -> bytes | str | Mapping[str, object]: ...


@dataclass(frozen=True)
class DistillProposal:
    artifact: ReviewArtifact
    plan: MutationPlan


@dataclass(frozen=True)
class DistillResult:
    schema_version: int
    task_packet: DistillTaskPacket
    task_packet_sha256: str
    proposal: DistillProposal
    run_state_sha256: str | None


@dataclass(frozen=True)
class _Candidate:
    claim: DistillClaimAnchor
    source: DistillSourceManifest
    block: DistillContextBlock


@dataclass(frozen=True)
class _Statement:
    statement_id: str
    text: str
    claim_ids: tuple[str, ...]
    block_refs: tuple[str, ...]


def _has_control(value: str, *, allow_layout: bool = False) -> bool:
    for character in value:
        if allow_layout and character in {"\n", "\r", "\t"}:
            continue
        category = unicodedata.category(character)
        if category.startswith("C") or category in {"Zl", "Zp"}:
            return True
    return False


def _utf8_bytes(value: object, label: str) -> bytes:
    if not isinstance(value, str):
        _fail(f"{label} is not valid UTF-8 text")
    try:
        return value.encode("utf-8")
    except UnicodeError:
        _fail(f"{label} is not valid UTF-8 text")


def _encoded_size(value: str, label: str) -> int:
    return len(_utf8_bytes(value, label))


def _is_private_or_secret(value: str) -> bool:
    folded = unicodedata.normalize("NFC", value).casefold()
    portable = folded.replace("\\/", "/").replace("\\", "/")
    if any(marker in portable for marker in _PRIVATE_MARKERS) or _FILE_SCHEME.search(portable):
        return True
    if _SECRET.search(value) is not None:
        return True
    for token in portable.split():
        if "/" not in token:
            continue
        if any(
            _SENSITIVE_COMPONENT.search(component) is not None
            for component in PurePosixPath(token.strip("`'\"()[]{}<>,.;:")).parts
        ):
            return True
    return False


def _text(
    value: object,
    label: str,
    *,
    maximum: int,
    minimum: int = 1,
    pattern: re.Pattern[str] | None = None,
    allow_layout: bool = False,
) -> str:
    if not isinstance(value, str):
        _fail(f"{label} must be bounded privacy-safe text")
    size = _encoded_size(value, label)
    if (
        size < minimum
        or size > maximum
        or _has_control(value, allow_layout=allow_layout)
        or _is_private_or_secret(value)
        or (pattern is not None and pattern.fullmatch(value) is None)
    ):
        _fail(f"{label} must be bounded privacy-safe text")
    return value


def _sha256(value: object, label: str) -> str:
    return _text(value, label, maximum=64, pattern=_SHA256)


def _canonical_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError):
        raise DistillError("distill value is not canonical JSON") from None


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _evidence_payload(value: DistillEvidenceAnchor) -> dict[str, object]:
    return {
        "block_ref": value.block_ref,
        "quote_sha256": value.quote_sha256,
        "source_id": value.source_id,
        "stance": value.stance,
    }


def _claim_payload(value: DistillClaimAnchor) -> dict[str, object]:
    return {
        "claim_id": value.claim_id,
        "confidence": value.confidence,
        "evidence": _evidence_payload(value.evidence),
        "record_sha256": value.record_sha256,
        "text": value.text,
    }


def _source_payload(value: DistillSourceManifest) -> dict[str, object]:
    return {
        "content_sha256": value.content_sha256,
        "kind": value.kind,
        "record_sha256": value.record_sha256,
        "source_id": value.source_id,
        "title": value.title,
    }


def _block_payload(value: DistillContextBlock) -> dict[str, object]:
    return {
        "block_ref": value.block_ref,
        "byte_length": value.byte_length,
        "line": value.line,
        "sha256": value.sha256,
        "source_id": value.source_id,
        "text": value.text,
    }


def _task_packet_payload(packet: DistillTaskPacket) -> dict[str, object]:
    return {
        "acceptance_checks": list(packet.acceptance_checks),
        "action_id": packet.action_id,
        "authority": packet.authority,
        "blocks": [_block_payload(value) for value in packet.blocks],
        "claims": [_claim_payload(value) for value in packet.claims],
        "context": {
            "schema_version": packet.context.schema_version,
            "budget_bytes": packet.context.budget_bytes,
            "used_bytes": packet.context.used_bytes,
            "source_text_bytes": packet.context.source_text_bytes,
            "claim_ids": list(packet.context.claim_ids),
            "block_refs": list(packet.context.block_refs),
        },
        "flow_id": packet.flow_id,
        "output_schema_version": packet.output_schema_version,
        "run_id": packet.run_id,
        "run_state_sha256": packet.run_state_sha256,
        "schema_version": packet.schema_version,
        "sources": [_source_payload(value) for value in packet.sources],
        "target": packet.target,
        "topic_manifest_sha256": packet.topic_manifest_sha256,
        "topic_ref": packet.topic_ref,
        "topic_snapshot_sha256": packet.topic_snapshot_sha256,
        "topic_title": packet.topic_title,
    }


def render_distill_task_packet(packet: DistillTaskPacket) -> bytes:
    """Return the exact canonical bytes counted by the context manifest."""

    if not isinstance(packet, DistillTaskPacket):
        _fail("distill task packet has invalid type")
    return _canonical_bytes(_task_packet_payload(packet))


def _packet_with_exact_usage(packet: DistillTaskPacket) -> DistillTaskPacket:
    current = packet
    for _ in range(16):
        actual = len(render_distill_task_packet(current))
        if actual == current.context.used_bytes:
            return current
        current = replace(
            current,
            context=replace(current.context, used_bytes=actual),
        )
    _fail("distill context byte accounting did not converge")


def _object_no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            _fail("executor output contains duplicate fields")
        result[key] = value
    return result


def _exact_object(
    value: object, label: str, keys: frozenset[str]
) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        _fail(f"{label} has missing or unknown fields")
    return value


def _string_list(
    value: object,
    label: str,
    *,
    maximum: int,
    pattern: re.Pattern[str] | None = None,
) -> tuple[str, ...]:
    if not isinstance(value, list) or not value or len(value) > maximum:
        _fail(f"{label} must be a bounded non-empty list")
    checked = tuple(
        _text(item, f"{label} item", maximum=256, pattern=pattern)
        for item in value
    )
    if len(set(checked)) != len(checked):
        _fail(f"{label} contains duplicates")
    return checked


def _normalize_for_match(value: str) -> str:
    return " ".join(value.casefold().split())


def _source_stable_hash(record: HashedRecord) -> tuple[str, str | None]:
    if not isinstance(record.payload, dict):
        _fail("machine source payload is malformed")
    payload_hash = _digest(record.payload)
    if record.payload_sha256 != payload_hash:
        _fail("machine source payload hash is stale")
    content_hash = (
        None
        if record.content is None
        else hashlib.sha256(_utf8_bytes(record.content, "machine source content")).hexdigest()
    )
    if record.content_sha256 != content_hash:
        _fail("machine source content hash is stale")
    stable = _digest(
        {
            "content_sha256": content_hash,
            "payload_sha256": payload_hash,
        }
    )
    if record.sha256 != stable:
        _fail("machine source stable hash is stale")
    return stable, content_hash


def _frontmatter_scalar(value: object) -> str:
    if not isinstance(value, str):
        _fail("machine wiki frontmatter is malformed")
    _utf8_bytes(value, "machine wiki frontmatter")
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
        raise DistillError("machine wiki frontmatter is malformed") from None


def _wiki_page_content_hash(page: WikiPage) -> str:
    if not isinstance(page.frontmatter, dict) or set(page.frontmatter) != {
        "id",
        "title",
        "claims",
        "updated_at",
    }:
        _fail("machine wiki frontmatter is malformed")
    lines = ["---\n"]
    for key, value in page.frontmatter.items():
        if not isinstance(key, str) or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]*", key) is None:
            _fail("machine wiki frontmatter is malformed")
        if isinstance(value, list):
            lines.append(f"{key}:\n")
            lines.extend(f"  - {_frontmatter_scalar(item)}\n" for item in value)
        else:
            lines.append(f"{key}: {_frontmatter_scalar(value)}\n")
    if not isinstance(page.body, str):
        _fail("machine wiki body is malformed")
    body = page.body.strip("\n")
    _utf8_bytes(body, "machine wiki body")
    lines.append("---\n")
    if body:
        lines.extend(("\n", body, "\n"))
    return hashlib.sha256(_utf8_bytes("".join(lines), "machine wiki page")).hexdigest()


def _validate_snapshot(snapshot: TopicSnapshot) -> tuple[dict[str, HashedRecord], list[HashedRecord]]:
    if (
        not isinstance(snapshot, TopicSnapshot)
        or type(snapshot.schema_version) is not int
        or snapshot.schema_version != 1
    ):
        _fail("distill requires a supported TopicSnapshot")
    _text(snapshot.spec_version, "topic spec version", maximum=32, pattern=_SPEC_VERSION)
    _text(snapshot.topic_ref, "topic ref", maximum=71, pattern=_TOPIC_REF)
    snapshot_hash = _sha256(snapshot.snapshot_sha256, "topic snapshot hash")
    if not isinstance(snapshot.manifest, dict):
        _fail("machine topic manifest is malformed")
    manifest_hash = _digest(snapshot.manifest)
    if manifest_hash != snapshot.manifest_sha256:
        _fail("machine topic manifest hash is stale")
    title = snapshot.manifest.get("topic")
    _text(title, "topic title", maximum=1024, allow_layout=True)

    sources: dict[str, HashedRecord] = {}
    actual_source_hashes: list[tuple[str, str]] = []
    for record in snapshot.sources:
        if not isinstance(record, HashedRecord):
            _fail("machine source record has invalid type")
        source_id = _text(record.record_id, "source id", maximum=16, pattern=_SOURCE_ID)
        if source_id in sources or record.payload.get("id") != source_id:
            _fail("machine source identity is invalid")
        stable, _ = _source_stable_hash(record)
        sources[source_id] = record
        actual_source_hashes.append((source_id, stable))
    if tuple(actual_source_hashes) != snapshot.source_hashes:
        _fail("machine source hash manifest is stale")

    active_claims: list[HashedRecord] = []
    claim_hashes: list[tuple[str, str]] = []
    seen_claims: set[str] = set()
    for record in snapshot.final_claims:
        if not isinstance(record, HashedRecord):
            _fail("machine claim record has invalid type")
        if not isinstance(record.payload, dict):
            _fail("machine claim payload is malformed")
        claim_id = _text(record.record_id, "claim id", maximum=16, pattern=_CLAIM_ID)
        payload_hash = _digest(record.payload)
        if (
            claim_id in seen_claims
            or record.payload.get("id") != claim_id
            or record.payload_sha256 != payload_hash
            or record.sha256 != payload_hash
            or record.content is not None
            or record.content_sha256 is not None
        ):
            _fail("machine claim hash or identity is stale")
        seen_claims.add(claim_id)
        claim_hashes.append((claim_id, payload_hash))
        status = record.payload.get("status")
        if status in {"verified", "final"}:
            active_claims.append(record)
        elif status != "retracted":
            _fail("machine final claim has unsupported status")

    wiki_hashes: list[tuple[str, str]] = []
    for page in snapshot.wiki_pages:
        if not isinstance(page, WikiPage):
            _fail("machine wiki page has invalid type")
        relative = _text(page.relative_ref, "wiki ref", maximum=4096)
        stored_page_hash = _sha256(page.sha256, "wiki page hash")
        content_hash = _wiki_page_content_hash(page)
        if content_hash != stored_page_hash:
            _fail("machine wiki page hash is stale")
        wiki_hashes.append((relative, content_hash))
    expected_snapshot = _digest(
        {
            "schema_version": 1,
            "spec_version": snapshot.spec_version,
            "manifest_sha256": manifest_hash,
            "sources": actual_source_hashes,
            "final_claims": claim_hashes,
            "wiki_pages": wiki_hashes,
        }
    )
    if expected_snapshot != snapshot_hash:
        _fail("machine topic snapshot hash is stale")
    if not active_claims:
        _fail("machine topic has no active final claims")
    return sources, active_claims


def _candidate_for_claim(
    record: HashedRecord,
    sources: Mapping[str, HashedRecord],
    limits: DistillLimits,
) -> _Candidate:
    claim_id = record.record_id
    claim_text = _text(
        record.payload.get("text"),
        "claim text",
        maximum=16 * 1024,
        allow_layout=True,
    )
    confidence = _text(record.payload.get("confidence"), "claim confidence", maximum=16)
    if confidence not in _CONFIDENCES:
        _fail("claim confidence is unsupported")
    evidence = record.payload.get("evidence")
    if not isinstance(evidence, list) or not evidence:
        _fail("active claim is missing evidence")

    selected: tuple[HashedRecord, str, str, int] | None = None
    for item in evidence:
        if (
            not isinstance(item, dict)
            or not {"source_id", "quote", "stance"}.issubset(item)
            or set(item) - {"source_id", "quote", "stance", "locator"}
        ):
            _fail("claim evidence is malformed")
        source_id = item.get("source_id")
        quote = item.get("quote")
        stance = item.get("stance")
        if (
            not isinstance(source_id, str)
            or _SOURCE_ID.fullmatch(source_id) is None
            or not isinstance(quote, str)
            or not quote
            or not isinstance(stance, str)
            or stance not in _STANCES
        ):
            _fail("claim evidence is malformed")
        if "locator" in item:
            locator = item["locator"]
            if (
                not isinstance(locator, dict)
                or set(locator) != {"type", "value"}
                or locator.get("type") not in _LOCATOR_TYPES
                or not isinstance(locator.get("value"), str)
                or not locator["value"]
            ):
                _fail("claim evidence is malformed")
        if source_id not in sources:
            _fail("claim evidence references a missing source")
        if stance != "supports":
            continue
        safe_quote = _text(quote, "evidence quote", maximum=16 * 1024, allow_layout=True)
        source = sources[source_id]
        if source.content is None:
            continue
        needle = _normalize_for_match(safe_quote)
        for line_number, line in enumerate(source.content.splitlines(), start=1):
            if not line.strip() or needle not in _normalize_for_match(line):
                continue
            if _encoded_size(line, "source block") > limits.max_block_bytes:
                continue
            _text(line, "source block", maximum=limits.max_block_bytes)
            selected = (source, safe_quote, line, line_number)
            break
        if selected is not None:
            break
    if selected is None:
        _fail("active claim has no safe self-contained supporting source block")

    source, quote, line, line_number = selected
    source_id = source.record_id
    stable_hash, content_hash = _source_stable_hash(source)
    if content_hash is None:
        _fail("selected source has no self-contained content")
    kind = _text(source.payload.get("kind"), "source kind", maximum=32)
    if kind not in _SOURCE_KINDS:
        _fail("source kind is unsupported")
    title = _text(source.payload.get("title"), "source title", maximum=1024, allow_layout=True)
    block_ref = f"sources/{source_id}/lines/{line_number}"
    block_hash = hashlib.sha256(line.encode("utf-8")).hexdigest()
    block = DistillContextBlock(
        block_ref=block_ref,
        source_id=source_id,
        line=line_number,
        text=line,
        sha256=block_hash,
        byte_length=len(line.encode("utf-8")),
    )
    manifest = DistillSourceManifest(
        source_id=source_id,
        kind=kind,
        title=title,
        record_sha256=stable_hash,
        content_sha256=content_hash,
    )
    claim = DistillClaimAnchor(
        claim_id=claim_id,
        text=claim_text,
        confidence=confidence,
        record_sha256=record.sha256,
        evidence=DistillEvidenceAnchor(
            source_id=source_id,
            block_ref=block_ref,
            quote_sha256=hashlib.sha256(quote.encode("utf-8")).hexdigest(),
            stance="supports",
        ),
    )
    return _Candidate(claim=claim, source=manifest, block=block)


def _base_packet(
    snapshot: TopicSnapshot,
    *,
    run_id: str,
    run_state_sha256: str | None,
    limits: DistillLimits,
    claims: Sequence[DistillClaimAnchor],
    sources: Sequence[DistillSourceManifest],
    blocks: Sequence[DistillContextBlock],
) -> DistillTaskPacket:
    manifest = DistillContextManifest(
        schema_version=1,
        budget_bytes=limits.max_context_bytes,
        used_bytes=0,
        source_text_bytes=sum(item.byte_length for item in blocks),
        claim_ids=tuple(item.claim_id for item in claims),
        block_refs=tuple(item.block_ref for item in blocks),
    )
    packet = DistillTaskPacket(
        schema_version=DISTILL_TASK_SCHEMA_VERSION,
        output_schema_version=DISTILL_OUTPUT_SCHEMA_VERSION,
        flow_id="distill",
        run_id=run_id,
        action_id="commit-review-proposal",
        authority="proposal",
        target="vault:review",
        topic_ref=snapshot.topic_ref,
        topic_snapshot_sha256=snapshot.snapshot_sha256,
        topic_manifest_sha256=snapshot.manifest_sha256,
        topic_title=str(snapshot.manifest["topic"]),
        run_state_sha256=run_state_sha256,
        claims=tuple(claims),
        sources=tuple(sources),
        blocks=tuple(blocks),
        context=manifest,
        acceptance_checks=_ACCEPTANCE_CHECKS,
    )
    return _packet_with_exact_usage(packet)


class DistillFlow:
    """Prepare one bounded packet and validate one evidence-bound proposal."""

    def __init__(
        self,
        *,
        policy: AuthorityPolicy,
        executor: DistillExecutor,
        limits: DistillLimits | None = None,
        run_store: RunStore | None = None,
    ) -> None:
        if not isinstance(policy, AuthorityPolicy):
            _fail("distill requires an authority policy")
        if not callable(getattr(executor, "execute", None)):
            _fail("distill requires an explicit executor")
        if run_store is not None and not isinstance(run_store, RunStore):
            _fail("distill run store has invalid type")
        self._policy = policy
        self._executor = executor
        self._limits = limits or DistillLimits()
        self._limits.validate()
        self._run_store = run_store

    def _require_proposal(self, capability: ActionCapability) -> None:
        try:
            grant = self._policy.require(capability)
        except AuthorityError as error:
            raise DistillError(str(error)) from None
        if any(getattr(grant, field) != expected for field, expected in _PROPOSAL_GRANT.items()):
            _fail("capability does not authorize the exact distill proposal action")

    def _run_binding(self, run_id: str, snapshot_hash: str) -> str | None:
        if self._run_store is None:
            return None
        try:
            state = self._run_store.status(run_id)
        except RunError as error:
            raise DistillError("distill run state is unavailable") from error
        if (
            state.get("run_id") != run_id
            or state.get("flow") != "distill"
            or state.get("status") != "running"
            or state.get("authority") != "proposal"
            or not isinstance(state.get("input"), dict)
            or state["input"].get("topic_snapshot_sha256") != snapshot_hash
        ):
            _fail("distill run state is not bound to the active topic snapshot")
        return _digest(state)

    def prepare_task_packet(
        self,
        snapshot: TopicSnapshot,
        *,
        run_id: str,
        proposal_capability: ActionCapability,
    ) -> DistillTaskPacket:
        """Validate and select exact claim/source context without invoking a model."""

        self._require_proposal(proposal_capability)
        checked_run_id = _text(run_id, "run id", maximum=64, pattern=_RUN_ID)
        sources, active_claims = _validate_snapshot(snapshot)
        run_state_hash = self._run_binding(checked_run_id, snapshot.snapshot_sha256)
        candidates = [
            _candidate_for_claim(record, sources, self._limits)
            for record in sorted(active_claims, key=lambda item: item.record_id)
        ]

        selected_claims: list[DistillClaimAnchor] = []
        selected_sources: dict[str, DistillSourceManifest] = {}
        selected_blocks: dict[str, DistillContextBlock] = {}
        for candidate in candidates:
            if len(selected_claims) == self._limits.max_claims:
                break
            trial_sources = dict(selected_sources)
            trial_sources[candidate.source.source_id] = candidate.source
            trial_blocks = dict(selected_blocks)
            trial_blocks[candidate.block.block_ref] = candidate.block
            if len(trial_blocks) > self._limits.max_blocks:
                continue
            trial_claims = [*selected_claims, candidate.claim]
            trial = _base_packet(
                snapshot,
                run_id=checked_run_id,
                run_state_sha256=run_state_hash,
                limits=self._limits,
                claims=trial_claims,
                sources=tuple(trial_sources[key] for key in sorted(trial_sources)),
                blocks=tuple(trial_blocks[key] for key in sorted(trial_blocks)),
            )
            if trial.context.used_bytes > self._limits.max_context_bytes:
                continue
            selected_claims = trial_claims
            selected_sources = trial_sources
            selected_blocks = trial_blocks

        if not selected_claims:
            _fail("distill context budget cannot fit one evidence-bound claim")
        packet = _base_packet(
            snapshot,
            run_id=checked_run_id,
            run_state_sha256=run_state_hash,
            limits=self._limits,
            claims=selected_claims,
            sources=tuple(selected_sources[key] for key in sorted(selected_sources)),
            blocks=tuple(selected_blocks[key] for key in sorted(selected_blocks)),
        )
        if packet.context.used_bytes != len(render_distill_task_packet(packet)):
            _fail("distill context byte accounting is inconsistent")
        return packet

    def _executor_output(
        self, packet: DistillTaskPacket, packet_hash: str
    ) -> tuple[str, str, tuple[_Statement, ...]]:
        try:
            raw = self._executor.execute(render_distill_task_packet(packet))
        except Exception:
            raise DistillError("distill executor failed") from None
        if isinstance(raw, Mapping):
            encoded = _canonical_bytes(raw)
        elif isinstance(raw, str):
            try:
                encoded = raw.encode("utf-8")
            except UnicodeError:
                _fail("executor output is not valid UTF-8")
        elif isinstance(raw, bytes):
            encoded = raw
        else:
            _fail("executor output has invalid type")
        if len(encoded) > self._limits.max_output_bytes:
            _fail("executor output exceeds its byte budget")
        try:
            value = json.loads(encoded.decode("utf-8"), object_pairs_hook=_object_no_duplicates)
        except DistillError:
            raise
        except (UnicodeError, ValueError, RecursionError):
            raise DistillError("executor output is not valid JSON") from None
        payload = _exact_object(
            value,
            "executor output",
            frozenset(
                {
                    "schema_version",
                    "task_packet_sha256",
                    "target_path",
                    "title",
                    "statements",
                }
            ),
        )
        if type(payload["schema_version"]) is not int or payload["schema_version"] != 1:
            _fail("executor output schema_version is unsupported")
        if payload["task_packet_sha256"] != packet_hash:
            _fail("executor output is bound to a different task packet")
        title = _text(payload["title"], "proposal title", maximum=256)
        target_path = self._target_path(payload["target_path"])
        rows = payload["statements"]
        if not isinstance(rows, list) or not rows or len(rows) > self._limits.max_statements:
            _fail("executor statements must be a bounded non-empty list")

        known_claims = {item.claim_id: item for item in packet.claims}
        known_blocks = {item.block_ref: item for item in packet.blocks}
        statements: list[_Statement] = []
        statement_ids: set[str] = set()
        used_claims: set[str] = set()
        used_blocks: set[str] = set()
        for row in rows:
            item = _exact_object(
                row,
                "executor statement",
                frozenset({"statement_id", "text", "claim_ids", "block_refs"}),
            )
            statement_id = _text(
                item["statement_id"],
                "statement id",
                maximum=64,
                pattern=_STATEMENT_ID,
            )
            if statement_id in statement_ids:
                _fail("executor statement ids must be unique")
            statement_ids.add(statement_id)
            text = _text(
                item["text"],
                "statement text",
                maximum=self._limits.max_statement_bytes,
                minimum=16,
            )
            claim_ids = _string_list(
                item["claim_ids"],
                "statement claim ids",
                maximum=self._limits.max_claims,
                pattern=_CLAIM_ID,
            )
            block_refs = _string_list(
                item["block_refs"],
                "statement block refs",
                maximum=self._limits.max_blocks,
            )
            if any(claim_id not in known_claims for claim_id in claim_ids):
                _fail("executor statement references an unknown claim")
            if any(block_ref not in known_blocks for block_ref in block_refs):
                _fail("executor statement references an unknown source block")
            required_refs = {
                known_claims[claim_id].evidence.block_ref for claim_id in claim_ids
            }
            if set(block_refs) != required_refs:
                _fail("executor statement block refs do not exactly match its claim evidence")
            used_claims.update(claim_ids)
            used_blocks.update(block_refs)
            statements.append(_Statement(statement_id, text, claim_ids, block_refs))

        if used_claims != set(known_claims) or used_blocks != set(known_blocks):
            _fail("executor proposal does not cover all selected evidence")
        if sum(_encoded_size(item.text, "statement text") for item in statements) < self._limits.min_synthesis_bytes:
            _fail("executor proposal is skeleton-only")
        return target_path, title, tuple(statements)

    @staticmethod
    def _target_path(value: object) -> str:
        text = _text(value, "proposal target path", maximum=4096)
        if "\\" in text or unicodedata.normalize("NFC", text) != text:
            _fail("proposal target path is not portable")
        path = PurePosixPath(text)
        if (
            path.is_absolute()
            or path.as_posix() != text
            or len(path.parts) < 2
            or len(path.parts) > 16
            or path.parts[0] != "knowledge"
            or ".." in path.parts
            or path.suffix != ".md"
            or any(part.startswith(".") for part in path.parts)
            or any(
                unicodedata.normalize("NFC", part).casefold() in ARCHIVE_COMPONENTS
                for part in path.parts
            )
            or any(_SENSITIVE_COMPONENT.search(part) is not None for part in path.parts)
        ):
            _fail("proposal target must be active Markdown human knowledge")
        for part in path.parts:
            if _encoded_size(part, "proposal path component") > 255:
                _fail("proposal target path component is too long")
        return text

    def _proposal(
        self,
        packet: DistillTaskPacket,
        packet_hash: str,
        *,
        target_path: str,
        title: str,
        statements: tuple[_Statement, ...],
        review_id: str,
        created_at: str,
        surface: str,
    ) -> DistillProposal:
        _text(review_id, "review id", maximum=64, pattern=_REVIEW_ID)
        _text(created_at, "review timestamp", maximum=32, pattern=_UTC)
        _text(surface, "review surface", maximum=16)
        block_by_ref = {item.block_ref: item for item in packet.blocks}
        content_lines = [f"# {title}", ""]
        for statement in statements:
            claims = ", ".join(f"`{item}`" for item in statement.claim_ids)
            evidence = ", ".join(
                f"`{ref}` (`sha256:{block_by_ref[ref].sha256}`)"
                for ref in statement.block_refs
            )
            content_lines.extend(
                (
                    f"- {statement.text}",
                    f"  - Claims: {claims}",
                    f"  - Evidence: {evidence}",
                )
            )
        content = "\n".join(content_lines).rstrip() + "\n"
        if _encoded_size(content, "proposal content") > self._limits.max_proposal_bytes:
            _fail("distill proposal exceeds its content budget")

        snapshot_ref = f"machine-snapshot/snapshot-{packet.topic_snapshot_sha256}"
        evidence_hashes: dict[str, str] = {snapshot_ref: packet.topic_snapshot_sha256}
        source_types: dict[str, str] = {snapshot_ref: "machine-topic"}
        for claim in packet.claims:
            ref = f"machine-claim/claim-{claim.claim_id}"
            evidence_hashes[ref] = claim.record_sha256
            source_types[ref] = "machine-claim"
        for block in packet.blocks:
            ref = f"machine-block/block-{block.source_id}-{block.line}"
            evidence_hashes[ref] = block.sha256
            source_types[ref] = "machine-block"
        source_refs = tuple(sorted(evidence_hashes))
        sources = tuple(SourceRef(kind=source_types[ref], ref=ref) for ref in source_refs)
        provenance = Provenance(
            run_id=packet.run_id,
            source_hashes=tuple((ref, evidence_hashes[ref]) for ref in source_refs),
        )
        evidence_lines = "\n".join(
            f"- `{ref}` (`sha256:{evidence_hashes[ref]}`)" for ref in source_refs
        )
        body = (
            "# Distill proposal\n\n"
            f"Task packet: `sha256:{packet_hash}`\n\n"
            f"Machine snapshot: `sha256:{packet.topic_snapshot_sha256}`\n\n"
            f"Target: `{target_path}`\n\n"
            "## Proposed knowledge\n\n"
            f"{content}\n"
            "## Evidence manifest\n\n"
            f"{evidence_lines}\n"
        )
        artifact = ReviewArtifact(
            schema_version=1,
            review_id=review_id,
            status="proposed",
            flow="distill",
            created_at=created_at,
            surface=surface,
            sources=sources,
            provenance=provenance,
            plan_path=f".lifeos/review-plans/{review_id}.json",
            body=body,
        )
        operation = MutationOperation(
            op="create",
            path=target_path,
            destination_path=None,
            source_refs=source_refs,
            precondition_sha256=None,
            postcondition_sha256=hashlib.sha256(content.encode("utf-8")).hexdigest(),
            content=content,
        )
        plan = MutationPlan(
            schema_version=1,
            review_id=review_id,
            review_body_sha256=review_body_sha256(body),
            provenance_sha256=provenance_sha256(provenance),
            operations=(operation,),
        )
        try:
            validate_artifact_plan(artifact, plan)
        except ReviewArtifactError as error:
            raise DistillError("distill proposal violates the review contract") from error
        return DistillProposal(artifact=artifact, plan=plan)

    def distill(
        self,
        snapshot: TopicSnapshot,
        *,
        run_id: str,
        review_id: str,
        created_at: str,
        surface: str,
        proposal_capability: ActionCapability,
    ) -> DistillResult:
        """Execute one bounded synthesis and return only an in-memory proposal."""

        packet = self.prepare_task_packet(
            snapshot,
            run_id=run_id,
            proposal_capability=proposal_capability,
        )
        packet_bytes = render_distill_task_packet(packet)
        packet_hash = hashlib.sha256(packet_bytes).hexdigest()
        target_path, title, statements = self._executor_output(packet, packet_hash)
        proposal = self._proposal(
            packet,
            packet_hash,
            target_path=target_path,
            title=title,
            statements=statements,
            review_id=review_id,
            created_at=created_at,
            surface=surface,
        )
        _validate_snapshot(snapshot)
        current_run_hash = self._run_binding(run_id, snapshot.snapshot_sha256)
        if current_run_hash != packet.run_state_sha256:
            _fail("distill run state changed while synthesis was executing")
        return DistillResult(
            schema_version=1,
            task_packet=packet,
            task_packet_sha256=packet_hash,
            proposal=proposal,
            run_state_sha256=current_run_hash,
        )
