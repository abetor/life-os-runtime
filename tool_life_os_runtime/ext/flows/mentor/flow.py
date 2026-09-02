"""Bounded mentor context and immutable review proposals.

The runtime may read only explicitly named active files. Model output is a
strict review record: this module has no project, knowledge, or memory write
path.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
from typing import Callable, Mapping, Protocol
import unicodedata
import uuid

from tool_life_os_runtime.ext.review.authority import (
    ActionCapability,
    AuthorityError,
    AuthorityPolicy,
)
from tool_life_os_runtime.ext.runs import (
    ActionUse,
    CommittedArtifact,
    PreparedArtifact,
    RunError,
    RunStore,
)
from tool_life_os_runtime.ext.vault.schema import VaultPathResolver, VaultSchemaError


MENTOR_SCHEMA_VERSION = 1
_MAX_JSON = 512 * 1024
_ID = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
_RUN_ID = re.compile(r"^run_[a-z0-9][a-z0-9_-]{0,62}$")
_PROPOSAL_ID = re.compile(r"^mentor-[a-z0-9][a-z0-9_-]{0,55}$")
_SHA = re.compile(r"^[0-9a-f]{64}$")
_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$")
_PRIVATE_PATH = re.compile(r"(?:/users/|/home/|[a-z]:[\\/](?:users|home)[\\/])")
_FILE_SCHEME = re.compile(r"(?:^|[^a-z0-9_])file:")
_ARCHIVES = frozenset({"_archive", "_trash", "_on_hold"})
_TEXT_SUFFIXES = frozenset({".json", ".jsonl", ".md", ".txt"})
_ZONE_CONFIG_NAMES = {
    "projects": "projects",
    "knowledge": "knowledge",
    "agent/memory": "memory",
}
_MAX_REF_PARTS = 32


class MentorFlowError(ValueError):
    """Mentor input, output, authority, or durable evidence is invalid."""


def _fail(message: str) -> None:
    raise MentorFlowError(message)


def _text(
    value: object, label: str, maximum: int = 8192, *, layout: bool = False
) -> str:
    if type(value) is not str or not value:
        _fail(f"{label} is invalid")
    try:
        encoded = value.encode("utf-8")
    except UnicodeError:
        _fail(f"{label} is invalid")
    if len(encoded) > maximum:
        _fail(f"{label} is invalid")
    if unicodedata.normalize("NFC", value) != value or any(
        (unicodedata.category(char).startswith("C") and not (layout and char in "\n\t"))
        or unicodedata.category(char) in {"Zl", "Zp"}
        for char in value
    ):
        _fail(f"{label} is invalid")
    lowered = value.casefold()
    if _PRIVATE_PATH.search(lowered) or _FILE_SCHEME.search(lowered):
        _fail(f"{label} contains a private path")
    return value


def _identifier(value: object, label: str, pattern: re.Pattern[str] = _ID) -> str:
    checked = _text(value, label, 128)
    if pattern.fullmatch(checked) is None:
        _fail(f"{label} is invalid")
    return checked


def _timestamp(value: object, label: str) -> str:
    checked = _text(value, label, 40)
    if _UTC.fullmatch(checked) is None:
        _fail(f"{label} must be UTC")
    try:
        datetime.fromisoformat(checked[:-1] + "+00:00")
    except ValueError:
        _fail(f"{label} must be UTC")
    return checked


def _hash(value: object, label: str) -> str:
    checked = _text(value, label, 64)
    if _SHA.fullmatch(checked) is None:
        _fail(f"{label} is invalid")
    return checked


def _exact_int(value: object, label: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        _fail(f"{label} is invalid")
    return value


def _ref(value: object, label: str) -> str:
    checked = _text(value, label, 2048)
    if "\\" in checked:
        _fail(f"{label} is invalid")
    path = PurePosixPath(checked)
    if (
        path.is_absolute()
        or path == PurePosixPath(".")
        or path.as_posix() != checked
        or ".." in path.parts
        or len(path.parts) > _MAX_REF_PARTS
        or any(len(part.encode("utf-8")) > 255 for part in path.parts)
        or any(
            part.startswith(".") or part.casefold() in _ARCHIVES for part in path.parts
        )
        or path.suffix.casefold() not in _TEXT_SUFFIXES
    ):
        _fail(f"{label} is invalid")
    return checked


def _canonical(value: object, maximum: int = _MAX_JSON) -> bytes:
    try:
        raw = (
            json.dumps(
                value,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
            + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError):
        _fail("mentor payload is not canonical JSON")
    if len(raw) > maximum:
        _fail("mentor payload is too large")
    return raw


def _pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            _fail("mentor JSON has duplicate fields")
        result[key] = value
    return result


def _decode(raw: bytes | str, label: str, maximum: int = _MAX_JSON) -> object:
    if isinstance(raw, str):
        try:
            source = raw.encode("utf-8")
        except UnicodeError:
            _fail(f"{label} is invalid")
    elif isinstance(raw, bytes):
        source = raw
    else:
        _fail(f"{label} is invalid")
    if not source or len(source) > maximum:
        _fail(f"{label} is invalid")
    try:
        return json.loads(source, object_pairs_hook=_pairs)
    except MentorFlowError:
        raise
    except (UnicodeError, ValueError, RecursionError):
        _fail(f"{label} is invalid")


def _mapping(value: object, label: str, keys: frozenset[str]) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or set(value) != keys:
        _fail(f"{label} has missing or unknown fields")
    return value


def _string_tuple(
    value: object, label: str, maximum: int, *, refs: bool = False
) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or len(value) > maximum:
        _fail(f"{label} is invalid")
    checked = tuple(
        (_ref(item, label) if refs else _identifier(item, label)) for item in value
    )
    if len({item.casefold() for item in checked}) != len(checked):
        _fail(f"{label} contains duplicates")
    return checked


def _items(value: object, label: str, maximum: int) -> tuple[object, ...]:
    if not isinstance(value, (list, tuple)) or len(value) > maximum:
        _fail(f"{label} is invalid")
    return tuple(value)


def _stat_signature(value: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _read_fd_bounded(fd: int, maximum: int) -> bytes:
    data = b""
    while len(data) <= maximum:
        chunk = os.read(fd, min(65536, maximum + 1 - len(data)))
        if not chunk:
            break
        data += chunk
    if len(data) > maximum:
        _fail("mentor source exceeds its byte bound")
    return data


@dataclass(frozen=True)
class MentorLimits:
    context_bytes: int = 64 * 1024
    max_blocks: int = 48
    block_bytes: int = 4096
    source_bytes: int = 2 * 1024 * 1024
    output_bytes: int = 128 * 1024
    schema_version: int = MENTOR_SCHEMA_VERSION


@dataclass(frozen=True)
class MentorRequest:
    run_id: str
    operation_id: str
    proposal_id: str
    created_at: str
    focus: str
    question: str
    project_refs: tuple[str, ...] = ()
    knowledge_refs: tuple[str, ...] = ()
    memory_refs: tuple[str, ...] = ()
    schema_version: int = MENTOR_SCHEMA_VERSION


@dataclass(frozen=True)
class MentorContextBlock:
    block_id: str
    zone: str
    logical_ref: str
    source_sha256: str
    source_bytes: int
    text: str
    truncated: bool
    schema_version: int = MENTOR_SCHEMA_VERSION


@dataclass(frozen=True)
class MentorContextManifest:
    budget_bytes: int
    used_bytes: int
    source_bytes: int
    block_ids: tuple[str, ...]
    omitted_refs: tuple[str, ...]
    schema_version: int = MENTOR_SCHEMA_VERSION


@dataclass(frozen=True)
class MentorTaskPacket:
    request: MentorRequest
    manifest: MentorContextManifest
    blocks: tuple[MentorContextBlock, ...]
    schema_version: int = MENTOR_SCHEMA_VERSION


@dataclass(frozen=True)
class MentorEvidenceAnchor:
    block_id: str
    logical_ref: str
    source_sha256: str
    schema_version: int = MENTOR_SCHEMA_VERSION


@dataclass(frozen=True)
class MentorObservation:
    observation_id: str
    text: str
    evidence_block_ids: tuple[str, ...]
    schema_version: int = MENTOR_SCHEMA_VERSION


@dataclass(frozen=True)
class MentorRecommendation:
    recommendation_id: str
    text: str
    rationale: str
    evidence_block_ids: tuple[str, ...]
    schema_version: int = MENTOR_SCHEMA_VERSION


@dataclass(frozen=True)
class MentorExecutorOutput:
    summary: str
    observations: tuple[MentorObservation, ...]
    recommendations: tuple[MentorRecommendation, ...]
    questions: tuple[str, ...] = ()
    schema_version: int = MENTOR_SCHEMA_VERSION


class MentorExecutor(Protocol):
    def execute(
        self, packet: MentorTaskPacket
    ) -> MentorExecutorOutput | bytes | str: ...


@dataclass(frozen=True)
class MentorProposalRecord:
    proposal_id: str
    status: str
    actor: str
    run_id: str
    operation_id: str
    created_at: str
    focus: str
    question: str
    task_packet_sha256: str
    context: MentorContextManifest
    evidence: tuple[MentorEvidenceAnchor, ...]
    summary: str
    observations: tuple[MentorObservation, ...]
    recommendations: tuple[MentorRecommendation, ...]
    questions: tuple[str, ...]
    kind: str = "mentor-proposal"
    flow: str = "mentor"
    schema_version: int = MENTOR_SCHEMA_VERSION


@dataclass(frozen=True)
class MentorResult:
    proposal_ref: str
    proposal_sha256: str
    evidence_artifact: str
    task_packet_artifact: str
    replayed: bool
    schema_version: int = MENTOR_SCHEMA_VERSION


@dataclass(frozen=True)
class MentorRunEvidence:
    operation_id: str
    output_ref: str
    request_sha256: str
    task_packet_sha256: str
    output_sha256: str
    run_state_sha256: str
    outcome_class: str = "proposal-pending"
    role: str = "mentor-operation-evidence"
    flow: str = "mentor"
    schema_version: int = MENTOR_SCHEMA_VERSION


@dataclass(frozen=True)
class MentorCapabilities:
    collect_bounded_mentor_context: ActionCapability
    read_mentor_knowledge: ActionCapability
    read_mentor_memory: ActionCapability
    commit_mentor_proposal: ActionCapability
    record_run_state: ActionCapability


@dataclass(frozen=True)
class MentorCrashHooks:
    after_prepare: Callable[[], None] | None = None
    after_proposal_publish: Callable[[], None] | None = None
    before_run_commit: Callable[[], None] | None = None


@dataclass(frozen=True)
class _ReviewPublication:
    artifact: PreparedArtifact
    replayed: bool
    directory_fd: int
    filename: str
    owned_identity: tuple[int, int] | None


def _limits(value: MentorLimits) -> MentorLimits:
    if (
        not isinstance(value, MentorLimits)
        or type(value.schema_version) is not int
        or value.schema_version != 1
    ):
        _fail("mentor limits are invalid")
    _exact_int(value.context_bytes, "context_bytes", 1024, 256 * 1024)
    _exact_int(value.max_blocks, "max_blocks", 1, 128)
    _exact_int(value.block_bytes, "block_bytes", 128, 32 * 1024)
    _exact_int(value.source_bytes, "source_bytes", value.block_bytes, 4 * 1024 * 1024)
    _exact_int(value.output_bytes, "output_bytes", 1024, 512 * 1024)
    return value


def _request_payload(value: MentorRequest) -> dict[str, object]:
    if (
        not isinstance(value, MentorRequest)
        or type(value.schema_version) is not int
        or value.schema_version != 1
    ):
        _fail("mentor request is invalid")
    return {
        "schema_version": 1,
        "run_id": _identifier(value.run_id, "run_id", _RUN_ID),
        "operation_id": _identifier(value.operation_id, "operation_id"),
        "proposal_id": _identifier(value.proposal_id, "proposal_id", _PROPOSAL_ID),
        "created_at": _timestamp(value.created_at, "created_at"),
        "focus": _text(value.focus, "focus", 4096, layout=True),
        "question": _text(value.question, "question", 8192, layout=True),
        "project_refs": list(
            _string_tuple(value.project_refs, "project_refs", 128, refs=True)
        ),
        "knowledge_refs": list(
            _string_tuple(value.knowledge_refs, "knowledge_refs", 128, refs=True)
        ),
        "memory_refs": list(
            _string_tuple(value.memory_refs, "memory_refs", 128, refs=True)
        ),
    }


def _parse_request(value: object) -> MentorRequest:
    item = _mapping(
        value,
        "mentor request",
        frozenset(
            {
                "schema_version",
                "run_id",
                "operation_id",
                "proposal_id",
                "created_at",
                "focus",
                "question",
                "project_refs",
                "knowledge_refs",
                "memory_refs",
            }
        ),
    )
    result = MentorRequest(
        item["run_id"],
        item["operation_id"],
        item["proposal_id"],
        item["created_at"],
        item["focus"],
        item["question"],
        tuple(item["project_refs"]) if isinstance(item["project_refs"], list) else (),
        tuple(item["knowledge_refs"])
        if isinstance(item["knowledge_refs"], list)
        else (),
        tuple(item["memory_refs"]) if isinstance(item["memory_refs"], list) else (),
        item["schema_version"],
    )
    _request_payload(result)
    if not all(
        isinstance(item[key], list)
        for key in ("project_refs", "knowledge_refs", "memory_refs")
    ):
        _fail("mentor request refs are invalid")
    return result


def _block_payload(value: MentorContextBlock) -> dict[str, object]:
    if (
        not isinstance(value, MentorContextBlock)
        or type(value.schema_version) is not int
        or value.schema_version != 1
        or type(value.zone) is not str
        or value.zone not in {"projects", "knowledge", "agent/memory"}
        or type(value.truncated) is not bool
    ):
        _fail("mentor context block is invalid")
    logical = _ref(value.logical_ref, "logical_ref")
    prefix = {
        "projects": "projects/",
        "knowledge": "knowledge/",
        "agent/memory": "agent/memory/",
    }[value.zone]
    if not logical.startswith(prefix):
        _fail("mentor context block role is invalid")
    return {
        "schema_version": 1,
        "block_id": _identifier(value.block_id, "block_id"),
        "zone": value.zone,
        "logical_ref": logical,
        "source_sha256": _hash(value.source_sha256, "source_sha256"),
        "source_bytes": _exact_int(
            value.source_bytes, "source_bytes", 1, 4 * 1024 * 1024
        ),
        "text": _text(value.text, "block text", 32 * 1024, layout=True),
        "truncated": value.truncated,
    }


def _parse_block(value: object) -> MentorContextBlock:
    item = _mapping(
        value,
        "mentor context block",
        frozenset(
            {
                "schema_version",
                "block_id",
                "zone",
                "logical_ref",
                "source_sha256",
                "source_bytes",
                "text",
                "truncated",
            }
        ),
    )
    result = MentorContextBlock(
        item["block_id"],
        item["zone"],
        item["logical_ref"],
        item["source_sha256"],
        item["source_bytes"],
        item["text"],
        item["truncated"],
        item["schema_version"],
    )
    _block_payload(result)
    return result


def _manifest_payload(value: MentorContextManifest) -> dict[str, object]:
    if (
        not isinstance(value, MentorContextManifest)
        or type(value.schema_version) is not int
        or value.schema_version != 1
    ):
        _fail("mentor context manifest is invalid")
    block_ids = _string_tuple(value.block_ids, "manifest block_ids", 128)
    omitted = _string_tuple(value.omitted_refs, "manifest omitted_refs", 384, refs=True)
    return {
        "schema_version": 1,
        "budget_bytes": _exact_int(value.budget_bytes, "budget_bytes", 1, 256 * 1024),
        "used_bytes": _exact_int(value.used_bytes, "used_bytes", 0, value.budget_bytes),
        "source_bytes": _exact_int(
            value.source_bytes, "source_bytes", 0, 4 * 1024 * 1024
        ),
        "block_ids": list(block_ids),
        "omitted_refs": list(omitted),
    }


def _parse_manifest(value: object) -> MentorContextManifest:
    item = _mapping(
        value,
        "mentor context manifest",
        frozenset(
            {
                "schema_version",
                "budget_bytes",
                "used_bytes",
                "source_bytes",
                "block_ids",
                "omitted_refs",
            }
        ),
    )
    if not isinstance(item["block_ids"], list) or not isinstance(
        item["omitted_refs"], list
    ):
        _fail("mentor manifest lists are invalid")
    result = MentorContextManifest(
        item["budget_bytes"],
        item["used_bytes"],
        item["source_bytes"],
        tuple(item["block_ids"]),
        tuple(item["omitted_refs"]),
        item["schema_version"],
    )
    _manifest_payload(result)
    return result


def _observation_payload(value: MentorObservation) -> dict[str, object]:
    if (
        not isinstance(value, MentorObservation)
        or type(value.schema_version) is not int
        or value.schema_version != 1
    ):
        _fail("mentor observation is invalid")
    anchors = _string_tuple(value.evidence_block_ids, "observation evidence", 48)
    if not anchors:
        _fail("mentor observation requires evidence")
    return {
        "schema_version": 1,
        "observation_id": _identifier(value.observation_id, "observation_id"),
        "text": _text(value.text, "observation text", 16 * 1024, layout=True),
        "evidence_block_ids": list(anchors),
    }


def _parse_observation(value: object) -> MentorObservation:
    item = _mapping(
        value,
        "mentor observation",
        frozenset({"schema_version", "observation_id", "text", "evidence_block_ids"}),
    )
    if not isinstance(item["evidence_block_ids"], list):
        _fail("mentor observation evidence is invalid")
    result = MentorObservation(
        item["observation_id"],
        item["text"],
        tuple(item["evidence_block_ids"]),
        item["schema_version"],
    )
    _observation_payload(result)
    return result


def _recommendation_payload(value: MentorRecommendation) -> dict[str, object]:
    if (
        not isinstance(value, MentorRecommendation)
        or type(value.schema_version) is not int
        or value.schema_version != 1
    ):
        _fail("mentor recommendation is invalid")
    anchors = _string_tuple(value.evidence_block_ids, "recommendation evidence", 48)
    if not anchors:
        _fail("mentor recommendation requires evidence")
    return {
        "schema_version": 1,
        "recommendation_id": _identifier(value.recommendation_id, "recommendation_id"),
        "text": _text(value.text, "recommendation text", 16 * 1024, layout=True),
        "rationale": _text(
            value.rationale, "recommendation rationale", 16 * 1024, layout=True
        ),
        "evidence_block_ids": list(anchors),
    }


def _parse_recommendation(value: object) -> MentorRecommendation:
    item = _mapping(
        value,
        "mentor recommendation",
        frozenset(
            {
                "schema_version",
                "recommendation_id",
                "text",
                "rationale",
                "evidence_block_ids",
            }
        ),
    )
    if not isinstance(item["evidence_block_ids"], list):
        _fail("mentor recommendation evidence is invalid")
    result = MentorRecommendation(
        item["recommendation_id"],
        item["text"],
        item["rationale"],
        tuple(item["evidence_block_ids"]),
        item["schema_version"],
    )
    _recommendation_payload(result)
    return result


def _output_payload(value: MentorExecutorOutput) -> dict[str, object]:
    if (
        not isinstance(value, MentorExecutorOutput)
        or type(value.schema_version) is not int
        or value.schema_version != 1
    ):
        _fail("mentor executor output is invalid")
    observations = _items(value.observations, "mentor observations", 64)
    recommendations = _items(value.recommendations, "mentor recommendations", 64)
    questions = _items(value.questions, "mentor questions", 32)
    return {
        "schema_version": 1,
        "summary": _text(value.summary, "summary", 32 * 1024, layout=True),
        "observations": [_observation_payload(item) for item in observations],
        "recommendations": [_recommendation_payload(item) for item in recommendations],
        "questions": [
            _text(item, "output question", 8192, layout=True) for item in questions
        ],
    }


def render_mentor_executor_output(value: MentorExecutorOutput) -> bytes:
    return _canonical(_output_payload(value), 128 * 1024)


def parse_mentor_executor_output(raw: bytes | str) -> MentorExecutorOutput:
    item = _mapping(
        _decode(raw, "mentor executor output", 128 * 1024),
        "mentor executor output",
        frozenset(
            {
                "schema_version",
                "summary",
                "observations",
                "recommendations",
                "questions",
            }
        ),
    )
    if not all(
        isinstance(item[key], list)
        for key in ("observations", "recommendations", "questions")
    ):
        _fail("mentor executor output lists are invalid")
    result = MentorExecutorOutput(
        item["summary"],
        tuple(_parse_observation(value) for value in item["observations"]),
        tuple(_parse_recommendation(value) for value in item["recommendations"]),
        tuple(item["questions"]),
        item["schema_version"],
    )
    source = raw.encode("utf-8") if isinstance(raw, str) else raw
    if source != render_mentor_executor_output(result):
        _fail("mentor executor output must use canonical JSON")
    return result


def _packet_payload(value: MentorTaskPacket) -> dict[str, object]:
    if (
        not isinstance(value, MentorTaskPacket)
        or type(value.schema_version) is not int
        or value.schema_version != 1
    ):
        _fail("mentor task packet is invalid")
    blocks = _items(value.blocks, "mentor task packet blocks", 128)
    manifest = _manifest_payload(value.manifest)
    payloads = [_block_payload(item) for item in blocks]
    if (
        tuple(item.block_id for item in blocks) != value.manifest.block_ids
        or sum(len(item.text.encode("utf-8")) for item in blocks)
        != value.manifest.used_bytes
        or sum(item.source_bytes for item in blocks) != value.manifest.source_bytes
    ):
        _fail("mentor context manifest disagrees with blocks")
    return {
        "schema_version": 1,
        "request": _request_payload(value.request),
        "manifest": manifest,
        "blocks": payloads,
    }


def render_mentor_task_packet(value: MentorTaskPacket) -> bytes:
    return _canonical(_packet_payload(value))


def parse_mentor_task_packet(raw: bytes | str) -> MentorTaskPacket:
    item = _mapping(
        _decode(raw, "mentor task packet"),
        "mentor task packet",
        frozenset({"schema_version", "request", "manifest", "blocks"}),
    )
    if not isinstance(item["blocks"], list):
        _fail("mentor task packet blocks are invalid")
    result = MentorTaskPacket(
        _parse_request(item["request"]),
        _parse_manifest(item["manifest"]),
        tuple(_parse_block(value) for value in item["blocks"]),
        item["schema_version"],
    )
    source = raw.encode("utf-8") if isinstance(raw, str) else raw
    if source != render_mentor_task_packet(result):
        _fail("mentor task packet must use canonical JSON")
    return result


def _anchor_payload(value: MentorEvidenceAnchor) -> dict[str, object]:
    if (
        not isinstance(value, MentorEvidenceAnchor)
        or type(value.schema_version) is not int
        or value.schema_version != 1
    ):
        _fail("mentor evidence anchor is invalid")
    return {
        "schema_version": 1,
        "block_id": _identifier(value.block_id, "anchor block_id"),
        "logical_ref": _ref(value.logical_ref, "anchor logical_ref"),
        "source_sha256": _hash(value.source_sha256, "anchor source_sha256"),
    }


def _parse_anchor(value: object) -> MentorEvidenceAnchor:
    item = _mapping(
        value,
        "mentor evidence anchor",
        frozenset({"schema_version", "block_id", "logical_ref", "source_sha256"}),
    )
    result = MentorEvidenceAnchor(
        item["block_id"],
        item["logical_ref"],
        item["source_sha256"],
        item["schema_version"],
    )
    _anchor_payload(result)
    return result


def _proposal_payload(value: MentorProposalRecord) -> dict[str, object]:
    if (
        not isinstance(value, MentorProposalRecord)
        or type(value.schema_version) is not int
        or value.schema_version != 1
        or value.kind != "mentor-proposal"
        or value.flow != "mentor"
        or value.status != "proposed"
        or value.actor != "runtime"
    ):
        _fail("mentor proposal is invalid")
    context = _manifest_payload(value.context)
    evidence_items = _items(value.evidence, "mentor proposal evidence", 128)
    observation_items = _items(value.observations, "mentor proposal observations", 64)
    recommendation_items = _items(
        value.recommendations, "mentor proposal recommendations", 64
    )
    question_items = _items(value.questions, "mentor proposal questions", 32)
    evidence = [_anchor_payload(item) for item in evidence_items]
    observations = [_observation_payload(item) for item in observation_items]
    recommendations = [_recommendation_payload(item) for item in recommendation_items]
    evidence_ids = tuple(str(item["block_id"]) for item in evidence)
    if evidence_ids != value.context.block_ids:
        _fail("mentor proposal evidence disagrees with its context")
    known = frozenset(evidence_ids)
    if any(
        not set(item.evidence_block_ids).issubset(known)
        for item in (*observation_items, *recommendation_items)
    ):
        _fail("mentor proposal claim cites unknown evidence")
    return {
        "schema_version": 1,
        "kind": value.kind,
        "flow": value.flow,
        "proposal_id": _identifier(value.proposal_id, "proposal_id", _PROPOSAL_ID),
        "status": value.status,
        "actor": value.actor,
        "run_id": _identifier(value.run_id, "run_id", _RUN_ID),
        "operation_id": _identifier(value.operation_id, "operation_id"),
        "created_at": _timestamp(value.created_at, "created_at"),
        "focus": _text(value.focus, "focus", 4096, layout=True),
        "question": _text(value.question, "question", 8192, layout=True),
        "task_packet_sha256": _hash(value.task_packet_sha256, "task_packet_sha256"),
        "context": context,
        "evidence": evidence,
        "summary": _text(value.summary, "summary", 32 * 1024, layout=True),
        "observations": observations,
        "recommendations": recommendations,
        "questions": [
            _text(item, "proposal question", 8192, layout=True)
            for item in question_items
        ],
    }


def render_mentor_proposal(value: MentorProposalRecord) -> bytes:
    return _canonical(_proposal_payload(value))


def parse_mentor_proposal(raw: bytes | str) -> MentorProposalRecord:
    keys = frozenset(
        {
            "schema_version",
            "kind",
            "flow",
            "proposal_id",
            "status",
            "actor",
            "run_id",
            "operation_id",
            "created_at",
            "focus",
            "question",
            "task_packet_sha256",
            "context",
            "evidence",
            "summary",
            "observations",
            "recommendations",
            "questions",
        }
    )
    item = _mapping(_decode(raw, "mentor proposal"), "mentor proposal", keys)
    if not all(
        isinstance(item[key], list)
        for key in ("evidence", "observations", "recommendations", "questions")
    ):
        _fail("mentor proposal lists are invalid")
    result = MentorProposalRecord(
        item["proposal_id"],
        item["status"],
        item["actor"],
        item["run_id"],
        item["operation_id"],
        item["created_at"],
        item["focus"],
        item["question"],
        item["task_packet_sha256"],
        _parse_manifest(item["context"]),
        tuple(_parse_anchor(value) for value in item["evidence"]),
        item["summary"],
        tuple(_parse_observation(value) for value in item["observations"]),
        tuple(_parse_recommendation(value) for value in item["recommendations"]),
        tuple(item["questions"]),
        item["kind"],
        item["flow"],
        item["schema_version"],
    )
    source = raw.encode("utf-8") if isinstance(raw, str) else raw
    if source != render_mentor_proposal(result):
        _fail("mentor proposal must use canonical JSON")
    return result


def mentor_evidence_artifact_name(operation_id: str) -> str:
    checked = _identifier(operation_id, "operation_id")
    return "mentor-evidence-" + hashlib.sha256(checked.encode()).hexdigest()[:32]


def mentor_task_artifact_name(operation_id: str) -> str:
    checked = _identifier(operation_id, "operation_id")
    return "mentor-task-" + hashlib.sha256(checked.encode()).hexdigest()[:32]


def _evidence_payload(value: MentorRunEvidence) -> dict[str, object]:
    if (
        not isinstance(value, MentorRunEvidence)
        or type(value.schema_version) is not int
        or value.schema_version != 1
        or value.role != "mentor-operation-evidence"
        or value.flow != "mentor"
        or value.outcome_class != "proposal-pending"
    ):
        _fail("mentor run evidence is invalid")
    output_ref = _ref(value.output_ref, "output_ref")
    output_path = PurePosixPath(output_ref)
    if len(output_path.parts) < 2 or not output_path.name.endswith(".mentor.json"):
        _fail("mentor output role is invalid")
    return {
        "schema_version": 1,
        "role": value.role,
        "flow": value.flow,
        "operation_id": _identifier(value.operation_id, "operation_id"),
        "output_ref": output_ref,
        "request_sha256": _hash(value.request_sha256, "request_sha256"),
        "task_packet_sha256": _hash(value.task_packet_sha256, "task_packet_sha256"),
        "output_sha256": _hash(value.output_sha256, "output_sha256"),
        "run_state_sha256": _hash(value.run_state_sha256, "run_state_sha256"),
        "outcome_class": value.outcome_class,
    }


def render_mentor_run_evidence(value: MentorRunEvidence) -> bytes:
    return _canonical(_evidence_payload(value))


def parse_mentor_run_evidence(raw: bytes | str) -> MentorRunEvidence:
    item = _mapping(
        _decode(raw, "mentor run evidence"),
        "mentor run evidence",
        frozenset(
            {
                "schema_version",
                "role",
                "flow",
                "operation_id",
                "output_ref",
                "request_sha256",
                "task_packet_sha256",
                "output_sha256",
                "run_state_sha256",
                "outcome_class",
            }
        ),
    )
    result = MentorRunEvidence(
        item["operation_id"],
        item["output_ref"],
        item["request_sha256"],
        item["task_packet_sha256"],
        item["output_sha256"],
        item["run_state_sha256"],
        item["outcome_class"],
        item["role"],
        item["flow"],
        item["schema_version"],
    )
    source = raw.encode("utf-8") if isinstance(raw, str) else raw
    if source != render_mentor_run_evidence(result):
        _fail("mentor run evidence must use canonical JSON")
    return result


def inspect_mentor_run_evidence(
    artifact: PreparedArtifact | CommittedArtifact, raw: bytes | str
) -> MentorRunEvidence:
    if not isinstance(artifact, (PreparedArtifact, CommittedArtifact)):
        _fail("mentor run evidence artifact is invalid")
    evidence = parse_mentor_run_evidence(raw)
    source = raw.encode("utf-8") if isinstance(raw, str) else raw
    relative = PurePosixPath(_ref(artifact.relative, "artifact relative"))
    expected = mentor_evidence_artifact_name(evidence.operation_id)
    if (
        artifact.name != expected
        or artifact.zone != "agent/runs"
        or relative.name != f"{expected}.json"
        or artifact.state_ref != f"agent/runs/{relative.as_posix()}"
        or artifact.sha256 != hashlib.sha256(source).hexdigest()
    ):
        _fail("mentor run evidence artifact binding is invalid")
    return evidence


class MentorFlow:
    def __init__(
        self,
        resolver: VaultPathResolver,
        run_store: RunStore,
        policy: AuthorityPolicy,
        *,
        limits: MentorLimits | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if (
            not isinstance(resolver, VaultPathResolver)
            or not isinstance(run_store, RunStore)
            or not isinstance(policy, AuthorityPolicy)
            or getattr(run_store, "_resolver", None) is not resolver
        ):
            _fail("mentor flow dependencies are invalid")
        self._resolver = resolver
        self._runs = run_store
        self._policy = policy
        self._limits = _limits(limits or MentorLimits())
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def _require(
        self, capability: ActionCapability, action_id: str
    ) -> ActionCapability:
        expected = {
            "collect-bounded-mentor-context": ("runtime", "read", "vault:projects"),
            "read-mentor-knowledge": ("runtime", "read", "vault:knowledge"),
            "read-mentor-memory": ("runtime", "read", "vault:agent/memory"),
            "commit-mentor-proposal": ("runtime", "proposal", "vault:review"),
            "record-run-state": ("runtime", "internal-write", "vault:agent/runs"),
        }
        try:
            grant = self._policy.require(capability)
        except AuthorityError as error:
            raise MentorFlowError(str(error)) from None
        if action_id not in expected or (
            grant.flow_id,
            grant.action_id,
            grant.actor,
            grant.authority,
            grant.target,
        ) != ("mentor", action_id, *expected[action_id]):
            _fail("mentor action capability is not exact")
        return grant

    def _check_run(self, run_id: str):
        checked = _identifier(run_id, "run_id", _RUN_ID)
        try:
            snapshot = self._runs.snapshot(checked)
        except RunError as error:
            raise MentorFlowError(str(error)) from None
        if (
            snapshot.state.get("flow") != "mentor"
            or snapshot.state.get("status") != "running"
            or snapshot.state.get("authority") != "proposal"
        ):
            _fail("mentor requires a running proposal mentor run")
        return checked, snapshot

    def _read_source(self, zone: str, relative: str) -> tuple[bytes, str]:
        checked = _ref(relative, f"{zone} ref")
        opened_dirs: list[int] = []
        directory_links: list[tuple[int, str, int, tuple[int, int]]] = []
        file_fd: int | None = None
        try:
            base = self._resolver.resolve(zone, must_exist=True)
            config_name = _ZONE_CONFIG_NAMES.get(zone)
            if config_name is None:
                _fail("mentor source zone is invalid")
            zone_relative = self._resolver.config.zone(config_name)
            root = base
            for _ in zone_relative.parts:
                root = root.parent
            root_fd = os.open(
                root,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
            opened_dirs.append(root_fd)
            root_named = os.stat(root, follow_symlinks=False)
            root_opened = os.fstat(root_fd)
            root_identity = (root_opened.st_dev, root_opened.st_ino)
            if not stat.S_ISDIR(root_opened.st_mode) or root_identity != (
                root_named.st_dev,
                root_named.st_ino,
            ):
                _fail("mentor vault root changed while opening")

            current_fd = root_fd
            for part in (*zone_relative.parts, *PurePosixPath(checked).parts[:-1]):
                child_fd = os.open(
                    part,
                    os.O_RDONLY
                    | getattr(os, "O_DIRECTORY", 0)
                    | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=current_fd,
                )
                opened_dirs.append(child_fd)
                named_child = os.stat(part, dir_fd=current_fd, follow_symlinks=False)
                opened_child = os.fstat(child_fd)
                identity = (opened_child.st_dev, opened_child.st_ino)
                if not stat.S_ISDIR(opened_child.st_mode) or identity != (
                    named_child.st_dev,
                    named_child.st_ino,
                ):
                    _fail("mentor source parent changed while opening")
                directory_links.append((current_fd, part, child_fd, identity))
                current_fd = child_fd

            leaf = PurePosixPath(checked).name
            named = os.stat(leaf, dir_fd=current_fd, follow_symlinks=False)
            if (
                not stat.S_ISREG(named.st_mode)
                or not 1 <= named.st_size <= self._limits.source_bytes
            ):
                _fail("mentor source is not a bounded regular file")
            file_fd = os.open(
                leaf,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=current_fd,
            )
            opened = os.fstat(file_fd)
            opened_signature = _stat_signature(opened)
            if not stat.S_ISREG(opened.st_mode) or opened_signature != _stat_signature(
                named
            ):
                _fail("mentor source changed while opening")
            data = _read_fd_bounded(file_fd, self._limits.source_bytes)
            os.lseek(file_fd, 0, os.SEEK_SET)
            if _read_fd_bounded(file_fd, self._limits.source_bytes) != data:
                _fail("mentor source content changed while reading")
            final = os.fstat(file_fd)
            named_final = os.stat(leaf, dir_fd=current_fd, follow_symlinks=False)
            if (
                _stat_signature(final) != opened_signature
                or _stat_signature(named_final) != opened_signature
            ):
                _fail("mentor source changed while reading")
            for parent_fd, part, child_fd, identity in directory_links:
                opened_parent = os.fstat(child_fd)
                named_parent = os.stat(part, dir_fd=parent_fd, follow_symlinks=False)
                if (
                    not stat.S_ISDIR(opened_parent.st_mode)
                    or (opened_parent.st_dev, opened_parent.st_ino) != identity
                    or (named_parent.st_dev, named_parent.st_ino) != identity
                ):
                    _fail("mentor source parent identity changed")
            root_final = os.stat(root, follow_symlinks=False)
            if (root_final.st_dev, root_final.st_ino) != root_identity:
                _fail("mentor vault root identity changed")
            self._resolver.revalidate(base, zone, must_exist=True)
            data.decode("utf-8")
            return data, f"{zone}/{checked}"
        except (OSError, UnicodeError, VaultSchemaError):
            _fail("mentor source cannot be read safely")
        finally:
            if file_fd is not None:
                os.close(file_fd)
            for directory_fd in reversed(opened_dirs):
                os.close(directory_fd)

    def prepare_task_packet(
        self, request: MentorRequest, *, capabilities: MentorCapabilities
    ) -> MentorTaskPacket:
        request_payload = _request_payload(request)
        if not isinstance(capabilities, MentorCapabilities):
            _fail("mentor capabilities are invalid")
        self._require(
            capabilities.collect_bounded_mentor_context,
            "collect-bounded-mentor-context",
        )
        self._require(capabilities.read_mentor_knowledge, "read-mentor-knowledge")
        self._require(capabilities.read_mentor_memory, "read-mentor-memory")
        run_id, _ = self._check_run(str(request_payload["run_id"]))
        if run_id != request.run_id:
            _fail("mentor request run binding is invalid")
        refs: list[tuple[str, str]] = []
        for zone, items in (
            ("projects", request.project_refs),
            ("knowledge", request.knowledge_refs),
            ("agent/memory", request.memory_refs),
        ):
            refs.extend((zone, item) for item in items)
        refs.sort(key=lambda item: (item[0], item[1].casefold(), item[1]))
        blocks: list[MentorContextBlock] = []
        omitted: list[str] = []
        used = 0
        source_bytes = 0
        for zone, relative in refs:
            logical = f"{zone}/{relative}"
            if len(blocks) >= self._limits.max_blocks:
                omitted.append(logical)
                continue
            raw, logical = self._read_source(zone, relative)
            if source_bytes + len(raw) > self._limits.source_bytes:
                omitted.append(logical)
                continue
            available = min(self._limits.block_bytes, self._limits.context_bytes - used)
            if available <= 0:
                omitted.append(logical)
                continue
            cut = raw[:available]
            while cut:
                try:
                    text = cut.decode("utf-8")
                    break
                except UnicodeDecodeError as error:
                    cut = cut[: error.start]
            else:
                omitted.append(logical)
                continue
            block_id = (
                "ctx-" + hashlib.sha256(f"{zone}\0{relative}".encode()).hexdigest()[:24]
            )
            blocks.append(
                MentorContextBlock(
                    block_id,
                    zone,
                    logical,
                    hashlib.sha256(raw).hexdigest(),
                    len(raw),
                    text,
                    len(cut) < len(raw),
                )
            )
            used += len(cut)
            source_bytes += len(raw)
        manifest = MentorContextManifest(
            self._limits.context_bytes,
            used,
            source_bytes,
            tuple(item.block_id for item in blocks),
            tuple(omitted),
        )
        packet = MentorTaskPacket(request, manifest, tuple(blocks))
        render_mentor_task_packet(packet)
        return packet

    @staticmethod
    def _coerce_output(
        value: MentorExecutorOutput | bytes | str,
    ) -> MentorExecutorOutput:
        if isinstance(value, MentorExecutorOutput):
            return parse_mentor_executor_output(render_mentor_executor_output(value))
        return parse_mentor_executor_output(value)

    def _review_location(self, filename: str) -> tuple[Path, str]:
        if PurePosixPath(filename).name != filename:
            _fail("mentor review filename is invalid")
        try:
            review = self._resolver.resolve("review", for_write=True, must_exist=True)
            runs = self._resolver.resolve("agent/runs", must_exist=True)
            root = runs
            for _ in self._resolver.config.zone("runs").parts:
                root = root.parent
            state_ref = (review / filename).relative_to(root).as_posix()
            resolved = self._resolver.resolve(
                "review", filename, for_write=True, must_exist=False
            )
        except (OSError, ValueError, VaultSchemaError):
            _fail("mentor review reference cannot be derived safely")
        if (
            resolved != review / filename
            or _ref(state_ref, "mentor review ref") != state_ref
        ):
            _fail("mentor review reference is not canonical")
        return review, state_ref

    @staticmethod
    def _retire_owned_review(
        directory_fd: int, filename: str, identity: tuple[int, int]
    ) -> bool:
        """Remove only the exact inode published through the anchored parent."""

        try:
            current = os.stat(filename, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            return True
        except OSError:
            return False
        if (current.st_dev, current.st_ino) != identity:
            return True
        quarantine = f".mentor-retire-{uuid.uuid4().hex}.tmp"
        try:
            os.rename(
                filename,
                quarantine,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
            )
            moved = os.stat(quarantine, dir_fd=directory_fd, follow_symlinks=False)
            if (moved.st_dev, moved.st_ino) != identity:
                try:
                    os.link(
                        quarantine,
                        filename,
                        src_dir_fd=directory_fd,
                        dst_dir_fd=directory_fd,
                        follow_symlinks=False,
                    )
                    os.unlink(quarantine, dir_fd=directory_fd)
                    os.fsync(directory_fd)
                except OSError:
                    pass
                return False
            os.unlink(quarantine, dir_fd=directory_fd)
            os.fsync(directory_fd)
            return True
        except FileNotFoundError:
            return True
        except OSError:
            return False

    @staticmethod
    def _close_review_publication(publication: _ReviewPublication) -> None:
        try:
            os.close(publication.directory_fd)
        except OSError:
            _fail("mentor review directory descriptor cannot be closed")

    def _publish_review(
        self, filename: str, data: bytes, review: Path, state_ref: str
    ) -> _ReviewPublication:
        if PurePosixPath(filename).name != filename or not filename.endswith(
            ".mentor.json"
        ):
            _fail("mentor review filename is invalid")
        directory_fd: int | None = None
        stage: str | None = None
        stage_identity: tuple[int, int] | None = None
        published_identity: tuple[int, int] | None = None
        replayed = False
        keep_open = False
        try:
            directory_fd = os.open(
                review,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
            opened = os.fstat(directory_fd)
            named = os.stat(review, follow_symlinks=False)
            if (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino):
                _fail("mentor review directory changed")
            stage = f".mentor-{uuid.uuid4().hex}.tmp"
            out = os.open(
                stage,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=directory_fd,
            )
            try:
                view = memoryview(data)
                while view:
                    written = os.write(out, view)
                    if written < 1:
                        _fail("mentor proposal write stalled")
                    view = view[written:]
                os.fsync(out)
                staged = os.fstat(out)
                stage_identity = (staged.st_dev, staged.st_ino)
            finally:
                os.close(out)
            try:
                os.link(
                    stage,
                    filename,
                    src_dir_fd=directory_fd,
                    dst_dir_fd=directory_fd,
                    follow_symlinks=False,
                )
                published = os.stat(
                    filename, dir_fd=directory_fd, follow_symlinks=False
                )
                if (published.st_dev, published.st_ino) != stage_identity:
                    _fail("mentor proposal publication changed")
                published_identity = stage_identity
                os.fsync(directory_fd)
            except FileExistsError:
                current_fd = os.open(
                    filename,
                    os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=directory_fd,
                )
                try:
                    named_file = os.fstat(current_fd)
                    if (
                        not stat.S_ISREG(named_file.st_mode)
                        or named_file.st_size > _MAX_JSON
                    ):
                        _fail("mentor proposal replay target is invalid")
                    current = b""
                    while True:
                        chunk = os.read(current_fd, 65536)
                        if not chunk:
                            break
                        current += chunk
                finally:
                    os.close(current_fd)
                if current != data:
                    _fail("mentor proposal replay disagrees with existing bytes")
                replayed = True
            self._resolver.revalidate(review, "review", for_write=True, must_exist=True)
            final_named = os.stat(review, follow_symlinks=False)
            if (final_named.st_dev, final_named.st_ino) != (
                opened.st_dev,
                opened.st_ino,
            ):
                _fail("mentor review directory changed")
            digest = hashlib.sha256(data).hexdigest()
            artifact = PreparedArtifact(
                "mentor-review-" + digest[:32],
                "review",
                filename,
                state_ref,
                digest,
            )
            keep_open = True
            return _ReviewPublication(
                artifact,
                replayed,
                directory_fd,
                filename,
                published_identity,
            )
        except BaseException as error:
            if (
                directory_fd is not None
                and published_identity is not None
                and not self._retire_owned_review(
                    directory_fd, filename, published_identity
                )
            ):
                raise MentorFlowError(
                    "mentor failed publication could not be retired safely"
                ) from None
            if isinstance(error, (OSError, VaultSchemaError)):
                _fail("mentor proposal cannot be published safely")
            raise
        finally:
            if directory_fd is not None:
                if stage is not None:
                    try:
                        os.unlink(stage, dir_fd=directory_fd)
                    except FileNotFoundError:
                        pass
                    except OSError:
                        pass
                if not keep_open:
                    os.close(directory_fd)

    def _read_committed_artifact(self, artifact: CommittedArtifact) -> bytes:
        try:
            path = self._resolver.resolve(
                artifact.zone, artifact.relative, must_exist=True
            )
            named = os.stat(path, follow_symlinks=False)
            if not stat.S_ISREG(named.st_mode) or named.st_size > _MAX_JSON:
                _fail("mentor committed artifact is invalid")
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            try:
                opened = os.fstat(fd)
                if (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino):
                    _fail("mentor committed artifact changed while opening")
                raw = b""
                while True:
                    chunk = os.read(fd, 65536)
                    if not chunk:
                        break
                    raw += chunk
            finally:
                os.close(fd)
            self._resolver.revalidate(
                path, artifact.zone, artifact.relative, must_exist=True
            )
        except (OSError, VaultSchemaError):
            _fail("mentor committed artifact cannot be read safely")
        if hashlib.sha256(raw).hexdigest() != artifact.sha256:
            _fail("mentor committed artifact hash changed")
        return raw

    def commit_proposal(
        self,
        packet: MentorTaskPacket,
        output: MentorExecutorOutput | bytes | str,
        *,
        capabilities: MentorCapabilities,
        hooks: MentorCrashHooks | None = None,
    ) -> MentorResult:
        packet_raw = render_mentor_task_packet(packet)
        output_value = self._coerce_output(output)
        output_raw = render_mentor_executor_output(output_value)
        if len(output_raw) > self._limits.output_bytes:
            _fail("mentor executor output exceeds its bound")
        known = frozenset(packet.manifest.block_ids)
        for item in (*output_value.observations, *output_value.recommendations):
            if not set(item.evidence_block_ids).issubset(known):
                _fail("mentor output cites context outside the packet")
        if not isinstance(capabilities, MentorCapabilities):
            _fail("mentor capabilities are invalid")
        caps = (
            self._require(
                capabilities.collect_bounded_mentor_context,
                "collect-bounded-mentor-context",
            ),
            self._require(capabilities.read_mentor_knowledge, "read-mentor-knowledge"),
            self._require(capabilities.read_mentor_memory, "read-mentor-memory"),
            self._require(
                capabilities.commit_mentor_proposal, "commit-mentor-proposal"
            ),
            self._require(capabilities.record_run_state, "record-run-state"),
        )
        run_id, snapshot = self._check_run(packet.request.run_id)
        checked_hooks = hooks or MentorCrashHooks()
        if not isinstance(checked_hooks, MentorCrashHooks) or any(
            item is not None and not callable(item)
            for item in (
                checked_hooks.after_prepare,
                checked_hooks.after_proposal_publish,
                checked_hooks.before_run_commit,
            )
        ):
            _fail("mentor crash hooks are invalid")
        packet_sha = hashlib.sha256(packet_raw).hexdigest()
        anchors = tuple(
            MentorEvidenceAnchor(item.block_id, item.logical_ref, item.source_sha256)
            for item in packet.blocks
        )
        proposal = MentorProposalRecord(
            packet.request.proposal_id,
            "proposed",
            "runtime",
            run_id,
            packet.request.operation_id,
            packet.request.created_at,
            packet.request.focus,
            packet.request.question,
            packet_sha,
            packet.manifest,
            anchors,
            output_value.summary,
            output_value.observations,
            output_value.recommendations,
            output_value.questions,
        )
        proposal_raw = render_mentor_proposal(proposal)
        filename = f"{packet.request.proposal_id}.mentor.json"
        review_path, output_ref = self._review_location(filename)
        request_raw = _canonical(_request_payload(packet.request))
        evidence_name = mentor_evidence_artifact_name(packet.request.operation_id)
        task_name = mentor_task_artifact_name(packet.request.operation_id)
        existing = next(
            (item for item in snapshot.artifacts if item.name == evidence_name),
            None,
        )
        if existing is not None:
            try:
                committed_snapshot = self._runs.producer_snapshot(
                    run_id, producer_evidence=evidence_name
                )
            except RunError as error:
                raise MentorFlowError(str(error)) from None
            bundle = {item.name: item for item in committed_snapshot.artifacts}
            evidence_artifact = bundle.get(evidence_name)
            if evidence_artifact is None:
                _fail("mentor replay lacks committed proposal evidence")
            committed = inspect_mentor_run_evidence(
                evidence_artifact,
                self._read_committed_artifact(evidence_artifact),
            )
            task_artifact = bundle.get(task_name)
            review_artifacts = tuple(
                item for item in bundle.values() if item.state_ref == output_ref
            )
            if (
                set(bundle)
                != {
                    evidence_name,
                    task_name,
                    next(iter(review_artifacts), existing).name,
                }
                or task_artifact is None
                or task_artifact.zone != "agent/runs"
                or task_artifact.relative != f"{run_id}/{task_name}.json"
                or task_artifact.state_ref != f"agent/runs/{run_id}/{task_name}.json"
                or task_artifact.sha256 != packet_sha
                or self._read_committed_artifact(task_artifact) != packet_raw
                or len(review_artifacts) != 1
                or review_artifacts[0].zone != "review"
                or review_artifacts[0].relative != filename
                or review_artifacts[0].sha256
                != hashlib.sha256(proposal_raw).hexdigest()
                or committed.output_ref != output_ref
                or committed.request_sha256 != hashlib.sha256(request_raw).hexdigest()
                or committed.task_packet_sha256 != packet_sha
                or committed.output_sha256 != hashlib.sha256(proposal_raw).hexdigest()
            ):
                _fail("mentor replay changes committed proposal evidence")
            return MentorResult(
                output_ref,
                committed.output_sha256,
                existing.name,
                task_name,
                True,
            )
        expected_packet = self.prepare_task_packet(
            packet.request, capabilities=capabilities
        )
        if render_mentor_task_packet(expected_packet) != packet_raw:
            _fail("mentor task packet disagrees with current exact sources")
        evidence = MentorRunEvidence(
            packet.request.operation_id,
            output_ref,
            hashlib.sha256(request_raw).hexdigest(),
            packet_sha,
            hashlib.sha256(proposal_raw).hexdigest(),
            snapshot.state_sha256,
        )
        evidence_raw = render_mentor_run_evidence(evidence)
        try:
            task_artifact = self._runs.prepare_run_artifact(
                run_id, name=task_name, data=packet_raw, maximum_bytes=_MAX_JSON
            )
            evidence_artifact = self._runs.prepare_run_artifact(
                run_id, name=evidence_name, data=evidence_raw, maximum_bytes=_MAX_JSON
            )
        except RunError as error:
            raise MentorFlowError(str(error)) from None
        if checked_hooks.after_prepare is not None:
            checked_hooks.after_prepare()
        publication: _ReviewPublication | None = None
        try:
            publication = self._publish_review(
                filename, proposal_raw, review_path, output_ref
            )
            if checked_hooks.after_proposal_publish is not None:
                checked_hooks.after_proposal_publish()
            if checked_hooks.before_run_commit is not None:
                checked_hooks.before_run_commit()
            try:
                self._runs.commit_step(
                    run_id,
                    step_id="mentor-"
                    + hashlib.sha256(packet.request.operation_id.encode()).hexdigest()[
                        :32
                    ],
                    authority="proposal",
                    input_hash=hashlib.sha256(request_raw).hexdigest(),
                    output_hash=hashlib.sha256(proposal_raw).hexdigest(),
                    next_phase="mentor-committed",
                    next_status="running",
                    prepared_artifacts=(
                        task_artifact,
                        publication.artifact,
                        evidence_artifact,
                    ),
                    expected_state_sha256=snapshot.state_sha256,
                    action_uses=tuple(ActionUse(cap) for cap in caps),
                    authority_policy=self._policy,
                )
            except RunError as error:
                raise MentorFlowError(str(error)) from None
        except BaseException:
            if (
                publication is not None
                and publication.owned_identity is not None
                and not self._retire_owned_review(
                    publication.directory_fd,
                    publication.filename,
                    publication.owned_identity,
                )
            ):
                _fail("mentor failed proposal could not be retired safely")
            raise
        finally:
            if publication is not None:
                self._close_review_publication(publication)
        return MentorResult(
            output_ref,
            hashlib.sha256(proposal_raw).hexdigest(),
            evidence_artifact.name,
            task_artifact.name,
            publication.replayed,
        )

    def mentor(
        self,
        request: MentorRequest,
        executor: MentorExecutor
        | Callable[[MentorTaskPacket], MentorExecutorOutput | bytes | str],
        *,
        capabilities: MentorCapabilities,
        hooks: MentorCrashHooks | None = None,
    ) -> MentorResult:
        packet = self.prepare_task_packet(request, capabilities=capabilities)
        try:
            value = (
                executor.execute(packet)
                if hasattr(executor, "execute")
                else executor(packet)
            )
        except MentorFlowError:
            raise
        except Exception:
            _fail("mentor executor failed")
        return self.commit_proposal(
            packet, value, capabilities=capabilities, hooks=hooks
        )
