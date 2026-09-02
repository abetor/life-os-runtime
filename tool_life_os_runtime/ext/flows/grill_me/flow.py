"""Interactive decision clarification with explicit human answer boundaries."""

from __future__ import annotations

from dataclasses import dataclass, replace
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
    RunSnapshot,
    RunStore,
)
from tool_life_os_runtime.ext.vault.schema import VaultPathResolver, VaultSchemaError


GRILL_SCHEMA_VERSION = 1
_MAX_JSON = 512 * 1024
_ID = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
_RUN_ID = re.compile(r"^run_[a-z0-9][a-z0-9_-]{0,62}$")
_RECORD_ID = re.compile(r"^grill-[a-z0-9][a-z0-9_-]{0,56}$")
_SHA = re.compile(r"^[0-9a-f]{64}$")
_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$")
_PRIVATE_PATH = re.compile(r"(?:/users/|/home/|[a-z]:[\\/](?:users|home)[\\/])")
_FILE_SCHEME = re.compile(r"(?:^|[^a-z0-9_])file:")
_ARCHIVES = frozenset({"_archive", "_trash", "_on_hold"})
_TEXT_SUFFIXES = frozenset({".json", ".jsonl", ".md", ".txt"})
_ZONE_CONFIG_NAMES = {"projects": "projects", "agent/memory": "memory"}
_MAX_REF_PARTS = 32


class GrillFlowError(ValueError):
    """Grill input, transcript, authority, or durable evidence is invalid."""


def _fail(message: str) -> None:
    raise GrillFlowError(message)


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
        _fail("grill payload is not canonical JSON")
    if len(raw) > maximum:
        _fail("grill payload is too large")
    return raw


def _pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            _fail("grill JSON has duplicate fields")
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
    except GrillFlowError:
        raise
    except (UnicodeError, ValueError, RecursionError):
        _fail(f"{label} is invalid")


def _mapping(value: object, label: str, keys: frozenset[str]) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or set(value) != keys:
        _fail(f"{label} has missing or unknown fields")
    return value


def _string_tuple(
    value: object,
    label: str,
    maximum: int,
    *,
    refs: bool = False,
    allow_empty: bool = True,
) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or len(value) > maximum:
        _fail(f"{label} is invalid")
    result = tuple(
        (_ref(item, label) if refs else _identifier(item, label)) for item in value
    )
    if (not allow_empty and not result) or len(
        {item.casefold() for item in result}
    ) != len(result):
        _fail(f"{label} is invalid")
    return result


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
        _fail("grill source exceeds its byte bound")
    return data


@dataclass(frozen=True)
class GrillLimits:
    context_bytes: int = 32 * 1024
    max_blocks: int = 24
    block_bytes: int = 4096
    source_bytes: int = 2 * 1024 * 1024
    max_turns: int = 24
    schema_version: int = GRILL_SCHEMA_VERSION


@dataclass(frozen=True)
class GrillRequest:
    run_id: str
    operation_id: str
    record_id: str
    created_at: str
    topic: str
    project_refs: tuple[str, ...] = ()
    memory_refs: tuple[str, ...] = ()
    schema_version: int = GRILL_SCHEMA_VERSION


@dataclass(frozen=True)
class GrillContextBlock:
    block_id: str
    zone: str
    logical_ref: str
    source_sha256: str
    source_bytes: int
    text: str
    truncated: bool
    schema_version: int = GRILL_SCHEMA_VERSION


@dataclass(frozen=True)
class GrillContextManifest:
    budget_bytes: int
    used_bytes: int
    source_bytes: int
    block_ids: tuple[str, ...]
    omitted_refs: tuple[str, ...]
    schema_version: int = GRILL_SCHEMA_VERSION


@dataclass(frozen=True)
class GrillQuestionOutput:
    question_id: str
    asked_at: str
    question: str
    evidence_block_ids: tuple[str, ...]
    schema_version: int = GRILL_SCHEMA_VERSION


@dataclass(frozen=True)
class GrillHumanAnswer:
    question_id: str
    actor: str
    answered_at: str
    exact_text: str
    schema_version: int = GRILL_SCHEMA_VERSION


@dataclass(frozen=True)
class GrillTurn:
    index: int
    question: GrillQuestionOutput
    answer: GrillHumanAnswer | None
    schema_version: int = GRILL_SCHEMA_VERSION


@dataclass(frozen=True)
class GrillExplicitDecision:
    decision_id: str
    actor: str
    decided_at: str
    exact_text: str
    schema_version: int = GRILL_SCHEMA_VERSION


@dataclass(frozen=True)
class GrillSession:
    run_id: str
    operation_id: str
    record_id: str
    created_at: str
    topic: str
    request_sha256: str
    context: GrillContextManifest
    blocks: tuple[GrillContextBlock, ...]
    turns: tuple[GrillTurn, ...]
    revision: int
    status: str
    resolution: str | None = None
    explicit_decision: GrillExplicitDecision | None = None
    kind: str = "grill-session"
    flow: str = "grill-me"
    schema_version: int = GRILL_SCHEMA_VERSION


class GrillExecutor(Protocol):
    def ask(
        self, session: GrillSession | None, context: tuple[GrillContextBlock, ...]
    ) -> GrillQuestionOutput | bytes | str: ...


@dataclass(frozen=True)
class GrillDecisionRecord:
    record_id: str
    status: str
    actor: str
    run_id: str
    operation_id: str
    created_at: str
    topic: str
    request_sha256: str
    context: GrillContextManifest
    evidence: tuple[GrillContextBlock, ...]
    turns: tuple[GrillTurn, ...]
    resolution: str
    explicit_decision: GrillExplicitDecision | None
    kind: str = "grill-decision"
    flow: str = "grill-me"
    schema_version: int = GRILL_SCHEMA_VERSION


@dataclass(frozen=True)
class GrillResult:
    status: str
    waiting_for: str | None
    session_artifact: str
    record_ref: str | None = None
    evidence_artifact: str | None = None
    replayed: bool = False
    schema_version: int = GRILL_SCHEMA_VERSION


@dataclass(frozen=True)
class GrillRunEvidence:
    operation_id: str
    output_ref: str
    request_sha256: str
    session_ref: str
    session_sha256: str
    output_sha256: str
    run_state_sha256: str
    outcome_class: str = "proposal-pending"
    role: str = "grill-operation-evidence"
    flow: str = "grill-me"
    schema_version: int = GRILL_SCHEMA_VERSION


@dataclass(frozen=True)
class GrillCapabilities:
    collect_decision_context: ActionCapability
    read_decision_memory: ActionCapability
    commit_question_answer_record: ActionCapability
    record_run_state: ActionCapability


@dataclass(frozen=True)
class GrillCrashHooks:
    after_prepare: Callable[[], None] | None = None
    after_record_publish: Callable[[], None] | None = None
    before_run_commit: Callable[[], None] | None = None


@dataclass(frozen=True)
class _ReviewPublication:
    artifact: PreparedArtifact
    replayed: bool
    directory_fd: int
    filename: str
    owned_identity: tuple[int, int] | None


def _limits(value: GrillLimits) -> GrillLimits:
    if (
        not isinstance(value, GrillLimits)
        or type(value.schema_version) is not int
        or value.schema_version != 1
    ):
        _fail("grill limits are invalid")
    _exact_int(value.context_bytes, "context_bytes", 1024, 128 * 1024)
    _exact_int(value.max_blocks, "max_blocks", 1, 64)
    _exact_int(value.block_bytes, "block_bytes", 128, 32 * 1024)
    _exact_int(value.source_bytes, "source_bytes", value.block_bytes, 4 * 1024 * 1024)
    _exact_int(value.max_turns, "max_turns", 1, 64)
    return value


def _request_payload(value: GrillRequest) -> dict[str, object]:
    if (
        not isinstance(value, GrillRequest)
        or type(value.schema_version) is not int
        or value.schema_version != 1
    ):
        _fail("grill request is invalid")
    return {
        "schema_version": 1,
        "run_id": _identifier(value.run_id, "run_id", _RUN_ID),
        "operation_id": _identifier(value.operation_id, "operation_id"),
        "record_id": _identifier(value.record_id, "record_id", _RECORD_ID),
        "created_at": _timestamp(value.created_at, "created_at"),
        "topic": _text(value.topic, "topic", 8192, layout=True),
        "project_refs": list(
            _string_tuple(value.project_refs, "project_refs", 64, refs=True)
        ),
        "memory_refs": list(
            _string_tuple(value.memory_refs, "memory_refs", 64, refs=True)
        ),
    }


def _block_payload(value: GrillContextBlock) -> dict[str, object]:
    if (
        not isinstance(value, GrillContextBlock)
        or type(value.schema_version) is not int
        or value.schema_version != 1
        or type(value.zone) is not str
        or value.zone not in {"projects", "agent/memory"}
        or type(value.truncated) is not bool
    ):
        _fail("grill context block is invalid")
    logical = _ref(value.logical_ref, "logical_ref")
    if not logical.startswith(value.zone + "/"):
        _fail("grill context block role is invalid")
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


def _parse_block(value: object) -> GrillContextBlock:
    item = _mapping(
        value,
        "grill context block",
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
    result = GrillContextBlock(
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


def _manifest_payload(value: GrillContextManifest) -> dict[str, object]:
    if (
        not isinstance(value, GrillContextManifest)
        or type(value.schema_version) is not int
        or value.schema_version != 1
    ):
        _fail("grill context manifest is invalid")
    return {
        "schema_version": 1,
        "budget_bytes": _exact_int(value.budget_bytes, "budget_bytes", 1, 128 * 1024),
        "used_bytes": _exact_int(value.used_bytes, "used_bytes", 0, value.budget_bytes),
        "source_bytes": _exact_int(
            value.source_bytes, "source_bytes", 0, 4 * 1024 * 1024
        ),
        "block_ids": list(_string_tuple(value.block_ids, "manifest block_ids", 64)),
        "omitted_refs": list(
            _string_tuple(value.omitted_refs, "manifest omitted_refs", 128, refs=True)
        ),
    }


def _parse_manifest(value: object) -> GrillContextManifest:
    item = _mapping(
        value,
        "grill context manifest",
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
        _fail("grill context manifest lists are invalid")
    result = GrillContextManifest(
        item["budget_bytes"],
        item["used_bytes"],
        item["source_bytes"],
        tuple(item["block_ids"]),
        tuple(item["omitted_refs"]),
        item["schema_version"],
    )
    _manifest_payload(result)
    return result


def _question_payload(value: GrillQuestionOutput) -> dict[str, object]:
    if (
        not isinstance(value, GrillQuestionOutput)
        or type(value.schema_version) is not int
        or value.schema_version != 1
    ):
        _fail("grill question output is invalid")
    return {
        "schema_version": 1,
        "question_id": _identifier(value.question_id, "question_id"),
        "asked_at": _timestamp(value.asked_at, "asked_at"),
        "question": _text(value.question, "question", 16 * 1024, layout=True),
        "evidence_block_ids": list(
            _string_tuple(
                value.evidence_block_ids, "question evidence", 24, allow_empty=False
            )
        ),
    }


def render_grill_question_output(value: GrillQuestionOutput) -> bytes:
    return _canonical(_question_payload(value), 64 * 1024)


def parse_grill_question_output(raw: bytes | str) -> GrillQuestionOutput:
    item = _mapping(
        _decode(raw, "grill question output", 64 * 1024),
        "grill question output",
        frozenset(
            {
                "schema_version",
                "question_id",
                "asked_at",
                "question",
                "evidence_block_ids",
            }
        ),
    )
    if not isinstance(item["evidence_block_ids"], list):
        _fail("grill question evidence is invalid")
    result = GrillQuestionOutput(
        item["question_id"],
        item["asked_at"],
        item["question"],
        tuple(item["evidence_block_ids"]),
        item["schema_version"],
    )
    source = raw.encode("utf-8") if isinstance(raw, str) else raw
    if source != render_grill_question_output(result):
        _fail("grill question output must use canonical JSON")
    return result


def _answer_payload(value: GrillHumanAnswer) -> dict[str, object]:
    if (
        not isinstance(value, GrillHumanAnswer)
        or type(value.schema_version) is not int
        or value.schema_version != 1
        or value.actor != "human"
    ):
        _fail("grill answer must be explicit human input")
    return {
        "schema_version": 1,
        "question_id": _identifier(value.question_id, "answer question_id"),
        "actor": value.actor,
        "answered_at": _timestamp(value.answered_at, "answered_at"),
        "exact_text": _text(
            value.exact_text, "answer exact_text", 32 * 1024, layout=True
        ),
    }


def _parse_answer(value: object) -> GrillHumanAnswer:
    item = _mapping(
        value,
        "grill human answer",
        frozenset(
            {"schema_version", "question_id", "actor", "answered_at", "exact_text"}
        ),
    )
    result = GrillHumanAnswer(
        item["question_id"],
        item["actor"],
        item["answered_at"],
        item["exact_text"],
        item["schema_version"],
    )
    _answer_payload(result)
    return result


def _decision_payload(value: GrillExplicitDecision) -> dict[str, object]:
    if (
        not isinstance(value, GrillExplicitDecision)
        or type(value.schema_version) is not int
        or value.schema_version != 1
        or value.actor != "human"
    ):
        _fail("grill decision must be explicit human input")
    return {
        "schema_version": 1,
        "decision_id": _identifier(value.decision_id, "decision_id"),
        "actor": value.actor,
        "decided_at": _timestamp(value.decided_at, "decided_at"),
        "exact_text": _text(
            value.exact_text, "decision exact_text", 32 * 1024, layout=True
        ),
    }


def _parse_decision(value: object) -> GrillExplicitDecision:
    item = _mapping(
        value,
        "grill explicit decision",
        frozenset(
            {"schema_version", "decision_id", "actor", "decided_at", "exact_text"}
        ),
    )
    result = GrillExplicitDecision(
        item["decision_id"],
        item["actor"],
        item["decided_at"],
        item["exact_text"],
        item["schema_version"],
    )
    _decision_payload(result)
    return result


def _turn_payload(value: GrillTurn) -> dict[str, object]:
    if (
        not isinstance(value, GrillTurn)
        or type(value.schema_version) is not int
        or value.schema_version != 1
    ):
        _fail("grill turn is invalid")
    answer = None if value.answer is None else _answer_payload(value.answer)
    question = _question_payload(value.question)
    if answer is not None and answer["question_id"] != question["question_id"]:
        _fail("grill answer does not match its question")
    return {
        "schema_version": 1,
        "index": _exact_int(value.index, "turn index", 0, 63),
        "question": question,
        "answer": answer,
    }


def _parse_turn(value: object) -> GrillTurn:
    item = _mapping(
        value,
        "grill turn",
        frozenset({"schema_version", "index", "question", "answer"}),
    )
    result = GrillTurn(
        item["index"],
        _parse_question_mapping(item["question"]),
        None if item["answer"] is None else _parse_answer(item["answer"]),
        item["schema_version"],
    )
    _turn_payload(result)
    return result


def _parse_question_mapping(value: object) -> GrillQuestionOutput:
    item = _mapping(
        value,
        "grill question",
        frozenset(
            {
                "schema_version",
                "question_id",
                "asked_at",
                "question",
                "evidence_block_ids",
            }
        ),
    )
    if not isinstance(item["evidence_block_ids"], list):
        _fail("grill question evidence is invalid")
    result = GrillQuestionOutput(
        item["question_id"],
        item["asked_at"],
        item["question"],
        tuple(item["evidence_block_ids"]),
        item["schema_version"],
    )
    _question_payload(result)
    return result


def _session_payload(value: GrillSession) -> dict[str, object]:
    if (
        not isinstance(value, GrillSession)
        or type(value.schema_version) is not int
        or value.schema_version != 1
        or value.kind != "grill-session"
        or value.flow != "grill-me"
        or type(value.status) is not str
        or value.status not in {"waiting-answer", "ready-decision", "complete"}
    ):
        _fail("grill session is invalid")
    context = _manifest_payload(value.context)
    blocks = _items(value.blocks, "grill session blocks", 64)
    turns = _items(value.turns, "grill session turns", 64)
    block_payloads = [_block_payload(item) for item in blocks]
    turn_payloads = [_turn_payload(item) for item in turns]
    if (
        not blocks
        or not turns
        or tuple(item.index for item in turns) != tuple(range(len(turns)))
    ):
        _fail("grill session sequence is invalid")
    if (
        tuple(item.block_id for item in blocks) != value.context.block_ids
        or sum(len(item.text.encode("utf-8")) for item in blocks)
        != value.context.used_bytes
        or sum(item.source_bytes for item in blocks) != value.context.source_bytes
    ):
        _fail("grill context manifest disagrees with blocks")
    known = frozenset(value.context.block_ids)
    question_ids = tuple(turn.question.question_id for turn in turns)
    if len(set(question_ids)) != len(question_ids) or any(
        not set(turn.question.evidence_block_ids).issubset(known) for turn in turns
    ):
        _fail("grill question lineage is invalid")
    unanswered = tuple(index for index, turn in enumerate(turns) if turn.answer is None)
    if value.status == "waiting-answer" and unanswered != (len(turns) - 1,):
        _fail("waiting grill session must have one final unanswered turn")
    if value.status in {"ready-decision", "complete"} and unanswered:
        _fail("grill decision state has unanswered questions")
    if value.status == "complete":
        if (
            type(value.resolution) is not str
            or value.resolution not in {"explicit-human-decision", "unresolved"}
            or (value.resolution == "explicit-human-decision")
            != (value.explicit_decision is not None)
        ):
            _fail("grill completed resolution is invalid")
    elif value.resolution is not None or value.explicit_decision is not None:
        _fail("unfinished grill session cannot contain a decision")
    return {
        "schema_version": 1,
        "kind": value.kind,
        "flow": value.flow,
        "run_id": _identifier(value.run_id, "run_id", _RUN_ID),
        "operation_id": _identifier(value.operation_id, "operation_id"),
        "record_id": _identifier(value.record_id, "record_id", _RECORD_ID),
        "created_at": _timestamp(value.created_at, "created_at"),
        "topic": _text(value.topic, "topic", 8192, layout=True),
        "request_sha256": _hash(value.request_sha256, "request_sha256"),
        "context": context,
        "blocks": block_payloads,
        "turns": turn_payloads,
        "revision": _exact_int(value.revision, "revision", 0, 128),
        "status": value.status,
        "resolution": value.resolution,
        "explicit_decision": None
        if value.explicit_decision is None
        else _decision_payload(value.explicit_decision),
    }


def render_grill_session(value: GrillSession) -> bytes:
    return _canonical(_session_payload(value))


def parse_grill_session(raw: bytes | str) -> GrillSession:
    keys = frozenset(
        {
            "schema_version",
            "kind",
            "flow",
            "run_id",
            "operation_id",
            "record_id",
            "created_at",
            "topic",
            "request_sha256",
            "context",
            "blocks",
            "turns",
            "revision",
            "status",
            "resolution",
            "explicit_decision",
        }
    )
    item = _mapping(_decode(raw, "grill session"), "grill session", keys)
    if not isinstance(item["blocks"], list) or not isinstance(item["turns"], list):
        _fail("grill session lists are invalid")
    result = GrillSession(
        item["run_id"],
        item["operation_id"],
        item["record_id"],
        item["created_at"],
        item["topic"],
        item["request_sha256"],
        _parse_manifest(item["context"]),
        tuple(_parse_block(value) for value in item["blocks"]),
        tuple(_parse_turn(value) for value in item["turns"]),
        item["revision"],
        item["status"],
        item["resolution"],
        None
        if item["explicit_decision"] is None
        else _parse_decision(item["explicit_decision"]),
        item["kind"],
        item["flow"],
        item["schema_version"],
    )
    source = raw.encode("utf-8") if isinstance(raw, str) else raw
    if source != render_grill_session(result):
        _fail("grill session must use canonical JSON")
    return result


def _record_payload(value: GrillDecisionRecord) -> dict[str, object]:
    if (
        not isinstance(value, GrillDecisionRecord)
        or type(value.schema_version) is not int
        or value.schema_version != 1
        or value.kind != "grill-decision"
        or value.flow != "grill-me"
        or value.status != "proposed"
        or value.actor != "human"
        or type(value.resolution) is not str
        or value.resolution not in {"explicit-human-decision", "unresolved"}
        or (value.resolution == "explicit-human-decision")
        != (value.explicit_decision is not None)
    ):
        _fail("grill decision record is invalid")
    context = _manifest_payload(value.context)
    evidence_items = _items(value.evidence, "grill decision evidence", 64)
    turn_items = _items(value.turns, "grill decision turns", 64)
    evidence = [_block_payload(item) for item in evidence_items]
    turns = [_turn_payload(item) for item in turn_items]
    if (
        tuple(item.block_id for item in evidence_items) != value.context.block_ids
        or sum(len(item.text.encode("utf-8")) for item in evidence_items)
        != value.context.used_bytes
        or sum(item.source_bytes for item in evidence_items)
        != value.context.source_bytes
        or not turn_items
        or tuple(item.index for item in turn_items) != tuple(range(len(turn_items)))
        or any(item.answer is None for item in turn_items)
        or len({item.question.question_id for item in turn_items}) != len(turn_items)
        or any(
            not set(item.question.evidence_block_ids).issubset(value.context.block_ids)
            for item in turn_items
        )
    ):
        _fail("grill decision record lineage is invalid")
    return {
        "schema_version": 1,
        "kind": value.kind,
        "flow": value.flow,
        "record_id": _identifier(value.record_id, "record_id", _RECORD_ID),
        "status": value.status,
        "actor": value.actor,
        "run_id": _identifier(value.run_id, "run_id", _RUN_ID),
        "operation_id": _identifier(value.operation_id, "operation_id"),
        "created_at": _timestamp(value.created_at, "created_at"),
        "topic": _text(value.topic, "topic", 8192, layout=True),
        "request_sha256": _hash(value.request_sha256, "request_sha256"),
        "context": context,
        "evidence": evidence,
        "turns": turns,
        "resolution": value.resolution,
        "explicit_decision": None
        if value.explicit_decision is None
        else _decision_payload(value.explicit_decision),
    }


def render_grill_decision_record(value: GrillDecisionRecord) -> bytes:
    return _canonical(_record_payload(value))


def parse_grill_decision_record(raw: bytes | str) -> GrillDecisionRecord:
    keys = frozenset(
        {
            "schema_version",
            "kind",
            "flow",
            "record_id",
            "status",
            "actor",
            "run_id",
            "operation_id",
            "created_at",
            "topic",
            "request_sha256",
            "context",
            "evidence",
            "turns",
            "resolution",
            "explicit_decision",
        }
    )
    item = _mapping(
        _decode(raw, "grill decision record"), "grill decision record", keys
    )
    if not isinstance(item["evidence"], list) or not isinstance(item["turns"], list):
        _fail("grill decision record lists are invalid")
    result = GrillDecisionRecord(
        item["record_id"],
        item["status"],
        item["actor"],
        item["run_id"],
        item["operation_id"],
        item["created_at"],
        item["topic"],
        item["request_sha256"],
        _parse_manifest(item["context"]),
        tuple(_parse_block(value) for value in item["evidence"]),
        tuple(_parse_turn(value) for value in item["turns"]),
        item["resolution"],
        None
        if item["explicit_decision"] is None
        else _parse_decision(item["explicit_decision"]),
        item["kind"],
        item["flow"],
        item["schema_version"],
    )
    source = raw.encode("utf-8") if isinstance(raw, str) else raw
    if source != render_grill_decision_record(result):
        _fail("grill decision record must use canonical JSON")
    return result


def grill_evidence_artifact_name(operation_id: str) -> str:
    checked = _identifier(operation_id, "operation_id")
    return "grill-evidence-" + hashlib.sha256(checked.encode()).hexdigest()[:32]


def _session_artifact_name(operation_id: str, revision: int) -> str:
    return (
        "grill-session-"
        + hashlib.sha256(
            _identifier(operation_id, "operation_id").encode()
        ).hexdigest()[:20]
        + f"-{_exact_int(revision, 'revision', 0, 128):04d}"
    )


def _evidence_payload(value: GrillRunEvidence) -> dict[str, object]:
    if (
        not isinstance(value, GrillRunEvidence)
        or type(value.schema_version) is not int
        or value.schema_version != 1
        or value.role != "grill-operation-evidence"
        or value.flow != "grill-me"
        or value.outcome_class != "proposal-pending"
    ):
        _fail("grill run evidence is invalid")
    output_ref = _ref(value.output_ref, "output_ref")
    session_ref = _ref(value.session_ref, "session_ref")
    output_path = PurePosixPath(output_ref)
    if (
        len(output_path.parts) < 2
        or not output_path.name.endswith(".grill.json")
        or not session_ref.startswith("agent/runs/")
    ):
        _fail("grill run evidence roles are invalid")
    return {
        "schema_version": 1,
        "role": value.role,
        "flow": value.flow,
        "operation_id": _identifier(value.operation_id, "operation_id"),
        "output_ref": output_ref,
        "request_sha256": _hash(value.request_sha256, "request_sha256"),
        "session_ref": session_ref,
        "session_sha256": _hash(value.session_sha256, "session_sha256"),
        "output_sha256": _hash(value.output_sha256, "output_sha256"),
        "run_state_sha256": _hash(value.run_state_sha256, "run_state_sha256"),
        "outcome_class": value.outcome_class,
    }


def render_grill_run_evidence(value: GrillRunEvidence) -> bytes:
    return _canonical(_evidence_payload(value))


def parse_grill_run_evidence(raw: bytes | str) -> GrillRunEvidence:
    item = _mapping(
        _decode(raw, "grill run evidence"),
        "grill run evidence",
        frozenset(
            {
                "schema_version",
                "role",
                "flow",
                "operation_id",
                "output_ref",
                "request_sha256",
                "session_ref",
                "session_sha256",
                "output_sha256",
                "run_state_sha256",
                "outcome_class",
            }
        ),
    )
    result = GrillRunEvidence(
        item["operation_id"],
        item["output_ref"],
        item["request_sha256"],
        item["session_ref"],
        item["session_sha256"],
        item["output_sha256"],
        item["run_state_sha256"],
        item["outcome_class"],
        item["role"],
        item["flow"],
        item["schema_version"],
    )
    source = raw.encode("utf-8") if isinstance(raw, str) else raw
    if source != render_grill_run_evidence(result):
        _fail("grill run evidence must use canonical JSON")
    return result


def inspect_grill_run_evidence(
    artifact: PreparedArtifact | CommittedArtifact, raw: bytes | str
) -> GrillRunEvidence:
    if not isinstance(artifact, (PreparedArtifact, CommittedArtifact)):
        _fail("grill run evidence artifact is invalid")
    evidence = parse_grill_run_evidence(raw)
    source = raw.encode("utf-8") if isinstance(raw, str) else raw
    relative = PurePosixPath(_ref(artifact.relative, "artifact relative"))
    expected = grill_evidence_artifact_name(evidence.operation_id)
    if (
        artifact.name != expected
        or artifact.zone != "agent/runs"
        or relative.name != f"{expected}.json"
        or artifact.state_ref != f"agent/runs/{relative.as_posix()}"
        or artifact.sha256 != hashlib.sha256(source).hexdigest()
    ):
        _fail("grill run evidence artifact binding is invalid")
    return evidence


class GrillMeFlow:
    def __init__(
        self,
        resolver: VaultPathResolver,
        run_store: RunStore,
        policy: AuthorityPolicy,
        *,
        limits: GrillLimits | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if (
            not isinstance(resolver, VaultPathResolver)
            or not isinstance(run_store, RunStore)
            or not isinstance(policy, AuthorityPolicy)
            or getattr(run_store, "_resolver", None) is not resolver
        ):
            _fail("grill flow dependencies are invalid")
        self._resolver = resolver
        self._runs = run_store
        self._policy = policy
        self._limits = _limits(limits or GrillLimits())
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def _require(
        self, capability: ActionCapability, action_id: str
    ) -> ActionCapability:
        expected = {
            "collect-decision-context": ("human", "read", "vault:projects"),
            "read-decision-memory": ("human", "read", "vault:agent/memory"),
            "commit-question-answer-record": ("human", "proposal", "vault:review"),
            "record-run-state": ("runtime", "internal-write", "vault:agent/runs"),
        }
        try:
            grant = self._policy.require(capability)
        except AuthorityError as error:
            raise GrillFlowError(str(error)) from None
        if action_id not in expected or (
            grant.flow_id,
            grant.action_id,
            grant.actor,
            grant.authority,
            grant.target,
        ) != ("grill-me", action_id, *expected[action_id]):
            _fail("grill action capability is not exact")
        return grant

    def _check_run(self, run_id: str) -> tuple[str, RunSnapshot]:
        checked = _identifier(run_id, "run_id", _RUN_ID)
        try:
            snapshot = self._runs.snapshot(checked)
        except RunError as error:
            raise GrillFlowError(str(error)) from None
        if (
            snapshot.state.get("flow") != "grill-me"
            or snapshot.state.get("status") != "running"
            or snapshot.state.get("authority") != "proposal"
        ):
            _fail("grill step requires a resumed proposal grill-me run")
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
                _fail("grill source zone is invalid")
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
                _fail("grill vault root changed while opening")

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
                    _fail("grill source parent changed while opening")
                directory_links.append((current_fd, part, child_fd, identity))
                current_fd = child_fd

            leaf = PurePosixPath(checked).name
            named = os.stat(leaf, dir_fd=current_fd, follow_symlinks=False)
            if (
                not stat.S_ISREG(named.st_mode)
                or not 1 <= named.st_size <= self._limits.source_bytes
            ):
                _fail("grill source is not a bounded regular file")
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
                _fail("grill source changed while opening")
            data = _read_fd_bounded(file_fd, self._limits.source_bytes)
            os.lseek(file_fd, 0, os.SEEK_SET)
            if _read_fd_bounded(file_fd, self._limits.source_bytes) != data:
                _fail("grill source content changed while reading")
            final = os.fstat(file_fd)
            named_final = os.stat(leaf, dir_fd=current_fd, follow_symlinks=False)
            if (
                _stat_signature(final) != opened_signature
                or _stat_signature(named_final) != opened_signature
            ):
                _fail("grill source changed while reading")
            for parent_fd, part, child_fd, identity in directory_links:
                opened_parent = os.fstat(child_fd)
                named_parent = os.stat(part, dir_fd=parent_fd, follow_symlinks=False)
                if (
                    not stat.S_ISDIR(opened_parent.st_mode)
                    or (opened_parent.st_dev, opened_parent.st_ino) != identity
                    or (named_parent.st_dev, named_parent.st_ino) != identity
                ):
                    _fail("grill source parent identity changed")
            root_final = os.stat(root, follow_symlinks=False)
            if (root_final.st_dev, root_final.st_ino) != root_identity:
                _fail("grill vault root identity changed")
            self._resolver.revalidate(base, zone, must_exist=True)
            data.decode("utf-8")
            return data, f"{zone}/{checked}"
        except (OSError, UnicodeError, VaultSchemaError):
            _fail("grill source cannot be read safely")
        finally:
            if file_fd is not None:
                os.close(file_fd)
            for directory_fd in reversed(opened_dirs):
                os.close(directory_fd)

    def _context(
        self, request: GrillRequest
    ) -> tuple[GrillContextManifest, tuple[GrillContextBlock, ...]]:
        refs = [("projects", item) for item in request.project_refs] + [
            ("agent/memory", item) for item in request.memory_refs
        ]
        refs.sort(key=lambda item: (item[0], item[1].casefold(), item[1]))
        blocks: list[GrillContextBlock] = []
        omitted: list[str] = []
        used = source_bytes = 0
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
                GrillContextBlock(
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
        if not blocks:
            _fail("grill requires at least one bounded context block")
        manifest = GrillContextManifest(
            self._limits.context_bytes,
            used,
            source_bytes,
            tuple(item.block_id for item in blocks),
            tuple(omitted),
        )
        return manifest, tuple(blocks)

    @staticmethod
    def _coerce_question(
        value: GrillQuestionOutput | bytes | str,
    ) -> GrillQuestionOutput:
        if isinstance(value, GrillQuestionOutput):
            return parse_grill_question_output(render_grill_question_output(value))
        return parse_grill_question_output(value)

    def _prepare_session(self, session: GrillSession) -> tuple[PreparedArtifact, bytes]:
        raw = render_grill_session(session)
        name = _session_artifact_name(session.operation_id, session.revision)
        try:
            return self._runs.prepare_run_artifact(
                session.run_id, name=name, data=raw, maximum_bytes=_MAX_JSON
            ), raw
        except RunError as error:
            raise GrillFlowError(str(error)) from None

    def _read_artifact(
        self, artifact: CommittedArtifact, maximum: int = _MAX_JSON
    ) -> bytes:
        try:
            path = self._resolver.resolve(
                artifact.zone, artifact.relative, must_exist=True
            )
            if path.is_symlink() or not path.is_file() or path.stat().st_size > maximum:
                _fail("grill run artifact is invalid")
            raw = path.read_bytes()
            self._resolver.revalidate(
                path, artifact.zone, artifact.relative, must_exist=True
            )
        except (OSError, VaultSchemaError):
            _fail("grill run artifact cannot be read safely")
        if hashlib.sha256(raw).hexdigest() != artifact.sha256:
            _fail("grill run artifact hash changed")
        return raw

    def _current_session(
        self, snapshot: RunSnapshot
    ) -> tuple[GrillSession, CommittedArtifact]:
        candidates: list[tuple[int, GrillSession, CommittedArtifact]] = []
        for artifact in snapshot.artifacts:
            if artifact.name.startswith("grill-session-"):
                session = parse_grill_session(self._read_artifact(artifact))
                if session.run_id == snapshot.state.get(
                    "run_id"
                ) and artifact.name == _session_artifact_name(
                    session.operation_id, session.revision
                ):
                    candidates.append((session.revision, session, artifact))
        if not candidates:
            _fail("grill run has no durable session")
        candidates.sort(key=lambda item: item[0])
        if len({item[1].operation_id for item in candidates}) != 1 or tuple(
            item[0] for item in candidates
        ) != tuple(range(candidates[-1][0] + 1)):
            _fail("grill run session lineage is ambiguous")
        _, session, artifact = candidates[-1]
        return session, artifact

    def begin(
        self,
        request: GrillRequest,
        question: GrillExecutor | GrillQuestionOutput | bytes | str,
        *,
        capabilities: GrillCapabilities,
        hooks: GrillCrashHooks | None = None,
    ) -> GrillResult:
        request_payload = _request_payload(request)
        if not isinstance(capabilities, GrillCapabilities):
            _fail("grill capabilities are invalid")
        caps = (
            self._require(
                capabilities.collect_decision_context, "collect-decision-context"
            ),
            self._require(capabilities.read_decision_memory, "read-decision-memory"),
            self._require(capabilities.record_run_state, "record-run-state"),
        )
        run_id, snapshot = self._check_run(request.run_id)
        request_raw = _canonical(request_payload)
        if snapshot.artifacts:
            session, artifact = self._current_session(snapshot)
            if (
                session.revision != 0
                or session.status != "waiting-answer"
                or session.run_id != run_id
                or session.operation_id != request.operation_id
                or session.record_id != request.record_id
                or session.request_sha256 != hashlib.sha256(request_raw).hexdigest()
            ):
                _fail("grill begin replay changes the committed session")
            if (
                not hasattr(question, "ask")
                and self._coerce_question(question) != session.turns[0].question
            ):
                _fail("grill begin replay changes the committed question")
            return GrillResult(
                "waiting_human", "grill-answer", artifact.name, replayed=True
            )
        manifest, blocks = self._context(request)
        if hasattr(question, "ask"):
            try:
                question_value = question.ask(None, blocks)
            except Exception:
                _fail("grill question executor failed")
        else:
            question_value = question
        asked = self._coerce_question(question_value)
        if not set(asked.evidence_block_ids).issubset(manifest.block_ids):
            _fail("grill question cites context outside the packet")
        session = GrillSession(
            run_id,
            request.operation_id,
            request.record_id,
            request.created_at,
            request.topic,
            hashlib.sha256(request_raw).hexdigest(),
            manifest,
            blocks,
            (GrillTurn(0, asked, None),),
            0,
            "waiting-answer",
        )
        artifact, session_raw = self._prepare_session(session)
        checked_hooks = self._hooks(hooks)
        if checked_hooks.after_prepare is not None:
            checked_hooks.after_prepare()
        if checked_hooks.before_run_commit is not None:
            checked_hooks.before_run_commit()
        try:
            self._runs.commit_step(
                run_id,
                step_id="grill-begin-"
                + hashlib.sha256(request.operation_id.encode()).hexdigest()[:28],
                authority="internal-write",
                input_hash=hashlib.sha256(request_raw).hexdigest(),
                output_hash=hashlib.sha256(session_raw).hexdigest(),
                next_phase="grill-question",
                next_status="waiting_human",
                waiting_for="grill-answer",
                prepared_artifacts=(artifact,),
                expected_state_sha256=snapshot.state_sha256,
                action_uses=tuple(ActionUse(cap) for cap in caps),
                authority_policy=self._policy,
            )
        except RunError as error:
            raise GrillFlowError(str(error)) from None
        return GrillResult("waiting_human", "grill-answer", artifact.name)

    def answer(
        self,
        run_id: str,
        answer: GrillHumanAnswer,
        *,
        capabilities: GrillCapabilities,
        next_question: GrillExecutor | GrillQuestionOutput | bytes | str | None = None,
        hooks: GrillCrashHooks | None = None,
    ) -> GrillResult:
        if not isinstance(capabilities, GrillCapabilities):
            _fail("grill capabilities are invalid")
        record_cap = self._require(capabilities.record_run_state, "record-run-state")
        checked_run, snapshot = self._check_run(run_id)
        session, _ = self._current_session(snapshot)
        checked_answer = _parse_answer(_answer_payload(answer))
        answered = next(
            (
                turn
                for turn in session.turns
                if turn.question.question_id == checked_answer.question_id
                and turn.answer is not None
            ),
            None,
        )
        if answered is not None:
            if answered.answer != checked_answer:
                _fail("grill answer replay changes committed human input")
            has_following_question = answered.index + 1 < len(session.turns)
            if has_following_question != (next_question is not None):
                _fail("grill answer replay changes the committed transition")
            if has_following_question and not hasattr(next_question, "ask"):
                assert next_question is not None
                if (
                    self._coerce_question(next_question)
                    != session.turns[answered.index + 1].question
                ):
                    _fail("grill answer replay changes the committed next question")
            if session.status == "waiting-answer":
                waiting = "grill-answer"
            elif session.status == "ready-decision":
                waiting = "grill-decision"
            else:
                _fail("grill answer replay is no longer the latest decision step")
            return GrillResult(
                "waiting_human",
                waiting,
                _session_artifact_name(session.operation_id, session.revision),
                replayed=True,
            )
        if session.status != "waiting-answer" or session.run_id != checked_run:
            _fail("grill session is not waiting for an answer")
        current = session.turns[-1]
        if (
            checked_answer.question_id != current.question.question_id
            or current.answer is not None
        ):
            _fail("grill answer does not match the pending question")
        turns = list(session.turns)
        turns[-1] = replace(current, answer=checked_answer)
        answered_session = replace(
            session,
            turns=tuple(turns),
            revision=session.revision + 1,
            status="ready-decision",
        )
        if next_question is not None:
            if len(turns) >= self._limits.max_turns:
                _fail("grill turn limit is exhausted")
            if hasattr(next_question, "ask"):
                try:
                    question_value = next_question.ask(answered_session, session.blocks)
                except Exception:
                    _fail("grill question executor failed")
            else:
                question_value = next_question
            asked = self._coerce_question(question_value)
            if asked.question_id in {
                item.question.question_id for item in turns
            } or not set(asked.evidence_block_ids).issubset(session.context.block_ids):
                _fail("grill next question is not bound to this session")
            turns.append(GrillTurn(len(turns), asked, None))
            status, waiting, phase = "waiting-answer", "grill-answer", "grill-question"
        else:
            status, waiting, phase = (
                "ready-decision",
                "grill-decision",
                "grill-decision",
            )
        updated = replace(answered_session, turns=tuple(turns), status=status)
        artifact, raw = self._prepare_session(updated)
        checked_hooks = self._hooks(hooks)
        if checked_hooks.after_prepare is not None:
            checked_hooks.after_prepare()
        if checked_hooks.before_run_commit is not None:
            checked_hooks.before_run_commit()
        answer_hash = hashlib.sha256(
            _canonical(_answer_payload(checked_answer))
        ).hexdigest()
        try:
            self._runs.commit_step(
                checked_run,
                step_id=f"grill-answer-{updated.revision:04d}-"
                + hashlib.sha256(session.operation_id.encode()).hexdigest()[:20],
                authority="internal-write",
                input_hash=answer_hash,
                output_hash=hashlib.sha256(raw).hexdigest(),
                next_phase=phase,
                next_status="waiting_human",
                waiting_for=waiting,
                prepared_artifacts=(artifact,),
                expected_state_sha256=snapshot.state_sha256,
                action_uses=(ActionUse(record_cap),),
                authority_policy=self._policy,
            )
        except RunError as error:
            raise GrillFlowError(str(error)) from None
        return GrillResult("waiting_human", waiting, artifact.name)

    @staticmethod
    def _hooks(value: GrillCrashHooks | None) -> GrillCrashHooks:
        hooks = value or GrillCrashHooks()
        if not isinstance(hooks, GrillCrashHooks) or any(
            item is not None and not callable(item)
            for item in (
                hooks.after_prepare,
                hooks.after_record_publish,
                hooks.before_run_commit,
            )
        ):
            _fail("grill crash hooks are invalid")
        return hooks

    def _review_location(self, filename: str) -> tuple[Path, str]:
        if PurePosixPath(filename).name != filename:
            _fail("grill review filename is invalid")
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
            _fail("grill review reference cannot be derived safely")
        if (
            resolved != review / filename
            or _ref(state_ref, "grill review ref") != state_ref
        ):
            _fail("grill review reference is not canonical")
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
        quarantine = f".grill-retire-{uuid.uuid4().hex}.tmp"
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
            _fail("grill review directory descriptor cannot be closed")

    def _publish_review(
        self, filename: str, data: bytes, review: Path, state_ref: str
    ) -> _ReviewPublication:
        if PurePosixPath(filename).name != filename or not filename.endswith(
            ".grill.json"
        ):
            _fail("grill review filename is invalid")
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
                _fail("grill review directory changed")
            stage = f".grill-{uuid.uuid4().hex}.tmp"
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
                        _fail("grill record write stalled")
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
                    _fail("grill record publication changed")
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
                        _fail("grill record replay target is invalid")
                    current = b""
                    while True:
                        chunk = os.read(current_fd, 65536)
                        if not chunk:
                            break
                        current += chunk
                finally:
                    os.close(current_fd)
                if current != data:
                    _fail("grill record replay disagrees with existing bytes")
                replayed = True
            self._resolver.revalidate(review, "review", for_write=True, must_exist=True)
            final_named = os.stat(review, follow_symlinks=False)
            if (final_named.st_dev, final_named.st_ino) != (
                opened.st_dev,
                opened.st_ino,
            ):
                _fail("grill review directory changed")
            digest = hashlib.sha256(data).hexdigest()
            artifact = PreparedArtifact(
                "grill-review-" + digest[:32],
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
                raise GrillFlowError(
                    "grill failed publication could not be retired safely"
                ) from None
            if isinstance(error, (OSError, VaultSchemaError)):
                _fail("grill record cannot be published safely")
            raise
        finally:
            if directory_fd is not None:
                if stage is not None:
                    try:
                        os.unlink(stage, dir_fd=directory_fd)
                    except OSError:
                        pass
                if not keep_open:
                    os.close(directory_fd)

    def finish(
        self,
        run_id: str,
        decision: GrillExplicitDecision | None,
        *,
        capabilities: GrillCapabilities,
        hooks: GrillCrashHooks | None = None,
    ) -> GrillResult:
        if not isinstance(capabilities, GrillCapabilities):
            _fail("grill capabilities are invalid")
        commit_cap = self._require(
            capabilities.commit_question_answer_record, "commit-question-answer-record"
        )
        record_cap = self._require(capabilities.record_run_state, "record-run-state")
        checked_run, snapshot = self._check_run(run_id)
        session, current_session_artifact = self._current_session(snapshot)
        if decision is not None:
            checked_decision = _parse_decision(_decision_payload(decision))
        else:
            checked_decision = None
        resolution = (
            "explicit-human-decision" if checked_decision is not None else "unresolved"
        )
        filename = f"{session.record_id}.grill.json"
        review_path, output_ref = self._review_location(filename)
        if session.status == "complete":
            if (
                session.explicit_decision != checked_decision
                or session.resolution != resolution
            ):
                _fail("grill finish replay changes explicit human input")
            evidence_name = grill_evidence_artifact_name(session.operation_id)
            try:
                committed_snapshot = self._runs.producer_snapshot(
                    checked_run, producer_evidence=evidence_name
                )
            except RunError as error:
                raise GrillFlowError(str(error)) from None
            bundle = {item.name: item for item in committed_snapshot.artifacts}
            evidence_artifact = bundle.get(evidence_name)
            if evidence_artifact is None:
                _fail("grill replay lacks committed operation evidence")
            committed = inspect_grill_run_evidence(
                evidence_artifact, self._read_artifact(evidence_artifact)
            )
            review_artifacts = tuple(
                item for item in bundle.values() if item.state_ref == output_ref
            )
            replay_record = GrillDecisionRecord(
                session.record_id,
                "proposed",
                "human",
                checked_run,
                session.operation_id,
                session.created_at,
                session.topic,
                session.request_sha256,
                session.context,
                session.blocks,
                session.turns,
                resolution,
                checked_decision,
            )
            replay_record_raw = render_grill_decision_record(replay_record)
            bundle_session = bundle.get(current_session_artifact.name)
            if (
                len(review_artifacts) != 1
                or set(bundle)
                != {
                    evidence_name,
                    current_session_artifact.name,
                    review_artifacts[0].name,
                }
                or bundle_session is None
                or bundle_session.state_ref != current_session_artifact.state_ref
                or bundle_session.sha256 != current_session_artifact.sha256
                or review_artifacts[0].zone != "review"
                or review_artifacts[0].relative != filename
                or review_artifacts[0].sha256
                != hashlib.sha256(replay_record_raw).hexdigest()
                or self._read_artifact(review_artifacts[0]) != replay_record_raw
                or committed.output_ref != output_ref
                or committed.request_sha256 != session.request_sha256
                or committed.session_ref != current_session_artifact.state_ref
                or committed.session_sha256 != current_session_artifact.sha256
                or committed.output_sha256
                != hashlib.sha256(replay_record_raw).hexdigest()
            ):
                _fail("grill replay changes committed operation evidence")
            return GrillResult(
                "running",
                None,
                current_session_artifact.name,
                committed.output_ref,
                evidence_name,
                True,
            )
        if session.status != "ready-decision" or any(
            turn.answer is None for turn in session.turns
        ):
            _fail("grill cannot finish before every question is answered")
        final_session = replace(
            session,
            revision=session.revision + 1,
            status="complete",
            resolution=resolution,
            explicit_decision=checked_decision,
        )
        session_artifact, session_raw = self._prepare_session(final_session)
        record = GrillDecisionRecord(
            session.record_id,
            "proposed",
            "human",
            checked_run,
            session.operation_id,
            session.created_at,
            session.topic,
            session.request_sha256,
            session.context,
            session.blocks,
            session.turns,
            resolution,
            checked_decision,
        )
        record_raw = render_grill_decision_record(record)
        evidence = GrillRunEvidence(
            session.operation_id,
            output_ref,
            session.request_sha256,
            session_artifact.state_ref,
            hashlib.sha256(session_raw).hexdigest(),
            hashlib.sha256(record_raw).hexdigest(),
            snapshot.state_sha256,
        )
        evidence_raw = render_grill_run_evidence(evidence)
        try:
            evidence_artifact = self._runs.prepare_run_artifact(
                checked_run,
                name=grill_evidence_artifact_name(session.operation_id),
                data=evidence_raw,
                maximum_bytes=_MAX_JSON,
            )
        except RunError as error:
            raise GrillFlowError(str(error)) from None
        checked_hooks = self._hooks(hooks)
        if checked_hooks.after_prepare is not None:
            checked_hooks.after_prepare()
        input_hash = hashlib.sha256(
            b"unresolved"
            if checked_decision is None
            else _canonical(_decision_payload(checked_decision))
        ).hexdigest()
        publication: _ReviewPublication | None = None
        try:
            publication = self._publish_review(
                filename, record_raw, review_path, output_ref
            )
            if checked_hooks.after_record_publish is not None:
                checked_hooks.after_record_publish()
            if checked_hooks.before_run_commit is not None:
                checked_hooks.before_run_commit()
            try:
                self._runs.commit_step(
                    checked_run,
                    step_id="grill-finish-"
                    + hashlib.sha256(session.operation_id.encode()).hexdigest()[:27],
                    authority="proposal",
                    input_hash=input_hash,
                    output_hash=hashlib.sha256(record_raw).hexdigest(),
                    next_phase="grill-committed",
                    next_status="running",
                    prepared_artifacts=(
                        session_artifact,
                        publication.artifact,
                        evidence_artifact,
                    ),
                    expected_state_sha256=snapshot.state_sha256,
                    action_uses=(ActionUse(commit_cap), ActionUse(record_cap)),
                    authority_policy=self._policy,
                )
            except RunError as error:
                raise GrillFlowError(str(error)) from None
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
                _fail("grill failed record could not be retired safely")
            raise
        finally:
            if publication is not None:
                self._close_review_publication(publication)
        return GrillResult(
            "running",
            None,
            session_artifact.name,
            output_ref,
            evidence_artifact.name,
            publication.replayed,
        )
