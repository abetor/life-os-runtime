"""Versioned review artifact and canonical mutation-plan contracts.

Review prose is a human view.  The separate JSON plan is the only machine
description of protected mutations, and it is bound to the exact prose and
provenance that a human reviewed.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
from pathlib import PurePosixPath
import re
from typing import Mapping, Sequence
import unicodedata


ARTIFACT_SCHEMA_VERSION = 1
PLAN_SCHEMA_VERSION = 1
DECISION_SCHEMA_VERSION = 1
APPLICATION_SCHEMA_VERSION = 1
APPLY_JOURNAL_SCHEMA_VERSION = 1

REVIEW_STATUSES = frozenset(
    {"proposed", "approved", "rejected", "applied", "superseded"}
)
SURFACES = frozenset({"silent", "batched", "gated"})
OPERATIONS = frozenset({"create", "update", "move", "archive"})
DECISION_ACTIONS = frozenset({"approve", "reject", "supersede"})
APPLY_JOURNAL_STATUSES = frozenset(
    {"prepared", "committing", "committed", "rolled_back"}
)
APPLY_OPERATION_STATUSES = frozenset({"pending", "committed", "rolled_back"})

_ID = re.compile(r"^rev_[a-z0-9][a-z0-9_-]{0,62}$")
_RUN_ID = re.compile(r"^run_[a-z0-9][a-z0-9_-]{0,62}$")
_JOURNAL_ID = re.compile(r"^apply_[a-z0-9][a-z0-9_-]{0,62}$")
_NAME = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$")
_PRIVATE_MARKERS = ("/" + "Users" + "/", "/" + "home" + "/", "file:")

_MAX_ARTIFACT_BYTES = 256 * 1024
_MAX_FRONTMATTER_BYTES = 64 * 1024
_MAX_BODY_BYTES = 192 * 1024
_MAX_PLAN_BYTES = 512 * 1024
_MAX_JOURNAL_BYTES = 256 * 1024
_MAX_CONTENT_BYTES = 192 * 1024
_MAX_SOURCES = 128
_MAX_OPERATIONS = 128
_MAX_DECISIONS = 128

_ARTIFACT_KEYS = frozenset(
    {
        "kind",
        "schema_version",
        "id",
        "status",
        "flow",
        "created_at",
        "surface",
        "sources",
        "provenance",
        "plan_path",
        "decisions",
        "application",
    }
)
_PLAN_KEYS = frozenset(
    {
        "schema_version",
        "review_id",
        "review_body_sha256",
        "provenance_sha256",
        "operations",
    }
)
_SOURCE_KEYS = frozenset({"kind", "ref"})
_PROVENANCE_KEYS = frozenset({"run_id", "source_hashes"})
_OPERATION_KEYS = frozenset(
    {
        "op",
        "path",
        "destination_path",
        "source_refs",
        "precondition_sha256",
        "postcondition_sha256",
        "content",
    }
)
_DECISION_KEYS = frozenset(
    {
        "schema_version",
        "sequence",
        "action",
        "actor",
        "at",
        "plan_sha256",
        "superseded_by",
    }
)
_APPLICATION_KEYS = frozenset(
    {
        "schema_version",
        "applied_at",
        "plan_sha256",
        "journal_id",
        "journal_sha256",
    }
)
_APPLY_JOURNAL_KEYS = frozenset(
    {
        "schema_version",
        "journal_id",
        "review_id",
        "plan_sha256",
        "status",
        "committed_at",
        "operations",
    }
)
_APPLY_JOURNAL_OPERATION_KEYS = frozenset(
    {
        "sequence",
        "op",
        "path",
        "destination_path",
        "precondition_sha256",
        "postcondition_sha256",
        "status",
    }
)


class ReviewArtifactError(ValueError):
    """Review metadata, mutation plan, or their binding is invalid."""


def _fail(message: str) -> None:
    raise ReviewArtifactError(message)


def _has_control(value: str, *, allow_newlines: bool = False) -> bool:
    for character in value:
        if allow_newlines and character in {"\n", "\r", "\t"}:
            continue
        category = unicodedata.category(character)
        if category.startswith("C") or category in {"Zl", "Zp"}:
            return True
    return False


def _text(
    value: object,
    label: str,
    *,
    maximum: int = 4096,
    pattern: re.Pattern[str] | None = None,
    privacy_safe: bool = True,
) -> str:
    try:
        encoded_size = len(value.encode("utf-8")) if isinstance(value, str) else -1
    except UnicodeError:
        _fail(f"{label} must be valid UTF-8 text")
    if (
        not isinstance(value, str)
        or not value
        or encoded_size > maximum
        or value.strip() != value
        or _has_control(value)
    ):
        _fail(f"{label} must be bounded text")
    if privacy_safe and any(marker in value for marker in _PRIVATE_MARKERS):
        _fail(f"{label} must not contain a private path")
    if pattern is not None and pattern.fullmatch(value) is None:
        _fail(f"{label} has invalid syntax")
    return value


def _body(value: object) -> str:
    try:
        encoded_size = len(value.encode("utf-8")) if isinstance(value, str) else -1
    except UnicodeError:
        _fail("review body is not valid UTF-8 text")
    if not isinstance(value, str) or encoded_size > _MAX_BODY_BYTES:
        _fail("review body is too large or not text")
    if "\x00" in value or _has_control(value, allow_newlines=True):
        _fail("review body contains invalid control characters")
    return value


def _exact_int(value: object, label: str, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        _fail(f"{label} must be an integer >= {minimum}")
    return value


def _sha256(value: object, label: str) -> str:
    return _text(value, label, maximum=64, pattern=_SHA256)


def _timestamp(value: object, label: str) -> str:
    text = _text(value, label, maximum=40)
    if _UTC.fullmatch(text) is None:
        _fail(f"{label} must be a UTC timestamp")
    try:
        datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError:
        _fail(f"{label} must be a valid UTC timestamp")
    return text


def _safe_ref(value: object, label: str) -> str:
    text = _text(value, label, maximum=1024)
    if unicodedata.normalize("NFC", text) != text:
        _fail(f"{label} must use canonical Unicode NFC")
    if "\\" in text:
        _fail(f"{label} must use portable separators")
    path = PurePosixPath(text)
    if path.is_absolute() or path == PurePosixPath(".") or ".." in path.parts:
        _fail(f"{label} must be a safe relative or logical reference")
    if path.as_posix() != text:
        _fail(f"{label} must use canonical POSIX form")
    return text


def _portable_namespace_path(value: str) -> PurePosixPath:
    return PurePosixPath(
        *(unicodedata.normalize("NFC", part.casefold()) for part in PurePosixPath(value).parts)
    )


def _knowledge_path(value: object, label: str) -> str:
    text = _safe_ref(value, label)
    path = PurePosixPath(text)
    if not path.parts or path.parts[0] != "knowledge" or len(path.parts) < 2:
        _fail(f"{label} must be inside knowledge")
    if path.suffix != ".md":
        _fail(f"{label} must name a Markdown knowledge file")
    return text


def _mapping(value: object, label: str, keys: frozenset[str]) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or set(value) != keys:
        _fail(f"{label} has missing or unknown fields")
    return value


def _sequence(value: object, label: str, maximum: int) -> Sequence[object]:
    if not isinstance(value, list) or len(value) > maximum:
        _fail(f"{label} must be a bounded list")
    return value


def _canonical_json_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError):
        _fail("value is not canonical JSON")


def _object_no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            _fail("JSON contains duplicate fields")
        result[key] = value
    return result


def _decode_json(raw: str, label: str) -> object:
    try:
        return json.loads(raw, object_pairs_hook=_object_no_duplicates)
    except ReviewArtifactError:
        raise
    except (UnicodeError, ValueError, RecursionError):
        _fail(f"{label} is not valid JSON")


def _decode_text(raw: str | bytes, label: str, maximum: int) -> str:
    if isinstance(raw, bytes):
        if len(raw) > maximum:
            _fail(f"{label} is too large")
        try:
            return raw.decode("utf-8")
        except UnicodeError:
            _fail(f"{label} is not valid UTF-8")
    if not isinstance(raw, str):
        _fail(f"{label} must be bytes or text")
    try:
        size = len(raw.encode("utf-8"))
    except UnicodeError:
        _fail(f"{label} is not valid UTF-8")
    if size > maximum:
        _fail(f"{label} is too large")
    return raw


@dataclass(frozen=True)
class SourceRef:
    kind: str
    ref: str


@dataclass(frozen=True)
class Provenance:
    run_id: str
    source_hashes: tuple[tuple[str, str], ...]

    def hashes(self) -> dict[str, str]:
        return dict(self.source_hashes)


@dataclass(frozen=True)
class ReviewDecision:
    schema_version: int
    sequence: int
    action: str
    actor: str
    at: str
    plan_sha256: str
    superseded_by: str | None = None


@dataclass(frozen=True)
class ApplicationEvidence:
    schema_version: int
    applied_at: str
    plan_sha256: str
    journal_id: str
    journal_sha256: str


@dataclass(frozen=True)
class ApplyJournalOperation:
    sequence: int
    op: str
    path: str
    destination_path: str | None
    precondition_sha256: str | None
    postcondition_sha256: str
    status: str


@dataclass(frozen=True)
class ApplyJournalEvidence:
    schema_version: int
    journal_id: str
    review_id: str
    plan_sha256: str
    status: str
    committed_at: str
    operations: tuple[ApplyJournalOperation, ...]


@dataclass(frozen=True)
class MutationOperation:
    op: str
    path: str
    destination_path: str | None
    source_refs: tuple[str, ...]
    precondition_sha256: str | None
    postcondition_sha256: str
    content: str | None


@dataclass(frozen=True)
class MutationPlan:
    schema_version: int
    review_id: str
    review_body_sha256: str
    provenance_sha256: str
    operations: tuple[MutationOperation, ...]


@dataclass(frozen=True)
class ReviewArtifact:
    schema_version: int
    review_id: str
    status: str
    flow: str
    created_at: str
    surface: str
    sources: tuple[SourceRef, ...]
    provenance: Provenance
    plan_path: str
    body: str
    decisions: tuple[ReviewDecision, ...] = ()
    application: ApplicationEvidence | None = None


def review_body_sha256(body: str) -> str:
    """Return the binding hash of the exact Markdown body bytes."""

    return hashlib.sha256(_body(body).encode("utf-8")).hexdigest()


def _source_payload(source: SourceRef) -> dict[str, str]:
    return {"kind": source.kind, "ref": source.ref}


def _provenance_payload(provenance: Provenance) -> dict[str, object]:
    return {
        "run_id": provenance.run_id,
        "source_hashes": dict(provenance.source_hashes),
    }


def provenance_sha256(provenance: Provenance) -> str:
    """Hash normalized provenance independently from frontmatter formatting."""

    checked = _parse_provenance(_provenance_payload(provenance), ())
    return hashlib.sha256(_canonical_json_bytes(_provenance_payload(checked))).hexdigest()


def _decision_payload(decision: ReviewDecision) -> dict[str, object]:
    return {
        "schema_version": decision.schema_version,
        "sequence": decision.sequence,
        "action": decision.action,
        "actor": decision.actor,
        "at": decision.at,
        "plan_sha256": decision.plan_sha256,
        "superseded_by": decision.superseded_by,
    }


def _application_payload(application: ApplicationEvidence) -> dict[str, object]:
    return {
        "schema_version": application.schema_version,
        "applied_at": application.applied_at,
        "plan_sha256": application.plan_sha256,
        "journal_id": application.journal_id,
        "journal_sha256": application.journal_sha256,
    }


def _apply_journal_operation_payload(
    operation: ApplyJournalOperation,
) -> dict[str, object]:
    return {
        "sequence": operation.sequence,
        "op": operation.op,
        "path": operation.path,
        "destination_path": operation.destination_path,
        "precondition_sha256": operation.precondition_sha256,
        "postcondition_sha256": operation.postcondition_sha256,
        "status": operation.status,
    }


def apply_journal_payload(journal: ApplyJournalEvidence) -> dict[str, object]:
    """Return the normalized independent apply-journal evidence object."""

    return {
        "schema_version": journal.schema_version,
        "journal_id": journal.journal_id,
        "review_id": journal.review_id,
        "plan_sha256": journal.plan_sha256,
        "status": journal.status,
        "committed_at": journal.committed_at,
        "operations": [
            _apply_journal_operation_payload(operation)
            for operation in journal.operations
        ],
    }


def _operation_payload(operation: MutationOperation) -> dict[str, object]:
    return {
        "op": operation.op,
        "path": operation.path,
        "destination_path": operation.destination_path,
        "source_refs": list(operation.source_refs),
        "precondition_sha256": operation.precondition_sha256,
        "postcondition_sha256": operation.postcondition_sha256,
        "content": operation.content,
    }


def mutation_plan_payload(plan: MutationPlan) -> dict[str, object]:
    """Return the normalized JSON object used for persistence and hashing."""

    return {
        "schema_version": plan.schema_version,
        "review_id": plan.review_id,
        "review_body_sha256": plan.review_body_sha256,
        "provenance_sha256": plan.provenance_sha256,
        "operations": [_operation_payload(operation) for operation in plan.operations],
    }


def render_mutation_plan(plan: MutationPlan) -> bytes:
    """Render one canonical JSON object terminated by a newline."""

    checked = parse_mutation_plan(_canonical_json_bytes(mutation_plan_payload(plan)))
    return _canonical_json_bytes(mutation_plan_payload(checked)) + b"\n"


def mutation_plan_sha256(plan: MutationPlan) -> str:
    """Hash the canonical plan bytes used by human decision evidence."""

    return hashlib.sha256(render_mutation_plan(plan)).hexdigest()


def render_apply_journal(journal: ApplyJournalEvidence) -> bytes:
    """Render independent apply evidence as canonical JSON plus newline."""

    candidate = _canonical_json_bytes(apply_journal_payload(journal)) + b"\n"
    checked = parse_apply_journal(candidate)
    return _canonical_json_bytes(apply_journal_payload(checked)) + b"\n"


def apply_journal_sha256(journal: ApplyJournalEvidence) -> str:
    """Hash exact canonical journal evidence for the artifact reference."""

    return hashlib.sha256(render_apply_journal(journal)).hexdigest()


def _parse_source(value: object) -> SourceRef:
    source = _mapping(value, "source", _SOURCE_KEYS)
    return SourceRef(
        kind=_text(source["kind"], "source.kind", maximum=64, pattern=_NAME),
        ref=_safe_ref(source["ref"], "source.ref"),
    )


def _parse_provenance(value: object, sources: Sequence[SourceRef]) -> Provenance:
    payload = _mapping(value, "provenance", _PROVENANCE_KEYS)
    run_id = _text(payload["run_id"], "provenance.run_id", maximum=64, pattern=_RUN_ID)
    hashes = payload["source_hashes"]
    if not isinstance(hashes, Mapping) or not hashes or len(hashes) > _MAX_SOURCES:
        _fail("provenance.source_hashes must be a bounded non-empty object")
    checked: dict[str, str] = {}
    for ref, digest in hashes.items():
        checked[_safe_ref(ref, "provenance source ref")] = _sha256(
            digest, "provenance source hash"
        )
    _require_disjoint_namespace(tuple(checked), "provenance source refs")
    if sources and set(checked) != {source.ref for source in sources}:
        _fail("provenance hashes must exactly match artifact source refs")
    return Provenance(run_id=run_id, source_hashes=tuple(sorted(checked.items())))


def _parse_decision(value: object, expected_sequence: int) -> ReviewDecision:
    payload = _mapping(value, "decision", _DECISION_KEYS)
    schema_version = _exact_int(payload["schema_version"], "decision.schema_version")
    if schema_version != DECISION_SCHEMA_VERSION:
        _fail("unsupported decision schema_version")
    sequence = _exact_int(payload["sequence"], "decision.sequence", minimum=1)
    if sequence != expected_sequence:
        _fail("decision sequence must be contiguous and ordered")
    action = _text(payload["action"], "decision.action", maximum=16)
    if action not in DECISION_ACTIONS:
        _fail("decision action is unsupported")
    superseded_by = payload["superseded_by"]
    if action == "supersede":
        superseded_by = _text(
            superseded_by, "decision.superseded_by", maximum=64, pattern=_ID
        )
    elif superseded_by is not None:
        _fail("only a supersede decision may name a replacement review")
    return ReviewDecision(
        schema_version=schema_version,
        sequence=sequence,
        action=action,
        actor=_text(payload["actor"], "decision.actor", maximum=128),
        at=_timestamp(payload["at"], "decision.at"),
        plan_sha256=_sha256(payload["plan_sha256"], "decision.plan_sha256"),
        superseded_by=superseded_by,
    )


def _parse_application(value: object) -> ApplicationEvidence:
    payload = _mapping(value, "application", _APPLICATION_KEYS)
    schema_version = _exact_int(payload["schema_version"], "application.schema_version")
    if schema_version != APPLICATION_SCHEMA_VERSION:
        _fail("unsupported application schema_version")
    return ApplicationEvidence(
        schema_version=schema_version,
        applied_at=_timestamp(payload["applied_at"], "application.applied_at"),
        plan_sha256=_sha256(payload["plan_sha256"], "application.plan_sha256"),
        journal_id=_text(
            payload["journal_id"],
            "application.journal_id",
            maximum=64,
            pattern=_JOURNAL_ID,
        ),
        journal_sha256=_sha256(
            payload["journal_sha256"], "application.journal_sha256"
        ),
    )


def _parse_apply_journal_operation(
    value: object, expected_sequence: int
) -> ApplyJournalOperation:
    payload = _mapping(value, "apply journal operation", _APPLY_JOURNAL_OPERATION_KEYS)
    sequence = _exact_int(
        payload["sequence"], "apply journal operation.sequence", minimum=1
    )
    if sequence != expected_sequence:
        _fail("apply journal operation sequence must be contiguous and ordered")
    op = _text(payload["op"], "apply journal operation.op", maximum=16)
    if op not in OPERATIONS:
        _fail("apply journal operation.op is unsupported")
    destination = payload["destination_path"]
    if op in {"move", "archive"}:
        destination = _knowledge_path(
            destination, "apply journal operation.destination_path"
        )
    elif destination is not None:
        _fail("create/update journal operation cannot name a destination")
    precondition = payload["precondition_sha256"]
    if op == "create":
        if precondition is not None:
            _fail("create journal operation requires an absent precondition")
    else:
        precondition = _sha256(
            precondition, "apply journal operation.precondition_sha256"
        )
    status = _text(payload["status"], "apply journal operation.status", maximum=16)
    if status not in APPLY_OPERATION_STATUSES:
        _fail("apply journal operation.status is unsupported")
    return ApplyJournalOperation(
        sequence=sequence,
        op=op,
        path=_knowledge_path(payload["path"], "apply journal operation.path"),
        destination_path=destination,
        precondition_sha256=precondition,
        postcondition_sha256=_sha256(
            payload["postcondition_sha256"],
            "apply journal operation.postcondition_sha256",
        ),
        status=status,
    )


def _validate_decision_status(
    status: str,
    decisions: Sequence[ReviewDecision],
    review_id: str,
    created_at: str,
    application: ApplicationEvidence | None,
) -> None:
    if not decisions:
        if status != "proposed":
            _fail("non-proposed review status requires explicit decision evidence")
        if application is not None:
            _fail("proposed review cannot contain application evidence")
        return
    current_status = "proposed"
    transition_actions = {
        "proposed": frozenset({"approve", "reject", "supersede"}),
        "approved": frozenset({"approve", "reject", "supersede"}),
        "rejected": frozenset({"approve", "supersede"}),
        "superseded": frozenset(),
    }
    action_status = {
        "approve": "approved",
        "reject": "rejected",
        "supersede": "superseded",
    }
    previous: ReviewDecision | None = None
    for current in decisions:
        if current.action not in transition_actions[current_status]:
            _fail("decision history contains an invalid transition")
        if (
            current_status == "approved"
            and current.action == "approve"
            and previous is not None
            and previous.plan_sha256 == current.plan_sha256
        ):
            _fail("decision history contains a redundant approval")
        if previous is not None and datetime.fromisoformat(
            current.at[:-1] + "+00:00"
        ) < datetime.fromisoformat(previous.at[:-1] + "+00:00"):
            _fail("decision timestamps must not move backwards")
        if datetime.fromisoformat(current.at[:-1] + "+00:00") < datetime.fromisoformat(
            created_at[:-1] + "+00:00"
        ):
            _fail("decision timestamp cannot precede review creation")
        current_status = action_status[current.action]
        previous = current
    last = decisions[-1]
    expected = {
        "approve": {"approved", "applied"},
        "reject": {"rejected"},
        "supersede": {"superseded"},
    }[last.action]
    if status not in expected:
        _fail("review status disagrees with explicit decision history")
    if last.superseded_by == review_id:
        _fail("a review cannot supersede itself")
    if status == "applied":
        if application is None:
            _fail("applied review requires application evidence")
        if application.plan_sha256 != last.plan_sha256:
            _fail("application and approval must bind the same plan")
        if datetime.fromisoformat(
            application.applied_at[:-1] + "+00:00"
        ) < datetime.fromisoformat(last.at[:-1] + "+00:00"):
            _fail("application timestamp cannot precede approval")
    elif application is not None:
        _fail("only applied status may contain application evidence")


def _parse_operation(value: object) -> MutationOperation:
    payload = _mapping(value, "operation", _OPERATION_KEYS)
    op = _text(payload["op"], "operation.op", maximum=16)
    if op not in OPERATIONS:
        _fail("operation.op is unsupported")
    path = _knowledge_path(payload["path"], "operation.path")
    destination = payload["destination_path"]
    content = payload["content"]
    precondition = payload["precondition_sha256"]
    postcondition = _sha256(payload["postcondition_sha256"], "operation postcondition")

    refs = _sequence(payload["source_refs"], "operation.source_refs", _MAX_SOURCES)
    if not refs:
        _fail("operation.source_refs must not be empty")
    source_refs = tuple(_safe_ref(ref, "operation source ref") for ref in refs)
    _require_disjoint_namespace(source_refs, "operation source refs")

    if op == "create":
        if precondition is not None:
            _fail("create operation requires an absent precondition")
        if destination is not None:
            _fail("create operation cannot name a destination")
    else:
        precondition = _sha256(precondition, "operation precondition")

    if op in {"create", "update"}:
        try:
            content_size = (
                len(content.encode("utf-8")) if isinstance(content, str) else -1
            )
        except UnicodeError:
            _fail("operation content must be valid UTF-8 text")
        if not isinstance(content, str) or content_size > _MAX_CONTENT_BYTES:
            _fail("create/update operation content must be bounded text")
        if "\x00" in content or _has_control(content, allow_newlines=True):
            _fail("operation content contains invalid control characters")
        if hashlib.sha256(content.encode("utf-8")).hexdigest() != postcondition:
            _fail("operation postcondition does not match exact content bytes")
        if destination is not None:
            _fail("create/update operation cannot name a destination")
    else:
        if content is not None:
            _fail("move/archive operation cannot embed content")
        destination = _knowledge_path(destination, "operation.destination_path")
        if destination == path:
            _fail("move/archive destination must differ from source")
        if postcondition != precondition:
            _fail("move/archive postcondition must preserve source bytes")
        if op == "archive" and "_archive" not in PurePosixPath(destination).parts:
            _fail("archive destination must be inside an _archive directory")

    return MutationOperation(
        op=op,
        path=path,
        destination_path=destination,
        source_refs=source_refs,
        precondition_sha256=precondition,
        postcondition_sha256=postcondition,
        content=content,
    )


def parse_mutation_plan(raw: str | bytes) -> MutationPlan:
    """Decode and validate bounded JSON without accepting duplicate fields."""

    text = _decode_text(raw, "mutation plan", _MAX_PLAN_BYTES)
    payload = _decode_json(text, "mutation plan")
    plan = _mapping(payload, "mutation plan", _PLAN_KEYS)
    schema_version = _exact_int(plan["schema_version"], "plan.schema_version")
    if schema_version != PLAN_SCHEMA_VERSION:
        _fail("unsupported mutation plan schema_version")
    operations_raw = _sequence(plan["operations"], "plan.operations", _MAX_OPERATIONS)
    if not operations_raw:
        _fail("mutation plan must contain at least one operation")
    operations = tuple(_parse_operation(value) for value in operations_raw)
    paths = [operation.path for operation in operations]
    destinations = [
        operation.destination_path
        for operation in operations
        if operation.destination_path is not None
    ]
    _require_disjoint_namespace(paths + destinations, "mutation plan")
    return MutationPlan(
        schema_version=schema_version,
        review_id=_text(plan["review_id"], "plan.review_id", maximum=64, pattern=_ID),
        review_body_sha256=_sha256(
            plan["review_body_sha256"], "plan.review_body_sha256"
        ),
        provenance_sha256=_sha256(
            plan["provenance_sha256"], "plan.provenance_sha256"
        ),
        operations=operations,
    )


def _require_disjoint_namespace(paths: Sequence[str], label: str) -> None:
    for index, first_text in enumerate(paths):
        first = _portable_namespace_path(first_text)
        for second_text in paths[index + 1 :]:
            second = _portable_namespace_path(second_text)
            if first == second or first in second.parents or second in first.parents:
                _fail(
                    f"{label} contains case-insensitive duplicate or parent/file collisions"
                )


def parse_apply_journal(raw: str | bytes) -> ApplyJournalEvidence:
    """Decode bounded independent journal evidence with exact operation records."""

    text = _decode_text(raw, "apply journal", _MAX_JOURNAL_BYTES)
    payload = _decode_json(text, "apply journal")
    journal = _mapping(payload, "apply journal", _APPLY_JOURNAL_KEYS)
    schema_version = _exact_int(
        journal["schema_version"], "apply journal.schema_version"
    )
    if schema_version != APPLY_JOURNAL_SCHEMA_VERSION:
        _fail("unsupported apply journal schema_version")
    status = _text(journal["status"], "apply journal.status", maximum=16)
    if status not in APPLY_JOURNAL_STATUSES:
        _fail("apply journal.status is unsupported")
    operations_raw = _sequence(
        journal["operations"], "apply journal.operations", _MAX_OPERATIONS
    )
    if not operations_raw:
        _fail("apply journal must contain at least one operation")
    operations = tuple(
        _parse_apply_journal_operation(value, index)
        for index, value in enumerate(operations_raw, start=1)
    )
    namespace = [operation.path for operation in operations]
    namespace.extend(
        operation.destination_path
        for operation in operations
        if operation.destination_path is not None
    )
    _require_disjoint_namespace(namespace, "apply journal")
    result = ApplyJournalEvidence(
        schema_version=schema_version,
        journal_id=_text(
            journal["journal_id"],
            "apply journal.journal_id",
            maximum=64,
            pattern=_JOURNAL_ID,
        ),
        review_id=_text(
            journal["review_id"],
            "apply journal.review_id",
            maximum=64,
            pattern=_ID,
        ),
        plan_sha256=_sha256(
            journal["plan_sha256"], "apply journal.plan_sha256"
        ),
        status=status,
        committed_at=_timestamp(
            journal["committed_at"], "apply journal.committed_at"
        ),
        operations=operations,
    )
    if text.encode("utf-8") != _canonical_json_bytes(apply_journal_payload(result)) + b"\n":
        _fail("apply journal must use exact canonical JSON encoding")
    return result


def _parse_frontmatter(text: str) -> tuple[dict[str, object], str]:
    if not text.startswith("---\n"):
        _fail("review artifact must start with Markdown frontmatter")
    boundary = text.find("\n---\n", 4)
    if boundary < 0:
        _fail("review artifact frontmatter is not terminated")
    frontmatter = text[4:boundary]
    if len(frontmatter.encode("utf-8")) > _MAX_FRONTMATTER_BYTES:
        _fail("review artifact frontmatter is too large")
    fields: dict[str, object] = {}
    for line in frontmatter.splitlines():
        if not line or line.startswith((" ", "\t")) or ": " not in line:
            _fail("review artifact frontmatter must use canonical single-line fields")
        key, encoded = line.split(": ", 1)
        if not _NAME.fullmatch(key) or key in fields:
            _fail("review artifact frontmatter has an invalid or duplicate field")
        if key not in _ARTIFACT_KEYS:
            _fail("review artifact frontmatter has missing or unknown fields")
        fields[key] = _decode_json(encoded, f"frontmatter field {key}")
    if set(fields) != _ARTIFACT_KEYS:
        _fail("review artifact frontmatter has missing or unknown fields")
    return fields, text[boundary + 5 :]


def parse_review_artifact(raw: str | bytes) -> ReviewArtifact:
    """Decode strict bounded frontmatter; prose cannot imply state."""

    text = _decode_text(raw, "review artifact", _MAX_ARTIFACT_BYTES)
    fields, body = _parse_frontmatter(text)
    if fields["kind"] != "lifeos-review":
        _fail("review artifact kind is unsupported")
    schema_version = _exact_int(fields["schema_version"], "artifact.schema_version")
    if schema_version != ARTIFACT_SCHEMA_VERSION:
        _fail("unsupported review artifact schema_version")
    review_id = _text(fields["id"], "artifact.id", maximum=64, pattern=_ID)
    created_at = _timestamp(fields["created_at"], "artifact.created_at")
    status = _text(fields["status"], "artifact.status", maximum=16)
    if status not in REVIEW_STATUSES:
        _fail("review artifact status is unsupported")
    sources_raw = _sequence(fields["sources"], "artifact.sources", _MAX_SOURCES)
    if not sources_raw:
        _fail("review artifact must have at least one source")
    sources = tuple(_parse_source(value) for value in sources_raw)
    source_refs = [source.ref for source in sources]
    _require_disjoint_namespace(source_refs, "review artifact source refs")
    provenance = _parse_provenance(fields["provenance"], sources)
    decisions_raw = _sequence(fields["decisions"], "artifact.decisions", _MAX_DECISIONS)
    decisions = tuple(
        _parse_decision(value, index)
        for index, value in enumerate(decisions_raw, start=1)
    )
    application = (
        None if fields["application"] is None else _parse_application(fields["application"])
    )
    _validate_decision_status(
        status, decisions, review_id, created_at, application
    )

    expected_plan_path = f".lifeos/review-plans/{review_id}.json"
    plan_path = _safe_ref(fields["plan_path"], "artifact.plan_path")
    if plan_path != expected_plan_path:
        _fail("artifact.plan_path must exactly match the review id")
    return ReviewArtifact(
        schema_version=schema_version,
        review_id=review_id,
        status=status,
        flow=_text(fields["flow"], "artifact.flow", maximum=64, pattern=_NAME),
        created_at=created_at,
        surface=_surface(fields["surface"]),
        sources=sources,
        provenance=provenance,
        plan_path=plan_path,
        body=_body(body),
        decisions=decisions,
        application=application,
    )


def _surface(value: object) -> str:
    surface = _text(value, "artifact.surface", maximum=16)
    if surface not in SURFACES:
        _fail("artifact.surface is unsupported")
    return surface


def render_review_artifact(artifact: ReviewArtifact) -> str:
    """Render deterministic Markdown with JSON-valued YAML frontmatter."""

    fields: tuple[tuple[str, object], ...] = (
        ("kind", "lifeos-review"),
        ("schema_version", artifact.schema_version),
        ("id", artifact.review_id),
        ("status", artifact.status),
        ("flow", artifact.flow),
        ("created_at", artifact.created_at),
        ("surface", artifact.surface),
        ("sources", [_source_payload(source) for source in artifact.sources]),
        ("provenance", _provenance_payload(artifact.provenance)),
        ("plan_path", artifact.plan_path),
        ("decisions", [_decision_payload(decision) for decision in artifact.decisions]),
        (
            "application",
            None
            if artifact.application is None
            else _application_payload(artifact.application),
        ),
    )
    raw = "---\n" + "\n".join(
        f"{key}: {_canonical_json_bytes(value).decode('utf-8')}" for key, value in fields
    ) + "\n---\n" + artifact.body
    checked = parse_review_artifact(raw)
    if checked != artifact:
        _fail("review artifact cannot be rendered canonically")
    return raw


def validate_plan_binding(artifact: ReviewArtifact, plan: MutationPlan) -> str:
    """Validate exact prose, provenance, identifiers, and source coverage."""

    checked_artifact = parse_review_artifact(render_review_artifact(artifact))
    checked_plan = parse_mutation_plan(render_mutation_plan(plan))
    if checked_plan.review_id != checked_artifact.review_id:
        _fail("mutation plan review_id does not match the artifact")
    if checked_plan.review_body_sha256 != review_body_sha256(checked_artifact.body):
        _fail("review prose changed after the mutation plan was created")
    if checked_plan.provenance_sha256 != provenance_sha256(
        checked_artifact.provenance
    ):
        _fail("review provenance changed after the mutation plan was created")
    artifact_refs = {source.ref for source in checked_artifact.sources}
    operation_refs = {
        ref for operation in checked_plan.operations for ref in operation.source_refs
    }
    if operation_refs != artifact_refs:
        _fail("mutation plan source refs must exactly cover artifact sources")
    return mutation_plan_sha256(checked_plan)


def _coerce_apply_journal(
    journal: ApplyJournalEvidence | Mapping[str, object] | str | bytes,
) -> ApplyJournalEvidence:
    if isinstance(journal, ApplyJournalEvidence):
        return parse_apply_journal(render_apply_journal(journal))
    if isinstance(journal, Mapping):
        return parse_apply_journal(_canonical_json_bytes(journal) + b"\n")
    return parse_apply_journal(journal)


def validate_apply_journal(
    artifact: ReviewArtifact,
    plan: MutationPlan,
    journal: ApplyJournalEvidence | Mapping[str, object] | str | bytes,
) -> ApplyJournalEvidence:
    """Verify independent committed journal evidence against artifact and plan."""

    if artifact.status != "applied" or artifact.application is None:
        _fail("apply journal validation requires applied artifact evidence")
    checked_plan = parse_mutation_plan(render_mutation_plan(plan))
    plan_hash = validate_plan_binding(artifact, checked_plan)
    checked_journal = _coerce_apply_journal(journal)
    application = artifact.application
    if application.plan_sha256 != plan_hash or (
        not artifact.decisions
        or artifact.decisions[-1].plan_sha256 != plan_hash
        or artifact.decisions[-1].action != "approve"
    ):
        _fail("application and approval do not bind the current mutation plan")
    if checked_journal.status != "committed" or any(
        operation.status != "committed" for operation in checked_journal.operations
    ):
        _fail("applied review requires a fully committed apply journal")
    if checked_journal.journal_id != application.journal_id:
        _fail("application evidence names a different apply journal")
    if apply_journal_sha256(checked_journal) != application.journal_sha256:
        _fail("application evidence does not hash the supplied apply journal")
    if checked_journal.review_id != artifact.review_id:
        _fail("apply journal review_id does not match the artifact")
    if checked_journal.plan_sha256 != plan_hash:
        _fail("apply journal does not bind the current mutation plan")
    if checked_journal.committed_at != application.applied_at:
        _fail("application timestamp does not match the apply journal")
    if len(checked_journal.operations) != len(checked_plan.operations):
        _fail("apply journal operation count does not match the mutation plan")
    for journal_operation, plan_operation in zip(
        checked_journal.operations, checked_plan.operations
    ):
        if (
            journal_operation.op,
            journal_operation.path,
            journal_operation.destination_path,
            journal_operation.precondition_sha256,
            journal_operation.postcondition_sha256,
        ) != (
            plan_operation.op,
            plan_operation.path,
            plan_operation.destination_path,
            plan_operation.precondition_sha256,
            plan_operation.postcondition_sha256,
        ):
            _fail("apply journal operation does not match the mutation plan")
    return checked_journal


def validate_artifact_plan(
    artifact: ReviewArtifact,
    plan: MutationPlan,
    *,
    apply_journal: ApplyJournalEvidence | Mapping[str, object] | str | bytes | None = None,
) -> str:
    """Validate decision binding and require independent evidence when applied."""

    digest = validate_plan_binding(artifact, plan)
    if artifact.status != "proposed":
        if not artifact.decisions or artifact.decisions[-1].plan_sha256 != digest:
            _fail("current review decision does not bind the current mutation plan")
    if artifact.status == "applied" and (
        artifact.application is None or artifact.application.plan_sha256 != digest
    ):
        _fail("application evidence does not bind the current mutation plan")
    if artifact.status == "applied":
        if apply_journal is None:
            _fail("applied review requires supplied apply journal evidence")
        validate_apply_journal(artifact, plan, apply_journal)
    elif apply_journal is not None:
        _fail("apply journal evidence is only valid for applied status")
    return digest
