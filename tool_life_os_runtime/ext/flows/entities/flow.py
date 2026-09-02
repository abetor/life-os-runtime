"""Versioned entity, confirmed done-event, and entity-trail lifecycles.

The three record families intentionally have separate files and identifiers.
Every domain mutation first publishes an exact replay request in ``RunStore``;
the run itself stays ``running`` for the shared finalize flow.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Callable, Iterator, Mapping, Sequence
import unicodedata
import uuid

from tool_life_os_runtime.ext.review.authority import (
    ActionCapability,
    AuthorityError,
    AuthorityPolicy,
)
from tool_life_os_runtime.ext.runs import ActionUse, PreparedArtifact, RunError, RunStore
from tool_life_os_runtime.ext.vault.schema import VaultPathResolver, VaultSchemaError


ENTITY_COLLECTION_SCHEMA_VERSION = 1
ENTITY_RECORD_SCHEMA_VERSION = 1
ENTITY_STEP_SCHEMA_VERSION = 1
NEXT_CHECK_POLICY_SCHEMA_VERSION = 1
DONE_EVENT_SCHEMA_VERSION = 1
TRAIL_EVENT_SCHEMA_VERSION = 1
HUMAN_CONFIRMATION_SCHEMA_VERSION = 1
ENTITY_MIGRATION_SCHEMA_VERSION = 1

_ENTITY_ID = re.compile(r"^ent-[a-z0-9][a-z0-9_-]{0,58}$")
_DONE_ID = re.compile(r"^done-[a-z0-9][a-z0-9_-]{0,57}$")
_TRAIL_ID = re.compile(r"^trail-[a-z0-9][a-z0-9_-]{0,56}$")
_OPERATION_ID = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
_STEP_ID = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
_DOMAIN = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$")
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ARCHIVES = frozenset({"_archive", "_trash", "_on_hold"})
_ENTITY_STATUSES = frozenset({"active", "closed", "dropped"})
_STEP_STATUSES = frozenset({"open", "done"})
_PRIORITIES = frozenset({"low", "medium", "high"})
_CHECK_KINDS = frozenset({"at", "after-update"})
_DONE_TYPES = frozenset(
    {"created", "followup-sent", "followup-answered", "closed", "merged", "correction"}
)
_TRAIL_ACTIONS = frozenset({"ping", "done", "skip", "silent"})
_MAX_JSON = 1024 * 1024
_MAX_JSONL = 4 * 1024 * 1024
_MAX_LINE = 16 * 1024
_MAX_RECORDS = 4096
_PRIVATE_PATH = re.compile(r"(?i)(?:/users/|/home/|[a-z]:\\users\\|[a-z]:\\home\\)")
_FILE_SCHEME = re.compile(r"(?i)(?:^|[^a-z0-9_])file:")
_SECRET = re.compile(
    r"(?i)(?:api[_ -]?key|authorization|bearer|cookie|credential|password|secret|token)"
    r"[\"']?\s*[:=]"
)

_ZONE_PARENTS = {
    "agent/memory/entities": "agent/memory",
    "agent/memory/trails": "agent/memory",
    "agent/logs/done-events": "agent/logs",
}


class EntitiesFlowError(ValueError):
    """Entity input, state, authority, or replay evidence is invalid."""


def _fail(message: str) -> None:
    raise EntitiesFlowError(message)


def _portable_key(value: str) -> str:
    return unicodedata.normalize("NFC", value).casefold()


def _text(
    value: object, label: str, *, limit: int = 4096, allow_empty: bool = False
) -> str:
    if not isinstance(value, str) or value != unicodedata.normalize("NFC", value):
        _fail(f"{label} must be NFC text")
    try:
        encoded = value.encode("utf-8")
    except UnicodeError:
        _fail(f"{label} must be valid UTF-8 text")
    if (not allow_empty and not value.strip()) or len(encoded) > limit:
        _fail(f"{label} must be bounded text")
    if any(
        unicodedata.category(character).startswith("C")
        or unicodedata.category(character) in {"Zl", "Zp"}
        for character in value
    ):
        _fail(f"{label} contains non-portable characters")
    if _PRIVATE_PATH.search(value) or _FILE_SCHEME.search(value) or _SECRET.search(value):
        _fail(f"{label} contains private or credential-like text")
    return value


def _identifier(value: object, label: str, pattern: re.Pattern[str]) -> str:
    text = _text(value, label, limit=64)
    if pattern.fullmatch(text) is None or _portable_key(text) in _ARCHIVES:
        _fail(f"{label} is invalid")
    return text


def _domain(value: object) -> str:
    return _identifier(value, "domain", _DOMAIN)


def _exact_int(value: object, label: str, *, minimum: int = 0, maximum: int) -> int:
    if type(value) is not int or value < minimum or value > maximum:
        _fail(f"{label} must be an integer from {minimum} to {maximum}")
    return value


def _timestamp(value: object, label: str) -> str:
    text = _text(value, label, limit=40)
    if _UTC.fullmatch(text) is None:
        _fail(f"{label} must be a UTC timestamp")
    try:
        parsed = datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError:
        _fail(f"{label} must be a valid UTC timestamp")
    if parsed.tzinfo is None:
        _fail(f"{label} must be a UTC timestamp")
    return text


def _temporal(value: object, label: str) -> str:
    text = _text(value, label, limit=40)
    try:
        if _DATE.fullmatch(text):
            datetime.fromisoformat(text)
        elif _UTC.fullmatch(text):
            datetime.fromisoformat(text[:-1] + "+00:00")
        else:
            raise ValueError
    except ValueError:
        _fail(f"{label} must be a date or UTC timestamp")
    return text


def _instant(value: str) -> datetime:
    if _DATE.fullmatch(value):
        return datetime.fromisoformat(value).replace(tzinfo=timezone.utc)
    return datetime.fromisoformat(value[:-1] + "+00:00")


def _hash(value: object, label: str) -> str:
    text = _text(value, label, limit=64)
    if _SHA256.fullmatch(text) is None:
        _fail(f"{label} must be sha256")
    return text


def _canonical(payload: Mapping[str, object]) -> bytes:
    try:
        raw = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8") + b"\n"
    except (TypeError, ValueError, UnicodeError, RecursionError):
        _fail("record is not canonical JSON")
    if len(raw) > _MAX_JSON:
        _fail("record is too large")
    return raw


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _run_step_id(family: str, public_id: str) -> str:
    """Namespace internal RunStore ids without changing public domain ids."""

    if family not in {"entity", "done", "trail"}:
        _fail("run step family is invalid")
    checked = _text(public_id, "public operation id", limit=64)
    return f"{family}-{hashlib.sha256(checked.encode('utf-8')).hexdigest()[:32]}"


def _object_no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            _fail("JSON has duplicate fields")
        result[key] = value
    return result


def _decode_json(raw: bytes, label: str, *, maximum: int = _MAX_JSON) -> object:
    if not raw or len(raw) > maximum:
        _fail(f"{label} is empty or too large")
    try:
        return json.loads(raw, object_pairs_hook=_object_no_duplicates)
    except EntitiesFlowError:
        raise
    except (UnicodeError, ValueError, RecursionError):
        _fail(f"{label} is not valid JSON")


@dataclass(frozen=True)
class NextCheckPolicy:
    kind: str
    due_at: str | None = None
    interval_days: int | None = None
    schema_version: int = NEXT_CHECK_POLICY_SCHEMA_VERSION


@dataclass(frozen=True)
class EntityStep:
    step_id: str
    text: str
    status: str = "open"
    checked_at: str | None = None
    schema_version: int = ENTITY_STEP_SCHEMA_VERSION


@dataclass(frozen=True)
class EntityRecord:
    entity_id: str
    domain: str
    title: str
    description: str
    status: str
    priority: str
    steps: tuple[EntityStep, ...]
    deadline: str | None
    next_review_at: str | None
    next_check: NextCheckPolicy | None
    escalation_paused_until: str | None
    created_at: str
    updated_at: str
    closed_at: str | None
    revision: int
    last_mutation_id: str
    last_mutation_sha256: str
    schema_version: int = ENTITY_RECORD_SCHEMA_VERSION


@dataclass(frozen=True)
class EntityCollection:
    domain: str
    revision: int
    entities: tuple[EntityRecord, ...]
    schema_version: int = ENTITY_COLLECTION_SCHEMA_VERSION


@dataclass(frozen=True)
class HumanConfirmation:
    confirmation_id: str
    confirmed_at: str
    exact_text: str
    actor: str = "human"
    schema_version: int = HUMAN_CONFIRMATION_SCHEMA_VERSION


@dataclass(frozen=True)
class DoneEventRecord:
    event_id: str
    event_type: str
    summary: str
    occurred_at: str
    recorded_at: str
    confirmation: HumanConfirmation
    entity_id: str | None = None
    root_event_id: str | None = None
    related_event_id: str | None = None
    followup_due_at: str | None = None
    merged_into_event_id: str | None = None
    schema_version: int = DONE_EVENT_SCHEMA_VERSION


@dataclass(frozen=True)
class TrailEvent:
    event_id: str
    entity_id: str
    action: str
    at: str
    note: str = ""
    schema_version: int = TRAIL_EVENT_SCHEMA_VERSION


@dataclass(frozen=True)
class StaleQuery:
    as_of: str
    threshold_days: int
    domains: tuple[str, ...] = ()


@dataclass(frozen=True)
class StaleEntity:
    entity: EntityRecord
    reasons: tuple[str, ...]
    stale_since: str


@dataclass(frozen=True)
class FollowupSignal:
    root_event_id: str
    state: str
    due_at: str
    sent_event_id: str | None
    entity_id: str | None


@dataclass(frozen=True)
class EntityMutationResult:
    entity: EntityRecord
    operation: str
    mutation_id: str
    collection_revision: int
    collection_sha256: str
    replayed: bool


@dataclass(frozen=True)
class EntitiesCapabilities:
    read_entity_state: ActionCapability
    read_done_events: ActionCapability
    read_trail_events: ActionCapability
    commit_entity_state: ActionCapability
    append_confirmed_done_event: ActionCapability
    append_entity_trail: ActionCapability
    record_run_state: ActionCapability

    @property
    def read(self) -> ActionCapability:
        return self.read_entity_state

    @property
    def commit(self) -> ActionCapability:
        return self.commit_entity_state

    @property
    def run(self) -> ActionCapability:
        return self.record_run_state


@dataclass(frozen=True)
class LegacyEntitiesMigration:
    schema_version: int
    source_sha256: str
    collection: EntityCollection
    trails: tuple[tuple[str, tuple[TrailEvent, ...]], ...]
    collection_bytes: bytes
    trail_files: tuple[tuple[str, bytes], ...]


def _next_check_payload(policy: NextCheckPolicy | None) -> dict[str, object] | None:
    if policy is None:
        return None
    if not isinstance(policy, NextCheckPolicy) or policy.schema_version != NEXT_CHECK_POLICY_SCHEMA_VERSION:
        _fail("next check policy schema is invalid")
    if policy.kind not in _CHECK_KINDS:
        _fail("next check policy kind is invalid")
    due_at = None if policy.due_at is None else _temporal(policy.due_at, "next check due_at")
    interval = policy.interval_days
    if policy.kind == "at":
        if due_at is None or interval is not None:
            _fail("at next check requires only due_at")
    else:
        if due_at is not None or type(interval) is not int or interval < 1 or interval > 3650:
            _fail("after-update next check requires bounded interval_days")
    return {
        "schema_version": policy.schema_version,
        "kind": policy.kind,
        "due_at": due_at,
        "interval_days": interval,
    }


def _parse_next_check(payload: object) -> NextCheckPolicy | None:
    if payload is None:
        return None
    if not isinstance(payload, Mapping) or set(payload) != {
        "schema_version", "kind", "due_at", "interval_days"
    }:
        _fail("next check policy has missing or unknown fields")
    policy = NextCheckPolicy(
        kind=payload["kind"] if isinstance(payload["kind"], str) else "",
        due_at=payload["due_at"] if isinstance(payload["due_at"], str) else None,
        interval_days=payload["interval_days"] if type(payload["interval_days"]) is int else None,
        schema_version=payload["schema_version"] if type(payload["schema_version"]) is int else -1,
    )
    _next_check_payload(policy)
    if payload["due_at"] is not None and policy.due_at is None:
        _fail("next check due_at has invalid type")
    if payload["interval_days"] is not None and policy.interval_days is None:
        _fail("next check interval_days has invalid type")
    return policy


def _step_payload(step: EntityStep) -> dict[str, object]:
    if not isinstance(step, EntityStep) or step.schema_version != ENTITY_STEP_SCHEMA_VERSION:
        _fail("entity step schema is invalid")
    step_id = _identifier(step.step_id, "step_id", _STEP_ID)
    text = _text(step.text, "step text")
    if step.status not in _STEP_STATUSES:
        _fail("entity step status is invalid")
    checked = None if step.checked_at is None else _timestamp(step.checked_at, "step checked_at")
    if (step.status == "done") != (checked is not None):
        _fail("entity step checked_at disagrees with status")
    return {
        "schema_version": step.schema_version,
        "id": step_id,
        "text": text,
        "status": step.status,
        "checked_at": checked,
    }


def _parse_step(payload: object) -> EntityStep:
    if not isinstance(payload, Mapping) or set(payload) != {
        "schema_version", "id", "text", "status", "checked_at"
    }:
        _fail("entity step has missing or unknown fields")
    step = EntityStep(
        step_id=payload["id"] if isinstance(payload["id"], str) else "",
        text=payload["text"] if isinstance(payload["text"], str) else "",
        status=payload["status"] if isinstance(payload["status"], str) else "",
        checked_at=payload["checked_at"] if isinstance(payload["checked_at"], str) else None,
        schema_version=payload["schema_version"] if type(payload["schema_version"]) is int else -1,
    )
    _step_payload(step)
    if payload["checked_at"] is not None and step.checked_at is None:
        _fail("entity step checked_at has invalid type")
    return step


def _entity_payload(entity: EntityRecord) -> dict[str, object]:
    if not isinstance(entity, EntityRecord) or entity.schema_version != ENTITY_RECORD_SCHEMA_VERSION:
        _fail("entity record schema is invalid")
    entity_id = _identifier(entity.entity_id, "entity_id", _ENTITY_ID)
    domain = _domain(entity.domain)
    title = _text(entity.title, "entity title", limit=512)
    description = _text(entity.description, "entity description", limit=8192, allow_empty=True)
    if entity.status not in _ENTITY_STATUSES or entity.priority not in _PRIORITIES:
        _fail("entity status or priority is invalid")
    if not isinstance(entity.steps, tuple) or len(entity.steps) > 256:
        _fail("entity steps must be a bounded tuple")
    steps = [_step_payload(step) for step in entity.steps]
    step_ids = [_portable_key(str(step["id"])) for step in steps]
    if len(step_ids) != len(set(step_ids)):
        _fail("entity step ids collide after NFC/casefold")
    deadline = None if entity.deadline is None else _temporal(entity.deadline, "entity deadline")
    review = None if entity.next_review_at is None else _temporal(entity.next_review_at, "entity next_review_at")
    paused = (
        None
        if entity.escalation_paused_until is None
        else _temporal(entity.escalation_paused_until, "entity escalation_paused_until")
    )
    created = _timestamp(entity.created_at, "entity created_at")
    updated = _timestamp(entity.updated_at, "entity updated_at")
    if _instant(updated) < _instant(created):
        _fail("entity updated_at precedes created_at")
    closed = None if entity.closed_at is None else _timestamp(entity.closed_at, "entity closed_at")
    if entity.status == "active" and closed is not None:
        _fail("active entity cannot have closed_at")
    if entity.status != "active" and closed is None:
        _fail("terminal entity requires closed_at")
    revision = _exact_int(entity.revision, "entity revision", minimum=1, maximum=2**31 - 1)
    mutation_id = _identifier(entity.last_mutation_id, "last_mutation_id", _OPERATION_ID)
    mutation_hash = _hash(entity.last_mutation_sha256, "last_mutation_sha256")
    return {
        "schema_version": entity.schema_version,
        "id": entity_id,
        "domain": domain,
        "title": title,
        "description": description,
        "status": entity.status,
        "priority": entity.priority,
        "steps": steps,
        "deadline": deadline,
        "next_review_at": review,
        "next_check": _next_check_payload(entity.next_check),
        "escalation_paused_until": paused,
        "created_at": created,
        "updated_at": updated,
        "closed_at": closed,
        "revision": revision,
        "last_mutation_id": mutation_id,
        "last_mutation_sha256": mutation_hash,
    }


_ENTITY_KEYS = frozenset(
    {
        "schema_version", "id", "domain", "title", "description", "status",
        "priority", "steps", "deadline", "next_review_at", "next_check",
        "escalation_paused_until", "created_at", "updated_at", "closed_at",
        "revision", "last_mutation_id", "last_mutation_sha256",
    }
)


def _parse_entity(payload: object) -> EntityRecord:
    if not isinstance(payload, Mapping) or set(payload) != _ENTITY_KEYS:
        _fail("entity record has missing or unknown fields")
    steps_raw = payload["steps"]
    if not isinstance(steps_raw, list):
        _fail("entity steps must be a list")
    entity = EntityRecord(
        entity_id=payload["id"] if isinstance(payload["id"], str) else "",
        domain=payload["domain"] if isinstance(payload["domain"], str) else "",
        title=payload["title"] if isinstance(payload["title"], str) else "",
        description=payload["description"] if isinstance(payload["description"], str) else "",
        status=payload["status"] if isinstance(payload["status"], str) else "",
        priority=payload["priority"] if isinstance(payload["priority"], str) else "",
        steps=tuple(_parse_step(step) for step in steps_raw),
        deadline=payload["deadline"] if isinstance(payload["deadline"], str) else None,
        next_review_at=payload["next_review_at"] if isinstance(payload["next_review_at"], str) else None,
        next_check=_parse_next_check(payload["next_check"]),
        escalation_paused_until=(
            payload["escalation_paused_until"]
            if isinstance(payload["escalation_paused_until"], str)
            else None
        ),
        created_at=payload["created_at"] if isinstance(payload["created_at"], str) else "",
        updated_at=payload["updated_at"] if isinstance(payload["updated_at"], str) else "",
        closed_at=payload["closed_at"] if isinstance(payload["closed_at"], str) else None,
        revision=payload["revision"] if type(payload["revision"]) is int else -1,
        last_mutation_id=payload["last_mutation_id"] if isinstance(payload["last_mutation_id"], str) else "",
        last_mutation_sha256=(
            payload["last_mutation_sha256"]
            if isinstance(payload["last_mutation_sha256"], str)
            else ""
        ),
        schema_version=payload["schema_version"] if type(payload["schema_version"]) is int else -1,
    )
    _entity_payload(entity)
    nullable = ("deadline", "next_review_at", "escalation_paused_until", "closed_at")
    for key in nullable:
        if payload[key] is not None and getattr(entity, key) is None:
            _fail(f"entity {key} has invalid type")
    return entity


def _collection_payload(collection: EntityCollection) -> dict[str, object]:
    if (
        not isinstance(collection, EntityCollection)
        or collection.schema_version != ENTITY_COLLECTION_SCHEMA_VERSION
    ):
        _fail("entity collection schema is invalid")
    domain = _domain(collection.domain)
    revision = _exact_int(collection.revision, "collection revision", minimum=0, maximum=2**31 - 1)
    if not isinstance(collection.entities, tuple) or len(collection.entities) > 1024:
        _fail("entity collection must be a bounded tuple")
    entities = [_entity_payload(entity) for entity in collection.entities]
    keys = [_portable_key(str(entity["id"])) for entity in entities]
    if len(keys) != len(set(keys)):
        _fail("entity ids collide after NFC/casefold")
    if any(entity["domain"] != domain for entity in entities):
        _fail("entity domain disagrees with collection")
    if keys != sorted(keys):
        _fail("entity collection must be sorted by portable id")
    return {
        "schema_version": collection.schema_version,
        "domain": domain,
        "revision": revision,
        "entities": entities,
    }


def _parse_collection(raw: bytes, *, expected_domain: str) -> EntityCollection:
    payload = _decode_json(raw, "entity collection")
    if not isinstance(payload, Mapping) or set(payload) != {
        "schema_version", "domain", "revision", "entities"
    }:
        _fail("entity collection has missing or unknown fields")
    entities_raw = payload["entities"]
    if not isinstance(entities_raw, list):
        _fail("entity collection entities must be a list")
    collection = EntityCollection(
        domain=payload["domain"] if isinstance(payload["domain"], str) else "",
        revision=payload["revision"] if type(payload["revision"]) is int else -1,
        entities=tuple(_parse_entity(item) for item in entities_raw),
        schema_version=payload["schema_version"] if type(payload["schema_version"]) is int else -1,
    )
    canonical = _canonical(_collection_payload(collection))
    if collection.domain != expected_domain:
        _fail("entity collection domain disagrees with filename")
    if raw != canonical:
        _fail("entity collection is not canonical JSON")
    return collection


def _confirmation_payload(confirmation: HumanConfirmation) -> dict[str, object]:
    if (
        not isinstance(confirmation, HumanConfirmation)
        or confirmation.schema_version != HUMAN_CONFIRMATION_SCHEMA_VERSION
    ):
        _fail("human confirmation schema is invalid")
    if confirmation.actor != "human":
        _fail("confirmation actor must be exactly human")
    return {
        "schema_version": confirmation.schema_version,
        "confirmation_id": _identifier(
            confirmation.confirmation_id, "confirmation_id", _OPERATION_ID
        ),
        "actor": confirmation.actor,
        "confirmed_at": _timestamp(confirmation.confirmed_at, "confirmation confirmed_at"),
        "exact_text": _text(confirmation.exact_text, "confirmation exact_text", limit=8192),
    }


def _parse_confirmation(payload: object) -> HumanConfirmation:
    if not isinstance(payload, Mapping) or set(payload) != {
        "schema_version", "confirmation_id", "actor", "confirmed_at", "exact_text"
    }:
        _fail("human confirmation has missing or unknown fields")
    confirmation = HumanConfirmation(
        confirmation_id=payload["confirmation_id"] if isinstance(payload["confirmation_id"], str) else "",
        confirmed_at=payload["confirmed_at"] if isinstance(payload["confirmed_at"], str) else "",
        exact_text=payload["exact_text"] if isinstance(payload["exact_text"], str) else "",
        actor=payload["actor"] if isinstance(payload["actor"], str) else "",
        schema_version=payload["schema_version"] if type(payload["schema_version"]) is int else -1,
    )
    _confirmation_payload(confirmation)
    return confirmation


def _done_payload(event: DoneEventRecord) -> dict[str, object]:
    if not isinstance(event, DoneEventRecord) or event.schema_version != DONE_EVENT_SCHEMA_VERSION:
        _fail("done event schema is invalid")
    event_id = _identifier(event.event_id, "done event_id", _DONE_ID)
    if event.event_type not in _DONE_TYPES:
        _fail("done event type is invalid")
    summary = _text(event.summary, "done summary", limit=8192)
    occurred = _timestamp(event.occurred_at, "done occurred_at")
    recorded = _timestamp(event.recorded_at, "done recorded_at")
    confirmation = _confirmation_payload(event.confirmation)
    if confirmation["exact_text"] != summary:
        _fail("done summary must exactly equal the human confirmation text")
    if _instant(str(confirmation["confirmed_at"])) > _instant(recorded):
        _fail("done confirmation cannot follow recorded_at")
    entity_id = None if event.entity_id is None else _identifier(event.entity_id, "done entity_id", _ENTITY_ID)
    root = None if event.root_event_id is None else _identifier(event.root_event_id, "done root_event_id", _DONE_ID)
    related = (
        None
        if event.related_event_id is None
        else _identifier(event.related_event_id, "done related_event_id", _DONE_ID)
    )
    due = None if event.followup_due_at is None else _temporal(event.followup_due_at, "done followup_due_at")
    merged = (
        None
        if event.merged_into_event_id is None
        else _identifier(event.merged_into_event_id, "done merged_into_event_id", _DONE_ID)
    )
    if event.event_type == "created":
        if root is not None or related is not None or merged is not None:
            _fail("created done event cannot reference another done event")
    else:
        if root is None or root == event_id:
            _fail("derived done event requires a distinct root_event_id")
        if due is not None:
            _fail("only created done event may set followup_due_at")
    if event.event_type == "followup-answered" and related is None:
        _fail("followup-answered requires related sent event")
    if event.event_type == "correction" and related is None:
        _fail("correction requires related event")
    if event.event_type == "merged":
        if merged is None or merged == root:
            _fail("merged event requires a distinct merge target")
    elif merged is not None:
        _fail("only merged event may set merged_into_event_id")
    return {
        "schema_version": event.schema_version,
        "id": event_id,
        "type": event.event_type,
        "summary": summary,
        "occurred_at": occurred,
        "recorded_at": recorded,
        "confirmation": confirmation,
        "entity_id": entity_id,
        "root_event_id": root,
        "related_event_id": related,
        "followup_due_at": due,
        "merged_into_event_id": merged,
    }


_DONE_KEYS = frozenset(
    {
        "schema_version", "id", "type", "summary", "occurred_at", "recorded_at",
        "confirmation", "entity_id", "root_event_id", "related_event_id",
        "followup_due_at", "merged_into_event_id",
    }
)


def _parse_done(payload: object) -> DoneEventRecord:
    if not isinstance(payload, Mapping) or set(payload) != _DONE_KEYS:
        _fail("done event has missing or unknown fields")
    event = DoneEventRecord(
        event_id=payload["id"] if isinstance(payload["id"], str) else "",
        event_type=payload["type"] if isinstance(payload["type"], str) else "",
        summary=payload["summary"] if isinstance(payload["summary"], str) else "",
        occurred_at=payload["occurred_at"] if isinstance(payload["occurred_at"], str) else "",
        recorded_at=payload["recorded_at"] if isinstance(payload["recorded_at"], str) else "",
        confirmation=_parse_confirmation(payload["confirmation"]),
        entity_id=payload["entity_id"] if isinstance(payload["entity_id"], str) else None,
        root_event_id=payload["root_event_id"] if isinstance(payload["root_event_id"], str) else None,
        related_event_id=payload["related_event_id"] if isinstance(payload["related_event_id"], str) else None,
        followup_due_at=payload["followup_due_at"] if isinstance(payload["followup_due_at"], str) else None,
        merged_into_event_id=(
            payload["merged_into_event_id"]
            if isinstance(payload["merged_into_event_id"], str)
            else None
        ),
        schema_version=payload["schema_version"] if type(payload["schema_version"]) is int else -1,
    )
    _done_payload(event)
    nullable = (
        "entity_id", "root_event_id", "related_event_id", "followup_due_at",
        "merged_into_event_id",
    )
    for key in nullable:
        if payload[key] is not None and getattr(event, key) is None:
            _fail(f"done {key} has invalid type")
    return event


def _trail_payload(event: TrailEvent) -> dict[str, object]:
    if not isinstance(event, TrailEvent) or event.schema_version != TRAIL_EVENT_SCHEMA_VERSION:
        _fail("trail event schema is invalid")
    if event.action not in _TRAIL_ACTIONS:
        _fail("trail action is invalid")
    return {
        "schema_version": event.schema_version,
        "id": _identifier(event.event_id, "trail event_id", _TRAIL_ID),
        "entity_id": _identifier(event.entity_id, "trail entity_id", _ENTITY_ID),
        "action": event.action,
        "at": _timestamp(event.at, "trail at"),
        "note": _text(event.note, "trail note", limit=8192, allow_empty=True),
    }


def _parse_trail(payload: object) -> TrailEvent:
    if not isinstance(payload, Mapping) or set(payload) != {
        "schema_version", "id", "entity_id", "action", "at", "note"
    }:
        _fail("trail event has missing or unknown fields")
    event = TrailEvent(
        event_id=payload["id"] if isinstance(payload["id"], str) else "",
        entity_id=payload["entity_id"] if isinstance(payload["entity_id"], str) else "",
        action=payload["action"] if isinstance(payload["action"], str) else "",
        at=payload["at"] if isinstance(payload["at"], str) else "",
        note=payload["note"] if isinstance(payload["note"], str) else "",
        schema_version=payload["schema_version"] if type(payload["schema_version"]) is int else -1,
    )
    _trail_payload(event)
    return event


def _parse_jsonl(raw: bytes, *, kind: str) -> tuple[object, ...]:
    if len(raw) > _MAX_JSONL:
        _fail(f"{kind} log is too large")
    if raw and not raw.endswith(b"\n"):
        _fail(f"{kind} log has a torn final line")
    lines = raw.splitlines()
    if len(lines) > _MAX_RECORDS:
        _fail(f"{kind} log has too many records")
    parsed: list[object] = []
    seen: dict[str, bytes] = {}
    for line in lines:
        if not line or len(line) + 1 > _MAX_LINE:
            _fail(f"{kind} log line is empty or too large")
        payload = _decode_json(line, f"{kind} log line", maximum=_MAX_LINE)
        record = _parse_done(payload) if kind == "done" else _parse_trail(payload)
        canonical = _canonical(
            _done_payload(record) if isinstance(record, DoneEventRecord) else _trail_payload(record)
        )
        if canonical != line + b"\n":
            _fail(f"{kind} log line is not canonical JSON")
        event_id = record.event_id
        key = _portable_key(event_id)
        if key in seen:
            _fail(f"{kind} event ids collide after NFC/casefold")
        seen[key] = canonical
        parsed.append(record)
    return tuple(parsed)


def _safe_name(name: str) -> str:
    if (
        not isinstance(name, str)
        or not name
        or "/" in name
        or "\\" in name
        or name in {".", ".."}
        or name != unicodedata.normalize("NFC", name)
    ):
        _fail("filesystem leaf is invalid")
    return name


def _directory_identity(fd: int) -> tuple[int, int]:
    metadata = os.fstat(fd)
    if not stat.S_ISDIR(metadata.st_mode):
        _fail("opened vault path is not a directory")
    return metadata.st_dev, metadata.st_ino


@dataclass(frozen=True)
class _Zone:
    symbolic: str
    path: Path
    parent_symbolic: str
    parent_path: Path
    parent_fd: int
    fd: int
    parent_identity: tuple[int, int]
    identity: tuple[int, int]


def _read_file_at(directory_fd: int, name: str, maximum: int) -> tuple[bytes, tuple[int, int]]:
    checked = _safe_name(name)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(checked, flags, dir_fd=directory_fd)
    except FileNotFoundError:
        raise
    except OSError:
        _fail("vault file cannot be opened safely")
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
            _fail("vault file is not a bounded regular file")
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
            _fail("vault file is too large")
        after = os.fstat(fd)
        try:
            named = os.stat(checked, dir_fd=directory_fd, follow_symlinks=False)
        except OSError:
            _fail("vault file changed during read")
        identity = (before.st_dev, before.st_ino)
        if (
            identity != (after.st_dev, after.st_ino)
            or identity != (named.st_dev, named.st_ino)
            or not stat.S_ISREG(named.st_mode)
        ):
            _fail("vault file changed during read")
        return raw, identity
    finally:
        os.close(fd)


def _file_identity(directory_fd: int, name: str) -> tuple[int, int] | None:
    try:
        metadata = os.stat(_safe_name(name), dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    except OSError:
        _fail("vault file identity cannot be read")
    if not stat.S_ISREG(metadata.st_mode):
        _fail("vault file must be regular")
    return metadata.st_dev, metadata.st_ino


def _atomic_replace_at(
    directory_fd: int,
    name: str,
    data: bytes,
    *,
    expected_identity: tuple[int, int] | None,
) -> None:
    checked = _safe_name(name)
    if not isinstance(data, bytes) or not data or len(data) > _MAX_JSONL:
        _fail("replacement bytes are invalid or too large")
    if _file_identity(directory_fd, checked) != expected_identity:
        _fail("vault file changed before replace")
    temporary = f".{checked}.{os.getpid()}.{uuid.uuid4().hex}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd: int | None = None
    try:
        fd = os.open(temporary, flags, 0o600, dir_fd=directory_fd)
        offset = 0
        while offset < len(data):
            written = os.write(fd, data[offset:])
            if written <= 0:
                _fail("vault replacement write did not progress")
            offset += written
        os.fsync(fd)
        temporary_identity = os.fstat(fd)
        if not stat.S_ISREG(temporary_identity.st_mode):
            _fail("vault replacement temporary is not regular")
        os.close(fd)
        fd = None
        named_temp = os.stat(temporary, dir_fd=directory_fd, follow_symlinks=False)
        if (named_temp.st_dev, named_temp.st_ino) != (
            temporary_identity.st_dev,
            temporary_identity.st_ino,
        ):
            _fail("vault replacement temporary changed")
        if _file_identity(directory_fd, checked) != expected_identity:
            _fail("vault file changed before replace")
        os.replace(temporary, checked, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
        os.fsync(directory_fd)
        try:
            published = os.stat(checked, dir_fd=directory_fd, follow_symlinks=False)
        except OSError:
            _fail("vault replacement target changed during publish")
        staged_identity = (temporary_identity.st_dev, temporary_identity.st_ino)
        if (
            not stat.S_ISREG(published.st_mode)
            or (published.st_dev, published.st_ino) != staged_identity
        ):
            _fail("vault replacement target changed during publish")
        current, current_identity = _read_file_at(directory_fd, checked, _MAX_JSONL)
        if current_identity != staged_identity or current != data:
            _fail("vault replacement verification failed")
    except EntitiesFlowError:
        raise
    except OSError:
        _fail("vault replacement failed")
    finally:
        if fd is not None:
            os.close(fd)
        try:
            os.unlink(temporary, dir_fd=directory_fd)
        except FileNotFoundError:
            pass
        except OSError:
            pass


class EntitiesFlow:
    """Deterministic operations over independent entity, done, and trail stores."""

    def __init__(
        self,
        resolver: VaultPathResolver,
        run_store: RunStore,
        policy: AuthorityPolicy,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not isinstance(resolver, VaultPathResolver):
            _fail("entities flow requires VaultPathResolver")
        if not isinstance(run_store, RunStore):
            _fail("entities flow requires RunStore")
        if not isinstance(policy, AuthorityPolicy):
            _fail("entities flow requires AuthorityPolicy")
        self._resolver = resolver
        self._runs = run_store
        self._policy = policy
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def _now(self) -> str:
        value = self._clock()
        if not isinstance(value, datetime) or value.tzinfo is None:
            _fail("clock must return an aware datetime")
        return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace(
            "+00:00", "Z"
        )

    def _require(self, capability: ActionCapability, action_id: str) -> ActionCapability:
        expected = {
            "read-entity-state": ("runtime-human-confirmed", "read", "vault:agent/memory/entities"),
            "read-done-events": ("runtime-human-confirmed", "read", "vault:agent/logs/done-events"),
            "read-trail-events": ("runtime-human-confirmed", "read", "vault:agent/memory/trails"),
            "commit-entity-state": ("runtime-human-confirmed", "domain-write", "vault:agent/memory/entities"),
            "append-confirmed-done-event": (
                "runtime-human-confirmed", "domain-write", "vault:agent/logs/done-events"
            ),
            "append-entity-trail": (
                "runtime-human-confirmed", "domain-write", "vault:agent/memory/trails"
            ),
            "record-run-state": ("runtime", "internal-write", "vault:agent/runs"),
        }
        try:
            grant = self._policy.require(capability)
        except AuthorityError as error:
            raise EntitiesFlowError(str(error)) from None
        actor, authority, target = expected[action_id]
        if (
            grant.flow_id != "entities"
            or grant.action_id != action_id
            or grant.actor != actor
            or grant.authority != authority
            or grant.target != target
        ):
            _fail(f"capability does not authorize {action_id}")
        return grant

    def _check_run(self, run_id: str) -> None:
        _identifier(run_id, "run_id", re.compile(r"^run_[a-z0-9][a-z0-9_-]{0,62}$"))
        try:
            state = self._runs.status(run_id)
        except RunError as error:
            raise EntitiesFlowError(str(error)) from None
        if (
            state.get("flow") != "entities"
            or state.get("status") != "running"
            or state.get("authority") != "domain-write"
        ):
            _fail("entity change requires a running entities run")

    def _open_zone(self, symbolic: str, *, for_write: bool) -> _Zone | None:
        parent_symbolic = _ZONE_PARENTS[symbolic]
        try:
            parent_path = self._resolver.resolve(
                parent_symbolic, for_write=for_write, must_exist=True
            )
            target = self._resolver.resolve(symbolic, for_write=for_write, must_exist=False)
        except VaultSchemaError:
            _fail("entities vault zone is unsafe")
        if target.parent != parent_path:
            _fail("derived entities zone is not a direct child of its authority parent")
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            parent_fd = os.open(parent_path, flags)
        except OSError:
            _fail("entities authority parent cannot be opened safely")
        leaf = target.name
        zone_fd: int | None = None
        try:
            parent_identity = _directory_identity(parent_fd)
            try:
                named = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                if not for_write:
                    os.close(parent_fd)
                    return None
                try:
                    os.mkdir(leaf, mode=0o700, dir_fd=parent_fd)
                    os.fsync(parent_fd)
                    named = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
                except OSError:
                    _fail("entities derived zone cannot be created safely")
            if not stat.S_ISDIR(named.st_mode):
                _fail("entities derived zone must be a real directory")
            try:
                zone_fd = os.open(leaf, flags, dir_fd=parent_fd)
            except OSError:
                _fail("entities derived zone cannot be opened safely")
            identity = _directory_identity(zone_fd)
            if identity != (named.st_dev, named.st_ino):
                _fail("entities derived zone changed while opening")
            zone = _Zone(
                symbolic,
                target,
                parent_symbolic,
                parent_path,
                parent_fd,
                zone_fd,
                parent_identity,
                identity,
            )
            self._revalidate_zone(zone, for_write=for_write)
            return zone
        except BaseException:
            if zone_fd is not None:
                os.close(zone_fd)
            os.close(parent_fd)
            raise

    def _revalidate_zone(self, zone: _Zone, *, for_write: bool) -> None:
        try:
            actual_parent = self._resolver.revalidate(
                zone.parent_path,
                zone.parent_symbolic,
                for_write=for_write,
                must_exist=True,
            )
            actual_zone = self._resolver.revalidate(
                zone.path, zone.symbolic, for_write=for_write, must_exist=True
            )
            parent_named = os.stat(actual_parent, follow_symlinks=False)
            zone_named = os.stat(actual_zone, follow_symlinks=False)
            child_named = os.stat(zone.path.name, dir_fd=zone.parent_fd, follow_symlinks=False)
        except (OSError, VaultSchemaError):
            _fail("entities vault zone changed during operation")
        if (
            _directory_identity(zone.parent_fd) != zone.parent_identity
            or _directory_identity(zone.fd) != zone.identity
            or (parent_named.st_dev, parent_named.st_ino) != zone.parent_identity
            or (zone_named.st_dev, zone_named.st_ino) != zone.identity
            or (child_named.st_dev, child_named.st_ino) != zone.identity
            or not stat.S_ISDIR(child_named.st_mode)
        ):
            _fail("entities vault zone changed during operation")

    @staticmethod
    def _close_zone(zone: _Zone | None) -> None:
        if zone is not None:
            os.close(zone.fd)
            os.close(zone.parent_fd)

    @contextmanager
    def _locked_zone(self, symbolic: str) -> Iterator[_Zone]:
        zone = self._open_zone(symbolic, for_write=True)
        assert zone is not None
        lock_fd: int | None = None
        try:
            try:
                lock_fd = os.open(
                    ".entities-flow.lock",
                    os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
                    0o600,
                    dir_fd=zone.fd,
                )
                if not stat.S_ISREG(os.fstat(lock_fd).st_mode):
                    _fail("entities flow lock is invalid")
                fcntl.flock(lock_fd, fcntl.LOCK_EX)
            except OSError:
                _fail("entities flow lock cannot be acquired")
            self._revalidate_zone(zone, for_write=True)
            yield zone
            self._revalidate_zone(zone, for_write=True)
        finally:
            if lock_fd is not None:
                try:
                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
                finally:
                    os.close(lock_fd)
            self._close_zone(zone)

    @staticmethod
    def _entity_names(zone: _Zone) -> tuple[tuple[str, str], ...]:
        found: list[tuple[str, str]] = []
        casefolded: set[str] = set()
        try:
            names = sorted(os.listdir(zone.fd), key=_portable_key)
        except OSError:
            _fail("entity namespace cannot be listed")
        if len(names) > 2048:
            _fail("entity namespace is too large")
        for name in names:
            if name == ".entities-flow.lock" or name in _ARCHIVES:
                continue
            if not name.endswith(".json"):
                continue
            stem = name[:-5]
            domain = _domain(stem)
            key = _portable_key(domain)
            if key in casefolded:
                _fail("entity domain filenames collide after NFC/casefold")
            casefolded.add(key)
            found.append((domain, name))
        return tuple(found)

    def _read_collection_at(self, zone: _Zone, domain: str) -> tuple[EntityCollection, tuple[int, int] | None]:
        checked = _domain(domain)
        name = f"{checked}.json"
        try:
            raw, identity = _read_file_at(zone.fd, name, _MAX_JSON)
        except FileNotFoundError:
            return EntityCollection(checked, 0, ()), None
        collection = _parse_collection(raw, expected_domain=checked)
        return collection, identity

    def _all_collections_at(self, zone: _Zone) -> tuple[EntityCollection, ...]:
        collections = []
        entity_ids: set[str] = set()
        for domain, name in self._entity_names(zone):
            raw, _ = _read_file_at(zone.fd, name, _MAX_JSON)
            collection = _parse_collection(raw, expected_domain=domain)
            for entity in collection.entities:
                key = _portable_key(entity.entity_id)
                if key in entity_ids:
                    _fail("entity id occurs in more than one domain")
                entity_ids.add(key)
            collections.append(collection)
        return tuple(collections)

    @staticmethod
    def _find_entity(collections: Sequence[EntityCollection], entity_id: str) -> EntityRecord:
        checked = _identifier(entity_id, "entity_id", _ENTITY_ID)
        matches = [
            entity
            for collection in collections
            for entity in collection.entities
            if _portable_key(entity.entity_id) == _portable_key(checked)
        ]
        if len(matches) != 1:
            _fail("entity does not exist or is ambiguous")
        return matches[0]

    def list_entities(
        self, capability: ActionCapability, domain: str | None = None
    ) -> tuple[EntityRecord, ...]:
        self._require(capability, "read-entity-state")
        zone = self._open_zone("agent/memory/entities", for_write=False)
        if zone is None:
            return ()
        try:
            self._revalidate_zone(zone, for_write=False)
            if domain is None:
                collections = self._all_collections_at(zone)
            else:
                collection, _ = self._read_collection_at(zone, _domain(domain))
                collections = (collection,)
            self._revalidate_zone(zone, for_write=False)
            return tuple(
                sorted(
                    (entity for item in collections for entity in item.entities),
                    key=lambda entity: (_portable_key(entity.domain), _portable_key(entity.entity_id)),
                )
            )
        finally:
            self._close_zone(zone)

    def status(self, capability: ActionCapability, entity_id: str) -> EntityRecord:
        return self._find_entity(self._collections_for_read(capability), entity_id)

    def _collections_for_read(self, capability: ActionCapability) -> tuple[EntityCollection, ...]:
        self._require(capability, "read-entity-state")
        zone = self._open_zone("agent/memory/entities", for_write=False)
        if zone is None:
            return ()
        try:
            self._revalidate_zone(zone, for_write=False)
            result = self._all_collections_at(zone)
            self._revalidate_zone(zone, for_write=False)
            return result
        finally:
            self._close_zone(zone)

    @staticmethod
    def _request_hash(request: Mapping[str, object]) -> str:
        return _digest(_canonical(request))

    def _prepare_run_evidence(
        self,
        *,
        run_id: str,
        operation_id: str,
        family: str,
        request: Mapping[str, object],
        expected_output_sha256: str,
        run_capability: ActionCapability,
    ) -> tuple[PreparedArtifact, str]:
        self._require(run_capability, "record-run-state")
        self._check_run(run_id)
        operation = _identifier(operation_id, "operation_id", _OPERATION_ID)
        output_hash = _hash(expected_output_sha256, "expected output sha256")
        request_hash = self._request_hash(request)
        evidence = _canonical(
            {
                "schema_version": 1,
                "flow": "entities",
                "family": family,
                "operation_id": operation,
                "request_sha256": request_hash,
                "expected_output_sha256": output_hash,
                "request": dict(request),
            }
        )
        artifact_name = f"entities-{hashlib.sha256((family + ':' + operation).encode()).hexdigest()[:24]}"
        try:
            artifact = self._runs.prepare_run_artifact(
                run_id, name=artifact_name, data=evidence, maximum_bytes=_MAX_JSON
            )
        except RunError as error:
            raise EntitiesFlowError(str(error)) from None
        return artifact, request_hash

    def _load_prepared_evidence(
        self, *, run_id: str, operation_id: str, family: str
    ) -> Mapping[str, object] | None:
        """Read a prior uncommitted request so retry does not sample the clock again."""

        operation = _identifier(operation_id, "operation_id", _OPERATION_ID)
        artifact_name = f"entities-{hashlib.sha256((family + ':' + operation).encode()).hexdigest()[:24]}.json"
        try:
            run_dir = self._resolver.resolve(
                "agent/runs", run_id, for_write=False, must_exist=True
            )
        except VaultSchemaError:
            _fail("prepared run evidence path is unsafe")
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            directory_fd = os.open(run_dir, flags)
        except OSError:
            _fail("prepared run evidence directory cannot be opened safely")
        try:
            identity = _directory_identity(directory_fd)
            try:
                raw, _ = _read_file_at(directory_fd, artifact_name, _MAX_JSON)
            except FileNotFoundError:
                return None
            try:
                actual = self._resolver.revalidate(
                    run_dir, "agent/runs", run_id, for_write=False, must_exist=True
                )
                named = os.stat(actual, follow_symlinks=False)
            except (OSError, VaultSchemaError):
                _fail("prepared run evidence directory changed")
            if (named.st_dev, named.st_ino) != identity:
                _fail("prepared run evidence directory changed")
            payload = _decode_json(raw, "prepared entities evidence")
            if not isinstance(payload, Mapping) or set(payload) != {
                "schema_version", "flow", "family", "operation_id", "request_sha256",
                "expected_output_sha256", "request",
            }:
                _fail("prepared entities evidence has missing or unknown fields")
            if (
                payload["schema_version"] != 1
                or payload["flow"] != "entities"
                or payload["family"] != family
                or payload["operation_id"] != operation
                or not isinstance(payload["request"], Mapping)
            ):
                _fail("prepared entities evidence binding is invalid")
            _hash(payload["request_sha256"], "prepared request sha256")
            _hash(payload["expected_output_sha256"], "prepared output sha256")
            if self._request_hash(payload["request"]) != payload["request_sha256"]:
                _fail("prepared entities request hash is invalid")
            if raw != _canonical(dict(payload)):
                _fail("prepared entities evidence is not canonical")
            return payload
        finally:
            os.close(directory_fd)

    def _commit_run(
        self,
        *,
        run_id: str,
        step_id: str,
        family: str,
        request_hash: str,
        output_hash: str,
        artifact: PreparedArtifact,
        actions: Sequence[ActionCapability],
        run_capability: ActionCapability,
    ) -> None:
        run_grant = self._require(run_capability, "record-run-state")
        uses = tuple(ActionUse(item) for item in (*actions, run_grant))
        try:
            state = self._runs.commit_step(
                run_id,
                step_id=_run_step_id(family, step_id),
                authority="domain-write",
                input_hash=request_hash,
                output_hash=output_hash,
                next_phase="entities-committed",
                next_status="running",
                prepared_artifacts=(artifact,),
                action_uses=uses,
                authority_policy=self._policy,
            )
        except RunError as error:
            raise EntitiesFlowError(str(error)) from None
        if state.get("status") != "running":
            _fail("entities flow must remain running for finalize")

    def _mutate_entity(
        self,
        capabilities: EntitiesCapabilities,
        *,
        run_id: str,
        mutation_id: str,
        operation: str,
        domain: str,
        entity_id: str,
        expected_revision: int | None,
        request_details: Mapping[str, object],
        transform: Callable[[EntityRecord | None, str, str], EntityRecord],
    ) -> EntityMutationResult:
        if not isinstance(capabilities, EntitiesCapabilities):
            _fail("entity mutation requires EntitiesCapabilities")
        # Validate the complete authority envelope before preparing any evidence.
        read_grant = self._require(capabilities.read_entity_state, "read-entity-state")
        commit_grant = self._require(capabilities.commit_entity_state, "commit-entity-state")
        self._require(capabilities.record_run_state, "record-run-state")
        checked_domain = _domain(domain)
        checked_entity = _identifier(entity_id, "entity_id", _ENTITY_ID)
        checked_mutation = _identifier(mutation_id, "mutation_id", _OPERATION_ID)
        if operation not in {
            "create", "update", "add-step", "check-step", "close", "drop",
            "set-deadline", "set-next-review", "set-next-check", "pause-escalation",
        }:
            _fail("entity operation is invalid")
        if expected_revision is not None:
            _exact_int(expected_revision, "expected_revision", minimum=1, maximum=2**31 - 1)

        request_base = {
            "schema_version": 1,
            "mutation_id": checked_mutation,
            "operation": operation,
            "domain": checked_domain,
            "entity_id": checked_entity,
            "expected_revision": expected_revision,
            "details": dict(request_details),
        }
        with self._locked_zone("agent/memory/entities") as zone:
            # The read capability is rechecked at the actual read boundary.
            self._require(read_grant, "read-entity-state")
            collections = self._all_collections_at(zone)
            collection = next(
                (item for item in collections if item.domain == checked_domain),
                EntityCollection(checked_domain, 0, ()),
            )
            current = next(
                (
                    item
                    for item in collection.entities
                    if _portable_key(item.entity_id) == _portable_key(checked_entity)
                ),
                None,
            )
            if current is None and operation != "create":
                _fail("entity does not exist")
            if current is not None and operation == "create" and current.last_mutation_id != checked_mutation:
                _fail("entity already exists")
            prior = self._load_prepared_evidence(
                run_id=run_id, operation_id=checked_mutation, family="entity"
            )
            prior_target: EntityRecord | None = None
            if prior is not None:
                prior_request = prior["request"]
                assert isinstance(prior_request, Mapping)
                if set(prior_request) != {*request_base, "target_entity"}:
                    _fail("prepared entity replay request shape is invalid")
                if {key: prior_request[key] for key in request_base} != request_base:
                    _fail("entity mutation replay conflicts with prepared request")
                prior_target = _parse_entity(prior_request["target_entity"])
            if current is not None and current.last_mutation_id == checked_mutation:
                if current.last_mutation_sha256 != self._request_hash(request_base):
                    _fail("entity mutation replay conflicts with committed request")
                target_entity = current
                replayed = True
            else:
                if current is not None and expected_revision is not None and current.revision != expected_revision:
                    _fail("entity revision is stale")
                if current is None and any(
                    _portable_key(entity.entity_id) == _portable_key(checked_entity)
                    for other in collections
                    for entity in other.entities
                ):
                    _fail("entity id already exists in another domain")
                if prior_target is None:
                    now = self._now()
                    target_entity = transform(current, now, self._request_hash(request_base))
                else:
                    target_entity = prior_target
                    expected_target_revision = 1 if current is None else current.revision + 1
                    if target_entity.revision != expected_target_revision:
                        _fail("prepared entity target disagrees with current revision")
                if target_entity.domain != checked_domain or target_entity.entity_id != checked_entity:
                    _fail("entity transform changed identity")
                target_entity = replace(
                    target_entity,
                    last_mutation_id=checked_mutation,
                    last_mutation_sha256=self._request_hash(request_base),
                )
                _entity_payload(target_entity)
                replayed = False

            entities = tuple(
                sorted(
                    (
                        target_entity
                        if _portable_key(item.entity_id) == _portable_key(checked_entity)
                        else item
                        for item in collection.entities
                    )
                    if current is not None
                    else (*collection.entities, target_entity),
                    key=lambda item: _portable_key(item.entity_id),
                )
            )
            target_collection = EntityCollection(
                checked_domain,
                collection.revision if replayed else collection.revision + 1,
                entities,
            )
            target_bytes = _canonical(_collection_payload(target_collection))
            output_hash = _digest(target_bytes)
            if prior is not None and prior["expected_output_sha256"] != output_hash:
                _fail("prepared entity output disagrees with current target")
            request = dict(request_base)
            request["target_entity"] = _entity_payload(target_entity)
            artifact, request_hash = self._prepare_run_evidence(
                run_id=run_id,
                operation_id=checked_mutation,
                family="entity",
                request=request,
                expected_output_sha256=output_hash,
                run_capability=capabilities.record_run_state,
            )
            # request_base is the durable replay key stored inside the entity.
            # The richer run request binds the exact target bytes and is the trace input.
            if not replayed:
                self._before_entity_replace()
                self._require(commit_grant, "commit-entity-state")
                _, identity = self._read_collection_at(zone, checked_domain)
                _atomic_replace_at(
                    zone.fd,
                    f"{checked_domain}.json",
                    target_bytes,
                    expected_identity=identity,
                )
                self._revalidate_zone(zone, for_write=True)
                actual, _ = self._read_collection_at(zone, checked_domain)
                if _canonical(_collection_payload(actual)) != target_bytes:
                    _fail("entity replace did not preserve exact target")
                self._after_domain_change("entity")
            self._commit_run(
                run_id=run_id,
                step_id=checked_mutation,
                family="entity",
                request_hash=request_hash,
                output_hash=output_hash,
                artifact=artifact,
                actions=(read_grant, commit_grant),
                run_capability=capabilities.record_run_state,
            )
            return EntityMutationResult(
                target_entity,
                operation,
                checked_mutation,
                target_collection.revision,
                output_hash,
                replayed,
            )

    def create(
        self,
        capabilities: EntitiesCapabilities,
        *,
        run_id: str,
        mutation_id: str,
        entity_id: str,
        domain: str,
        title: str,
        description: str = "",
        priority: str = "medium",
        deadline: str | None = None,
        next_review_at: str | None = None,
        next_check: NextCheckPolicy | None = None,
    ) -> EntityMutationResult:
        checked_title = _text(title, "entity title", limit=512)
        checked_description = _text(description, "entity description", limit=8192, allow_empty=True)
        if priority not in _PRIORITIES:
            _fail("entity priority is invalid")
        checked_deadline = None if deadline is None else _temporal(deadline, "entity deadline")
        checked_review = None if next_review_at is None else _temporal(next_review_at, "entity next_review_at")
        _next_check_payload(next_check)

        def build(current: EntityRecord | None, now: str, request_hash: str) -> EntityRecord:
            if current is not None:
                return current
            return EntityRecord(
                entity_id,
                domain,
                checked_title,
                checked_description,
                "active",
                priority,
                (),
                checked_deadline,
                checked_review,
                next_check,
                None,
                now,
                now,
                None,
                1,
                mutation_id,
                request_hash,
            )

        return self._mutate_entity(
            capabilities,
            run_id=run_id,
            mutation_id=mutation_id,
            operation="create",
            domain=domain,
            entity_id=entity_id,
            expected_revision=None,
            request_details={
                "title": checked_title,
                "description": checked_description,
                "priority": priority,
                "deadline": checked_deadline,
                "next_review_at": checked_review,
                "next_check": _next_check_payload(next_check),
            },
            transform=build,
        )

    def update(
        self,
        capabilities: EntitiesCapabilities,
        *,
        run_id: str,
        mutation_id: str,
        entity_id: str,
        domain: str,
        expected_revision: int,
        title: str | None = None,
        description: str | None = None,
        priority: str | None = None,
    ) -> EntityMutationResult:
        if title is None and description is None and priority is None:
            _fail("entity update must change at least one field")
        checked_title = None if title is None else _text(title, "entity title", limit=512)
        checked_description = (
            None
            if description is None
            else _text(description, "entity description", limit=8192, allow_empty=True)
        )
        if priority is not None and priority not in _PRIORITIES:
            _fail("entity priority is invalid")

        def build(current: EntityRecord | None, now: str, request_hash: str) -> EntityRecord:
            assert current is not None
            if current.status != "active":
                _fail("terminal entity cannot be updated")
            return replace(
                current,
                title=current.title if checked_title is None else checked_title,
                description=current.description if checked_description is None else checked_description,
                priority=current.priority if priority is None else priority,
                revision=current.revision + 1,
                updated_at=now,
            )

        return self._mutate_entity(
            capabilities,
            run_id=run_id,
            mutation_id=mutation_id,
            operation="update",
            domain=domain,
            entity_id=entity_id,
            expected_revision=expected_revision,
            request_details={
                "title": checked_title,
                "description": checked_description,
                "priority": priority,
            },
            transform=build,
        )

    def add_step(
        self,
        capabilities: EntitiesCapabilities,
        *,
        run_id: str,
        mutation_id: str,
        entity_id: str,
        domain: str,
        expected_revision: int,
        step: EntityStep,
    ) -> EntityMutationResult:
        _step_payload(step)
        if step.status != "open":
            _fail("new entity step must be open")

        def build(current: EntityRecord | None, now: str, request_hash: str) -> EntityRecord:
            assert current is not None
            if current.status != "active":
                _fail("terminal entity cannot receive a step")
            if any(_portable_key(item.step_id) == _portable_key(step.step_id) for item in current.steps):
                _fail("entity step already exists")
            return replace(current, steps=(*current.steps, step), revision=current.revision + 1, updated_at=now)

        return self._mutate_entity(
            capabilities,
            run_id=run_id,
            mutation_id=mutation_id,
            operation="add-step",
            domain=domain,
            entity_id=entity_id,
            expected_revision=expected_revision,
            request_details={"step": _step_payload(step)},
            transform=build,
        )

    def check_step(
        self,
        capabilities: EntitiesCapabilities,
        *,
        run_id: str,
        mutation_id: str,
        entity_id: str,
        domain: str,
        expected_revision: int,
        step_id: str,
        checked_at: str | None = None,
    ) -> EntityMutationResult:
        checked_step = _identifier(step_id, "step_id", _STEP_ID)
        supplied_at = None if checked_at is None else _timestamp(checked_at, "checked_at")

        def build(current: EntityRecord | None, now: str, request_hash: str) -> EntityRecord:
            assert current is not None
            if current.status != "active":
                _fail("terminal entity step cannot be checked")
            matches = [item for item in current.steps if item.step_id == checked_step]
            if len(matches) != 1 or matches[0].status != "open":
                _fail("open entity step does not exist")
            at = supplied_at or now
            steps = tuple(
                replace(item, status="done", checked_at=at) if item.step_id == checked_step else item
                for item in current.steps
            )
            return replace(current, steps=steps, revision=current.revision + 1, updated_at=now)

        return self._mutate_entity(
            capabilities,
            run_id=run_id,
            mutation_id=mutation_id,
            operation="check-step",
            domain=domain,
            entity_id=entity_id,
            expected_revision=expected_revision,
            request_details={"step_id": checked_step, "checked_at": supplied_at},
            transform=build,
        )

    def _terminal(
        self,
        capabilities: EntitiesCapabilities,
        *,
        run_id: str,
        mutation_id: str,
        entity_id: str,
        domain: str,
        expected_revision: int,
        status: str,
        at: str | None,
    ) -> EntityMutationResult:
        terminal_at = None if at is None else _timestamp(at, "terminal at")

        def build(current: EntityRecord | None, now: str, request_hash: str) -> EntityRecord:
            assert current is not None
            if current.status != "active":
                _fail("entity is already terminal")
            effective = terminal_at or now
            return replace(
                current,
                status=status,
                closed_at=effective,
                revision=current.revision + 1,
                updated_at=now,
            )

        return self._mutate_entity(
            capabilities,
            run_id=run_id,
            mutation_id=mutation_id,
            operation="close" if status == "closed" else "drop",
            domain=domain,
            entity_id=entity_id,
            expected_revision=expected_revision,
            request_details={"status": status, "at": terminal_at},
            transform=build,
        )

    def close(
        self,
        capabilities: EntitiesCapabilities,
        *,
        run_id: str,
        mutation_id: str,
        entity_id: str,
        domain: str,
        expected_revision: int,
        closed_at: str | None = None,
    ) -> EntityMutationResult:
        return self._terminal(
            capabilities,
            run_id=run_id,
            mutation_id=mutation_id,
            entity_id=entity_id,
            domain=domain,
            expected_revision=expected_revision,
            status="closed",
            at=closed_at,
        )

    def drop(
        self,
        capabilities: EntitiesCapabilities,
        *,
        run_id: str,
        mutation_id: str,
        entity_id: str,
        domain: str,
        expected_revision: int,
        dropped_at: str | None = None,
    ) -> EntityMutationResult:
        return self._terminal(
            capabilities,
            run_id=run_id,
            mutation_id=mutation_id,
            entity_id=entity_id,
            domain=domain,
            expected_revision=expected_revision,
            status="dropped",
            at=dropped_at,
        )

    def _set_policy_field(
        self,
        capabilities: EntitiesCapabilities,
        *,
        run_id: str,
        mutation_id: str,
        entity_id: str,
        domain: str,
        expected_revision: int,
        operation: str,
        field: str,
        value: object,
    ) -> EntityMutationResult:
        def build(current: EntityRecord | None, now: str, request_hash: str) -> EntityRecord:
            assert current is not None
            if current.status != "active":
                _fail("terminal entity policy cannot be changed")
            return replace(
                current,
                **{field: value, "revision": current.revision + 1, "updated_at": now},
            )

        return self._mutate_entity(
            capabilities,
            run_id=run_id,
            mutation_id=mutation_id,
            operation=operation,
            domain=domain,
            entity_id=entity_id,
            expected_revision=expected_revision,
            request_details={
                "field": field,
                "value": _next_check_payload(value) if isinstance(value, NextCheckPolicy) else value,
            },
            transform=build,
        )

    def set_deadline(
        self,
        capabilities: EntitiesCapabilities,
        *,
        run_id: str,
        mutation_id: str,
        entity_id: str,
        domain: str,
        expected_revision: int,
        deadline: str | None,
    ) -> EntityMutationResult:
        value = None if deadline is None else _temporal(deadline, "entity deadline")
        return self._set_policy_field(
            capabilities,
            run_id=run_id,
            mutation_id=mutation_id,
            entity_id=entity_id,
            domain=domain,
            expected_revision=expected_revision,
            operation="set-deadline",
            field="deadline",
            value=value,
        )

    def set_next_review(
        self,
        capabilities: EntitiesCapabilities,
        *,
        run_id: str,
        mutation_id: str,
        entity_id: str,
        domain: str,
        expected_revision: int,
        next_review_at: str | None,
    ) -> EntityMutationResult:
        value = (
            None
            if next_review_at is None
            else _temporal(next_review_at, "entity next_review_at")
        )
        return self._set_policy_field(
            capabilities,
            run_id=run_id,
            mutation_id=mutation_id,
            entity_id=entity_id,
            domain=domain,
            expected_revision=expected_revision,
            operation="set-next-review",
            field="next_review_at",
            value=value,
        )

    def set_next_check(
        self,
        capabilities: EntitiesCapabilities,
        *,
        run_id: str,
        mutation_id: str,
        entity_id: str,
        domain: str,
        expected_revision: int,
        next_check: NextCheckPolicy | None,
    ) -> EntityMutationResult:
        _next_check_payload(next_check)
        return self._set_policy_field(
            capabilities,
            run_id=run_id,
            mutation_id=mutation_id,
            entity_id=entity_id,
            domain=domain,
            expected_revision=expected_revision,
            operation="set-next-check",
            field="next_check",
            value=next_check,
        )

    def pause_escalation(
        self,
        capabilities: EntitiesCapabilities,
        *,
        run_id: str,
        mutation_id: str,
        entity_id: str,
        domain: str,
        expected_revision: int,
        until: str | None,
    ) -> EntityMutationResult:
        value = None if until is None else _temporal(until, "escalation pause until")
        return self._set_policy_field(
            capabilities,
            run_id=run_id,
            mutation_id=mutation_id,
            entity_id=entity_id,
            domain=domain,
            expected_revision=expected_revision,
            operation="pause-escalation",
            field="escalation_paused_until",
            value=value,
        )

    def stale(
        self, capability: ActionCapability, query: StaleQuery
    ) -> tuple[StaleEntity, ...]:
        if not isinstance(query, StaleQuery):
            _fail("stale query must use StaleQuery")
        as_of_text = _temporal(query.as_of, "stale as_of")
        threshold = _exact_int(
            query.threshold_days, "stale threshold_days", minimum=1, maximum=3650
        )
        if not isinstance(query.domains, tuple) or len(query.domains) > 128:
            _fail("stale query domains must be a bounded tuple")
        domains = tuple(_domain(item) for item in query.domains)
        if len(domains) != len({_portable_key(item) for item in domains}):
            _fail("stale query domains collide")
        as_of = _instant(as_of_text)
        results: list[StaleEntity] = []
        for entity in self.list_entities(capability):
            if entity.status != "active" or (domains and entity.domain not in domains):
                continue
            if (
                entity.escalation_paused_until is not None
                and as_of < _instant(entity.escalation_paused_until)
            ):
                continue
            reasons: list[tuple[str, datetime]] = []
            inactivity = _instant(entity.updated_at) + timedelta(days=threshold)
            if inactivity <= as_of:
                reasons.append(("inactivity", inactivity))
            if entity.deadline is not None and _instant(entity.deadline) <= as_of:
                reasons.append(("deadline", _instant(entity.deadline)))
            if entity.next_review_at is not None and _instant(entity.next_review_at) <= as_of:
                reasons.append(("review", _instant(entity.next_review_at)))
            if entity.next_check is not None:
                check = entity.next_check
                if check.kind == "at":
                    assert check.due_at is not None
                    due = _instant(check.due_at)
                else:
                    assert check.interval_days is not None
                    due = _instant(entity.updated_at) + timedelta(days=check.interval_days)
                if due <= as_of:
                    reasons.append(("check", due))
            if reasons:
                earliest = min(due for _, due in reasons)
                reason_names = tuple(name for name in ("deadline", "review", "check", "inactivity") if any(item[0] == name for item in reasons))
                results.append(
                    StaleEntity(
                        entity,
                        reason_names,
                        earliest.astimezone(timezone.utc).isoformat(timespec="microseconds").replace(
                            "+00:00", "Z"
                        ),
                    )
                )
        return tuple(
            sorted(
                results,
                key=lambda item: (
                    _instant(item.stale_since),
                    _portable_key(item.entity.domain),
                    _portable_key(item.entity.entity_id),
                ),
            )
        )

    stale_entities = stale

    @staticmethod
    def _read_done_at(zone: _Zone) -> tuple[tuple[DoneEventRecord, ...], bytes, tuple[int, int] | None]:
        try:
            raw, identity = _read_file_at(zone.fd, "events.jsonl", _MAX_JSONL)
        except FileNotFoundError:
            return (), b"", None
        records = _parse_jsonl(raw, kind="done")
        return tuple(item for item in records if isinstance(item, DoneEventRecord)), raw, identity

    @staticmethod
    def _validate_done_graph(events: Sequence[DoneEventRecord], new: DoneEventRecord) -> None:
        by_id = {item.event_id: item for item in events}
        if events and _instant(new.recorded_at) < _instant(events[-1].recorded_at):
            _fail("done events must be appended in recorded_at order")
        if new.event_type == "created":
            return
        assert new.root_event_id is not None
        root = by_id.get(new.root_event_id)
        if root is None or root.event_type != "created":
            _fail("done root event does not exist")
        if new.entity_id is not None and new.entity_id != root.entity_id:
            _fail("done derived event entity_id disagrees with root")
        related = by_id.get(new.related_event_id) if new.related_event_id else None
        if new.event_type == "followup-sent":
            if any(
                item.root_event_id == root.event_id
                and item.event_type in {"followup-sent", "followup-answered", "closed", "merged"}
                for item in events
            ):
                _fail("done followup is already sent or terminal")
        elif new.event_type == "followup-answered":
            if (
                related is None
                or related.event_type != "followup-sent"
                or related.root_event_id != root.event_id
            ):
                _fail("followup answer requires the matching sent event")
            if any(
                item.root_event_id == root.event_id
                and item.event_type in {"followup-answered", "closed", "merged"}
                for item in events
            ):
                _fail("done followup is already answered or terminal")
        elif new.event_type in {"closed", "merged"}:
            if any(
                item.root_event_id == root.event_id and item.event_type in {"closed", "merged"}
                for item in events
            ):
                _fail("done event is already terminal")
            if new.event_type == "merged":
                target = by_id.get(new.merged_into_event_id or "")
                if target is None or target.event_type != "created":
                    _fail("done merge target does not exist")
        elif new.event_type == "correction" and related is None:
            _fail("done correction target does not exist")

    def append_done_event(
        self,
        capabilities: EntitiesCapabilities,
        *,
        run_id: str,
        event: DoneEventRecord,
    ) -> DoneEventRecord:
        if not isinstance(capabilities, EntitiesCapabilities):
            _fail("done append requires EntitiesCapabilities")
        payload = _done_payload(event)
        line = _canonical(payload)
        if len(line) > _MAX_LINE:
            _fail("done event line is too large")
        read_grant = self._require(capabilities.read_done_events, "read-done-events")
        append_grant = self._require(
            capabilities.append_confirmed_done_event, "append-confirmed-done-event"
        )
        self._require(capabilities.record_run_state, "record-run-state")
        with self._locked_zone("agent/logs/done-events") as zone:
            self._require(read_grant, "read-done-events")
            events, raw, identity = self._read_done_at(zone)
            matches = [item for item in events if _portable_key(item.event_id) == _portable_key(event.event_id)]
            if matches:
                if len(matches) != 1 or _canonical(_done_payload(matches[0])) != line:
                    _fail("done event replay conflicts with existing event")
                replayed = True
            else:
                self._validate_done_graph(events, event)
                if len(raw) + len(line) > _MAX_JSONL:
                    _fail("done event log would exceed its bound")
                replayed = False
            output_hash = _digest(line)
            artifact, request_hash = self._prepare_run_evidence(
                run_id=run_id,
                operation_id=event.event_id,
                family="done",
                request={"schema_version": 1, "record": payload},
                expected_output_sha256=output_hash,
                run_capability=capabilities.record_run_state,
            )
            if not replayed:
                self._before_log_replace("done")
                self._require(append_grant, "append-confirmed-done-event")
                _atomic_replace_at(
                    zone.fd,
                    "events.jsonl",
                    raw + line,
                    expected_identity=identity,
                )
                self._revalidate_zone(zone, for_write=True)
                self._after_domain_change("done")
            self._commit_run(
                run_id=run_id,
                step_id=event.event_id,
                family="done",
                request_hash=request_hash,
                output_hash=output_hash,
                artifact=artifact,
                actions=(read_grant, append_grant),
                run_capability=capabilities.record_run_state,
            )
            return event

    def create_done(
        self,
        capabilities: EntitiesCapabilities,
        *,
        run_id: str,
        event_id: str,
        summary: str,
        occurred_at: str,
        confirmation: HumanConfirmation,
        entity_id: str | None = None,
        followup_due_at: str | None = None,
        recorded_at: str | None = None,
    ) -> DoneEventRecord:
        event = DoneEventRecord(
            event_id=event_id,
            event_type="created",
            summary=summary,
            occurred_at=occurred_at,
            recorded_at=recorded_at or confirmation.confirmed_at,
            confirmation=confirmation,
            entity_id=entity_id,
            followup_due_at=followup_due_at,
        )
        return self.append_done_event(capabilities, run_id=run_id, event=event)

    record_done = create_done

    def record_followup_sent(
        self,
        capabilities: EntitiesCapabilities,
        *,
        run_id: str,
        event_id: str,
        root_event_id: str,
        summary: str,
        confirmation: HumanConfirmation,
        at: str | None = None,
        entity_id: str | None = None,
    ) -> DoneEventRecord:
        timestamp = at or confirmation.confirmed_at
        return self.append_done_event(
            capabilities,
            run_id=run_id,
            event=DoneEventRecord(
                event_id,
                "followup-sent",
                summary,
                timestamp,
                timestamp,
                confirmation,
                entity_id=entity_id,
                root_event_id=root_event_id,
            ),
        )

    def record_followup_answered(
        self,
        capabilities: EntitiesCapabilities,
        *,
        run_id: str,
        event_id: str,
        root_event_id: str,
        sent_event_id: str,
        summary: str,
        confirmation: HumanConfirmation,
        at: str | None = None,
        entity_id: str | None = None,
    ) -> DoneEventRecord:
        timestamp = at or confirmation.confirmed_at
        return self.append_done_event(
            capabilities,
            run_id=run_id,
            event=DoneEventRecord(
                event_id,
                "followup-answered",
                summary,
                timestamp,
                timestamp,
                confirmation,
                entity_id=entity_id,
                root_event_id=root_event_id,
                related_event_id=sent_event_id,
            ),
        )

    def close_done(
        self,
        capabilities: EntitiesCapabilities,
        *,
        run_id: str,
        event_id: str,
        root_event_id: str,
        summary: str,
        confirmation: HumanConfirmation,
        at: str | None = None,
        entity_id: str | None = None,
    ) -> DoneEventRecord:
        timestamp = at or confirmation.confirmed_at
        return self.append_done_event(
            capabilities,
            run_id=run_id,
            event=DoneEventRecord(
                event_id,
                "closed",
                summary,
                timestamp,
                timestamp,
                confirmation,
                entity_id=entity_id,
                root_event_id=root_event_id,
            ),
        )

    def list_done_events(
        self, capability: ActionCapability
    ) -> tuple[DoneEventRecord, ...]:
        self._require(capability, "read-done-events")
        zone = self._open_zone("agent/logs/done-events", for_write=False)
        if zone is None:
            return ()
        try:
            self._revalidate_zone(zone, for_write=False)
            events, _, _ = self._read_done_at(zone)
            self._revalidate_zone(zone, for_write=False)
            return events
        finally:
            self._close_zone(zone)

    def followup_signals(
        self, capability: ActionCapability, *, as_of: str
    ) -> tuple[FollowupSignal, ...]:
        cutoff_text = _temporal(as_of, "followup as_of")
        cutoff = _instant(cutoff_text)
        events = tuple(
            event
            for event in self.list_done_events(capability)
            if _instant(event.recorded_at) <= cutoff
        )
        signals: list[FollowupSignal] = []
        for root in (item for item in events if item.event_type == "created"):
            if root.followup_due_at is None:
                continue
            derived = [item for item in events if item.root_event_id == root.event_id]
            if any(item.event_type in {"followup-answered", "closed", "merged"} for item in derived):
                continue
            sent = next((item for item in reversed(derived) if item.event_type == "followup-sent"), None)
            if sent is not None:
                signals.append(
                    FollowupSignal(
                        root.event_id,
                        "pending",
                        root.followup_due_at,
                        sent.event_id,
                        root.entity_id,
                    )
                )
            elif _instant(root.followup_due_at) <= cutoff:
                signals.append(
                    FollowupSignal(
                        root.event_id,
                        "unsent",
                        root.followup_due_at,
                        None,
                        root.entity_id,
                    )
                )
        return tuple(
            sorted(
                signals,
                key=lambda item: (
                    0 if item.state == "unsent" else 1,
                    _instant(item.due_at),
                    _portable_key(item.root_event_id),
                ),
            )
        )

    project_followups = followup_signals

    @staticmethod
    def _read_trails_at(
        zone: _Zone, entity_id: str
    ) -> tuple[tuple[TrailEvent, ...], bytes, tuple[int, int] | None]:
        checked = _identifier(entity_id, "entity_id", _ENTITY_ID)
        name = f"{checked}.jsonl"
        try:
            raw, identity = _read_file_at(zone.fd, name, _MAX_JSONL)
        except FileNotFoundError:
            return (), b"", None
        records = _parse_jsonl(raw, kind="trail")
        trails = tuple(item for item in records if isinstance(item, TrailEvent))
        if any(item.entity_id != checked for item in trails):
            _fail("trail entity_id disagrees with filename")
        return trails, raw, identity

    def append_trail(
        self,
        capabilities: EntitiesCapabilities,
        *,
        run_id: str,
        event: TrailEvent,
    ) -> TrailEvent:
        if not isinstance(capabilities, EntitiesCapabilities):
            _fail("trail append requires EntitiesCapabilities")
        payload = _trail_payload(event)
        line = _canonical(payload)
        if len(line) > _MAX_LINE:
            _fail("trail event line is too large")
        read_entity = self._require(capabilities.read_entity_state, "read-entity-state")
        read_trail = self._require(capabilities.read_trail_events, "read-trail-events")
        append_grant = self._require(capabilities.append_entity_trail, "append-entity-trail")
        self._require(capabilities.record_run_state, "record-run-state")
        # FK observation precedes opening the trail writer.
        entity = self.status(read_entity, event.entity_id)
        if entity.entity_id != event.entity_id:
            _fail("trail entity FK is invalid")
        with self._locked_zone("agent/memory/trails") as zone:
            self._require(read_trail, "read-trail-events")
            trails, raw, identity = self._read_trails_at(zone, event.entity_id)
            matches = [item for item in trails if _portable_key(item.event_id) == _portable_key(event.event_id)]
            if matches:
                if len(matches) != 1 or _canonical(_trail_payload(matches[0])) != line:
                    _fail("trail replay conflicts with existing event")
                replayed = True
            else:
                if trails and _instant(event.at) < _instant(trails[-1].at):
                    _fail("trail events must be appended in time order")
                if len(raw) + len(line) > _MAX_JSONL:
                    _fail("trail log would exceed its bound")
                replayed = False
            output_hash = _digest(line)
            artifact, request_hash = self._prepare_run_evidence(
                run_id=run_id,
                operation_id=event.event_id,
                family="trail",
                request={"schema_version": 1, "record": payload},
                expected_output_sha256=output_hash,
                run_capability=capabilities.record_run_state,
            )
            if not replayed:
                self._before_log_replace("trail")
                self._require(append_grant, "append-entity-trail")
                _atomic_replace_at(
                    zone.fd,
                    f"{event.entity_id}.jsonl",
                    raw + line,
                    expected_identity=identity,
                )
                self._revalidate_zone(zone, for_write=True)
                self._after_domain_change("trail")
            self._commit_run(
                run_id=run_id,
                step_id=event.event_id,
                family="trail",
                request_hash=request_hash,
                output_hash=output_hash,
                artifact=artifact,
                actions=(read_entity, read_trail, append_grant),
                run_capability=capabilities.record_run_state,
            )
            return event

    def list_trails(
        self, capability: ActionCapability, entity_id: str
    ) -> tuple[TrailEvent, ...]:
        self._require(capability, "read-trail-events")
        zone = self._open_zone("agent/memory/trails", for_write=False)
        if zone is None:
            return ()
        try:
            self._revalidate_zone(zone, for_write=False)
            events, _, _ = self._read_trails_at(zone, entity_id)
            self._revalidate_zone(zone, for_write=False)
            return events
        finally:
            self._close_zone(zone)

    def consecutive_silent(self, capability: ActionCapability, entity_id: str) -> int:
        count = 0
        for event in reversed(self.list_trails(capability, entity_id)):
            if event.action != "silent":
                break
            count += 1
        return count

    def _before_entity_replace(self) -> None:
        """Test seam after durable RunStore evidence and before entity replace."""

    def _before_log_replace(self, kind: str) -> None:
        """Test seam after durable RunStore evidence and before a log replace."""

    def _after_domain_change(self, kind: str) -> None:
        """Test seam after a domain effect and before RunStore commit."""


def _legacy_timestamp(value: object, label: str) -> str:
    text = _text(value, label, limit=40)
    if _DATE.fullmatch(text):
        return text + "T00:00:00Z"
    return _timestamp(text, label)


def _legacy_priority(value: object) -> str:
    if isinstance(value, str) and value in _PRIORITIES:
        return value
    if type(value) is int and 0 <= value <= 5:
        if value <= 1:
            return "low"
        if value <= 3:
            return "medium"
        return "high"
    return "medium"


def migrate_legacy_entities(source: bytes, *, domain: str) -> LegacyEntitiesMigration:
    """Pure, deterministic legacy-list conversion; performs no filesystem I/O."""

    checked_domain = _domain(domain)
    if not isinstance(source, bytes) or not source or len(source) > _MAX_JSON:
        _fail("legacy entity input must be bounded bytes")
    payload = _decode_json(source, "legacy entities")
    if not isinstance(payload, list) or len(payload) > 1024:
        _fail("legacy entities must be a bounded list")
    entities: list[EntityRecord] = []
    trails_by_entity: list[tuple[str, tuple[TrailEvent, ...]]] = []
    seen_entities: set[str] = set()
    for index, item in enumerate(payload):
        if not isinstance(item, Mapping):
            _fail("legacy entity must be an object")
        allowed = {
            "id", "name", "title", "why", "description", "domain", "status",
            "priority", "created", "created_at", "updated_at", "deadline",
            "next_review_at", "next_check_after", "steps", "trail", "trails",
            "scale", "owner", "impact", "urgency", "effort",
        }
        if not set(item).issubset(allowed):
            _fail("legacy entity has unknown fields")
        entity_id = _identifier(item.get("id"), "legacy entity id", _ENTITY_ID)
        if _portable_key(entity_id) in seen_entities:
            _fail("legacy entity ids collide")
        seen_entities.add(_portable_key(entity_id))
        item_domain = _domain(item.get("domain", checked_domain))
        if item_domain != checked_domain:
            _fail("legacy entity domain disagrees with migration input")
        title_value = item.get("title", item.get("name"))
        title = _text(title_value, "legacy entity title", limit=512)
        description_value = item.get("description", item.get("why", ""))
        description = _text(
            description_value, "legacy entity description", limit=8192, allow_empty=True
        )
        status_value = item.get("status", "active")
        status_map = {"active": "active", "closed": "closed", "done": "closed", "dropped": "dropped"}
        if not isinstance(status_value, str) or status_value not in status_map:
            _fail("legacy entity status is invalid")
        status_value = status_map[status_value]
        created = _legacy_timestamp(item.get("created_at", item.get("created")), "legacy created")
        updated = _legacy_timestamp(item.get("updated_at", item.get("created_at", item.get("created"))), "legacy updated")
        steps_raw = item.get("steps", [])
        if not isinstance(steps_raw, list) or len(steps_raw) > 256:
            _fail("legacy entity steps must be a bounded list")
        steps: list[EntityStep] = []
        for step_index, step in enumerate(steps_raw, start=1):
            if not isinstance(step, Mapping) or not set(step).issubset({"id", "text", "done", "status", "owner", "checked_at"}):
                _fail("legacy entity step is invalid")
            done = step.get("done", step.get("status") == "done")
            if not isinstance(done, bool):
                _fail("legacy entity step done must be boolean")
            step_id = step.get("id", f"step_{step_index}")
            checked_at = step.get("checked_at")
            if done and checked_at is None:
                checked_at = updated
            steps.append(
                EntityStep(
                    _identifier(step_id, "legacy step id", _STEP_ID),
                    _text(step.get("text"), "legacy step text"),
                    "done" if done else "open",
                    _legacy_timestamp(checked_at, "legacy step checked_at") if done else None,
                )
            )
        deadline = item.get("deadline")
        review = item.get("next_review_at")
        next_after = item.get("next_check_after")
        deadline_text = None if deadline is None else _temporal(deadline, "legacy deadline")
        review_text = None if review is None else _temporal(review, "legacy next review")
        next_check = (
            None
            if next_after is None
            else NextCheckPolicy("at", _temporal(next_after, "legacy next check"))
        )
        migration_id = f"migrate_{hashlib.sha256((checked_domain + ':' + entity_id).encode()).hexdigest()[:16]}"
        mutation_hash = _digest(
            _canonical(
                {
                    "schema_version": ENTITY_MIGRATION_SCHEMA_VERSION,
                    "source_sha256": hashlib.sha256(source).hexdigest(),
                    "entity_id": entity_id,
                }
            )
        )
        entity = EntityRecord(
            entity_id,
            checked_domain,
            title,
            description,
            status_value,
            _legacy_priority(item.get("priority")),
            tuple(steps),
            deadline_text,
            review_text,
            next_check,
            None,
            created,
            updated,
            updated if status_value != "active" else None,
            1,
            migration_id,
            mutation_hash,
        )
        _entity_payload(entity)
        entities.append(entity)
        trail_raw = item.get("trails", item.get("trail", []))
        if not isinstance(trail_raw, list) or len(trail_raw) > _MAX_RECORDS:
            _fail("legacy embedded trails must be a bounded list")
        trails: list[TrailEvent] = []
        for trail_index, trail in enumerate(trail_raw, start=1):
            if not isinstance(trail, Mapping) or not set(trail).issubset({"id", "at", "action", "kind", "note"}):
                _fail("legacy embedded trail is invalid")
            action = trail.get("action", trail.get("kind"))
            # Legacy "created" was an observation, not an entity mutation in the
            # target trail vocabulary; ``ping`` is its non-terminal projection.
            if action == "created":
                action = "ping"
            if not isinstance(action, str) or action not in _TRAIL_ACTIONS:
                _fail("legacy embedded trail action is invalid")
            at = _legacy_timestamp(trail.get("at"), "legacy trail at")
            seed = f"{entity_id}:{trail_index}:{at}:{action}"
            trail_id = trail.get(
                "id", f"trail-{hashlib.sha256(seed.encode()).hexdigest()[:20]}"
            )
            trails.append(
                TrailEvent(
                    _identifier(trail_id, "legacy trail id", _TRAIL_ID),
                    entity_id,
                    action,
                    at,
                    _text(trail.get("note", ""), "legacy trail note", limit=8192, allow_empty=True),
                )
            )
        trails_by_entity.append((entity_id, tuple(trails)))
    collection = EntityCollection(
        checked_domain,
        1,
        tuple(sorted(entities, key=lambda entity: _portable_key(entity.entity_id))),
    )
    collection_bytes = _canonical(_collection_payload(collection))
    trail_files = tuple(
        (
            f"{entity_id}.jsonl",
            b"".join(_canonical(_trail_payload(event)) for event in trails),
        )
        for entity_id, trails in sorted(trails_by_entity, key=lambda item: _portable_key(item[0]))
    )
    return LegacyEntitiesMigration(
        ENTITY_MIGRATION_SCHEMA_VERSION,
        hashlib.sha256(source).hexdigest(),
        collection,
        tuple(sorted(trails_by_entity, key=lambda item: _portable_key(item[0]))),
        collection_bytes,
        trail_files,
    )


plan_legacy_entities_migration = migrate_legacy_entities
