"""Versioned day/week planning with bounded context and replay-safe rollover."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, replace
from datetime import date, datetime, timedelta, timezone
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
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
from tool_life_os_runtime.ext.runs import (
    ActionUse,
    PreparedArtifact,
    RunError,
    RunStore,
)
from tool_life_os_runtime.ext.vault.schema import VaultPathResolver, VaultSchemaError


PLAN_TASK_SCHEMA_VERSION = 1
PLAN_POLICY_SCHEMA_VERSION = 1
DAY_PLAN_SCHEMA_VERSION = 1
WEEK_PLAN_SCHEMA_VERSION = 1
SKIPPED_TASK_SCHEMA_VERSION = 1
PLAN_PACKET_SCHEMA_VERSION = 1
PLAN_MUTATION_SCHEMA_VERSION = 1
PLAN_PREIMAGE_SCHEMA_VERSION = 1
PLAN_FEEDBACK_SCHEMA_VERSION = 1

_ID = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
_TASK_ID = re.compile(r"^task-[a-z0-9][a-z0-9_-]{0,56}$")
_SKIP_ID = re.compile(r"^skip-[a-z0-9][a-z0-9_-]{0,56}$")
_PROJECT_SLUG = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
_ENTITY_ID = re.compile(r"^ent-[a-z0-9][a-z0-9_-]{0,58}$")
_DOMAIN = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_PRIORITIES = frozenset({"low", "medium", "high"})
_TASK_STATUSES = frozenset({"open", "done", "skipped", "rolled-over"})
_PLAN_STATUSES = frozenset({"active", "closed", "rolled-over"})
_ARCHIVE_KEYS = frozenset({"_archive", "_trash", "_on_hold"})
_MAX_JSON = 1024 * 1024
_MAX_MARKDOWN = 1024 * 1024
_MAX_JSONL = 4 * 1024 * 1024
_MAX_LINE = 32 * 1024
_MAX_TASKS = 512
_MAX_CONTEXT = 256
_MAX_PROJECT_INTENTS = 4096
_PRIVATE_PATH = re.compile(r"(?i)(?:/users/|/home/|[a-z]:\\users\\|[a-z]:\\home\\)")
_FILE_SCHEME = re.compile(r"(?i)(?:^|[^a-z0-9_])file:")
_SECRET = re.compile(
    r"(?i)(?:api[_ -]?key|authorization|bearer|cookie|credential|password|secret|token)"
    r"[\"']?\s*[:=]"
)


class PlanFlowError(ValueError):
    """Plan input, state, authority, context, or replay evidence is invalid."""


def _fail(message: str) -> None:
    raise PlanFlowError(message)


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
    if (
        _PRIVATE_PATH.search(value)
        or _FILE_SCHEME.search(value)
        or _SECRET.search(value)
    ):
        _fail(f"{label} contains private or credential-like text")
    return value


def _identifier(value: object, label: str, pattern: re.Pattern[str] = _ID) -> str:
    checked = _text(value, label, limit=64)
    if pattern.fullmatch(checked) is None or _portable_key(checked) in _ARCHIVE_KEYS:
        _fail(f"{label} is invalid")
    return checked


def _exact_int(value: object, label: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or value < minimum or value > maximum:
        _fail(f"{label} must be an integer from {minimum} to {maximum}")
    return value


def _date_text(value: object, label: str) -> str:
    checked = _text(value, label, limit=10)
    if _DATE.fullmatch(checked) is None:
        _fail(f"{label} must be an ISO date")
    try:
        parsed = date.fromisoformat(checked)
    except ValueError:
        _fail(f"{label} must be an ISO date")
    if parsed.isoformat() != checked:
        _fail(f"{label} must be an ISO date")
    return checked


def _week_start(value: object) -> str:
    checked = _date_text(value, "week_start")
    if date.fromisoformat(checked).weekday() != 0:
        _fail("week_start must be a Monday")
    return checked


def _timestamp(value: object, label: str) -> str:
    checked = _text(value, label, limit=40)
    if _UTC.fullmatch(checked) is None:
        _fail(f"{label} must be a UTC timestamp")
    try:
        parsed = datetime.fromisoformat(checked[:-1] + "+00:00")
    except ValueError:
        _fail(f"{label} must be a UTC timestamp")
    if parsed.tzinfo is None:
        _fail(f"{label} must be a UTC timestamp")
    return checked


def _hash(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        _fail(f"{label} must be sha256")
    return value


def _canonical(payload: Mapping[str, object], *, maximum: int = _MAX_JSON) -> bytes:
    try:
        raw = (
            json.dumps(
                payload,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
            + b"\n"
        )
    except (TypeError, ValueError, UnicodeError, RecursionError):
        _fail("plan payload is not canonical JSON")
    if not raw or len(raw) > maximum:
        _fail("plan payload is too large")
    return raw


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _object_no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            _fail("plan JSON has duplicate fields")
        result[key] = value
    return result


def _decode(raw: bytes, label: str, *, maximum: int = _MAX_JSON) -> object:
    if not isinstance(raw, bytes) or not raw or len(raw) > maximum:
        _fail(f"{label} is empty or too large")
    try:
        return json.loads(raw, object_pairs_hook=_object_no_duplicates)
    except PlanFlowError:
        raise
    except (UnicodeError, ValueError, RecursionError):
        _fail(f"{label} is not valid JSON")


@dataclass(frozen=True)
class PlanPolicy:
    physical_quota: int
    max_focus: int
    schema_version: int = PLAN_POLICY_SCHEMA_VERSION


@dataclass(frozen=True)
class PlanTask:
    task_id: str
    text: str
    scheduled_for: str
    status: str = "open"
    priority: str = "medium"
    physical_units: int = 0
    focus: bool = False
    project_slug: str | None = None
    entity_id: str | None = None
    rollover_count: int = 0
    completed_at: str | None = None
    skipped_at: str | None = None
    feedback: str | None = None
    schema_version: int = PLAN_TASK_SCHEMA_VERSION


@dataclass(frozen=True)
class DayPlan:
    date: str
    status: str
    revision: int
    policy: PlanPolicy
    tasks: tuple[PlanTask, ...]
    created_at: str
    updated_at: str
    last_operation_id: str
    last_operation_sha256: str
    schema_version: int = DAY_PLAN_SCHEMA_VERSION


@dataclass(frozen=True)
class WeekPlan:
    week_start: str
    status: str
    revision: int
    policy: PlanPolicy
    tasks: tuple[PlanTask, ...]
    created_at: str
    updated_at: str
    last_operation_id: str
    last_operation_sha256: str
    schema_version: int = WEEK_PLAN_SCHEMA_VERSION


@dataclass(frozen=True)
class ProjectPlanContext:
    slug: str
    name: str
    goal: str
    revision: int
    next_steps: tuple[str, ...]
    blockers: tuple[str, ...]
    snapshot_sha256: str


@dataclass(frozen=True)
class EntityPlanContext:
    entity_id: str
    domain: str
    title: str
    priority: str
    deadline: str | None
    next_review_at: str | None
    revision: int
    record_sha256: str


@dataclass(frozen=True)
class PlanContextQuery:
    kind: str
    period: str
    as_of: str
    project_limit: int = 64
    entity_limit: int = 128
    maximum_bytes: int = 256 * 1024


@dataclass(frozen=True)
class PlanningPacket:
    kind: str
    period: str
    as_of: str
    current_plan_sha256: str | None
    current_tasks: tuple[PlanTask, ...]
    projects: tuple[ProjectPlanContext, ...]
    entities: tuple[EntityPlanContext, ...]
    projects_truncated: bool
    entities_truncated: bool
    packet_sha256: str
    schema_version: int = PLAN_PACKET_SCHEMA_VERSION


@dataclass(frozen=True)
class SkippedTaskEvent:
    event_id: str
    operation_id: str
    task_id: str
    task_text: str
    source_date: str
    target_date: str | None
    reason: str
    at: str
    project_slug: str | None = None
    entity_id: str | None = None
    schema_version: int = SKIPPED_TASK_SCHEMA_VERSION


@dataclass(frozen=True)
class PlanMutationResult:
    operation_id: str
    operation: str
    day_plan: DayPlan | None
    week_plan: WeekPlan | None
    skipped_events: tuple[SkippedTaskEvent, ...]
    feedback_proposal_ref: str | None
    output_sha256: str
    replayed: bool
    schema_version: int = PLAN_MUTATION_SCHEMA_VERSION


@dataclass(frozen=True)
class PlanCapabilities:
    collect_plan_context: ActionCapability
    read_plan_project_context: ActionCapability
    read_plan_entity_context: ActionCapability
    snapshot_task_preimage: ActionCapability
    extract_feedback_markers: ActionCapability
    commit_feedback_proposal: ActionCapability
    commit_plan_or_rollover: ActionCapability
    record_run_state: ActionCapability


def _policy_payload(policy: PlanPolicy) -> dict[str, object]:
    if (
        not isinstance(policy, PlanPolicy)
        or policy.schema_version != PLAN_POLICY_SCHEMA_VERSION
    ):
        _fail("plan policy schema is invalid")
    return {
        "schema_version": policy.schema_version,
        "physical_quota": _exact_int(policy.physical_quota, "physical_quota", 0, 10000),
        "max_focus": _exact_int(policy.max_focus, "max_focus", 0, 64),
    }


def _parse_policy(payload: object) -> PlanPolicy:
    if not isinstance(payload, Mapping) or set(payload) != {
        "schema_version",
        "physical_quota",
        "max_focus",
    }:
        _fail("plan policy has missing or unknown fields")
    policy = PlanPolicy(
        physical_quota=(
            payload["physical_quota"] if type(payload["physical_quota"]) is int else -1
        ),
        max_focus=payload["max_focus"] if type(payload["max_focus"]) is int else -1,
        schema_version=(
            payload["schema_version"] if type(payload["schema_version"]) is int else -1
        ),
    )
    _policy_payload(policy)
    return policy


def _task_payload(task: PlanTask) -> dict[str, object]:
    if (
        not isinstance(task, PlanTask)
        or task.schema_version != PLAN_TASK_SCHEMA_VERSION
    ):
        _fail("plan task schema is invalid")
    task_id = _identifier(task.task_id, "task_id", _TASK_ID)
    text = _text(task.text, "task text", limit=2048)
    scheduled = _date_text(task.scheduled_for, "task scheduled_for")
    if not isinstance(task.status, str) or task.status not in _TASK_STATUSES:
        _fail("task status is invalid")
    if not isinstance(task.priority, str) or task.priority not in _PRIORITIES:
        _fail("task priority is invalid")
    if type(task.focus) is not bool:
        _fail("task focus must be boolean")
    physical = _exact_int(task.physical_units, "task physical_units", 0, 10000)
    rollover = _exact_int(task.rollover_count, "task rollover_count", 0, 3650)
    project = (
        None
        if task.project_slug is None
        else _identifier(task.project_slug, "task project_slug", _PROJECT_SLUG)
    )
    entity = (
        None
        if task.entity_id is None
        else _identifier(task.entity_id, "task entity_id", _ENTITY_ID)
    )
    completed = (
        None
        if task.completed_at is None
        else _timestamp(task.completed_at, "task completed_at")
    )
    skipped = (
        None
        if task.skipped_at is None
        else _timestamp(task.skipped_at, "task skipped_at")
    )
    feedback = (
        None
        if task.feedback is None
        else _text(task.feedback, "task feedback", limit=4096)
    )
    if task.status == "done":
        if completed is None or skipped is not None:
            _fail("done task timestamps are inconsistent")
    elif task.status == "skipped":
        if skipped is None or completed is not None:
            _fail("skipped task timestamps are inconsistent")
    elif completed is not None or skipped is not None:
        _fail("open or rolled-over task has terminal timestamps")
    if feedback is not None and task.status != "skipped":
        _fail("task feedback requires skipped status")
    return {
        "schema_version": task.schema_version,
        "id": task_id,
        "text": text,
        "scheduled_for": scheduled,
        "status": task.status,
        "priority": task.priority,
        "physical_units": physical,
        "focus": task.focus,
        "project_slug": project,
        "entity_id": entity,
        "rollover_count": rollover,
        "completed_at": completed,
        "skipped_at": skipped,
        "feedback": feedback,
    }


_TASK_KEYS = frozenset(
    {
        "schema_version",
        "id",
        "text",
        "scheduled_for",
        "status",
        "priority",
        "physical_units",
        "focus",
        "project_slug",
        "entity_id",
        "rollover_count",
        "completed_at",
        "skipped_at",
        "feedback",
    }
)


def _parse_task(payload: object) -> PlanTask:
    if not isinstance(payload, Mapping) or set(payload) != _TASK_KEYS:
        _fail("plan task has missing or unknown fields")
    nullable = ("project_slug", "entity_id", "completed_at", "skipped_at", "feedback")
    for key in nullable:
        if payload[key] is not None and not isinstance(payload[key], str):
            _fail(f"plan task {key} has invalid type")
    task = PlanTask(
        task_id=payload["id"] if isinstance(payload["id"], str) else "",
        text=payload["text"] if isinstance(payload["text"], str) else "",
        scheduled_for=(
            payload["scheduled_for"]
            if isinstance(payload["scheduled_for"], str)
            else ""
        ),
        status=payload["status"] if isinstance(payload["status"], str) else "",
        priority=payload["priority"] if isinstance(payload["priority"], str) else "",
        physical_units=(
            payload["physical_units"] if type(payload["physical_units"]) is int else -1
        ),
        focus=payload["focus"] if type(payload["focus"]) is bool else None,  # type: ignore[arg-type]
        project_slug=payload["project_slug"],
        entity_id=payload["entity_id"],
        rollover_count=(
            payload["rollover_count"] if type(payload["rollover_count"]) is int else -1
        ),
        completed_at=payload["completed_at"],
        skipped_at=payload["skipped_at"],
        feedback=payload["feedback"],
        schema_version=(
            payload["schema_version"] if type(payload["schema_version"]) is int else -1
        ),
    )
    _task_payload(task)
    return task


def _validate_tasks(
    tasks: object, policy: PlanPolicy, *, day: str | None, week: str | None
) -> tuple[PlanTask, ...]:
    if not isinstance(tasks, tuple) or len(tasks) > _MAX_TASKS:
        _fail("plan tasks must be a bounded tuple")
    rendered = [_task_payload(task) for task in tasks]
    ids = [_portable_key(str(item["id"])) for item in rendered]
    if len(ids) != len(set(ids)) or ids != sorted(ids):
        _fail("plan tasks must have unique portable ids in sorted order")
    start = None if week is None else date.fromisoformat(week)
    for task in tasks:
        scheduled = date.fromisoformat(task.scheduled_for)
        if day is not None and task.scheduled_for != day:
            _fail("day task scheduled_for disagrees with plan date")
        if start is not None and not (start <= scheduled <= start + timedelta(days=6)):
            _fail("week task scheduled_for is outside the ISO week")
    active_by_day: dict[str, list[PlanTask]] = {}
    for task in tasks:
        if task.status == "open":
            active_by_day.setdefault(task.scheduled_for, []).append(task)
    for items in active_by_day.values():
        if sum(item.physical_units for item in items) > policy.physical_quota:
            _fail("physical quota is exceeded")
        if sum(item.focus for item in items) > policy.max_focus:
            _fail("max-focus invariant is exceeded")
    return tasks


def _day_payload(plan: DayPlan) -> dict[str, object]:
    if not isinstance(plan, DayPlan) or plan.schema_version != DAY_PLAN_SCHEMA_VERSION:
        _fail("day plan schema is invalid")
    period = _date_text(plan.date, "day plan date")
    if not isinstance(plan.status, str) or plan.status not in _PLAN_STATUSES:
        _fail("day plan status is invalid")
    revision = _exact_int(plan.revision, "day plan revision", 1, 2**31 - 1)
    policy = _policy_payload(plan.policy)
    tasks = _validate_tasks(plan.tasks, plan.policy, day=period, week=None)
    created = _timestamp(plan.created_at, "day plan created_at")
    updated = _timestamp(plan.updated_at, "day plan updated_at")
    if datetime.fromisoformat(updated[:-1] + "+00:00") < datetime.fromisoformat(
        created[:-1] + "+00:00"
    ):
        _fail("day plan updated_at precedes created_at")
    return {
        "schema_version": plan.schema_version,
        "kind": "day",
        "date": period,
        "status": plan.status,
        "revision": revision,
        "policy": policy,
        "tasks": [_task_payload(item) for item in tasks],
        "created_at": created,
        "updated_at": updated,
        "last_operation_id": _identifier(plan.last_operation_id, "last_operation_id"),
        "last_operation_sha256": _hash(
            plan.last_operation_sha256, "last_operation_sha256"
        ),
    }


def _week_payload(plan: WeekPlan) -> dict[str, object]:
    if (
        not isinstance(plan, WeekPlan)
        or plan.schema_version != WEEK_PLAN_SCHEMA_VERSION
    ):
        _fail("week plan schema is invalid")
    period = _week_start(plan.week_start)
    if not isinstance(plan.status, str) or plan.status not in _PLAN_STATUSES - {
        "rolled-over"
    }:
        _fail("week plan status is invalid")
    revision = _exact_int(plan.revision, "week plan revision", 1, 2**31 - 1)
    policy = _policy_payload(plan.policy)
    tasks = _validate_tasks(plan.tasks, plan.policy, day=None, week=period)
    created = _timestamp(plan.created_at, "week plan created_at")
    updated = _timestamp(plan.updated_at, "week plan updated_at")
    if datetime.fromisoformat(updated[:-1] + "+00:00") < datetime.fromisoformat(
        created[:-1] + "+00:00"
    ):
        _fail("week plan updated_at precedes created_at")
    return {
        "schema_version": plan.schema_version,
        "kind": "week",
        "week_start": period,
        "status": plan.status,
        "revision": revision,
        "policy": policy,
        "tasks": [_task_payload(item) for item in tasks],
        "created_at": created,
        "updated_at": updated,
        "last_operation_id": _identifier(plan.last_operation_id, "last_operation_id"),
        "last_operation_sha256": _hash(
            plan.last_operation_sha256, "last_operation_sha256"
        ),
    }


_DAY_KEYS = frozenset(
    {
        "schema_version",
        "kind",
        "date",
        "status",
        "revision",
        "policy",
        "tasks",
        "created_at",
        "updated_at",
        "last_operation_id",
        "last_operation_sha256",
    }
)
_WEEK_KEYS = frozenset(
    {
        "schema_version",
        "kind",
        "week_start",
        "status",
        "revision",
        "policy",
        "tasks",
        "created_at",
        "updated_at",
        "last_operation_id",
        "last_operation_sha256",
    }
)


def _parse_day(raw: bytes) -> DayPlan:
    payload = _decode(raw, "day plan")
    if not isinstance(payload, Mapping) or set(payload) != _DAY_KEYS:
        _fail("day plan has missing or unknown fields")
    if payload["kind"] != "day" or not isinstance(payload["tasks"], list):
        _fail("day plan kind or tasks are invalid")
    plan = DayPlan(
        date=payload["date"] if isinstance(payload["date"], str) else "",
        status=payload["status"] if isinstance(payload["status"], str) else "",
        revision=payload["revision"] if type(payload["revision"]) is int else -1,
        policy=_parse_policy(payload["policy"]),
        tasks=tuple(_parse_task(item) for item in payload["tasks"]),
        created_at=(
            payload["created_at"] if isinstance(payload["created_at"], str) else ""
        ),
        updated_at=(
            payload["updated_at"] if isinstance(payload["updated_at"], str) else ""
        ),
        last_operation_id=(
            payload["last_operation_id"]
            if isinstance(payload["last_operation_id"], str)
            else ""
        ),
        last_operation_sha256=(
            payload["last_operation_sha256"]
            if isinstance(payload["last_operation_sha256"], str)
            else ""
        ),
        schema_version=(
            payload["schema_version"] if type(payload["schema_version"]) is int else -1
        ),
    )
    canonical = _canonical(_day_payload(plan))
    if raw != canonical:
        _fail("day plan is not canonical JSON")
    return plan


def _parse_week(raw: bytes) -> WeekPlan:
    payload = _decode(raw, "week plan")
    if not isinstance(payload, Mapping) or set(payload) != _WEEK_KEYS:
        _fail("week plan has missing or unknown fields")
    if payload["kind"] != "week" or not isinstance(payload["tasks"], list):
        _fail("week plan kind or tasks are invalid")
    plan = WeekPlan(
        week_start=(
            payload["week_start"] if isinstance(payload["week_start"], str) else ""
        ),
        status=payload["status"] if isinstance(payload["status"], str) else "",
        revision=payload["revision"] if type(payload["revision"]) is int else -1,
        policy=_parse_policy(payload["policy"]),
        tasks=tuple(_parse_task(item) for item in payload["tasks"]),
        created_at=(
            payload["created_at"] if isinstance(payload["created_at"], str) else ""
        ),
        updated_at=(
            payload["updated_at"] if isinstance(payload["updated_at"], str) else ""
        ),
        last_operation_id=(
            payload["last_operation_id"]
            if isinstance(payload["last_operation_id"], str)
            else ""
        ),
        last_operation_sha256=(
            payload["last_operation_sha256"]
            if isinstance(payload["last_operation_sha256"], str)
            else ""
        ),
        schema_version=(
            payload["schema_version"] if type(payload["schema_version"]) is int else -1
        ),
    )
    canonical = _canonical(_week_payload(plan))
    if raw != canonical:
        _fail("week plan is not canonical JSON")
    return plan


def render_day_plan(plan: DayPlan) -> bytes:
    """Render the exact canonical machine representation."""

    return _canonical(_day_payload(plan))


def render_week_plan(plan: WeekPlan) -> bytes:
    """Render the exact canonical machine representation."""

    return _canonical(_week_payload(plan))


def parse_day_plan(raw: bytes) -> DayPlan:
    """Parse one exact canonical day-plan document."""

    return _parse_day(raw)


def parse_week_plan(raw: bytes) -> WeekPlan:
    """Parse one exact canonical week-plan document."""

    return _parse_week(raw)


def _markdown_task(task: PlanTask) -> str:
    mark = "x" if task.status == "done" else "-" if task.status == "skipped" else " "
    labels = [task.task_id, task.status, task.priority]
    if task.focus:
        labels.append("focus")
    if task.physical_units:
        labels.append(f"physical:{task.physical_units}")
    if task.project_slug is not None:
        labels.append(f"project:{task.project_slug}")
    if task.entity_id is not None:
        labels.append(f"entity:{task.entity_id}")
    return f"- [{mark}] {task.text} ({', '.join(labels)})"


def render_day_markdown(plan: DayPlan) -> bytes:
    _day_payload(plan)
    lines = [
        "---",
        "kind: lifeos-day-plan",
        f"schema_version: {plan.schema_version}",
        f"date: {plan.date}",
        f"revision: {plan.revision}",
        "---",
        "",
        f"# Day plan - {plan.date}",
        "",
        *(_markdown_task(task) for task in plan.tasks),
        "",
    ]
    raw = "\n".join(lines).encode("utf-8")
    if len(raw) > _MAX_MARKDOWN:
        _fail("day plan Markdown is too large")
    return raw


def render_week_markdown(plan: WeekPlan) -> bytes:
    _week_payload(plan)
    lines = [
        "---",
        "kind: lifeos-week-plan",
        f"schema_version: {plan.schema_version}",
        f"week_start: {plan.week_start}",
        f"revision: {plan.revision}",
        "---",
        "",
        f"# Week plan - {plan.week_start}",
        "",
    ]
    for scheduled in sorted({task.scheduled_for for task in plan.tasks}):
        lines.extend(
            [
                f"## {scheduled}",
                "",
                *(
                    _markdown_task(task)
                    for task in plan.tasks
                    if task.scheduled_for == scheduled
                ),
                "",
            ]
        )
    raw = "\n".join(lines).encode("utf-8")
    if len(raw) > _MAX_MARKDOWN:
        _fail("week plan Markdown is too large")
    return raw


def _safe_parts(relative: str) -> tuple[str, ...]:
    if not isinstance(relative, str) or "\\" in relative:
        _fail("plan relative path is invalid")
    path = PurePosixPath(relative)
    if path.is_absolute() or not path.parts or ".." in path.parts:
        _fail("plan relative path is invalid")
    for part in path.parts:
        if (
            part in {"", "."}
            or part != unicodedata.normalize("NFC", part)
            or any(
                unicodedata.category(character).startswith("C") for character in part
            )
        ):
            _fail("plan relative path is invalid")
    return path.parts


def _directory_identity(fd: int) -> tuple[int, int]:
    try:
        metadata = os.fstat(fd)
    except OSError:
        _fail("plan directory identity cannot be read")
    if not stat.S_ISDIR(metadata.st_mode):
        _fail("plan directory is not a directory")
    return metadata.st_dev, metadata.st_ino


def _listdir(fd: int, label: str) -> tuple[str, ...]:
    try:
        names = os.listdir(fd)
    except OSError:
        _fail(f"{label} cannot be listed safely")
    if not all(
        isinstance(name, str) and name == unicodedata.normalize("NFC", name)
        for name in names
    ):
        _fail(f"{label} contains non-portable names")
    return tuple(names)


def _open_dir_at(root_fd: int, relative: str, *, create: bool = False) -> int:
    current = os.dup(root_fd)
    try:
        for part in _safe_parts(relative):
            if create:
                try:
                    os.mkdir(part, 0o700, dir_fd=current)
                    os.fsync(current)
                except FileExistsError:
                    pass
                except OSError:
                    _fail("plan directory cannot be created safely")
            child: int | None = None
            try:
                child = os.open(
                    part,
                    os.O_RDONLY
                    | getattr(os, "O_DIRECTORY", 0)
                    | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=current,
                )
                opened = os.fstat(child)
                named = os.stat(part, dir_fd=current, follow_symlinks=False)
            except OSError:
                if child is not None:
                    os.close(child)
                _fail("plan directory cannot be opened safely")
            if not stat.S_ISDIR(opened.st_mode) or (opened.st_dev, opened.st_ino) != (
                named.st_dev,
                named.st_ino,
            ):
                os.close(child)
                _fail("plan directory changed while opening")
            os.close(current)
            current = child
        return current
    except BaseException:
        os.close(current)
        raise


def _read_at(
    directory_fd: int, name: str, maximum: int
) -> tuple[bytes, tuple[int, int]]:
    checked = _identifier(
        name, "plan file name", re.compile(r"^[a-z0-9][a-z0-9_.-]{0,127}$")
    )
    fd: int | None = None
    try:
        fd = os.open(
            checked,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory_fd,
        )
        before = os.fstat(fd)
        named = os.stat(checked, dir_fd=directory_fd, follow_symlinks=False)
        identity = (before.st_dev, before.st_ino)
        if (
            not stat.S_ISREG(before.st_mode)
            or identity != (named.st_dev, named.st_ino)
            or before.st_size > maximum
        ):
            _fail("plan file is unsafe or too large")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(fd, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(fd)
        final_named = os.stat(checked, dir_fd=directory_fd, follow_symlinks=False)
        if (
            len(raw) > maximum
            or identity != (after.st_dev, after.st_ino)
            or identity != (final_named.st_dev, final_named.st_ino)
            or (before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            != (after.st_size, after.st_mtime_ns, after.st_ctime_ns)
        ):
            _fail("plan file changed while read")
        return raw, identity
    except FileNotFoundError:
        raise
    except PlanFlowError:
        raise
    except OSError:
        _fail("plan file cannot be read safely")
    finally:
        if fd is not None:
            os.close(fd)


def _identity_at(directory_fd: int, name: str) -> tuple[int, int] | None:
    try:
        metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    except OSError:
        _fail("plan file identity cannot be read")
    if not stat.S_ISREG(metadata.st_mode):
        _fail("plan file must be regular")
    return metadata.st_dev, metadata.st_ino


def _atomic_at(
    directory_fd: int,
    name: str,
    data: bytes,
    *,
    expected_identity: tuple[int, int] | None,
    maximum: int,
) -> tuple[int, int]:
    checked = _identifier(
        name, "plan file name", re.compile(r"^[a-z0-9][a-z0-9_.-]{0,127}$")
    )
    if not isinstance(data, bytes) or not data or len(data) > maximum:
        _fail("plan replacement bytes are invalid or too large")
    if _identity_at(directory_fd, checked) != expected_identity:
        _fail("plan file changed before replace")
    temporary = f".{checked}.{os.getpid()}.{uuid.uuid4().hex}.tmp"
    fd: int | None = None
    try:
        fd = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=directory_fd,
        )
        offset = 0
        while offset < len(data):
            written = os.write(fd, data[offset:])
            if written < 1:
                _fail("plan replacement write made no progress")
            offset += written
        os.fsync(fd)
        staged = os.fstat(fd)
        if not stat.S_ISREG(staged.st_mode):
            _fail("plan replacement stage is not regular")
        os.close(fd)
        fd = None
        named_stage = os.stat(temporary, dir_fd=directory_fd, follow_symlinks=False)
        staged_identity = (staged.st_dev, staged.st_ino)
        if staged_identity != (named_stage.st_dev, named_stage.st_ino):
            _fail("plan replacement stage changed")
        if _identity_at(directory_fd, checked) != expected_identity:
            _fail("plan file changed before replace")
        os.replace(temporary, checked, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
        os.fsync(directory_fd)
        published = os.stat(checked, dir_fd=directory_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(published.st_mode)
            or (published.st_dev, published.st_ino) != staged_identity
        ):
            _fail("plan replacement target changed during publish")
        actual, actual_identity = _read_at(directory_fd, checked, maximum)
        if actual_identity != staged_identity or actual != data:
            _fail("plan replacement verification failed")
        return staged_identity
    except PlanFlowError:
        raise
    except OSError:
        _fail("plan replacement failed")
    finally:
        if fd is not None:
            os.close(fd)
        try:
            os.unlink(temporary, dir_fd=directory_fd)
        except FileNotFoundError:
            pass
        except OSError:
            pass


def _create_once_at(directory_fd: int, name: str, data: bytes, *, maximum: int) -> bool:
    checked = _identifier(
        name, "plan file name", re.compile(r"^[a-z0-9][a-z0-9_.-]{0,127}$")
    )
    if not isinstance(data, bytes) or not data or len(data) > maximum:
        _fail("plan immutable bytes are invalid or too large")
    try:
        existing, _ = _read_at(directory_fd, checked, maximum)
    except FileNotFoundError:
        pass
    else:
        if existing != data:
            _fail("plan immutable replay conflicts with existing bytes")
        return False
    temporary = f".{checked}.{os.getpid()}.{uuid.uuid4().hex}.tmp"
    fd: int | None = None
    try:
        fd = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=directory_fd,
        )
        offset = 0
        while offset < len(data):
            written = os.write(fd, data[offset:])
            if written < 1:
                _fail("plan immutable write made no progress")
            offset += written
        os.fsync(fd)
        staged = os.fstat(fd)
        if not stat.S_ISREG(staged.st_mode):
            _fail("plan immutable stage is not regular")
        os.close(fd)
        fd = None
        named_stage = os.stat(temporary, dir_fd=directory_fd, follow_symlinks=False)
        staged_identity = (staged.st_dev, staged.st_ino)
        if staged_identity != (named_stage.st_dev, named_stage.st_ino):
            _fail("plan immutable stage changed")
        try:
            os.link(
                temporary,
                checked,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
                follow_symlinks=False,
            )
        except FileExistsError:
            existing, _ = _read_at(directory_fd, checked, maximum)
            if existing != data:
                _fail("plan immutable replay conflicts with existing bytes")
            return False
        os.fsync(directory_fd)
        actual, actual_identity = _read_at(directory_fd, checked, maximum)
        if actual != data or actual_identity != staged_identity:
            _fail("plan immutable target changed during publish")
        return True
    except PlanFlowError:
        raise
    except OSError:
        _fail("plan immutable artifact cannot be published")
    finally:
        if fd is not None:
            os.close(fd)
        try:
            os.unlink(temporary, dir_fd=directory_fd)
        except FileNotFoundError:
            pass
        except OSError:
            pass


def _task_context_payload(task: PlanTask) -> dict[str, object]:
    return _task_payload(task)


def _project_context_payload(item: ProjectPlanContext) -> dict[str, object]:
    if not isinstance(item, ProjectPlanContext):
        _fail("project plan context has invalid type")
    if not isinstance(item.next_steps, tuple) or not isinstance(item.blockers, tuple):
        _fail("project plan context collections must be tuples")
    if len(item.next_steps) > 256 or len(item.blockers) > 256:
        _fail("project plan context is too large")
    return {
        "slug": _identifier(item.slug, "context project slug", _PROJECT_SLUG),
        "name": _text(item.name, "context project name", limit=512),
        "goal": _text(item.goal, "context project goal", limit=16384),
        "revision": _exact_int(item.revision, "context project revision", 1, 2**31 - 1),
        "next_steps": [
            _text(value, "context project step", limit=4096)
            for value in item.next_steps
        ],
        "blockers": [
            _text(value, "context project blocker", limit=4096)
            for value in item.blockers
        ],
        "snapshot_sha256": _hash(item.snapshot_sha256, "project snapshot sha256"),
    }


def _entity_context_payload(item: EntityPlanContext) -> dict[str, object]:
    if not isinstance(item, EntityPlanContext):
        _fail("entity plan context has invalid type")
    deadline = (
        None
        if item.deadline is None
        else _entity_date_or_timestamp(item.deadline, "entity deadline")
    )
    review = (
        None
        if item.next_review_at is None
        else _entity_date_or_timestamp(item.next_review_at, "entity next review")
    )
    return {
        "entity_id": _identifier(item.entity_id, "context entity_id", _ENTITY_ID),
        "domain": _identifier(item.domain, "context entity domain", _DOMAIN),
        "title": _text(item.title, "context entity title", limit=512),
        "priority": (
            item.priority
            if isinstance(item.priority, str) and item.priority in _PRIORITIES
            else _fail("context entity priority is invalid")
        ),
        "deadline": deadline,
        "next_review_at": review,
        "revision": _exact_int(item.revision, "context entity revision", 1, 2**31 - 1),
        "record_sha256": _hash(item.record_sha256, "entity record sha256"),
    }


def _packet_base(packet: PlanningPacket) -> dict[str, object]:
    if (
        not isinstance(packet, PlanningPacket)
        or packet.schema_version != PLAN_PACKET_SCHEMA_VERSION
    ):
        _fail("planning packet schema is invalid")
    if not isinstance(packet.kind, str) or packet.kind not in {"day", "week"}:
        _fail("planning packet kind is invalid")
    period = (
        _date_text(packet.period, "packet period")
        if packet.kind == "day"
        else _week_start(packet.period)
    )
    if (
        type(packet.projects_truncated) is not bool
        or type(packet.entities_truncated) is not bool
    ):
        _fail("planning packet truncation flags must be boolean")
    current_hash = (
        None
        if packet.current_plan_sha256 is None
        else _hash(packet.current_plan_sha256, "current plan sha256")
    )
    return {
        "schema_version": packet.schema_version,
        "kind": packet.kind,
        "period": period,
        "as_of": _timestamp(packet.as_of, "packet as_of"),
        "current_plan_sha256": current_hash,
        "current_tasks": [_task_context_payload(item) for item in packet.current_tasks],
        "projects": [_project_context_payload(item) for item in packet.projects],
        "entities": [_entity_context_payload(item) for item in packet.entities],
        "projects_truncated": packet.projects_truncated,
        "entities_truncated": packet.entities_truncated,
    }


def render_planning_packet(packet: PlanningPacket) -> bytes:
    payload = _packet_base(packet)
    if _digest(_canonical(payload)) != _hash(packet.packet_sha256, "packet_sha256"):
        _fail("planning packet hash is invalid")
    payload["packet_sha256"] = packet.packet_sha256
    return _canonical(payload)


def _skip_payload(event: SkippedTaskEvent) -> dict[str, object]:
    if (
        not isinstance(event, SkippedTaskEvent)
        or event.schema_version != SKIPPED_TASK_SCHEMA_VERSION
    ):
        _fail("skipped task event schema is invalid")
    target = (
        None
        if event.target_date is None
        else _date_text(event.target_date, "skip target_date")
    )
    return {
        "schema_version": event.schema_version,
        "id": _identifier(event.event_id, "skip event_id", _SKIP_ID),
        "operation_id": _identifier(event.operation_id, "skip operation_id"),
        "task_id": _identifier(event.task_id, "skip task_id", _TASK_ID),
        "task_text": _text(event.task_text, "skip task text", limit=2048),
        "source_date": _date_text(event.source_date, "skip source_date"),
        "target_date": target,
        "reason": _text(event.reason, "skip reason", limit=4096),
        "at": _timestamp(event.at, "skip at"),
        "project_slug": (
            None
            if event.project_slug is None
            else _identifier(event.project_slug, "skip project_slug", _PROJECT_SLUG)
        ),
        "entity_id": (
            None
            if event.entity_id is None
            else _identifier(event.entity_id, "skip entity_id", _ENTITY_ID)
        ),
    }


def _parse_skip(payload: object) -> SkippedTaskEvent:
    keys = {
        "schema_version",
        "id",
        "operation_id",
        "task_id",
        "task_text",
        "source_date",
        "target_date",
        "reason",
        "at",
        "project_slug",
        "entity_id",
    }
    if not isinstance(payload, Mapping) or set(payload) != keys:
        _fail("skipped task event has missing or unknown fields")
    for key in ("target_date", "project_slug", "entity_id"):
        if payload[key] is not None and not isinstance(payload[key], str):
            _fail(f"skipped task event {key} has invalid type")
    event = SkippedTaskEvent(
        event_id=payload["id"] if isinstance(payload["id"], str) else "",
        operation_id=(
            payload["operation_id"] if isinstance(payload["operation_id"], str) else ""
        ),
        task_id=payload["task_id"] if isinstance(payload["task_id"], str) else "",
        task_text=payload["task_text"] if isinstance(payload["task_text"], str) else "",
        source_date=(
            payload["source_date"] if isinstance(payload["source_date"], str) else ""
        ),
        target_date=payload["target_date"],
        reason=payload["reason"] if isinstance(payload["reason"], str) else "",
        at=payload["at"] if isinstance(payload["at"], str) else "",
        project_slug=payload["project_slug"],
        entity_id=payload["entity_id"],
        schema_version=(
            payload["schema_version"] if type(payload["schema_version"]) is int else -1
        ),
    )
    _skip_payload(event)
    return event


def _parse_skip_log(raw: bytes) -> tuple[SkippedTaskEvent, ...]:
    if len(raw) > _MAX_JSONL or (raw and not raw.endswith(b"\n")):
        _fail("skipped task trace is too large or torn")
    events: list[SkippedTaskEvent] = []
    seen: set[str] = set()
    for line in raw.splitlines():
        if not line or len(line) + 1 > _MAX_LINE:
            _fail("skipped task trace line is invalid")
        event = _parse_skip(_decode(line, "skipped task trace line", maximum=_MAX_LINE))
        canonical = _canonical(_skip_payload(event), maximum=_MAX_LINE)
        if canonical != line + b"\n":
            _fail("skipped task trace is not canonical JSONL")
        key = _portable_key(event.event_id)
        if key in seen:
            _fail("skipped task trace event ids collide")
        seen.add(key)
        events.append(event)
    return tuple(events)


_PROJECT_INTENT_KEYS = frozenset(
    {
        "schema_version",
        "transition_id",
        "operation",
        "slug",
        "request_sha256",
        "request",
        "source",
        "destination",
        "project_directory_identity",
        "before",
        "preimages",
        "targets",
        "target_sha256",
        "archived_children",
        "child_observation",
        "child_policy",
        "schedule",
        "schedule_observation",
        "schedule_receipt",
        "status",
    }
)


def _read_project_intents(
    projects_fd: int,
) -> tuple[dict[str, bytes], frozenset[str]]:
    try:
        metadata = os.stat(
            ".lifeos-project-intents",
            dir_fd=projects_fd,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        return {}, frozenset()
    except OSError:
        _fail("project transition evidence cannot be inspected")
    if not stat.S_ISDIR(metadata.st_mode):
        _fail("project transition evidence namespace is unsafe")
    intents_fd = _open_dir_at(projects_fd, ".lifeos-project-intents")
    result: dict[str, bytes] = {}
    pending: set[str] = set()
    try:
        names = sorted(
            _listdir(intents_fd, "project transition evidence namespace"),
            key=_portable_key,
        )
        if len(names) > _MAX_PROJECT_INTENTS:
            _fail("project transition evidence exceeds its structural bound")
        for name in names:
            if not name.endswith(".json"):
                _fail("project transition evidence contains an unknown entry")
            transition_id = _identifier(name[:-5], "project context transition id")
            try:
                raw, _identity = _read_at(intents_fd, name, _MAX_JSON)
            except FileNotFoundError:
                _fail("project transition evidence changed while read")
            intent = _decode(raw, "project context transition intent")
            request = intent.get("request") if isinstance(intent, Mapping) else None
            if (
                not isinstance(intent, Mapping)
                or set(intent) != _PROJECT_INTENT_KEYS
                or raw != _canonical(dict(intent))
                or intent["schema_version"] != 1
                or intent["transition_id"] != transition_id
                or not isinstance(intent["status"], str)
                or intent["status"]
                not in {
                    "prepared",
                    "domain_committed",
                    "schedule_committed",
                    "complete",
                }
                or not isinstance(request, Mapping)
                or request.get("schema_version") != 1
                or request.get("transition_id") != transition_id
                or request.get("operation") != intent["operation"]
                or request.get("slug") != intent["slug"]
                or intent["request_sha256"] != _digest(_canonical(dict(request)))
            ):
                _fail("project transition evidence violates the public schema")
            slug = _identifier(intent["slug"], "project transition slug", _PROJECT_SLUG)
            result[transition_id] = raw
            if intent["status"] != "complete":
                pending.add(_portable_key(slug))
    finally:
        os.close(intents_fd)
    return result, frozenset(pending)


def _parse_project_context(
    project_raw: bytes,
    state_raw: bytes,
    log_raw: bytes,
    intent_raw: bytes,
    *,
    directory_name: str,
) -> ProjectPlanContext:
    project = _decode(project_raw, "project context record")
    state = _decode(state_raw, "project context state")
    intent = _decode(intent_raw, "project context transition intent")
    project_keys = {
        "schema_version",
        "slug",
        "name",
        "goal",
        "domains",
        "kind",
        "status",
        "created_at",
        "updated_at",
        "on_hold_since",
        "on_hold_reason",
        "archived_at",
        "revision",
        "last_transition_id",
        "schedule_ids",
    }
    state_keys = {
        "schema_version",
        "project_slug",
        "revision",
        "next_steps",
        "blockers",
        "open_questions",
        "milestones",
        "last_session",
    }
    if (
        not isinstance(project, Mapping)
        or set(project) != project_keys
        or not isinstance(state, Mapping)
        or set(state) != state_keys
        or not isinstance(intent, Mapping)
        or set(intent) != _PROJECT_INTENT_KEYS
        or project_raw != _canonical(dict(project))
        or state_raw != _canonical(dict(state))
        or intent_raw != _canonical(dict(intent))
    ):
        _fail("project context violates the public schema")
    if (
        project["schema_version"] != 1
        or state["schema_version"] != 1
        or project["status"] != "active"
        or not isinstance(project["slug"], str)
        or project["slug"] != directory_name
        or state["project_slug"] != project["slug"]
        or type(project["revision"]) is not int
        or state["revision"] != project["revision"]
        or not isinstance(project["name"], str)
        or not isinstance(project["goal"], str)
        or not isinstance(state["next_steps"], list)
        or not isinstance(state["blockers"], list)
    ):
        _fail("project context is inconsistent")
    slug = _identifier(project["slug"], "project context slug", _PROJECT_SLUG)
    revision = _exact_int(project["revision"], "project context revision", 1, 2**31 - 1)
    if (
        not isinstance(project["kind"], str)
        or project["kind"] not in {"general", "research"}
        or not isinstance(project["domains"], list)
        or not project["domains"]
        or len(project["domains"]) > 32
        or not all(isinstance(item, str) for item in project["domains"])
        or not isinstance(project["schedule_ids"], list)
        or len(project["schedule_ids"]) > 128
        or not all(isinstance(item, str) for item in project["schedule_ids"])
        or any(
            project[key] is not None
            for key in ("on_hold_since", "on_hold_reason", "archived_at")
        )
    ):
        _fail("active project context lifecycle fields are invalid")
    domains = [
        _identifier(item, "project context domain", _PROJECT_SLUG)
        for item in project["domains"]
    ]
    schedules = [
        _identifier(item, "project context schedule id")
        for item in project["schedule_ids"]
    ]
    if len(domains) != len(set(domains)) or len(schedules) != len(set(schedules)):
        _fail("project context domains or schedules are duplicated")
    created = _timestamp(project["created_at"], "project context created_at")
    updated = _timestamp(project["updated_at"], "project context updated_at")
    if datetime.fromisoformat(updated[:-1] + "+00:00") < datetime.fromisoformat(
        created[:-1] + "+00:00"
    ):
        _fail("project context updated_at precedes created_at")
    _identifier(project["last_transition_id"], "project context transition id")
    transition_id = project["last_transition_id"]
    request = intent["request"]
    target_hashes = intent["target_sha256"]
    if (
        intent["schema_version"] != 1
        or intent["status"] != "complete"
        or intent["transition_id"] != transition_id
        or intent["slug"] != slug
        or intent["destination"] != directory_name
        or not isinstance(request, Mapping)
        or request.get("schema_version") != 1
        or request.get("transition_id") != transition_id
        or request.get("slug") != slug
        or request.get("operation") != intent["operation"]
        or intent["request_sha256"] != _digest(_canonical(dict(request)))
        or not isinstance(target_hashes, Mapping)
        or set(target_hashes) != {"project.json", "state.json", "log.md"}
        or target_hashes["project.json"] != _digest(project_raw)
        or target_hashes["state.json"] != _digest(state_raw)
        or target_hashes["log.md"] != _digest(log_raw)
    ):
        _fail("project context lacks exact completed transition evidence")
    try:
        log_text = log_raw.decode("utf-8")
    except UnicodeError:
        _fail("project context log is not UTF-8")
    if not log_text:
        _fail("project context log is empty")
    steps: list[str] = []
    step_ids: set[str] = set()
    for item in state["next_steps"]:
        if (
            not isinstance(item, Mapping)
            or set(item) != {"id", "text", "status", "priority"}
            or not all(isinstance(item[key], str) for key in item)
        ):
            _fail("project context step is invalid")
        _identifier(item["id"], "project context step id")
        _text(item["text"], "project context step text")
        if (
            item["status"] not in {"open", "done", "skipped"}
            or item["priority"] not in _PRIORITIES
        ):
            _fail("project context step status or priority is invalid")
        step_key = _portable_key(item["id"])
        if step_key in step_ids:
            _fail("project context step ids collide")
        step_ids.add(step_key)
        if item["status"] == "open":
            steps.append(item["text"])
    blockers: list[str] = []
    blocker_ids: set[str] = set()
    for item in state["blockers"]:
        if (
            not isinstance(item, Mapping)
            or set(item) != {"id", "text", "status"}
            or not all(isinstance(item[key], str) for key in item)
        ):
            _fail("project context blocker is invalid")
        _identifier(item["id"], "project context blocker id")
        _text(item["text"], "project context blocker text")
        if item["status"] not in {"open", "resolved"}:
            _fail("project context blocker status is invalid")
        blocker_key = _portable_key(item["id"])
        if blocker_key in blocker_ids:
            _fail("project context blocker ids collide")
        blocker_ids.add(blocker_key)
        if item["status"] == "open":
            blockers.append(item["text"])
    for collection_name, allowed_statuses in (
        ("open_questions", {"open", "answered"}),
        ("milestones", {"planned", "reached", "dropped"}),
    ):
        collection = state[collection_name]
        if not isinstance(collection, list) or len(collection) > 256:
            _fail(f"project context {collection_name} is invalid")
        item_ids: set[str] = set()
        for item in collection:
            expected_keys = (
                {"id", "text", "status", "answer"}
                if collection_name == "open_questions"
                else {"id", "text", "status"}
            )
            if not isinstance(item, Mapping) or set(item) != expected_keys:
                _fail(f"project context {collection_name} item is invalid")
            item_id = _identifier(item["id"], f"project context {collection_name} id")
            _text(item["text"], f"project context {collection_name} text")
            if (
                not isinstance(item["status"], str)
                or item["status"] not in allowed_statuses
            ):
                _fail(f"project context {collection_name} status is invalid")
            if collection_name == "open_questions":
                answer = item["answer"]
                if (item["status"] == "answered") != isinstance(answer, str):
                    _fail("project context question answer is inconsistent")
                if isinstance(answer, str):
                    _text(answer, "project context question answer")
            key = _portable_key(item_id)
            if key in item_ids:
                _fail(f"project context {collection_name} ids collide")
            item_ids.add(key)
    session = state["last_session"]
    if session is not None:
        if not isinstance(session, Mapping) or set(session) != {"at", "summary"}:
            _fail("project context last_session is invalid")
        _timestamp(session["at"], "project context session at")
        _text(session["summary"], "project context session summary")
    snapshot = _digest(
        _canonical(
            {
                "location": directory_name,
                "project_sha256": _digest(project_raw),
                "state_sha256": _digest(state_raw),
                "log_sha256": _digest(log_raw),
            }
        )
    )
    return ProjectPlanContext(
        slug,
        _text(project["name"], "project context name", limit=512),
        _text(project["goal"], "project context goal", limit=16384),
        revision,
        tuple(steps),
        tuple(blockers),
        snapshot,
    )


_ENTITY_KEYS = frozenset(
    {
        "schema_version",
        "id",
        "domain",
        "title",
        "description",
        "status",
        "priority",
        "steps",
        "deadline",
        "next_review_at",
        "next_check",
        "escalation_paused_until",
        "created_at",
        "updated_at",
        "closed_at",
        "revision",
        "last_mutation_id",
        "last_mutation_sha256",
    }
)


def _entity_date_or_timestamp(value: object, label: str) -> str:
    if not isinstance(value, str):
        _fail(f"{label} has invalid type")
    if _DATE.fullmatch(value):
        return _date_text(value, label)
    _timestamp(value, label)
    return value


def _parse_entity_context(payload: object, *, domain: str) -> EntityPlanContext | None:
    if not isinstance(payload, Mapping) or set(payload) != _ENTITY_KEYS:
        _fail("entity context violates the public schema")
    string_keys = (
        "id",
        "domain",
        "title",
        "description",
        "status",
        "priority",
        "created_at",
        "updated_at",
        "last_mutation_id",
        "last_mutation_sha256",
    )
    if (
        payload["schema_version"] != 1
        or not all(isinstance(payload[key], str) for key in string_keys)
        or not isinstance(payload["steps"], list)
        or type(payload["revision"]) is not int
    ):
        _fail("entity context scalar fields are invalid")
    if payload["domain"] != domain:
        _fail("entity context domain disagrees with collection")
    entity_id = _identifier(payload["id"], "entity context id", _ENTITY_ID)
    _identifier(payload["domain"], "entity context domain", _DOMAIN)
    title = _text(payload["title"], "entity context title", limit=512)
    _text(
        payload["description"],
        "entity context description",
        limit=8192,
        allow_empty=True,
    )
    if payload["priority"] not in _PRIORITIES or payload["status"] not in {
        "active",
        "closed",
        "dropped",
    }:
        _fail("entity context status or priority is invalid")
    created_at = _timestamp(payload["created_at"], "entity context created_at")
    updated_at = _timestamp(payload["updated_at"], "entity context updated_at")
    if datetime.fromisoformat(updated_at[:-1] + "+00:00") < datetime.fromisoformat(
        created_at[:-1] + "+00:00"
    ):
        _fail("entity context updated_at precedes created_at")
    _identifier(payload["last_mutation_id"], "entity context mutation id")
    _hash(payload["last_mutation_sha256"], "entity context mutation sha256")
    revision = _exact_int(payload["revision"], "entity context revision", 1, 2**31 - 1)
    step_ids: set[str] = set()
    if len(payload["steps"]) > 256:
        _fail("entity context steps exceed their bound")
    for item in payload["steps"]:
        if not isinstance(item, Mapping) or set(item) != {
            "schema_version",
            "id",
            "text",
            "status",
            "checked_at",
        }:
            _fail("entity context step is invalid")
        if (
            item["schema_version"] != 1
            or not isinstance(item["id"], str)
            or not isinstance(item["text"], str)
            or not isinstance(item["status"], str)
            or item["status"] not in {"open", "done"}
            or (
                item["checked_at"] is not None
                and not isinstance(item["checked_at"], str)
            )
        ):
            _fail("entity context step fields are invalid")
        step_id = _identifier(item["id"], "entity context step id")
        _text(item["text"], "entity context step text")
        if (item["status"] == "done") != (item["checked_at"] is not None):
            _fail("entity context step checked_at is inconsistent")
        if item["checked_at"] is not None:
            _timestamp(item["checked_at"], "entity context step checked_at")
        key = _portable_key(step_id)
        if key in step_ids:
            _fail("entity context step ids collide")
        step_ids.add(key)
    next_check = payload["next_check"]
    if next_check is not None:
        if not isinstance(next_check, Mapping) or set(next_check) != {
            "schema_version",
            "kind",
            "due_at",
            "interval_days",
        }:
            _fail("entity context next_check is invalid")
        kind = next_check["kind"]
        if (
            next_check["schema_version"] != 1
            or not isinstance(kind, str)
            or kind not in {"at", "after-update"}
        ):
            _fail("entity context next_check fields are invalid")
        if kind == "at":
            _entity_date_or_timestamp(
                next_check["due_at"], "entity context next_check due"
            )
            if next_check["interval_days"] is not None:
                _fail("entity context at check cannot have interval")
        else:
            _exact_int(
                next_check["interval_days"],
                "entity context next_check interval",
                1,
                3650,
            )
            if next_check["due_at"] is not None:
                _fail("entity context after-update check cannot have due_at")
    paused = payload["escalation_paused_until"]
    if paused is not None:
        _entity_date_or_timestamp(paused, "entity context escalation pause")
    closed = payload["closed_at"]
    if payload["status"] == "active":
        if closed is not None:
            _fail("active entity context cannot have closed_at")
    else:
        if closed is None:
            _fail("terminal entity context requires closed_at")
        _timestamp(closed, "entity context closed_at")
    deadline = (
        None
        if payload["deadline"] is None
        else _entity_date_or_timestamp(payload["deadline"], "entity context deadline")
    )
    review = (
        None
        if payload["next_review_at"] is None
        else _entity_date_or_timestamp(
            payload["next_review_at"], "entity context next_review_at"
        )
    )
    if payload["status"] != "active":
        return None
    record_hash = _digest(_canonical(dict(payload)))
    return EntityPlanContext(
        entity_id,
        domain,
        title,
        payload["priority"],
        deadline,
        review,
        revision,
        record_hash,
    )


@dataclass(frozen=True)
class _PlanPair:
    plan: DayPlan | WeekPlan | None
    json_raw: bytes | None
    markdown_raw: bytes | None


class PlanFlow:
    """Day/week plan state, bounded context, skip trace, and rollover."""

    def __init__(
        self,
        resolver: VaultPathResolver,
        run_store: RunStore,
        policy: AuthorityPolicy,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if (
            not isinstance(resolver, VaultPathResolver)
            or not isinstance(run_store, RunStore)
            or not isinstance(policy, AuthorityPolicy)
            or getattr(run_store, "_resolver", None) is not resolver
        ):
            _fail("plan flow dependencies are invalid")
        self._resolver = resolver
        self._runs = run_store
        self._policy = policy
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        root_fd: int | None = None
        try:
            tasks = resolver.resolve("tasks", for_write=False, must_exist=True)
            configured = resolver.config.zone("tasks")
            vault_root = tasks
            for _part in configured.parts:
                vault_root = vault_root.parent
            root_fd = os.open(
                vault_root,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
            opened = os.fstat(root_fd)
            named = os.stat(vault_root, follow_symlinks=False)
            if not stat.S_ISDIR(opened.st_mode) or (opened.st_dev, opened.st_ino) != (
                named.st_dev,
                named.st_ino,
            ):
                _fail("configured vault root cannot be pinned")
            self._vault_root = Path(vault_root)
            self._vault_identity = (opened.st_dev, opened.st_ino)
            self._tasks_relative = configured.as_posix()
        except (OSError, VaultSchemaError, PlanFlowError):
            _fail("configured vault root cannot be pinned")
        finally:
            if root_fd is not None:
                os.close(root_fd)

    def _now(self) -> str:
        value = self._clock()
        if not isinstance(value, datetime) or value.tzinfo is None:
            _fail("plan clock must return an aware datetime")
        return (
            value.astimezone(timezone.utc)
            .isoformat(timespec="microseconds")
            .replace("+00:00", "Z")
        )

    def _require(
        self, capability: ActionCapability, action_id: str
    ) -> ActionCapability:
        expected = {
            "collect-plan-context": ("runtime", "read", "vault:tasks"),
            "read-plan-project-context": ("runtime", "read", "vault:projects"),
            "read-plan-entity-context": ("runtime", "read", "vault:agent/memory"),
            "snapshot-task-preimage": (
                "runtime",
                "domain-write",
                "vault:agent/logs/tasks",
            ),
            "extract-feedback-markers": ("runtime", "read", "vault:tasks"),
            "commit-feedback-proposal": ("runtime", "proposal", "vault:review"),
            "commit-plan-or-rollover": ("runtime", "domain-write", "vault:tasks"),
            "record-run-state": ("runtime", "internal-write", "vault:agent/runs"),
        }
        try:
            grant = self._policy.require(capability)
        except AuthorityError as error:
            raise PlanFlowError(str(error)) from None
        if (
            action_id not in expected
            or (grant.flow_id, grant.action_id) != ("plan", action_id)
            or (grant.actor, grant.authority, grant.target) != expected[action_id]
        ):
            _fail("plan action capability is not exact")
        return grant

    def _check_run(self, run_id: str) -> str:
        checked = _identifier(
            run_id, "run_id", re.compile(r"^run_[a-z0-9][a-z0-9_-]{0,62}$")
        )
        try:
            state = self._runs.status(checked)
        except RunError as error:
            raise PlanFlowError(str(error)) from None
        if (
            state.get("flow") != "plan"
            or state.get("status") != "running"
            or state.get("authority") != "domain-write"
        ):
            _fail("plan mutation requires a running domain-write plan run")
        return checked

    def _open_root(self) -> int:
        fd: int | None = None
        try:
            fd = os.open(
                self._vault_root,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
            opened = os.fstat(fd)
            named = os.stat(self._vault_root, follow_symlinks=False)
            if (opened.st_dev, opened.st_ino) != self._vault_identity or (
                named.st_dev,
                named.st_ino,
            ) != self._vault_identity:
                _fail("configured vault root identity changed")
            return fd
        except (OSError, PlanFlowError):
            if fd is not None:
                os.close(fd)
            _fail("configured vault root cannot be opened safely")

    def _revalidate_root(self, root_fd: int) -> None:
        try:
            opened = os.fstat(root_fd)
            named = os.stat(self._vault_root, follow_symlinks=False)
        except OSError:
            _fail("configured vault root cannot be revalidated")
        if (opened.st_dev, opened.st_ino) != self._vault_identity or (
            named.st_dev,
            named.st_ino,
        ) != self._vault_identity:
            _fail("configured vault root identity changed")

    def _open_configured(
        self, root_fd: int, symbolic: str, *, for_write: bool
    ) -> tuple[int, Path, tuple[int, int]]:
        try:
            config_name = "memory" if symbolic == "agent/memory" else symbolic
            relative = self._resolver.config.zone(config_name).as_posix()
            path = self._resolver.resolve(
                symbolic, for_write=for_write, must_exist=True
            )
            fd = _open_dir_at(root_fd, relative)
            identity = _directory_identity(fd)
            named = os.stat(path, follow_symlinks=False)
            self._resolver.revalidate(
                path, symbolic, for_write=for_write, must_exist=True
            )
            if identity != (named.st_dev, named.st_ino):
                _fail("configured plan context zone changed while opening")
            return fd, path, identity
        except (OSError, VaultSchemaError, PlanFlowError):
            if "fd" in locals():
                os.close(fd)
            _fail("configured plan context zone cannot be opened safely")

    def _revalidate_configured(
        self,
        fd: int,
        path: Path,
        identity: tuple[int, int],
        symbolic: str,
        *,
        for_write: bool,
    ) -> None:
        try:
            actual = self._resolver.revalidate(
                path, symbolic, for_write=for_write, must_exist=True
            )
            named = os.stat(actual, follow_symlinks=False)
        except (OSError, VaultSchemaError):
            _fail("configured plan context zone changed during operation")
        if (
            _directory_identity(fd) != identity
            or (named.st_dev, named.st_ino) != identity
        ):
            _fail("configured plan context zone changed during operation")

    @contextmanager
    def _locked_tasks(self) -> Iterator[tuple[int, int, Path, tuple[int, int]]]:
        root_fd = self._open_root()
        tasks_fd: int | None = None
        lock_fd: int | None = None
        try:
            tasks_fd, path, identity = self._open_configured(
                root_fd, "tasks", for_write=True
            )
            lock_fd = os.open(
                ".plan-flow.lock",
                os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=tasks_fd,
            )
            lock_stat = os.fstat(lock_fd)
            lock_named = os.stat(
                ".plan-flow.lock", dir_fd=tasks_fd, follow_symlinks=False
            )
            if not stat.S_ISREG(lock_stat.st_mode) or (
                lock_stat.st_dev,
                lock_stat.st_ino,
            ) != (lock_named.st_dev, lock_named.st_ino):
                _fail("plan lock is invalid")
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            self._revalidate_configured(
                tasks_fd, path, identity, "tasks", for_write=True
            )
            yield root_fd, tasks_fd, path, identity
            self._revalidate_configured(
                tasks_fd, path, identity, "tasks", for_write=True
            )
            self._revalidate_root(root_fd)
        except OSError:
            _fail("plan lock cannot be acquired safely")
        finally:
            if lock_fd is not None:
                try:
                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
                finally:
                    os.close(lock_fd)
            if tasks_fd is not None:
                os.close(tasks_fd)
            os.close(root_fd)

    @contextmanager
    def _opened_tasks(self) -> Iterator[tuple[int, int, Path, tuple[int, int]]]:
        """Open the tasks zone for a read-only operation without creating a lock."""

        root_fd = self._open_root()
        tasks_fd: int | None = None
        try:
            tasks_fd, path, identity = self._open_configured(
                root_fd, "tasks", for_write=False
            )
            yield root_fd, tasks_fd, path, identity
            self._revalidate_configured(
                tasks_fd, path, identity, "tasks", for_write=False
            )
            self._revalidate_root(root_fd)
        finally:
            if tasks_fd is not None:
                os.close(tasks_fd)
            os.close(root_fd)

    @staticmethod
    def _period_dir(tasks_fd: int, kind: str, *, create: bool) -> int | None:
        name = "days" if kind == "day" else "weeks"
        try:
            metadata = os.stat(name, dir_fd=tasks_fd, follow_symlinks=False)
        except FileNotFoundError:
            if not create:
                return None
            return _open_dir_at(tasks_fd, name, create=True)
        except OSError:
            _fail("plan period namespace cannot be inspected")
        if not stat.S_ISDIR(metadata.st_mode):
            _fail("plan period namespace is unsafe")
        return _open_dir_at(tasks_fd, name)

    @staticmethod
    def _revalidate_period_parent(
        tasks_fd: int,
        directory_fd: int,
        parent: str,
        identity: tuple[int, int],
    ) -> None:
        try:
            named = os.stat(parent, dir_fd=tasks_fd, follow_symlinks=False)
        except OSError:
            _fail("plan period namespace changed during operation")
        if (
            not stat.S_ISDIR(named.st_mode)
            or _directory_identity(directory_fd) != identity
            or (named.st_dev, named.st_ino) != identity
        ):
            _fail("plan period namespace changed during operation")

    def _read_pair_at(self, tasks_fd: int, kind: str, period: str) -> _PlanPair:
        checked = (
            _date_text(period, "plan period") if kind == "day" else _week_start(period)
        )
        directory_fd = self._period_dir(tasks_fd, kind, create=False)
        if directory_fd is None:
            return _PlanPair(None, None, None)
        try:
            try:
                json_raw, json_identity = _read_at(
                    directory_fd, f"{checked}.json", _MAX_JSON
                )
            except FileNotFoundError:
                json_raw = None
                json_identity = None
            try:
                markdown_raw, markdown_identity = _read_at(
                    directory_fd, f"{checked}.md", _MAX_MARKDOWN
                )
            except FileNotFoundError:
                markdown_raw = None
                markdown_identity = None
            if (json_raw is None) != (markdown_raw is None):
                _fail("plan machine state and Markdown projection are incomplete")
            if json_raw is None or markdown_raw is None:
                return _PlanPair(None, None, None)
            if (
                _identity_at(directory_fd, f"{checked}.json") != json_identity
                or _identity_at(directory_fd, f"{checked}.md") != markdown_identity
            ):
                _fail("plan pair changed while read")
            plan: DayPlan | WeekPlan
            if kind == "day":
                plan = _parse_day(json_raw)
                if plan.date != checked or markdown_raw != render_day_markdown(plan):
                    _fail("day plan filename or Markdown projection disagrees")
            else:
                plan = _parse_week(json_raw)
                if plan.week_start != checked or markdown_raw != render_week_markdown(
                    plan
                ):
                    _fail("week plan filename or Markdown projection disagrees")
            return _PlanPair(plan, json_raw, markdown_raw)
        finally:
            os.close(directory_fd)

    def read_day(self, capability: ActionCapability, period: str) -> DayPlan | None:
        self._require(capability, "collect-plan-context")
        with self._opened_tasks() as (_root_fd, tasks_fd, _path, _identity):
            pair = self._read_pair_at(tasks_fd, "day", period)
            if pair.plan is not None and not isinstance(pair.plan, DayPlan):
                _fail("day plan reader returned the wrong record kind")
            return pair.plan

    def read_week(
        self, capability: ActionCapability, week_start: str
    ) -> WeekPlan | None:
        self._require(capability, "collect-plan-context")
        with self._opened_tasks() as (_root_fd, tasks_fd, _path, _identity):
            pair = self._read_pair_at(tasks_fd, "week", week_start)
            if pair.plan is not None and not isinstance(pair.plan, WeekPlan):
                _fail("week plan reader returned the wrong record kind")
            return pair.plan

    def _project_contexts(self, root_fd: int) -> tuple[ProjectPlanContext, ...]:
        projects_fd, path, identity = self._open_configured(
            root_fd, "projects", for_write=False
        )
        result: list[ProjectPlanContext] = []
        try:
            intents, pending_projects = _read_project_intents(projects_fd)
            for name in sorted(
                _listdir(projects_fd, "projects context namespace"),
                key=_portable_key,
            ):
                portable = _portable_key(name)
                if portable in _ARCHIVE_KEYS:
                    if name != portable:
                        _fail("projects namespace aliases a lifecycle archive")
                    continue
                if name.startswith("."):
                    continue
                if len(result) >= _MAX_CONTEXT:
                    _fail("project context exceeds its structural bound")
                _identifier(name, "project context directory", _PROJECT_SLUG)
                child_fd = _open_dir_at(projects_fd, name)
                try:
                    project_raw, project_identity = _read_at(
                        child_fd, "project.json", _MAX_JSON
                    )
                    state_raw, state_identity = _read_at(
                        child_fd, "state.json", _MAX_JSON
                    )
                    log_raw, log_identity = _read_at(child_fd, "log.md", _MAX_JSONL)
                    project_hint = _decode(project_raw, "project context record")
                    if not isinstance(project_hint, Mapping):
                        _fail("project context record is invalid")
                    transition_id = _identifier(
                        project_hint.get("last_transition_id"),
                        "project context transition id",
                    )
                    intent_raw = intents.get(transition_id)
                    if intent_raw is None:
                        _fail("project context lacks transition evidence")
                    if (
                        _identity_at(child_fd, "project.json") != project_identity
                        or _identity_at(child_fd, "state.json") != state_identity
                        or _identity_at(child_fd, "log.md") != log_identity
                    ):
                        _fail("project context bundle changed while read")
                except FileNotFoundError:
                    _fail("project context bundle is incomplete")
                finally:
                    os.close(child_fd)
                context = _parse_project_context(
                    project_raw,
                    state_raw,
                    log_raw,
                    intent_raw,
                    directory_name=name,
                )
                if _portable_key(context.slug) in pending_projects:
                    _fail("project has a pending transition requiring reconciliation")
                result.append(context)
            self._revalidate_configured(
                projects_fd, path, identity, "projects", for_write=False
            )
        finally:
            os.close(projects_fd)
        return tuple(sorted(result, key=lambda item: _portable_key(item.slug)))

    def _entity_contexts(self, root_fd: int) -> tuple[EntityPlanContext, ...]:
        memory_fd, path, identity = self._open_configured(
            root_fd, "agent/memory", for_write=False
        )
        entities_fd: int | None = None
        result: list[EntityPlanContext] = []
        try:
            try:
                metadata = os.stat("entities", dir_fd=memory_fd, follow_symlinks=False)
            except FileNotFoundError:
                return ()
            except OSError:
                _fail("entity context namespace cannot be inspected")
            if not stat.S_ISDIR(metadata.st_mode):
                _fail("entity context namespace is unsafe")
            entities_fd = _open_dir_at(memory_fd, "entities")
            for name in sorted(
                _listdir(entities_fd, "entity context namespace"),
                key=_portable_key,
            ):
                if name.startswith("."):
                    continue
                portable = _portable_key(name)
                if portable in _ARCHIVE_KEYS:
                    if name != portable:
                        _fail("entity context aliases an archive namespace")
                    continue
                if not name.endswith(".json"):
                    _fail("entity context namespace contains an unknown entry")
                domain = _identifier(
                    name[:-5], "entity context collection domain", _DOMAIN
                )
                try:
                    raw, file_identity = _read_at(entities_fd, name, _MAX_JSON)
                except FileNotFoundError:
                    _fail("entity context collection changed while read")
                collection = _decode(raw, "entity context collection")
                if (
                    not isinstance(collection, Mapping)
                    or set(collection)
                    != {"schema_version", "domain", "revision", "entities"}
                    or collection["schema_version"] != 1
                    or collection["domain"] != domain
                    or type(collection["revision"]) is not int
                    or not isinstance(collection["entities"], list)
                    or raw != _canonical(dict(collection))
                ):
                    _fail("entity context collection violates the public schema")
                _exact_int(
                    collection["revision"],
                    "entity context collection revision",
                    0,
                    2**31 - 1,
                )
                if _identity_at(entities_fd, name) != file_identity:
                    _fail("entity context collection changed while read")
                collection_ids: list[str] = []
                for payload in collection["entities"]:
                    context = _parse_entity_context(payload, domain=domain)
                    if isinstance(payload, Mapping) and isinstance(
                        payload.get("id"), str
                    ):
                        collection_ids.append(_portable_key(payload["id"]))
                    if context is not None:
                        result.append(context)
                        if len(result) > _MAX_CONTEXT:
                            _fail("entity context exceeds its structural bound")
                if collection_ids != sorted(collection_ids) or len(
                    collection_ids
                ) != len(set(collection_ids)):
                    _fail("entity context collection ids are not exact and sorted")
            self._revalidate_configured(
                memory_fd, path, identity, "agent/memory", for_write=False
            )
        finally:
            if entities_fd is not None:
                os.close(entities_fd)
            os.close(memory_fd)
        keys = [_portable_key(item.entity_id) for item in result]
        if len(keys) != len(set(keys)):
            _fail("entity context ids collide across collections")
        return tuple(
            sorted(
                result,
                key=lambda item: (
                    _portable_key(item.domain),
                    _portable_key(item.entity_id),
                ),
            )
        )

    def _packet_at(
        self,
        root_fd: int,
        tasks_fd: int,
        query: PlanContextQuery,
        *,
        task_grant: ActionCapability,
        project_grant: ActionCapability,
        entity_grant: ActionCapability,
    ) -> PlanningPacket:
        if (
            not isinstance(query, PlanContextQuery)
            or not isinstance(query.kind, str)
            or query.kind not in {"day", "week"}
        ):
            _fail("plan context query is invalid")
        period = (
            _date_text(query.period, "context period")
            if query.kind == "day"
            else _week_start(query.period)
        )
        as_of = _timestamp(query.as_of, "context as_of")
        project_limit = _exact_int(
            query.project_limit, "project_limit", 0, _MAX_CONTEXT
        )
        entity_limit = _exact_int(query.entity_limit, "entity_limit", 0, _MAX_CONTEXT)
        maximum = _exact_int(
            query.maximum_bytes, "packet maximum_bytes", 1024, _MAX_JSON
        )
        self._require(task_grant, "collect-plan-context")
        pair = self._read_pair_at(tasks_fd, query.kind, period)
        self._require(project_grant, "read-plan-project-context")
        all_projects = self._project_contexts(root_fd)
        self._require(entity_grant, "read-plan-entity-context")
        all_entities = self._entity_contexts(root_fd)
        current_tasks = () if pair.plan is None else pair.plan.tasks
        base = PlanningPacket(
            query.kind,
            period,
            as_of,
            None if pair.json_raw is None else _digest(pair.json_raw),
            current_tasks,
            all_projects[:project_limit],
            all_entities[:entity_limit],
            len(all_projects) > project_limit,
            len(all_entities) > entity_limit,
            "0" * 64,
        )
        payload = _packet_base(base)
        packet = replace(base, packet_sha256=_digest(_canonical(payload)))
        if len(render_planning_packet(packet)) > maximum:
            _fail("planning packet exceeds the requested byte bound")
        return packet

    def planning_packet(
        self, capabilities: PlanCapabilities, query: PlanContextQuery
    ) -> PlanningPacket:
        if not isinstance(capabilities, PlanCapabilities):
            _fail("planning packet requires PlanCapabilities")
        task_grant = self._require(
            capabilities.collect_plan_context, "collect-plan-context"
        )
        project_grant = self._require(
            capabilities.read_plan_project_context, "read-plan-project-context"
        )
        entity_grant = self._require(
            capabilities.read_plan_entity_context, "read-plan-entity-context"
        )
        with self._opened_tasks() as (root_fd, tasks_fd, _path, _identity):
            return self._packet_at(
                root_fd,
                tasks_fd,
                query,
                task_grant=task_grant,
                project_grant=project_grant,
                entity_grant=entity_grant,
            )

    @staticmethod
    def _evidence_stem(operation_id: str) -> str:
        checked = _identifier(operation_id, "operation_id")
        return (
            "plan-evidence-" + hashlib.sha256(checked.encode("utf-8")).hexdigest()[:32]
        )

    @staticmethod
    def _validate_packet_payload(payload: object) -> None:
        keys = {
            "schema_version",
            "kind",
            "period",
            "as_of",
            "current_plan_sha256",
            "current_tasks",
            "projects",
            "entities",
            "projects_truncated",
            "entities_truncated",
            "packet_sha256",
        }
        if not isinstance(payload, Mapping) or set(payload) != keys:
            _fail("durable planning packet has missing or unknown fields")
        if (
            payload["schema_version"] != PLAN_PACKET_SCHEMA_VERSION
            or not isinstance(payload["kind"], str)
            or payload["kind"] not in {"day", "week"}
        ):
            _fail("durable planning packet schema or kind is invalid")
        if payload["kind"] == "day":
            _date_text(payload["period"], "durable packet period")
        else:
            _week_start(payload["period"])
        _timestamp(payload["as_of"], "durable packet as_of")
        if payload["current_plan_sha256"] is not None:
            _hash(payload["current_plan_sha256"], "durable current plan sha256")
        if (
            not isinstance(payload["current_tasks"], list)
            or len(payload["current_tasks"]) > _MAX_TASKS
            or not isinstance(payload["projects"], list)
            or len(payload["projects"]) > _MAX_CONTEXT
            or not isinstance(payload["entities"], list)
            or len(payload["entities"]) > _MAX_CONTEXT
            or type(payload["projects_truncated"]) is not bool
            or type(payload["entities_truncated"]) is not bool
        ):
            _fail("durable planning packet collections are invalid")
        for item in payload["current_tasks"]:
            _parse_task(item)
        project_keys = {
            "slug",
            "name",
            "goal",
            "revision",
            "next_steps",
            "blockers",
            "snapshot_sha256",
        }
        for item in payload["projects"]:
            if (
                not isinstance(item, Mapping)
                or set(item) != project_keys
                or not isinstance(item["next_steps"], list)
                or not isinstance(item["blockers"], list)
            ):
                _fail("durable project context is invalid")
            _project_context_payload(
                ProjectPlanContext(
                    item["slug"],
                    item["name"],
                    item["goal"],
                    item["revision"],
                    tuple(item["next_steps"]),
                    tuple(item["blockers"]),
                    item["snapshot_sha256"],
                )
            )
        entity_keys = {
            "entity_id",
            "domain",
            "title",
            "priority",
            "deadline",
            "next_review_at",
            "revision",
            "record_sha256",
        }
        for item in payload["entities"]:
            if not isinstance(item, Mapping) or set(item) != entity_keys:
                _fail("durable entity context is invalid")
            _entity_context_payload(
                EntityPlanContext(
                    item["entity_id"],
                    item["domain"],
                    item["title"],
                    item["priority"],
                    item["deadline"],
                    item["next_review_at"],
                    item["revision"],
                    item["record_sha256"],
                )
            )
        claimed = _hash(payload["packet_sha256"], "durable packet sha256")
        base = dict(payload)
        del base["packet_sha256"]
        if _digest(_canonical(base)) != claimed:
            _fail("durable planning packet hash is invalid")

    def _validate_mutation_evidence(self, payload: Mapping[str, object]) -> None:
        self._validate_packet_payload(payload["packet"])
        self._validate_file_evidence(payload["targets"], payload["preimages"])
        assert isinstance(payload["targets"], list)
        operation = payload["operation"]
        operation_id = _identifier(payload["operation_id"], "evidence operation_id")
        request = payload["request"]
        assert isinstance(request, Mapping)
        if (
            request.get("operation") != operation
            or request.get("operation_id") != operation_id
        ):
            _fail("plan replay request binding is invalid")
        common = {"schema_version", "operation", "operation_id"}
        expected_revision: int | None
        if operation in {"commit-day", "skip-task"}:
            expected_request_keys = (
                common | {"period", "expected_revision", "status", "policy", "tasks"}
                if operation == "commit-day"
                else common
                | {
                    "period",
                    "task_id",
                    "expected_revision",
                    "reason",
                    "skipped_at",
                    "feedback",
                }
            )
            if set(request) != expected_request_keys:
                _fail("plan replay request has missing or unknown fields")
            period = request.get("period")
            _date_text(period, "evidence day period")
            expected_paths = {
                f"days/{period}.json",
                f"days/{period}.md",
            }
        elif operation == "commit-week":
            if set(request) != common | {
                "week_start",
                "expected_revision",
                "status",
                "policy",
                "tasks",
            }:
                _fail("plan replay request has missing or unknown fields")
            period = request.get("week_start")
            _week_start(period)
            expected_paths = {
                f"weeks/{period}.json",
                f"weeks/{period}.md",
            }
        elif operation == "rollover-day":
            if set(request) != common | {
                "source_date",
                "target_date",
                "expected_revision",
                "policy",
            }:
                _fail("plan replay request has missing or unknown fields")
            source = request.get("source_date")
            target = request.get("target_date")
            _date_text(source, "evidence rollover source")
            _date_text(target, "evidence rollover target")
            expected_paths = {
                f"days/{source}.json",
                f"days/{source}.md",
                f"days/{target}.json",
                f"days/{target}.md",
            }
        else:
            _fail("plan replay operation is invalid")
        if request.get("schema_version") != PLAN_MUTATION_SCHEMA_VERSION:
            _fail("plan replay request schema is invalid")
        raw_expected = request.get("expected_revision")
        if raw_expected is None:
            expected_revision = None
            if operation in {"skip-task", "rollover-day"}:
                _fail("plan replay request requires expected_revision")
        else:
            expected_revision = _exact_int(
                raw_expected, "evidence expected_revision", 1, 2**31 - 1
            )
        if operation in {"commit-day", "commit-week"}:
            if not isinstance(request.get("status"), str) or request.get(
                "status"
            ) not in {"active", "closed"}:
                _fail("plan replay requested status is invalid")
            _parse_policy(request.get("policy"))
            raw_tasks = request.get("tasks")
            if not isinstance(raw_tasks, list) or len(raw_tasks) > _MAX_TASKS:
                _fail("plan replay requested tasks are invalid")
            for item in raw_tasks:
                _parse_task(item)
        elif operation == "skip-task":
            _identifier(request.get("task_id"), "evidence skip task_id", _TASK_ID)
            _text(request.get("reason"), "evidence skip reason", limit=4096)
            _timestamp(request.get("skipped_at"), "evidence skipped_at")
            if request.get("feedback") is not None:
                _text(request.get("feedback"), "evidence skip feedback", limit=4096)
        elif request.get("policy") is not None:
            _parse_policy(request.get("policy"))
        decoded = {
            relative: data
            for relative, data, _maximum in (
                self._decode_file_item(item, preimage=False)
                for item in payload["targets"]
            )
        }
        if set(decoded) != expected_paths:
            _fail("plan replay target paths disagree with the operation")
        before_decoded = {
            relative: data
            for relative, data, _maximum in (
                self._decode_file_item(item, preimage=True)
                for item in payload["preimages"]
            )
        }
        if set(before_decoded) != expected_paths:
            _fail("plan replay preimage paths disagree with the operation")
        request_hash = _digest(_canonical(dict(request)))
        parsed_plans: dict[str, DayPlan | WeekPlan] = {}
        before_plans: dict[str, DayPlan | WeekPlan] = {}
        for relative, raw in decoded.items():
            assert raw is not None
            if not relative.endswith(".json"):
                continue
            plan: DayPlan | WeekPlan
            if relative.startswith("days/"):
                plan = _parse_day(raw)
                markdown = decoded[relative[:-5] + ".md"]
                if markdown != render_day_markdown(plan):
                    _fail("durable day plan Markdown binding is invalid")
            else:
                plan = _parse_week(raw)
                markdown = decoded[relative[:-5] + ".md"]
                if markdown != render_week_markdown(plan):
                    _fail("durable week plan Markdown binding is invalid")
            parsed_plans[relative] = plan
            if (
                plan.last_operation_id != operation_id
                or plan.last_operation_sha256 != request_hash
            ):
                _fail("durable plan target is not bound to its request")
            before_raw = before_decoded[relative]
            before_markdown = before_decoded[relative[:-5] + ".md"]
            if (before_raw is None) != (before_markdown is None):
                _fail("durable plan preimage pair is incomplete")
            if before_raw is None:
                continue
            if relative.startswith("days/"):
                before_plan: DayPlan | WeekPlan = _parse_day(before_raw)
                if before_markdown != render_day_markdown(before_plan):
                    _fail("durable day preimage Markdown binding is invalid")
            else:
                before_plan = _parse_week(before_raw)
                if before_markdown != render_week_markdown(before_plan):
                    _fail("durable week preimage Markdown binding is invalid")
            before_plans[relative] = before_plan
        packet = payload["packet"]
        assert isinstance(packet, Mapping)
        packet_as_of = _timestamp(packet["as_of"], "durable packet as_of")
        skipped = tuple(_parse_skip(item) for item in payload["skipped_events"])
        feedback = self._validate_feedback_payload(payload["feedback_proposal"])
        expected_skipped: tuple[SkippedTaskEvent, ...] = ()
        expected_feedback: dict[str, object] | None = None
        if operation == "commit-day":
            plan_path = f"days/{request['period']}.json"
            target_plan = parsed_plans[plan_path]
            assert isinstance(target_plan, DayPlan)
            prior = before_plans.get(plan_path)
            if prior is not None and not isinstance(prior, DayPlan):
                _fail("durable day preimage has the wrong kind")
            if expected_revision is None:
                if prior is not None:
                    _fail("new day replay has an unexpected preimage")
            elif (
                not isinstance(prior, DayPlan)
                or prior.status != "active"
                or prior.revision != expected_revision
            ):
                _fail("day replay preimage disagrees with expected revision")
            target_payload = _day_payload(target_plan)
            expected_created = packet_as_of if prior is None else prior.created_at
            if (
                target_payload["status"] != request.get("status")
                or target_payload["policy"] != request.get("policy")
                or target_payload["tasks"] != request.get("tasks")
                or target_plan.revision
                != (1 if expected_revision is None else expected_revision + 1)
                or target_plan.created_at != expected_created
                or target_plan.updated_at != packet_as_of
            ):
                _fail("durable day target disagrees with its request")
            expected_skipped = self._skip_events(
                operation_id,
                () if prior is None else prior.tasks,
                target_plan.tasks,
                target_date=None,
            )
            skipped_ids = {_portable_key(item.task_id) for item in expected_skipped}
            expected_feedback = self._feedback_proposal(
                operation_id,
                tuple(
                    task
                    for task in target_plan.tasks
                    if _portable_key(task.task_id) in skipped_ids
                ),
                packet_as_of,
            )
        elif operation == "commit-week":
            plan_path = f"weeks/{request['week_start']}.json"
            target_plan = parsed_plans[plan_path]
            assert isinstance(target_plan, WeekPlan)
            prior = before_plans.get(plan_path)
            if prior is not None and not isinstance(prior, WeekPlan):
                _fail("durable week preimage has the wrong kind")
            if expected_revision is None:
                if prior is not None:
                    _fail("new week replay has an unexpected preimage")
            elif (
                not isinstance(prior, WeekPlan)
                or prior.status != "active"
                or prior.revision != expected_revision
            ):
                _fail("week replay preimage disagrees with expected revision")
            target_payload = _week_payload(target_plan)
            expected_created = packet_as_of if prior is None else prior.created_at
            if (
                target_payload["status"] != request.get("status")
                or target_payload["policy"] != request.get("policy")
                or target_payload["tasks"] != request.get("tasks")
                or target_plan.revision
                != (1 if expected_revision is None else expected_revision + 1)
                or target_plan.created_at != expected_created
                or target_plan.updated_at != packet_as_of
            ):
                _fail("durable week target disagrees with its request")
            expected_skipped = self._skip_events(
                operation_id,
                () if prior is None else prior.tasks,
                target_plan.tasks,
                target_date=None,
            )
            skipped_ids = {_portable_key(item.task_id) for item in expected_skipped}
            expected_feedback = self._feedback_proposal(
                operation_id,
                tuple(
                    task
                    for task in target_plan.tasks
                    if _portable_key(task.task_id) in skipped_ids
                ),
                packet_as_of,
            )
        elif operation == "skip-task":
            plan_path = f"days/{request['period']}.json"
            target_plan = parsed_plans[plan_path]
            assert isinstance(target_plan, DayPlan)
            prior = before_plans.get(plan_path)
            if not isinstance(prior, DayPlan) or not isinstance(expected_revision, int):
                _fail("skip replay requires an exact day preimage")
            prior_matches = [
                item
                for item in prior.tasks
                if _portable_key(item.task_id)
                == _portable_key(str(request.get("task_id")))
            ]
            if (
                prior.status != "active"
                or prior.revision != expected_revision
                or len(prior_matches) != 1
                or prior_matches[0].status != "open"
            ):
                _fail("skip replay preimage disagrees with its request")
            replacement = replace(
                prior_matches[0],
                status="skipped",
                skipped_at=str(request["skipped_at"]),
                feedback=request.get("feedback"),
            )
            expected_tasks = tuple(
                sorted(
                    (
                        replacement
                        if _portable_key(item.task_id)
                        == _portable_key(replacement.task_id)
                        else item
                        for item in prior.tasks
                    ),
                    key=lambda item: _portable_key(item.task_id),
                )
            )
            if (
                target_plan.revision != expected_revision + 1
                or target_plan.status != "active"
                or target_plan.policy != prior.policy
                or target_plan.tasks != expected_tasks
                or target_plan.created_at != prior.created_at
                or target_plan.updated_at != packet_as_of
            ):
                _fail("durable skipped task target disagrees with its request")
            generated = self._skip_events(
                operation_id, prior.tasks, target_plan.tasks, target_date=None
            )
            if len(generated) != 1:
                _fail("skip replay does not produce exactly one trace event")
            expected_skipped = (replace(generated[0], reason=str(request["reason"])),)
            expected_feedback = self._feedback_proposal(
                operation_id, (replacement,), packet_as_of
            )
        else:
            source_path = f"days/{request['source_date']}.json"
            target_path = f"days/{request['target_date']}.json"
            source_plan = parsed_plans[source_path]
            target_plan = parsed_plans[target_path]
            assert isinstance(source_plan, DayPlan) and isinstance(target_plan, DayPlan)
            source_before = before_plans.get(source_path)
            target_before = before_plans.get(target_path)
            if (
                not isinstance(source_before, DayPlan)
                or not isinstance(expected_revision, int)
                or target_before is not None
                or source_before.status != "active"
                or source_before.revision != expected_revision
            ):
                _fail("rollover replay preimages disagree with its request")
            expected_policy = request.get("policy")
            target_policy = (
                source_before.policy
                if expected_policy is None
                else _parse_policy(expected_policy)
            )
            expected_source_tasks = tuple(
                replace(task, status="rolled-over") if task.status == "open" else task
                for task in source_before.tasks
            )
            expected_target_tasks = tuple(
                sorted(
                    (
                        replace(
                            task,
                            scheduled_for=str(request["target_date"]),
                            rollover_count=task.rollover_count + 1,
                        )
                        for task in source_before.tasks
                        if task.status == "open"
                    ),
                    key=lambda item: _portable_key(item.task_id),
                )
            )
            if (
                source_plan.status != "rolled-over"
                or source_plan.revision != expected_revision + 1
                or source_plan.policy != source_before.policy
                or source_plan.tasks != expected_source_tasks
                or source_plan.created_at != source_before.created_at
                or source_plan.updated_at != packet_as_of
                or target_plan.status != "active"
                or target_plan.revision != 1
                or target_plan.policy != target_policy
                or target_plan.tasks != expected_target_tasks
                or target_plan.created_at != packet_as_of
                or target_plan.updated_at != packet_as_of
            ):
                _fail("durable rollover targets disagree with their request")
        if skipped != expected_skipped or feedback != expected_feedback:
            _fail("plan replay trace or feedback disagrees with its mutation")
        result_kind = payload["result_kind"]
        result_period = payload["result_period"]
        if operation == "commit-week":
            expected_result = ("week", request.get("week_start"))
        elif operation == "rollover-day":
            expected_result = ("day", request.get("target_date"))
        else:
            expected_result = ("day", request.get("period"))
        if (result_kind, result_period) != expected_result:
            _fail("plan replay result binding is invalid")
        output_binding = {
            "targets": [
                {"relative": item["relative"], "sha256": item["sha256"]}
                for item in payload["targets"]
            ],
            "skipped_events": [_skip_payload(item) for item in skipped],
            "feedback_proposal": feedback,
        }
        if _digest(_canonical(output_binding)) != payload["output_sha256"]:
            _fail("plan replay output hash is invalid")

    def _load_evidence(
        self, root_fd: int, run_id: str, operation_id: str
    ) -> dict[str, object] | None:
        runs_relative = self._resolver.config.zone("runs").as_posix()
        run_fd = _open_dir_at(root_fd, f"{runs_relative}/{run_id}")
        try:
            name = self._evidence_stem(operation_id) + ".json"
            try:
                raw, _ = _read_at(run_fd, name, _MAX_JSON)
            except FileNotFoundError:
                return None
        finally:
            os.close(run_fd)
        payload = _decode(raw, "plan replay evidence")
        expected = {
            "schema_version",
            "flow",
            "operation",
            "operation_id",
            "request",
            "packet",
            "targets",
            "preimages",
            "skipped_events",
            "feedback_proposal",
            "result_kind",
            "result_period",
            "output_sha256",
        }
        if not isinstance(payload, Mapping) or set(payload) != expected:
            _fail("plan replay evidence has missing or unknown fields")
        if (
            payload["schema_version"] != PLAN_MUTATION_SCHEMA_VERSION
            or payload["flow"] != "plan"
            or payload["operation_id"] != operation_id
            or not isinstance(payload["operation"], str)
            or not isinstance(payload["request"], Mapping)
            or not isinstance(payload["packet"], Mapping)
            or not isinstance(payload["targets"], list)
            or not isinstance(payload["preimages"], list)
            or not isinstance(payload["skipped_events"], list)
            or not isinstance(payload["result_kind"], str)
            or payload["result_kind"] not in {"day", "week"}
            or not isinstance(payload["result_period"], str)
        ):
            _fail("plan replay evidence fields are invalid")
        _hash(payload["output_sha256"], "plan replay output sha256")
        if raw != _canonical(dict(payload)):
            _fail("plan replay evidence is not canonical JSON")
        self._validate_mutation_evidence(payload)
        return dict(payload)

    @staticmethod
    def _file_item(relative: str, data: bytes, maximum: int) -> dict[str, object]:
        if not isinstance(data, bytes) or not data or len(data) > maximum:
            _fail("plan target bytes are invalid or too large")
        return {
            "relative": relative,
            "maximum": maximum,
            "sha256": _digest(data),
            "bytes_base64": base64.b64encode(data).decode("ascii"),
        }

    @staticmethod
    def _preimage_item(
        relative: str, data: bytes | None, maximum: int
    ) -> dict[str, object]:
        return {
            "relative": relative,
            "maximum": maximum,
            "exists": data is not None,
            "sha256": None if data is None else _digest(data),
            "bytes_base64": (
                None if data is None else base64.b64encode(data).decode("ascii")
            ),
        }

    @staticmethod
    def _decode_file_item(
        item: object, *, preimage: bool
    ) -> tuple[str, bytes | None, int]:
        target_keys = {"relative", "maximum", "sha256", "bytes_base64"}
        preimage_keys = target_keys | {"exists"}
        if not isinstance(item, Mapping) or set(item) != (
            preimage_keys if preimage else target_keys
        ):
            _fail("plan file evidence has missing or unknown fields")
        relative = item["relative"]
        if not isinstance(relative, str):
            _fail("plan file evidence relative path is invalid")
        parts = _safe_parts(relative)
        if (
            len(parts) != 2
            or parts[0] not in {"days", "weeks"}
            or not re.fullmatch(r"\d{4}-\d{2}-\d{2}\.(?:json|md)", parts[1])
        ):
            _fail("plan file evidence escapes day/week state")
        maximum = _exact_int(item["maximum"], "plan file maximum", 1, _MAX_JSON)
        if preimage and type(item["exists"]) is not bool:
            _fail("plan preimage existence flag must be boolean")
        exists = not preimage or item["exists"] is True
        if not exists:
            if item["sha256"] is not None or item["bytes_base64"] is not None:
                _fail("missing plan preimage cannot contain bytes")
            return relative, None, maximum
        if not isinstance(item["bytes_base64"], str):
            _fail("plan file evidence bytes are invalid")
        try:
            data = base64.b64decode(item["bytes_base64"], validate=True)
        except (ValueError, TypeError):
            _fail("plan file evidence bytes are invalid")
        if not data or len(data) > maximum or _digest(data) != item["sha256"]:
            _fail("plan file evidence hash or size is invalid")
        _hash(item["sha256"], "plan file evidence sha256")
        return relative, data, maximum

    def _validate_file_evidence(self, targets: object, preimages: object) -> None:
        if (
            not isinstance(targets, list)
            or not isinstance(preimages, list)
            or not targets
            or len(targets) > 4
            or len(targets) != len(preimages)
        ):
            _fail("plan target/preimage evidence is invalid")
        target_items = [
            self._decode_file_item(item, preimage=False) for item in targets
        ]
        preimage_items = [
            self._decode_file_item(item, preimage=True) for item in preimages
        ]
        target_names = [item[0] for item in target_items]
        preimage_names = [item[0] for item in preimage_items]
        if (
            target_names != sorted(target_names)
            or preimage_names != target_names
            or len(target_names) != len(set(target_names))
        ):
            _fail("plan target/preimage paths are not exact and sorted")

    @staticmethod
    def _validate_feedback_payload(payload: object) -> dict[str, object] | None:
        if payload is None:
            return None
        keys = {
            "schema_version",
            "proposal_id",
            "operation_id",
            "status",
            "created_at",
            "items",
            "relative",
        }
        if not isinstance(payload, Mapping) or set(payload) != keys:
            _fail("plan feedback proposal has missing or unknown fields")
        if (
            payload["schema_version"] != PLAN_FEEDBACK_SCHEMA_VERSION
            or payload["status"] != "proposed"
            or not isinstance(payload["items"], list)
            or not isinstance(payload["relative"], str)
            or not re.fullmatch(
                r"tasks-feedback-[0-9a-f]{32}\.json", payload["relative"]
            )
        ):
            _fail("plan feedback proposal fields are invalid")
        _identifier(payload["proposal_id"], "feedback proposal id")
        _identifier(payload["operation_id"], "feedback operation id")
        _timestamp(payload["created_at"], "feedback created_at")
        if not payload["items"] or len(payload["items"]) > _MAX_TASKS:
            _fail("plan feedback proposal items are invalid")
        seen: set[str] = set()
        for item in payload["items"]:
            if not isinstance(item, Mapping) or set(item) != {
                "task_id",
                "task_text",
                "feedback",
                "source_date",
            }:
                _fail("plan feedback proposal item is invalid")
            task_id = _identifier(item["task_id"], "feedback task_id", _TASK_ID)
            _text(item["task_text"], "feedback task text", limit=2048)
            _text(item["feedback"], "feedback text", limit=4096)
            _date_text(item["source_date"], "feedback source date")
            key = _portable_key(task_id)
            if key in seen:
                _fail("plan feedback proposal task ids collide")
            seen.add(key)
        return dict(payload)

    @staticmethod
    def _feedback_proposal(
        operation_id: str, tasks: Sequence[PlanTask], created_at: str
    ) -> dict[str, object] | None:
        items = [
            {
                "task_id": task.task_id,
                "task_text": task.text,
                "feedback": task.feedback,
                "source_date": task.scheduled_for,
            }
            for task in tasks
            if task.status == "skipped" and task.feedback is not None
        ]
        if not items:
            return None
        token = hashlib.sha256(operation_id.encode("utf-8")).hexdigest()[:32]
        payload = {
            "schema_version": PLAN_FEEDBACK_SCHEMA_VERSION,
            "proposal_id": f"plan-feedback-{token[:24]}",
            "operation_id": operation_id,
            "status": "proposed",
            "created_at": created_at,
            "items": sorted(
                items, key=lambda item: _portable_key(str(item["task_id"]))
            ),
            "relative": f"tasks-feedback-{token}.json",
        }
        PlanFlow._validate_feedback_payload(payload)
        return payload

    @staticmethod
    def _skip_events(
        operation_id: str,
        before: Sequence[PlanTask],
        after: Sequence[PlanTask],
        *,
        target_date: str | None,
    ) -> tuple[SkippedTaskEvent, ...]:
        prior = {_portable_key(item.task_id): item for item in before}
        events: list[SkippedTaskEvent] = []
        for task in after:
            previous = prior.get(_portable_key(task.task_id))
            if task.status != "skipped" or (
                previous is not None and previous.status == "skipped"
            ):
                continue
            assert task.skipped_at is not None
            seed = f"{operation_id}:{task.task_id}"
            event_id = "skip-" + hashlib.sha256(seed.encode("utf-8")).hexdigest()[:32]
            events.append(
                SkippedTaskEvent(
                    event_id,
                    operation_id,
                    task.task_id,
                    task.text,
                    task.scheduled_for,
                    target_date,
                    task.feedback or "Task was explicitly skipped.",
                    task.skipped_at,
                    task.project_slug,
                    task.entity_id,
                )
            )
        return tuple(sorted(events, key=lambda item: _portable_key(item.event_id)))

    @staticmethod
    def _validate_context_references(
        tasks: Sequence[PlanTask], packet: PlanningPacket
    ) -> None:
        projects = {_portable_key(item.slug) for item in packet.projects}
        entities = {_portable_key(item.entity_id) for item in packet.entities}
        for task in tasks:
            if (
                task.project_slug is not None
                and _portable_key(task.project_slug) not in projects
            ):
                _fail("task project reference is missing from active project context")
            if (
                task.entity_id is not None
                and _portable_key(task.entity_id) not in entities
            ):
                _fail("task entity reference is missing from active entity context")

    def _make_evidence(
        self,
        *,
        operation: str,
        operation_id: str,
        request: Mapping[str, object],
        packet: PlanningPacket,
        targets: Sequence[tuple[str, bytes, int]],
        preimages: Mapping[str, bytes | None],
        skipped: Sequence[SkippedTaskEvent],
        feedback: dict[str, object] | None,
        result_kind: str,
        result_period: str,
    ) -> dict[str, object]:
        target_items = [
            self._file_item(relative, data, maximum)
            for relative, data, maximum in sorted(targets)
        ]
        preimage_items = [
            self._preimage_item(relative, preimages[relative], maximum)
            for relative, _data, maximum in sorted(targets)
        ]
        output_binding = {
            "targets": [
                {"relative": item["relative"], "sha256": item["sha256"]}
                for item in target_items
            ],
            "skipped_events": [_skip_payload(item) for item in skipped],
            "feedback_proposal": feedback,
        }
        evidence = {
            "schema_version": PLAN_MUTATION_SCHEMA_VERSION,
            "flow": "plan",
            "operation": operation,
            "operation_id": operation_id,
            "request": dict(request),
            "packet": json.loads(render_planning_packet(packet)),
            "targets": target_items,
            "preimages": preimage_items,
            "skipped_events": [_skip_payload(item) for item in skipped],
            "feedback_proposal": feedback,
            "result_kind": result_kind,
            "result_period": result_period,
            "output_sha256": _digest(_canonical(output_binding)),
        }
        raw = _canonical(evidence)
        parsed = _decode(raw, "plan replay evidence")
        assert isinstance(parsed, Mapping)
        self._validate_mutation_evidence(parsed)
        return dict(parsed)

    def _open_logs_tasks(self, root_fd: int) -> tuple[int, Path, tuple[int, int]]:
        try:
            path = self._resolver.resolve(
                "agent/logs/tasks", for_write=True, must_exist=False
            )
            relative = path.relative_to(self._vault_root).as_posix()
            fd = _open_dir_at(root_fd, relative, create=True)
            identity = _directory_identity(fd)
            actual = self._resolver.revalidate(
                path, "agent/logs/tasks", for_write=True, must_exist=True
            )
            named = os.stat(actual, follow_symlinks=False)
            if identity != (named.st_dev, named.st_ino):
                _fail("task log zone changed while opening")
            return fd, path, identity
        except (OSError, ValueError, VaultSchemaError, PlanFlowError):
            if "fd" in locals():
                os.close(fd)
            _fail("task log zone cannot be opened safely")

    def _revalidate_logs_tasks(
        self, fd: int, path: Path, identity: tuple[int, int]
    ) -> None:
        try:
            actual = self._resolver.revalidate(
                path, "agent/logs/tasks", for_write=True, must_exist=True
            )
            named = os.stat(actual, follow_symlinks=False)
        except (OSError, VaultSchemaError):
            _fail("task log zone changed during operation")
        if (
            _directory_identity(fd) != identity
            or (named.st_dev, named.st_ino) != identity
        ):
            _fail("task log zone changed during operation")

    def _publish_preimage(
        self,
        root_fd: int,
        operation: str,
        operation_id: str,
        preimages: object,
    ) -> str:
        if not isinstance(preimages, list):
            _fail("plan preimages are invalid")
        logs_fd, path, identity = self._open_logs_tasks(root_fd)
        preimages_fd: int | None = None
        try:
            preimages_fd = _open_dir_at(logs_fd, "preimages", create=True)
            token = hashlib.sha256(operation_id.encode("utf-8")).hexdigest()[:32]
            payload = {
                "schema_version": PLAN_PREIMAGE_SCHEMA_VERSION,
                "operation": operation,
                "operation_id": operation_id,
                "captured": preimages,
            }
            raw = _canonical(payload)
            _create_once_at(preimages_fd, f"{token}.json", raw, maximum=_MAX_JSON)
            self._revalidate_logs_tasks(logs_fd, path, identity)
            return f"agent/logs/tasks/preimages/{token}.json"
        finally:
            if preimages_fd is not None:
                os.close(preimages_fd)
            os.close(logs_fd)

    def _append_skipped(
        self, root_fd: int, payloads: object
    ) -> tuple[SkippedTaskEvent, ...]:
        if not isinstance(payloads, list):
            _fail("skipped task evidence is invalid")
        requested = tuple(_parse_skip(item) for item in payloads)
        if not requested:
            return ()
        logs_fd, path, identity = self._open_logs_tasks(root_fd)
        try:
            try:
                raw, file_identity = _read_at(logs_fd, "skipped.jsonl", _MAX_JSONL)
            except FileNotFoundError:
                raw = b""
                file_identity = None
            existing = _parse_skip_log(raw)
            by_id = {_portable_key(item.event_id): item for item in existing}
            additions: list[SkippedTaskEvent] = []
            for event in requested:
                prior = by_id.get(_portable_key(event.event_id))
                if prior is not None:
                    if _canonical(
                        _skip_payload(prior), maximum=_MAX_LINE
                    ) != _canonical(_skip_payload(event), maximum=_MAX_LINE):
                        _fail("skipped task replay conflicts with existing event")
                    continue
                additions.append(event)
                by_id[_portable_key(event.event_id)] = event
            if additions:
                target = raw + b"".join(
                    _canonical(_skip_payload(item), maximum=_MAX_LINE)
                    for item in additions
                )
                if len(target) > _MAX_JSONL:
                    _fail("skipped task trace would exceed its bound")
                _atomic_at(
                    logs_fd,
                    "skipped.jsonl",
                    target,
                    expected_identity=file_identity,
                    maximum=_MAX_JSONL,
                )
            self._revalidate_logs_tasks(logs_fd, path, identity)
            return requested
        finally:
            os.close(logs_fd)

    def _publish_feedback(self, root_fd: int, payload: object) -> str | None:
        checked = self._validate_feedback_payload(payload)
        if checked is None:
            return None
        review_fd, path, identity = self._open_configured(
            root_fd, "review", for_write=True
        )
        try:
            raw = _canonical(
                {key: value for key, value in checked.items() if key != "relative"}
            )
            relative = str(checked["relative"])
            _create_once_at(review_fd, relative, raw, maximum=_MAX_JSON)
            self._revalidate_configured(
                review_fd, path, identity, "review", for_write=True
            )
            return f"review/{relative}"
        finally:
            os.close(review_fd)

    def _apply_targets(
        self,
        tasks_fd: int,
        tasks_path: Path,
        tasks_identity: tuple[int, int],
        targets: object,
        preimages: object,
    ) -> None:
        self._validate_file_evidence(targets, preimages)
        assert isinstance(targets, list) and isinstance(preimages, list)
        old = {
            relative: data
            for relative, data, _maximum in (
                self._decode_file_item(item, preimage=True) for item in preimages
            )
        }
        publications: list[tuple[int, str, bytes | None, int, tuple[int, int]]] = []
        try:
            for item in targets:
                relative, target, maximum = self._decode_file_item(item, preimage=False)
                assert target is not None
                parent, name = _safe_parts(relative)
                directory_fd: int | None = _open_dir_at(tasks_fd, parent, create=True)
                try:
                    parent_identity = _directory_identity(directory_fd)
                    try:
                        current, current_identity = _read_at(
                            directory_fd, name, maximum
                        )
                    except FileNotFoundError:
                        current = None
                        current_identity = None
                    if current == target:
                        self._revalidate_configured(
                            tasks_fd,
                            tasks_path,
                            tasks_identity,
                            "tasks",
                            for_write=True,
                        )
                        self._revalidate_period_parent(
                            tasks_fd, directory_fd, parent, parent_identity
                        )
                        continue
                    if current != old[relative]:
                        _fail("plan target conflicts with its durable preimage")
                    self._before_task_replace(relative)
                    self._revalidate_configured(
                        tasks_fd,
                        tasks_path,
                        tasks_identity,
                        "tasks",
                        for_write=True,
                    )
                    self._revalidate_period_parent(
                        tasks_fd, directory_fd, parent, parent_identity
                    )
                    published_identity = _atomic_at(
                        directory_fd,
                        name,
                        target,
                        expected_identity=current_identity,
                        maximum=maximum,
                    )
                    publications.append(
                        (
                            directory_fd,
                            name,
                            old[relative],
                            maximum,
                            published_identity,
                        )
                    )
                    directory_fd = None
                    retained_fd = publications[-1][0]
                    self._revalidate_configured(
                        tasks_fd,
                        tasks_path,
                        tasks_identity,
                        "tasks",
                        for_write=True,
                    )
                    self._revalidate_period_parent(
                        tasks_fd, retained_fd, parent, parent_identity
                    )
                    self._after_task_replace(relative)
                    self._revalidate_configured(
                        tasks_fd,
                        tasks_path,
                        tasks_identity,
                        "tasks",
                        for_write=True,
                    )
                    self._revalidate_period_parent(
                        tasks_fd, retained_fd, parent, parent_identity
                    )
                finally:
                    if directory_fd is not None:
                        os.close(directory_fd)
            for item in targets:
                relative, target, maximum = self._decode_file_item(item, preimage=False)
                assert target is not None
                parent, name = _safe_parts(relative)
                self._revalidate_configured(
                    tasks_fd,
                    tasks_path,
                    tasks_identity,
                    "tasks",
                    for_write=True,
                )
                directory_fd = _open_dir_at(tasks_fd, parent)
                try:
                    parent_identity = _directory_identity(directory_fd)
                    actual, _ = _read_at(directory_fd, name, maximum)
                    if actual != target:
                        _fail("plan target verification failed")
                    self._revalidate_configured(
                        tasks_fd,
                        tasks_path,
                        tasks_identity,
                        "tasks",
                        for_write=True,
                    )
                    self._revalidate_period_parent(
                        tasks_fd, directory_fd, parent, parent_identity
                    )
                finally:
                    os.close(directory_fd)
        except BaseException:
            recovery_failed = False
            for directory_fd, name, preimage, maximum, published_identity in reversed(
                publications
            ):
                try:
                    if _identity_at(directory_fd, name) != published_identity:
                        recovery_failed = True
                        continue
                    if preimage is None:
                        os.unlink(name, dir_fd=directory_fd)
                        os.fsync(directory_fd)
                    else:
                        _atomic_at(
                            directory_fd,
                            name,
                            preimage,
                            expected_identity=published_identity,
                            maximum=maximum,
                        )
                except BaseException:
                    recovery_failed = True
            if recovery_failed:
                _fail("plan target recovery could not restore exact owned publications")
            raise
        finally:
            for directory_fd, _name, _old, _maximum, _identity in publications:
                os.close(directory_fd)

    def _commit_run(
        self,
        *,
        run_id: str,
        operation_id: str,
        request: Mapping[str, object],
        evidence: Mapping[str, object],
        artifact: PreparedArtifact,
        actions: Sequence[ActionCapability],
    ) -> None:
        step_id = (
            "plan-" + hashlib.sha256(operation_id.encode("utf-8")).hexdigest()[:32]
        )
        try:
            state = self._runs.commit_step(
                run_id,
                step_id=step_id,
                authority="domain-write",
                input_hash=_digest(_canonical(dict(request))),
                output_hash=str(evidence["output_sha256"]),
                next_phase="plan-committed",
                next_status="running",
                prepared_artifacts=(artifact,),
                action_uses=tuple(ActionUse(item) for item in actions),
                authority_policy=self._policy,
            )
        except RunError as error:
            raise PlanFlowError(str(error)) from None
        if state.get("status") != "running":
            _fail("plan flow must remain running for finalize")

    def _execute(
        self,
        capabilities: PlanCapabilities,
        *,
        run_id: str,
        operation_id: str,
        operation: str,
        request: Mapping[str, object],
        query_kind: str,
        query_period: str,
        build: Callable[[int, int, str, PlanningPacket], dict[str, object]],
    ) -> PlanMutationResult:
        if not isinstance(capabilities, PlanCapabilities):
            _fail("plan mutation requires PlanCapabilities")
        checked_run = self._check_run(run_id)
        checked_operation = _identifier(operation_id, "operation_id")
        task_grant = self._require(
            capabilities.collect_plan_context, "collect-plan-context"
        )
        project_grant = self._require(
            capabilities.read_plan_project_context, "read-plan-project-context"
        )
        entity_grant = self._require(
            capabilities.read_plan_entity_context, "read-plan-entity-context"
        )
        snapshot_grant = self._require(
            capabilities.snapshot_task_preimage, "snapshot-task-preimage"
        )
        extract_grant = self._require(
            capabilities.extract_feedback_markers, "extract-feedback-markers"
        )
        commit_grant = self._require(
            capabilities.commit_plan_or_rollover, "commit-plan-or-rollover"
        )
        run_grant = self._require(capabilities.record_run_state, "record-run-state")
        replayed = False
        with self._locked_tasks() as (root_fd, tasks_fd, tasks_path, tasks_identity):
            prior = self._load_evidence(root_fd, checked_run, checked_operation)
            if prior is None:
                now = self._now()
                packet = self._packet_at(
                    root_fd,
                    tasks_fd,
                    PlanContextQuery(
                        query_kind, query_period, now, _MAX_CONTEXT, _MAX_CONTEXT
                    ),
                    task_grant=task_grant,
                    project_grant=project_grant,
                    entity_grant=entity_grant,
                )
                evidence = build(root_fd, tasks_fd, now, packet)
                if (
                    evidence.get("operation") != operation
                    or evidence.get("operation_id") != checked_operation
                    or evidence.get("request") != dict(request)
                ):
                    _fail("plan mutation builder returned inconsistent evidence")
            else:
                if prior["operation"] != operation or prior["request"] != dict(request):
                    _fail("plan mutation replay conflicts with durable request")
                evidence = prior
                replayed = True
            raw = _canonical(evidence)
            feedback_payload = evidence["feedback_proposal"]
            feedback_grant: ActionCapability | None = None
            if feedback_payload is not None:
                feedback_grant = self._require(
                    capabilities.commit_feedback_proposal,
                    "commit-feedback-proposal",
                )
            try:
                artifact = self._runs.prepare_run_artifact(
                    checked_run,
                    name=self._evidence_stem(checked_operation),
                    data=raw,
                    maximum_bytes=_MAX_JSON,
                )
            except RunError as error:
                raise PlanFlowError(str(error)) from None
            self._require(snapshot_grant, "snapshot-task-preimage")
            self._publish_preimage(
                root_fd,
                operation,
                checked_operation,
                evidence["preimages"],
            )
            self._require(extract_grant, "extract-feedback-markers")
            feedback_ref = None
            if feedback_grant is not None:
                self._require(feedback_grant, "commit-feedback-proposal")
                feedback_ref = self._publish_feedback(root_fd, feedback_payload)
            self._require(commit_grant, "commit-plan-or-rollover")
            self._apply_targets(
                tasks_fd,
                tasks_path,
                tasks_identity,
                evidence["targets"],
                evidence["preimages"],
            )
            self._require(snapshot_grant, "snapshot-task-preimage")
            if evidence["skipped_events"]:
                self._before_skip_append()
            skipped = self._append_skipped(root_fd, evidence["skipped_events"])
            self._revalidate_configured(
                tasks_fd, tasks_path, tasks_identity, "tasks", for_write=True
            )
            actions: list[ActionCapability] = [
                task_grant,
                project_grant,
                entity_grant,
                snapshot_grant,
                extract_grant,
            ]
            if feedback_grant is not None:
                actions.append(feedback_grant)
            actions.extend((commit_grant, run_grant))
            self._commit_run(
                run_id=checked_run,
                operation_id=checked_operation,
                request=request,
                evidence=evidence,
                artifact=artifact,
                actions=actions,
            )
            self._after_run_commit()
            result_kind = str(evidence["result_kind"])
            result_period = str(evidence["result_period"])
            pair = self._read_pair_at(tasks_fd, result_kind, result_period)
            day_plan = pair.plan if isinstance(pair.plan, DayPlan) else None
            week_plan = pair.plan if isinstance(pair.plan, WeekPlan) else None
            return PlanMutationResult(
                checked_operation,
                operation,
                day_plan,
                week_plan,
                skipped,
                feedback_ref,
                str(evidence["output_sha256"]),
                replayed,
            )

    def _before_task_replace(self, relative: str) -> None:
        """Test seam after durable evidence and preimage, before one replace."""

    def _after_task_replace(self, relative: str) -> None:
        """Test seam after one task file replace, before the next effect."""

    def _before_skip_append(self) -> None:
        """Test seam after plan replacement, before skipped-trace append."""

    def _after_run_commit(self) -> None:
        """Test seam after recoverable RunStore commit."""

    @staticmethod
    def _expected_revision(value: int | None) -> int | None:
        if value is None:
            return None
        return _exact_int(value, "expected_revision", 1, 2**31 - 1)

    def commit_day(
        self,
        capabilities: PlanCapabilities,
        *,
        run_id: str,
        operation_id: str,
        period: str,
        tasks: tuple[PlanTask, ...],
        policy: PlanPolicy,
        expected_revision: int | None = None,
        status: str = "active",
    ) -> PlanMutationResult:
        checked_operation = _identifier(operation_id, "operation_id")
        checked_period = _date_text(period, "day period")
        checked_expected = self._expected_revision(expected_revision)
        _policy_payload(policy)
        checked_tasks = _validate_tasks(tasks, policy, day=checked_period, week=None)
        if not isinstance(status, str) or status not in {"active", "closed"}:
            _fail("commit-day status must be active or closed")
        request = {
            "schema_version": PLAN_MUTATION_SCHEMA_VERSION,
            "operation": "commit-day",
            "operation_id": checked_operation,
            "period": checked_period,
            "expected_revision": checked_expected,
            "status": status,
            "policy": _policy_payload(policy),
            "tasks": [_task_payload(item) for item in checked_tasks],
        }

        def build(
            _root_fd: int,
            tasks_fd: int,
            now: str,
            packet: PlanningPacket,
        ) -> dict[str, object]:
            pair = self._read_pair_at(tasks_fd, "day", checked_period)
            current = pair.plan
            if current is None:
                if checked_expected is not None:
                    _fail("day plan expected revision is stale")
                revision = 1
                created = now
                before_tasks: tuple[PlanTask, ...] = ()
            else:
                if not isinstance(current, DayPlan):
                    _fail("day plan has the wrong record kind")
                if current.status != "active":
                    _fail("terminal day plan cannot be replaced")
                if checked_expected is None or current.revision != checked_expected:
                    _fail("day plan expected revision is stale")
                revision = current.revision + 1
                created = current.created_at
                before_tasks = current.tasks
            self._validate_context_references(checked_tasks, packet)
            request_hash = _digest(_canonical(request))
            target = DayPlan(
                checked_period,
                status,
                revision,
                policy,
                checked_tasks,
                created,
                now,
                checked_operation,
                request_hash,
            )
            json_raw = render_day_plan(target)
            markdown_raw = render_day_markdown(target)
            skipped = self._skip_events(
                checked_operation,
                before_tasks,
                checked_tasks,
                target_date=None,
            )
            skipped_ids = {_portable_key(item.task_id) for item in skipped}
            feedback = self._feedback_proposal(
                checked_operation,
                tuple(
                    task
                    for task in checked_tasks
                    if _portable_key(task.task_id) in skipped_ids
                ),
                now,
            )
            targets = (
                (f"days/{checked_period}.json", json_raw, _MAX_JSON),
                (f"days/{checked_period}.md", markdown_raw, _MAX_MARKDOWN),
            )
            preimages = {
                f"days/{checked_period}.json": pair.json_raw,
                f"days/{checked_period}.md": pair.markdown_raw,
            }
            return self._make_evidence(
                operation="commit-day",
                operation_id=checked_operation,
                request=request,
                packet=packet,
                targets=targets,
                preimages=preimages,
                skipped=skipped,
                feedback=feedback,
                result_kind="day",
                result_period=checked_period,
            )

        return self._execute(
            capabilities,
            run_id=run_id,
            operation_id=checked_operation,
            operation="commit-day",
            request=request,
            query_kind="day",
            query_period=checked_period,
            build=build,
        )

    def commit_week(
        self,
        capabilities: PlanCapabilities,
        *,
        run_id: str,
        operation_id: str,
        week_start: str,
        tasks: tuple[PlanTask, ...],
        policy: PlanPolicy,
        expected_revision: int | None = None,
        status: str = "active",
    ) -> PlanMutationResult:
        checked_operation = _identifier(operation_id, "operation_id")
        checked_week = _week_start(week_start)
        checked_expected = self._expected_revision(expected_revision)
        _policy_payload(policy)
        checked_tasks = _validate_tasks(tasks, policy, day=None, week=checked_week)
        if not isinstance(status, str) or status not in {"active", "closed"}:
            _fail("commit-week status must be active or closed")
        request = {
            "schema_version": PLAN_MUTATION_SCHEMA_VERSION,
            "operation": "commit-week",
            "operation_id": checked_operation,
            "week_start": checked_week,
            "expected_revision": checked_expected,
            "status": status,
            "policy": _policy_payload(policy),
            "tasks": [_task_payload(item) for item in checked_tasks],
        }

        def build(
            _root_fd: int,
            tasks_fd: int,
            now: str,
            packet: PlanningPacket,
        ) -> dict[str, object]:
            pair = self._read_pair_at(tasks_fd, "week", checked_week)
            current = pair.plan
            if current is None:
                if checked_expected is not None:
                    _fail("week plan expected revision is stale")
                revision = 1
                created = now
                before_tasks: tuple[PlanTask, ...] = ()
            else:
                if not isinstance(current, WeekPlan):
                    _fail("week plan has the wrong record kind")
                if current.status != "active":
                    _fail("terminal week plan cannot be replaced")
                if checked_expected is None or current.revision != checked_expected:
                    _fail("week plan expected revision is stale")
                revision = current.revision + 1
                created = current.created_at
                before_tasks = current.tasks
            self._validate_context_references(checked_tasks, packet)
            request_hash = _digest(_canonical(request))
            target = WeekPlan(
                checked_week,
                status,
                revision,
                policy,
                checked_tasks,
                created,
                now,
                checked_operation,
                request_hash,
            )
            json_raw = render_week_plan(target)
            markdown_raw = render_week_markdown(target)
            skipped = self._skip_events(
                checked_operation,
                before_tasks,
                checked_tasks,
                target_date=None,
            )
            skipped_ids = {_portable_key(item.task_id) for item in skipped}
            feedback = self._feedback_proposal(
                checked_operation,
                tuple(
                    task
                    for task in checked_tasks
                    if _portable_key(task.task_id) in skipped_ids
                ),
                now,
            )
            targets = (
                (f"weeks/{checked_week}.json", json_raw, _MAX_JSON),
                (f"weeks/{checked_week}.md", markdown_raw, _MAX_MARKDOWN),
            )
            preimages = {
                f"weeks/{checked_week}.json": pair.json_raw,
                f"weeks/{checked_week}.md": pair.markdown_raw,
            }
            return self._make_evidence(
                operation="commit-week",
                operation_id=checked_operation,
                request=request,
                packet=packet,
                targets=targets,
                preimages=preimages,
                skipped=skipped,
                feedback=feedback,
                result_kind="week",
                result_period=checked_week,
            )

        return self._execute(
            capabilities,
            run_id=run_id,
            operation_id=checked_operation,
            operation="commit-week",
            request=request,
            query_kind="week",
            query_period=checked_week,
            build=build,
        )

    def skip_task(
        self,
        capabilities: PlanCapabilities,
        *,
        run_id: str,
        operation_id: str,
        period: str,
        task_id: str,
        expected_revision: int,
        reason: str,
        skipped_at: str,
        feedback: str | None = None,
    ) -> PlanMutationResult:
        checked_operation = _identifier(operation_id, "operation_id")
        checked_period = _date_text(period, "skip period")
        checked_task = _identifier(task_id, "skip task_id", _TASK_ID)
        checked_revision = _exact_int(
            expected_revision, "expected_revision", 1, 2**31 - 1
        )
        checked_reason = _text(reason, "skip reason", limit=4096)
        checked_at = _timestamp(skipped_at, "skipped_at")
        checked_feedback = (
            None if feedback is None else _text(feedback, "skip feedback", limit=4096)
        )
        request = {
            "schema_version": PLAN_MUTATION_SCHEMA_VERSION,
            "operation": "skip-task",
            "operation_id": checked_operation,
            "period": checked_period,
            "task_id": checked_task,
            "expected_revision": checked_revision,
            "reason": checked_reason,
            "skipped_at": checked_at,
            "feedback": checked_feedback,
        }

        def build(
            _root_fd: int,
            tasks_fd: int,
            now: str,
            packet: PlanningPacket,
        ) -> dict[str, object]:
            pair = self._read_pair_at(tasks_fd, "day", checked_period)
            if not isinstance(pair.plan, DayPlan):
                _fail("skip requires an existing day plan")
            current = pair.plan
            if current.status != "active" or current.revision != checked_revision:
                _fail("skip day plan precondition is stale")
            matches = [
                item
                for item in current.tasks
                if _portable_key(item.task_id) == _portable_key(checked_task)
            ]
            if len(matches) != 1 or matches[0].status != "open":
                _fail("skip requires one open task")
            target_task = replace(
                matches[0],
                status="skipped",
                skipped_at=checked_at,
                feedback=checked_feedback,
            )
            target_tasks = tuple(
                sorted(
                    (
                        target_task
                        if _portable_key(item.task_id) == _portable_key(checked_task)
                        else item
                        for item in current.tasks
                    ),
                    key=lambda item: _portable_key(item.task_id),
                )
            )
            _validate_tasks(target_tasks, current.policy, day=checked_period, week=None)
            self._validate_context_references(target_tasks, packet)
            target = DayPlan(
                checked_period,
                "active",
                current.revision + 1,
                current.policy,
                target_tasks,
                current.created_at,
                now,
                checked_operation,
                _digest(_canonical(request)),
            )
            skipped = self._skip_events(
                checked_operation,
                current.tasks,
                target_tasks,
                target_date=None,
            )
            if len(skipped) != 1:
                _fail("skip mutation did not produce exactly one trace event")
            event = replace(skipped[0], reason=checked_reason)
            feedback_payload = self._feedback_proposal(
                checked_operation, (target_task,), now
            )
            json_raw = render_day_plan(target)
            markdown_raw = render_day_markdown(target)
            targets = (
                (f"days/{checked_period}.json", json_raw, _MAX_JSON),
                (f"days/{checked_period}.md", markdown_raw, _MAX_MARKDOWN),
            )
            preimages = {
                f"days/{checked_period}.json": pair.json_raw,
                f"days/{checked_period}.md": pair.markdown_raw,
            }
            return self._make_evidence(
                operation="skip-task",
                operation_id=checked_operation,
                request=request,
                packet=packet,
                targets=targets,
                preimages=preimages,
                skipped=(event,),
                feedback=feedback_payload,
                result_kind="day",
                result_period=checked_period,
            )

        return self._execute(
            capabilities,
            run_id=run_id,
            operation_id=checked_operation,
            operation="skip-task",
            request=request,
            query_kind="day",
            query_period=checked_period,
            build=build,
        )

    def rollover_day(
        self,
        capabilities: PlanCapabilities,
        *,
        run_id: str,
        operation_id: str,
        source_date: str,
        target_date: str,
        expected_revision: int,
        policy: PlanPolicy | None = None,
    ) -> PlanMutationResult:
        checked_operation = _identifier(operation_id, "operation_id")
        checked_source = _date_text(source_date, "rollover source_date")
        checked_target = _date_text(target_date, "rollover target_date")
        if date.fromisoformat(checked_target) <= date.fromisoformat(checked_source):
            _fail("rollover target_date must follow source_date")
        checked_revision = _exact_int(
            expected_revision, "expected_revision", 1, 2**31 - 1
        )
        if policy is not None:
            _policy_payload(policy)
        request = {
            "schema_version": PLAN_MUTATION_SCHEMA_VERSION,
            "operation": "rollover-day",
            "operation_id": checked_operation,
            "source_date": checked_source,
            "target_date": checked_target,
            "expected_revision": checked_revision,
            "policy": None if policy is None else _policy_payload(policy),
        }

        def build(
            _root_fd: int,
            tasks_fd: int,
            now: str,
            packet: PlanningPacket,
        ) -> dict[str, object]:
            source_pair = self._read_pair_at(tasks_fd, "day", checked_source)
            target_pair = self._read_pair_at(tasks_fd, "day", checked_target)
            if not isinstance(source_pair.plan, DayPlan):
                _fail("rollover source day does not exist")
            source = source_pair.plan
            if source.status != "active" or source.revision != checked_revision:
                _fail("rollover source precondition is stale")
            if target_pair.plan is not None:
                _fail("rollover target day already exists")
            target_policy = source.policy if policy is None else policy
            carried = tuple(
                sorted(
                    (
                        replace(
                            task,
                            scheduled_for=checked_target,
                            rollover_count=task.rollover_count + 1,
                        )
                        for task in source.tasks
                        if task.status == "open"
                    ),
                    key=lambda item: _portable_key(item.task_id),
                )
            )
            source_tasks = tuple(
                replace(task, status="rolled-over") if task.status == "open" else task
                for task in source.tasks
            )
            _validate_tasks(carried, target_policy, day=checked_target, week=None)
            _validate_tasks(source_tasks, source.policy, day=checked_source, week=None)
            self._validate_context_references(carried, packet)
            request_hash = _digest(_canonical(request))
            source_target = DayPlan(
                checked_source,
                "rolled-over",
                source.revision + 1,
                source.policy,
                source_tasks,
                source.created_at,
                now,
                checked_operation,
                request_hash,
            )
            new_target = DayPlan(
                checked_target,
                "active",
                1,
                target_policy,
                carried,
                now,
                now,
                checked_operation,
                request_hash,
            )
            targets = (
                (
                    f"days/{checked_source}.json",
                    render_day_plan(source_target),
                    _MAX_JSON,
                ),
                (
                    f"days/{checked_source}.md",
                    render_day_markdown(source_target),
                    _MAX_MARKDOWN,
                ),
                (
                    f"days/{checked_target}.json",
                    render_day_plan(new_target),
                    _MAX_JSON,
                ),
                (
                    f"days/{checked_target}.md",
                    render_day_markdown(new_target),
                    _MAX_MARKDOWN,
                ),
            )
            preimages = {
                f"days/{checked_source}.json": source_pair.json_raw,
                f"days/{checked_source}.md": source_pair.markdown_raw,
                f"days/{checked_target}.json": target_pair.json_raw,
                f"days/{checked_target}.md": target_pair.markdown_raw,
            }
            return self._make_evidence(
                operation="rollover-day",
                operation_id=checked_operation,
                request=request,
                packet=packet,
                targets=targets,
                preimages=preimages,
                skipped=(),
                feedback=None,
                result_kind="day",
                result_period=checked_target,
            )

        return self._execute(
            capabilities,
            run_id=run_id,
            operation_id=checked_operation,
            operation="rollover-day",
            request=request,
            query_kind="day",
            query_period=checked_target,
            build=build,
        )
