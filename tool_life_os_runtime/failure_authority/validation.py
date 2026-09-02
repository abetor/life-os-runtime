"""Fail-closed validation and action authorization for the P0 matrix."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from .catalog import (
    REQUIRED_ACTION_IDS,
    REQUIRED_ACTION_TARGETS,
    REQUIRED_FLOW_IDS,
    SCHEMA_VERSION,
)
from .registry import (
    ACTION_SECURITY_FIELDS,
    FLOW_SECURITY_FIELDS,
    REQUIRED_ACTION_SECURITY_DIGESTS,
    REQUIRED_FLOW_SECURITY_DIGESTS,
)


class FailureAuthorityError(ValueError):
    """The matrix or requested action violates the declared contract."""


EVAL_CLASSES = frozenset({"objective", "bounded-subjective", "owner-judgment"})
AUTHORITIES = (
    "read",
    "internal-write",
    "proposal",
    "domain-write",
    "protected-write",
    "external-send",
    "destructive",
)
_AUTHORITY_RANK = {name: rank for rank, name in enumerate(AUTHORITIES)}
ACCESS_CLASSES = frozenset({"read", "write", "invoke"})
RETRY_OWNERS = frozenset({"runtime", "scheduler", "gateway", "human", "none"})
_PRIVATE_HOME_MARKERS = ("/" + "Users" + "/", "/" + "home" + "/")
ACTORS = frozenset(
    {
        "runtime",
        "runtime-human-approved",
        "runtime-human-confirmed",
        "human",
        "system",
        "scheduler",
        "gateway",
    }
)
EFFECT_KINDS = frozenset(
    {
        "read-only",
        "artifact-commit",
        "run-state-commit",
        "proposal-commit",
        "protected-artifact-commit",
        "append-only-log",
        "append-only-domain-event",
        "outbox-artifact-commit",
        "append-only-trace",
        "bounded-metrics-commit",
        "done-event-append",
        "trail-append",
        "review-finalization-commit",
        "task-snapshot-commit",
        "connector-call",
        "scheduler-connector-invocation",
        "scheduler-execution",
        "gateway-transport",
        "gateway-connector-invocation",
        "gateway-receipt-commit",
        "gateway-receipt-reconciliation",
    }
)
_FLOW_KEYS = frozenset(
    {
        "flow_id", "actor", "eval_class", "authority_ceiling", "allowed_reads",
        "allowed_writes", "allowed_invocations", "irreversible_effects",
        "crash_points", "retry_owner", "rollback", "actions",
    }
)
_ACTION_KEYS = frozenset(
    {
        "action_id", "actor", "authority", "target", "access", "effect_kind",
        "artifact_commit", "irreversible", "crash_points", "retry_owner", "rollback",
    }
)


def _fail(message: str) -> None:
    raise FailureAuthorityError(message)


def _plain_string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or value.strip() != value:
        _fail(f"{label} must be a non-empty canonical string")
    if (
        value.startswith(("/", "~"))
        or "\\" in value
        or any(marker in value for marker in _PRIVATE_HOME_MARKERS)
        or value.startswith("file:")
    ):
        _fail(f"{label} contains a private or absolute path")
    return value


def authority_at_most(authority: str, ceiling: str) -> bool:
    """Compare two authorities using the one canonical P0 total order."""

    if (
        not isinstance(authority, str)
        or not isinstance(ceiling, str)
        or authority not in _AUTHORITY_RANK
        or ceiling not in _AUTHORITY_RANK
    ):
        _fail("unknown authority rank")
    return _AUTHORITY_RANK[authority] <= _AUTHORITY_RANK[ceiling]


def _string_list(value: object, label: str, *, nonempty: bool = False) -> list[str]:
    if not isinstance(value, list):
        _fail(f"{label} must be a list")
    result = [_plain_string(item, f"{label} item") for item in value]
    if nonempty and not result:
        _fail(f"{label} must not be empty")
    if result != sorted(set(result)):
        _fail(f"{label} must be sorted and unique")
    return result


def validate_matrix(payload: Mapping[str, Any]) -> None:
    """Validate the complete matrix, including semantic authority invariants."""

    if not isinstance(payload, Mapping):
        _fail("matrix must be an object")
    if (
        set(REQUIRED_ACTION_TARGETS) != REQUIRED_FLOW_IDS
        or set(REQUIRED_ACTION_SECURITY_DIGESTS) != REQUIRED_FLOW_IDS
        or set(REQUIRED_FLOW_SECURITY_DIGESTS) != REQUIRED_FLOW_IDS
    ):
        _fail("internal action registry does not match required flows")
    if set(payload) != {"schema_version", "flow_inventory", "flows"}:
        _fail("matrix has missing or unknown top-level fields")
    if type(payload["schema_version"]) is not int or payload["schema_version"] != SCHEMA_VERSION:
        _fail("unsupported matrix schema_version")
    inventory = _string_list(payload["flow_inventory"], "flow_inventory", nonempty=True)
    if set(inventory) != REQUIRED_FLOW_IDS:
        _fail("flow_inventory does not match the required target flow set")
    flows = payload["flows"]
    if not isinstance(flows, list):
        _fail("flows must be a list")
    flow_ids: list[str] = []
    for flow in flows:
        if not isinstance(flow, Mapping) or set(flow) != _FLOW_KEYS:
            _fail("flow has missing or unknown fields")
        flow_id = _plain_string(flow["flow_id"], "flow_id")
        flow_ids.append(flow_id)
        if flow["actor"] not in ACTORS:
            _fail(f"{flow_id} has invalid actor")
        if flow["eval_class"] not in EVAL_CLASSES:
            _fail(f"{flow_id} has no valid eval class")
        ceiling = flow["authority_ceiling"]
        if ceiling not in _AUTHORITY_RANK or ceiling == "destructive":
            _fail(f"{flow_id} has invalid authority ceiling")
        reads = _string_list(flow["allowed_reads"], f"{flow_id}.allowed_reads")
        writes = _string_list(flow["allowed_writes"], f"{flow_id}.allowed_writes")
        invokes = _string_list(flow["allowed_invocations"], f"{flow_id}.allowed_invocations")
        crash_points = _string_list(flow["crash_points"], f"{flow_id}.crash_points", nonempty=True)
        irreversible = _string_list(flow["irreversible_effects"], f"{flow_id}.irreversible_effects")
        if flow["retry_owner"] not in RETRY_OWNERS:
            _fail(f"{flow_id} has invalid retry owner")
        _plain_string(flow["rollback"], f"{flow_id}.rollback")
        for zone in writes:
            if zone.startswith(("legacy:", "migration:legacy")):
                _fail(f"{flow_id} attempts a legacy write")
        actions = flow["actions"]
        if not isinstance(actions, list) or not actions:
            _fail(f"{flow_id} has no actions")
        action_ids: list[str] = []
        derived_writes: set[str] = set()
        derived_invokes: set[str] = set()
        derived_reads: set[str] = set()
        derived_crash_points: set[str] = set()
        derived_irreversible: set[str] = set()
        for action in actions:
            if not isinstance(action, Mapping) or set(action) != _ACTION_KEYS:
                _fail(f"{flow_id} action has missing or unknown fields")
            action_id = _plain_string(action["action_id"], f"{flow_id}.action_id")
            action_ids.append(action_id)
            if action["actor"] not in ACTORS:
                _fail(f"{flow_id}/{action_id} has invalid actor")
            authority = action["authority"]
            if authority not in _AUTHORITY_RANK or authority == "destructive":
                _fail(f"{flow_id}/{action_id} has invalid authority")
            if not authority_at_most(authority, ceiling):
                _fail(f"{flow_id}/{action_id} exceeds flow authority ceiling")
            target = _plain_string(action["target"], f"{flow_id}/{action_id}.target")
            access = action["access"]
            if access not in ACCESS_CLASSES:
                _fail(f"{flow_id}/{action_id} has invalid access")
            if access == "read" and authority != "read":
                _fail(f"{flow_id}/{action_id} read action has non-read authority")
            if access == "write" and authority in {"read", "external-send"}:
                _fail(f"{flow_id}/{action_id} write action has invalid authority")
            if access == "read" and target not in reads:
                _fail(f"{flow_id}/{action_id} reads an undeclared target")
            if access == "read":
                derived_reads.add(target)
            if access == "write":
                derived_writes.add(target)
            if access == "invoke":
                derived_invokes.add(target)
            if target.startswith(("legacy:", "migration:legacy")) and access != "read":
                _fail(f"{flow_id}/{action_id} attempts a legacy mutation")
            if target == "vault:knowledge":
                if access == "write" and not (
                    flow_id == "apply" and authority == "protected-write"
                ):
                    _fail("knowledge write is not protected apply")
                if access != "read" and authority != "protected-write":
                    _fail("knowledge target requires protected-write")
            if authority == "protected-write" and target != "vault:knowledge":
                _fail(f"{flow_id}/{action_id} misuses protected-write")
            if authority == "external-send" and not (
                (flow_id == "gateway-delivery" and action["effect_kind"] == "gateway-connector-invocation")
                or (flow_id == "gateway-transport" and action["effect_kind"] == "gateway-transport")
            ):
                _fail("external-send is outside the gateway transport boundary")
            if action["effect_kind"] in {"gateway-transport", "scheduler-execution"} and action["artifact_commit"]:
                _fail("transport or scheduler execution is mixed with artifact commit")
            if action["artifact_commit"] and access != "write":
                _fail(f"{flow_id}/{action_id} marks a non-write as artifact commit")
            if not isinstance(action["irreversible"], bool):
                _fail(f"{flow_id}/{action_id}.irreversible must be boolean")
            action_crashes = _string_list(action["crash_points"], f"{flow_id}/{action_id}.crash_points", nonempty=True)
            derived_crash_points.update(action_crashes)
            if action["retry_owner"] not in RETRY_OWNERS:
                _fail(f"{flow_id}/{action_id} has invalid retry owner")
            _plain_string(action["rollback"], f"{flow_id}/{action_id}.rollback")
            if action["effect_kind"] not in EFFECT_KINDS:
                _fail(f"{flow_id}/{action_id} has invalid effect kind")
            if action["irreversible"]:
                derived_irreversible.add(f"{flow_id}/{action_id}")
        if len(action_ids) != len(set(action_ids)):
            _fail(f"{flow_id} has duplicate action IDs")
        if set(action_ids) != REQUIRED_ACTION_IDS[flow_id]:
            _fail(f"{flow_id} actions do not match the required action set")
        if action_ids != list(REQUIRED_ACTION_TARGETS[flow_id]):
            _fail(f"{flow_id} actions are not in canonical execution order")
        actual_targets = {
            action["action_id"]: (action["access"], action["target"])
            for action in actions
        }
        if actual_targets != REQUIRED_ACTION_TARGETS[flow_id]:
            _fail(f"{flow_id} actions do not match the required target registry")
        actual_security_digests = {
            action["action_id"]: hashlib.sha256(
                json.dumps(
                    {field: action[field] for field in ACTION_SECURITY_FIELDS},
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest()
            for action in actions
        }
        if actual_security_digests != REQUIRED_ACTION_SECURITY_DIGESTS[flow_id]:
            _fail(f"{flow_id} actions do not match the exact security registry")
        if reads != sorted(derived_reads):
            _fail(f"{flow_id}.allowed_reads does not match read action targets")
        if writes != sorted(derived_writes):
            _fail(f"{flow_id}.allowed_writes does not match action targets")
        if invokes != sorted(derived_invokes):
            _fail(f"{flow_id}.allowed_invocations does not match action targets")
        if crash_points != sorted(derived_crash_points):
            _fail(f"{flow_id}.crash_points does not match action crash points")
        if irreversible != sorted(derived_irreversible):
            _fail(f"{flow_id}.irreversible_effects does not match actions")
        if flow_id in {"ambient", "bundle"} and (
            flow["actor"] != "system" or {action["actor"] for action in actions} != {"system"}
        ):
            _fail(f"{flow_id} scheduled actions must use the system actor")
        if flow_id == "scheduler-execution":
            if {action["actor"] for action in actions} != {"scheduler"}:
                _fail("scheduler execution actions must use the scheduler actor")
            if {action["retry_owner"] for action in actions} != {"scheduler"}:
                _fail("scheduler execution retry owner must be scheduler")
            invoke = next(action for action in actions if action["action_id"] == "invoke-runtime-flow")
            if invoke["authority"] != "internal-write":
                _fail("scheduler runtime invocation requires internal-write authority")
        if flow_id == "gateway-delivery":
            if {action["actor"] for action in actions} != {"runtime"}:
                _fail("gateway connector actions must use the runtime actor")
            if {action["retry_owner"] for action in actions} != {"runtime"}:
                _fail("gateway connector retry owner must be runtime")
        if flow_id == "gateway-transport":
            if {action["actor"] for action in actions} != {"gateway"}:
                _fail("gateway transport actions must use the gateway actor")
            if {action["retry_owner"] for action in actions} != {"gateway"}:
                _fail("gateway transport retry owner must be gateway")
        flow_security = {field: flow[field] for field in FLOW_SECURITY_FIELDS}
        flow_digest = hashlib.sha256(
            json.dumps(
                flow_security,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        if flow_digest != REQUIRED_FLOW_SECURITY_DIGESTS[flow_id]:
            _fail(f"{flow_id} does not match the exact flow security registry")
    if flow_ids != sorted(flow_ids) or len(flow_ids) != len(set(flow_ids)):
        _fail("flows must be sorted with unique IDs")
    if set(flow_ids) != REQUIRED_FLOW_IDS:
        _fail("flows do not match the required target flow set")


def load_matrix(path: Path) -> dict[str, Any]:
    """Load a UTF-8 JSON matrix and validate it before returning data."""

    try:
        payload = json.loads(path.read_text("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise FailureAuthorityError("matrix is not readable canonical JSON") from exc
    if not isinstance(payload, dict):
        _fail("matrix must be an object")
    validate_matrix(payload)
    return payload


def authorize_action(
    payload: Mapping[str, Any],
    *,
    flow_id: str,
    action_id: str,
    actor: str,
    authority: str,
    target: str,
) -> Mapping[str, Any]:
    """Return the exact declared action or fail closed on any mismatch."""

    validate_matrix(payload)
    flow = next((item for item in payload["flows"] if item["flow_id"] == flow_id), None)
    if flow is None:
        _fail("unknown flow")
    action = next((item for item in flow["actions"] if item["action_id"] == action_id), None)
    if action is None:
        _fail("unknown action")
    requested = {"actor": actor, "authority": authority, "target": target}
    for field, actual in requested.items():
        if action[field] != actual:
            _fail(f"action {field} mismatch")
    return action
