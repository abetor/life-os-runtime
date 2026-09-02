"""Runtime capability checks backed by the exact P0-06 action matrix.

Task packets are untrusted data.  They may request an action, but only a
capability issued independently by deterministic routing can authorize it.
Both objects are checked against the canonical matrix on every use.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Mapping
import unicodedata

from tool_life_os_runtime.failure_authority import (
    FailureAuthorityError,
    authorize_action,
    canonical_matrix,
    validate_matrix,
)


AUTHORITY_SCHEMA_VERSION = 1
_PACKET_KEYS = frozenset(
    {
        "schema_version",
        "flow_id",
        "action_id",
        "actor",
        "authority",
        "target",
        "payload",
    }
)
_SECRET_KEYS = (
    "api_key",
    "authorization",
    "chat_id",
    "cookie",
    "credential",
    "password",
    "secret",
    "token",
)
_PRIVATE_MARKERS = ("/" + "Users" + "/", "/" + "home" + "/", "file:")
_MAX_PACKET_BYTES = 64 * 1024


class AuthorityError(ValueError):
    """An action or untrusted task packet exceeds its exact capability."""


def _fail(message: str) -> None:
    raise AuthorityError(message)


def _has_control(value: str) -> bool:
    return any(
        unicodedata.category(character).startswith("C")
        or unicodedata.category(character) in {"Zl", "Zp"}
        for character in value
    )


def _text(value: object, label: str, *, limit: int = 4096) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > limit
        or value.strip() != value
        or _has_control(value)
        or any(marker in value for marker in _PRIVATE_MARKERS)
    ):
        _fail(f"{label} must be bounded privacy-safe text")
    return value


def _safe_json(value: object, label: str, *, depth: int = 0) -> object:
    if depth > 8:
        _fail(f"{label} is too deeply nested")
    if value is None or isinstance(value, bool) or type(value) in {int, float}:
        return value
    if isinstance(value, str):
        if (
            len(value.encode("utf-8")) > 8192
            or _has_control(value)
            or any(marker in value for marker in _PRIVATE_MARKERS)
        ):
            _fail(f"{label} contains unsafe text")
        return value
    if isinstance(value, list):
        if len(value) > 128:
            _fail(f"{label} has too many items")
        return [
            _safe_json(item, f"{label} item", depth=depth + 1) for item in value
        ]
    if isinstance(value, Mapping):
        if len(value) > 128:
            _fail(f"{label} has too many fields")
        checked: dict[str, object] = {}
        for key, item in value.items():
            checked_key = _text(key, f"{label} key", limit=128)
            if any(marker in checked_key.lower() for marker in _SECRET_KEYS):
                _fail(f"{label} contains a forbidden secret field")
            checked[checked_key] = _safe_json(
                item, f"{label}.{checked_key}", depth=depth + 1
            )
        return checked
    _fail(f"{label} contains a non-JSON value")


def _canonical_bytes(value: Mapping[str, object]) -> bytes:
    try:
        raw = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError):
        _fail("authority payload is not canonical JSON")
    if len(raw) > _MAX_PACKET_BYTES:
        _fail("authority payload is too large")
    return raw


@dataclass(frozen=True)
class ActionCapability:
    """One exact action grant derived from the canonical P0-06 matrix."""

    schema_version: int
    flow_id: str
    action_id: str
    actor: str
    authority: str
    target: str
    access: str
    effect_kind: str
    artifact_commit: bool
    matrix_sha256: str


class AuthorityPolicy:
    """Issue and revalidate exact per-action capabilities."""

    def __init__(self) -> None:
        matrix = canonical_matrix()
        validate_matrix(matrix)
        self._matrix = matrix
        self._matrix_sha256 = hashlib.sha256(_canonical_bytes(matrix)).hexdigest()
        self._issued: dict[int, ActionCapability] = {}

    @property
    def matrix_sha256(self) -> str:
        return self._matrix_sha256

    def issue(
        self,
        *,
        flow_id: str,
        action_id: str,
        actor: str,
        authority: str,
        target: str,
    ) -> ActionCapability:
        """Issue only when actor, authority, and target match one exact action."""

        try:
            action = authorize_action(
                self._matrix,
                flow_id=_text(flow_id, "flow_id", limit=128),
                action_id=_text(action_id, "action_id", limit=128),
                actor=_text(actor, "actor", limit=128),
                authority=_text(authority, "authority", limit=128),
                target=_text(target, "target", limit=256),
            )
        except FailureAuthorityError as error:
            raise AuthorityError(str(error)) from None
        capability = ActionCapability(
            schema_version=AUTHORITY_SCHEMA_VERSION,
            flow_id=flow_id,
            action_id=action_id,
            actor=actor,
            authority=authority,
            target=target,
            access=str(action["access"]),
            effect_kind=str(action["effect_kind"]),
            artifact_commit=bool(action["artifact_commit"]),
            matrix_sha256=self._matrix_sha256,
        )
        self._issued[id(capability)] = capability
        return capability

    def require(self, capability: ActionCapability) -> ActionCapability:
        """Reject fabricated, stale, or field-mutated capability objects."""

        if not isinstance(capability, ActionCapability):
            _fail("action requires an ActionCapability")
        if self._issued.get(id(capability)) is not capability:
            _fail("capability was not issued by this authority policy")
        if (
            type(capability.schema_version) is not int
            or capability.schema_version != AUTHORITY_SCHEMA_VERSION
            or capability.matrix_sha256 != self._matrix_sha256
        ):
            _fail("capability schema or matrix binding is invalid")
        try:
            action = authorize_action(
                self._matrix,
                flow_id=capability.flow_id,
                action_id=capability.action_id,
                actor=capability.actor,
                authority=capability.authority,
                target=capability.target,
            )
        except FailureAuthorityError as error:
            raise AuthorityError(str(error)) from None
        canonical_fields = (
            str(action["access"]),
            str(action["effect_kind"]),
            bool(action["artifact_commit"]),
        )
        if canonical_fields != (
            capability.access,
            capability.effect_kind,
            capability.artifact_commit,
        ):
            _fail("capability fields do not match the canonical action")
        return capability


def authorize_task_packet(
    packet: Mapping[str, object],
    capability: ActionCapability,
    *,
    policy: AuthorityPolicy,
) -> dict[str, object]:
    """Validate an untrusted packet without allowing it to raise authority."""

    if not isinstance(policy, AuthorityPolicy):
        _fail("task packet requires its issuing authority policy")
    grant = policy.require(capability)
    if not isinstance(packet, Mapping) or set(packet) != _PACKET_KEYS:
        _fail("task packet has missing or unknown fields")
    if (
        type(packet["schema_version"]) is not int
        or packet["schema_version"] != AUTHORITY_SCHEMA_VERSION
    ):
        _fail("unsupported task packet schema_version")
    requested = {
        "flow_id": _text(packet["flow_id"], "packet.flow_id", limit=128),
        "action_id": _text(packet["action_id"], "packet.action_id", limit=128),
        "actor": _text(packet["actor"], "packet.actor", limit=128),
        "authority": _text(packet["authority"], "packet.authority", limit=128),
        "target": _text(packet["target"], "packet.target", limit=256),
    }
    for field, actual in requested.items():
        if actual != getattr(grant, field):
            _fail(f"task packet {field} exceeds or disagrees with capability")
    payload = _safe_json(packet["payload"], "task packet payload")
    if not isinstance(payload, dict):
        _fail("task packet payload must be an object")
    checked = dict(packet)
    checked["payload"] = payload
    _canonical_bytes(checked)
    return checked
