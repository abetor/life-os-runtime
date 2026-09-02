"""Deterministic batched digest flow over a closed source window."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hashlib
import os
from pathlib import PurePosixPath
import re
import stat
from typing import Callable, Mapping, Protocol, Sequence

from tool_life_os_runtime.ext.flows.ambient.flow import (
    AmbientFlow,
    AmbientFlowError,
    _canonical as _ambient_canonical,
    _decode as _ambient_decode,
    _hash as _ambient_hash,
    _identifier as _ambient_identifier,
    _instant as _ambient_instant,
    _mapping as _ambient_mapping,
    _portable as _ambient_portable,
    _run_id as _ambient_run_id,
    _safe_ref as _ambient_safe_ref,
    _text as _ambient_text,
    _timestamp as _ambient_timestamp,
)
from tool_life_os_runtime.ext.flows.memory import MemoryFlowError, parse_memory_proposal
from tool_life_os_runtime.ext.review.artifact import (
    ReviewArtifactError,
    parse_review_artifact,
)
from tool_life_os_runtime.ext.review.authority import (
    ActionCapability,
    AuthorityError,
    AuthorityPolicy,
)
from tool_life_os_runtime.ext.runs import (
    ActionUse,
    CommittedArtifact,
    OutboxError,
    OutboxStore,
    PreparedArtifact,
    RunError,
    RunStore,
    validate_event,
    validate_receipt,
)
from tool_life_os_runtime.ext.vault.schema import VaultPathResolver


BUNDLE_SCHEMA_VERSION = 1
_MAX_JSON = 4 * 1024 * 1024
_MAX_EVIDENCE = 1024 * 1024
_MAX_FILES = 1024
_MAX_ITEMS = 512
_MAX_TOTAL = 8 * 1024 * 1024
_PRIORITIES = ("low", "medium", "high", "critical")
_RECEIPT_ID = re.compile(r"^receipt_[0-9a-f]{56}$")


class BundleFlowError(ValueError):
    """Bundle request, evidence, or source snapshot is unsafe."""


def _fail(message: str) -> None:
    raise BundleFlowError(message)


def _wrap(callable_value, *args, **kwargs):
    try:
        return callable_value(*args, **kwargs)
    except AmbientFlowError as error:
        raise BundleFlowError(str(error).replace("ambient", "bundle")) from None


def _canonical(payload: Mapping[str, object], *, maximum: int = _MAX_JSON) -> bytes:
    return _wrap(_ambient_canonical, payload, maximum=maximum)


def _decode(raw: bytes, label: str, *, maximum: int = _MAX_JSON) -> object:
    return _wrap(_ambient_decode, raw, label, maximum=maximum)


def _mapping(
    value: object, label: str, keys: set[str] | frozenset[str]
) -> Mapping[str, object]:
    return _wrap(_ambient_mapping, value, label, keys)


def _text(value: object, label: str, *, limit: int = 4096) -> str:
    return _wrap(_ambient_text, value, label, limit=limit)


def _identifier(value: object, label: str) -> str:
    return _wrap(_ambient_identifier, value, label)


def _run_id(value: object) -> str:
    return _wrap(_ambient_run_id, value)


def _hash(value: object, label: str) -> str:
    return _wrap(_ambient_hash, value, label)


def _timestamp(value: object, label: str) -> str:
    return _wrap(_ambient_timestamp, value, label)


def _instant(value: str):
    return _ambient_instant(value)


def _safe_ref(value: object, label: str) -> str:
    return _wrap(_ambient_safe_ref, value, label)


def _portable(value: str) -> str:
    return _ambient_portable(value)


@dataclass(frozen=True)
class BundleWindow:
    start: str
    end: str
    schema_version: int = BUNDLE_SCHEMA_VERSION


@dataclass(frozen=True)
class BundleRequest:
    operation_id: str
    observed_at: str
    window: BundleWindow
    schema_version: int = BUNDLE_SCHEMA_VERSION


@dataclass(frozen=True)
class BundleItem:
    kind: str
    source_id: str
    source_ref: str
    source_sha256: str
    created_at: str
    priority: str
    expires_at: str | None = None
    supersedes: str | None = None
    schema_version: int = BUNDLE_SCHEMA_VERSION


@dataclass(frozen=True)
class BundleManifest:
    window: BundleWindow
    items: tuple[BundleItem, ...]
    batch_digest: str
    schema_version: int = BUNDLE_SCHEMA_VERSION


@dataclass(frozen=True)
class BundleCapabilities:
    collect_batched_items: ActionCapability
    read_pending_outbox: ActionCapability
    commit_bundle_outbox_event: ActionCapability
    record_run_state: ActionCapability


class BundleReceiptVerificationPort(Protocol):
    """Trust boundary for independently committed gateway receipt evidence."""

    def verify_delivered(
        self,
        *,
        receipt: Mapping[str, object],
        receipt_raw: bytes,
        event: Mapping[str, object],
        event_raw: bytes,
    ) -> bool: ...


@dataclass(frozen=True)
class BundleCrashHooks:
    after_source_read: Callable[[], None] | None = None
    after_payload_prepare: Callable[[], None] | None = None
    after_event_publish: Callable[[], None] | None = None
    after_evidence_prepare: Callable[[], None] | None = None
    after_run_intent: Callable[[], None] | None = None
    after_run_state: Callable[[], None] | None = None
    after_run_trace: Callable[[], None] | None = None


@dataclass(frozen=True)
class BundleRunEvidence:
    run_id: str
    operation_id: str
    request_sha256: str
    run_state_sha256: str
    outcome: str
    item_count: int
    batch_digest: str
    marker_ref: str | None
    marker_sha256: str | None
    payload_ref: str | None
    payload_sha256: str | None
    event_ref: str | None
    event_sha256: str | None
    event_id: str | None
    schema_version: int = BUNDLE_SCHEMA_VERSION


@dataclass(frozen=True)
class BundleResult:
    outcome: str
    event_id: str | None
    evidence_artifact: str
    batch_digest: str
    replayed: bool


def _window_payload(value: BundleWindow) -> dict[str, object]:
    if (
        not isinstance(value, BundleWindow)
        or type(value.schema_version) is not int
        or value.schema_version != 1
    ):
        _fail("bundle window schema is invalid")
    start = _timestamp(value.start, "window start")
    end = _timestamp(value.end, "window end")
    if _instant(start) >= _instant(end):
        _fail("bundle window is invalid")
    return {"schema_version": 1, "start": start, "end": end}


def _request_payload(value: BundleRequest) -> dict[str, object]:
    if (
        not isinstance(value, BundleRequest)
        or type(value.schema_version) is not int
        or value.schema_version != 1
    ):
        _fail("bundle request schema is invalid")
    operation = _identifier(value.operation_id, "operation_id")
    observed = _timestamp(value.observed_at, "observed_at")
    window = _window_payload(value.window)
    if _instant(str(window["end"])) > _instant(observed):
        _fail("bundle window is not closed")
    return {
        "schema_version": 1,
        "operation_id": operation,
        "observed_at": observed,
        "window": window,
    }


def _item_payload(value: BundleItem) -> dict[str, object]:
    if (
        not isinstance(value, BundleItem)
        or type(value.schema_version) is not int
        or value.schema_version != 1
    ):
        _fail("bundle item schema is invalid")
    kind = _text(value.kind, "bundle item kind", limit=16)
    if kind not in {"review", "outbox"}:
        _fail("bundle item kind is invalid")
    priority = _text(value.priority, "bundle item priority", limit=16)
    if priority not in _PRIORITIES:
        _fail("bundle item priority is invalid")
    return {
        "schema_version": 1,
        "kind": kind,
        "source_id": _identifier(value.source_id, "source_id"),
        "source_ref": _safe_ref(value.source_ref, "source_ref"),
        "source_sha256": _hash(value.source_sha256, "source_sha256"),
        "created_at": _timestamp(value.created_at, "created_at"),
        "priority": priority,
        "expires_at": None
        if value.expires_at is None
        else _timestamp(value.expires_at, "expires_at"),
        "supersedes": None
        if value.supersedes is None
        else _identifier(value.supersedes, "supersedes"),
    }


def _parse_item(value: object) -> BundleItem:
    item = _mapping(
        value,
        "bundle item",
        {
            "schema_version",
            "kind",
            "source_id",
            "source_ref",
            "source_sha256",
            "created_at",
            "priority",
            "expires_at",
            "supersedes",
        },
    )
    result = BundleItem(
        item["kind"] if isinstance(item["kind"], str) else "",
        item["source_id"] if isinstance(item["source_id"], str) else "",
        item["source_ref"] if isinstance(item["source_ref"], str) else "",
        item["source_sha256"] if isinstance(item["source_sha256"], str) else "",
        item["created_at"] if isinstance(item["created_at"], str) else "",
        item["priority"] if isinstance(item["priority"], str) else "",
        item["expires_at"] if isinstance(item["expires_at"], str) else None,
        item["supersedes"] if isinstance(item["supersedes"], str) else None,
        item["schema_version"] if type(item["schema_version"]) is int else -1,
    )
    if item["expires_at"] is not None and result.expires_at is None:
        _fail("bundle item expires_at has invalid type")
    if item["supersedes"] is not None and result.supersedes is None:
        _fail("bundle item supersedes has invalid type")
    _item_payload(result)
    return result


def _item_order(value: BundleItem) -> tuple[object, ...]:
    return (
        -_PRIORITIES.index(value.priority),
        value.created_at,
        value.kind,
        _portable(value.source_id),
        value.source_sha256,
    )


def _manifest_core(
    window: BundleWindow, items: Sequence[BundleItem]
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "kind": "batched-digest",
        "window": _window_payload(window),
        "items": [_item_payload(item) for item in items],
    }


def render_bundle_manifest(value: BundleManifest) -> bytes:
    if (
        not isinstance(value, BundleManifest)
        or type(value.schema_version) is not int
        or value.schema_version != 1
    ):
        _fail("bundle manifest schema is invalid")
    if (
        not isinstance(value.items, tuple)
        or not value.items
        or len(value.items) > _MAX_ITEMS
    ):
        _fail("bundle manifest items are invalid")
    for item in value.items:
        _item_payload(item)
    ordered = tuple(sorted(value.items, key=_item_order))
    if ordered != value.items:
        _fail("bundle manifest items are not deterministically sorted")
    ids = [(item.kind, _portable(item.source_id)) for item in ordered]
    if len(ids) != len(set(ids)):
        _fail("bundle manifest item identities collide")
    by_id = {_portable(item.source_id): item for item in ordered}
    for item in ordered:
        if item.supersedes is None:
            continue
        target = _portable(item.supersedes)
        if target == _portable(item.source_id):
            _fail("bundle item cannot supersede itself")
        seen = {_portable(item.source_id)}
        while target in by_id:
            if target in seen:
                _fail("bundle supersede chain has a cycle")
            seen.add(target)
            next_item = by_id[target]
            if next_item.supersedes is None:
                break
            target = _portable(next_item.supersedes)
    core = _manifest_core(value.window, ordered)
    digest = hashlib.sha256(_canonical(core)).hexdigest()
    if _hash(value.batch_digest, "batch_digest") != digest:
        _fail("bundle manifest digest is invalid")
    return _canonical({**core, "batch_digest": digest}, maximum=_MAX_EVIDENCE)


def parse_bundle_manifest(raw: bytes | str) -> BundleManifest:
    if isinstance(raw, str):
        try:
            raw = raw.encode("utf-8")
        except UnicodeError:
            _fail("bundle manifest is not valid UTF-8")
    item = _mapping(
        _decode(raw, "bundle manifest", maximum=_MAX_EVIDENCE),
        "bundle manifest",
        {"schema_version", "kind", "window", "items", "batch_digest"},
    )
    if (
        type(item["schema_version"]) is not int
        or item["schema_version"] != 1
        or item["kind"] != "batched-digest"
        or not isinstance(item["items"], list)
    ):
        _fail("bundle manifest shape is invalid")
    window_item = _mapping(
        item["window"], "bundle window", {"schema_version", "start", "end"}
    )
    if type(window_item["schema_version"]) is not int:
        _fail("bundle window schema is invalid")
    window = BundleWindow(
        window_item["start"] if isinstance(window_item["start"], str) else "",
        window_item["end"] if isinstance(window_item["end"], str) else "",
        window_item["schema_version"]
        if type(window_item["schema_version"]) is int
        else -1,
    )
    manifest = BundleManifest(
        window,
        tuple(_parse_item(value) for value in item["items"]),
        item["batch_digest"] if isinstance(item["batch_digest"], str) else "",
        item["schema_version"] if type(item["schema_version"]) is int else -1,
    )
    render_bundle_manifest(manifest)
    return manifest


def _evidence_payload(value: BundleRunEvidence) -> dict[str, object]:
    if (
        not isinstance(value, BundleRunEvidence)
        or type(value.schema_version) is not int
        or value.schema_version != 1
    ):
        _fail("bundle evidence schema is invalid")
    outcome = _text(value.outcome, "bundle evidence outcome", limit=16)
    if outcome not in {"emitted", "empty"}:
        _fail("bundle evidence outcome is invalid")
    if type(value.item_count) is not int or not 0 <= value.item_count <= _MAX_ITEMS:
        _fail("bundle evidence item count is invalid")
    nullable = (
        value.marker_ref,
        value.marker_sha256,
        value.payload_ref,
        value.payload_sha256,
        value.event_ref,
        value.event_sha256,
        value.event_id,
    )
    if value.outcome == "emitted":
        if value.item_count < 1 or any(item is None for item in nullable):
            _fail("emitted bundle evidence is incomplete")
    elif value.item_count != 0 or any(item is not None for item in nullable):
        _fail("empty bundle evidence is invalid")
    return {
        "schema_version": 1,
        "flow": "bundle",
        "run_id": _run_id(value.run_id),
        "operation_id": _identifier(value.operation_id, "operation_id"),
        "request_sha256": _hash(value.request_sha256, "request_sha256"),
        "run_state_sha256": _hash(value.run_state_sha256, "run_state_sha256"),
        "outcome": outcome,
        "item_count": value.item_count,
        "batch_digest": _hash(value.batch_digest, "batch_digest"),
        "marker_ref": None
        if value.marker_ref is None
        else _safe_ref(value.marker_ref, "marker_ref"),
        "marker_sha256": None
        if value.marker_sha256 is None
        else _hash(value.marker_sha256, "marker_sha256"),
        "payload_ref": None
        if value.payload_ref is None
        else _safe_ref(value.payload_ref, "payload_ref"),
        "payload_sha256": None
        if value.payload_sha256 is None
        else _hash(value.payload_sha256, "payload_sha256"),
        "event_ref": None
        if value.event_ref is None
        else _safe_ref(value.event_ref, "event_ref"),
        "event_sha256": None
        if value.event_sha256 is None
        else _hash(value.event_sha256, "event_sha256"),
        "event_id": None
        if value.event_id is None
        else _identifier(value.event_id, "event_id"),
    }


def render_bundle_run_evidence(value: BundleRunEvidence) -> bytes:
    return _canonical(_evidence_payload(value), maximum=_MAX_EVIDENCE)


def parse_bundle_run_evidence(raw: bytes | str) -> BundleRunEvidence:
    if isinstance(raw, str):
        try:
            raw = raw.encode("utf-8")
        except UnicodeError:
            _fail("bundle evidence is not valid UTF-8")
    item = _mapping(
        _decode(raw, "bundle evidence", maximum=_MAX_EVIDENCE),
        "bundle evidence",
        {
            "schema_version",
            "flow",
            "run_id",
            "operation_id",
            "request_sha256",
            "run_state_sha256",
            "outcome",
            "item_count",
            "batch_digest",
            "marker_ref",
            "marker_sha256",
            "payload_ref",
            "payload_sha256",
            "event_ref",
            "event_sha256",
            "event_id",
        },
    )
    if item["flow"] != "bundle":
        _fail("bundle evidence flow is invalid")
    result = BundleRunEvidence(
        item["run_id"] if isinstance(item["run_id"], str) else "",
        item["operation_id"] if isinstance(item["operation_id"], str) else "",
        item["request_sha256"] if isinstance(item["request_sha256"], str) else "",
        item["run_state_sha256"] if isinstance(item["run_state_sha256"], str) else "",
        item["outcome"] if isinstance(item["outcome"], str) else "",
        item["item_count"] if type(item["item_count"]) is int else -1,
        item["batch_digest"] if isinstance(item["batch_digest"], str) else "",
        item["marker_ref"] if isinstance(item["marker_ref"], str) else None,
        item["marker_sha256"] if isinstance(item["marker_sha256"], str) else None,
        item["payload_ref"] if isinstance(item["payload_ref"], str) else None,
        item["payload_sha256"] if isinstance(item["payload_sha256"], str) else None,
        item["event_ref"] if isinstance(item["event_ref"], str) else None,
        item["event_sha256"] if isinstance(item["event_sha256"], str) else None,
        item["event_id"] if isinstance(item["event_id"], str) else None,
        item["schema_version"] if type(item["schema_version"]) is int else -1,
    )
    for name in (
        "marker_ref",
        "marker_sha256",
        "payload_ref",
        "payload_sha256",
        "event_ref",
        "event_sha256",
        "event_id",
    ):
        if item[name] is not None and getattr(result, name) is None:
            _fail("bundle evidence nullable field has invalid type")
    _evidence_payload(result)
    return result


def bundle_evidence_artifact_name(operation_id: str) -> str:
    checked = _identifier(operation_id, "operation_id")
    return "bundle-evidence-" + hashlib.sha256(checked.encode()).hexdigest()[:32]


def _bundle_anchor_artifact_name(operation_id: str) -> str:
    checked = _identifier(operation_id, "operation_id")
    return "bundle-anchor-" + hashlib.sha256(checked.encode()).hexdigest()[:32]


def inspect_bundle_run_evidence(
    artifact: CommittedArtifact, raw: bytes
) -> BundleRunEvidence:
    if not isinstance(artifact, CommittedArtifact):
        _fail("bundle evidence artifact has invalid type")
    evidence = parse_bundle_run_evidence(raw)
    expected_name = bundle_evidence_artifact_name(evidence.operation_id)
    token = hashlib.sha256(evidence.operation_id.encode()).hexdigest()[:32]
    if (
        artifact.name != expected_name
        or artifact.zone != "agent/runs"
        or artifact.relative != f"{evidence.run_id}/{expected_name}.json"
        or artifact.state_ref != f"agent/runs/{artifact.relative}"
        or artifact.sha256 != hashlib.sha256(raw).hexdigest()
        or artifact.step_id != f"bundle-{token}"
    ):
        _fail("bundle evidence artifact binding is invalid")
    return evidence


class BundleFlow(AmbientFlow):
    """Collect exact batched sources from a closed window and publish one digest."""

    def __init__(
        self,
        resolver: VaultPathResolver,
        run_store: RunStore,
        policy: AuthorityPolicy,
        clock: Callable[[], datetime] | None = None,
        receipt_verifier: BundleReceiptVerificationPort | None = None,
    ) -> None:
        try:
            super().__init__(resolver, run_store, policy, clock)
        except AmbientFlowError as error:
            raise BundleFlowError(str(error).replace("ambient", "bundle")) from None
        if receipt_verifier is not None and not callable(
            getattr(receipt_verifier, "verify_delivered", None)
        ):
            self.close()
            _fail("bundle receipt verifier is invalid")
        self._receipt_verifier = receipt_verifier

    def _require_capabilities(
        self, value: BundleCapabilities
    ) -> tuple[ActionCapability, ...]:
        if not isinstance(value, BundleCapabilities):
            _fail("bundle capabilities are invalid")
        expected = (
            (
                value.collect_batched_items,
                "collect-batched-items",
                "read",
                "vault:review",
            ),
            (
                value.read_pending_outbox,
                "read-pending-outbox",
                "read",
                "vault:agent/outbox",
            ),
            (
                value.commit_bundle_outbox_event,
                "commit-bundle-outbox-event",
                "internal-write",
                "vault:agent/outbox",
            ),
            (
                value.record_run_state,
                "record-run-state",
                "internal-write",
                "vault:agent/runs",
            ),
        )
        grants: list[ActionCapability] = []
        for capability, action, authority, target in expected:
            try:
                grant = self._policy.require(capability)
            except AuthorityError as error:
                raise BundleFlowError(str(error)) from None
            if (
                grant.flow_id,
                grant.action_id,
                grant.actor,
                grant.authority,
                grant.target,
            ) != ("bundle", action, "system", authority, target):
                _fail("bundle action capability is not exact")
            grants.append(grant)
        return tuple(grants)

    def _run_snapshot(self, run_id: str):
        checked = _run_id(run_id)
        try:
            snapshot = self._runs.snapshot(checked)
        except RunError as error:
            raise BundleFlowError(str(error)) from None
        if (
            snapshot.state.get("flow") != "bundle"
            or snapshot.state.get("status") != "running"
            or snapshot.state.get("authority") != "internal-write"
        ):
            _fail("bundle collection requires a running internal-write bundle run")
        return snapshot

    @staticmethod
    def _in_window(created_at: str, window: BundleWindow) -> bool:
        return _instant(window.start) <= _instant(created_at) < _instant(window.end)

    def _scan_review_items(
        self, window: BundleWindow, observed_at: str
    ) -> list[BundleItem]:
        zone = self._open_zone("review")
        items: list[BundleItem] = []
        try:
            names = sorted(os.listdir(zone.fd), key=_portable)
            if len(names) > _MAX_FILES:
                _fail("bundle review namespace exceeds its bound")
            total = 0
            seen: set[str] = set()
            for name in names:
                portable = _portable(name)
                if portable in seen:
                    _fail("bundle review namespace has portable-name collisions")
                seen.add(portable)
                if name.startswith("."):
                    continue
                metadata = os.stat(name, dir_fd=zone.fd, follow_symlinks=False)
                if not stat.S_ISREG(metadata.st_mode):
                    _fail("bundle review namespace contains an unsafe entry")
                source = self._read_at(zone.fd, name, f"{zone.relative}/{name}")
                total += len(source.raw)
                if total > _MAX_TOTAL:
                    _fail("bundle review snapshot exceeds its byte bound")
                status: str | None = None
                source_id: str | None = None
                created_at: str | None = None
                surface = self._resolver.config.surface
                expires: str | None = None
                if name.endswith(".md"):
                    try:
                        review = parse_review_artifact(source.raw)
                    except ReviewArtifactError:
                        _fail(
                            "bundle review source violates the accepted review schema"
                        )
                    status, source_id, created_at, surface = (
                        review.status,
                        review.review_id,
                        review.created_at,
                        review.surface,
                    )
                elif name.endswith(".memory.json"):
                    try:
                        proposal = parse_memory_proposal(source.raw)
                    except MemoryFlowError:
                        _fail(
                            "bundle review source violates the accepted memory proposal schema"
                        )
                    status, source_id, created_at = (
                        proposal.status,
                        proposal.proposal_id,
                        proposal.created_at,
                    )
                    if proposal.decay.mode == "expires":
                        expires = proposal.decay.expires_at
                elif name.startswith("tasks-feedback-") and name.endswith(".json"):
                    proposal = self._plan_feedback(source.raw)
                    status, source_id, created_at = (
                        str(proposal["status"]),
                        str(proposal["proposal_id"]),
                        str(proposal["created_at"]),
                    )
                else:
                    continue
                if status in {"approved", "rejected", "applied", "superseded"}:
                    continue
                if status != "proposed" or source_id is None or created_at is None:
                    _fail("bundle review source status is invalid")
                if surface != "batched" or not self._in_window(created_at, window):
                    continue
                if expires is not None and _instant(expires) <= _instant(observed_at):
                    continue
                items.append(
                    BundleItem(
                        "review",
                        source_id,
                        source.relative,
                        source.sha256,
                        created_at,
                        "medium",
                        expires,
                        None,
                    )
                )
            self._revalidate_zone(zone)
            return items
        except OSError:
            raise BundleFlowError(
                "bundle review namespace cannot be scanned safely"
            ) from None
        finally:
            os.close(zone.fd)

    def _require_committed_event_lineage(
        self, event: Mapping[str, object], source
    ) -> None:
        try:
            snapshot = self._runs.snapshot(str(event["run_id"]))
            trace = self._runs.trace_events(str(event["run_id"]))
        except RunError as error:
            raise BundleFlowError(str(error)) from None
        matches = tuple(
            item
            for item in snapshot.artifacts
            if item.zone == "agent/outbox"
            and item.state_ref == source.relative
            and item.relative == f"{event['event_id']}.json"
            and item.sha256 == source.sha256
        )
        if len(matches) != 1 or snapshot.state.get("flow") != event["flow_id"]:
            _fail("bundle source event lacks exact committed run evidence")
        committed = matches[0]
        steps = tuple(
            item for item in trace if item.get("step_id") == committed.step_id
        )
        if len(steps) != 1 or not isinstance(steps[0].get("actions"), list):
            _fail("bundle source event lacks exact committed action evidence")
        expected_action = event["action"]
        actions = [
            action
            for action in steps[0]["actions"]
            if isinstance(action, Mapping)
            and all(
                action.get(field) == expected_action[field]
                for field in ("action_id", "actor", "authority", "target")
            )
            and action.get("status") == "succeeded"
            and action.get("artifact_commit") is True
            and action.get("effect_kind") == "outbox-artifact-commit"
        ]
        if len(actions) != 1:
            _fail("bundle source event action lineage is not exact")

    def _delivered_event_ids(
        self,
        outbox_zone,
        events: Mapping[str, tuple[Mapping[str, object], object]],
    ) -> set[str]:
        try:
            receipts_fd, identity = self._open_child(
                outbox_zone.fd,
                "receipts",
                f"{outbox_zone.relative}/receipts",
            )
        except AmbientFlowError:
            try:
                os.stat("receipts", dir_fd=outbox_zone.fd, follow_symlinks=False)
            except FileNotFoundError:
                return set()
            raise
        delivered: set[str] = set()
        try:
            names = sorted(os.listdir(receipts_fd), key=_portable)
            if len(names) > _MAX_FILES:
                _fail("bundle receipt namespace exceeds its bound")
            seen: set[str] = set()
            for name in names:
                portable = _portable(name)
                if portable in seen:
                    _fail("bundle receipt namespace has portable-name collisions")
                seen.add(portable)
                if not name.endswith(".json"):
                    _fail("bundle receipt namespace contains an unknown entry")
                source = self._read_at(
                    receipts_fd,
                    name,
                    f"{outbox_zone.relative}/receipts/{name}",
                    maximum=64 * 1024,
                )
                try:
                    receipt = validate_receipt(
                        _decode(source.raw, "delivery receipt", maximum=64 * 1024)
                    )
                except (RunError, ValueError):
                    _fail("bundle delivery receipt violates its accepted schema")
                if (
                    source.raw != _canonical(receipt, maximum=64 * 1024) + b"\n"
                    or _RECEIPT_ID.fullmatch(str(receipt["receipt_id"])) is None
                    or name != f"{receipt['receipt_id']}.json"
                ):
                    _fail("bundle receipt filename disagrees with its id")
                if receipt["status"] == "delivered":
                    event_source = events.get(str(receipt["event_id"]))
                    if event_source is None:
                        _fail("bundle delivered receipt references an unknown event")
                    event, event_file = event_source
                    if receipt["run_id"] != event["run_id"] or _instant(
                        str(receipt["at"])
                    ) < _instant(str(event["created_at"])):
                        _fail("bundle delivered receipt disagrees with its event")
                    self._require_committed_event_lineage(event, event_file)
                    if self._receipt_verifier is None:
                        continue
                    try:
                        verified = self._receipt_verifier.verify_delivered(
                            receipt=receipt,
                            receipt_raw=source.raw,
                            event=event,
                            event_raw=event_file.raw,
                        )
                    except Exception as error:
                        raise BundleFlowError(
                            "bundle receipt verifier failed"
                        ) from error
                    if type(verified) is not bool:
                        _fail("bundle receipt verifier returned an invalid result")
                    if verified:
                        delivered.add(str(receipt["event_id"]))
            self._revalidate_child(outbox_zone.fd, "receipts", receipts_fd, identity)
            return delivered
        finally:
            os.close(receipts_fd)

    def _scan_outbox_items(self, window: BundleWindow) -> list[BundleItem]:
        zone = self._open_zone("agent/outbox")
        items: list[BundleItem] = []
        try:
            names = sorted(os.listdir(zone.fd), key=_portable)
            if len(names) > _MAX_FILES:
                _fail("bundle outbox namespace exceeds its bound")
            total = 0
            seen: set[str] = set()
            events: dict[str, tuple[Mapping[str, object], object]] = {}
            for name in names:
                portable = _portable(name)
                if portable in seen:
                    _fail("bundle outbox namespace has portable-name collisions")
                seen.add(portable)
                if not name.endswith(".json"):
                    continue
                source = self._read_at(
                    zone.fd, name, f"{zone.relative}/{name}", maximum=64 * 1024
                )
                total += len(source.raw)
                if total > _MAX_TOTAL:
                    _fail("bundle outbox snapshot exceeds its byte bound")
                try:
                    event = validate_event(
                        _decode(source.raw, "outbox event", maximum=64 * 1024)
                    )
                except (OutboxError, ValueError):
                    _fail("bundle outbox event violates its accepted schema")
                if (
                    source.raw != _canonical(event, maximum=64 * 1024) + b"\n"
                    or name != f"{event['event_id']}.json"
                ):
                    _fail("bundle outbox event is not canonical")
                event_id = str(event["event_id"])
                if event_id in events:
                    _fail("bundle outbox event identities collide")
                events[event_id] = (event, source)
            delivered = self._delivered_event_ids(zone, events)
            for event, source in events.values():
                if (
                    event["flow_id"] == "bundle"
                    or event["event_id"] in delivered
                    or event["status"] != "pending"
                    or event["delivery_policy"]["surface"] != "batched"  # type: ignore[index]
                    or not self._in_window(str(event["created_at"]), window)
                ):
                    continue
                priority = {
                    "low": "low",
                    "normal": "medium",
                    "high": "high",
                    "critical": "critical",
                }[str(event["urgency"])]
                items.append(
                    BundleItem(
                        "outbox",
                        str(event["event_id"]),
                        source.relative,
                        source.sha256,
                        str(event["created_at"]),
                        priority,
                    )
                )
            self._revalidate_zone(zone)
            return items
        except OSError:
            raise BundleFlowError(
                "bundle outbox namespace cannot be scanned safely"
            ) from None
        finally:
            os.close(zone.fd)

    @staticmethod
    def _normalize_items(
        items: Sequence[BundleItem], observed_at: str
    ) -> tuple[BundleItem, ...]:
        by_identity: dict[tuple[str, str], BundleItem] = {}
        for item in items:
            _item_payload(item)
            if item.expires_at is not None and _instant(item.expires_at) <= _instant(
                observed_at
            ):
                continue
            key = (item.kind, _portable(item.source_id))
            prior = by_identity.get(key)
            if prior is not None and _item_payload(prior) != _item_payload(item):
                _fail("bundle source identity has conflicting versions")
            by_identity[key] = item
        superseded = {
            _portable(item.supersedes)
            for item in by_identity.values()
            if item.supersedes is not None
        }
        if any(item.supersedes == item.source_id for item in by_identity.values()):
            _fail("bundle item cannot supersede itself")
        result = tuple(
            sorted(
                (
                    item
                    for item in by_identity.values()
                    if _portable(item.source_id) not in superseded
                ),
                key=_item_order,
            )
        )
        if len(result) > _MAX_ITEMS:
            _fail("bundle item set exceeds its bound")
        return result

    def _scan_all_items(self, request: BundleRequest) -> tuple[BundleItem, ...]:
        return self._normalize_items(
            [
                *self._scan_review_items(request.window, request.observed_at),
                *self._scan_outbox_items(request.window),
            ],
            request.observed_at,
        )

    def _publish_payload(
        self, *, name: str, filename: str, raw: bytes
    ) -> tuple[PreparedArtifact, bool]:
        try:
            return self._publish_outbox_payload(
                name=name, relative_name=filename, raw=raw
            )
        except AmbientFlowError as error:
            raise BundleFlowError(str(error).replace("ambient", "bundle")) from None

    def _read_ref_bundle(
        self, state_ref: str, *, maximum: int = _MAX_EVIDENCE
    ) -> bytes:
        try:
            return self._read_ref(state_ref, maximum=maximum)
        except AmbientFlowError as error:
            raise BundleFlowError(str(error).replace("ambient", "bundle")) from None

    def _outbox_prepared_bundle(
        self, *, name: str, state_ref: str, sha256: str
    ) -> PreparedArtifact:
        try:
            return self._outbox_prepared(name=name, state_ref=state_ref, sha256=sha256)
        except AmbientFlowError as error:
            raise BundleFlowError(str(error).replace("ambient", "bundle")) from None

    def _publish_event(
        self,
        *,
        capability: ActionCapability,
        run_id: str,
        manifest: BundleManifest,
        payload: PreparedArtifact,
    ) -> tuple[Mapping[str, object], PreparedArtifact]:
        try:
            with OutboxStore(
                self._resolver, self._runs, policy=self._policy, clock=self._clock
            ) as outbox:
                event = outbox.enqueue(
                    capability,
                    run_id=run_id,
                    event_type="batched_digest",
                    semantic_key=f"bundle:v1:{manifest.window.start}:{manifest.window.end}:{manifest.batch_digest}",
                    summary=f"{len(manifest.items)} batched Life OS items are ready.",
                    artifact_zone="agent/outbox",
                    artifact_relative=payload.relative,
                    urgency="normal",
                    surface="gated",
                    requires_receipt=True,
                )
        except OutboxError as error:
            raise BundleFlowError(str(error)) from None
        event_raw = _canonical(event, maximum=64 * 1024) + b"\n"
        event_id = _identifier(event.get("event_id"), "event_id")
        event_ref = f"{self._resolver.config.zone('outbox').as_posix()}/{event_id}.json"
        if self._read_ref_bundle(event_ref, maximum=64 * 1024) != event_raw:
            _fail("bundle event bytes disagree with the outbox commit")
        prepared = PreparedArtifact(
            "bundle-event-" + event_id.removeprefix("event_")[:24],
            "agent/outbox",
            f"{event_id}.json",
            event_ref,
            hashlib.sha256(event_raw).hexdigest(),
        )
        return event, prepared

    @staticmethod
    def _marker_payload(
        *, request_sha: str, manifest: BundleManifest, payload: PreparedArtifact
    ) -> dict[str, object]:
        return {
            "schema_version": 1,
            "kind": "bundle-operation",
            "request_sha256": request_sha,
            "item_count": len(manifest.items),
            "batch_digest": manifest.batch_digest,
            "payload_ref": payload.state_ref,
            "payload_sha256": payload.sha256,
        }

    def _parse_marker(
        self, raw: bytes, request_sha: str
    ) -> tuple[BundleManifest, str, str]:
        item = _mapping(
            _decode(raw, "bundle operation marker", maximum=_MAX_EVIDENCE),
            "bundle operation marker",
            {
                "schema_version",
                "kind",
                "request_sha256",
                "item_count",
                "batch_digest",
                "payload_ref",
                "payload_sha256",
            },
        )
        if (
            type(item["schema_version"]) is not int
            or item["schema_version"] != 1
            or item["kind"] != "bundle-operation"
            or item["request_sha256"] != request_sha
        ):
            _fail("bundle operation marker conflicts with the request")
        if (
            type(item["item_count"]) is not int
            or not 1 <= int(item["item_count"]) <= _MAX_ITEMS
        ):
            _fail("bundle operation marker count is invalid")
        digest = _hash(item["batch_digest"], "batch_digest")
        payload_ref = _safe_ref(item["payload_ref"], "payload_ref")
        payload_sha = _hash(item["payload_sha256"], "payload_sha256")
        if PurePosixPath(payload_ref).name != f"bundle-{digest}.json":
            _fail("bundle operation payload name disagrees with its digest")
        payload_raw = self._read_ref_bundle(payload_ref)
        if hashlib.sha256(payload_raw).hexdigest() != payload_sha:
            _fail("bundle operation payload changed")
        manifest = parse_bundle_manifest(payload_raw)
        if manifest.batch_digest != digest or len(manifest.items) != item["item_count"]:
            _fail("bundle operation marker disagrees with its manifest")
        return manifest, payload_ref, payload_sha

    @staticmethod
    def _anchor_payload(
        *,
        operation_id: str,
        request_sha: str,
        marker: PreparedArtifact,
        payload: PreparedArtifact,
        batch_digest: str,
    ) -> dict[str, object]:
        return {
            "schema_version": 1,
            "kind": "bundle-pre-event-anchor",
            "operation_id": _identifier(operation_id, "operation_id"),
            "request_sha256": _hash(request_sha, "request_sha256"),
            "batch_digest": _hash(batch_digest, "batch_digest"),
            "marker_ref": _safe_ref(marker.state_ref, "marker_ref"),
            "marker_sha256": _hash(marker.sha256, "marker_sha256"),
            "payload_ref": _safe_ref(payload.state_ref, "payload_ref"),
            "payload_sha256": _hash(payload.sha256, "payload_sha256"),
        }

    def _parse_anchor(
        self, raw: bytes, *, operation_id: str, request_sha: str
    ) -> Mapping[str, object]:
        item = _mapping(
            _decode(raw, "bundle pre-event anchor", maximum=_MAX_EVIDENCE),
            "bundle pre-event anchor",
            {
                "schema_version",
                "kind",
                "operation_id",
                "request_sha256",
                "batch_digest",
                "marker_ref",
                "marker_sha256",
                "payload_ref",
                "payload_sha256",
            },
        )
        if (
            type(item["schema_version"]) is not int
            or item["schema_version"] != 1
            or item["kind"] != "bundle-pre-event-anchor"
            or item["operation_id"] != operation_id
            or item["request_sha256"] != request_sha
        ):
            _fail("bundle pre-event anchor conflicts with the request")
        batch_digest = _hash(item["batch_digest"], "batch_digest")
        marker_ref = _safe_ref(item["marker_ref"], "marker_ref")
        marker_sha = _hash(item["marker_sha256"], "marker_sha256")
        payload_ref = _safe_ref(item["payload_ref"], "payload_ref")
        payload_sha = _hash(item["payload_sha256"], "payload_sha256")
        token = hashlib.sha256(operation_id.encode()).hexdigest()
        if (
            PurePosixPath(marker_ref).name != f"bundle-op-{token[:32]}.json"
            or PurePosixPath(payload_ref).name != f"bundle-{batch_digest}.json"
        ):
            _fail("bundle pre-event anchor has invalid content-address bindings")
        return {
            **item,
            "batch_digest": batch_digest,
            "marker_ref": marker_ref,
            "marker_sha256": marker_sha,
            "payload_ref": payload_ref,
            "payload_sha256": payload_sha,
        }

    def _commit_pre_event_anchor(
        self,
        *,
        snapshot,
        operation_id: str,
        request_sha: str,
        marker: PreparedArtifact,
        payload: PreparedArtifact,
        batch_digest: str,
        record_run_state: ActionCapability,
    ):
        anchor_name = _bundle_anchor_artifact_name(operation_id)
        anchor_raw = _canonical(
            self._anchor_payload(
                operation_id=operation_id,
                request_sha=request_sha,
                marker=marker,
                payload=payload,
                batch_digest=batch_digest,
            ),
            maximum=_MAX_EVIDENCE,
        )
        try:
            anchor = self._runs.prepare_run_artifact(
                str(snapshot.state["run_id"]),
                name=anchor_name,
                data=anchor_raw,
                maximum_bytes=_MAX_EVIDENCE,
            )
            self._runs.commit_step(
                str(snapshot.state["run_id"]),
                step_id=anchor_name,
                authority="internal-write",
                input_hash=request_sha,
                output_hash=anchor.sha256,
                next_phase="bundle-prepared",
                next_status="running",
                prepared_artifacts=(marker, payload, anchor),
                expected_state_sha256=snapshot.state_sha256,
                action_uses=(ActionUse(record_run_state),),
                authority_policy=self._policy,
            )
        except RunError as error:
            raise BundleFlowError(str(error)) from None
        return self._run_snapshot(str(snapshot.state["run_id"]))

    def _anchored_recovery(
        self,
        *,
        snapshot,
        operation_id: str,
        request_sha: str,
    ) -> tuple[BundleManifest, PreparedArtifact, PreparedArtifact] | None:
        anchor_name = _bundle_anchor_artifact_name(operation_id)
        if not any(item.name == anchor_name for item in snapshot.artifacts):
            return None
        try:
            producer = self._runs.producer_snapshot(
                str(snapshot.state["run_id"]), producer_evidence=anchor_name
            )
        except RunError as error:
            raise BundleFlowError(str(error)) from None
        artifacts = {item.name: item for item in producer.artifacts}
        anchor = artifacts.get(anchor_name)
        if anchor is None:
            _fail("bundle pre-event anchor is not committed")
        self._require_exact_anchor_trace(
            snapshot=snapshot,
            flow_id="bundle",
            request_sha=request_sha,
            anchor_name=anchor_name,
        )
        anchor_data = self._parse_anchor(
            self._read_ref_bundle(anchor.state_ref),
            operation_id=operation_id,
            request_sha=request_sha,
        )
        token = hashlib.sha256(operation_id.encode()).hexdigest()
        marker_name = "bundle-marker-" + token[:24]
        payload_name = "bundle-payload-" + str(anchor_data["payload_sha256"])[:24]
        if set(artifacts) != {anchor_name, marker_name, payload_name}:
            _fail("bundle pre-event producer bundle is not exact")
        marker_committed = artifacts[marker_name]
        payload_committed = artifacts[payload_name]
        bindings = (
            (
                marker_committed,
                str(anchor_data["marker_ref"]),
                str(anchor_data["marker_sha256"]),
            ),
            (
                payload_committed,
                str(anchor_data["payload_ref"]),
                str(anchor_data["payload_sha256"]),
            ),
        )
        for artifact, state_ref, digest in bindings:
            if artifact.state_ref != state_ref or artifact.sha256 != digest:
                _fail("bundle pre-event artifact binding is invalid")
        marker = self._outbox_prepared_bundle(
            name=marker_name,
            state_ref=marker_committed.state_ref,
            sha256=marker_committed.sha256,
        )
        payload = self._outbox_prepared_bundle(
            name=payload_name,
            state_ref=payload_committed.state_ref,
            sha256=payload_committed.sha256,
        )
        manifest, payload_ref, payload_sha = self._parse_marker(
            self._read_ref_bundle(marker.state_ref), request_sha
        )
        if (
            payload_ref != payload.state_ref
            or payload_sha != payload.sha256
            or manifest.batch_digest != anchor_data["batch_digest"]
        ):
            _fail("bundle marker disagrees with its committed anchor")
        return manifest, marker, payload

    def _prior_committed_recovery(
        self,
        *,
        snapshot,
        operation_id: str,
        request_sha: str,
    ) -> tuple[BundleManifest, PreparedArtifact, PreparedArtifact] | None:
        token = hashlib.sha256(operation_id.encode()).hexdigest()
        marker_relative = f"artifacts/bundle-op-{token[:32]}.json"
        marker_file = self._read_optional_outbox(marker_relative)
        if marker_file is None:
            return None
        manifest, payload_ref, payload_sha = self._parse_marker(
            marker_file.raw, request_sha
        )
        zone = self._open_zone("agent/outbox")
        matches: list[tuple[Mapping[str, object], object]] = []
        try:
            names = sorted(os.listdir(zone.fd), key=_portable)
            if len(names) > _MAX_FILES:
                _fail("bundle recovery outbox namespace exceeds its bound")
            seen: set[str] = set()
            for name in names:
                portable = _portable(name)
                if portable in seen:
                    _fail(
                        "bundle recovery outbox namespace has portable-name collisions"
                    )
                seen.add(portable)
                if not name.endswith(".json"):
                    continue
                source = self._read_at(
                    zone.fd,
                    name,
                    f"{zone.relative}/{name}",
                    maximum=64 * 1024,
                )
                try:
                    event = validate_event(
                        _decode(source.raw, "bundle recovery event", maximum=64 * 1024)
                    )
                except (OutboxError, ValueError):
                    _fail("bundle recovery outbox event is invalid")
                if (
                    source.raw != _canonical(event, maximum=64 * 1024) + b"\n"
                    or name != f"{event['event_id']}.json"
                ):
                    _fail("bundle recovery outbox event is not canonical")
                if (
                    event["flow_id"] == "bundle"
                    and event["type"] == "batched_digest"
                    and event["artifact_ref"] == payload_ref
                    and event["artifact_sha256"] == payload_sha
                    and event["summary"]
                    == f"{len(manifest.items)} batched Life OS items are ready."
                    and event["urgency"] == "normal"
                    and event["delivery_policy"]["surface"] == "gated"  # type: ignore[index]
                ):
                    matches.append((event, source))
            self._revalidate_zone(zone)
        except OSError:
            raise BundleFlowError(
                "bundle prior event cannot be scanned safely"
            ) from None
        finally:
            os.close(zone.fd)
        if not matches:
            return None
        if len(matches) != 1:
            _fail("bundle prior event binding is ambiguous")
        event, event_source = matches[0]
        prior_run_id = str(event["run_id"])
        if prior_run_id == snapshot.state["run_id"]:
            _fail("bundle current-run event lacks its pre-event anchor")
        try:
            prior_snapshot = self._runs.snapshot(prior_run_id)
        except RunError as error:
            raise BundleFlowError(str(error)) from None
        if (
            prior_snapshot.state.get("flow") != "bundle"
            or prior_snapshot.state.get("status") != "running"
            or prior_snapshot.state.get("authority") != "internal-write"
        ):
            _fail("bundle prior event run is invalid")
        replay = self._committed_replay(
            snapshot=prior_snapshot,
            evidence_name=bundle_evidence_artifact_name(operation_id),
            request_sha=request_sha,
            operation_id=operation_id,
        )
        if replay is None or replay.event_id != event["event_id"]:
            _fail("bundle prior event lacks exact committed producer evidence")
        try:
            producer = self._runs.producer_snapshot(
                prior_run_id,
                producer_evidence=bundle_evidence_artifact_name(operation_id),
            )
        except RunError as error:
            raise BundleFlowError(str(error)) from None
        evidence_artifact = next(
            (
                item
                for item in producer.artifacts
                if item.name == bundle_evidence_artifact_name(operation_id)
            ),
            None,
        )
        if evidence_artifact is None:
            _fail("bundle prior evidence is missing")
        evidence = inspect_bundle_run_evidence(
            evidence_artifact,
            self._read_ref_bundle(evidence_artifact.state_ref),
        )
        if (
            evidence.marker_ref
            != f"{self._resolver.config.zone('outbox').as_posix()}/{marker_relative}"
            or evidence.marker_sha256 != marker_file.sha256
            or evidence.payload_ref != payload_ref
            or evidence.payload_sha256 != payload_sha
            or evidence.event_ref != event_source.relative
            or evidence.event_sha256 != event_source.sha256
            or evidence.batch_digest != manifest.batch_digest
            or evidence.item_count != len(manifest.items)
        ):
            _fail("bundle prior marker disagrees with committed evidence")
        marker = self._outbox_prepared_bundle(
            name="bundle-marker-" + token[:24],
            state_ref=str(evidence.marker_ref),
            sha256=str(evidence.marker_sha256),
        )
        payload = self._outbox_prepared_bundle(
            name="bundle-payload-" + payload_sha[:24],
            state_ref=payload_ref,
            sha256=payload_sha,
        )
        return manifest, marker, payload

    def _commit_evidence(
        self,
        *,
        snapshot,
        evidence: BundleRunEvidence,
        evidence_raw: bytes,
        external: Sequence[PreparedArtifact],
        grants: Sequence[ActionCapability],
        hooks: BundleCrashHooks,
    ) -> BundleResult:
        try:
            evidence_artifact = self._runs.prepare_run_artifact(
                evidence.run_id,
                name=bundle_evidence_artifact_name(evidence.operation_id),
                data=evidence_raw,
                maximum_bytes=_MAX_EVIDENCE,
            )
        except RunError as error:
            raise BundleFlowError(str(error)) from None
        if hooks.after_evidence_prepare is not None:
            hooks.after_evidence_prepare()
        uses = tuple(
            grants
            if evidence.outcome == "emitted"
            else (grants[0], grants[1], grants[3])
        )
        token = hashlib.sha256(evidence.operation_id.encode()).hexdigest()[:32]
        try:
            self._runs.commit_step(
                evidence.run_id,
                step_id=f"bundle-{token}",
                authority="internal-write",
                input_hash=evidence.request_sha256,
                output_hash=evidence_artifact.sha256,
                next_phase="bundle-committed",
                next_status="running",
                prepared_artifacts=(*external, evidence_artifact),
                expected_state_sha256=snapshot.state_sha256,
                action_uses=tuple(ActionUse(item) for item in uses),
                authority_policy=self._policy,
                after_prepare=hooks.after_run_intent,
                after_state=hooks.after_run_state,
                after_trace=hooks.after_run_trace,
            )
        except RunError as error:
            raise BundleFlowError(str(error)) from None
        return BundleResult(
            evidence.outcome,
            evidence.event_id,
            evidence_artifact.name,
            evidence.batch_digest,
            False,
        )

    def _committed_replay(
        self,
        *,
        snapshot,
        evidence_name: str,
        request_sha: str,
        operation_id: str,
    ) -> BundleResult | None:
        existing = next(
            (item for item in snapshot.artifacts if item.name == evidence_name), None
        )
        if existing is None:
            return None
        try:
            bundle = self._runs.producer_snapshot(
                snapshot.state["run_id"], producer_evidence=evidence_name
            )
        except RunError as error:
            raise BundleFlowError(str(error)) from None
        artifacts = {item.name: item for item in bundle.artifacts}
        committed = artifacts.get(evidence_name)
        if committed is None:
            _fail("bundle replay lacks committed evidence")
        evidence = inspect_bundle_run_evidence(
            committed, self._read_ref_bundle(committed.state_ref)
        )
        if (
            evidence.request_sha256 != request_sha
            or evidence.operation_id != operation_id
            or evidence.run_id != snapshot.state["run_id"]
        ):
            _fail("bundle replay conflicts with the request")
        final_actions = (
            (
                "collect-batched-items",
                "read-pending-outbox",
                "commit-bundle-outbox-event",
                "record-run-state",
            )
            if evidence.outcome == "emitted"
            else (
                "collect-batched-items",
                "read-pending-outbox",
                "record-run-state",
            )
        )
        self._require_exact_committed_trace(
            snapshot=snapshot,
            flow_id="bundle",
            step_id=f"bundle-{hashlib.sha256(operation_id.encode()).hexdigest()[:32]}",
            input_hash=request_sha,
            output_hash=committed.sha256,
            action_ids=final_actions,
        )
        expected = {evidence_name}
        if evidence.outcome == "emitted":
            self._require_exact_anchor_trace(
                snapshot=snapshot,
                flow_id="bundle",
                request_sha=request_sha,
                anchor_name=_bundle_anchor_artifact_name(operation_id),
            )
            assert (
                evidence.marker_ref
                and evidence.marker_sha256
                and evidence.payload_ref
                and evidence.payload_sha256
            )
            assert evidence.event_ref and evidence.event_sha256 and evidence.event_id
            token = hashlib.sha256(operation_id.encode()).hexdigest()
            bindings = (
                (
                    "bundle-marker-" + token[:24],
                    evidence.marker_ref,
                    evidence.marker_sha256,
                ),
                (
                    "bundle-payload-" + evidence.payload_sha256[:24],
                    evidence.payload_ref,
                    evidence.payload_sha256,
                ),
                (
                    "bundle-event-" + evidence.event_id.removeprefix("event_")[:24],
                    evidence.event_ref,
                    evidence.event_sha256,
                ),
            )
            expected.update(name for name, _ref, _sha in bindings)
            for name, state_ref, digest in bindings:
                artifact = artifacts.get(name)
                if (
                    artifact is None
                    or artifact.state_ref != state_ref
                    or artifact.sha256 != digest
                    or hashlib.sha256(self._read_ref_bundle(state_ref)).hexdigest()
                    != digest
                ):
                    _fail("bundle replay outbox binding is invalid")
        if set(artifacts) != expected:
            _fail("bundle replay producer bundle is not exact")
        return BundleResult(
            evidence.outcome,
            evidence.event_id,
            evidence_name,
            evidence.batch_digest,
            True,
        )

    def _prepared_evidence(
        self, *, run_id: str, evidence_name: str, request_sha: str, operation_id: str
    ) -> tuple[BundleRunEvidence, bytes] | None:
        state_ref = f"{self._resolver.config.zone('runs').as_posix()}/{run_id}/{evidence_name}.json"
        try:
            raw = self._read_ref_bundle(state_ref)
        except BundleFlowError:
            path = self._root_path / PurePosixPath(state_ref)
            try:
                os.stat(path, follow_symlinks=False)
            except FileNotFoundError:
                return None
            except OSError:
                _fail("bundle prepared evidence cannot be inspected")
            raise
        evidence = parse_bundle_run_evidence(raw)
        if (
            evidence.run_id != run_id
            or evidence.operation_id != operation_id
            or evidence.request_sha256 != request_sha
        ):
            _fail("bundle prepared evidence conflicts with the request")
        return evidence, raw

    def _commit_recomputed_prepared(
        self,
        *,
        snapshot,
        evidence: BundleRunEvidence,
        raw: bytes,
        grants: Sequence[ActionCapability],
        hooks: BundleCrashHooks,
    ) -> BundleResult:
        if evidence.run_state_sha256 != snapshot.state_sha256:
            _fail("bundle prepared evidence has a stale run precondition")
        if evidence.outcome == "emitted":
            _fail("bundle emitted recovery requires a committed pre-event anchor")
        result = self._commit_evidence(
            snapshot=snapshot,
            evidence=evidence,
            evidence_raw=raw,
            external=(),
            grants=grants,
            hooks=hooks,
        )
        return BundleResult(
            result.outcome,
            result.event_id,
            result.evidence_artifact,
            result.batch_digest,
            True,
        )

    def _verified_sources(
        self,
        request: BundleRequest,
        hooks: BundleCrashHooks,
    ) -> tuple[BundleItem, ...]:
        with self._source_identity_snapshot() as source_identities:
            items = self._scan_all_items(request)
        identity_manifest = self._identity_manifest(source_identities)
        if hooks.after_source_read is not None:
            hooks.after_source_read()
        with self._source_identity_snapshot() as verified_source_identities:
            verified_items = self._scan_all_items(request)
        verified_identity_manifest = self._identity_manifest(verified_source_identities)
        if identity_manifest != verified_identity_manifest or [
            _item_payload(item) for item in items
        ] != [_item_payload(item) for item in verified_items]:
            _fail("bundle sources changed after the bounded snapshot")
        return items

    def collect(
        self,
        capabilities: BundleCapabilities,
        *,
        run_id: str,
        request: BundleRequest,
        crash_hooks: BundleCrashHooks | None = None,
    ) -> BundleResult:
        try:
            return self._collect(
                capabilities, run_id=run_id, request=request, crash_hooks=crash_hooks
            )
        except AmbientFlowError as error:
            raise BundleFlowError(str(error).replace("ambient", "bundle")) from None

    def _collect(
        self,
        capabilities: BundleCapabilities,
        *,
        run_id: str,
        request: BundleRequest,
        crash_hooks: BundleCrashHooks | None,
    ) -> BundleResult:
        grants = self._require_capabilities(capabilities)
        self._check_root()
        request_data = _request_payload(request)
        request_sha = hashlib.sha256(_canonical(request_data)).hexdigest()
        checked_run = _run_id(run_id)
        snapshot = self._run_snapshot(checked_run)
        hooks = crash_hooks or BundleCrashHooks()
        if not isinstance(hooks, BundleCrashHooks) or any(
            value is not None and not callable(value)
            for value in hooks.__dict__.values()
        ):
            _fail("bundle crash hooks are invalid")
        evidence_name = bundle_evidence_artifact_name(request.operation_id)
        replay = self._committed_replay(
            snapshot=snapshot,
            evidence_name=evidence_name,
            request_sha=request_sha,
            operation_id=request.operation_id,
        )
        if replay is not None:
            return replay
        prepared = self._prepared_evidence(
            run_id=checked_run,
            evidence_name=evidence_name,
            request_sha=request_sha,
            operation_id=request.operation_id,
        )
        token = hashlib.sha256(request.operation_id.encode()).hexdigest()
        anchored = self._anchored_recovery(
            snapshot=snapshot,
            operation_id=request.operation_id,
            request_sha=request_sha,
        )
        if anchored is None:
            anchored = self._prior_committed_recovery(
                snapshot=snapshot,
                operation_id=request.operation_id,
                request_sha=request_sha,
            )
        if anchored is not None:
            if prepared is not None and prepared[0].outcome != "emitted":
                _fail("bundle prepared evidence conflicts with its committed anchor")
            manifest, marker_artifact, payload = anchored
            event, event_artifact = self._publish_event(
                capability=grants[2],
                run_id=checked_run,
                manifest=manifest,
                payload=payload,
            )
            if hooks.after_event_publish is not None:
                hooks.after_event_publish()
            evidence = BundleRunEvidence(
                checked_run,
                request.operation_id,
                request_sha,
                snapshot.state_sha256,
                "emitted",
                len(manifest.items),
                manifest.batch_digest,
                marker_artifact.state_ref,
                marker_artifact.sha256,
                payload.state_ref,
                payload.sha256,
                event_artifact.state_ref,
                event_artifact.sha256,
                str(event["event_id"]),
            )
            result = self._commit_evidence(
                snapshot=snapshot,
                evidence=evidence,
                evidence_raw=render_bundle_run_evidence(evidence),
                external=(marker_artifact, payload, event_artifact),
                grants=grants,
                hooks=hooks,
            )
            return BundleResult(
                result.outcome,
                result.event_id,
                result.evidence_artifact,
                result.batch_digest,
                True,
            )

        if prepared is not None and prepared[0].outcome == "emitted":
            _fail("bundle emitted recovery requires a committed pre-event anchor")
        items = self._verified_sources(request, hooks)
        if not items:
            empty_core = _manifest_core(request.window, ())
            digest = hashlib.sha256(_canonical(empty_core)).hexdigest()
            evidence = BundleRunEvidence(
                checked_run,
                request.operation_id,
                request_sha,
                snapshot.state_sha256,
                "empty",
                0,
                digest,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            )
            evidence_raw = render_bundle_run_evidence(evidence)
            if prepared is not None:
                if prepared[0] != evidence or prepared[1] != evidence_raw:
                    _fail("bundle prepared evidence disagrees with recomputed sources")
                return self._commit_recomputed_prepared(
                    snapshot=snapshot,
                    evidence=evidence,
                    raw=evidence_raw,
                    grants=grants,
                    hooks=hooks,
                )
            return self._commit_evidence(
                snapshot=snapshot,
                evidence=evidence,
                evidence_raw=evidence_raw,
                external=(),
                grants=grants,
                hooks=hooks,
            )
        if prepared is not None:
            _fail("bundle prepared evidence disagrees with recomputed sources")
        core = _manifest_core(request.window, items)
        digest = hashlib.sha256(_canonical(core)).hexdigest()
        manifest = BundleManifest(request.window, items, digest)
        payload_raw = render_bundle_manifest(manifest)
        payload_sha = hashlib.sha256(payload_raw).hexdigest()
        payload, _ = self._publish_payload(
            name="bundle-payload-" + payload_sha[:24],
            filename=f"bundle-{digest}.json",
            raw=payload_raw,
        )
        marker_raw = _canonical(
            self._marker_payload(
                request_sha=request_sha, manifest=manifest, payload=payload
            ),
            maximum=_MAX_EVIDENCE,
        )
        marker, _ = self._publish_payload(
            name="bundle-marker-" + token[:24],
            filename=f"bundle-op-{token[:32]}.json",
            raw=marker_raw,
        )
        snapshot = self._commit_pre_event_anchor(
            snapshot=snapshot,
            operation_id=request.operation_id,
            request_sha=request_sha,
            marker=marker,
            payload=payload,
            batch_digest=digest,
            record_run_state=grants[3],
        )
        if hooks.after_payload_prepare is not None:
            hooks.after_payload_prepare()
        event, event_artifact = self._publish_event(
            capability=grants[2], run_id=checked_run, manifest=manifest, payload=payload
        )
        if hooks.after_event_publish is not None:
            hooks.after_event_publish()
        evidence = BundleRunEvidence(
            checked_run,
            request.operation_id,
            request_sha,
            snapshot.state_sha256,
            "emitted",
            len(items),
            digest,
            marker.state_ref,
            marker.sha256,
            payload.state_ref,
            payload.sha256,
            event_artifact.state_ref,
            event_artifact.sha256,
            str(event["event_id"]),
        )
        return self._commit_evidence(
            snapshot=snapshot,
            evidence=evidence,
            evidence_raw=render_bundle_run_evidence(evidence),
            external=(marker, payload, event_artifact),
            grants=grants,
            hooks=hooks,
        )
