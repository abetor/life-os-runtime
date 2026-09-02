"""P4-04 exact gateway subprocess, receipt, replay, and privacy contract."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import time

import pytest

import tool_life_os_runtime.ext.connectors.gateway.connector as gateway_module
from tool_life_os_runtime.ext.connectors.gateway import (
    GATEWAY_CONNECTOR_SCHEMA_VERSION,
    GATEWAY_DELIVERY_ACTION_ORDER,
    GatewayConnector,
    GatewayConnectorError,
    GatewayDeliveryCapabilities,
    GatewayDeliveryService,
)
from tool_life_os_runtime.ext.connectors.probes import DEFAULT_SPECS
from tool_life_os_runtime.ext.flows.ambient import (
    AmbientAvailability,
    AmbientCapabilities,
    AmbientFlow,
    AmbientRequest,
    AmbientReviewBudget,
)
from tool_life_os_runtime.ext.flows.plan import (
    DayPlan,
    PlanPolicy,
    PlanTask,
    render_day_plan,
)
from tool_life_os_runtime.ext.review.authority import AuthorityPolicy
from tool_life_os_runtime.ext.runs import OutboxStore, RunStore
from tool_life_os_runtime.ext.vault.config import load_vault_config
from tool_life_os_runtime.ext.vault.schema import VaultPathResolver


SPEC = next(item for item in DEFAULT_SPECS if item.tool == "gateway")
ZERO = "0" * 64
ONE = "1" * 64
VAULT_FIXTURE = Path(__file__).parent / "fixtures" / "vault-minimal"

FAKE = r"""#!/usr/bin/env python3
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

root = Path(os.environ["FAKE_GATEWAY_ROOT"])
mode_path = root / "mode.json"
mode = json.loads(mode_path.read_text("utf-8")) if mode_path.exists() else {}
args = sys.argv[1:]
stdin = sys.stdin.buffer.read()
with (root / "calls.jsonl").open("a", encoding="utf-8") as stream:
    stream.write(json.dumps({
        "argv": args,
        "stdin": stdin.decode("utf-8", "replace"),
        "allowed": os.environ.get("ALLOWED"),
        "forbidden_present": "FORBIDDEN" in os.environ,
    }, sort_keys=True) + "\n")

def emit(payload, code=0, *, duplicate=False):
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    if duplicate:
        raw = raw.replace('"schema_version":1', '"schema_version":1,"schema_version":1', 1)
    sys.stdout.write(raw + "\n")
    raise SystemExit(code)

def receipt(event, status, attempts, effect=None):
    return {
        "schema_version": 1,
        "event_id": event["event_id"],
        "dedupe_key": event["dedupe_key"],
        "status": status,
        "effect_sha256": effect if effect is not None else ("1" * 64 if status == "delivered" else "0" * 64),
        "attempts": attempts,
    }

if args == ["capabilities", "--json"]:
    time.sleep(mode.get("capability_delay", 0))
    raw_path = root / "capabilities.raw"
    if raw_path.exists():
        sys.stdout.write(raw_path.read_text("utf-8"))
        raise SystemExit(mode.get("capability_exit", 0))
    emit(json.loads((root / "capabilities.json").read_text("utf-8")), mode.get("capability_exit", 0))

operation = args[2] if len(args) >= 3 and args[0] == "--home" else ""
states = root / "states"
states.mkdir(exist_ok=True)

if operation == "dispatch-event":
    time.sleep(mode.get("dispatch_delay", 0))
    if mode.get("descendant_marker"):
        marker = mode["descendant_marker"]
        code = "import time; from pathlib import Path; time.sleep(0.8); Path(" + repr(marker) + ").write_text('survived','utf-8')"
        subprocess.Popen([sys.executable, "-c", code])
    if mode.get("dispatch_timeout"):
        time.sleep(60)
    if mode.get("stdout_overflow"):
        sys.stdout.write("S" * 70000)
        raise SystemExit(0)
    if mode.get("stderr_overflow"):
        sys.stderr.write("E" * 70000)
    if mode.get("raw_dispatch") is not None:
        sys.stdout.write(mode["raw_dispatch"])
        raise SystemExit(mode.get("dispatch_exit", 1))
    event = json.loads(stdin)
    event_hash = hashlib.sha256(json.dumps(event, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    state_path = states / (event["event_id"] + ".json")
    prior = json.loads(state_path.read_text("utf-8")) if state_path.exists() else None
    if prior is not None and prior["event_sha256"] != event_hash:
        emit({
            "schema_version": 1,
            "event_id": event["event_id"],
            "status": "error",
            "receipt": None,
            "replayed": False,
            "error": {"code": "event_conflict"},
        }, 1)
    if prior is not None and prior["receipt"]["status"] == "delivered":
        emit({
            "schema_version": 1,
            "event_id": event["event_id"],
            "status": "delivered",
            "receipt": prior["receipt"],
            "replayed": True,
        })
    if mode.get("dispatch_error"):
        emit({
            "schema_version": 1,
            "event_id": event["event_id"],
            "status": "error",
            "receipt": None,
            "replayed": False,
            "error": {"code": "invalid_config"},
        }, 1)
    status = mode.get("dispatch_status", "delivered")
    attempts = (prior["receipt"]["attempts"] if prior else 0) + 1
    current = receipt(event, status, attempts, mode.get("effect_sha256"))
    if mode.get("attempts_bool"):
        current["attempts"] = True
    if mode.get("dispatch_receipt_mismatch"):
        current["event_id"] = "event_" + "f" * 58
    state_path.write_text(json.dumps({"event_sha256": event_hash, "receipt": current}), "utf-8")
    response = {
        "schema_version": 1,
        "event_id": event["event_id"],
        "status": status,
        "receipt": current,
        "replayed": False,
    }
    exit_code = {"delivered": 0, "failed": 1, "retryable": 111}.get(status, 1)
    emit(response, exit_code, duplicate=bool(mode.get("duplicate_dispatch")))

if operation == "receipt":
    time.sleep(mode.get("receipt_delay", 0))
    event_id = args[3] if len(args) > 3 else ""
    if mode.get("raw_receipt") is not None:
        sys.stdout.write(mode["raw_receipt"])
        raise SystemExit(mode.get("receipt_exit", 1))
    state_path = states / (event_id + ".json")
    if mode.get("lookup_missing") or not state_path.exists():
        emit({
            "schema_version": 1,
            "event_id": event_id,
            "status": "not_found",
            "dedupe_key": None,
            "effect_sha256": None,
            "attempts": 0,
        }, 1)
    current = json.loads(state_path.read_text("utf-8"))["receipt"]
    if mode.get("lookup_receipt_mismatch"):
        current["dedupe_key"] = "sha256:" + "f" * 64
    emit(current, mode.get("receipt_exit", 0), duplicate=bool(mode.get("duplicate_receipt")))

emit({"schema_version": 1, "status": "error", "error": {"code": "bad_argv"}}, 1)
"""


def _canonical(value: object, *, newline: bool = True) -> bytes:
    raw = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return raw + (b"\n" if newline else b"")


def _capabilities(version: str = "0.1.0") -> dict[str, object]:
    return {
        "schema_version": 1,
        "tool": "gateway",
        "version": version,
        "capabilities": [item.to_dict() for item in SPEC.expected_capabilities],
    }


def _event(
    *,
    surface: str = "gated",
    requires_receipt: bool = True,
    summary: str = "Synthetic delivery is ready.",
) -> dict[str, object]:
    digest = hashlib.sha256(b"runtime-gateway-event").hexdigest()
    return {
        "schema_version": 1,
        "event_id": "event_" + digest[:58],
        "run_id": "run_gateway",
        "flow_id": "ambient",
        "action": {
            "action_id": "commit-nudge-outbox-event",
            "actor": "system",
            "authority": "internal-write",
            "target": "vault:agent/outbox",
        },
        "type": "ambient-nudge",
        "summary": summary,
        "artifact_ref": "review/synthetic-proposal.md",
        "artifact_sha256": ZERO,
        "urgency": "normal",
        "dedupe_key": "sha256:" + digest,
        "delivery_policy": {
            "surface": surface,
            "requires_receipt": requires_receipt,
        },
        "status": "pending",
        "created_at": "2026-01-15T09:00:00Z",
    }


def _write_mode(root: Path, **mode: object) -> None:
    root.joinpath("mode.json").write_text(json.dumps(mode), "utf-8")


def _setup(
    tmp_path: Path,
    *,
    timeout: float = 2.0,
    command: tuple[str, ...] | None = None,
) -> tuple[GatewayConnector, Path, Path]:
    root = tmp_path / "fake"
    root.mkdir()
    script = root / "fake_gateway.py"
    script.write_text(FAKE, "utf-8")
    root.joinpath("capabilities.json").write_text(json.dumps(_capabilities()), "utf-8")
    root.joinpath("calls.jsonl").write_text("", "utf-8")
    home = tmp_path / "gateway-home"
    home.mkdir()
    environment = {"FAKE_GATEWAY_ROOT": str(root), "ALLOWED": "selected"}
    connector = GatewayConnector(
        gateway_home=home,
        target="delivery",
        command=command or (sys.executable, str(script)),
        cwd=root,
        env=environment,
        timeout=timeout,
    )
    return connector, root, home


def _calls(root: Path) -> list[dict[str, object]]:
    return [
        json.loads(line)
        for line in root.joinpath("calls.jsonl").read_text("utf-8").splitlines()
    ]


def _source_files(
    tmp_path: Path, event: dict[str, object]
) -> tuple[Path, Path, bytes, bytes]:
    outbox = tmp_path / "vault/agent/outbox"
    artifact = tmp_path / "vault/review/synthetic-proposal.md"
    outbox.mkdir(parents=True)
    artifact.parent.mkdir(parents=True)
    event_path = outbox / f"{event['event_id']}.json"
    event_path.write_bytes(_canonical(event))
    artifact.write_bytes(b"Synthetic artifact remains authoritative.\n")
    return event_path, artifact, event_path.read_bytes(), artifact.read_bytes()


class _RecordingConnector(GatewayConnector):
    def __init__(
        self,
        inner: GatewayConnector,
        actions: list[str],
        *,
        crash_receipt_once: bool = False,
    ) -> None:
        self.inner = inner
        self.actions = actions
        self.crash_receipt_once = crash_receipt_once

    def deliver(self, event):
        self.actions.append("invoke-normalized-gateway-event")
        return self.inner.deliver(event)

    def receipt(self, event):
        self.actions.append("read-gateway-delivery-receipt")
        receipt = self.inner.receipt(event)
        if self.crash_receipt_once:
            self.crash_receipt_once = False
            raise RuntimeError("synthetic-crash")
        return receipt


class _RecordingOutboxStore(OutboxStore):
    def __init__(self, *args, actions: list[str], **kwargs) -> None:
        self.actions = actions
        self.crash_after_record_once = False
        super().__init__(*args, **kwargs)

    def read_for_delivery(self, capability, event_id):
        self.actions.append("read-semantic-outbox-event")
        return super().read_for_delivery(capability, event_id)

    def read_committed_for_delivery(self, capability, event_id):
        self.actions.append("read-semantic-outbox-event")
        return super().read_committed_for_delivery(capability, event_id)

    def record_delivery_receipt(self, capability, **kwargs):
        self.actions.append("reconcile-outbox-receipt")
        receipt = super().record_delivery_receipt(capability, **kwargs)
        if self.crash_after_record_once:
            self.crash_after_record_once = False
            raise RuntimeError("synthetic-crash")
        return receipt


def _delivery_capabilities(policy: AuthorityPolicy) -> GatewayDeliveryCapabilities:
    return GatewayDeliveryCapabilities(
        policy.issue(
            flow_id="gateway-delivery",
            action_id="read-semantic-outbox-event",
            actor="runtime",
            authority="read",
            target="vault:agent/outbox",
        ),
        policy.issue(
            flow_id="gateway-delivery",
            action_id="invoke-normalized-gateway-event",
            actor="runtime",
            authority="external-send",
            target="gateway:normalized-event-stdin",
        ),
        policy.issue(
            flow_id="gateway-delivery",
            action_id="read-gateway-delivery-receipt",
            actor="runtime",
            authority="read",
            target="gateway:delivery-receipt",
        ),
        policy.issue(
            flow_id="gateway-delivery",
            action_id="reconcile-outbox-receipt",
            actor="runtime",
            authority="internal-write",
            target="vault:agent/outbox",
        ),
    )


def _delivery_outbox(
    tmp_path: Path, actions: list[str]
) -> tuple[Path, _RecordingOutboxStore, AuthorityPolicy, dict[str, object]]:
    vault = tmp_path / "vault"
    shutil.copytree(VAULT_FIXTURE, vault)
    config = load_vault_config(vault / "lifeos.toml")
    resolver = VaultPathResolver(vault, config)

    now = datetime(2026, 1, 15, 9, tzinfo=timezone.utc)

    def clock() -> datetime:
        nonlocal now
        current = now
        now += timedelta(microseconds=1)
        return current

    run_store = RunStore(resolver, clock=clock)
    run_store.create(
        run_id="run_gateway",
        flow="ambient",
        phase="scan",
        authority="internal-write",
        executor="codex",
        input_data={"fixture": "gateway-delivery"},
    )
    run_store.resume("run_gateway", executor="codex")
    policy = AuthorityPolicy()
    plan = DayPlan(
        "2026-01-15",
        "active",
        1,
        PlanPolicy(10, 3),
        (
            PlanTask(
                "task-gateway",
                "Synthetic gateway delivery task",
                "2026-01-15",
                priority="high",
            ),
        ),
        "2026-01-15T08:00:00Z",
        "2026-01-15T08:00:00Z",
        "plan_gateway",
        ZERO,
    )
    day = vault / "tasks/days/2026-01-15.json"
    day.parent.mkdir(parents=True, exist_ok=True)
    day.write_bytes(render_day_plan(plan))

    def ambient_capability(action_id: str, authority: str, target: str):
        return policy.issue(
            flow_id="ambient",
            action_id=action_id,
            actor="system",
            authority=authority,
            target=target,
        )

    ambient_capabilities = AmbientCapabilities(
        ambient_capability("scan-eligible-signals", "read", "vault:tasks"),
        ambient_capability("read-ambient-projects", "read", "vault:projects"),
        ambient_capability("read-ambient-review", "read", "vault:review"),
        ambient_capability("read-ambient-memory", "read", "vault:agent/memory"),
        ambient_capability(
            "commit-nudge-outbox-event", "internal-write", "vault:agent/outbox"
        ),
        ambient_capability("record-run-state", "internal-write", "vault:agent/runs"),
    )
    request = AmbientRequest(
        "gateway_delivery",
        "2026-01-15T09:00:00Z",
        AmbientAvailability(
            "available",
            "2026-01-15T08:00:00Z",
            "2026-01-15T10:00:00Z",
        ),
        AmbientReviewBudget(10, 20),
    )
    with AmbientFlow(resolver, run_store, policy, clock) as ambient:
        emitted = ambient.scan(
            ambient_capabilities,
            run_id="run_gateway",
            request=request,
        )
    assert emitted.outcome == "emitted" and emitted.event_id is not None
    event = json.loads(
        (vault / "agent/outbox" / f"{emitted.event_id}.json").read_text("utf-8")
    )
    store = _RecordingOutboxStore(
        resolver,
        run_store,
        policy=policy,
        clock=clock,
        actions=actions,
    )
    return vault, store, policy, event


def test_runtime_delivery_uses_exact_four_actions_and_reconciles_idempotently(
    tmp_path: Path,
) -> None:
    actions: list[str] = []
    vault, store, policy, event = _delivery_outbox(tmp_path, actions)
    connector, _, _ = _setup(tmp_path)
    service = GatewayDeliveryService(
        outbox_store=store,
        connector=_RecordingConnector(connector, actions),
        policy=policy,
    )
    capabilities = _delivery_capabilities(policy)
    event_path = vault / "agent/outbox" / f"{event['event_id']}.json"
    artifact_path = vault / str(event["artifact_ref"])
    before = (event_path.read_bytes(), artifact_path.read_bytes())

    first = service.deliver(str(event["event_id"]), capabilities)
    second = service.deliver(str(event["event_id"]), capabilities)

    assert first.status == "delivered" and first.replayed is False
    assert second.replayed is True
    assert first.outbox_receipt_id == second.outbox_receipt_id
    assert first.attempt_id == second.attempt_id
    assert first.action_ids == GATEWAY_DELIVERY_ACTION_ORDER
    assert actions == list(GATEWAY_DELIVERY_ACTION_ORDER) * 2
    assert (
        hashlib.sha256(event_path.read_bytes()).hexdigest() == first.source_event_sha256
    )
    assert (event_path.read_bytes(), artifact_path.read_bytes()) == before
    assert json.loads(event_path.read_text("utf-8"))["status"] == "pending"
    assert len(list((vault / "agent/outbox/receipts").glob("receipt_*.json"))) == 1
    store.close()


def test_runtime_delivery_requires_a_stored_event_not_a_caller_mapping(
    tmp_path: Path,
) -> None:
    actions: list[str] = []
    vault, store, policy, event = _delivery_outbox(tmp_path, actions)
    connector, root, _ = _setup(tmp_path)
    service = GatewayDeliveryService(
        outbox_store=store,
        connector=_RecordingConnector(connector, actions),
        policy=policy,
    )
    capabilities = _delivery_capabilities(policy)
    changed = {**event, "summary": "Changed summary with the same identity."}

    with pytest.raises(GatewayConnectorError, match="gateway-outbox-read-failed"):
        service.deliver(changed, capabilities)  # type: ignore[arg-type]
    with pytest.raises(GatewayConnectorError, match="gateway-outbox-read-failed"):
        service.deliver("event_" + "f" * 58, capabilities)

    assert actions == ["read-semantic-outbox-event"] * 2
    assert _calls(root) == []
    assert not (vault / "agent/outbox/receipts").exists()
    store.close()


def test_runtime_delivery_rejects_canonical_event_payload_forgery_before_send(
    tmp_path: Path,
) -> None:
    actions: list[str] = []
    vault, store, policy, event = _delivery_outbox(tmp_path, actions)
    connector, root, _ = _setup(tmp_path)
    service = GatewayDeliveryService(
        outbox_store=store,
        connector=_RecordingConnector(connector, actions),
        policy=policy,
    )
    event_path = vault / "agent/outbox" / f"{event['event_id']}.json"
    forged = {**event, "summary": "Forged summary with unchanged event identity."}
    event_path.write_bytes(_canonical(forged))

    with pytest.raises(GatewayConnectorError, match="gateway-outbox-read-failed"):
        service.deliver(str(event["event_id"]), _delivery_capabilities(policy))

    assert actions == ["read-semantic-outbox-event"]
    assert _calls(root) == []
    assert not (vault / "agent/outbox/receipts").exists()
    store.close()


def test_runtime_delivery_rejects_noncanonical_event_bytes_before_send(
    tmp_path: Path,
) -> None:
    actions: list[str] = []
    vault, store, policy, event = _delivery_outbox(tmp_path, actions)
    connector, root, _ = _setup(tmp_path)
    service = GatewayDeliveryService(
        outbox_store=store,
        connector=_RecordingConnector(connector, actions),
        policy=policy,
    )
    event_path = vault / "agent/outbox" / f"{event['event_id']}.json"
    event_path.write_text(
        json.dumps(event, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        "utf-8",
    )

    with pytest.raises(GatewayConnectorError, match="gateway-outbox-read-failed"):
        service.deliver(str(event["event_id"]), _delivery_capabilities(policy))

    assert actions == ["read-semantic-outbox-event"]
    assert _calls(root) == []
    assert not (vault / "agent/outbox/receipts").exists()
    store.close()


def test_runtime_delivery_preflights_all_capabilities_before_read_or_send(
    tmp_path: Path,
) -> None:
    actions: list[str] = []
    _, store, policy, event = _delivery_outbox(tmp_path, actions)
    connector, root, _ = _setup(tmp_path)
    service = GatewayDeliveryService(
        outbox_store=store,
        connector=_RecordingConnector(connector, actions),
        policy=policy,
    )
    valid = _delivery_capabilities(policy)
    wrong = GatewayDeliveryCapabilities(
        valid.read_semantic_outbox_event,
        valid.read_semantic_outbox_event,
        valid.read_gateway_delivery_receipt,
        valid.reconcile_outbox_receipt,
    )

    with pytest.raises(
        GatewayConnectorError, match="invalid-gateway-delivery-capabilities"
    ):
        service.deliver(str(event["event_id"]), wrong)

    assert actions == []
    assert _calls(root) == []
    store.close()


def test_runtime_transient_preserves_pending_event_then_retries_exactly(
    tmp_path: Path,
) -> None:
    actions: list[str] = []
    vault, store, policy, event = _delivery_outbox(tmp_path, actions)
    connector, root, _ = _setup(tmp_path)
    service = GatewayDeliveryService(
        outbox_store=store,
        connector=_RecordingConnector(connector, actions),
        policy=policy,
    )
    capabilities = _delivery_capabilities(policy)
    event_path = vault / "agent/outbox" / f"{event['event_id']}.json"
    artifact_path = vault / str(event["artifact_ref"])
    before = (event_path.read_bytes(), artifact_path.read_bytes())
    _write_mode(root, dispatch_status="retryable")

    with pytest.raises(GatewayConnectorError, match="gateway-transient") as caught:
        service.deliver(str(event["event_id"]), capabilities)
    assert caught.value.retryable is True
    assert actions == list(GATEWAY_DELIVERY_ACTION_ORDER[:2])
    assert (event_path.read_bytes(), artifact_path.read_bytes()) == before
    assert not (vault / "agent/outbox/receipts").exists()

    _write_mode(root, dispatch_status="delivered")
    result = service.deliver(str(event["event_id"]), capabilities)
    assert result.status == "delivered"
    assert result.gateway_receipt.attempts == 2
    assert actions[2:] == list(GATEWAY_DELIVERY_ACTION_ORDER)
    assert (event_path.read_bytes(), artifact_path.read_bytes()) == before
    assert len(list((vault / "agent/outbox/receipts").glob("receipt_*.json"))) == 1
    store.close()


def test_runtime_permanent_failure_records_evidence_without_changing_source(
    tmp_path: Path,
) -> None:
    actions: list[str] = []
    vault, store, policy, event = _delivery_outbox(tmp_path, actions)
    connector, root, _ = _setup(tmp_path)
    service = GatewayDeliveryService(
        outbox_store=store,
        connector=_RecordingConnector(connector, actions),
        policy=policy,
    )
    capabilities = _delivery_capabilities(policy)
    event_path = vault / "agent/outbox" / f"{event['event_id']}.json"
    artifact_path = vault / str(event["artifact_ref"])
    before = (event_path.read_bytes(), artifact_path.read_bytes())
    _write_mode(root, dispatch_status="failed")

    result = service.deliver(str(event["event_id"]), capabilities)

    assert result.status == result.gateway_receipt.status == "failed"
    assert actions == list(GATEWAY_DELIVERY_ACTION_ORDER)
    assert (event_path.read_bytes(), artifact_path.read_bytes()) == before
    receipt = json.loads(
        (
            vault / "agent/outbox/receipts" / f"{result.outbox_receipt_id}.json"
        ).read_text("utf-8")
    )
    assert receipt["status"] == "failed"
    store.close()


def test_runtime_crash_after_receipt_replays_without_duplicate_reconciliation(
    tmp_path: Path,
) -> None:
    actions: list[str] = []
    vault, store, policy, event = _delivery_outbox(tmp_path, actions)
    connector, _, _ = _setup(tmp_path)
    recording = _RecordingConnector(connector, actions, crash_receipt_once=True)
    service = GatewayDeliveryService(
        outbox_store=store,
        connector=recording,
        policy=policy,
    )
    capabilities = _delivery_capabilities(policy)

    with pytest.raises(RuntimeError, match="synthetic-crash"):
        service.deliver(str(event["event_id"]), capabilities)
    assert actions == list(GATEWAY_DELIVERY_ACTION_ORDER[:3])
    assert not (vault / "agent/outbox/receipts").exists()

    recovered = service.deliver(str(event["event_id"]), capabilities)
    assert recovered.replayed is True
    assert actions[3:] == list(GATEWAY_DELIVERY_ACTION_ORDER)
    assert len(list((vault / "agent/outbox/receipts").glob("receipt_*.json"))) == 1
    store.close()


def test_runtime_crash_after_receipt_commit_reconciles_same_receipt(
    tmp_path: Path,
) -> None:
    actions: list[str] = []
    vault, store, policy, event = _delivery_outbox(tmp_path, actions)
    connector, _, _ = _setup(tmp_path)
    service = GatewayDeliveryService(
        outbox_store=store,
        connector=_RecordingConnector(connector, actions),
        policy=policy,
    )
    capabilities = _delivery_capabilities(policy)
    store.crash_after_record_once = True

    with pytest.raises(RuntimeError, match="synthetic-crash"):
        service.deliver(str(event["event_id"]), capabilities)
    receipts = vault / "agent/outbox/receipts"
    assert len(list(receipts.glob("receipt_*.json"))) == 1

    recovered = service.deliver(str(event["event_id"]), capabilities)
    assert recovered.replayed is True
    assert actions == list(GATEWAY_DELIVERY_ACTION_ORDER) * 2
    assert len(list(receipts.glob("receipt_*.json"))) == 1
    store.close()


def test_runtime_unavailable_is_private_and_leaves_event_retryable(
    tmp_path: Path,
) -> None:
    actions: list[str] = []
    vault, store, policy, event = _delivery_outbox(tmp_path, actions)
    missing = tmp_path / "private-token-must-not-appear"
    connector, _, _ = _setup(tmp_path, command=(str(missing),))
    service = GatewayDeliveryService(
        outbox_store=store,
        connector=_RecordingConnector(connector, actions),
        policy=policy,
    )
    event_path = vault / "agent/outbox" / f"{event['event_id']}.json"
    before = event_path.read_bytes()

    with pytest.raises(GatewayConnectorError) as caught:
        service.deliver(str(event["event_id"]), _delivery_capabilities(policy))

    assert caught.value.retryable is True
    assert str(missing) not in str(caught.value)
    assert actions == list(GATEWAY_DELIVERY_ACTION_ORDER[:2])
    assert event_path.read_bytes() == before
    assert not (vault / "agent/outbox/receipts").exists()
    store.close()


def test_deliver_sends_exact_canonical_event_and_reads_persistent_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    observed_processes: list[dict[str, object]] = []
    real_popen = gateway_module.subprocess.Popen

    def recording_popen(*args, **kwargs):
        observed_processes.append(dict(kwargs))
        return real_popen(*args, **kwargs)

    monkeypatch.setattr(gateway_module.subprocess, "Popen", recording_popen)
    monkeypatch.setenv("FORBIDDEN", "parent-secret-must-not-pass")
    connector, root, home = _setup(tmp_path)
    event = _event()

    delivered = connector.deliver(event)

    assert delivered.schema_version == GATEWAY_CONNECTOR_SCHEMA_VERSION
    assert delivered.status == "delivered" and delivered.replayed is False
    assert delivered.receipt.to_dict() == {
        "schema_version": 1,
        "event_id": event["event_id"],
        "dedupe_key": event["dedupe_key"],
        "status": "delivered",
        "effect_sha256": ONE,
        "attempts": 1,
    }
    calls = _calls(root)
    assert [item["argv"] for item in calls] == [
        ["capabilities", "--json"],
        ["--home", str(home), "dispatch-event", "--json"],
        ["--home", str(home), "receipt", event["event_id"], "--json"],
    ]
    normalized = json.loads(calls[1]["stdin"])
    assert normalized == {
        "schema_version": 1,
        "event_id": event["event_id"],
        "dedupe_key": event["dedupe_key"],
        "target": "delivery",
        "source": "runtime",
        "kind": "ambient-nudge",
        "text": "Synthetic delivery is ready.",
        "project": None,
        "ref": None,
    }
    assert calls[1]["stdin"].endswith("\n")
    assert event["run_id"] not in calls[1]["stdin"]
    assert event["artifact_ref"] not in calls[1]["stdin"]
    assert all(item["allowed"] == "selected" for item in calls)
    assert all(item["forbidden_present"] is False for item in calls)
    assert (
        delivered.source_event_sha256 == hashlib.sha256(_canonical(event)).hexdigest()
    )
    assert (
        delivered.gateway_event_sha256
        == hashlib.sha256(_canonical(normalized, newline=False)).hexdigest()
    )
    assert all(item["shell"] is False for item in observed_processes)
    assert all(item["start_new_session"] is True for item in observed_processes)


def test_delivered_replay_is_deduplicated_and_receipt_lookup_is_read_only(
    tmp_path: Path,
) -> None:
    connector, root, _ = _setup(tmp_path)
    event = _event()

    first = connector.deliver(event)
    second = connector.deliver(event)
    looked_up = connector.receipt(event)

    assert first.receipt == second.receipt == looked_up
    assert first.replayed is False and second.replayed is True
    assert second.receipt.attempts == 1
    assert len([call for call in _calls(root) if "dispatch-event" in call["argv"]]) == 2


def test_transient_then_retry_preserves_source_and_recovers_same_identity(
    tmp_path: Path,
) -> None:
    connector, root, _ = _setup(tmp_path)
    event = _event()
    event_path, artifact_path, event_before, artifact_before = _source_files(
        tmp_path, event
    )
    _write_mode(root, dispatch_status="retryable")

    with pytest.raises(GatewayConnectorError, match="gateway-transient") as caught:
        connector.deliver(event)

    assert caught.value.retryable is True
    assert caught.value.receipt is not None
    assert caught.value.receipt.status == "retryable"
    assert event_path.read_bytes() == event_before
    assert artifact_path.read_bytes() == artifact_before
    assert json.loads(event_path.read_text("utf-8"))["status"] == "pending"

    _write_mode(root, dispatch_status="delivered")
    recovered = connector.deliver(event)
    replay = connector.deliver(event)
    assert recovered.status == "delivered" and recovered.receipt.attempts == 2
    assert replay.replayed is True and replay.receipt == recovered.receipt
    assert event_path.read_bytes() == event_before
    assert artifact_path.read_bytes() == artifact_before


def test_valid_permanent_failure_returns_evidence_without_outbox_mutation(
    tmp_path: Path,
) -> None:
    connector, root, _ = _setup(tmp_path)
    event = _event()
    event_path, artifact_path, event_before, artifact_before = _source_files(
        tmp_path, event
    )
    _write_mode(root, dispatch_status="failed")

    result = connector.deliver(event)

    assert result.status == "failed"
    assert result.receipt.status == "failed"
    assert event_path.read_bytes() == event_before
    assert artifact_path.read_bytes() == artifact_before


def test_unavailable_gateway_is_retryable_and_preserves_source(tmp_path: Path) -> None:
    missing = tmp_path / "missing-gateway"
    connector, _, _ = _setup(tmp_path, command=(str(missing),))
    event = _event()
    event_path, artifact_path, event_before, artifact_before = _source_files(
        tmp_path, event
    )

    with pytest.raises(GatewayConnectorError, match="gateway-unavailable") as caught:
        connector.deliver(event)

    assert caught.value.category == "unavailable" and caught.value.retryable
    assert event_path.read_bytes() == event_before
    assert artifact_path.read_bytes() == artifact_before


def test_timeout_kills_process_group_and_preserves_source(tmp_path: Path) -> None:
    connector, root, _ = _setup(tmp_path, timeout=0.25)
    event = _event()
    event_path, artifact_path, event_before, artifact_before = _source_files(
        tmp_path, event
    )
    marker = tmp_path / "descendant-survived"
    _write_mode(root, dispatch_timeout=True, descendant_marker=str(marker))

    started = time.monotonic()
    with pytest.raises(GatewayConnectorError, match="gateway-timeout") as caught:
        connector.deliver(event)
    elapsed = time.monotonic() - started
    wait_until = time.monotonic() + 1.1
    while time.monotonic() < wait_until and not marker.exists():
        time.sleep(0.01)

    assert caught.value.retryable and elapsed < 0.6
    assert not marker.exists()
    assert event_path.read_bytes() == event_before
    assert artifact_path.read_bytes() == artifact_before


def test_one_deadline_bounds_handshake_and_dispatch_together(tmp_path: Path) -> None:
    connector, root, _ = _setup(tmp_path, timeout=0.2)
    _write_mode(root, capability_delay=0.12, dispatch_delay=0.12)

    started = time.monotonic()
    with pytest.raises(GatewayConnectorError, match="gateway-timeout"):
        connector.deliver(_event())

    assert 0.16 <= time.monotonic() - started < 0.48


def test_one_deadline_also_bounds_persistent_receipt_read(tmp_path: Path) -> None:
    connector, root, _ = _setup(tmp_path, timeout=0.65)
    _write_mode(
        root,
        capability_delay=0.1,
        dispatch_delay=0.1,
        receipt_delay=0.6,
    )

    started = time.monotonic()
    with pytest.raises(GatewayConnectorError, match="gateway-timeout") as caught:
        connector.deliver(_event())

    assert caught.value.retryable
    assert 0.58 <= time.monotonic() - started < 0.95
    assert len(_calls(root)) == 3


def test_parent_exit_with_descendant_pipe_is_bounded_and_group_is_killed(
    tmp_path: Path,
) -> None:
    connector, root, _ = _setup(tmp_path, timeout=0.4)
    marker = tmp_path / "detached-pipe-survived"
    _write_mode(root, descendant_marker=str(marker))

    started = time.monotonic()
    with pytest.raises(GatewayConnectorError, match="gateway-timeout"):
        connector.deliver(_event())
    wait_until = time.monotonic() + 1.1
    while time.monotonic() < wait_until and not marker.exists():
        time.sleep(0.01)

    assert time.monotonic() - started < 1.7
    assert not marker.exists()


def test_selector_setup_failure_reaps_process_and_returns_generic_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    connector, _, _ = _setup(tmp_path, timeout=0.3)
    real_popen = gateway_module.subprocess.Popen
    observed: dict[str, object] = {}

    def recording_popen(*args, **kwargs):
        process = real_popen(*args, **kwargs)
        observed["process"] = process
        return process

    def broken_selector():
        raise OSError("private selector diagnostic /private/path")

    monkeypatch.setattr(gateway_module.subprocess, "Popen", recording_popen)
    monkeypatch.setattr(gateway_module.selectors, "DefaultSelector", broken_selector)

    with pytest.raises(GatewayConnectorError, match="connector-process-io") as caught:
        connector.deliver(_event())

    process = observed["process"]
    assert getattr(process, "poll")() is not None
    assert "private" not in str(caught.value)


@pytest.mark.parametrize(
    ("mode", "expected"),
    [
        ({"dispatch_receipt_mismatch": True}, "gateway-receipt-identity-mismatch"),
        ({"lookup_receipt_mismatch": True}, "gateway-receipt-identity-mismatch"),
        ({"lookup_missing": True}, "gateway-persistent-receipt-mismatch"),
        ({"attempts_bool": True}, "invalid-gateway-receipt"),
        ({"effect_sha256": ZERO}, "invalid-gateway-receipt"),
        ({"duplicate_dispatch": True}, "duplicate-json-field"),
        ({"duplicate_receipt": True}, "duplicate-json-field"),
    ],
)
def test_receipt_and_dispatch_tampering_fails_closed(
    tmp_path: Path, mode: dict[str, object], expected: str
) -> None:
    connector, root, _ = _setup(tmp_path)
    _write_mode(root, **mode)

    with pytest.raises(GatewayConnectorError, match=expected):
        connector.deliver(_event())


@pytest.mark.parametrize("field", ["stdout_overflow", "stderr_overflow"])
def test_machine_output_is_bounded_and_not_reflected(
    tmp_path: Path, field: str
) -> None:
    connector, root, _ = _setup(tmp_path)
    private = "/private/source/path token=must-not-leak"
    mode: dict[str, object] = {field: True, "raw_dispatch": private}
    if field == "stderr_overflow":
        mode = {field: True, "raw_dispatch": private, "dispatch_exit": 1}
    _write_mode(root, **mode)

    with pytest.raises(GatewayConnectorError) as caught:
        connector.deliver(_event())

    rendered = str(caught.value)
    assert "private" not in rendered and "token" not in rendered
    assert caught.value.stdout_bytes <= 64 * 1024 + 1
    assert caught.value.stderr_bytes <= 64 * 1024 + 1


@pytest.mark.parametrize(
    "capabilities",
    [
        _capabilities("0.2.0"),
        {**_capabilities(), "schema_version": True},
        {**_capabilities(), "unknown": "field"},
        {
            **_capabilities(),
            "capabilities": list(reversed(_capabilities()["capabilities"])),
        },
    ],
)
def test_capability_drift_fails_before_dispatch(
    tmp_path: Path, capabilities: dict[str, object]
) -> None:
    connector, root, _ = _setup(tmp_path)
    root.joinpath("capabilities.json").write_text(json.dumps(capabilities), "utf-8")

    with pytest.raises(GatewayConnectorError, match="capability-contract-mismatch"):
        connector.deliver(_event())

    assert [item["argv"] for item in _calls(root)] == [["capabilities", "--json"]]


def test_duplicate_capability_json_fails_before_dispatch(tmp_path: Path) -> None:
    connector, root, _ = _setup(tmp_path)
    root.joinpath("capabilities.raw").write_text(
        '{"schema_version":1,"schema_version":1,"tool":"gateway",'
        '"version":"0.1.0","capabilities":[]}\n',
        "utf-8",
    )

    with pytest.raises(GatewayConnectorError, match="duplicate-json-field"):
        connector.deliver(_event())


@pytest.mark.parametrize(
    "event",
    [
        _event(surface="batched"),
        _event(requires_receipt=False),
        {**_event(), "schema_version": True},
        {**_event(), "summary": "token=private-value"},
        {**_event(), "summary": "see /users/private/note.md"},
        {**_event(), "summary": "bad\ud800surrogate"},
        {**_event(), "unknown": "field"},
    ],
)
def test_invalid_or_non_deliverable_outbox_event_has_no_effect(
    tmp_path: Path, event: dict[str, object]
) -> None:
    connector, root, home = _setup(tmp_path)

    with pytest.raises(GatewayConnectorError):
        connector.deliver(event)

    assert _calls(root) == []
    assert list(home.iterdir()) == []


def test_gateway_error_envelope_is_generic_and_does_not_query_receipt(
    tmp_path: Path,
) -> None:
    connector, root, _ = _setup(tmp_path)
    _write_mode(root, dispatch_error=True)

    with pytest.raises(
        GatewayConnectorError, match="gateway-dispatch-failed"
    ) as caught:
        connector.deliver(_event(summary="Safe bounded summary."))

    assert caught.value.category == "fatal"
    assert [item["argv"] for item in _calls(root)] == [
        ["capabilities", "--json"],
        [
            "--home",
            str(tmp_path / "gateway-home"),
            "dispatch-event",
            "--json",
        ],
    ]


def test_unexpected_gateway_exit_is_transient_without_parsing_private_output(
    tmp_path: Path,
) -> None:
    connector, root, _ = _setup(tmp_path)
    _write_mode(
        root,
        raw_dispatch='{"private":"/private/path","token":"secret"}\n',
        dispatch_exit=99,
    )

    with pytest.raises(GatewayConnectorError, match="gateway-transient") as caught:
        connector.deliver(_event())

    assert caught.value.retryable is True
    assert "private" not in str(caught.value)


def test_missing_receipt_lookup_is_read_only(tmp_path: Path) -> None:
    connector, root, home = _setup(tmp_path)
    before = os.stat(home)

    assert connector.receipt(_event()) is None

    after = os.stat(home)
    assert (before.st_dev, before.st_ino, before.st_mtime_ns, before.st_ctime_ns) == (
        after.st_dev,
        after.st_ino,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    assert [item["argv"] for item in _calls(root)] == [
        ["capabilities", "--json"],
        [
            "--home",
            str(home),
            "receipt",
            _event()["event_id"],
            "--json",
        ],
    ]


def test_replaced_gateway_home_is_rejected_before_process(tmp_path: Path) -> None:
    connector, root, home = _setup(tmp_path)
    saved = tmp_path / "gateway-home-saved"
    home.rename(saved)
    home.mkdir()

    with pytest.raises(GatewayConnectorError, match="connector-directory-moved"):
        connector.deliver(_event())

    assert _calls(root) == []


@pytest.mark.parametrize(
    "kwargs",
    [
        {"target": "../gateway"},
        {"target": "bad\ud800target"},
        {"command": ("tool-gateway", "--token=private")},
        {"timeout": True},
        {"timeout": 0.001},
        {"env": {"BAD=NAME": "value"}},
        {"env": {"GOOD": "bad\ud800value"}},
    ],
)
def test_constructor_rejects_unsafe_configuration(
    tmp_path: Path, kwargs: dict[str, object]
) -> None:
    root = tmp_path / "root"
    root.mkdir()
    home = tmp_path / "home"
    home.mkdir()
    base: dict[str, object] = {
        "gateway_home": home,
        "target": "delivery",
        "command": (sys.executable, "-c", "pass"),
        "cwd": root,
        "env": {},
    }

    with pytest.raises(GatewayConnectorError):
        GatewayConnector(**{**base, **kwargs})


def test_connector_never_imports_neighbor_package() -> None:
    source = Path(gateway_module.__file__).read_text("utf-8")
    assert "tool_gateway" not in source


def test_symlink_home_is_rejected(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)

    with pytest.raises(GatewayConnectorError, match="invalid-gateway-home"):
        GatewayConnector(
            gateway_home=link,
            target="delivery",
            command=(sys.executable, "-c", "pass"),
            cwd=tmp_path,
            env={},
        )


def test_command_literal_is_not_interpreted_by_a_shell(tmp_path: Path) -> None:
    marker = tmp_path / "shell-marker"
    connector, root, _ = _setup(
        tmp_path,
        command=(
            sys.executable,
            str(tmp_path / "fake/fake_gateway.py"),
            f"$(touch {marker})",
        ),
    )

    with pytest.raises(GatewayConnectorError):
        connector.deliver(_event())

    assert not marker.exists()
    assert _calls(root)[0]["argv"][0] == f"$(touch {marker})"


def test_no_gateway_files_are_packaged_from_sibling() -> None:
    package = Path(gateway_module.__file__).parent
    assert sorted(path.name for path in package.iterdir() if path.suffix == ".py") == [
        "__init__.py",
        "connector.py",
    ]
