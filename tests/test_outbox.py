"""P1-06 semantic outbox, dedupe, receipts, and crash replay."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import multiprocessing
import os
from pathlib import Path
import shutil

import pytest

from tool_life_os_runtime.ext.review.authority import AuthorityPolicy
from tool_life_os_runtime.ext.runs import (
    ActionUse,
    PreparedArtifact,
    RunError,
    RunStore,
    validate_receipt,
)
from tool_life_os_runtime.ext.runs import outbox as outbox_module
from tool_life_os_runtime.ext.runs.outbox import (
    OutboxError,
    OutboxStore,
    bound_receipt_effect_hash,
    semantic_dedupe_key,
    validate_event,
)
from tool_life_os_runtime.ext.vault.config import load_vault_config
from tool_life_os_runtime.ext.vault.schema import VaultPathResolver


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "vault-minimal"
ZERO_HASH = "0" * 64
ONE_HASH = "1" * 64


class _Clock:
    def __init__(self) -> None:
        self.value = datetime(2026, 1, 15, 9, 0, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        current = self.value
        self.value += timedelta(seconds=1)
        return current


def _stores(tmp_path: Path) -> tuple[Path, RunStore, OutboxStore, AuthorityPolicy]:
    vault = tmp_path / "vault"
    shutil.copytree(FIXTURE, vault)
    artifact = vault / "review/proposal.md"
    artifact.write_text("# Synthetic committed artifact\n", "utf-8")
    config = load_vault_config(vault / "lifeos.toml")
    resolver = VaultPathResolver(vault, config)
    run_store = RunStore(resolver, clock=_Clock())
    run_store.create(
        run_id="run_ambient",
        flow="ambient",
        phase="scan",
        authority="internal-write",
        executor="codex",
        input_data={},
    )
    policy = AuthorityPolicy()
    return vault, run_store, OutboxStore(
        resolver, run_store, policy=policy, clock=_Clock()
    ), policy


def _enqueue_capability(policy: AuthorityPolicy):
    return policy.issue(
        flow_id="ambient",
        action_id="commit-nudge-outbox-event",
        actor="system",
        authority="internal-write",
        target="vault:agent/outbox",
    )


def _read_capability(policy: AuthorityPolicy):
    return policy.issue(
        flow_id="gateway-delivery",
        action_id="read-semantic-outbox-event",
        actor="runtime",
        authority="read",
        target="vault:agent/outbox",
    )


def _receipt_capability(policy: AuthorityPolicy):
    return policy.issue(
        flow_id="gateway-delivery",
        action_id="reconcile-outbox-receipt",
        actor="runtime",
        authority="internal-write",
        target="vault:agent/outbox",
    )


def _enqueue(
    store: OutboxStore,
    policy: AuthorityPolicy,
    *,
    run_id: str = "run_ambient",
    summary: str = "Synthetic review needs a decision.",
    after_prepare=None,
    after_publish=None,
) -> dict[str, object]:
    return store.enqueue(
        _enqueue_capability(policy),
        run_id=run_id,
        event_type="review-ready",
        semantic_key="review:synthetic-proposal",
        summary=summary,
        artifact_zone="review",
        artifact_relative="proposal.md",
        urgency="normal",
        surface="gated",
        requires_receipt=True,
        after_prepare=after_prepare,
        after_publish=after_publish,
    )


def _child_enqueue(vault_text: str, crash_point: str) -> None:
    vault = Path(vault_text)
    config = load_vault_config(vault / "lifeos.toml")
    resolver = VaultPathResolver(vault, config)
    run_store = RunStore(resolver, clock=_Clock())
    policy = AuthorityPolicy()
    clock = _Clock()
    clock()
    store = OutboxStore(resolver, run_store, policy=policy, clock=clock)

    def hook() -> None:
        os._exit(83)

    _enqueue(
        store,
        policy,
        after_prepare=hook if crash_point == "prepare" else None,
        after_publish=hook if crash_point == "publish" else None,
    )


def test_semantic_key_is_deterministic_and_opaque() -> None:
    arguments = {
        "flow_id": "ambient",
        "event_type": "review-ready",
        "semantic_key": "review:synthetic-proposal",
        "artifact_ref": "review/proposal.md",
    }
    first = semantic_dedupe_key(**arguments)

    assert first == semantic_dedupe_key(**arguments)
    assert first.startswith("sha256:")
    assert "synthetic-proposal" not in first
    assert len(first) == 71


def test_enqueue_commits_exact_semantic_event_before_delivery(tmp_path) -> None:
    vault, _, store, policy = _stores(tmp_path)
    artifact_before = (vault / "review/proposal.md").read_bytes()

    event = _enqueue(store, policy)

    event_path = vault / "agent/outbox" / f"{event['event_id']}.json"
    assert json.loads(event_path.read_text("utf-8")) == event
    assert validate_event(event) == event
    assert event["action"] == {
        "action_id": "commit-nudge-outbox-event",
        "actor": "system",
        "authority": "internal-write",
        "target": "vault:agent/outbox",
    }
    assert event["status"] == "pending"
    assert event["artifact_ref"] == "review/proposal.md"
    assert event["artifact_sha256"] == hashlib.sha256(artifact_before).hexdigest()
    assert (vault / "review/proposal.md").read_bytes() == artifact_before
    assert not (vault / "agent/outbox/receipts").exists()
    assert not (vault / "agent/outbox/.recovery").exists()
    assert not list((vault / "agent/outbox").glob(".event_*.pending"))


def test_duplicate_invocation_creates_one_item_even_from_a_new_run(tmp_path) -> None:
    vault, run_store, store, policy = _stores(tmp_path)
    first = _enqueue(store, policy)
    run_store.create(
        run_id="run_ambient_retry",
        flow="ambient",
        phase="scan",
        authority="internal-write",
        executor="claude",
        input_data={},
    )

    replays = [
        _enqueue(store, policy, run_id="run_ambient_retry") for _ in range(12)
    ]

    assert replays == [first] * 12
    assert {event["run_id"] for event in replays} == {"run_ambient"}
    assert list((vault / "agent/outbox").glob("event_*.json")) == [
        vault / "agent/outbox" / f"{first['event_id']}.json"
    ]
    assert not (vault / "agent/outbox/.recovery").exists()
    assert not list((vault / "agent/outbox").glob(".event_*.pending"))


def test_same_dedupe_identity_with_changed_payload_fails_closed(tmp_path) -> None:
    vault, _, store, policy = _stores(tmp_path)
    event = _enqueue(store, policy)
    before = (vault / "agent/outbox" / f"{event['event_id']}.json").read_bytes()

    with pytest.raises(OutboxError, match="different event"):
        _enqueue(store, policy, summary="A conflicting summary.")

    assert (vault / "agent/outbox" / f"{event['event_id']}.json").read_bytes() == before


def test_gateway_read_requires_exact_read_capability(tmp_path) -> None:
    _, _, store, policy = _stores(tmp_path)
    event = _enqueue(store, policy)

    assert store.read_for_delivery(
        _read_capability(policy), str(event["event_id"])
    ) == event
    with pytest.raises(OutboxError, match="gateway outbox read"):
        store.read_for_delivery(
            _enqueue_capability(policy), str(event["event_id"])
        )


def test_failed_gateway_receipt_does_not_rollback_event_or_artifact(tmp_path) -> None:
    vault, _, store, policy = _stores(tmp_path)
    event = _enqueue(store, policy)
    event_path = vault / "agent/outbox" / f"{event['event_id']}.json"
    artifact_path = vault / "review/proposal.md"
    event_before = event_path.read_bytes()
    artifact_before = artifact_path.read_bytes()

    failed = store.record_delivery_receipt(
        _receipt_capability(policy),
        event_id=str(event["event_id"]),
        attempt_id="attempt_first",
        status="failed",
        effect_hash=ZERO_HASH,
    )

    assert validate_receipt(failed) == failed
    assert failed["status"] == "failed"
    assert failed["effect_hash"] == bound_receipt_effect_hash(
        event_sha256=hashlib.sha256(event_before).hexdigest(),
        gateway_effect_sha256=ZERO_HASH,
    )
    assert event_path.read_bytes() == event_before
    assert artifact_path.read_bytes() == artifact_before
    assert json.loads(
        (vault / "agent/outbox/receipts" / f"{failed['receipt_id']}.json").read_text("utf-8")
    ) == failed

    delivered = store.record_delivery_receipt(
        _receipt_capability(policy),
        event_id=str(event["event_id"]),
        attempt_id="attempt_retry",
        status="delivered",
        effect_hash=ONE_HASH,
    )
    assert delivered["status"] == "delivered"
    assert delivered["effect_hash"] == bound_receipt_effect_hash(
        event_sha256=hashlib.sha256(event_before).hexdigest(),
        gateway_effect_sha256=ONE_HASH,
    )
    assert delivered["receipt_id"] != failed["receipt_id"]
    assert len(list((vault / "agent/outbox/receipts").glob("*.json"))) == 2
    assert event_path.read_bytes() == event_before
    assert artifact_path.read_bytes() == artifact_before


def test_receipt_attempt_is_idempotent_but_conflicting_evidence_fails(tmp_path) -> None:
    _, _, store, policy = _stores(tmp_path)
    event = _enqueue(store, policy)
    arguments = {
        "event_id": str(event["event_id"]),
        "attempt_id": "attempt_first",
        "status": "failed",
        "effect_hash": ZERO_HASH,
    }

    first = store.record_delivery_receipt(_receipt_capability(policy), **arguments)
    assert store.record_delivery_receipt(
        _receipt_capability(policy), **arguments
    ) == first
    with pytest.raises(OutboxError, match="different event evidence"):
        store.record_delivery_receipt(
            _receipt_capability(policy),
            **{**arguments, "status": "delivered"},
        )


@pytest.mark.parametrize("crash_point", ["prepare", "publish"])
def test_process_exit_then_replay_has_one_semantic_item(tmp_path, crash_point) -> None:
    vault, _, store, policy = _stores(tmp_path)
    child = multiprocessing.Process(
        target=_child_enqueue, args=(str(vault), crash_point)
    )
    child.start()
    child.join(10)
    assert child.exitcode == 83

    event = _enqueue(store, policy)

    assert len(list((vault / "agent/outbox").glob("event_*.json"))) == 1
    assert validate_event(
        json.loads(
            (vault / "agent/outbox" / f"{event['event_id']}.json").read_text("utf-8")
        )
    ) == event
    assert not list((vault / "agent/outbox").glob(".event_*.pending"))
    assert not (vault / "agent/outbox/.recovery").exists()


def test_outbox_swap_does_not_publish_through_symlink(tmp_path, monkeypatch) -> None:
    vault, _, store, policy = _stores(tmp_path)
    outbox = vault / "agent/outbox"
    saved = vault / "agent/outbox-saved"
    outside = tmp_path / "outside"
    outside.mkdir()
    real_rename_noreplace = outbox_module._rename_noreplace
    swapped = False

    def swap_then_rename(directory_fd, source, destination):
        nonlocal swapped
        if destination.startswith("event_") and not swapped:
            swapped = True
            outbox.rename(saved)
            os.symlink(outside, outbox, target_is_directory=True)
        return real_rename_noreplace(directory_fd, source, destination)

    monkeypatch.setattr(outbox_module, "_rename_noreplace", swap_then_rename)
    with pytest.raises(OutboxError, match="changed during operation"):
        _enqueue(store, policy)

    assert list(outside.iterdir()) == []
    assert not list(saved.glob("event_*.json"))
    recovery = list((saved / ".recovery").glob("*.recovery"))
    assert len(recovery) == 1
    assert recovery[0].name.startswith("event-")


@pytest.mark.fresh_inode
def test_temp_cleanup_never_deletes_a_substituted_foreign_leaf(
    tmp_path, monkeypatch
) -> None:
    vault, _, store, policy = _stores(tmp_path)
    outbox = vault / "agent/outbox"
    foreign = b"foreign stage collision\n"

    def substitute_then_report_collision(directory_fd, source, destination):
        os.unlink(source, dir_fd=directory_fd)
        fd = os.open(
            source,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
            dir_fd=directory_fd,
        )
        with os.fdopen(fd, "wb") as handle:
            handle.write(foreign)
            handle.flush()
            os.fsync(handle.fileno())
        return False

    monkeypatch.setattr(
        outbox_module, "_rename_noreplace", substitute_then_report_collision
    )
    with pytest.raises(OutboxError, match="foreign leaf"):
        _enqueue(store, policy)

    stages = list(outbox.glob(".event_*.pending"))
    assert len(stages) == 1
    assert stages[0].read_bytes() == foreign
    assert any(
        path.read_bytes() == foreign
        for path in (outbox / ".recovery").glob("stage-*.recovery")
    )
    assert not list(outbox.glob("event_*.json"))


@pytest.mark.fresh_inode
def test_foreign_replacement_at_rollback_seam_is_preserved(
    tmp_path, monkeypatch
) -> None:
    vault, _, store, policy = _stores(tmp_path)
    outbox = vault / "agent/outbox"
    foreign = b"foreign collision\n"

    def substitute(directory_fd, name, identity, expected):
        os.unlink(name, dir_fd=directory_fd)
        fd = os.open(
            name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
            dir_fd=directory_fd,
        )
        with os.fdopen(fd, "wb") as handle:
            handle.write(foreign)
            handle.flush()
            os.fsync(handle.fileno())
        raise OutboxError("injected replacement")

    monkeypatch.setattr(store, "_revalidate_publication", substitute)
    with pytest.raises(OutboxError, match="could not be quarantined"):
        _enqueue(store, policy)

    event_files = list(outbox.glob("event_*.json"))
    assert len(event_files) == 1
    assert event_files[0].read_bytes() == foreign


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"summary": "/" + "Users" + "/private/note.md"}, "privacy-safe"),
        ({"summary": "line one\nline two"}, "privacy-safe"),
        ({"semantic_key": "/" + "home" + "/private"}, "privacy-safe"),
        ({"summary": "Author" + "ization: " + "Bea" + "rer synthetic-value"}, "credential"),
        ({"summary": "api_key=synthetic-value"}, "credential"),
        ({"semantic_key": "coo" + "kie: synthetic-value"}, "credential"),
        ({"semantic_key": "Bea" + "rer synthetic-value"}, "sensitive"),
        ({"summary": "Author" + "ization: " + "Bea" + "rer x"}, "credential"),
        ({"semantic_key": "x-api-key: x"}, "credential"),
        ({"artifact_relative": "../knowledge/note.md"}, "relative"),
        ({"requires_receipt": 1}, "boolean"),
    ],
)
def test_event_inputs_fail_closed(tmp_path, change, message) -> None:
    _, _, store, policy = _stores(tmp_path)
    arguments = {
        "run_id": "run_ambient",
        "event_type": "review-ready",
        "semantic_key": "review:synthetic-proposal",
        "summary": "Synthetic review needs a decision.",
        "artifact_zone": "review",
        "artifact_relative": "proposal.md",
        "requires_receipt": True,
    }
    arguments.update(change)

    with pytest.raises(OutboxError, match=message):
        store.enqueue(_enqueue_capability(policy), **arguments)


def test_symlink_artifact_is_rejected_before_event_commit(tmp_path) -> None:
    vault, _, store, policy = _stores(tmp_path)
    target = vault / "review/target.md"
    target.write_text("synthetic\n", "utf-8")
    (vault / "review/link.md").symlink_to(target.name)

    with pytest.raises(OutboxError, match="anchored safely"):
        store.enqueue(
            _enqueue_capability(policy),
            run_id="run_ambient",
            event_type="review-ready",
            semantic_key="review:symlink",
            summary="Synthetic review needs a decision.",
            artifact_zone="review",
            artifact_relative="link.md",
        )
    assert not list((vault / "agent/outbox").glob("event_*.json"))


def test_corrupt_existing_event_action_and_unknown_fields_fail_closed(tmp_path) -> None:
    vault, _, store, policy = _stores(tmp_path)
    event = _enqueue(store, policy)
    path = vault / "agent/outbox" / f"{event['event_id']}.json"
    corrupt = dict(event)
    corrupt["action"] = {**event["action"], "authority": "domain-write"}
    path.write_text(json.dumps(corrupt), "utf-8")

    with pytest.raises(OutboxError, match="canonical"):
        store.read_for_delivery(_read_capability(policy), str(event["event_id"]))

    corrupt = dict(event)
    corrupt["unexpected"] = True
    path.write_text(json.dumps(corrupt), "utf-8")
    with pytest.raises(OutboxError, match="unknown fields"):
        store.read_for_delivery(_read_capability(policy), str(event["event_id"]))


def test_capability_for_other_write_cannot_commit_outbox(tmp_path) -> None:
    _, _, store, policy = _stores(tmp_path)
    proposal = policy.issue(
        flow_id="distill",
        action_id="commit-review-proposal",
        actor="runtime",
        authority="proposal",
        target="vault:review",
    )

    with pytest.raises(OutboxError, match="outbox artifact commit"):
        store.enqueue(
            proposal,
            run_id="run_ambient",
            event_type="review-ready",
            semantic_key="review:synthetic-proposal",
            summary="Synthetic review needs a decision.",
            artifact_zone="review",
            artifact_relative="proposal.md",
        )


def test_capability_flow_must_match_authoritative_run_flow(tmp_path) -> None:
    vault, run_store, store, policy = _stores(tmp_path)
    run_store.create(
        run_id="run_apply",
        flow="apply",
        phase="verify",
        authority="protected-write",
        executor="codex",
        input_data={},
    )

    with pytest.raises(OutboxError, match="flow does not match"):
        _enqueue(store, policy, run_id="run_apply")

    assert not list((vault / "agent/outbox").glob("event_*.json"))


def test_single_finalize_emit_action_cannot_generalize_cross_flow_commit_or_delivery(
    tmp_path,
) -> None:
    vault, run_store, store, policy = _stores(tmp_path)
    run_store.create(
        run_id="run_distill",
        flow="distill",
        phase="validate",
        authority="proposal",
        executor="codex",
        input_data={},
    )
    run_store.resume("run_distill", executor="codex")
    log_dir = vault / "agent/logs/finalize"
    log_dir.mkdir()
    outcome = log_dir / "outcome.json"
    outcome.write_text('{"outcome":"review-ready"}\n', "utf-8")
    finalize = policy.issue(
        flow_id="finalize",
        action_id="emit-semantic-outbox-event",
        actor="runtime",
        authority="internal-write",
        target="vault:agent/outbox",
    )
    event = store.enqueue(
        finalize,
        run_id="run_distill",
        event_type="review-ready",
        semantic_key="finalize:run_distill:review-ready",
        summary="Review is ready for a decision.",
        artifact_zone="agent/logs",
        artifact_relative="finalize/outcome.json",
    )

    with pytest.raises(OutboxError, match="not yet bound"):
        store.read_for_delivery(_read_capability(policy), str(event["event_id"]))
    with pytest.raises(OutboxError, match="not yet bound"):
        store.record_delivery_receipt(
            _receipt_capability(policy),
            event_id=str(event["event_id"]),
            attempt_id="attempt_early",
            status="delivered",
            effect_hash=ZERO_HASH,
        )
    assert not (vault / "agent/outbox/receipts").exists()

    with pytest.raises(RunError, match="exact canonical finalize sequence"):
        run_store.commit_step(
            "run_distill",
            step_id="finalize-complete",
            authority="internal-write",
            input_hash=ZERO_HASH,
            output_hash=str(event["artifact_sha256"]),
            next_phase="finalized",
            next_status="succeeded",
            prepared_artifacts=(
                PreparedArtifact(
                    "finalize-event",
                    "agent/outbox",
                    f"{event['event_id']}.json",
                    f"agent/outbox/{event['event_id']}.json",
                    hashlib.sha256(
                        json.dumps(
                            event,
                            ensure_ascii=False,
                            sort_keys=True,
                            separators=(",", ":"),
                        ).encode("utf-8")
                        + b"\n"
                    ).hexdigest(),
                ),
            ),
            action_uses=(ActionUse(finalize),),
            authority_policy=policy,
        )

    assert run_store.status("run_distill")["status"] == "running"
    assert not (vault / "agent/runs/run_distill/intents/finalize-complete.json").exists()
    with pytest.raises(OutboxError, match="not yet bound"):
        store.read_for_delivery(_read_capability(policy), str(event["event_id"]))


def test_capability_cannot_exceed_immutable_run_authority(tmp_path) -> None:
    vault, run_store, store, policy = _stores(tmp_path)
    run_store.create(
        run_id="run_ambient_read_only",
        flow="ambient",
        phase="scan",
        authority="read",
        executor="codex",
        input_data={},
    )

    with pytest.raises(OutboxError, match="exceeds the immutable run authority"):
        _enqueue(store, policy, run_id="run_ambient_read_only")

    assert not list((vault / "agent/outbox").glob("event_*.json"))


def test_bound_vault_root_swap_cannot_redirect_event_to_replacement(
    tmp_path,
) -> None:
    vault, _, store, policy = _stores(tmp_path)
    replacement = tmp_path / "replacement"
    shutil.copytree(vault, replacement)
    original = tmp_path / "original-vault"
    vault.rename(original)
    replacement.rename(vault)

    with pytest.raises(OutboxError, match="root|anchored safely"):
        _enqueue(store, policy)

    assert not list((vault / "agent/outbox").glob("event_*.json"))
    assert not list((original / "agent/outbox").glob("event_*.json"))


def test_event_change_during_receipt_commit_is_detected_and_receipt_quarantined(
    tmp_path, monkeypatch
) -> None:
    vault, _, store, policy = _stores(tmp_path)
    event = _enqueue(store, policy)
    event_path = vault / "agent/outbox" / f"{event['event_id']}.json"
    real_create = outbox_module._create_json_once_at

    def create_then_mutate_event(directory_fd, name, payload):
        identity = real_create(directory_fd, name, payload)
        event_path.write_bytes(event_path.read_bytes() + b" ")
        return identity

    monkeypatch.setattr(
        outbox_module, "_create_json_once_at", create_then_mutate_event
    )
    with pytest.raises(OutboxError, match="changed during receipt"):
        store.record_delivery_receipt(
            _receipt_capability(policy),
            event_id=str(event["event_id"]),
            attempt_id="attempt_mutated",
            status="delivered",
            effect_hash=ONE_HASH,
        )

    receipts = vault / "agent/outbox/receipts"
    assert not list(receipts.glob("receipt_*.json"))
    assert len(list((receipts / ".recovery").glob("receipt-*.recovery"))) == 1


def test_outbox_and_run_store_cannot_be_bound_to_different_vaults(tmp_path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    shutil.copytree(FIXTURE, first)
    shutil.copytree(FIXTURE, second)
    first_resolver = VaultPathResolver(
        first, load_vault_config(first / "lifeos.toml")
    )
    second_resolver = VaultPathResolver(
        second, load_vault_config(second / "lifeos.toml")
    )

    with pytest.raises(OutboxError, match="share one vault"):
        OutboxStore(first_resolver, RunStore(second_resolver))
