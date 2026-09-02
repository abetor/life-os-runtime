"""P3-09 bounded lint, conservative fixes, and exact replay acceptance."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import itertools
import json
import os
from pathlib import Path
import shutil

import pytest

import tool_life_os_runtime.ext.flows.lint.flow as lint_module

from tool_life_os_runtime.ext.flows.lint import (
    LINT_ZONE_ORDER,
    LintCapabilities,
    LintCrashHooks,
    LintFlow,
    LintFlowError,
    LintLimits,
    LintRequest,
    LintReviewDecision,
    inspect_lint_run_evidence,
    lint_evidence_artifact_name,
    parse_lint_report,
    parse_lint_request,
    parse_lint_review,
    parse_lint_run_evidence,
    render_lint_report,
    render_lint_request,
    render_lint_review,
    render_lint_run_evidence,
)
from tool_life_os_runtime.ext.review.authority import AuthorityPolicy
from tool_life_os_runtime.ext.runs import RunStore
from tool_life_os_runtime.ext.vault.config import load_vault_config
from tool_life_os_runtime.ext.vault.schema import VaultPathResolver


FIXTURE = Path(__file__).parent / "fixtures/vault-minimal"
ZERO_HASH = "0" * 64
LINT_ACTIONS = (
    ("scan-inbox-zone", "read", "vault:inbox"),
    ("scan-non-archive-zones", "read", "vault:knowledge"),
    ("scan-task-zone", "read", "vault:tasks"),
    ("scan-project-zone", "read", "vault:projects"),
    ("scan-memory-zone", "read", "vault:agent/memory"),
    ("apply-allowlisted-inbox-fix", "domain-write", "vault:inbox"),
    ("apply-allowlisted-task-fix", "domain-write", "vault:tasks"),
    ("apply-allowlisted-project-fix", "domain-write", "vault:projects"),
    ("commit-semantic-lint-findings", "proposal", "vault:review"),
    ("record-run-state", "internal-write", "vault:agent/runs"),
)


class _Crash(RuntimeError):
    pass


class _Executor:
    def __init__(self, responder=None) -> None:
        self.packets: list[bytes] = []
        self._responder = responder

    def execute(self, packet: bytes):
        self.packets.append(packet)
        payload = json.loads(packet)
        findings = [] if self._responder is None else self._responder(payload)
        return {
            "schema_version": 1,
            "task_packet_sha256": hashlib.sha256(packet).hexdigest(),
            "findings": findings,
        }


def _note(title: str, marker: str = "Portable fixture text.") -> bytes:
    return (
        f'---\ntags:\n  - fixture\ndate: "2026-08-20"\n---\n\n# {title}\n\n{marker}\n'
    ).encode()


def _setup(
    tmp_path: Path,
    *,
    mode: str = "infra",
    apply_fixes: bool = False,
    zones: tuple[str, ...] = LINT_ZONE_ORDER,
    executor=None,
    limits: LintLimits | None = None,
):
    vault = tmp_path / "vault"
    shutil.copytree(FIXTURE, vault)
    resolver = VaultPathResolver(vault, load_vault_config(vault))
    policy = AuthorityPolicy()
    runs = RunStore(
        resolver,
        clock=lambda: datetime(2026, 8, 20, 12, tzinfo=timezone.utc),
    )
    request = LintRequest(
        1,
        "run_lint_one",
        mode,
        zones=zones,
        apply_fixes=apply_fixes,
    )
    runs.create(
        run_id=request.run_id,
        flow="lint",
        phase="scan",
        authority="domain-write",
        executor="fixture",
        input_data={
            "apply_fixes": apply_fixes,
            "mode": mode,
            "zones": list(zones),
        },
    )
    runs.resume(request.run_id, executor="fixture")
    issued = {
        action: policy.issue(
            flow_id="lint",
            action_id=action,
            actor="runtime",
            authority=authority,
            target=target,
        )
        for action, authority, target in LINT_ACTIONS
    }
    capabilities = LintCapabilities(*(issued[item[0]] for item in LINT_ACTIONS))
    flow = LintFlow(
        resolver,
        runs,
        policy,
        executor=executor,
        limits=limits,
    )
    return vault, resolver, policy, runs, request, capabilities, flow


def _anchor(span: dict[str, object]) -> dict[str, object]:
    return {
        key: span[key]
        for key in (
            "span_id",
            "path",
            "source_sha256",
            "span_sha256",
            "line_start",
            "line_end",
        )
    }


def _snapshot_sources(vault: Path) -> dict[str, bytes]:
    result = {}
    for zone in LINT_ZONE_ORDER:
        root = vault.joinpath(*zone.split("/"))
        for path in root.rglob("*"):
            if path.is_file() and not path.is_symlink():
                result[path.relative_to(vault).as_posix()] = path.read_bytes()
    return result


def _snapshot_vault_files(vault: Path) -> dict[str, bytes]:
    return {
        path.relative_to(vault).as_posix(): path.read_bytes()
        for path in vault.rglob("*")
        if path.is_file() and not path.is_symlink()
    }


def test_request_report_review_and_run_evidence_are_strict_canonical_v1(
    tmp_path: Path,
) -> None:
    vault, _, _, runs, request, capabilities, flow = _setup(tmp_path)
    (vault / "inbox/item.md").write_bytes(_note("Item"))

    assert parse_lint_request(render_lint_request(request)) == request
    result = flow.execute(request, capabilities=capabilities)
    assert parse_lint_report(render_lint_report(result.report)) == result.report
    assert result.proposal is None

    artifact = next(
        item
        for item in runs.snapshot(request.run_id).artifacts
        if item.name.startswith("lint-evidence-")
    )
    raw = vault.joinpath(*artifact.state_ref.split("/")).read_bytes()
    evidence = parse_lint_run_evidence(raw)
    assert render_lint_run_evidence(evidence) == raw
    assert inspect_lint_run_evidence(artifact, raw) == evidence

    with pytest.raises(LintFlowError, match="canonical JSON"):
        parse_lint_request(
            render_lint_request(request).replace(b'"mode":', b'"mode": ')
        )
    payload = json.loads(render_lint_request(request))
    payload["unknown"] = True
    with pytest.raises(LintFlowError, match="unknown fields"):
        parse_lint_request(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        )
    with pytest.raises(LintFlowError, match="duplicate"):
        parse_lint_request(b'{"schema_version":1,"schema_version":1}\n')


def test_report_and_run_evidence_reject_wrong_tuple_types_and_duplicates(
    tmp_path: Path,
) -> None:
    vault, _, _, runs, request, capabilities, flow = _setup(
        tmp_path,
        apply_fixes=True,
    )
    (vault / "inbox/item.md").write_bytes(_note("Item").rstrip())
    result = flow.execute(request, capabilities=capabilities)
    report = result.report

    with pytest.raises(LintFlowError, match="findings are invalid"):
        render_lint_report(replace(report, findings=list(report.findings)))
    duplicate_source = tuple(
        sorted(
            (*report.sources, report.sources[0]),
            key=lambda item: (
                LINT_ZONE_ORDER.index(item.zone),
                item.path.casefold(),
                item.path,
            ),
        )
    )
    duplicate_source_payload = [
        lint_module._source_payload(item) for item in duplicate_source
    ]
    with pytest.raises(LintFlowError, match="sources collide"):
        render_lint_report(
            replace(
                report,
                sources=duplicate_source,
                source_bundle_sha256=lint_module._digest(duplicate_source_payload),
            )
        )
    with pytest.raises(LintFlowError, match="finding ids collide"):
        render_lint_report(
            replace(report, findings=(*report.findings, report.findings[0]))
        )

    artifact = next(
        item
        for item in runs.snapshot(request.run_id).artifacts
        if item.name.startswith("lint-evidence-")
    )
    evidence = parse_lint_run_evidence(
        vault.joinpath(*artifact.state_ref.split("/")).read_bytes()
    )
    with pytest.raises(LintFlowError, match="receipts are invalid"):
        render_lint_run_evidence(replace(evidence, receipts=list(evidence.receipts)))
    with pytest.raises(LintFlowError, match="receipts collide"):
        render_lint_run_evidence(
            replace(evidence, receipts=(*evidence.receipts, evidence.receipts[0]))
        )

    report_payload = json.loads(render_lint_report(report))
    report_payload["schema_version"] = True
    with pytest.raises(LintFlowError, match="report is invalid"):
        parse_lint_report(lint_module._canonical(report_payload, 4 * 1024 * 1024))
    evidence_payload = json.loads(render_lint_run_evidence(evidence))
    evidence_payload["schema_version"] = True
    with pytest.raises(LintFlowError, match="run evidence is invalid"):
        parse_lint_run_evidence(
            lint_module._canonical(evidence_payload, 4 * 1024 * 1024)
        )


def test_infra_scans_exact_five_zones_and_only_normalizes_allowlisted_notes(
    tmp_path: Path,
) -> None:
    vault, _, _, runs, request, capabilities, flow = _setup(tmp_path, apply_fixes=True)
    originals = {}
    for zone in ("inbox", "tasks", "projects", "knowledge", "agent/memory"):
        path = vault.joinpath(*zone.split("/"), "active.md")
        data = b"\xef\xbb\xbf" + _note(zone).replace(b"\n", b"\r\n").rstrip(b"\r\n")
        path.write_bytes(data)
        originals[zone] = data
    (vault / "tasks/days").mkdir()
    (vault / "tasks/days/runtime.md").write_bytes(_note("Runtime").rstrip())
    (vault / "projects/p").mkdir()
    (vault / "projects/p/log.md").write_bytes(_note("Log").rstrip())
    (vault / "knowledge/_archive").mkdir()
    (vault / "knowledge/_archive/ignored.md").write_bytes(b"private ignored bytes")
    (vault / "agent/reading").mkdir()
    (vault / "agent/reading/outside.md").write_bytes(b"outside current matrix")
    (vault / "agent/logs/outside.md").write_bytes(b"outside current matrix")

    result = flow.execute(request, capabilities=capabilities)

    fixed = {receipt.path for receipt in result.receipts}
    assert fixed == {"inbox/active.md", "tasks/active.md", "projects/active.md"}
    for zone in ("inbox", "tasks", "projects"):
        path = vault.joinpath(*zone.split("/"), "active.md")
        assert path.read_bytes() == _note(zone)
    for zone in ("knowledge", "agent/memory"):
        path = vault.joinpath(*zone.split("/"), "active.md")
        assert path.read_bytes() == originals[zone]
    assert (vault / "tasks/days/runtime.md").read_bytes() == _note("Runtime").rstrip()
    assert (vault / "projects/p/log.md").read_bytes() == _note("Log").rstrip()
    source_paths = {source.path for source in result.report.sources}
    assert "knowledge/_archive/ignored.md" not in source_paths
    assert not any(path.startswith("agent/reading/") for path in source_paths)
    assert not any(path.startswith("agent/logs/") for path in source_paths)
    assert result.proposal is not None
    proposal_path = vault / f"review/{result.proposal.proposal_id}.lint.json"
    assert parse_lint_review(proposal_path.read_bytes()) == result.proposal
    assert not list(vault.glob(".lifeos/review-plans/*lint*"))

    action_ids = [
        action["action_id"]
        for event in runs.trace_events(request.run_id)
        for action in event["actions"]
    ]
    assert action_ids[-7:] == [
        "scan-inbox-zone",
        "scan-non-archive-zones",
        "scan-task-zone",
        "scan-project-zone",
        "scan-memory-zone",
        "commit-semantic-lint-findings",
        "record-run-state",
    ]


def test_apply_false_and_nonmarkdown_domain_files_are_never_rewritten(
    tmp_path: Path,
) -> None:
    vault, _, _, _, request, capabilities, flow = _setup(tmp_path)
    (vault / "inbox/item.md").write_bytes(_note("Item").rstrip())
    (vault / "projects/project.json").write_bytes(b'{"opaque":true}\n')
    before = _snapshot_sources(vault)

    result = flow.execute(request, capabilities=capabilities)

    assert result.receipts == ()
    assert _snapshot_sources(vault) == before
    assert any(item.rule_id == "infra.final-newline" for item in result.report.findings)


def test_public_plan_and_memory_parsers_are_applied_to_owned_machine_files(
    tmp_path: Path,
) -> None:
    vault, _, _, _, request, capabilities, flow = _setup(tmp_path)
    (vault / "tasks/days").mkdir()
    (vault / "tasks/days/2026-08-20.json").write_bytes(b"{}\n")
    (vault / "agent/memory/metadata/records").mkdir(parents=True)
    (vault / "agent/memory/metadata/records/mem-invalid.json").write_bytes(b"{}\n")

    result = flow.execute(request, capabilities=capabilities)

    invalid_paths = {
        item.anchors[0].path
        for item in result.report.findings
        if item.rule_id == "infra.domain.invalid"
    }
    assert invalid_paths == {
        "tasks/days/2026-08-20.json",
        "agent/memory/metadata/records/mem-invalid.json",
    }


def test_content_is_full_coverage_per_file_with_exact_supplied_anchors(
    tmp_path: Path,
) -> None:
    def responder(packet):
        return [
            {
                "rule_id": "content.unresolved-placeholder",
                "severity": "warning",
                "anchors": [_anchor(packet["spans"][0])],
            }
        ]

    executor = _Executor(responder)
    vault, _, _, runs, request, capabilities, flow = _setup(
        tmp_path, mode="content", executor=executor
    )
    first = _note("First", "UNIQUE-FIRST-MARKER")
    second = _note("Second", "UNIQUE-SECOND-MARKER")
    (vault / "inbox/a.md").write_bytes(first)
    (vault / "inbox/b.md").write_bytes(second)

    result = flow.execute(request, capabilities=capabilities)

    assert len(executor.packets) == 2
    assert len(result.report.batch_ids) == 2
    packet_paths = {
        span["path"] for raw in executor.packets for span in json.loads(raw)["spans"]
    }
    assert packet_paths == {"inbox/a.md", "inbox/b.md"}
    assert all(
        item.mode == "content" and len(item.anchors) == 1
        for item in result.report.findings
    )
    assert result.proposal is not None
    assert result.proposal.report_ref.endswith(".json")
    report_raw = render_lint_report(result.report)
    trace_raw = json.dumps(runs.trace_events(request.run_id)).encode()
    for marker in (b"UNIQUE-FIRST-MARKER", b"UNIQUE-SECOND-MARKER"):
        assert marker not in report_raw
        assert marker not in trace_raw

    replay = flow.execute(request, capabilities=capabilities)
    assert replay.replayed
    assert len(executor.packets) == 2


def test_long_utf8_line_is_split_without_sampling_or_byte_loss(
    tmp_path: Path,
) -> None:
    executor = _Executor()
    limits = LintLimits(
        max_file_bytes=4096,
        max_total_bytes=4096,
        max_span_bytes=64,
        max_packet_bytes=2048,
        max_context_bytes=8192,
    )
    vault, _, _, _, request, capabilities, flow = _setup(
        tmp_path,
        mode="content",
        executor=executor,
        limits=limits,
    )
    raw = _note("Long", "αβγδε" * 80)
    (vault / "inbox/long.md").write_bytes(raw)

    flow.execute(request, capabilities=capabilities)

    spans = [
        span for packet in executor.packets for span in json.loads(packet)["spans"]
    ]
    assert b"".join(span["text"].encode() for span in spans) == raw
    assert all(len(span["text"].encode()) <= limits.max_span_bytes for span in spans)


def test_deep_accepts_multi_source_anchor_and_rejects_forged_or_single_source(
    tmp_path: Path,
) -> None:
    def responder(packet):
        return [
            {
                "rule_id": "deep.cross-source-conflict",
                "severity": "error",
                "anchors": [_anchor(span) for span in packet["spans"][:2]],
            }
        ]

    executor = _Executor(responder)
    vault, _, _, _, request, capabilities, flow = _setup(
        tmp_path, mode="deep", executor=executor
    )
    (vault / "inbox/a.md").write_bytes(_note("A"))
    (vault / "inbox/b.md").write_bytes(_note("B"))
    result = flow.execute(request, capabilities=capabilities)
    deep = [item for item in result.report.findings if item.mode == "deep"]
    assert len(deep) == 1
    assert {anchor.path for anchor in deep[0].anchors} == {
        "inbox/a.md",
        "inbox/b.md",
    }

    def invalid(packet):
        return [
            {
                "rule_id": "deep.cross-source-conflict",
                "severity": "error",
                "anchors": [_anchor(packet["spans"][0])],
            }
        ]

    other = tmp_path / "other"
    executor = _Executor(invalid)
    vault, _, _, _, request, capabilities, flow = _setup(
        other, mode="deep", executor=executor
    )
    (vault / "inbox/a.md").write_bytes(_note("A"))
    (vault / "inbox/b.md").write_bytes(_note("B"))
    with pytest.raises(LintFlowError, match="two exact sources"):
        flow.execute(request, capabilities=capabilities)


def test_executor_output_is_canonical_bounded_and_cannot_forge_an_anchor(
    tmp_path: Path,
) -> None:
    class Forged:
        def execute(self, packet):
            payload = json.loads(packet)
            span = _anchor(payload["spans"][0])
            span["source_sha256"] = ZERO_HASH
            value = {
                "schema_version": 1,
                "task_packet_sha256": hashlib.sha256(packet).hexdigest(),
                "findings": [
                    {
                        "rule_id": "content.duplicate",
                        "severity": "error",
                        "anchors": [span],
                    }
                ],
            }
            return json.dumps(value, indent=2)

    vault, _, _, _, request, capabilities, flow = _setup(
        tmp_path,
        mode="content",
        executor=Forged(),
    )
    (vault / "inbox/a.md").write_bytes(_note("A"))
    with pytest.raises(LintFlowError, match="canonical JSON"):
        flow.execute(request, capabilities=capabilities)


def test_symlink_is_a_finding_and_total_source_bound_fails_closed(
    tmp_path: Path,
) -> None:
    vault, _, _, _, request, capabilities, flow = _setup(tmp_path)
    outside = tmp_path / "outside.md"
    outside.write_bytes(b"must not be read")
    os.symlink(outside, vault / "inbox/link.md")
    result = flow.execute(request, capabilities=capabilities)
    assert any(
        item.rule_id == "infra.entry.unsupported" for item in result.report.findings
    )
    assert all(source.path != "inbox/link.md" for source in result.report.sources)

    other = tmp_path / "bounded"
    limits = LintLimits(max_file_bytes=64, max_total_bytes=8)
    vault, _, _, _, request, capabilities, flow = _setup(other, limits=limits)
    (vault / "inbox/a.txt").write_bytes(b"123456")
    (vault / "inbox/b.txt").write_bytes(b"abcdef")
    with pytest.raises(LintFlowError, match="source bytes"):
        flow.execute(request, capabilities=capabilities)


@pytest.mark.parametrize("seam", ["after_fix_prepare", "after_fix_publish"])
def test_direct_fix_recovers_exactly_at_both_crash_seams(
    tmp_path: Path, seam: str
) -> None:
    vault, _, _, runs, request, capabilities, flow = _setup(tmp_path, apply_fixes=True)
    path = vault / "inbox/a.md"
    path.write_bytes(_note("A").rstrip())
    hooks = LintCrashHooks(**{seam: lambda: (_ for _ in ()).throw(_Crash())})

    with pytest.raises(_Crash):
        flow.execute(request, capabilities=capabilities, crash_hooks=hooks)

    recovered = flow.execute(request, capabilities=capabilities)
    assert recovered.replayed
    assert path.read_bytes() == _note("A")
    assert len(recovered.receipts) == 1
    assert recovered.receipts[0].status in {"applied", "already-applied"}
    assert not list((vault / "inbox").glob(".lifeos-lint-*.slot"))
    assert runs.status(request.run_id)["phase"] == "lint-report-committed"


def test_precondition_change_keeps_foreign_bytes_and_moves_finding_to_review(
    tmp_path: Path,
) -> None:
    vault, _, _, _, request, capabilities, flow = _setup(tmp_path, apply_fixes=True)
    path = vault / "inbox/a.md"
    path.write_bytes(_note("A").rstrip())
    foreign = _note("Foreign")

    result = flow.execute(
        request,
        capabilities=capabilities,
        crash_hooks=LintCrashHooks(after_fix_prepare=lambda: path.write_bytes(foreign)),
    )

    assert path.read_bytes() == foreign
    assert result.receipts[0].status == "precondition-changed"
    attempted = [item for item in result.report.findings if item.fix is not None]
    assert attempted and all(item.resolution == "review" for item in attempted)
    assert result.proposal is not None


def test_recovery_does_not_adapt_a_pending_fix_to_new_foreign_bytes(
    tmp_path: Path,
) -> None:
    vault, _, _, _, request, capabilities, flow = _setup(tmp_path, apply_fixes=True)
    path = vault / "inbox/a.md"
    path.write_bytes(_note("A").rstrip())
    foreign = _note("Foreign").rstrip()

    def replace_then_crash() -> None:
        path.write_bytes(foreign)
        raise _Crash

    with pytest.raises(_Crash):
        flow.execute(
            request,
            capabilities=capabilities,
            crash_hooks=LintCrashHooks(after_fix_prepare=replace_then_crash),
        )

    recovered = flow.execute(request, capabilities=capabilities)
    assert path.read_bytes() == foreign
    assert recovered.receipts[0].status == "precondition-changed"
    assert all(item.resolution == "review" for item in recovered.report.findings)


def test_leaf_race_during_exchange_is_rolled_back_to_foreign_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    vault, _, _, _, request, capabilities, flow = _setup(tmp_path, apply_fixes=True)
    path = vault / "inbox/a.md"
    path.write_bytes(_note("A").rstrip())
    foreign = _note("Foreign concurrent writer")
    original_exchange = lint_module._rename_exchange
    raced = False

    def race(parent_fd: int, slot: str, leaf: str) -> None:
        nonlocal raced
        if not raced:
            raced = True
            fd = os.open(leaf, os.O_WRONLY | os.O_TRUNC, dir_fd=parent_fd)
            try:
                os.write(fd, foreign)
                os.fsync(fd)
            finally:
                os.close(fd)
        original_exchange(parent_fd, slot, leaf)

    monkeypatch.setattr(lint_module, "_rename_exchange", race)
    with pytest.raises(LintFlowError, match="exchange cannot be verified"):
        flow.execute(request, capabilities=capabilities)
    assert path.read_bytes() == foreign


def test_prepared_final_evidence_recovers_after_proposal_publication_crash(
    tmp_path: Path,
) -> None:
    vault, _, _, runs, request, capabilities, flow = _setup(tmp_path)
    (vault / "inbox/bad.md").write_bytes(b"# Missing frontmatter\n")

    with pytest.raises(_Crash):
        flow.execute(
            request,
            capabilities=capabilities,
            crash_hooks=LintCrashHooks(
                after_proposal_publish=lambda: (_ for _ in ()).throw(_Crash())
            ),
        )

    recovered = flow.execute(request, capabilities=capabilities)
    assert recovered.replayed
    assert recovered.proposal is not None
    assert (
        parse_lint_review(
            vault.joinpath(
                *("review/" + recovered.proposal.proposal_id + ".lint.json").split("/")
            ).read_bytes()
        )
        == recovered.proposal
    )
    assert runs.status(request.run_id)["phase"] == "lint-report-committed"


def test_prepared_final_recovery_preflights_proposal_capability_before_any_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    vault, _, policy, runs, request, capabilities, flow = _setup(tmp_path)
    (vault / "inbox/bad.md").write_bytes(b"# Missing frontmatter\n")
    original_publish = flow._publish_review

    monkeypatch.setattr(
        flow,
        "_publish_review",
        lambda _value: (_ for _ in ()).throw(_Crash()),
    )
    with pytest.raises(_Crash):
        flow.execute(request, capabilities=capabilities)
    monkeypatch.setattr(flow, "_publish_review", original_publish)

    before_state = runs.snapshot(request.run_id).state_sha256
    before_review = {
        path.name: path.read_bytes() for path in (vault / "review").iterdir()
    }
    wrong = policy.issue(
        flow_id="lint",
        action_id="record-run-state",
        actor="runtime",
        authority="internal-write",
        target="vault:agent/runs",
    )
    with pytest.raises(
        LintFlowError,
        match="capability does not authorize lint action commit-semantic-lint-findings",
    ):
        flow.execute(
            request,
            capabilities=replace(
                capabilities,
                commit_semantic_lint_findings=wrong,
            ),
        )

    assert runs.snapshot(request.run_id).state_sha256 == before_state
    assert {
        path.name: path.read_bytes() for path in (vault / "review").iterdir()
    } == before_review
    assert not list((vault / "review").glob("lintprop-*.lint.json"))


@pytest.mark.parametrize(
    "mutation",
    ["mode", "run-id", "request-binding", "apply-fixes"],
)
def test_prepared_final_evidence_rejects_request_field_matrix_before_commit(
    tmp_path: Path,
    mutation: str,
) -> None:
    vault, _, _, runs, request, capabilities, flow = _setup(tmp_path)

    with pytest.raises(_Crash):
        flow.execute(
            request,
            capabilities=capabilities,
            crash_hooks=LintCrashHooks(
                before_run_commit=lambda: (_ for _ in ()).throw(_Crash())
            ),
        )

    run_directory = vault / f"agent/runs/{request.run_id}"
    evidence_path = next(run_directory.glob("lint-evidence-*.json"))
    evidence = parse_lint_run_evidence(evidence_path.read_bytes())
    report = evidence.report
    if mutation == "mode":
        report = replace(report, mode="content")
        evidence = replace(evidence, report=report)
    elif mutation == "run-id":
        report = replace(report, run_id="run_lint_other")
        evidence = replace(evidence, report=report)
    elif mutation == "request-binding":
        request_hash = "1" * 64
        operation_id = lint_module._operation(request_hash)
        report = replace(
            report,
            operation_id=operation_id,
            request_sha256=request_hash,
        )
        evidence = replace(
            evidence,
            operation_id=operation_id,
            request_sha256=request_hash,
            report=report,
        )
    elif mutation == "apply-fixes":
        precondition = "2" * 64
        postcondition = "3" * 64
        transforms = ("append-final-newline",)
        fix_id = (
            "lint-fix-"
            + lint_module._digest(
                {
                    "path": "inbox/forged.md",
                    "post": postcondition,
                    "pre": precondition,
                    "transforms": list(transforms),
                }
            )[:32]
        )
        fix = lint_module.LintFix(
            fix_id,
            "infra.text.normalization",
            "inbox",
            "inbox/forged.md",
            precondition,
            postcondition,
            transforms,
        )
        finding = lint_module._finding(
            mode="infra",
            rule="infra.final-newline",
            anchors=(
                lint_module.LintEvidenceAnchor(
                    "inbox/forged.md",
                    precondition,
                ),
            ),
            fix=fix,
            resolution="auto-fixed",
        )
        receipt = lint_module.LintFixReceipt(
            fix_id,
            "inbox/forged.md",
            precondition,
            postcondition,
            "applied",
        )
        report = replace(report, status="findings", findings=(finding,))
        evidence = replace(evidence, report=report, receipts=(receipt,))
    else:  # pragma: no cover - the parameter list is closed above
        raise AssertionError(mutation)
    evidence_path.write_bytes(render_lint_run_evidence(evidence))

    before_state = runs.snapshot(request.run_id).state_sha256
    before_review = {
        path.name: path.read_bytes() for path in (vault / "review").iterdir()
    }
    with pytest.raises(LintFlowError, match="conflicts with this request"):
        flow.execute(request, capabilities=capabilities)

    assert runs.snapshot(request.run_id).state_sha256 == before_state
    assert {
        path.name: path.read_bytes() for path in (vault / "review").iterdir()
    } == before_review
    assert not any(
        item.name.startswith("lint-evidence-")
        for item in runs.snapshot(request.run_id).artifacts
    )


@pytest.mark.parametrize(
    "mutation",
    ["context-bytes", "context-hash", "batch-order", "missing-batch", "extra-batch"],
)
def test_prepared_semantic_final_requires_exact_committed_context_before_effects(
    tmp_path: Path,
    mutation: str,
) -> None:
    executor = _Executor()
    vault, _, _, runs, request, capabilities, flow = _setup(
        tmp_path,
        mode="content",
        executor=executor,
    )
    (vault / "inbox/a.md").write_bytes(_note("A"))
    (vault / "inbox/b.md").write_bytes(_note("B"))

    with pytest.raises(_Crash):
        flow.execute(
            request,
            capabilities=capabilities,
            crash_hooks=LintCrashHooks(
                before_run_commit=lambda: (_ for _ in ()).throw(_Crash())
            ),
        )

    run_directory = vault / f"agent/runs/{request.run_id}"
    evidence_path = next(run_directory.glob("lint-evidence-*.json"))
    evidence = parse_lint_run_evidence(evidence_path.read_bytes())
    report = evidence.report
    assert len(report.batch_ids) == 2
    packets_by_batch = {}
    for path in run_directory.glob("lint-packet-*.json"):
        packet = json.loads(path.read_bytes())
        packets_by_batch[packet["batch_id"]] = path.read_bytes()

    def context(batch_ids: tuple[str, ...]) -> tuple[int, str]:
        raws = [packets_by_batch[batch_id] for batch_id in batch_ids]
        return (
            sum(len(raw) for raw in raws),
            lint_module._digest([hashlib.sha256(raw).hexdigest() for raw in raws]),
        )

    if mutation == "context-bytes":
        report = replace(report, context_bytes=report.context_bytes + 1)
    elif mutation == "context-hash":
        report = replace(report, context_sha256=ZERO_HASH)
    elif mutation == "batch-order":
        batch_ids = tuple(reversed(report.batch_ids))
        context_bytes, context_sha256 = context(batch_ids)
        report = replace(
            report,
            batch_ids=batch_ids,
            context_bytes=context_bytes,
            context_sha256=context_sha256,
        )
    elif mutation == "missing-batch":
        batch_ids = report.batch_ids[:-1]
        context_bytes, context_sha256 = context(batch_ids)
        report = replace(
            report,
            batch_ids=batch_ids,
            context_bytes=context_bytes,
            context_sha256=context_sha256,
        )
    elif mutation == "extra-batch":
        report = replace(
            report,
            batch_ids=(*report.batch_ids, "lint-batch-" + "f" * 32),
        )
    else:  # pragma: no cover - parameter list is closed above
        raise AssertionError(mutation)
    evidence_path.write_bytes(
        render_lint_run_evidence(replace(evidence, report=report))
    )
    before = _snapshot_vault_files(vault)
    before_state = runs.snapshot(request.run_id).state_sha256

    with pytest.raises(LintFlowError, match="context"):
        flow.execute(request, capabilities=capabilities)

    assert _snapshot_vault_files(vault) == before
    assert runs.snapshot(request.run_id).state_sha256 == before_state


@pytest.mark.parametrize("mode", ["content", "deep"])
def test_prepared_semantic_final_recovers_exact_committed_context(
    tmp_path: Path,
    mode: str,
) -> None:
    executor = _Executor()
    vault, _, _, runs, request, capabilities, flow = _setup(
        tmp_path,
        mode=mode,
        executor=executor,
    )
    (vault / "inbox/a.md").write_bytes(_note("A"))
    (vault / "inbox/b.md").write_bytes(_note("B"))
    with pytest.raises(_Crash):
        flow.execute(
            request,
            capabilities=capabilities,
            crash_hooks=LintCrashHooks(
                before_run_commit=lambda: (_ for _ in ()).throw(_Crash())
            ),
        )
    packet_count = len(executor.packets)

    recovered = flow.execute(request, capabilities=capabilities)

    assert recovered.replayed
    assert len(executor.packets) == packet_count
    assert recovered.report.context_bytes == sum(
        len(packet) for packet in executor.packets
    )
    assert recovered.report.context_sha256 == lint_module._digest(
        [hashlib.sha256(packet).hexdigest() for packet in executor.packets]
    )
    assert runs.status(request.run_id)["phase"] == "lint-report-committed"


def test_prepared_semantic_final_binds_every_finding_to_batch_evidence(
    tmp_path: Path,
) -> None:
    def responder(packet):
        return [
            {
                "rule_id": "content.duplicate",
                "severity": "error",
                "anchors": [_anchor(packet["spans"][0])],
            }
        ]

    executor = _Executor(responder)
    vault, _, _, runs, request, capabilities, flow = _setup(
        tmp_path,
        mode="content",
        executor=executor,
    )
    (vault / "inbox/a.md").write_bytes(_note("A"))
    with pytest.raises(_Crash):
        flow.execute(
            request,
            capabilities=capabilities,
            crash_hooks=LintCrashHooks(
                before_run_commit=lambda: (_ for _ in ()).throw(_Crash())
            ),
        )

    run_directory = vault / f"agent/runs/{request.run_id}"
    evidence_path = next(run_directory.glob("lint-evidence-*.json"))
    evidence = parse_lint_run_evidence(evidence_path.read_bytes())
    original = evidence.report.findings[0]
    changed = lint_module._finding(
        mode="content",
        rule="content.stale-reference",
        severity=original.severity,
        anchors=original.anchors,
    )
    report = replace(evidence.report, findings=(changed,))
    evidence_path.write_bytes(
        render_lint_run_evidence(replace(evidence, report=report))
    )
    before = _snapshot_vault_files(vault)
    before_state = runs.snapshot(request.run_id).state_sha256

    with pytest.raises(LintFlowError, match="batch evidence"):
        flow.execute(request, capabilities=capabilities)

    assert _snapshot_vault_files(vault) == before
    assert runs.snapshot(request.run_id).state_sha256 == before_state


@pytest.mark.parametrize("mode", ["content", "deep"])
def test_prepared_semantic_final_rejects_forged_infra_finding_without_effects(
    tmp_path: Path,
    mode: str,
) -> None:
    executor = _Executor()
    vault, _, _, runs, request, capabilities, flow = _setup(
        tmp_path,
        mode=mode,
        executor=executor,
    )
    (vault / "inbox/a.md").write_bytes(_note("A"))
    (vault / "inbox/b.md").write_bytes(_note("B"))
    with pytest.raises(_Crash):
        flow.execute(
            request,
            capabilities=capabilities,
            crash_hooks=LintCrashHooks(
                before_run_commit=lambda: (_ for _ in ()).throw(_Crash())
            ),
        )

    run_directory = vault / f"agent/runs/{request.run_id}"
    evidence_path = next(run_directory.glob("lint-evidence-*.json"))
    evidence = parse_lint_run_evidence(evidence_path.read_bytes())
    source = evidence.report.sources[0]
    forged = lint_module._finding(
        mode="infra",
        rule="infra.domain.invalid",
        anchors=(lint_module.LintEvidenceAnchor(source.path, source.sha256),),
    )
    report = replace(evidence.report, status="findings", findings=(forged,))
    proposal = flow._proposal_for_report(
        report,
        created_at=str(runs.snapshot(request.run_id).state["created_at"]),
    )
    assert proposal is not None
    proposal_raw = render_lint_review(proposal)
    evidence_path.write_bytes(
        render_lint_run_evidence(
            replace(
                evidence,
                report=report,
                proposal_ref=f"review/{proposal.proposal_id}.lint.json",
                proposal_sha256=hashlib.sha256(proposal_raw).hexdigest(),
            )
        )
    )
    before = _snapshot_vault_files(vault)
    before_state = runs.snapshot(request.run_id).state_sha256

    with pytest.raises(LintFlowError, match="committed infra evidence"):
        flow.execute(request, capabilities=capabilities)

    assert _snapshot_vault_files(vault) == before
    assert runs.snapshot(request.run_id).state_sha256 == before_state
    assert not list((vault / "review").glob("lintprop-*.lint.json"))


@pytest.mark.parametrize("mode", ["content", "deep"])
@pytest.mark.parametrize("mutation", ["omitted", "changed-infra", "changed-mode"])
def test_prepared_semantic_final_rejects_omitted_or_changed_mode_findings(
    tmp_path: Path,
    mode: str,
    mutation: str,
) -> None:
    executor = _Executor()
    vault, _, _, runs, request, capabilities, flow = _setup(
        tmp_path,
        mode=mode,
        executor=executor,
    )
    (vault / "inbox/bad.md").write_bytes(b"# Missing frontmatter\n")
    with pytest.raises(_Crash):
        flow.execute(
            request,
            capabilities=capabilities,
            crash_hooks=LintCrashHooks(
                before_run_commit=lambda: (_ for _ in ()).throw(_Crash())
            ),
        )

    run_directory = vault / f"agent/runs/{request.run_id}"
    evidence_path = next(run_directory.glob("lint-evidence-*.json"))
    evidence = parse_lint_run_evidence(evidence_path.read_bytes())
    original = evidence.report.findings[0]
    assert original.mode == "infra"
    if mutation == "omitted":
        findings = ()
    elif mutation == "changed-infra":
        findings = (
            lint_module._finding(
                mode="infra",
                rule="infra.domain.invalid",
                severity=original.severity,
                anchors=original.anchors,
            ),
        )
    elif mutation == "changed-mode":
        findings = (
            lint_module._finding(
                mode=mode,
                rule=(
                    "content.unsupported-claim"
                    if mode == "content"
                    else "deep.orphan-reference"
                ),
                severity=original.severity,
                anchors=original.anchors,
            ),
        )
    else:  # pragma: no cover - parameter list is closed above
        raise AssertionError(mutation)
    report = replace(
        evidence.report,
        status="findings" if findings else "clean",
        findings=findings,
    )
    proposal = flow._proposal_for_report(
        report,
        created_at=str(runs.snapshot(request.run_id).state["created_at"]),
    )
    proposal_raw = None if proposal is None else render_lint_review(proposal)
    evidence_path.write_bytes(
        render_lint_run_evidence(
            replace(
                evidence,
                report=report,
                proposal_ref=(
                    None
                    if proposal is None
                    else f"review/{proposal.proposal_id}.lint.json"
                ),
                proposal_sha256=(
                    None
                    if proposal_raw is None
                    else hashlib.sha256(proposal_raw).hexdigest()
                ),
            )
        )
    )
    before = _snapshot_vault_files(vault)
    before_state = runs.snapshot(request.run_id).state_sha256

    with pytest.raises(LintFlowError, match="committed infra evidence"):
        flow.execute(request, capabilities=capabilities)

    assert _snapshot_vault_files(vault) == before
    assert runs.snapshot(request.run_id).state_sha256 == before_state


def test_committed_infra_evidence_resumes_once_and_keeps_exact_trace_bundle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executor = _Executor()
    vault, _, _, runs, request, capabilities, flow = _setup(
        tmp_path,
        mode="content",
        executor=executor,
    )
    (vault / "inbox/a.md").write_bytes(_note("A"))
    original_commit = flow._commit_infra_evidence

    def commit_then_crash(*args, **kwargs):
        original_commit(*args, **kwargs)
        raise _Crash

    monkeypatch.setattr(flow, "_commit_infra_evidence", commit_then_crash)
    with pytest.raises(_Crash):
        flow.execute(request, capabilities=capabilities)
    monkeypatch.setattr(flow, "_commit_infra_evidence", original_commit)

    snapshot = runs.snapshot(request.run_id)
    infra_artifacts = [
        artifact
        for artifact in snapshot.artifacts
        if artifact.name.startswith("lint-infra-evidence-")
    ]
    assert len(infra_artifacts) == 1
    infra_raw = vault.joinpath(*infra_artifacts[0].state_ref.split("/")).read_bytes()
    assert executor.packets == []

    result = flow.execute(request, capabilities=capabilities)

    final_name = lint_evidence_artifact_name(result.report.operation_id)
    assert tuple(
        artifact.name
        for artifact in runs.producer_snapshot(
            request.run_id, producer_evidence=final_name
        ).artifacts
    ) == (final_name,)
    assert (
        vault.joinpath(*infra_artifacts[0].state_ref.split("/")).read_bytes()
        == infra_raw
    )
    trace = runs.trace_events(request.run_id)
    infra_events = [
        event for event in trace if str(event["step_id"]).startswith("lint-infra-")
    ]
    assert len(infra_events) == 1
    assert [action["action_id"] for action in infra_events[0]["actions"]] == [
        "scan-inbox-zone",
        "scan-non-archive-zones",
        "scan-task-zone",
        "scan-project-zone",
        "scan-memory-zone",
        "record-run-state",
    ]


def test_committed_infra_evidence_cannot_self_validate_after_mutation(
    tmp_path: Path,
) -> None:
    vault, _, _, _, request, capabilities, flow = _setup(tmp_path)
    (vault / "inbox/a.md").write_bytes(_note("A"))
    with pytest.raises(_Crash):
        flow.execute(
            request,
            capabilities=capabilities,
            crash_hooks=LintCrashHooks(
                before_run_commit=lambda: (_ for _ in ()).throw(_Crash())
            ),
        )
    run_directory = vault / f"agent/runs/{request.run_id}"
    infra_path = next(run_directory.glob("lint-infra-evidence-*.json"))
    payload = json.loads(infra_path.read_bytes())
    payload["role"] = "lint-infra-evidence-forged"
    infra_path.write_bytes(lint_module._canonical(payload, 4 * 1024 * 1024))
    before = _snapshot_vault_files(vault)

    with pytest.raises(LintFlowError, match="run artifacts are invalid"):
        flow.execute(request, capabilities=capabilities)

    assert _snapshot_vault_files(vault) == before


def test_evidence_inspector_rejects_artifact_or_content_tampering(
    tmp_path: Path,
) -> None:
    vault, _, _, runs, request, capabilities, flow = _setup(tmp_path)
    result = flow.execute(request, capabilities=capabilities)
    artifact = next(
        item
        for item in runs.snapshot(request.run_id).artifacts
        if item.name.startswith("lint-evidence-")
    )
    raw = vault.joinpath(*artifact.state_ref.split("/")).read_bytes()

    with pytest.raises(LintFlowError, match="artifact binding"):
        inspect_lint_run_evidence(replace(artifact, sha256=ZERO_HASH), raw)
    evidence = parse_lint_run_evidence(raw)
    altered = replace(
        evidence,
        report=replace(evidence.report, context_sha256="1" * 64),
    )
    altered_raw = render_lint_run_evidence(altered)
    with pytest.raises(LintFlowError, match="artifact binding"):
        inspect_lint_run_evidence(artifact, altered_raw)
    assert result.report == evidence.report


@pytest.mark.parametrize(
    ("scenario", "expected_error"),
    [
        ("scan", "scan-inbox-zone"),
        ("apply", "apply-allowlisted-inbox-fix"),
        ("fix-run", "record-run-state"),
        ("batch-run", "record-run-state"),
    ],
)
def test_wrong_capability_fails_before_target_artifact_or_executor_effects(
    tmp_path: Path,
    scenario: str,
    expected_error: str,
) -> None:
    executor = _Executor() if scenario == "batch-run" else None
    vault, _, policy, _, request, capabilities, flow = _setup(
        tmp_path,
        mode="content" if scenario == "batch-run" else "infra",
        apply_fixes=scenario in {"apply", "fix-run"},
        executor=executor,
    )
    (vault / "inbox/a.md").write_bytes(
        _note("A").rstrip() if scenario in {"apply", "fix-run"} else _note("A")
    )
    if scenario == "scan":
        wrong = policy.issue(
            flow_id="lint",
            action_id="scan-task-zone",
            actor="runtime",
            authority="read",
            target="vault:tasks",
        )
        capabilities = replace(capabilities, scan_inbox_zone=wrong)
    elif scenario == "apply":
        wrong = policy.issue(
            flow_id="lint",
            action_id="record-run-state",
            actor="runtime",
            authority="internal-write",
            target="vault:agent/runs",
        )
        capabilities = replace(capabilities, apply_allowlisted_inbox_fix=wrong)
    else:
        wrong = policy.issue(
            flow_id="lint",
            action_id="scan-inbox-zone",
            actor="runtime",
            authority="read",
            target="vault:inbox",
        )
        capabilities = replace(capabilities, record_run_state=wrong)

    before = _snapshot_vault_files(vault)
    with pytest.raises(LintFlowError, match=expected_error):
        flow.execute(request, capabilities=capabilities)

    assert _snapshot_vault_files(vault) == before
    assert executor is None or executor.packets == []


def test_invalid_limits_fail_before_vault_effects() -> None:
    with pytest.raises(LintFlowError, match="positive exact integers"):
        LintLimits(max_findings=0).validate()


def test_request_requires_exact_five_zones_and_exact_schema_integer(
    tmp_path: Path,
) -> None:
    vault, _, _, _, request, _, _ = _setup(tmp_path)
    before = _snapshot_sources(vault)

    with pytest.raises(LintFlowError, match="exact five-zone order"):
        render_lint_request(replace(request, zones=("inbox",)))
    with pytest.raises(LintFlowError, match="request is invalid"):
        render_lint_request(replace(request, schema_version=True))
    with pytest.raises(LintFlowError, match="request is invalid"):
        parse_lint_request(
            render_lint_request(request).replace(
                b'"schema_version":1', b'"schema_version":true'
            )
        )

    assert _snapshot_sources(vault) == before


def test_pending_fix_evidence_requires_exact_schema_integer_before_target_effect(
    tmp_path: Path,
) -> None:
    vault, _, _, _, request, capabilities, flow = _setup(
        tmp_path,
        apply_fixes=True,
    )
    path = vault / "inbox/a.md"
    original = _note("A").rstrip()
    path.write_bytes(original)

    with pytest.raises(_Crash):
        flow.execute(
            request,
            capabilities=capabilities,
            crash_hooks=LintCrashHooks(
                after_fix_prepare=lambda: (_ for _ in ()).throw(_Crash())
            ),
        )
    evidence_path = next(
        (vault / f"agent/runs/{request.run_id}").glob("lint-fix-evidence-*.json")
    )
    payload = json.loads(evidence_path.read_bytes())
    payload["schema_version"] = True
    evidence_path.write_bytes(lint_module._canonical(payload))

    with pytest.raises(LintFlowError, match="pending lint fix evidence is invalid"):
        flow.execute(request, capabilities=capabilities)
    assert path.read_bytes() == original


def test_completed_run_replays_current_canonical_human_decision(
    tmp_path: Path,
) -> None:
    vault, _, _, _, request, capabilities, flow = _setup(tmp_path)
    (vault / "inbox/bad.md").write_bytes(b"# invalid\n")
    result = flow.execute(request, capabilities=capabilities)
    assert result.proposal is not None
    proposal_path = vault / f"review/{result.proposal.proposal_id}.lint.json"
    decided = replace(
        result.proposal,
        status="approved",
        human_decision=LintReviewDecision(
            action="approve",
            actor="human",
            at="2026-08-20T13:00:00Z",
        ),
    )
    proposal_path.write_bytes(render_lint_review(decided))

    replay = flow.execute(request, capabilities=capabilities)

    assert replay.replayed
    assert replay.proposal == decided
    assert parse_lint_review(proposal_path.read_bytes()) == decided


def test_deep_bounded_schedule_covers_every_cross_source_pair(
    tmp_path: Path,
) -> None:
    executor = _Executor()
    limits = LintLimits(
        max_file_bytes=4096,
        max_total_bytes=16384,
        max_span_bytes=512,
        max_packet_bytes=1200,
        max_context_bytes=65536,
    )
    vault, _, _, _, request, capabilities, flow = _setup(
        tmp_path,
        mode="deep",
        executor=executor,
        limits=limits,
    )
    all_paths = {f"inbox/{name}.md" for name in ("a", "b", "c")}
    for name in ("a", "b", "c"):
        (vault / f"inbox/{name}.md").write_bytes(_note(name.upper(), name * 90))

    result = flow.execute(request, capabilities=capabilities)

    observed_pairs: set[tuple[str, str]] = set()
    for raw in executor.packets:
        packet = json.loads(raw)
        paths = sorted({span["path"] for span in packet["spans"]})
        observed_pairs.update(itertools.combinations(paths, 2))
        assert len(raw) <= limits.max_packet_bytes
    assert observed_pairs == set(itertools.combinations(sorted(all_paths), 2))
    assert result.report.context_bytes == sum(len(raw) for raw in executor.packets)
    assert result.report.context_bytes <= limits.max_context_bytes


@pytest.mark.parametrize("replacement", ["root", "zone"])
def test_direct_fix_rejects_root_or_zone_replacement_before_slot_write(
    tmp_path: Path,
    replacement: str,
) -> None:
    vault, _, _, _, request, capabilities, flow = _setup(tmp_path, apply_fixes=True)
    (vault / "inbox/a.md").write_bytes(_note("A").rstrip())
    saved = tmp_path / f"saved-{replacement}"

    def replace_binding() -> None:
        if replacement == "root":
            vault.rename(saved)
            shutil.copytree(saved, vault)
        else:
            inbox = vault / "inbox"
            inbox.rename(saved)
            shutil.copytree(saved, inbox)

    with pytest.raises(LintFlowError, match="identity changed"):
        flow.execute(
            request,
            capabilities=capabilities,
            crash_hooks=LintCrashHooks(after_fix_prepare=replace_binding),
        )

    assert not list((vault / "inbox").glob(".lifeos-lint-*.slot"))
    saved_inbox = saved / "inbox" if replacement == "root" else saved
    assert not list(saved_inbox.glob(".lifeos-lint-*.slot"))


def test_parent_replacement_during_slot_creation_never_writes_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    vault, _, _, _, request, capabilities, flow = _setup(tmp_path, apply_fixes=True)
    parent = vault / "projects/p"
    parent.mkdir()
    (parent / "a.md").write_bytes(_note("A").rstrip())
    displaced = vault / "projects/p-displaced"
    original = lint_module._write_once_at
    raced = False

    def race(parent_fd: int, name: str, data: bytes) -> None:
        nonlocal raced
        if not raced and name.endswith(".slot"):
            raced = True
            parent.rename(displaced)
            parent.mkdir()
            (parent / "a.md").write_bytes(_note("Foreign"))
        original(parent_fd, name, data)

    monkeypatch.setattr(lint_module, "_write_once_at", race)
    with pytest.raises(LintFlowError, match="parent cannot be revalidated"):
        flow.execute(request, capabilities=capabilities)

    assert (parent / "a.md").read_bytes() == _note("Foreign")
    assert not list(parent.glob(".lifeos-lint-*.slot"))
    assert not list(displaced.glob(".lifeos-lint-*.slot"))


def test_walk_zone_closes_every_pending_directory_fd_after_repeated_failure(
    tmp_path: Path,
) -> None:
    vault, _, _, _, _, _, flow = _setup(
        tmp_path,
        limits=LintLimits(max_entries_per_directory=4),
    )
    for name in ("a", "b", "c"):
        (vault / "inbox" / name).mkdir()
    for ordinal in range(5):
        (vault / "inbox/a" / f"{ordinal}.txt").write_bytes(b"x")
    fd_root = Path("/proc/self/fd")
    if not fd_root.exists():
        fd_root = Path("/dev/fd")

    before = len(list(fd_root.iterdir()))
    for _ in range(40):
        with pytest.raises(LintFlowError, match="entry bound"):
            flow._walk_zone("inbox")
    after = len(list(fd_root.iterdir()))

    assert after == before


@pytest.mark.parametrize("owned_slot_bytes", ["old", "new", "foreign"])
def test_after_fix_commit_resume_restores_evidence_and_retires_only_owned_slot(
    tmp_path: Path,
    owned_slot_bytes: str,
) -> None:
    vault, _, _, runs, request, capabilities, flow = _setup(
        tmp_path,
        apply_fixes=True,
    )
    path = vault / "inbox/a.md"
    old = _note("A").rstrip()
    new = _note("A")
    path.write_bytes(old)
    unrelated = vault / "inbox/.lifeos-lint-unrelated.slot"
    unrelated.write_bytes(b"unrelated")
    owned_path: Path | None = None

    def crash_after_fix_commit() -> None:
        nonlocal owned_path
        candidates = [
            item
            for item in (vault / "inbox").glob(".lifeos-lint-*.slot")
            if item != unrelated
        ]
        assert len(candidates) == 1
        owned_path = candidates[0]
        if owned_slot_bytes == "new":
            owned_path.write_bytes(new)
        elif owned_slot_bytes == "foreign":
            owned_path.write_bytes(b"foreign")
        raise _Crash

    with pytest.raises(_Crash):
        flow.execute(
            request,
            capabilities=capabilities,
            crash_hooks=LintCrashHooks(after_fix_commit=crash_after_fix_commit),
        )

    assert owned_path is not None
    assert path.read_bytes() == new
    assert runs.status(request.run_id)["phase"] == "lint-fix-committed"
    if owned_slot_bytes == "foreign":
        with pytest.raises(LintFlowError, match="foreign bytes"):
            flow.execute(request, capabilities=capabilities)
        assert owned_path.read_bytes() == b"foreign"
        assert unrelated.read_bytes() == b"unrelated"
        assert not list(
            (vault / f"agent/runs/{request.run_id}").glob("lint-evidence-*.json")
        )
        return

    recovered = flow.execute(request, capabilities=capabilities)

    assert recovered.replayed
    assert len(recovered.receipts) == 1
    assert recovered.receipts[0].status == "already-applied"
    assert any(
        item.fix is not None and item.resolution == "auto-fixed"
        for item in recovered.report.findings
    )
    assert not owned_path.exists()
    assert unrelated.read_bytes() == b"unrelated"
    assert runs.status(request.run_id)["phase"] == "lint-report-committed"


def test_executor_surrogate_and_duplicate_findings_fail_at_domain_boundary(
    tmp_path: Path,
) -> None:
    class Surrogate:
        def execute(self, _packet: bytes) -> str:
            return "\ud800"

    vault, _, _, _, request, capabilities, flow = _setup(
        tmp_path / "surrogate", mode="content", executor=Surrogate()
    )
    (vault / "inbox/a.md").write_bytes(_note("A"))
    with pytest.raises(LintFlowError, match="valid UTF-8"):
        flow.execute(request, capabilities=capabilities)

    def duplicate(packet: dict[str, object]) -> list[dict[str, object]]:
        finding = {
            "rule_id": "content.duplicate",
            "severity": "error",
            "anchors": [_anchor(packet["spans"][0])],
        }
        return [finding, finding]

    executor = _Executor(duplicate)
    vault, _, _, _, request, capabilities, flow = _setup(
        tmp_path / "duplicate", mode="content", executor=executor
    )
    (vault / "inbox/a.md").write_bytes(_note("A"))
    with pytest.raises(LintFlowError, match="duplicate findings"):
        flow.execute(request, capabilities=capabilities)


@pytest.mark.parametrize(
    "mutation",
    [
        "bool-schema",
        "wrong-packet-hash",
        "unknown-anchor",
        "wrong-source-hash",
        "noncanonical",
        "duplicate-finding",
        "duplicate-anchor",
        "wrong-mode",
        "wrong-rule",
        "wrong-line",
        "wrong-span",
    ],
)
def test_changed_pending_batch_evidence_fails_before_final_effects(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    def responder(packet):
        return [
            {
                "rule_id": "content.duplicate",
                "severity": "error",
                "anchors": [_anchor(packet["spans"][0])],
            }
        ]

    executor = _Executor(responder)
    vault, _, _, runs, request, capabilities, flow = _setup(
        tmp_path,
        mode="content",
        executor=executor,
    )
    (vault / "inbox/a.md").write_bytes(_note("A"))
    original_commit = runs.commit_step

    def crash_before_batch_commit(*args, **kwargs):
        if str(kwargs.get("step_id", "")).startswith("lint-batch-"):
            raise _Crash
        return original_commit(*args, **kwargs)

    monkeypatch.setattr(runs, "commit_step", crash_before_batch_commit)
    with pytest.raises(_Crash):
        flow.execute(request, capabilities=capabilities)
    monkeypatch.setattr(runs, "commit_step", original_commit)

    before_state = runs.snapshot(request.run_id).state_sha256
    run_directory = vault / f"agent/runs/{request.run_id}"
    batch_paths = list(run_directory.glob("lint-batch-evidence-*.json"))
    assert len(batch_paths) == 1
    batch_path = batch_paths[0]
    original_raw = batch_path.read_bytes()
    payload = json.loads(original_raw)
    valid = lint_module._parse_finding(payload["findings"][0])
    anchor = valid.anchors[0]

    def changed_finding(*, mode="content", rule="content.duplicate", anchors=None):
        finding = lint_module._finding(
            mode=mode,
            rule=rule,
            severity="error",
            anchors=valid.anchors if anchors is None else anchors,
        )
        return lint_module._finding_payload(finding)

    if mutation == "bool-schema":
        payload["schema_version"] = True
    elif mutation == "wrong-packet-hash":
        payload["packet_sha256"] = ZERO_HASH
    elif mutation == "unknown-anchor":
        unknown = replace(anchor, path="knowledge/forged.md")
        payload["findings"] = [changed_finding(anchors=(anchor, unknown))]
    elif mutation == "wrong-source-hash":
        payload["findings"] = [
            changed_finding(anchors=(replace(anchor, source_sha256=ZERO_HASH),))
        ]
    elif mutation == "noncanonical":
        batch_path.write_bytes(b" " + original_raw)
    elif mutation == "duplicate-finding":
        payload["findings"].append(payload["findings"][0])
    elif mutation == "duplicate-anchor":
        payload["findings"][0]["anchors"].append(payload["findings"][0]["anchors"][0])
    elif mutation == "wrong-mode":
        payload["findings"] = [changed_finding(mode="deep")]
    elif mutation == "wrong-rule":
        payload["findings"] = [changed_finding(rule="content.outside-contract")]
    elif mutation == "wrong-line":
        payload["findings"] = [
            changed_finding(
                anchors=(
                    replace(
                        anchor,
                        line_start=anchor.line_start + 1,
                        line_end=anchor.line_end + 1,
                    ),
                )
            )
        ]
    elif mutation == "wrong-span":
        payload["findings"] = [
            changed_finding(anchors=(replace(anchor, span_sha256=ZERO_HASH),))
        ]
    else:  # pragma: no cover - the parameter list is closed above
        raise AssertionError(mutation)
    if mutation != "noncanonical":
        batch_path.write_bytes(
            lint_module._canonical(payload, lint_module._MAX_BATCH_EVIDENCE)
        )

    with pytest.raises(LintFlowError):
        flow.execute(request, capabilities=capabilities)

    assert runs.snapshot(request.run_id).state_sha256 == before_state
    assert len(executor.packets) == 1
    assert not list(run_directory.glob("lint-evidence-*.json"))
    assert not list((vault / "review").glob("lintprop-*.lint.json"))


def test_inspector_requires_exact_latest_run_artifact_binding(
    tmp_path: Path,
) -> None:
    vault, _, _, runs, request, capabilities, flow = _setup(tmp_path)
    result = flow.execute(request, capabilities=capabilities)
    name = lint_evidence_artifact_name(result.report.operation_id)
    bundle = runs.producer_snapshot(request.run_id, producer_evidence=name)
    assert tuple(item.name for item in bundle.artifacts) == (name,)
    artifact = bundle.artifacts[0]
    assert artifact.relative == f"{request.run_id}/{name}.json"
    raw = vault.joinpath(*artifact.state_ref.split("/")).read_bytes()
    assert inspect_lint_run_evidence(artifact, raw).report == result.report

    forged_relative = f"foreign/{artifact.relative}"
    forged = replace(
        artifact,
        relative=forged_relative,
        state_ref=f"agent/runs/{forged_relative}",
    )
    with pytest.raises(LintFlowError, match="artifact binding"):
        inspect_lint_run_evidence(forged, raw)
    with pytest.raises(LintFlowError, match="artifact binding"):
        inspect_lint_run_evidence(replace(artifact, step_id="lint-final-wrong"), raw)

    report_raw = render_lint_report(result.report)
    trace_raw = json.dumps(runs.trace_events(request.run_id)).encode("utf-8")
    private_root = str(vault).encode("utf-8")
    assert private_root not in report_raw
    assert private_root not in trace_raw


@pytest.mark.parametrize("mismatch", ["stale-state", "non-derivable-preimage"])
def test_pending_fix_record_mismatch_fails_without_changes(
    tmp_path: Path,
    mismatch: str,
) -> None:
    vault, _, _, runs, request, capabilities, flow = _setup(
        tmp_path,
        apply_fixes=True,
    )
    target = vault / "inbox/pending.md"
    preimage = (
        _note("Pending").rstrip()
        if mismatch == "stale-state"
        else b"not a valid obsidian note"
    )
    target.write_bytes(preimage)
    candidate = preimage + b"\n"
    precondition = hashlib.sha256(preimage).hexdigest()
    postcondition = hashlib.sha256(candidate).hexdigest()
    transforms = ("append-final-newline",)
    fix_id = (
        "lint-fix-"
        + lint_module._digest(
            {
                "path": "inbox/pending.md",
                "post": postcondition,
                "pre": precondition,
                "transforms": list(transforms),
            }
        )[:32]
    )
    fix = lint_module.LintFix(
        fix_id,
        "infra.text.normalization",
        "inbox",
        "inbox/pending.md",
        precondition,
        postcondition,
        transforms,
    )
    token = hashlib.sha256(fix_id.encode()).hexdigest()[:24]
    evidence_name = f"lint-fix-evidence-{token}"
    preimage_name = f"lint-fix-preimage-{token}"
    run_directory = vault / f"agent/runs/{request.run_id}"
    (run_directory / f"{preimage_name}.json").write_bytes(preimage)
    payload = {
        "fix": lint_module._fix_payload(fix),
        "flow": "lint",
        "preimage_name": preimage_name,
        "preimage_sha256": precondition,
        "role": "lint-fix-evidence",
        "run_state_sha256": (
            ZERO_HASH
            if mismatch == "stale-state"
            else runs.snapshot(request.run_id).state_sha256
        ),
        "schema_version": 1,
    }
    (run_directory / f"{evidence_name}.json").write_bytes(
        lint_module._canonical(payload)
    )
    before = _snapshot_vault_files(vault)
    before_state = runs.snapshot(request.run_id).state_sha256

    expected = "stale run-state" if mismatch == "stale-state" else "allowlisted note"
    with pytest.raises(LintFlowError, match=expected):
        flow.execute(request, capabilities=capabilities)

    assert _snapshot_vault_files(vault) == before
    assert runs.snapshot(request.run_id).state_sha256 == before_state
    assert target.read_bytes() == preimage


def test_replay_requires_final_to_be_the_latest_exact_producer(
    tmp_path: Path,
) -> None:
    vault, _, _, runs, request, capabilities, flow = _setup(tmp_path)
    result = flow.execute(request, capabilities=capabilities)
    state_hash = runs.snapshot(request.run_id).state_sha256
    raw = b'{"schema_version":1}\n'
    later = runs.prepare_run_artifact(
        request.run_id,
        name="lint-later-record",
        data=raw,
        maximum_bytes=1024,
    )
    runs.commit_step(
        request.run_id,
        step_id="lint-later-record",
        authority="internal-write",
        input_hash=result.report.request_sha256,
        output_hash=later.sha256,
        next_phase="lint-later-recorded",
        prepared_artifacts=(later,),
        expected_state_sha256=state_hash,
    )
    before = _snapshot_vault_files(vault)
    before_state = runs.snapshot(request.run_id).state_sha256

    with pytest.raises(LintFlowError, match="latest exact producer"):
        flow.execute(request, capabilities=capabilities)

    assert _snapshot_vault_files(vault) == before
    assert runs.snapshot(request.run_id).state_sha256 == before_state


def test_prepared_final_requires_the_complete_canonical_finding_order(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def responder(packet):
        return [
            {
                "rule_id": "content.duplicate",
                "severity": "error",
                "anchors": [_anchor(packet["spans"][0])],
            }
        ]

    executor = _Executor(responder)
    vault, _, _, runs, request, capabilities, flow = _setup(
        tmp_path,
        mode="content",
        executor=executor,
    )
    (vault / "inbox/bad.md").write_bytes(b"# Missing frontmatter\n")
    original_publish = flow._publish_review
    monkeypatch.setattr(
        flow,
        "_publish_review",
        lambda _value: (_ for _ in ()).throw(_Crash()),
    )
    with pytest.raises(_Crash):
        flow.execute(request, capabilities=capabilities)
    monkeypatch.setattr(flow, "_publish_review", original_publish)

    run_directory = vault / f"agent/runs/{request.run_id}"
    evidence_path = next(run_directory.glob("lint-evidence-*.json"))
    payload = json.loads(evidence_path.read_bytes())
    findings = payload["report"]["findings"]
    infra = [item for item in findings if item["mode"] == "infra"]
    semantic = [item for item in findings if item["mode"] != "infra"]
    assert findings != [*infra, *semantic]
    payload["report"]["findings"] = [*infra, *semantic]
    evidence_path.write_bytes(lint_module._canonical(payload, 4 * 1024 * 1024))
    before = _snapshot_vault_files(vault)
    before_state = runs.snapshot(request.run_id).state_sha256

    with pytest.raises(LintFlowError, match="canonically ordered"):
        flow.execute(request, capabilities=capabilities)

    assert _snapshot_vault_files(vault) == before
    assert runs.snapshot(request.run_id).state_sha256 == before_state
    assert not list((vault / "review").glob("lintprop-*.lint.json"))


@pytest.mark.parametrize("source_step", ["infra", "fix", "batch", "final"])
def test_replay_requires_exact_action_trace_for_each_committed_source_step(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    source_step: str,
) -> None:
    executor = _Executor()
    mode = "content" if source_step == "batch" else "infra"
    apply_fixes = source_step == "fix"
    vault, _, policy, runs, request, capabilities, flow = _setup(
        tmp_path,
        mode=mode,
        apply_fixes=apply_fixes,
        executor=executor if mode == "content" else None,
    )
    if source_step == "fix":
        (vault / "inbox/fix.md").write_bytes(_note("Fix").rstrip())
    elif source_step == "batch":
        (vault / "inbox/batch.md").write_bytes(_note("Batch"))
    original_commit = runs.commit_step

    def commit_with_mismatched_trace(*args, **kwargs):
        step_id = str(kwargs.get("step_id", ""))
        prefixes = {
            "infra": "lint-infra-",
            "fix": "lint-fix-",
            "batch": "lint-batch-",
            "final": "lint-final-",
        }
        if step_id.startswith(prefixes[source_step]):
            kwargs = dict(kwargs)
            kwargs["action_uses"] = ()
            kwargs["authority_policy"] = policy
        return original_commit(*args, **kwargs)

    monkeypatch.setattr(runs, "commit_step", commit_with_mismatched_trace)
    flow.execute(request, capabilities=capabilities)
    monkeypatch.setattr(runs, "commit_step", original_commit)
    before = _snapshot_vault_files(vault)
    before_state = runs.snapshot(request.run_id).state_sha256

    with pytest.raises(LintFlowError, match="trace binding"):
        flow.execute(request, capabilities=capabilities)

    assert _snapshot_vault_files(vault) == before
    assert runs.snapshot(request.run_id).state_sha256 == before_state
