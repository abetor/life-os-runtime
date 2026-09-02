"""Gate P3 synthetic clean-vault trajectory with a legacy-access tripwire."""

from __future__ import annotations

import builtins
from contextlib import contextmanager
from dataclasses import fields
from datetime import datetime, timedelta, timezone
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
from typing import Iterator

import pytest

from tool_life_os_runtime.ext.flows.ambient import (
    AmbientAvailability,
    AmbientCapabilities,
    AmbientFlow,
    AmbientRequest,
    AmbientReviewBudget,
)
from tool_life_os_runtime.ext.flows.book import (
    BOOK_SCHEMA_VERSION,
    BookCapabilities,
    BookCommand,
    BookFlow,
    BookSourceManifest,
)
from tool_life_os_runtime.ext.flows.bundle import (
    BundleCapabilities,
    BundleFlow,
    BundleRequest,
    BundleWindow,
)
from tool_life_os_runtime.ext.flows.entities import (
    EntitiesCapabilities,
    EntitiesFlow,
)
from tool_life_os_runtime.ext.flows.finalize import (
    FinalizeArtifactRoles,
    FinalizeCapabilities,
    FinalizeFlow,
    parse_outcome_record,
)
from tool_life_os_runtime.ext.flows.grill_me import (
    GrillCapabilities,
    GrillExplicitDecision,
    GrillHumanAnswer,
    GrillMeFlow,
    GrillQuestionOutput,
    GrillRequest,
    parse_grill_decision_record,
)
from tool_life_os_runtime.ext.flows.ingest import (
    INGEST_CONNECTOR_SCHEMA_VERSION,
    INGEST_SCHEMA_VERSION,
    IngestCapabilities,
    IngestConnectorRequest,
    IngestConnectorResult,
    IngestFlow,
    IngestInput,
    InMemoryIngestDedupeStore,
)
from tool_life_os_runtime.ext.flows.lint import (
    LINT_ZONE_ORDER,
    LintCapabilities,
    LintFlow,
    LintRequest,
)
from tool_life_os_runtime.ext.flows.memory import (
    DecayPolicy,
    DeletionPolicy,
    MemoryCapabilities,
    MemoryFlow,
    MemoryProposalRecord,
    RetentionPolicy,
    memory_evidence_artifact_name,
)
from tool_life_os_runtime.ext.flows.mentor import (
    MentorCapabilities,
    MentorExecutorOutput,
    MentorFlow,
    MentorObservation,
    MentorRecommendation,
    MentorRequest,
    parse_mentor_proposal,
)
from tool_life_os_runtime.ext.flows.obsidian import NoteEdit, NoteRef, ObsidianFlow
from tool_life_os_runtime.ext.flows.plan import (
    PlanCapabilities,
    PlanFlow,
    PlanPolicy,
    PlanTask,
)
from tool_life_os_runtime.ext.flows.project import ProjectCapabilities, ProjectFlow
from tool_life_os_runtime.ext.flows.report import (
    DailyLogRecord,
    HumanMaterial,
    ReportCapabilities,
    ReportContext,
    ReportContextItem,
    ReportFlow,
    daily_memory_evidence,
    report_evidence_artifact_name,
)
from tool_life_os_runtime.ext.review.authority import AuthorityPolicy
from tool_life_os_runtime.ext.runs import OutboxStore, RunStore
from tool_life_os_runtime.ext.runs.store import FINALIZE_ACTION_ORDER
from tool_life_os_runtime.ext.skills import check, install, uninstall
from tool_life_os_runtime.ext.vault.config import load_vault_config
from tool_life_os_runtime.ext.vault.migrate import init_vault
from tool_life_os_runtime.ext.vault.schema import VaultPathResolver
from tool_life_os_runtime.failure_authority import canonical_matrix


class _Clock:
    def __init__(self) -> None:
        self.value = datetime(2026, 8, 20, 9, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        current = self.value
        self.value += timedelta(microseconds=1)
        return current


class _IngestConnector:
    def collect(self, request: IngestConnectorRequest) -> IngestConnectorResult:
        content = _note(
            f"Synthetic {request.classification}",
            "Connector output retains only bounded synthetic provenance.",
        )
        return IngestConnectorResult(
            INGEST_CONNECTOR_SCHEMA_VERSION,
            request.connector,
            f"{request.connector}/manifests/{request.classification}.json",
            request.canonical_source_sha256,
            hashlib.sha256(request.canonical_source.encode("utf-8")).hexdigest(),
            hashlib.sha256(content.encode("utf-8")).hexdigest(),
            content,
        )


def _note(title: str, body: str) -> str:
    return f'---\ntags:\n  - fixture\ndate: "2026-08-20"\n---\n\n# {title}\n\n{body}\n'


def _tree_snapshot(root: Path) -> dict[str, tuple[str, bytes]]:
    return {
        path.relative_to(root).as_posix(): (
            "symlink" if path.is_symlink() else "file" if path.is_file() else "dir",
            os.readlink(path).encode("utf-8")
            if path.is_symlink()
            else path.read_bytes()
            if path.is_file()
            else b"",
        )
        for path in sorted(root.rglob("*"))
    }


def _descriptor_path(value: int) -> str | None:
    get_path = getattr(fcntl, "F_GETPATH", None)
    if get_path is not None:
        try:
            raw = fcntl.fcntl(value, get_path, b"\0" * 1024)
        except (OSError, ValueError):
            pass
        else:
            if isinstance(raw, bytes):
                target = os.fsdecode(raw.split(b"\0", 1)[0])
                if target:
                    return os.path.normpath(os.path.abspath(target))
    for prefix in ("/dev/fd", "/proc/self/fd"):
        link = f"{prefix}/{value}"
        try:
            target = os.readlink(link)
        except OSError:
            continue
        if not os.path.isabs(target):
            target = os.path.join(prefix, target)
        return os.path.normpath(os.path.abspath(target))
    return None


def _absolute_path(value: object, *, dir_fd: object = None) -> str | None:
    if isinstance(value, int):
        return _descriptor_path(value)
    try:
        raw = os.fsdecode(os.fspath(value))
    except TypeError:
        return None
    if os.path.isabs(raw):
        return os.path.normpath(raw)
    base = _descriptor_path(dir_fd) if isinstance(dir_fd, int) else os.getcwd()
    if base is None:
        return None
    return os.path.normpath(os.path.join(base, raw))


@contextmanager
def _deny_legacy_access(
    monkeypatch: pytest.MonkeyPatch, legacy: Path
) -> Iterator[None]:
    """Reject any content or directory access below the configured legacy root."""

    legacy_text = os.path.normpath(os.fspath(legacy))

    def guarded(function):
        def call(path, *args, **kwargs):
            candidate = _absolute_path(path, dir_fd=kwargs.get("dir_fd"))
            if (
                candidate is not None
                and os.path.commonpath((legacy_text, candidate)) == legacy_text
            ):
                raise AssertionError(
                    f"legacy access attempted through {function.__name__}"
                )
            return function(path, *args, **kwargs)

        return call

    with monkeypatch.context() as patcher:
        for owner, name in (
            (builtins, "open"),
            (io, "open"),
            (os, "open"),
            (os, "stat"),
            (os, "lstat"),
            (os, "listdir"),
            (os, "scandir"),
        ):
            patcher.setattr(owner, name, guarded(getattr(owner, name)))
        yield


def test_legacy_tripwire_resolves_relative_directory_descriptors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    legacy = tmp_path / "legacy-vault"
    legacy.mkdir()
    (legacy / "sentinel-private.md").write_bytes(b"private\n")
    parent_fd = os.open(tmp_path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    legacy_fd = os.open(legacy, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        with _deny_legacy_access(monkeypatch, legacy):
            blocked_calls = (
                (
                    os.open,
                    ("legacy-vault/sentinel-private.md", os.O_RDONLY),
                    {"dir_fd": parent_fd},
                ),
                (os.stat, ("legacy-vault",), {"dir_fd": parent_fd}),
                (os.lstat, ("legacy-vault",), {"dir_fd": parent_fd}),
                (
                    os.open,
                    ("sentinel-private.md", os.O_RDONLY),
                    {"dir_fd": legacy_fd},
                ),
                (os.stat, (".",), {"dir_fd": legacy_fd}),
                (os.lstat, (".",), {"dir_fd": legacy_fd}),
                (os.listdir, (legacy_fd,), {}),
                (os.scandir, (legacy_fd,), {}),
            )
            for function, args, kwargs in blocked_calls:
                with pytest.raises(AssertionError, match="legacy access attempted"):
                    function(*args, **kwargs)
    finally:
        os.close(legacy_fd)
        os.close(parent_fd)


def _matrix_action(flow_id: str, action_id: str) -> dict[str, object]:
    flow = next(
        flow for flow in canonical_matrix()["flows"] if flow["flow_id"] == flow_id
    )
    return next(
        action for action in flow["actions"] if action["action_id"] == action_id
    )


def _issue(policy: AuthorityPolicy, flow_id: str, action_id: str):
    action = _matrix_action(flow_id, action_id)
    return policy.issue(
        flow_id=flow_id,
        action_id=action_id,
        actor=str(action["actor"]),
        authority=str(action["authority"]),
        target=str(action["target"]),
    )


def _capabilities(cls, policy: AuthorityPolicy, flow_id: str, overrides=None):
    mapping = overrides or {}
    return cls(
        **{
            field.name: _issue(
                policy,
                flow_id,
                mapping.get(field.name, field.name.replace("_", "-")),
            )
            for field in fields(cls)
        }
    )


def _start(
    runs: RunStore,
    run_id: str,
    flow: str,
    authority: str,
    input_data: dict[str, object],
) -> None:
    runs.create(
        run_id=run_id,
        flow=flow,
        phase=flow,
        authority=authority,
        executor="fixture",
        input_data=input_data,
    )
    runs.resume(run_id, executor="fixture")


def _finalize_capabilities(policy: AuthorityPolicy) -> FinalizeCapabilities:
    return _capabilities(FinalizeCapabilities, policy, "finalize")


def _artifact_name(runs: RunStore, run_id: str, prefix: str) -> str:
    matches = [
        artifact.name
        for artifact in runs.snapshot(run_id).artifacts
        if artifact.name.startswith(prefix)
    ]
    assert len(matches) == 1, (run_id, prefix, matches)
    return matches[0]


def test_clean_vault_p3_trajectory_does_not_access_legacy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    legacy = tmp_path / "legacy-vault"
    legacy.mkdir()
    (legacy / "sentinel-private.md").write_bytes(b"must never be opened\n")
    legacy_before = _tree_snapshot(legacy)
    vault = tmp_path / "clean-vault"
    assert init_vault(vault, read_only_roots=(legacy,)).status == "initialized"
    config = load_vault_config(vault)
    resolver = VaultPathResolver(vault, config)
    clock = _Clock()
    policy = AuthorityPolicy()
    runs = RunStore(resolver, clock=clock)
    outbox = OutboxStore(resolver, runs, policy=policy, clock=clock)
    finalize = FinalizeFlow(resolver, runs, outbox, policy=policy, clock=clock)
    finalize_caps = _finalize_capabilities(policy)
    produced: list[tuple[str, str, tuple[str, ...]]] = []

    with _deny_legacy_access(monkeypatch, legacy):
        obsidian = ObsidianFlow(resolver, policy)
        capture = _note("Synthetic capture", "A bounded input for the P3 gate.")
        receipt = obsidian.edit_note(
            NoteEdit(
                1,
                "create_p3_capture",
                NoteRef(1, "inbox", "p3-capture.md"),
                None,
                capture,
            ),
            capability=_issue(policy, "obsidian", "edit-inbox"),
        )
        assert receipt.status == "applied"
        assert (
            obsidian.read_note(
                NoteRef(1, "inbox", "p3-capture.md"),
                capability=_issue(policy, "obsidian", "read-inbox-note"),
            ).sha256
            == hashlib.sha256(capture.encode("utf-8")).hexdigest()
        )

        ingest_caps = IngestCapabilities(
            classify=_issue(policy, "ingest", "classify-declared-input"),
            read_dedupe=_issue(policy, "ingest", "read-inbox-dedupe-state"),
            commit_review=_issue(policy, "ingest", "commit-review-proposal"),
            note_read=_issue(policy, "obsidian", "read-inbox-note"),
            read_manifest=_issue(policy, "ingest", "read-source-manifest"),
            extract=_issue(policy, "ingest", "extract-heavy-input"),
            research=_issue(policy, "ingest", "research-heavy-input"),
        )
        ingest = IngestFlow(
            resolver,
            policy,
            dedupe_store=InMemoryIngestDedupeStore(),
            connector=_IngestConnector(),
        )
        ingested = ingest.ingest(
            IngestInput(
                INGEST_SCHEMA_VERSION,
                "run_ingest_p3",
                "rev_ingest_p3",
                "2026-08-20T09:00:00Z",
                "auto",
                "https://example.test/p3/article",
                "knowledge/domains/p3/article.md",
                "gated",
            ),
            capabilities=ingest_caps,
        )
        assert ingested.status == "proposed"
        assert ingested.review_artifact is not None
        assert not (vault / "knowledge/domains/p3/article.md").exists()

        _start(
            runs,
            "run_project_p3",
            "project",
            "domain-write",
            {"project_slug": "p3-project"},
        )
        project_caps = ProjectCapabilities(
            read=_issue(policy, "project", "read-project-state"),
            commit=_issue(policy, "project", "commit-project-transition"),
            run=_issue(policy, "project", "record-run-state"),
            schedule=_issue(policy, "project", "apply-linked-schedule-transition"),
        )
        project_result = ProjectFlow(resolver, runs, policy, clock=clock).create(
            project_caps,
            run_id="run_project_p3",
            transition_id="project_create_p3",
            slug="p3-project",
            name="P3 synthetic project",
            goal="Exercise the clean-vault P3 trajectory.",
            domains=("systems",),
        )
        produced.append(
            (
                "run_project_p3",
                "project_transition",
                ("succeeded",),
            )
        )

        _start(
            runs,
            "run_entities_p3",
            "entities",
            "domain-write",
            {"scope": "synthetic"},
        )
        entity_result = EntitiesFlow(resolver, runs, policy, clock).create(
            _capabilities(EntitiesCapabilities, policy, "entities"),
            run_id="run_entities_p3",
            mutation_id="entity_create_p3",
            entity_id="ent-p3",
            domain="systems",
            title="P3 review entity",
            description="Synthetic planning context.",
        )
        assert entity_result.entity.status == "active"
        produced.append(
            (
                "run_entities_p3",
                _artifact_name(runs, "run_entities_p3", "entities-"),
                ("succeeded",),
            )
        )

        _start(
            runs,
            "run_plan_p3",
            "plan",
            "domain-write",
            {"scope": "synthetic"},
        )
        plan_result = PlanFlow(resolver, runs, policy, clock=clock).commit_day(
            _capabilities(PlanCapabilities, policy, "plan"),
            run_id="run_plan_p3",
            operation_id="plan_commit_p3",
            period="2026-08-20",
            tasks=(
                PlanTask(
                    "task-p3",
                    "Review the synthetic P3 checkpoint.",
                    "2026-08-20",
                    project_slug="p3-project",
                    entity_id="ent-p3",
                    priority="high",
                    focus=True,
                ),
            ),
            policy=PlanPolicy(5, 2),
        )
        assert plan_result.day_plan is not None
        produced.append(
            (
                "run_plan_p3",
                _artifact_name(runs, "run_plan_p3", "plan-evidence-"),
                ("succeeded",),
            )
        )

        _start(
            runs,
            "run_book_p3",
            "book",
            "domain-write",
            {"slug": "p3-book"},
        )
        book_caps = _capabilities(
            BookCapabilities,
            policy,
            "book",
            {"commit_knowledge_proposal": "commit-reading-knowledge-proposal"},
        )
        book = BookFlow(resolver, runs, policy)
        manifest = BookSourceManifest(
            BOOK_SCHEMA_VERSION,
            "source_p3_book",
            "coursedump/manifests/p3-book.json",
            "1" * 64,
            "2" * 64,
            "P3 Synthetic Handbook",
            8,
        )
        book.execute(
            BookCommand(
                BOOK_SCHEMA_VERSION,
                "run_book_p3",
                "mut_active_p3",
                "active",
                "p3-book",
                "2026-08-20T09:10:00Z",
            ),
            manifest,
            capabilities=book_caps,
        )
        book_anchor = book.execute(
            BookCommand(
                BOOK_SCHEMA_VERSION,
                "run_book_p3",
                "mut_anchor_p3",
                "anchor",
                "p3-book",
                "2026-08-20T09:20:00Z",
                chapter=2,
                text="A state transition must remain replayable.",
                anchor_id="anchor_p3",
                review_id="rev_book_p3",
                target_path="knowledge/domains/p3/book-anchor.md",
                surface="gated",
            ),
            manifest,
            capabilities=book_caps,
        )
        assert book_anchor.review_artifact is not None
        produced.append(
            (
                "run_book_p3",
                "book-" + hashlib.sha256(b"mut_anchor_p3").hexdigest()[:40],
                ("waiting_human",),
            )
        )

        project_ref = f"{project_result.snapshot.location}/state.json"
        project_path = vault / "projects" / project_ref
        entity_path = vault / "agent/memory/entities/systems.json"
        report_context = ReportContext(
            (
                ReportContextItem(
                    "entity",
                    "agent/memory/entities/systems.json",
                    hashlib.sha256(entity_path.read_bytes()).hexdigest(),
                ),
                ReportContextItem(
                    "project",
                    f"projects/{project_ref}",
                    hashlib.sha256(project_path.read_bytes()).hexdigest(),
                ),
            )
        )
        _start(
            runs,
            "run_report_p3",
            "report",
            "proposal",
            {"period": "2026-08-20"},
        )
        report_caps = _capabilities(ReportCapabilities, policy, "report")
        report = ReportFlow(resolver, runs, policy, clock=clock)
        daily = DailyLogRecord(
            "rpt-p3-daily",
            "2026-08-20",
            "run_report_p3",
            "report_daily_p3",
            "2026-08-20T09:30:00Z",
            (
                HumanMaterial(
                    "human_p3",
                    "daily-human-entry",
                    "human",
                    "2026-08-20T09:29:00Z",
                    "The bounded checkpoint remained reversible.",
                ),
            ),
            report_context,
            "The report keeps the primary human evidence attached.",
        )
        report.record_daily(daily, capabilities=report_caps)
        memory_evidence = daily_memory_evidence(daily, "human_p3")
        report_proposal = MemoryProposalRecord(
            proposal_id="memprop-report-p3",
            status="proposed",
            operation="create",
            memory_id="mem-report-p3",
            memory_kind="feedback",
            scope="workday",
            candidate_text="The bounded checkpoint remained reversible.",
            evidence=(memory_evidence,),
            current_memory_ref=None,
            current_memory_sha256=None,
            precondition_sha256=None,
            retention=RetentionPolicy("review", review_at="2026-09-20T00:00:00Z"),
            decay=DecayPolicy("stale-after", stale_after_days=30),
            deletion=DeletionPolicy("forget"),
            producer_flow="report",
            run_id="run_report_p3",
            operation_id="report_extract_p3",
            created_at="2026-08-20T09:35:00Z",
        )
        report.extract_memory(
            report_proposal,
            event_id="rpt-report-event-p3",
            recorded_at="2026-08-20T09:35:00Z",
            context=report_context,
            capabilities=report_caps,
        )
        produced.append(
            (
                "run_report_p3",
                report_evidence_artifact_name("report_extract_p3"),
                ("waiting_human",),
            )
        )

        _start(
            runs,
            "run_memory_p3",
            "memory",
            "domain-write",
            {"scope": "synthetic"},
        )
        memory_proposal = MemoryProposalRecord(
            proposal_id="memprop-memory-p3",
            status="proposed",
            operation="create",
            memory_id="mem-memory-p3",
            memory_kind="feedback",
            scope="workday",
            candidate_text="The bounded checkpoint remained reversible.",
            evidence=(memory_evidence,),
            current_memory_ref=None,
            current_memory_sha256=None,
            precondition_sha256=None,
            retention=RetentionPolicy("manual"),
            decay=DecayPolicy("stale-after", stale_after_days=30),
            deletion=DeletionPolicy("forget"),
            producer_flow="memory",
            run_id="run_memory_p3",
            operation_id="memory_propose_p3",
            created_at="2026-08-20T09:40:00Z",
        )
        MemoryFlow(resolver, runs, policy, clock=clock).propose(
            _capabilities(MemoryCapabilities, policy, "memory"), memory_proposal
        )
        produced.append(
            (
                "run_memory_p3",
                memory_evidence_artifact_name("memory_propose_p3"),
                ("waiting_human",),
            )
        )

        guide = vault / "knowledge/domains/p3/guide.md"
        guide.parent.mkdir(parents=True, exist_ok=True)
        guide.write_text("Keep the next checkpoint bounded and reversible.\n", "utf-8")
        decisions = vault / "agent/memory/decisions.jsonl"
        decisions.write_text('{"actor":"human","decision":"review one pilot"}\n')
        _start(
            runs,
            "run_mentor_p3",
            "mentor",
            "proposal",
            {"scope": "synthetic"},
        )
        mentor_caps = _capabilities(MentorCapabilities, policy, "mentor")
        mentor = MentorFlow(resolver, runs, policy, clock=clock)
        mentor_request = MentorRequest(
            "run_mentor_p3",
            "mentor_p3",
            "mentor-p3",
            "2026-08-20T09:45:00Z",
            "Choose a bounded checkpoint.",
            "What should a human review?",
            (project_ref,),
            ("domains/p3/guide.md",),
            ("decisions.jsonl",),
        )
        packet = mentor.prepare_task_packet(mentor_request, capabilities=mentor_caps)
        mentor_result = mentor.commit_proposal(
            packet,
            MentorExecutorOutput(
                "Review one reversible checkpoint without changing project state.",
                (
                    MentorObservation(
                        "obs-p3",
                        "The project remains active.",
                        packet.manifest.block_ids[:1],
                    ),
                ),
                (
                    MentorRecommendation(
                        "rec-p3",
                        "Review one checkpoint.",
                        "The action remains bounded.",
                        packet.manifest.block_ids,
                    ),
                ),
                ("Which exact checkpoint should the human approve?",),
            ),
            capabilities=mentor_caps,
        )
        assert (
            parse_mentor_proposal(
                (vault / mentor_result.proposal_ref).read_bytes()
            ).status
            == "proposed"
        )
        produced.append(
            (
                "run_mentor_p3",
                mentor_result.evidence_artifact,
                ("waiting_human",),
            )
        )

        _start(
            runs,
            "run_grill_p3",
            "grill-me",
            "proposal",
            {"scope": "synthetic"},
        )
        grill_caps = _capabilities(GrillCapabilities, policy, "grill-me")
        grill = GrillMeFlow(resolver, runs, policy, clock=clock)
        block_ids = (
            "ctx-" + hashlib.sha256(b"agent/memory\0decisions.jsonl").hexdigest()[:24],
            "ctx-"
            + hashlib.sha256(f"projects\0{project_ref}".encode("utf-8")).hexdigest()[
                :24
            ],
        )
        question = GrillQuestionOutput(
            "question-p3",
            "2026-08-20T09:46:00Z",
            "What exact condition must hold?",
            block_ids,
        )
        grill.begin(
            GrillRequest(
                "run_grill_p3",
                "grill_p3",
                "grill-p3",
                "2026-08-20T09:46:00Z",
                "Clarify the reversible checkpoint.",
                (project_ref,),
                ("decisions.jsonl",),
            ),
            question,
            capabilities=grill_caps,
        )
        runs.resume("run_grill_p3", executor="fixture")
        grill.answer(
            "run_grill_p3",
            GrillHumanAnswer(
                "question-p3",
                "human",
                "2026-08-20T09:47:00Z",
                "The checkpoint can be reverted from its recorded state.",
            ),
            capabilities=grill_caps,
        )
        runs.resume("run_grill_p3", executor="fixture")
        grill_result = grill.finish(
            "run_grill_p3",
            GrillExplicitDecision(
                "decision-p3",
                "human",
                "2026-08-20T09:48:00Z",
                "Proceed with one reversible checkpoint.",
            ),
            capabilities=grill_caps,
        )
        assert grill_result.record_ref is not None
        grill_record = parse_grill_decision_record(
            (vault / grill_result.record_ref).read_bytes()
        )
        assert grill_record.status == "proposed"
        assert grill_record.resolution == "explicit-human-decision"
        assert grill_result.evidence_artifact is not None
        produced.append(
            (
                "run_grill_p3",
                grill_result.evidence_artifact,
                ("waiting_human",),
            )
        )

        lint_request = LintRequest(1, "run_lint_p3", "infra", LINT_ZONE_ORDER, False)
        _start(
            runs,
            lint_request.run_id,
            "lint",
            "domain-write",
            {
                "apply_fixes": lint_request.apply_fixes,
                "mode": lint_request.mode,
                "zones": list(lint_request.zones),
            },
        )
        lint_result = LintFlow(resolver, runs, policy).execute(
            lint_request,
            capabilities=_capabilities(LintCapabilities, policy, "lint"),
        )
        produced.append(
            (
                lint_request.run_id,
                lint_result.prepared_artifact.name,
                ("waiting_human",),
            )
        )

        _start(
            runs,
            "run_ambient_p3",
            "ambient",
            "internal-write",
            {"fixture": "synthetic"},
        )
        with AmbientFlow(resolver, runs, policy, clock) as ambient:
            ambient_result = ambient.scan(
                _capabilities(AmbientCapabilities, policy, "ambient"),
                run_id="run_ambient_p3",
                request=AmbientRequest(
                    "ambient_p3",
                    "2026-08-20T09:50:00Z",
                    AmbientAvailability(
                        "quiet",
                        "2026-08-20T08:00:00Z",
                        "2026-08-20T11:00:00Z",
                    ),
                    AmbientReviewBudget(10, 20),
                ),
            )
        assert ambient_result.outcome == "emitted"
        assert ambient_result.event_id is not None

        _start(
            runs,
            "run_bundle_p3",
            "bundle",
            "internal-write",
            {"fixture": "synthetic"},
        )
        with BundleFlow(resolver, runs, policy, clock) as bundle:
            bundle_result = bundle.collect(
                _capabilities(BundleCapabilities, policy, "bundle"),
                run_id="run_bundle_p3",
                request=BundleRequest(
                    "bundle_p3",
                    "2026-08-20T10:00:00Z",
                    BundleWindow("2026-08-20T08:00:00Z", "2026-08-20T09:59:59Z"),
                ),
            )
        assert bundle_result.outcome == "emitted"
        receipt = outbox.record_delivery_receipt(
            _issue(policy, "gateway-delivery", "reconcile-outbox-receipt"),
            event_id=ambient_result.event_id,
            attempt_id="attempt_p3",
            status="delivered",
            effect_hash="3" * 64,
        )
        assert receipt["status"] == "delivered"
        produced.extend(
            (
                (
                    "run_ambient_p3",
                    ambient_result.evidence_artifact,
                    ("succeeded",),
                ),
                (
                    "run_bundle_p3",
                    bundle_result.evidence_artifact,
                    ("succeeded",),
                ),
            )
        )

        final_results = {}
        for run_id, evidence_name, expected_statuses in produced:
            result = finalize.finalize(
                run_id,
                artifacts=FinalizeArtifactRoles(producer_evidence=evidence_name),
                capabilities=finalize_caps,
            )
            assert result.terminal_status in expected_statuses
            assert (
                tuple(
                    action["action_id"]
                    for action in runs.trace_events(run_id)[-1]["actions"]
                )
                == FINALIZE_ACTION_ORDER
            )
            parsed = parse_outcome_record((vault / result.domain_log_ref).read_bytes())
            assert parsed.flow_id == runs.status(run_id)["flow"]
            assert parsed.source_step_id is not None
            assert parsed.source_bundle_sha256 is not None
            assert (
                finalize.finalize(
                    run_id,
                    artifacts=FinalizeArtifactRoles(producer_evidence=evidence_name),
                    capabilities=finalize_caps,
                )
                == result
            )
            final_results[run_id] = result
        for run_id in ("run_mentor_p3", "run_grill_p3"):
            outcome = parse_outcome_record(
                (vault / final_results[run_id].domain_log_ref).read_bytes()
            )
            assert outcome.accepted is False
            assert outcome.outcome_kind == "proposal-ready"
            assert outcome.decision_status == "proposed"
        mentor_outcome = parse_outcome_record(
            (vault / final_results["run_mentor_p3"].domain_log_ref).read_bytes()
        )
        grill_outcome = parse_outcome_record(
            (vault / final_results["run_grill_p3"].domain_log_ref).read_bytes()
        )
        assert (mentor_outcome.producer_operation, mentor_outcome.pending_kind) == (
            "proposal",
            "mentor-proposal",
        )
        assert (grill_outcome.producer_operation, grill_outcome.pending_kind) == (
            "finish",
            "grill-decision",
        )
        lint_outcome = parse_outcome_record(
            (vault / final_results["run_lint_p3"].domain_log_ref).read_bytes()
        )
        assert (
            lint_outcome.outcome_kind,
            lint_outcome.producer_operation,
            lint_outcome.decision_status,
            lint_outcome.pending_kind,
        ) == ("proposal-ready", "lint-infra", "proposed", "lint-proposal")
        for run_id in ("run_ambient_p3", "run_bundle_p3"):
            outcome = parse_outcome_record(
                (vault / final_results[run_id].domain_log_ref).read_bytes()
            )
            assert outcome.outcome_kind == "domain-updated"
            assert outcome.producer_operation == "emitted"
            assert outcome.decision_status is None
            event_id = final_results[run_id].outbox_event_id
            assert event_id is not None
            event = json.loads((vault / f"agent/outbox/{event_id}.json").read_bytes())
            assert event["delivery_policy"]["surface"] == "silent"

        manifest_root = tmp_path / "skill-manifests"
        manifest_root.mkdir()
        installed = install(vault, manifest_root)
        assert len(installed.installed) == 30
        assert check(vault, manifest_root).ok is True
        removed = uninstall(vault, manifest_root)
        assert len(removed.removed) == 30
        assert not any(
            path.name == "SKILL.md"
            for root in (vault / ".claude/skills", vault / ".agents/skills")
            if root.exists()
            for path in root.rglob("SKILL.md")
        )

        protected_knowledge = [
            path
            for path in (vault / "knowledge").rglob("*")
            if path.is_file() and path.name != ".gitkeep"
        ]
        assert protected_knowledge == [guide]

    assert _tree_snapshot(legacy) == legacy_before
    outbox.close()
