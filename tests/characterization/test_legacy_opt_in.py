"""Safe exact comparisons with legacy code; private imports require explicit opt-in."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from types import ModuleType

import pytest

from tests.characterization._legacy_opt_in import (
    bytecode_snapshot,
    loaded_legacy_module,
    resolve_read_only_legacy,
    source_hashes,
)
from tests.characterization.observations import (
    OBSERVERS,
    ObservationInput,
    comparison_failures,
)


LEGACY_SOURCES = (
    "tools/finalize.py",
    "tools/project.py",
    "tools/task_rollover.py",
    "tools/entity.py",
    "tools/done_log.py",
    "tools/trails.py",
    "tools/reading_state.py",
    "tools/notify.py",
    "tools/system_audit.py",
)
GOLDEN = json.loads(
    (Path(__file__).with_name("golden_observations.json")).read_text("utf-8")
)["observations"]


def _write_trace(path: Path, events: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(event) + "\n" for event in events), "utf-8")


def test_opt_in_config_fails_closed_when_legacy_is_writable(tmp_path):
    config = tmp_path / "config.toml"
    config.write_text(
        '[migration.legacy_vault]\npath = "/synthetic/legacy"\nread_only = false\n',
        "utf-8",
    )

    with pytest.raises(RuntimeError, match="read_only=true"):
        resolve_read_only_legacy(config)


def test_opt_in_loader_is_no_bytecode_and_restores_module_state(tmp_path, monkeypatch):
    scripts = tmp_path / "system/scripts"
    source = scripts / "tools/synthetic_contract.py"
    source.parent.mkdir(parents=True)
    source.write_text("VALUE = 'synthetic'\n", "utf-8")
    module_name = "_lifeos_characterization_cache_miss"
    previous = ModuleType(module_name)
    monkeypatch.setitem(sys.modules, module_name, previous)
    monkeypatch.setattr(sys, "dont_write_bytecode", False)

    with loaded_legacy_module(scripts, "tools/synthetic_contract.py", module_name) as module:
        assert module.VALUE == "synthetic"
        assert sys.dont_write_bytecode is True
        assert sys.modules[module_name] is module

    assert sys.dont_write_bytecode is False
    assert sys.modules[module_name] is previous
    assert not (source.parent / "__pycache__").exists()
    assert not list(tmp_path.rglob("*.pyc"))


def _opt_in_scripts_root() -> Path:
    raw_config = os.environ.get("LIFEOS_LEGACY_CHARACTERIZATION_CONFIG")
    if not raw_config:
        pytest.skip(
            "set LIFEOS_LEGACY_CHARACTERIZATION_CONFIG for exact read-only comparison"
        )
    return resolve_read_only_legacy(Path(raw_config)) / "system/scripts"


def test_opt_in_exact_legacy_characterization(tmp_path, monkeypatch, capsys):
    scripts = _opt_in_scripts_root()
    before_hashes = source_hashes(scripts, LEGACY_SOURCES)
    before_bytecode = bytecode_snapshot(scripts)
    observations = {}

    with loaded_legacy_module(
        scripts, "tools/task_rollover.py", "_lifeos_legacy_task_rollover"
    ) as rollover:
        rollover_root = tmp_path / "rollover-vault"
        source = rollover_root / "tasks/today.md"
        snapshot_dir = rollover_root / "agent/logs/tasks"
        preimage = rollover_root / "preimage.md"
        task_text = (
            "---\ndate: \"2026-01-15\"\n---\n\n"
            "- [x] Synthetic completed task\n"
            "> fb: deterministic fixture feedback\n"
            "> continuation without personal prose\n"
        )
        source.parent.mkdir(parents=True)
        source.write_text(task_text, "utf-8")
        preimage.write_text(task_text, "utf-8")
        assert rollover.extract_frontmatter_date(task_text) == "2026-01-15"
        blocks = rollover.parse_feedback_blocks(task_text)
        assert blocks == [
            (
                "- [x] Synthetic completed task",
                "deterministic fixture feedback continuation without personal prose",
            )
        ]
        rendered = rollover.render_review("2026-01-15", blocks)
        assert "## \u041c\u0435\u0442\u0430" in rendered
        assert "## \u0416\u0434\u0443 \u0440\u0435\u0448\u0435\u043d\u0438\u044f" in rendered
        assert rollover.snapshot_today(source, snapshot_dir).is_file()
        events = [{"event": "snapshot"}]
        source.write_text("# Synthetic replacement\n", "utf-8")
        events.append({"event": "replace"})
        _write_trace(rollover_root / "trace.jsonl", events)
        observations["task_rollover"] = OBSERVERS["task_rollover"](
            ObservationInput(root=rollover_root)
        )

    with loaded_legacy_module(
        scripts, "tools/project.py", "_lifeos_legacy_project"
    ) as project:
        projects = tmp_path / "project-vault/projects"
        active = projects / "portable-project"
        active.mkdir(parents=True)
        (active / "project.json").write_text(
            json.dumps({"slug": "portable-project", "status": "active"}), "utf-8"
        )
        (active / "state.json").write_text(json.dumps(project.empty_state()), "utf-8")
        (active / "log.md").write_text("# Synthetic project log\n", "utf-8")
        engine = active / "research/portable-engine"
        engine.mkdir(parents=True)
        (engine / "project.json").write_text(
            json.dumps({"status": "active"}), "utf-8"
        )
        schedule = projects.parent / "agent/schedule/portable-schedule.json"
        schedule.parent.mkdir(parents=True)
        schedule.write_text(
            json.dumps(
                {
                    "status": "active",
                    "_project_slug": "portable-project",
                }
            ),
            "utf-8",
        )
        monkeypatch.setattr(project, "PROJECTS_DIR", projects)
        monkeypatch.setattr(project, "now_iso", lambda: "2026-01-15T10:00:00Z")
        project.cmd_archive(
            argparse.Namespace(
                slug="portable-project",
                cascade=True,
                keep_engines_active=False,
            )
        )
        observations["project_transitions"] = OBSERVERS["project_transitions"](
            ObservationInput(root=projects.parent)
        )

    with loaded_legacy_module(
        scripts, "tools/entity.py", "_lifeos_legacy_entity"
    ) as entity:
        entity_root = tmp_path / "entity-vault"
        entities_dir = entity_root / "agent/memory/entities"
        (entities_dir / "ai").mkdir(parents=True)
        existing = entity.Entity(
            id="ent-001",
            name="Synthetic initiative",
            scale="initiative",
            status="active",
            owner="human",
            domain="ai",
            created="2026-01-15",
        )
        monkeypatch.setattr(entity, "DOMAINS_DIR", entities_dir)
        monkeypatch.setattr(entity, "render_markdown", lambda domain, entities: None)
        entity.save_entities("ai", [existing])
        assert entity.next_id({"ai": [existing]}) == "ent-002"

    with loaded_legacy_module(
        scripts, "tools/done_log.py", "_lifeos_legacy_done_log"
    ) as done_log:
        logs_dir = entity_root / "agent/logs"
        done_path = logs_dir / "done_log.json"
        monkeypatch.setattr(done_log, "LOGS_DIR", logs_dir)
        monkeypatch.setattr(done_log, "LOG_PATH", done_path)
        monkeypatch.setattr(done_log, "ARCHIVE_PATH", logs_dir / "done_log_archive.json")
        done_log.cmd_add(
            argparse.Namespace(
                item="Synthetic event",
                date="2026-01-15",
                domain="ai",
                context="fixture",
                delay=5,
            )
        )

    with loaded_legacy_module(
        scripts, "tools/trails.py", "_lifeos_legacy_trails"
    ) as trails:
        trail_dir = entity_root / "agent/memory/trails"
        monkeypatch.setattr(trails, "TRAILS_DIR", trail_dir)
        trails.log_action("ent-001", "ping", allow_orphan=True)
        trails.log_action("ent-001", "silent", allow_orphan=True)
        assert trails.consecutive_silent("ent-001") == 1
        observations["entity_done_trails"] = OBSERVERS["entity_done_trails"](
            ObservationInput(
                root=entity_root,
                entity_path="agent/memory/entities/ai/entities.json",
                done_path="agent/logs/done_log.json",
            )
        )

    with loaded_legacy_module(
        scripts, "tools/reading_state.py", "_lifeos_legacy_reading"
    ) as reading:
        reading_dir = tmp_path / "reading-vault/agent/reading"
        monkeypatch.setattr(reading, "READING_DIR", reading_dir)
        monkeypatch.setattr(reading, "VAULT_ROOT", tmp_path / "reading-vault")
        monkeypatch.setattr(reading, "today", lambda: "2026-01-15")
        reading.write_state(
            "portable-handbook",
            {
                "slug": "portable-handbook",
                "title": "Portable Systems Handbook",
                "started_at": "2026-01-15",
                "current_chapter": 1,
                "anchors": [],
                "last_session": None,
                "log_path": "agent/reading/portable-handbook-log.md",
            },
        )
        reading.cmd_advance("portable-handbook", chapter=2, note="synthetic note")
        state = reading.cmd_anchor("portable-handbook", "Synthetic anchor", chapter=2)
        assert state["current_chapter"] == 2 and len(state["anchors"]) == 1
        assert (reading_dir / "portable-handbook-log.md").is_file()
        monkeypatch.setattr(reading.book_manifest, "cmd_set_status", lambda slug, status: None)
        monkeypatch.setattr(reading, "_close_linked_done_log", lambda slug, decision, reason: None)
        reading.cmd_close("portable-handbook", "finished")
        observations["reading"] = OBSERVERS["reading"](
            ObservationInput(root=tmp_path / "reading-vault")
        )

    with loaded_legacy_module(
        scripts, "tools/notify.py", "_lifeos_legacy_notify"
    ) as notify:
        surface_root = tmp_path / "surface-vault"
        silent = surface_root / "silent-review.md"
        gated = surface_root / "gated-review.md"
        silent.parent.mkdir(parents=True)
        silent.write_text("---\nsurface: silent\n---\n# Synthetic review\n", "utf-8")
        gated.write_text("---\nsurface: gated\n---\n# Synthetic review\n", "utf-8")
        surface_events = []

        def fake_delivery(
            text, sent, channel, reason, title="", review=None, forced=False
        ):
            surface_events.append(
                {
                    "surface": notify.read_surface(Path(review)),
                    "action": "send" if sent else "suppress",
                }
            )

        monkeypatch.setattr(notify, "notify", lambda *args, **kwargs: True)
        monkeypatch.setattr(notify, "log_delivery", fake_delivery)
        for review in (silent, gated):
            monkeypatch.setattr(
                sys,
                "argv",
                [
                    "notify.py",
                    "Synthetic notification",
                    "--review",
                    str(review),
                    "--no-availability",
                ],
            )
            notify.main()
        _write_trace(surface_root / "trace.jsonl", surface_events)
        observations["surface"] = OBSERVERS["surface"](
            ObservationInput(root=surface_root)
        )

    with loaded_legacy_module(
        scripts, "tools/finalize.py", "_lifeos_legacy_finalize"
    ) as finalize:
        vault = tmp_path / "finalize-vault"
        review_dir = vault / "review"
        review_dir.mkdir(parents=True)
        review = review_dir / "rev_fixture.md"
        review.write_text("# Synthetic review\n", "utf-8")
        captured: list[tuple[str, dict]] = []
        monkeypatch.setattr(finalize, "VAULT_ROOT", vault)
        monkeypatch.setattr(finalize, "REVIEW_DIR", review_dir)
        monkeypatch.setattr(finalize, "TRASH_DIR", vault / "_trash")
        monkeypatch.setattr(
            finalize,
            "APPLY_MARKERS_DIR",
            vault / "agent/_buffer/apply-in-progress",
        )
        monkeypatch.setattr(
            finalize, "log_stats", lambda event, **meta: captured.append((event, meta))
        )
        monkeypatch.setattr(finalize, "append_to_log", lambda line: None)
        finalize.cmd_begin(
            argparse.Namespace(
                review="review/rev_fixture.md",
                planned_files="knowledge/domains/ai/portable-workflow.md",
            )
        )
        result = finalize.cmd_apply(
            argparse.Namespace(
                review="review/rev_fixture.md",
                log_note=None,
                keep_review=False,
                conflict_check="clean",
                conflict_count=0,
                updated_files="knowledge/domains/ai/portable-workflow.md",
                entities_changed="",
            )
        )
        assert result["ok"] is True and result["evidence"] is True
        assert not review.exists() and (vault / "_trash/rev_fixture.md").is_file()
        assert any(event == "review-apply" for event, _ in captured)
        assert not list((vault / "agent/_buffer/apply-in-progress").glob("*.json"))
        observations["review_apply"] = OBSERVERS["review_apply"](
            ObservationInput(root=vault)
        )

        finalize_events = []
        attempt = {"number": 0}

        def fake_validate(files):
            finalize_events.append(
                {"attempt": attempt["number"], "event": "validate"}
            )
            return []

        def fake_stats(event, **meta):
            finalize_events.append(
                {"attempt": attempt["number"], "event": "metrics"}
            )

        monkeypatch.setattr(finalize, "validate_critical_files", fake_validate)
        monkeypatch.setattr(finalize, "log_stats", fake_stats)
        for number in (1, 2):
            attempt["number"] = number
            transform = finalize.cmd_transform(
                argparse.Namespace(
                    skill="lint",
                    validate_files=["synthetic.json"],
                    action=None,
                )
            )
            assert transform["ok"] is True
            finalize_events.append({"attempt": number, "event": "success"})
        _write_trace(vault / "trace.jsonl", finalize_events)
        observations["finalize"] = OBSERVERS["finalize"](
            ObservationInput(root=vault)
        )

    capsys.readouterr()
    with loaded_legacy_module(
        scripts, "tools/system_audit.py", "_lifeos_legacy_system_audit"
    ) as system_audit:
        audit_root = tmp_path / "audit-vault"
        redirected = {
            "VAULT_ROOT": audit_root,
            "BUFFER_DIR": audit_root / "agent/_buffer",
            "STATS_FILE": audit_root / "agent/stats.json",
            "RUNS_DIR": audit_root / "agent/logs/runs",
            "TRACES_DIR": audit_root / "agent/logs/traces",
            "SETTINGS_FILE": audit_root / ".claude/settings.json",
            "PROJECT_SKILLS_DIR": audit_root / ".claude/skills",
            "SCRIPTS_TOOLS_DIR": audit_root / "system/scripts/tools",
            "WIKI_LOG": audit_root / "knowledge/log.md",
            "TASKS_TODAY": audit_root / "tasks/today.md",
            "PROJECTS_DIR": audit_root / "projects",
            "SCHEDULE_DIR": audit_root / "agent/schedule",
            "REVIEW_DIR": audit_root / "review",
        }
        for name, path in redirected.items():
            monkeypatch.setattr(system_audit, name, path)
        with pytest.raises(SystemExit) as exited:
            system_audit.cmd_run(
                argparse.Namespace(
                    section=["A"],
                    window_alive=30,
                    window_correct=14,
                    format="json",
                    print=False,
                    fail_on=[],
                )
            )
        assert exited.value.code == 0
        payload = json.loads(capsys.readouterr().out)
        assert {
            "date",
            "report_path",
            "windows",
            "sections",
            "summary",
            "findings",
        } == set(payload)
        assert (audit_root / payload["report_path"]).is_file()

    assert set(observations) == set(OBSERVERS)
    for group, actual in observations.items():
        assert comparison_failures(group, actual, GOLDEN[group]) == set()
    assert source_hashes(scripts, LEGACY_SOURCES) == before_hashes
    assert bytecode_snapshot(scripts) == before_bytecode
