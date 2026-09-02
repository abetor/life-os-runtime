import copy
import json
import os
import re
from datetime import date
from pathlib import Path

import pytest

from tool_life_os_runtime.dev_manifest.scanner import (
    Candidate,
    ManifestError,
    _python_execution_target,
    _source_ref,
    _source_set_digest,
    _validate_candidates,
    build_manifest,
    main,
    render_markdown,
    resolve_legacy_vault,
    verify_artifact_pair,
    write_artifacts,
)


def _write(path: Path, body: str = "") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, "utf-8")


def _fixture_vault(root: Path, *, unknown_script: bool = False) -> Path:
    vault = root / "private-person-vault"
    _write(vault / ".gitignore", "__pycache__/\nsystem/scripts/config.json\n")
    (vault / ".git").mkdir(parents=True)
    _write(vault / ".claude/skills/ingest/SKILL.md", "run system/scripts/tools/ingest_route.py\n")
    _write(vault / ".claude/skills/_archive/old/SKILL.md", "must not be inventoried\n")
    _write(vault / ".claude/skills/_shared/review-template.md", "empty fixture template\n")
    _write(vault / ".agents/skills/work-obsidian-ingest/SKILL.md", "generated wrapper\n")
    _write(vault / "system/scripts/tools/ingest_route.py", "# ingest fixture\n")
    _write(vault / "system/scripts/tools/__pycache__/ingest_route.pyc", "generated cache\n")
    _write(vault / "system/scripts/config.json", '{"local": "private"}\n')
    _write(vault / "system/scripts/hooks/session_start.py", "# hook fixture\n")
    _write(vault / "system/templates/new.md", "# empty fixture\n")
    _write(
        vault / "agent/schedule/private-meeting-with-private-name.json",
        json.dumps(
            {
                "status": "active",
                "name": "private prose must never leave source",
                "prompt": "secret personal payload",
                "command": ["python", "system/scripts/tools/ingest_route.py"],
                "last_run": "2026-08-19T08:00:00+05:00",
                "last_result": "success",
            },
            ensure_ascii=False,
        ),
    )
    _write(
        vault / "agent/schedule/completed-private.json",
        json.dumps({"status": "completed", "prompt": "also private"}),
    )
    if unknown_script:
        _write(vault / "system/scripts/tools/not_classified.py", "# new unknown source\n")
    return vault


def _record_for(manifest, relative_path: str):
    source_ref = _source_ref(relative_path)
    return next(record for record in manifest["records"] if record["source_ref"] == source_ref)


def test_manifest_is_reconciled_classified_and_privacy_safe(tmp_path):
    vault = _fixture_vault(tmp_path)

    manifest = build_manifest(vault, date(2026, 8, 19))
    json_body = json.dumps(manifest, ensure_ascii=False)
    markdown = render_markdown(manifest)
    combined = json_body + markdown

    assert manifest["reconciliation"] == {
        "method": "whole-root rg --files --hidden then documented-scope filter",
        "ok": True,
        "source_count": 7,
        "source_set_sha256": _source_set_digest(
            {
                ".claude/skills/ingest/SKILL.md",
                ".claude/skills/_shared/review-template.md",
                ".agents/skills/work-obsidian-ingest/SKILL.md",
                "system/scripts/tools/ingest_route.py",
                "system/scripts/hooks/session_start.py",
                "system/templates/new.md",
                "agent/schedule/private-meeting-with-private-name.json",
            }
        ),
        "duplicates": [],
        "unclassified": [],
    }
    assert all(record["target"] for record in manifest["records"])
    assert all(record["target"] != "owner-decision" for record in manifest["records"])
    ingest_script = _record_for(manifest, "system/scripts/tools/ingest_route.py")
    schedule_ref = next(record["source_ref"] for record in manifest["records"] if record["kind"] == "schedule")
    assert set(ingest_script["usage_refs"]) == {
        _source_ref(".claude/skills/ingest/SKILL.md"),
        schedule_ref,
    }
    assert ingest_script["last_known_run"] == {
        "at": "2026-08-19T08:00:00+05:00",
        "result": "success",
        "evidence": schedule_ref,
    }
    assert all(re.fullmatch(r"source:sha256:[0-9a-f]{64}", record["source_ref"]) for record in manifest["records"])
    assert all(
        ref == "legacy-scheduler" or re.fullmatch(r"source:sha256:[0-9a-f]{64}", ref)
        for record in manifest["records"]
        for ref in record["usage_refs"]
    )
    assert str(vault) not in combined
    for private_text in (
        "private-meeting-with-private-name",
        "private prose must never leave source",
        "secret personal payload",
        "completed-private",
        "system/scripts/tools/ingest_route.py",
        ".claude/skills/ingest/SKILL.md",
    ):
        assert private_text not in combined


def test_private_names_in_every_scoped_path_kind_are_hashed(tmp_path):
    vault = _fixture_vault(tmp_path)
    private_marker = "private-client-albatross"
    private_paths = (
        f".claude/skills/{private_marker}/SKILL.md",
        f"system/scripts/tools/{private_marker}/ingest_route.py",
        f"system/templates/{private_marker}/note-template.md",
    )
    for relative in private_paths:
        _write(vault / relative, "empty synthetic fixture\n")

    manifest = build_manifest(vault, date(2026, 8, 19))
    json_path, markdown_path = write_artifacts(manifest, tmp_path / "published")
    combined = json_path.read_text("utf-8") + markdown_path.read_text("utf-8")

    assert private_marker not in combined
    assert all(_record_for(manifest, relative)["source_ref_kind"] == "sha256" for relative in private_paths)


@pytest.mark.parametrize("link_kind", ["file", "directory"])
def test_external_symlink_in_scoped_root_fails_before_artifact_write(tmp_path, link_kind):
    vault = _fixture_vault(tmp_path)
    external = tmp_path / "external"
    external.mkdir()
    output = tmp_path / "artifacts"
    if link_kind == "file":
        target = external / "outside.md"
        target.write_text("outside\n", "utf-8")
        (vault / "system/templates/external-link.md").symlink_to(target)
    else:
        (external / "outside.md").write_text("outside\n", "utf-8")
        (vault / "system/templates/external-link-dir").symlink_to(external, target_is_directory=True)

    with pytest.raises(ManifestError, match="symlink"):
        manifest = build_manifest(vault, date(2026, 8, 19))
        write_artifacts(manifest, output)

    assert not output.exists()


def test_prose_words_do_not_count_as_usage_or_last_run(tmp_path):
    vault = _fixture_vault(tmp_path)
    for skill_name in ("plan", "apply"):
        _write(vault / f".claude/skills/{skill_name}/SKILL.md", "synthetic skill\n")
    _write(vault / "system/templates/prose-only.md", "Words plan and apply are ordinary prose here.\n")
    _write(
        vault / "agent/schedule/prose-only.json",
        json.dumps(
            {
                "status": "active",
                "prompt": "Please plan a result and apply careful reasoning.",
                "last_run": "2026-08-19T09:00:00+05:00",
                "last_result": "success",
            }
        ),
    )

    manifest = build_manifest(vault, date(2026, 8, 19))
    prose_schedule_ref = _source_ref("agent/schedule/prose-only.json")

    for skill_name in ("plan", "apply"):
        record = _record_for(manifest, f".claude/skills/{skill_name}/SKILL.md")
        assert prose_schedule_ref not in record["usage_refs"]
        assert record["last_known_run"] is None


def test_short_module_imports_and_python_m_argv_count_but_prose_does_not(tmp_path):
    vault = _fixture_vault(tmp_path)
    modules = {
        "system/scripts/utils/url_policy.py": "utils.url_policy",
        "system/scripts/tools/lint_health.py": "tools.lint_health",
        "system/scripts/infra/task.py": "infra.task",
        "system/scripts/hooks/session_start.py": "hooks.session_start",
    }
    for relative in modules:
        _write(vault / relative, "# synthetic module fixture\n")
    importer = "system/scripts/tests/test_harness_fixes.py"
    _write(
        vault / importer,
        "from utils import lint_infra\n"
        "from utils import (\n"
        "    url_policy as policy,\n"
        ")\n"
        "from tools import lint_health as lint_health\n"
        "from infra import task, scheduler as scheduler_module\n"
        "from hooks import session_start as hook\n",
    )
    _write(vault / "system/scripts/utils/lint_infra.py", "# exact live import-form fixture\n")
    _write(vault / "system/scripts/infra/scheduler.py", "# parent-package multi-import fixture\n")
    _write(
        vault / "system/templates/module-prose.md",
        "Ordinary prose mentions utils.url_policy, tools.lint_health, infra.task, and hooks.session_start.\n",
    )
    module_schedule = "agent/schedule/module-argv.json"
    _write(
        vault / module_schedule,
        json.dumps(
            {
                "status": "active",
                "execution": "command",
                "command": ["python3", "-u", "-m", "tools.lint_health"],
                "last_run": "2026-08-19T10:00:00+05:00",
                "last_result": "success",
            }
        ),
    )
    script_schedule = "agent/schedule/script-argv.json"
    _write(
        vault / script_schedule,
        json.dumps(
            {
                "status": "active",
                "execution": "command",
                "command": ["python3", "-I", "system/scripts/tools/lint_health.py"],
                "last_run": "2026-08-19T09:30:00+05:00",
                "last_result": "success",
            }
        ),
    )
    direct_schedule = "agent/schedule/direct-script-argv.json"
    _write(
        vault / direct_schedule,
        json.dumps(
            {
                "status": "active",
                "execution": "command",
                "command": ["system/scripts/tools/lint_health.py", "--check"],
                "last_run": "2026-08-19T09:45:00+05:00",
                "last_result": "success",
            }
        ),
    )
    prose_schedule = "agent/schedule/module-prose.json"
    _write(
        vault / prose_schedule,
        json.dumps(
            {
                "status": "active",
                "execution": "command",
                "command": "python3 -m tools.lint_health",
                "prompt": (
                    "Quoted prose says 'python3 system/scripts/tools/lint_health.py' "
                    "and discusses utils.url_policy."
                ),
                "last_run": "2026-08-19T11:00:00+05:00",
                "last_result": "success",
            }
        ),
    )
    echo_schedule = "agent/schedule/module-echo.json"
    _write(
        vault / echo_schedule,
        json.dumps(
            {
                "status": "active",
                "execution": "command",
                "command": ["echo", "system/scripts/tools/lint_health.py"],
                "last_run": "2026-08-19T12:00:00+05:00",
                "last_result": "success",
            }
        ),
    )
    shell_schedule = "agent/schedule/module-shell.json"
    _write(
        vault / shell_schedule,
        json.dumps(
            {
                "status": "active",
                "execution": "command",
                "command": ["sh", "-c", "python3 system/scripts/tools/lint_health.py"],
                "last_run": "2026-08-19T13:00:00+05:00",
                "last_result": "success",
            }
        ),
    )
    terminal_schedule = "agent/schedule/module-terminal-flag.json"
    _write(
        vault / terminal_schedule,
        json.dumps(
            {
                "status": "active",
                "execution": "command",
                "command": ["python3", "--help", "-m", "tools.lint_health"],
                "last_run": "2026-08-19T14:00:00+05:00",
                "last_result": "success",
            }
        ),
    )
    separator_schedule = "agent/schedule/module-after-separator.json"
    _write(
        vault / separator_schedule,
        json.dumps(
            {
                "status": "active",
                "execution": "command",
                "command": ["python3", "--", "-m", "tools.lint_health"],
                "last_run": "2026-08-19T15:00:00+05:00",
                "last_result": "success",
            }
        ),
    )

    manifest = build_manifest(vault, date(2026, 8, 19))
    importer_ref = _source_ref(importer)
    prose_template_ref = _source_ref("system/templates/module-prose.md")
    prose_schedule_ref = _source_ref(prose_schedule)
    echo_schedule_ref = _source_ref(echo_schedule)
    shell_schedule_ref = _source_ref(shell_schedule)
    terminal_schedule_ref = _source_ref(terminal_schedule)
    separator_schedule_ref = _source_ref(separator_schedule)

    imported_modules = {
        *modules,
        "system/scripts/utils/lint_infra.py",
        "system/scripts/infra/scheduler.py",
    }
    for relative in imported_modules:
        record = _record_for(manifest, relative)
        assert importer_ref in record["usage_refs"]
        assert prose_template_ref not in record["usage_refs"]
        assert prose_schedule_ref not in record["usage_refs"]
        assert echo_schedule_ref not in record["usage_refs"]
        assert shell_schedule_ref not in record["usage_refs"]
        assert terminal_schedule_ref not in record["usage_refs"]
        assert separator_schedule_ref not in record["usage_refs"]
    lint_record = _record_for(manifest, "system/scripts/tools/lint_health.py")
    assert _source_ref(module_schedule) in lint_record["usage_refs"]
    assert _source_ref(script_schedule) in lint_record["usage_refs"]
    assert _source_ref(direct_schedule) in lint_record["usage_refs"]
    assert lint_record["last_known_run"] == {
        "at": "2026-08-19T10:00:00+05:00",
        "result": "success",
        "evidence": _source_ref(module_schedule),
    }


def test_python_code_usage_requires_ast_import_or_literal_executable_argv(tmp_path):
    vault = _fixture_vault(tmp_path)
    target = "system/scripts/tools/lint_health.py"
    negative_source = "system/scripts/tests/test_harness_fixes.py"
    positive_source = "system/scripts/tests/test_audit_regressions.py"
    _write(vault / target, "# synthetic executable target\n")
    _write(
        vault / negative_source,
        "import subprocess\n"
        "PROSE = 'echo python3 -m tools.lint_health'\n"
        "subprocess.run(['echo', 'system/scripts/tools/lint_health.py'])\n"
        "subprocess.run(['sh', '-c', 'python3 system/scripts/tools/lint_health.py'])\n",
    )
    _write(
        vault / positive_source,
        "import subprocess\n"
        "subprocess.run(['python3', '-u', '-m', 'tools.lint_health'])\n",
    )

    record = _record_for(build_manifest(vault, date(2026, 8, 19)), target)

    assert _source_ref(positive_source) in record["usage_refs"]
    assert _source_ref(negative_source) not in record["usage_refs"]


def test_relative_imports_resolve_against_full_and_short_importer_packages(tmp_path):
    vault = _fixture_vault(tmp_path)
    same_package_source = "system/scripts/utils/lint_infra.py"
    nested_parent_source = "system/scripts/tests/nested/test_harness_fixes.py"
    targets = {
        "system/scripts/utils/derived_signals.py": same_package_source,
        "system/scripts/utils/vault.py": same_package_source,
        "system/scripts/tests/eval_apply.py": nested_parent_source,
    }
    for relative in targets:
        _write(vault / relative, "# synthetic relative-import target\n")
    _write(
        vault / same_package_source,
        "from .derived_signals import answered_with_open_tasks\n"
        "from . import vault as vault_module\n",
    )
    _write(
        vault / nested_parent_source,
        "from .. import (\n"
        "    eval_apply as apply_fixture,\n"
        ")\n",
    )

    manifest = build_manifest(vault, date(2026, 8, 19))

    for target, source in targets.items():
        assert _source_ref(source) in _record_for(manifest, target)["usage_refs"]


@pytest.mark.parametrize(
    ("argv", "expected"),
    [
        (["python3", "-h", "system/scripts/tools/lint_health.py"], None),
        (["python3", "--help", "-m", "tools.lint_health"], None),
        (["python3", "-V", "system/scripts/tools/lint_health.py"], None),
        (["python3", "--version", "-m", "tools.lint_health"], None),
        (
            ["python3", "-I", "--", "system/scripts/tools/lint_health.py"],
            ("script", "system/scripts/tools/lint_health.py"),
        ),
        (["python3", "--", "-m", "tools.lint_health"], ("script", "-m")),
    ],
)
def test_python_execution_terminal_flags_and_separator(argv, expected):
    assert _python_execution_target(argv) == expected


def test_split_ownership_keeps_one_primary_and_explicit_handoffs(tmp_path):
    vault = _fixture_vault(tmp_path)
    expected = {
        "system/scripts/tools/book_manifest.py": (
            "runtime",
            ["connector:coursedump"],
            ["runtime:reading-lifecycle -> connector:coursedump:source-extraction"],
        ),
        "system/scripts/tools/auto_research.py": (
            "connector:researcher",
            ["runtime"],
            ["runtime:research-recipe -> connector:researcher:execution"],
        ),
        "system/scripts/tools/engine_watchdog.py": (
            "connector:scheduler",
            ["connector:researcher"],
            ["connector:researcher:run-state -> connector:scheduler:cadence-retry"],
        ),
        "system/scripts/tools/notify.py": (
            "runtime",
            ["connector:gateway"],
            ["runtime:semantic-selection -> connector:gateway:transport"],
        ),
    }
    for relative in expected:
        _write(vault / relative, "# synthetic split fixture\n")

    manifest = build_manifest(vault, date(2026, 8, 19))

    for relative, (primary, secondary, handoffs) in expected.items():
        record = _record_for(manifest, relative)
        assert record["target"] == primary
        assert record["secondary_targets"] == secondary
        assert record["handoffs"] == handoffs
        assert primary not in record["secondary_targets"]


def test_duplicate_source_fails():
    private_marker = "private-client-albatross"
    duplicate = Candidate(f"system/templates/{private_marker}.md", "template")
    with pytest.raises(ManifestError, match="duplicate sources") as caught:
        _validate_candidates([duplicate, duplicate])
    message = str(caught.value)
    assert "count=1" in message
    assert _source_ref(duplicate.relative_path) in message
    assert private_marker not in message


def test_unclassified_error_uses_only_count_and_hashed_ref():
    private_marker = "private-client-oriole"
    relative = f"system/scripts/tools/{private_marker}.py"

    with pytest.raises(ManifestError, match="unclassified sources") as caught:
        _validate_candidates([Candidate(relative, "script")])

    message = str(caught.value)
    assert "count=1" in message
    assert _source_ref(relative) in message
    assert private_marker not in message


def test_independent_reconciliation_runs_one_whole_root_rg_then_filters(tmp_path, monkeypatch):
    from tool_life_os_runtime.dev_manifest import scanner as scanner_module

    vault = _fixture_vault(tmp_path)
    _write(vault / "knowledge/out-of-scope.md", "not inventory source\n")
    calls = []
    real_run = scanner_module.subprocess.run

    def recording_run(argv, **kwargs):
        calls.append(argv)
        return real_run(argv, **kwargs)

    monkeypatch.setattr(scanner_module.subprocess, "run", recording_run)
    sources = scanner_module.independent_rg_source_set(vault)

    assert len(calls) == 1
    assert calls[0][:3] == ["rg", "--files", "--hidden"]
    assert calls[0][-1] == str(vault.resolve())
    assert "knowledge/out-of-scope.md" not in sources
    assert "system/scripts/tools/ingest_route.py" in sources


def test_unclassified_source_fails_before_artifact_write(tmp_path):
    vault = _fixture_vault(tmp_path, unknown_script=True)
    output = tmp_path / "artifacts"

    with pytest.raises(ManifestError, match="unclassified sources"):
        manifest = build_manifest(vault, date(2026, 8, 19))
        write_artifacts(manifest, output)

    assert not output.exists()


@pytest.mark.parametrize("failure", ["unclassified", "malformed"])
def test_cli_error_stdout_never_leaks_private_candidate_path(tmp_path, capsys, failure):
    vault = _fixture_vault(tmp_path)
    private_marker = "private-client-kingfisher"
    if failure == "unclassified":
        relative = f"system/scripts/tools/{private_marker}.py"
        _write(vault / relative, "# unknown synthetic source\n")
        expected = "unclassified sources"
    else:
        relative = f"agent/schedule/{private_marker}.json"
        _write(vault / relative, "{ malformed private payload")
        expected = "invalid schedule JSON"
    config = tmp_path / "config.toml"
    config.write_text(f'[migration.legacy_vault]\npath = "{vault}"\nread_only = true\n', "utf-8")

    assert main(["--config", str(config), "--output-dir", str(tmp_path / "out"), "--date", "2026-08-19"]) == 1

    stdout = capsys.readouterr().out
    assert expected in stdout
    assert "count=1" in stdout
    assert _source_ref(relative) in stdout
    assert private_marker not in stdout
    assert relative not in stdout


def test_config_requires_explicit_read_only_legacy_root(tmp_path):
    vault = _fixture_vault(tmp_path)
    config = tmp_path / "config.toml"
    config.write_text(f'[migration.legacy_vault]\npath = "{vault}"\nread_only = false\n', "utf-8")

    with pytest.raises(ManifestError, match="explicitly read_only"):
        resolve_legacy_vault(config)


@pytest.mark.parametrize("output_location", ["same", "child", "parent"])
def test_cli_rejects_output_overlapping_read_only_legacy(tmp_path, output_location, capsys):
    vault = _fixture_vault(tmp_path)
    config = tmp_path / "config.toml"
    config.write_text(f'[migration.legacy_vault]\npath = "{vault}"\nread_only = true\n', "utf-8")
    output = {"same": vault, "child": vault / "generated", "parent": vault.parent}[output_location]

    assert main(["--config", str(config), "--output-dir", str(output), "--date", "2026-08-19"]) == 1
    assert "overlaps the read-only legacy vault" in capsys.readouterr().out
    assert not (output / "migration-manifest-2026-08-19.json").exists()
    assert not (output / "migration-manifest-2026-08-19.md").exists()


def test_artifacts_are_atomic_views_of_same_manifest(tmp_path):
    manifest = build_manifest(_fixture_vault(tmp_path), date(2026, 8, 19))
    json_path, markdown_path = write_artifacts(manifest, tmp_path / "docs")

    authoritative = json.loads(json_path.read_text("utf-8"))
    assert {key: value for key, value in authoritative.items() if key != "artifact_pair"} == manifest
    assert authoritative["artifact_pair"]["authoritative"] == "json"
    assert markdown_path.read_text("utf-8") == render_markdown(manifest)
    verify_artifact_pair(json_path, markdown_path)
    assert not list((tmp_path / "docs").glob("*.tmp"))
    assert not list((tmp_path / "docs").glob("*.prepared"))


def test_json_is_committed_last_and_detects_partial_pair_failure(tmp_path):
    output = tmp_path / "docs"
    original = build_manifest(_fixture_vault(tmp_path), date(2026, 8, 19))
    json_path, markdown_path = write_artifacts(original, output)
    original_json = json_path.read_bytes()
    original_markdown = markdown_path.read_bytes()
    updated = copy.deepcopy(original)
    updated["records"][0]["outcome"] = "updated-synthetic-outcome"

    def fail_authoritative_json(source: Path, target: Path) -> None:
        if target.suffix == ".json":
            raise OSError("injected authoritative commit failure")
        os.replace(source, target)

    with pytest.raises(OSError, match="injected authoritative"):
        write_artifacts(updated, output, _replace=fail_authoritative_json)

    assert json_path.read_bytes() == original_json
    assert markdown_path.read_bytes() != original_markdown
    with pytest.raises(ManifestError, match="pair mismatch"):
        verify_artifact_pair(json_path, markdown_path)
    assert not list(output.glob("*.prepared"))
