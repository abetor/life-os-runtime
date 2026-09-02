"""Build a privacy-safe migration manifest from a read-only legacy vault.

The scanner is deliberately not registered in the public ``lifeos`` CLI.  It
is a development tool for migration characterization and P5 planning.  The
JSON artifact is authoritative; Markdown is only a generated human view.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import re
import subprocess
import tomllib
from dataclasses import dataclass
from datetime import date
from functools import lru_cache
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Iterable, Mapping, Sequence

from tool_life_os_runtime.shared.fs import atomic_write


TARGETS = frozenset(
    {
        "runtime",
        "connector:coursedump",
        "connector:researcher",
        "connector:scheduler",
        "connector:gateway",
        "private-data",
        "generated-wrapper",
        "retire",
        "owner-decision",
    }
)
_ISO_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?$")
_SAFE_RUN_RESULTS = frozenset({"success", "failed", "completed", "timeout", "missed"})


class ManifestError(RuntimeError):
    """The inventory is incomplete, ambiguous, unsafe, or unreconciled."""


@dataclass(frozen=True)
class Candidate:
    relative_path: str
    kind: str
    metadata: Mapping[str, Any] | None = None


@dataclass(frozen=True)
class Record:
    source_ref: str
    kind: str
    target: str
    secondary_targets: tuple[str, ...]
    handoffs: tuple[str, ...]
    classification_evidence: str
    usage_refs: tuple[str, ...]
    last_known_run: Mapping[str, str] | None


_RUNTIME_SCRIPTS = frozenset(
    {
        "README.md",
        "ambient.py",
        "ambient_evening_job.py",
        "availability.py",
        "book_apply.py",
        "book_manifest.py",
        "codex_skill_sync.py",
        "compile_context.py",
        "correction_extract.py",
        "cross_domain.py",
        "daily_note.py",
        "derived_signals.py",
        "diff_collect.py",
        "done_log.py",
        "entity.py",
        "evening_recap.py",
        "feedback_loop.py",
        "fence_fix.py",
        "finalize.py",
        "hub_refresh.py",
        "inbox_plan.py",
        "ingest_dedup.py",
        "ingest_route.py",
        "link_check.py",
        "lint_health.py",
        "lint_infra.py",
        "lint_mass_creation.py",
        "memory_hygiene.py",
        "mentor_archive.py",
        "mentor_context.py",
        "metrics.py",
        "migrate_entities.py",
        "notify.py",  # tools/notify.py; utils/notify.py is handled separately
        "notify_buffer_check.py",
        "output.py",
        "project.py",
        "project_progress.py",
        "push_quota.py",
        "pusher_context.py",
        "query.py",
        "raw_sync_check.py",
        "reading_state.py",
        "reflect_signals.py",
        "reflection_archive.py",
        "reflection_mortality.py",
        "report_route.py",
        "research_log.py",
        "skill_audit.py",
        "skill_health.py",
        "skill_registry.py",
        "soul_promotion_check.py",
        "source_manifest.py",
        "stats.py",
        "system_audit.py",
        "task_evaluator.py",
        "task_rollover.py",
        "techdebt.py",
        "trails.py",
        "training.py",
        "url_policy.py",
        "validate_note.py",
        "vault-ctl.py",
        "vault-status.py",
        "vault.py",
        "weekly_note.py",
        "wiki_index.py",
        "wiki_log.py",
        "wordcount_ai.py",
    }
)
_COURSEDUMP_SCRIPTS = frozenset(
    {
        "book_split.py",
        "book_stream.py",
        "book_to_md.py",
        "to_markdown.py",
        "tutorial_detect.py",
        "url_transcript.py",
        "yt_transcript.py",
    }
)
_RESEARCHER_SCRIPTS = frozenset(
    {"auto_research.py", "research_engine.py", "youtube_research.py"}
)
_SCHEDULER_SCRIPTS = frozenset(
    {"engine_watchdog.py", "schedule.py", "schedule_contract.py", "scheduler.py", "task.py", "task_schema.py"}
)
_PRIVATE_SCRIPTS = frozenset({"crm_pinger.py", "daily_commit.py", "fun_card.py", "fun_week_plan.py"})
_RETIRE_SCRIPTS = frozenset(
    {
        "com.vault.scheduler.plist",
        "com.vault.telegram.plist",
        "humanize_typography.py",
        "migrate_engine_schema.py",
        "raw_normalize_tags.py",
    }
)
_RUNTIME_TESTS = frozenset(
    {
        "eval_apply.py",
        "eval_ingest.py",
        "eval_judge.py",
        "eval_lint_deep.py",
        "eval_report_extract.py",
        "test_audit_regressions.py",
        "test_harness_fixes.py",
        "test_ingest_route.py",
    }
)
_SCRIPT_OUTCOMES = {
    "crm_pinger.py": "private-reminder-recipe",
    "cross_domain.py": "cross-domain-retrieval",
    "daily_commit.py": "private-repository-maintenance",
    "fun_card.py": "private-nudge-recipe",
    "fun_week_plan.py": "private-week-planning-recipe",
    "humanize_typography.py": "migration-format-normalization",
    "raw_sync_check.py": "source-freshness-check",
    "reflection_mortality.py": "accepted-outcome-metrics",
    "statusline_context.py": "harness-status-context",
    "wordcount_ai.py": "content-size-signal",
}
_SPLIT_OWNERSHIP: Mapping[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    "system/scripts/tools/book_manifest.py": (
        ("connector:coursedump",),
        ("runtime:reading-lifecycle -> connector:coursedump:source-extraction",),
    ),
    "system/scripts/tools/auto_research.py": (
        ("runtime",),
        ("runtime:research-recipe -> connector:researcher:execution",),
    ),
    "system/scripts/tools/engine_watchdog.py": (
        ("connector:researcher",),
        ("connector:researcher:run-state -> connector:scheduler:cadence-retry",),
    ),
    "system/scripts/tools/notify.py": (
        ("connector:gateway",),
        ("runtime:semantic-selection -> connector:gateway:transport",),
    ),
}


def _assert_contained(path: Path, vault: Path) -> None:
    try:
        path.resolve(strict=True).relative_to(vault.resolve(strict=True))
    except (OSError, ValueError) as exc:
        raise ManifestError("scoped source escaped the legacy vault") from exc


def _validate_no_symlinks(root: Path, vault: Path) -> None:
    """Reject links anywhere below a documented source root, even if ignored."""
    try:
        logical_parts = root.relative_to(vault).parts
    except ValueError as exc:
        raise ManifestError("scoped root escaped the legacy vault") from exc
    cursor = vault
    for part in logical_parts:
        cursor = cursor / part
        if cursor.is_symlink():
            raise ManifestError("symlink found in scoped legacy sources")
    if not root.is_dir():
        raise ManifestError("required scoped source directory is missing")
    _assert_contained(root, vault)
    for current, directories, filenames in os.walk(root, followlinks=False):
        base = Path(current)
        for name in sorted([*directories, *filenames]):
            path = base / name
            if path.is_symlink():
                raise ManifestError("symlink found in scoped legacy sources")
            _assert_contained(path, vault)


def _iter_files(root: Path, vault: Path) -> list[Path]:
    _validate_no_symlinks(root, vault)
    found: list[Path] = []
    for current, directories, filenames in os.walk(root, followlinks=False):
        ignored = "__pycache__" in Path(current).relative_to(root).parts
        directories.sort()
        filenames.sort()
        base = Path(current)
        if ignored:
            continue
        found.extend(
            base / filename
            for filename in filenames
            if not filename.endswith((".pyc", ".pyo"))
            and not (root.name == "scripts" and base == root and filename == "config.json")
        )
    return found


def _relative(path: Path, vault: Path) -> str:
    _assert_contained(path, vault)
    try:
        return path.relative_to(vault).as_posix()
    except ValueError as exc:
        raise ManifestError("source escaped the legacy vault") from exc


def _privacy_safe_issue(label: str, relative_paths: Iterable[str]) -> ManifestError:
    refs = sorted({_source_ref(relative_path) for relative_path in relative_paths})
    return ManifestError(f"{label}: count={len(refs)}, refs={','.join(refs)}")


def _read_schedule(path: Path, vault: Path) -> Mapping[str, Any]:
    relative = _relative(path, vault)
    try:
        value = json.loads(path.read_text("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise _privacy_safe_issue("invalid schedule JSON", (relative,)) from exc
    if not isinstance(value, dict):
        raise _privacy_safe_issue("schedule must contain a JSON object", (relative,))
    return value


def discover_candidates(vault: Path) -> list[Candidate]:
    """Enumerate the scoped legacy sources without following directory links."""
    vault = vault.resolve(strict=True)
    candidates: list[Candidate] = []

    claude_skills = vault / ".claude" / "skills"
    scoped_roots = (
        claude_skills,
        vault / ".agents" / "skills",
        vault / "system" / "scripts",
        vault / "system" / "templates",
        vault / "agent" / "schedule",
    )
    for scoped_root in scoped_roots:
        _validate_no_symlinks(scoped_root, vault)
    for child in sorted(claude_skills.iterdir(), key=lambda item: item.name):
        if child.is_dir() and not child.name.startswith("_"):
            candidates.extend(Candidate(_relative(path, vault), "skill") for path in _iter_files(child, vault))

    wrappers = vault / ".agents" / "skills"
    candidates.extend(Candidate(_relative(path, vault), "wrapper") for path in _iter_files(wrappers, vault))

    scripts = vault / "system" / "scripts"
    for path in _iter_files(scripts, vault):
        relative = _relative(path, vault)
        kind = "hook" if relative.startswith("system/scripts/hooks/") else "script"
        candidates.append(Candidate(relative, kind))

    for template_root in (claude_skills / "_shared", vault / "system" / "templates"):
        candidates.extend(Candidate(_relative(path, vault), "template") for path in _iter_files(template_root, vault))

    schedules = vault / "agent" / "schedule"
    for path in sorted(schedules.iterdir(), key=lambda item: item.name):
        if path.is_file() and path.suffix == ".json":
            metadata = _read_schedule(path, vault)
            if metadata.get("status") == "active":
                candidates.append(Candidate(_relative(path, vault), "schedule", metadata))

    return candidates


def _rg_whole_vault(vault: Path) -> list[Path]:
    try:
        completed = subprocess.run(
            ["rg", "--files", "--hidden", "--glob", "!.git/**", str(vault)],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
    except OSError as exc:
        raise ManifestError("rg is required for independent source-set reconciliation") from exc
    if completed.returncode not in (0, 1):
        raise ManifestError("rg --files failed during source-set reconciliation")
    return [Path(line) for line in completed.stdout.splitlines() if line]


def independent_rg_source_set(vault: Path) -> set[str]:
    """Run rg once at the vault root, then filter the documented scope."""
    vault = vault.resolve(strict=True)
    for root in (
        vault / ".claude" / "skills",
        vault / ".agents" / "skills",
        vault / "system" / "scripts",
        vault / "system" / "templates",
        vault / "agent" / "schedule",
    ):
        _validate_no_symlinks(root, vault)
    sources: set[str] = set()
    for path in _rg_whole_vault(vault):
        relative = _relative(path, vault)
        parts = PurePosixPath(relative).parts
        in_active_skill = (
            len(parts) >= 4
            and parts[:2] == (".claude", "skills")
            and not parts[2].startswith("_")
        )
        in_shared_skill_templates = len(parts) >= 4 and parts[:3] == (".claude", "skills", "_shared")
        in_wrappers = len(parts) >= 3 and parts[:2] == (".agents", "skills")
        in_scripts = len(parts) >= 3 and parts[:2] == ("system", "scripts")
        in_templates = len(parts) >= 3 and parts[:2] == ("system", "templates")
        if in_active_skill or in_shared_skill_templates or in_wrappers or in_scripts or in_templates:
            sources.add(relative)
            continue
        if parts[:2] == ("agent", "schedule") and len(parts) == 3 and path.suffix == ".json":
            if _read_schedule(path, vault).get("status") == "active":
                sources.add(relative)
    return sources


def _classify_script(relative_path: str) -> tuple[str, str] | None:
    path = PurePosixPath(relative_path)
    name = path.name
    parts = path.parts
    if "_archive" in parts:
        return "retire", "ownership-map:archived-script"
    if name == "__init__.py":
        return "retire", "ownership-map:package-scaffold"
    if name in _RUNTIME_TESTS:
        return "runtime", "ownership-map:characterization"
    if name == "eval_research.py":
        return "connector:researcher", "ownership-map:researcher-eval"
    if relative_path == "system/scripts/utils/notify.py":
        return "connector:gateway", "ownership-map:gateway-transport"
    if name in _RUNTIME_SCRIPTS:
        return "runtime", "ownership-map:runtime-domain"
    if name in _COURSEDUMP_SCRIPTS:
        return "connector:coursedump", "ownership-map:source-extraction"
    if name in _RESEARCHER_SCRIPTS:
        return "connector:researcher", "ownership-map:research"
    if name in _SCHEDULER_SCRIPTS:
        return "connector:scheduler", "ownership-map:scheduling"
    if name == "telegram_bot.py":
        return "connector:gateway", "ownership-map:gateway-transport"
    if name in _PRIVATE_SCRIPTS:
        return "private-data", "owner-decision:private-recipe"
    if name in _RETIRE_SCRIPTS:
        return "retire", "ownership-map:migration-only"
    if name in {"statusline-repo.sh", "statusline_context.py"}:
        return "generated-wrapper", "ownership-map:harness-adapter"
    return None


def classify(candidate: Candidate) -> tuple[str, str] | None:
    if candidate.kind == "skill":
        return "runtime", "ownership-map:canonical-skill"
    if candidate.kind == "wrapper":
        return "generated-wrapper", "ownership-map:codex-wrapper"
    if candidate.kind == "template":
        if candidate.relative_path.startswith("system/templates/research-project/"):
            return "connector:researcher", "ownership-map:research-template"
        return "runtime", "ownership-map:runtime-template"
    if candidate.kind == "schedule":
        return "private-data", "authority-map:private-schedule-instance"
    if candidate.kind == "hook":
        if candidate.relative_path.endswith("/notification_route.py"):
            return "connector:gateway", "ownership-map:gateway-hook"
        if candidate.relative_path.endswith("/__init__.py"):
            return "retire", "ownership-map:package-scaffold"
        return "generated-wrapper", "ownership-map:harness-adapter"
    if candidate.kind == "script":
        return _classify_script(candidate.relative_path)
    return None


def _source_ref(relative_path: str) -> str:
    digest = hashlib.sha256(relative_path.encode("utf-8")).hexdigest()
    return f"source:sha256:{digest}"


def _source_set_digest(paths: Iterable[str]) -> str:
    body = "\n".join(sorted(paths)) + "\n"
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def _skill_or_wrapper_name(candidate: Candidate) -> str | None:
    path = PurePosixPath(candidate.relative_path)
    if candidate.kind in {"skill", "wrapper"}:
        try:
            return path.parts[path.parts.index("skills") + 1]
        except (ValueError, IndexError):
            return None
    return None


def _bounded_literal(text: str, literal: str) -> bool:
    boundary = r"A-Za-z0-9_./-"
    return re.search(rf"(?<![{boundary}]){re.escape(literal)}(?![{boundary}])", text) is not None


def _python_module_refs(relative_path: str) -> tuple[str, ...]:
    """Derive importable full and scripts-root-relative module names."""
    path = PurePosixPath(relative_path)
    if path.suffix != ".py":
        return ()
    parts = list(path.with_suffix("").parts)
    if parts and parts[-1] == "__init__":
        parts.pop()
    if not parts:
        return ()
    refs = [".".join(parts)]
    if tuple(parts[:2]) == ("system", "scripts") and len(parts) > 2:
        refs.append(".".join(parts[2:]))
    return tuple(dict.fromkeys(refs))


def _python_package_refs(relative_path: str) -> tuple[str, ...]:
    """Derive package contexts used to resolve relative imports."""
    path = PurePosixPath(relative_path)
    if path.suffix != ".py":
        return ()
    parts = list(path.with_suffix("").parts)
    if not parts:
        return ()
    parts.pop()
    if not parts:
        return ()
    refs = [".".join(parts)]
    if tuple(parts[:2]) == ("system", "scripts") and len(parts) > 2:
        refs.append(".".join(parts[2:]))
    return tuple(dict.fromkeys(refs))


def _resolved_import_from(node: ast.ImportFrom, package: str) -> set[str]:
    package_parts = package.split(".") if package else []
    parents = node.level - 1
    if parents > len(package_parts):
        return set()
    base = package_parts[: len(package_parts) - parents]
    if node.module:
        base.extend(node.module.split("."))
    prefix = ".".join(base)
    resolved = {prefix} if prefix else set()
    resolved.update(
        ".".join([*base, alias.name])
        for alias in node.names
        if alias.name != "*"
    )
    return resolved


@lru_cache(maxsize=512)
def _imported_modules(text: str, packages: tuple[str, ...]) -> frozenset[str]:
    """Extract exact absolute and importer-relative targets."""
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return frozenset()
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0 and node.module:
                modules.add(node.module)
                modules.update(
                    f"{node.module}.{alias.name}"
                    for alias in node.names
                    if alias.name != "*"
                )
            elif node.level > 0:
                for package in packages:
                    modules.update(_resolved_import_from(node, package))
    return frozenset(modules)


def _module_imported(text: str, module: str, source: Candidate) -> bool:
    packages = _python_package_refs(source.relative_path)
    return module in _imported_modules(text, packages)


def _is_python_executable(token: str) -> bool:
    name = PurePosixPath(token.replace("\\", "/")).name
    return re.fullmatch(r"python(?:3(?:\.\d+)*)?", name) is not None


def _python_execution_target(argv: Sequence[str]) -> tuple[str, str] | None:
    """Return the one script/module executed by a direct Python argv."""
    if not argv or not _is_python_executable(argv[0]):
        return None
    index = 1
    while index < len(argv):
        token = argv[index]
        if token in {"-h", "--help", "-V", "-VV", "--version"}:
            return None
        if token == "-m":
            return ("module", argv[index + 1]) if index + 1 < len(argv) else None
        if token in {"-c", "-"}:
            return None
        if token == "--":
            return ("script", argv[index + 1]) if index + 1 < len(argv) else None
        if token.startswith("-"):
            if token in {"-W", "-X", "--check-hash-based-pycs"}:
                index += 1
                if index >= len(argv):
                    return None
            index += 1
            continue
        return "script", token
    return None


def _path_token_matches(token: str, relative_path: str) -> bool:
    normalized = token.replace("\\", "/").removeprefix("./")
    return normalized == relative_path or normalized.endswith("/" + relative_path)


def _argv_invokes(candidate: Candidate, argv: Sequence[str]) -> bool:
    if not argv:
        return False
    python_target = _python_execution_target(argv)
    if python_target is not None:
        kind, value = python_target
        if kind == "module":
            return value in _python_module_refs(candidate.relative_path)
        return _path_token_matches(value, candidate.relative_path)
    if _path_token_matches(argv[0], candidate.relative_path):
        return True
    surface_name = _skill_or_wrapper_name(candidate)
    return surface_name is not None and argv[0] == f"/{surface_name}"


def _literal_argv(node: ast.AST) -> tuple[str, ...]:
    if not isinstance(node, (ast.List, ast.Tuple)):
        return ()
    values: list[str] = []
    for element in node.elts:
        if not isinstance(element, ast.Constant) or not isinstance(element.value, str):
            return ()
        values.append(element.value)
    return tuple(values)


@lru_cache(maxsize=512)
def _structured_python_argvs(text: str) -> tuple[tuple[str, ...], ...]:
    """Extract literal argv only from standard subprocess execution calls."""
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return ()
    argvs: list[tuple[str, ...]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not node.args:
            continue
        function = node.func
        if not isinstance(function, ast.Attribute) or function.attr not in {
            "run",
            "Popen",
            "call",
            "check_call",
            "check_output",
        }:
            continue
        argv = _literal_argv(node.args[0])
        if argv:
            argvs.append(argv)
    return tuple(argvs)


def _technical_file_references(text: str, candidate: Candidate, source: Candidate) -> bool:
    """Use syntax for code; use exact path/slash surfaces for documentation."""
    if PurePosixPath(source.relative_path).suffix == ".py":
        if any(
            _module_imported(text, module, source)
            for module in _python_module_refs(candidate.relative_path)
        ):
            return True
        return any(_argv_invokes(candidate, argv) for argv in _structured_python_argvs(text))
    relative = candidate.relative_path
    if _bounded_literal(text, relative):
        return True
    surface_name = _skill_or_wrapper_name(candidate)
    return surface_name is not None and _bounded_literal(text, f"/{surface_name}")


def _invocation_argv(value: Any) -> tuple[str, ...]:
    if isinstance(value, list) and all(isinstance(token, str) for token in value):
        return tuple(value)
    return ()


def _schedule_invokes(candidate: Candidate, metadata: Mapping[str, Any]) -> bool:
    """Use only the executable position of structured command/execution argv."""
    argvs = tuple(
        argv
        for value in (metadata.get("command"), metadata.get("execution"))
        if (argv := _invocation_argv(value))
    )
    return any(_argv_invokes(candidate, argv) for argv in argvs)


def _safe_last_run(metadata: Mapping[str, Any], evidence: str) -> Mapping[str, str] | None:
    timestamp = metadata.get("last_run")
    if not isinstance(timestamp, str) or not _ISO_TIMESTAMP.fullmatch(timestamp):
        return None
    raw_result = metadata.get("last_result")
    result = raw_result if isinstance(raw_result, str) and raw_result in _SAFE_RUN_RESULTS else "unknown"
    return {"at": timestamp, "result": result, "evidence": evidence}


def _schedule_evidence(vault: Path) -> list[Candidate]:
    schedules = vault / "agent" / "schedule"
    evidence: list[Candidate] = []
    for path in sorted(schedules.iterdir(), key=lambda item: item.name):
        if path.is_file() and path.suffix == ".json":
            evidence.append(Candidate(_relative(path, vault), "schedule", _read_schedule(path, vault)))
    return evidence


def _usage_and_runs(vault: Path, candidates: Sequence[Candidate]) -> tuple[dict[str, tuple[str, ...]], dict[str, Mapping[str, str] | None]]:
    technical_text: dict[str, str] = {}
    schedule_evidence = _schedule_evidence(vault)
    for candidate in candidates:
        if candidate.kind == "schedule":
            continue
        path = vault / candidate.relative_path
        try:
            technical_text[candidate.relative_path] = path.read_text("utf-8")
        except (OSError, UnicodeError):
            technical_text[candidate.relative_path] = ""
    refs: dict[str, tuple[str, ...]] = {}
    runs: dict[str, Mapping[str, str] | None] = {}
    for candidate in candidates:
        if candidate.kind == "schedule":
            reference = _source_ref(candidate.relative_path)
            refs[candidate.relative_path] = ("legacy-scheduler",)
            runs[candidate.relative_path] = _safe_last_run(candidate.metadata or {}, reference)
            continue
        found: set[str] = set()
        run_evidence: list[Mapping[str, str]] = []
        searchable = [other for other in candidates if other.kind != "schedule"] + schedule_evidence
        for other in searchable:
            if other.relative_path == candidate.relative_path:
                continue
            if other.kind == "schedule":
                referenced = _schedule_invokes(candidate, other.metadata or {})
            else:
                referenced = _technical_file_references(
                    technical_text[other.relative_path], candidate, other
                )
            if not referenced:
                continue
            reference = _source_ref(other.relative_path)
            found.add(reference)
            if other.kind == "schedule":
                last_run = _safe_last_run(other.metadata or {}, reference)
                if last_run is not None:
                    run_evidence.append(last_run)
        refs[candidate.relative_path] = tuple(sorted(found))
        runs[candidate.relative_path] = max(run_evidence, key=lambda item: item["at"]) if run_evidence else None
    return refs, runs


def _outcome(candidate: Candidate, target: str) -> str:
    if candidate.kind in {"script", "hook"}:
        specific = _SCRIPT_OUTCOMES.get(PurePosixPath(candidate.relative_path).name)
        if specific is not None:
            return specific
    if target == "runtime":
        return "runtime-capability"
    if target.startswith("connector:"):
        return "external-tool-capability"
    if target == "private-data":
        return "private-recipe"
    if target == "generated-wrapper":
        return "harness-adapter"
    if target == "retire":
        return "no-target-product-outcome"
    return "owner-classification-required"


def _validate_candidates(candidates: Sequence[Candidate]) -> dict[str, tuple[str, str]]:
    seen: set[str] = set()
    duplicates: set[str] = set()
    classifications: dict[str, tuple[str, str]] = {}
    unclassified: list[str] = []
    for candidate in candidates:
        if candidate.relative_path in seen:
            duplicates.add(candidate.relative_path)
        seen.add(candidate.relative_path)
        classification = classify(candidate)
        if classification is None or classification[0] not in TARGETS:
            unclassified.append(candidate.relative_path)
        else:
            classifications[candidate.relative_path] = classification
            secondary_targets, handoffs = _SPLIT_OWNERSHIP.get(candidate.relative_path, ((), ()))
            if any(target not in TARGETS or target == classification[0] for target in secondary_targets):
                raise ManifestError("invalid split ownership target")
            if bool(secondary_targets) != bool(handoffs):
                raise ManifestError("split ownership requires secondary targets and handoffs")
    if duplicates:
        raise _privacy_safe_issue("duplicate sources", duplicates)
    if unclassified:
        raise _privacy_safe_issue("unclassified sources", unclassified)
    return classifications


def build_manifest(vault: Path, generated_on: date) -> dict[str, Any]:
    vault = vault.resolve(strict=True)
    candidates = discover_candidates(vault)
    classifications = _validate_candidates(candidates)
    discovered_set = {candidate.relative_path for candidate in candidates}
    rg_set = independent_rg_source_set(vault)
    if discovered_set != rg_set:
        raise ManifestError(
            "source-set reconciliation failed: "
            f"scanner_only={len(discovered_set - rg_set)}, rg_only={len(rg_set - discovered_set)}"
        )
    usage_refs, last_runs = _usage_and_runs(vault, candidates)

    records: list[dict[str, Any]] = []
    counts_by_kind: dict[str, int] = {}
    counts_by_target: dict[str, int] = {}
    active_skill_names: set[str] = set()
    for candidate in sorted(candidates, key=lambda item: item.relative_path):
        target, evidence = classifications[candidate.relative_path]
        source_ref = _source_ref(candidate.relative_path)
        secondary_targets, handoffs = _SPLIT_OWNERSHIP.get(candidate.relative_path, ((), ()))
        record = Record(
            source_ref=source_ref,
            kind=candidate.kind,
            target=target,
            secondary_targets=secondary_targets,
            handoffs=handoffs,
            classification_evidence=evidence,
            usage_refs=usage_refs[candidate.relative_path],
            last_known_run=last_runs[candidate.relative_path],
        )
        serialized: dict[str, Any] = {
            "source_ref": record.source_ref,
            "source_ref_kind": "sha256",
            "kind": record.kind,
            "target": record.target,
            "secondary_targets": list(record.secondary_targets),
            "handoffs": list(record.handoffs),
            "classification_evidence": record.classification_evidence,
            "outcome": _outcome(candidate, target),
            "usage_refs": list(record.usage_refs),
            "last_known_run": record.last_known_run,
        }
        records.append(serialized)
        counts_by_kind[record.kind] = counts_by_kind.get(record.kind, 0) + 1
        counts_by_target[record.target] = counts_by_target.get(record.target, 0) + 1
        if candidate.kind == "skill":
            active_skill_names.add(PurePosixPath(candidate.relative_path).parts[2])

    return {
        "schema_version": 1,
        "generated_notice": "GENERATED tool_life_os_runtime.dev_manifest; do not edit",
        "generated_on": generated_on.isoformat(),
        "generated_by": "tool_life_os_runtime.dev_manifest",
        "scope": {
            "active_skills": ".claude/skills/<active>/",
            "generated_wrappers": ".agents/skills/",
            "scripts_and_hooks": "system/scripts/",
            "templates": [".claude/skills/_shared/", "system/templates/"],
            "active_schedules": "agent/schedule/*.json with status=active",
        },
        "privacy": {
            "absolute_paths": "omitted",
            "all_source_paths_and_usage_refs": "sha256-source-ref-only",
            "schedule_payloads": "omitted",
            "personal_content": "omitted",
        },
        "reconciliation": {
            "method": "whole-root rg --files --hidden then documented-scope filter",
            "ok": True,
            "source_count": len(discovered_set),
            "source_set_sha256": _source_set_digest(discovered_set),
            "duplicates": [],
            "unclassified": [],
        },
        "counts": {
            "inventory_entities": {
                "active_skills": len(active_skill_names),
                "active_schedules": counts_by_kind.get("schedule", 0),
                "generated_wrappers": counts_by_kind.get("wrapper", 0),
                "script_files_including_hooks": counts_by_kind.get("script", 0) + counts_by_kind.get("hook", 0),
            },
            "by_kind": dict(sorted(counts_by_kind.items())),
            "by_target": dict(sorted(counts_by_target.items())),
        },
        "records": records,
    }


def render_markdown(manifest: Mapping[str, Any]) -> str:
    reconciliation = manifest["reconciliation"]
    lines = [
        "<!-- GENERATED by tool_life_os_runtime.dev_manifest; do not edit by hand -->",
        "",
        f"# Migration manifest - {manifest['generated_on']}",
        "",
        "Privacy-safe render: source paths, usage paths, and payload schedules are omitted.",
        "Each source is represented by a stable SHA-256 reference.",
        "",
        "## Reconciliation",
        "",
        f"- Method: `{reconciliation['method']}`.",
        f"- Source count: `{reconciliation['source_count']}`.",
        f"- Source-set SHA-256: `{reconciliation['source_set_sha256']}`.",
        "- Duplicate: `0`.",
        "- Unclassified: `0`.",
        f"- Active skills: `{manifest['counts']['inventory_entities']['active_skills']}`.",
        f"- Active schedules: `{manifest['counts']['inventory_entities']['active_schedules']}`.",
        "",
        "## Counts by kind",
        "",
        "| Kind | Count |",
        "|---|---:|",
    ]
    for kind, count in manifest["counts"]["by_kind"].items():
        lines.append(f"| `{kind}` | {count} |")
    lines.extend(["", "## Counts by target", "", "| Target | Count |", "|---|---:|"])
    for target, count in manifest["counts"]["by_target"].items():
        lines.append(f"| `{target}` | {count} |")
    lines.extend(
        [
            "",
            "## Sources",
            "",
            "| Source ref | Kind | Target | Secondary targets | Handoffs | Outcome | Usage refs | Last known run |",
            "|---|---|---|---|---:|---|---:|---|",
        ]
    )
    for record in manifest["records"]:
        run = record["last_known_run"]
        run_view = "unknown" if run is None else f"{run['at']} / {run['result']}"
        source_ref = str(record["source_ref"]).replace("|", "\\|")
        secondary = ", ".join(record["secondary_targets"]) or "none"
        lines.append(
            f"| `{source_ref}` | `{record['kind']}` | `{record['target']}` | `{secondary}` | "
            f"{len(record['handoffs'])} | `{record['outcome']}` | {len(record['usage_refs'])} | `{run_view}` |"
        )
    lines.append("")
    return "\n".join(lines)


def _text_sha256(body: str) -> str:
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def verify_artifact_pair(json_path: Path, markdown_path: Path) -> None:
    try:
        authoritative = json.loads(json_path.read_text("utf-8"))
        pair = authoritative["artifact_pair"]
        expected_name = pair["markdown_file"]
        expected_digest = pair["markdown_sha256"]
        markdown_body = markdown_path.read_text("utf-8")
    except (OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError) as exc:
        raise ManifestError("migration manifest artifact pair is incomplete") from exc
    if expected_name != markdown_path.name or expected_digest != _text_sha256(markdown_body):
        raise ManifestError("migration manifest artifact pair mismatch")


def write_artifacts(
    manifest: Mapping[str, Any],
    output_dir: Path,
    *,
    _replace: Callable[[Path, Path], None] = os.replace,
) -> tuple[Path, Path]:
    """Prepare both views, publish Markdown first, authoritative JSON last."""
    output_dir.mkdir(parents=True, exist_ok=True)
    stem = f"migration-manifest-{manifest['generated_on']}"
    json_path = output_dir / f"{stem}.json"
    markdown_path = output_dir / f"{stem}.md"
    markdown_body = render_markdown(manifest)
    authoritative = dict(manifest)
    authoritative["artifact_pair"] = {
        "authoritative": "json",
        "commit_order": "prepared-markdown -> markdown -> json",
        "markdown_file": markdown_path.name,
        "markdown_sha256": _text_sha256(markdown_body),
    }
    json_body = json.dumps(authoritative, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    markdown_prepared = output_dir / f".{markdown_path.name}.prepared"
    json_prepared = output_dir / f".{json_path.name}.prepared"
    try:
        atomic_write(markdown_prepared, markdown_body)
        atomic_write(json_prepared, json_body)
        _replace(markdown_prepared, markdown_path)
        _replace(json_prepared, json_path)
    finally:
        markdown_prepared.unlink(missing_ok=True)
        json_prepared.unlink(missing_ok=True)
    verify_artifact_pair(json_path, markdown_path)
    return json_path, markdown_path


def resolve_legacy_vault(config_path: Path) -> Path:
    try:
        config = tomllib.loads(config_path.read_text("utf-8"))
        migration = config["migration"]["legacy_vault"]
        raw_path = migration["path"]
        read_only = migration["read_only"]
    except (OSError, UnicodeError, tomllib.TOMLDecodeError, KeyError, TypeError) as exc:
        raise ManifestError("invalid local runtime config for migration.legacy_vault") from exc
    if read_only is not True:
        raise ManifestError("migration.legacy_vault must be explicitly read_only")
    if not isinstance(raw_path, str) or not Path(raw_path).is_absolute():
        raise ManifestError("migration.legacy_vault.path must be absolute")
    try:
        vault = Path(raw_path).resolve(strict=True)
    except OSError as exc:
        raise ManifestError("migration.legacy_vault.path cannot be resolved") from exc
    if not vault.is_dir():
        raise ManifestError("migration.legacy_vault.path must be a directory")
    return vault


def ensure_output_does_not_overlap_legacy(output_dir: Path, legacy_vault: Path) -> None:
    """Reject writes at, below, or above the read-only legacy root."""
    output = output_dir.resolve(strict=False)
    legacy = legacy_vault.resolve(strict=True)
    if output == legacy or output in legacy.parents or legacy in output.parents:
        raise ManifestError("output directory overlaps the read-only legacy vault")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build the legacy migration manifest")
    parser.add_argument("--config", required=True, type=Path, help="local runtime config.toml")
    parser.add_argument("--output-dir", type=Path, default=Path("docs"))
    parser.add_argument("--date", type=date.fromisoformat, default=date.today())
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        vault = resolve_legacy_vault(args.config)
        ensure_output_does_not_overlap_legacy(args.output_dir, vault)
        manifest = build_manifest(vault, args.date)
        paths = write_artifacts(manifest, args.output_dir)
    except ManifestError as exc:
        print(f"manifest error: {exc}")
        return 1
    except (OSError, UnicodeError):
        print("manifest error: artifact generation failed")
        return 1
    print(
        json.dumps(
            {
                "ok": True,
                "source_count": manifest["reconciliation"]["source_count"],
                "artifacts": [path.name for path in paths],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
