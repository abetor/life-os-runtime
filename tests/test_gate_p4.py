"""Executable technical acceptance for Gate P4."""

from __future__ import annotations

from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest

import tool_life_os_runtime.ext.gates.p4.registry as gate_module

from tool_life_os_runtime.ext.connectors.scheduler import (
    SchedulerConnectorError,
    canonical_recipe_descriptors,
    diff_recipes,
    install_recipes,
)
from tool_life_os_runtime.ext.gates.p4 import (
    CommandEvidence,
    P4GateError,
    audit_connector_boundaries,
    audit_safe_install_defaults,
    canonical_connector_boundaries,
    canonical_connector_source_policies,
    canonical_install_source_policies,
    canonical_source_policy_manifest,
    canonical_source_policy_manifest_sha256,
    canonical_upstream_specs,
    parse_upstream_evidence,
    render_upstream_evidence,
    run_research_review_e2e,
    run_upstream_evidence,
    validate_upstream_evidence,
)


ROOT = Path(__file__).resolve().parents[1]
CONNECTORS = ROOT / "tool_life_os_runtime/ext/connectors"
PACKAGE = ROOT / "tool_life_os_runtime"
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
LIVE_P4_WORKSPACE = os.environ.get("LIFEOS_P4_WORKSPACE", "")


def _synthetic_upstream_workspace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Path:
    """Create clean temporary Git repositories for runner contract tests."""

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    for spec in canonical_upstream_specs():
        repo = workspace / spec.repo
        repo.mkdir()
        subprocess.run(("git", "init", "-q"), cwd=repo, check=True)
        subprocess.run(
            ("git", "config", "user.email", "gate@example.invalid"),
            cwd=repo,
            check=True,
        )
        subprocess.run(
            ("git", "config", "user.name", "Gate Fixture"), cwd=repo, check=True
        )
        (repo / "tracked.txt").write_text("tracked\n", "utf-8")
        subprocess.run(("git", "add", "tracked.txt"), cwd=repo, check=True)
        subprocess.run(("git", "commit", "-q", "-m", "fixture"), cwd=repo, check=True)

    real_git_output = gate_module._git_output

    def git_output(repo: Path, *arguments: str) -> str:
        if arguments[:2] == ("merge-base", "--is-ancestor"):
            return ""
        return real_git_output(repo, *arguments)

    monkeypatch.setattr(gate_module, "_git_output", git_output)
    return workspace


def _command(argv: tuple[str, ...], *, returncode: int = 0) -> CommandEvidence:
    return CommandEvidence(
        argv=argv,
        returncode=returncode,
        duration_ms=1,
        stdout_bytes=0,
        stderr_bytes=0,
        stdout_sha256=EMPTY_SHA256,
        stderr_sha256=EMPTY_SHA256,
        timed_out=False,
    )


def test_connector_registry_audits_exact_tree_without_sibling_imports_or_human_parsing() -> (
    None
):
    records = audit_connector_boundaries(CONNECTORS.resolve())

    assert records == canonical_connector_boundaries()
    assert tuple(record.connector_id for record in records) == (
        "coursedump",
        "gateway",
        "llmwiki",
        "probes",
        "researcher",
        "scheduler",
    )
    assert {record.output_mode for record in records} == {"json", "exit-code-only"}
    assert next(
        record for record in records if record.connector_id == "llmwiki"
    ).operations == ("validate",)
    policies = canonical_connector_source_policies()
    assert len(policies) == 14
    assert tuple(sorted(policy.source_file for policy in policies)) == tuple(
        sorted(
            path.relative_to(CONNECTORS).as_posix() for path in CONNECTORS.rglob("*.py")
        )
    )
    assert all(policy.call_count >= 0 for policy in policies)
    assert all(len(policy.ast_sha256) == 64 for policy in policies)
    assert all(len(policy.call_inventory_sha256) == 64 for policy in policies)
    assert all(len(policy.source_sha256) == 64 for policy in policies)
    install_policies = canonical_install_source_policies()
    assert len(install_policies) == 78
    assert len({policy.source_file for policy in install_policies}) == 78
    assert all(len(policy.source_sha256) == 64 for policy in install_policies)
    assert canonical_source_policy_manifest_sha256() == (
        "23dc31983d487ac8aff70408e5623e6a3ce093edd5b8a69f87e6d729dae013cf"
    )
    assert hashlib.sha256(canonical_source_policy_manifest()).hexdigest() == (
        canonical_source_policy_manifest_sha256()
    )


def test_connector_audit_rejects_sibling_import_unknown_process_and_inventory_drift(
    tmp_path: Path,
) -> None:
    copied = tmp_path / "connectors"
    shutil.copytree(CONNECTORS, copied)
    researcher = copied / "researcher/connector.py"
    researcher.write_text(
        researcher.read_text("utf-8") + "\nimport json, researcher as sibling\n",
        "utf-8",
    )
    with pytest.raises(P4GateError, match="import inventory"):
        audit_connector_boundaries(copied.resolve())

    for unexpected in (
        '\nimport runpy\nrunpy.run_module("researcher")\n',
        "\nimport random\nrandom.random()\n",
        "\nfrom json import *\n",
    ):
        shutil.rmtree(copied)
        shutil.copytree(CONNECTORS, copied)
        target = copied / "probes/capabilities.py"
        target.write_text(target.read_text("utf-8") + unexpected, "utf-8")
        with pytest.raises(P4GateError, match="import inventory"):
            audit_connector_boundaries(copied.resolve())

    shutil.rmtree(copied)
    shutil.copytree(CONNECTORS, copied)
    llmwiki = copied / "llmwiki/connector.py"
    llmwiki.write_text(
        llmwiki.read_text("utf-8")
        + "\ndef _parse_human_ui():\n"
        + '    return subprocess.Popen(["llmwiki", "doctor"])\n',
        "utf-8",
    )
    with pytest.raises(P4GateError, match="subprocess boundary is not exact"):
        audit_connector_boundaries(copied.resolve())

    shutil.rmtree(copied)
    shutil.copytree(CONNECTORS, copied)
    gateway = copied / "gateway/connector.py"
    gateway.write_text(
        gateway.read_text("utf-8")
        + "\nfrom subprocess import Popen as launch\n"
        + 'def _alias_bypass():\n    return launch(["tool-gateway", "doctor"])\n',
        "utf-8",
    )
    with pytest.raises(P4GateError, match="import inventory"):
        audit_connector_boundaries(copied.resolve())

    shutil.rmtree(copied)
    shutil.copytree(CONNECTORS, copied)
    probes = copied / "probes/capabilities.py"
    probes.write_text(
        probes.read_text("utf-8")
        + "\nimport importlib as loader\n"
        + 'def _dynamic_bypass():\n    return loader.import_module("researcher")\n',
        "utf-8",
    )
    with pytest.raises(P4GateError, match="import inventory"):
        audit_connector_boundaries(copied.resolve())

    bypasses = (
        (
            "researcher/connector.py",
            "\nlaunch = subprocess.Popen\n"
            "def _assigned_popen():\n"
            '    return launch(["research", "status"])\n',
            "call inventory",
        ),
        (
            "researcher/connector.py",
            "\nprocess_module = subprocess\n"
            "def _module_alias():\n"
            '    return process_module.Popen(["research", "status"])\n',
            "call inventory",
        ),
        (
            "gateway/connector.py",
            "\ndef _container_alias():\n"
            '    return [subprocess.Popen][0](["tool-gateway", "doctor"])\n',
            "call inventory",
        ),
        (
            "researcher/connector.py",
            "\ndef _output_bypass():\n"
            '    return subprocess.check_output(["research", "status"]).splitlines()\n',
            "unregistered subprocess API",
        ),
        (
            "gateway/connector.py",
            "\ndef _getattr_bypass():\n"
            '    return getattr(subprocess, "Popen")(["tool-gateway", "doctor"])\n',
            "call inventory",
        ),
        (
            "scheduler/connector.py",
            "\ndef _spawn_bypass():\n"
            '    return os.spawnv(os.P_WAIT, "/bin/true", ["true"])\n',
            "unregistered os process API",
        ),
        (
            "probes/capabilities.py",
            "\nimport builtins\n"
            "def _dict_import_bypass():\n"
            '    return builtins.__dict__["__import__"]("researcher")\n',
            "import inventory",
        ),
        (
            "coursedump/connector.py",
            "\nrunner = exec\n"
            "def _exec_bypass():\n"
            '    return runner("import researcher")\n',
            "call inventory",
        ),
    )
    for relative, suffix, error in bypasses:
        shutil.rmtree(copied)
        shutil.copytree(CONNECTORS, copied)
        target = copied / relative
        target.write_text(target.read_text("utf-8") + suffix, "utf-8")
        with pytest.raises(P4GateError, match=error):
            audit_connector_boundaries(copied.resolve())

    shutil.rmtree(copied)
    shutil.copytree(CONNECTORS, copied)
    generic = copied / "llmwiki/connector.py"
    generic.write_text(
        generic.read_text("utf-8")
        + "\ndef _unexpected_call():\n    return arbitrary.invoke()\n",
        "utf-8",
    )
    with pytest.raises(P4GateError, match="call inventory"):
        audit_connector_boundaries(copied.resolve())

    shutil.rmtree(copied)
    shutil.copytree(CONNECTORS, copied)
    callable_alias = copied / "researcher/connector.py"
    callable_alias.write_text(
        callable_alias.read_text("utf-8") + "\nunused_launch = subprocess.Popen\n",
        "utf-8",
    )
    with pytest.raises(P4GateError, match="AST is not allowlisted"):
        audit_connector_boundaries(copied.resolve())

    with pytest.raises(P4GateError, match="boundary registry must be exact"):
        audit_connector_boundaries(
            CONNECTORS.resolve(), boundaries=canonical_connector_boundaries()[:-1]
        )

    shutil.rmtree(copied)
    shutil.copytree(CONNECTORS, copied)
    scheduler = copied / "scheduler/connector.py"
    scheduler.write_text(
        scheduler.read_text("utf-8")
        + '\ndef _builtin_bypass():\n    return __import__("tool_scheduler")\n',
        "utf-8",
    )
    with pytest.raises(P4GateError, match="dynamic import"):
        audit_connector_boundaries(copied.resolve())

    shutil.rmtree(copied)
    shutil.copytree(CONNECTORS, copied)
    coursedump = copied / "coursedump/connector.py"
    coursedump.write_text(
        coursedump.read_text("utf-8").replace(
            "process = subprocess.Popen(", "process = missing_process("
        ),
        "utf-8",
    )
    with pytest.raises(P4GateError, match="subprocess boundary is not exact"):
        audit_connector_boundaries(copied.resolve())

    shutil.rmtree(copied)
    shutil.copytree(CONNECTORS, copied)
    (copied / "unregistered.py").write_text("value = 1\n", "utf-8")
    with pytest.raises(P4GateError, match="inventory is not registered"):
        audit_connector_boundaries(copied.resolve())


def test_source_audits_reject_descendant_symlinks_and_fd_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    copied_connectors = tmp_path / "connectors-leaf-symlink"
    shutil.copytree(CONNECTORS, copied_connectors)
    connector_leaf = copied_connectors / "researcher/connector.py"
    connector_leaf.unlink()
    connector_leaf.symlink_to(CONNECTORS / "researcher/connector.py")
    with pytest.raises(P4GateError, match="symlink"):
        audit_connector_boundaries(copied_connectors.resolve())

    copied_connectors = tmp_path / "connectors-parent-symlink"
    shutil.copytree(CONNECTORS, copied_connectors)
    connector_parent = copied_connectors / "researcher"
    moved_parent = tmp_path / "researcher-real"
    connector_parent.rename(moved_parent)
    connector_parent.symlink_to(moved_parent, target_is_directory=True)
    with pytest.raises(P4GateError, match="symlink"):
        audit_connector_boundaries(copied_connectors.resolve())

    copied_package = tmp_path / "package-leaf-symlink"
    shutil.copytree(PACKAGE, copied_package)
    package_leaf = copied_package / "cli.py"
    package_leaf.unlink()
    package_leaf.symlink_to(PACKAGE / "cli.py")
    with pytest.raises(P4GateError, match="symlink"):
        audit_safe_install_defaults(copied_package.resolve())

    copied_connectors = tmp_path / "connectors-race"
    shutil.copytree(CONNECTORS, copied_connectors)
    raced_leaf = copied_connectors / "researcher/connector.py"
    backup = raced_leaf.with_suffix(".bak")
    replaced = False

    def replace_opened_source(relative: str, phase: str) -> None:
        nonlocal replaced
        if relative == "researcher/connector.py" and phase == "opened" and not replaced:
            replaced = True
            raced_leaf.rename(backup)
            shutil.copy2(backup, raced_leaf)

    monkeypatch.setattr(gate_module, "_source_read_observer", replace_opened_source)
    with pytest.raises(P4GateError, match="changed during read"):
        audit_connector_boundaries(copied_connectors.resolve())
    assert replaced is True


def test_source_audits_reject_raw_whitespace_and_policy_self_tamper(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    copied_connectors = tmp_path / "connectors-whitespace"
    shutil.copytree(CONNECTORS, copied_connectors)
    connector = copied_connectors / "researcher/connector.py"
    connector.write_text(connector.read_text("utf-8") + "\n", "utf-8")
    with pytest.raises(P4GateError, match="raw source"):
        audit_connector_boundaries(copied_connectors.resolve())

    copied_package = tmp_path / "package-comment"
    shutil.copytree(PACKAGE, copied_package)
    cli = copied_package / "cli.py"
    cli.write_text(cli.read_text("utf-8") + "\n# unreviewed drift\n", "utf-8")
    with pytest.raises(P4GateError, match="runtime install source"):
        audit_safe_install_defaults(copied_package.resolve())

    copied_package = tmp_path / "package-policy-self-tamper"
    shutil.copytree(PACKAGE, copied_package)
    cli = copied_package / "cli.py"
    cli.write_text(
        cli.read_text("utf-8")
        + "\nimport operator\n"
        + "import tool_life_os_runtime.ext.connectors.scheduler as module\n"
        + 'operator.attrgetter("install_" + "recipes")(module)(None)\n',
        "utf-8",
    )
    source = cli.read_text("utf-8")
    tree = gate_module.ast.parse(source, filename="cli.py")
    imports = gate_module._import_inventory(tree)
    call_count, call_sha256 = gate_module._call_inventory(tree)
    policies = list(gate_module._INSTALL_SOURCE_POLICIES)
    index = next(
        index for index, policy in enumerate(policies) if policy.source_file == "cli.py"
    )
    policies[index] = replace(
        policies[index],
        ast_sha256=gate_module._ast_sha256(tree),
        import_count=len(imports),
        import_inventory_sha256=gate_module._import_inventory_sha256(imports),
        call_count=call_count,
        call_inventory_sha256=call_sha256,
        source_sha256=hashlib.sha256(source.encode("utf-8")).hexdigest(),
    )
    monkeypatch.setattr(gate_module, "_INSTALL_SOURCE_POLICIES", tuple(policies))
    with pytest.raises(P4GateError, match="not the reviewed artifact"):
        audit_safe_install_defaults(copied_package.resolve())


def test_upstream_runner_binds_exact_repos_heads_commands_and_observations(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = _synthetic_upstream_workspace(tmp_path, monkeypatch)
    calls: list[tuple[tuple[str, ...], Path, float]] = []

    def execute(argv: tuple[str, ...], cwd: Path, timeout: float) -> CommandEvidence:
        calls.append((argv, cwd, timeout))
        return _command(argv)

    evidence = run_upstream_evidence(
        workspace.resolve(), timeout_per_command=123, executor=execute
    )
    specs = canonical_upstream_specs()

    assert len(evidence) == len(specs) == 5
    assert tuple(record.repo for record in evidence) == tuple(
        spec.repo for spec in specs
    )
    assert all(record.accepted_head_is_ancestor for record in evidence)
    assert all(len(record.before_tests.head) == 40 for record in evidence)
    assert all(len(record.before_tests.tree) == 40 for record in evidence)
    assert all(
        record.before_tests == record.after_tests == record.after_baseline
        and record.before_tests.clean is True
        for record in evidence
    )
    assert calls == [
        (argv, (workspace / spec.repo).resolve(), 123.0)
        for spec in specs
        for argv in (spec.test_argv, spec.baseline_argv)
    ]


def test_upstream_specs_cannot_be_mistaken_for_executed_green_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = _synthetic_upstream_workspace(tmp_path, monkeypatch)
    specs = canonical_upstream_specs()
    with pytest.raises(P4GateError, match="evidence mismatch"):
        validate_upstream_evidence(specs)

    def execute(argv: tuple[str, ...], _cwd: Path, _timeout: float) -> CommandEvidence:
        return _command(argv)

    evidence = run_upstream_evidence(workspace.resolve(), executor=execute)
    broken = replace(evidence[0], tests=replace(evidence[0].tests, returncode=1))
    with pytest.raises(P4GateError, match="command evidence"):
        validate_upstream_evidence((broken, *evidence[1:]))
    wrong_head = replace(evidence[0], accepted_head_is_ancestor=False)
    with pytest.raises(P4GateError, match="repository evidence"):
        validate_upstream_evidence((wrong_head, *evidence[1:]))
    changed_tree = replace(
        evidence[0],
        after_tests=replace(evidence[0].after_tests, tree="f" * 40),
    )
    with pytest.raises(P4GateError, match="repository evidence"):
        validate_upstream_evidence((changed_tree, *evidence[1:]))


def test_upstream_evidence_has_strict_canonical_public_artifact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = _synthetic_upstream_workspace(tmp_path, monkeypatch)
    def execute(argv: tuple[str, ...], _cwd: Path, _timeout: float) -> CommandEvidence:
        return _command(argv)

    evidence = run_upstream_evidence(workspace.resolve(), executor=execute)
    artifact = render_upstream_evidence(evidence)
    assert parse_upstream_evidence(artifact) == evidence
    assert artifact.endswith(b"\n")
    assert b"/Users/" not in artifact

    with pytest.raises(P4GateError, match="not canonical"):
        parse_upstream_evidence(b" " + artifact)

    duplicate = artifact.replace(
        b'{"schema_version":1,',
        b'{"schema_version":1,"schema_version":1,',
        1,
    )
    with pytest.raises(P4GateError, match="duplicate"):
        parse_upstream_evidence(duplicate)

    payload = json.loads(artifact)
    payload["upstreams"][0]["tests"]["unexpected"] = True
    extra = (
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        + b"\n"
    )
    with pytest.raises(P4GateError, match="invalid command"):
        parse_upstream_evidence(extra)

    del payload["upstreams"][0]["tests"]["unexpected"]
    payload["upstreams"][0]["accepted_head_is_ancestor"] = False
    tampered = (
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        + b"\n"
    )
    with pytest.raises(P4GateError, match="repository evidence"):
        parse_upstream_evidence(tampered)


def test_upstream_snapshot_rejects_dirty_tree_and_runner_detects_command_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(("git", "init", "-q"), cwd=repo, check=True)
    subprocess.run(
        ("git", "config", "user.email", "gate@example.invalid"),
        cwd=repo,
        check=True,
    )
    subprocess.run(("git", "config", "user.name", "Gate Fixture"), cwd=repo, check=True)
    (repo / "tracked.txt").write_text("tracked\n", "utf-8")
    subprocess.run(("git", "add", "tracked.txt"), cwd=repo, check=True)
    subprocess.run(("git", "commit", "-q", "-m", "fixture"), cwd=repo, check=True)
    (repo / "untracked.txt").write_text("dirty\n", "utf-8")
    with pytest.raises(P4GateError, match="worktree is dirty"):
        gate_module._repository_snapshot(repo)

    real_snapshot = gate_module._repository_snapshot
    snapshots = 0

    def mutate_after_tests(path: Path):
        nonlocal snapshots
        snapshots += 1
        observed = real_snapshot(path)
        return replace(observed, tree="f" * 40) if snapshots == 2 else observed

    monkeypatch.setattr(gate_module, "_repository_snapshot", mutate_after_tests)
    workspace = _synthetic_upstream_workspace(tmp_path, monkeypatch)
    calls: list[tuple[str, ...]] = []

    def execute(argv: tuple[str, ...], _cwd: Path, _timeout: float) -> CommandEvidence:
        calls.append(argv)
        return _command(argv)

    with pytest.raises(P4GateError, match="changed during tests"):
        run_upstream_evidence(workspace.resolve(), executor=execute)
    assert calls == [canonical_upstream_specs()[0].test_argv]


def test_clean_install_has_no_runnable_scheduler_or_implicit_gateway(
    tmp_path: Path,
) -> None:
    evidence = audit_safe_install_defaults(PACKAGE.resolve())
    assert evidence.scheduler_recipe_ids == ("ambient", "bundle")
    assert evidence.scheduler_statuses == (
        "integration_required",
        "integration_required",
    )
    assert evidence.gateway_required_parameters == (
        "gateway_home",
        "target",
        "command",
        "cwd",
        "env",
    )
    assert evidence.implicit_activation_calls == ()

    home = tmp_path / "scheduler-home"
    (home / "jobs").mkdir(parents=True)
    plan = diff_recipes(home, canonical_recipe_descriptors())
    assert plan.actions == ()
    assert plan.deferred_ids == ("ambient", "bundle")
    with pytest.raises(SchedulerConnectorError, match="integration-gaps"):
        install_recipes(plan)
    assert tuple((home / "jobs").iterdir()) == ()


def test_safe_install_audit_rejects_alias_and_dynamic_activation(
    tmp_path: Path,
) -> None:
    attacks = (
        "from tool_life_os_runtime.ext.connectors.scheduler import "
        "install_recipes as activate\nactivate(None)\n",
        "from tool_life_os_runtime.ext.connectors.gateway import "
        "GatewayConnector as Connect\nConnect(None, None, None, None, None)\n",
        "import tool_life_os_runtime.ext.connectors.scheduler as module\n"
        'getattr(module, "install_recipes")(None)\n',
        "import importlib\n"
        'module = importlib.import_module("tool_life_os_runtime.ext.connectors.scheduler")\n'
        'activate = module.__dict__["install_" + "recipes"]\n'
        "activate(None)\n",
        "import operator\n"
        "import tool_life_os_runtime.ext.connectors.scheduler as module\n"
        'operator.attrgetter("install_" + "recipes")(module)(None)\n',
        "import tool_life_os_runtime.ext.connectors.scheduler as module\n"
        'activate = vars(module).get("install_" + "recipes")\n'
        "activate(None)\n",
        "import tool_life_os_runtime.ext.connectors.scheduler as module\n"
        'activate = module.__dict__.get("install_" + "recipes")\n'
        "activate(None)\n",
    )
    for index, source in enumerate(attacks):
        copied = tmp_path / f"package-{index}"
        shutil.copytree(PACKAGE, copied)
        (copied / "ext" / "activation_bypass.py").write_text(source, "utf-8")
        with pytest.raises(P4GateError, match="not allowlisted"):
            audit_safe_install_defaults(copied.resolve())


@pytest.mark.skipif(
    not LIVE_P4_WORKSPACE,
    reason="set LIFEOS_P4_WORKSPACE to opt into the live cross-repository E2E",
)
def test_real_sibling_local_course_to_llmwiki_to_runtime_review_is_private(
    tmp_path: Path,
) -> None:
    workspace = Path(LIVE_P4_WORKSPACE)
    researcher = workspace / "tool-researcher"
    llmwiki = workspace / "tool-llm-wiki"
    if not researcher.is_dir() or not llmwiki.is_dir():
        pytest.skip("sibling repository absent")
    legacy_vault = tmp_path / "legacy-vault"
    legacy_corpora = tmp_path / "legacy-corpora"
    legacy_vault.mkdir()
    legacy_corpora.mkdir()
    (legacy_vault / "sentinel.bin").write_bytes(b"legacy-vault-sentinel\n")
    (legacy_corpora / "sentinel.bin").write_bytes(b"legacy-corpora-sentinel\n")
    legacy_vault.chmod(0)
    legacy_corpora.chmod(0)

    try:
        evidence = run_research_review_e2e(
            workspace.resolve(),
            (tmp_path / "clean-e2e").resolve(),
            forbidden_roots=(legacy_vault.resolve(), legacy_corpora.resolve()),
        )
    finally:
        legacy_vault.chmod(0o700)
        legacy_corpora.chmod(0o700)

    assert evidence.status == "passed"
    assert evidence.source_kind == "local-markdown"
    assert evidence.document_count == 1
    assert evidence.researcher_import_status == "imported"
    assert evidence.researcher_import_windows == 1
    assert evidence.researcher_import_candidates == 1
    assert evidence.researcher_import_verified == 1
    assert evidence.researcher_import_duplicates == 0
    assert len(evidence.researcher_import_output_sha256) == 64
    assert evidence.review_status == "proposed"
    assert evidence.review_source_ref == evidence.topic_ref
    assert evidence.review_source_sha256 == evidence.topic_snapshot_sha256
    assert evidence.researcher_head_before == evidence.researcher_head_after
    assert evidence.llmwiki_head_before == evidence.llmwiki_head_after
    assert evidence.llmwiki_audit_status == "passed"
    assert evidence.llmwiki_audit_findings == 0
    assert evidence.llmwiki_audit_sha256 == hashlib.sha256(b"[]\n").hexdigest()
    assert evidence.llmwiki_audited_snapshot_sha256 == evidence.topic_snapshot_sha256
    assert evidence.forbidden_before_sha256 == evidence.forbidden_after_sha256
    assert (legacy_vault / "sentinel.bin").read_bytes() == b"legacy-vault-sentinel\n"
    assert (
        legacy_corpora / "sentinel.bin"
    ).read_bytes() == b"legacy-corpora-sentinel\n"
    portable = json.dumps(evidence.__dict__, sort_keys=True)
    assert "/Users/" not in portable
    assert "/home/" not in portable.casefold()
    assert "legacy-vault-sentinel" not in portable
    assert "legacy-corpora-sentinel" not in portable


@pytest.mark.skipif(
    not LIVE_P4_WORKSPACE,
    reason="set LIFEOS_P4_WORKSPACE to opt into the live cross-repository E2E",
)
def test_e2e_rejects_thin_topic_even_when_validate_accepts_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def make_thin(topic: Path) -> None:
        page = topic / "final/wiki/course.md"
        raw = page.read_text("utf-8")
        _empty, frontmatter, _body = raw.split("---\n", 2)
        claim_id = next(
            line.removeprefix("  - ")
            for line in frontmatter.splitlines()
            if line.startswith("  - clm_")
        )
        page.write_text(
            "---\n" + frontmatter + f"---\n\nTiny ({claim_id}).\n",
            "utf-8",
        )

    monkeypatch.setattr(gate_module, "_before_llmwiki_audit", make_thin)
    with pytest.raises(P4GateError, match="audit found incomplete topic"):
        run_research_review_e2e(
            Path(LIVE_P4_WORKSPACE).resolve(), (tmp_path / "thin-e2e").resolve()
        )


@pytest.mark.skipif(
    not LIVE_P4_WORKSPACE,
    reason="set LIFEOS_P4_WORKSPACE to opt into the live cross-repository E2E",
)
def test_e2e_rejects_sibling_head_change_after_commands(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = gate_module._repository_snapshot
    observations = 0

    def changed_after(path: Path):
        nonlocal observations
        observations += 1
        snapshot = original(path)
        return replace(snapshot, head="f" * 40) if observations == 3 else snapshot

    monkeypatch.setattr(gate_module, "_repository_snapshot", changed_after)
    with pytest.raises(P4GateError, match="sibling repository changed"):
        run_research_review_e2e(
            Path(LIVE_P4_WORKSPACE).resolve(),
            (tmp_path / "head-change-e2e").resolve(),
        )


@pytest.mark.skipif(
    not LIVE_P4_WORKSPACE,
    reason="set LIFEOS_P4_WORKSPACE to opt into the live cross-repository E2E",
)
def test_e2e_rejects_legacy_overlap_before_creating_scratch(tmp_path: Path) -> None:
    forbidden = tmp_path / "legacy"
    forbidden.mkdir()
    scratch = forbidden / "target"

    with pytest.raises(P4GateError, match="unsafe forbidden-root relation"):
        run_research_review_e2e(
            Path(LIVE_P4_WORKSPACE).resolve(),
            scratch.resolve(),
            forbidden_roots=(forbidden.resolve(),),
        )
    assert not scratch.exists()
