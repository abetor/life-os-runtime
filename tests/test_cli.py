"""P1-08 integrated CLI acceptance."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import threading
import tomllib

import pytest

from tool_life_os_runtime import cli
from tool_life_os_runtime.ext.connectors.probes import DEFAULT_SPECS, ProbeRecord
from tool_life_os_runtime.ext.runs.store import RunStore
from tool_life_os_runtime.ext.vault.config import load_vault_config
from tool_life_os_runtime.ext.vault.schema import VaultPathResolver


def _toml_string(path: Path) -> str:
    return json.dumps(str(path))


def _runtime_home(
    tmp_path: Path, *, main: Path | None = None, alternate: Path | None = None
) -> tuple[Path, Path, Path]:
    home = tmp_path / "runtime-home"
    home.mkdir()
    main = main or tmp_path / "vault-main"
    alternate = alternate or tmp_path / "vault-alternate"
    topics = tmp_path / "topics"
    legacy = tmp_path / "legacy"
    topics.mkdir()
    legacy.mkdir()
    (home / "config.toml").write_text(
        f"""schema_version = 1
default_vault = "main"

[vaults.main]
path = {_toml_string(main)}

[vaults.alternate]
path = {_toml_string(alternate)}

[machine_knowledge]
topics_root = {_toml_string(topics)}

[migration.legacy_vault]
path = {_toml_string(legacy)}
read_only = true
""",
        "utf-8",
    )
    return home, main, alternate


def _compatible_records() -> tuple[ProbeRecord, ...]:
    return tuple(
        ProbeRecord(
            tool=spec.tool,
            status=("compatible" if spec.machine_contract_available else "unavailable"),
            optional=spec.optional,
            probe_argv=spec.argv,
            minimum_supported_tool_version=".".join(map(str, spec.minimum_version)),
            maximum_supported_tool_version_exclusive=".".join(
                map(str, spec.maximum_version_exclusive)
            ),
            expected_capabilities=spec.expected_capabilities,
            returncode=0 if spec.machine_contract_available else None,
            protocol_version=1 if spec.machine_contract_available else None,
            error=(
                None
                if spec.machine_contract_available
                else "machine_contract_unavailable"
            ),
        )
        for spec in DEFAULT_SPECS
    )


def _capability_payload(spec, *, version: str = "0.1.0") -> dict[str, object]:
    return {
        "schema_version": 1,
        "tool": spec.tool,
        "version": version,
        "capabilities": [
            capability.to_dict() for capability in spec.expected_capabilities
        ],
    }


def _configure_tool(
    home: Path,
    *,
    name: str,
    argv: tuple[str, ...],
    cwd: Path | None = None,
    env_names: tuple[str, ...] = (),
) -> None:
    lines = [f"[tools.{name}]", f"argv = {json.dumps(list(argv))}"]
    if cwd is not None:
        lines.append(f"cwd = {_toml_string(cwd)}")
    if env_names:
        lines.append(f"env = {json.dumps(list(env_names))}")
    with (home / "config.toml").open("a", encoding="utf-8") as handle:
        handle.write("\n" + "\n".join(lines) + "\n")


def _configured_probe_script(
    path: Path,
    *,
    payload: dict[str, object],
    prefix: tuple[str, ...],
    cwd: Path,
    required_env: tuple[str, str] | None = None,
    forbidden_envs: tuple[str, ...] = (),
) -> None:
    conditions = [
        f"sys.argv[1:] == {[*prefix, 'capabilities', '--json']!r}",
        f"os.getcwd() == {str(cwd)!r}",
    ]
    if required_env is not None:
        conditions.append(f"os.environ.get({required_env[0]!r}) == {required_env[1]!r}")
    conditions.extend(f"{name!r} not in os.environ" for name in forbidden_envs)
    path.write_text(
        "import json, os, sys\n"
        f"if not ({' and '.join(conditions)}): raise SystemExit(64)\n"
        f"print(json.dumps({payload!r}, separators=(',', ':')))\n",
        "utf-8",
    )


def _tree_snapshot(root: Path) -> dict[str, tuple[str, int, int, int]]:
    result: dict[str, tuple[str, int, int, int]] = {}
    if not root.exists():
        return result
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        metadata = path.lstat()
        if path.is_symlink():
            body = os.readlink(path).encode("utf-8")
            kind = "symlink"
        elif path.is_file():
            body = path.read_bytes()
            kind = "file"
        else:
            body = b""
            kind = "directory"
        result[relative] = (
            kind + ":" + hashlib.sha256(body).hexdigest(),
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
        )
    return result


def test_init_and_scan_are_deterministic_and_scan_is_read_only(
    tmp_path, monkeypatch, capsys
) -> None:
    home, vault, _ = _runtime_home(tmp_path)
    monkeypatch.delenv(cli.VAULT_ENV, raising=False)

    assert cli.main(["--home", str(home), "init"]) == cli.EXIT_OK
    first = json.loads(capsys.readouterr().out)
    assert first["schema_version"] == 1
    assert first["kind"] == "vault-init"
    assert first["status"] == "initialized"
    assert set(vault.iterdir()) >= {vault / "lifeos.toml", vault / "knowledge"}

    before = _tree_snapshot(vault)
    assert cli.main(["--home", str(home), "scan"]) == cli.EXIT_OK
    scanned = json.loads(capsys.readouterr().out)
    assert scanned["schema_version"] == 1
    assert scanned["kind"] == "vault-scan"
    assert scanned["file_count"] == 1
    assert "files" not in scanned
    assert str(vault) not in json.dumps(scanned)
    assert _tree_snapshot(vault) == before

    assert cli.main(["--home", str(home), "init"]) == cli.EXIT_OK
    repeated = json.loads(capsys.readouterr().out)
    assert repeated["status"] == "already_initialized"
    assert _tree_snapshot(vault) == before


def test_vault_alias_precedence_is_cli_then_env_then_default(
    tmp_path, monkeypatch, capsys
) -> None:
    home, main_vault, alternate = _runtime_home(tmp_path)
    monkeypatch.setenv(cli.VAULT_ENV, "alternate")

    assert cli.main(["--home", str(home), "init"]) == cli.EXIT_OK
    capsys.readouterr()
    assert alternate.joinpath("lifeos.toml").is_file()
    assert not main_vault.exists()

    assert cli.main(["--home", str(home), "init", "--vault", "main"]) == cli.EXIT_OK
    capsys.readouterr()
    assert main_vault.joinpath("lifeos.toml").is_file()


def test_doctor_and_status_share_report_without_printing_paths(
    tmp_path, monkeypatch, capsys
) -> None:
    home, vault, _ = _runtime_home(tmp_path)
    monkeypatch.delenv(cli.VAULT_ENV, raising=False)
    assert cli.main(["--home", str(home), "init"]) == cli.EXIT_OK
    capsys.readouterr()
    monkeypatch.setattr(
        cli,
        "_probe_connectors",
        lambda _repo, _config=None: _compatible_records(),
    )

    before = _tree_snapshot(tmp_path)
    assert cli.main(["--home", str(home), "doctor"]) == cli.EXIT_OK
    human = capsys.readouterr().out
    assert "lifeos doctor: warning" in human
    assert str(home) not in human
    assert str(vault) not in human

    assert cli.main(["--home", str(home), "status", "--json"]) == cli.EXIT_OK
    machine_text = capsys.readouterr().out
    machine = json.loads(machine_text)
    assert machine["schema_version"] == 1
    assert machine["status"] == "warning"
    assert str(home) not in machine_text
    assert str(vault) not in machine_text
    assert _tree_snapshot(tmp_path) == before


def test_configured_connector_uses_argv_cwd_and_env_allowlist_without_leak(
    tmp_path, monkeypatch, capsys
) -> None:
    home, vault, _ = _runtime_home(tmp_path)
    probe_cwd = tmp_path / "probe-cwd"
    probe_cwd.mkdir()
    synthetic_secret = "P4-configured-secret-value"
    scripts = []
    for spec in DEFAULT_SPECS:
        script = tmp_path / f"configured-{spec.tool}.py"
        prefix = (f"profile-{spec.tool}",)
        scripts.append(script)
        _configured_probe_script(
            script,
            payload=_capability_payload(spec),
            prefix=prefix,
            cwd=probe_cwd,
            required_env=("P4_DOCTOR_SECRET", synthetic_secret),
            forbidden_envs=("PATH", "P4_UNLISTED_SECRET", "P4_MISSING_SECRET"),
        )
        _configure_tool(
            home,
            name=spec.tool,
            argv=(str(Path(sys.executable).resolve()), str(script), *prefix),
            cwd=probe_cwd,
            env_names=("P4_DOCTOR_SECRET", "P4_MISSING_SECRET"),
        )
    monkeypatch.setenv("P4_DOCTOR_SECRET", synthetic_secret)
    monkeypatch.setenv("P4_UNLISTED_SECRET", "must-not-reach-child")
    monkeypatch.delenv("P4_MISSING_SECRET", raising=False)
    monkeypatch.setenv("PATH", "")

    assert cli.main(["--home", str(home), "init"]) == cli.EXIT_OK
    capsys.readouterr()
    assert cli.main(["--home", str(home), "doctor"]) == cli.EXIT_OK
    human = capsys.readouterr().out
    for spec in DEFAULT_SPECS:
        expected = (
            "ok (connector_compatible)"
            if spec.machine_contract_available
            else "warning (connector_machine_contract_unavailable)"
        )
        assert f"connectors.{spec.tool}: {expected}" in human
    assert synthetic_secret not in human
    assert all(str(script) not in human for script in scripts)
    assert str(probe_cwd) not in human

    assert cli.main(["--home", str(home), "status", "--json"]) == cli.EXIT_OK
    machine_text = capsys.readouterr().out
    machine = json.loads(machine_text)
    connectors = next(
        section for section in machine["sections"] if section["name"] == "connectors"
    )
    assert {check["id"]: check["code"] for check in connectors["checks"]} == {
        f"connectors.{spec.tool}": (
            "connector_compatible"
            if spec.machine_contract_available
            else "connector_machine_contract_unavailable"
        )
        for spec in DEFAULT_SPECS
    }
    assert synthetic_secret not in machine_text
    assert "must-not-reach-child" not in machine_text
    assert "P4_MISSING_SECRET" not in machine_text
    assert all(str(script) not in machine_text for script in scripts)
    assert str(vault) not in machine_text


def test_unconfigured_ambient_path_connector_is_not_executed(
    tmp_path, monkeypatch, capsys
) -> None:
    home, _, _ = _runtime_home(tmp_path)
    fake_bin = tmp_path / "ambient-bin"
    fake_bin.mkdir()
    marker = tmp_path / "ambient-probe-ran"
    executable = fake_bin / "research"
    executable.write_text(
        "#!/bin/sh\n" + f"printf ran > {str(marker)!r}\n" + "exit 1\n",
        "utf-8",
    )
    executable.chmod(0o755)
    monkeypatch.setenv("PATH", str(fake_bin))

    assert cli.main(["--home", str(home), "init"]) == cli.EXIT_OK
    capsys.readouterr()
    assert cli.main(["--home", str(home), "doctor"]) == cli.EXIT_OK
    human = capsys.readouterr().out

    assert not marker.exists()
    assert "connectors.researcher: warning (connector_probe_missing)" in human
    assert (
        "connectors.llm-wiki: warning (connector_machine_contract_unavailable)"
    ) in human


def test_unknown_configured_connector_fails_doctor_without_execution_or_leak(
    tmp_path, monkeypatch, capsys
) -> None:
    home, _, _ = _runtime_home(tmp_path)
    marker = tmp_path / "unknown-ran"
    script = tmp_path / "unknown.py"
    script.write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).write_text('ran')\n",
        "utf-8",
    )
    _configure_tool(
        home,
        name="unknown-connector",
        argv=(str(Path(sys.executable).resolve()), str(script)),
    )
    monkeypatch.setenv("PATH", "/private/ambient-path")

    assert cli.main(["--home", str(home), "init"]) == cli.EXIT_OK
    capsys.readouterr()
    assert cli.main(["--home", str(home), "status", "--json"]) == cli.EXIT_FAIL
    machine_text = capsys.readouterr().out
    payload = json.loads(machine_text)
    connectors = next(
        section for section in payload["sections"] if section["name"] == "connectors"
    )

    assert connectors["checks"] == [
        {
            "code": "connector_probe_malformed",
            "id": "connectors.probe",
            "ref": None,
            "required": True,
            "status": "failure",
        }
    ]
    assert not marker.exists()
    assert "unknown-connector" not in machine_text
    assert str(script) not in machine_text


def test_configured_one_version_ahead_fails_doctor_safely(
    tmp_path, monkeypatch, capsys
) -> None:
    home, _, _ = _runtime_home(tmp_path)
    probe_cwd = tmp_path / "probe-cwd"
    probe_cwd.mkdir()
    script = tmp_path / "future-research.py"
    spec = next(item for item in DEFAULT_SPECS if item.tool == "researcher")
    _configured_probe_script(
        script,
        payload=_capability_payload(spec, version="0.2.0"),
        prefix=(),
        cwd=probe_cwd,
    )
    _configure_tool(
        home,
        name="researcher",
        argv=(str(Path(sys.executable).resolve()), str(script)),
        cwd=probe_cwd,
    )
    monkeypatch.setenv("PATH", "")

    assert cli.main(["--home", str(home), "init"]) == cli.EXIT_OK
    capsys.readouterr()
    assert cli.main(["--home", str(home), "status", "--json"]) == cli.EXIT_FAIL
    machine_text = capsys.readouterr().out
    payload = json.loads(machine_text)
    connectors = next(
        section for section in payload["sections"] if section["name"] == "connectors"
    )
    researcher = next(
        check
        for check in connectors["checks"]
        if check["id"] == "connectors.researcher"
    )
    assert researcher == {
        "code": "connector_contract_error",
        "id": "connectors.researcher",
        "ref": None,
        "required": False,
        "status": "failure",
    }
    assert "0.2.0" not in machine_text
    assert str(script) not in machine_text


def test_missing_optional_configured_connector_does_not_block_unrelated_scan(
    tmp_path, monkeypatch, capsys
) -> None:
    home, _, _ = _runtime_home(tmp_path)
    _configure_tool(
        home,
        name="gateway",
        argv=("missing-p4-gateway",),
    )
    monkeypatch.setenv("PATH", "")

    assert cli.main(["--home", str(home), "init"]) == cli.EXIT_OK
    capsys.readouterr()
    assert cli.main(["--home", str(home), "doctor"]) == cli.EXIT_OK
    human = capsys.readouterr().out
    assert "connectors.gateway: warning (optional_connector_unavailable)" in human

    assert cli.main(["--home", str(home), "scan"]) == cli.EXIT_OK
    scanned = json.loads(capsys.readouterr().out)
    assert scanned["kind"] == "vault-scan"


def test_status_requires_json_flag(capsys) -> None:
    with pytest.raises(SystemExit) as error:
        cli.main(["status"])
    assert error.value.code == cli.EXIT_FAIL
    assert "--json" in capsys.readouterr().err


def test_run_status_reads_only_authoritative_state(
    tmp_path, monkeypatch, capsys
) -> None:
    home, vault, _ = _runtime_home(tmp_path)
    monkeypatch.delenv(cli.VAULT_ENV, raising=False)
    assert cli.main(["--home", str(home), "init"]) == cli.EXIT_OK
    capsys.readouterr()
    profile = load_vault_config(vault)
    store = RunStore(VaultPathResolver(vault, profile))
    expected = store.create(
        run_id="run_cli",
        flow="distill",
        phase="collect",
        authority="proposal",
        executor="fixture",
        input_data={"source_ref": "inbox/fixture.md", "source_sha256": "0" * 64},
    )
    trace = vault / "agent/runs/run_cli/trace.jsonl"
    trace.write_bytes(b"not-json\n")
    before = _tree_snapshot(vault)

    assert cli.main(["--home", str(home), "run-status", "run_cli"]) == cli.EXIT_OK
    assert json.loads(capsys.readouterr().out) == expected
    assert _tree_snapshot(vault) == before


def test_skills_cli_reports_drift_and_preserves_modified_wrapper(
    tmp_path, monkeypatch, capsys
) -> None:
    home, vault, _ = _runtime_home(tmp_path)
    monkeypatch.delenv(cli.VAULT_ENV, raising=False)
    assert cli.main(["--home", str(home), "init"]) == cli.EXIT_OK
    capsys.readouterr()
    knowledge_before = _tree_snapshot(vault / "knowledge")

    assert cli.main(["--home", str(home), "skills", "install"]) == cli.EXIT_OK
    installed = json.loads(capsys.readouterr().out)
    assert installed["kind"] == "skills-install"
    assert installed["changed"] is True

    assert cli.main(["--home", str(home), "skills", "check"]) == cli.EXIT_OK
    checked = json.loads(capsys.readouterr().out)
    assert checked["ok"] is True

    modified = vault / ".claude/skills/lifeos-ingest/SKILL.md"
    modified.write_bytes(modified.read_bytes() + b"\nmanual owner change\n")
    assert cli.main(["--home", str(home), "skills", "check"]) == cli.EXIT_FAIL
    drift = json.loads(capsys.readouterr().out)
    assert drift["ok"] is False

    assert cli.main(["--home", str(home), "skills", "uninstall"]) == cli.EXIT_OK
    removed = json.loads(capsys.readouterr().out)
    assert ".claude/skills/lifeos-ingest/SKILL.md" in removed["preserved"]
    assert modified.read_bytes().endswith(b"manual owner change\n")
    assert not (vault / ".agents/skills/lifeos-ingest/SKILL.md").exists()
    assert _tree_snapshot(vault / "knowledge") == knowledge_before


def test_config_or_runtime_root_change_aborts_before_target_write(
    tmp_path, monkeypatch, capsys
) -> None:
    home, vault, _ = _runtime_home(tmp_path)
    saved_home = tmp_path / "runtime-home-saved"
    replacement = tmp_path / "runtime-home-replacement"
    replacement.mkdir()
    original_parse = cli._parse_snapshot

    def parse_then_change_root(raw, loader):
        result = original_parse(raw, loader)
        home.rename(saved_home)
        replacement.rename(home)
        return result

    monkeypatch.setattr(cli, "_parse_snapshot", parse_then_change_root)
    assert cli.main(["--home", str(home), "init"]) == cli.EXIT_FAIL
    error_text = capsys.readouterr().err
    assert "configuration" in error_text
    assert not vault.exists()
    assert saved_home.joinpath("config.toml").is_file()


@pytest.mark.parametrize("unsafe_home", ["relative-home", "", "bad\u0085home"])
def test_unsafe_home_fails_without_traceback(unsafe_home, capsys) -> None:
    assert cli.main(["--home", unsafe_home, "scan"]) == cli.EXIT_FAIL
    error_text = capsys.readouterr().err
    assert "runtime home" in error_text
    assert "Traceback" not in error_text


def test_symlinked_config_fails_without_traceback(tmp_path, capsys) -> None:
    home, _, _ = _runtime_home(tmp_path)
    real = home / "config.toml"
    moved = home / "actual.toml"
    real.rename(moved)
    real.symlink_to(moved)
    assert cli.main(["--home", str(home), "scan"]) == cli.EXIT_FAIL
    error_text = capsys.readouterr().err
    assert "cannot be read safely" in error_text
    assert str(home) not in error_text
    assert "Traceback" not in error_text


def test_all_usage_errors_exit_one(capsys) -> None:
    for argv in (
        [],
        ["missing"],
        ["init", "--missing"],
        ["skills"],
        ["skills", "missing"],
    ):
        with pytest.raises(SystemExit) as error:
            cli.main(argv)
        assert error.value.code == cli.EXIT_FAIL
        assert "error" in capsys.readouterr().err


def test_lifeos_entrypoint_is_registered() -> None:
    project = Path(__file__).resolve().parents[1]
    metadata = tomllib.loads((project / "pyproject.toml").read_text("utf-8"))

    assert metadata["project"]["scripts"]["lifeos"] == ("tool_life_os_runtime.cli:main")


@pytest.mark.parametrize(
    "argv",
    [
        ["scan"],
        ["doctor"],
        ["status", "--json"],
    ],
)
def test_deep_runtime_toml_never_escapes_as_raw_exception(
    tmp_path, argv, capsys
) -> None:
    home, _, _ = _runtime_home(tmp_path)
    nested = "[" * 500 + "0" + "]" * 500
    (home / "config.toml").write_text("x = " + nested + "\n", "utf-8")

    assert cli.main(["--home", str(home), *argv]) == cli.EXIT_FAIL
    captured = capsys.readouterr()
    assert "Traceback" not in captured.out + captured.err
    assert "RecursionError" not in captured.out + captured.err


def test_huge_toml_integer_and_deep_vault_profile_fail_bounded(
    tmp_path, monkeypatch, capsys
) -> None:
    home, vault, _ = _runtime_home(tmp_path)
    original = (home / "config.toml").read_text("utf-8")
    (home / "config.toml").write_text(
        original.replace("schema_version = 1", "schema_version = " + "9" * 5000),
        "utf-8",
    )
    assert cli.main(["--home", str(home), "scan"]) == cli.EXIT_FAIL
    error_text = capsys.readouterr().err
    assert "ValueError" not in error_text
    assert "Traceback" not in error_text

    (home / "config.toml").write_text(original, "utf-8")
    monkeypatch.delenv(cli.VAULT_ENV, raising=False)
    assert cli.main(["--home", str(home), "init"]) == cli.EXIT_OK
    capsys.readouterr()
    nested = "[" * 500 + "0" + "]" * 500
    (vault / "lifeos.toml").write_text("x = " + nested + "\n", "utf-8")
    assert cli.main(["--home", str(home), "run-status", "run_missing"]) == cli.EXIT_FAIL
    error_text = capsys.readouterr().err
    assert "RecursionError" not in error_text
    assert "Traceback" not in error_text


def test_untrusted_config_keys_are_never_rendered_to_stderr(tmp_path, capsys) -> None:
    home, _, _ = _runtime_home(tmp_path)
    marker = "/private/owner/top-secret-token"
    with (home / "config.toml").open("a", encoding="utf-8") as handle:
        handle.write(f'"bad\\n\\u001b{marker}" = 1\n')

    assert cli.main(["--home", str(home), "scan"]) == cli.EXIT_FAIL
    error_text = capsys.readouterr().err
    assert error_text == "lifeos: runtime configuration is invalid\n"
    assert marker not in error_text
    assert "\x1b" not in error_text


def test_snapshot_thread_start_failure_closes_descriptors(
    tmp_path, monkeypatch
) -> None:
    fd_root = Path("/dev/fd")
    if not fd_root.is_dir():
        pytest.skip("descriptor filesystem unavailable")
    home, _, _ = _runtime_home(tmp_path)
    raw = (home / "config.toml").read_bytes()

    def fail_start(_self):
        raise RuntimeError("synthetic thread start failure")

    before = len(list(fd_root.iterdir()))
    monkeypatch.setattr(threading.Thread, "start", fail_start)
    with pytest.raises(cli.CliError, match="bounded configuration parser failed"):
        cli._parse_snapshot(raw, cli.load_runtime_config)
    assert len(list(fd_root.iterdir())) == before

    monkeypatch.setattr(cli, "_probe_connectors", lambda _repo: _compatible_records())
    report = cli._doctor_report(home)
    assert report.status == "failure"
    assert len(list(fd_root.iterdir())) == before


@pytest.mark.parametrize("target_exists", [False, True])
def test_skills_install_requires_initialized_vault_before_any_write(
    tmp_path, target_exists, capsys
) -> None:
    home, vault, _ = _runtime_home(tmp_path)
    if target_exists:
        vault.mkdir()
    before = _tree_snapshot(tmp_path)

    assert cli.main(["--home", str(home), "skills", "install"]) == cli.EXIT_FAIL
    capsys.readouterr()
    assert _tree_snapshot(tmp_path) == before
    assert not (home / "install").exists()


def test_skills_install_rejects_profile_only_incomplete_vault_without_write(
    tmp_path, capsys
) -> None:
    home, vault, _ = _runtime_home(tmp_path)
    vault.mkdir()
    shutil.copy2(
        Path(__file__).parent / "fixtures/vault-minimal/lifeos.toml",
        vault / "lifeos.toml",
    )
    before = _tree_snapshot(tmp_path)

    assert cli.main(["--home", str(home), "skills", "install"]) == cli.EXIT_FAIL
    capsys.readouterr()

    assert _tree_snapshot(tmp_path) == before
    assert not (home / "install").exists()


def test_skills_rejects_changed_runtime_home_before_manifest_creation(
    tmp_path, monkeypatch, capsys
) -> None:
    home, vault, _ = _runtime_home(tmp_path)
    assert cli.main(["--home", str(home), "init"]) == cli.EXIT_OK
    capsys.readouterr()
    saved_home = tmp_path / "runtime-home-saved"
    replacement = tmp_path / "runtime-home-replacement"
    shutil.copytree(home, replacement)
    original_manifest_root = cli._manifest_root

    def swap_then_open(home_path, *, create, expected_home_identity):
        home.rename(saved_home)
        replacement.rename(home)
        return original_manifest_root(
            home_path,
            create=create,
            expected_home_identity=expected_home_identity,
        )

    monkeypatch.setattr(cli, "_manifest_root", swap_then_open)
    assert cli.main(["--home", str(home), "skills", "install"]) == cli.EXIT_FAIL
    capsys.readouterr()
    assert not (home / "install").exists()
    assert not (saved_home / "install").exists()
    assert not list(vault.glob(".agents/skills/*"))
    assert not list(vault.glob(".claude/skills/*"))


def test_skills_expected_identity_rejects_changed_vault_before_write(
    tmp_path, monkeypatch, capsys
) -> None:
    home, vault, _ = _runtime_home(tmp_path)
    assert cli.main(["--home", str(home), "init"]) == cli.EXIT_OK
    capsys.readouterr()
    saved_vault = tmp_path / "vault-main-saved"
    replacement = tmp_path / "vault-main-replacement"
    shutil.copytree(vault, replacement)
    original_install = cli.install

    def swap_then_install(*args, **kwargs):
        vault.rename(saved_vault)
        replacement.rename(vault)
        return original_install(*args, **kwargs)

    monkeypatch.setattr(cli, "install", swap_then_install)
    assert cli.main(["--home", str(home), "skills", "install"]) == cli.EXIT_FAIL
    capsys.readouterr()
    assert not list(vault.glob(".agents/skills/*"))
    assert not list(vault.glob(".claude/skills/*"))
    assert not list(saved_vault.glob(".agents/skills/*"))
    assert not list(saved_vault.glob(".claude/skills/*"))
    assert not (home / "install/lifeos-skills-v1.json").exists()


def test_skills_bind_runtime_home_container_when_install_inode_is_relocated(
    tmp_path, monkeypatch, capsys
) -> None:
    home, vault, _ = _runtime_home(tmp_path)
    assert cli.main(["--home", str(home), "init"]) == cli.EXIT_OK
    capsys.readouterr()
    saved_home = tmp_path / "runtime-home-saved"
    original_install = cli.install
    swapped = False

    def relocate_install_then_call(*args, **kwargs):
        nonlocal swapped
        home.rename(saved_home)
        home.mkdir()
        (saved_home / "install").rename(home / "install")
        swapped = True
        return original_install(*args, **kwargs)

    monkeypatch.setattr(cli, "install", relocate_install_then_call)
    assert cli.main(["--home", str(home), "skills", "install"]) == cli.EXIT_FAIL
    capsys.readouterr()

    assert swapped is True
    assert not (home / "install/lifeos-skills-v1.json").exists()
    assert not list(vault.glob(".agents/skills/*"))
    assert not list(vault.glob(".claude/skills/*"))


def test_run_status_does_not_emit_state_from_changed_vault(
    tmp_path, monkeypatch, capsys
) -> None:
    home, vault, _ = _runtime_home(tmp_path)
    assert cli.main(["--home", str(home), "init"]) == cli.EXIT_OK
    capsys.readouterr()
    profile = load_vault_config(vault)
    RunStore(VaultPathResolver(vault, profile)).create(
        run_id="run_bound",
        flow="distill",
        phase="collect",
        authority="proposal",
        executor="old-executor",
        input_data={"source_ref": "inbox/fixture.md", "source_sha256": "0" * 64},
    )
    saved_vault = tmp_path / "vault-main-saved"
    replacement = tmp_path / "vault-main-replacement"
    shutil.copytree(vault, replacement)
    replacement_state = replacement / "agent/runs/run_bound/state.json"
    payload = json.loads(replacement_state.read_text("utf-8"))
    payload["executor"] = "new-executor"
    replacement_state.write_text(
        json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n", "utf-8"
    )
    original_status = RunStore.status

    def swap_then_status(self, run_id):
        vault.rename(saved_vault)
        replacement.rename(vault)
        return original_status(self, run_id)

    monkeypatch.setattr(RunStore, "status", swap_then_status)
    assert cli.main(["--home", str(home), "run-status", "run_bound"]) == cli.EXIT_FAIL
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "new-executor" not in captured.err
