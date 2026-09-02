"""P0-05 fake-PATH checks for exact neighboring CLI contracts."""

from __future__ import annotations

import io
import json
import os
import signal
import subprocess
import sys
import time
from dataclasses import replace
from pathlib import Path

import pytest

from tool_life_os_runtime.ext.connectors.probes import (
    DEFAULT_SPECS,
    ProbeSpec,
    probe_all,
    probe_tool,
)
from tool_life_os_runtime.ext.connectors.probes.capabilities import (
    MAX_PROBE_OUTPUT_BYTES,
)
import tool_life_os_runtime.ext.connectors.probes.capabilities as probes_module


def _payload(spec: ProbeSpec, *, version: str = "0.1.0") -> dict[str, object]:
    return {
        "schema_version": 1,
        "tool": spec.tool,
        "version": version,
        "capabilities": [
            capability.to_dict() for capability in spec.expected_capabilities
        ],
    }


def _fake_executable(
    directory: Path,
    name: str,
    *,
    stdout: str,
    stderr: str = "",
    exit_code: int = 0,
) -> None:
    path = directory / name
    path.write_text(
        "#!/bin/sh\n"
        'if [ "$1" != capabilities ] || [ "$2" != --json ]; then exit 64; fi\n'
        "printf '%s' " + _shell_single_quote(stdout) + "\n"
        "printf '%s' " + _shell_single_quote(stderr) + " >&2\n"
        f"exit {exit_code}\n",
        "utf-8",
    )
    path.chmod(0o755)


def _shell_single_quote(value: str) -> str:
    return "'" + value.replace("'", "'\\''") + "'"


def _path_env(fake_bin: Path) -> dict[str, str]:
    return {"PATH": str(fake_bin), "LC_ALL": "C"}


def test_integrator_side_matrix_fixes_exact_contracts():
    researcher = DEFAULT_SPECS[0]
    start = researcher.expected_capabilities[0]

    assert researcher.required_capabilities == (
        "start",
        "status",
        "resume",
        "extend",
        "doctor",
    )
    assert start.argv == (
        "research",
        "start",
        "<topic>",
        "--base",
        "<topics-root>",
        "--json",
    )
    assert start.machine_output.required_fields == (
        "schema_version",
        "status",
        "topic_dir",
    )
    assert dict(start.exit_codes)[76] == "waiting_human"
    assert start.idempotency == "deduplicated"
    for capability in researcher.expected_capabilities[2:4]:
        assert dict(capability.exit_codes)[76] == "waiting_human"


def test_supported_matrix_records_only_expected_contracts(tmp_path):
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    for spec in DEFAULT_SPECS:
        _fake_executable(fake_bin, spec.executable, stdout=json.dumps(_payload(spec)))

    before = sorted(path.relative_to(tmp_path) for path in tmp_path.rglob("*"))
    records = probe_all(cwd=tmp_path, env=_path_env(fake_bin))
    after = sorted(path.relative_to(tmp_path) for path in tmp_path.rglob("*"))

    assert before == after
    assert [record.tool for record in records] == [spec.tool for spec in DEFAULT_SPECS]
    assert {record.tool: (record.status, record.error) for record in records} == {
        spec.tool: (
            ("compatible", None)
            if spec.machine_contract_available
            else ("unavailable", "machine_contract_unavailable")
        )
        for spec in DEFAULT_SPECS
    }
    for record, spec in zip(records, DEFAULT_SPECS, strict=True):
        assert record.probe_argv == spec.argv
        assert record.protocol_version == (
            1 if spec.machine_contract_available else None
        )
        assert record.missing_machine_modes == ()
        assert record.expected_capabilities == spec.expected_capabilities
        assert record.to_dict()["expected_capabilities"] == [
            capability.to_dict() for capability in spec.expected_capabilities
        ]


def test_optional_missing_tool_is_structured_unavailable(tmp_path):
    spec = replace(DEFAULT_SPECS[0], executable="not-installed", optional=True)

    record = probe_tool(spec, cwd=tmp_path, env=_path_env(tmp_path))

    assert record.status == "unavailable"
    assert record.error == "executable_not_found"


def test_missing_llmwiki_machine_contract_is_an_explicit_gap_without_execution(
    tmp_path, monkeypatch
):
    spec = next(item for item in DEFAULT_SPECS if item.tool == "llm-wiki")
    monkeypatch.setattr(
        subprocess,
        "Popen",
        lambda *_args, **_kwargs: pytest.fail("integration gap reached subprocess"),
    )

    record = probe_tool(
        spec,
        cwd=tmp_path,
        env={"PATH": "/ambient"},
        command=("/private/configured/llmwiki",),
    )

    assert record.status == "unavailable"
    assert record.error == "machine_contract_unavailable"
    assert record.probe_argv == ()
    assert record.expected_capabilities == ()
    assert record.returncode is None
    assert record.missing_machine_modes == spec.required_capabilities


def test_required_missing_tool_is_contract_error(tmp_path):
    spec = replace(DEFAULT_SPECS[0], executable="not-installed", optional=False)

    record = probe_tool(spec, cwd=tmp_path, env=_path_env(tmp_path))

    assert record.status == "contract_error"
    assert record.error == "required_executable_not_found"


def test_missing_cwd_is_distinct_from_missing_executable(tmp_path):
    record = probe_tool(
        DEFAULT_SPECS[0],
        cwd=tmp_path / "missing-cwd",
        env=_path_env(tmp_path),
    )

    assert record.status == "contract_error"
    assert record.error == "probe_cwd_not_directory"
    assert record.missing_machine_modes == ()


@pytest.mark.parametrize("version", ["0.0.9", "0.2.0"])
def test_incompatible_version_is_not_serialized(tmp_path, version):
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    spec = DEFAULT_SPECS[0]
    _fake_executable(
        fake_bin, spec.executable, stdout=json.dumps(_payload(spec, version=version))
    )

    record = probe_tool(spec, cwd=tmp_path, env=_path_env(fake_bin))

    assert record.status == "contract_error"
    assert record.error == "unsupported_tool_version"
    if version != record.maximum_supported_tool_version_exclusive:
        assert version not in json.dumps(record.to_dict())


def test_huge_semver_component_is_structured_contract_error(tmp_path):
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    spec = DEFAULT_SPECS[0]
    huge_component = "7" * 10_000
    _fake_executable(
        fake_bin,
        spec.executable,
        stdout=json.dumps(_payload(spec, version=f"0.{huge_component}.0")),
    )

    record = probe_tool(spec, cwd=tmp_path, env=_path_env(fake_bin))
    serialized = json.dumps(record.to_dict())

    assert record.status == "contract_error"
    assert record.error == "invalid_machine_output"
    assert huge_component not in serialized


@pytest.mark.parametrize(
    "stdout",
    [
        "research 0.1.0 supports status",
        "{not-json}",
        "[]",
        '{"schema_version": 1}',
        '{}\n{"schema_version": 1}',
    ],
)
def test_human_or_malformed_machine_output_is_rejected(tmp_path, stdout):
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    spec = DEFAULT_SPECS[0]
    _fake_executable(fake_bin, spec.executable, stdout=stdout)

    record = probe_tool(spec, cwd=tmp_path, env=_path_env(fake_bin))

    assert record.status == "contract_error"
    assert record.error == "invalid_machine_output"
    assert record.missing_machine_modes == spec.required_capabilities
    assert stdout not in json.dumps(record.to_dict())


@pytest.mark.parametrize("location", ["top", "nested"])
def test_duplicate_machine_output_fields_are_rejected_recursively(tmp_path, location):
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    spec = DEFAULT_SPECS[0]
    stdout = json.dumps(_payload(spec), separators=(",", ":"))
    if location == "top":
        stdout = stdout.replace(
            '"schema_version":1',
            '"schema_version":999,"schema_version":1',
            1,
        )
    else:
        stdout = stdout.replace(
            '"name":"start"',
            '"name":"forged","name":"start"',
            1,
        )
    _fake_executable(fake_bin, spec.executable, stdout=stdout)

    record = probe_tool(spec, cwd=tmp_path, env=_path_env(fake_bin))

    assert record.status == "contract_error"
    assert record.error == "invalid_machine_output"
    assert record.protocol_version is None


def test_missing_required_mode_is_preserved_in_contract_error(tmp_path):
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    spec = DEFAULT_SPECS[0]
    payload = _payload(spec)
    payload["capabilities"] = payload["capabilities"][1:]
    _fake_executable(fake_bin, spec.executable, stdout=json.dumps(payload))

    record = probe_tool(spec, cwd=tmp_path, env=_path_env(fake_bin))

    assert record.status == "contract_error"
    assert record.error == "capability_contract_mismatch"
    assert record.missing_machine_modes == ("start",)


@pytest.mark.parametrize(
    "exit_code,status,error",
    [(75, "quota", "probe_quota"), (111, "transient", "probe_transient")],
)
def test_quota_and_transient_are_not_compatibility_errors(
    tmp_path, exit_code, status, error
):
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    spec = DEFAULT_SPECS[0]
    untrusted_stdout = (
        "x" * (MAX_PROBE_OUTPUT_BYTES + 100) if exit_code == 75 else "untrusted output"
    )
    _fake_executable(
        fake_bin,
        spec.executable,
        stdout=untrusted_stdout,
        stderr="secret diagnostic",
        exit_code=exit_code,
    )

    record = probe_tool(spec, cwd=tmp_path, env=_path_env(fake_bin))

    assert record.status == status
    assert record.error == error
    assert record.returncode == exit_code
    assert record.missing_machine_modes == ()
    assert record.stdout_bytes <= MAX_PROBE_OUTPUT_BYTES + 1
    assert "secret diagnostic" not in json.dumps(record.to_dict())


def test_permanent_nonzero_probe_is_contract_error_without_output(tmp_path):
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    spec = DEFAULT_SPECS[0]
    _fake_executable(
        fake_bin,
        spec.executable,
        stdout="private diagnostic",
        stderr="token=private-value",
        exit_code=1,
    )

    record = probe_tool(spec, cwd=tmp_path, env=_path_env(fake_bin))
    serialized = json.dumps(record.to_dict())

    assert record.status == "contract_error"
    assert record.returncode == 1
    assert record.error == "machine_probe_nonzero_exit"
    assert "private diagnostic" not in serialized
    assert "private-value" not in serialized


@pytest.mark.parametrize("field", ["argv", "idempotency", "extra-secret"])
def test_malicious_self_report_is_rejected_and_never_serialized(tmp_path, field):
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    spec = DEFAULT_SPECS[0]
    payload = _payload(spec)
    secret = "UNTRUSTED-PROBE-FIELD-MUST-NOT-SERIALIZE-4f29"
    if field == "argv":
        payload["capabilities"][0]["argv"] = ["sh", "-c", secret]
    elif field == "idempotency":
        payload["capabilities"][0]["idempotency"] = secret
    else:
        payload["debug"] = secret
    _fake_executable(fake_bin, spec.executable, stdout=json.dumps(payload))

    record = probe_tool(spec, cwd=tmp_path, env=_path_env(fake_bin))
    serialized = json.dumps(record.to_dict())

    assert record.status == "contract_error"
    assert record.error in {"capability_contract_mismatch", "invalid_machine_output"}
    assert secret not in serialized
    assert [capability.to_dict() for capability in record.expected_capabilities] == [
        capability.to_dict() for capability in spec.expected_capabilities
    ]


def test_exact_contract_rejects_bool_where_integer_schema_is_expected(tmp_path):
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    spec = DEFAULT_SPECS[0]
    payload = _payload(spec)
    payload["capabilities"][0]["machine_output"]["schema_version"] = True
    _fake_executable(fake_bin, spec.executable, stdout=json.dumps(payload))

    record = probe_tool(spec, cwd=tmp_path, env=_path_env(fake_bin))

    assert record.status == "contract_error"
    assert record.error == "capability_contract_mismatch"


@pytest.mark.parametrize("stream", ["stdout", "stderr"])
def test_probe_output_is_bounded_before_parsing(tmp_path, stream):
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    spec = DEFAULT_SPECS[0]
    large = "x" * (MAX_PROBE_OUTPUT_BYTES + 100)
    _fake_executable(
        fake_bin,
        spec.executable,
        stdout=large if stream == "stdout" else json.dumps(_payload(spec)),
        stderr=large if stream == "stderr" else "",
    )

    record = probe_tool(spec, cwd=tmp_path, env=_path_env(fake_bin))

    assert record.status == "contract_error"
    assert record.error == "probe_output_too_large"
    assert record.stdout_bytes <= MAX_PROBE_OUTPUT_BYTES + 1
    assert record.stderr_bytes <= MAX_PROBE_OUTPUT_BYTES + 1
    assert large not in json.dumps(record.to_dict())


def test_subprocess_boundary_uses_argv_explicit_cwd_env_and_no_shell(
    monkeypatch, tmp_path
):
    spec = DEFAULT_SPECS[0]
    payload = json.dumps(_payload(spec)).encode()
    seen = {}

    monkeypatch.setattr(
        "tool_life_os_runtime.ext.connectors.probes.capabilities.shutil.which",
        lambda executable, path: "/fake/" + executable,
    )

    class FakeProcess:
        def __init__(self):
            self.stdout = io.BytesIO(payload)
            self.stderr = io.BytesIO()

        def wait(self, timeout=None):
            seen["wait_timeout"] = timeout
            return 0

        def kill(self):
            raise AssertionError("compatible probe must not be killed")

    def fake_popen(argv, **kwargs):
        seen["argv"] = argv
        seen.update(kwargs)
        return FakeProcess()

    monkeypatch.setattr(subprocess, "Popen", fake_popen)
    record = probe_tool(spec, cwd=tmp_path, env={"PATH": "/fake"})

    assert record.status == "compatible"
    assert seen["argv"] == ["research", "capabilities", "--json"]
    assert seen["cwd"] == tmp_path
    assert seen["env"] == {"PATH": "/fake"}
    assert seen["stdin"] is subprocess.DEVNULL
    assert seen["shell"] is False
    assert seen["stdout"] is subprocess.PIPE
    assert seen["stderr"] is subprocess.PIPE
    assert seen["start_new_session"] is True
    assert 0 < seen["wait_timeout"] <= 5.0


def test_configured_command_prefix_is_used_but_never_serialized(monkeypatch, tmp_path):
    spec = DEFAULT_SPECS[0]
    payload = json.dumps(_payload(spec)).encode()
    seen = {}
    private_prefix = (str(Path(sys.executable).resolve()), "--profile", "owner-secret")

    class FakeProcess:
        def __init__(self):
            self.stdout = io.BytesIO(payload)
            self.stderr = io.BytesIO()

        def wait(self, timeout=None):
            return 0

        def kill(self):
            raise AssertionError("compatible probe must not be killed")

    def fake_popen(argv, **kwargs):
        seen["argv"] = argv
        seen.update(kwargs)
        return FakeProcess()

    monkeypatch.setattr(subprocess, "Popen", fake_popen)
    record = probe_tool(
        spec,
        cwd=tmp_path,
        env={"PATH": "/configured", "TOKEN": "private-value"},
        command=private_prefix,
    )

    assert record.status == "compatible"
    assert seen["argv"] == [*private_prefix, "capabilities", "--json"]
    assert seen["env"] == {"PATH": "/configured", "TOKEN": "private-value"}
    serialized = json.dumps(record.to_dict())
    assert record.probe_argv == spec.argv
    assert "owner-secret" not in serialized
    assert "private-value" not in serialized


@pytest.mark.parametrize(
    "command",
    [(), ["tool", "bad\narg"], ["tool"] * 33, "tool"],
)
def test_invalid_configured_command_fails_before_process_start(
    tmp_path, monkeypatch, command
):
    monkeypatch.setattr(
        subprocess,
        "Popen",
        lambda *_args, **_kwargs: pytest.fail("invalid command reached subprocess"),
    )

    record = probe_tool(
        DEFAULT_SPECS[0],
        cwd=tmp_path,
        env={"PATH": ""},
        command=command,
    )

    assert record.status == "contract_error"
    assert record.error == "configured_command_invalid"
    assert record.missing_machine_modes == DEFAULT_SPECS[0].required_capabilities


@pytest.mark.parametrize(
    "target", ["relative-executable", "symlink-executable", "symlink-cwd"]
)
def test_configured_target_symlinks_and_relative_executable_fail_before_process(
    tmp_path, monkeypatch, target
):
    real_cwd = tmp_path / "cwd"
    real_cwd.mkdir()
    cwd = real_cwd
    command: tuple[str, ...] = (str(Path(sys.executable).resolve()),)
    if target == "relative-executable":
        command = ("./bin/research",)
    elif target == "symlink-executable":
        executable = tmp_path / "research-link"
        executable.symlink_to(sys.executable)
        command = (str(executable),)
    else:
        cwd = tmp_path / "cwd-link"
        cwd.symlink_to(real_cwd, target_is_directory=True)
    monkeypatch.setattr(
        subprocess,
        "Popen",
        lambda *_args, **_kwargs: pytest.fail("unsafe target reached subprocess"),
    )

    record = probe_tool(
        DEFAULT_SPECS[0],
        cwd=cwd,
        env={"PATH": ""},
        command=command,
    )

    assert record.status == "contract_error"
    assert record.error in {"configured_cwd_unsafe", "configured_executable_unsafe"}


def test_same_byte_configured_executable_replacement_before_popen_is_detected(
    tmp_path, monkeypatch
):
    spec = DEFAULT_SPECS[0]
    executable = tmp_path / "configured-research"
    payload = json.dumps(_payload(spec))
    _fake_executable(
        tmp_path,
        executable.name,
        stdout=payload,
    )
    original_run = probes_module._run_bounded

    def replace_then_run(argv, **kwargs):
        before = executable.with_suffix(".before")
        executable.rename(before)
        executable.write_bytes(before.read_bytes())
        executable.chmod(0o755)
        return original_run(argv, **kwargs)

    monkeypatch.setattr(probes_module, "_run_bounded", replace_then_run)

    record = probe_tool(
        spec,
        cwd=tmp_path,
        env={"PATH": ""},
        command=(str(executable),),
    )

    assert record.status == "contract_error"
    assert record.error == "configured_target_changed"
    assert record.returncode == 0
    assert payload not in json.dumps(record.to_dict())


def test_configured_cwd_replacement_before_popen_is_detected(tmp_path, monkeypatch):
    spec = DEFAULT_SPECS[0]
    cwd = tmp_path / "configured-cwd"
    cwd.mkdir()
    moved = tmp_path / "configured-cwd-before"
    executable = tmp_path / "configured-research"
    payload = json.dumps(_payload(spec))
    _fake_executable(
        tmp_path,
        executable.name,
        stdout=payload,
    )
    original_run = probes_module._run_bounded

    def replace_then_run(argv, **kwargs):
        cwd.rename(moved)
        cwd.mkdir()
        return original_run(argv, **kwargs)

    monkeypatch.setattr(probes_module, "_run_bounded", replace_then_run)

    record = probe_tool(
        spec,
        cwd=cwd,
        env={"PATH": ""},
        command=(str(executable),),
    )

    assert record.status == "contract_error"
    assert record.error == "configured_target_changed"
    assert record.returncode == 0


def test_background_descendant_holding_pipes_is_killed_within_deadline(tmp_path):
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    spec = DEFAULT_SPECS[0]
    executable = fake_bin / spec.executable
    executable.write_text(
        "#!/bin/sh\n"
        'if [ "$1" != capabilities ] || [ "$2" != --json ]; then exit 64; fi\n'
        "/bin/sleep 30 &\n"
        "printf '%s' " + _shell_single_quote(json.dumps(_payload(spec))) + "\n"
        "exit 0\n",
        "utf-8",
    )
    executable.chmod(0o755)

    started = time.monotonic()
    record = probe_tool(spec, cwd=tmp_path, env=_path_env(fake_bin), timeout=0.2)
    elapsed = time.monotonic() - started

    assert record.status == "transient"
    assert record.error == "probe_timeout"
    assert elapsed < 1.5


def test_escaped_descendant_cannot_retain_owner_pipe_descriptors(tmp_path):
    if not Path("/dev/fd").is_dir():
        pytest.skip("descriptor inventory is unavailable")
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    spec = DEFAULT_SPECS[0]
    executable = fake_bin / spec.executable
    pid_file = tmp_path / "escaped.pid"
    executable.write_text(
        f"#!{sys.executable}\n"
        "import json, pathlib, subprocess, sys\n"
        f"child = subprocess.Popen([{sys.executable!r}, '-c', 'import time; time.sleep(30)'], start_new_session=True)\n"
        f"pathlib.Path({str(pid_file)!r}).write_text(str(child.pid), encoding='utf-8')\n"
        f"print(json.dumps({_payload(spec)!r}, separators=(',', ':')))\n",
        "utf-8",
    )
    executable.chmod(0o755)
    before = len(os.listdir("/dev/fd"))
    try:
        record = probe_tool(spec, cwd=tmp_path, env=_path_env(fake_bin), timeout=0.2)
        assert record.status == "transient"
        assert record.error == "probe_timeout"
        assert len(os.listdir("/dev/fd")) == before
    finally:
        if pid_file.is_file():
            try:
                os.kill(int(pid_file.read_text("utf-8")), signal.SIGKILL)
            except (OSError, ValueError):
                pass


@pytest.mark.parametrize("failing_start", [1, 2])
def test_reader_start_failure_kills_reaps_and_closes_pipes(
    tmp_path, monkeypatch, failing_start
):
    if not Path("/dev/fd").is_dir():
        pytest.skip("descriptor inventory is unavailable")
    spec = DEFAULT_SPECS[0]
    script = tmp_path / "blocking-probe.py"
    pid_file = tmp_path / "probe.pid"
    script.write_text(
        "import os, pathlib, time\n"
        f"pathlib.Path({str(pid_file)!r}).write_text(str(os.getpid()), encoding='utf-8')\n"
        "time.sleep(30)\n",
        "utf-8",
    )
    original_start = probes_module.threading.Thread.start
    calls = 0

    def fail_selected_start(thread):
        nonlocal calls
        calls += 1
        if calls == failing_start:
            raise RuntimeError("thread unavailable")
        return original_start(thread)

    monkeypatch.setattr(probes_module.threading.Thread, "start", fail_selected_start)
    before = len(os.listdir("/dev/fd"))

    record = probe_tool(
        spec,
        cwd=tmp_path,
        env={},
        command=(str(Path(sys.executable).resolve()), str(script)),
    )

    assert record.status == "contract_error"
    assert record.error == "probe_execution_failed"
    assert calls == failing_start
    assert len(os.listdir("/dev/fd")) == before
    if pid_file.is_file():
        with pytest.raises(ProcessLookupError):
            os.kill(int(pid_file.read_text("utf-8")), 0)


def test_timeout_is_transient_not_contract_error(monkeypatch, tmp_path):
    spec = DEFAULT_SPECS[0]
    monkeypatch.setattr(
        "tool_life_os_runtime.ext.connectors.probes.capabilities.shutil.which",
        lambda executable, path: "/fake/" + executable,
    )

    class FakeProcess:
        def __init__(self):
            self.stdout = io.BytesIO()
            self.stderr = io.BytesIO()
            self.killed = False

        def wait(self, timeout=None):
            if not self.killed:
                raise subprocess.TimeoutExpired(["research"], timeout)
            return -9

        def kill(self):
            self.killed = True

    monkeypatch.setattr(subprocess, "Popen", lambda argv, **kwargs: FakeProcess())
    record = probe_tool(spec, cwd=tmp_path, env={"PATH": "/fake"})

    assert record.status == "transient"
    assert record.error == "probe_timeout"
