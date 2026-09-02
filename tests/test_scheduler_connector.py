"""P4-03 scheduler observation and recipe contract acceptance."""

from __future__ import annotations

from dataclasses import replace
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import tomllib

import pytest

from tool_life_os_runtime.ext.connectors.probes import DEFAULT_SPECS
from tool_life_os_runtime.ext.connectors.scheduler import (
    SchedulerConnector,
    SchedulerConnectorError,
    SchedulerRecipe,
    canonical_recipe_descriptors,
    recipe_set_sha256,
    render_recipe,
)


SCHEDULER_SMOKE_ROOT = os.environ.get("LIFEOS_SCHEDULER_SMOKE_ROOT", "")
SCHEDULER_REPO = Path(SCHEDULER_SMOKE_ROOT or "/nonexistent/scheduler-smoke")
SPEC = next(spec for spec in DEFAULT_SPECS if spec.tool == "scheduler")


def _home(tmp_path: Path) -> Path:
    home = tmp_path / "scheduler-home"
    (home / "jobs").mkdir(parents=True)
    return home


def _connector(tmp_path: Path, *, timeout: float = 3) -> SchedulerConnector:
    return SchedulerConnector(
        command=(sys.executable, "-m", "tool_scheduler"),
        cwd=SCHEDULER_REPO,
        env={"PATH": os.environ.get("PATH", "")},
        home=_home(tmp_path),
        timeout=timeout,
    )


def _fake(tmp_path: Path, body: str, *, timeout: float = 1) -> SchedulerConnector:
    tmp_path.mkdir(parents=True, exist_ok=True)
    script = tmp_path / "fake_scheduler.py"
    script.write_text(body, "utf-8")
    return SchedulerConnector(
        command=(sys.executable, str(script)),
        cwd=tmp_path,
        env={"PATH": os.environ.get("PATH", "")},
        home=_home(tmp_path),
        timeout=timeout,
    )


def _capabilities() -> dict[str, object]:
    return {
        "schema_version": 1,
        "tool": "scheduler",
        "version": "0.1.0",
        "capabilities": [item.to_dict() for item in SPEC.expected_capabilities],
    }


def _script_payload(operation: str, payload: object, *, exit_code: int = 0) -> str:
    capabilities = json.dumps(_capabilities(), sort_keys=True, separators=(",", ":"))
    output = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return f"""import sys
if sys.argv[-2:] == ['capabilities', '--json']:
    print({capabilities!r})
    raise SystemExit(0)
if {operation!r} in sys.argv:
    print({output!r})
    raise SystemExit({exit_code})
raise SystemExit(9)
"""


def _list_with_job() -> dict[str, object]:
    return {
        "schema_version": 1,
        "status": "ok",
        "enabled": False,
        "jobs": [
            {
                "name": "ambient",
                "enabled": False,
                "schedule": {"kind": "every", "every_seconds": 900},
                "policy": {
                    "retries": 3,
                    "retry_delay_seconds": 300,
                    "quota_wait_seconds": 3600,
                    "timeout_seconds": 0,
                },
                "state": {
                    "last_run": "2026-08-20T10:00:00+00:00",
                    "last_status": "ok",
                    "fails": 0,
                    "next_run": 1_787_220_900.0,
                    "next_run_iso": "2026-08-20T10:15:00+00:00",
                    "next_run_reason": "schedule",
                },
            }
        ],
        "errors": [],
    }


@pytest.mark.skipif(
    not SCHEDULER_SMOKE_ROOT,
    reason="set LIFEOS_SCHEDULER_SMOKE_ROOT to opt into the live connector smoke",
)
def test_real_scheduler_machine_surface_is_exact_and_read_only(tmp_path: Path) -> None:
    home = _home(tmp_path)
    before = tuple(
        (path.relative_to(home).as_posix(), path.stat().st_ino, path.stat().st_mtime_ns)
        for path in (home, home / "jobs")
    )
    connector = SchedulerConnector(
        command=(sys.executable, "-m", "tool_scheduler"),
        cwd=SCHEDULER_REPO,
        env={"PATH": os.environ.get("PATH", "")},
        home=home,
    )
    assert connector.list_jobs().jobs == ()
    assert connector.list_jobs().enabled is False
    assert connector.doctor().status == "ok"
    assert connector.job_schema().schema_version == 1
    connector.close()
    after = tuple(
        (path.relative_to(home).as_posix(), path.stat().st_ino, path.stat().st_mtime_ns)
        for path in (home, home / "jobs")
    )
    assert after == before
    assert not (home / ".enabled").exists()


def test_structured_exit_one_list_and_doctor_are_results(tmp_path: Path) -> None:
    list_payload = {
        "schema_version": 1,
        "status": "error",
        "enabled": False,
        "jobs": [],
        "errors": [{"code": "invalid_job", "job": "bad.toml"}],
    }
    connector = _fake(
        tmp_path / "list",
        _script_payload("list", list_payload, exit_code=1),
    )
    result = connector.list_jobs()
    assert result.status == "error"
    assert result.errors[0].code == "invalid_job"
    connector.close()


def test_valid_job_policy_and_iso_state_are_parsed(tmp_path: Path) -> None:
    connector = _fake(tmp_path / "valid-job", _script_payload("list", _list_with_job()))
    job = connector.list_jobs().jobs[0]
    assert job.policy.retry_delay_seconds == 300
    assert job.policy.quota_wait_seconds == 3600
    assert job.state.last_run == "2026-08-20T10:00:00+00:00"
    connector.close()


@pytest.mark.parametrize(
    ("section", "field", "value"),
    [
        ("policy", "retry_delay_seconds", 0),
        ("policy", "quota_wait_seconds", 0),
        ("state", "last_run", "not-an-iso-timestamp"),
        ("state", "next_run_iso", "also-not-iso"),
    ],
)
def test_impossible_job_policy_and_state_are_rejected(
    tmp_path: Path, section: str, field: str, value: object
) -> None:
    payload = _list_with_job()
    job = payload["jobs"][0]
    job[section][field] = value
    connector = _fake(
        tmp_path / f"invalid-{section}-{field}",
        _script_payload("list", payload),
    )
    with pytest.raises(SchedulerConnectorError):
        connector.list_jobs()
    connector.close()

    doctor_payload = {
        "schema_version": 1,
        "status": "error",
        "enabled": False,
        "problems": [{"code": "missing_jobs_dir"}],
    }
    connector = _fake(
        tmp_path / "doctor",
        _script_payload("doctor", doctor_payload, exit_code=1),
    )
    result = connector.doctor()
    assert result.status == "error"
    assert result.problems[0].code == "missing_jobs_dir"
    connector.close()


@pytest.mark.parametrize(
    ("raw", "code"),
    [
        ('{"schema_version":1,"schema_version":1}\n', "duplicate-json-key"),
        (
            '{"enabled":false,"errors":[],"jobs":[],"schema_version":true,"status":"ok"}\n',
            "invalid-scheduler-list-schema",
        ),
        (
            '{"enabled":false,"errors":[],"jobs":[],"schema_version":1,"status":"new"}\n',
            "invalid-scheduler-list-status",
        ),
        (
            '{ "enabled":false,"errors":[],"jobs":[],"schema_version":1,"status":"ok"}\n',
            "noncanonical-scheduler-list",
        ),
    ],
)
def test_scheduler_list_rejects_strict_json_boundaries(
    tmp_path: Path, raw: str, code: str
) -> None:
    capabilities = json.dumps(_capabilities(), sort_keys=True, separators=(",", ":"))
    script = f"""import sys
if 'capabilities' in sys.argv:
 print({capabilities!r})
else:
 sys.stdout.write({raw!r})
"""
    connector = _fake(tmp_path, script)
    with pytest.raises(SchedulerConnectorError) as caught:
        connector.list_jobs()
    assert caught.value.code == code
    connector.close()


def test_one_deadline_spans_handshake_and_operation(tmp_path: Path) -> None:
    capabilities = json.dumps(_capabilities(), sort_keys=True, separators=(",", ":"))
    payload = json.dumps(
        {
            "schema_version": 1,
            "status": "ok",
            "enabled": False,
            "jobs": [],
            "errors": [],
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    script = f"""import sys,time
time.sleep(0.17)
print({capabilities!r} if 'capabilities' in sys.argv else {payload!r})
"""
    connector = _fake(tmp_path, script, timeout=0.30)
    with pytest.raises(SchedulerConnectorError) as caught:
        connector.list_jobs()
    assert caught.value.code == "scheduler-list-timeout"
    connector.close()


def test_timeout_kills_descendant_after_direct_child_exits(tmp_path: Path) -> None:
    marker = tmp_path / "orphan-marker"
    capabilities = json.dumps(_capabilities(), sort_keys=True, separators=(",", ":"))
    child = (
        "import pathlib,time; time.sleep(0.4); "
        f"pathlib.Path({str(marker)!r}).write_text('orphan', encoding='utf-8')"
    )
    script = f"""import subprocess,sys
if 'capabilities' in sys.argv:
 print({capabilities!r})
else:
 subprocess.Popen([sys.executable, '-c', {child!r}], stdout=sys.stdout, stderr=sys.stderr)
"""
    connector = _fake(tmp_path / "descendant", script, timeout=0.1)
    with pytest.raises(SchedulerConnectorError, match="scheduler-list-timeout"):
        connector.list_jobs()
    time.sleep(0.5)
    assert not marker.exists()
    connector.close()


@pytest.mark.parametrize("operation", ["list", "doctor"])
@pytest.mark.parametrize("code", ["filesystem_error", "invalid_state"])
def test_problem_schema_rejects_job_for_global_errors(
    tmp_path: Path, operation: str, code: str
) -> None:
    payload = (
        {
            "schema_version": 1,
            "status": "error",
            "enabled": False,
            "jobs": [],
            "errors": [{"code": code, "job": "foreign"}],
        }
        if operation == "list"
        else {
            "schema_version": 1,
            "status": "error",
            "enabled": False,
            "problems": [{"code": code, "job": "foreign"}],
        }
    )
    connector = _fake(
        tmp_path / f"{operation}-{code}",
        _script_payload(operation, payload, exit_code=1),
    )
    with pytest.raises(SchedulerConnectorError, match="shape"):
        getattr(connector, "list_jobs" if operation == "list" else "doctor")()
    connector.close()


def test_doctor_stale_state_requires_plain_job_name(tmp_path: Path) -> None:
    for index, problem in enumerate(
        ({"code": "stale_state"}, {"code": "stale_state", "job": "old.toml"})
    ):
        payload = {
            "schema_version": 1,
            "status": "error",
            "enabled": False,
            "problems": [problem],
        }
        connector = _fake(
            tmp_path / f"stale-{index}",
            _script_payload("doctor", payload, exit_code=1),
        )
        with pytest.raises(SchedulerConnectorError):
            connector.doctor()
        connector.close()


def test_optional_invalid_job_field_cannot_be_null(tmp_path: Path) -> None:
    payload = {
        "schema_version": 1,
        "status": "error",
        "enabled": False,
        "jobs": [],
        "errors": [{"code": "invalid_job", "job": None}],
    }
    connector = _fake(
        tmp_path / "null-job", _script_payload("list", payload, exit_code=1)
    )
    with pytest.raises(SchedulerConnectorError):
        connector.list_jobs()
    connector.close()


def test_jobs_identity_change_during_handshake_stops_before_operation(
    tmp_path: Path,
) -> None:
    root = tmp_path / "case"
    root.mkdir()
    home = _home(root)
    capabilities = json.dumps(_capabilities(), sort_keys=True, separators=(",", ":"))
    log = root / "argv.jsonl"
    script = root / "fake_scheduler.py"
    script.write_text(
        f"""import json,os,pathlib,sys
p=pathlib.Path({str(log)!r})
with p.open('a', encoding='utf-8') as h: h.write(json.dumps(sys.argv[1:])+'\\n')
if 'capabilities' in sys.argv:
 jobs=pathlib.Path({str(home / "jobs")!r})
 jobs.rename(jobs.with_name('jobs-old'))
 jobs.mkdir()
 print({capabilities!r})
else:
 raise SystemExit(8)
""",
        "utf-8",
    )
    connector = SchedulerConnector(
        command=(sys.executable, str(script)),
        cwd=root,
        env={"PATH": os.environ.get("PATH", "")},
        home=home,
        timeout=1,
    )
    with pytest.raises(SchedulerConnectorError, match="scheduler-path-changed"):
        connector.list_jobs()
    assert [json.loads(line) for line in log.read_text("utf-8").splitlines()] == [
        ["capabilities", "--json"]
    ]
    connector.close()


def _recipe() -> SchedulerRecipe:
    return SchedulerRecipe(
        recipe_id="ambient",
        recipe_version=1,
        flow_id="ambient",
        argv=("lifeos", "flow", "ambient", "--vault", "default"),
        vault_profile="default",
        every="15m",
        at=None,
        timeout_seconds=300,
        retries=3,
        retry_delay="5m",
        quota_wait="1h",
        environment_allowlist=("LIFE_OS_RUNTIME_DATA", "PATH"),
    )


def test_recipe_render_is_deterministic_disabled_and_env_bounded() -> None:
    raw = render_recipe(_recipe())
    assert raw == render_recipe(_recipe())
    parsed = tomllib.loads(raw.decode("utf-8"))
    assert parsed["enabled"] is False
    assert parsed["every"] == "15m"
    assert parsed["retries"] == 3
    assert parsed["command"].startswith(
        'env -i LIFE_OS_RUNTIME_DATA="${LIFE_OS_RUNTIME_DATA-}" PATH="${PATH-}" '
    )
    assert "lifeos flow ambient --vault default" in parsed["command"]
    assert "HOME=" not in parsed["command"]


def test_unresolved_canonical_recipes_cannot_render_or_install() -> None:
    recipes = canonical_recipe_descriptors()
    assert [item.recipe_id for item in recipes] == ["ambient", "bundle"]
    assert {item.integration_status for item in recipes} == {"integration_required"}
    assert {(item.every, item.at) for item in recipes} == {(None, None)}
    assert recipe_set_sha256(recipes) == recipe_set_sha256(recipes)
    for recipe in recipes:
        with pytest.raises(
            SchedulerConnectorError, match="scheduler-recipe-integration-required"
        ):
            render_recipe(recipe)


def test_recipe_rejects_private_argv_and_contract_drift() -> None:
    with pytest.raises(SchedulerConnectorError, match="private"):
        render_recipe(replace(_recipe(), argv=("/" + "Users/private/bin/lifeos",)))
    with pytest.raises(SchedulerConnectorError, match="exits"):
        render_recipe(replace(_recipe(), expected_exits=((0, "success"),)))
    with pytest.raises(SchedulerConnectorError, match="schema"):
        render_recipe(replace(_recipe(), schema_version=True))


def test_connector_does_not_import_scheduler_package() -> None:
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys; import tool_life_os_runtime.ext.connectors.scheduler; "
            "assert 'tool_scheduler' not in sys.modules",
        ],
        cwd=Path(__file__).resolve().parents[1],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
