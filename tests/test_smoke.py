"""CLI smoke: doctor is non-mutating and an invalid flag exits with code 1.

Live harness runs belong under smoke/ and use exit 77 for an unavailable
environment; they are intentionally outside this hermetic suite.
"""
import os
import tomllib
from pathlib import Path

import pytest
from conftest import _env_sample_vars

from tool_life_os_runtime.cli import DATA_ENV, EXIT_FAIL, main, resolve_home


def test_doctor_requires_runtime_config_without_mutating_home(tmp_path, capsys):
    home = tmp_path / "data"
    home.mkdir()
    before = list(home.iterdir())

    assert main(["--home", str(home), "doctor"]) == EXIT_FAIL

    assert "runtime_home.config: failure" in capsys.readouterr().out
    assert list(home.iterdir()) == before


def test_doctor_uses_tools_data_default_and_env_override(tmp_path, monkeypatch):
    """Resolve CLI, then tool env, then the user data root; never default to cwd."""
    assert DATA_ENV == "LIFE_OS_RUNTIME_DATA"
    monkeypatch.delenv(DATA_ENV, raising=False)
    default_home = Path.home() / "tools-data" / "life-os-runtime-data"
    assert resolve_home() == default_home

    env_home = tmp_path / "from-env"
    monkeypatch.setenv(DATA_ENV, str(env_home))
    assert resolve_home() == env_home

    cli_home = tmp_path / "from-cli"
    assert resolve_home(str(cli_home)) == cli_home


def test_doctor_missing_home_fails_and_does_not_create(tmp_path, capsys):
    home = tmp_path / "no-such-home"
    assert main(["--home", str(home), "doctor"]) == EXIT_FAIL
    assert not home.exists()  # Doctor diagnoses state and must not mutate it.


def test_usage_error_exits_1(capsys):
    """The exit contract maps an invalid flag to 1 instead of argparse's 2."""
    with pytest.raises(SystemExit) as e:
        main(["doctor", "--no-such-flag"])
    assert e.value.code == EXIT_FAIL
    assert "error" in capsys.readouterr().err


def test_env_sample_creds_scrubbed(tmp_path):
    """The conftest isolator removes .env.sample variables from hermetic tests."""
    # Parse [# ]NAME= # purpose without matching prose in the header.
    sample = tmp_path / ".env.sample"
    sample.write_text("# prose header: NAME=\n# FOO_TOKEN=   # secret\nBAR_KEY=x\n", "utf-8")
    assert _env_sample_vars(sample) == ["FOO_TOKEN", "BAR_KEY"]
    # Observable effect: no variable declared by the repository sample reaches a test.
    leaked = [n for n in _env_sample_vars() if n in os.environ]
    assert not leaked, f"credentials from .env.sample are visible to the test: {leaked}"


def test_bootstrap_config_example_is_parseable_and_legacy_is_read_only():
    sample = Path(__file__).resolve().parents[1] / "deploy" / "config.example.toml"
    data = tomllib.loads(sample.read_text("utf-8"))

    assert data["schema_version"] == 1
    assert data["default_vault"] in data["vaults"]
    assert data["machine_knowledge"]["topics_root"].startswith("/absolute/path/")
    assert data["migration"]["legacy_vault"]["read_only"] is True
    assert data["migration"]["legacy_machine_knowledge"]["read_only"] is True
