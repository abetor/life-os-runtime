"""Isolate tests from user storage and credentials: HOME/cwd -> tmp, clean env.

A test that accidentally reads the real $HOME for configuration or state, or
writes into cwd, silently damages the user's machine. Prevent that by design,
not convention. Autouse fixtures make every test hermetic by construction.
"""
import re
import sys
from pathlib import Path

import pytest

# Import the package without installation so tests run from any location.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# Remove credential variables declared in .env.sample, including commented
# examples. Otherwise a real token from the process environment can leak into a
# supposedly hermetic test, call a live API locally, and fail only on a clean
# machine. Conservatively remove only names declared in .env.sample instead of
# guessing across os.environ, because removing an unrelated PATH-like variable
# can be more dangerous than a missed heuristic.
_ENV_VAR_RE = re.compile(r"([A-Z][A-Z0-9_]*)=")


def _env_sample_vars(sample: Path | None = None) -> list[str]:
    """Return variable names from .env.sample lines shaped like [# ]NAME= # why."""
    if sample is None:
        sample = Path(__file__).resolve().parents[1] / ".env.sample"
    if not sample.is_file():
        return []
    names = []
    for line in sample.read_text("utf-8").splitlines():
        m = _ENV_VAR_RE.match(line.lstrip("# ").strip())
        if m:
            names.append(m.group(1))
    return names


@pytest.fixture(autouse=True)
def isolate(tmp_path, monkeypatch):
    # The underscore is deliberate: tmp_path/"home" collided with tests that
    # created their own "home" directory and caused FileExistsError.
    home = tmp_path / "_isolated_home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.chdir(tmp_path)
    for name in _env_sample_vars():
        monkeypatch.delenv(name, raising=False)
