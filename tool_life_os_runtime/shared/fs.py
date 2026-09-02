"""File primitives: atomic writes and a self-ignoring state directory.

Vendored from the tool template, originally derived from a generic repository
state convention. This repository owns its copy.
"""
from __future__ import annotations

import os
from pathlib import Path

# Self-ignore: Git treats the directory as ignored in any repository, regardless
# of the root .gitignore, so state cannot enter `git add .` in another project.
GITIGNORE_BODY = "# Tool state directory - not part of the repository\n*\n"


def atomic_write(path: str | Path, data: str | bytes, encoding: str = "utf-8") -> None:
    """Write without partial states: adjacent temporary file plus ``os.replace``.

    Replacement is atomic within one filesystem. Readers never observe a
    partially written file; a crashed process can leave only a temporary file,
    not a corrupted original.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    if isinstance(data, str):
        tmp.write_text(data, encoding=encoding)
    else:
        tmp.write_bytes(data)
    os.replace(tmp, path)


def ensure_state_dir(path: str | Path) -> Path:
    """Create a state directory with a self-ignoring .gitignore and return it.

    This operation is idempotent: an existing .gitignore is never overwritten
    because its owner may have customized it. Exclusive creation also avoids
    clobbering the file when concurrent processes race.
    """
    d = Path(path)
    d.mkdir(parents=True, exist_ok=True)
    gi = d / ".gitignore"
    if not gi.exists():
        try:
            with open(gi, "x", encoding="utf-8") as f:
                f.write(GITIGNORE_BODY)
        except FileExistsError:
            pass  # Another process created it between exists() and open().
    return d
