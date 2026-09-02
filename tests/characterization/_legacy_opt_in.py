"""Opt-in loader for exact legacy characterization without bytecode writes."""

from __future__ import annotations

import hashlib
import importlib.util
import sys
import tomllib
from contextlib import contextmanager
from pathlib import Path
from types import ModuleType
from typing import Iterator, Mapping, Sequence


def resolve_read_only_legacy(config_path: Path) -> Path:
    config = tomllib.loads(config_path.read_text("utf-8"))
    migration = config["migration"]["legacy_vault"]
    if migration.get("read_only") is not True:
        raise RuntimeError("legacy characterization requires read_only=true")
    root = Path(migration["path"])
    if not root.is_absolute():
        raise RuntimeError("legacy characterization requires an absolute root")
    return root.resolve(strict=True)


def source_hashes(scripts_root: Path, relative_paths: Sequence[str]) -> Mapping[str, str]:
    hashes: dict[str, str] = {}
    root = scripts_root.resolve(strict=True)
    for relative in relative_paths:
        path = (root / relative).resolve(strict=True)
        path.relative_to(root)
        hashes[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    return hashes


def bytecode_snapshot(scripts_root: Path) -> tuple[tuple[str, int, int], ...]:
    root = scripts_root.resolve(strict=True)
    snapshot = []
    for path in sorted(root.rglob("*.pyc")):
        resolved = path.resolve(strict=True)
        resolved.relative_to(root)
        stat = resolved.stat()
        snapshot.append((resolved.relative_to(root).as_posix(), stat.st_size, stat.st_mtime_ns))
    return tuple(snapshot)


def _inside(path: str | None, root: Path) -> bool:
    if not path:
        return False
    try:
        Path(path).resolve(strict=False).relative_to(root)
    except (OSError, ValueError):
        return False
    return True


@contextmanager
def loaded_legacy_module(
    scripts_root: Path, relative_path: str, module_name: str
) -> Iterator[ModuleType]:
    """Load an exact opted-in module while containing imports and cache writes."""
    root = scripts_root.resolve(strict=True)
    source = (root / relative_path).resolve(strict=True)
    source.relative_to(root)
    if source.suffix != ".py":
        raise RuntimeError("legacy characterization accepts Python source only")
    spec = importlib.util.spec_from_file_location(module_name, source)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load opted-in legacy source")

    module = importlib.util.module_from_spec(spec)
    modules_before = dict(sys.modules)
    path_before = list(sys.path)
    bytecode_before = sys.dont_write_bytecode
    sys.modules[module_name] = module
    sys.path.insert(0, str(root))
    sys.dont_write_bytecode = True
    try:
        spec.loader.exec_module(module)
        yield module
    finally:
        sys.dont_write_bytecode = bytecode_before
        sys.path[:] = path_before
        for name, loaded in list(sys.modules.items()):
            loaded_path = getattr(loaded, "__file__", None)
            if name == module_name or _inside(loaded_path, root):
                previous = modules_before.get(name)
                if previous is None:
                    sys.modules.pop(name, None)
                else:
                    sys.modules[name] = previous
