"""Fail-closed TOML loading: an unknown field is an error, not an omission.

Vendored from the tool template and derived from a generic job-configuration
loader. A silently swallowed field-name typo produces a configuration that
appears applied but has no effect, so unknown fields fail the load.
"""
from __future__ import annotations

import tomllib
from pathlib import Path


def load_toml(path: str | Path, *, known: set[str],
              required: frozenset[str] | set[str] = frozenset()) -> dict:
    """Load TOML, validate its fields, and return the untyped dictionary.

    Raise ValueError for unknown or missing required fields. Invalid TOML also
    arrives as ValueError because TOMLDecodeError is a subclass. The caller
    supplies defaults and type validation; this layer only enforces the agreed
    field set.
    """
    path = Path(path)
    raw = tomllib.loads(path.read_text("utf-8"))
    unknown = set(raw) - set(known)
    if unknown:
        raise ValueError(f"{path.name}: unknown fields {sorted(unknown)}")
    missing = set(required) - set(raw)
    if missing:
        raise ValueError(f"{path.name}: missing required fields {sorted(missing)}")
    return raw
