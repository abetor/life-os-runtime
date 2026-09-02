"""Versioned Life OS recipe model for the external periodic scheduler."""

from __future__ import annotations

from dataclasses import dataclass
import json
import re
import shlex
from typing import Sequence
import unicodedata

from .connector import SchedulerConnectorError


SCHEDULER_RECIPE_SCHEMA_VERSION = 1

_ID = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
_ENV = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_AT = re.compile(r"^(?:[01]\d|2[0-3]):[0-5]\d$")
_DURATION = re.compile(r"^([1-9][0-9]{0,9})([smhd])$")
_PRIVATE = re.compile(r"(?i)(?:/users/|/home/|[a-z]:\\users\\|[a-z]:\\home\\|file:)")
_EXPECTED_EXITS = (
    (0, "success"),
    (1, "failure"),
    (75, "quota"),
    (111, "transient"),
)


@dataclass(frozen=True)
class SchedulerRecipe:
    recipe_id: str
    recipe_version: int
    flow_id: str
    argv: tuple[str, ...]
    vault_profile: str
    every: str | None
    at: str | None
    timeout_seconds: int
    retries: int
    retry_delay: str
    quota_wait: str
    environment_allowlist: tuple[str, ...]
    expected_exits: tuple[tuple[int, str], ...] = _EXPECTED_EXITS
    integration_status: str = "available"
    schema_version: int = SCHEDULER_RECIPE_SCHEMA_VERSION


def _fail(code: str) -> None:
    raise SchedulerConnectorError(code)


def _text(value: object, label: str, maximum: int = 4096) -> str:
    if not isinstance(value, str) or not value:
        _fail(f"invalid-{label}")
    try:
        encoded = value.encode("utf-8")
    except UnicodeError:
        _fail(f"invalid-{label}")
    if (
        len(encoded) > maximum
        or value != unicodedata.normalize("NFC", value)
        or any(
            unicodedata.category(character).startswith("C")
            or unicodedata.category(character) in {"Zl", "Zp"}
            for character in value
        )
    ):
        _fail(f"invalid-{label}")
    return value


def _duration(value: object, label: str) -> str:
    checked = _text(value, label, 16)
    match = _DURATION.fullmatch(checked)
    if match is None:
        _fail(f"invalid-{label}")
    seconds = (
        int(match.group(1)) * {"s": 1, "m": 60, "h": 3600, "d": 86400}[match.group(2)]
    )
    if seconds > 2**31 - 1:
        _fail(f"invalid-{label}")
    return checked


def validate_recipe(value: SchedulerRecipe) -> SchedulerRecipe:
    if (
        not isinstance(value, SchedulerRecipe)
        or type(value.schema_version) is not int
        or value.schema_version != 1
        or type(value.recipe_version) is not int
        or not 1 <= value.recipe_version <= 2**31 - 1
    ):
        _fail("invalid-scheduler-recipe-schema")
    recipe_id = _text(value.recipe_id, "recipe-id", 64)
    flow_id = _text(value.flow_id, "recipe-flow", 64)
    profile = _text(value.vault_profile, "recipe-profile", 64)
    if any(_ID.fullmatch(item) is None for item in (recipe_id, flow_id, profile)):
        _fail("invalid-scheduler-recipe-id")
    if value.integration_status not in {"available", "integration_required"}:
        _fail("invalid-scheduler-recipe-status")
    if not isinstance(value.argv, tuple) or len(value.argv) > 64:
        _fail("invalid-scheduler-recipe-argv")
    if value.integration_status == "available" and not value.argv:
        _fail("available-scheduler-recipe-has-no-argv")
    for argument in value.argv:
        checked = _text(argument, "recipe-argument")
        if _PRIVATE.search(checked):
            _fail("private-scheduler-recipe-argument")
    if value.every is not None and value.at is not None:
        _fail("scheduler-recipe-needs-one-cadence")
    if (
        value.integration_status == "available"
        and value.every is None
        and value.at is None
    ):
        _fail("scheduler-recipe-needs-one-cadence")
    if value.every is not None:
        _duration(value.every, "recipe-every")
    if value.at is not None:
        checked_at = _text(value.at, "recipe-at", 5)
        if _AT.fullmatch(checked_at) is None:
            _fail("invalid-recipe-at")
    if (
        type(value.timeout_seconds) is not int
        or not 0 <= value.timeout_seconds <= 30 * 24 * 60 * 60
        or type(value.retries) is not int
        or not 0 <= value.retries <= 1000
    ):
        _fail("invalid-scheduler-recipe-policy")
    _duration(value.retry_delay, "recipe-retry-delay")
    _duration(value.quota_wait, "recipe-quota-wait")
    if (
        not isinstance(value.environment_allowlist, tuple)
        or len(value.environment_allowlist) > 64
        or tuple(sorted(value.environment_allowlist)) != value.environment_allowlist
        or len(set(value.environment_allowlist)) != len(value.environment_allowlist)
        or any(_ENV.fullmatch(item) is None for item in value.environment_allowlist)
    ):
        _fail("invalid-scheduler-recipe-environment")
    if value.expected_exits != _EXPECTED_EXITS:
        _fail("invalid-scheduler-recipe-exits")
    return value


def _command(value: SchedulerRecipe) -> str:
    assignments = " ".join(
        f'{name}="${{{name}-}}"' for name in value.environment_allowlist
    )
    prefix = "env -i" + (f" {assignments}" if assignments else "")
    return f"{prefix} {shlex.join(value.argv)}"


def render_recipe(value: SchedulerRecipe) -> bytes:
    """Render one accepted recipe as deterministic scheduler TOML.

    A descriptor with unresolved runtime integration is intentionally not
    renderable and therefore cannot become an inert-looking production job.
    """

    checked = validate_recipe(value)
    if checked.integration_status != "available":
        _fail("scheduler-recipe-integration-required")
    lines = [
        f"command = {json.dumps(_command(checked), ensure_ascii=False)}",
    ]
    if checked.every is not None:
        lines.append(f"every = {json.dumps(checked.every)}")
    else:
        lines.append(f"at = {json.dumps(checked.at)}")
    lines.extend(
        (
            "enabled = false",
            f"retries = {checked.retries}",
            f"retry_delay = {json.dumps(checked.retry_delay)}",
            f"quota_wait = {json.dumps(checked.quota_wait)}",
            f"timeout = {checked.timeout_seconds}",
        )
    )
    raw = ("\n".join(lines) + "\n").encode("utf-8")
    if len(raw) > 64 * 1024:
        _fail("scheduler-recipe-too-large")
    return raw


def canonical_recipe_descriptors() -> tuple[SchedulerRecipe, ...]:
    """Return honest P4 descriptors without inventing a missing flow entry."""

    common = {
        "recipe_version": 1,
        "argv": (),
        "vault_profile": "default",
        "timeout_seconds": 300,
        "retries": 3,
        "retry_delay": "5m",
        "quota_wait": "1h",
        "environment_allowlist": ("LIFE_OS_RUNTIME_DATA", "PATH"),
        "integration_status": "integration_required",
    }
    return (
        SchedulerRecipe("ambient", flow_id="ambient", every=None, at=None, **common),
        SchedulerRecipe("bundle", flow_id="bundle", every=None, at=None, **common),
    )


def recipe_set_sha256(recipes: Sequence[SchedulerRecipe]) -> str:
    """Stable public identity for a validated ordered recipe descriptor set."""

    import hashlib

    checked = tuple(validate_recipe(recipe) for recipe in recipes)
    if tuple(recipe.recipe_id for recipe in checked) != tuple(
        sorted(recipe.recipe_id for recipe in checked)
    ) or len({recipe.recipe_id for recipe in checked}) != len(checked):
        _fail("scheduler-recipe-set-is-not-canonical")
    payload = [
        {
            "schema_version": recipe.schema_version,
            "recipe_id": recipe.recipe_id,
            "recipe_version": recipe.recipe_version,
            "flow_id": recipe.flow_id,
            "argv": list(recipe.argv),
            "vault_profile": recipe.vault_profile,
            "every": recipe.every,
            "at": recipe.at,
            "timeout_seconds": recipe.timeout_seconds,
            "retries": recipe.retries,
            "retry_delay": recipe.retry_delay,
            "quota_wait": recipe.quota_wait,
            "environment_allowlist": list(recipe.environment_allowlist),
            "expected_exits": [
                [code, outcome] for code, outcome in recipe.expected_exits
            ],
            "integration_status": recipe.integration_status,
        }
        for recipe in checked
    ]
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
