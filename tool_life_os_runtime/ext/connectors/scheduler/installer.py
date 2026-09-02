"""Crash-recoverable ownership boundary for generated scheduler recipes."""

from __future__ import annotations

import ctypes
from dataclasses import dataclass, field
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Mapping, Sequence

from .connector import SchedulerConnectorError
from .recipes import SchedulerRecipe, recipe_set_sha256, render_recipe, validate_recipe


SCHEDULER_INSTALL_SCHEMA_VERSION = 1

_MANIFEST = ".lifeos-runtime-recipes-v1.json"
_MAX_RECIPES = 128
_MAX_MANIFEST = 512 * 1024
_SHA = re.compile(r"^[0-9a-f]{64}$")
_FILE = re.compile(r"^lifeos-[a-z0-9][a-z0-9_-]{0,63}\.toml$")


@dataclass(frozen=True)
class SchedulerRecipeAction:
    kind: str
    recipe_id: str
    filename: str
    before_sha256: str | None
    after_sha256: str | None


@dataclass(frozen=True)
class SchedulerRecipePlan:
    schema_version: int
    plan_id: str
    recipe_set_sha256: str
    home_identity: tuple[int, int]
    jobs_identity: tuple[int, int]
    manifest_sha256: str | None
    target_manifest_sha256: str
    actions: tuple[SchedulerRecipeAction, ...]
    deferred_ids: tuple[str, ...]
    conflicts: tuple[str, ...]
    _home: Path = field(repr=False, compare=False)
    _recipes: tuple[SchedulerRecipe, ...] = field(repr=False, compare=False)
    _rendered: tuple[tuple[str, bytes], ...] = field(repr=False, compare=False)
    _source_manifest: bytes | None = field(repr=False, compare=False)
    _target_manifest: bytes = field(repr=False, compare=False)


@dataclass(frozen=True)
class SchedulerInstallResult:
    schema_version: int
    status: str
    plan_id: str
    changed: bool
    installed: tuple[str, ...]
    updated: tuple[str, ...]
    retired: tuple[str, ...]
    deferred: tuple[str, ...]


@dataclass(frozen=True)
class SchedulerCheck:
    schema_version: int
    ok: bool
    plan_id: str
    drift: tuple[SchedulerRecipeAction, ...]
    deferred: tuple[str, ...]
    conflicts: tuple[str, ...]


def _fail(code: str) -> None:
    raise SchedulerConnectorError(code)


def _canonical(value: object) -> bytes:
    try:
        return (
            json.dumps(
                value,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
            + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError):
        _fail("scheduler-install-json-invalid")


def _pairs(items: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in items:
        if key in result:
            _fail("scheduler-manifest-duplicate-field")
        result[key] = value
    return result


def _identity(metadata: os.stat_result) -> tuple[int, int]:
    if not stat.S_ISDIR(metadata.st_mode):
        _fail("scheduler-install-root-is-not-directory")
    return metadata.st_dev, metadata.st_ino


def _file_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    if not stat.S_ISREG(metadata.st_mode):
        _fail("scheduler-owned-path-is-not-file")
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _open_root(path: Path) -> tuple[int, tuple[int, int]]:
    if not isinstance(path, Path) or not path.is_absolute():
        _fail("scheduler-home-is-invalid")
    try:
        fd = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
        opened = _identity(os.fstat(fd))
        named = _identity(os.stat(path, follow_symlinks=False))
        if opened != named:
            raise OSError("root moved")
        return fd, opened
    except SchedulerConnectorError:
        raise
    except OSError:
        _fail("scheduler-home-cannot-be-pinned")


def _open_dir_at(parent_fd: int, name: str) -> tuple[int, tuple[int, int]]:
    try:
        fd = os.open(
            name,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            dir_fd=parent_fd,
        )
        opened = _identity(os.fstat(fd))
        named = _identity(os.stat(name, dir_fd=parent_fd, follow_symlinks=False))
        if opened != named:
            raise OSError("directory moved")
        return fd, opened
    except SchedulerConnectorError:
        raise
    except OSError:
        _fail("scheduler-directory-cannot-be-pinned")


def _revalidate_root(path: Path, fd: int, expected: tuple[int, int]) -> None:
    try:
        if (
            _identity(os.fstat(fd)) != expected
            or _identity(os.stat(path, follow_symlinks=False)) != expected
        ):
            _fail("scheduler-home-changed")
    except SchedulerConnectorError:
        raise
    except OSError:
        _fail("scheduler-home-changed")


def _revalidate_child(
    parent_fd: int, name: str, fd: int, expected: tuple[int, int]
) -> None:
    try:
        if (
            _identity(os.fstat(fd)) != expected
            or _identity(os.stat(name, dir_fd=parent_fd, follow_symlinks=False))
            != expected
        ):
            _fail("scheduler-directory-changed")
    except SchedulerConnectorError:
        raise
    except OSError:
        _fail("scheduler-directory-changed")


def _read_at(
    directory_fd: int, name: str, maximum: int
) -> tuple[bytes, tuple[int, int, int, int, int]]:
    file_fd = -1
    try:
        file_fd = os.open(
            name,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
            dir_fd=directory_fd,
        )
        before = _file_identity(os.fstat(file_fd))
        if before[2] > maximum:
            _fail("scheduler-owned-file-is-too-large")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            block = os.read(file_fd, min(64 * 1024, remaining))
            if not block:
                break
            chunks.append(block)
            remaining -= len(block)
        raw = b"".join(chunks)
        after = _file_identity(os.fstat(file_fd))
        named = _file_identity(
            os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        )
        if (
            before != after
            or before != named
            or len(raw) != before[2]
            or len(raw) > maximum
        ):
            _fail("scheduler-owned-file-changed")
        return raw, before
    except SchedulerConnectorError:
        raise
    except FileNotFoundError:
        _fail("scheduler-owned-file-is-missing")
    except OSError:
        _fail("scheduler-owned-file-cannot-be-read")
    finally:
        if file_fd >= 0:
            os.close(file_fd)


def _read_optional(directory_fd: int, name: str, maximum: int) -> bytes | None:
    try:
        os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    except OSError:
        _fail("scheduler-owned-file-cannot-be-inspected")
    return _read_at(directory_fd, name, maximum)[0]


def _manifest_payload(files: Mapping[str, tuple[str, str]]) -> dict[str, object]:
    rows = [
        {"recipe_id": recipe_id, "filename": filename, "sha256": sha256}
        for recipe_id, (filename, sha256) in sorted(files.items())
    ]
    return {"schema_version": 1, "files": rows}


def _parse_manifest(raw: bytes) -> dict[str, tuple[str, str]]:
    if not raw or len(raw) > _MAX_MANIFEST:
        _fail("scheduler-manifest-is-invalid")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
    except SchedulerConnectorError:
        raise
    except (UnicodeError, ValueError, RecursionError):
        _fail("scheduler-manifest-is-invalid")
    if (
        not isinstance(value, Mapping)
        or set(value) != {"schema_version", "files"}
        or type(value["schema_version"]) is not int
        or value["schema_version"] != 1
        or not isinstance(value["files"], list)
        or len(value["files"]) > _MAX_RECIPES
        or raw != _canonical(value)
    ):
        _fail("scheduler-manifest-is-invalid")
    result: dict[str, tuple[str, str]] = {}
    filenames: set[str] = set()
    for row in value["files"]:
        if not isinstance(row, Mapping) or set(row) != {
            "recipe_id",
            "filename",
            "sha256",
        }:
            _fail("scheduler-manifest-row-is-invalid")
        recipe_id, filename, digest = row["recipe_id"], row["filename"], row["sha256"]
        if (
            not isinstance(recipe_id, str)
            or not isinstance(filename, str)
            or not isinstance(digest, str)
            or _FILE.fullmatch(filename) is None
            or filename != f"lifeos-{recipe_id}.toml"
            or _SHA.fullmatch(digest) is None
            or recipe_id in result
            or filename in filenames
        ):
            _fail("scheduler-manifest-row-is-invalid")
        result[recipe_id] = (filename, digest)
        filenames.add(filename)
    if list(result) != sorted(result):
        _fail("scheduler-manifest-is-not-sorted")
    return result


def _owned_manifest(jobs_fd: int) -> tuple[bytes | None, dict[str, tuple[str, str]]]:
    raw = _read_optional(jobs_fd, _MANIFEST, _MAX_MANIFEST)
    return raw, {} if raw is None else _parse_manifest(raw)


def _plan_payload(
    recipe_sha: str,
    home_identity: tuple[int, int],
    jobs_identity: tuple[int, int],
    manifest_sha: str | None,
    target_manifest_sha: str,
    actions: Sequence[SchedulerRecipeAction],
    deferred: Sequence[str],
    conflicts: Sequence[str],
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "recipe_set_sha256": recipe_sha,
        "home_identity": list(home_identity),
        "jobs_identity": list(jobs_identity),
        "manifest_sha256": manifest_sha,
        "target_manifest_sha256": target_manifest_sha,
        "actions": [
            {
                "kind": item.kind,
                "recipe_id": item.recipe_id,
                "filename": item.filename,
                "before_sha256": item.before_sha256,
                "after_sha256": item.after_sha256,
            }
            for item in actions
        ],
        "deferred_ids": list(deferred),
        "conflicts": list(conflicts),
    }


def _actions_between(
    source: Mapping[str, tuple[str, str]],
    target: Mapping[str, tuple[str, str]],
) -> tuple[SchedulerRecipeAction, ...]:
    actions: list[SchedulerRecipeAction] = []
    for recipe_id in sorted(set(source) | set(target)):
        before = source.get(recipe_id)
        after = target.get(recipe_id)
        if before == after:
            continue
        if before is None:
            assert after is not None
            actions.append(
                SchedulerRecipeAction("create", recipe_id, after[0], None, after[1])
            )
        elif after is None:
            actions.append(
                SchedulerRecipeAction("retire", recipe_id, before[0], before[1], None)
            )
        else:
            if before[0] != after[0]:
                _fail("scheduler-manifest-filename-drift")
            actions.append(
                SchedulerRecipeAction(
                    "update", recipe_id, after[0], before[1], after[1]
                )
            )
    return tuple(actions)


def diff_recipes(home: Path, recipes: Sequence[SchedulerRecipe]) -> SchedulerRecipePlan:
    if (
        not isinstance(recipes, Sequence)
        or isinstance(recipes, (str, bytes))
        or len(recipes) > _MAX_RECIPES
    ):
        _fail("scheduler-recipe-set-is-invalid")
    checked = tuple(validate_recipe(recipe) for recipe in recipes)
    if tuple(recipe.recipe_id for recipe in checked) != tuple(
        sorted(recipe.recipe_id for recipe in checked)
    ):
        _fail("scheduler-recipe-set-is-not-sorted")
    if len({recipe.recipe_id for recipe in checked}) != len(checked):
        _fail("scheduler-recipe-set-collides")
    recipe_sha = recipe_set_sha256(checked)
    rendered: dict[str, bytes] = {}
    deferred = tuple(
        recipe.recipe_id
        for recipe in checked
        if recipe.integration_status != "available"
    )
    for recipe in checked:
        if recipe.integration_status == "available":
            rendered[f"lifeos-{recipe.recipe_id}.toml"] = render_recipe(recipe)

    home_fd, home_identity = _open_root(home)
    jobs_fd = -1
    try:
        jobs_fd, jobs_identity = _open_dir_at(home_fd, "jobs")
        active = _active_journal(jobs_fd)
        if active is not None:
            return _plan_from_journal(
                active[1],
                home=home,
                home_identity=home_identity,
                jobs_identity=jobs_identity,
                recipes=checked,
                recipe_sha=recipe_sha,
                rendered=rendered,
                deferred=deferred,
            )
        manifest_raw, owned = _owned_manifest(jobs_fd)
        manifest_sha = (
            None if manifest_raw is None else hashlib.sha256(manifest_raw).hexdigest()
        )
        actions: list[SchedulerRecipeAction] = []
        conflicts: list[str] = []
        target_files: dict[str, tuple[str, str]] = {}
        desired_by_id = {
            recipe.recipe_id: f"lifeos-{recipe.recipe_id}.toml"
            for recipe in checked
            if recipe.integration_status == "available"
        }
        for recipe_id in sorted(set(owned) | set(desired_by_id)):
            owned_row = owned.get(recipe_id)
            desired_name = desired_by_id.get(recipe_id)
            filename = desired_name or (owned_row[0] if owned_row is not None else "")
            before_sha: str | None = None
            try:
                raw, _signature = _read_at(jobs_fd, filename, 64 * 1024)
                before_sha = hashlib.sha256(raw).hexdigest()
            except SchedulerConnectorError as error:
                if error.code != "scheduler-owned-file-is-missing":
                    raise
            if owned_row is None:
                assert desired_name is not None
                after_sha = hashlib.sha256(rendered[desired_name]).hexdigest()
                if before_sha is not None:
                    conflicts.append(recipe_id)
                else:
                    actions.append(
                        SchedulerRecipeAction(
                            "create", recipe_id, desired_name, None, after_sha
                        )
                    )
                target_files[recipe_id] = (desired_name, after_sha)
                continue
            owned_name, owned_sha = owned_row
            if filename != owned_name or before_sha != owned_sha:
                conflicts.append(recipe_id)
                if desired_name is not None:
                    target_files[recipe_id] = (
                        desired_name,
                        hashlib.sha256(rendered[desired_name]).hexdigest(),
                    )
                continue
            if desired_name is None:
                actions.append(
                    SchedulerRecipeAction(
                        "retire", recipe_id, owned_name, owned_sha, None
                    )
                )
                continue
            after_sha = hashlib.sha256(rendered[desired_name]).hexdigest()
            target_files[recipe_id] = (desired_name, after_sha)
            if after_sha != owned_sha:
                actions.append(
                    SchedulerRecipeAction(
                        "update", recipe_id, desired_name, owned_sha, after_sha
                    )
                )
        target_manifest = _canonical(_manifest_payload(target_files))
        target_manifest_sha = hashlib.sha256(target_manifest).hexdigest()
        actions_tuple = tuple(actions)
        conflicts_tuple = tuple(sorted(conflicts))
        payload = _plan_payload(
            recipe_sha,
            home_identity,
            jobs_identity,
            manifest_sha,
            target_manifest_sha,
            actions_tuple,
            deferred,
            conflicts_tuple,
        )
        plan_id = (
            "scheduler-plan-" + hashlib.sha256(_canonical(payload)).hexdigest()[:32]
        )
        _revalidate_child(home_fd, "jobs", jobs_fd, jobs_identity)
        _revalidate_root(home, home_fd, home_identity)
        return SchedulerRecipePlan(
            1,
            plan_id,
            recipe_sha,
            home_identity,
            jobs_identity,
            manifest_sha,
            target_manifest_sha,
            actions_tuple,
            deferred,
            conflicts_tuple,
            home,
            checked,
            tuple(sorted(rendered.items())),
            manifest_raw,
            target_manifest,
        )
    finally:
        if jobs_fd >= 0:
            os.close(jobs_fd)
        os.close(home_fd)


def check_recipes(home: Path, recipes: Sequence[SchedulerRecipe]) -> SchedulerCheck:
    plan = diff_recipes(home, recipes)
    return SchedulerCheck(
        1,
        not plan.actions and not plan.conflicts and not plan.deferred_ids,
        plan.plan_id,
        plan.actions,
        plan.deferred_ids,
        plan.conflicts,
    )


def _rename_between(
    source_fd: int,
    source: str,
    target_fd: int,
    target: str,
    *,
    exchange: bool,
) -> None:
    library = ctypes.CDLL(None, use_errno=True)
    if hasattr(library, "renameatx_np"):
        function = library.renameatx_np
        flag = 0x00000002 if exchange else 0x00000004
    elif sys.platform.startswith("linux") and hasattr(library, "renameat2"):
        function = library.renameat2
        flag = 0x00000002 if exchange else 0x00000001
    else:
        _fail("scheduler-identity-bound-rename-unavailable")
    function.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    function.restype = ctypes.c_int
    result = function(
        source_fd, os.fsencode(source), target_fd, os.fsencode(target), flag
    )
    if result != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def _write_stage(directory_fd: int, name: str, raw: bytes) -> None:
    try:
        existing = _read_optional(directory_fd, name, len(raw))
        if existing is not None:
            if existing != raw:
                _fail("scheduler-stage-conflict")
            return
        fd = os.open(
            name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=directory_fd,
        )
        try:
            view = memoryview(raw)
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    raise OSError("short write")
                view = view[written:]
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(directory_fd)
    except SchedulerConnectorError:
        raise
    except OSError:
        _fail("scheduler-stage-write-failed")


def _current_sha(directory_fd: int, name: str) -> str | None:
    try:
        raw, _signature = _read_at(directory_fd, name, 64 * 1024)
    except SchedulerConnectorError as error:
        if error.code == "scheduler-owned-file-is-missing":
            return None
        raise
    return hashlib.sha256(raw).hexdigest()


def _retain_stage(directory_fd: int, name: str, label: str) -> None:
    raw, signature = _read_at(directory_fd, name, _MAX_MANIFEST)
    retained = (
        f".lifeos-retained-{label}-{signature[0]:x}-{signature[1]:x}-"
        f"{hashlib.sha256(raw).hexdigest()[:16]}"
    )
    try:
        _rename_between(directory_fd, name, directory_fd, retained, exchange=False)
    except OSError:
        _fail("scheduler-stage-retire-failed")


def _journal_payload(plan: SchedulerRecipePlan) -> bytes:
    return _canonical(
        {
            "schema_version": 1,
            "plan_id": plan.plan_id,
            "plan": _plan_payload(
                plan.recipe_set_sha256,
                plan.home_identity,
                plan.jobs_identity,
                plan.manifest_sha256,
                plan.target_manifest_sha256,
                plan.actions,
                plan.deferred_ids,
                plan.conflicts,
            ),
            "source_manifest": (
                None
                if plan._source_manifest is None
                else json.loads(plan._source_manifest)
            ),
            "target_manifest": json.loads(plan._target_manifest),
        }
    )


def _parse_action(value: object) -> SchedulerRecipeAction:
    if not isinstance(value, Mapping) or set(value) != {
        "kind",
        "recipe_id",
        "filename",
        "before_sha256",
        "after_sha256",
    }:
        _fail("scheduler-journal-action-is-invalid")
    kind = value["kind"]
    recipe_id = value["recipe_id"]
    filename = value["filename"]
    before = value["before_sha256"]
    after = value["after_sha256"]
    if (
        kind not in {"create", "update", "retire"}
        or not isinstance(recipe_id, str)
        or not isinstance(filename, str)
        or _FILE.fullmatch(filename) is None
        or filename != f"lifeos-{recipe_id}.toml"
        or (
            before is not None
            and (not isinstance(before, str) or _SHA.fullmatch(before) is None)
        )
        or (
            after is not None
            and (not isinstance(after, str) or _SHA.fullmatch(after) is None)
        )
        or (kind == "create" and (before is not None or after is None))
        or (kind == "update" and (before is None or after is None))
        or (kind == "retire" and (before is None or after is not None))
    ):
        _fail("scheduler-journal-action-is-invalid")
    return SchedulerRecipeAction(kind, recipe_id, filename, before, after)


def _active_journal(
    jobs_fd: int,
) -> tuple[bytes, Mapping[str, object]] | None:
    names: list[str] = []
    seen: set[str] = set()
    try:
        with os.scandir(jobs_fd) as entries:
            for index, entry in enumerate(entries):
                if index >= 1023:
                    _fail("scheduler-jobs-namespace-is-too-large")
                name = entry.name
                folded = name.casefold()
                if folded in seen:
                    _fail("scheduler-jobs-namespace-collides")
                seen.add(folded)
                if name.startswith(".lifeos-transaction-") and name.endswith(".json"):
                    names.append(name)
    except SchedulerConnectorError:
        raise
    except OSError:
        _fail("scheduler-jobs-namespace-cannot-be-read")
    names.sort()
    if len(names) > 1:
        _fail("scheduler-has-multiple-active-transactions")
    if not names:
        return None
    raw, _signature = _read_at(jobs_fd, names[0], _MAX_MANIFEST)
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
    except SchedulerConnectorError:
        raise
    except (UnicodeError, ValueError, RecursionError):
        _fail("scheduler-journal-is-invalid")
    if (
        not isinstance(value, Mapping)
        or set(value)
        != {
            "schema_version",
            "plan_id",
            "plan",
            "source_manifest",
            "target_manifest",
        }
        or type(value["schema_version"]) is not int
        or value["schema_version"] != 1
        or not isinstance(value["plan_id"], str)
        or raw != _canonical(value)
    ):
        _fail("scheduler-journal-is-invalid")
    return raw, value


def _plan_from_journal(
    journal: Mapping[str, object],
    *,
    home: Path,
    home_identity: tuple[int, int],
    jobs_identity: tuple[int, int],
    recipes: tuple[SchedulerRecipe, ...],
    recipe_sha: str,
    rendered: Mapping[str, bytes],
    deferred: tuple[str, ...],
) -> SchedulerRecipePlan:
    plan_raw = journal["plan"]
    if not isinstance(plan_raw, Mapping) or set(plan_raw) != {
        "schema_version",
        "recipe_set_sha256",
        "home_identity",
        "jobs_identity",
        "manifest_sha256",
        "target_manifest_sha256",
        "actions",
        "deferred_ids",
        "conflicts",
    }:
        _fail("scheduler-journal-plan-is-invalid")
    home_row = plan_raw["home_identity"]
    jobs_row = plan_raw["jobs_identity"]
    actions_raw = plan_raw["actions"]
    deferred_raw = plan_raw["deferred_ids"]
    conflicts_raw = plan_raw["conflicts"]
    manifest_sha = plan_raw["manifest_sha256"]
    target_sha = plan_raw["target_manifest_sha256"]
    if (
        type(plan_raw["schema_version"]) is not int
        or plan_raw["schema_version"] != 1
        or plan_raw["recipe_set_sha256"] != recipe_sha
        or not isinstance(home_row, list)
        or len(home_row) != 2
        or any(type(item) is not int or item < 0 for item in home_row)
        or tuple(home_row) != home_identity
        or not isinstance(jobs_row, list)
        or len(jobs_row) != 2
        or any(type(item) is not int or item < 0 for item in jobs_row)
        or tuple(jobs_row) != jobs_identity
        or (
            manifest_sha is not None
            and (
                not isinstance(manifest_sha, str)
                or _SHA.fullmatch(manifest_sha) is None
            )
        )
        or not isinstance(target_sha, str)
        or _SHA.fullmatch(target_sha) is None
        or not isinstance(actions_raw, list)
        or len(actions_raw) > _MAX_RECIPES
        or not isinstance(deferred_raw, list)
        or tuple(deferred_raw) != deferred
        or not isinstance(conflicts_raw, list)
        or conflicts_raw
    ):
        _fail("scheduler-journal-plan-is-invalid")
    actions = tuple(_parse_action(item) for item in actions_raw)
    if tuple(action.recipe_id for action in actions) != tuple(
        sorted(action.recipe_id for action in actions)
    ) or len({action.recipe_id for action in actions}) != len(actions):
        _fail("scheduler-journal-actions-are-not-canonical")
    source_value = journal["source_manifest"]
    if source_value is None:
        source_manifest = None
        source_files: dict[str, tuple[str, str]] = {}
        if manifest_sha is not None:
            _fail("scheduler-journal-source-manifest-binding-is-invalid")
    else:
        source_manifest = _canonical(source_value)
        source_files = _parse_manifest(source_manifest)
        if (
            manifest_sha is None
            or hashlib.sha256(source_manifest).hexdigest() != manifest_sha
        ):
            _fail("scheduler-journal-source-manifest-binding-is-invalid")
    target_manifest = _canonical(journal["target_manifest"])
    if hashlib.sha256(target_manifest).hexdigest() != target_sha:
        _fail("scheduler-journal-manifest-binding-is-invalid")
    target_files = _parse_manifest(target_manifest)
    desired = {
        filename.removeprefix("lifeos-").removesuffix(".toml"): (
            filename,
            hashlib.sha256(raw).hexdigest(),
        )
        for filename, raw in rendered.items()
    }
    if desired != target_files:
        _fail("scheduler-journal-recipe-binding-is-invalid")
    if actions != _actions_between(source_files, target_files):
        _fail("scheduler-journal-action-binding-is-invalid")
    plan_payload = _plan_payload(
        recipe_sha,
        home_identity,
        jobs_identity,
        manifest_sha,
        target_sha,
        actions,
        deferred,
        (),
    )
    plan_id = (
        "scheduler-plan-" + hashlib.sha256(_canonical(plan_payload)).hexdigest()[:32]
    )
    if journal["plan_id"] != plan_id:
        _fail("scheduler-journal-plan-binding-is-invalid")
    return SchedulerRecipePlan(
        1,
        plan_id,
        recipe_sha,
        home_identity,
        jobs_identity,
        manifest_sha,
        target_sha,
        actions,
        deferred,
        (),
        home,
        recipes,
        tuple(sorted(rendered.items())),
        source_manifest,
        target_manifest,
    )


def _validate_plan_fields(plan: SchedulerRecipePlan) -> None:
    if (
        type(plan) is not SchedulerRecipePlan
        or type(plan.schema_version) is not int
        or plan.schema_version != 1
        or not isinstance(plan._home, Path)
        or not plan._home.is_absolute()
        or not isinstance(plan._recipes, tuple)
        or len(plan._recipes) > _MAX_RECIPES
        or not isinstance(plan._rendered, tuple)
        or not isinstance(plan._target_manifest, bytes)
        or (
            plan._source_manifest is not None
            and not isinstance(plan._source_manifest, bytes)
        )
        or not plan.plan_id.startswith("scheduler-plan-")
        or _SHA.fullmatch(plan.recipe_set_sha256) is None
        or _SHA.fullmatch(plan.target_manifest_sha256) is None
        or (
            plan.manifest_sha256 is not None
            and _SHA.fullmatch(plan.manifest_sha256) is None
        )
    ):
        _fail("scheduler-install-plan-is-invalid")
    payload = _plan_payload(
        plan.recipe_set_sha256,
        plan.home_identity,
        plan.jobs_identity,
        plan.manifest_sha256,
        plan.target_manifest_sha256,
        plan.actions,
        plan.deferred_ids,
        plan.conflicts,
    )
    expected_id = (
        "scheduler-plan-" + hashlib.sha256(_canonical(payload)).hexdigest()[:32]
    )
    if (
        expected_id != plan.plan_id
        or hashlib.sha256(plan._target_manifest).hexdigest()
        != plan.target_manifest_sha256
    ):
        _fail("scheduler-install-plan-binding-is-invalid")
    expected = diff_recipes(plan._home, plan._recipes)
    if (
        plan.home_identity != expected.home_identity
        or plan.jobs_identity != expected.jobs_identity
    ):
        _fail("scheduler-install-plan-is-stale")
    if (
        plan != expected
        or plan._home != expected._home
        or plan._recipes != expected._recipes
        or plan._rendered != expected._rendered
        or plan._source_manifest != expected._source_manifest
        or plan._target_manifest != expected._target_manifest
    ):
        _fail("scheduler-install-plan-derivation-is-invalid")


def _validate_plan(plan: SchedulerRecipePlan) -> None:
    try:
        _validate_plan_fields(plan)
    except SchedulerConnectorError:
        raise
    except Exception:
        _fail("scheduler-install-plan-is-invalid")


def _validate_target_state(jobs_fd: int, plan: SchedulerRecipePlan) -> None:
    target = _parse_manifest(plan._target_manifest)
    for _recipe_id, (filename, digest) in target.items():
        if _current_sha(jobs_fd, filename) != digest:
            _fail("scheduler-installed-target-changed")
    for action in plan.actions:
        if (
            action.kind == "retire"
            and _current_sha(jobs_fd, action.filename) is not None
        ):
            _fail("scheduler-retired-target-reappeared")


def install_recipes(plan: SchedulerRecipePlan) -> SchedulerInstallResult:
    _validate_plan(plan)
    if plan.conflicts:
        _fail("scheduler-install-has-conflicts")
    if plan.deferred_ids:
        _fail("scheduler-install-has-integration-gaps")
    if not plan.actions and plan.manifest_sha256 == plan.target_manifest_sha256:
        return SchedulerInstallResult(
            1, "unchanged", plan.plan_id, False, (), (), (), ()
        )

    rendered = dict(plan._rendered)
    home_fd, home_identity = _open_root(plan._home)
    jobs_fd = -1
    try:
        jobs_fd, jobs_identity = _open_dir_at(home_fd, "jobs")
        if home_identity != plan.home_identity or jobs_identity != plan.jobs_identity:
            _fail("scheduler-install-plan-is-stale")
        try:
            fcntl.flock(jobs_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            _fail("scheduler-install-is-locked")
        current_manifest = _read_optional(jobs_fd, _MANIFEST, _MAX_MANIFEST)
        current_manifest_sha = (
            None
            if current_manifest is None
            else hashlib.sha256(current_manifest).hexdigest()
        )
        journal_name = f".lifeos-transaction-{plan.plan_id}.json"
        journal_raw = _journal_payload(plan)
        existing_journal = _read_optional(jobs_fd, journal_name, len(journal_raw))
        recovering = existing_journal == journal_raw
        if current_manifest_sha != plan.manifest_sha256 and not (
            recovering and current_manifest_sha == plan.target_manifest_sha256
        ):
            _fail("scheduler-install-manifest-changed")
        if existing_journal is None:
            for action in plan.actions:
                if _current_sha(jobs_fd, action.filename) != action.before_sha256:
                    _fail("scheduler-install-plan-is-stale")
            _write_stage(jobs_fd, journal_name, journal_raw)
        elif existing_journal != journal_raw:
            _fail("scheduler-install-journal-conflict")
        for action in plan.actions:
            stage_name = f".lifeos-stage-{plan.plan_id}-{action.recipe_id}"
            retire_name = f".lifeos-retired-{plan.plan_id}-{action.recipe_id}"
            current = _current_sha(jobs_fd, action.filename)
            retired = _current_sha(jobs_fd, retire_name)
            staged = _current_sha(jobs_fd, stage_name)
            if action.kind == "create":
                if current == action.after_sha256 and staged is None:
                    continue
                if current is not None:
                    _fail("scheduler-create-target-changed")
                raw = rendered.get(action.filename)
                if (
                    raw is None
                    or hashlib.sha256(raw).hexdigest() != action.after_sha256
                ):
                    _fail("scheduler-create-bytes-missing")
                _write_stage(jobs_fd, stage_name, raw)
                try:
                    _rename_between(
                        jobs_fd, stage_name, jobs_fd, action.filename, exchange=False
                    )
                except OSError:
                    _fail("scheduler-create-publish-failed")
            elif action.kind == "update":
                if current == action.after_sha256 and retired == action.before_sha256:
                    continue
                if current == action.after_sha256 and staged == action.before_sha256:
                    try:
                        _rename_between(
                            jobs_fd,
                            stage_name,
                            jobs_fd,
                            retire_name,
                            exchange=False,
                        )
                    except OSError:
                        _fail("scheduler-update-retire-failed")
                    continue
                if current != action.before_sha256:
                    _fail("scheduler-update-target-changed")
                raw = rendered.get(action.filename)
                if (
                    raw is None
                    or hashlib.sha256(raw).hexdigest() != action.after_sha256
                ):
                    _fail("scheduler-update-bytes-missing")
                _write_stage(jobs_fd, stage_name, raw)
                try:
                    _rename_between(
                        jobs_fd, stage_name, jobs_fd, action.filename, exchange=True
                    )
                except OSError:
                    _fail("scheduler-update-publish-failed")
                if _current_sha(jobs_fd, stage_name) != action.before_sha256:
                    try:
                        _rename_between(
                            jobs_fd,
                            stage_name,
                            jobs_fd,
                            action.filename,
                            exchange=True,
                        )
                    except OSError:
                        pass
                    _fail("scheduler-update-target-was-substituted")
                try:
                    _rename_between(
                        jobs_fd, stage_name, jobs_fd, retire_name, exchange=False
                    )
                except OSError:
                    _fail("scheduler-update-retire-failed")
            elif action.kind == "retire":
                if current is None and retired == action.before_sha256:
                    continue
                if current != action.before_sha256:
                    _fail("scheduler-retire-target-changed")
                try:
                    _rename_between(
                        jobs_fd,
                        action.filename,
                        jobs_fd,
                        retire_name,
                        exchange=False,
                    )
                except OSError:
                    _fail("scheduler-retire-failed")
            else:
                _fail("scheduler-install-action-is-invalid")
            os.fsync(jobs_fd)

        _validate_target_state(jobs_fd, plan)
        manifest_stage = f".lifeos-stage-{plan.plan_id}-manifest"
        manifest_retired = f".lifeos-retired-{plan.plan_id}-manifest"
        if current_manifest_sha == plan.target_manifest_sha256:
            staged_manifest = _current_sha(jobs_fd, manifest_stage)
            if staged_manifest is not None:
                if staged_manifest not in {
                    plan.manifest_sha256,
                    plan.target_manifest_sha256,
                }:
                    _fail("scheduler-manifest-stage-conflict")
                _retain_stage(jobs_fd, manifest_stage, f"{plan.plan_id}-manifest")
        if current_manifest_sha != plan.target_manifest_sha256:
            _write_stage(jobs_fd, manifest_stage, plan._target_manifest)
            if current_manifest is None:
                try:
                    _rename_between(
                        jobs_fd,
                        manifest_stage,
                        jobs_fd,
                        _MANIFEST,
                        exchange=False,
                    )
                except OSError:
                    existing = _read_optional(jobs_fd, _MANIFEST, _MAX_MANIFEST)
                    if existing != plan._target_manifest:
                        _fail("scheduler-manifest-publish-failed")
            else:
                existing = _read_optional(jobs_fd, _MANIFEST, _MAX_MANIFEST)
                if existing != current_manifest:
                    _fail("scheduler-manifest-changed")
                try:
                    _rename_between(
                        jobs_fd, manifest_stage, jobs_fd, _MANIFEST, exchange=True
                    )
                except OSError:
                    _fail("scheduler-manifest-publish-failed")
                if (
                    _read_optional(jobs_fd, manifest_stage, _MAX_MANIFEST)
                    != current_manifest
                ):
                    try:
                        _rename_between(
                            jobs_fd,
                            manifest_stage,
                            jobs_fd,
                            _MANIFEST,
                            exchange=True,
                        )
                    except OSError:
                        pass
                    _fail("scheduler-manifest-was-substituted")
                try:
                    _rename_between(
                        jobs_fd,
                        manifest_stage,
                        jobs_fd,
                        manifest_retired,
                        exchange=False,
                    )
                except OSError:
                    _fail("scheduler-old-manifest-retire-failed")
        if _read_optional(jobs_fd, _MANIFEST, _MAX_MANIFEST) != plan._target_manifest:
            _fail("scheduler-manifest-verification-failed")
        _validate_target_state(jobs_fd, plan)
        history_name = f".lifeos-completed-{plan.plan_id}.json"
        try:
            _rename_between(
                jobs_fd, journal_name, jobs_fd, history_name, exchange=False
            )
        except OSError:
            existing_history = _read_optional(jobs_fd, history_name, len(journal_raw))
            if existing_history != journal_raw:
                _fail("scheduler-journal-retire-failed")
        os.fsync(jobs_fd)
        _validate_target_state(jobs_fd, plan)
        _revalidate_child(home_fd, "jobs", jobs_fd, jobs_identity)
        _revalidate_root(plan._home, home_fd, home_identity)
        return SchedulerInstallResult(
            1,
            "installed",
            plan.plan_id,
            bool(plan.actions) or plan.manifest_sha256 != plan.target_manifest_sha256,
            tuple(
                action.recipe_id for action in plan.actions if action.kind == "create"
            ),
            tuple(
                action.recipe_id for action in plan.actions if action.kind == "update"
            ),
            tuple(
                action.recipe_id for action in plan.actions if action.kind == "retire"
            ),
            (),
        )
    finally:
        for fd in (jobs_fd, home_fd):
            if fd >= 0:
                os.close(fd)


def uninstall_recipes(plan: SchedulerRecipePlan) -> SchedulerInstallResult:
    _validate_plan(plan)
    if any(action.kind != "retire" for action in plan.actions) or plan._rendered:
        _fail("scheduler-uninstall-plan-is-invalid")
    return install_recipes(plan)
