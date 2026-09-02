"""P4-03 generated scheduler recipe ownership and preservation tests."""

from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path

import pytest

import tool_life_os_runtime.ext.connectors.scheduler.installer as installer_module
from tool_life_os_runtime.ext.connectors.scheduler import (
    SchedulerConnectorError,
    SchedulerRecipe,
    SchedulerRecipeAction,
    canonical_recipe_descriptors,
    check_recipes,
    diff_recipes,
    install_recipes,
    uninstall_recipes,
)


def _home(tmp_path: Path) -> Path:
    home = tmp_path / "scheduler-home"
    (home / "jobs").mkdir(parents=True)
    (home / "logs").mkdir()
    (home / ".enabled").write_bytes(b"")
    (home / "state.json").write_text('{"user":{}}\n', "utf-8")
    (home / "logs/scheduler.jsonl").write_text("synthetic-log\n", "utf-8")
    (home / "jobs/user.toml").write_text('command = "true"\nevery = "1h"\n', "utf-8")
    return home


def _recipe(*, version: int = 1, every: str = "15m") -> SchedulerRecipe:
    return SchedulerRecipe(
        recipe_id="ambient",
        recipe_version=version,
        flow_id="ambient",
        argv=("lifeos", "flow", "ambient", "--vault", "default"),
        vault_profile="default",
        every=every,
        at=None,
        timeout_seconds=300,
        retries=3,
        retry_delay="5m",
        quota_wait="1h",
        environment_allowlist=("LIFE_OS_RUNTIME_DATA", "PATH"),
    )


def _protected(home: Path) -> dict[str, bytes]:
    return {
        name: (home / name).read_bytes()
        for name in (
            ".enabled",
            "state.json",
            "logs/scheduler.jsonl",
            "jobs/user.toml",
        )
    }


def _rebind_plan(plan, *, actions, rendered, target_manifest):
    target_sha = hashlib.sha256(target_manifest).hexdigest()
    payload = installer_module._plan_payload(
        plan.recipe_set_sha256,
        plan.home_identity,
        plan.jobs_identity,
        plan.manifest_sha256,
        target_sha,
        actions,
        plan.deferred_ids,
        plan.conflicts,
    )
    plan_id = (
        "scheduler-plan-"
        + hashlib.sha256(installer_module._canonical(payload)).hexdigest()[:32]
    )
    return replace(
        plan,
        plan_id=plan_id,
        target_manifest_sha256=target_sha,
        actions=tuple(actions),
        _rendered=tuple(rendered),
        _target_manifest=target_manifest,
    )


def test_diff_is_read_only_install_repeat_update_and_uninstall_preserve_user_state(
    tmp_path: Path,
) -> None:
    home = _home(tmp_path)
    protected = _protected(home)
    before = sorted(path.relative_to(home).as_posix() for path in home.rglob("*"))

    plan = diff_recipes(home, (_recipe(),))
    assert [action.kind for action in plan.actions] == ["create"]
    assert (
        sorted(path.relative_to(home).as_posix() for path in home.rglob("*")) == before
    )

    result = install_recipes(plan)
    assert result.changed is True and result.installed == ("ambient",)
    generated = home / "jobs/lifeos-ambient.toml"
    assert generated.is_file()
    assert "enabled = false" in generated.read_text("utf-8")
    assert _protected(home) == protected

    repeated = diff_recipes(home, (_recipe(),))
    assert repeated.actions == () and repeated.conflicts == ()
    assert check_recipes(home, (_recipe(),)).ok is True
    assert install_recipes(repeated).changed is False

    update = diff_recipes(home, (_recipe(version=2, every="30m"),))
    assert [action.kind for action in update.actions] == ["update"]
    updated = install_recipes(update)
    assert updated.updated == ("ambient",)
    assert 'every = "30m"' in generated.read_text("utf-8")
    assert _protected(home) == protected

    removal = diff_recipes(home, ())
    assert [action.kind for action in removal.actions] == ["retire"]
    removed = uninstall_recipes(removal)
    assert removed.retired == ("ambient",)
    assert not generated.exists()
    assert _protected(home) == protected
    manifest = json.loads(
        (home / "jobs/.lifeos-runtime-recipes-v1.json").read_text("utf-8")
    )
    assert manifest == {"schema_version": 1, "files": []}


def test_foreign_collision_and_modified_owned_file_are_preserved(
    tmp_path: Path,
) -> None:
    home = _home(tmp_path)
    target = home / "jobs/lifeos-ambient.toml"
    target.write_text("foreign\n", "utf-8")
    plan = diff_recipes(home, (_recipe(),))
    assert plan.conflicts == ("ambient",)
    with pytest.raises(SchedulerConnectorError, match="conflicts"):
        install_recipes(plan)
    assert target.read_text("utf-8") == "foreign\n"

    target.unlink()
    install_recipes(diff_recipes(home, (_recipe(),)))
    target.write_text("user-edited-owned-file\n", "utf-8")
    drift = diff_recipes(home, ())
    assert drift.conflicts == ("ambient",)
    with pytest.raises(SchedulerConnectorError, match="conflicts"):
        uninstall_recipes(drift)
    assert target.read_text("utf-8") == "user-edited-owned-file\n"


def test_stale_plan_and_jobs_replacement_fail_without_writes(tmp_path: Path) -> None:
    home = _home(tmp_path)
    plan = diff_recipes(home, (_recipe(),))
    original = home / "jobs"
    detached = home / "jobs-detached"
    original.rename(detached)
    original.mkdir()
    (original / "foreign.toml").write_text("foreign\n", "utf-8")
    with pytest.raises(SchedulerConnectorError, match="stale"):
        install_recipes(plan)
    assert (original / "foreign.toml").read_text("utf-8") == "foreign\n"
    assert not (detached / "lifeos-ambient.toml").exists()


def test_manifest_tamper_and_owned_symlink_fail_closed(tmp_path: Path) -> None:
    home = _home(tmp_path)
    install_recipes(diff_recipes(home, (_recipe(),)))
    manifest = home / "jobs/.lifeos-runtime-recipes-v1.json"
    manifest.write_text('{"schema_version":true,"files":[]}\n', "utf-8")
    with pytest.raises(SchedulerConnectorError, match="manifest"):
        diff_recipes(home, (_recipe(),))

    home = _home(tmp_path / "symlink")
    outside = tmp_path / "outside.toml"
    outside.write_text("outside\n", "utf-8")
    (home / "jobs/lifeos-ambient.toml").symlink_to(outside)
    with pytest.raises(SchedulerConnectorError):
        diff_recipes(home, (_recipe(),))
    assert outside.read_text("utf-8") == "outside\n"


def test_integration_required_descriptors_never_create_support_or_jobs(
    tmp_path: Path,
) -> None:
    home = _home(tmp_path)
    recipes = canonical_recipe_descriptors()
    plan = diff_recipes(home, recipes)
    assert plan.actions == ()
    assert plan.deferred_ids == ("ambient", "bundle")
    assert check_recipes(home, recipes).ok is False
    with pytest.raises(SchedulerConnectorError, match="integration-gaps"):
        install_recipes(plan)
    assert sorted(path.name for path in (home / "jobs").iterdir()) == ["user.toml"]


def test_plan_binding_rejects_mutated_public_fields(tmp_path: Path) -> None:
    home = _home(tmp_path)
    plan = diff_recipes(home, (_recipe(),))
    with pytest.raises(SchedulerConnectorError, match="binding"):
        install_recipes(replace(plan, target_manifest_sha256="0" * 64))


@pytest.mark.parametrize(
    "mutate",
    [
        lambda plan: replace(plan, actions=(object(),)),
        lambda plan: replace(plan, _recipes=(object(),)),
        lambda plan: replace(plan, _rendered=(("bad", object()),)),
        lambda plan: replace(plan, _target_manifest=None),
        lambda plan: replace(plan, deferred_ids=([],)),
    ],
)
def test_malformed_public_plan_is_normalized_before_effects(
    tmp_path: Path, mutate
) -> None:
    home = _home(tmp_path)
    before = _protected(home)
    plan = mutate(diff_recipes(home, (_recipe(),)))
    with pytest.raises(SchedulerConnectorError):
        install_recipes(plan)
    assert _protected(home) == before
    assert not (home / "jobs/lifeos-ambient.toml").exists()
    assert not list((home / "jobs").glob(".lifeos-*"))


def test_forged_self_consistent_plan_cannot_enable_recipe_or_retire_foreign(
    tmp_path: Path,
) -> None:
    home = _home(tmp_path)
    plan = diff_recipes(home, (_recipe(),))
    filename, safe = plan._rendered[0]
    unsafe = safe.replace(b"enabled = false", b"enabled = true")
    unsafe_sha = hashlib.sha256(unsafe).hexdigest()
    target_manifest = installer_module._canonical(
        installer_module._manifest_payload({"ambient": (filename, unsafe_sha)})
    )
    forged_create = _rebind_plan(
        plan,
        actions=(
            SchedulerRecipeAction("create", "ambient", filename, None, unsafe_sha),
        ),
        rendered=((filename, unsafe),),
        target_manifest=target_manifest,
    )
    with pytest.raises(SchedulerConnectorError, match="derivation"):
        install_recipes(forged_create)
    assert not (home / "jobs/lifeos-ambient.toml").exists()
    assert not list((home / "jobs").glob(".lifeos-transaction-*"))

    foreign = home / "jobs/lifeos-victim.toml"
    foreign.write_bytes(b"foreign\n")
    empty = diff_recipes(home, ())
    forged_retire = _rebind_plan(
        empty,
        actions=(
            SchedulerRecipeAction(
                "retire",
                "victim",
                foreign.name,
                hashlib.sha256(foreign.read_bytes()).hexdigest(),
                None,
            ),
        ),
        rendered=(),
        target_manifest=empty._target_manifest,
    )
    with pytest.raises(SchedulerConnectorError, match="derivation"):
        uninstall_recipes(forged_retire)
    assert foreign.read_bytes() == b"foreign\n"


def test_forged_recovery_journal_cannot_claim_foreign_recipe(tmp_path: Path) -> None:
    home = _home(tmp_path)
    foreign = home / "jobs/lifeos-victim.toml"
    foreign.write_bytes(b"foreign\n")
    empty = diff_recipes(home, ())
    forged = _rebind_plan(
        empty,
        actions=(
            SchedulerRecipeAction(
                "retire",
                "victim",
                foreign.name,
                hashlib.sha256(foreign.read_bytes()).hexdigest(),
                None,
            ),
        ),
        rendered=(),
        target_manifest=empty._target_manifest,
    )
    journal = home / "jobs" / f".lifeos-transaction-{forged.plan_id}.json"
    journal.write_bytes(installer_module._journal_payload(forged))

    with pytest.raises(SchedulerConnectorError, match="action-binding"):
        diff_recipes(home, ())
    assert foreign.read_bytes() == b"foreign\n"


@pytest.mark.parametrize("fail_call", [1, 2, 3])
def test_install_recovers_from_durable_journal_in_a_new_plan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fail_call: int
) -> None:
    home = _home(tmp_path)
    plan = diff_recipes(home, (_recipe(),))
    original = installer_module._rename_between
    calls = 0

    def fail_once(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == fail_call:
            raise OSError("synthetic crash")
        return original(*args, **kwargs)

    monkeypatch.setattr(installer_module, "_rename_between", fail_once)
    with pytest.raises(SchedulerConnectorError):
        install_recipes(plan)
    monkeypatch.setattr(installer_module, "_rename_between", original)

    recovered_plan = diff_recipes(home, (_recipe(),))
    assert recovered_plan.plan_id == plan.plan_id
    result = install_recipes(recovered_plan)
    assert result.changed is True
    assert (home / "jobs/lifeos-ambient.toml").is_file()
    assert check_recipes(home, (_recipe(),)).ok is True
    assert list((home / "jobs").glob(".lifeos-transaction-*.json")) == []


@pytest.mark.parametrize("fail_call", [1, 2, 3, 4, 5])
def test_update_recovers_every_publish_boundary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fail_call: int
) -> None:
    home = _home(tmp_path)
    install_recipes(diff_recipes(home, (_recipe(),)))
    plan = diff_recipes(home, (_recipe(version=2, every="30m"),))
    original = installer_module._rename_between
    calls = 0

    def fail_once(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == fail_call:
            raise OSError("synthetic crash")
        return original(*args, **kwargs)

    monkeypatch.setattr(installer_module, "_rename_between", fail_once)
    with pytest.raises(SchedulerConnectorError):
        install_recipes(plan)
    monkeypatch.setattr(installer_module, "_rename_between", original)

    recovered = diff_recipes(home, (_recipe(version=2, every="30m"),))
    assert recovered.plan_id == plan.plan_id
    install_recipes(recovered)
    assert check_recipes(home, (_recipe(version=2, every="30m"),)).ok is True
    assert 'every = "30m"' in (home / "jobs/lifeos-ambient.toml").read_text("utf-8")
    assert list((home / "jobs").glob(".lifeos-stage-*")) == []


@pytest.mark.parametrize("fail_call", [1, 2, 3, 4])
def test_uninstall_recovers_and_never_removes_user_jobs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fail_call: int
) -> None:
    home = _home(tmp_path)
    protected = _protected(home)
    install_recipes(diff_recipes(home, (_recipe(),)))
    plan = diff_recipes(home, ())
    original = installer_module._rename_between
    calls = 0

    def fail_once(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == fail_call:
            raise OSError("synthetic crash")
        return original(*args, **kwargs)

    monkeypatch.setattr(installer_module, "_rename_between", fail_once)
    with pytest.raises(SchedulerConnectorError):
        uninstall_recipes(plan)
    monkeypatch.setattr(installer_module, "_rename_between", original)

    recovered = diff_recipes(home, ())
    assert recovered.plan_id == plan.plan_id
    uninstall_recipes(recovered)
    assert check_recipes(home, ()).ok is True
    assert not (home / "jobs/lifeos-ambient.toml").exists()
    assert _protected(home) == protected
    assert list((home / "jobs").glob(".lifeos-stage-*")) == []
