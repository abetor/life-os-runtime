from __future__ import annotations

from dataclasses import replace
import os
from pathlib import Path
import re
import shutil

import pytest

from tool_life_os_runtime.ext.connectors.probes import (
    DEFAULT_SPECS,
    MachineOutputContract,
    ProbeRecord,
    ProbeSpec,
)
from tool_life_os_runtime.ext.vault.doctor import (
    DoctorError,
    load_status,
    render_status,
    run_doctor,
    validate_status,
)
from tool_life_os_runtime.ext.vault.doctor.report import (
    MAX_CONFIG_BYTES,
    MAX_STATUS_BYTES,
)
import tool_life_os_runtime.ext.vault.doctor.report as doctor_report


FIXTURES = Path(__file__).parent / "fixtures"
HASH_REF = re.compile(r"^sha256:[0-9a-f]{64}$")


def _repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    (root / "tool_life_os_runtime").mkdir(parents=True)
    (root / "pyproject.toml").write_text("[project]\nname='fixture'\n", "utf-8")
    return root


def _runtime_home(tmp_path: Path, vault: Path) -> Path:
    home = tmp_path / "runtime-home"
    home.mkdir()
    (home / "config.toml").write_text(
        f'''schema_version = 1
default_vault = "main"

[vaults.main]
path = "{vault}"

[machine_knowledge]
topics_root = "{tmp_path / "topics"}"

[migration.legacy]
path = "{tmp_path / "legacy"}"
read_only = true
''',
        "utf-8",
    )
    return home


def _compatible(spec) -> ProbeRecord:
    if not spec.machine_contract_available:
        return ProbeRecord(
            tool=spec.tool,
            status="unavailable",
            optional=spec.optional,
            probe_argv=spec.argv,
            minimum_supported_tool_version="0.1.0",
            maximum_supported_tool_version_exclusive="0.2.0",
            expected_capabilities=spec.expected_capabilities,
            error="machine_contract_unavailable",
        )
    return ProbeRecord(
        tool=spec.tool,
        status="compatible",
        optional=spec.optional,
        probe_argv=spec.argv,
        minimum_supported_tool_version="0.1.0",
        maximum_supported_tool_version_exclusive="0.2.0",
        expected_capabilities=spec.expected_capabilities,
        returncode=0,
        protocol_version=1,
    )


def _records() -> tuple[ProbeRecord, ...]:
    return tuple(_compatible(spec) for spec in DEFAULT_SPECS)


def _setup(tmp_path: Path, fixture: str = "vault-populated") -> tuple[Path, Path, Path]:
    vault = tmp_path / "vault"
    shutil.copytree(FIXTURES / fixture, vault)
    return _repo(tmp_path), _runtime_home(tmp_path, vault), vault


def _snapshot(*roots: Path) -> dict[str, tuple[str, int, int, int]]:
    result: dict[str, tuple[str, int, int, int]] = {}
    for root in roots:
        for path in [root, *sorted(root.rglob("*"))]:
            relative = f"{root.name}/{path.relative_to(root).as_posix()}"
            metadata = path.lstat()
            if path.is_symlink():
                kind = "symlink:" + os.readlink(path)
            elif path.is_file():
                kind = path.read_bytes().hex()
            elif path.is_dir():
                kind = "directory"
            else:
                kind = "special"
            result[relative] = (
                kind,
                metadata.st_size,
                metadata.st_mtime_ns,
                metadata.st_ctime_ns,
            )
    return result


def _section(payload: dict[str, object], name: str) -> dict[str, object]:
    return next(section for section in payload["sections"] if section["name"] == name)


def test_doctor_sections_are_ordered_versioned_and_all_green_on_populated_fixture(
    tmp_path,
):
    repo, runtime_home, _ = _setup(tmp_path)

    report = run_doctor(
        repo_root=repo,
        runtime_home=runtime_home,
        connector_probe=_records,
    )
    payload = report.to_dict()

    assert report.status == "warning"
    assert payload["schema_version"] == 1
    assert payload["kind"] == "lifeos-doctor-status"
    assert [section["name"] for section in payload["sections"]] == [
        "repo",
        "runtime_home",
        "vault",
        "connectors",
    ]
    assert [section["status"] for section in payload["sections"]] == [
        "ok",
        "ok",
        "ok",
        "warning",
    ]
    assert load_status(render_status(report)) == validate_status(payload)


def test_missing_optional_zone_and_connector_are_warnings(tmp_path):
    repo, runtime_home, _ = _setup(tmp_path, "vault-minimal")
    records = list(_records())
    records[0] = replace(
        records[0],
        status="unavailable",
        returncode=None,
        protocol_version=None,
        missing_machine_modes=DEFAULT_SPECS[0].required_capabilities,
        error="executable_not_found",
    )

    payload = run_doctor(
        repo_root=repo,
        runtime_home=runtime_home,
        connector_probe=lambda: records,
    ).to_dict()

    assert payload["status"] == "warning"
    warning_codes = {
        check["code"]
        for section in payload["sections"]
        for check in section["checks"]
        if check["status"] == "warning"
    }
    assert warning_codes == {
        "optional_zone_missing",
        "optional_connector_unavailable",
        "connector_machine_contract_unavailable",
    }


def test_required_connector_unavailable_is_failure(tmp_path):
    repo, runtime_home, _ = _setup(tmp_path)
    required = replace(DEFAULT_SPECS[0], optional=False)
    record = replace(
        _compatible(required),
        status="unavailable",
        returncode=None,
        protocol_version=None,
        missing_machine_modes=required.required_capabilities,
        error="required_executable_not_found",
    )

    payload = run_doctor(
        repo_root=repo,
        runtime_home=runtime_home,
        connector_probe=lambda: (record,),
        expected_specs=(required,),
    ).to_dict()

    assert payload["status"] == "failure"
    check = _section(payload, "connectors")["checks"][0]
    assert check["code"] == "required_connector_unavailable"
    assert check["required"] is True


def test_required_schema_break_is_failure_and_optional_corruption_is_not_missing(
    tmp_path,
):
    repo, runtime_home, vault = _setup(tmp_path)
    shutil.rmtree(vault / "knowledge")
    reading = vault / "agent/reading"
    shutil.rmtree(reading)
    reading.write_text("wrong type", "utf-8")

    payload = run_doctor(
        repo_root=repo,
        runtime_home=runtime_home,
        connector_probe=_records,
    ).to_dict()

    vault_checks = {
        check["id"]: check for check in _section(payload, "vault")["checks"]
    }
    assert payload["status"] == "failure"
    assert vault_checks["vault.zone.knowledge"]["code"] == "required_zone_corrupt"
    assert vault_checks["vault.zone.agent.reading"]["code"] == "optional_zone_corrupt"


def test_malformed_config_and_probe_fail_closed_without_diagnostics_or_paths(tmp_path):
    repo, runtime_home, vault = _setup(tmp_path)
    (runtime_home / "config.toml").write_text(
        'schema_version = 1\nunknown_security_field = "/private/secret"\n', "utf-8"
    )

    payload = run_doctor(
        repo_root=repo,
        runtime_home=runtime_home,
        connector_probe=lambda: (object(),),
    ).to_dict()
    rendered = render_status(payload)

    assert payload["status"] == "failure"
    assert _section(payload, "runtime_home")["status"] == "failure"
    assert _section(payload, "vault")["status"] == "failure"
    assert (
        _section(payload, "connectors")["checks"][0]["code"]
        == "connector_probe_malformed"
    )
    for private in (str(repo), str(runtime_home), str(vault), "/private/secret"):
        assert private not in rendered
    for section in payload["sections"]:
        for check in section["checks"]:
            assert check["ref"] is None or HASH_REF.fullmatch(check["ref"])


def test_symlinked_explicit_root_and_malformed_typed_probe_fail_closed(tmp_path):
    repo, runtime_home, _ = _setup(tmp_path)
    repo_link = tmp_path / "repo-link"
    repo_link.symlink_to(repo, target_is_directory=True)
    malformed = replace(_records()[0], tool=[])  # type: ignore[arg-type]

    payload = run_doctor(
        repo_root=repo_link,
        runtime_home=runtime_home,
        connector_probe=lambda: (malformed,),
    ).to_dict()

    assert _section(payload, "repo")["checks"][0]["code"] == "root_invalid"
    assert (
        _section(payload, "connectors")["checks"][0]["code"]
        == "connector_probe_malformed"
    )


def test_doctor_does_not_read_home_or_change_bytes_mtime_or_ctime(
    tmp_path, monkeypatch
):
    repo, runtime_home, vault = _setup(tmp_path)
    before = _snapshot(repo, runtime_home, vault)

    monkeypatch.setattr(
        Path, "home", classmethod(lambda _cls: pytest.fail("HOME scan"))
    )
    report = run_doctor(
        repo_root=repo,
        runtime_home=runtime_home,
        connector_probe=_records,
    )

    assert report.status == "warning"
    assert _snapshot(repo, runtime_home, vault) == before


def test_oversized_config_is_rejected_before_parser_and_status_stays_bounded(tmp_path):
    repo, runtime_home, _ = _setup(tmp_path)
    (runtime_home / "config.toml").write_bytes(b"x" * (MAX_CONFIG_BYTES + 1))

    report = run_doctor(
        repo_root=repo, runtime_home=runtime_home, connector_probe=_records
    )
    rendered = render_status(report)

    assert report.status == "failure"
    assert len(rendered.encode("utf-8")) < MAX_STATUS_BYTES


def test_config_path_replacement_during_parse_is_rejected_and_replacement_is_not_read(
    tmp_path, monkeypatch
):
    repo, runtime_home, _ = _setup(tmp_path)
    config_path = runtime_home / "config.toml"
    saved = runtime_home / "captured-config.toml"
    original_loader = doctor_report.load_runtime_config

    def replace_after_capture(snapshot_path: Path):
        config_path.rename(saved)
        config_path.write_text('invalid = "/private/replacement-secret"\n', "utf-8")
        return original_loader(snapshot_path)

    monkeypatch.setattr(doctor_report, "load_runtime_config", replace_after_capture)
    report = run_doctor(
        repo_root=repo,
        runtime_home=runtime_home,
        connector_probe=_records,
    )
    rendered = render_status(report)

    assert _section(report.to_dict(), "runtime_home")["status"] == "failure"
    assert "/private/replacement-secret" not in rendered
    assert saved.read_text("utf-8").startswith("schema_version = 1")


def test_repo_root_swap_uses_held_fd_and_fails_root_revalidation(tmp_path, monkeypatch):
    repo, runtime_home, _ = _setup(tmp_path)
    original_repo = tmp_path / "original-repo"
    original_entry_state = doctor_report._entry_state_at
    swapped = False

    def swap_after_first_anchored_check(root_fd, relative, *, directory):
        nonlocal swapped
        result = original_entry_state(root_fd, relative, directory=directory)
        if not swapped:
            swapped = True
            repo.rename(original_repo)
            repo.mkdir()
        return result

    monkeypatch.setattr(
        doctor_report, "_entry_state_at", swap_after_first_anchored_check
    )
    payload = run_doctor(
        repo_root=repo,
        runtime_home=runtime_home,
        connector_probe=_records,
    ).to_dict()

    checks = {item["id"]: item for item in _section(payload, "repo")["checks"]}
    assert checks["repo.root"]["code"] == "root_changed"
    assert checks["repo.package"]["code"] == "required_entry_valid"
    assert checks["repo.pyproject"]["code"] == "required_entry_valid"
    assert not (repo / "pyproject.toml").exists()


def test_runtime_root_swap_during_parse_rejects_original_config_and_never_reads_replacement(
    tmp_path, monkeypatch
):
    repo, runtime_home, _ = _setup(tmp_path)
    original_home = tmp_path / "original-runtime-home"
    original_loader = doctor_report.load_runtime_config

    def swap_root(snapshot_path: Path):
        runtime_home.rename(original_home)
        runtime_home.mkdir()
        (runtime_home / "config.toml").write_text(
            'invalid = "/private/replacement-runtime-secret"\n', "utf-8"
        )
        return original_loader(snapshot_path)

    monkeypatch.setattr(doctor_report, "load_runtime_config", swap_root)
    report = run_doctor(
        repo_root=repo,
        runtime_home=runtime_home,
        connector_probe=_records,
    )
    payload = report.to_dict()
    rendered = render_status(report)

    checks = {item["id"]: item for item in _section(payload, "runtime_home")["checks"]}
    assert checks["runtime_home.root"]["code"] == "root_changed"
    assert _section(payload, "runtime_home")["status"] == "failure"
    assert (
        _section(payload, "vault")["checks"][0]["code"] == "runtime_config_unavailable"
    )
    assert "/private/replacement-runtime-secret" not in rendered


@pytest.mark.parametrize("mutation", ["config", "root"])
def test_runtime_config_is_revalidated_after_configured_connector_probe(
    tmp_path, mutation
):
    repo, runtime_home, _ = _setup(tmp_path)
    original_home = tmp_path / "runtime-home-before-probe"
    marker = "/private/replacement-after-probe-secret"
    received = []

    def mutate_during_probe(config):
        received.append(config)
        if mutation == "root":
            runtime_home.rename(original_home)
            runtime_home.mkdir()
        (runtime_home / "config.toml").write_text(
            f'unknown = "{marker}"\n',
            "utf-8",
        )
        return _records()

    report = run_doctor(
        repo_root=repo,
        runtime_home=runtime_home,
        configured_connector_probe=mutate_during_probe,
    )
    payload = report.to_dict()
    rendered = render_status(report)
    runtime_checks = {
        item["id"]: item for item in _section(payload, "runtime_home")["checks"]
    }

    assert len(received) == 1
    assert received[0] is not None
    assert report.status == "failure"
    changed_id = "runtime_home.root" if mutation == "root" else "runtime_home.config"
    assert runtime_checks[changed_id]["status"] == "failure"
    assert marker not in rendered


@pytest.mark.parametrize("target", ["repo", "vault"])
def test_repo_and_vault_roots_are_revalidated_after_configured_probe(tmp_path, target):
    repo, runtime_home, vault = _setup(tmp_path)
    selected = repo if target == "repo" else vault
    replacement = tmp_path / f"{target}-replacement"
    detached = tmp_path / f"{target}-detached"
    shutil.copytree(selected, replacement)

    def replace_root(_config):
        selected.rename(detached)
        replacement.rename(selected)
        return _records()

    payload = run_doctor(
        repo_root=repo,
        runtime_home=runtime_home,
        configured_connector_probe=replace_root,
    ).to_dict()

    section = _section(payload, target)
    assert section["status"] == "failure"
    assert section["checks"]
    assert {check["code"] for check in section["checks"]} == {"root_changed"}


def test_legacy_and_configured_probe_callbacks_together_fail_closed(tmp_path):
    repo, runtime_home, _ = _setup(tmp_path)

    payload = run_doctor(
        repo_root=repo,
        runtime_home=runtime_home,
        connector_probe=_records,
        configured_connector_probe=lambda _config: _records(),
    ).to_dict()

    connector = _section(payload, "connectors")
    assert connector["status"] == "failure"
    assert connector["checks"][0]["code"] == "connector_probe_malformed"


def test_vault_root_swap_during_parse_checks_original_fd_but_never_reports_green(
    tmp_path, monkeypatch
):
    repo, runtime_home, vault = _setup(tmp_path)
    original_vault = tmp_path / "original-vault"
    original_loader = doctor_report.load_vault_config

    def swap_root(snapshot_path: Path):
        vault.rename(original_vault)
        vault.mkdir()
        (vault / "lifeos.toml").write_text(
            'invalid = "/private/replacement-vault-secret"\n', "utf-8"
        )
        return original_loader(snapshot_path)

    monkeypatch.setattr(doctor_report, "load_vault_config", swap_root)
    report = run_doctor(
        repo_root=repo,
        runtime_home=runtime_home,
        connector_probe=_records,
    )
    payload = report.to_dict()
    rendered = render_status(report)

    checks = {item["id"]: item for item in _section(payload, "vault")["checks"]}
    assert checks["vault.root"]["code"] == "root_changed"
    assert checks["vault.zone.knowledge"]["code"] == "zone_present"
    assert _section(payload, "vault")["status"] == "failure"
    assert "/private/replacement-vault-secret" not in rendered


def _spec_with_capability(capability: object) -> ProbeSpec:
    return replace(DEFAULT_SPECS[0], expected_capabilities=(capability,))


@pytest.mark.parametrize(
    "capability",
    [
        object(),
        replace(DEFAULT_SPECS[0].expected_capabilities[0], name="bad\nname"),
        replace(DEFAULT_SPECS[0].expected_capabilities[0], argv=()),
        replace(
            DEFAULT_SPECS[0].expected_capabilities[0],
            argv=("research",) + ("arg",) * 64,
        ),
        replace(
            DEFAULT_SPECS[0].expected_capabilities[0],
            argv=("research", "x" * 4097),
        ),
        replace(DEFAULT_SPECS[0].expected_capabilities[0], argv=("wrong-tool", "run")),
        replace(
            DEFAULT_SPECS[0].expected_capabilities[0], argv=("research", "bad\narg")
        ),
        replace(
            DEFAULT_SPECS[0].expected_capabilities[0],
            machine_output=object(),
        ),
        replace(
            DEFAULT_SPECS[0].expected_capabilities[0],
            machine_output=MachineOutputContract("yaml", 1, ("status",)),
        ),
        replace(
            DEFAULT_SPECS[0].expected_capabilities[0],
            machine_output=MachineOutputContract("json", True, ("status",)),
        ),
        replace(
            DEFAULT_SPECS[0].expected_capabilities[0],
            machine_output=MachineOutputContract("json", 1, ("status", "status")),
        ),
        replace(
            DEFAULT_SPECS[0].expected_capabilities[0],
            machine_output=MachineOutputContract(
                "json", 1, tuple(f"field_{index}" for index in range(65))
            ),
        ),
        replace(DEFAULT_SPECS[0].expected_capabilities[0], exit_codes=()),
        replace(
            DEFAULT_SPECS[0].expected_capabilities[0],
            exit_codes=((0, "success"),)
            + tuple((index, "failure") for index in range(1, 33)),
        ),
        replace(
            DEFAULT_SPECS[0].expected_capabilities[0],
            exit_codes=((0, "success"), (0, "failure")),
        ),
        replace(
            DEFAULT_SPECS[0].expected_capabilities[0],
            exit_codes=((0, "success"), (256, "failure")),
        ),
        replace(
            DEFAULT_SPECS[0].expected_capabilities[0],
            exit_codes=((1, "failure"),),
        ),
        replace(DEFAULT_SPECS[0].expected_capabilities[0], idempotency="maybe"),
        replace(DEFAULT_SPECS[0].expected_capabilities[0], idempotency="bad\nvalue"),
    ],
)
def test_nested_connector_spec_contracts_fail_closed_and_bounded(tmp_path, capability):
    repo, runtime_home, _ = _setup(tmp_path)

    payload = run_doctor(
        repo_root=repo,
        runtime_home=runtime_home,
        connector_probe=lambda: (),
        expected_specs=(_spec_with_capability(capability),),
    ).to_dict()

    connector = _section(payload, "connectors")
    assert connector["status"] == "failure"
    assert connector["checks"] == [
        {
            "id": "connectors.probe",
            "status": "failure",
            "required": True,
            "code": "connector_specs_invalid",
            "ref": None,
        }
    ]


def test_nested_probe_record_object_is_malformed_not_exception(tmp_path):
    repo, runtime_home, _ = _setup(tmp_path)
    record = replace(_records()[0], expected_capabilities=(object(),))

    payload = run_doctor(
        repo_root=repo,
        runtime_home=runtime_home,
        connector_probe=lambda: (record,),
    ).to_dict()

    connector = _section(payload, "connectors")
    assert connector["status"] == "failure"
    researcher = next(
        check for check in connector["checks"] if check["id"] == "connectors.researcher"
    )
    assert researcher["code"] == "connector_probe_malformed"


def test_connector_spec_property_error_and_capability_count_fail_closed(tmp_path):
    repo, runtime_home, _ = _setup(tmp_path)

    class ExplodingSpec(ProbeSpec):
        @property
        def argv(self):
            raise RuntimeError("must stay private")

    original = DEFAULT_SPECS[0]
    exploding = ExplodingSpec(
        original.tool,
        original.executable,
        original.expected_capabilities,
        original.minimum_version,
        original.maximum_version_exclusive,
        original.optional,
    )
    too_many = replace(
        original,
        expected_capabilities=(original.expected_capabilities[0],) * 65,
    )

    for malformed in (exploding, too_many):
        payload = run_doctor(
            repo_root=repo,
            runtime_home=runtime_home,
            connector_probe=lambda: (),
            expected_specs=(malformed,),
        ).to_dict()
        connector = _section(payload, "connectors")
        assert connector["checks"][0]["code"] == "connector_specs_invalid"


@pytest.mark.parametrize(
    "mutate",
    [
        lambda payload: payload.update(schema_version=True),
        lambda payload: payload.update(extra=True),
        lambda payload: payload["summary"].update(warning_count=True),
        lambda payload: payload["sections"].reverse(),
        lambda payload: payload["sections"][0]["checks"].reverse(),
        lambda payload: payload["sections"][0]["checks"][0].update(ref="/private/path"),
        lambda payload: payload["sections"][0]["checks"][0].update(status="warning"),
        lambda payload: payload["sections"][0]["checks"][0].update(status=[]),
    ],
)
def test_status_schema_is_exact_type_sensitive_and_derived(tmp_path, mutate):
    repo, runtime_home, _ = _setup(tmp_path)
    payload = run_doctor(
        repo_root=repo, runtime_home=runtime_home, connector_probe=_records
    ).to_dict()
    mutate(payload)

    with pytest.raises(DoctorError):
        validate_status(payload)


def test_status_loader_rejects_duplicate_fields_and_oversized_input(tmp_path):
    repo, runtime_home, _ = _setup(tmp_path)
    rendered = render_status(
        run_doctor(repo_root=repo, runtime_home=runtime_home, connector_probe=_records)
    )
    duplicate = rendered.replace(
        '"schema_version": 1', '"schema_version": 1, "schema_version": 1'
    )

    with pytest.raises(DoctorError, match="duplicate"):
        load_status(duplicate)
    with pytest.raises(DoctorError, match="too large"):
        load_status(" " * (MAX_STATUS_BYTES + 1))


def test_status_loader_normalizes_huge_integer_decoder_error():
    malformed = '{"schema_version":' + "9" * 5000 + "}"

    with pytest.raises(DoctorError, match="status JSON is invalid"):
        load_status(malformed)


def test_status_loader_normalizes_deep_nesting_decoder_error():
    malformed = "[" * 10_000 + "]" * 10_000

    with pytest.raises(DoctorError, match="status JSON is invalid"):
        load_status(malformed)


def test_missing_probe_results_are_canonical_warnings_not_success(tmp_path):
    repo, runtime_home, _ = _setup(tmp_path)

    payload = run_doctor(repo_root=repo, runtime_home=runtime_home).to_dict()

    connector = _section(payload, "connectors")
    assert connector["status"] == "warning"
    assert [check["id"] for check in connector["checks"]] == sorted(
        check["id"] for check in connector["checks"]
    )
    assert {check["code"] for check in connector["checks"]} == {
        "connector_probe_missing"
    }
