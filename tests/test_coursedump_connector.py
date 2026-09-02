"""P4-01 bounded coursedump process and artifact-registration contract."""

from __future__ import annotations

from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import shutil
import time

import pytest

import tool_life_os_runtime.ext.connectors.coursedump.connector as coursedump_module

from tool_life_os_runtime.ext.connectors.coursedump import (
    COURSEDUMP_CONNECTOR_SCHEMA_VERSION,
    CoursedumpConnector,
    CoursedumpConnectorError,
    parse_artifact_manifest,
    render_artifact_manifest,
)
from tool_life_os_runtime.ext.connectors.probes import DEFAULT_SPECS
from tool_life_os_runtime.ext.flows.ingest import (
    INGEST_CONNECTOR_SCHEMA_VERSION,
    IngestConnectorRequest,
    IngestConnectorResult,
)


ZERO = "0" * 64
SPEC = next(item for item in DEFAULT_SPECS if item.tool == "coursedump")


FAKE = r"""#!/usr/bin/env python3
import json
import os
from pathlib import Path
import subprocess
import sys
import time

root = Path(os.environ["FAKE_RESPONSES"])
with Path(os.environ["FAKE_LOG"]).open("a", encoding="utf-8") as stream:
    stream.write(json.dumps(sys.argv[1:], ensure_ascii=True, separators=(",", ":")) + "\n")

operation = sys.argv[1] if len(sys.argv) > 1 else ""
if operation == "capabilities":
    response = json.loads((root / "capabilities.response.json").read_text("utf-8"))
else:
    response = json.loads((root / f"{operation}.response.json").read_text("utf-8"))

if response.get("descendant_timeout"):
    code = (
        "import os,time; from pathlib import Path; "
        "time.sleep(0.8); Path(os.environ['FAKE_CHILD_MARKER']).write_text('survived','utf-8')"
    )
    subprocess.Popen([sys.executable, "-c", code])
    time.sleep(60)

time.sleep(response.get("delay", 0))
if response.get("mutate_data_home"):
    data_home = Path(os.environ["FAKE_DATA_HOME"])
    if data_home.exists():
        data_home.rename(data_home.with_name(data_home.name + "-held"))
    data_home.mkdir()

stderr = response.get("stderr", "")
sys.stderr.write(stderr)
if "raw_stdout" in response:
    sys.stdout.write(response["raw_stdout"])
else:
    sys.stdout.write(
        json.dumps(
            response["payload"],
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    )
raise SystemExit(response.get("exit", 0))
"""


def _canonical(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        + b"\n"
    )


def _ingest_digest(classification: str, source: str) -> str:
    return hashlib.sha256(
        b"lifeos-ingest-source-v1\0"
        + classification.encode("ascii")
        + b"\0"
        + source.encode("utf-8")
    ).hexdigest()


def _capabilities(version: str = "0.1.0") -> dict[str, object]:
    return {
        "schema_version": 1,
        "tool": "coursedump",
        "version": version,
        "capabilities": [item.to_dict() for item in SPEC.expected_capabilities],
    }


def _response(
    root: Path,
    operation: str,
    payload: object | None = None,
    *,
    exit_code: int = 0,
    stderr: str = "",
    raw_stdout: str | None = None,
    descendant_timeout: bool = False,
    delay: float = 0,
    mutate_data_home: bool = False,
) -> None:
    model: dict[str, object] = {
        "exit": exit_code,
        "stderr": stderr,
        "descendant_timeout": descendant_timeout,
        "delay": delay,
        "mutate_data_home": mutate_data_home,
    }
    if raw_stdout is None:
        model["payload"] = payload
    else:
        model["raw_stdout"] = raw_stdout
    (root / f"{operation}.response.json").write_text(
        json.dumps(model, ensure_ascii=True), "utf-8"
    )


def _plan(source: str, *, title: str = "Synthetic course") -> dict[str, object]:
    return {
        "schema_version": 1,
        "source": {
            "input": source,
            "title": title,
            "adapter": "_SyntheticSource",
            "is_local": False,
        },
        "items": [
            {"kind": "pdf", "count": 1, "size_bytes": 512, "work_items": 1},
            {
                "kind": "video",
                "count": 2,
                "size_bytes": 1024,
                "work_items": 2,
            },
        ],
        "estimate": {
            "basis": "size",
            "media_items": 2,
            "media_bytes": 1024,
            "media_duration_seconds": 5.0,
            "asr_seconds": 0.625,
        },
    }


def _external_artifact(data_home: Path, source: str, name: str = "course-a") -> Path:
    course = data_home / "out" / name
    (course / "raw").mkdir(parents=True)
    (course / "text").mkdir()
    rows = [
        {
            "rel": "lesson.txt",
            "kind": "text",
            "size": 12,
            "remote": "",
            "skip": "",
            "target": "lesson.txt.md",
            "index": 0,
            "vid": "",
            "title": "Lesson",
        },
        {
            "rel": "video.mp4",
            "kind": "video",
            "size": 120,
            "remote": "remote-video",
            "skip": "",
            "target": "video.mp4.md",
            "index": 1,
            "vid": "video-1",
            "title": "Video",
        },
        {
            "rel": "handout.pdf",
            "kind": "pdf",
            "size": 48,
            "remote": "remote-handout",
            "skip": "",
            "target": "handout.pdf.md",
            "index": 0,
            "vid": "",
            "title": "Handout",
        },
    ]
    (course / "manifest.jsonl").write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows),
        "utf-8",
    )
    (course / "source.json").write_text(
        json.dumps(
            {"source": source, "title": "Synthetic course", "adapter": "fixture"},
            ensure_ascii=False,
            indent=1,
        ),
        "utf-8",
    )
    (course / "raw/source.bin").write_bytes(b"raw-external-bytes")
    (course / "text/lesson.txt.md").write_text("external extracted text\n", "utf-8")
    (course / "text/video.mp4.md").write_text("external video text\n", "utf-8")
    (course / "text/handout.pdf.md").write_text("external handout text\n", "utf-8")
    return course


def _run(source: str, course: Path, *, errors: int = 0) -> dict[str, object]:
    return {
        "schema_version": 1,
        "status": "succeeded" if errors == 0 else "completed-with-errors",
        "artifact": {
            "source": source,
            "course_dir": str(course),
            "done": 3 - errors,
            "total": 3,
            "errors": errors,
        },
    }


def _status(source: str, course: Path) -> dict[str, object]:
    return {
        "schema_version": 1,
        "runs": [
            {
                "course": course.name,
                "source": source,
                "artifact": str(course),
                "done": 3,
                "total": 3,
                "errors": 0,
            }
        ],
    }


def _error_row(rel: str = "handout.pdf") -> dict[str, object]:
    return {
        "ts": "2026-08-20T12:00:00",
        "rel": rel,
        "error": "synthetic extraction failure",
        "trace": "Traceback (most recent call last):\nSyntheticError: failed\n",
    }


def _write_errors(course: Path, rows: list[dict[str, object]]) -> None:
    (course / "errors.jsonl").write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows),
        "utf-8",
    )


def _setup(tmp_path: Path, *, timeout: float = 2.0, data_home_exists: bool = False):
    fake = tmp_path / "fake-coursedump"
    fake.write_text(FAKE, "utf-8")
    fake.chmod(0o755)
    responses = tmp_path / "responses"
    responses.mkdir()
    log = tmp_path / "calls.jsonl"
    _response(responses, "capabilities", _capabilities())
    data_home = tmp_path / "coursedump-data"
    if data_home_exists:
        data_home.mkdir()
    vault = tmp_path / "vault"
    vault.mkdir()
    marker = tmp_path / "child-survived"
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "FAKE_RESPONSES": str(responses),
        "FAKE_LOG": str(log),
        "FAKE_CHILD_MARKER": str(marker),
        "FAKE_DATA_HOME": str(data_home),
    }
    connector = CoursedumpConnector(
        data_home=data_home,
        command=(str(fake),),
        cwd=tmp_path,
        env=env,
        forbidden_roots=(vault,),
        timeout=timeout,
    )
    return connector, responses, data_home, vault, log, marker


def _calls(log: Path) -> list[list[str]]:
    return [json.loads(line) for line in log.read_text("utf-8").splitlines()]


def _snapshot(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file() and not path.is_symlink()
    }


def test_plan_and_status_are_exact_read_only_argv_operations(tmp_path: Path):
    connector, responses, data_home, _vault, log, _marker = _setup(tmp_path)
    source = "https://example.test/synthetic-course"
    _response(responses, "plan", _plan(source))
    _response(responses, "status", {"schema_version": 1, "runs": []})

    assert not data_home.exists()
    plan = connector.plan(source)
    status = connector.status()

    assert plan.schema_version == COURSEDUMP_CONNECTOR_SCHEMA_VERSION
    assert plan.source_sha256 == hashlib.sha256(source.encode()).hexdigest()
    assert plan.title == "Synthetic course"
    assert [item.kind for item in plan.items] == ["pdf", "video"]
    assert status.artifacts == ()
    assert not data_home.exists()
    assert _calls(log) == [
        ["capabilities", "--json"],
        ["plan", source, "--data", str(data_home), "--json"],
        ["capabilities", "--json"],
        ["status", "--data", str(data_home), "--json"],
    ]


def test_run_registers_only_hashed_external_manifest_refs(tmp_path: Path):
    connector, responses, data_home, vault, _log, _marker = _setup(
        tmp_path, data_home_exists=True
    )
    source = "https://example.test/private-shaped-source?opaque=1"
    course = _external_artifact(data_home, source)
    raw_before = _snapshot(course)
    vault_before = _snapshot(vault)
    _response(responses, "run", _run(source, course))

    result = connector.run(source)
    artifact = result.artifact
    rendered = render_artifact_manifest(artifact)

    assert result.status == "succeeded"
    assert parse_artifact_manifest(rendered) == artifact
    assert (
        artifact.manifest_sha256
        == hashlib.sha256((course / "manifest.jsonl").read_bytes()).hexdigest()
    )
    assert (
        artifact.source_manifest_sha256
        == hashlib.sha256((course / "source.json").read_bytes()).hexdigest()
    )
    assert artifact.artifact_ref.startswith("coursedump/artifacts/artifact_")
    assert str(tmp_path).encode() not in rendered
    assert source.encode() not in rendered
    assert _snapshot(course) == raw_before
    assert _snapshot(vault) == vault_before

    book = artifact.to_book_source_manifest("Synthetic course")
    assert book.manifest_id == artifact.manifest_id
    assert book.manifest_ref == artifact.manifest_ref
    assert book.manifest_sha256 == artifact.manifest_sha256
    assert book.source_sha256 == artifact.source_sha256
    assert book.chapter_count == 3


def test_status_registers_external_artifacts_without_exposing_paths(tmp_path: Path):
    connector, responses, data_home, _vault, _log, _marker = _setup(
        tmp_path, data_home_exists=True
    )
    source = "https://example.test/course-status"
    course = _external_artifact(data_home, source)
    _response(responses, "status", _status(source, course))

    result = connector.status()
    serialized = render_artifact_manifest(result.artifacts[0])

    assert len(result.artifacts) == 1
    assert result.artifacts[0].status == "observed"
    assert str(course).encode() not in serialized
    assert source.encode() not in serialized


def test_collect_implements_ingest_port_with_bounded_manifest_note(tmp_path: Path):
    connector, responses, data_home, vault, _log, _marker = _setup(
        tmp_path, data_home_exists=True
    )
    source = "https://example.test/course-ingest"
    course = _external_artifact(data_home, source)
    _response(responses, "plan", _plan(source))
    _response(responses, "run", _run(source, course))
    before = _snapshot(vault)
    request = IngestConnectorRequest(
        INGEST_CONNECTOR_SCHEMA_VERSION,
        "run_ingest_connector",
        "course",
        "coursedump",
        source,
        _ingest_digest("course", source),
        64 * 1024,
    )

    result = connector.collect(request)

    assert isinstance(result, IngestConnectorResult)
    assert result.connector == "coursedump"
    assert result.canonical_source_sha256 == request.canonical_source_sha256
    assert result.source_ref.startswith("coursedump/artifacts/")
    assert hashlib.sha256(result.content.encode()).hexdigest() == result.content_sha256
    assert source not in result.content
    assert str(data_home) not in result.content
    assert "raw-external-bytes" not in result.content
    assert _snapshot(vault) == before


def test_collect_rejects_unbound_source_hash_before_process_execution(tmp_path: Path):
    connector, _responses, _data, _vault, log, _marker = _setup(tmp_path)
    request = IngestConnectorRequest(
        INGEST_CONNECTOR_SCHEMA_VERSION,
        "run_ingest_connector",
        "course",
        "coursedump",
        "synthetic-source",
        "3" * 64,
        64 * 1024,
    )

    with pytest.raises(CoursedumpConnectorError, match="source-hash-binding"):
        connector.collect(request)

    assert not log.exists()


@pytest.mark.parametrize(
    "mutation",
    [
        lambda payload: payload.update(version="0.2.0"),
        lambda payload: payload.update(schema_version=True),
        lambda payload: payload["capabilities"].reverse(),
        lambda payload: payload["capabilities"][0].update(idempotency="changed"),
    ],
)
def test_capability_handshake_is_exact_before_operation(tmp_path: Path, mutation):
    connector, responses, _data, _vault, log, _marker = _setup(tmp_path)
    payload = _capabilities()
    mutation(payload)
    _response(responses, "capabilities", payload)
    _response(responses, "plan", _plan("synthetic-source"))

    with pytest.raises(CoursedumpConnectorError) as raised:
        connector.plan("synthetic-source")

    assert raised.value.category == "contract"
    assert _calls(log) == [["capabilities", "--json"]]


@pytest.mark.parametrize(
    "exit_code,category",
    [(75, "quota"), (111, "transient"), (1, "fatal"), (9, "transient")],
)
def test_exit_mapping_is_stable_and_diagnostics_are_not_exposed(
    tmp_path: Path, exit_code: int, category: str
):
    connector, responses, _data, _vault, _log, _marker = _setup(tmp_path)
    source = "synthetic-source"
    if exit_code == 1:
        payload = {
            "schema_version": 1,
            "source": None,
            "items": [],
            "estimate": None,
            "status": "failure",
            "error": "plan-failed",
        }
    else:
        payload = {"private": "must-not-propagate"}
    _response(
        responses,
        "plan",
        payload,
        exit_code=exit_code,
        stderr="credential detail must not propagate",
    )

    with pytest.raises(CoursedumpConnectorError) as raised:
        connector.plan(source)

    assert raised.value.category == category
    assert raised.value.returncode == exit_code
    assert "credential" not in str(raised.value)


def test_exit_one_with_malformed_envelope_is_contract_not_fatal(tmp_path: Path):
    connector, responses, _data, _vault, _log, _marker = _setup(tmp_path)
    _response(responses, "plan", {"status": "failure"}, exit_code=1)

    with pytest.raises(CoursedumpConnectorError) as raised:
        connector.plan("synthetic-source")

    assert raised.value.category == "contract"
    assert raised.value.code == "invalid-failure-envelope"


@pytest.mark.parametrize("stream", ["stdout", "stderr"])
def test_machine_streams_are_bounded_before_parsing(tmp_path: Path, stream: str):
    connector, responses, _data, _vault, _log, _marker = _setup(tmp_path)
    large = "x" * (64 * 1024 + 10)
    _response(
        responses,
        "plan",
        _plan("synthetic-source"),
        raw_stdout=large if stream == "stdout" else None,
        stderr=large if stream == "stderr" else "",
    )

    with pytest.raises(CoursedumpConnectorError) as raised:
        connector.plan("synthetic-source")

    assert raised.value.code == "machine-output-size"


def test_timeout_cleans_process_group_and_inherited_pipes(tmp_path: Path):
    connector, responses, _data, _vault, _log, marker = _setup(tmp_path, timeout=0.15)
    _response(responses, "plan", descendant_timeout=True)
    started = time.monotonic()

    with pytest.raises(CoursedumpConnectorError) as raised:
        connector.plan("synthetic-source")

    assert raised.value.category == "transient"
    assert time.monotonic() - started < 1.0
    time.sleep(0.9)
    assert not marker.exists()


def test_handshake_and_operation_share_one_monotonic_deadline(tmp_path: Path):
    connector, responses, _data, _vault, _log, _marker = _setup(tmp_path, timeout=0.25)
    _response(responses, "capabilities", _capabilities(), delay=0.14)
    _response(responses, "plan", _plan("synthetic-source"), delay=0.14)
    started = time.monotonic()

    with pytest.raises(CoursedumpConnectorError) as raised:
        connector.plan("synthetic-source")

    assert raised.value.code == "connector-timeout"
    assert raised.value.category == "transient"
    assert time.monotonic() - started < 0.4


def test_selector_setup_failure_reaps_child_and_closes_pipes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    connector, _responses, _data, _vault, _log, _marker = _setup(tmp_path)
    children = []
    popen = coursedump_module.subprocess.Popen

    def recording_popen(*args, **kwargs):
        child = popen(*args, **kwargs)
        children.append(child)
        return child

    class BrokenSelector:
        def __init__(self):
            raise RuntimeError("selector setup failed")

    monkeypatch.setattr(coursedump_module.subprocess, "Popen", recording_popen)
    monkeypatch.setattr(coursedump_module.selectors, "DefaultSelector", BrokenSelector)
    before = len(os.listdir("/dev/fd"))

    with pytest.raises(CoursedumpConnectorError) as raised:
        connector.plan("synthetic-source")

    assert raised.value.code == "connector-process-io"
    assert raised.value.category == "transient"
    assert len(children) == 1 and children[0].poll() is not None
    assert len(os.listdir("/dev/fd")) == before


def test_unknown_handshake_exit_is_transient(tmp_path: Path):
    connector, responses, _data, _vault, log, _marker = _setup(tmp_path)
    _response(responses, "capabilities", {"diagnostic": "bounded"}, exit_code=9)

    with pytest.raises(CoursedumpConnectorError) as raised:
        connector.plan("synthetic-source")

    assert raised.value.category == "transient"
    assert raised.value.returncode == 9
    assert _calls(log) == [["capabilities", "--json"]]


def test_source_is_one_argv_item_and_never_shell_expanded(tmp_path: Path):
    connector, responses, data_home, _vault, log, _marker = _setup(tmp_path)
    marker = tmp_path / "must-not-exist"
    source = f"synthetic-source;touch {marker}"
    _response(responses, "plan", _plan(source))

    connector.plan(source)

    assert not marker.exists()
    assert _calls(log)[1] == ["plan", source, "--data", str(data_home), "--json"]


def test_artifact_symlink_and_source_binding_fail_closed_without_fd_leak(
    tmp_path: Path,
):
    connector, responses, data_home, _vault, _log, _marker = _setup(
        tmp_path, data_home_exists=True
    )
    source = "synthetic-source"
    course = _external_artifact(data_home, source)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "manifest.jsonl").write_text("{}\n", "utf-8")
    (course / "manifest.jsonl").unlink()
    (course / "manifest.jsonl").symlink_to(outside / "manifest.jsonl")
    _response(responses, "run", _run(source, course))
    before = len(os.listdir("/dev/fd"))

    for _ in range(25):
        with pytest.raises(CoursedumpConnectorError):
            connector.run(source)

    assert len(os.listdir("/dev/fd")) == before


def test_artifact_registration_rejects_symlinked_data_home_without_fd_leak(
    tmp_path: Path,
):
    connector, responses, data_home, _vault, _log, _marker = _setup(
        tmp_path, data_home_exists=True
    )
    source = "synthetic-source"
    foreign_home = tmp_path / "foreign-data"
    foreign_course = _external_artifact(foreign_home, source)
    data_home.rmdir()
    data_home.symlink_to(foreign_home, target_is_directory=True)
    lexical_course = data_home / "out" / foreign_course.name
    _response(responses, "run", _run(source, lexical_course))
    before = len(os.listdir("/dev/fd"))

    with pytest.raises(CoursedumpConnectorError, match="data-home"):
        connector.run(source)

    assert len(os.listdir("/dev/fd")) == before


@pytest.mark.parametrize("initially_exists", [False, True])
def test_data_home_creation_or_replacement_during_dry_operation_is_rejected(
    tmp_path: Path, initially_exists: bool
):
    connector, responses, data_home, _vault, _log, _marker = _setup(
        tmp_path, data_home_exists=initially_exists
    )
    source = "synthetic-source"
    _response(responses, "plan", _plan(source), mutate_data_home=True)

    with pytest.raises(CoursedumpConnectorError, match="data-home"):
        connector.plan(source)

    assert data_home.is_dir() and not data_home.is_symlink()
    if initially_exists:
        assert data_home.with_name(data_home.name + "-held").is_dir()


def test_machine_json_with_non_utf8_scalar_key_is_normalized_to_contract_error(
    tmp_path: Path,
):
    connector, responses, _data, _vault, _log, _marker = _setup(tmp_path)
    payload = _plan("synthetic-source")
    payload["\ud800"] = True
    _response(responses, "plan", payload)

    with pytest.raises(CoursedumpConnectorError, match="noncanonical"):
        connector.plan("synthetic-source")


def test_constructor_rejects_vault_overlap_and_generic_malformed_values(
    tmp_path: Path,
):
    fake = tmp_path / "fake"
    fake.write_text("#!/bin/sh\nexit 0\n", "utf-8")
    fake.chmod(0o755)
    vault = tmp_path / "vault"
    vault.mkdir()

    with pytest.raises(CoursedumpConnectorError, match="overlaps"):
        CoursedumpConnector(
            data_home=vault / "coursedump",
            command=(str(fake),),
            cwd=tmp_path,
            env={"PATH": os.environ.get("PATH", "")},
            forbidden_roots=(vault,),
        )
    with pytest.raises(CoursedumpConnectorError):
        CoursedumpConnector(
            data_home=tmp_path / "data",
            command=("sh", "-c", "echo unsafe"),
            cwd="relative",
            env={"PATH": os.environ.get("PATH", "")},
        )


@pytest.mark.parametrize(
    "mutation",
    ["empty", "partial", "noncanonical", "total", "done", "status"],
)
def test_registration_rejects_partial_or_inconsistent_external_manifest(
    tmp_path: Path, mutation: str
):
    connector, responses, data_home, _vault, _log, _marker = _setup(
        tmp_path, data_home_exists=True
    )
    source = "synthetic-source"
    course = _external_artifact(data_home, source)
    payload = _run(source, course)
    manifest = course / "manifest.jsonl"
    if mutation == "empty":
        manifest.write_bytes(b"")
    elif mutation == "partial":
        manifest.write_bytes(manifest.read_bytes().removesuffix(b"\n"))
    elif mutation == "noncanonical":
        rows = [json.loads(line) for line in manifest.read_text("utf-8").splitlines()]
        manifest.write_text(
            "".join(
                json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n"
                for row in rows
            ),
            "utf-8",
        )
    elif mutation == "total":
        payload["artifact"]["total"] = 4
    elif mutation == "done":
        (course / "text/handout.pdf.md").unlink()
    else:
        payload = _run(source, course, errors=1)
    _response(responses, "run", payload)

    with pytest.raises(CoursedumpConnectorError, match="manifest"):
        connector.run(source)


def test_status_errors_are_bound_to_external_error_log(tmp_path: Path):
    connector, responses, data_home, _vault, _log, _marker = _setup(
        tmp_path, data_home_exists=True
    )
    source = "synthetic-source"
    course = _external_artifact(data_home, source)
    payload = _status(source, course)
    payload["runs"][0]["errors"] = 1
    _response(responses, "status", payload)

    with pytest.raises(CoursedumpConnectorError, match="error count"):
        connector.status()


@pytest.mark.parametrize("operation", ["run", "status"])
def test_durable_canonical_error_rows_accept_matching_report(
    tmp_path: Path, operation: str
):
    connector, responses, data_home, _vault, _log, _marker = _setup(
        tmp_path, data_home_exists=True
    )
    source = "synthetic-source"
    course = _external_artifact(data_home, source)
    (course / "text/handout.pdf.md").unlink()
    _write_errors(course, [_error_row()])
    if operation == "run":
        _response(responses, "run", _run(source, course, errors=1))
        result = connector.run(source)
        assert result.status == "completed-with-errors"
        assert result.artifact.errors == 1
    else:
        payload = _status(source, course)
        payload["runs"][0].update(done=2, errors=1)
        _response(responses, "status", payload)
        result = connector.status()
        assert result.artifacts[0].errors == 1


@pytest.mark.parametrize("operation", ["run", "status"])
def test_error_log_same_inode_rewrite_with_restored_mtime_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, operation: str
):
    connector, responses, data_home, _vault, _log, _marker = _setup(
        tmp_path, data_home_exists=True
    )
    source = "synthetic-source"
    course = _external_artifact(data_home, source)
    (course / "text/handout.pdf.md").unlink()
    _write_errors(course, [_error_row()])
    errors_path = course / "errors.jsonl"
    original_raw = errors_path.read_bytes()
    altered_raw = original_raw.replace(b"synthetic", b"alternate")
    assert altered_raw != original_raw
    assert len(altered_raw) == len(original_raw)
    original_metadata = errors_path.stat()

    if operation == "run":
        _response(responses, "run", _run(source, course, errors=1))
    else:
        payload = _status(source, course)
        payload["runs"][0].update(done=2, errors=1)
        _response(responses, "status", payload)

    original_open = coursedump_module.os.open
    original_fstat = coursedump_module.os.fstat
    errors_fd: int | None = None
    error_fstats = 0

    def capture_open(path, flags, mode=0o777, *, dir_fd=None):
        nonlocal errors_fd
        descriptor = original_open(path, flags, mode, dir_fd=dir_fd)
        if path == "errors.jsonl":
            errors_fd = descriptor
        return descriptor

    def rewrite_before_final_fstat(descriptor):
        nonlocal error_fstats
        if descriptor == errors_fd:
            error_fstats += 1
            if error_fstats == 2:
                errors_path.write_bytes(altered_raw)
                os.utime(
                    errors_path,
                    ns=(original_metadata.st_atime_ns, original_metadata.st_mtime_ns),
                )
        return original_fstat(descriptor)

    monkeypatch.setattr(coursedump_module.os, "open", capture_open)
    monkeypatch.setattr(coursedump_module.os, "fstat", rewrite_before_final_fstat)

    with pytest.raises(CoursedumpConnectorError, match="changed during read"):
        if operation == "run":
            connector.run(source)
        else:
            connector.status()
    assert errors_path.read_bytes() == altered_raw
    assert errors_path.stat().st_ino == original_metadata.st_ino
    assert errors_path.stat().st_size == original_metadata.st_size
    assert errors_path.stat().st_mtime_ns == original_metadata.st_mtime_ns
    assert errors_path.stat().st_ctime_ns != original_metadata.st_ctime_ns


@pytest.mark.parametrize("operation", ["run", "status"])
def test_zero_reported_errors_requires_absent_or_empty_durable_log(
    tmp_path: Path, operation: str
):
    connector, responses, data_home, _vault, _log, _marker = _setup(
        tmp_path, data_home_exists=True
    )
    source = "synthetic-source"
    course = _external_artifact(data_home, source)
    _write_errors(course, [_error_row()])
    if operation == "run":
        _response(responses, "run", _run(source, course))
    else:
        _response(responses, "status", _status(source, course))

    with pytest.raises(CoursedumpConnectorError, match="error count"):
        if operation == "run":
            connector.run(source)
        else:
            connector.status()


@pytest.mark.parametrize("operation", ["run", "status"])
@pytest.mark.parametrize(
    "malformation",
    [
        "missing",
        "not-json",
        "partial",
        "duplicate",
        "wrong-type",
        "noncanonical",
        "oversized",
        "count",
    ],
)
def test_run_and_status_reject_invalid_or_inconsistent_error_rows(
    tmp_path: Path, operation: str, malformation: str
):
    connector, responses, data_home, _vault, _log, _marker = _setup(
        tmp_path, data_home_exists=True
    )
    source = "synthetic-source"
    course = _external_artifact(data_home, source)
    (course / "text/handout.pdf.md").unlink()
    errors_path = course / "errors.jsonl"
    row = _error_row()
    if malformation == "not-json":
        errors_path.write_bytes(b"not-json\n")
    elif malformation == "partial":
        errors_path.write_text(json.dumps(row, ensure_ascii=False), "utf-8")
    elif malformation == "duplicate":
        errors_path.write_bytes(
            b'{"ts":"2026-08-20T12:00:00","rel":"handout.pdf",'
            b'"error":"first","error":"second","trace":"trace"}\n'
        )
    elif malformation == "wrong-type":
        row["ts"] = 20260820
        _write_errors(course, [row])
    elif malformation == "noncanonical":
        errors_path.write_text(
            json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n",
            "utf-8",
        )
    elif malformation == "oversized":
        row["error"] = "x" * (16 * 1024 + 1)
        _write_errors(course, [row])
    elif malformation == "count":
        _write_errors(course, [row, row])
    if operation == "run":
        _response(responses, "run", _run(source, course, errors=1))
    else:
        payload = _status(source, course)
        payload["runs"][0].update(done=2, errors=1)
        _response(responses, "status", payload)

    with pytest.raises(CoursedumpConnectorError):
        if operation == "run":
            connector.run(source)
        else:
            connector.status()


@pytest.mark.parametrize("location", ["machine", "source-manifest"])
def test_json_integers_are_bounded_to_signed_64_bit(tmp_path: Path, location: str):
    connector, responses, data_home, _vault, _log, _marker = _setup(
        tmp_path, data_home_exists=True
    )
    source = "synthetic-source"
    if location == "machine":
        payload = _plan(source)
        payload["items"][0]["size_bytes"] = 2**63
        _response(responses, "plan", payload)
        operation = connector.plan
    else:
        course = _external_artifact(data_home, source)
        source_payload = json.loads((course / "source.json").read_bytes())
        source_payload["extra_integer"] = 2**63
        (course / "source.json").write_text(json.dumps(source_payload), "utf-8")
        _response(responses, "run", _run(source, course))
        operation = connector.run

    with pytest.raises(CoursedumpConnectorError):
        operation(source)


def test_artifact_manifest_rejects_recomputed_unbound_fields(tmp_path: Path):
    connector, responses, data_home, _vault, _log, _marker = _setup(
        tmp_path, data_home_exists=True
    )
    source = "synthetic-source"
    course = _external_artifact(data_home, source)
    _response(responses, "run", _run(source, course))
    artifact = connector.run(source).artifact

    with pytest.raises(CoursedumpConnectorError, match="hash-binding"):
        render_artifact_manifest(replace(artifact, total=4))
    payload = json.loads(render_artifact_manifest(artifact))
    payload["unknown"] = True
    with pytest.raises(CoursedumpConnectorError, match="artifact-manifest"):
        parse_artifact_manifest(_canonical(payload))
    with pytest.raises(CoursedumpConnectorError, match="duplicate"):
        parse_artifact_manifest(b'{"schema_version":1,"schema_version":1}\n')


def test_no_sibling_package_import_or_vault_copy_implementation() -> None:
    package = Path(__file__).resolve().parents[1] / (
        "tool_life_os_runtime/ext/connectors/coursedump/connector.py"
    )
    source = package.read_text("utf-8")

    assert "import coursedump" not in source
    assert "shell=True" not in source
    assert "copyfile" not in source
    assert "copytree" not in source
    assert shutil.which("python3") is not None
    assert ZERO not in source
