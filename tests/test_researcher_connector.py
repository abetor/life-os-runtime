"""P4-02 researcher process, wait-state, and final-topic connector contract."""

from __future__ import annotations

from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import time

import pytest

import tool_life_os_runtime.ext.connectors.researcher.connector as connector_module
from tool_life_os_runtime.ext.connectors.llmwiki import (
    HashedRecord,
    LlmWikiConnector,
    TopicSnapshot,
    WikiPage,
)
from tool_life_os_runtime.ext.connectors.probes import DEFAULT_SPECS
from tool_life_os_runtime.ext.connectors.researcher import (
    RESEARCHER_CONNECTOR_SCHEMA_VERSION,
    ResearcherConnector,
    ResearcherConnectorError,
)


SPEC = next(item for item in DEFAULT_SPECS if item.tool == "researcher")
ZERO = "0" * 64
UPSTREAM_SMOKE_ROOT = os.environ.get("LIFEOS_RESEARCHER_SMOKE_ROOT", "")
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
response = json.loads((root / f"{operation}.json").read_text("utf-8"))
if response.get("descendant"):
    subprocess.Popen([
        sys.executable,
        "-c",
        "import os,time; from pathlib import Path; time.sleep(1); "
        "Path(os.environ['CHILD_MARKER']).write_text('survived','utf-8')",
    ])
    time.sleep(60)
if response.get("move_root"):
    topics = Path(os.environ["TOPICS_ROOT"])
    topics.rename(topics.with_name(topics.name + "-old"))
    topics.mkdir()
if response.get("move_topic"):
    topic = Path(response["move_topic"])
    topic.rename(topic.with_name(topic.name + "-old"))
    topic.mkdir()
time.sleep(response.get("delay", 0))
sys.stderr.write(response.get("stderr", ""))
if "raw" in response:
    sys.stdout.write(response["raw"])
else:
    sys.stdout.write(json.dumps(response["payload"], ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n")
raise SystemExit(response.get("exit", 0))
"""


def _canonical(value: object) -> str:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    )


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")[:-1]).hexdigest()


def _capabilities(version: str = "0.1.0") -> dict[str, object]:
    return {
        "schema_version": 1,
        "tool": "researcher",
        "version": version,
        "capabilities": [item.to_dict() for item in SPEC.expected_capabilities],
    }


def _response(
    responses: Path,
    operation: str,
    payload: object | None = None,
    *,
    exit_code: int = 0,
    raw: str | None = None,
    stderr: str = "",
    **flags: object,
) -> None:
    value: dict[str, object] = {"exit": exit_code, "stderr": stderr, **flags}
    value["payload" if raw is None else "raw"] = payload if raw is None else raw
    (responses / f"{operation}.json").write_text(json.dumps(value), "utf-8")


class Boundary:
    def __init__(self, snapshot: TopicSnapshot | None = None) -> None:
        self.snapshot = snapshot
        self.paths: list[Path] = []

    def load_topic(self, topic_dir: str | os.PathLike[str]) -> TopicSnapshot:
        self.paths.append(Path(topic_dir))
        if self.snapshot is None:
            raise ValueError("private validation detail")
        return self.snapshot


def _setup(
    tmp_path: Path,
    *,
    timeout: float = 2.0,
    boundary=None,
    topics_root: Path | None = None,
):
    topics = topics_root or tmp_path / "topics"
    topics.mkdir(parents=True, exist_ok=True)
    responses = tmp_path / "responses"
    responses.mkdir(parents=True)
    script = tmp_path / "fake_researcher.py"
    script.write_text(FAKE, "utf-8")
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    log = tmp_path / "argv.jsonl"
    _response(responses, "capabilities", _capabilities())
    env = {
        "FAKE_RESPONSES": str(responses),
        "FAKE_LOG": str(log),
        "TOPICS_ROOT": str(topics),
        "CHILD_MARKER": str(tmp_path / "child-survived"),
    }
    connector = ResearcherConnector(
        topics_root=topics,
        command=(sys.executable, str(script)),
        cwd=tmp_path,
        env=env,
        topic_boundary=boundary or Boundary(),
        timeout=timeout,
    )
    return connector, topics, responses, log


def _topic(topics: Path, name: str = "topic-a") -> Path:
    result = topics / name
    result.mkdir()
    return result


def _run_payload(topic: Path, status: str = "running", phase: str = "collecting"):
    return {
        "schema_version": 1,
        "status": status,
        "topic_dir": str(topic),
        "phase": phase,
    }


def _source_plan_payload(
    *,
    source_kind: str = "local-markdown",
    relative_path: str = "lesson.md",
    title: str = "Lesson",
    document_sha256: str = "d" * 64,
    size_bytes: int = 8,
    window_count: int = 1,
) -> dict[str, object]:
    document_id = (
        "doc_"
        + hashlib.sha256(
            (relative_path + "\0" + document_sha256).encode("utf-8")
        ).hexdigest()[:24]
    )
    document = {
        "document_id": document_id,
        "relative_path": relative_path,
        "title": title,
        "sha256": document_sha256,
        "size_bytes": size_bytes,
        "window_count": window_count,
    }
    payload = {
        "schema_version": 1,
        "plan_id": "",
        "status": "waiting_human",
        "source_kind": source_kind,
        "corpus_sha256": "",
        "documents": [document],
        "window": {"max_chars": 12000, "overlap_chars": 512},
    }
    return _rebind_source_plan(payload)


def _rebind_source_plan(payload: dict[str, object]) -> dict[str, object]:
    body = {
        "schema_version": 1,
        "source_kind": payload["source_kind"],
        "documents": payload["documents"],
        "window": payload["window"],
    }
    corpus_sha256 = _digest(body)
    payload["corpus_sha256"] = corpus_sha256
    payload["plan_id"] = (
        "plan_"
        + hashlib.sha256(
            ("source-import-v1:" + corpus_sha256).encode("ascii")
        ).hexdigest()[:24]
    )
    return payload


def _record(
    record_id: str, payload: dict[str, object], *, source: bool
) -> HashedRecord:
    payload_hash = _digest(payload)
    stable_hash = (
        _digest({"content_sha256": None, "payload_sha256": payload_hash})
        if source
        else payload_hash
    )
    return HashedRecord(record_id, payload, stable_hash, payload_hash)


def _snapshot(path: Path) -> TopicSnapshot:
    source_id = "src_aaaaaaaaaaaa"
    claim_id = "clm_bbbbbbbbbbbb"
    source = _record(source_id, {"id": source_id, "kind": "local"}, source=True)
    claim = _record(
        claim_id,
        {"id": claim_id, "status": "verified", "evidence": []},
        source=False,
    )
    frontmatter = {
        "id": "wik_cccccccccccc",
        "title": "Page",
        "claims": [claim_id],
        "updated_at": "2026-01-15T09:02:00+00:00",
    }
    wiki_text = (
        "---\n"
        "id: wik_cccccccccccc\n"
        "title: Page\n"
        "claims:\n"
        f"  - {claim_id}\n"
        "updated_at: 2026-01-15T09:02:00+00:00\n"
        "---\n\n"
        "# Page\n"
    )
    wiki = WikiPage(
        "page.md",
        frontmatter,
        "# Page",
        hashlib.sha256(wiki_text.encode("utf-8")).hexdigest(),
    )
    manifest = {"slug": path.name}
    manifest_hash = _digest(manifest)
    snapshot_payload = {
        "schema_version": 1,
        "spec_version": "0.1.0",
        "manifest_sha256": manifest_hash,
        "sources": [[source_id, source.sha256]],
        "final_claims": [[claim_id, claim.sha256]],
        "wiki_pages": [[wiki.relative_ref, wiki.sha256]],
    }
    snapshot_hash = _digest(snapshot_payload)
    return TopicSnapshot(
        1,
        "0.1.0",
        "sha256:" + hashlib.sha256(os.fsencode(path)).hexdigest(),
        manifest,
        manifest_hash,
        (source,),
        (claim,),
        (wiki,),
        ((source_id, source.sha256),),
        snapshot_hash,
    )


def test_public_schema_and_exact_argv_for_all_machine_operations(
    tmp_path: Path,
) -> None:
    connector, topics, responses, log = _setup(tmp_path)
    topic = _topic(topics)
    _response(responses, "start", _run_payload(topic))
    _response(
        responses,
        "status",
        {"schema_version": 1, "status": "running", "phase": "collecting", "cycles": 1},
    )
    _response(responses, "resume", _run_payload(topic, "done", "done"))
    _response(responses, "extend", _run_payload(topic, "running", "planned"))

    assert (
        connector.start("Synthetic topic").schema_version
        == RESEARCHER_CONNECTOR_SCHEMA_VERSION
    )
    assert connector.status("topic-a").status == "running"
    assert connector.resume("topic-a").status == "done"
    assert connector.extend("topic-a").phase == "planned"

    calls = [json.loads(line) for line in log.read_text("utf-8").splitlines()]
    assert calls == [
        ["capabilities", "--json"],
        ["start", "Synthetic topic", "--base", str(topics), "--json"],
        ["capabilities", "--json"],
        ["status", str(topic)],
        ["capabilities", "--json"],
        ["resume", str(topic), "--json"],
        ["capabilities", "--json"],
        ["extend", str(topic), "--json"],
    ]


@pytest.mark.parametrize("operation", ["start", "resume", "extend"])
def test_exit_76_is_successful_wait_result_with_semantic_event(
    tmp_path: Path, operation: str
) -> None:
    connector, topics, responses, _ = _setup(tmp_path)
    topic = _topic(topics)
    _response(
        responses,
        operation,
        _run_payload(topic, "waiting_human", "planned"),
        exit_code=76,
    )

    result = (
        connector.start("Synthetic")
        if operation == "start"
        else getattr(connector, operation)("topic-a")
    )

    assert result.status == "waiting_human"
    assert result.upstream_exit_code == 76
    assert result.runtime_exit_code == 0
    assert result.event is not None
    assert result.event.status == "waiting_human"
    assert result.event.topic_ref == result.topic_ref
    assert result.event.event_type == "researcher-waiting-human"
    assert result.event.surface == "gated" and result.event.requires_receipt is True
    assert str(topic) not in repr(result)


@pytest.mark.parametrize(
    ("exit_code", "category", "runtime_exit"),
    [(75, "quota", 75), (111, "transient", 111), (42, "transient", 111)],
)
def test_retry_exit_classes_are_normalized_and_propagated(
    tmp_path: Path, exit_code: int, category: str, runtime_exit: int
) -> None:
    connector, topics, responses, _ = _setup(tmp_path)
    topic = _topic(topics)
    _response(responses, "resume", _run_payload(topic, "quota"), exit_code=exit_code)
    with pytest.raises(ResearcherConnectorError) as caught:
        connector.resume("topic-a")
    assert caught.value.category == category
    assert caught.value.returncode == exit_code
    assert caught.value.runtime_exit_code == runtime_exit
    assert str(topic) not in str(caught.value)


def test_exit_one_requires_generic_failure_envelope_and_is_fatal(
    tmp_path: Path,
) -> None:
    connector, topics, responses, _ = _setup(tmp_path)
    _topic(topics)
    _response(
        responses,
        "resume",
        {
            "schema_version": 1,
            "status": "error",
            "topic_dir": None,
            "phase": None,
            "error": {"code": "invalid_checkpoint"},
        },
        exit_code=1,
        stderr="/" + "Users/private/secret\n",
    )
    with pytest.raises(ResearcherConnectorError) as caught:
        connector.resume("topic-a")
    assert caught.value.category == "fatal"
    assert caught.value.code == "researcher-resume-failed"
    assert "secret" not in str(caught.value)

    _response(responses, "resume", raw="not-json\n", exit_code=1)
    with pytest.raises(ResearcherConnectorError) as malformed:
        connector.resume("topic-a")
    assert malformed.value.category == "contract"
    assert malformed.value.code == "invalid-failure-envelope"


def test_exact_handshake_rejects_version_capability_and_malformed_json(
    tmp_path: Path,
) -> None:
    connector, topics, responses, _ = _setup(tmp_path)
    topic = _topic(topics)
    _response(
        responses,
        "status",
        {"schema_version": 1, "status": "running", "phase": "planned"},
    )
    _response(responses, "capabilities", _capabilities("0.2.0"))
    with pytest.raises(ResearcherConnectorError, match="capability-contract-mismatch"):
        connector.status(topic.name)

    _response(
        responses, "capabilities", raw='{"schema_version":1,"schema_version":1}\n'
    )
    with pytest.raises(ResearcherConnectorError, match="duplicate-machine-field"):
        connector.status(topic.name)


def test_surrogate_machine_object_key_is_normalized(tmp_path: Path) -> None:
    connector, topics, responses, _ = _setup(tmp_path)
    topic = _topic(topics)
    _response(responses, "capabilities", raw='{"\\ud800":1}\n')

    with pytest.raises(ResearcherConnectorError, match="noncanonical-machine-output"):
        connector.status(topic.name)


def test_source_plan_is_bounded_typed_and_waiting_human(tmp_path: Path) -> None:
    connector, _topics, responses, log = _setup(tmp_path)
    source = tmp_path / "corpus"
    source.mkdir()
    payload = _source_plan_payload()
    _response(responses, "source-plan", payload, exit_code=76)

    result = connector.source_plan(source, kind="local-markdown")

    assert result.status == "waiting_human"
    assert result.runtime_exit_code == 0
    assert result.documents[0].relative_path == "lesson.md"
    assert result.event.semantic_key.endswith(str(payload["corpus_sha256"]))
    assert result.event.event_type == "researcher-source-plan"
    calls = [json.loads(line) for line in log.read_text("utf-8").splitlines()]
    assert calls[-1] == [
        "source-plan",
        str(source),
        "--kind",
        "local-markdown",
        "--json",
    ]
    assert str(source) not in repr(result)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: {**value, "status": "running"},
        lambda value: {**value, "documents": [{"document_id": True}]},
        lambda value: {**value, "window": {"max_chars": 12001, "overlap_chars": 512}},
        lambda value: {**value, "extra": 1},
    ],
)
def test_source_plan_rejects_malformed_contract(tmp_path: Path, mutation) -> None:
    connector, _topics, responses, _ = _setup(tmp_path)
    source = tmp_path / "corpus"
    source.mkdir()
    valid = _source_plan_payload()
    _response(responses, "source-plan", mutation(valid), exit_code=76)
    with pytest.raises(ResearcherConnectorError):
        connector.source_plan(source)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: {**value, "schema_version": True},
        lambda value: {**value, "documents": []},
        lambda value: {**value, "plan_id": "plan_" + "0" * 24},
        lambda value: {**value, "corpus_sha256": "0" * 64},
        lambda value: {
            **value,
            "documents": [{**value["documents"][0], "document_id": "doc_" + "0" * 24}],
        },
        lambda value: {
            **value,
            "documents": [{**value["documents"][0], "window_count": 384}],
        },
    ],
)
def test_source_plan_rejects_noncanonical_upstream_bindings(
    tmp_path: Path, mutation
) -> None:
    connector, _topics, responses, _ = _setup(tmp_path)
    source = tmp_path / "corpus"
    source.mkdir()
    _response(
        responses,
        "source-plan",
        mutation(_source_plan_payload()),
        exit_code=76,
    )

    with pytest.raises(ResearcherConnectorError):
        connector.source_plan(source, kind="local-markdown")


def test_source_plan_binds_explicit_kind_and_total_document_size(
    tmp_path: Path,
) -> None:
    connector, _topics, responses, _ = _setup(tmp_path)
    source = tmp_path / "corpus"
    source.mkdir()
    wrong_kind = _source_plan_payload(source_kind="coursedump-manifest")
    _response(responses, "source-plan", wrong_kind, exit_code=76)
    with pytest.raises(ResearcherConnectorError, match="invalid-source-kind"):
        connector.source_plan(source, kind="local-markdown")

    documents = [
        _source_plan_payload(
            relative_path=f"lesson-{index:02}.md",
            size_bytes=2 * 1024 * 1024,
        )["documents"][0]
        for index in range(9)
    ]
    oversized = _source_plan_payload()
    oversized["documents"] = documents
    _rebind_source_plan(oversized)
    _response(responses, "source-plan", oversized, exit_code=76)
    with pytest.raises(ResearcherConnectorError, match="invalid-source-documents"):
        connector.source_plan(source, kind="local-markdown")


def test_topic_root_and_named_topic_replacement_are_rejected(tmp_path: Path) -> None:
    connector, topics, responses, _ = _setup(tmp_path)
    topic = _topic(topics)
    _response(
        responses,
        "status",
        {"schema_version": 1, "status": "running", "phase": "planned"},
        move_topic=str(topic),
    )
    with pytest.raises(ResearcherConnectorError, match="topic-artifact-moved"):
        connector.status(topic.name)

    connector2, topics2, responses2, _ = _setup(tmp_path / "second")
    topic2 = _topic(topics2)
    _response(
        responses2,
        "status",
        {"schema_version": 1, "status": "running", "phase": "planned"},
        move_root=True,
    )
    with pytest.raises(ResearcherConnectorError, match="topics-root-moved"):
        connector2.status(topic2.name)


def test_topic_replacement_during_handshake_stops_before_mutating_operation(
    tmp_path: Path,
) -> None:
    connector, topics, responses, log = _setup(tmp_path)
    topic = _topic(topics)
    _response(
        responses,
        "capabilities",
        _capabilities(),
        move_topic=str(topic),
    )
    _response(responses, "resume", _run_payload(topic))

    with pytest.raises(ResearcherConnectorError, match="topic-artifact-moved"):
        connector.resume(topic.name)

    calls = [json.loads(line) for line in log.read_text("utf-8").splitlines()]
    assert calls == [["capabilities", "--json"]]


def test_timeout_kills_process_group_and_does_not_wait_for_inherited_pipes(
    tmp_path: Path,
) -> None:
    connector, topics, responses, _ = _setup(tmp_path, timeout=0.15)
    topic = _topic(topics)
    _response(
        responses,
        "status",
        {"schema_version": 1, "status": "running", "phase": "planned"},
        descendant=True,
    )
    started = time.monotonic()
    with pytest.raises(ResearcherConnectorError, match="connector-timeout"):
        connector.status(topic.name)
    assert time.monotonic() - started < 0.8
    time.sleep(1.05)
    assert not (tmp_path / "child-survived").exists()


def test_selector_setup_failure_reaps_child_closes_streams_and_fds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    connector, topics, responses, _ = _setup(tmp_path, timeout=0.3)
    topic = _topic(topics)
    _response(
        responses,
        "status",
        {"schema_version": 1, "status": "running", "phase": "planned"},
        delay=60,
    )
    real_popen = connector_module.subprocess.Popen
    observed: dict[str, object] = {}

    def capture(*args, **kwargs):
        process = real_popen(*args, **kwargs)
        observed["process"] = process
        observed["stdout"] = process.stdout
        observed["stderr"] = process.stderr
        return process

    def fail_selector():
        raise OSError("selector unavailable")

    monkeypatch.setattr(connector_module.subprocess, "Popen", capture)
    monkeypatch.setattr(connector_module.selectors, "DefaultSelector", fail_selector)
    before = len(os.listdir("/dev/fd"))
    with pytest.raises(ResearcherConnectorError, match="connector-process-io"):
        connector.status(topic.name)
    after = len(os.listdir("/dev/fd"))
    process = observed["process"]
    assert process.poll() is not None
    assert observed["stdout"].closed and observed["stderr"].closed
    assert after == before


def test_import_validates_through_boundary_and_registers_only_refs_and_hashes(
    tmp_path: Path,
) -> None:
    boundary = Boundary()
    connector, topics, _responses, _ = _setup(tmp_path, boundary=boundary)
    topic = _topic(topics)
    snapshot = _snapshot(topic)
    boundary.snapshot = snapshot
    _response(
        _responses,
        "status",
        {"schema_version": 1, "status": "done", "phase": "done"},
    )

    result = connector.import_topic(topic.name)

    assert boundary.paths == [topic]
    assert result.status == "proposed"
    assert result.review.topic_snapshot is snapshot
    assert result.review.source_sha256 == snapshot.snapshot_sha256
    registration = result.registration
    assert registration.sources[0].logical_ref.endswith("/sources/src_aaaaaaaaaaaa")
    assert registration.claims[0].logical_ref.endswith("/claims/clm_bbbbbbbbbbbb")
    assert registration.wiki[0].logical_ref.endswith("/wiki/page.md")
    assert len(registration.registration_sha256) == 64
    assert "/Users/" not in repr(registration)

    replayed = connector.import_topic(topic.name)
    assert replayed == result
    assert boundary.paths == [topic, topic]


def test_import_rejects_nonfinal_topic_before_validation(tmp_path: Path) -> None:
    boundary = Boundary()
    connector, topics, responses, _ = _setup(tmp_path, boundary=boundary)
    topic = _topic(topics)
    boundary.snapshot = _snapshot(topic)
    _response(
        responses,
        "status",
        {"schema_version": 1, "status": "running", "phase": "synthesizing"},
    )

    with pytest.raises(ResearcherConnectorError, match="topic-not-final"):
        connector.import_topic(topic.name)

    assert boundary.paths == []


def test_import_rejects_invalid_snapshot_and_moved_topic(tmp_path: Path) -> None:
    boundary = Boundary()
    connector, topics, _responses, _ = _setup(tmp_path, boundary=boundary)
    topic = _topic(topics)
    boundary.snapshot = replace(_snapshot(topic), snapshot_sha256="bad")
    _response(
        _responses,
        "status",
        {"schema_version": 1, "status": "done", "phase": "done"},
    )
    with pytest.raises(ResearcherConnectorError, match="topic-snapshot-hash-binding"):
        connector.import_topic(topic.name)

    class MovingBoundary(Boundary):
        def load_topic(self, topic_dir):
            path = Path(topic_dir)
            path.rename(path.with_name(path.name + "-old"))
            path.mkdir()
            return _snapshot(path)

    second = tmp_path / "second"
    connector2, topics2, _responses2, _ = _setup(second, boundary=MovingBoundary())
    topic2 = _topic(topics2)
    _response(
        _responses2,
        "status",
        {"schema_version": 1, "status": "done", "phase": "done"},
    )
    with pytest.raises(ResearcherConnectorError, match="topic-artifact-moved"):
        connector2.import_topic(topic2.name)


def test_import_binds_done_status_to_the_same_named_topic_inode(tmp_path: Path) -> None:
    boundary = Boundary()
    connector, topics, responses, _ = _setup(tmp_path, boundary=boundary)
    topic = _topic(topics)
    boundary.snapshot = _snapshot(topic)
    _response(
        responses,
        "status",
        {"schema_version": 1, "status": "done", "phase": "done"},
    )
    real_status = connector.status

    def status_then_replace(name: str):
        result = real_status(name)
        topic.rename(topic.with_name(topic.name + "-old"))
        topic.mkdir()
        boundary.snapshot = _snapshot(topic)
        return result

    connector.status = status_then_replace  # type: ignore[method-assign]

    with pytest.raises(ResearcherConnectorError, match="topic-artifact-moved"):
        connector.import_topic(topic.name)

    assert boundary.paths == []


@pytest.mark.parametrize("part", ["source-payload", "source-content", "claim", "wiki"])
def test_import_deeply_rehashes_detached_topic_snapshot(
    tmp_path: Path, part: str
) -> None:
    boundary = Boundary()
    connector, topics, responses, _ = _setup(tmp_path, boundary=boundary)
    topic = _topic(topics)
    snapshot = _snapshot(topic)
    if part == "source-payload":
        source = snapshot.sources[0]
        snapshot = replace(
            snapshot,
            sources=(replace(source, payload={**source.payload, "kind": "forged"}),),
        )
    elif part == "source-content":
        source = snapshot.sources[0]
        snapshot = replace(snapshot, sources=(replace(source, content="forged"),))
    elif part == "claim":
        claim = snapshot.final_claims[0]
        snapshot = replace(
            snapshot,
            final_claims=(replace(claim, payload={**claim.payload, "text": "forged"}),),
        )
    else:
        page = snapshot.wiki_pages[0]
        snapshot = replace(
            snapshot, wiki_pages=(replace(page, body=page.body + "\nforged"),)
        )
    boundary.snapshot = snapshot
    _response(
        responses,
        "status",
        {"schema_version": 1, "status": "done", "phase": "done"},
    )

    with pytest.raises(ResearcherConnectorError, match="hash-binding"):
        connector.import_topic(topic.name)


def test_connector_never_writes_runtime_review_or_runstore(tmp_path: Path) -> None:
    connector, topics, responses, _ = _setup(tmp_path)
    topic = _topic(topics)
    _response(
        responses,
        "resume",
        _run_payload(topic, "waiting_human", "planned"),
        exit_code=76,
    )
    before = {path.relative_to(tmp_path).as_posix() for path in tmp_path.rglob("*")}
    connector.resume(topic.name)
    after = {path.relative_to(tmp_path).as_posix() for path in tmp_path.rglob("*")}
    assert after - before == {"argv.jsonl"}


def test_repeated_status_calls_close_all_process_descriptors(tmp_path: Path) -> None:
    connector, topics, responses, _ = _setup(tmp_path)
    topic = _topic(topics)
    _response(
        responses,
        "status",
        {"schema_version": 1, "status": "running", "phase": "planned"},
    )
    before = len(os.listdir("/dev/fd"))
    for _ in range(24):
        connector.status(topic.name)
    assert len(os.listdir("/dev/fd")) == before


def test_handshake_and_operation_share_one_total_deadline(tmp_path: Path) -> None:
    connector, topics, responses, _ = _setup(tmp_path, timeout=0.2)
    topic = _topic(topics)
    _response(responses, "capabilities", _capabilities(), delay=0.12)
    _response(
        responses,
        "status",
        {"schema_version": 1, "status": "running", "phase": "planned"},
        delay=0.12,
    )
    started = time.monotonic()
    with pytest.raises(ResearcherConnectorError, match="connector-timeout"):
        connector.status(topic.name)
    assert 0.18 <= time.monotonic() - started < 0.55


@pytest.mark.skipif(
    not UPSTREAM_SMOKE_ROOT
    or not (Path(UPSTREAM_SMOKE_ROOT) / "researcher").is_dir(),
    reason="set LIFEOS_RESEARCHER_SMOKE_ROOT to opt into the live connector smoke",
)
def test_real_researcher_source_plan_and_status_smoke(tmp_path: Path) -> None:
    upstream = Path(UPSTREAM_SMOKE_ROOT)
    topics = tmp_path / "topics"
    topics.mkdir()
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "lesson.md").write_text("# Lesson\n\nStable evidence.\n", "utf-8")
    topic = _topic(topics, "fixture-topic")
    (topic / "work").mkdir()
    (topic / "work/checkpoint.json").write_text(
        json.dumps(
            {
                "phase": "planned",
                "topic": "Fixture",
                "queue": [],
                "done": [],
                "sessions": {},
            }
        ),
        "utf-8",
    )
    env = dict(os.environ)
    env["PYTHONPATH"] = str(upstream)
    connector = ResearcherConnector(
        topics_root=topics,
        command=(sys.executable, "-m", "researcher"),
        cwd=upstream,
        env=env,
        topic_boundary=Boundary(),
        timeout=5,
    )

    plan = connector.source_plan(corpus, kind="local-markdown")
    status = connector.status(topic.name)

    assert plan.status == "waiting_human" and len(plan.documents) == 1
    assert status.status == "running" and status.phase == "planned"


def _write_jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    path.write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows), "utf-8"
    )


def _real_topic(tmp_path: Path) -> Path:
    root = tmp_path / "topics" / "fixture-topic"
    (root / "sources/content").mkdir(parents=True)
    (root / "staging").mkdir()
    (root / "final/wiki").mkdir(parents=True)
    (root / "work").mkdir()
    source_id = "src_aaaaaaaaaaaa"
    claim_id = "clm_bbbbbbbbbbbb"
    (root / "topic.json").write_text(
        json.dumps(
            {
                "spec_version": "0.1.0",
                "topic": "Synthetic fixture",
                "slug": "fixture-topic",
                "created_at": "2026-01-15T09:00:00+00:00",
            }
        )
        + "\n",
        "utf-8",
    )
    (root / "sources/content/source.md").write_text("Synthetic fact\n", "utf-8")
    _write_jsonl(
        root / "sources/sources.jsonl",
        [
            {
                "id": source_id,
                "kind": "local",
                "title": "Synthetic source",
                "content_path": "sources/content/source.md",
                "meta": {"declared": True},
            }
        ],
    )
    _write_jsonl(
        root / "final/claims.jsonl",
        [
            {
                "id": claim_id,
                "text": "Synthetic fact anchored to a source",
                "confidence": "high",
                "status": "verified",
                "evidence": [
                    {
                        "source_id": source_id,
                        "quote": "Synthetic fact",
                        "stance": "supports",
                        "locator": {"type": "line", "value": "1"},
                    }
                ],
                "created_at": "2026-01-15T09:01:00+00:00",
            }
        ],
    )
    (root / "staging/claims.jsonl").write_text("", "utf-8")
    (root / "final/wiki/page.md").write_text(
        "---\nid: wik_cccccccccccc\ntitle: Fixture\nclaims:\n"
        f"  - {claim_id}\nupdated_at: 2026-01-15T09:02:00+00:00\n"
        "---\n\n# Fixture\n\nSynthetic body.\n",
        "utf-8",
    )
    return root


def test_real_temp_topic_validate_and_review_adapter_smoke(tmp_path: Path) -> None:
    topic = _real_topic(tmp_path)
    validator = tmp_path / "validator.py"
    validator.write_text("import sys; raise SystemExit(0)\n", "utf-8")
    llmwiki = LlmWikiConnector(
        topics_root=topic.parent,
        command=(sys.executable, str(validator)),
        cwd=tmp_path,
        env={},
    )
    adapter, _topics, responses, _ = _setup(
        tmp_path / "connector", boundary=llmwiki, topics_root=topic.parent
    )
    _response(
        responses,
        "status",
        {"schema_version": 1, "status": "done", "phase": "done"},
    )

    result = adapter.import_topic(topic.name)

    assert result.status == "proposed"
    assert result.registration.sources and result.registration.claims
    assert result.registration.wiki
