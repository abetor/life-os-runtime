"""P2-04 llm-wiki subprocess and direct-read connector acceptance."""

from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
import stat
import sys
import time

import pytest

from tool_life_os_runtime.ext.connectors.llmwiki import (
    MAX_CONNECTOR_OUTPUT_BYTES,
    VALIDATE_ARGV_SUFFIX,
    VALIDATE_EXIT_CODES,
    LlmWikiConnector,
    LlmWikiConnectorError,
)
from tool_life_os_runtime.ext.connectors.llmwiki import connector as connector_module


SOURCE_ID = "src_aaaaaaaaaaaa"
CLAIM_ID = "clm_bbbbbbbbbbbb"
WIKI_ID = "wik_cccccccccccc"


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _write_jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    path.write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows),
        "utf-8",
    )


def _topic(tmp_path: Path) -> tuple[Path, dict[str, object], dict[str, object]]:
    root = tmp_path / "topics" / "fixture-topic"
    (root / "sources/content").mkdir(parents=True)
    (root / "staging").mkdir()
    (root / "final/wiki").mkdir(parents=True)
    (root / "work").mkdir()
    manifest = {
        "spec_version": "0.1.0",
        "topic": "Synthetic fixture",
        "slug": "fixture-topic",
        "created_at": "2026-01-15T09:00:00+00:00",
    }
    source = {
        "id": SOURCE_ID,
        "kind": "local",
        "title": "Synthetic source",
        "content_path": "sources/content/source.md",
        "meta": {"declared": True},
    }
    claim = {
        "id": CLAIM_ID,
        "text": "Synthetic fact anchored to a source",
        "confidence": "high",
        "status": "verified",
        "evidence": [
            {
                "source_id": SOURCE_ID,
                "quote": "Synthetic fact",
                "stance": "supports",
                "locator": {"type": "line", "value": "1"},
            }
        ],
        "created_at": "2026-01-15T09:01:00+00:00",
    }
    (root / "topic.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", "utf-8"
    )
    (root / "sources/content/source.md").write_text("Synthetic fact\n", "utf-8")
    _write_jsonl(root / "sources/sources.jsonl", [source])
    _write_jsonl(root / "final/claims.jsonl", [claim])
    (root / "staging/claims.jsonl").write_text("", "utf-8")
    (root / "final/wiki/fixture.md").write_text(
        "---\n"
        f"id: {WIKI_ID}\n"
        "title: Fixture page\n"
        "claims:\n"
        f"  - {CLAIM_ID}\n"
        "updated_at: 2026-01-15T09:02:00+00:00\n"
        "---\n\n"
        "# Fixture page\n\nSynthetic body.\n",
        "utf-8",
    )
    return root, source, claim


def _validator(tmp_path: Path) -> tuple[Path, Path]:
    script = tmp_path / "fake_llmwiki.py"
    log = tmp_path / "argv.json"
    script.write_text(
        """import json
import os
import sys

with open(os.environ["ARGV_LOG"], "w", encoding="utf-8") as stream:
    json.dump(sys.argv[1:], stream)
mode = os.environ.get("VALIDATOR_MODE", "valid")
if mode == "invalid":
    print(os.environ.get("PRIVATE_DIAGNOSTIC", "invalid topic"), file=sys.stderr)
    raise SystemExit(1)
if mode == "overflow":
    os.write(1, b"x" * 70000)
    raise SystemExit(0)
if mode == "unknown":
    raise SystemExit(42)
if mode == "timeout":
    import time
    time.sleep(2)
if mode == "detached-pipe-holder":
    import subprocess
    subprocess.Popen([
        sys.executable,
        "-c",
        "import os,time; os.setsid(); "
        "[(print('held', flush=True), time.sleep(0.05)) for _ in range(100)]",
    ])
print("OK")
""",
        "utf-8",
    )
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    return script, log


def _connector(
    tmp_path: Path,
    topic: Path,
    *,
    mode: str = "valid",
    private: str = "",
    timeout: float = 10.0,
) -> tuple[LlmWikiConnector, Path]:
    script, log = _validator(tmp_path)
    env = {
        "ARGV_LOG": str(log),
        "VALIDATOR_MODE": mode,
        "PRIVATE_DIAGNOSTIC": private,
    }
    return (
        LlmWikiConnector(
            topics_root=topic.parent,
            command=(sys.executable, str(script)),
            cwd=tmp_path,
            env=env,
            timeout=timeout,
        ),
        log,
    )


def _tree_snapshot(root: Path) -> dict[str, tuple[bytes, int, int]]:
    return {
        path.relative_to(root).as_posix(): (
            path.read_bytes(),
            path.stat().st_mtime_ns,
            path.stat().st_ctime_ns,
        )
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def test_known_topic_validates_and_reads_stable_public_spec_snapshot(tmp_path: Path) -> None:
    topic, source, claim = _topic(tmp_path)
    connector, argv_log = _connector(tmp_path, topic)
    before = _tree_snapshot(topic)

    first = connector.load_topic(topic)
    second = connector.load_topic(topic)

    assert first == second
    assert first.schema_version == 1
    assert first.spec_version == "0.1.0"
    assert first.manifest["slug"] == "fixture-topic"
    assert first.sources[0].payload == source
    assert first.sources[0].content == "Synthetic fact\n"
    assert first.sources[0].content_sha256 == hashlib.sha256(
        b"Synthetic fact\n"
    ).hexdigest()
    assert first.final_claims[0].payload == claim
    assert first.wiki_pages[0].frontmatter["claims"] == [CLAIM_ID]
    assert first.wiki_pages[0].body.endswith("Synthetic body.")
    payload_hash = hashlib.sha256(_canonical(source)).hexdigest()
    content_hash = hashlib.sha256(b"Synthetic fact\n").hexdigest()
    stable_source_hash = hashlib.sha256(
        _canonical(
            {
                "payload_sha256": payload_hash,
                "content_sha256": content_hash,
            }
        )
    ).hexdigest()
    assert first.sources[0].payload_sha256 == payload_hash
    assert first.source_hashes == ((SOURCE_ID, stable_source_hash),)
    assert len(first.snapshot_sha256) == 64
    assert json.loads(argv_log.read_text("utf-8")) == ["validate", str(topic)]
    assert VALIDATE_ARGV_SUFFIX == ("validate", "<topic-dir>")
    assert VALIDATE_EXIT_CODES == frozenset({0, 1})
    assert _tree_snapshot(topic) == before


def test_returned_records_are_detached_from_repeated_reads(tmp_path: Path) -> None:
    topic, _source, _claim = _topic(tmp_path)
    connector, _ = _connector(tmp_path, topic)
    first = connector.load_topic(topic)
    first.sources[0].payload["title"] = "caller mutation"

    second = connector.load_topic(topic)

    assert second.sources[0].payload["title"] == "Synthetic source"


def test_upstream_invalid_output_is_not_parsed_or_leaked(tmp_path: Path) -> None:
    topic, _source, _claim = _topic(tmp_path)
    marker = "/" + "Users" + "/private/topic diagnostic"
    connector, _ = _connector(tmp_path, topic, mode="invalid", private=marker)

    result = connector.validate_topic(topic)

    assert result.status == "invalid"
    assert result.returncode == 1
    assert result.issue_code == "upstream-validation-failed"
    assert result.stderr_bytes == len((marker + "\n").encode("utf-8"))
    assert marker not in repr(result)
    with pytest.raises(LlmWikiConnectorError) as caught:
        connector.load_topic(topic)
    assert caught.value.code == "upstream-validation-failed"
    assert marker not in str(caught.value)


def test_missing_source_fk_is_structured_and_privacy_safe(tmp_path: Path) -> None:
    topic, _source, claim = _topic(tmp_path)
    claim["evidence"][0]["source_id"] = "src_dddddddddddd"
    claim["text"] = "/" + "Users" + "/private fact must not leak"
    _write_jsonl(topic / "final/claims.jsonl", [claim])
    connector, _ = _connector(tmp_path, topic)

    with pytest.raises(LlmWikiConnectorError) as caught:
        connector.read_topic(topic)

    assert caught.value.code == "topic-invalid"
    assert ("missing-source-fk", "src_dddddddddddd") in {
        (issue.code, issue.reference) for issue in caught.value.issues
    }
    assert "/Users/" not in repr(caught.value.issues)


def test_public_spec_accepts_compatible_patch_version(tmp_path: Path) -> None:
    topic, _source, _claim = _topic(tmp_path)
    manifest = json.loads((topic / "topic.json").read_text("utf-8"))
    manifest["spec_version"] = "0.1.7"
    (topic / "topic.json").write_text(json.dumps(manifest) + "\n", "utf-8")
    connector, _ = _connector(tmp_path, topic)

    snapshot = connector.read_topic(topic)

    assert snapshot.spec_version == "0.1.7"


def test_public_spec_rejects_unsupported_minor_version(tmp_path: Path) -> None:
    topic, _source, _claim = _topic(tmp_path)
    manifest = json.loads((topic / "topic.json").read_text("utf-8"))
    manifest["spec_version"] = "0.2.0"
    (topic / "topic.json").write_text(json.dumps(manifest) + "\n", "utf-8")
    connector, _ = _connector(tmp_path, topic)

    with pytest.raises(LlmWikiConnectorError) as caught:
        connector.read_topic(topic)

    assert caught.value.code == "topic-invalid"
    assert {issue.code for issue in caught.value.issues} == {"schema-mismatch"}


def test_unknown_schema_field_is_rejected(tmp_path: Path) -> None:
    topic, source, _claim = _topic(tmp_path)
    source["unknown_security_field"] = True
    _write_jsonl(topic / "sources/sources.jsonl", [source])
    connector, _ = _connector(tmp_path, topic)

    with pytest.raises(LlmWikiConnectorError) as caught:
        connector.read_topic(topic)

    assert "schema-mismatch" in {issue.code for issue in caught.value.issues}


@pytest.mark.parametrize(
    ("target", "field", "bad_value"),
    [
        ("source", "kind", []),
        ("claim", "confidence", {}),
        ("claim", "status", []),
        ("evidence", "stance", {}),
        ("locator", "type", []),
    ],
)
def test_unhashable_enum_values_are_schema_findings_not_type_errors(
    tmp_path: Path, target: str, field: str, bad_value: object
) -> None:
    topic, source, claim = _topic(tmp_path)
    if target == "source":
        source[field] = bad_value
        _write_jsonl(topic / "sources/sources.jsonl", [source])
    else:
        container = claim
        if target == "evidence":
            container = claim["evidence"][0]
        elif target == "locator":
            container = claim["evidence"][0]["locator"]
        container[field] = bad_value
        _write_jsonl(topic / "final/claims.jsonl", [claim])
    connector, _ = _connector(tmp_path, topic)

    with pytest.raises(LlmWikiConnectorError) as caught:
        connector.read_topic(topic)

    assert caught.value.code == "topic-invalid"
    assert "schema-mismatch" in {issue.code for issue in caught.value.issues}


def test_source_content_is_required_to_stay_inside_topic_and_affects_hash(
    tmp_path: Path,
) -> None:
    topic, source, _claim = _topic(tmp_path)
    connector, _ = _connector(tmp_path, topic)
    original = connector.read_topic(topic)
    (topic / "sources/content/source.md").write_text("Changed source\n", "utf-8")

    changed = connector.read_topic(topic)

    assert changed.sources[0].payload_sha256 == original.sources[0].payload_sha256
    assert changed.sources[0].content == "Changed source\n"
    assert changed.sources[0].sha256 != original.sources[0].sha256
    assert changed.snapshot_sha256 != original.snapshot_sha256

    source["content_path"] = "../private-source.md"
    _write_jsonl(topic / "sources/sources.jsonl", [source])
    with pytest.raises(LlmWikiConnectorError) as caught:
        connector.read_topic(topic)
    assert {issue.code for issue in caught.value.issues} == {
        "source-not-self-contained"
    }


def test_missing_declared_source_content_is_structured(tmp_path: Path) -> None:
    topic, _source, _claim = _topic(tmp_path)
    (topic / "sources/content/source.md").unlink()
    connector, _ = _connector(tmp_path, topic)

    with pytest.raises(LlmWikiConnectorError) as caught:
        connector.read_topic(topic)

    assert caught.value.code == "topic-invalid"
    assert {issue.code for issue in caught.value.issues} == {
        "source-content-missing"
    }


def test_source_content_symlink_cannot_escape_topic(tmp_path: Path) -> None:
    topic, source, _claim = _topic(tmp_path)
    private = tmp_path / "private.txt"
    private.write_text("private bytes", "utf-8")
    (topic / "sources/content/source.md").unlink()
    (topic / "sources/content/source.md").symlink_to(private)
    source["title"] = str(private)
    _write_jsonl(topic / "sources/sources.jsonl", [source])
    connector, _ = _connector(tmp_path, topic)

    with pytest.raises(LlmWikiConnectorError) as caught:
        connector.read_topic(topic)

    assert {issue.code for issue in caught.value.issues} == {
        "source-content-unsafe"
    }
    assert str(private) not in str(caught.value)
    assert str(private) not in repr(caught.value.issues)


def test_jsonl_issue_locations_keep_original_line_numbers(tmp_path: Path) -> None:
    topic, source, _claim = _topic(tmp_path)
    second = dict(source, id="src_dddddddddddd", unknown=True)
    (topic / "sources/sources.jsonl").write_text(
        "not-json\n" + json.dumps(second) + "\n",
        "utf-8",
    )
    connector, _ = _connector(tmp_path, topic)

    with pytest.raises(LlmWikiConnectorError) as caught:
        connector.read_topic(topic)

    locations = {(issue.code, issue.location) for issue in caught.value.issues}
    assert ("invalid-jsonl", "sources/sources.jsonl:1") in locations
    assert ("schema-mismatch", "sources/sources.jsonl:2") in locations


def test_topic_move_before_final_revalidation_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    topic, _source, _claim = _topic(tmp_path)
    connector, _ = _connector(tmp_path, topic)
    original = topic.parent / "fixture-topic-original"

    def move_and_replace(_path: Path) -> None:
        topic.rename(original)
        topic.mkdir()

    monkeypatch.setattr(connector, "_before_topic_revalidate", move_and_replace)

    with pytest.raises(LlmWikiConnectorError, match="topic-moved"):
        connector.read_topic(topic)
    assert (original / "topic.json").is_file()


@pytest.mark.parametrize(
    ("relative", "operation"),
    [
        ("sources/content/source.md", "mutate"),
        ("sources/sources.jsonl", "delete"),
        ("final/wiki/fixture.md", "replace"),
    ],
)
def test_read_leaf_change_at_final_seam_is_rejected_as_moved_topic(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    relative: str,
    operation: str,
) -> None:
    topic, _source, _claim = _topic(tmp_path)
    connector, _ = _connector(tmp_path, topic)
    target = topic / relative

    def change_leaf(_path: Path) -> None:
        if operation == "mutate":
            target.write_text("changed after read\n", "utf-8")
        elif operation == "delete":
            target.unlink()
        else:
            replacement = target.with_name("replacement.md")
            replacement.write_text(target.read_text("utf-8") + "changed\n", "utf-8")
            replacement.replace(target)

    monkeypatch.setattr(connector, "_before_topic_revalidate", change_leaf)

    with pytest.raises(LlmWikiConnectorError, match="topic-moved"):
        connector.read_topic(topic)


@pytest.mark.parametrize(
    "relative",
    ["sources/sources.jsonl", "final/claims.jsonl"],
)
def test_absent_optional_leaf_appearing_at_final_seam_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    relative: str,
) -> None:
    topic, _source, _claim = _topic(tmp_path)
    target = topic / relative
    target.unlink()
    (topic / "final/wiki/fixture.md").unlink()
    if relative == "sources/sources.jsonl":
        (topic / "final/claims.jsonl").unlink()
    connector, _ = _connector(tmp_path, topic)

    def create_optional_leaf(_path: Path) -> None:
        target.write_text("", "utf-8")

    monkeypatch.setattr(
        connector, "_before_topic_revalidate", create_optional_leaf
    )

    with pytest.raises(LlmWikiConnectorError, match="topic-moved"):
        connector.read_topic(topic)


@pytest.mark.parametrize("initial", ["missing-directory", "empty-set"])
def test_optional_wiki_set_change_at_final_seam_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    initial: str,
) -> None:
    topic, _source, _claim = _topic(tmp_path)
    wiki_dir = topic / "final/wiki"
    wiki_page = wiki_dir / "fixture.md"
    wiki_page.unlink()
    if initial == "missing-directory":
        wiki_dir.rmdir()
    connector, _ = _connector(tmp_path, topic)

    def change_wiki_set(_path: Path) -> None:
        if initial == "missing-directory":
            wiki_dir.mkdir()
        else:
            wiki_page.write_text("new page after read\n", "utf-8")

    monkeypatch.setattr(connector, "_before_topic_revalidate", change_wiki_set)

    with pytest.raises(LlmWikiConnectorError, match="topic-moved"):
        connector.read_topic(topic)


def test_symlink_or_outside_topic_is_rejected_without_following(
    tmp_path: Path,
) -> None:
    topic, _source, _claim = _topic(tmp_path)
    connector, _ = _connector(tmp_path, topic)
    outside = tmp_path / "outside"
    outside.mkdir()
    link = topic.parent / "linked-topic"
    link.symlink_to(outside, target_is_directory=True)

    assert connector.validate_topic(link).issue_code == "unsafe-topic"
    with pytest.raises(LlmWikiConnectorError, match="unsafe-topic"):
        connector.read_topic(tmp_path / "outside")


def test_subprocess_is_argv_only_with_explicit_cwd_env_and_bounded_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    topic, _source, _claim = _topic(tmp_path)
    connector, _ = _connector(tmp_path, topic, mode="overflow")
    real_popen = connector_module.subprocess.Popen
    observed: dict[str, object] = {}

    def recording_popen(*args, **kwargs):
        observed["argv"] = args[0]
        observed["shell"] = kwargs.get("shell")
        observed["cwd"] = kwargs.get("cwd")
        observed["env"] = kwargs.get("env")
        return real_popen(*args, **kwargs)

    monkeypatch.setattr(connector_module.subprocess, "Popen", recording_popen)
    result = connector.validate_topic(topic)

    assert observed["argv"][-2:] == ["validate", str(topic)]
    assert observed["shell"] is False
    assert observed["cwd"] == tmp_path
    assert observed["env"] == connector._env
    assert result.status == "contract_error"
    assert result.issue_code == "output-too-large"
    assert result.stdout_bytes == MAX_CONNECTOR_OUTPUT_BYTES + 1


def test_unknown_exit_is_transient_under_runtime_failure_contract(tmp_path: Path) -> None:
    topic, _source, _claim = _topic(tmp_path)
    connector, _ = _connector(tmp_path, topic, mode="unknown")

    result = connector.validate_topic(topic)

    assert (result.status, result.returncode, result.issue_code) == (
        "transient",
        42,
        "unknown-exit",
    )


def test_timeout_and_missing_executable_are_structured(tmp_path: Path) -> None:
    topic, _source, _claim = _topic(tmp_path)
    connector, _ = _connector(tmp_path, topic, mode="timeout", timeout=0.05)

    timeout = connector.validate_topic(topic)

    assert timeout.status == "transient"
    assert timeout.issue_code == "timeout"

    unavailable = LlmWikiConnector(
        topics_root=topic.parent,
        command=(str(tmp_path / "missing-llmwiki"),),
        cwd=tmp_path,
        env={},
    ).validate_topic(topic)
    assert unavailable.status == "unavailable"
    assert unavailable.issue_code == "executable-unavailable"


def test_detached_descendant_holding_pipes_cannot_extend_deadline(
    tmp_path: Path,
) -> None:
    topic, _source, _claim = _topic(tmp_path)
    connector, _ = _connector(
        tmp_path,
        topic,
        mode="detached-pipe-holder",
        timeout=0.25,
    )

    started = time.monotonic()
    result = connector.validate_topic(topic)
    elapsed = time.monotonic() - started

    assert result.status == "valid"
    assert elapsed < 0.75


def test_selector_constructor_failure_cleans_process_and_pipes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    topic, _source, _claim = _topic(tmp_path)
    connector, _ = _connector(tmp_path, topic, mode="timeout", timeout=1.0)
    real_popen = connector_module.subprocess.Popen
    observed: list[object] = []

    def recording_popen(*args, **kwargs):
        process = real_popen(*args, **kwargs)
        observed.append(process)
        return process

    def failing_selector():
        raise RuntimeError("synthetic selector constructor failure")

    monkeypatch.setattr(connector_module.subprocess, "Popen", recording_popen)
    monkeypatch.setattr(
        connector_module.selectors, "DefaultSelector", failing_selector
    )

    started = time.monotonic()
    result = connector.validate_topic(topic)
    elapsed = time.monotonic() - started

    assert (result.status, result.issue_code) == (
        "contract_error",
        "subprocess-setup-failed",
    )
    assert elapsed < 0.75
    process = observed[0]
    assert process.poll() is not None
    assert process.stdout.closed
    assert process.stderr.closed


def test_selector_register_failure_cleans_partial_setup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    topic, _source, _claim = _topic(tmp_path)
    connector, _ = _connector(tmp_path, topic, mode="timeout", timeout=1.0)
    real_popen = connector_module.subprocess.Popen
    real_selector = connector_module.selectors.DefaultSelector
    observed: list[object] = []
    wrappers: list[object] = []

    def recording_popen(*args, **kwargs):
        process = real_popen(*args, **kwargs)
        observed.append(process)
        return process

    class FailingRegisterSelector:
        def __init__(self) -> None:
            self.inner = real_selector()
            self.calls = 0
            self.closed = False

        def register(self, *args, **kwargs):
            self.calls += 1
            if self.calls == 2:
                raise RuntimeError("synthetic selector register failure")
            return self.inner.register(*args, **kwargs)

        def close(self) -> None:
            self.closed = True
            self.inner.close()

    def failing_register_selector():
        wrapper = FailingRegisterSelector()
        wrappers.append(wrapper)
        return wrapper

    monkeypatch.setattr(connector_module.subprocess, "Popen", recording_popen)
    monkeypatch.setattr(
        connector_module.selectors,
        "DefaultSelector",
        failing_register_selector,
    )

    result = connector.validate_topic(topic)

    assert (result.status, result.issue_code) == (
        "contract_error",
        "subprocess-setup-failed",
    )
    process = observed[0]
    assert process.poll() is not None
    assert process.stdout.closed
    assert process.stderr.closed
    assert wrappers[0].closed is True


@pytest.mark.parametrize(
    ("target", "field"),
    [
        ("manifest", "topic"),
        ("source", "title"),
        ("claim", "text"),
        ("wiki", "title"),
    ],
)
def test_escaped_lone_surrogate_is_a_structured_schema_error(
    tmp_path: Path, target: str, field: str
) -> None:
    topic, source, claim = _topic(tmp_path)
    value = "escaped-" + chr(0xD800) + "-surrogate"
    if target == "manifest":
        manifest = json.loads((topic / "topic.json").read_text("utf-8"))
        manifest[field] = value
        (topic / "topic.json").write_text(
            json.dumps(manifest, ensure_ascii=True) + "\n", "utf-8"
        )
    elif target == "source":
        source[field] = value
        (topic / "sources/sources.jsonl").write_text(
            json.dumps(source, ensure_ascii=True) + "\n", "utf-8"
        )
    elif target == "claim":
        claim[field] = value
        (topic / "final/claims.jsonl").write_text(
            json.dumps(claim, ensure_ascii=True) + "\n", "utf-8"
        )
    else:
        wiki = topic / "final/wiki/fixture.md"
        wiki.write_text(
            wiki.read_text("utf-8").replace(
                "title: Fixture page", f"title: {json.dumps(value)}"
            ),
            "utf-8",
        )
    connector, _ = _connector(tmp_path, topic)

    with pytest.raises(LlmWikiConnectorError) as caught:
        connector.read_topic(topic)

    assert caught.value.code == "topic-invalid"
    assert "schema-mismatch" in {issue.code for issue in caught.value.issues}


def test_lone_surrogate_in_connector_inputs_is_normalized(tmp_path: Path) -> None:
    topic, _source, _claim = _topic(tmp_path)

    with pytest.raises(LlmWikiConnectorError, match="invalid-command"):
        LlmWikiConnector(
            topics_root=topic.parent,
            command=("llmwiki-\ud800",),
            cwd=tmp_path,
            env={},
        )
    with pytest.raises(LlmWikiConnectorError, match="invalid-environment"):
        LlmWikiConnector(
            topics_root=topic.parent,
            command=("llmwiki",),
            cwd=tmp_path,
            env={"BAD": "\ud800"},
        )


def test_connector_never_imports_neighbor_package() -> None:
    source = Path(connector_module.__file__).read_text("utf-8")
    tree = ast.parse(source)
    imported = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }
    assert not any(name == "llmwiki" or name.startswith("llmwiki.") for name in imported)
