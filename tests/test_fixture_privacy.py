"""Privacy, public target contracts and opt-in exact legacy characterization."""

from __future__ import annotations

import getpass
import hashlib
import importlib.util
import json
import os
import re
import socket
import sys
import tomllib
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from types import ModuleType
from typing import Iterator
from urllib.parse import urlsplit

import pytest


FIXTURES = Path(__file__).parent / "fixtures"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
SCHEDULE_RE = re.compile(
    r"^(?:daily \d{2}:\d{2}|weekly (?:mon|tue|wed|thu|fri|sat|sun) \d{2}:\d{2}|"
    r"every \d+[mh]|\d{4}-\d{2}-\d{2} \d{2}:\d{2})$"
)


@dataclass(frozen=True)
class PrivacyFinding:
    path: str
    rule: str


HOME_PATH_RE = re.compile(r"(?i)(?:/Users/|/home/|[A-Z]:\\Users\\)[^\s\"']+")
PERSON_FIELD_RE = re.compile(
    r"(?im)^\s*[\"']?(?:real_name|full_name|owner_name|person_name|author|owner|person)[\"']?"
    r"\s*[:=]\s*(?P<value>[^\r\n#,}]+)"
)
PERSON_PROSE_RE = re.compile(
    r"(?i:\b(?:met|meeting with|spoke with|written by|authored by|owned by|"
    r"assigned to|contact(?:ed)?|person is))\s+"
    r"(?P<value>(?-i:[A-Z][a-z]{2,}(?:[-'][A-Z][a-z]{2,})?\s+"
    r"[A-Z][a-z]{2,}(?:[-'][A-Z][a-z]{2,})?))\b"
)
SECRET_FIELD_RE = re.compile(
    r"(?im)^\s*[\"']?(?P<key>[A-Z0-9_.-]*(?:token|secret|password|passwd|"
    r"api[_-]?key|authorization|cookie)[A-Z0-9_.-]*)[\"']?\s*[:=]\s*"
    r"(?P<value>[^\r\n]+)"
)
HOST_FIELD_RE = re.compile(
    r"(?im)^\s*[\"']?(?:host|hostname|workstation|machine_name|computer_name|"
    r"internal_host|private_host|base_url|endpoint)[\"']?"
    r"\s*[:=]\s*(?P<value>[^\r\n#,}]+)"
)
BARE_HOST_PROSE_RE = re.compile(
    r"(?i)\b(?:host|hostname|workstation|laptop|machine|computer)\s+"
    r"(?:(?:was\s+)?named|called)\s+(?P<value>[a-z0-9][a-z0-9._-]{2,})\b"
)
HOSTISH_WORKSTATION_RE = re.compile(
    r"(?i)\b(?:on|from|via)\s+(?:host|workstation|laptop|machine|computer)\s+"
    r"(?P<value>(?=[a-z0-9._-]*[-.0-9])[a-z0-9][a-z0-9._-]{2,})\b"
)
EMAIL_RE = re.compile(r"(?i)\b[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
URL_RE = re.compile(r"(?i)https?://[^\s<>()\"']+")
PRIVATE_HOST_RE = re.compile(
    r"(?i)(?:\b(?:[a-z0-9-]+\.)+(?:internal|private|corp|lan|local)\b|"
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|"
    r"172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b)"
)
TOKEN_LITERAL_PATTERNS = (
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]{8,}"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{16,}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    re.compile(r"\bAKIA[A-Z0-9]{16}\b"),
    re.compile(r"\bAIza[A-Za-z0-9_-]{24,}\b"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
)
RESERVED_HOSTS = {"example.com", "example.org", "example.net", "example.invalid"}
SYNTHETIC_PERSON_ALLOWLIST = frozenset(
    {"fixture-person", "synthetic-person", "human", "nobody"}
)
SYNTHETIC_HOST_ALLOWLIST = frozenset({"fixture-host", "fixture-node"})


def _placeholder(value: str, *, allowlist: frozenset[str] = frozenset()) -> bool:
    normalized = value.strip().strip("\"'").strip()
    lowered = normalized.casefold()
    return (
        not normalized
        or normalized.startswith("${")
        or normalized.startswith("<")
        or lowered in allowlist
        or lowered.startswith(("placeholder", "redacted"))
    )


def _secret_reference(key: str, value: str) -> bool:
    normalized = value.strip().removesuffix(",").strip().strip("\"'").strip()
    lowered = normalized.casefold()
    return (
        not normalized
        or normalized.startswith("${")
        or normalized.startswith("<")
        or lowered.startswith(("fixture-placeholder", "placeholder", "redacted"))
        or (
            key.casefold().endswith(("_env", "-env", ".env"))
            and re.fullmatch(r"[A-Z][A-Z0-9_]*", normalized) is not None
        )
    )


def _reserved_host(host: str | None) -> bool:
    if not host:
        return False
    host = host.casefold().rstrip(".")
    return any(host == allowed or host.endswith("." + allowed) for allowed in RESERVED_HOSTS)


def _local_private_markers(extra: tuple[str, ...]) -> tuple[str, ...]:
    markers = {marker.strip() for marker in extra if len(marker.strip()) >= 4}
    for marker in (
        Path.home().name,
        getpass.getuser(),
        socket.gethostname(),
        socket.getfqdn(),
    ):
        if len(marker.strip()) >= 4 and marker.casefold() not in {"home", "localhost"}:
            markers.add(marker.strip())
    return tuple(sorted(markers))


def _private_host_value(value: str) -> bool:
    normalized = value.strip().strip("\"'").rstrip(".,;:)")
    candidate = urlsplit(normalized if "://" in normalized else "//" + normalized).hostname
    return not _placeholder(normalized, allowlist=SYNTHETIC_HOST_ALLOWLIST) and not _reserved_host(
        candidate
    )


def _privacy_rules(text: str, *, private_markers: tuple[str, ...]) -> set[str]:
    rules: set[str] = set()
    if "\x00" in text:
        rules.add("binary-content")
    if HOME_PATH_RE.search(text):
        rules.add("private-absolute-path")
    if PRIVATE_HOST_RE.search(text):
        rules.add("private-url-or-host")

    for match in PERSON_FIELD_RE.finditer(text):
        if not _placeholder(match.group("value"), allowlist=SYNTHETIC_PERSON_ALLOWLIST):
            rules.add("personal-name-marker")
    for match in PERSON_PROSE_RE.finditer(text):
        if not _placeholder(match.group("value"), allowlist=SYNTHETIC_PERSON_ALLOWLIST):
            rules.add("personal-name-marker")
    for match in SECRET_FIELD_RE.finditer(text):
        if not _secret_reference(match.group("key"), match.group("value")):
            rules.add("token-or-secret")
    for pattern in TOKEN_LITERAL_PATTERNS:
        if pattern.search(text):
            rules.add("token-or-secret")

    for match in EMAIL_RE.finditer(text):
        host = match.group(0).rsplit("@", 1)[1]
        if not _reserved_host(host):
            rules.add("non-placeholder-email")
    for match in URL_RE.finditer(text):
        if not _reserved_host(urlsplit(match.group(0)).hostname):
            rules.add("private-url-or-host")
    for match in HOST_FIELD_RE.finditer(text):
        value = match.group("value").strip().strip("\"'")
        if _private_host_value(value):
            rules.add("private-url-or-host")
    for pattern in (BARE_HOST_PROSE_RE, HOSTISH_WORKSTATION_RE):
        for match in pattern.finditer(text):
            if _private_host_value(match.group("value")):
                rules.add("private-url-or-host")

    for marker in _local_private_markers(private_markers):
        if re.search(r"(?<![\w-])" + re.escape(marker) + r"(?![\w-])", text, re.I):
            rules.add("local-person-or-host-marker")
    return rules


def scan_fixture_tree(
    root: Path, *, private_markers: tuple[str, ...] = ()
) -> list[PrivacyFinding]:
    findings: list[PrivacyFinding] = []
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root).as_posix()
        if path.is_symlink():
            findings.append(PrivacyFinding(rel, "symlink"))
            continue
        if not path.is_file():
            continue
        try:
            text = path.read_bytes().decode("utf-8")
        except UnicodeDecodeError:
            findings.append(PrivacyFinding(rel, "non-utf8"))
            continue
        for rule in sorted(_privacy_rules(rel + "\n" + text, private_markers=private_markers)):
            findings.append(PrivacyFinding(rel, rule))
    return findings


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@contextmanager
def _loaded_source_no_bytecode(path: Path, module_name: str) -> Iterator[ModuleType]:
    """Execute one opted-in source module without creating import artifacts."""
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load opted-in source module")
    module = importlib.util.module_from_spec(spec)
    missing = object()
    previous_module = sys.modules.get(module_name, missing)
    previous_bytecode = sys.dont_write_bytecode
    sys.modules[module_name] = module
    sys.dont_write_bytecode = True
    try:
        spec.loader.exec_module(module)
    except BaseException:
        if previous_module is missing:
            sys.modules.pop(module_name, None)
        else:
            sys.modules[module_name] = previous_module
        raise
    finally:
        sys.dont_write_bytecode = previous_bytecode
    try:
        yield module
    finally:
        if previous_module is missing:
            sys.modules.pop(module_name, None)
        else:
            sys.modules[module_name] = previous_module


def _json(path: Path):
    return json.loads(path.read_text("utf-8"))


def _jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text("utf-8").splitlines() if line]


def _scalar(value: str):
    value = value.strip()
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return value.strip("\"'")


def _frontmatter(path: Path) -> tuple[dict, str]:
    text = path.read_text("utf-8")
    if not text.startswith("---\n") or "\n---\n" not in text[4:]:
        return {}, text
    raw, body = text[4:].split("\n---\n", 1)
    result: dict = {}
    section: str | None = None
    for line in raw.splitlines():
        if not line.strip() or line.lstrip().startswith("-") or ":" not in line:
            continue
        indent = len(line) - len(line.lstrip())
        key, value = line.strip().split(":", 1)
        if indent == 0:
            section = key if not value.strip() else None
            result[key] = {} if section else _scalar(value)
        elif section and indent >= 2:
            result[section][key] = _scalar(value)
    return result, body


def _knowledge_rules(path: Path) -> set[str]:
    meta, body = _frontmatter(path)
    rules = set()
    if not meta:
        rules.add("note.frontmatter.required")
    if not any(line.startswith("# ") for line in body.splitlines()):
        rules.add("note.h1.required")
    return rules


def _review_rules(path: Path) -> set[str]:
    meta, body = _frontmatter(path)
    rules = set()
    if "## \u041c\u0435\u0442\u0430" not in body:
        rules.add("review.meta.required")
    if "## \u0416\u0434\u0443 \u0440\u0435\u0448\u0435\u043d\u0438\u044f" not in body:
        rules.add("review.decisions.required")
    else:
        waiting = body.split("## \u0416\u0434\u0443 \u0440\u0435\u0448\u0435\u043d\u0438\u044f", 1)[1].split("\n## ", 1)[0]
        has_checkbox = re.search(r"^- \[[ xX]\] ", waiting, re.M) is not None
        if not has_checkbox and "\u043d\u0435\u0442 \u043e\u0442\u043a\u0440\u044b\u0442\u044b\u0445 \u0432\u043e\u043f\u0440\u043e\u0441\u043e\u0432" not in waiting.lower():
            rules.add("review.decision-checkbox.required")
    if "\u0422\u0438\u043f: ingest" in body and "## \u041f\u0440\u0438\u043b\u043e\u0436\u0435\u043d\u0438\u0435: \u0438\u0441\u0445\u043e\u0434\u043d\u0438\u043a" not in body:
        rules.add("review.ingest-source.required")
    if meta.get("status") in {"approved", "applied"} and not {
        "approved_by",
        "approved_at",
        "approved_plan_sha256",
    }.issubset(meta):
        rules.add("review.approval-evidence.required")
    return rules


def _task_rules(path: Path) -> set[str]:
    _, body = _frontmatter(path)
    return set() if re.search(r"^- \[[ xX]\] ", body, re.M) else {"task.checkbox.required"}


def _project_rules(path: Path) -> set[str]:
    data = _json(path)
    rules = set()
    for key in ("next_steps", "blockers", "open_questions"):
        if not isinstance(data.get(key), list):
            rules.add("project." + key.replace("_", "-") + ".required")
    if not all(
        isinstance(step, dict) and {"id", "text", "status"}.issubset(step)
        for step in data.get("next_steps", [])
    ):
        rules.add("project.step.shape")
    if data.get("last_session") is not None and not isinstance(
        data.get("last_session"), (str, dict)
    ):
        rules.add("project.last-session.invalid")
    return rules


def _entity_rules(path: Path) -> set[str]:
    rows = _json(path)
    rules = set()
    for row in rows if isinstance(rows, list) else []:
        if row.get("scale") not in {"atom", "initiative", "routine"}:
            rules.add("entity.scale.invalid")
        if row.get("status") not in {"active", "done", "dropped"}:
            rules.add("entity.status.invalid")
        if not isinstance(row.get("trail"), list):
            rules.add("entity.trail.invalid")
        if not isinstance(row.get("created"), str) or not DATE_RE.fullmatch(row["created"]):
            rules.add("entity.created.invalid")
    return rules


def _reading_rules(path: Path) -> set[str]:
    data = _json(path)
    rules = set()
    if not isinstance(data.get("title"), str) or not data.get("title"):
        rules.add("reading.title.required")
    if not isinstance(data.get("current_chapter"), int) or data.get("current_chapter", -1) < 0:
        rules.add("reading.chapter.invalid")
    if not isinstance(data.get("anchors"), list):
        rules.add("reading.anchors.invalid")
    if not isinstance(data.get("started_at"), str) or not DATE_RE.fullmatch(data["started_at"]):
        rules.add("reading.started-at.invalid")
    log_path = PurePosixPath(str(data.get("log_path", "")))
    if log_path.is_absolute() or ".." in log_path.parts:
        rules.add("reading.log-path.unsafe")
    return rules


def _memory_rules(path: Path) -> set[str]:
    rules = set()
    for row in _jsonl(path):
        if not isinstance(row.get("source"), dict):
            rules.add("memory.source.required")
        if not isinstance(row.get("retention"), dict):
            rules.add("memory.retention.required")
        if not row.get("last_confirmed_at"):
            rules.add("memory.last-confirmed.required")
        if not isinstance(row.get("deletion"), dict):
            rules.add("memory.deletion.required")
    return rules


def _schedule_rules(path: Path) -> set[str]:
    data = _json(path)
    rules = set()
    allowed_fields = {
        "name",
        "type",
        "schedule",
        "prompt",
        "status",
        "model",
        "effort",
        "skill",
        "domain",
        "priority",
        "last_run",
        "last_result",
        "retries",
        "max_retries",
        "created_by",
        "created_at",
        "allowed_tools",
        "timeout",
        "cost_class",
        "opus_reason",
        "night_only",
        "execution",
        "command",
        "_ambient_type",
        "created_for",
        "_engine_slug",
        "_project_slug",
    }
    if set(data) - allowed_fields:
        rules.add("schedule.extra-field.invalid")
    if not isinstance(data.get("name"), str) or not data.get("name"):
        rules.add("schedule.name.required")
    if data.get("type") not in {"recurring", "once"}:
        rules.add("schedule.type.invalid")
    if not isinstance(data.get("schedule"), str) or not SCHEDULE_RE.fullmatch(data["schedule"]):
        rules.add("schedule.cadence.invalid")
    if data.get("status", "active") not in {"active", "paused", "completed", "failed", "missed"}:
        rules.add("schedule.status.invalid")
    for field in ("prompt", "created_by"):
        if field in data and not isinstance(data[field], str):
            rules.add(f"schedule.{field.replace('_', '-')}.invalid")
    for field in (
        "model",
        "effort",
        "skill",
        "domain",
        "last_run",
        "last_result",
        "created_at",
        "opus_reason",
        "_ambient_type",
        "created_for",
        "_engine_slug",
        "_project_slug",
    ):
        if data.get(field) is not None and not isinstance(data[field], str):
            rules.add(f"schedule.{field.strip('_').replace('_', '-')}.invalid")
    for field in ("priority", "retries", "max_retries"):
        if not isinstance(data.get(field, 0), int) or data.get(field, 0) < 0:
            rules.add(f"schedule.{field.replace('_', '-')}.invalid")
    if data.get("allowed_tools") is not None and not (
        isinstance(data.get("allowed_tools"), list)
        and all(isinstance(tool, str) for tool in data["allowed_tools"])
    ):
        rules.add("schedule.allowed-tools.invalid")
    if data.get("timeout") is not None and (
        not isinstance(data.get("timeout"), int) or data["timeout"] < 1
    ):
        rules.add("schedule.timeout.invalid")
    if data.get("execution", "claude") not in {"claude", "command"}:
        rules.add("schedule.execution.invalid")
    if data.get("night_only") is not None and not isinstance(data.get("night_only"), bool):
        rules.add("schedule.night-only.invalid")
    if data.get("cost_class") is not None and data.get("cost_class") not in {
        "cheap",
        "standard",
        "premium",
    }:
        rules.add("schedule.cost-class.invalid")
    if data.get("command") is not None and not (
        isinstance(data.get("command"), list)
        and all(isinstance(token, str) for token in data["command"])
    ):
        rules.add("schedule.command.invalid")
    if data.get("execution") == "command" and not (
        isinstance(data.get("command"), list) and data["command"]
    ):
        rules.add("schedule.command.required")
    return rules


CASE_VALIDATORS = {
    "knowledge": _knowledge_rules,
    "review": _review_rules,
    "task": _task_rules,
    "project": _project_rules,
    "entity": _entity_rules,
    "reading": _reading_rules,
    "memory": _memory_rules,
    "schedule": _schedule_rules,
}


def test_fixture_tree_has_no_private_markers():
    assert scan_fixture_tree(FIXTURES) == []


@pytest.mark.parametrize(
    ("rule", "payload"),
    [
        ("private-absolute-path", "cache moved to C:\\Users\\fixture-owner\\vault\\index\n"),
        ("personal-name-marker", "author: Morgan Private\n"),
        ("non-placeholder-email", "contact = person@private-team.test\n"),
        ("private-url-or-host", "See https://notes.team.internal/api for details.\n"),
        ("private-url-or-host", "server = 172.20.8.4\n"),
        ("token-or-secret", '"service_token": "fixture-private-value"\n'),
        (
            "token-or-secret",
            "Author" + "ization: " + "Bea" + "rer abcdefghijklmnopqrst\n",
        ),
        (
            "token-or-secret",
            "---" + "--BEGIN " + "PRIVATE KEY-----\nfixture material\n",
        ),
    ],
)
def test_privacy_scan_rejects_semantic_private_examples(tmp_path, rule, payload):
    injected = tmp_path / "vault-injected"
    injected.mkdir()
    (injected / "record.data").write_text(payload, "utf-8")
    assert rule in {finding.rule for finding in scan_fixture_tree(injected)}


@pytest.mark.parametrize(
    "payload",
    [
        "owner: Morgan Private\n",
        '"person": "Casey Actual"\n',
        "The note was written by Morgan Private after review.\n",
    ],
)
def test_privacy_scan_rejects_bounded_person_shapes_in_fields_and_prose(tmp_path, payload):
    root = tmp_path / "vault-injected"
    root.mkdir()
    (root / "note.txt").write_text(payload, "utf-8")
    assert "personal-name-marker" in {finding.rule for finding in scan_fixture_tree(root)}


@pytest.mark.parametrize(
    "payload",
    [
        "host: private-workstation-17\n",
        "The export came from workstation private-workstation-17.\n",
        "The build ran on host devbox-42.\n",
        "The machine was named privatebuildnode.\n",
    ],
)
def test_privacy_scan_rejects_keyword_bound_bare_hosts(tmp_path, payload):
    root = tmp_path / "vault-injected"
    root.mkdir()
    (root / "note.txt").write_text(payload, "utf-8")
    assert "private-url-or-host" in {finding.rule for finding in scan_fixture_tree(root)}


def test_privacy_scan_checks_unknown_suffix_symlink_non_utf8_and_local_markers(tmp_path):
    root = tmp_path / "vault-injected"
    root.mkdir()
    (root / "opaque.blob").write_text("owner_name = Casey Actual\n", "utf-8")
    (root / "broken.bin").write_bytes(b"\xff\xfe")
    target = root / "target.txt"
    target.write_text("synthetic\n", "utf-8")
    (root / "linked.txt").symlink_to(target)
    (root / "marker.txt").write_text("Private Fixture Owner\n", "utf-8")

    findings = scan_fixture_tree(root, private_markers=("Private Fixture Owner",))
    observed = {(finding.path, finding.rule) for finding in findings}
    assert ("opaque.blob", "personal-name-marker") in observed
    assert ("broken.bin", "non-utf8") in observed
    assert ("linked.txt", "symlink") in observed
    assert ("marker.txt", "local-person-or-host-marker") in observed


def test_local_markers_include_login_and_real_hosts_when_home_is_patched(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "decoy-home"))
    expected = {
        value.strip().casefold()
        for value in (getpass.getuser(), socket.gethostname(), socket.getfqdn())
        if len(value.strip()) >= 4 and value.casefold() not in {"home", "localhost"}
    }
    markers = {value.casefold() for value in _local_private_markers(())}
    assert expected <= markers

    root = tmp_path / "vault-injected"
    root.mkdir()
    (root / "runtime.txt").write_text("\n".join(sorted(expected)) + "\n", "utf-8")
    assert "local-person-or-host-marker" in {finding.rule for finding in scan_fixture_tree(root)}


def test_privacy_scan_allows_reserved_examples_and_secret_references(tmp_path):
    root = tmp_path / "vault-safe"
    root.mkdir()
    (root / "safe.txt").write_text(
        "author: fixture-person\n"
        "contact: fixture@example.invalid\n"
        "endpoint: https://docs.example.invalid/api\n"
        "owner: human\n"
        "person: synthetic-person\n"
        "The Portable Systems Handbook is a synthetic title.\n"
        "The host application renders a fixture view.\n"
        "The build ran on workstation fixture-node.\n"
        'api_token = "${FIXTURE_API_TOKEN}"\n'
        'bot_token_env = "FIXTURE_BOT_TOKEN"\n',
        "utf-8",
    )
    assert scan_fixture_tree(root) == []


def test_fixture_map_covers_target_and_characterization_domains():
    minimal = FIXTURES / "vault-minimal"
    populated = FIXTURES / "vault-populated"
    legacy = FIXTURES / "vault-legacy-characterization"
    required_minimal_dirs = {
        "inbox",
        "review",
        "tasks",
        "projects",
        "knowledge",
        "agent/memory",
        "agent/logs",
        "agent/dashboard",
        "agent/runs",
        "agent/outbox",
    }
    assert (minimal / "lifeos.toml").is_file()
    assert all((minimal / rel).is_dir() for rel in required_minimal_dirs)

    required_populated = {
        "knowledge": populated / "knowledge/domains/ai/portable-workflow.md",
        "review": populated / "review/rev_fixture-001.md",
        "tasks": populated / "tasks/2026-01-15.md",
        "project": populated / "projects/portable-fixture/project.json",
        "entity": populated / "knowledge/domains/ai/entities.json",
        "reading": populated / "agent/reading/portable-handbook.json",
        "memory": populated / "agent/memory/decisions.jsonl",
    }
    assert all(path.is_file() for path in required_populated.values())
    assert not any((populated / "agent/schedule").glob("*"))
    assert (legacy / "agent/schedule/valid/ambient-scan.json").is_file()


def test_review_plan_has_real_non_noop_hashes_and_payload():
    vault = FIXTURES / "vault-populated"
    review_path = vault / "review/rev_fixture-001.md"
    meta, _ = _frontmatter(review_path)
    provenance = meta["provenance"]
    source_hashes = provenance["source_hashes"]
    assert isinstance(source_hashes, dict) and source_hashes
    for rel, expected_hash in source_hashes.items():
        source = vault / rel
        assert source.is_file()
        assert SHA256_RE.fullmatch(expected_hash)
        assert _sha256(source.read_bytes()) == expected_hash

    plan_rel = PurePosixPath(meta["plan_path"])
    assert not plan_rel.is_absolute() and ".." not in plan_rel.parts
    plan = _json(vault / plan_rel)
    assert plan["review_id"] == meta["id"]
    assert plan["operations"]
    for operation in plan["operations"]:
        target_rel = PurePosixPath(operation["path"])
        assert target_rel.parts[0] == "knowledge"
        target = vault / target_rel
        before = target.read_bytes()
        after = operation["content"].encode("utf-8")
        assert operation["op"] == "update"
        assert _sha256(before) == operation["precondition_sha256"]
        assert _sha256(after) == operation["postcondition_sha256"]
        assert before != after
        assert operation["precondition_sha256"] != operation["postcondition_sha256"]


def test_populated_run_envelope_trace_and_outbox_follow_design_contracts():
    vault = FIXTURES / "vault-populated"
    run_dir = vault / "agent/runs/run_fixture-001"
    state = _json(run_dir / "state.json")
    assert set(state) == {
        "schema_version",
        "run_id",
        "flow",
        "status",
        "phase",
        "authority",
        "executor",
        "input",
        "artifacts",
        "attempt",
        "created_at",
        "updated_at",
        "waiting_for",
        "last_error",
    }
    assert state["status"] in {
        "created",
        "running",
        "waiting_human",
        "succeeded",
        "failed",
        "quota_wait",
        "transient_wait",
        "cancelled",
    }
    assert state["status"] == "waiting_human" and state["waiting_for"]
    assert isinstance(state["input"], dict) and isinstance(state["artifacts"], dict)
    assert isinstance(state["attempt"], int) and state["attempt"] >= 1
    assert "model" not in state and "effort" not in state
    for artifact in state["artifacts"].values():
        assert (vault / artifact).is_file()

    for event in _jsonl(run_dir / "trace.jsonl"):
        assert {
            "at",
            "run_id",
            "step_id",
            "input_hash",
            "output_hash",
            "executor_profile",
            "tool_outcomes",
        }.issubset(event)
        assert SHA256_RE.fullmatch(event["input_hash"])
        assert SHA256_RE.fullmatch(event["output_hash"])
        assert isinstance(event["tool_outcomes"], list)

    outbox = _json(vault / "agent/outbox/event_fixture-001.json")
    assert {
        "type",
        "summary",
        "artifact_ref",
        "urgency",
        "dedupe_key",
        "delivery_policy",
    }.issubset(outbox)
    assert outbox["summary"] and outbox["dedupe_key"]
    assert outbox["delivery_policy"]["surface"] in {"silent", "batched", "gated"}
    assert (vault / outbox["artifact_ref"]).is_file()
    assert not {"token", "chat_id", "channel_secret"}.intersection(outbox)


def test_populated_domain_records_match_public_target_contracts():
    """These local validators characterize public target fixtures, not legacy code."""
    vault = FIXTURES / "vault-populated"
    assert not _knowledge_rules(vault / "knowledge/domains/ai/portable-workflow.md")
    assert not _review_rules(vault / "review/rev_fixture-001.md")
    assert not _task_rules(vault / "tasks/2026-01-15.md")
    assert not _project_rules(vault / "projects/portable-fixture/state.json")
    assert not _entity_rules(vault / "knowledge/domains/ai/entities.json")
    assert not _reading_rules(vault / "agent/reading/portable-handbook.json")
    assert not _memory_rules(vault / "agent/memory/decisions.jsonl")
    assert not _schedule_rules(
        FIXTURES / "vault-legacy-characterization/agent/schedule/valid/ambient-scan.json"
    )


@pytest.mark.parametrize(
    ("heading", "replacement", "expected_rule"),
    [
        ("## \u041c\u0435\u0442\u0430", "## Fixture details", "review.meta.required"),
        ("## \u0416\u0434\u0443 \u0440\u0435\u0448\u0435\u043d\u0438\u044f", "## Fixture decision", "review.decisions.required"),
    ],
)
def test_public_review_contract_requires_decision_sections(
    tmp_path, heading, replacement, expected_rule
):
    source = (FIXTURES / "vault-populated/review/rev_fixture-001.md").read_text("utf-8")
    mutation = tmp_path / "review.md"
    mutation.write_text(source.replace(heading, replacement), "utf-8")
    assert _review_rules(mutation) == {expected_rule}


def test_public_project_contract_accepts_object_last_session(tmp_path):
    state = tmp_path / "state.json"
    state.write_text(
        json.dumps(
            {
                "next_steps": [],
                "blockers": [],
                "open_questions": [],
                "last_session": {"at": "2026-01-15T10:00:00Z", "summary": "synthetic"},
            }
        ),
        "utf-8",
    )
    assert _project_rules(state) == set()


@pytest.mark.parametrize(
    ("field", "value", "expected_rule"),
    [
        ("unexpected", True, "schedule.extra-field.invalid"),
        ("status", "unknown", "schedule.status.invalid"),
        ("allowed_tools", "shell", "schedule.allowed-tools.invalid"),
        ("timeout", 0, "schedule.timeout.invalid"),
    ],
)
def test_public_schedule_contract_rejects_strict_field_mutations(
    tmp_path, field, value, expected_rule
):
    schedule = _json(
        FIXTURES / "vault-legacy-characterization/agent/schedule/valid/ambient-scan.json"
    )
    schedule[field] = value
    mutation = tmp_path / "schedule.json"
    mutation.write_text(json.dumps(schedule), "utf-8")
    assert _schedule_rules(mutation) == {expected_rule}


def test_broken_variants_are_independent_seed_mutations():
    cases = _json(FIXTURES / "vault-broken/cases.json")
    assert len({case["id"] for case in cases}) == len(cases)
    for case in cases:
        validator = CASE_VALIDATORS[case["contract"]]
        seed = FIXTURES / PurePosixPath(case["seed"])
        mutation = FIXTURES / PurePosixPath(case["mutation"])
        assert seed.is_file() and mutation.is_file() and seed != mutation
        assert validator(seed) == set(), case["id"]
        assert validator(mutation) == {case["expected_rule"]}, case["id"]


@pytest.mark.parametrize("initial_setting", [False, True])
def test_source_loader_is_cache_miss_no_bytecode_and_restores_process_state(
    tmp_path, monkeypatch, initial_setting
):
    source = tmp_path / "synthetic_opt_in_module.py"
    source.write_text("VALUE = 'synthetic'\n", "utf-8")
    module_name = f"_lifeos_no_bytecode_{initial_setting}"
    monkeypatch.setattr(sys, "dont_write_bytecode", initial_setting)
    assert not (tmp_path / "__pycache__").exists()

    with _loaded_source_no_bytecode(source, module_name) as module:
        assert module.VALUE == "synthetic"
        assert sys.dont_write_bytecode is initial_setting
        assert sys.modules[module_name] is module

    assert sys.dont_write_bytecode is initial_setting
    assert module_name not in sys.modules
    assert not (tmp_path / "__pycache__").exists()
    assert not list(tmp_path.rglob("*.pyc"))


def test_source_loader_restores_state_when_module_execution_fails(tmp_path, monkeypatch):
    source = tmp_path / "synthetic_failing_module.py"
    source.write_text("raise RuntimeError('synthetic import failure')\n", "utf-8")
    module_name = "_lifeos_no_bytecode_failure"
    previous_module = ModuleType(module_name)
    monkeypatch.setitem(sys.modules, module_name, previous_module)
    monkeypatch.setattr(sys, "dont_write_bytecode", False)

    with pytest.raises(RuntimeError, match="synthetic import failure"):
        with _loaded_source_no_bytecode(source, module_name):
            pytest.fail("failing source must not reach the context body")

    assert sys.dont_write_bytecode is False
    assert sys.modules[module_name] is previous_module
    assert not (tmp_path / "__pycache__").exists()
    assert not list(tmp_path.rglob("*.pyc"))


def test_opt_in_exact_legacy_validators_accept_synthetic_fixtures(monkeypatch):
    """Opt-in only: load exact private validators after a read-only config check."""
    raw_config = os.environ.get("LIFEOS_LEGACY_COMPAT_CONFIG")
    if not raw_config:
        pytest.skip("set LIFEOS_LEGACY_COMPAT_CONFIG to opt into read-only legacy validation")

    config_path = Path(raw_config)
    config = tomllib.loads(config_path.read_text("utf-8"))
    migration = config["migration"]["legacy_vault"]
    assert migration["read_only"] is True
    legacy_root = Path(migration["path"])
    assert legacy_root.is_absolute() and legacy_root.is_dir()

    validate_path = legacy_root / "system/scripts/utils/validate_note.py"
    task_schema_path = legacy_root / "system/scripts/infra/task_schema.py"
    assert validate_path.is_file() and task_schema_path.is_file()
    before = {path: _sha256(path.read_bytes()) for path in (validate_path, task_schema_path)}

    with (
        _loaded_source_no_bytecode(
            validate_path, "_lifeos_opt_in_legacy_validate_note"
        ) as legacy_validate,
        _loaded_source_no_bytecode(
            task_schema_path, "_lifeos_opt_in_legacy_task_schema"
        ) as legacy_task_schema,
    ):
        populated = FIXTURES / "vault-populated"
        monkeypatch.setattr(legacy_validate, "VAULT_ROOT", populated)
        for relative in (
            "knowledge/domains/ai/portable-workflow.md",
            "review/rev_fixture-001.md",
            "tasks/2026-01-15.md",
            "projects/portable-fixture/state.json",
        ):
            assert legacy_validate.validate_note(populated / relative) == [], relative

        schedule = _json(
            FIXTURES / "vault-legacy-characterization/agent/schedule/valid/ambient-scan.json"
        )
        legacy_task_schema.TaskSchema.model_validate(schedule)
    assert {path: _sha256(path.read_bytes()) for path in before} == before


def test_every_machine_fixture_is_syntactically_parseable():
    for path in FIXTURES.rglob("*"):
        if path.is_file() and not path.is_symlink():
            if path.suffix == ".json":
                _json(path)
            elif path.suffix == ".jsonl":
                _jsonl(path)
            elif path.suffix == ".toml":
                tomllib.loads(path.read_text("utf-8"))
