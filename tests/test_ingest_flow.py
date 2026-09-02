"""P3-02 deterministic ingest routing and review-only output acceptance."""

from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path
import shutil

import pytest

from tool_life_os_runtime.ext.flows.ingest import (
    INGEST_CONNECTOR_SCHEMA_VERSION,
    INGEST_SCHEMA_VERSION,
    IngestCapabilities,
    IngestConnectorRequest,
    IngestConnectorResult,
    IngestError,
    IngestFlow,
    IngestInput,
    InMemoryIngestDedupeStore,
    classify_ingest_input,
    parse_ingest_input,
    parse_ingest_result,
    render_ingest_input,
    render_ingest_result,
)
from tool_life_os_runtime.ext.review.artifact import validate_artifact_plan
from tool_life_os_runtime.ext.review.authority import AuthorityPolicy
from tool_life_os_runtime.ext.vault.config import load_vault_config
from tool_life_os_runtime.ext.vault.schema import VaultPathResolver


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/vault-minimal"
ZERO = "0" * 64

INGEST_ACTIONS = {
    "classify-declared-input": ("read", "external:declared-input"),
    "read-inbox-dedupe-state": ("read", "vault:inbox"),
    "read-source-manifest": ("read", "tool:source-manifest"),
    "extract-heavy-input": ("internal-write", "tool:coursedump"),
    "research-heavy-input": ("internal-write", "tool:researcher"),
    "commit-review-proposal": ("proposal", "vault:review"),
}


def _note(title: str = "Synthetic inbox note", body: str = "Portable content.") -> str:
    return f'---\ntags:\n  - fixture\ndate: "2026-08-20"\n---\n\n# {title}\n\n{body}\n'


def _snapshot(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file() and not path.is_symlink()
    }


class _Connector:
    def __init__(self) -> None:
        self.calls: list[IngestConnectorRequest] = []

    def collect(self, request: IngestConnectorRequest) -> IngestConnectorResult:
        self.calls.append(request)
        content = _note(
            f"Synthetic {request.classification}",
            "Normalized connector content with explicit source provenance.",
        )
        return IngestConnectorResult(
            INGEST_CONNECTOR_SCHEMA_VERSION,
            request.connector,
            f"{request.connector}/manifests/{request.classification}.json",
            request.canonical_source_sha256,
            hashlib.sha256(
                f"manifest:{request.canonical_source}".encode("utf-8")
            ).hexdigest(),
            hashlib.sha256(content.encode("utf-8")).hexdigest(),
            content,
        )


def _issue(policy: AuthorityPolicy, action_id: str):
    authority, target = INGEST_ACTIONS[action_id]
    return policy.issue(
        flow_id="ingest",
        action_id=action_id,
        actor="runtime",
        authority=authority,
        target=target,
    )


def _setup(tmp_path: Path, *, connector=None, dedupe_store=None):
    vault = tmp_path / "vault"
    shutil.copytree(FIXTURE, vault)
    (vault / "inbox/capture.md").write_text(_note(), "utf-8")
    policy = AuthorityPolicy()
    resolver = VaultPathResolver(vault, load_vault_config(vault))
    caps = IngestCapabilities(
        classify=_issue(policy, "classify-declared-input"),
        read_dedupe=_issue(policy, "read-inbox-dedupe-state"),
        commit_review=_issue(policy, "commit-review-proposal"),
        note_read=policy.issue(
            flow_id="obsidian",
            action_id="read-inbox-note",
            actor="runtime",
            authority="read",
            target="vault:inbox",
        ),
        read_manifest=_issue(policy, "read-source-manifest"),
        extract=_issue(policy, "extract-heavy-input"),
        research=_issue(policy, "research-heavy-input"),
    )
    store = dedupe_store or InMemoryIngestDedupeStore()
    return (
        vault,
        policy,
        caps,
        IngestFlow(resolver, policy, dedupe_store=store, connector=connector),
    )


def _request(
    source: str,
    *,
    kind: str = "auto",
    review_id: str = "rev_ingest_one",
    target: str = "knowledge/domains/inbox/synthetic.md",
) -> IngestInput:
    return IngestInput(
        INGEST_SCHEMA_VERSION,
        "run_ingest_one",
        review_id,
        "2026-08-20T12:00:00Z",
        kind,
        source,
        target,
        "gated",
    )


@pytest.mark.parametrize(
    ("source", "kind", "classification", "canonical_suffix"),
    [
        ("inbox/capture.md", "auto", "note", "inbox/capture.md"),
        (
            "https://example.test/article?b=2&a=1#part",
            "auto",
            "url",
            "/article?a=1&b=2",
        ),
        ("https://youtu.be/synthetic", "auto", "video", "/synthetic"),
        (
            "https://example.test/books/portable.epub",
            "auto",
            "book",
            "/books/portable.epub",
        ),
        (
            "https://example.test/courses/portable",
            "auto",
            "course",
            "/courses/portable",
        ),
        (
            "synthetic unclassified input",
            "auto",
            "unknown",
            "synthetic unclassified input",
        ),
    ],
)
def test_deterministic_routing_matrix(source, kind, classification, canonical_suffix):
    actual, canonical = classify_ingest_input(_request(source, kind=kind))

    assert actual == classification
    assert canonical.endswith(canonical_suffix)


@pytest.mark.parametrize("classification", ["url", "video", "book", "course"])
def test_heavy_inputs_use_only_injected_connector_and_return_review(
    tmp_path: Path, classification: str
) -> None:
    connector = _Connector()
    vault, _, caps, flow = _setup(tmp_path, connector=connector)
    before = _snapshot(vault)
    source = {
        "url": "https://example.test/article",
        "video": "https://example.test/media/lesson.mp4",
        "book": "https://example.test/library/book.epub",
        "course": "https://example.test/courses/course-one",
    }[classification]

    result = flow.ingest(
        _request(source, kind=classification, review_id=f"rev_{classification}_one"),
        capabilities=caps,
    )

    expected_connector = "researcher" if classification == "url" else "coursedump"
    assert result.classification == classification
    assert result.route == expected_connector
    assert result.status == "proposed"
    assert result.review_artifact is not None
    assert result.mutation_plan is not None
    assert result.review_artifact.flow == "ingest"
    assert result.review_artifact.status == "proposed"
    assert validate_artifact_plan(result.review_artifact, result.mutation_plan)
    assert [call.connector for call in connector.calls] == [expected_connector]
    assert _snapshot(vault) == before


def test_local_note_uses_obsidian_read_validation_and_never_writes_vault(
    tmp_path: Path,
) -> None:
    vault, _, caps, flow = _setup(tmp_path)
    before = _snapshot(vault)

    result = flow.ingest(_request("inbox/capture.md"), capabilities=caps)

    assert result.classification == "note"
    assert result.route == "local-note"
    assert result.review_artifact is not None
    assert result.mutation_plan is not None
    assert result.mutation_plan.operations[0].content == _note()
    assert result.review_artifact.sources[0].ref == "inbox/capture.md"
    assert _snapshot(vault) == before
    assert not list(vault.rglob("rev_ingest_one*"))


def test_invalid_local_note_is_rejected_by_obsidian_primitives(tmp_path: Path) -> None:
    vault, _, caps, flow = _setup(tmp_path)
    (vault / "inbox/capture.md").write_text("# Missing frontmatter\n", "utf-8")

    with pytest.raises(IngestError, match="read safely"):
        flow.ingest(_request("inbox/capture.md"), capabilities=caps)


def test_unknown_returns_bounded_explicit_fallback_without_connector_or_proposal(
    tmp_path: Path,
) -> None:
    connector = _Connector()
    _, _, caps, flow = _setup(tmp_path, connector=connector)
    minimal = IngestCapabilities(caps.classify, caps.read_dedupe)

    result = flow.ingest(_request("synthetic unsupported input"), capabilities=minimal)

    assert result.classification == "unknown"
    assert result.route == "fallback"
    assert result.status == "unsupported"
    assert result.review_artifact is None
    assert result.mutation_plan is None
    assert result.fallback is not None
    assert result.fallback.accepted_kinds == (
        "note",
        "url",
        "video",
        "book",
        "course",
    )
    assert len(result.fallback.message.encode("utf-8")) <= 1024
    assert connector.calls == []


def test_canonical_input_and_result_json_round_trip_strictly(tmp_path: Path) -> None:
    connector = _Connector()
    _, _, caps, flow = _setup(tmp_path, connector=connector)
    request = _request("https://example.test/article")

    assert parse_ingest_input(render_ingest_input(request)) == request
    result = flow.ingest(request, capabilities=caps)
    assert parse_ingest_result(render_ingest_result(result)) == result

    raw = json.loads(render_ingest_input(request))
    raw["unknown"] = True
    malformed = json.dumps(raw, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    with pytest.raises(IngestError, match="unknown fields"):
        parse_ingest_input(malformed)
    with pytest.raises(IngestError, match="duplicate"):
        parse_ingest_input(
            b'{"created_at":"2026-08-20T12:00:00Z","created_at":"2026-08-20T12:00:00Z"}\n'
        )
    with pytest.raises(IngestError, match="canonical JSON"):
        parse_ingest_input(
            render_ingest_input(request).replace(b'"kind":"auto"', b'"kind": "auto"')
        )


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("route", "coursedump"),
        ("connector", "coursedump"),
        ("source_ref", "researcher/manifests/other.json"),
        ("dedupe_key", ZERO),
    ],
)
def test_result_top_level_route_connector_source_and_dedupe_bind_nested_proposal(
    tmp_path: Path, field: str, replacement: str
) -> None:
    connector = _Connector()
    _, _, caps, flow = _setup(tmp_path, connector=connector)
    result = flow.ingest(_request("https://example.test/article"), capabilities=caps)
    payload = json.loads(render_ingest_result(result))
    payload[field] = replacement
    tampered = (
        json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode()

    with pytest.raises(IngestError):
        parse_ingest_result(tampered)


@pytest.mark.parametrize(
    "ingest_input",
    [
        replace(_request("inbox/capture.md"), schema_version=2),
        replace(_request("inbox/capture.md"), source="x" * (16 * 1024 + 1)),
        replace(_request("inbox/capture.md"), source="inbox/cafe\u0301.md"),
        replace(_request("inbox/capture.md"), source="inbox/_archive/capture.md"),
        replace(
            _request("inbox/capture.md"), target_path="knowledge/_trash/capture.md"
        ),
        replace(
            _request("inbox/capture.md"), target_path="knowledge/domains/cafe\u0301.md"
        ),
    ],
)
def test_malformed_bounds_nfc_and_archive_paths_fail_closed(ingest_input) -> None:
    with pytest.raises(IngestError):
        render_ingest_input(ingest_input)


def test_exact_capabilities_are_required_before_route_effects(tmp_path: Path) -> None:
    connector = _Connector()
    vault, policy, caps, flow = _setup(tmp_path, connector=connector)
    before = _snapshot(vault)

    with pytest.raises(IngestError, match="exact ingest action"):
        flow.ingest(
            _request("https://example.test/article"),
            capabilities=replace(caps, classify=caps.read_dedupe),
        )
    with pytest.raises(IngestError, match="exact ingest action"):
        flow.ingest(
            _request("https://example.test/article"),
            capabilities=replace(caps, read_dedupe=caps.classify),
        )
    with pytest.raises(IngestError, match="research-heavy-input"):
        flow.ingest(
            _request("https://example.test/article"),
            capabilities=replace(caps, research=None),
        )
    other = AuthorityPolicy()
    foreign = other.issue(
        flow_id="ingest",
        action_id="classify-declared-input",
        actor="runtime",
        authority="read",
        target="external:declared-input",
    )
    with pytest.raises(IngestError, match="not issued"):
        flow.ingest(
            _request("synthetic unknown"),
            capabilities=replace(caps, classify=foreign),
        )

    assert connector.calls == []
    assert _snapshot(vault) == before
    assert policy.matrix_sha256 == caps.classify.matrix_sha256


def test_wrong_obsidian_capability_cannot_read_local_note(tmp_path: Path) -> None:
    vault, _, caps, flow = _setup(tmp_path)
    before = _snapshot(vault)

    with pytest.raises(IngestError, match="read safely"):
        flow.ingest(
            _request("inbox/capture.md"),
            capabilities=replace(caps, note_read=caps.classify),
        )

    assert _snapshot(vault) == before


def test_cross_instance_replay_binds_exact_request_and_skips_connector(
    tmp_path: Path,
) -> None:
    connector = _Connector()
    store = InMemoryIngestDedupeStore()
    vault, policy, caps, first_flow = _setup(
        tmp_path, connector=connector, dedupe_store=store
    )
    request = _request(
        "https://EXAMPLE.test/article?b=2&a=1#first",
        review_id="rev_dedupe_one",
    )
    first = first_flow.ingest(request, capabilities=caps)
    second_flow = IngestFlow(
        VaultPathResolver(vault, load_vault_config(vault)),
        policy,
        dedupe_store=store,
    )
    with pytest.raises(IngestError, match="conflicts with stored evidence"):
        second_flow.ingest(
            _request(
                "https://example.test/article?a=1&b=2",
                review_id="rev_dedupe_other",
            ),
            capabilities=caps,
        )
    with pytest.raises(IngestError, match="conflicts with stored evidence"):
        second_flow.ingest(
            _request(
                "https://example.test/article?a=1&b=2",
                review_id="rev_dedupe_one",
                target="knowledge/domains/inbox/other.md",
            ),
            capabilities=caps,
        )
    second = second_flow.ingest(
        _request(
            "https://example.test/article?a=1&b=2#second",
            review_id="rev_dedupe_one",
        ),
        capabilities=caps,
    )

    assert first.dedupe_key == second.dedupe_key
    assert not first.replayed and second.replayed
    assert second.review_artifact == first.review_artifact
    assert second.mutation_plan == first.mutation_plan
    assert len(connector.calls) == 1


def test_same_review_id_with_changed_note_content_conflicts(tmp_path: Path) -> None:
    store = InMemoryIngestDedupeStore()
    vault, policy, caps, flow = _setup(tmp_path, dedupe_store=store)
    flow.ingest(_request("inbox/capture.md"), capabilities=caps)
    (vault / "inbox/capture.md").write_text(
        _note(body="Changed portable content."), "utf-8"
    )
    retry = IngestFlow(
        VaultPathResolver(vault, load_vault_config(vault)),
        policy,
        dedupe_store=store,
    )
    with pytest.raises(IngestError, match="conflicts with stored evidence"):
        retry.ingest(_request("inbox/capture.md"), capabilities=caps)


def test_same_review_id_with_changed_route_conflicts_before_connector(
    tmp_path: Path,
) -> None:
    connector = _Connector()
    store = InMemoryIngestDedupeStore()
    vault, policy, caps, flow = _setup(
        tmp_path, connector=connector, dedupe_store=store
    )
    source = "https://example.test/courses/portable"
    flow.ingest(_request(source, kind="course"), capabilities=caps)
    retry = IngestFlow(
        VaultPathResolver(vault, load_vault_config(vault)),
        policy,
        dedupe_store=store,
        connector=connector,
    )

    with pytest.raises(IngestError, match="conflicts with stored evidence"):
        retry.ingest(_request(source, kind="url"), capabilities=caps)

    assert len(connector.calls) == 1


@pytest.mark.parametrize("mode", ["exception", "bad-binding", "bad-content"])
def test_connector_errors_and_malformed_results_are_normalized(
    tmp_path: Path, mode: str
) -> None:
    class _BadConnector:
        def collect(self, request):
            if mode == "exception":
                raise RuntimeError("connector credential detail")
            content = _note()
            return IngestConnectorResult(
                INGEST_CONNECTOR_SCHEMA_VERSION,
                request.connector,
                "connector/manifests/source.json",
                ZERO if mode == "bad-binding" else request.canonical_source_sha256,
                ZERO,
                ZERO
                if mode == "bad-content"
                else hashlib.sha256(content.encode()).hexdigest(),
                content,
            )

    _, _, caps, flow = _setup(tmp_path, connector=_BadConnector())

    with pytest.raises(IngestError) as raised:
        flow.ingest(_request("https://example.test/article"), capabilities=caps)
    assert "credential" not in str(raised.value)


def test_temporary_clean_vault_has_no_configured_or_legacy_source_access(
    tmp_path: Path,
) -> None:
    connector = _Connector()
    vault, _, caps, flow = _setup(tmp_path, connector=connector)
    before = _snapshot(vault)

    result = flow.ingest(
        _request("https://example.test/courses/clean", kind="course"),
        capabilities=caps,
    )

    assert result.review_artifact is not None
    assert result.mutation_plan is not None
    assert all(
        not path.is_absolute()
        for path in (Path(source.ref) for source in result.review_artifact.sources)
    )
    assert _snapshot(vault) == before
