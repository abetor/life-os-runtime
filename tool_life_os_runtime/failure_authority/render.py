"""Deterministic JSON and Markdown rendering for the P0 matrix."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from .validation import load_matrix, validate_matrix


def render_json(payload: Mapping[str, Any]) -> str:
    validate_matrix(payload)
    return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def render_markdown(payload: Mapping[str, Any], *, json_sha256: str) -> str:
    validate_matrix(payload)
    lines = [
        "# Failure and authority matrix",
        "",
        "JSON is the authoritative artifact. Markdown is a deterministic projection.",
        f"SHA-256 JSON: `{json_sha256}`.",
        "",
        "All paths below are symbolic contract zones, not filesystem paths.",
        "Legacy and migration roots are never write targets.",
        "The scheduler invokes the runtime with internal-write authority, but the runtime reauthorizes each downstream action as system.",
        "The runtime connector reads the outbox and sends normalized stdin; gateway transport does not read the vault, while receipt commit and reconciliation remain separate actions.",
        "",
        "| Flow | Actor | Eval | Ceiling | Reads | Writes | Invokes | Retry | Rollback |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for flow in payload["flows"]:
        cells = (
            flow["flow_id"], flow["actor"], flow["eval_class"], flow["authority_ceiling"],
            ", ".join(flow["allowed_reads"]) or "none",
            ", ".join(flow["allowed_writes"]) or "none",
            ", ".join(flow["allowed_invocations"]) or "none",
            flow["retry_owner"], flow["rollback"],
        )
        lines.append("| " + " | ".join(cells) + " |")
    lines.extend(["", "## Actions", ""])
    for flow in payload["flows"]:
        lines.extend(
            [
                f"### `{flow['flow_id']}`",
                "",
                f"Crash points: {', '.join(flow['crash_points'])}.",
                "Irreversible effects: " + (", ".join(flow["irreversible_effects"]) or "none") + ".",
                "",
                "| Action | Actor | Authority | Access | Target | Effect | Artifact commit | Retry | Rollback |",
                "|---|---|---|---|---|---|---|---|---|",
            ]
        )
        for action in flow["actions"]:
            lines.append(
                "| "
                + " | ".join(
                    (
                        action["action_id"], action["actor"], action["authority"],
                        action["access"], action["target"], action["effect_kind"],
                        "yes" if action["artifact_commit"] else "no",
                        action["retry_owner"], action["rollback"],
                    )
                )
                + " |"
            )
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_pair(payload: Mapping[str, Any]) -> tuple[str, str]:
    json_text = render_json(payload)
    digest = hashlib.sha256(json_text.encode("utf-8")).hexdigest()
    return json_text, render_markdown(payload, json_sha256=digest)


def check_artifacts(json_path: Path, markdown_path: Path) -> None:
    payload = load_matrix(json_path)
    expected_json, expected_markdown = render_pair(payload)
    if json_path.read_text("utf-8") != expected_json:
        raise ValueError("JSON artifact is not canonical")
    if markdown_path.read_text("utf-8") != expected_markdown:
        raise ValueError("Markdown projection does not match JSON")
