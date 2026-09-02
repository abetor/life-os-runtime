"""Independent filesystem and call-trace observations for legacy contracts."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping


Observation = dict[str, Any]


@dataclass(frozen=True)
class ObservationInput:
    root: Path
    slug: str = "portable-project"
    review_name: str = "rev_fixture.md"
    period: str = "2026-01-15"
    entity_id: str = "ent-001"
    reading_slug: str = "portable-handbook"
    entity_path: str = "agent/memory/entities/ai.json"
    done_path: str = "agent/logs/done-events.jsonl"
    trail_path: str = "agent/memory/trails/ent-001.jsonl"


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text("utf-8"))


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text("utf-8").splitlines() if line]


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _relative_shape(path: Path, root: Path, slug: str) -> str:
    relative = path.relative_to(root).as_posix()
    if relative.startswith(f"projects/_archive/{slug}-"):
        return "projects/_archive/<slug>-<date>"
    if relative == f"projects/{slug}/project.json":
        return "projects/<slug>"
    return relative


def observe_review_apply(source: ObservationInput) -> Observation:
    root = source.root
    stem = Path(source.review_name).stem
    return {
        "review_archived": (root / "_trash" / source.review_name).is_file(),
        "marker_removed": not (
            root / "agent/_buffer/apply-in-progress" / f"{stem}.json"
        ).exists(),
    }


def observe_project_transitions(source: ObservationInput) -> Observation:
    root = source.root
    matches = sorted(root.glob(f"projects/**/{source.slug}*/project.json"))
    if len(matches) != 1:
        location = "missing-or-ambiguous"
        project_status = None
    else:
        location = _relative_shape(matches[0], root, source.slug)
        project_status = _read_json(matches[0]).get("status")
    engine_paths = sorted(root.glob(f"projects/**/{source.slug}*/research/*/project.json"))
    schedule = root / "agent/schedule/portable-schedule.json"
    return {
        "archived_location": location,
        "project_status": project_status,
        "engine_status": _read_json(engine_paths[0]).get("status") if engine_paths else None,
        "schedule_status": _read_json(schedule).get("status") if schedule.is_file() else None,
    }


def observe_task_rollover(source: ObservationInput) -> Observation:
    root = source.root
    events = _read_jsonl(root / "trace.jsonl")
    names = [event["event"] for event in events]
    snapshot = root / f"agent/logs/tasks/{source.period}.md"
    preimage = root / "preimage.md"
    return {
        "snapshot_precedes_replace": names.index("snapshot") < names.index("replace"),
        "snapshot_preserves_preimage": _sha256(snapshot) == _sha256(preimage),
    }


def observe_entity_done_trails(source: ObservationInput) -> Observation:
    root = source.root
    entity_path = root / source.entity_path
    done_path = root / source.done_path
    trail_path = root / source.trail_path
    entity = _read_json(entity_path)[0]
    done_payload = _read_json(done_path) if done_path.suffix == ".json" else None
    done = done_payload["events"][0] if done_payload is not None else _read_jsonl(done_path)[0]
    trail = _read_jsonl(trail_path)
    return {
        "record_paths_distinct": len({entity_path, done_path, trail_path}) == 3,
        "identifier_namespaces_distinct": entity["id"] != done["id"],
        "trail_entry_count": len(trail),
    }


def observe_reading(source: ObservationInput) -> Observation:
    root = source.root
    state = root / f"agent/reading/{source.reading_slug}.json"
    log = root / f"agent/reading/{source.reading_slug}-log.md"
    text = log.read_text("utf-8") if log.is_file() else ""
    return {
        "state_removed": not state.exists(),
        "log_retained": log.is_file(),
        "close_recorded": "closed: finished" in text,
    }


def observe_surface(source: ObservationInput) -> Observation:
    events = _read_jsonl(source.root / "trace.jsonl")
    return {
        "silent_transport_count": sum(
            event["action"] == "send" and event["surface"] == "silent"
            for event in events
        ),
        "gated_transport_count": sum(
            event["action"] == "send" and event["surface"] == "gated"
            for event in events
        ),
    }


def observe_finalize(source: ObservationInput) -> Observation:
    events = _read_jsonl(source.root / "trace.jsonl")
    by_attempt: dict[int, list[str]] = {}
    for event in events:
        by_attempt.setdefault(int(event["attempt"]), []).append(event["event"])
    first = by_attempt[1]
    return {
        "validation_before_success": first.index("validate") < first.index("success"),
        "retry_metric_effects": sum(
            event["event"] == "metrics" for event in events
        ),
    }


OBSERVERS: Mapping[str, Callable[[ObservationInput], Observation]] = {
    "review_apply": observe_review_apply,
    "project_transitions": observe_project_transitions,
    "task_rollover": observe_task_rollover,
    "entity_done_trails": observe_entity_done_trails,
    "reading": observe_reading,
    "surface": observe_surface,
    "finalize": observe_finalize,
}


OBSERVATION_RULES: Mapping[str, Mapping[str, str]] = {
    "review_apply": {
        "review_archived": "effect.review-archived",
        "marker_removed": "effect.apply-marker-removed",
    },
    "project_transitions": {
        "archived_location": "artifact.project-archive-location",
        "project_status": "trajectory.project-status-archived",
        "engine_status": "side-effect.project-engine-cascade",
        "schedule_status": "side-effect.project-schedule-cascade",
    },
    "task_rollover": {
        "snapshot_precedes_replace": "trajectory.snapshot-before-replace",
        "snapshot_preserves_preimage": "artifact.snapshot-preserves-preimage",
    },
    "entity_done_trails": {
        "record_paths_distinct": "artifact.entity-done-trail-distinct",
        "identifier_namespaces_distinct": "artifact.identifier-namespaces-distinct",
        "trail_entry_count": "side-effect.trail-append",
    },
    "reading": {
        "state_removed": "effect.reading-state-removed",
        "log_retained": "side-effect.reading-log-retained",
        "close_recorded": "artifact.reading-close-recorded",
    },
    "surface": {
        "silent_transport_count": "side-effect.surface-silent-no-transport",
        "gated_transport_count": "side-effect.surface-gated-transports",
    },
    "finalize": {
        "validation_before_success": "trajectory.validation-before-success",
        "retry_metric_effects": "legacy.finalize-retry-metric-effects",
    },
}


def comparison_failures(
    group: str, actual: Mapping[str, Any], golden: Mapping[str, Any]
) -> set[str]:
    rules = OBSERVATION_RULES[group]
    if set(actual) != set(rules) or set(golden) != set(rules):
        raise AssertionError(f"observation fields drifted for {group}")
    return {rules[field] for field in rules if actual[field] != golden[field]}
