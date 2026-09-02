# Failure and authority matrix

JSON is the authoritative artifact. Markdown is a deterministic projection.
SHA-256 JSON: `4d5a67b803c89180f65dd8f16e74ab71b66540575bcca0ed2487a78b1819fb3e`.

All paths below are symbolic contract zones, not filesystem paths.
Legacy and migration roots are never write targets.
The scheduler invokes the runtime with internal-write authority, but the runtime reauthorizes each downstream action as system.
The runtime connector reads the outbox and sends normalized stdin; gateway transport does not read the vault, while receipt commit and reconciliation remain separate actions.

| Flow | Actor | Eval | Ceiling | Reads | Writes | Invokes | Retry | Rollback |
|---|---|---|---|---|---|---|---|---|
| ambient | system | bounded-subjective | internal-write | vault:agent/memory, vault:projects, vault:review, vault:tasks | vault:agent/outbox, vault:agent/runs | none | scheduler | dedupe-by-semantic-key-and-resume-scan |
| apply | runtime-human-approved | objective | protected-write | vault:knowledge, vault:review | vault:agent/runs, vault:knowledge, vault:review | none | runtime | reconcile-apply-journal-to-old-or-new-set |
| ask | runtime | bounded-subjective | proposal | vault:agent/memory, vault:knowledge | vault:agent/runs, vault:review | none | runtime | discard-uncommitted-synthesis-or-resume-by-context-hash |
| book | runtime | bounded-subjective | domain-write | tool:source-manifest, vault:agent/reading, vault:knowledge | vault:agent/reading, vault:agent/runs, vault:review | none | runtime | resume-from-source-manifest-and-reading-state-hash |
| bundle | system | objective | internal-write | vault:agent/outbox, vault:review | vault:agent/outbox, vault:agent/runs | none | scheduler | dedupe-by-bundle-window-and-source-hashes |
| distill | runtime | bounded-subjective | proposal | machine-topic:source-manifests, machine-topic:validated-claims | vault:agent/runs, vault:review | tool:llmwiki | runtime | archive-partial-proposal-and-resume-from-source-hashes |
| engine | runtime | bounded-subjective | proposal | machine-topic:research-checkpoint | vault:agent/runs, vault:review | tool:researcher | scheduler | resume-same-researcher-run-without-second-engine |
| entities | runtime-human-confirmed | objective | domain-write | vault:agent/logs/done-events, vault:agent/memory/entities, vault:agent/memory/trails | vault:agent/logs/done-events, vault:agent/memory/entities, vault:agent/memory/trails, vault:agent/runs | none | runtime | reconcile-entity-hash-and-append-correction |
| finalize | runtime | objective | internal-write | vault:agent/runs, vault:review | vault:agent/logs, vault:agent/logs/metrics, vault:agent/outbox, vault:agent/runs, vault:agent/runs/trace | none | runtime | repeat-finalize-with-semantic-dedupe |
| gateway-delivery | runtime | objective | external-send | gateway:delivery-receipt, vault:agent/outbox | vault:agent/outbox | gateway:normalized-event-stdin | runtime | keep-outbox-artifact-and-reconcile-valid-receipt |
| gateway-transport | gateway | objective | external-send | gateway:normalized-event-stdin | gateway:delivery-receipt | gateway:channel-transport | gateway | reconcile-receipt-by-dedupe-key-never-delete-runtime-artifact |
| grill-me | human | owner-judgment | proposal | vault:agent/memory, vault:projects | vault:agent/runs, vault:review | none | human | resume-from-recorded-questions-without-inferred-consent |
| ingest | runtime | bounded-subjective | domain-write | external:declared-input, tool:source-manifest, vault:inbox | vault:agent/runs, vault:inbox, vault:review | tool:coursedump, tool:researcher | runtime | resume-from-source-manifest-and-dedupe-key |
| lint | runtime | bounded-subjective | domain-write | vault:agent/memory, vault:inbox, vault:knowledge, vault:projects, vault:tasks | vault:agent/runs, vault:inbox, vault:projects, vault:review, vault:tasks | none | runtime | restore-precondition-bytes-and-keep-finding |
| memory | runtime | bounded-subjective | domain-write | vault:agent/logs, vault:agent/memory, vault:review | vault:agent/memory-metadata, vault:agent/runs, vault:review | none | runtime | restore-metadata-precondition-and-supersede-proposal |
| mentor | runtime | bounded-subjective | proposal | vault:agent/memory, vault:knowledge, vault:projects | vault:agent/runs, vault:review | none | runtime | discard-unvalidated-output-or-supersede-proposal |
| obsidian | runtime | objective | domain-write | vault:agent/memory, vault:inbox, vault:knowledge, vault:projects, vault:tasks | vault:agent/memory-metadata, vault:inbox, vault:projects, vault:tasks | none | runtime | restore-precondition-bytes-or-archive |
| plan | runtime | bounded-subjective | domain-write | vault:agent/memory, vault:projects, vault:tasks | vault:agent/logs/tasks, vault:agent/runs, vault:review, vault:tasks | none | runtime | restore-task-precondition-or-reconcile-by-task-id |
| project | runtime | objective | domain-write | vault:projects | vault:agent/runs, vault:projects, vault:review | tool:scheduler | runtime | reconcile-project-state-and-physical-lifecycle |
| report | runtime | bounded-subjective | proposal | vault:agent/logs, vault:agent/memory, vault:projects, vault:tasks | vault:agent/logs, vault:agent/runs, vault:review | none | runtime | supersede-report-proposal-and-dedupe-log |
| research | runtime | bounded-subjective | proposal | external:declared-research-input, machine-topic:validated-claims | vault:agent/runs, vault:review | tool:researcher | scheduler | resume-researcher-checkpoint-then-dedupe-proposal |
| review-decision | human | owner-judgment | domain-write | vault:review | vault:review | none | human | append-correcting-decision-with-current-plan-hash |
| scheduler-execution | scheduler | objective | internal-write | scheduler:recipe | scheduler:job-state | runtime:flow-entry | scheduler | retry-technical-invocation-without-domain-decision |

## Actions

### `ambient`

Crash points: after-prepare-before-replace, during-bounded-read.
Irreversible effects: none.

| Action | Actor | Authority | Access | Target | Effect | Artifact commit | Retry | Rollback |
|---|---|---|---|---|---|---|---|---|
| scan-eligible-signals | system | read | read | vault:tasks | read-only | no | scheduler | none-read-only |
| read-ambient-projects | system | read | read | vault:projects | read-only | no | scheduler | none-read-only |
| read-ambient-review | system | read | read | vault:review | read-only | no | scheduler | none-read-only |
| read-ambient-memory | system | read | read | vault:agent/memory | read-only | no | scheduler | none-read-only |
| commit-nudge-outbox-event | system | internal-write | write | vault:agent/outbox | outbox-artifact-commit | yes | scheduler | dedupe-or-expire-outbox-item |
| record-run-state | system | internal-write | write | vault:agent/runs | run-state-commit | yes | scheduler | reconcile-run-envelope |

### `apply`

Crash points: after-journal-before-first-replace, after-knowledge-commit-before-review-finalization, after-prepare-before-replace, after-replace-before-journal-finalize, between-knowledge-replaces, during-bounded-read.
Irreversible effects: none.

| Action | Actor | Authority | Access | Target | Effect | Artifact commit | Retry | Rollback |
|---|---|---|---|---|---|---|---|---|
| verify-approved-plan | runtime-human-approved | read | read | vault:review | read-only | no | runtime | none-read-only |
| read-knowledge-preconditions | runtime-human-approved | read | read | vault:knowledge | read-only | no | runtime | none-read-only |
| commit-approved-knowledge | runtime-human-approved | protected-write | write | vault:knowledge | protected-artifact-commit | yes | runtime | reconcile-apply-journal |
| finalize-applied-review | runtime-human-approved | internal-write | write | vault:review | review-finalization-commit | yes | runtime | reconcile-review-status-from-apply-journal |
| record-run-state | runtime | internal-write | write | vault:agent/runs | run-state-commit | yes | runtime | reconcile-run-envelope |

### `ask`

Crash points: after-prepare-before-replace, during-bounded-read.
Irreversible effects: none.

| Action | Actor | Authority | Access | Target | Effect | Artifact commit | Retry | Rollback |
|---|---|---|---|---|---|---|---|---|
| retrieve-cited-evidence | runtime | read | read | vault:knowledge | read-only | no | runtime | none-read-only |
| read-memory-retrieval-scope | runtime | read | read | vault:agent/memory | read-only | no | runtime | none-read-only |
| optional-file-back-proposal | runtime | proposal | write | vault:review | proposal-commit | yes | runtime | archive-or-supersede-proposal |
| record-run-state | runtime | internal-write | write | vault:agent/runs | run-state-commit | yes | runtime | reconcile-run-envelope |

### `book`

Crash points: after-prepare-before-replace, during-bounded-read.
Irreversible effects: none.

| Action | Actor | Authority | Access | Target | Effect | Artifact commit | Retry | Rollback |
|---|---|---|---|---|---|---|---|---|
| read-source-manifest | runtime | read | read | tool:source-manifest | read-only | no | runtime | none-read-only |
| read-reading-state | runtime | read | read | vault:agent/reading | read-only | no | runtime | none-read-only |
| read-reading-knowledge | runtime | read | read | vault:knowledge | read-only | no | runtime | none-read-only |
| commit-reading-state | runtime | domain-write | write | vault:agent/reading | artifact-commit | yes | runtime | reconcile-precondition-hash |
| commit-reading-knowledge-proposal | runtime | proposal | write | vault:review | proposal-commit | yes | runtime | archive-or-supersede-proposal |
| record-run-state | runtime | internal-write | write | vault:agent/runs | run-state-commit | yes | runtime | reconcile-run-envelope |

### `bundle`

Crash points: after-prepare-before-replace, during-bounded-read.
Irreversible effects: none.

| Action | Actor | Authority | Access | Target | Effect | Artifact commit | Retry | Rollback |
|---|---|---|---|---|---|---|---|---|
| collect-batched-items | system | read | read | vault:review | read-only | no | scheduler | none-read-only |
| read-pending-outbox | system | read | read | vault:agent/outbox | read-only | no | scheduler | none-read-only |
| commit-bundle-outbox-event | system | internal-write | write | vault:agent/outbox | outbox-artifact-commit | yes | scheduler | dedupe-or-supersede-bundle |
| record-run-state | system | internal-write | write | vault:agent/runs | run-state-commit | yes | scheduler | reconcile-run-envelope |

### `distill`

Crash points: after-prepare-before-replace, after-tool-exit-before-artifact-registration, during-bounded-read.
Irreversible effects: none.

| Action | Actor | Authority | Access | Target | Effect | Artifact commit | Retry | Rollback |
|---|---|---|---|---|---|---|---|---|
| read-validated-claims | runtime | read | read | machine-topic:validated-claims | read-only | no | runtime | none-read-only |
| read-source-manifests | runtime | read | read | machine-topic:source-manifests | read-only | no | runtime | none-read-only |
| validate-machine-topic | runtime | read | invoke | tool:llmwiki | connector-call | no | runtime | none-read-only-validation |
| commit-review-proposal | runtime | proposal | write | vault:review | proposal-commit | yes | runtime | archive-or-supersede-proposal |
| record-run-state | runtime | internal-write | write | vault:agent/runs | run-state-commit | yes | runtime | reconcile-run-envelope |

### `engine`

Crash points: after-prepare-before-replace, after-tool-exit-before-artifact-registration, during-bounded-read.
Irreversible effects: none.

| Action | Actor | Authority | Access | Target | Effect | Artifact commit | Retry | Rollback |
|---|---|---|---|---|---|---|---|---|
| read-research-checkpoint | runtime | read | read | machine-topic:research-checkpoint | read-only | no | runtime | none-read-only |
| compat-resume-researcher | runtime | internal-write | invoke | tool:researcher | connector-call | no | scheduler | resume-from-registered-artifact |
| commit-engine-compat-proposal | runtime | proposal | write | vault:review | proposal-commit | yes | runtime | archive-or-supersede-proposal |
| record-run-state | runtime | internal-write | write | vault:agent/runs | run-state-commit | yes | runtime | reconcile-run-envelope |

### `entities`

Crash points: after-prepare-before-replace, during-bounded-read.
Irreversible effects: none.

| Action | Actor | Authority | Access | Target | Effect | Artifact commit | Retry | Rollback |
|---|---|---|---|---|---|---|---|---|
| read-entity-state | runtime-human-confirmed | read | read | vault:agent/memory/entities | read-only | no | runtime | none-read-only |
| read-done-events | runtime-human-confirmed | read | read | vault:agent/logs/done-events | read-only | no | runtime | none-read-only |
| read-trail-events | runtime-human-confirmed | read | read | vault:agent/memory/trails | read-only | no | runtime | none-read-only |
| commit-entity-state | runtime-human-confirmed | domain-write | write | vault:agent/memory/entities | artifact-commit | yes | runtime | reconcile-precondition-hash |
| append-confirmed-done-event | runtime-human-confirmed | domain-write | write | vault:agent/logs/done-events | done-event-append | yes | runtime | append-correcting-done-event |
| append-entity-trail | runtime-human-confirmed | domain-write | write | vault:agent/memory/trails | trail-append | yes | runtime | append-correcting-trail-event |
| record-run-state | runtime | internal-write | write | vault:agent/runs | run-state-commit | yes | runtime | reconcile-run-envelope |

### `finalize`

Crash points: after-prepare-before-replace, during-bounded-read.
Irreversible effects: none.

| Action | Actor | Authority | Access | Target | Effect | Artifact commit | Retry | Rollback |
|---|---|---|---|---|---|---|---|---|
| validate-run-artifacts | runtime | read | read | vault:agent/runs | read-only | no | runtime | none-read-only |
| read-review-outcome | runtime | read | read | vault:review | read-only | no | runtime | none-read-only |
| append-domain-log | runtime | internal-write | write | vault:agent/logs | append-only-log | yes | runtime | reconcile-precondition-hash |
| append-run-trace | runtime | internal-write | write | vault:agent/runs/trace | append-only-trace | yes | runtime | dedupe-by-semantic-step-id |
| commit-bounded-metrics | runtime | internal-write | write | vault:agent/logs/metrics | bounded-metrics-commit | yes | runtime | recompute-from-redacted-trace |
| emit-semantic-outbox-event | runtime | internal-write | write | vault:agent/outbox | outbox-artifact-commit | yes | runtime | dedupe-by-semantic-key |
| finalize-run-state | runtime | internal-write | write | vault:agent/runs | run-state-commit | yes | runtime | reconcile-run-envelope |

### `gateway-delivery`

Crash points: after-receipt-before-outbox-reconciliation, after-tool-exit-before-artifact-registration, during-bounded-read.
Irreversible effects: none.

| Action | Actor | Authority | Access | Target | Effect | Artifact commit | Retry | Rollback |
|---|---|---|---|---|---|---|---|---|
| read-semantic-outbox-event | runtime | read | read | vault:agent/outbox | read-only | no | runtime | none-read-only |
| invoke-normalized-gateway-event | runtime | external-send | invoke | gateway:normalized-event-stdin | gateway-connector-invocation | no | runtime | leave-outbox-retryable-until-valid-receipt |
| read-gateway-delivery-receipt | runtime | read | read | gateway:delivery-receipt | read-only | no | runtime | none-read-only |
| reconcile-outbox-receipt | runtime | internal-write | write | vault:agent/outbox | gateway-receipt-reconciliation | yes | runtime | repeat-reconciliation-by-dedupe-key |

### `gateway-transport`

Crash points: after-channel-accept-before-receipt-commit, during-bounded-read.
Irreversible effects: gateway-transport/deliver-channel-event.

| Action | Actor | Authority | Access | Target | Effect | Artifact commit | Retry | Rollback |
|---|---|---|---|---|---|---|---|---|
| read-normalized-event-stdin | gateway | read | read | gateway:normalized-event-stdin | read-only | no | gateway | none-read-only |
| deliver-channel-event | gateway | external-send | invoke | gateway:channel-transport | gateway-transport | no | gateway | none-after-accept-dedupe-before-retry |
| commit-delivery-receipt | gateway | internal-write | write | gateway:delivery-receipt | gateway-receipt-commit | yes | gateway | reconcile-receipt-by-dedupe-key |

### `grill-me`

Crash points: after-prepare-before-replace, during-bounded-read.
Irreversible effects: none.

| Action | Actor | Authority | Access | Target | Effect | Artifact commit | Retry | Rollback |
|---|---|---|---|---|---|---|---|---|
| collect-decision-context | human | read | read | vault:projects | read-only | no | runtime | none-read-only |
| read-decision-memory | human | read | read | vault:agent/memory | read-only | no | runtime | none-read-only |
| commit-question-answer-record | human | proposal | write | vault:review | proposal-commit | yes | runtime | archive-or-supersede-proposal |
| record-run-state | runtime | internal-write | write | vault:agent/runs | run-state-commit | yes | runtime | reconcile-run-envelope |

### `ingest`

Crash points: after-prepare-before-replace, after-tool-exit-before-artifact-registration, during-bounded-read.
Irreversible effects: none.

| Action | Actor | Authority | Access | Target | Effect | Artifact commit | Retry | Rollback |
|---|---|---|---|---|---|---|---|---|
| classify-declared-input | runtime | read | read | external:declared-input | read-only | no | runtime | none-read-only |
| read-inbox-dedupe-state | runtime | read | read | vault:inbox | read-only | no | runtime | none-read-only |
| read-source-manifest | runtime | read | read | tool:source-manifest | read-only | no | runtime | none-read-only |
| store-inbox-item | runtime | domain-write | write | vault:inbox | artifact-commit | yes | runtime | reconcile-precondition-hash |
| extract-heavy-input | runtime | internal-write | invoke | tool:coursedump | connector-call | no | runtime | resume-from-registered-artifact |
| research-heavy-input | runtime | internal-write | invoke | tool:researcher | connector-call | no | runtime | resume-from-registered-artifact |
| commit-review-proposal | runtime | proposal | write | vault:review | proposal-commit | yes | runtime | archive-or-supersede-proposal |
| record-run-state | runtime | internal-write | write | vault:agent/runs | run-state-commit | yes | runtime | reconcile-run-envelope |

### `lint`

Crash points: after-prepare-before-replace, during-bounded-read.
Irreversible effects: none.

| Action | Actor | Authority | Access | Target | Effect | Artifact commit | Retry | Rollback |
|---|---|---|---|---|---|---|---|---|
| scan-inbox-zone | runtime | read | read | vault:inbox | read-only | no | runtime | none-read-only |
| scan-non-archive-zones | runtime | read | read | vault:knowledge | read-only | no | runtime | none-read-only |
| scan-task-zone | runtime | read | read | vault:tasks | read-only | no | runtime | none-read-only |
| scan-project-zone | runtime | read | read | vault:projects | read-only | no | runtime | none-read-only |
| scan-memory-zone | runtime | read | read | vault:agent/memory | read-only | no | runtime | none-read-only |
| apply-allowlisted-inbox-fix | runtime | domain-write | write | vault:inbox | artifact-commit | yes | runtime | reconcile-precondition-hash |
| apply-allowlisted-task-fix | runtime | domain-write | write | vault:tasks | artifact-commit | yes | runtime | reconcile-precondition-hash |
| apply-allowlisted-project-fix | runtime | domain-write | write | vault:projects | artifact-commit | yes | runtime | reconcile-precondition-hash |
| commit-semantic-lint-findings | runtime | proposal | write | vault:review | proposal-commit | yes | runtime | archive-or-supersede-proposal |
| record-run-state | runtime | internal-write | write | vault:agent/runs | run-state-commit | yes | runtime | reconcile-run-envelope |

### `memory`

Crash points: after-prepare-before-replace, during-bounded-read.
Irreversible effects: none.

| Action | Actor | Authority | Access | Target | Effect | Artifact commit | Retry | Rollback |
|---|---|---|---|---|---|---|---|---|
| read-current-memory | runtime | read | read | vault:agent/memory | read-only | no | runtime | none-read-only |
| check-evidence-and-retention | runtime | read | read | vault:agent/logs | read-only | no | runtime | none-read-only |
| read-memory-review-state | runtime | read | read | vault:review | read-only | no | runtime | none-read-only |
| commit-semantic-memory-proposal | runtime | proposal | write | vault:review | proposal-commit | yes | runtime | archive-or-supersede-proposal |
| commit-deterministic-memory-metadata | runtime | domain-write | write | vault:agent/memory-metadata | artifact-commit | yes | runtime | reconcile-precondition-hash |
| record-run-state | runtime | internal-write | write | vault:agent/runs | run-state-commit | yes | runtime | reconcile-run-envelope |

### `mentor`

Crash points: after-prepare-before-replace, during-bounded-read.
Irreversible effects: none.

| Action | Actor | Authority | Access | Target | Effect | Artifact commit | Retry | Rollback |
|---|---|---|---|---|---|---|---|---|
| collect-bounded-mentor-context | runtime | read | read | vault:projects | read-only | no | runtime | none-read-only |
| read-mentor-knowledge | runtime | read | read | vault:knowledge | read-only | no | runtime | none-read-only |
| read-mentor-memory | runtime | read | read | vault:agent/memory | read-only | no | runtime | none-read-only |
| commit-mentor-proposal | runtime | proposal | write | vault:review | proposal-commit | yes | runtime | archive-or-supersede-proposal |
| record-run-state | runtime | internal-write | write | vault:agent/runs | run-state-commit | yes | runtime | reconcile-run-envelope |

### `obsidian`

Crash points: after-prepare-before-replace, during-bounded-read.
Irreversible effects: none.

| Action | Actor | Authority | Access | Target | Effect | Artifact commit | Retry | Rollback |
|---|---|---|---|---|---|---|---|---|
| read-inbox-note | runtime | read | read | vault:inbox | read-only | no | runtime | none-read-only |
| read-safe-note | runtime | read | read | vault:knowledge | read-only | no | runtime | none-read-only |
| read-task-note | runtime | read | read | vault:tasks | read-only | no | runtime | none-read-only |
| read-project-note | runtime | read | read | vault:projects | read-only | no | runtime | none-read-only |
| read-memory-note | runtime | read | read | vault:agent/memory | read-only | no | runtime | none-read-only |
| edit-inbox | runtime | domain-write | write | vault:inbox | artifact-commit | yes | runtime | reconcile-precondition-hash |
| edit-tasks | runtime | domain-write | write | vault:tasks | artifact-commit | yes | runtime | reconcile-precondition-hash |
| edit-projects | runtime | domain-write | write | vault:projects | artifact-commit | yes | runtime | reconcile-precondition-hash |
| edit-memory-metadata | runtime | domain-write | write | vault:agent/memory-metadata | artifact-commit | yes | runtime | reconcile-precondition-hash |

### `plan`

Crash points: after-prepare-before-replace, after-rollover-prepare-before-task-replace, after-snapshot-before-task-replace, during-bounded-read.
Irreversible effects: none.

| Action | Actor | Authority | Access | Target | Effect | Artifact commit | Retry | Rollback |
|---|---|---|---|---|---|---|---|---|
| collect-plan-context | runtime | read | read | vault:tasks | read-only | no | runtime | none-read-only |
| read-plan-project-context | runtime | read | read | vault:projects | read-only | no | runtime | none-read-only |
| read-plan-entity-context | runtime | read | read | vault:agent/memory | read-only | no | runtime | none-read-only |
| snapshot-task-preimage | runtime | domain-write | write | vault:agent/logs/tasks | task-snapshot-commit | yes | runtime | retain-snapshot-and-reconcile-task-replace |
| extract-feedback-markers | runtime | read | read | vault:tasks | read-only | no | runtime | none-read-only |
| commit-feedback-proposal | runtime | proposal | write | vault:review | proposal-commit | yes | runtime | archive-or-supersede-proposal |
| commit-plan-or-rollover | runtime | domain-write | write | vault:tasks | artifact-commit | yes | runtime | restore-task-precondition-or-reconcile-rollover |
| record-run-state | runtime | internal-write | write | vault:agent/runs | run-state-commit | yes | runtime | reconcile-run-envelope |

### `project`

Crash points: after-move-before-state-replace, after-prepare-before-replace, after-project-prepare-before-move, after-project-transition-before-schedule-reconciliation, during-bounded-read.
Irreversible effects: none.

| Action | Actor | Authority | Access | Target | Effect | Artifact commit | Retry | Rollback |
|---|---|---|---|---|---|---|---|---|
| read-project-state | runtime | read | read | vault:projects | read-only | no | runtime | none-read-only |
| commit-project-transition | runtime | domain-write | write | vault:projects | artifact-commit | yes | runtime | reconcile-project-state-and-location |
| apply-linked-schedule-transition | runtime | domain-write | invoke | tool:scheduler | scheduler-connector-invocation | no | scheduler | reconcile-schedules-from-project-lifecycle |
| commit-project-knowledge-proposal | runtime | proposal | write | vault:review | proposal-commit | yes | runtime | archive-or-supersede-proposal |
| record-run-state | runtime | internal-write | write | vault:agent/runs | run-state-commit | yes | runtime | reconcile-run-envelope |

### `report`

Crash points: after-prepare-before-replace, during-bounded-read.
Irreversible effects: none.

| Action | Actor | Authority | Access | Target | Effect | Artifact commit | Retry | Rollback |
|---|---|---|---|---|---|---|---|---|
| read-report-projects | runtime | read | read | vault:projects | read-only | no | runtime | none-read-only |
| read-report-tasks | runtime | read | read | vault:tasks | read-only | no | runtime | none-read-only |
| collect-primary-evidence | runtime | read | read | vault:agent/logs | read-only | no | runtime | none-read-only |
| read-report-memory | runtime | read | read | vault:agent/memory | read-only | no | runtime | none-read-only |
| commit-memory-proposal | runtime | proposal | write | vault:review | proposal-commit | yes | runtime | archive-or-supersede-proposal |
| append-report-log | runtime | internal-write | write | vault:agent/logs | append-only-log | yes | runtime | reconcile-precondition-hash |
| record-run-state | runtime | internal-write | write | vault:agent/runs | run-state-commit | yes | runtime | reconcile-run-envelope |

### `research`

Crash points: after-prepare-before-replace, after-tool-exit-before-artifact-registration, during-bounded-read.
Irreversible effects: none.

| Action | Actor | Authority | Access | Target | Effect | Artifact commit | Retry | Rollback |
|---|---|---|---|---|---|---|---|---|
| read-declared-research-input | runtime | read | read | external:declared-research-input | read-only | no | runtime | none-read-only |
| read-validated-research-claims | runtime | read | read | machine-topic:validated-claims | read-only | no | runtime | none-read-only |
| start-or-resume-researcher | runtime | internal-write | invoke | tool:researcher | connector-call | no | scheduler | resume-from-registered-artifact |
| commit-research-proposal | runtime | proposal | write | vault:review | proposal-commit | yes | runtime | archive-or-supersede-proposal |
| record-run-state | runtime | internal-write | write | vault:agent/runs | run-state-commit | yes | runtime | reconcile-run-envelope |

### `review-decision`

Crash points: after-prepare-before-replace, during-bounded-read.
Irreversible effects: none.

| Action | Actor | Authority | Access | Target | Effect | Artifact commit | Retry | Rollback |
|---|---|---|---|---|---|---|---|---|
| inspect-review-and-plan | human | read | read | vault:review | read-only | no | runtime | none-read-only |
| record-approve-reject-or-supersede | human | domain-write | write | vault:review | artifact-commit | yes | runtime | append-correcting-decision |

### `scheduler-execution`

Crash points: after-prepare-before-replace, after-tool-exit-before-artifact-registration, during-bounded-read.
Irreversible effects: none.

| Action | Actor | Authority | Access | Target | Effect | Artifact commit | Retry | Rollback |
|---|---|---|---|---|---|---|---|---|
| read-versioned-recipe | scheduler | read | read | scheduler:recipe | read-only | no | scheduler | none-read-only |
| record-job-attempt | scheduler | internal-write | write | scheduler:job-state | scheduler-execution | no | scheduler | retry-by-job-policy |
| invoke-runtime-flow | scheduler | internal-write | invoke | runtime:flow-entry | scheduler-execution | no | scheduler | runtime-reauthorizes-each-downstream-action-as-system |
