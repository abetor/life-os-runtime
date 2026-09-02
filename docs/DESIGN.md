# Design

## 1. Context and boundary

The runtime sits between a person, a filesystem vault, agent harnesses, and a
set of independent command-line tools. It owns Life OS semantics but does not
reimplement download, research, scheduling, or delivery engines.

```text
human / chat / note editor
            |
            v
    canonical skills + lifeos CLI
            |
            v
    tool-life-os-runtime
      |          |           |
      |          |           +--> configured vault
      |          |                review, knowledge, tasks,
      |          |                projects, memory, run state
      |          |
      |          +--------------> attached or headless agent harness
      |
      +-------------------------> versioned CLI subprocesses
                                  coursedump, researcher, llm-wiki,
                                  scheduler, gateway
```

The runtime decides what a result means for the person, which authority is
required, and where a validated artifact belongs. Each external tool answers a
technical question inside its own boundary.

## 2. Storage ownership

### 2.1 Repository

The repository contains:

- versioned schemas and deterministic state transitions;
- flow modules and validators;
- canonical skills and deterministic wrapper generation;
- connector contracts;
- migration primitives;
- synthetic fixtures and tests.

It contains no personal vault, downloaded media, machine corpus, credential,
runtime log, delivery receipt, or operational state.

### 2.2 User vault

The vault is authoritative for personal data and portable flow state:

```text
<vault>/
  lifeos.toml
  inbox/
  review/
  tasks/
  knowledge/
  projects/
  agent/
    memory/
    logs/
    dashboard/
    runs/
    outbox/
  .claude/skills/       # generated wrappers, when installed
  .agents/skills/       # generated wrappers, when installed
```

`<vault>` is a configured path, never a hardcoded directory. Initialization
accepts only an absent or empty target. Migration sources are read-only and can
never be used as the first write target.

### 2.3 Runtime home

Runtime home is selected in this order:

1. explicit `--home /absolute/path`;
2. `LIFE_OS_RUNTIME_DATA`;
3. `$HOME/tools-data/life-os-runtime-data`.

The current working directory is not a fallback. Runtime home may contain local
configuration, vault aliases, generated-wrapper manifests, and rebuildable
cache. It must not hold the only copy of project state, memory, review data, or
flow results.

### 2.4 External tool data

Machine corpora, downloaded source material, scheduler state, transport logs,
and delivery receipts stay in data roots owned by their respective tools. A
vault may reference them through manifests and provenance but does not copy raw
multi-gigabyte inputs for the appearance of self-containment.

Secrets enter only through a selected subprocess environment or an external
secret manager. Config files, trace records, fixtures, and generated artifacts
must never contain credential values.

## 3. Vault zones and authority

| Zone | Data owner | Writer | Gate |
|---|---|---|---|
| `inbox/` | person | person or explicit import | dedupe and manifest |
| `review/` | person | runtime flows | schema, provenance, and surface policy |
| `knowledge/` | person | approved apply flow only | approved review and atomic transaction |
| `tasks/` | person | planning commands | schema, quota, and diff |
| `projects/` | person | project commands | lifecycle schema |
| `agent/memory/` | person | memory and report flows | evidence and retention policy |
| `agent/logs/` | runtime | finalizer and run logger | append-only record |
| `agent/runs/` | runtime | run state machine | atomic state and reconciliation |
| `agent/outbox/` | runtime | surface policy | semantic event schema |

Action classes describe authority, not model difficulty:

- `read`: inspect declared zones without mutation;
- `internal-write`: write run, log, or dashboard state without changing a human decision;
- `proposal`: create a review proposal without changing knowledge;
- `domain-write`: write schema-checked projects, tasks, or agent data;
- `protected-write`: apply an approved review plan to knowledge;
- `external-send`: deliver a semantic event through the gateway;
- `destructive`: permanent deletion or irreversible external work.

Every action records actor, flow, target, and actual authority class. A
scheduled invocation acts as a separate system actor. An executor cannot raise
its authority through prompt text. Version 0 uses archive instead of destructive
deletion.

## 4. Review and protected writes

Markdown is the human review surface, while a versioned JSON mutation plan is
the machine contract. A review artifact includes status, flow, source refs,
provenance, and a path to its plan. The plan records create, update, move, and
archive operations with precondition and expected postcondition hashes.

The presence of a review file is not approval. Approval is an explicit state
transition with an approver, timestamp, and plan hash. Apply revalidates the
artifact and plan before any protected write. If prose and the plan diverge,
the operation fails closed and reports the mismatch.

## 5. Flow contract

Each flow is an explicit Python module with an input schema, phases, authority
ceiling, artifact validator, and acceptance cases. The runtime deliberately does
not introduce a general workflow language.

### 5.1 Run envelope

Minimal state under `agent/runs/<run-id>/state.json` contains:

```json
{
  "schema_version": 1,
  "run_id": "run_example",
  "flow": "distill",
  "status": "running",
  "phase": "synthesize",
  "authority": "proposal",
  "executor": "codex",
  "input": {},
  "artifacts": {},
  "attempt": 2,
  "created_at": "2026-01-15T09:00:00Z",
  "updated_at": "2026-01-15T09:02:00Z",
  "waiting_for": null,
  "last_error": null
}
```

Status transitions are explicit:

```text
created -> running -> waiting_human -> running -> succeeded
                    \-> failed
         \-> quota_wait / transient_wait
         \-> cancelled
```

The scheduler is not authoritative for this state. It only invokes the command
again after a quota or transient delay. The runtime reconciles persisted state
and continues from the first unfinished phase.

Trace is not hidden state. Resume must work from state and committed artifacts
even when a detailed harness transcript is unavailable. Trace records bounded
semantic step IDs, hashes, executor profile, and tool outcomes rather than raw
network traffic or unbounded model output.

### 5.2 Lifecycle

```text
route
  -> resolve profile and authority
  -> create or resume run
  -> collect deterministic context
  -> optional human plan gate
  -> execute a bounded task packet or deterministic action
  -> validate the returned artifact
  -> commit within the allowed zone
  -> emit a semantic event
  -> finalize trace and metrics
```

Required invariants:

- input and output schemas are versioned;
- retry never duplicates mutations;
- unfinished phases come from persisted state, not chat history;
- an LLM never writes final protected state directly;
- task packets bound context and list acceptance checks;
- external paths are normalized before subprocess execution;
- agent output remains untrusted until deterministic validation;
- bypasses are explicit, testable exceptions rather than prompt notes.

### 5.3 Attached and headless execution

Attached mode uses the agent already in conversation with the person. Headless
mode lets a scheduler or CLI invoke a configured harness adapter. Both modes use
the same task packet, artifact contract, and authority checks. Model selection
belongs to role routing such as collect, reason, synthesize, or critic rather
than literals embedded in a flow.

## 6. Skill surface

A canonical skill is a routing and capability contract. It does not own every
implementation it invokes. Each resource defines:

1. when to select or reject the skill;
2. bounded context and exact action IDs;
3. an artifact contract and allowed commits;
4. typed connector requirements;
5. deterministic validation rules.

Harness-specific wrappers are generated from canonical resources. They contain
only routing metadata and a source hash, never a copied private prompt. Install,
check, and uninstall are explicit commands. Repeated installation is byte-for-
byte deterministic.

The public pack covers ingest, apply, ask, research, stateful research resume,
projects, planning, reading, mentoring, reports, lint, ambient suggestions,
batched delivery, decision clarification, and safe vault operations.

## 7. Connector contract

Common subprocess rules:

- configuration stores an argv array, never a shell command string;
- `shell=True` is forbidden;
- cwd is explicit and is never an implicit data home;
- only an allowlisted environment reaches the process;
- machine output is one versioned JSON object or documented JSONL;
- stdout and stderr are bounded;
- timeout terminates the complete process group;
- version and schema mismatches fail before mutation;
- unknown external exit codes are treated as transient until classified.

Runtime exit classes are:

- `0`: reached the declared result or safely entered `waiting_human`;
- `75`: quota wait, retry only after the reset window;
- `111`: transient failure, retry with bounded backoff;
- `1`: permanent, configuration, contract, or usage failure.

The researcher plan gate has a dedicated upstream result that the connector
normalizes into persisted `waiting_human` state and a successful runtime exit.

The scheduler receives versioned job recipes with explicit command, home,
vault alias, retry policy, concurrency key, expected exit classes, and event
policy. Recipes are disabled by default. The gateway receives a semantic event
ID, reloads canonical event bytes from the outbox, and records delivery through
a separate receipt action. Transport never reads the vault directly.

## 8. Domain model

Projects use physical lifecycle directories plus `project.json`, `state.json`,
and an append-only human log. Entities, confirmed done events, and trails remain
separate from tasks because their lifecycle and staleness semantics differ.

Memory describes the person and the system. Knowledge describes the world and
domains. Memory proposals must return to primary evidence rather than rewriting
one summary from another. Shared memory applies retention and stale-evidence
checks because errors can affect every flow.

Raw books and extracted text remain outside this runtime. The runtime owns
reading state and proposal links. Planning enforces physical quota and focus
limits. Lint separates deterministic infrastructure fixes from semantic
findings, which remain proposals when they affect protected knowledge.

## 9. Package structure

```text
tool_life_os_runtime/
  cli.py
  shared/                 # owned copies of generic adapters and utilities
  failure_authority/      # canonical action and failure matrix
  dev_manifest/           # privacy-safe migration inventory renderer
  ext/
    vault/                # config, schema, doctor, migration
    runs/                 # state, trace, outbox
    review/               # review models, decisions, atomic apply
    flows/                # explicit domain flows
    connectors/           # versioned subprocess contracts
    skills/               # canonical resources and wrappers
    gates/                # deterministic acceptance registries
tests/                    # hermetic tests and synthetic vault fixtures
deploy/                   # sanitized configuration examples
smoke/                    # live-check convention, outside the default suite
```

CLI registration is centralized, but flow implementations stay isolated. A new
capability is tested in its extension directory before integration with the CLI.

## 10. Migration strategy

Migration follows a strangler sequence:

1. inventory each legacy capability without publishing source paths;
2. characterize important behavior with synthetic or read-only evidence;
3. reproduce schemas and failure cases in privacy-safe fixtures;
4. implement the replacement without access to the source vault;
5. run shadow reads on a disposable copy;
6. compare artifacts, authority, recovery, and completeness;
7. switch wrappers, jobs, or routes explicitly;
8. observe for a declared window with rollback available;
9. retire legacy code only after an accepted checkpoint.

A successful process exit does not prove complete work. Connector contracts
separately validate completeness, expected inputs, output schemas, and evidence
coverage.

## 11. Failure handling and rollback

All multi-file mutations use prepare, validate, commit, and cleanup phases.
Temporary paths are on the same filesystem as their targets. Committed intents
carry preimage and postimage hashes. Recovery reconciles intent, target bytes,
state, and trace instead of replaying an operation blindly.

Representative failure classes include invalid executor output, stale approval,
precondition mismatch, interrupted rename, subprocess timeout, incompatible
connector versions, quota exhaustion, transient transport failure, and delivery
receipt loss. Each failure has a declared retry owner and rollback behavior.

## 12. Verification

The hermetic suite covers schema mutation, path confinement, atomic apply and
reconciliation, exact authority trajectories, connector exits and timeouts,
wrapper determinism, privacy checks, and end-to-end flows on synthetic vaults.
It redirects home and cwd into temporary directories and never requires network
or live credentials.

Live checks use disposable paths and explicit opt-in. A valid live check must
also fail against a deliberately dead target, preventing a green result that
tested nothing.

## 13. Security properties

- Path validation rejects traversal, symlink swaps, and undeclared roots.
- Protected knowledge changes require explicit approval and precondition hashes.
- Agent output is data, never authority.
- Connector environments are allowlisted and process output is bounded.
- Credentials are neither persisted nor copied into artifacts.
- Runtime state is separate from source and personal vault contents.
- External delivery cannot read arbitrary vault files.
- Destructive deletion is outside the initial authority model.

## 14. Deliberate non-goals

- storing a personal vault, media, credentials, or corpora in the repository;
- becoming a scheduler, delivery gateway, research engine, or downloader;
- building a generic workflow DSL before repeated flows justify one;
- writing knowledge without an approved review artifact;
- binding a flow to one model or harness;
- performing a big-bang migration of an active vault;
- claiming probabilistic quality from deterministic tests alone.
