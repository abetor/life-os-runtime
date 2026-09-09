# life-os-runtime

Filesystem runtime for personal knowledge vaults, with resumable flow APIs, explicit authority, and human review for protected knowledge writes.

[Quick start](#quick-start) | [Offline demo](#offline-demo) | [Architecture](docs/DESIGN.md) | [Tests](#tests) | [Contributing and agent guide](AGENTS.md) | [MIT license](LICENSE)

## Problem

A personal knowledge vault can hold notes, projects, tasks, and memory, but a
directory layout alone does not make long-running agent work safe. Automated
flows need explicit authority, resumable state, validation before writes, and
stable boundaries around external tools. They also need to keep private vault
content, credentials, logs, and downloaded corpora outside the source tree.

## What it does

`life-os-runtime` is a filesystem runtime for a personal Life OS. It:

- validates versioned vault configuration and schema;
- initializes and scans explicitly configured vaults without following unsafe
  paths;
- provides Python flow implementations for ingest, review, apply, planning,
  projects, reading, memory, reports, linting, mentoring, and proactive notifications;
- enforces action-level authority before state changes or external effects;
- records bounded run state, traces, and semantic outbox events;
- installs deterministic thin skill wrappers for supported agent harnesses;
- calls independent tools through versioned CLI connector contracts.

The repository is `life-os-runtime`, the distribution is `tool-life-os-runtime`, and the
Python package is `tool_life_os_runtime`. The CLI is `lifeos`, equivalent to
`python3 -m tool_life_os_runtime`.

The public CLI currently exposes `init`, `scan`, `doctor`, `status`, `run-status`,
and `skills`. Flow execution is a Python integration surface under
[flow APIs](tool_life_os_runtime/ext/flows/) and
[review/apply APIs](tool_life_os_runtime/ext/review/); this release has no
CLI command that launches those flows.

## Architecture

```text
human or agent
      |
      v
 lifeos CLI and canonical skills
      |
      v
 tool-life-os-runtime
   |        |          |
   |        |          +--> configured vault
   |        |               review, knowledge, tasks, projects, run state
   |        |
   |        +-------------> human approval and atomic apply boundary
   |
   +----------------------> versioned CLI connectors
                             coursedump, researcher, llm-wiki,
                             scheduler, gateway
```

The runtime owns Life OS semantics and flow state. Each connected tool owns its
technical domain. The scheduler owns timing and retries; the gateway owns
transport; research and corpus tools own their data formats. Connectors use
subprocess argv arrays, bounded machine output, explicit working directories,
and fail-closed version checks.

See [docs/DESIGN.md](docs/DESIGN.md) for authority classes, flow lifecycle,
storage ownership, failure handling, and connector boundaries.

## Quick start

Python 3.11 or newer is required.

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -e .

export LIFE_OS_RUNTIME_DATA="$HOME/.local/share/life-os-runtime"
mkdir -p "$LIFE_OS_RUNTIME_DATA"
cp deploy/config.example.toml "$LIFE_OS_RUNTIME_DATA/config.toml"
```

Replace every placeholder with a suitable absolute local path. The main
vault path must be absent or empty; migration paths are read-only sources.
Then run:

```bash
lifeos init --vault main
lifeos doctor
lifeos scan --vault main
lifeos status --json
```

`--home /absolute/path` overrides `LIFE_OS_RUNTIME_DATA`. If neither is set,
the documented default is `$HOME/tools-data/life-os-runtime-data`. The current
working directory is never used as an implicit data home. Vault selection uses
`--vault ALIAS`, then `LIFE_OS_VAULT`, then `default_vault` from config.

## Offline demo

The following sequence exercises the deterministic local surface after the
example config points at an empty disposable vault:

```bash
lifeos init --vault main
lifeos skills install --vault main
lifeos skills check --vault main
lifeos doctor
lifeos status --json
lifeos skills uninstall --vault main
```

`doctor`, `status`, `scan`, and `run-status` are read-only. `init` writes only
to a configured absent or empty target and rejects overlap with declared
migration roots. Generated scheduler recipes are disabled by default.

## Data and credential boundary

Repository, runtime home, vault, and external corpora have separate ownership:

| Location | Contents | Policy |
|---|---|---|
| Repository | code, schemas, tests, synthetic fixtures, public examples | no user data, credentials, logs, or runtime output |
| Runtime home | local config, aliases, generated-wrapper manifests, rebuildable cache | configured by `--home` or `LIFE_OS_RUNTIME_DATA` |
| Vault | personal knowledge, projects, tasks, review artifacts, run state, outbox | always explicit in runtime config |
| Tool data roots | downloaded material, machine corpora, scheduler state, delivery receipts | owned and configured by the corresponding tool |

Credentials are supplied to selected subprocesses through the process
environment or an external secret manager. They are never stored in config,
the vault, traces, fixtures, or the repository. Raw harness transcripts are not
copied into the vault automatically.

## Limitations

- External CLI tools are not bundled. A connector remains unavailable until a
  compatible executable and explicit configuration are present.
- The llm-wiki integration uses its public validation surface; no unsupported
  capability handshake is invented.
- Deterministic behavior is covered by the test suite, but probabilistic model
  quality and real human workflow behavior still require separate live review.
- Live connector checks are opt-in. Set `LIFEOS_RESEARCHER_SMOKE_ROOT` to an
  installed researcher source tree before running that specific smoke test.
- Two review fixtures and the retrieval stop-word list contain Russian text on purpose:
  multilingual vault content is part of the contract.
- The P4 gate audits installed sources by AST hash, and the allowlisted hashes are
  generated with Python 3.13. On 3.11 and 3.12 the runtime imports and runs, but the
  gate's audit tests fail, so CI covers 3.13 only.
- Foreign-substitution detection at rename seams compares inode numbers. On APFS a
  file recreated after unlink gets a new inode; on ext4 the freed inode number is
  reused at once, so a same-name unlink-and-recreate by another process can pass as
  the original there. Seven tests that depend on a fresh inode skip on such
  filesystems and say so; an atomic replacement through rename is still detected.

## Tests

Run the full hermetic suite without bytecode or pytest cache artifacts:

```bash
python3 -m pip install 'pytest>=8'
PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -q -p no:cacheprovider
```

The suite redirects `HOME` and the working directory to temporary locations,
removes declared credential variables, uses synthetic vault fixtures, and keeps
live agent or network checks outside the default gate.

The suite also needs `rg` (ripgrep) on PATH: the dev-manifest reconciliation shells
out to it, and ten tests fail without it.

## Provenance

This repository began as a public source snapshot of a personal tool. Earlier local development
history is not included.

## License

MIT. Copyright (c) 2026 abetor. See [LICENSE](LICENSE).
