# AGENTS.md - tool-life-os-runtime

`tool-life-os-runtime` provides filesystem-backed Life OS flows, authority
checks, review and apply boundaries, resumable run state, skills, migrations,
and CLI connectors. It owns runtime semantics, not downloading, research,
scheduling, delivery, or external tool storage. The repository contains code,
schemas, public examples, and synthetic fixtures only. Personal vault content,
credentials, logs, run output, downloaded material, and machine corpora stay
outside the repository.

## Read in this order

1. `README.md` - scope, setup, storage ownership, limitations, and tests.
2. `docs/DESIGN.md` - authority, flow, state, review, connector, and recovery
   contracts.
3. `docs/failure-authority-matrix.md` and
   `docs/failure-authority-matrix.json` - projected and authoritative action
   policy.
4. `tests/` - executable contracts and synthetic vault fixtures.

## Core invariants

- The configured vault is authoritative for personal data and portable flow
  state. Runtime home contains local configuration and rebuildable state only.
- Agent output is untrusted data until deterministic validation succeeds.
  Prompt text cannot grant authority.
- Protected knowledge changes require an approved review artifact, a matching
  mutation plan, and precondition validation before atomic apply.
- Long-running flows persist explicit state, resume from the first unfinished
  phase, and do not depend on chat history or raw harness transcripts.
- Cross tool boundaries through explicit subprocess argv, bounded versioned
  machine output, an explicit working directory, and an allowlisted environment.
  Never import sibling repositories or invoke a shell command string.
- Multi-file changes use prepare, validate, commit, and recovery phases.
  Retries must not duplicate mutations or external effects.

## Working rules

- Before claiming a change passes, run exactly:

```bash
python3 -m pytest -q -p no:cacheprovider
```

- The default suite is hermetic. Redirect home, cwd, and vaults to temporary
  locations; clear credential variables; use synthetic fixtures; and never
  contact an external network, live agent, subscription, or private data root.
- Keep runtime home, vault paths, external tool roots, and credentials outside
  source control. Configuration may name environment variables but must never
  contain credential values. Do not add personal absolute paths.
- Initialization writes only to an absent or empty configured vault. Migration
  sources remain read-only until an explicit, validated transition.
- State is versioned JSON or JSONL written atomically. Markdown is a human
  review surface, not a hidden state machine.
- Keep source, tests, docstrings, CLI output, documentation, and non-legacy
  fixtures in English. Preserve legacy multilingual fixture text only when the
  exact bytes are the behavior under test.
- Keep flow implementations explicit. Do not introduce a general workflow
  framework or shared abstraction before repeated concrete consumers justify
  it.
- Add regression coverage for failures, recovery, authority limits, path
  confinement, and connector output bounds whenever those areas change.
- Commits use an imperative English subject, one logical change, no private or
  generated state, and plain ASCII punctuation.

## Contract changes

Treat CLI arguments and exit classes, runtime-home and vault resolution,
configuration and vault schemas, run and review artifacts, authority classes,
apply transaction semantics, outbox events, connector machine formats, and the
failure-authority matrix as public contracts. A contract change must update
`README.md`, `docs/DESIGN.md`, the matrix artifacts when applicable, and tests
in the same change. Version persisted and machine-readable formats instead of
silently changing them.

## Non-English test fixtures

- This public tree contains two intentional Cyrillic legacy-schema fixtures:
  `tests/fixtures/vault-broken/review/rev_invalid-001.md` and
  `tests/fixtures/vault-populated/review/rev_fixture-001.md`. Their headings and
  type label are the data under test. Test code uses Unicode escapes so source,
  comments, and docstrings remain English-only.
- Russian stop words remain supported by retrieval through Unicode-escaped
  literals. This preserves multilingual behavior without embedding non-English
  comments or documentation in source.
