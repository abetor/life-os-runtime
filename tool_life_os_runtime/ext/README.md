# Domain extensions

Each capability lives in its own directory and is tested before registration
with the central CLI.

Target layout:

- `vault/` - schema, config, init, scan, doctor, status, migrations;
- `runs/` - resumable state, reconciliation, trace, executors;
- `review/` - artifact, authority, approve, apply;
- `flows/<name>/` - explicit Life OS flows without a shared DSL;
- `connectors/<tool>/` - subprocess contracts for adjacent tools;
- `skills/` - the canonical skill pack and generated wrappers.

An implementation worker owns one extension directory. The integration phase
updates `cli.py`, `pyproject.toml`, and shared documentation only after that
module passes acceptance.
