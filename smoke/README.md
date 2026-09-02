# Smoke tests

Tests under `tests/` are hermetic and do not access the network or live agent
harnesses. Live checks involving real CLIs, networks, or subscriptions belong
here as separate `smoke_*.py` or `smoke_*.sh` scripts. Run them manually or via
the scheduler; they are not part of the CI gate.

Convention: exit 77 means skipped because the environment lacks a binary, login,
or network. Any other nonzero code is a failure.

## Live-check report

Passing code checks are not live evidence. A run report uses this table:

| Step | Expected | Observed | Result |
|---|---|---|---|

It also includes an explicit unchecked-boundaries section describing what was
not exercised live and why.

Anti-vacuity check: before trusting a passing smoke test, point it at a known
dead target such as invalid configuration or a stopped service. The test must
fail. Passing against a dead target is a defect in the test, not success. Exit
77 is valid only when the check explicitly reports that it did not run.
