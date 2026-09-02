# Deploy

The runtime has no daemon and installs no launchd or systemd units. Background
execution belongs to `tool-scheduler`; external delivery belongs to
`tool-gateway`.

This directory may contain only:

- safe examples of local installation profiles;
- a renderer for scheduler job recipes;
- enable, shadow, rollback, and uninstall instructions;
- placeholders without absolute user paths or secrets.

`config.example.toml` documents the tested bootstrap shape. Absolute values are
set only in the external runtime home and are never committed.

The runtime does not create its own long-lived process while a scheduler job can
express the required behavior. Generated recipes are disabled by default.
