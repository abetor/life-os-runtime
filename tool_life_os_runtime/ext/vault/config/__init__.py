"""Strict configuration contracts for the portable vault runtime."""

from .models import (
    ConfigError,
    MachineKnowledgeConfig,
    MigrationRoot,
    ResolvedValue,
    RuntimeConfig,
    ToolCommand,
    VaultAlias,
    VaultConfig,
    load_runtime_config,
    load_vault_config,
    render_redacted,
    resolve_precedence,
    resolve_vault,
)

__all__ = [
    "ConfigError",
    "MachineKnowledgeConfig",
    "MigrationRoot",
    "ResolvedValue",
    "RuntimeConfig",
    "ToolCommand",
    "VaultAlias",
    "VaultConfig",
    "load_runtime_config",
    "load_vault_config",
    "render_redacted",
    "resolve_precedence",
    "resolve_vault",
]
