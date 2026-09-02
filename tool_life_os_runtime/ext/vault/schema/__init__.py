"""Portable vault zone schema and safe resolver."""

from .model import (
    ARCHIVE_COMPONENTS,
    SCHEMA_VERSION,
    ZONE_SPECS,
    VaultPathResolver,
    VaultSchemaError,
    VaultSchemaReport,
    ZoneCheck,
    ZoneSpec,
    ZoneState,
    is_archive_path,
    iter_active_paths,
    validate_vault,
)

__all__ = [
    "ARCHIVE_COMPONENTS",
    "SCHEMA_VERSION",
    "ZONE_SPECS",
    "VaultPathResolver",
    "VaultSchemaError",
    "VaultSchemaReport",
    "ZoneCheck",
    "ZoneSpec",
    "ZoneState",
    "is_archive_path",
    "iter_active_paths",
    "validate_vault",
]
