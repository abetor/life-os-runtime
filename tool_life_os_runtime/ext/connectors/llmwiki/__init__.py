"""Read-only connector for the public llm-wiki topic contract."""

from .connector import (
    MAX_CONNECTOR_OUTPUT_BYTES,
    SUPPORTED_SPEC_VERSION,
    VALIDATE_ARGV_SUFFIX,
    VALIDATE_EXIT_CODES,
    HashedRecord,
    LlmWikiConnector,
    LlmWikiConnectorError,
    TopicIssue,
    TopicSnapshot,
    TopicValidation,
    WikiPage,
)

__all__ = [
    "MAX_CONNECTOR_OUTPUT_BYTES",
    "SUPPORTED_SPEC_VERSION",
    "VALIDATE_ARGV_SUFFIX",
    "VALIDATE_EXIT_CODES",
    "HashedRecord",
    "LlmWikiConnector",
    "LlmWikiConnectorError",
    "TopicIssue",
    "TopicSnapshot",
    "TopicValidation",
    "WikiPage",
]
