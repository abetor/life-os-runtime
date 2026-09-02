"""P0 failure/authority matrix as a reusable fixture for later phases."""

from .catalog import (
    REQUIRED_ACTION_IDS,
    REQUIRED_ACTION_TARGETS,
    REQUIRED_FLOW_IDS,
    SCHEMA_VERSION,
    canonical_matrix,
)
from .render import check_artifacts, render_json, render_markdown, render_pair
from .registry import (
    ACTION_SECURITY_FIELDS,
    FLOW_SECURITY_FIELDS,
    REQUIRED_ACTION_SECURITY_DIGESTS,
    REQUIRED_FLOW_SECURITY_DIGESTS,
)
from .validation import (
    FailureAuthorityError,
    authority_at_most,
    authorize_action,
    load_matrix,
    validate_matrix,
)

__all__ = [
    "FailureAuthorityError",
    "ACTION_SECURITY_FIELDS",
    "FLOW_SECURITY_FIELDS",
    "REQUIRED_ACTION_IDS",
    "REQUIRED_ACTION_TARGETS",
    "REQUIRED_ACTION_SECURITY_DIGESTS",
    "REQUIRED_FLOW_SECURITY_DIGESTS",
    "REQUIRED_FLOW_IDS",
    "SCHEMA_VERSION",
    "authority_at_most",
    "authorize_action",
    "canonical_matrix",
    "check_artifacts",
    "load_matrix",
    "render_json",
    "render_markdown",
    "render_pair",
    "validate_matrix",
]
