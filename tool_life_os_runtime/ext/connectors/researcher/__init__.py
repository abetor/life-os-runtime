"""Public researcher process and final-topic connector contract."""

from .connector import (
    MAX_CONNECTOR_OUTPUT_BYTES,
    RESEARCHER_CONNECTOR_SCHEMA_VERSION,
    ResearcherArtifactRef,
    ResearcherArtifactRegistration,
    ResearcherConnector,
    ResearcherConnectorError,
    ResearcherEvent,
    ResearcherImportResult,
    ResearcherResult,
    ResearcherReviewAdapter,
    ResearcherSourceDocument,
    ResearcherSourcePlan,
    TopicBoundary,
)

__all__ = [
    "MAX_CONNECTOR_OUTPUT_BYTES",
    "RESEARCHER_CONNECTOR_SCHEMA_VERSION",
    "ResearcherArtifactRef",
    "ResearcherArtifactRegistration",
    "ResearcherConnector",
    "ResearcherConnectorError",
    "ResearcherEvent",
    "ResearcherImportResult",
    "ResearcherResult",
    "ResearcherReviewAdapter",
    "ResearcherSourceDocument",
    "ResearcherSourcePlan",
    "TopicBoundary",
]
