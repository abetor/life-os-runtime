"""Public bounded gateway delivery connector contract."""

from .connector import (
    GATEWAY_CONNECTOR_SCHEMA_VERSION,
    GATEWAY_DELIVERY_ACTION_ORDER,
    MAX_GATEWAY_MACHINE_BYTES,
    GatewayConnector,
    GatewayConnectorError,
    GatewayDelivery,
    GatewayDeliveryCapabilities,
    GatewayDeliveryOutcome,
    GatewayDeliveryService,
    GatewayEvent,
    GatewayReceipt,
)

__all__ = [
    "GATEWAY_CONNECTOR_SCHEMA_VERSION",
    "GATEWAY_DELIVERY_ACTION_ORDER",
    "MAX_GATEWAY_MACHINE_BYTES",
    "GatewayConnector",
    "GatewayConnectorError",
    "GatewayDelivery",
    "GatewayDeliveryCapabilities",
    "GatewayDeliveryOutcome",
    "GatewayDeliveryService",
    "GatewayEvent",
    "GatewayReceipt",
]
