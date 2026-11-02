"""
Paquete público de telemetría, mensajería SQS y seguridad Webhook.
Expone la interfaz pública (__all__) integrando los módulos del equipo.
"""

try:
    from .exceptions import (
        CorruptedMessageError,
        QueueTimeoutError,
        SQSConnectionError,
        VulcanoError,
        WebhookDeliveryError,
        WebhookSignatureError,
        WebhookTimestampError,
    )
except ImportError:
    pass

try:
    from .sanitizer import (
        parse_queue_name,
        parse_secret_key,
        parse_wait_time,
        parse_webhook_url,
    )
except ImportError:
    pass

try:
    from .core_sqs import consume_events, get_sqs_client, produce_event
except ImportError:
    pass

try:
    from .webhook_crypto import generate_signature, verify_signature
except ImportError:
    pass

try:
    from .logging_engine import AsyncJSONFormatter, setup_vulcano_logging
except ImportError:
    pass

__all__ = [
    "VulcanoError",
    "SQSConnectionError",
    "QueueTimeoutError",
    "CorruptedMessageError",
    "WebhookSignatureError",
    "WebhookTimestampError",
    "WebhookDeliveryError",
    "parse_queue_name",
    "parse_wait_time",
    "parse_webhook_url",
    "parse_secret_key",
    "get_sqs_client",
    "produce_event",
    "consume_events",
    "generate_signature",
    "verify_signature",
    "AsyncJSONFormatter",
    "setup_vulcano_logging",
]
