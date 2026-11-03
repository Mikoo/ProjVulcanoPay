"""Servidor HTTP Receptor de Webhooks (FastAPI) para Vulcano Pay.

Rol 3 — Seguridad Criptográfica HMAC y Receptor FastAPI.
Responsable: Integrante 3.

Expone el endpoint asíncrono POST /webhook que verifica la firma HMAC-SHA256
sobre los bytes crudos de la petición antes de decodificar el JSON, encola
el evento validado en AWS SQS (LocalStack) y responde HTTP 202 Accepted.
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from typing import Any

from fastapi import FastAPI, HTTPException, Request, status

from vulcano_telemetry.exceptions import (
    CorruptedMessageError,
    SQSConnectionError,
    WebhookSignatureError,
    WebhookTimestampError,
)
from vulcano_telemetry.webhook_crypto import verify_signature

try:
    from vulcano_telemetry.core_sqs import get_sqs_client, produce_event
except ImportError:
    get_sqs_client = None  # type: ignore[assignment]
    produce_event = None  # type: ignore[assignment]

logger = logging.getLogger("vulcano_engine")

# Constantes de configuración y seguridad
DEFAULT_SECRET_FALLBACK: str = "mi_clave_secreta_super_segura_vulcano_123"
DEFAULT_SQS_ENDPOINT: str = "http://localhost:4566"
DEFAULT_SQS_QUEUE: str = "vulcano-events-queue"
DEFAULT_AWS_ACCOUNT_ID: str = "000000000000"
MAX_PAYLOAD_BYTES: int = 1 * 1024 * 1024  # Límite de 1 MB contra DoS

app = FastAPI(
    title="Vulcano Pay Webhook Receiver",
    description=(
        "Receptor de Webhooks financieros con validación HMAC-SHA256 "
        "en tiempo constante y encolado asíncrono en AWS SQS."
    ),
    version="1.0.0",
)


def _get_webhook_secret() -> str:
    """Obtiene el secreto HMAC desde variables de entorno.

    En entorno de desarrollo utiliza el fallback definido por contrato con
    ``app_operator.py`` si ``VULCANO_WEBHOOK_SECRET`` no está definida.
    En entorno de producción (``VULCANO_ENV=production``) exige que la
    variable esté explícitamente configurada.
    """
    env_secret = os.environ.get("VULCANO_WEBHOOK_SECRET")
    if env_secret and env_secret.strip():
        return env_secret.strip()

    environment = os.environ.get("VULCANO_ENV", "development").strip().lower()
    if environment == "production":
        raise WebhookSignatureError(
            "Configuración insegura: VULCANO_WEBHOOK_SECRET no está definida "
            "en producción."
        )

    logger.warning(
        "Usando clave HMAC de respaldo para desarrollo local. "
        "Configure VULCANO_WEBHOOK_SECRET en su entorno."
    )
    return DEFAULT_SECRET_FALLBACK


def _get_sqs_config() -> tuple[str, str]:
    """Construye el endpoint y el QueueUrl de SQS a partir del entorno."""
    endpoint_url = (
        os.environ.get("VULCANO_SQS_ENDPOINT", DEFAULT_SQS_ENDPOINT)
        .strip()
        .rstrip("/")
    )
    queue_name = os.environ.get(
        "VULCANO_SQS_QUEUE", DEFAULT_SQS_QUEUE
    ).strip()
    queue_url = f"{endpoint_url}/{DEFAULT_AWS_ACCOUNT_ID}/{queue_name}"
    return endpoint_url, queue_url


def _parse_verified_json(raw_bytes: bytes) -> dict[str, Any]:
    """Decodifica y parsea el JSON únicamente tras haber validado el HMAC."""
    if not raw_bytes:
        raise CorruptedMessageError("El cuerpo del Webhook está vacío.")

    try:
        decoded_text = raw_bytes.decode("utf-8")
        parsed_data = json.loads(decoded_text)
    except (UnicodeDecodeError, json.JSONDecodeError) as err:
        raise CorruptedMessageError(
            "El cuerpo del Webhook no contiene un JSON UTF-8 válido."
        ) from err

    if not isinstance(parsed_data, dict):
        raise CorruptedMessageError(
            "El payload JSON del Webhook debe ser un objeto (clave-valor)."
        )

    return parsed_data


def _publish_to_sqs(event_data: dict[str, Any]) -> str:
    """Publica el evento autenticado en SQS utilizando ``core_sqs.py``."""
    if get_sqs_client is None or produce_event is None:
        raise SQSConnectionError(
            "El módulo core_sqs.py (Rol 2) no está disponible para publicar."
        )

    endpoint_url, queue_url = _get_sqs_config()
    try:
        sqs_client = get_sqs_client(endpoint_url)
        message_id = produce_event(sqs_client, queue_url, event_data)
    except SQSConnectionError:
        raise
    except Exception as err:
        sqs_err = SQSConnectionError(
            "Fallo al publicar el evento del Webhook en SQS."
        )
        sqs_err.add_note(f"queue_url={queue_url}")
        raise sqs_err from err

    return str(message_id)


@app.post("/webhook", status_code=status.HTTP_202_ACCEPTED)
async def receive_webhook(request: Request) -> dict[str, str]:
    """Recibe, autentica y encola un evento Webhook entrante.

    Flujo estricto de seguridad:
    1. Lee ``await request.body()`` en bytes crudos y verifica tamaño máximo.
    2. Extrae ``X-Webhook-Signature`` y verifica HMAC-SHA256 + Timestamp.
    3. Si la firma o el timestamp fallan, rechaza con HTTP 401.
    4. Recién después de autenticar, parsea el JSON (si falla, HTTP 400).
    5. Publica en SQS mediante ``get_sqs_client`` y ``produce_event``
       (si falla SQS, HTTP 503).
    6. Responde HTTP 202 Accepted.
    """
    raw_bytes = await request.body()

    webhook_id = (
        request.headers.get("X-Webhook-Id")
        or f"wh_{uuid.uuid4().hex[:12]}"
    )
    trace_id = (
        request.headers.get("X-Trace-Id")
        or f"tr_{uuid.uuid4().hex[:12]}"
    )

    if len(raw_bytes) > MAX_PAYLOAD_BYTES:
        logger.warning(
            "Webhook rechazado por exceder el tamaño máximo (%s bytes).",
            len(raw_bytes),
            extra={"webhook_id": webhook_id, "trace_id": trace_id},
        )
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="El cuerpo de la petición excede el límite permitido.",
        )

    signature_header = request.headers.get("X-Webhook-Signature", "")

    try:
        secret = _get_webhook_secret()
        verify_signature(
            secret=secret,
            header_value=signature_header,
            payload_bytes=raw_bytes,
        )
    except (WebhookSignatureError, WebhookTimestampError) as exc:
        logger.warning(
            "Rechazo de seguridad en Webhook [%s]: %s",
            type(exc).__name__,
            exc,
            extra={"webhook_id": webhook_id, "trace_id": trace_id},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
        ) from exc

    try:
        event_data = _parse_verified_json(raw_bytes)
    except CorruptedMessageError as exc:
        logger.warning(
            "Payload JSON corrupto en Webhook autenticado: %s",
            exc,
            extra={"webhook_id": webhook_id, "trace_id": trace_id},
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    try:
        message_id = _publish_to_sqs(event_data)
    except SQSConnectionError as exc:
        logger.error(
            "Error de disponibilidad SQS al encolar Webhook: %s",
            exc,
            extra={"webhook_id": webhook_id, "trace_id": trace_id},
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Servicio de mensajería SQS no disponible temporalmente.",
        ) from exc

    logger.info(
        "Webhook autenticado y encolado en SQS exitosamente.",
        extra={
            "webhook_id": webhook_id,
            "message_id": message_id,
            "trace_id": trace_id,
        },
    )
    return {
        "status": "accepted",
        "webhook_id": webhook_id,
        "message_id": message_id,
        "trace_id": trace_id,
    }


__all__ = [
    "DEFAULT_SECRET_FALLBACK",
    "DEFAULT_SQS_ENDPOINT",
    "DEFAULT_SQS_QUEUE",
    "MAX_PAYLOAD_BYTES",
    "app",
    "receive_webhook",
]

