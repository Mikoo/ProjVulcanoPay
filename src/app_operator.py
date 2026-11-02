"""
Punto de entrada CLI y coordinador de integración de Vulcano Pay (Rol 5).
Integra sanitizadores declarativos, despacho de Webhooks con HMAC-SHA256,
Idempotencia, Backoff Exponencial con Full Jitter (log2), consumo SQS con
Long Polling, captura quirúrgica con except* y apagado limpio bajo PEP 765.
"""

import argparse
import hashlib
import hmac
import json
import logging
import math
import os
import random
import time
import uuid
from typing import Any, Dict, List
from urllib.parse import urlparse

import requests
import uvicorn

# ---------------------------------------------------------------------------
# Importaciones de los módulos del equipo con contratos de respaldo
# para permitir pruebas independientes antes de integrar todos los roles.
# ---------------------------------------------------------------------------
try:
    from vulcano_telemetry.exceptions import (
        CorruptedMessageError,
        SQSConnectionError,
        VulcanoError,
        WebhookDeliveryError,
        WebhookSignatureError,
        WebhookTimestampError,
    )
except ImportError:
    class VulcanoError(Exception):
        """Excepción base de respaldo para el ecosistema Vulcano."""

    class SQSConnectionError(VulcanoError):
        """Error de conexión con SQS LocalStack."""

    class CorruptedMessageError(VulcanoError):
        """Mensaje SQS con formato JSON inválido."""

    class WebhookSignatureError(VulcanoError):
        """Firma HMAC-SHA256 inválida o ausente."""

    class WebhookTimestampError(VulcanoError):
        """Timestamp fuera de la ventana de tolerancia (Replay Attack)."""

    class WebhookDeliveryError(VulcanoError):
        """Fallo en la entrega HTTP POST del Webhook."""

try:
    from vulcano_telemetry.sanitizer import (
        parse_queue_name,
        parse_secret_key,
        parse_wait_time,
        parse_webhook_url,
    )
except ImportError:
    def parse_queue_name(value: str) -> str:
        """Validador de respaldo para nombre de cola SQS."""
        if not value.startswith("vulcano-") or not value.endswith("-queue"):
            raise argparse.ArgumentTypeError(
                f"Nombre de cola inválido '{value}'. "
                "Patrón: 'vulcano-<nombre>-queue'."
            )
        return value

    def parse_wait_time(value: str) -> int:
        """Validador de respaldo para WaitTimeSeconds (1 a 20 s)."""
        try:
            val = int(value)
            if not 1 <= val <= 20:
                raise ValueError()
            return val
        except ValueError as err:
            raise argparse.ArgumentTypeError(
                f"WaitTimeSeconds inválido '{value}'. "
                "Debe estar entre 1 y 20 s."
            ) from err

    def parse_webhook_url(value: str) -> str:
        """Validador de respaldo para URL HTTP/HTTPS."""
        parsed = urlparse(value)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise argparse.ArgumentTypeError(f"URL inválida '{value}'.")
        return value

    def parse_secret_key(value: str) -> str:
        """Validador de respaldo para clave secreta HMAC (mín. 16 chars)."""
        if len(value) < 16:
            raise argparse.ArgumentTypeError(
                "La clave HMAC debe tener al menos 16 caracteres."
            )
        return value

try:
    from vulcano_telemetry.webhook_crypto import generate_signature
except ImportError:
    def generate_signature(
        secret: str, timestamp: int, payload_bytes: bytes
    ) -> str:
        """Generador HMAC-SHA256 de respaldo sobre timestamp.payload_bytes."""
        to_sign = f"{timestamp}.".encode("utf-8") + payload_bytes
        return hmac.new(
            secret.encode("utf-8"), to_sign, hashlib.sha256
        ).hexdigest()

try:
    from vulcano_telemetry.core_sqs import (
        consume_events,
        get_sqs_client,
        produce_event,
    )
except ImportError:
    get_sqs_client = None  # type: ignore[assignment]
    produce_event = None  # type: ignore[assignment]
    consume_events = None  # type: ignore[assignment]

try:
    from vulcano_telemetry.logging_engine import setup_vulcano_logging
    logger = setup_vulcano_logging()
except ImportError:
    logging.basicConfig(
        level=logging.INFO, format="[%(levelname)s] %(message)s"
    )
    logger = logging.getLogger("vulcano_engine")

# Códigos HTTP transitorios que ameritan reintento con Backoff Exponencial
RETRIABLE_STATUS_CODES = {408, 429, 500, 502, 503, 504}
DEFAULT_SECRET_FALLBACK = "mi_clave_secreta_super_segura_vulcano_123"


# ---------------------------------------------------------------------------
# 1. Algoritmo de Backoff Exponencial con Full Jitter
# ---------------------------------------------------------------------------
def calculate_full_jitter_backoff(
    attempt: int, base_delay: float = 0.5, max_delay: float = 8.0
) -> float:
    """
    Calcula espera exponencial con Full Jitter acotando el exponente mediante
    logaritmo en base 2 (math.log2) para evitar desbordamiento de memoria
    en potencias 2**attempt y desincronizar reintentos concurrentes.
    """
    if attempt < 0 or base_delay <= 0 or max_delay <= 0:
        return 0.0

    saturation_index = math.log2(max_delay / base_delay)
    if attempt >= saturation_index:
        cap = float(max_delay)
    else:
        cap = min(max_delay, base_delay * (2 ** attempt))

    return random.uniform(0.0, cap)


def build_signed_headers(
    secret: str, payload_bytes: bytes, event_id: str, event_topic: str
) -> Dict[str, str]:
    """
    Construye las cabeceras HTTP de seguridad e idempotencia:
    - X-Webhook-Signature: Contrato t=timestamp,v1=signature (HMAC-SHA256)
    - X-Webhook-Id: Clave de idempotencia estable ante reintentos
    - X-Webhook-Event: Identificador de enrutamiento del tópico
    """
    timestamp = int(time.time())
    signature = generate_signature(secret, timestamp, payload_bytes)
    return {
        "Content-Type": "application/json",
        "X-Webhook-Signature": f"t={timestamp},v1={signature}",
        "X-Webhook-Id": event_id,
        "X-Webhook-Event": event_topic,
    }


def dispatch_single_request(
    target_url: str,
    secret: str,
    payload_bytes: bytes,
    event_id: str,
    event_topic: str,
) -> requests.Response:
    """Realiza un único intento HTTP POST recalculando timestamp y firma."""
    headers = build_signed_headers(
        secret, payload_bytes, event_id, event_topic
    )
    response = requests.post(
        target_url, data=payload_bytes, headers=headers, timeout=10
    )
    if response.status_code in (401, 403):
        sig_err = WebhookSignatureError(
            f"Receptor rechazó firma o timestamp ({response.status_code}): "
            f"{response.text}"
        )
        sig_err.add_note(
            f"X-Webhook-Signature: {headers['X-Webhook-Signature']}"
        )
        raise sig_err
    return response


# ---------------------------------------------------------------------------
# 2. Despachador Resiliente de Webhooks (Client Dispatcher)
# ---------------------------------------------------------------------------
def dispatch_webhook(
    target_url: str,
    secret: str,
    payload_dict: Dict[str, Any],
    max_retries: int = 3,
) -> Dict[str, Any]:
    """
    Firma el payload con HMAC-SHA256 e inyecta X-Webhook-Signature y
    X-Webhook-Id en una petición HTTP POST con reintentos Full Jitter
    ante fallos transitorios de red o respuestas HTTP 5xx / 429.
    """
    payload_bytes = json.dumps(payload_dict, ensure_ascii=False).encode(
        "utf-8"
    )
    tx_id = payload_dict.get("transaction_id")
    event_id = str(tx_id) if tx_id else f"evt_{uuid.uuid4().hex[:12]}"
    event_topic = str(payload_dict.get("event_type", "payment.settlement"))

    for attempt in range(max_retries):
        try:
            response = dispatch_single_request(
                target_url, secret, payload_bytes, event_id, event_topic
            )
        except requests.RequestException as err:
            if attempt < max_retries - 1:
                delay = calculate_full_jitter_backoff(attempt)
                logger.warning(
                    "Fallo de red hacia %s (intento %s/%s). "
                    "Reintentando en %.2fs...",
                    target_url,
                    attempt + 1,
                    max_retries,
                    delay,
                )
                time.sleep(delay)
                continue
            delivery_err = WebhookDeliveryError(
                f"Error de red tras {max_retries} intentos hacia {target_url}"
            )
            delivery_err.add_note(f"Target URL: {target_url}")
            delivery_err.add_note(f"X-Webhook-Id: {event_id}")
            raise delivery_err from err

        if (
            response.status_code in RETRIABLE_STATUS_CODES
            and attempt < max_retries - 1
        ):
            delay = calculate_full_jitter_backoff(attempt)
            logger.warning(
                "Destino respondió HTTP %s (intento %s/%s). "
                "Backoff Full Jitter: %.2fs...",
                response.status_code,
                attempt + 1,
                max_retries,
                delay,
            )
            time.sleep(delay)
            continue

        if response.status_code >= 400:
            http_err = WebhookDeliveryError(
                f"Destino respondió HTTP {response.status_code}: "
                f"{response.text}"
            )
            http_err.add_note(f"Target URL: {target_url}")
            http_err.add_note(f"X-Webhook-Id: {event_id}")
            raise http_err

        data: Dict[str, Any] = (
            response.json()
            if response.content
            else {"status_code": response.status_code}
        )
        logger.info(
            "Webhook entregado [ID=%s] HTTP %s: %s",
            event_id,
            response.status_code,
            data,
        )
        return data

    raise WebhookDeliveryError("Agotados los intentos de entrega.")


# ---------------------------------------------------------------------------
# 3. Construcción del Parser CLI Declarativo (argparse)
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    """Construye el parser CLI integrando los sanitizadores declarativos."""
    env_secret = os.environ.get(
        "VULCANO_WEBHOOK_SECRET", DEFAULT_SECRET_FALLBACK
    )
    parser = argparse.ArgumentParser(
        prog="VulcanoCLI",
        description="Motor de Eventos SQS y Webhooks HMAC (Vulcano Pay)",
    )
    parser.add_argument(
        "-q",
        "--queue",
        type=parse_queue_name,
        default="vulcano-events-queue",
        help="Nombre de la cola SQS (patrón: vulcano-<nombre>-queue)",
    )
    parser.add_argument(
        "-w",
        "--wait-time",
        type=parse_wait_time,
        default=10,
        help="Tiempo de Long Polling SQS entre 1 y 20 segundos (default: 10)",
    )
    parser.add_argument(
        "--url",
        type=parse_webhook_url,
        default="http://localhost:8000/webhook",
        help="URL del Webhook Receptor o Destino HTTP/HTTPS",
    )
    parser.add_argument(
        "--secret",
        type=parse_secret_key,
        default=env_secret,
        help="Clave secreta HMAC (env VULCANO_WEBHOOK_SECRET o mín. 16 chars)",
    )
    parser.add_argument(
        "--endpoint-url",
        type=parse_webhook_url,
        default="http://localhost:4566",
        help="Endpoint de AWS SQS / LocalStack (http://localhost:4566)",
    )
    default_payload = (
        '{"transaction_id": "tx_9981", "amount": 350.00, '
        '"status": "COMPLETED"}'
    )
    parser.add_argument(
        "--payload",
        type=str,
        default=default_payload,
        help="Carga útil JSON del evento para enviar o encolar",
    )
    parser.add_argument(
        "--mode",
        choices=[
            "produce-sqs",
            "start-receiver",
            "start-dispatcher",
            "send-webhook",
        ],
        default="send-webhook",
        help="Modo operativo del motor Vulcano",
    )
    return parser


# ---------------------------------------------------------------------------
# 4. Operaciones de Coordinación por Modo
# ---------------------------------------------------------------------------
def run_produce_sqs(args: argparse.Namespace) -> None:
    """Publica un evento directamente en la cola SQS de LocalStack."""
    if get_sqs_client is None or produce_event is None:
        raise SQSConnectionError(
            "El módulo core_sqs.py (Rol 2) aún no está implementado."
        )

    try:
        event_data = json.loads(args.payload)
    except json.JSONDecodeError as err:
        raise CorruptedMessageError(
            "El argumento --payload no es un JSON válido."
        ) from err

    sqs_client = get_sqs_client(endpoint_url=args.endpoint_url)
    base_url = args.endpoint_url.rstrip("/")
    queue_url = f"{base_url}/000000000000/{args.queue}"
    msg_id = produce_event(sqs_client, queue_url, event_data)
    logger.info(
        "Evento producido directamente en SQS. MessageId: %s",
        msg_id,
        extra={"message_id": msg_id},
    )


def run_start_receiver(args: argparse.Namespace) -> None:
    """Inicia el servidor HTTP receptor de Webhooks local con FastAPI."""
    parsed = urlparse(args.url)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or 8000
    logger.info(
        "Iniciando servidor receptor de Webhooks en http://%s:%s ...",
        host,
        port,
    )
    uvicorn.run(
        "vulcano_telemetry.webhook_receiver:app",
        host=host,
        port=port,
        reload=False,
    )


def run_start_dispatcher(args: argparse.Namespace) -> None:
    """Consume eventos de SQS con Long Polling y los despacha por HTTP POST."""
    if get_sqs_client is None or consume_events is None:
        raise SQSConnectionError(
            "El módulo core_sqs.py (Rol 2) aún no está implementado."
        )

    sqs_client = get_sqs_client(endpoint_url=args.endpoint_url)
    base_url = args.endpoint_url.rstrip("/")
    queue_url = f"{base_url}/000000000000/{args.queue}"
    logger.info(
        "Iniciando despachador SQS -> Webhooks desde '%s' (WaitTime=%ss)...",
        queue_url,
        args.wait_time,
    )

    events = consume_events(sqs_client, queue_url, wait_time=args.wait_time)
    errors: List[Exception] = []

    for event in events:
        msg_id = event.get("message_id", "N/A")
        receipt_handle = event.get("receipt_handle")
        body = event.get("body", {})
        try:
            dispatch_webhook(args.url, args.secret, body)
            if receipt_handle:
                sqs_client.delete_message(
                    QueueUrl=queue_url, ReceiptHandle=receipt_handle
                )
                logger.info(
                    "Evento SQS despachado y eliminado. MessageId: %s",
                    msg_id,
                    extra={"message_id": msg_id},
                )
        except VulcanoError as exc:
            exc.add_note(f"Fallo procesando MessageId SQS: {msg_id}")
            errors.append(exc)

    logger.info(
        "Ciclo de despacho finalizado. Procesados %s eventos de SQS.",
        len(events),
    )
    if errors:
        raise ExceptionGroup(
            "Errores durante el despacho del lote SQS", errors
        )


# ---------------------------------------------------------------------------
# 5. Punto de Entrada Principal (except* + Norma PEP 765 en finally)
# ---------------------------------------------------------------------------
def main() -> None:
    """Ejecuta el motor CLI con captura except* y apagado limpio PEP 765."""
    parser = build_parser()
    args = parser.parse_args()
    logger.info("Iniciando VulcanoCLI en modo '%s'", args.mode)

    try:
        if args.mode == "send-webhook":
            payload_dict = json.loads(args.payload)
            dispatch_webhook(args.url, args.secret, payload_dict)
        elif args.mode == "produce-sqs":
            run_produce_sqs(args)
        elif args.mode == "start-receiver":
            run_start_receiver(args)
        elif args.mode == "start-dispatcher":
            run_start_dispatcher(args)
    except* WebhookSignatureError as group:
        logger.error(
            "Errores de firma HMAC en Webhooks (%s):", len(group.exceptions)
        )
        for exc in group.exceptions:
            logger.error("  • [Firma Inválida] %s", exc)
    except* WebhookTimestampError as group:
        logger.error(
            "Ataques de Replay / Timestamp fuera de tolerancia (%s):",
            len(group.exceptions),
        )
        for exc in group.exceptions:
            logger.error("  • [Replay/Timestamp] %s", exc)
    except* SQSConnectionError as group:
        logger.error(
            "Errores de comunicación con SQS LocalStack (%s):",
            len(group.exceptions),
        )
        for exc in group.exceptions:
            logger.error("  • [SQS LocalStack] %s", exc)
    except* (WebhookDeliveryError, CorruptedMessageError) as group:
        logger.error(
            "Errores de entrega o mensajes corruptos (%s):",
            len(group.exceptions),
        )
        for exc in group.exceptions:
            logger.error("  • [Despacho/Payload] %s", exc)
    finally:
        # Cumplimiento estricto PEP 765 (Python 3.14):
        # Prohibido usar return, break o continue dentro del bloque finally.
        logger.info("Liberando recursos de observabilidad...")
        listener = getattr(logger, "listener", None)
        if listener is not None:
            listener.stop()


if __name__ == "__main__":
    main()
