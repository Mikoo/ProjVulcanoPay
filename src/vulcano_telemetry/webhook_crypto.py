"""Seguridad criptográfica HMAC-SHA256 para Webhooks de Vulcano Pay.

Rol 3 — Seguridad Criptográfica HMAC y Receptor FastAPI.
Responsable: Integrante 3.

Provee generación y verificación de firmas criptográficas HMAC-SHA256
sobre bytes crudos (raw bytes), protección contra Timing Attacks mediante
comparación en tiempo constante (hmac.compare_digest) y prevención de
Replay Attacks mediante ventana deslizante de tolerancia temporal.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import time

from vulcano_telemetry.exceptions import (
    WebhookSignatureError,
    WebhookTimestampError,
)

DEFAULT_TOLERANCE_SEC: int = 300
_HEX_SHA256_PATTERN: str = r"^[0-9a-fA-F]{64}$"
_HEX_SHA256_RE = re.compile(_HEX_SHA256_PATTERN)


def _validate_crypto_inputs(
    secret: str, timestamp: int, payload_bytes: bytes
) -> None:
    """Valida los tipos y precondiciones de entrada para el cálculo HMAC."""
    if not isinstance(secret, str) or not secret.strip():
        raise WebhookSignatureError(
            "La clave secreta HMAC debe ser una cadena no vacía."
        )
    if isinstance(timestamp, bool) or not isinstance(timestamp, int):
        raise WebhookSignatureError(
            "El timestamp para firmar debe ser un número entero válido."
        )
    if not isinstance(payload_bytes, bytes):
        raise WebhookSignatureError(
            "El payload debe proporcionarse en formato bytes crudos."
        )


def _parse_signature_header(header_value: str) -> tuple[int, str]:
    """Extrae y valida el formato de 't' (timestamp) y 'v1' (firma hex).

    Formato esperado: ``t=<timestamp>,v1=<hex_digest>``
    """
    if not isinstance(header_value, str) or not header_value.strip():
        raise WebhookSignatureError(
            "La cabecera X-Webhook-Signature está ausente o vacía."
        )

    parts = [segment.strip() for segment in header_value.strip().split(",")]
    parsed_fields: dict[str, str] = {}

    for part in parts:
        if "=" not in part:
            raise WebhookSignatureError(
                "Cabecera X-Webhook-Signature malformada: "
                "se esperaba el formato 't=<timestamp>,v1=<firma>'."
            )
        key, value = part.split("=", 1)
        clean_key = key.strip()
        clean_value = value.strip()
        if not clean_key or clean_key in parsed_fields:
            raise WebhookSignatureError(
                "Cabecera X-Webhook-Signature malformada: "
                "claves vacías o duplicadas."
            )
        parsed_fields[clean_key] = clean_value

    raw_timestamp = parsed_fields.get("t")
    signature_hex = parsed_fields.get("v1")

    if not raw_timestamp or not signature_hex:
        raise WebhookSignatureError(
            "Cabecera X-Webhook-Signature incompleta: "
            "debe contener los parámetros 't' y 'v1'."
        )

    if not re.fullmatch(r"^\d+$", raw_timestamp):
        raise WebhookSignatureError(
            f"Formato de timestamp inválido en cabecera: '{raw_timestamp}'."
        )

    try:
        timestamp = int(raw_timestamp)
    except ValueError as err:
        raise WebhookSignatureError(
            "No se pudo interpretar el timestamp de la cabecera."
        ) from err

    if timestamp <= 0:
        raise WebhookSignatureError(
            "El timestamp de la cabecera debe ser un entero positivo."
        )

    if not _HEX_SHA256_RE.fullmatch(signature_hex):
        raise WebhookSignatureError(
            "El parámetro 'v1' no contiene un digest hexadecimal SHA-256 "
            "válido de 64 caracteres."
        )

    return timestamp, signature_hex.lower()


def _validate_timestamp_window(
    timestamp: int, tolerance_sec: int = DEFAULT_TOLERANCE_SEC
) -> None:
    """Verifica que el timestamp se encuentre dentro de la ventana permitida.

    Rechaza tanto timestamps expirados (antiguos) como futuros que excedan
    ``tolerance_sec`` segundos respecto del reloj actual.
    """
    if isinstance(tolerance_sec, bool) or not isinstance(tolerance_sec, int):
        raise WebhookTimestampError(
            "La tolerancia temporal debe ser un número entero de segundos."
        )
    if tolerance_sec < 0:
        raise WebhookTimestampError(
            "La tolerancia temporal no puede ser negativa."
        )

    current_time = int(time.time())
    drift = abs(current_time - timestamp)
    if drift > tolerance_sec:
        direction = "antiguo" if timestamp < current_time else "futuro"
        err = WebhookTimestampError(
            f"Timestamp {direction} fuera de la ventana de tolerancia "
            f"(diferencia={drift}s, máximo={tolerance_sec}s)."
        )
        err.add_note(
            f"timestamp_recibido={timestamp}, timestamp_actual={current_time}"
        )
        raise err


def generate_signature(
    secret: str, timestamp: int, payload_bytes: bytes
) -> str:
    """Calcula la firma HMAC-SHA256 hexadecimal sobre ``timestamp.payload_bytes``.

    Args:
        secret: Clave secreta compartida para el cálculo HMAC.
        timestamp: Marca de tiempo UNIX en segundos (entero).
        payload_bytes: Cuerpo crudo de la petición en bytes.

    Returns:
        Digest hexadecimal en minúsculas de 64 caracteres.
    """
    _validate_crypto_inputs(secret, timestamp, payload_bytes)
    message = f"{timestamp}.".encode("utf-8") + payload_bytes
    return hmac.new(
        secret.encode("utf-8"), message, hashlib.sha256
    ).hexdigest()


def verify_signature(
    secret: str,
    header_value: str,
    payload_bytes: bytes,
    tolerance_sec: int = DEFAULT_TOLERANCE_SEC,
) -> bool:
    """Verifica autenticidad, integridad y vigencia temporal de un Webhook.

    Extrae ``t`` y ``v1`` de ``header_value``, valida la antigüedad frente
    a Replay Attacks (por defecto 300 segundos) y compara el HMAC-SHA256
    en tiempo constante mediante ``hmac.compare_digest()``.

    Args:
        secret: Clave secreta compartida para validar el HMAC.
        header_value: Valor de la cabecera ``X-Webhook-Signature``.
        payload_bytes: Cuerpo crudo original de la petición en bytes.
        tolerance_sec: Ventana máxima aceptada en segundos (default: 300).

    Returns:
        ``True`` si la firma y el timestamp son válidos.

    Raises:
        WebhookSignatureError: Si la cabecera falta, está malformada o la
            firma no coincide con el payload/secreto.
        WebhookTimestampError: Si el timestamp está fuera de la ventana de
            tolerancia (antiguo o futuro).
    """
    if not isinstance(secret, str) or not secret.strip():
        raise WebhookSignatureError(
            "La clave secreta HMAC debe ser una cadena no vacía."
        )
    if not isinstance(payload_bytes, bytes):
        raise WebhookSignatureError(
            "El payload debe proporcionarse en formato bytes crudos."
        )

    timestamp, received_signature = _parse_signature_header(header_value)
    _validate_timestamp_window(timestamp, tolerance_sec=tolerance_sec)

    expected_signature = generate_signature(secret, timestamp, payload_bytes)
    if not hmac.compare_digest(expected_signature, received_signature):
        sig_error = WebhookSignatureError(
            "La firma HMAC-SHA256 no coincide con el cuerpo crudo recibido."
        )
        sig_error.add_note(f"timestamp_verificado={timestamp}")
        raise sig_error

    return True


__all__ = [
    "DEFAULT_TOLERANCE_SEC",
    "generate_signature",
    "verify_signature",
]

