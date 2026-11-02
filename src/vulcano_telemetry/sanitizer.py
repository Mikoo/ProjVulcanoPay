"""Validadores de entrada para la CLI de VulcanoEventEngine.

Rol 1 — Robustez de Entradas, Excepciones y Sanitización.
Responsable: Paz Villarreal, Sebastián.

Cada función se usa como ``type=`` de ``argparse``. Argparse llama a la
función con el texto que escribió el usuario. Si la función lanza
``argparse.ArgumentTypeError``, argparse muestra el mensaje y termina con
código de salida 2, sin ejecutar el resto del programa.

La idea es "validar en la frontera": que ningún dato inválido llegue a la
lógica de SQS, HMAC o logging.
"""

from __future__ import annotations

import argparse
import re
from urllib.parse import urlparse

# Patrón pedido por la consigna para las colas SQS.
QUEUE_NAME_PATTERN = r"^vulcano-[a-z0-9-]+-queue$"
_QUEUE_NAME_RE = re.compile(QUEUE_NAME_PATTERN)

WAIT_TIME_MIN = 1
WAIT_TIME_MAX = 20
SECRET_KEY_MIN_LENGTH = 16


def _clean_text(value: object, field_name: str) -> str:
    """Devuelve el texto sin espacios accidentales o lanza un error claro.

    argparse siempre entrega ``str``, pero validar el tipo igual protege a
    la función si alguien la llama directamente desde otro módulo o test.
    """
    if not isinstance(value, str):
        raise argparse.ArgumentTypeError(
            f"{field_name} debe ser texto (recibido: {type(value).__name__})."
        )
    return value.strip()


def parse_queue_name(value: str) -> str:
    """Valida el nombre de una cola SQS.

    Formato obligatorio: ``vulcano-<nombre>-queue``, solo minúsculas,
    números y guiones. Ejemplo válido: ``vulcano-events-queue``.
    """
    clean_value = _clean_text(value, "El nombre de la cola")

    if not _QUEUE_NAME_RE.fullmatch(clean_value):
        raise argparse.ArgumentTypeError(
            f"Nombre de cola inválido: '{clean_value}'. "
            f"Debe cumplir el patrón {QUEUE_NAME_PATTERN} "
            "(ejemplo: vulcano-events-queue)."
        )

    return clean_value


def parse_wait_time(value: str) -> int:
    """Valida el tiempo de espera de SQS (``WaitTimeSeconds``).

    Debe ser un número entero entre 1 y 20 segundos, inclusive.
    """
    if isinstance(value, bool):
        raise argparse.ArgumentTypeError(
            f"Tiempo de espera inválido: '{value}'. Debe ser un entero "
            f"entre {WAIT_TIME_MIN} y {WAIT_TIME_MAX} segundos."
        )

    try:
        wait_time = int(str(value).strip())
    except (TypeError, ValueError) as error:
        raise argparse.ArgumentTypeError(
            f"Tiempo de espera inválido: '{value}'. Debe ser un entero "
            f"entre {WAIT_TIME_MIN} y {WAIT_TIME_MAX} segundos."
        ) from error

    if not WAIT_TIME_MIN <= wait_time <= WAIT_TIME_MAX:
        raise argparse.ArgumentTypeError(
            f"Tiempo de espera fuera de rango: {wait_time}. "
            f"Debe estar entre {WAIT_TIME_MIN} y {WAIT_TIME_MAX} segundos."
        )

    return wait_time


def parse_webhook_url(value: str) -> str:
    """Valida una URL HTTP o HTTPS con host presente.

    Se usa tanto para la URL del webhook como para el endpoint de
    LocalStack (``http://localhost:4566``).
    """
    clean_value = _clean_text(value, "La URL del webhook")

    if any(character.isspace() for character in clean_value):
        raise argparse.ArgumentTypeError(
            f"URL inválida: '{clean_value}'. No puede contener espacios."
        )

    try:
        parsed = urlparse(clean_value)
        # Acceder a .port valida que el puerto sea numérico cuando existe.
        parsed.port
    except ValueError as error:
        raise argparse.ArgumentTypeError(
            f"URL inválida: '{clean_value}'. {error}"
        ) from error

    if parsed.scheme not in ("http", "https") or not parsed.netloc or not parsed.hostname:
        raise argparse.ArgumentTypeError(
            f"URL inválida: '{clean_value}'. Debe usar http:// o https:// "
            "y tener un host válido (ejemplo: http://localhost:8000/webhook)."
        )

    return clean_value


def parse_secret_key(value: str) -> str:
    """Valida la clave compartida para firmar HMAC-SHA256.

    Debe tener al menos 16 caracteres. Por seguridad, el mensaje de error
    nunca muestra el valor de la clave: solo informa la longitud recibida.
    """
    clean_value = _clean_text(value, "La clave secreta")

    if len(clean_value) < SECRET_KEY_MIN_LENGTH:
        raise argparse.ArgumentTypeError(
            "La clave secreta HMAC es demasiado corta: "
            f"{len(clean_value)} caracteres. "
            f"Mínimo requerido: {SECRET_KEY_MIN_LENGTH}."
        )

    return clean_value


__all__ = [
    "QUEUE_NAME_PATTERN",
    "WAIT_TIME_MIN",
    "WAIT_TIME_MAX",
    "SECRET_KEY_MIN_LENGTH",
    "parse_queue_name",
    "parse_wait_time",
    "parse_webhook_url",
    "parse_secret_key",
]
