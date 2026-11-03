"""Excepciones de dominio de VulcanoEventEngine.

Rol 1 — Robustez de Entradas, Excepciones y Sanitización.
Responsable: Paz Villarreal, Sebastián.

Regla de oro de la cátedra:
    TODAS las excepciones heredan de ``Exception``.
    Nunca heredamos directamente de ``BaseException``.

¿Por qué? Porque ``BaseException`` también engloba eventos del sistema que
NO son errores de la aplicación, como ``KeyboardInterrupt`` (Ctrl+C) o
``SystemExit``. Si nuestras excepciones vivieran en esa rama, un
``except Exception`` no las atraparía y para capturarlas habría que usar
``except BaseException``, que también atraparía el cierre del programa.
"""


class VulcanoError(Exception):
    """Error base de todos los componentes de VulcanoEventEngine.

    Cualquier fallo propio del dominio puede capturarse con:
        except VulcanoError as error:
            ...
    """


# ---------------------------------------------------------------------------
# Familia SQS: problemas al hablar con la cola (LocalStack / AWS)
# ---------------------------------------------------------------------------


class SQSConnectionError(VulcanoError):
    """No se pudo conectar con SQS (red, credenciales o endpoint caído)."""


class QueueTimeoutError(VulcanoError):
    """Se agotó el tiempo de espera al leer o escribir en la cola."""


class CorruptedMessageError(VulcanoError):
    """El mensaje recibido no es JSON válido o le faltan campos obligatorios."""


# ---------------------------------------------------------------------------
# Familia Webhook: problemas de seguridad y entrega HTTP
# ---------------------------------------------------------------------------


class WebhookSignatureError(VulcanoError):
    """La firma HMAC-SHA256 no coincide con la calculada sobre el cuerpo crudo."""


class WebhookTimestampError(VulcanoError):
    """El timestamp está fuera de la ventana permitida (posible replay attack)."""


class WebhookDeliveryError(VulcanoError):
    """No se pudo entregar el evento al endpoint del cliente."""


__all__ = [
    "VulcanoError",
    "SQSConnectionError",
    "QueueTimeoutError",
    "CorruptedMessageError",
    "WebhookSignatureError",
    "WebhookTimestampError",
    "WebhookDeliveryError",
]
