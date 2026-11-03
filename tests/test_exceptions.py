"""Tests de la jerarquía de excepciones del Rol 1."""

import pytest

from vulcano_telemetry.exceptions import (
    CorruptedMessageError,
    QueueTimeoutError,
    SQSConnectionError,
    VulcanoError,
    WebhookDeliveryError,
    WebhookSignatureError,
    WebhookTimestampError,
)

ERRORES_DE_DOMINIO = [
    SQSConnectionError,
    QueueTimeoutError,
    CorruptedMessageError,
    WebhookSignatureError,
    WebhookTimestampError,
    WebhookDeliveryError,
]


def test_vulcano_error_hereda_directo_de_exception():
    """La base del dominio no debe heredar de BaseException."""
    assert VulcanoError.__bases__ == (Exception,)


@pytest.mark.parametrize("error_cls", ERRORES_DE_DOMINIO)
def test_cada_error_hereda_de_vulcano_y_exception(error_cls):
    """Todos los errores concretos son parte de la misma familia."""
    assert error_cls.__bases__ == (VulcanoError,)
    assert issubclass(error_cls, VulcanoError)
    assert issubclass(error_cls, Exception)


@pytest.mark.parametrize("error_cls", ERRORES_DE_DOMINIO)
def test_conserva_el_mensaje(error_cls):
    """El texto que le pasamos al constructor queda disponible en str()."""
    error = error_cls("fallo de prueba")
    assert str(error) == "fallo de prueba"


def test_se_puede_capturar_como_vulcano_error():
    """Un except VulcanoError atrapa a cualquier error del dominio."""
    with pytest.raises(VulcanoError):
        raise WebhookSignatureError("firma inválida")


def test_se_puede_agregar_contexto_con_add_note():
    """add_note() permite sumar contexto sin perder el error original."""
    error = WebhookDeliveryError("no se pudo entregar")
    error.add_note("TraceId=abc-123")

    assert error.__notes__ == ["TraceId=abc-123"]
