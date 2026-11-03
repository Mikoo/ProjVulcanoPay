"""Tests de los sanitizadores de argumentos del Rol 1."""

import argparse

import pytest

from vulcano_telemetry.sanitizer import (
    SECRET_KEY_MIN_LENGTH,
    WAIT_TIME_MAX,
    WAIT_TIME_MIN,
    parse_queue_name,
    parse_secret_key,
    parse_wait_time,
    parse_webhook_url,
)


# ---------------------------------------------------------------------------
# parse_queue_name
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        "vulcano-events-queue",
        "vulcano-payments-queue",
        "vulcano-a1-queue",
        "  vulcano-events-queue  ",
    ],
)
def test_queue_name_valido(value):
    assert parse_queue_name(value) == value.strip()


@pytest.mark.parametrize(
    "value",
    [
        "",
        "   ",
        "events-queue",
        "vulcano-events",
        "Vulcano-events-queue",
        "vulcano_events_queue",
        "vulcano-events-queue-extra",
        "vulcano-events-queue/otra",
        "vulcano-ñ-queue",
        None,
        123,
    ],
)
def test_queue_name_invalido(value):
    with pytest.raises(argparse.ArgumentTypeError):
        parse_queue_name(value)


# ---------------------------------------------------------------------------
# parse_wait_time
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("value", ["1", "10", "20", " 5 ", 1, 20])
def test_wait_time_valido(value):
    assert parse_wait_time(value) == int(value)


@pytest.mark.parametrize(
    "value",
    ["0", "21", "-1", "10.5", "abc", "", None, True, False],
)
def test_wait_time_invalido(value):
    with pytest.raises(argparse.ArgumentTypeError):
        parse_wait_time(value)


def test_wait_time_limites():
    assert parse_wait_time(str(WAIT_TIME_MIN)) == WAIT_TIME_MIN
    assert parse_wait_time(str(WAIT_TIME_MAX)) == WAIT_TIME_MAX


# ---------------------------------------------------------------------------
# parse_webhook_url
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        "http://localhost:8000/webhook",
        "https://example.com/path?x=1",
        "http://127.0.0.1:4566",
        "https://sub.example.com",
        "  http://localhost:8000/webhook  ",
    ],
)
def test_webhook_url_valida(value):
    assert parse_webhook_url(value) == value.strip()


@pytest.mark.parametrize(
    "value",
    [
        "",
        "   ",
        "example.com",
        "ftp://example.com",
        "http://",
        "http:///solo-path",
        "http://exa mple.com",
        "http://localhost:abc",
        None,
        123,
    ],
)
def test_webhook_url_invalida(value):
    with pytest.raises(argparse.ArgumentTypeError):
        parse_webhook_url(value)


# ---------------------------------------------------------------------------
# parse_secret_key
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        "a" * SECRET_KEY_MIN_LENGTH,
        "clave-super-segura-2026",
        "  " + ("b" * SECRET_KEY_MIN_LENGTH) + "  ",
    ],
)
def test_secret_key_valida(value):
    assert parse_secret_key(value) == value.strip()


@pytest.mark.parametrize(
    "value",
    [
        "",
        "   ",
        "a" * (SECRET_KEY_MIN_LENGTH - 1),
        None,
        123,
    ],
)
def test_secret_key_invalida(value):
    with pytest.raises(argparse.ArgumentTypeError):
        parse_secret_key(value)


def test_error_de_secret_no_filtra_la_clave():
    """El mensaje de error no debe revelar el secreto en los logs."""
    secreto_corto = "mi-clave-secret"

    with pytest.raises(argparse.ArgumentTypeError) as excinfo:
        parse_secret_key(secreto_corto)

    assert secreto_corto not in str(excinfo.value)
    assert str(len(secreto_corto)) in str(excinfo.value)
