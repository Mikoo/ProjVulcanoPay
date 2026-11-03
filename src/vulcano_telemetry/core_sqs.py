"""Módulo de mensajería asíncrona SQS con Boto3 y LocalStack (Rol 2).

Gestiona la conexión al endpoint local de AWS SQS (LocalStack), la publicación
de eventos enriquecidos con MessageAttributes de trazabilidad y el consumo
resiliente mediante Long Polling, preservando el encadenamiento de excepciones
y la derivación de Poison Messages hacia la Dead Letter Queue (DLQ).
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
import logging
import os
from typing import Any, Dict, List
import uuid

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from vulcano_telemetry.exceptions import (
    CorruptedMessageError,
    QueueTimeoutError,
    SQSConnectionError,
)

logger = logging.getLogger("vulcano_engine")

DEFAULT_LOCALSTACK_ENDPOINT = "http://localhost:4566"
DEFAULT_AWS_REGION = "us-east-1"


def get_sqs_client(
    endpoint_url: str = DEFAULT_LOCALSTACK_ENDPOINT,
    region_name: str = DEFAULT_AWS_REGION,
) -> Any:
    """
    Inicializa y retorna el cliente Boto3 para AWS SQS apuntando a LocalStack.
    """
    resolved_endpoint = os.environ.get("AWS_ENDPOINT_URL", endpoint_url)
    resolved_region = os.environ.get("AWS_DEFAULT_REGION", region_name)

    try:
        return boto3.client(
            "sqs",
            endpoint_url=resolved_endpoint,
            region_name=resolved_region,
            aws_access_key_id=os.environ.get("AWS_ACCESS_KEY_ID", "test"),
            aws_secret_access_key=os.environ.get(
                "AWS_SECRET_ACCESS_KEY", "test"
            ),
        )
    except (ClientError, BotoCoreError, ValueError) as err:
        sqs_err = SQSConnectionError(
            f"No se pudo inicializar el cliente SQS hacia {resolved_endpoint}."
        )
        sqs_err.add_note(f"EndpointUrl: {resolved_endpoint}")
        raise sqs_err from err


def produce_event(
    sqs_client: Any, queue_url: str, event_data: Dict[str, Any]
) -> str:
    """
    Serializa un evento a JSON y lo envía a una cola SQS inyectando
    MessageAttributes de trazabilidad (TraceId, EventTopic, Timestamp, Source).
    """
    if not isinstance(event_data, dict):
        corrupt_err = CorruptedMessageError(
            "El payload a publicar en SQS debe ser un diccionario JSON válido."
        )
        corrupt_err.add_note(f"Tipo recibido: {type(event_data).__name__}")
        raise corrupt_err

    trace_id = str(event_data.get("event_id") or uuid.uuid4())
    event_topic = str(event_data.get("topic", "payment.completed"))
    iso_timestamp = datetime.now(timezone.utc).isoformat()

    message_attributes = {
        "TraceId": {"StringValue": trace_id, "DataType": "String"},
        "EventTopic": {"StringValue": event_topic, "DataType": "String"},
        "Timestamp": {"StringValue": iso_timestamp, "DataType": "String"},
        "Source": {
            "StringValue": "VulcanoWebhookEngine",
            "DataType": "String",
        },
    }

    try:
        payload_json = json.dumps(event_data, ensure_ascii=False)
        response = sqs_client.send_message(
            QueueUrl=queue_url,
            MessageBody=payload_json,
            MessageAttributes=message_attributes,
        )
        message_id = str(response.get("MessageId", ""))
        logger.info(
            "Evento enviado a SQS exitosamente. MessageId: %s | TraceId: %s",
            message_id,
            trace_id,
            extra={"message_id": message_id, "trace_id": trace_id},
        )
        return message_id
    except (ClientError, BotoCoreError) as err:
        sqs_err = SQSConnectionError(
            "Fallo al enviar mensaje a la cola SQS en LocalStack."
        )
        sqs_err.add_note(f"QueueUrl: {queue_url}")
        sqs_err.add_note(f"TraceId: {trace_id}")
        raise sqs_err from err


def acknowledge_message(
    sqs_client: Any, queue_url: str, receipt_handle: str
) -> None:
    """
    Elimina explícitamente un mensaje de la cola SQS mediante su ReceiptHandle
    una vez confirmado su procesamiento exitoso.
    """
    try:
        sqs_client.delete_message(
            QueueUrl=queue_url, ReceiptHandle=receipt_handle
        )
    except (ClientError, BotoCoreError) as err:
        sqs_err = SQSConnectionError(
            "Error al confirmar y eliminar el mensaje (delete_message) en SQS."
        )
        sqs_err.add_note(f"QueueUrl: {queue_url}")
        raise sqs_err from err


def _parse_sqs_message(
    msg: Dict[str, Any], queue_url: str
) -> Dict[str, Any]:
    """
    Decodifica y valida la estructura JSON de un mensaje SQS individual.
    Si el JSON está corrupto, lanza CorruptedMessageError con notas forenses.
    """
    msg_id = str(msg.get("MessageId", "unknown"))
    receipt_handle = str(msg.get("ReceiptHandle", ""))
    raw_body = msg.get("Body", "")

    try:
        body = json.loads(raw_body)
        if not isinstance(body, dict):
            raise ValueError(
                "El cuerpo JSON decodificado no es un objeto/diccionario."
            )
    except (json.JSONDecodeError, TypeError, ValueError) as err:
        corrupt_err = CorruptedMessageError(
            f"Mensaje SQS corrupto detectado (MessageId: {msg_id})."
        )
        corrupt_err.add_note(f"MessageId: {msg_id}")
        corrupt_err.add_note(f"QueueUrl: {queue_url}")
        raise corrupt_err from err

    return {
        "receipt_handle": receipt_handle,
        "message_id": msg_id,
        "body": body,
        "attributes": msg.get("MessageAttributes", {}),
    }


def consume_events(
    sqs_client: Any,
    queue_url: str,
    wait_time: int = 10,
    max_messages: int = 5,
    auto_delete: bool = False,
) -> List[Dict[str, Any]]:
    """
    Consume mensajes de SQS aplicando Long Polling (WaitTimeSeconds 1-20s).

    Si un mensaje contiene JSON corrupto (Poison Message), NO se elimina de la
    cola para permitir que actúe el VisibilityTimeout y la RedrivePolicy lo
    derive automáticamente hacia la Dead Letter Queue (vulcano-events-dlq).
    """
    try:
        response = sqs_client.receive_message(
            QueueUrl=queue_url,
            MaxNumberOfMessages=max_messages,
            WaitTimeSeconds=wait_time,
            MessageAttributeNames=["All"],
            AttributeNames=["All"],
        )
    except (ClientError, BotoCoreError) as err:
        if "Timeout" in str(err) or "RequestTimeout" in str(err):
            timeout_err = QueueTimeoutError(
                f"Tiempo de espera agotado consultando la cola {queue_url}."
            )
            timeout_err.add_note(f"WaitTimeSeconds: {wait_time}")
            raise timeout_err from err

        sqs_err = SQSConnectionError(
            "Error en la recepción de mensajes desde SQS LocalStack."
        )
        sqs_err.add_note(f"QueueUrl: {queue_url}")
        raise sqs_err from err

    processed: List[Dict[str, Any]] = []
    for msg in response.get("Messages", []):
        parsed_item = _parse_sqs_message(msg, queue_url)
        if auto_delete and parsed_item["receipt_handle"]:
            acknowledge_message(
                sqs_client, queue_url, parsed_item["receipt_handle"]
            )
        processed.append(parsed_item)

    return processed


__all__ = [
    "DEFAULT_LOCALSTACK_ENDPOINT",
    "DEFAULT_AWS_REGION",
    "get_sqs_client",
    "produce_event",
    "acknowledge_message",
    "consume_events",
]
