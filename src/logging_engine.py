"""Engine de observabilidad con formato JSON, QueueHandler y compresión Gzip."""

import gzip
import json
import logging
import logging.handlers
import os
import queue
import shutil
import traceback
from datetime import UTC, datetime


class AsyncJSONFormatter(logging.Formatter):
    """Formateador JSON estructurado conforme a ISO 8601 UTC."""

    _RESERVED = (
        "name", "msg", "args", "levelname", "levelno", "pathname",
        "filename", "module", "exc_info", "exc_text", "stack_info",
        "lineno", "funcName", "created", "msecs", "relativeCreated",
        "thread", "threadName", "processName", "process", "taskName",
        "message", "asctime",
    )

    def format(self, record):
        log_data = {
            "timestamp": datetime.now(UTC).isoformat(),
            "logger": record.name,
            "level": record.levelname,
            "message": record.getMessage(),
            "process": record.process,
            "thread_name": record.threadName,
        }

        message_id = getattr(record, "message_id", None)
        if message_id is not None:
            log_data["MessageId"] = message_id

        webhook_id = getattr(record, "webhook_id", None)
        if webhook_id is not None:
            log_data["WebhookId"] = webhook_id

        trace_id = getattr(record, "trace_id", None)
        if trace_id is not None:
            log_data["TraceId"] = trace_id

        for key, value in record.__dict__.items():
            if key in self._RESERVED or key.startswith("_"):
                continue
            if key in log_data:
                continue
            try:
                json.dumps(value)
                log_data[key] = value
            except (TypeError, ValueError):
                log_data[key] = repr(value)

        if record.exc_info:
            log_data["exception"] = self._serialize_exception(record.exc_info[1])

        if record.stack_info:
            log_data["stack_info"] = record.stack_info

        return json.dumps(log_data, ensure_ascii=False, default=str)

    def _serialize_exception(self, exc):
        """Serializa una excepción (o ExceptionGroup) de forma recursiva."""
        if exc is None:
            return {}

        payload = {
            "type": type(exc).__name__,
            "message": str(exc),
            "traceback": "".join(
                traceback.format_exception(type(exc), exc, exc.__traceback__)
            ),
        }

        notes = getattr(exc, "__notes__", None)
        if notes:
            payload["notes"] = list(notes)

        sub_exceptions = getattr(exc, "exceptions", None)
        if sub_exceptions:
            payload["sub_exceptions"] = [
                self._serialize_exception(sub) for sub in sub_exceptions
            ]

        return payload


def gzip_namer(default_name):
    """Agrega la extensión .gz al nombre del archivo rotado."""
    return default_name + ".gz"


def gzip_rotator(source, dest):
    """Comprime ``source`` a ``dest`` en Gzip y elimina el original."""
    with open(source, "rb") as f_in, gzip.open(dest, "wb") as f_out:
        shutil.copyfileobj(f_in, f_out)
    os.remove(source)


def setup_vulcano_logging(log_filename="vulcano_events.log"):
    """Configura el pipeline de logging no bloqueante con QueueHandler/QueueListener."""
    log_queue = queue.Queue(-1)
    queue_handler = logging.handlers.QueueHandler(log_queue)

    file_handler = logging.handlers.RotatingFileHandler(
        log_filename, maxBytes=2 * 1024 * 1024, backupCount=3, encoding="utf-8"
    )
    file_handler.setFormatter(AsyncJSONFormatter())
    file_handler.namer = gzip_namer
    file_handler.rotator = gzip_rotator

    listener = logging.handlers.QueueListener(log_queue, file_handler)
    listener.start()

    logger = logging.getLogger("vulcano_engine")
    logger.setLevel(logging.INFO)
    logger.addHandler(queue_handler)
    logger.listener = listener
    return logger


def shutdown_vulcano_logging(logger):
    """Detiene el listener y cierra los handlers de forma ordenada."""
    listener = getattr(logger, "listener", None)
    if listener is not None:
        listener.stop()
    for handler in logger.handlers:
        handler.flush()
        handler.close()
    logger.handlers.clear()