# 🌋 Vulcano Pay — Motor de Eventos SQS, Webhooks HMAC y Observabilidad Asíncrona (TP-2)

Sistema de procesamiento de eventos financieros desacoplado mediante **AWS SQS (LocalStack)** y **Boto3**, recepción y despacho de **Webhooks HTTP firmados con HMAC-SHA256**, y pipeline de **observabilidad estructurada JSON no bloqueante** con compresión Gzip bajo **Python 3.14 (PEP 765)**.

---

## 👥 Integrantes y Asignación de Roles

| Rol | Integrante | Archivos a Cargo | Estado |
| :--- | :--- | :--- | :--- |
| **Rol 1:** Robustez de Entradas, Excepciones y Sanitización | **Paz Villarreal, Sebastián** | `src/vulcano_telemetry/exceptions.py`<br>`src/vulcano_telemetry/sanitizer.py` | ✅ Asignado |
| **Rol 2:** Mensajería Asíncrona SQS con Boto3 y LocalStack | *Por definir (Georgina / Tamara / Leonel)* | `src/vulcano_telemetry/core_sqs.py` | ⏳ Pendiente |
| **Rol 3:** Seguridad Criptográfica HMAC y Receptor FastAPI | *Por definir (Georgina / Tamara / Leonel)* | `src/vulcano_telemetry/webhook_crypto.py`<br>`src/vulcano_telemetry/webhook_receiver.py` | ⏳ Pendiente |
| **Rol 4:** Observabilidad, Logging JSON y Compresión Gzip | **Isella, Lucía Daniza** | `src/vulcano_telemetry/logging_engine.py` | ✅ Asignado |
| **Rol 5:** Coordinador CLI, Despachador Webhook y `except*` | **Ahumada, Germán Maximiliano Leonel** | `src/app_operator.py`<br>`src/vulcano_telemetry/__init__.py` | ✅ Asignado |
| **Rol 6:** Simulación de Caos y Auditoría Forense de Logs | *Por definir (Georgina / Tamara / Leonel)* | `tests/test_chaos.py`<br>`tests/test_forensic_log.py` | ⏳ Pendiente |

**Integrantes del equipo:**
- Ahumada, Germán Maximiliano Leonel
- Isasmendi, Leonel
- Isella, Lucía Daniza
- Paz Villarreal, Sebastián
- Sosa, Tamara Gabriela
- Vaca, Georgina Zulma

---

## 📁 Estructura del Proyecto

```text
ProjVulcanoPay/
├── src/
│   ├── vulcano_telemetry/
│   │   ├── __init__.py           # Expone la API pública del paquete (__all__) [Rol 5]
│   │   ├── exceptions.py         # Excepciones semánticas custom de Vulcano y Webhooks [Rol 1]
│   │   ├── sanitizer.py          # Validación declarativa con argparse (callables custom) [Rol 1]
│   │   ├── core_sqs.py           # Cliente Boto3, SQS Producer/Consumer con Long Polling [Rol 2]
│   │   ├── webhook_crypto.py     # Firma y verificación HMAC-SHA256 (Timing-safe + Timestamps) [Rol 3]
│   │   ├── webhook_receiver.py   # Servidor HTTP local (FastAPI) POST /webhook (<100ms, 202) [Rol 3]
│   │   └── logging_engine.py     # AsyncJSONFormatter, QueueHandler/Listener y Gzip rollover [Rol 4]
│   └── app_operator.py           # Punto de entrada CLI ejecutable (argparse + except* + PEP 765) [Rol 5]
├── tests/
│   ├── test_chaos.py             # Inyección de caos, firmas inválidas y Poison Messages a DLQ [Rol 6]
│   └── test_forensic_log.py      # Validación de logs JSON y descompresión Gzip [Rol 6]
├── requirements.txt              # Dependencias del proyecto
├── pyproject.toml                # Configuración de rutas para pytest
└── README.md                     # Guía del proyecto y documentación técnica
```

---

## 🛠️ Guía Rápida de Tareas por Rol (Resumen de Consigna)

### 🔹 Rol 1: Excepciones y Sanitización (`exceptions.py` y `sanitizer.py`)
1. **`exceptions.py`**:
   - Excepción base `VulcanoError(Exception)` *(nunca heredar de `BaseException`)*.
   - Subclases SQS: `SQSConnectionError`, `QueueTimeoutError`, `CorruptedMessageError`.
   - Subclases Webhook: `WebhookSignatureError`, `WebhookTimestampError`, `WebhookDeliveryError`.
2. **`sanitizer.py`** (Validadores para `argparse` que lanzan `argparse.ArgumentTypeError`):
   - `parse_queue_name(value)`: Valida con regex el patrón `^vulcano-[a-z0-9-]+-queue$`.
   - `parse_wait_time(value)`: Valida que `WaitTimeSeconds` esté entre `1` y `20` segundos.
   - `parse_webhook_url(value)`: Valida con `urllib.parse` que sea una URL `http` o `https` válida.
   - `parse_secret_key(value)`: Valida que la clave secreta HMAC tenga al menos `16` caracteres.

### 🔹 Rol 2: Mensajería SQS con Boto3 y LocalStack (`core_sqs.py`)
1. **`get_sqs_client(endpoint_url="http://localhost:4566")`**: Cliente `boto3.client("sqs", ...)` con credenciales simuladas (`test` / `us-east-1`).
2. **`produce_event(sqs_client, queue_url, event_data)`**: Envía JSON con `send_message()` inyectando `MessageAttributes` (`TraceId`, `EventTopic`, `Timestamp`, `Source`). Captura `ClientError`, agrega contexto con `.add_note()` y relanza como `SQSConnectionError`.
3. **`consume_events(sqs_client, queue_url, wait_time=10, max_messages=5)`**: Consume aplicando **Long Polling** (`WaitTimeSeconds`) y `VisibilityTimeout`. Si el JSON está corrupto lanza `CorruptedMessageError` (para que derive a la DLQ `vulcano-events-dlq`); si se procesa con éxito elimina el mensaje con `delete_message(ReceiptHandle=...)`.

### 🔹 Rol 3: Criptografía HMAC y Servidor Receptor (`webhook_crypto.py` y `webhook_receiver.py`)
1. **`webhook_crypto.py`**:
   - `generate_signature(secret, timestamp, payload_bytes) -> str`: Calcula `HMAC-SHA256` en hex sobre `f"{timestamp}.".encode("utf-8") + payload_bytes`.
   - `verify_signature(secret, header_value, payload_bytes, tolerance_sec=300) -> bool`: Extrae `t` y `v1` de `X-Webhook-Signature`. Valida antigüedad máxima de 300s contra `time.time()` (si falla lanza `WebhookTimestampError`) y compara firmas en tiempo constante con **`hmac.compare_digest()`** (si falla lanza `WebhookSignatureError`).
2. **`webhook_receiver.py`**:
   - Servidor FastAPI con endpoint `POST /webhook`.
   - Lee `raw_bytes = await request.body()` **antes** de llamar a `await request.json()`, verifica la firma HMAC (devuelve `401 Unauthorized` si falla), publica en SQS LocalStack y responde **`HTTP 202 Accepted`** en menos de 100 ms.

### 🔹 Rol 4: Observabilidad y Logging JSON No Bloqueante (`logging_engine.py`)
1. **`AsyncJSONFormatter(logging.Formatter)`**:
   - Formatea cada log en JSON con `timestamp` en **ISO 8601 UTC estricto** (`datetime.now(timezone.utc).isoformat()`), `logger`, `level`, `message`, `process_id`, `thread_name`, `trace_id`, `message_id`, `webhook_id`.
   - Serializa recursivamente árboles de excepciones (`ExceptionGroup`) incluyendo notas de `.add_note()`.
2. **`setup_vulcano_logging()`**:
   - Desacopla la escritura en disco usando `QueueHandler` (`queue.Queue(-1)`) y `QueueListener`.
   - Configura `RotatingFileHandler` a **2 MB** (`backupCount=3`) con callbacks `gzip_namer` y `gzip_rotator` para comprimir los rotados a `.log.gz`.

### 🔹 Rol 5: Coordinador CLI, Despachador y `except*` (`app_operator.py` e `__init__.py`)
1. **`dispatch_webhook(target_url, secret, payload_dict)`**: Firma el evento y envía `POST` con cabecera `X-Webhook-Signature`.
2. **CLI (`argparse`)**: Integra los sanitizadores del Rol 1 y soporta los modos operativos (`produce-sqs`, `start-receiver`, `start-dispatcher`, `send-webhook`).
3. **Manejo con `except*` y PEP 765**: Captura quirúrgica de grupos de errores (`except* WebhookSignatureError`, `except* WebhookTimestampError`, `except* SQSConnectionError`) y apagado limpio del `QueueListener` en `finally` (sin usar `return`, `break` ni `continue`).

### 🔹 Rol 6: Simulación de Caos y Pruebas Forenses (`tests/`)
1. **`tests/test_chaos.py`**:
   - Simula webhooks con firmas falsas y verifica respuesta `401 Unauthorized` / `WebhookSignatureError`.
   - Simula Replay Attack (timestamp de hace 1 hora) y verifica `WebhookTimestampError`.
   - Envía *Poison Messages* (JSON inválido) a SQS y verifica su derivación a la Dead Letter Queue (`vulcano-events-dlq`).
2. **`tests/test_forensic_log.py`**:
   - Descomprime archivos `.log.gz` generados y valida la presencia e integridad de los campos JSON (`timestamp`, `message_id`, `trace_id`).

---

## ⚠️ Reglas Obligatorias de Evaluación (Checklist antes de hacer Push)

1. **Prohibido `BaseException`**: Todas las excepciones custom heredan de `Exception`. Prohibido usar `except: pass` o capturar `BaseException`.
2. **Norma PEP 765 (Python 3.14)**: Prohibido usar `return`, `break` o `continue` dentro de bloques `finally`.
3. **Boto3 + LocalStack**: Todas las operaciones SQS usan `boto3` apuntando a `http://localhost:4566`.
4. **Raw Bytes + `compare_digest`**: Validar siempre la firma HMAC sobre `await request.body()` antes de `.json()`, usando `hmac.compare_digest()`.
5. **I/O Desacoplado**: Todo log a disco pasa exclusivamente por `QueueHandler` y `QueueListener`.
6. **Fechas UTC**: Timestamps en logs en formato ISO 8601 UTC (`timezone.utc`).

---

## 🚀 Cómo Configurar el Entorno Local

1. Clonar el repositorio:
   `git clone https://github.com/Mikoo/ProjVulcanoPay.git`
2. Crear y activar el entorno virtual (Python 3.14):
   `python -m venv .venv` y `.\.venv\Scripts\Activate.ps1`
3. Instalar dependencias y linters:
   `pip install -r requirements.txt` y `pip install flake8 pylint`