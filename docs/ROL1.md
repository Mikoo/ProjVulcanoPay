# Rol 1 — Robustez de Entradas, Excepciones y Sanitización

**Responsable:** Paz Villarreal, Sebastián  
**Archivos:** `src/vulcano_telemetry/exceptions.py` y `src/vulcano_telemetry/sanitizer.py`  
**Tests:** `tests/test_exceptions.py` y `tests/test_sanitizer.py`

---

## 1. Objetivo

Este rol cubre la **frontera de entrada** del sistema y el **vocabulario de
errores** del dominio:

1. Rechazar argumentos inválidos de la CLI antes de que el programa se
   conecte a SQS, al receptor o al despachador.
2. Definir excepciones con nombre propio para que los demás roles puedan
   capturar y reportar cada falla de forma específica.

---

## 2. Contrato público

### 2.1 Excepciones

Todas heredan de `VulcanoError`, que hereda directamente de `Exception`.
**Nunca** se hereda de `BaseException`.

| Excepción | ¿Cuándo se usa? | Rol que la lanza |
|---|---|---|
| `VulcanoError` | Base de todos los errores del dominio | Todos |
| `SQSConnectionError` | Falla la conexión con SQS / LocalStack | Rol 2 |
| `QueueTimeoutError` | Se agota el tiempo de espera de la cola | Rol 2 |
| `CorruptedMessageError` | El mensaje no es JSON válido o le faltan campos | Rol 2 |
| `WebhookSignatureError` | La firma HMAC no coincide | Rol 3 |
| `WebhookTimestampError` | El timestamp está fuera de la ventana de 300 s | Rol 3 |
| `WebhookDeliveryError` | No se pudo entregar el webhook al cliente | Rol 5 |

Ejemplo de uso:

```python
from vulcano_telemetry.exceptions import WebhookSignatureError

raise WebhookSignatureError("La firma HMAC no coincide")
```

Ejemplo de captura específica:

```python
try:
    verificar_firma(...)
except WebhookSignatureError:
    return 401
```

### 2.2 Sanitizadores

Cada función se usa como `type=` de `argparse`. Si el valor no cumple la
regla, lanza `argparse.ArgumentTypeError`.

| Función | Regla | Ejemplo válido |
|---|---|---|
| `parse_queue_name(value)` | `^vulcano-[a-z0-9-]+-queue$` | `vulcano-events-queue` |
| `parse_wait_time(value)` | Entero entre 1 y 20 | `10` |
| `parse_webhook_url(value)` | `http`/`https`, host y puerto numérico | `http://localhost:8000/webhook` |
| `parse_secret_key(value)` | Mínimo 16 caracteres | `clave-super-segura-2026` |

Ejemplo de integración en la CLI:

```python
import argparse

from vulcano_telemetry.sanitizer import parse_queue_name

parser = argparse.ArgumentParser()
parser.add_argument("--queue", type=parse_queue_name)
args = parser.parse_args()
```

Si el usuario escribe `--queue cola_invalida`, argparse muestra el error y
termina con **código de salida 2**. La función `main()` no se ejecuta, no se
crea el cliente boto3 y no se hace ninguna llamada a SQS.

---

## 3. Cómo verificar

Desde la raíz del repositorio:

```bash
python -m pytest -q
```

Resultado esperado:

```text
70 passed
```

También se puede probar la integración real con el CLI del Rol 5:

```bash
python src/app_operator.py --mode produce-sqs --queue cola_invalida
```

Salida esperada:

```text
VulcanoCLI: error: argument -q/--queue: Nombre de cola inválido: 'cola_invalida'.
Debe cumplir el patrón ^vulcano-[a-z0-9-]+-queue$ ...
```

Código de salida: `2`.

Casos útiles para una demo:

```bash
# Válido
python src/app_operator.py --mode produce-sqs --queue vulcano-events-queue --wait-time 10

# Inválidos
python src/app_operator.py --mode produce-sqs --queue cola_invalida
python src/app_operator.py --mode produce-sqs --wait-time 99
python src/app_operator.py --mode produce-sqs --url ftp://ejemplo.com
python src/app_operator.py --mode produce-sqs --secret corta
```

> Nota: los comandos con argumentos válidos pueden fallar más adelante si
> el Rol 2 todavía no implementó `core_sqs.py`. Eso es esperado: la
> validación del Rol 1 ocurre antes.

---

## 4. Decisiones de diseño

- **`Exception` en vez de `BaseException`.** `BaseException` incluye
  `KeyboardInterrupt` y `SystemExit`. Nuestros errores son errores de
  aplicación y deben ser capturables con `except Exception` sin mezclarse
  con el cierre del programa.
- **`re.fullmatch` en vez de `re.match`.** `fullmatch` exige que todo el
  texto coincida con el patrón; `match` aceptaría un prefijo válido seguido
  de basura.
- **`strip()` en los textos.** Elimina espacios accidentales de la CLI y
  normaliza el valor que se usa después (por ejemplo, para HMAC).
- **La clave secreta no se muestra en los errores.** Solo se informa la
  longitud. Así la clave no queda escrita en logs ni en la terminal.
- **Validación del puerto.** `urlparse` + `parsed.port` rechazan puertos no
  numéricos como `http://localhost:abc`.
- **Validación de tipo.** Si otra función llama al sanitizador con `None` o
  un número, se lanza `ArgumentTypeError` en vez de un `AttributeError`.

---

## 5. Notas para los próximos roles

- **Rol 2 (`core_sqs.py`):** lanzar `SQSConnectionError` cuando falle la
  conexión con LocalStack, `QueueTimeoutError` cuando se agote el long
  polling y `CorruptedMessageError` cuando el JSON sea inválido. El mensaje
  corrupto debe quedar sin borrar para que SQS lo derive a la DLQ.
- **Rol 3 (`webhook_crypto.py` / `webhook_receiver.py`):** lanzar
  `WebhookTimestampError` si el timestamp está fuera de la ventana de 300 s
  y `WebhookSignatureError` si `hmac.compare_digest()` falla. El receptor
  debe responder `401`.
- **Rol 4 (`logging_engine.py`):** puede serializar estas excepciones; el
  campo `exception` del log debe conservar el mensaje y las notas de
  `add_note()`.
- **Rol 5 (`app_operator.py`):** ya importa los cuatro sanitizadores y las
  excepciones. Las funciones se usan como `type=` de argparse y las
  excepciones se capturan con `except*`.
- **Rol 6 (`tests/`):** los tests de caos pueden importar estas excepciones
  para verificar respuestas `401`, timestamps vencidos y mensajes corruptos.

---

## 6. Checklist de aceptación

- [x] `VulcanoError` hereda de `Exception`.
- [x] Los seis errores concretos heredan de `VulcanoError`.
- [x] No se usa `BaseException` en ninguna excepción.
- [x] Los cuatro sanitizadores lanzan `argparse.ArgumentTypeError`.
- [x] El nombre de cola respeta `^vulcano-[a-z0-9-]+-queue$`.
- [x] El tiempo de espera está entre 1 y 20.
- [x] La URL exige `http`/`https`, host y puerto numérico.
- [x] La clave secreta exige al menos 16 caracteres.
- [x] El error de la clave no filtra el secreto.
- [x] `python -m pytest -q` devuelve `70 passed`.
