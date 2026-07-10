import asyncio
import ipaddress
import json
import logging
import os
import re
import secrets
import shutil
import signal
import subprocess
import tempfile
import time
from collections import defaultdict
from datetime import datetime
from logging.handlers import RotatingFileHandler
from typing import Dict, Optional, Tuple

import nmap
from cryptography.fernet import Fernet
from dotenv import load_dotenv
from quart import Quart, jsonify, request
from telegram import Bot
from telegram.error import TelegramError

from recon_planner import build_recon_plan, recon_plan_to_jsonl, recon_plan_to_markdown
from tool_inventory import build_tool_inventory, inventory_to_jsonl, inventory_to_markdown
from ui import UI_HTML

load_dotenv()

"""
Быстрое сканирование:
curl -X POST http://localhost:5000/scan \
    -H "Content-Type: application/json" \
    -d '{"target": "127.0.0.1", "scan_type": "Ping"}'

Планирование сканирования:
curl -X POST http://localhost:5000/schedule \
    -H "Content-Type: application/json" \
    -d '{"target": "192.168.1.1", "scan_type": "TCP", "interval": 10}'

Управление задачами:
# Список задач
curl http://localhost:5000/tasks

# Отмена задачи
curl -X DELETE http://localhost:5000/tasks/192.168.1.1-TCP

# Health check
curl http://localhost:5000/health
"""


# Глобальные переменные
start_time = datetime.now()
VERSION = "1.1.0"
SCAN_LOG_PATH = os.getenv("SCAN_LOG_PATH", "/app/logs/scan_log.txt")
RESULTS_DIR = os.getenv("RESULTS_DIR", "encrypted_results")
APP_HOST = os.getenv("APP_HOST", "127.0.0.1")


def _parse_bool_env(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on", "y"}


def _parse_int_env(
    name: str,
    default: int,
    min_value: Optional[int] = None,
    max_value: Optional[int] = None,
) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        parsed = int(value)
    except (ValueError, TypeError):
        raise RuntimeError(f"{name} must be integer, got: {value!r}")

    if min_value is not None and parsed < min_value:
        raise RuntimeError(f"{name} must be >= {min_value}, got: {parsed}")
    if max_value is not None and parsed > max_value:
        raise RuntimeError(f"{name} must be <= {max_value}, got: {parsed}")

    return parsed


def _create_log_handler():
    for path in [SCAN_LOG_PATH, "scan_log.txt"]:
        try:
            log_dir = os.path.dirname(path)
            if log_dir:
                os.makedirs(log_dir, exist_ok=True)
            return RotatingFileHandler(
                path,
                maxBytes=10 * 1024 * 1024,
                backupCount=5,
            )
        except (OSError, ValueError):
            continue
    return logging.StreamHandler()


logging.basicConfig(
    handlers=[_create_log_handler()],
    level=logging.INFO,
    format="[%(asctime)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

# Конфиденциальные данные из переменных среды
TELEGRAM_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")
bot = Bot(token=TELEGRAM_TOKEN) if TELEGRAM_TOKEN and CHAT_ID else None

# Безопасные настройки API
API_AUTH_REQUIRED = _parse_bool_env("API_AUTH_REQUIRED", True)
API_AUTH_HEADER = os.getenv("API_AUTH_HEADER", "X-API-KEY").strip() or "X-API-KEY"
API_AUTH_TOKEN = os.getenv("API_AUTH_TOKEN", "").strip()
if API_AUTH_REQUIRED and not API_AUTH_TOKEN:
    raise RuntimeError(
        "API_AUTH_REQUIRED=true, but API_AUTH_TOKEN is empty. Set API_AUTH_TOKEN for security."
    )

# Защита от перегруза
RATE_LIMIT_WINDOW_SECONDS = _parse_int_env(
    "RATE_LIMIT_WINDOW_SECONDS", default=60, min_value=1, max_value=3600
)
MAX_REQUESTS_PER_WINDOW = _parse_int_env(
    "MAX_REQUESTS_PER_WINDOW", default=10, min_value=1, max_value=200
)
MAX_RATE_LIMIT_CLIENTS = _parse_int_env(
    "MAX_RATE_LIMIT_CLIENTS", default=10_000, min_value=100, max_value=100_000
)
MAX_CONCURRENT_SCANS = _parse_int_env("MAX_CONCURRENT_SCANS", default=2, min_value=1, max_value=20)
MAX_SCHEDULED_TASKS = _parse_int_env(
    "MAX_SCHEDULED_TASKS", default=100, min_value=1, max_value=10_000
)
SCAN_TIMEOUT_SECONDS = _parse_int_env(
    "SCAN_TIMEOUT_SECONDS", default=1800, min_value=60, max_value=7200
)
APP_PORT = _parse_int_env("APP_PORT", default=5000, min_value=1, max_value=65535)
TOOL_INVENTORY_CACHE_SECONDS = _parse_int_env(
    "TOOL_INVENTORY_CACHE_SECONDS", default=300, min_value=0, max_value=3600
)
MAX_TARGET_ADDRESSES = _parse_int_env(
    "MAX_TARGET_ADDRESSES", default=4096, min_value=1, max_value=1_048_576
)
MAX_REQUEST_BODY_BYTES = _parse_int_env(
    "MAX_REQUEST_BODY_BYTES", default=1_048_576, min_value=1024, max_value=16_777_216
)
MIN_SCHEDULE_INTERVAL_MINUTES = _parse_int_env(
    "MIN_SCHEDULE_INTERVAL_MINUTES", default=1, min_value=1, max_value=1440
)
MAX_SCHEDULE_INTERVAL_MINUTES = _parse_int_env(
    "MAX_SCHEDULE_INTERVAL_MINUTES", default=10_080, min_value=1, max_value=525_600
)
if MIN_SCHEDULE_INTERVAL_MINUTES > MAX_SCHEDULE_INTERVAL_MINUTES:
    raise RuntimeError(
        "MIN_SCHEDULE_INTERVAL_MINUTES must not exceed MAX_SCHEDULE_INTERVAL_MINUTES"
    )

# Таймауты/настройки Nmap из окружения
HOST_TIMEOUT_SEC = _parse_int_env("NMAP_HOST_TIMEOUT_SEC", default=300, min_value=1, max_value=3600)
NMAP_MAX_RETRIES = _parse_int_env("NMAP_MAX_RETRIES", default=2, min_value=0, max_value=10)

# Генерация/загрузка ключа для шифрования
FERNET_KEY = os.getenv("FERNET_KEY", "").strip()
if not FERNET_KEY:
    raise RuntimeError(
        "FERNET_KEY не задан! Укажите его в .env или переменных окружения. "
        "Без него нельзя расшифровать результаты."
    )
try:
    cipher = Fernet(FERNET_KEY.encode())
except Exception as exc:
    raise RuntimeError(
        "Неверный FERNET_KEY. Проверьте формат (должен быть валидным Fernet key)."
    ) from exc


app = Quart(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_REQUEST_BODY_BYTES
scan_tasks = {}
rate_limits = defaultdict(list)
tool_inventory_cache = {}
_scan_semaphore: Optional[asyncio.Semaphore] = None

SUPPORTED_SCAN_TYPES = {
    "SYN": "-sS",
    "TCP": "-sT",
    "UDP": "-sU",
    "Aggressive": "-A",
    "OS": "-O",
    "Ping": "-sn",
}


def _normalize_scan_type(scan_type: str) -> Optional[str]:
    normalized = scan_type.strip()
    if not normalized:
        return None

    for key in SUPPORTED_SCAN_TYPES:
        if key.lower() == normalized.lower():
            return key

    return None


auth_domain_re = re.compile(
    r"^(?:(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}|localhost)$",
    re.IGNORECASE,
)


def _get_scan_semaphore() -> asyncio.Semaphore:
    global _scan_semaphore
    if _scan_semaphore is None:
        _scan_semaphore = asyncio.Semaphore(MAX_CONCURRENT_SCANS)
    return _scan_semaphore


def get_scan_type_choices() -> str:
    return ", ".join(f"'{k}'" for k in SUPPORTED_SCAN_TYPES.keys())


def log_event(event: str):
    logging.info(event)
    print(event)


def _validate_scan_payload(
    payload: Optional[Dict],
) -> Tuple[Optional[str], Optional[str], Optional[float], Optional[str]]:
    """Return target, scan_type, interval (optional), error_code."""
    if not isinstance(payload, dict):
        return None, None, None, "Отсутствуют или некорректные данные запроса"

    target = payload.get("target")
    if isinstance(target, str):
        target = target.strip()

    if not target:
        return None, None, None, "Не указан target"

    scan_type = payload.get("scan_type", "TCP")
    if not isinstance(scan_type, str):
        return None, None, None, "scan_type должен быть строкой"

    normalized_scan_type = _normalize_scan_type(scan_type)
    if normalized_scan_type is None:
        return (
            None,
            None,
            None,
            f"Недопустимый scan_type. Допустимые: {get_scan_type_choices()}",
        )
    scan_type = normalized_scan_type

    interval = payload.get("interval", 30)
    interval_value = None
    if interval is not None:
        if isinstance(interval, bool) or not isinstance(interval, (int, float)):
            return target, scan_type, None, "Интервал должен быть числом"
        if interval <= 0:
            return target, scan_type, None, "Интервал должен быть положительным числом"
        if interval < MIN_SCHEDULE_INTERVAL_MINUTES:
            return (
                target,
                scan_type,
                None,
                f"Интервал должен быть не меньше {MIN_SCHEDULE_INTERVAL_MINUTES} мин.",
            )
        if interval > MAX_SCHEDULE_INTERVAL_MINUTES:
            return (
                target,
                scan_type,
                None,
                f"Интервал должен быть не больше {MAX_SCHEDULE_INTERVAL_MINUTES} мин.",
            )
        interval_value = float(interval)

    if not validate_ip_or_host(target):
        return target, scan_type, interval_value, "Неверный IP, CIDR или домен"

    return target, scan_type, interval_value, None


def require_api_auth():
    if not API_AUTH_REQUIRED:
        return None

    token = request.headers.get(API_AUTH_HEADER)
    if not token:
        return jsonify({"error": f"Не указан API токен ({API_AUTH_HEADER})"}), 401
    if not secrets.compare_digest(token, API_AUTH_TOKEN):
        return jsonify({"error": "Неверный API токен"}), 403
    return None


def _client_key() -> str:
    return request.remote_addr or "unknown"


def _cleanup_finished_tasks() -> list:
    finished_task_ids = [task_id for task_id, task in scan_tasks.items() if task.done()]
    if not finished_task_ids:
        return []

    for task_id in finished_task_ids:
        try:
            task = scan_tasks.pop(task_id)
            if task.cancelled():
                log_event(f"Задача {task_id} удалена из реестра после отмены")
            else:
                exception = task.exception()
                if exception is not None:
                    log_event(f"Задача {task_id} завершилась с ошибкой: {exception}")
        except Exception as e:
            log_event(f"Ошибка удаления задачи {task_id}: {e}")

    return finished_task_ids


def check_rate_limit() -> bool:
    client_ip = _client_key()
    now = time.time()

    if client_ip not in rate_limits and len(rate_limits) >= MAX_RATE_LIMIT_CLIENTS:
        stale_before = now - RATE_LIMIT_WINDOW_SECONDS
        stale_clients = [
            key
            for key, timestamps in rate_limits.items()
            if not timestamps or timestamps[-1] <= stale_before
        ]
        for key in stale_clients:
            rate_limits.pop(key, None)

        if len(rate_limits) >= MAX_RATE_LIMIT_CLIENTS:
            oldest_client = min(
                rate_limits,
                key=lambda key: rate_limits[key][-1] if rate_limits[key] else 0,
            )
            rate_limits.pop(oldest_client, None)

    request_window = rate_limits[client_ip]
    rate_limits[client_ip] = [
        req_time for req_time in request_window if now - req_time < RATE_LIMIT_WINDOW_SECONDS
    ]

    if len(rate_limits[client_ip]) >= MAX_REQUESTS_PER_WINDOW:
        return False

    rate_limits[client_ip].append(now)
    return True


def _bool_query_param(name: str, default: bool = False) -> bool:
    value = request.args.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on", "y"}


def get_cached_tool_inventory(expand: bool = False) -> Dict:
    cache_key = "expanded" if expand else "summary"
    cached = tool_inventory_cache.get(cache_key)
    now = time.time()
    if (
        cached
        and TOOL_INVENTORY_CACHE_SECONDS > 0
        and now - cached["created_at"] < TOOL_INVENTORY_CACHE_SECONDS
    ):
        return cached["inventory"]

    inventory = build_tool_inventory(expand=expand)
    tool_inventory_cache[cache_key] = {"created_at": now, "inventory": inventory}
    return inventory


async def send_telegram_message(message: str):
    if not bot:
        log_event("Telegram не настроен. Сообщение не отправлено.")
        return
    try:
        await bot.send_message(chat_id=CHAT_ID, text=message)
    except TelegramError as e:
        log_event(f"Ошибка отправки сообщения в Telegram: {e}")
    except Exception as e:
        log_event(f"Неожиданная ошибка при отправке Telegram сообщения: {e}")


def validate_ip_or_host(target: str) -> bool:
    """Валидация IP, сети и домена."""
    if not isinstance(target, str) or not target:
        return False

    target = target.strip()
    if len(target) > 253:
        return False

    # Блокируем наиболее опасные символы для предотвращения нестабильного поведения
    dangerous_chars = [";", "&", "|", "`", "$", "(", ")", "<", ">", "\\", "\n", "\r", "\t"]
    if any(char in target for char in dangerous_chars):
        log_event(f"Potential injection-like input detected in target: {target}")
        return False

    try:
        network = ipaddress.ip_network(target, strict=False)
        if network.num_addresses > MAX_TARGET_ADDRESSES:
            log_event(
                f"Target range is too large: {target} contains {network.num_addresses} addresses"
            )
            return False
        return True
    except ValueError:
        return auth_domain_re.fullmatch(target) is not None


def build_scan_args(scan_type: str) -> str:
    if scan_type not in SUPPORTED_SCAN_TYPES:
        raise ValueError(f"Недопустимый scan_type: {scan_type}")

    base = SUPPORTED_SCAN_TYPES[scan_type]
    extra = [f"--host-timeout {HOST_TIMEOUT_SEC}s", f"--max-retries {NMAP_MAX_RETRIES}"]

    return f"{base} {' '.join(extra)}"


def scan_network(target: str, scan_type: str):
    """
    СИНХРОННАЯ функция, запускается в ThreadPool.
    Исключения НЕ глотаем — пусть летят в async слой.
    """
    scanner = nmap.PortScanner()
    scan_args = build_scan_args(scan_type)
    log_event(f"Запуск сканирования {target} с типом {scan_type} и аргументами: {scan_args}")

    try:
        scanner.scan(target, arguments=scan_args, timeout=SCAN_TIMEOUT_SECONDS)
    except nmap.PortScannerTimeout as exc:
        raise TimeoutError(f"Nmap did not finish within {SCAN_TIMEOUT_SECONDS} seconds") from exc
    return process_scan_results(scanner)


def process_scan_results(scanner: nmap.PortScanner) -> dict:
    results = {
        "scan_time": datetime.now().isoformat(),
        "scan_count": len(scanner.all_hosts()),
        "hosts": [],
    }
    for host in scanner.all_hosts():
        host_data = {
            "host": host,
            "hostname": scanner[host].hostname() or "N/A",
            "state": scanner[host].state(),
            "protocols": {},
        }
        for proto in scanner[host].all_protocols():
            ports = []
            for port in sorted(scanner[host][proto].keys()):
                pi = scanner[host][proto][port]
                ports.append(
                    {
                        "port": port,
                        "state": pi.get("state", "unknown"),
                        "name": pi.get("name", "unknown"),
                        "product": pi.get("product", "unknown"),
                        "version": pi.get("version", "unknown"),
                    }
                )
            host_data["protocols"][proto] = ports
        results["hosts"].append(host_data)
    return results


def _write_encrypted_result(path: str, encrypted_data: bytes) -> None:
    """Atomically persist encrypted output with owner-only permissions."""
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, mode=0o700, exist_ok=True)
    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb", dir=directory, prefix=".scan-", delete=False
        ) as handle:
            temporary_path = handle.name
            os.chmod(temporary_path, 0o600)
            handle.write(encrypted_data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
    finally:
        if temporary_path and os.path.exists(temporary_path):
            os.unlink(temporary_path)


async def save_scan_results_async(results: dict, target: str, scan_type: str):
    if not results:
        return

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    safe_target = "".join(c if c.isalnum() or c in [".", "_", "-"] else "_" for c in target)[:120]
    filename = f"{safe_target}_{scan_type}_{timestamp}.json"
    path = os.path.join(RESULTS_DIR, filename)

    try:
        encrypted_data = cipher.encrypt(json.dumps(results, indent=2).encode())
        await asyncio.to_thread(_write_encrypted_result, path, encrypted_data)
        log_event(f"Результаты сохранены в {path}")
        await send_telegram_message(f"Сканирование {target} завершено. Результаты: {filename}")
    except Exception as e:
        err = f"Ошибка сохранения результатов: {e}"
        log_event(err)
        await send_telegram_message(f"Ошибка сохранения результатов для {target}: {e}")
        raise


async def async_scan(target: str, scan_type: str):
    loop = asyncio.get_running_loop()
    try:
        async with _get_scan_semaphore():
            results = await asyncio.wait_for(
                loop.run_in_executor(None, scan_network, target, scan_type),
                timeout=SCAN_TIMEOUT_SECONDS + 5,
            )
    except asyncio.TimeoutError as e:
        err = f"Таймаут сканирования {target} ({scan_type})"
        log_event(err)
        await send_telegram_message(f" {err}")
        raise TimeoutError(err) from e
    except Exception as e:
        err = f"Ошибка при сканировании {target} ({scan_type}): {e}"
        log_event(err)
        await send_telegram_message(f" {err}")
        raise

    if results:
        await save_scan_results_async(results, target, scan_type)
    return results


@app.route("/scan", methods=["POST"])
async def start_scan():
    try:
        auth_error = require_api_auth()
        if auth_error:
            return auth_error

        if not check_rate_limit():
            return jsonify({"error": "Превышен лимит запросов"}), 429

        data = await request.get_json(silent=True)
        target, scan_type, _, error = _validate_scan_payload(data)
        if error:
            return jsonify({"error": error}), 400

        log_event(f"Получен запрос на сканирование: {target}, тип: {scan_type}")
        results = await async_scan(target, scan_type)
        return jsonify(results or {"message": "Сканирование завершено без результатов"}), 200
    except TimeoutError as e:
        err = f"Таймаут сканирования: {e}"
        log_event(err)
        await send_telegram_message(f"API timeout: {err}")
        return jsonify({"error": str(e)}), 504
    except Exception as e:
        err = f"API ошибка в /scan: {e}"
        log_event(err)
        await send_telegram_message(f"API ошибка: {e}")
        return jsonify({"error": "Внутренняя ошибка сканирования"}), 500


async def periodic_scan(target: str, scan_type: str, interval_minutes: float):
    """Асинхронное периодическое сканирование"""
    try:
        interval = float(interval_minutes)
    except (TypeError, ValueError):
        raise ValueError("Интервал должен быть числом")

    if interval <= 0:
        raise ValueError("Интервал должен быть положительным числом")

    log_event(f"Запущено периодическое сканирование {target} каждые {interval} минут")
    await send_telegram_message(
        f"Запущено периодическое сканирование {target} каждые {interval} минут"
    )

    while True:
        _cleanup_finished_tasks()
        try:
            log_event(f"Выполняется периодическое сканирование: {target}")
            await async_scan(target, scan_type)
        except asyncio.CancelledError:
            log_event(f"Периодическое сканирование {target} отменено")
            break
        except Exception as e:
            err = f"Ошибка периодического сканирования {target}: {e}"
            log_event(err)
            await send_telegram_message(f" {err}")

        try:
            await asyncio.sleep(interval * 60)
        except asyncio.CancelledError:
            break


@app.route("/schedule", methods=["POST"])
async def add_scheduled_scan():
    try:
        auth_error = require_api_auth()
        if auth_error:
            return auth_error

        if not check_rate_limit():
            return jsonify({"error": "Превышен лимит запросов"}), 429

        data = await request.get_json(silent=True)
        target, scan_type, interval, error = _validate_scan_payload(data)
        if error:
            return jsonify({"error": error}), 400

        if interval is None:
            interval = 30.0

        task_id = f"{target}-{scan_type}"
        _cleanup_finished_tasks()
        if task_id in scan_tasks:
            return jsonify({"error": "Сканирование уже запланировано"}), 400
        if len(scan_tasks) >= MAX_SCHEDULED_TASKS:
            return jsonify({"error": "Достигнут лимит запланированных задач"}), 429

        task = asyncio.create_task(periodic_scan(target, scan_type, interval))
        scan_tasks[task_id] = task
        log_event(f"Сканирование {target} запланировано каждые {interval} минут")

        return jsonify(
            {
                "message": f"Сканирование {target} запланировано каждые {interval} минут",
                "task_id": task_id,
            }
        ), 200
    except Exception as e:
        err = f"Ошибка в /schedule: {e}"
        log_event(err)
        return jsonify({"error": "Внутренняя ошибка планировщика"}), 500


@app.route("/tasks", methods=["GET"])
async def list_tasks():
    auth_error = require_api_auth()
    if auth_error:
        return auth_error

    _cleanup_finished_tasks()
    tasks_info = []
    for task_id, task in scan_tasks.items():
        tasks_info.append(
            {
                "id": task_id,
                "running": not task.done(),
                "cancelled": task.cancelled(),
            }
        )
    return jsonify(tasks_info), 200


@app.route("/tasks/<path:task_id>", methods=["DELETE"])
async def cancel_task(task_id):
    auth_error = require_api_auth()
    if auth_error:
        return auth_error

    _cleanup_finished_tasks()
    if task_id in scan_tasks:
        scan_tasks[task_id].cancel()
        del scan_tasks[task_id]
        log_event(f"Задача {task_id} отменена")
        await send_telegram_message(f"Задача {task_id} отменена")
        return jsonify({"message": f"Задача {task_id} отменена"}), 200
    return jsonify({"error": "Задача не найдена"}), 404


@app.route("/tools", methods=["GET"])
async def tools_inventory():
    auth_error = require_api_auth()
    if auth_error:
        return auth_error
    if not check_rate_limit():
        return jsonify({"error": "Превышен лимит запросов"}), 429

    expand = _bool_query_param("expand", False)
    inventory = await asyncio.to_thread(get_cached_tool_inventory, expand=expand)
    return jsonify(inventory), 200


@app.route("/tools/ai-context", methods=["GET"])
async def tools_ai_context():
    auth_error = require_api_auth()
    if auth_error:
        return auth_error
    if not check_rate_limit():
        return jsonify({"error": "Превышен лимит запросов"}), 429

    expand = _bool_query_param("expand", False)
    output_format = request.args.get("format", "jsonl").strip().lower()
    inventory = await asyncio.to_thread(get_cached_tool_inventory, expand=expand)
    if output_format in {"md", "markdown"}:
        return (
            inventory_to_markdown(inventory),
            200,
            {"Content-Type": "text/markdown; charset=utf-8"},
        )
    return (
        inventory_to_jsonl(inventory),
        200,
        {"Content-Type": "application/x-ndjson; charset=utf-8"},
    )


@app.route("/recon/plan", methods=["POST"])
async def recon_plan():
    auth_error = require_api_auth()
    if auth_error:
        return auth_error
    if not check_rate_limit():
        return jsonify({"error": "Превышен лимит запросов"}), 429

    data = await request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Expected scan result JSON"}), 400

    scan = data.get("scan") or data.get("result") or data
    if not isinstance(scan, dict) or not isinstance(scan.get("hosts"), list):
        return jsonify({"error": "Expected parsed Nmap result with hosts[]"}), 400

    inventory = await asyncio.to_thread(
        get_cached_tool_inventory, expand=_bool_query_param("expand", False)
    )
    plan = await asyncio.to_thread(build_recon_plan, scan, inventory=inventory)
    output_format = request.args.get("format", "json").strip().lower()
    if output_format == "jsonl":
        return (
            recon_plan_to_jsonl(plan),
            200,
            {"Content-Type": "application/x-ndjson; charset=utf-8"},
        )
    if output_format in {"md", "markdown"}:
        return recon_plan_to_markdown(plan), 200, {"Content-Type": "text/markdown; charset=utf-8"}
    return jsonify(plan), 200


@app.route("/", methods=["GET"])
@app.route("/ui", methods=["GET"])
async def dashboard():
    return UI_HTML, 200, {"Content-Type": "text/html; charset=utf-8"}


@app.after_request
async def add_security_headers(response):
    response.headers.setdefault("Cache-Control", "no-store")
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
        "connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'",
    )
    return response


def _check_nmap_available() -> bool:
    executable = shutil.which("nmap")
    if not executable:
        return False
    try:
        result = subprocess.run(
            [executable, "--version"],
            capture_output=True,
            check=False,
            timeout=3,
        )
        return result.returncode == 0
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        return False


@app.route("/health", methods=["GET"])
async def health_check():
    _cleanup_finished_tasks()
    nmap_available = _check_nmap_available()
    status = "healthy" if nmap_available else "unhealthy"

    return jsonify(
        {
            "status": status,
            "version": VERSION,
            "tasks_count": len(scan_tasks),
            "telegram_configured": bot is not None,
            "uptime": str(datetime.now() - start_time),
            "fernet_key_configured": bool(FERNET_KEY),
            "nmap_available": nmap_available,
            "max_requests_per_window": MAX_REQUESTS_PER_WINDOW,
            "rate_limit_window_seconds": RATE_LIMIT_WINDOW_SECONDS,
            "max_concurrent_scans": MAX_CONCURRENT_SCANS,
            "max_scheduled_tasks": MAX_SCHEDULED_TASKS,
            "max_target_addresses": MAX_TARGET_ADDRESSES,
        }
    ), 200


@app.route("/api/docs", methods=["GET"])
async def api_docs():
    return jsonify(
        {
            "name": "Nmap Automation Framework API",
            "version": VERSION,
            "security": {
                "api_auth_required": API_AUTH_REQUIRED,
                "api_auth_header": API_AUTH_HEADER,
                "rate_limit": f"{MAX_REQUESTS_PER_WINDOW} requests per {RATE_LIMIT_WINDOW_SECONDS} seconds",
                "max_concurrent_scans": MAX_CONCURRENT_SCANS,
            },
            "endpoints": {
                "POST /scan": {
                    "description": "Немедленное сканирование сети",
                    "request": {
                        "target": "IP адрес, диапазон или домен",
                        "scan_type": "SYN|TCP|UDP|Aggressive|OS|Ping",
                    },
                    "example": {"target": "192.168.1.1", "scan_type": "TCP"},
                },
                "POST /schedule": {
                    "description": "Планирование периодического сканирования",
                    "request": {
                        "target": "IP адрес, диапазон или домен",
                        "scan_type": "Тип сканирования",
                        "interval": "Интервал в минутах",
                    },
                    "example": {
                        "target": "192.168.1.0/24",
                        "scan_type": "SYN",
                        "interval": 30,
                    },
                },
                "GET /tasks": {"description": "Список активных задач"},
                "DELETE /tasks/<task_id>": {"description": "Отмена задачи по ID"},
                "GET /health": {"description": "Проверка состояния сервиса"},
                "GET /tools": {
                    "description": "Инвентаризация официальных Kali/pentest инструментов"
                },
                "GET /tools/ai-context": {
                    "description": "JSONL/Markdown контекст инструментов для GPT/Claude"
                },
                "POST /recon/plan": {
                    "description": "AI-readable next-step recon plan from parsed Nmap results",
                    "request": {"scan": "Parsed /scan response or object with hosts[]"},
                    "formats": "json|jsonl|markdown",
                },
            },
        }
    ), 200


async def load_initial_tasks():
    """Загрузка начальных задач из переменной окружения"""
    initial_tasks_raw = os.getenv("INITIAL_TASKS", "[]")
    if not initial_tasks_raw.strip():
        return

    try:
        initial_tasks = json.loads(initial_tasks_raw)
        if not isinstance(initial_tasks, list):
            log_event("INITIAL_TASKS должен быть массивом")
            return

        for task_config in initial_tasks:
            if len(scan_tasks) >= MAX_SCHEDULED_TASKS:
                log_event(
                    f"INITIAL_TASKS: достигнут лимит {MAX_SCHEDULED_TASKS}; остальные задачи пропущены"
                )
                break
            if not isinstance(task_config, dict):
                log_event("INITIAL_TASKS содержит некорректный элемент")
                continue

            target, scan_type, interval, error = _validate_scan_payload(task_config)
            if error:
                log_event(f"INITIAL_TASKS: skipped task ({error}). Payload: {task_config}")
                continue

            if interval is None:
                interval = 30.0

            task_id = f"{target}-{scan_type}"
            if task_id in scan_tasks:
                continue

            task = asyncio.create_task(periodic_scan(target, scan_type, interval))
            scan_tasks[task_id] = task
            log_event(f"Загружена начальная задача: {target} ({scan_type}) каждые {interval} минут")
    except json.JSONDecodeError as e:
        log_event(f"Ошибка парсинга INITIAL_TASKS (JSON): {e}")
    except (KeyError, TypeError) as e:
        log_event(f"Ошибка в структуре INITIAL_TASKS: {e}")
    except Exception as e:
        log_event(f"Ошибка загрузки INITIAL_TASKS: {e}")


async def main():
    log_event(f"Сервис запущен (версия {VERSION})")
    await send_telegram_message(f"Nmap Automation Framework v{VERSION} запущен")

    await load_initial_tasks()

    loop = asyncio.get_running_loop()
    stop_event = asyncio.Event()
    registered_signals = []
    for signame in {"SIGINT", "SIGTERM"}:
        try:
            sig = getattr(signal, signame)
            loop.add_signal_handler(sig, stop_event.set)
            registered_signals.append(sig)
        except (NotImplementedError, AttributeError, ValueError):
            pass

    shutdown_trigger = stop_event.wait if registered_signals else None
    server_task = asyncio.create_task(
        app.run_task(
            host=APP_HOST,
            port=APP_PORT,
            shutdown_trigger=shutdown_trigger,
        )
    )
    stop_waiter = asyncio.create_task(stop_event.wait()) if registered_signals else None
    try:
        if stop_waiter is None:
            await server_task
        else:
            done, _ = await asyncio.wait(
                {stop_waiter, server_task},
                return_when=asyncio.FIRST_COMPLETED,
            )
            if server_task in done:
                await server_task
    finally:
        for sig in registered_signals:
            loop.remove_signal_handler(sig)
        if stop_waiter is not None and not stop_waiter.done():
            stop_waiter.cancel()

        if stop_event.is_set():
            log_event("Получен сигнал остановки")
        await send_telegram_message("Nmap Automation Framework останавливается")

        _cleanup_finished_tasks()
        scheduled_tasks = list(scan_tasks.values())
        for task in scheduled_tasks:
            task.cancel()

        shutdown_tasks = [*scheduled_tasks, server_task]
        try:
            await asyncio.wait_for(
                asyncio.gather(*shutdown_tasks, return_exceptions=True),
                timeout=30.0,
            )
        except asyncio.TimeoutError:
            log_event("Принудительная остановка задач по таймауту")
            for task in shutdown_tasks:
                task.cancel()
            await asyncio.gather(*shutdown_tasks, return_exceptions=True)

        log_event("Сервис остановлен")
        await send_telegram_message("Nmap Automation Framework остановлен")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log_event("Получен сигнал KeyboardInterrupt")
    except Exception as e:
        log_event(f"Критическая ошибка: {e}")
