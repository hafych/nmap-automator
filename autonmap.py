import nmap
import json
import os
import asyncio
import ipaddress
import signal
import socket
from datetime import datetime
from quart import Quart, request, jsonify
from cryptography.fernet import Fernet
import logging
from logging.handlers import RotatingFileHandler
from telegram import Bot
from telegram.error import TelegramError
from dotenv import load_dotenv

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
VERSION = "1.0.0"

# Настройка логирования с ротацией
logging.basicConfig(
    handlers=[
        RotatingFileHandler(
            "/app/logs/scan_log.txt", maxBytes=10 * 1024 * 1024, backupCount=5
        )
    ],
    level=logging.INFO,
    format="[%(asctime)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

# Конфиденциальные данные из переменных среды
TELEGRAM_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")
bot = Bot(token=TELEGRAM_TOKEN) if TELEGRAM_TOKEN and CHAT_ID else None

# Таймауты/настройки Nmap из окружения
HOST_TIMEOUT_SEC = int(os.getenv("NMAP_HOST_TIMEOUT_SEC", "300"))
NMAP_MAX_RETRIES = os.getenv("NMAP_MAX_RETRIES")  # например "2" или ""

# Генерация/загрузка ключа для шифрования
FERNET_KEY = os.getenv("FERNET_KEY")
if not FERNET_KEY:
    raise RuntimeError(
        "FERNET_KEY не задан! Укажите его в .env или переменных окружения. "
        "Без него нельзя расшифровать старые файлы!"
    )
FERNET_KEY = FERNET_KEY.strip()  # Удаляем невидимые символы
cipher = Fernet(FERNET_KEY.encode())

"""
# Генерация/загрузка ключа для шифрования
FERNET_KEY = os.getenv("FERNET_KEY")
if not FERNET_KEY:
    FERNET_KEY = Fernet.generate_key().decode()
    logging.warning(
        "FERNET_KEY не задан. Сгенерирован новый ключ. Сохрани его для повторного использования!"
    )
    print(f"ВНИМАНИЕ: Сгенерирован новый ключ шифрования: {FERNET_KEY}")
    logging.warning(f"Новый ключ: {FERNET_KEY}")
cipher = Fernet(FERNET_KEY.encode())
"""

print("=== DEBUG FERNET KEY ===")
print(f"Raw value: [{FERNET_KEY}]")
print(f"Length: {len(FERNET_KEY)}")
print(f"Last 5 chars: [{FERNET_KEY[-5:]}]")
print(f"repr: {repr(FERNET_KEY)}")
print("=========================")

app = Quart(__name__)
scan_tasks = {}  # Для хранения активных задач

SUPPORTED_SCAN_TYPES = {
    "SYN": "-sS",
    "TCP": "-sT",
    "UDP": "-sU",
    "Aggressive": "-A",
    "OS": "-O",
    "Ping": "-sn",
}


def get_scan_type_choices() -> str:
    return ", ".join(f"'{k}'" for k in SUPPORTED_SCAN_TYPES.keys())


def log_event(event: str):
    logging.info(event)
    print(event)


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
    """Улучшенная валидация IP, подсетей и доменов"""
    if not target:
        return False
    try:
        ipaddress.ip_network(target, strict=False)  # IP / подсеть
        return True
    except ValueError:
        try:
            socket.gethostbyname(target)  # домен
            return True
        except (socket.error, UnicodeError):
            log_event(f"Неверный адрес или домен: {target}")
            return False


def build_scan_args(scan_type: str) -> str:
    if scan_type not in SUPPORTED_SCAN_TYPES:
        raise ValueError(f"Недопустимый scan_type: {scan_type}")

    base = SUPPORTED_SCAN_TYPES[scan_type]
    # Нормируем host-timeout и max-retries для переносимых таймаутов
    extra = [f"--host-timeout {HOST_TIMEOUT_SEC}s"]
    if NMAP_MAX_RETRIES:
        extra.append(f"--max-retries {NMAP_MAX_RETRIES}")
    return f"{base} {' '.join(extra)}"


def scan_network(target: str, scan_type: str):
    """
    СИНХРОННАЯ функция, запускается в ThreadPool.
    Исключения НЕ глотаем — пусть летят в async слой.
    """
    scanner = nmap.PortScanner()
    scan_args = build_scan_args(scan_type)
    log_event(
        f"Запуск сканирования {target} с типом {scan_type} и аргументами: {scan_args}"
    )

    # ВАЖНО: НЕ передаём timeout= в scan(), это не кросс-версионно.
    scanner.scan(target, arguments=scan_args)

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
            # детерминированный порядок
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


async def save_scan_results_async(results: dict, target: str, scan_type: str):
    if not results:
        return
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = "".join(
        c if c.isalnum() or c in [".", "_", "-"] else "_" for c in target
    )[:120]
    filename = f"{safe_target}_{scan_type}_{timestamp}.json"
    os.makedirs("encrypted_results", exist_ok=True)
    path = os.path.join("encrypted_results", filename)
    try:
        encrypted_data = cipher.encrypt(json.dumps(results, indent=2).encode())
        with open(path, "wb") as enc_file:
            enc_file.write(encrypted_data)
        log_event(f"Результаты сохранены в {path}")
        await send_telegram_message(
            f"Сканирование {target} завершено. Результаты: {filename}"
        )
    except Exception as e:
        err = f"Ошибка сохранения результатов: {e}"
        log_event(err)
        await send_telegram_message(f"Ошибка сохранения результатов для {target}: {e}")


async def async_scan(target: str, scan_type: str):
    loop = asyncio.get_running_loop()
    try:
        results = await loop.run_in_executor(None, scan_network, target, scan_type)
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
        data = await request.json
        if not data:
            return jsonify({"error": "Отсутствуют данные"}), 400

        target = data.get("target")
        scan_type = data.get("scan_type", "SYN")

        if not target:
            return jsonify({"error": "Не указан target"}), 400

        if scan_type not in SUPPORTED_SCAN_TYPES:
            return jsonify(
                {
                    "error": f"Недопустимый scan_type. Допустимые: {get_scan_type_choices()}"
                }
            ), 400

        if not validate_ip_or_host(target):
            return jsonify({"error": "Неверный IP или домен"}), 400

        log_event(f"Получен запрос на сканирование: {target}, тип: {scan_type}")
        results = await async_scan(target, scan_type)
        return jsonify(
            results or {"message": "Сканирование завершено без результатов"}
        ), 200
    except Exception as e:
        err = f"API ошибка в /scan: {e}"
        log_event(err)
        await send_telegram_message(f" API ошибка: {e}")
        return jsonify({"error": str(e)}), 500


async def periodic_scan(target: str, scan_type: str, interval_minutes: float):
    """Асинхронное периодическое сканирование"""
    log_event(
        f"Запущено периодическое сканирование {target} каждые {interval_minutes} минут"
    )
    await send_telegram_message(
        f"Запущено периодическое сканирование {target} каждые {interval_minutes} минут"
    )
    while True:
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
            await asyncio.sleep(interval_minutes * 60)
        except asyncio.CancelledError:
            break


@app.route("/schedule", methods=["POST"])
async def add_scheduled_scan():
    try:
        data = await request.json
        if not data:
            return jsonify({"error": "Отсутствуют данные"}), 400

        target = data.get("target")
        scan_type = data.get("scan_type", "SYN")
        interval = data.get("interval", 30)

        if not target:
            return jsonify({"error": "Не указан target"}), 400

        if scan_type not in SUPPORTED_SCAN_TYPES:
            return jsonify(
                {
                    "error": f"Недопустимый scan_type. Допустимые: {get_scan_type_choices()}"
                }
            ), 400

        if not validate_ip_or_host(target):
            return jsonify({"error": "Неверный IP или домен"}), 400

        if not isinstance(interval, (int, float)) or interval <= 0:
            return jsonify({"error": "Интервал должен быть положительным числом"}), 400

        task_id = f"{target}-{scan_type}"
        if task_id in scan_tasks:
            return jsonify({"error": "Сканирование уже запланировано"}), 400

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
        return jsonify({"error": str(e)}), 500


@app.route("/tasks", methods=["GET"])
async def list_tasks():
    tasks_info = []
    for task_id, task in scan_tasks.items():
        tasks_info.append(
            {"id": task_id, "running": not task.done(), "cancelled": task.cancelled()}
        )
    return jsonify(tasks_info), 200


@app.route("/tasks/<task_id>", methods=["DELETE"])
async def cancel_task(task_id):
    if task_id in scan_tasks:
        scan_tasks[task_id].cancel()
        del scan_tasks[task_id]
        log_event(f"Задача {task_id} отменена")
        await send_telegram_message(f" Задача {task_id} отменена")
        return jsonify({"message": f"Задача {task_id} отменена"}), 200
    return jsonify({"error": "Задача не найдена"}), 404


@app.route("/health", methods=["GET"])
async def health_check():
    return jsonify(
        {
            "status": "healthy",
            "version": VERSION,
            "tasks_count": len(scan_tasks),
            "telegram_configured": bot is not None,
            "uptime": str(datetime.now() - start_time),
            "fernet_key_configured": FERNET_KEY is not None,
        }
    ), 200


@app.route("/api/docs", methods=["GET"])
async def api_docs():
    return jsonify(
        {
            "name": "Nmap Automation Framework API",
            "version": VERSION,
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
            },
        }
    ), 200


async def load_initial_tasks():
    """Загрузка начальных задач из переменной окружения"""
    initial_tasks_raw = os.getenv("INITIAL_TASKS", "[]")
    if not initial_tasks_raw.strip():
        return  # Пустая строка

    try:
        initial_tasks = json.loads(initial_tasks_raw)
        if not isinstance(initial_tasks, list):
            log_event("INITIAL_TASKS должен быть массивом")
            return

        for task_config in initial_tasks:
            target = task_config["target"]
            scan_type = task_config.get("scan_type", "SYN")
            interval = task_config.get("interval", 30)

            if scan_type not in SUPPORTED_SCAN_TYPES:
                log_event(f"Пропущена задача (некорректный scan_type): {scan_type}")
                continue

            task_id = f"{target}-{scan_type}"
            if task_id not in scan_tasks:  # Избегаем дубликатов
                task = asyncio.create_task(periodic_scan(target, scan_type, interval))
                scan_tasks[task_id] = task
                log_event(
                    f"Загружена начальная задача: {target} ({scan_type}) каждые {interval} минут"
                )
    except json.JSONDecodeError as e:
        log_event(f"Ошибка парсинга INITIAL_TASKS (JSON): {e}")
    except (KeyError, TypeError) as e:
        log_event(f"Ошибка в структуре INITIAL_TASKS: {e}")
    except Exception as e:
        log_event(f"Ошибка загрузки INITIAL_TASKS: {e}")


async def main():
    log_event(f"Сервис запущен (версия {VERSION})")
    await send_telegram_message(f"Nmap Automation Framework v{VERSION} запущен")

    # Загрузка начальных задач
    await load_initial_tasks()

    # Запуск сервера
    server_task = asyncio.create_task(app.run_task(host="0.0.0.0", port=5000))

    # Обработка остановки (кроссплатформенная)
    loop = asyncio.get_running_loop()
    stop_event = asyncio.Event()
    for signame in {"SIGINT", "SIGTERM"}:
        try:
            sig = getattr(signal, signame)
            loop.add_signal_handler(sig, stop_event.set)
        except (NotImplementedError, AttributeError, ValueError):
            # Windows или другая платформа
            pass

    await stop_event.wait()
    log_event("Получен сигнал остановки")
    await send_telegram_message(" Nmap Automation Framework останавливается")

    # Отмена всех задач
    for task in scan_tasks.values():
        task.cancel()
    server_task.cancel()

    # Ожидание завершения задач с таймаутом
    try:
        await asyncio.wait_for(
            asyncio.gather(*scan_tasks.values(), server_task, return_exceptions=True),
            timeout=30.0,  # 30 секунд на завершение
        )
    except asyncio.TimeoutError:
        log_event("Принудительная остановка задач по таймауту")

    log_event("Сервис остановлен")
    await send_telegram_message(" Nmap Automation Framework остановлен")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log_event("Получен сигнал KeyboardInterrupt")
    except Exception as e:
        log_event(f"Критическая ошибка: {e}")
