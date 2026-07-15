import asyncio
import hashlib
import ipaddress
import json
import logging
import math
import os
import re
import secrets
import shutil
import signal
import subprocess
import tempfile
import threading
import time
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from cryptography.fernet import Fernet, InvalidToken
from dotenv import load_dotenv
from quart import Quart, g, jsonify, request
from telegram import Bot
from telegram.error import TelegramError

from recon_planner import build_recon_plan, recon_plan_to_jsonl, recon_plan_to_markdown
from scan_engine import (
    PRODUCT_NAME,
    DiscoveryError,
    NmapNotFoundError,
    NmapScanError,
    NmapTimeoutError,
    available_discovery_engines,
    diff_scan_results,
    import_nmap_xml,
    run_nmap_scan,
    supported_scan_types,
    validate_discovery,
    validate_ports_expression,
    validate_scripts_expression,
)
from state_store import StateStore
from tool_inventory import build_tool_inventory, inventory_to_jsonl, inventory_to_markdown
from ui import UI_HTML

load_dotenv()

"""
Recon Operator — multi-tool recon control plane (Nmap engine, Kali inventory, planner).

Immediate scan (async job):
curl -X POST http://127.0.0.1:5000/scan \\
  -H "X-API-KEY: $API_TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{"target":"127.0.0.1","scan_type":"Ping"}'

Poll job:
curl -H "X-API-KEY: $API_TOKEN" http://127.0.0.1:5000/jobs/<job_id>
"""


start_time = datetime.now(timezone.utc)
VERSION = "1.7.0"
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

TELEGRAM_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")
bot = Bot(token=TELEGRAM_TOKEN) if TELEGRAM_TOKEN and CHAT_ID else None

API_AUTH_REQUIRED = _parse_bool_env("API_AUTH_REQUIRED", True)
API_AUTH_HEADER = os.getenv("API_AUTH_HEADER", "X-API-KEY").strip() or "X-API-KEY"


def _load_api_auth_tokens() -> list:
    """Load one or more operator API tokens from the environment.

    Supports:
    - API_AUTH_TOKEN=single-token (legacy)
    - API_AUTH_TOKENS=token-a,token-b
    - API_AUTH_TOKENS='["token-a","token-b"]' (JSON array)
    """
    tokens: list = []
    multi_raw = os.getenv("API_AUTH_TOKENS", "").strip()
    if multi_raw:
        if multi_raw.startswith("["):
            try:
                parsed = json.loads(multi_raw)
            except json.JSONDecodeError as exc:
                raise RuntimeError(
                    "API_AUTH_TOKENS must be a JSON array or comma-separated list"
                ) from exc
            if not isinstance(parsed, list):
                raise RuntimeError("API_AUTH_TOKENS JSON value must be an array of strings")
            tokens.extend(str(item).strip() for item in parsed if str(item).strip())
        else:
            tokens.extend(part.strip() for part in multi_raw.split(",") if part.strip())

    single = os.getenv("API_AUTH_TOKEN", "").strip()
    if single:
        tokens.append(single)

    # Preserve order, drop duplicates.
    unique: list = []
    seen = set()
    for token in tokens:
        if token in seen:
            continue
        seen.add(token)
        unique.append(token)
    return unique


API_AUTH_TOKENS = _load_api_auth_tokens()
# Backward-compatible alias used by docs and older code paths.
API_AUTH_TOKEN = API_AUTH_TOKENS[0] if API_AUTH_TOKENS else ""
if API_AUTH_REQUIRED and not API_AUTH_TOKENS:
    raise RuntimeError(
        "API_AUTH_REQUIRED=true, but no API tokens are configured. "
        "Set API_AUTH_TOKEN and/or API_AUTH_TOKENS."
    )

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
MAX_SCAN_JOBS = _parse_int_env("MAX_SCAN_JOBS", default=200, min_value=10, max_value=10_000)
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
RESULTS_MAX_FILES = _parse_int_env("RESULTS_MAX_FILES", default=500, min_value=1, max_value=100_000)
RESULTS_MAX_AGE_DAYS = _parse_int_env(
    "RESULTS_MAX_AGE_DAYS", default=0, min_value=0, max_value=3650
)
MAX_IMPORT_XML_BYTES = _parse_int_env(
    "MAX_IMPORT_XML_BYTES", default=64 * 1024 * 1024, min_value=1024, max_value=64 * 1024 * 1024
)
STATE_DB_PATH = (
    os.getenv("STATE_DB_PATH", "data/recon_operator.db").strip() or "data/recon_operator.db"
)
if MIN_SCHEDULE_INTERVAL_MINUTES > MAX_SCHEDULE_INTERVAL_MINUTES:
    raise RuntimeError(
        "MIN_SCHEDULE_INTERVAL_MINUTES must not exceed MAX_SCHEDULE_INTERVAL_MINUTES"
    )

HOST_TIMEOUT_SEC = _parse_int_env("NMAP_HOST_TIMEOUT_SEC", default=300, min_value=1, max_value=3600)
NMAP_MAX_RETRIES = _parse_int_env("NMAP_MAX_RETRIES", default=2, min_value=0, max_value=10)

FERNET_KEY = os.getenv("FERNET_KEY", "").strip()
if not FERNET_KEY:
    raise RuntimeError(
        "FERNET_KEY is not set. Provide it in .env or the environment. "
        "Without it stored results cannot be decrypted."
    )
try:
    cipher = Fernet(FERNET_KEY.encode())
except Exception as exc:
    raise RuntimeError(
        "Invalid FERNET_KEY. Check the format (must be a valid Fernet key)."
    ) from exc


app = Quart(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_REQUEST_BODY_BYTES
scan_tasks: Dict[str, asyncio.Task] = {}
scan_jobs: Dict[str, Dict[str, Any]] = {}
rate_limits = defaultdict(list)
tool_inventory_cache = {}
tool_inventory_locks = defaultdict(threading.Lock)
_scan_semaphore: Optional[asyncio.Semaphore] = None
_jobs_lock = asyncio.Lock()
state_store = StateStore(STATE_DB_PATH)

SUPPORTED_SCAN_TYPES = {name: name for name in supported_scan_types()}
RESULT_FILENAME_RE = re.compile(
    r"^(?:o[a-f0-9]{12}_)?[A-Za-z0-9._-]{1,200}_\w+_\d{8}_\d{6}_\d+\.json$"
)
OWNER_RESULT_PREFIX_RE = re.compile(r"^o([a-f0-9]{12})_")


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _utc_now_iso() -> str:
    return _utc_now().isoformat()


def _normalize_scan_type(scan_type: str) -> Optional[str]:
    normalized = scan_type.strip()
    if not normalized:
        return None

    for key in SUPPORTED_SCAN_TYPES:
        if key.lower() == normalized.lower():
            return key

    return None


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
) -> Tuple[
    Optional[str],
    Optional[str],
    Optional[float],
    Optional[str],
    Optional[str],
    Optional[str],
    Optional[str],
]:
    """Return target, scan_type, interval, ports, scripts, discovery, error."""
    if not isinstance(payload, dict):
        return None, None, None, None, None, None, "Missing or invalid request body"

    target = payload.get("target")
    if isinstance(target, str):
        target = target.strip()

    if not target:
        return None, None, None, None, None, None, "target is required"

    scan_type = payload.get("scan_type", "TCP")
    if not isinstance(scan_type, str):
        return None, None, None, None, None, None, "scan_type must be a string"

    normalized_scan_type = _normalize_scan_type(scan_type)
    if normalized_scan_type is None:
        return (
            None,
            None,
            None,
            None,
            None,
            None,
            f"Invalid scan_type. Allowed: {get_scan_type_choices()}",
        )
    scan_type = normalized_scan_type

    ports, ports_error = validate_ports_expression(payload.get("ports"))
    if ports_error:
        return target, scan_type, None, None, None, None, ports_error
    scripts, scripts_error = validate_scripts_expression(payload.get("scripts"))
    if scripts_error:
        return target, scan_type, None, None, None, None, scripts_error
    discovery, discovery_error = validate_discovery(payload.get("discovery"))
    if discovery_error:
        return target, scan_type, None, None, None, None, discovery_error

    interval = payload.get("interval", 30)
    interval_value = None
    if interval is not None:
        if isinstance(interval, bool) or not isinstance(interval, (int, float)):
            return target, scan_type, None, ports, scripts, discovery, "interval must be a number"
        try:
            interval_value = float(interval)
        except (OverflowError, ValueError):
            return (
                target,
                scan_type,
                None,
                ports,
                scripts,
                discovery,
                "interval must be a finite number",
            )
        if not math.isfinite(interval_value):
            return (
                target,
                scan_type,
                None,
                ports,
                scripts,
                discovery,
                "interval must be a finite number",
            )
        if interval_value <= 0:
            return (
                target,
                scan_type,
                None,
                ports,
                scripts,
                discovery,
                "interval must be a positive number",
            )
        if interval_value < MIN_SCHEDULE_INTERVAL_MINUTES:
            return (
                target,
                scan_type,
                None,
                ports,
                scripts,
                discovery,
                f"interval must be at least {MIN_SCHEDULE_INTERVAL_MINUTES} minutes",
            )
        if interval_value > MAX_SCHEDULE_INTERVAL_MINUTES:
            return (
                target,
                scan_type,
                None,
                ports,
                scripts,
                discovery,
                f"interval must be at most {MAX_SCHEDULE_INTERVAL_MINUTES} minutes",
            )

    if not validate_ip_or_host(target):
        return (
            target,
            scan_type,
            interval_value,
            ports,
            scripts,
            discovery,
            "Invalid IP, CIDR, or hostname",
        )

    return (
        _canonicalize_valid_target(target),
        scan_type,
        interval_value,
        ports,
        scripts,
        discovery,
        None,
    )


def _token_is_authorized(candidate: str) -> bool:
    """Multi-token check with compare_digest when lengths match."""
    if not candidate or not API_AUTH_TOKENS:
        return False
    matched = False
    for allowed in API_AUTH_TOKENS:
        # secrets.compare_digest requires equal-length inputs.
        if len(candidate) != len(allowed):
            continue
        matched = secrets.compare_digest(candidate, allowed) or matched
    return matched


def owner_id_from_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def current_owner_id() -> str:
    try:
        return getattr(g, "owner_id", "local")
    except RuntimeError:
        # Outside a request context (startup tasks, unit helpers).
        return "local"


def owner_result_prefix(owner_id: Optional[str] = None) -> str:
    value = owner_id or current_owner_id()
    return f"o{value[:12]}_"


def result_visible_to_owner(filename: str, owner_id: Optional[str] = None) -> bool:
    """Legacy files (no owner prefix) remain visible to any authenticated operator."""
    owner = owner_id or current_owner_id()
    match = OWNER_RESULT_PREFIX_RE.match(filename)
    if not match:
        return True
    return match.group(1) == owner[:12]


def job_visible_to_owner(job: Dict[str, Any], owner_id: Optional[str] = None) -> bool:
    owner = owner_id or current_owner_id()
    job_owner = job.get("owner_id")
    return job_owner is None or job_owner == owner


def make_task_id(target: str, scan_type: str, owner_id: Optional[str] = None) -> str:
    owner = owner_id or current_owner_id()
    return f"o{owner[:12]}-{target}-{scan_type}"


def require_api_auth():
    if not API_AUTH_REQUIRED:
        g.owner_id = "local"
        return None

    token = request.headers.get(API_AUTH_HEADER)
    if not token:
        return jsonify({"error": f"API token missing ({API_AUTH_HEADER})"}), 401
    if not _token_is_authorized(token):
        return jsonify({"error": "Invalid API token"}), 403
    g.owner_id = owner_id_from_token(token)
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
                log_event(f"Task {task_id} removed from registry after cancellation")
            else:
                exception = task.exception()
                if exception is not None:
                    log_event(f"Task {task_id} finished with error: {exception}")
        except Exception as e:
            log_event(f"Error removing task {task_id}: {e}")

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
    with tool_inventory_locks[cache_key]:
        cached = tool_inventory_cache.get(cache_key)
        now = time.time()
        if (
            cached
            and TOOL_INVENTORY_CACHE_SECONDS > 0
            and now - cached["created_at"] < TOOL_INVENTORY_CACHE_SECONDS
        ):
            return cached["inventory"]

        inventory = build_tool_inventory(expand=expand)
        tool_inventory_cache[cache_key] = {
            "created_at": time.time(),
            "inventory": inventory,
        }
        return inventory


async def send_telegram_message(message: str):
    if not bot:
        log_event("Telegram is not configured. Message not sent.")
        return
    try:
        await bot.send_message(chat_id=CHAT_ID, text=message)
    except TelegramError as e:
        log_event(f"Telegram send error: {e}")
    except Exception as e:
        log_event(f"Unexpected Telegram error: {e}")


def validate_ip_or_host(target: str) -> bool:
    """Validate IP, network, or domain syntax."""
    if not isinstance(target, str) or not target:
        return False

    target = target.strip()
    if len(target) > 253:
        return False

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
        auth_domain_re = re.compile(
            r"^(?:(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}|localhost)$",
            re.IGNORECASE,
        )
        return auth_domain_re.fullmatch(target) is not None


def _canonicalize_valid_target(target: str) -> str:
    """Return a stable task/scan target after validation has succeeded."""
    try:
        return str(ipaddress.ip_address(target))
    except ValueError:
        try:
            return str(ipaddress.ip_network(target, strict=False))
        except ValueError:
            return target.lower()


def build_scan_args(scan_type: str) -> str:
    """Legacy helper retained for tests and docs; engine builds argv lists."""
    if scan_type not in SUPPORTED_SCAN_TYPES:
        raise ValueError(f"Invalid scan_type: {scan_type}")
    return f"{scan_type} --host-timeout {HOST_TIMEOUT_SEC}s --max-retries {NMAP_MAX_RETRIES}"


def scan_network(
    target: str,
    scan_type: str,
    ports: Optional[str] = None,
    scripts: Optional[str] = None,
    discovery: Optional[str] = None,
) -> dict:
    """
    Synchronous scan entry point used by the async executor.
    Exceptions propagate to the async layer.
    """
    log_event(
        f"Starting scan {target} type={scan_type} ports={ports} "
        f"scripts={scripts} discovery={discovery}"
    )
    try:
        return run_nmap_scan(
            target,
            scan_type,
            host_timeout_sec=HOST_TIMEOUT_SEC,
            max_retries=NMAP_MAX_RETRIES,
            scan_timeout_sec=SCAN_TIMEOUT_SECONDS,
            ports=ports,
            scripts=scripts,
            discovery=discovery,
        )
    except NmapTimeoutError as exc:
        raise TimeoutError(str(exc)) from exc
    except DiscoveryError as exc:
        raise RuntimeError(str(exc)) from exc


def _result_files() -> List[Path]:
    directory = Path(RESULTS_DIR)
    if not directory.is_dir():
        return []
    return sorted(
        (path for path in directory.iterdir() if path.is_file() and path.suffix == ".json"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )


def apply_results_retention(directory: Optional[str] = None) -> Dict[str, int]:
    """Delete old encrypted results by count and optional age."""
    root = Path(directory or RESULTS_DIR)
    if not root.is_dir():
        return {"deleted": 0, "remaining": 0}

    files = [path for path in root.iterdir() if path.is_file() and path.suffix == ".json"]
    deleted = 0
    now = time.time()

    if RESULTS_MAX_AGE_DAYS > 0:
        max_age_seconds = RESULTS_MAX_AGE_DAYS * 86400
        for path in list(files):
            try:
                if now - path.stat().st_mtime > max_age_seconds:
                    path.unlink()
                    deleted += 1
                    files.remove(path)
            except OSError as exc:
                log_event(f"Retention age cleanup failed for {path}: {exc}")

    files.sort(key=lambda path: path.stat().st_mtime)
    while len(files) > RESULTS_MAX_FILES:
        path = files.pop(0)
        try:
            path.unlink()
            deleted += 1
        except OSError as exc:
            log_event(f"Retention count cleanup failed for {path}: {exc}")

    return {"deleted": deleted, "remaining": len(files)}


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


async def save_scan_results_async(
    results: dict,
    target: str,
    scan_type: str,
    owner_id: Optional[str] = None,
) -> Optional[str]:
    if not results:
        return None

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    safe_target = "".join(c if c.isalnum() or c in [".", "_", "-"] else "_" for c in target)[:120]
    owner = owner_id or "local"
    filename = f"{owner_result_prefix(owner)}{safe_target}_{scan_type}_{timestamp}.json"
    path = os.path.join(RESULTS_DIR, filename)

    try:
        encrypted_data = cipher.encrypt(json.dumps(results, indent=2).encode())
        await asyncio.to_thread(_write_encrypted_result, path, encrypted_data)
        await asyncio.to_thread(apply_results_retention, RESULTS_DIR)
        log_event(f"Results saved to {path}")
        await send_telegram_message(f"Scan {target} finished. Results: {filename}")
        return filename
    except Exception as e:
        err = f"Error saving results: {e}"
        log_event(err)
        await send_telegram_message(f"Error saving results for {target}: {e}")
        raise


def _job_public_view(job: Dict[str, Any], *, include_result: bool = True) -> Dict[str, Any]:
    view = {
        "job_id": job["job_id"],
        "target": job["target"],
        "scan_type": job["scan_type"],
        "ports": job.get("ports"),
        "scripts": job.get("scripts"),
        "discovery": job.get("discovery"),
        "status": job["status"],
        "created_at": job["created_at"],
        "started_at": job.get("started_at"),
        "finished_at": job.get("finished_at"),
        "error": job.get("error"),
        "result_file": job.get("result_file"),
        "kind": job.get("kind", "immediate"),
    }
    if include_result and job.get("status") == "completed":
        view["result"] = job.get("result")
    return view


def _persist_job(job: Dict[str, Any]) -> None:
    try:
        state_store.upsert_job(job)
        state_store.prune_jobs(MAX_SCAN_JOBS)
    except Exception as exc:
        log_event(f"Failed to persist job {job.get('job_id')}: {exc}")


async def _prune_jobs_locked() -> None:
    """Keep completed/failed jobs within MAX_SCAN_JOBS."""
    if len(scan_jobs) <= MAX_SCAN_JOBS:
        return
    terminal = [
        job
        for job in scan_jobs.values()
        if job["status"] in {"completed", "failed", "cancelled", "timeout"}
    ]
    terminal.sort(key=lambda item: item.get("finished_at") or item.get("created_at") or "")
    overflow = len(scan_jobs) - MAX_SCAN_JOBS
    for job in terminal[:overflow]:
        removed = scan_jobs.pop(job["job_id"], None)
        if removed:
            try:
                state_store.delete_job(job["job_id"])
            except Exception as exc:
                log_event(f"Failed to delete persisted job {job['job_id']}: {exc}")


async def _set_job_fields(job_id: str, **fields: Any) -> None:
    async with _jobs_lock:
        job = scan_jobs.get(job_id)
        if not job:
            return
        job.update(fields)
        _persist_job(job)


async def _run_scan_job(job_id: str) -> None:
    async with _jobs_lock:
        job = scan_jobs.get(job_id)
        if not job or job["status"] == "cancelled":
            return
        job["status"] = "running"
        job["started_at"] = _utc_now_iso()
        target = job["target"]
        scan_type = job["scan_type"]
        ports = job.get("ports")
        scripts = job.get("scripts")
        discovery = job.get("discovery")
        owner_id = job.get("owner_id") or "local"
        _persist_job(job)

    loop = asyncio.get_running_loop()
    try:
        async with _get_scan_semaphore():
            results = await asyncio.wait_for(
                loop.run_in_executor(
                    None,
                    lambda: scan_network(
                        target,
                        scan_type,
                        ports=ports,
                        scripts=scripts,
                        discovery=discovery,
                    ),
                ),
                timeout=SCAN_TIMEOUT_SECONDS + 5,
            )
        result_file = await save_scan_results_async(results, target, scan_type, owner_id=owner_id)
        await _set_job_fields(
            job_id,
            status="completed",
            finished_at=_utc_now_iso(),
            result=results,
            result_file=result_file,
            error=None,
        )
    except asyncio.CancelledError:
        await _set_job_fields(
            job_id,
            status="cancelled",
            finished_at=_utc_now_iso(),
            error="Scan cancelled",
        )
        raise
    except asyncio.TimeoutError:
        err = f"Scan timeout for {target} ({scan_type})"
        log_event(err)
        await send_telegram_message(err)
        await _set_job_fields(
            job_id,
            status="timeout",
            finished_at=_utc_now_iso(),
            error=err,
        )
    except TimeoutError as exc:
        err = str(exc)
        log_event(err)
        await send_telegram_message(err)
        await _set_job_fields(
            job_id,
            status="timeout",
            finished_at=_utc_now_iso(),
            error=err,
        )
    except (NmapNotFoundError, NmapScanError, Exception) as exc:
        err = f"Scan error for {target} ({scan_type}): {exc}"
        log_event(err)
        await send_telegram_message(err)
        await _set_job_fields(
            job_id,
            status="failed",
            finished_at=_utc_now_iso(),
            error=str(exc),
        )
    finally:
        async with _jobs_lock:
            job = scan_jobs.get(job_id)
            if job:
                job["task"] = None
            await _prune_jobs_locked()


async def create_scan_job(
    target: str,
    scan_type: str,
    *,
    kind: str = "immediate",
    ports: Optional[str] = None,
    scripts: Optional[str] = None,
    discovery: Optional[str] = None,
    owner_id: Optional[str] = None,
) -> Dict[str, Any]:
    owner = owner_id or current_owner_id()
    async with _jobs_lock:
        await _prune_jobs_locked()
        active = sum(1 for job in scan_jobs.values() if job["status"] in {"queued", "running"})
        if active >= MAX_SCAN_JOBS:
            raise RuntimeError("Scan job capacity reached")

        job_id = str(uuid.uuid4())
        job = {
            "job_id": job_id,
            "target": target,
            "scan_type": scan_type,
            "ports": ports,
            "scripts": scripts,
            "discovery": discovery,
            "owner_id": owner,
            "status": "queued",
            "created_at": _utc_now_iso(),
            "started_at": None,
            "finished_at": None,
            "error": None,
            "result": None,
            "result_file": None,
            "kind": kind,
            "task": None,
        }
        scan_jobs[job_id] = job
        _persist_job(job)
        task = asyncio.create_task(_run_scan_job(job_id))
        job["task"] = task
        return _job_public_view(job, include_result=False)


async def async_scan(
    target: str,
    scan_type: str,
    ports: Optional[str] = None,
    scripts: Optional[str] = None,
    discovery: Optional[str] = None,
    owner_id: Optional[str] = None,
) -> dict:
    """Run a scan and wait for completion (used by scheduled scans)."""
    job = await create_scan_job(
        target,
        scan_type,
        kind="scheduled",
        ports=ports,
        scripts=scripts,
        discovery=discovery,
        owner_id=owner_id,
    )
    job_id = job["job_id"]
    while True:
        async with _jobs_lock:
            current = scan_jobs.get(job_id)
            if not current:
                raise RuntimeError("Scan job disappeared")
            status = current["status"]
            if status in {"completed", "failed", "cancelled", "timeout"}:
                if status == "completed":
                    return current.get("result") or {}
                if status == "timeout":
                    raise TimeoutError(current.get("error") or "Scan timed out")
                if status == "cancelled":
                    raise asyncio.CancelledError()
                raise RuntimeError(current.get("error") or "Scan failed")
            task = current.get("task")
        if task is not None:
            try:
                await asyncio.wait_for(asyncio.shield(task), timeout=0.5)
            except asyncio.TimeoutError:
                pass
            except asyncio.CancelledError:
                raise
            except Exception:
                # Job state is the source of truth; continue loop.
                pass
        else:
            await asyncio.sleep(0.05)


@app.route("/scan", methods=["POST"])
async def start_scan():
    try:
        auth_error = require_api_auth()
        if auth_error:
            return auth_error

        if not check_rate_limit():
            return jsonify({"error": "Rate limit exceeded"}), 429

        data = await request.get_json(silent=True)
        target, scan_type, _, ports, scripts, discovery, error = _validate_scan_payload(data)
        if error:
            return jsonify({"error": error}), 400

        wait = _bool_query_param("wait", False)
        log_event(f"Scan requested: {target}, type={scan_type}, wait={wait}")

        if wait:
            try:
                results = await async_scan(
                    target,
                    scan_type,
                    ports=ports,
                    scripts=scripts,
                    discovery=discovery,
                    owner_id=current_owner_id(),
                )
            except TimeoutError as e:
                return jsonify({"error": str(e)}), 504
            except Exception as e:
                log_event(f"API error in /scan wait mode: {e}")
                return jsonify({"error": "Internal scan error"}), 500
            return jsonify(results or {"message": "Scan completed with no results"}), 200

        job = await create_scan_job(
            target,
            scan_type,
            kind="immediate",
            ports=ports,
            scripts=scripts,
            discovery=discovery,
            owner_id=current_owner_id(),
        )
        return jsonify(job), 202
    except Exception as e:
        err = f"API error in /scan: {e}"
        log_event(err)
        await send_telegram_message(f"API error: {e}")
        return jsonify({"error": "Internal scan error"}), 500


@app.route("/jobs", methods=["GET"])
async def list_jobs():
    auth_error = require_api_auth()
    if auth_error:
        return auth_error

    owner = current_owner_id()
    async with _jobs_lock:
        jobs = [
            _job_public_view(job, include_result=False)
            for job in sorted(
                scan_jobs.values(),
                key=lambda item: item.get("created_at") or "",
                reverse=True,
            )
            if job_visible_to_owner(job, owner)
        ]
    return jsonify(jobs), 200


@app.route("/jobs/<job_id>", methods=["GET"])
async def get_job(job_id: str):
    auth_error = require_api_auth()
    if auth_error:
        return auth_error

    async with _jobs_lock:
        job = scan_jobs.get(job_id)
    if not job:
        job = await asyncio.to_thread(state_store.get_job, job_id)
        if not job:
            return jsonify({"error": "Job not found"}), 404
    if not job_visible_to_owner(job):
        return jsonify({"error": "Job not found"}), 404
    return jsonify(_job_public_view(job, include_result=True)), 200


@app.route("/jobs/<job_id>", methods=["DELETE"])
async def cancel_job(job_id: str):
    auth_error = require_api_auth()
    if auth_error:
        return auth_error

    async with _jobs_lock:
        job = scan_jobs.get(job_id)
        if not job or not job_visible_to_owner(job):
            return jsonify({"error": "Job not found"}), 404
        if job["status"] in {"completed", "failed", "cancelled", "timeout"}:
            return jsonify({"message": f"Job already {job['status']}", "job_id": job_id}), 200
        task = job.get("task")
        job["status"] = "cancelled"
        job["finished_at"] = _utc_now_iso()
        job["error"] = "Scan cancelled"
        if task is not None and not task.done():
            task.cancel()
        _persist_job(job)
    log_event(f"Job {job_id} cancelled")
    return jsonify({"message": f"Job {job_id} cancelled", "job_id": job_id}), 200


async def periodic_scan(
    target: str,
    scan_type: str,
    interval_minutes: float,
    ports: Optional[str] = None,
    scripts: Optional[str] = None,
    discovery: Optional[str] = None,
    owner_id: Optional[str] = None,
):
    """Async recurring scan loop."""
    try:
        interval = float(interval_minutes)
    except (TypeError, ValueError):
        raise ValueError("interval must be a number")

    if interval <= 0:
        raise ValueError("interval must be a positive number")

    owner = owner_id or "local"
    log_event(f"Started periodic scan {target} every {interval} minutes")
    await send_telegram_message(
        f"{PRODUCT_NAME}: started periodic scan {target} every {interval} minutes"
    )

    while True:
        _cleanup_finished_tasks()
        try:
            log_event(f"Running periodic scan: {target}")
            await async_scan(
                target,
                scan_type,
                ports=ports,
                scripts=scripts,
                discovery=discovery,
                owner_id=owner,
            )
        except asyncio.CancelledError:
            log_event(f"Periodic scan {target} cancelled")
            break
        except Exception as e:
            err = f"Periodic scan error for {target}: {e}"
            log_event(err)
            await send_telegram_message(err)

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
            return jsonify({"error": "Rate limit exceeded"}), 429

        data = await request.get_json(silent=True)
        target, scan_type, interval, ports, scripts, discovery, error = _validate_scan_payload(data)
        if error:
            return jsonify({"error": error}), 400

        if interval is None:
            interval = 30.0

        owner = current_owner_id()
        task_id = make_task_id(target, scan_type, owner)
        _cleanup_finished_tasks()
        if task_id in scan_tasks:
            return jsonify({"error": "Scan already scheduled"}), 400
        if len(scan_tasks) >= MAX_SCHEDULED_TASKS:
            return jsonify({"error": "Scheduled task limit reached"}), 429

        task = asyncio.create_task(
            periodic_scan(
                target,
                scan_type,
                interval,
                ports=ports,
                scripts=scripts,
                discovery=discovery,
                owner_id=owner,
            )
        )
        scan_tasks[task_id] = task
        try:
            state_store.upsert_scheduled_task(
                task_id,
                target,
                scan_type,
                interval,
                ports=ports,
                scripts=scripts,
                discovery=discovery,
                owner_id=owner,
                created_at=_utc_now_iso(),
            )
        except Exception as exc:
            log_event(f"Failed to persist scheduled task {task_id}: {exc}")
        log_event(f"Scan {target} scheduled every {interval} minutes")

        return jsonify(
            {
                "message": f"Scan {target} scheduled every {interval} minutes",
                "task_id": task_id,
            }
        ), 200
    except Exception as e:
        err = f"Error in /schedule: {e}"
        log_event(err)
        return jsonify({"error": "Internal scheduler error"}), 500


@app.route("/tasks", methods=["GET"])
async def list_tasks():
    auth_error = require_api_auth()
    if auth_error:
        return auth_error

    owner = current_owner_id()
    owner_prefix = f"o{owner[:12]}-"
    _cleanup_finished_tasks()
    tasks_info = []
    for task_id, task in scan_tasks.items():
        # Legacy tasks without owner prefix remain visible for compatibility.
        if task_id.startswith("o") and not task_id.startswith(owner_prefix):
            continue
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

    owner = current_owner_id()
    owner_prefix = f"o{owner[:12]}-"
    if task_id.startswith("o") and not task_id.startswith(owner_prefix):
        return jsonify({"error": "Task not found"}), 404

    _cleanup_finished_tasks()
    if task_id in scan_tasks:
        scan_tasks[task_id].cancel()
        del scan_tasks[task_id]
        try:
            state_store.delete_scheduled_task(task_id)
        except Exception as exc:
            log_event(f"Failed to delete persisted task {task_id}: {exc}")
        log_event(f"Task {task_id} cancelled")
        await send_telegram_message(f"Task {task_id} cancelled")
        return jsonify({"message": f"Task {task_id} cancelled"}), 200
    return jsonify({"error": "Task not found"}), 404


def _safe_result_path(result_id: str) -> Optional[Path]:
    name = os.path.basename(result_id.strip())
    if name != result_id.strip() or ".." in name:
        return None
    if not RESULT_FILENAME_RE.fullmatch(name) and not re.fullmatch(
        r"^[A-Za-z0-9._-]{1,220}\.json$", name
    ):
        return None
    path = Path(RESULTS_DIR).resolve() / name
    try:
        path.resolve().relative_to(Path(RESULTS_DIR).resolve())
    except ValueError:
        return None
    return path if path.is_file() else None


@app.route("/results", methods=["GET"])
async def list_results():
    auth_error = require_api_auth()
    if auth_error:
        return auth_error

    limit = _parse_optional_limit(request.args.get("limit"), default=50, max_value=500)
    owner = current_owner_id()
    files = await asyncio.to_thread(_result_files)
    items = []
    for path in files:
        if not result_visible_to_owner(path.name, owner):
            continue
        try:
            stat = path.stat()
            items.append(
                {
                    "id": path.name,
                    "filename": path.name,
                    "size_bytes": stat.st_size,
                    "modified_at": datetime.fromtimestamp(
                        stat.st_mtime, tz=timezone.utc
                    ).isoformat(),
                }
            )
        except OSError:
            continue
        if len(items) >= limit:
            break
    return jsonify({"count": len(items), "results": items}), 200


def _parse_optional_limit(raw: Optional[str], default: int, max_value: int) -> int:
    if raw is None or raw == "":
        return default
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return default
    if value < 1:
        return default
    return min(value, max_value)


@app.route("/results/<path:result_id>", methods=["GET"])
async def get_result(result_id: str):
    auth_error = require_api_auth()
    if auth_error:
        return auth_error

    path = _safe_result_path(result_id)
    if path is None or not result_visible_to_owner(path.name):
        return jsonify({"error": "Result not found"}), 404

    try:
        encrypted = await asyncio.to_thread(path.read_bytes)
        plaintext = cipher.decrypt(encrypted)
        payload = json.loads(plaintext.decode("utf-8"))
    except InvalidToken:
        return jsonify({"error": "Unable to decrypt result with configured FERNET_KEY"}), 500
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        log_event(f"Result read error for {result_id}: {exc}")
        return jsonify({"error": "Result file is unreadable"}), 500

    return jsonify({"id": path.name, "filename": path.name, "result": payload}), 200


async def _load_result_reference(ref: Any) -> Tuple[Optional[dict], Optional[str]]:
    """Resolve a result object or {id: filename} reference."""
    if isinstance(ref, dict) and isinstance(ref.get("hosts"), list):
        return ref, None
    if isinstance(ref, dict) and ref.get("result") and isinstance(ref["result"], dict):
        return ref["result"], None
    result_id = None
    if isinstance(ref, str):
        result_id = ref
    elif isinstance(ref, dict):
        result_id = ref.get("id") or ref.get("filename") or ref.get("result_id")
    if not result_id or not isinstance(result_id, str):
        return None, "Expected a scan result object or result id"
    path = _safe_result_path(result_id)
    if path is None or not result_visible_to_owner(path.name):
        return None, f"Result not found: {result_id}"
    try:
        encrypted = await asyncio.to_thread(path.read_bytes)
        plaintext = cipher.decrypt(encrypted)
        return json.loads(plaintext.decode("utf-8")), None
    except InvalidToken:
        return None, "Unable to decrypt result with configured FERNET_KEY"
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        log_event(f"Result load error for {result_id}: {exc}")
        return None, "Result file is unreadable"


@app.route("/results/import", methods=["POST"])
async def import_result_xml():
    auth_error = require_api_auth()
    if auth_error:
        return auth_error
    if not check_rate_limit():
        return jsonify({"error": "Rate limit exceeded"}), 429

    content_type = (request.content_type or "").lower()
    target_label = ""
    scan_type = "Import"
    xml_bytes: Optional[bytes] = None

    if "application/json" in content_type:
        data = await request.get_json(silent=True)
        if not isinstance(data, dict) or not isinstance(data.get("xml"), str):
            return jsonify({"error": "Expected JSON body with xml string"}), 400
        xml_bytes = data["xml"].encode("utf-8")
        if isinstance(data.get("target"), str):
            target_label = data["target"].strip()
        if isinstance(data.get("scan_type"), str) and data["scan_type"].strip():
            scan_type = data["scan_type"].strip()[:40]
    else:
        xml_bytes = await request.get_data(cache=False)
        target_label = (request.args.get("target") or "").strip()

    if not xml_bytes:
        return jsonify({"error": "Empty XML payload"}), 400
    if len(xml_bytes) > MAX_IMPORT_XML_BYTES:
        return jsonify(
            {"error": f"XML exceeds {MAX_IMPORT_XML_BYTES // (1024 * 1024)} MiB limit"}
        ), 413

    try:
        result = await asyncio.to_thread(
            import_nmap_xml,
            xml_bytes,
            target=target_label or "xml-import",
            scan_type=scan_type,
        )
    except Exception as exc:
        log_event(f"XML import failed: {exc}")
        return jsonify({"error": f"XML import failed: {exc}"}), 400

    filename = await save_scan_results_async(
        result,
        result.get("target") or "xml-import",
        scan_type,
        owner_id=current_owner_id(),
    )
    return jsonify({"id": filename, "filename": filename, "result": result}), 201


@app.route("/results/diff", methods=["POST"])
async def diff_results():
    auth_error = require_api_auth()
    if auth_error:
        return auth_error
    if not check_rate_limit():
        return jsonify({"error": "Rate limit exceeded"}), 429

    data = await request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Expected JSON with baseline and current"}), 400

    baseline, baseline_error = await _load_result_reference(
        data.get("baseline") or data.get("old") or data.get("a")
    )
    if baseline_error:
        return jsonify({"error": f"baseline: {baseline_error}"}), 400
    current, current_error = await _load_result_reference(
        data.get("current") or data.get("new") or data.get("b")
    )
    if current_error:
        return jsonify({"error": f"current: {current_error}"}), 400

    diff = await asyncio.to_thread(diff_scan_results, baseline, current)
    return jsonify(diff), 200


@app.route("/tools", methods=["GET"])
async def tools_inventory():
    auth_error = require_api_auth()
    if auth_error:
        return auth_error
    if not check_rate_limit():
        return jsonify({"error": "Rate limit exceeded"}), 429

    expand = _bool_query_param("expand", False)
    inventory = await asyncio.to_thread(get_cached_tool_inventory, expand=expand)
    return jsonify(inventory), 200


@app.route("/tools/ai-context", methods=["GET"])
async def tools_ai_context():
    auth_error = require_api_auth()
    if auth_error:
        return auth_error
    if not check_rate_limit():
        return jsonify({"error": "Rate limit exceeded"}), 429

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
        return jsonify({"error": "Rate limit exceeded"}), 429

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


def _render_dashboard_html() -> tuple:
    nonce = secrets.token_urlsafe(18)
    html = UI_HTML.replace("__CSP_NONCE__", nonce)
    csp = (
        f"default-src 'self'; style-src 'nonce-{nonce}'; script-src 'nonce-{nonce}'; "
        f"connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'self'; "
        f"form-action 'self'"
    )
    return (
        html,
        200,
        {
            "Content-Type": "text/html; charset=utf-8",
            "Content-Security-Policy": csp,
        },
    )


@app.route("/", methods=["GET"])
@app.route("/ui", methods=["GET"])
async def dashboard():
    return _render_dashboard_html()


@app.after_request
async def add_security_headers(response):
    response.headers.setdefault("Cache-Control", "no-store")
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    # HTML dashboard sets a nonce-based CSP; API responses get a tight default.
    if "Content-Security-Policy" not in response.headers:
        content_type = (response.content_type or "").lower()
        if "text/html" in content_type:
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; frame-ancestors 'none'; base-uri 'self'"
            )
        else:
            response.headers["Content-Security-Policy"] = (
                "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
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


def _health_payload(*, nmap_available: bool) -> dict:
    return {
        "status": "healthy" if nmap_available else "unhealthy",
        "product": PRODUCT_NAME,
        "version": VERSION,
        "ready": nmap_available,
        "live": True,
        "tasks_count": len(scan_tasks),
        "telegram_configured": bot is not None,
        "uptime": str(_utc_now() - start_time),
        "fernet_key_configured": bool(FERNET_KEY),
        "nmap_available": nmap_available,
        "max_requests_per_window": MAX_REQUESTS_PER_WINDOW,
        "rate_limit_window_seconds": RATE_LIMIT_WINDOW_SECONDS,
        "max_concurrent_scans": MAX_CONCURRENT_SCANS,
        "max_scheduled_tasks": MAX_SCHEDULED_TASKS,
        "max_scan_jobs": MAX_SCAN_JOBS,
        "max_target_addresses": MAX_TARGET_ADDRESSES,
        "results_max_files": RESULTS_MAX_FILES,
        "results_max_age_days": RESULTS_MAX_AGE_DAYS,
        "state_db": STATE_DB_PATH,
        "discovery_engines": {
            name: bool(path) for name, path in available_discovery_engines().items()
        },
    }


@app.route("/live", methods=["GET"])
async def liveness():
    """Process liveness: event loop is responsive."""
    return jsonify(
        {
            "status": "live",
            "product": PRODUCT_NAME,
            "version": VERSION,
            "uptime": str(_utc_now() - start_time),
        }
    ), 200


@app.route("/ready", methods=["GET"])
async def readiness():
    """Readiness: dependencies required to accept scan work."""
    nmap_available = _check_nmap_available()
    payload = {
        "status": "ready" if nmap_available else "not_ready",
        "product": PRODUCT_NAME,
        "version": VERSION,
        "nmap_available": nmap_available,
        "fernet_key_configured": bool(FERNET_KEY),
        "state_db": STATE_DB_PATH,
    }
    return jsonify(payload), 200 if nmap_available else 503


@app.route("/health", methods=["GET"])
async def health_check():
    """Detailed health snapshot (readiness semantics for HTTP status)."""
    _cleanup_finished_tasks()
    nmap_available = _check_nmap_available()
    async with _jobs_lock:
        jobs_count = len(scan_jobs)
        active_jobs = sum(1 for job in scan_jobs.values() if job["status"] in {"queued", "running"})

    payload = _health_payload(nmap_available=nmap_available)
    payload["jobs_count"] = jobs_count
    payload["active_jobs"] = active_jobs
    return jsonify(payload), 200 if nmap_available else 503


def build_openapi_spec() -> dict:
    scan_types = list(SUPPORTED_SCAN_TYPES.keys())
    error_schema = {
        "type": "object",
        "properties": {"error": {"type": "string"}},
        "required": ["error"],
    }
    scan_request = {
        "type": "object",
        "required": ["target"],
        "properties": {
            "target": {"type": "string", "example": "127.0.0.1"},
            "scan_type": {"type": "string", "enum": scan_types, "example": "TCP"},
            "interval": {"type": "number", "example": 30},
            "ports": {"type": "string", "example": "22,80,443"},
            "scripts": {"type": "string", "example": "banner"},
            "discovery": {
                "type": "string",
                "enum": ["auto", "naabu", "rustscan", "none"],
            },
        },
    }
    security = [{"ApiKeyAuth": []}] if API_AUTH_REQUIRED else []
    return {
        "openapi": "3.0.3",
        "info": {
            "title": f"{PRODUCT_NAME} API",
            "version": VERSION,
            "description": (
                "Multi-tool recon control plane: Nmap engine, hybrid discovery, "
                "Kali inventory, review-only recon plans, encrypted results."
            ),
        },
        "servers": [{"url": f"http://{APP_HOST}:{APP_PORT}", "description": "Configured bind"}],
        "components": {
            "securitySchemes": {
                "ApiKeyAuth": {
                    "type": "apiKey",
                    "in": "header",
                    "name": API_AUTH_HEADER,
                }
            },
            "schemas": {
                "Error": error_schema,
                "ScanRequest": scan_request,
                "Job": {
                    "type": "object",
                    "properties": {
                        "job_id": {"type": "string"},
                        "status": {
                            "type": "string",
                            "enum": [
                                "queued",
                                "running",
                                "completed",
                                "failed",
                                "cancelled",
                                "timeout",
                            ],
                        },
                        "target": {"type": "string"},
                        "scan_type": {"type": "string"},
                        "result": {"type": "object"},
                        "result_file": {"type": "string", "nullable": True},
                        "error": {"type": "string", "nullable": True},
                    },
                },
            },
        },
        "security": security,
        "paths": {
            "/live": {
                "get": {
                    "summary": "Liveness probe",
                    "security": [],
                    "responses": {"200": {"description": "Process is live"}},
                }
            },
            "/ready": {
                "get": {
                    "summary": "Readiness probe",
                    "security": [],
                    "responses": {
                        "200": {"description": "Ready to accept scans"},
                        "503": {"description": "Not ready (for example Nmap missing)"},
                    },
                }
            },
            "/health": {
                "get": {
                    "summary": "Detailed health",
                    "security": [],
                    "responses": {
                        "200": {"description": "Healthy / ready"},
                        "503": {"description": "Unhealthy / not ready"},
                    },
                }
            },
            "/api/docs": {
                "get": {
                    "summary": "Human-readable runtime API docs",
                    "security": [],
                    "responses": {"200": {"description": "JSON docs"}},
                }
            },
            "/openapi.json": {
                "get": {
                    "summary": "OpenAPI 3 document",
                    "security": [],
                    "responses": {"200": {"description": "OpenAPI schema"}},
                }
            },
            "/scan": {
                "post": {
                    "summary": "Queue or run a scan",
                    "parameters": [
                        {
                            "name": "wait",
                            "in": "query",
                            "schema": {"type": "boolean"},
                            "description": "Block until the scan finishes",
                        }
                    ],
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/ScanRequest"}
                            }
                        },
                    },
                    "responses": {
                        "200": {"description": "Completed result when wait=1"},
                        "202": {
                            "description": "Job accepted",
                            "content": {
                                "application/json": {"schema": {"$ref": "#/components/schemas/Job"}}
                            },
                        },
                        "400": {
                            "description": "Validation error",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/Error"}
                                }
                            },
                        },
                        "401": {"description": "Missing API token"},
                        "403": {"description": "Invalid API token"},
                        "429": {"description": "Rate limited"},
                        "504": {"description": "Scan timeout"},
                    },
                }
            },
            "/jobs": {
                "get": {
                    "summary": "List scan jobs",
                    "responses": {"200": {"description": "Job list"}},
                }
            },
            "/jobs/{job_id}": {
                "get": {
                    "summary": "Get job status/result",
                    "parameters": [
                        {
                            "name": "job_id",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "string"},
                        }
                    ],
                    "responses": {
                        "200": {"description": "Job"},
                        "404": {"description": "Not found"},
                    },
                },
                "delete": {
                    "summary": "Cancel a job",
                    "parameters": [
                        {
                            "name": "job_id",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "string"},
                        }
                    ],
                    "responses": {
                        "200": {"description": "Cancelled"},
                        "404": {"description": "Not found"},
                    },
                },
            },
            "/schedule": {
                "post": {
                    "summary": "Schedule a recurring scan",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/ScanRequest"}
                            }
                        },
                    },
                    "responses": {
                        "200": {"description": "Scheduled"},
                        "400": {"description": "Validation error"},
                        "429": {"description": "Limit reached"},
                    },
                }
            },
            "/tasks": {
                "get": {
                    "summary": "List scheduled tasks",
                    "responses": {"200": {"description": "Tasks"}},
                }
            },
            "/tasks/{task_id}": {
                "delete": {
                    "summary": "Cancel scheduled task",
                    "parameters": [
                        {
                            "name": "task_id",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "string"},
                        }
                    ],
                    "responses": {
                        "200": {"description": "Cancelled"},
                        "404": {"description": "Not found"},
                    },
                }
            },
            "/results": {
                "get": {
                    "summary": "List encrypted results",
                    "responses": {"200": {"description": "Result index"}},
                }
            },
            "/results/{result_id}": {
                "get": {
                    "summary": "Decrypt and return a stored result",
                    "parameters": [
                        {
                            "name": "result_id",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "string"},
                        }
                    ],
                    "responses": {
                        "200": {"description": "Decrypted result"},
                        "404": {"description": "Not found"},
                    },
                }
            },
            "/results/import": {
                "post": {
                    "summary": "Import Nmap XML",
                    "responses": {
                        "201": {"description": "Imported"},
                        "400": {"description": "Parse error"},
                        "413": {"description": "Payload too large"},
                    },
                }
            },
            "/results/diff": {
                "post": {
                    "summary": "Diff two scan results",
                    "responses": {"200": {"description": "Diff summary"}},
                }
            },
            "/tools": {
                "get": {
                    "summary": "Kali/pentest tool inventory",
                    "responses": {"200": {"description": "Inventory JSON"}},
                }
            },
            "/tools/ai-context": {
                "get": {
                    "summary": "AI-readable inventory context",
                    "parameters": [
                        {
                            "name": "format",
                            "in": "query",
                            "schema": {"type": "string", "enum": ["jsonl", "markdown", "md"]},
                        }
                    ],
                    "responses": {"200": {"description": "JSONL or Markdown"}},
                }
            },
            "/recon/plan": {
                "post": {
                    "summary": "Build review-only multi-tool recon plan",
                    "responses": {"200": {"description": "Plan JSON/Markdown/JSONL"}},
                }
            },
            "/": {
                "get": {
                    "summary": "Operator dashboard",
                    "security": [],
                    "responses": {"200": {"description": "HTML dashboard"}},
                }
            },
            "/ui": {
                "get": {
                    "summary": "Operator dashboard (alias)",
                    "security": [],
                    "responses": {"200": {"description": "HTML dashboard"}},
                }
            },
        },
    }


@app.route("/openapi.json", methods=["GET"])
async def openapi_json():
    return jsonify(build_openapi_spec()), 200


@app.route("/api/docs", methods=["GET"])
async def api_docs():
    return jsonify(
        {
            "name": f"{PRODUCT_NAME} API",
            "product": PRODUCT_NAME,
            "version": VERSION,
            "openapi": "/openapi.json",
            "probes": {"live": "/live", "ready": "/ready", "health": "/health"},
            "security": {
                "api_auth_required": API_AUTH_REQUIRED,
                "api_auth_header": API_AUTH_HEADER,
                "api_token_count": len(API_AUTH_TOKENS),
                "rate_limit": f"{MAX_REQUESTS_PER_WINDOW} requests per {RATE_LIMIT_WINDOW_SECONDS} seconds",
                "max_concurrent_scans": MAX_CONCURRENT_SCANS,
            },
            "scan_types": list(SUPPORTED_SCAN_TYPES.keys()),
            "endpoints": {
                "POST /scan": {
                    "description": "Queue an immediate scan (202 job) or wait with ?wait=1",
                    "request": {
                        "target": "IP address, CIDR, or hostname",
                        "scan_type": "TCP|SYN|UDP|OS|Aggressive|Ping|Version|Safe|Vuln|Full|Hybrid|HybridNaabu|HybridRustScan",
                        "ports": "Optional Nmap port expression",
                        "scripts": "Optional extra NSE script names",
                        "discovery": "Optional auto|naabu|rustscan|none",
                    },
                    "query": {"wait": "If true, block until the scan finishes"},
                    "example": {
                        "target": "192.168.1.1",
                        "scan_type": "Version",
                        "ports": "22,80,443",
                    },
                },
                "GET /jobs": {"description": "List recent scan jobs"},
                "GET /jobs/<job_id>": {"description": "Get scan job status and result"},
                "DELETE /jobs/<job_id>": {"description": "Cancel a queued or running job"},
                "POST /schedule": {
                    "description": "Schedule a recurring scan",
                    "request": {
                        "target": "IP address, range, or hostname",
                        "scan_type": "Scan type",
                        "interval": "Interval in minutes",
                        "ports": "Optional ports",
                        "scripts": "Optional NSE scripts",
                    },
                    "example": {
                        "target": "192.168.1.0/24",
                        "scan_type": "SYN",
                        "interval": 30,
                    },
                },
                "GET /tasks": {"description": "List scheduled tasks"},
                "DELETE /tasks/<task_id>": {"description": "Cancel a scheduled task"},
                "GET /results": {"description": "List encrypted result files"},
                "GET /results/<id>": {"description": "Decrypt and return a stored result"},
                "POST /results/import": {
                    "description": "Import Nmap XML, encrypt, and return parsed result",
                    "request": {"xml": "Nmap XML string", "target": "optional label"},
                },
                "POST /results/diff": {
                    "description": "Diff two scan results (objects or stored result ids)",
                    "request": {"baseline": "result or {id}", "current": "result or {id}"},
                },
                "GET /live": {"description": "Liveness probe (always 200 when process is up)"},
                "GET /ready": {"description": "Readiness probe (503 when Nmap missing)"},
                "GET /health": {"description": "Detailed health snapshot"},
                "GET /openapi.json": {"description": "OpenAPI 3 schema"},
                "GET /tools": {
                    "description": "Inventory of Kali/pentest tools across recon categories"
                },
                "GET /tools/ai-context": {
                    "description": "JSONL/Markdown tool context for GPT/Claude"
                },
                "POST /recon/plan": {
                    "description": "Review-only multi-tool recon plan from parsed scan results",
                    "request": {"scan": "Parsed scan response or object with hosts[]"},
                    "formats": "json|jsonl|markdown",
                },
            },
        }
    ), 200


async def load_initial_tasks():
    """Load startup scheduled tasks from the environment."""
    initial_tasks_raw = os.getenv("INITIAL_TASKS", "[]")
    if not initial_tasks_raw.strip():
        return

    try:
        initial_tasks = json.loads(initial_tasks_raw)
        if not isinstance(initial_tasks, list):
            log_event("INITIAL_TASKS must be an array")
            return

        for task_config in initial_tasks:
            if len(scan_tasks) >= MAX_SCHEDULED_TASKS:
                log_event(
                    f"INITIAL_TASKS: reached limit {MAX_SCHEDULED_TASKS}; remaining tasks skipped"
                )
                break
            if not isinstance(task_config, dict):
                log_event("INITIAL_TASKS contains an invalid element")
                continue

            target, scan_type, interval, ports, scripts, discovery, error = _validate_scan_payload(
                task_config
            )
            if error:
                log_event(f"INITIAL_TASKS: skipped task ({error}). Payload: {task_config}")
                continue

            if interval is None:
                interval = 30.0

            owner = "local"
            task_id = make_task_id(target, scan_type, owner)
            if task_id in scan_tasks:
                continue

            task = asyncio.create_task(
                periodic_scan(
                    target,
                    scan_type,
                    interval,
                    ports=ports,
                    scripts=scripts,
                    discovery=discovery,
                    owner_id=owner,
                )
            )
            scan_tasks[task_id] = task
            try:
                state_store.upsert_scheduled_task(
                    task_id,
                    target,
                    scan_type,
                    interval,
                    ports=ports,
                    scripts=scripts,
                    discovery=discovery,
                    owner_id=owner,
                    created_at=_utc_now_iso(),
                )
            except Exception as exc:
                log_event(f"Failed to persist INITIAL_TASKS entry {task_id}: {exc}")
            log_event(f"Loaded initial task: {target} ({scan_type}) every {interval} minutes")
    except json.JSONDecodeError as e:
        log_event(f"INITIAL_TASKS JSON parse error: {e}")
    except (KeyError, TypeError) as e:
        log_event(f"INITIAL_TASKS structure error: {e}")
    except Exception as e:
        log_event(f"INITIAL_TASKS load error: {e}")


async def load_persisted_state():
    """Restore job history and scheduled tasks from SQLite after restart."""
    try:
        jobs = await asyncio.to_thread(state_store.list_jobs, MAX_SCAN_JOBS)
    except Exception as exc:
        log_event(f"Failed to load persisted jobs: {exc}")
        jobs = []

    async with _jobs_lock:
        for job in jobs:
            # Do not resume in-flight work across restarts.
            if job.get("status") in {"queued", "running"}:
                job["status"] = "failed"
                job["error"] = "Interrupted by service restart"
                job["finished_at"] = job.get("finished_at") or _utc_now_iso()
                try:
                    state_store.upsert_job(job)
                except Exception as exc:
                    log_event(f"Failed to finalize interrupted job {job.get('job_id')}: {exc}")
            scan_jobs[job["job_id"]] = job
        log_event(f"Loaded {len(scan_jobs)} persisted scan jobs from {STATE_DB_PATH}")

    try:
        tasks = await asyncio.to_thread(state_store.list_scheduled_tasks)
    except Exception as exc:
        log_event(f"Failed to load persisted scheduled tasks: {exc}")
        return

    for row in tasks:
        if len(scan_tasks) >= MAX_SCHEDULED_TASKS:
            log_event("Persisted scheduled tasks: limit reached; remaining skipped")
            break
        task_id = row["task_id"]
        if task_id in scan_tasks:
            continue
        task = asyncio.create_task(
            periodic_scan(
                row["target"],
                row["scan_type"],
                float(row["interval_minutes"]),
                ports=row.get("ports"),
                scripts=row.get("scripts"),
                discovery=row.get("discovery"),
                owner_id=row.get("owner_id") or "local",
            )
        )
        scan_tasks[task_id] = task
        log_event(f"Restored scheduled task {task_id} every {row['interval_minutes']} minutes")


async def main():
    log_event(f"{PRODUCT_NAME} started (version {VERSION})")
    await send_telegram_message(f"{PRODUCT_NAME} v{VERSION} started")

    await load_persisted_state()
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
            log_event("Stop signal received")
        await send_telegram_message(f"{PRODUCT_NAME} is shutting down")

        _cleanup_finished_tasks()
        scheduled_tasks = list(scan_tasks.values())
        for task in scheduled_tasks:
            task.cancel()

        async with _jobs_lock:
            job_tasks = [
                job["task"]
                for job in scan_jobs.values()
                if job.get("task") is not None and not job["task"].done()
            ]
            for task in job_tasks:
                task.cancel()

        shutdown_tasks = [*scheduled_tasks, *job_tasks, server_task]
        try:
            await asyncio.wait_for(
                asyncio.gather(*shutdown_tasks, return_exceptions=True),
                timeout=30.0,
            )
        except asyncio.TimeoutError:
            log_event("Forced task shutdown after timeout")
            for task in shutdown_tasks:
                task.cancel()
            await asyncio.gather(*shutdown_tasks, return_exceptions=True)

        log_event("Service stopped")
        await send_telegram_message(f"{PRODUCT_NAME} stopped")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log_event("KeyboardInterrupt received")
    except Exception as e:
        log_event(f"Critical error: {e}")
