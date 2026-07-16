"""Configuration surface (lazy re-export from server)."""

from __future__ import annotations

from typing import Any

_EXPORTS = frozenset(
    {
        "VERSION",
        "APP_HOST",
        "APP_PORT",
        "STATE_DB_PATH",
        "RESULTS_DIR",
        "RESULTS_MAX_FILES",
        "RESULTS_MAX_AGE_DAYS",
        "LEGACY_RESULTS_SHARED",
        "FERNET_KEY",
        "API_AUTH_REQUIRED",
        "API_AUTH_HEADER",
        "API_AUTH_KEYS",
        "API_AUTH_TOKENS",
        "API_AUTH_TOKEN",
        "API_KEY_SCOPES",
        "WORKER_ID",
        "REDIS_URL",
        "JOB_LEASE_SECONDS",
        "SCHEDULER_LEADER_SECONDS",
        "app",
        "state_store",
        "scan_jobs",
        "scan_tasks",
    }
)


def __getattr__(name: str) -> Any:
    if name in _EXPORTS:
        from recon_operator import server as _server

        return getattr(_server, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
