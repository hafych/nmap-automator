"""Scheduler leadership and recurring scans (lazy re-export from server)."""

from __future__ import annotations

from typing import Any

_EXPORTS = frozenset(
    {
        "SCHEDULER_LEADER_POLL_SECONDS",
        "SCHEDULER_LEADER_SECONDS",
        "SCHEDULER_LOCK_NAME",
        "is_scheduler_leader",
        "periodic_scan",
        "scheduler_leader_loop",
        "stop_all_local_schedules",
        "sync_scheduled_tasks_from_store",
        "try_become_scheduler_leader",
    }
)


def __getattr__(name: str) -> Any:
    if name in _EXPORTS:
        from recon_operator import server as _server

        return getattr(_server, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
