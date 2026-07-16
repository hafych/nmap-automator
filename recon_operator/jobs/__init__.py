"""Scan job queue, leases, and claim loop (lazy re-export from server)."""

from __future__ import annotations

from importlib import import_module
from typing import Any

_EXPORTS = frozenset(
    {
        "JOB_CLAIM_POLL_SECONDS",
        "JOB_LEASE_SECONDS",
        "WORKER_ID",
        "async_scan",
        "create_scan_job",
        "job_claim_loop",
        "scan_jobs",
        "_adopt_claimed_job",
        "_claim_job_for_worker",
        "_prune_jobs_locked",
        "_renew_job_lease",
        "_run_scan_job",
        "_set_job_fields",
    }
)


def __getattr__(name: str) -> Any:
    if name in _EXPORTS:
        _server = import_module("recon_operator.server")

        return getattr(_server, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
