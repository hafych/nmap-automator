"""SQLite persistence for scheduled tasks and scan job history."""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS scheduled_tasks (
    task_id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    scan_type TEXT NOT NULL,
    interval_minutes REAL NOT NULL,
    ports TEXT,
    scripts TEXT,
    discovery TEXT,
    owner_id TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_jobs (
    job_id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    scan_type TEXT NOT NULL,
    ports TEXT,
    scripts TEXT,
    discovery TEXT,
    status TEXT NOT NULL,
    kind TEXT NOT NULL,
    owner_id TEXT,
    created_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT,
    error TEXT,
    result_file TEXT,
    result_json TEXT
);

CREATE INDEX IF NOT EXISTS idx_scan_jobs_created ON scan_jobs(created_at);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_status ON scan_jobs(status);
"""


class StateStore:
    """Thread-safe SQLite store for durable operator state."""

    def __init__(self, path: str):
        self.path = str(path)
        self._lock = threading.Lock()
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.executescript(SCHEMA)
            self._migrate(conn)
            conn.commit()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=30, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    @staticmethod
    def _table_columns(conn: sqlite3.Connection, table: str) -> List[str]:
        rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
        return [row["name"] for row in rows]

    def _migrate(self, conn: sqlite3.Connection) -> None:
        job_cols = self._table_columns(conn, "scan_jobs")
        if "owner_id" not in job_cols:
            conn.execute("ALTER TABLE scan_jobs ADD COLUMN owner_id TEXT")
        task_cols = self._table_columns(conn, "scheduled_tasks")
        if "owner_id" not in task_cols:
            conn.execute("ALTER TABLE scheduled_tasks ADD COLUMN owner_id TEXT")
        # Owner indexes after column migration so older DBs upgrade cleanly.
        conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_jobs_owner ON scan_jobs(owner_id)")
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_scheduled_tasks_owner ON scheduled_tasks(owner_id)"
        )

    def upsert_scheduled_task(
        self,
        task_id: str,
        target: str,
        scan_type: str,
        interval_minutes: float,
        *,
        ports: Optional[str] = None,
        scripts: Optional[str] = None,
        discovery: Optional[str] = None,
        owner_id: Optional[str] = None,
        created_at: str,
    ) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO scheduled_tasks(
                    task_id, target, scan_type, interval_minutes, ports, scripts,
                    discovery, owner_id, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(task_id) DO UPDATE SET
                    target=excluded.target,
                    scan_type=excluded.scan_type,
                    interval_minutes=excluded.interval_minutes,
                    ports=excluded.ports,
                    scripts=excluded.scripts,
                    discovery=excluded.discovery,
                    owner_id=excluded.owner_id
                """,
                (
                    task_id,
                    target,
                    scan_type,
                    float(interval_minutes),
                    ports,
                    scripts,
                    discovery,
                    owner_id,
                    created_at,
                ),
            )
            conn.commit()

    def delete_scheduled_task(self, task_id: str) -> None:
        with self._lock, self._connect() as conn:
            conn.execute("DELETE FROM scheduled_tasks WHERE task_id = ?", (task_id,))
            conn.commit()

    def list_scheduled_tasks(self, owner_id: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._lock, self._connect() as conn:
            if owner_id:
                rows = conn.execute(
                    """
                    SELECT * FROM scheduled_tasks
                    WHERE owner_id IS NULL OR owner_id = ?
                    ORDER BY created_at ASC
                    """,
                    (owner_id,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM scheduled_tasks ORDER BY created_at ASC"
                ).fetchall()
        return [dict(row) for row in rows]

    def upsert_job(self, job: Dict[str, Any]) -> None:
        result = job.get("result")
        result_json = None
        if result is not None:
            result_json = json.dumps(result, ensure_ascii=False)
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO scan_jobs(
                    job_id, target, scan_type, ports, scripts, discovery, status, kind,
                    owner_id, created_at, started_at, finished_at, error, result_file, result_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(job_id) DO UPDATE SET
                    target=excluded.target,
                    scan_type=excluded.scan_type,
                    ports=excluded.ports,
                    scripts=excluded.scripts,
                    discovery=excluded.discovery,
                    status=excluded.status,
                    kind=excluded.kind,
                    owner_id=excluded.owner_id,
                    started_at=excluded.started_at,
                    finished_at=excluded.finished_at,
                    error=excluded.error,
                    result_file=excluded.result_file,
                    result_json=excluded.result_json
                """,
                (
                    job["job_id"],
                    job.get("target") or "",
                    job.get("scan_type") or "",
                    job.get("ports"),
                    job.get("scripts"),
                    job.get("discovery"),
                    job.get("status") or "queued",
                    job.get("kind") or "immediate",
                    job.get("owner_id"),
                    job.get("created_at") or "",
                    job.get("started_at"),
                    job.get("finished_at"),
                    job.get("error"),
                    job.get("result_file"),
                    result_json,
                ),
            )
            conn.commit()

    def get_job(self, job_id: str) -> Optional[Dict[str, Any]]:
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT * FROM scan_jobs WHERE job_id = ?", (job_id,)).fetchone()
        if row is None:
            return None
        return self._row_to_job(dict(row))

    def list_jobs(self, limit: int = 200, owner_id: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._lock, self._connect() as conn:
            if owner_id:
                rows = conn.execute(
                    """
                    SELECT * FROM scan_jobs
                    WHERE owner_id IS NULL OR owner_id = ?
                    ORDER BY created_at DESC
                    LIMIT ?
                    """,
                    (owner_id, max(1, int(limit))),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM scan_jobs ORDER BY created_at DESC LIMIT ?",
                    (max(1, int(limit)),),
                ).fetchall()
        return [self._row_to_job(dict(row)) for row in rows]

    def prune_jobs(self, max_jobs: int) -> int:
        if max_jobs < 1:
            return 0
        with self._lock, self._connect() as conn:
            count = conn.execute("SELECT COUNT(*) AS c FROM scan_jobs").fetchone()["c"]
            overflow = count - max_jobs
            if overflow <= 0:
                return 0
            conn.execute(
                """
                DELETE FROM scan_jobs WHERE job_id IN (
                    SELECT job_id FROM scan_jobs
                    ORDER BY COALESCE(finished_at, created_at) ASC
                    LIMIT ?
                )
                """,
                (overflow,),
            )
            conn.commit()
            return overflow

    def delete_job(self, job_id: str) -> None:
        with self._lock, self._connect() as conn:
            conn.execute("DELETE FROM scan_jobs WHERE job_id = ?", (job_id,))
            conn.commit()

    @staticmethod
    def _row_to_job(row: Dict[str, Any]) -> Dict[str, Any]:
        result = None
        raw = row.get("result_json")
        if raw:
            try:
                result = json.loads(raw)
            except json.JSONDecodeError:
                result = None
        return {
            "job_id": row["job_id"],
            "target": row["target"],
            "scan_type": row["scan_type"],
            "ports": row.get("ports"),
            "scripts": row.get("scripts"),
            "discovery": row.get("discovery"),
            "status": row["status"],
            "kind": row.get("kind") or "immediate",
            "owner_id": row.get("owner_id"),
            "created_at": row.get("created_at"),
            "started_at": row.get("started_at"),
            "finished_at": row.get("finished_at"),
            "error": row.get("error"),
            "result_file": row.get("result_file"),
            "result": result,
            "task": None,
        }
