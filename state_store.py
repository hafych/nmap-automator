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
    result_json TEXT,
    lease_owner TEXT,
    lease_until REAL
);

CREATE INDEX IF NOT EXISTS idx_scan_jobs_created ON scan_jobs(created_at);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_status ON scan_jobs(status);

CREATE TABLE IF NOT EXISTS leadership (
    lock_name TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL,
    lease_until REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    action TEXT NOT NULL,
    actor_key_id TEXT,
    actor_owner_prefix TEXT,
    target TEXT,
    scan_type TEXT,
    job_id TEXT,
    task_id TEXT,
    result_file TEXT,
    status TEXT,
    detail TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_events_ts ON audit_events(ts);
CREATE INDEX IF NOT EXISTS idx_audit_events_action ON audit_events(action);
"""


class _ClosingConnection(sqlite3.Connection):
    """SQLite connection that closes after its transaction context exits."""

    def __exit__(self, exc_type, exc_value, traceback):
        try:
            return super().__exit__(exc_type, exc_value, traceback)
        finally:
            self.close()


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
        conn = sqlite3.connect(
            self.path,
            timeout=30,
            check_same_thread=False,
            factory=_ClosingConnection,
        )
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
        if "lease_owner" not in job_cols:
            conn.execute("ALTER TABLE scan_jobs ADD COLUMN lease_owner TEXT")
        if "lease_until" not in job_cols:
            conn.execute("ALTER TABLE scan_jobs ADD COLUMN lease_until REAL")
        task_cols = self._table_columns(conn, "scheduled_tasks")
        if "owner_id" not in task_cols:
            conn.execute("ALTER TABLE scheduled_tasks ADD COLUMN owner_id TEXT")
        # Owner indexes after column migration so older DBs upgrade cleanly.
        conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_jobs_owner ON scan_jobs(owner_id)")
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_scheduled_tasks_owner ON scheduled_tasks(owner_id)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_scan_jobs_lease ON scan_jobs(status, lease_until)"
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
                    owner_id, created_at, started_at, finished_at, error, result_file, result_json,
                    lease_owner, lease_until
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    result_json=excluded.result_json,
                    lease_owner=excluded.lease_owner,
                    lease_until=excluded.lease_until
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
                    job.get("lease_owner"),
                    job.get("lease_until"),
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

    def try_claim_job(
        self,
        job_id: str,
        worker_id: str,
        *,
        now: float,
        lease_seconds: float,
        started_at: str,
    ) -> Optional[Dict[str, Any]]:
        """Atomically claim a queued (or expired-lease) job for ``worker_id``."""
        lease_until = float(now) + float(lease_seconds)
        with self._lock, self._connect() as conn:
            cursor = conn.execute(
                """
                UPDATE scan_jobs
                SET status = 'running',
                    lease_owner = ?,
                    lease_until = ?,
                    started_at = COALESCE(started_at, ?),
                    error = NULL
                WHERE job_id = ?
                  AND (
                    status = 'queued'
                    OR (
                        status = 'running'
                        AND (lease_until IS NULL OR lease_until < ?)
                    )
                  )
                """,
                (worker_id, lease_until, started_at, job_id, float(now)),
            )
            conn.commit()
            if cursor.rowcount < 1:
                return None
            row = conn.execute("SELECT * FROM scan_jobs WHERE job_id = ?", (job_id,)).fetchone()
        return self._row_to_job(dict(row)) if row is not None else None

    def claim_next_job(
        self,
        worker_id: str,
        *,
        now: float,
        lease_seconds: float,
        started_at: str,
    ) -> Optional[Dict[str, Any]]:
        """Claim the oldest claimable job for this worker, if any."""
        with self._lock, self._connect() as conn:
            row = conn.execute(
                """
                SELECT job_id FROM scan_jobs
                WHERE status = 'queued'
                   OR (
                        status = 'running'
                        AND (lease_until IS NULL OR lease_until < ?)
                   )
                ORDER BY created_at ASC
                LIMIT 1
                """,
                (float(now),),
            ).fetchone()
            if row is None:
                return None
            job_id = row["job_id"]
        return self.try_claim_job(
            job_id,
            worker_id,
            now=now,
            lease_seconds=lease_seconds,
            started_at=started_at,
        )

    def renew_job_lease(
        self,
        job_id: str,
        worker_id: str,
        *,
        now: float,
        lease_seconds: float,
    ) -> bool:
        lease_until = float(now) + float(lease_seconds)
        with self._lock, self._connect() as conn:
            cursor = conn.execute(
                """
                UPDATE scan_jobs
                SET lease_until = ?
                WHERE job_id = ?
                  AND lease_owner = ?
                  AND status = 'running'
                """,
                (lease_until, job_id, worker_id),
            )
            conn.commit()
            return cursor.rowcount > 0

    def release_job_lease(self, job_id: str, worker_id: str) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                UPDATE scan_jobs
                SET lease_owner = NULL, lease_until = NULL
                WHERE job_id = ? AND lease_owner = ?
                """,
                (job_id, worker_id),
            )
            conn.commit()

    def try_acquire_leadership(
        self,
        lock_name: str,
        worker_id: str,
        *,
        now: float,
        lease_seconds: float,
    ) -> bool:
        """Acquire or renew a named leadership lease (e.g. scheduler)."""
        lease_until = float(now) + float(lease_seconds)
        with self._lock, self._connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO leadership(lock_name, owner_id, lease_until)
                VALUES (?, ?, ?)
                ON CONFLICT(lock_name) DO UPDATE SET
                    owner_id = excluded.owner_id,
                    lease_until = excluded.lease_until
                WHERE leadership.lease_until < ?
                   OR leadership.owner_id = ?
                """,
                (lock_name, worker_id, lease_until, float(now), worker_id),
            )
            conn.commit()
            if cursor.rowcount > 0:
                return True
            row = conn.execute(
                "SELECT owner_id FROM leadership WHERE lock_name = ?",
                (lock_name,),
            ).fetchone()
            return bool(row and row["owner_id"] == worker_id)

    def get_leader(self, lock_name: str) -> Optional[Dict[str, Any]]:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT lock_name, owner_id, lease_until FROM leadership WHERE lock_name = ?",
                (lock_name,),
            ).fetchone()
        return dict(row) if row is not None else None

    def release_leadership(self, lock_name: str, worker_id: str) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "DELETE FROM leadership WHERE lock_name = ? AND owner_id = ?",
                (lock_name, worker_id),
            )
            conn.commit()

    def append_audit_event(
        self,
        *,
        ts: str,
        action: str,
        actor_key_id: Optional[str] = None,
        actor_owner_prefix: Optional[str] = None,
        target: Optional[str] = None,
        scan_type: Optional[str] = None,
        job_id: Optional[str] = None,
        task_id: Optional[str] = None,
        result_file: Optional[str] = None,
        status: Optional[str] = None,
        detail: Optional[str] = None,
        max_events: int = 10_000,
    ) -> None:
        """Append an audit event and prune oldest rows beyond max_events."""
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO audit_events(
                    ts, action, actor_key_id, actor_owner_prefix, target, scan_type,
                    job_id, task_id, result_file, status, detail
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    ts,
                    action,
                    actor_key_id,
                    actor_owner_prefix,
                    target,
                    scan_type,
                    job_id,
                    task_id,
                    result_file,
                    status,
                    detail,
                ),
            )
            if max_events > 0:
                conn.execute(
                    """
                    DELETE FROM audit_events
                    WHERE id NOT IN (
                        SELECT id FROM audit_events ORDER BY id DESC LIMIT ?
                    )
                    """,
                    (int(max_events),),
                )
            conn.commit()

    def list_audit_events(
        self,
        *,
        limit: int = 100,
        action: Optional[str] = None,
        actor_key_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        limit = max(1, min(int(limit), 1000))
        params: List[Any] = []
        if action and actor_key_id:
            query = """
                SELECT id, ts, action, actor_key_id, actor_owner_prefix, target, scan_type,
                       job_id, task_id, result_file, status, detail
                FROM audit_events
                WHERE action = ? AND actor_key_id = ?
                ORDER BY id DESC
                LIMIT ?
            """
            params.extend((action, actor_key_id))
        elif action:
            query = """
                SELECT id, ts, action, actor_key_id, actor_owner_prefix, target, scan_type,
                       job_id, task_id, result_file, status, detail
                FROM audit_events
                WHERE action = ?
                ORDER BY id DESC
                LIMIT ?
            """
            params.append(action)
        elif actor_key_id:
            query = """
                SELECT id, ts, action, actor_key_id, actor_owner_prefix, target, scan_type,
                       job_id, task_id, result_file, status, detail
                FROM audit_events
                WHERE actor_key_id = ?
                ORDER BY id DESC
                LIMIT ?
            """
            params.append(actor_key_id)
        else:
            query = """
                SELECT id, ts, action, actor_key_id, actor_owner_prefix, target, scan_type,
                       job_id, task_id, result_file, status, detail
                FROM audit_events
                ORDER BY id DESC
                LIMIT ?
            """
        params.append(limit)
        with self._lock, self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(row) for row in rows]

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
            "lease_owner": row.get("lease_owner"),
            "lease_until": row.get("lease_until"),
            "task": None,
        }
