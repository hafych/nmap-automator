import asyncio
import concurrent.futures
import math
import os
import stat
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

# Path is used by retention and result tests.

os.environ["API_AUTH_REQUIRED"] = "true"
os.environ["API_AUTH_TOKEN"] = "test-token"
os.environ["FERNET_KEY"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
os.environ["SCAN_LOG_PATH"] = "/tmp/nmap-automator-test.log"
os.environ["TELEGRAM_BOT_TOKEN"] = ""
os.environ["TELEGRAM_CHAT_ID"] = ""
os.environ["RESULTS_MAX_FILES"] = "500"
os.environ["RESULTS_MAX_AGE_DAYS"] = "0"
os.environ["STATE_DB_PATH"] = "/tmp/recon-operator-test.db"

import autonmap


class PayloadValidationTests(unittest.TestCase):
    def test_scan_type_is_case_insensitive_and_canonical(self):
        target, scan_type, interval, ports, scripts, discovery, error = (
            autonmap._validate_scan_payload(
                {
                    "target": "127.0.0.1",
                    "scan_type": "tcp",
                    "interval": 5,
                    "ports": "22,80",
                    "discovery": "auto",
                }
            )
        )

        self.assertIsNone(error)
        self.assertEqual(target, "127.0.0.1")
        self.assertEqual(scan_type, "TCP")
        self.assertEqual(interval, 5.0)
        self.assertEqual(ports, "22,80")
        self.assertIsNone(scripts)
        self.assertEqual(discovery, "auto")

    def test_bad_interval_is_rejected(self):
        *_, error = autonmap._validate_scan_payload(
            {"target": "127.0.0.1", "scan_type": "Ping", "interval": 0}
        )

        self.assertEqual(error, "interval must be a positive number")

    def test_schedule_interval_is_bounded(self):
        *_, short_error = autonmap._validate_scan_payload(
            {
                "target": "127.0.0.1",
                "scan_type": "Ping",
                "interval": autonmap.MIN_SCHEDULE_INTERVAL_MINUTES - 0.5,
            }
        )
        *_, long_error = autonmap._validate_scan_payload(
            {
                "target": "127.0.0.1",
                "scan_type": "Ping",
                "interval": autonmap.MAX_SCHEDULE_INTERVAL_MINUTES + 1,
            }
        )

        self.assertIn("at least", short_error)
        self.assertIn("at most", long_error)

    def test_default_scan_type_is_unprivileged_tcp(self):
        _, scan_type, _, _, _, _, error = autonmap._validate_scan_payload({"target": "127.0.0.1"})

        self.assertIsNone(error)
        self.assertEqual(scan_type, "TCP")

    def test_oversized_network_is_rejected(self):
        *_, error = autonmap._validate_scan_payload({"target": "10.0.0.0/8", "scan_type": "Ping"})

        self.assertEqual(error, "Invalid IP, CIDR, or hostname")

    def test_version_and_vuln_profiles_are_accepted(self):
        for profile in ("Version", "Safe", "Vuln", "Full", "Hybrid", "HybridNaabu"):
            with self.subTest(profile=profile):
                _, scan_type, _, _, _, _, error = autonmap._validate_scan_payload(
                    {"target": "127.0.0.1", "scan_type": profile}
                )
                self.assertIsNone(error)
                self.assertEqual(scan_type, profile)

    def test_invalid_ports_are_rejected(self):
        *_, error = autonmap._validate_scan_payload(
            {"target": "127.0.0.1", "scan_type": "TCP", "ports": "80;id"}
        )
        self.assertIn("ports", error.lower())

    def test_syntactically_valid_domain_does_not_require_dns(self):
        self.assertTrue(autonmap.validate_ip_or_host("offline-host.example.invalid"))


class ScanExecutionTests(unittest.TestCase):
    def test_scan_network_uses_unified_engine(self):
        captured = {}

        def fake_run(
            target,
            scan_type,
            host_timeout_sec,
            max_retries,
            scan_timeout_sec,
            ports=None,
            scripts=None,
            discovery=None,
            **_kwargs,
        ):
            captured.update(
                {
                    "target": target,
                    "scan_type": scan_type,
                    "host_timeout_sec": host_timeout_sec,
                    "max_retries": max_retries,
                    "scan_timeout_sec": scan_timeout_sec,
                    "ports": ports,
                    "scripts": scripts,
                    "discovery": discovery,
                }
            )
            return {"hosts": [], "scan_count": 0}

        with mock.patch("autonmap.run_nmap_scan", side_effect=fake_run):
            result = autonmap.scan_network("127.0.0.1", "Ping")

        self.assertEqual(result["hosts"], [])
        self.assertEqual(captured["scan_timeout_sec"], autonmap.SCAN_TIMEOUT_SECONDS)
        self.assertEqual(captured["scan_type"], "Ping")


class TaskCleanupTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        autonmap.scan_tasks.clear()
        autonmap.scan_jobs.clear()
        autonmap.rate_limits.clear()

    async def test_finished_tasks_are_removed(self):
        task = asyncio.create_task(asyncio.sleep(0))
        await task
        autonmap.scan_tasks["127.0.0.1-Ping"] = task

        removed = autonmap._cleanup_finished_tasks()

        self.assertEqual(removed, ["127.0.0.1-Ping"])
        self.assertEqual(autonmap.scan_tasks, {})


class RateLimitTests(unittest.TestCase):
    def setUp(self):
        autonmap.rate_limits.clear()

    def tearDown(self):
        autonmap.rate_limits.clear()

    def test_stale_client_is_evicted_when_bucket_table_is_full(self):
        original_limit = autonmap.MAX_RATE_LIMIT_CLIENTS
        original_client_key = autonmap._client_key
        now = autonmap.time.time()
        autonmap.MAX_RATE_LIMIT_CLIENTS = 2
        autonmap.rate_limits["active"] = [now]
        autonmap.rate_limits["stale"] = [now - autonmap.RATE_LIMIT_WINDOW_SECONDS - 1]
        autonmap._client_key = lambda: "new"
        try:
            allowed = autonmap.check_rate_limit()
        finally:
            autonmap.MAX_RATE_LIMIT_CLIENTS = original_limit
            autonmap._client_key = original_client_key

        self.assertTrue(allowed)
        self.assertNotIn("stale", autonmap.rate_limits)
        self.assertIn("new", autonmap.rate_limits)


class ResultPersistenceTests(unittest.IsolatedAsyncioTestCase):
    async def test_encrypted_results_are_owner_only(self):
        original_results_dir = autonmap.RESULTS_DIR
        original_sender = autonmap.send_telegram_message

        async def ignore_message(_message):
            return None

        with tempfile.TemporaryDirectory() as tmp:
            autonmap.RESULTS_DIR = tmp
            autonmap.send_telegram_message = ignore_message
            try:
                filename = await autonmap.save_scan_results_async(
                    {"hosts": []}, "127.0.0.1", "Ping"
                )
            finally:
                autonmap.RESULTS_DIR = original_results_dir
                autonmap.send_telegram_message = original_sender

            files = os.listdir(tmp)
            self.assertEqual(len(files), 1)
            self.assertEqual(filename, files[0])
            mode = stat.S_IMODE(os.stat(os.path.join(tmp, files[0])).st_mode)
            self.assertEqual(mode, 0o600)

    def test_retention_deletes_excess_files(self):
        original_max = autonmap.RESULTS_MAX_FILES
        autonmap.RESULTS_MAX_FILES = 2
        try:
            with tempfile.TemporaryDirectory() as tmp:
                for index in range(4):
                    path = Path(tmp) / f"host_Ping_20260101_00000{index}_00000{index}.json"
                    path.write_bytes(b"x")
                    os.utime(path, (index + 1, index + 1))
                summary = autonmap.apply_results_retention(tmp)
                remaining = list(Path(tmp).glob("*.json"))
        finally:
            autonmap.RESULTS_MAX_FILES = original_max

        self.assertEqual(summary["remaining"], 2)
        self.assertEqual(summary["deleted"], 2)
        self.assertEqual(len(remaining), 2)


class ApiTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        autonmap.scan_tasks.clear()
        autonmap.scan_jobs.clear()
        autonmap.rate_limits.clear()
        self.client = autonmap.app.test_client()

    async def test_tasks_requires_api_token(self):
        response = await self.client.get("/tasks")

        self.assertEqual(response.status_code, 401)

    async def test_health_reports_status(self):
        original_check = autonmap._check_nmap_available
        autonmap._check_nmap_available = lambda: True
        try:
            response = await self.client.get("/health")
            payload = await response.get_json()
        finally:
            autonmap._check_nmap_available = original_check

        self.assertEqual(response.status_code, 200)
        self.assertEqual(payload["status"], "healthy")
        self.assertIn("jobs_count", payload)

    async def test_dashboard_loads(self):
        response = await self.client.get("/")
        body = await response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn("Recon Operator", body)
        self.assertIn("observations", body)
        self.assertIn("Scan History", body)
        self.assertIn("waitForJob", body)
        self.assertIn("Import XML", body)
        self.assertIn("Diff last two", body)
        self.assertNotIn("__CSP_NONCE__", body)
        self.assertIn('nonce="', body)
        csp = response.headers["Content-Security-Policy"]
        self.assertIn("nonce-", csp)
        self.assertNotIn("unsafe-inline", csp)

    async def test_responses_include_security_headers(self):
        response = await self.client.get("/health")

        self.assertEqual(response.headers["Cache-Control"], "no-store")
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        self.assertIn("frame-ancestors 'none'", response.headers["Content-Security-Policy"])
        self.assertIn("default-src 'none'", response.headers["Content-Security-Policy"])

    async def test_scan_queues_job_by_default(self):
        async def fake_create(
            target, scan_type, kind="immediate", ports=None, scripts=None, discovery=None
        ):
            return {
                "job_id": "job-1",
                "target": target,
                "scan_type": scan_type,
                "status": "queued",
                "created_at": "now",
                "kind": kind,
                "ports": ports,
                "scripts": scripts,
                "discovery": discovery,
            }

        original = autonmap.create_scan_job
        autonmap.create_scan_job = fake_create
        try:
            response = await self.client.post(
                "/scan",
                headers={"X-API-KEY": "test-token"},
                json={"target": "127.0.0.1", "scan_type": "Ping"},
            )
            payload = await response.get_json()
        finally:
            autonmap.create_scan_job = original

        self.assertEqual(response.status_code, 202)
        self.assertEqual(payload["job_id"], "job-1")
        self.assertEqual(payload["status"], "queued")

    async def test_scan_wait_mode_returns_result(self):
        original_scan = autonmap.async_scan

        async def fake_scan(target, scan_type, ports=None, scripts=None, discovery=None):
            return {"hosts": [], "target": target, "scan_type": scan_type}

        autonmap.async_scan = fake_scan
        try:
            response = await self.client.post(
                "/scan?wait=1",
                headers={"X-API-KEY": "test-token"},
                json={"target": "127.0.0.1", "scan_type": "Ping"},
            )
            payload = await response.get_json()
        finally:
            autonmap.async_scan = original_scan

        self.assertEqual(response.status_code, 200)
        self.assertEqual(payload["target"], "127.0.0.1")

    async def test_scan_timeout_returns_gateway_timeout(self):
        original_scan = autonmap.async_scan

        async def timeout_scan(target, scan_type, ports=None, scripts=None, discovery=None):
            raise TimeoutError("scan took too long")

        autonmap.async_scan = timeout_scan
        try:
            response = await self.client.post(
                "/scan?wait=1",
                headers={"X-API-KEY": "test-token"},
                json={"target": "127.0.0.1", "scan_type": "Ping"},
            )
            payload = await response.get_json()
        finally:
            autonmap.async_scan = original_scan

        self.assertEqual(response.status_code, 504)
        self.assertIn("scan took too long", payload["error"])

    async def test_schedule_rejects_tasks_above_configured_limit(self):
        class PendingTask:
            @staticmethod
            def done():
                return False

        original_limit = autonmap.MAX_SCHEDULED_TASKS
        autonmap.MAX_SCHEDULED_TASKS = 1
        autonmap.scan_tasks["existing-TCP"] = PendingTask()
        try:
            response = await self.client.post(
                "/schedule",
                headers={"X-API-KEY": "test-token"},
                json={"target": "127.0.0.1", "scan_type": "TCP", "interval": 30},
            )
            payload = await response.get_json()
        finally:
            autonmap.MAX_SCHEDULED_TASKS = original_limit
            autonmap.scan_tasks.clear()

        self.assertEqual(response.status_code, 429)
        self.assertIn("limit", payload["error"].lower())

    async def test_jobs_and_results_endpoints(self):
        sample = {
            "hosts": [{"host": "127.0.0.1", "hostname": "N/A", "state": "up", "protocols": {}}],
            "scan_count": 1,
        }
        original_results_dir = autonmap.RESULTS_DIR
        with tempfile.TemporaryDirectory() as tmp:
            autonmap.RESULTS_DIR = tmp
            filename = await autonmap.save_scan_results_async(sample, "127.0.0.1", "Ping")
            list_response = await self.client.get("/results", headers={"X-API-KEY": "test-token"})
            list_payload = await list_response.get_json()
            get_response = await self.client.get(
                f"/results/{filename}", headers={"X-API-KEY": "test-token"}
            )
            get_payload = await get_response.get_json()
            autonmap.RESULTS_DIR = original_results_dir

        self.assertEqual(list_response.status_code, 200)
        self.assertEqual(list_payload["count"], 1)
        self.assertEqual(get_response.status_code, 200)
        self.assertEqual(get_payload["result"]["scan_count"], 1)

        autonmap.scan_jobs["job-x"] = {
            "job_id": "job-x",
            "target": "127.0.0.1",
            "scan_type": "Ping",
            "status": "completed",
            "created_at": "t0",
            "started_at": "t1",
            "finished_at": "t2",
            "error": None,
            "result": sample,
            "result_file": filename,
            "kind": "immediate",
            "task": None,
        }
        job_response = await self.client.get("/jobs/job-x", headers={"X-API-KEY": "test-token"})
        job_payload = await job_response.get_json()
        self.assertEqual(job_response.status_code, 200)
        self.assertEqual(job_payload["status"], "completed")
        self.assertEqual(job_payload["result"]["scan_count"], 1)

        list_jobs = await self.client.get("/jobs", headers={"X-API-KEY": "test-token"})
        list_jobs_payload = await list_jobs.get_json()
        self.assertEqual(list_jobs.status_code, 200)
        self.assertTrue(any(job["job_id"] == "job-x" for job in list_jobs_payload))

    async def test_create_scan_job_completes_with_mocked_engine(self):
        original_results_dir = autonmap.RESULTS_DIR
        original_scan = autonmap.scan_network
        original_sender = autonmap.send_telegram_message

        async def ignore_message(_message):
            return None

        def fake_scan(target, scan_type, ports=None, scripts=None, discovery=None):
            return {
                "hosts": [{"host": target, "hostname": "N/A", "state": "up", "protocols": {}}],
                "scan_count": 1,
                "target": target,
                "scan_type": scan_type,
            }

        with tempfile.TemporaryDirectory() as tmp:
            autonmap.RESULTS_DIR = tmp
            autonmap.scan_network = fake_scan
            autonmap.send_telegram_message = ignore_message
            try:
                job = await autonmap.create_scan_job("127.0.0.1", "Ping")
                job_id = job["job_id"]
                for _ in range(50):
                    async with autonmap._jobs_lock:
                        status = autonmap.scan_jobs[job_id]["status"]
                        result_file = autonmap.scan_jobs[job_id].get("result_file")
                    if status in {"completed", "failed", "timeout"}:
                        break
                    await asyncio.sleep(0.02)
            finally:
                autonmap.RESULTS_DIR = original_results_dir
                autonmap.scan_network = original_scan
                autonmap.send_telegram_message = original_sender

        self.assertEqual(status, "completed")
        self.assertIsNotNone(result_file)

    async def test_import_and_diff_endpoints(self):
        sample_xml = """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap" start="1" version="7.95" xmloutputversion="1.05">
  <host>
    <status state="up"/>
    <address addr="192.0.2.10" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>
    </ports>
  </host>
</nmaprun>
"""
        baseline = {
            "hosts": [
                {
                    "host": "192.0.2.10",
                    "hostname": "N/A",
                    "state": "up",
                    "protocols": {"tcp": [{"port": 22, "state": "open", "name": "ssh"}]},
                }
            ]
        }
        current = {
            "hosts": [
                {
                    "host": "192.0.2.10",
                    "hostname": "N/A",
                    "state": "up",
                    "protocols": {
                        "tcp": [
                            {"port": 22, "state": "open", "name": "ssh"},
                            {"port": 80, "state": "open", "name": "http"},
                        ]
                    },
                }
            ]
        }
        original_results_dir = autonmap.RESULTS_DIR
        original_sender = autonmap.send_telegram_message

        async def ignore_message(_message):
            return None

        with tempfile.TemporaryDirectory() as tmp:
            autonmap.RESULTS_DIR = tmp
            autonmap.send_telegram_message = ignore_message
            try:
                import_response = await self.client.post(
                    "/results/import",
                    headers={"X-API-KEY": "test-token"},
                    json={"xml": sample_xml, "target": "192.0.2.10"},
                )
                import_payload = await import_response.get_json()
                diff_response = await self.client.post(
                    "/results/diff",
                    headers={"X-API-KEY": "test-token"},
                    json={"baseline": baseline, "current": current},
                )
                diff_payload = await diff_response.get_json()
            finally:
                autonmap.RESULTS_DIR = original_results_dir
                autonmap.send_telegram_message = original_sender

        self.assertEqual(import_response.status_code, 201)
        self.assertEqual(import_payload["result"]["hosts"][0]["host"], "192.0.2.10")
        self.assertEqual(diff_response.status_code, 200)
        self.assertTrue(diff_payload["summary"]["changed"])
        self.assertEqual(diff_payload["summary"]["ports_opened"], 1)

    async def test_cancel_job_endpoint(self):
        autonmap.scan_jobs["job-cancel"] = {
            "job_id": "job-cancel",
            "target": "127.0.0.1",
            "scan_type": "Ping",
            "status": "queued",
            "created_at": "t0",
            "started_at": None,
            "finished_at": None,
            "error": None,
            "result": None,
            "result_file": None,
            "kind": "immediate",
            "task": None,
        }
        response = await self.client.delete("/jobs/job-cancel", headers={"X-API-KEY": "test-token"})
        payload = await response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertIn("cancelled", payload["message"].lower())
        self.assertEqual(autonmap.scan_jobs["job-cancel"]["status"], "cancelled")

    async def test_dashboard_exposes_accessible_controls_and_feedback(self):
        response = await self.client.get("/")
        body = await response.get_data(as_text=True)

        self.assertIn('role="status" aria-live="polite"', body)
        self.assertIn('role="tablist"', body)
        self.assertIn('aria-selected="true"', body)
        self.assertIn('for="toolsBox"', body)
        self.assertIn('for="resultBox"', body)
        self.assertIn(":focus-visible", body)
        self.assertIn("refresh({ announce: false })", body)


class PayloadHardeningRegressionTests(unittest.TestCase):
    def test_non_finite_intervals_are_rejected(self):
        for interval in (math.nan, math.inf, -math.inf):
            with self.subTest(interval=interval):
                *_, error = autonmap._validate_scan_payload(
                    {"target": "127.0.0.1", "scan_type": "Ping", "interval": interval}
                )

                self.assertEqual(error, "interval must be a finite number")

    def test_targets_are_canonicalized_before_task_ids_are_built(self):
        cases = {
            "LOCALHOST": "localhost",
            "Example.COM": "example.com",
            "192.0.2.7/24": "192.0.2.0/24",
            "2001:0db8::1": "2001:db8::1",
        }

        for supplied, expected in cases.items():
            with self.subTest(target=supplied):
                target, _, _, _, _, _, error = autonmap._validate_scan_payload(
                    {"target": supplied, "scan_type": "Ping", "interval": 5}
                )

                self.assertIsNone(error)
                self.assertEqual(target, expected)


class CacheSingleFlightRegressionTests(unittest.TestCase):
    def test_concurrent_cache_misses_build_inventory_once(self):
        original_builder = autonmap.build_tool_inventory
        original_cache = dict(autonmap.tool_inventory_cache)
        calls = 0
        calls_lock = threading.Lock()
        start = threading.Barrier(8)

        def fake_builder(expand=False):
            nonlocal calls
            with calls_lock:
                calls += 1
            time.sleep(0.05)
            return {"expand": expand}

        def load_inventory(_index):
            start.wait(timeout=2)
            return autonmap.get_cached_tool_inventory(False)

        autonmap.tool_inventory_cache.clear()
        autonmap.build_tool_inventory = fake_builder
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                results = list(pool.map(load_inventory, range(8)))
        finally:
            autonmap.build_tool_inventory = original_builder
            autonmap.tool_inventory_cache.clear()
            autonmap.tool_inventory_cache.update(original_cache)

        self.assertEqual(calls, 1)
        self.assertEqual(results, [{"expand": False}] * 8)


class AuthAndCoverageRegressionTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        autonmap.scan_tasks.clear()
        autonmap.scan_jobs.clear()
        autonmap.rate_limits.clear()
        self.client = autonmap.app.test_client()

    def test_multi_token_authorization(self):
        original = list(autonmap.API_AUTH_TOKENS)
        autonmap.API_AUTH_TOKENS = ["alpha-token-111", "beta-token-2222"]
        try:
            self.assertTrue(autonmap._token_is_authorized("alpha-token-111"))
            self.assertTrue(autonmap._token_is_authorized("beta-token-2222"))
            self.assertFalse(autonmap._token_is_authorized("nope"))
            self.assertFalse(autonmap._token_is_authorized("alpha-token-11"))
        finally:
            autonmap.API_AUTH_TOKENS = original

    async def test_invalid_token_is_rejected(self):
        response = await self.client.get("/tasks", headers={"X-API-KEY": "wrong-token"})
        payload = await response.get_json()
        self.assertEqual(response.status_code, 403)
        self.assertIn("Invalid", payload["error"])

    async def test_schedule_create_list_and_cancel(self):
        async def noop_periodic(*_args, **_kwargs):
            await asyncio.Event().wait()

        original = autonmap.periodic_scan
        autonmap.periodic_scan = noop_periodic
        try:
            create = await self.client.post(
                "/schedule",
                headers={"X-API-KEY": "test-token"},
                json={"target": "127.0.0.1", "scan_type": "Ping", "interval": 30},
            )
            created = await create.get_json()
            self.assertEqual(create.status_code, 200)
            task_id = created["task_id"]

            listed = await self.client.get("/tasks", headers={"X-API-KEY": "test-token"})
            listed_payload = await listed.get_json()
            self.assertTrue(any(item["id"] == task_id for item in listed_payload))

            cancelled = await self.client.delete(
                f"/tasks/{task_id}", headers={"X-API-KEY": "test-token"}
            )
            self.assertEqual(cancelled.status_code, 200)
        finally:
            autonmap.periodic_scan = original
            for task in list(autonmap.scan_tasks.values()):
                task.cancel()
            autonmap.scan_tasks.clear()

    async def test_rate_limit_blocks_excess_requests(self):
        original_max = autonmap.MAX_REQUESTS_PER_WINDOW
        original_key = autonmap._client_key
        autonmap.MAX_REQUESTS_PER_WINDOW = 1
        autonmap._client_key = lambda: "rate-test-client"
        autonmap.rate_limits.clear()
        try:
            first = await self.client.get("/tools", headers={"X-API-KEY": "test-token"})
            second = await self.client.get("/tools", headers={"X-API-KEY": "test-token"})
        finally:
            autonmap.MAX_REQUESTS_PER_WINDOW = original_max
            autonmap._client_key = original_key
            autonmap.rate_limits.clear()

        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 429)

    async def test_result_path_traversal_is_rejected(self):
        response = await self.client.get(
            "/results/../secrets.json",
            headers={"X-API-KEY": "test-token"},
        )
        self.assertEqual(response.status_code, 404)

    async def test_load_persisted_state_marks_inflight_failed(self):
        original_results = list(autonmap.scan_jobs.items())
        autonmap.scan_jobs.clear()

        def fake_list_jobs(limit=200):
            return [
                {
                    "job_id": "inflight-1",
                    "target": "127.0.0.1",
                    "scan_type": "Ping",
                    "status": "running",
                    "kind": "immediate",
                    "created_at": "t0",
                    "task": None,
                }
            ]

        def fake_list_tasks():
            return []

        def fake_upsert(job):
            self.assertEqual(job["status"], "failed")
            self.assertIn("restart", job["error"].lower())

        original_jobs = autonmap.state_store.list_jobs
        original_tasks = autonmap.state_store.list_scheduled_tasks
        original_upsert = autonmap.state_store.upsert_job
        autonmap.state_store.list_jobs = fake_list_jobs
        autonmap.state_store.list_scheduled_tasks = fake_list_tasks
        autonmap.state_store.upsert_job = fake_upsert
        try:
            await autonmap.load_persisted_state()
            self.assertEqual(autonmap.scan_jobs["inflight-1"]["status"], "failed")
        finally:
            autonmap.state_store.list_jobs = original_jobs
            autonmap.state_store.list_scheduled_tasks = original_tasks
            autonmap.state_store.upsert_job = original_upsert
            autonmap.scan_jobs.clear()
            for key, value in original_results:
                autonmap.scan_jobs[key] = value

    def test_retention_by_age(self):
        original_age = autonmap.RESULTS_MAX_AGE_DAYS
        original_max = autonmap.RESULTS_MAX_FILES
        autonmap.RESULTS_MAX_AGE_DAYS = 1
        autonmap.RESULTS_MAX_FILES = 100
        try:
            with tempfile.TemporaryDirectory() as tmp:
                old = Path(tmp) / "old_Ping_20260101_000000_1.json"
                new = Path(tmp) / "new_Ping_20260102_000000_1.json"
                old.write_bytes(b"old")
                new.write_bytes(b"new")
                now = time.time()
                os.utime(old, (now - 3 * 86400, now - 3 * 86400))
                os.utime(new, (now, now))
                summary = autonmap.apply_results_retention(tmp)
                names = {path.name for path in Path(tmp).glob("*.json")}
        finally:
            autonmap.RESULTS_MAX_AGE_DAYS = original_age
            autonmap.RESULTS_MAX_FILES = original_max

        self.assertEqual(summary["deleted"], 1)
        self.assertEqual(names, {"new_Ping_20260102_000000_1.json"})


class ReadinessRegressionTests(unittest.IsolatedAsyncioTestCase):
    async def test_health_returns_service_unavailable_without_nmap(self):
        original_check = autonmap._check_nmap_available
        autonmap._check_nmap_available = lambda: False
        try:
            response = await autonmap.app.test_client().get("/health")
            payload = await response.get_json()
        finally:
            autonmap._check_nmap_available = original_check

        self.assertEqual(response.status_code, 503)
        self.assertEqual(payload["status"], "unhealthy")
        self.assertFalse(payload["nmap_available"])
        self.assertFalse(payload["ready"])

    async def test_liveness_stays_up_without_nmap(self):
        original_check = autonmap._check_nmap_available
        autonmap._check_nmap_available = lambda: False
        client = autonmap.app.test_client()
        try:
            live = await client.get("/live")
            ready = await client.get("/ready")
            live_payload = await live.get_json()
            ready_payload = await ready.get_json()
        finally:
            autonmap._check_nmap_available = original_check

        self.assertEqual(live.status_code, 200)
        self.assertEqual(live_payload["status"], "live")
        self.assertEqual(ready.status_code, 503)
        self.assertEqual(ready_payload["status"], "not_ready")

    async def test_openapi_document_is_valid_shape(self):
        response = await autonmap.app.test_client().get("/openapi.json")
        payload = await response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(payload["openapi"], "3.0.3")
        self.assertIn("/scan", payload["paths"])
        self.assertIn("/live", payload["paths"])
        self.assertIn("ApiKeyAuth", payload["components"]["securitySchemes"])


if __name__ == "__main__":
    unittest.main()
