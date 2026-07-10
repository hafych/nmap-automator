import asyncio
import os
import stat
import tempfile
import unittest

os.environ["API_AUTH_REQUIRED"] = "true"
os.environ["API_AUTH_TOKEN"] = "test-token"
os.environ["FERNET_KEY"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
os.environ["SCAN_LOG_PATH"] = "/tmp/nmap-automator-test.log"
os.environ["TELEGRAM_BOT_TOKEN"] = ""
os.environ["TELEGRAM_CHAT_ID"] = ""

import autonmap


class PayloadValidationTests(unittest.TestCase):
    def test_scan_type_is_case_insensitive_and_canonical(self):
        target, scan_type, interval, error = autonmap._validate_scan_payload(
            {"target": "127.0.0.1", "scan_type": "tcp", "interval": 5}
        )

        self.assertIsNone(error)
        self.assertEqual(target, "127.0.0.1")
        self.assertEqual(scan_type, "TCP")
        self.assertEqual(interval, 5.0)

    def test_bad_interval_is_rejected(self):
        *_, error = autonmap._validate_scan_payload(
            {"target": "127.0.0.1", "scan_type": "Ping", "interval": 0}
        )

        self.assertEqual(error, "Интервал должен быть положительным числом")

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

        self.assertIn("не меньше", short_error)
        self.assertIn("не больше", long_error)

    def test_default_scan_type_is_unprivileged_tcp(self):
        _, scan_type, _, error = autonmap._validate_scan_payload({"target": "127.0.0.1"})

        self.assertIsNone(error)
        self.assertEqual(scan_type, "TCP")

    def test_oversized_network_is_rejected(self):
        *_, error = autonmap._validate_scan_payload({"target": "10.0.0.0/8", "scan_type": "Ping"})

        self.assertEqual(error, "Неверный IP, CIDR или домен")

    def test_syntactically_valid_domain_does_not_require_dns(self):
        self.assertTrue(autonmap.validate_ip_or_host("offline-host.example.invalid"))


class ScanExecutionTests(unittest.TestCase):
    def test_nmap_process_receives_total_timeout(self):
        captured = {}

        class FakeScanner:
            def scan(self, target, arguments, timeout):
                captured.update({"target": target, "arguments": arguments, "timeout": timeout})

            def all_hosts(self):
                return []

        original_scanner = autonmap.nmap.PortScanner
        autonmap.nmap.PortScanner = FakeScanner
        try:
            result = autonmap.scan_network("127.0.0.1", "Ping")
        finally:
            autonmap.nmap.PortScanner = original_scanner

        self.assertEqual(result["hosts"], [])
        self.assertEqual(captured["timeout"], autonmap.SCAN_TIMEOUT_SECONDS)


class TaskCleanupTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        autonmap.scan_tasks.clear()
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
                await autonmap.save_scan_results_async({"hosts": []}, "127.0.0.1", "Ping")
            finally:
                autonmap.RESULTS_DIR = original_results_dir
                autonmap.send_telegram_message = original_sender

            files = os.listdir(tmp)
            self.assertEqual(len(files), 1)
            mode = stat.S_IMODE(os.stat(os.path.join(tmp, files[0])).st_mode)
            self.assertEqual(mode, 0o600)


class ApiTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        autonmap.scan_tasks.clear()
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

    async def test_dashboard_loads(self):
        response = await self.client.get("/")
        body = await response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn("Nmap Operator Console", body)
        self.assertIn("observations", body)

    async def test_responses_include_security_headers(self):
        response = await self.client.get("/health")

        self.assertEqual(response.headers["Cache-Control"], "no-store")
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        self.assertIn("frame-ancestors 'none'", response.headers["Content-Security-Policy"])

    async def test_scan_timeout_returns_gateway_timeout(self):
        original_scan = autonmap.async_scan

        async def timeout_scan(target, scan_type):
            raise TimeoutError("scan took too long")

        autonmap.async_scan = timeout_scan
        try:
            response = await self.client.post(
                "/scan",
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
        self.assertIn("лимит", payload["error"])


if __name__ == "__main__":
    unittest.main()
