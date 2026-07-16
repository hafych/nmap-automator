"""Browser smoke tests for the operator dashboard (Playwright).

Run only in the CI e2e job (or locally with browsers installed):

    RUN_E2E=1 python -m unittest discover -s e2e -v
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_for_live(base_url: str, timeout: float = 30.0) -> None:
    deadline = time.time() + timeout
    last_error = None
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(f"{base_url}/live", timeout=1.5) as response:
                if response.status == 200:
                    return
        except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
            last_error = exc
            time.sleep(0.2)
    raise TimeoutError(f"Server did not become live at {base_url}/live: {last_error}")


@unittest.skipUnless(os.getenv("RUN_E2E") == "1", "Set RUN_E2E=1 to run Playwright smoke tests")
class DashboardPlaywrightSmokeTests(unittest.TestCase):
    server: subprocess.Popen | None = None
    base_url: str = ""
    tmpdir: tempfile.TemporaryDirectory | None = None
    token: str = "e2e-browser-token-aaaaaaaa"
    fernet: str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

    @classmethod
    def setUpClass(cls) -> None:
        try:
            from playwright.sync_api import sync_playwright  # noqa: F401
        except ImportError as exc:
            raise unittest.SkipTest(f"playwright not installed: {exc}") from exc

        cls.tmpdir = tempfile.TemporaryDirectory(prefix="recon-e2e-")
        port = _free_port()
        cls.base_url = f"http://127.0.0.1:{port}"
        env = os.environ.copy()
        env.update(
            {
                "API_AUTH_REQUIRED": "true",
                "API_AUTH_TOKEN": cls.token,
                "FERNET_KEY": cls.fernet,
                "APP_HOST": "127.0.0.1",
                "APP_PORT": str(port),
                "STATE_DB_PATH": str(Path(cls.tmpdir.name) / "state.db"),
                "RESULTS_DIR": str(Path(cls.tmpdir.name) / "results"),
                "SCAN_LOG_PATH": str(Path(cls.tmpdir.name) / "scan.log"),
                "TELEGRAM_BOT_TOKEN": "",
                "TELEGRAM_CHAT_ID": "",
                "INITIAL_TASKS": "[]",
            }
        )
        cls.server = subprocess.Popen(
            [sys.executable, str(ROOT / "autonmap.py")],
            cwd=str(ROOT),
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            _wait_for_live(cls.base_url)
        except Exception:
            cls.tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls) -> None:
        if cls.server is not None:
            cls.server.terminate()
            try:
                cls.server.wait(timeout=10)
            except subprocess.TimeoutExpired:
                cls.server.kill()
                cls.server.wait(timeout=5)
            cls.server = None
        if cls.tmpdir is not None:
            cls.tmpdir.cleanup()
            cls.tmpdir = None

    def test_dashboard_loads_with_accessible_controls_and_nonce_csp(self):
        from playwright.sync_api import sync_playwright

        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            page = browser.new_page()
            response = page.goto(self.base_url + "/", wait_until="networkidle")
            self.assertIsNotNone(response)
            assert response is not None
            self.assertEqual(response.status, 200)

            title = page.title()
            body = page.content()
            self.assertIn("Recon Operator", body)
            self.assertTrue(title == "Recon Operator" or "Recon" in body)

            token = page.locator("#apiToken")
            self.assertTrue(token.count() >= 1)
            self.assertEqual(token.get_attribute("type"), "password")

            # Focus ring / keyboard path: token field is focusable.
            token.focus()
            self.assertTrue(
                page.evaluate("document.activeElement && document.activeElement.id === 'apiToken'")
            )

            key_meta = page.locator("#keyMeta")
            self.assertTrue(key_meta.count() >= 1)

            csp = response.headers.get("content-security-policy", "")
            self.assertIn("nonce-", csp)
            self.assertNotIn("unsafe-inline", csp)

            # Authenticated whoami via page context (same-origin).
            page.fill("#apiToken", self.token)
            page.keyboard.press("Tab")
            whoami = page.evaluate(
                """async (token) => {
                    const res = await fetch('/auth/whoami', {
                        headers: { 'X-API-KEY': token }
                    });
                    return { status: res.status, body: await res.json() };
                }""",
                self.token,
            )
            self.assertEqual(whoami["status"], 200)
            self.assertIn("key_id", whoami["body"])
            self.assertIn("scopes", whoami["body"])

            live = page.evaluate(
                """async () => {
                    const res = await fetch('/live');
                    return { status: res.status, body: await res.json() };
                }"""
            )
            self.assertEqual(live["status"], 200)
            self.assertEqual(live["body"]["status"], "live")

            browser.close()


if __name__ == "__main__":
    unittest.main()
