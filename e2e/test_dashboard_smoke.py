"""Browser smoke tests for the operator dashboard (Playwright).

Run only in the CI e2e job (or locally with browsers installed):

    RUN_E2E=1 python -m unittest discover -s e2e -v
"""

from __future__ import annotations

import os
import unittest

from helpers import DashboardServer


@unittest.skipUnless(os.getenv("RUN_E2E") == "1", "Set RUN_E2E=1 to run Playwright smoke tests")
class DashboardPlaywrightSmokeTests(unittest.TestCase):
    server: DashboardServer | None = None

    @classmethod
    def setUpClass(cls) -> None:
        try:
            from playwright.sync_api import sync_playwright  # noqa: F401
        except ImportError as exc:
            raise unittest.SkipTest(f"playwright not installed: {exc}") from exc

        cls.server = DashboardServer()
        cls.server.start()

    @classmethod
    def tearDownClass(cls) -> None:
        if cls.server is not None:
            cls.server.stop()
            cls.server = None

    def test_dashboard_loads_with_accessible_controls_and_nonce_csp(self):
        from playwright.sync_api import sync_playwright

        assert self.server is not None
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            page = browser.new_page()
            response = page.goto(self.server.base_url + "/", wait_until="networkidle")
            self.assertIsNotNone(response)
            assert response is not None
            self.assertEqual(response.status, 200)

            body = page.content()
            self.assertIn("Recon Operator", body)

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

            page.fill("#apiToken", self.server.token)
            page.keyboard.press("Tab")
            whoami = page.evaluate(
                """async (token) => {
                    const res = await fetch('/auth/whoami', {
                        headers: { 'X-API-KEY': token }
                    });
                    return { status: res.status, body: await res.json() };
                }""",
                self.server.token,
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
