"""Focused regression checks for the expanded Cros catalog and local app surface."""

from __future__ import annotations

import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import Mock, patch

import app_catalog
import app_server
import learning_catalog
import osint_tool
import security_tools


class CatalogTests(unittest.TestCase):
    def test_catalog_lessons_and_actions_stay_in_sync(self) -> None:
        self.assertEqual(92, len(app_catalog.CATALOG))
        self.assertEqual(92, len(app_catalog.TOOL_KEYS))
        self.assertEqual(app_catalog.TOOL_KEYS, set(learning_catalog.LEARNING))
        self.assertEqual(len(learning_catalog.SOURCES), len({item["id"] for item in learning_catalog.SOURCES}))

        advanced = {item["id"] for item in app_catalog.CATALOG if item["category"] == "advanced"}
        security = {item["id"] for item in app_catalog.CATALOG if item["category"] == "security"}
        self.assertLessEqual(advanced, set(osint_tool.ADVANCED_ACTIONS))
        self.assertLessEqual(security, set(security_tools.SECURITY_ACTIONS))

    def test_ui_has_personalization_and_current_counts(self) -> None:
        web = Path(__file__).resolve().parent / "web"
        html = (web / "index.html").read_text(encoding="utf-8")
        script = (web / "app.js").read_text(encoding="utf-8")
        styles = (web / "styles.css").read_text(encoding="utf-8")
        for marker in ('id="tool-count-hero">92</b> TOOLS INDEXED', "DEFENSE / 50", 'data-filter="favorites"', 'data-filter="recent"', 'data-columns="5"', 'id="investigation-workbench"', 'id="neural-map"', 'id="workspace-dock"', 'id="session-progress"'):
            self.assertIn(marker, html)
        for marker in ("favoriteTools", "recentTools", "setColumns", "scheduleToolRender", "persistWorkspace", "scanImage", "searchNames", "startToolSession"):
            self.assertIn(marker, script)
        self.assertIn("content-visibility: auto", styles)
        self.assertIn("body.fixed-columns .tool-grid", styles)


class ToolSmokeTests(unittest.TestCase):
    def test_new_local_analysis_tools_complete_with_safe_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            first = root / "before.txt"
            second = root / "after.txt"
            image = root / "sample.png"
            first.write_text("alpha\nbeta\n", encoding="utf-8")
            second.write_text("alpha\ngamma\n", encoding="utf-8")
            image.write_bytes(b"\x89PNG\r\n\x1a\n" + b"0" * 32)

            inputs = [
                str(image),
                "Example.COM, 192.0.2.1, 192.0.2.1, https://Example.COM/path",
                str(first),
                str(second),
                "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0In0.",
            ]
            with patch.object(osint_tool.Prompt, "ask", side_effect=inputs), \
                    patch.object(osint_tool, "console", Mock()), \
                    patch.object(osint_tool, "pause", return_value=None):
                osint_tool.file_type_inspector()
                osint_tool.ioc_normalizer()
                osint_tool.text_file_compare()
                osint_tool.jwt_decoder()

    def test_new_security_audits_handle_empty_or_unavailable_results(self) -> None:
        checks = [
            security_tools.firewall_rule_review,
            security_tools.network_profile_audit,
            security_tools.uac_smartscreen_audit,
            security_tools.recovery_readiness_audit,
            security_tools.path_security_audit,
            security_tools.certificate_expiry_audit,
            security_tools.event_log_health_audit,
            security_tools.risky_windows_features_audit,
            security_tools.credential_guard_audit,
            security_tools.powershell_policy_audit,
        ]
        with patch.object(security_tools, "loading", side_effect=lambda _label, action: action()), \
                patch.object(security_tools, "powershell_json", return_value=[]), \
                patch.object(security_tools, "command", return_value=(0, "Windows RE status unavailable in test", "")), \
                patch.object(security_tools, "registry_value", return_value=None), \
                patch.object(security_tools, "table", return_value=None), \
                patch.object(security_tools, "pause", return_value=None), \
                patch("builtins.print"):
            for check in checks:
                check()


class ApiTests(unittest.TestCase):
    def test_workspace_and_session_inputs_are_sanitized(self) -> None:
        cleaned = app_server.clean_workspace_state({
            "favorite_tools": ["osint:1", "missing:999"],
            "graph": {"nodes": [{"id": "n1", "label": "Lead", "type": "person", "x": -50, "y": 900}],
                      "edges": [{"id": "bad", "source": "n1", "target": "missing"}]},
        })
        self.assertEqual(["osint:1"], cleaned["favorite_tools"])
        self.assertEqual(40.0, cleaned["graph"]["nodes"][0]["x"])
        self.assertEqual(388.0, cleaned["graph"]["nodes"][0]["y"])
        self.assertEqual([], cleaned["graph"]["edges"])
        with self.assertRaises(ValueError):
            app_server.start_tool_session("osint", "1", username="bad name")

    def test_catalog_and_learning_api(self) -> None:
        server = app_server.CrosServer(("127.0.0.1", 0), app_server.Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        host, port = server.server_address

        def get(path: str, token: str = app_server.TOKEN) -> tuple[int, dict]:
            request = urllib.request.Request(f"http://{host}:{port}{path}")
            if token:
                request.add_header("X-Cros-Token", token)
            with urllib.request.urlopen(request, timeout=5) as response:
                return response.status, json.loads(response.read().decode("utf-8"))

        try:
            self.assertEqual((200, True), (get("/api/health", token="")[0], get("/api/health", token="")[1]["ok"]))
            catalog_status, catalog = get("/api/catalog")
            learning_status, learning = get("/api/learning")
            self.assertEqual(200, catalog_status)
            self.assertEqual(92, catalog["count"])
            self.assertEqual(200, learning_status)
            self.assertEqual(92, learning["count"])
            with self.assertRaises(urllib.error.HTTPError) as denied:
                get("/api/catalog", token="wrong")
            self.assertEqual(403, denied.exception.code)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main(verbosity=2)
