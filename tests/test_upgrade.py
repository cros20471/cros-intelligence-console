"""Focused regression checks for the expanded Cros catalog and local app surface."""

from __future__ import annotations

import json
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

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
        osint = {item["id"] for item in app_catalog.CATALOG if item["category"] == "osint"}
        security = {item["id"] for item in app_catalog.CATALOG if item["category"] == "security"}
        self.assertLessEqual(osint, set(osint_tool.MAIN_ACTIONS))
        self.assertLessEqual(advanced, set(osint_tool.ADVANCED_ACTIONS))
        self.assertLessEqual(security, set(security_tools.SECURITY_ACTIONS))

    def test_ui_has_personalization_and_current_counts(self) -> None:
        web = ROOT / "web"
        html = (web / "index.html").read_text(encoding="utf-8")
        script = (web / "app.js").read_text(encoding="utf-8")
        styles = (web / "styles.css").read_text(encoding="utf-8")
        for marker in ('id="tool-count-hero">92</b> TOOLS INDEXED', "DEFENSE / 50", 'data-filter="favorites"', 'data-filter="recent"', 'data-columns="5"', 'id="investigation-workbench"', 'id="neural-map"', 'id="workspace-dock"', 'id="session-progress"', 'id="session-app-results"', 'id="session-socials"', 'id="session-view-map"', 'id="workspace-customize"', 'id="workspace-width-control"', 'data-workspace-tab-size="large"'):
            self.assertIn(marker, html)
        for marker in ("favoriteTools", "recentTools", "setColumns", "scheduleToolRender", "persistWorkspace", "scanImage", "searchNames", "startToolSession", "addSocialToMap", "renderSessionSocialResults", "renderSessionAppResults", "setWorkspaceTabSize", "setWorkspaceHomeView"):
            self.assertIn(marker, script)
        self.assertIn('id="session-log" hidden', html)
        self.assertIn('id="session-advanced-toggle" hidden', html)
        self.assertNotIn('id="terminal-button"', html)
        self.assertNotIn('$("#session-log").hidden = Boolean(options.hideOutput)', script)
        for marker in ("native-paste-form", "native-search-builder", "native-coordinate-form", "native-hash-reputation-form", "runNativeDiagnostics"):
            self.assertIn(marker, script)
        for marker in ('data-logo-style="signal"', 'data-logo-style="scope"', 'data-logo-style="shield"', 'id="custom-logo-file"', 'class="settings-jump-nav"'):
            self.assertIn(marker, html)
        self.assertNotIn('data-logo-style="prism"', html)
        for marker in ("changeLogoStyle", "useCustomLogo", "cros-logo-style"):
            self.assertIn(marker, script)
        self.assertIn("content-visibility: auto", styles)
        self.assertIn("body.fixed-columns .tool-grid", styles)

    def test_window_identity_targets_the_real_app_title(self) -> None:
        source = (ROOT / "app_server.py").read_text(encoding="utf-8")
        self.assertIn('buffer.value.startswith("Cros // Intelligence Center")', source)
        self.assertNotIn('"Cros // Intelligence Console" in buffer.value', source)

    def test_logo_presets_render_as_real_png_images(self) -> None:
        for preset in ("signal", "scope", "shield", "mono"):
            rendered = app_server.render_logo_preset(preset)
            self.assertTrue(rendered.startswith(b"\x89PNG\r\n\x1a\n"), preset)
            self.assertGreater(len(rendered), 1_000, preset)
        cleaned = app_server.clean_appearance_state({"cros-logo-style": "scope"})
        self.assertEqual("scope", cleaned["cros-logo-style"])
        self.assertNotIn("prism", app_server.LOGO_PRESETS)
        self.assertRegex(app_server.versioned_app_icon_path().name, r"^cros-icon-[0-9a-f]{12}\.ico$")


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
    def test_blackbird_social_results_only_returns_found_social_sites(self) -> None:
        output = (
            "  \u2714\ufe0f  [Instagram] https://www.instagram.com/example/\n"
            "  \u2714  [GitHub] https://github.com/example\n"
            "  \u2713  [Reddit] https://www.reddit.com/user/example\n"
            "  \u2714  [YouTube Channel] https://www.youtube.com/c/example/about\n"
            "  \u2714  [Instagram] https://www.instagram.com/example/\n"
            "  \u2714  [Instagram] javascript:alert(1)\n"
        )
        with patch.object(app_server, "BLACKBIRD_SOCIAL_NAMES", frozenset({"instagram", "reddit"})):
            results = app_server.blackbird_social_results(output, "example")
        self.assertEqual([
            {"platform": "Instagram", "url": "https://www.instagram.com/example/", "username": "example"},
            {"platform": "GitHub", "url": "https://github.com/example", "username": "example"},
            {"platform": "Reddit", "url": "https://www.reddit.com/user/example", "username": "example"},
            {"platform": "YouTube Channel", "url": "https://www.youtube.com/c/example/about", "username": "example"},
        ], results)

    def test_blackbird_engine_packages_are_scoped_to_python_abi(self) -> None:
        self.assertEqual(osint_tool.ENGINE_DEPS_DIR / osint_tool.sys.implementation.cache_tag,
                         osint_tool.engine_runtime_dir())

    def test_visual_diagnostics_reports_local_app_health(self) -> None:
        payload = app_server.local_diagnostics_payload()
        labels = {item["label"] for item in payload["checks"]}
        self.assertTrue({"Desktop app", "Python runtime", "Username engines", "Network binding"} <= labels)
        self.assertGreaterEqual(len(payload["providers"]), 4)

    def test_console_oriented_output_becomes_app_result_data(self) -> None:
        result = app_server.session_display_results(
            "Domain or URL: \nExternal research link (copy when needed):\n"
            "https://web.archive.org/web/*/example.com\n"
        )
        self.assertEqual([{
            "label": "Open website history",
            "url": "https://web.archive.org/web/*/example.com",
            "host": "web.archive.org",
        }], result["links"])
        self.assertEqual([], result["facts"])
        self.assertEqual([], result["findings"])

        hash_result = app_server.session_display_results(
            "Hash value: +--------- Hash Identifier ---------+\n"
            "| Length: 32 hexadecimal characters |\n"
            "| Likely type: MD5 or NTLM |\n"
            "+-----------------------------------+\n"
            "Length identifies possible formats, not a guaranteed algorithm.\n"
        )
        self.assertEqual([
            {"label": "Length", "value": "32 hexadecimal characters"},
            {"label": "Likely type", "value": "MD5 or NTLM"},
        ], hash_result["facts"])
        self.assertEqual(["Length identifies possible formats, not a guaranteed algorithm."], hash_result["findings"])

    def test_session_result_opener_only_accepts_an_exact_live_return(self) -> None:
        session_id = "result-open-test"
        live_url = "https://github.com/example"
        session = {
            "category": "osint",
            "username": "example",
            "output": f"  \u2714  [GitHub] {live_url}\n",
        }
        with app_server.TOOL_SESSIONS_LOCK:
            app_server.TOOL_SESSIONS[session_id] = session
        try:
            with patch.object(app_server.webbrowser, "open", return_value=True) as opener:
                app_server.open_session_result(session_id, live_url)
                opener.assert_called_once_with(live_url)
            with self.assertRaises(ValueError):
                app_server.open_session_result(session_id, "https://example.com/not-returned")
        finally:
            with app_server.TOOL_SESSIONS_LOCK:
                app_server.TOOL_SESSIONS.pop(session_id, None)

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

    def test_embedded_prompt_detection_only_flags_live_prompts(self) -> None:
        self.assertEqual("Full path to a file:", app_server._pending_session_prompt("Full path to a file: ", False))
        self.assertEqual("", app_server._pending_session_prompt("Scan complete\n", False))
        self.assertEqual("", app_server._pending_session_prompt("Full path to a file: ", True))

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
