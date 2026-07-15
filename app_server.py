"""Local-only desktop shell for Cros OSINT and defensive security tools."""

from __future__ import annotations

import concurrent.futures
import base64
import binascii
import json
import mimetypes
import os
import platform
import secrets
import struct
import subprocess
import sys
import threading
import time
import tempfile
import urllib.parse
import uuid
import webbrowser
import zlib
from collections import Counter
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from app_catalog import CATALOG, TOOL_KEYS
from learning_catalog import LEARNING, SOURCES
from image_analysis import analyze_image_file

APP_DIR = Path(__file__).resolve().parent
WEB_DIR = APP_DIR / "web"
TOKEN = secrets.token_urlsafe(24)
STARTED = time.monotonic()
LAST_SEEN = time.monotonic()
LAST_SEEN_LOCK = threading.Lock()
LEARNING_PROGRESS_FILE = APP_DIR / "learning_progress.json"
LEARNING_PROGRESS_LOCK = threading.Lock()
WORKSPACE_STATE_FILE = APP_DIR / "workspace_state.json"
WORKSPACE_STATE_LOCK = threading.Lock()
APP_ICON_FILE = WEB_DIR / "cros.ico"
APP_LOGO_FILE = WEB_DIR / "cros-logo.png"
APP_ICON_HANDLES: list[int] = []
def touch() -> None:
    global LAST_SEEN
    with LAST_SEEN_LOCK:
        LAST_SEEN = time.monotonic()


def read_learning_progress() -> list[str]:
    with LEARNING_PROGRESS_LOCK:
        try:
            value = json.loads(LEARNING_PROGRESS_FILE.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return []
    if not isinstance(value, list):
        return []
    return sorted({str(key) for key in value if str(key) in TOOL_KEYS})


def write_learning_progress(values: object) -> list[str]:
    if not isinstance(values, list):
        raise ValueError("Completed lessons must be a list")
    completed = sorted({str(key) for key in values if str(key) in TOOL_KEYS})
    temporary = LEARNING_PROGRESS_FILE.with_suffix(".tmp")
    with LEARNING_PROGRESS_LOCK:
        temporary.write_text(json.dumps(completed, indent=2), encoding="utf-8")
        os.replace(temporary, LEARNING_PROGRESS_FILE)
    return completed


def _short_text(value: object, limit: int) -> str:
    return str(value or "").strip()[:limit]


def clean_workspace_state(value: object) -> dict:
    source = value if isinstance(value, dict) else {}
    pins = []
    for item in source.get("pins", []) if isinstance(source.get("pins"), list) else []:
        if not isinstance(item, dict) or len(pins) >= 100:
            continue
        pin_id = _short_text(item.get("id"), 100)
        if not pin_id:
            continue
        pins.append({
            "id": pin_id,
            "title": _short_text(item.get("title"), 80),
            "target": _short_text(item.get("target"), 2048),
            "note": _short_text(item.get("note"), 240),
            "priority": bool(item.get("priority")),
            "created": int(item.get("created", 0)) if str(item.get("created", 0)).isdigit() else 0,
        })

    favorites = []
    for key in source.get("favorite_tools", []) if isinstance(source.get("favorite_tools"), list) else []:
        key = str(key)
        if key in TOOL_KEYS and key not in favorites:
            favorites.append(key)
    recent = []
    for key in source.get("recent_tools", []) if isinstance(source.get("recent_tools"), list) else []:
        key = str(key)
        if key in TOOL_KEYS and key not in recent:
            recent.append(key)

    graph_source = source.get("graph") if isinstance(source.get("graph"), dict) else {}
    nodes = []
    node_ids = set()
    for item in graph_source.get("nodes", []) if isinstance(graph_source.get("nodes"), list) else []:
        if not isinstance(item, dict) or len(nodes) >= 150:
            continue
        node_id = _short_text(item.get("id"), 100)
        label = _short_text(item.get("label"), 80)
        if not node_id or not label or node_id in node_ids:
            continue
        try:
            x = min(960.0, max(40.0, float(item.get("x", 500))))
            y = min(520.0, max(40.0, float(item.get("y", 280))))
        except (TypeError, ValueError):
            x, y = 500.0, 280.0
        node_ids.add(node_id)
        nodes.append({"id": node_id, "label": label, "type": _short_text(item.get("type"), 24) or "entity",
                      "note": _short_text(item.get("note"), 300), "x": x, "y": y})

    edges = []
    edge_ids = set()
    for item in graph_source.get("edges", []) if isinstance(graph_source.get("edges"), list) else []:
        if not isinstance(item, dict) or len(edges) >= 300:
            continue
        edge_id = _short_text(item.get("id"), 100)
        source_id = _short_text(item.get("source"), 100)
        target_id = _short_text(item.get("target"), 100)
        if not edge_id or edge_id in edge_ids or source_id == target_id or source_id not in node_ids or target_id not in node_ids:
            continue
        edge_ids.add(edge_id)
        edges.append({"id": edge_id, "source": source_id, "target": target_id,
                      "label": _short_text(item.get("label"), 60)})
    return {"pins": pins, "favorite_tools": favorites, "recent_tools": recent[:12],
            "graph": {"nodes": nodes, "edges": edges}}


def read_workspace_state() -> dict:
    with WORKSPACE_STATE_LOCK:
        try:
            value = json.loads(WORKSPACE_STATE_FILE.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            value = {}
    return clean_workspace_state(value)


def write_workspace_state(value: object) -> dict:
    cleaned = clean_workspace_state(value)
    temporary = WORKSPACE_STATE_FILE.with_suffix(".tmp")
    with WORKSPACE_STATE_LOCK:
        temporary.write_text(json.dumps(cleaned, indent=2, ensure_ascii=False), encoding="utf-8")
        os.replace(temporary, WORKSPACE_STATE_FILE)
    return cleaned


def console_python() -> str:
    executable = Path(sys.executable)
    if executable.name.lower() == "pythonw.exe":
        console = executable.with_name("python.exe")
        if console.is_file(): return str(console)
    return str(executable)


def open_pinned_target(raw_target: object) -> None:
    target = str(raw_target or "").strip()
    if not target or len(target) > 2048:
        raise ValueError("The pin does not contain a valid target")
    parsed = urllib.parse.urlsplit(target)
    if parsed.scheme.lower() in {"http", "https", "mailto"}:
        if not webbrowser.open(target):
            raise OSError("Windows could not open that link")
        return
    path = Path(os.path.expandvars(os.path.expanduser(target)))
    if not path.exists():
        raise ValueError("That file or folder does not exist")
    os.startfile(str(path.resolve()))  # type: ignore[attr-defined]


def name_search_payload(raw_query: object) -> dict:
    query = _short_text(raw_query, 100)
    if not query:
        raise ValueError("Enter a name or username")
    username = query.lstrip("@").strip()
    if not all(char.isalnum() or char in "._-" for char in username) or len(username) > 64:
        username = ""
    variants = []
    if username and " " not in query:
        chunks = [part for part in username.lower().replace("-", ".").replace("_", ".").split(".") if part]
        compact = "".join(chunks)
        for candidate in [username.lower(), compact, ".".join(chunks), "_".join(chunks), "-".join(chunks),
                          f"the{compact}", f"real{compact}", f"{compact}official"]:
            if candidate and candidate not in variants:
                variants.append(candidate)
    encoded = urllib.parse.quote_plus(query)
    searches = [
        {"name": "Google", "url": f"https://www.google.com/search?q={encoded}"},
        {"name": "Bing", "url": f"https://www.bing.com/search?q={encoded}"},
        {"name": "DuckDuckGo", "url": f"https://duckduckgo.com/?q={encoded}"},
        {"name": "GitHub code and profiles", "url": f"https://github.com/search?q={encoded}&type=users"},
    ]
    profiles = []
    if username:
        profiles = [
            {"name": "GitHub", "url": f"https://github.com/{username}"},
            {"name": "Reddit", "url": f"https://www.reddit.com/user/{username}"},
            {"name": "X", "url": f"https://x.com/{username}"},
            {"name": "Instagram", "url": f"https://www.instagram.com/{username}/"},
            {"name": "TikTok", "url": f"https://www.tiktok.com/@{username}"},
            {"name": "YouTube", "url": f"https://www.youtube.com/@{username}"},
        ]
    return {"query": query, "variants": variants[:12], "profiles": profiles, "searches": searches,
            "notice": "Candidate links are leads, not confirmed identity matches. Compare multiple public details before connecting accounts."}


ALLOWED_WEB_HOSTS = {
    "google.com", "www.google.com", "lens.google.com", "bing.com", "www.bing.com", "duckduckgo.com",
    "github.com", "reddit.com", "www.reddit.com", "x.com", "instagram.com", "www.instagram.com",
    "tiktok.com", "www.tiktok.com", "youtube.com", "www.youtube.com", "yandex.com", "yandex.ru",
}


def open_allowed_web_url(raw_url: object) -> None:
    url = _short_text(raw_url, 2048)
    parsed = urllib.parse.urlsplit(url)
    host = (parsed.hostname or "").lower()
    if parsed.scheme != "https" or host not in ALLOWED_WEB_HOSTS:
        raise ValueError("That web destination is not in the research allowlist")
    if not webbrowser.open(url):
        raise OSError("Windows could not open that research page")


def analyze_uploaded_image(body: dict) -> dict:
    encoded = str(body.get("data", ""))
    if encoded.startswith("data:"):
        encoded = encoded.partition(",")[2]
    if not encoded or len(encoded) > 16_000_000:
        raise ValueError("Choose an image smaller than 10 MB")
    try:
        data = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("The image data is invalid") from exc
    if not data or len(data) > 10_000_000:
        raise ValueError("Choose an image smaller than 10 MB")
    suffix = Path(_short_text(body.get("name"), 120)).suffix.lower()
    if suffix not in {".jpg", ".jpeg", ".png", ".webp", ".gif", ".bmp", ".tif", ".tiff"}:
        suffix = ".img"
    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(prefix="cros-image-", suffix=suffix, delete=False) as temporary:
            temporary.write(data)
            temporary_path = Path(temporary.name)
        return analyze_image_file(temporary_path, include_thumbnail=True)
    finally:
        if temporary_path:
            try: temporary_path.unlink(missing_ok=True)
            except OSError: pass


def fallback_icon_bytes() -> bytes:
    size = 64
    rows = []
    for y in range(size):
        row = bytearray([0])
        for x in range(size):
            distance = abs(x - 31.5) + abs(y - 31.5)
            red, green, blue, alpha = (0, 0, 0, 0)
            if distance <= 28:
                red, green, blue, alpha = (12, 13, 27, 255)
            if 24.5 <= distance <= 28.5:
                red, green, blue, alpha = (133, 102, 255, 255)
            radius = ((x - 31.5) ** 2 + (y - 31.5) ** 2) ** 0.5
            if 10.5 <= radius <= 15.5 and not (x > 32 and abs(y - 31.5) < 8):
                red, green, blue, alpha = (244, 242, 250, 255)
            row.extend((red, green, blue, alpha))
        rows.append(bytes(row))

    def chunk(kind: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", binascii.crc32(kind + data) & 0xFFFFFFFF)

    png = b"\x89PNG\r\n\x1a\n"
    png += chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0))
    png += chunk(b"IDAT", zlib.compress(b"".join(rows), 9))
    png += chunk(b"IEND", b"")
    header = struct.pack("<HHH", 0, 1, 1)
    entry = struct.pack("<BBBBHHII", size, size, 0, 0, 1, 32, len(png), 22)
    return header + entry + png


def render_logo_icon_bytes() -> bytes | None:
    """Build a multi-size Windows icon from the project logo when Pillow is available."""
    if not APP_LOGO_FILE.is_file():
        return None
    try:
        from io import BytesIO
        from PIL import Image

        with Image.open(APP_LOGO_FILE) as source:
            image = source.convert("RGBA")
            side = min(image.size)
            left = (image.width - side) // 2
            top = (image.height - side) // 2
            image = image.crop((left, top, left + side, top + side))
            output = BytesIO()
            image.save(output, format="ICO", sizes=[
                (16, 16), (24, 24), (32, 32), (48, 48),
                (64, 64), (128, 128), (256, 256),
            ])
            return output.getvalue()
    except (ImportError, OSError, ValueError):
        return None


def ensure_app_icon() -> Path | None:
    try:
        logo_is_newer = (
            APP_LOGO_FILE.is_file()
            and (
                not APP_ICON_FILE.is_file()
                or APP_LOGO_FILE.stat().st_mtime_ns > APP_ICON_FILE.stat().st_mtime_ns
            )
        )
        if logo_is_newer:
            rendered = render_logo_icon_bytes()
            if rendered:
                APP_ICON_FILE.write_bytes(rendered)
        if not APP_ICON_FILE.is_file():
            APP_ICON_FILE.write_bytes(fallback_icon_bytes())
        return APP_ICON_FILE
    except OSError:
        return None


def app_icon_bytes() -> bytes:
    icon_path = ensure_app_icon()
    if icon_path:
        try:
            return icon_path.read_bytes()
        except OSError:
            pass
    return fallback_icon_bytes()


def set_cros_window_identity(hwnd: int, icon_path: Path) -> bool:
    """Give the browser-hosted window its own Windows taskbar identity."""
    if os.name != "nt":
        return False
    try:
        import ctypes
        from ctypes import wintypes

        class GUID(ctypes.Structure):
            _fields_ = [
                ("Data1", ctypes.c_ulong),
                ("Data2", ctypes.c_ushort),
                ("Data3", ctypes.c_ushort),
                ("Data4", ctypes.c_ubyte * 8),
            ]

            @classmethod
            def parse(cls, value: str):
                return cls.from_buffer_copy(uuid.UUID(value).bytes_le)

        class PROPERTYKEY(ctypes.Structure):
            _fields_ = [("fmtid", GUID), ("pid", ctypes.c_ulong)]

        class PROPVARIANT_VALUE(ctypes.Union):
            _fields_ = [("pwszVal", ctypes.c_wchar_p), ("padding", ctypes.c_ubyte * 16)]

        class PROPVARIANT(ctypes.Structure):
            _anonymous_ = ("value",)
            _fields_ = [
                ("vt", ctypes.c_ushort),
                ("reserved1", ctypes.c_ushort),
                ("reserved2", ctypes.c_ushort),
                ("reserved3", ctypes.c_ushort),
                ("value", PROPVARIANT_VALUE),
            ]

        iid_property_store = GUID.parse("886D8EEB-8CF2-4446-8D02-CDBA1DBDCF99")
        app_model_fmtid = GUID.parse("9F4C2855-9F79-4B39-A8D0-E1D42DE1D5F3")
        ole32 = ctypes.windll.ole32
        shell32 = ctypes.windll.shell32
        initialized = ole32.CoInitializeEx(None, 0x2)
        should_uninitialize = initialized in (0, 1)
        try:
            store = ctypes.c_void_p()
            get_store = shell32.SHGetPropertyStoreForWindow
            get_store.argtypes = [wintypes.HWND, ctypes.POINTER(GUID), ctypes.POINTER(ctypes.c_void_p)]
            get_store.restype = ctypes.c_long
            if get_store(wintypes.HWND(hwnd), ctypes.byref(iid_property_store), ctypes.byref(store)) < 0:
                return False
            if not store.value:
                return False

            vtable = ctypes.cast(store, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p))).contents
            release = ctypes.WINFUNCTYPE(ctypes.c_ulong, ctypes.c_void_p)(vtable[2])
            set_value = ctypes.WINFUNCTYPE(
                ctypes.c_long, ctypes.c_void_p, ctypes.POINTER(PROPERTYKEY), ctypes.POINTER(PROPVARIANT)
            )(vtable[6])
            commit = ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_void_p)(vtable[7])
            try:
                for property_id, text in (
                    (5, "Cros.IntelligenceConsole"),
                    (3, f"{icon_path},0"),
                ):
                    key = PROPERTYKEY(app_model_fmtid, property_id)
                    buffer = ctypes.create_unicode_buffer(text)
                    value = PROPVARIANT()
                    value.vt = 31  # VT_LPWSTR
                    value.pwszVal = ctypes.cast(buffer, ctypes.c_wchar_p)
                    if set_value(store, ctypes.byref(key), ctypes.byref(value)) < 0:
                        return False
                return commit(store) >= 0
            finally:
                release(store)
        finally:
            if should_uninitialize:
                ole32.CoUninitialize()
    except (AttributeError, OSError, TypeError, ValueError):
        return False


def apply_cros_window_icon(icon_path: Path) -> None:
    if os.name != "nt":
        return
    try:
        import ctypes
        from ctypes import wintypes

        user32 = ctypes.windll.user32
        load_image = user32.LoadImageW
        load_image.argtypes = [wintypes.HINSTANCE, wintypes.LPCWSTR, wintypes.UINT,
                               ctypes.c_int, ctypes.c_int, wintypes.UINT]
        load_image.restype = wintypes.HANDLE
        large_handle = load_image(None, str(icon_path), 1, 256, 256, 0x0010)
        small_handle = load_image(None, str(icon_path), 1, 16, 16, 0x0010)
        if not large_handle and not small_handle:
            return
        large_handle = large_handle or small_handle
        small_handle = small_handle or large_handle
        APP_ICON_HANDLES.extend((int(large_handle), int(small_handle)))
        callback_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
        identified_windows: set[int] = set()

        # Edge can reset its icon while the app page finishes loading. Reapply
        # briefly so the Cros mark wins instead of the generic Edge badge.
        for _ in range(48):
            matches: list[int] = []

            def find_window(hwnd, _lparam):
                length = user32.GetWindowTextLengthW(hwnd)
                if length:
                    buffer = ctypes.create_unicode_buffer(length + 1)
                    user32.GetWindowTextW(hwnd, buffer, length + 1)
                    if "Cros // Intelligence Console" in buffer.value:
                        matches.append(int(hwnd))
                return True

            user32.EnumWindows(callback_type(find_window), 0)
            if matches:
                for hwnd in matches:
                    user32.SendMessageW(hwnd, 0x0080, 1, large_handle)
                    user32.SendMessageW(hwnd, 0x0080, 0, small_handle)
                    if hwnd not in identified_windows and set_cros_window_identity(hwnd, icon_path):
                        identified_windows.add(hwnd)
                        # Recreate the taskbar button after the dedicated AppID
                        # is set, preventing it from remaining grouped as Edge.
                        user32.ShowWindow(hwnd, 0)
                        user32.ShowWindow(hwnd, 3)
            time.sleep(0.25)
    except (AttributeError, OSError, ValueError):
        return


def launch_tool(category: str, tool_id: str) -> None:
    if category == "terminal" and tool_id == "main":
        allowed = True
    else:
        allowed = f"{category}:{tool_id}" in TOOL_KEYS
    if not allowed: raise ValueError("Tool is not in the local allowlist")
    flags = getattr(subprocess, "CREATE_NEW_CONSOLE", 0)
    env = os.environ.copy()
    env["PYTHONUTF8"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    subprocess.Popen(
        [console_python(), str(APP_DIR / "tool_runner.py"), category, tool_id],
        cwd=str(APP_DIR), env=env, creationflags=flags, close_fds=True,
    )


def status_payload() -> dict:
    import security_tools

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        posture_future = pool.submit(security_tools.collect_protection_posture)
        process_future = pool.submit(security_tools.collect_processes)
        connection_future = pool.submit(security_tools.collect_connections)
        startup_future = pool.submit(security_tools.collect_startup)
        posture = posture_future.result()
        processes = process_future.result()
        connections = connection_future.result()
        startup = startup_future.result()

    result_counts = Counter(str(row[1]) for row in posture)
    established = sum(1 for row in connections if str(row.get("State", "")).lower() == "established")
    listening = sum(1 for row in connections if str(row.get("State", "")).lower() in {"listen", "listening"})
    return {
        "machine": os.environ.get("COMPUTERNAME", platform.node()) or "LOCAL MACHINE",
        "platform": f"Windows {platform.release()}",
        "checked_at": datetime.now().astimezone().strftime("%I:%M:%S %p"),
        "uptime_seconds": int(time.monotonic() - STARTED),
        "summary": {
            "pass": result_counts.get("PASS", 0),
            "review": result_counts.get("REVIEW", 0),
            "unknown": result_counts.get("UNKNOWN", 0),
            "processes": len(processes),
            "connections": len(connections),
            "established": established,
            "listening": listening,
            "startup": len(startup),
        },
        "posture": [
            {"check": str(row[0]), "result": str(row[1]), "detail": str(row[2])}
            for row in posture
        ],
    }


def open_local_app(url: str) -> None:
    icon_path = ensure_app_icon()
    candidates = []
    for base in (os.environ.get("PROGRAMFILES(X86)"), os.environ.get("PROGRAMFILES"), os.environ.get("LOCALAPPDATA")):
        if not base: continue
        root = Path(base)
        candidates += [
            root / "Microsoft" / "Edge" / "Application" / "msedge.exe",
            root / "Google" / "Chrome" / "Application" / "chrome.exe",
        ]
    for browser in candidates:
        try:
            if browser.is_file():
                subprocess.Popen([str(browser), f"--app={url}", "--start-maximized"], close_fds=True)
                if icon_path:
                    threading.Thread(target=apply_cros_window_icon, args=(icon_path,), daemon=True).start()
                return
        except OSError:
            pass
    webbrowser.open(url)


class CrosServer(ThreadingHTTPServer):
    daemon_threads = True


class Handler(BaseHTTPRequestHandler):
    server_version = "CrosLocal/1.0"

    def log_message(self, *_args) -> None:
        return

    def end_headers(self) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
            "connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'",
        )
        super().end_headers()

    def json_response(self, value: object, status: int = 200) -> None:
        data = json.dumps(value, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def authorized(self) -> bool:
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
        supplied = self.headers.get("X-Cros-Token", "") or query.get("token", [""])[0]
        return secrets.compare_digest(str(supplied), TOKEN)

    def read_json(self, limit: int = 262_144) -> dict:
        try: length = min(int(self.headers.get("Content-Length", "0")), limit)
        except ValueError: length = 0
        if not length: return {}
        try: value = json.loads(self.rfile.read(length).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError): return {}
        return value if isinstance(value, dict) else {}

    def do_GET(self) -> None:
        touch()
        route = urllib.parse.urlsplit(self.path).path
        if route == "/api/health":
            self.json_response({"ok": True, "app": "cros-local"})
            return
        if route == "/api/catalog":
            if not self.authorized(): self.json_response({"error": "unauthorized"}, 403); return
            self.json_response({"tools": CATALOG, "count": len(CATALOG)})
            return
        if route == "/api/learning":
            if not self.authorized(): self.json_response({"error": "unauthorized"}, 403); return
            self.json_response({"lessons": LEARNING, "sources": SOURCES, "count": len(LEARNING),
                                "completed": read_learning_progress()})
            return
        if route == "/api/workspace":
            if not self.authorized(): self.json_response({"error": "unauthorized"}, 403); return
            self.json_response(read_workspace_state())
            return
        if route == "/api/status":
            if not self.authorized(): self.json_response({"error": "unauthorized"}, 403); return
            try: self.json_response(status_payload())
            except Exception as exc: self.json_response({"error": str(exc)}, 500)
            return

        if route == "/favicon.ico":
            data = app_icon_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "image/x-icon")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return

        files = {
            "/": "index.html",
            "/index.html": "index.html",
            "/styles.css": "styles.css",
            "/app.js": "app.js",
            "/app-icon.png": "cros-logo.png",
            "/manifest.json": "manifest.json",
        }
        name = files.get(route)
        if not name:
            self.send_error(404)
            return
        path = WEB_DIR / name
        try: data = path.read_bytes()
        except OSError:
            self.send_error(404)
            return
        content_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        self.send_response(200)
        self.send_header("Content-Type", content_type + ("; charset=utf-8" if content_type.startswith("text/") or "javascript" in content_type else ""))
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self) -> None:
        touch()
        if not self.authorized(): self.json_response({"error": "unauthorized"}, 403); return
        route = urllib.parse.urlsplit(self.path).path
        body = self.read_json(16_500_000 if route == "/api/image-analyze" else 262_144)
        if route == "/api/name-search":
            try: self.json_response(name_search_payload(body.get("query")))
            except ValueError as exc: self.json_response({"error": str(exc)}, 400)
            return
        if route == "/api/image-analyze":
            try: self.json_response(analyze_uploaded_image(body))
            except (OSError, RuntimeError, ValueError) as exc: self.json_response({"error": str(exc)}, 400)
            return
        if route == "/api/open-url":
            try:
                open_allowed_web_url(body.get("url"))
                self.json_response({"ok": True})
            except ValueError as exc: self.json_response({"error": str(exc)}, 400)
            except OSError as exc: self.json_response({"error": str(exc)}, 500)
            return
        if route == "/api/launch":
            category = str(body.get("category", "")).lower().strip()
            tool_id = str(body.get("id", "")).strip()
            try:
                launch_tool(category, tool_id)
                self.json_response({"ok": True, "launched": f"{category}:{tool_id}"})
            except (OSError, ValueError) as exc:
                self.json_response({"error": str(exc)}, 400)
            return
        if route == "/api/open":
            allowed = {"folder": APP_DIR}
            target = allowed.get(str(body.get("target", "")))
            if target is None: self.json_response({"error": "invalid target"}, 400); return
            try:
                os.startfile(target)  # type: ignore[attr-defined]
                self.json_response({"ok": True})
            except OSError as exc:
                self.json_response({"error": str(exc)}, 500)
            return
        if route == "/api/learning-progress":
            try:
                completed = write_learning_progress(body.get("completed", []))
                self.json_response({"ok": True, "completed": completed})
            except (OSError, ValueError) as exc:
                self.json_response({"error": str(exc)}, 400)
            return
        if route == "/api/workspace":
            try:
                self.json_response(write_workspace_state(body))
            except OSError as exc:
                self.json_response({"error": str(exc)}, 500)
            return
        if route == "/api/open-pinned":
            try:
                open_pinned_target(body.get("target"))
                self.json_response({"ok": True})
            except ValueError as exc:
                self.json_response({"error": str(exc)}, 400)
            except OSError as exc:
                self.json_response({"error": str(exc)}, 500)
            return
        if route == "/api/ping":
            self.json_response({"ok": True})
            return
        if route == "/api/shutdown":
            self.json_response({"ok": True})
            threading.Thread(target=self.server.shutdown, daemon=True).start()
            return
        self.send_error(404)


def main() -> None:
    server = CrosServer(("127.0.0.1", 0), Handler)
    host, port = server.server_address
    url = f"http://{host}:{port}/?token={urllib.parse.quote(TOKEN)}"

    def idle_monitor():
        while True:
            time.sleep(30)
            with LAST_SEEN_LOCK: idle = time.monotonic() - LAST_SEEN
            if idle > 240:
                server.shutdown()
                return

    threading.Thread(target=idle_monitor, daemon=True).start()
    threading.Thread(target=lambda: (time.sleep(0.25), open_local_app(url)), daemon=True).start()
    try: server.serve_forever(poll_interval=0.5)
    finally: server.server_close()


if __name__ == "__main__":
    main()
