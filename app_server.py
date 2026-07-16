"""Local-only desktop shell for Cros OSINT and defensive security tools."""

from __future__ import annotations

import concurrent.futures
import base64
import binascii
import codecs
import ctypes
import hashlib
import json
import mimetypes
import os
import platform
import re
import secrets
import shutil
import ssl
import struct
import subprocess
import sys
import threading
import time
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import uuid
import webbrowser
import zlib
import zipfile
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
APPEARANCE_STATE_FILE = APP_DIR / "appearance_state.json"
APPEARANCE_STATE_LOCK = threading.Lock()
KEY_VAULT_FILE = APP_DIR / "local_key_vault.json"
KEY_VAULT_LOCK = threading.Lock()
# OSINT Dog's edge currently rejects the default Python 3.14 cipher offer on
# some Windows installations. Keep certificate verification enabled while
# allowing a compatible TLS 1.2 cipher set for this provider only.
OSINT_DOG_SSL_CONTEXT = ssl.create_default_context()
OSINT_DOG_SSL_CONTEXT.minimum_version = ssl.TLSVersion.TLSv1_2
try:
    OSINT_DOG_SSL_CONTEXT.set_ciphers("DEFAULT:@SECLEVEL=1")
except ssl.SSLError:
    pass
APP_ICON_FILE = WEB_DIR / "cros.ico"
APP_LOGO_FILE = WEB_DIR / "cros-logo.png"
APP_ICON_HANDLES: list[int] = []
TOOL_SESSIONS: dict[str, dict] = {}
TOOL_SESSIONS_LOCK = threading.Lock()
ANSI_ESCAPE = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))")
# Match the stable platform + URL portion; terminal status glyph encoding varies.
BLACKBIRD_FOUND_RE = re.compile(r"\[([^\]\r\n]{1,100})\]\s+(https?://[^\s\r\n]+)")
EMAIL_FOUND_RE = re.compile(r"\b[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+\b")
BLACKBIRD_SOCIAL_NAMES: frozenset[str] | None = None


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


def blackbird_social_names() -> frozenset[str]:
    global BLACKBIRD_SOCIAL_NAMES
    if BLACKBIRD_SOCIAL_NAMES is not None:
        return BLACKBIRD_SOCIAL_NAMES
    names: set[str] = set()
    data_file = APP_DIR / "blackbird" / "data" / "wmn-data.json"
    try:
        value = json.loads(data_file.read_text(encoding="utf-8"))
        for site in value.get("sites", []) if isinstance(value, dict) else []:
            if isinstance(site, dict) and str(site.get("cat", "")).lower() == "social":
                name = _short_text(site.get("name"), 100).lower()
                if name:
                    names.add(name)
    except (OSError, json.JSONDecodeError):
        pass
    BLACKBIRD_SOCIAL_NAMES = frozenset(names)
    return BLACKBIRD_SOCIAL_NAMES


def blackbird_social_results(output: str, username: str) -> list[dict[str, str]]:
    if not username:
        return []
    known_social_names = blackbird_social_names()
    results = []
    seen = set()
    for match in BLACKBIRD_FOUND_RE.finditer(output):
        platform = _short_text(match.group(1), 100)
        url = _short_text(match.group(2).rstrip(".,;)]}"), 2048)
        try:
            parsed = urllib.parse.urlsplit(url)
        except ValueError:
            continue
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            continue
        # Prefer Blackbird's current site catalog so generic URLs (for
        # example GitHub or a documentation page) do not become social leads.
        # If the catalog is unavailable, keep the live labeled result rather
        # than making the whole in-app account search appear empty.
        if known_social_names and platform.lower() not in known_social_names:
            continue
        key = (platform.lower(), url.lower())
        if key in seen:
            continue
        seen.add(key)
        results.append({"platform": platform, "url": url, "username": username})
        if len(results) >= 200:
            break
    # Some Blackbird versions stream only the checked URL (without a
    # [Platform] label). Recover those live results from the hostname so the
    # in-app result card and map action are still available.
    known_urls = {item["url"].lower() for item in results}
    for raw_url in re.findall(r"https?://[^\s\r\n]+", output):
        url = _short_text(raw_url.rstrip(".,;)]}"), 2048)
        try:
            parsed = urllib.parse.urlsplit(url)
        except ValueError:
            continue
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or url.lower() in known_urls:
            continue
        host_parts = parsed.hostname.lower().split(".")
        platform = host_parts[-2].replace("-", " ").title() if len(host_parts) >= 2 else parsed.hostname
        if known_social_names and platform.lower() not in known_social_names:
            continue
        results.append({"platform": platform, "url": url, "username": username})
        known_urls.add(url.lower())
        if len(results) >= 200:
            break
    return results


def blackbird_email_results(output: str) -> list[str]:
    """Return distinct email-shaped strings shown by live engine output."""
    results = []
    seen = set()
    for match in EMAIL_FOUND_RE.finditer(output):
        value = match.group(0).strip(".,;:[](){}<>\"").lower()
        if value not in seen and len(value) <= 254:
            seen.add(value)
            results.append(value)
        if len(results) >= 100:
            break
    return results


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
            y = min(388.0, max(32.0, float(item.get("y", 210))))
        except (TypeError, ValueError):
            x, y = 500.0, 210.0
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


APPEARANCE_KEYS = {
    "cros-accent", "cros-custom-accent", "cros-background", "cros-star-color", "cros-particles",
    "cros-wings", "cros-compact", "cros-animations", "cros-glow", "cros-motion", "cros-particle-density",
    "cros-light-smoothing", "cros-star-brightness", "cros-shape", "cros-columns", "cros-rail-autoclose",
    "cros-operator-name",
}
HEX_APPEARANCE_KEYS = {"cros-custom-accent", "cros-background", "cros-star-color"}


def clean_appearance_state(value: object) -> dict[str, str]:
    source = value if isinstance(value, dict) else {}
    result: dict[str, str] = {}
    for key in APPEARANCE_KEYS:
        raw = source.get(key)
        if raw is None:
            continue
        text = _short_text(raw, 40 if key == "cros-operator-name" else 32)
        if key in HEX_APPEARANCE_KEYS and not re.fullmatch(r"#[0-9a-fA-F]{6}", text):
            continue
        if key == "cros-accent" and text not in {"violet", "cyan", "red", "green", "amber", "ice", "custom"}:
            continue
        if key in {"cros-shape"} and text not in {"soft", "sharp", "round"}:
            continue
        if key == "cros-columns" and text not in {"auto", "3", "4", "5"}:
            continue
        if key == "cros-rail-autoclose" and text not in {"0", "3000", "5000", "10000"}:
            continue
        if key == "cros-operator-name" and not re.fullmatch(r"[^\r\n]{1,40}", text):
            continue
        if key in {"cros-particles", "cros-wings", "cros-compact", "cros-animations"} and text not in {"true", "false"}:
            continue
        if key in {"cros-glow", "cros-motion", "cros-particle-density", "cros-light-smoothing", "cros-star-brightness"}:
            try:
                number = int(text)
            except ValueError:
                continue
            bounds = {"cros-glow": (0, 100), "cros-motion": (35, 180), "cros-particle-density": (20, 180), "cros-light-smoothing": (20, 100), "cros-star-brightness": (30, 240)}[key]
            if not bounds[0] <= number <= bounds[1]:
                continue
            text = str(number)
        result[key] = text
    return result


def read_appearance_state() -> dict[str, str]:
    with APPEARANCE_STATE_LOCK:
        try:
            value = json.loads(APPEARANCE_STATE_FILE.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            value = {}
    return clean_appearance_state(value)


def write_appearance_state(value: object) -> dict[str, str]:
    cleaned = clean_appearance_state(value)
    temporary = APPEARANCE_STATE_FILE.with_suffix(".tmp")
    with APPEARANCE_STATE_LOCK:
        temporary.write_text(json.dumps(cleaned, indent=2), encoding="utf-8")
        os.replace(temporary, APPEARANCE_STATE_FILE)
    return cleaned


class _DataBlob(ctypes.Structure):
    _fields_ = [("cbData", ctypes.c_uint32), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]


def protect_local_key(value: str) -> str:
    raw = value.encode("utf-8")
    buffer = ctypes.create_string_buffer(raw)
    source = _DataBlob(len(raw), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte)))
    protected = _DataBlob()
    if os.name != "nt" or not ctypes.windll.crypt32.CryptProtectData(ctypes.byref(source), "Cros local API key", None, None, None, 0, ctypes.byref(protected)):
        raise OSError("Windows could not protect the local API key")
    try:
        return base64.b64encode(ctypes.string_at(protected.pbData, protected.cbData)).decode("ascii")
    finally:
        ctypes.windll.kernel32.LocalFree(protected.pbData)


def unprotect_local_key(value: str) -> str:
    try:
        raw = base64.b64decode(str(value).strip().encode("ascii"), validate=True)
    except (UnicodeEncodeError, ValueError, binascii.Error) as exc:
        raise OSError("The saved local key is not valid encrypted data") from exc
    buffer = ctypes.create_string_buffer(raw)
    source = _DataBlob(len(raw), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte)))
    plain = _DataBlob()
    if os.name != "nt" or not ctypes.windll.crypt32.CryptUnprotectData(ctypes.byref(source), None, None, None, None, 0, ctypes.byref(plain)):
        raise OSError("Windows could not unlock the local API key")
    try:
        return ctypes.string_at(plain.pbData, plain.cbData).decode("utf-8")
    finally:
        ctypes.windll.kernel32.LocalFree(plain.pbData)


def read_provider_keys() -> dict[str, str]:
    try:
        saved = json.loads(KEY_VAULT_FILE.read_text(encoding="utf-8"))
        return {name: unprotect_local_key(str(value)) for name, value in saved.items() if name in {"osintdog"} and value}
    except (OSError, ValueError, json.JSONDecodeError, binascii.Error, UnicodeError):
        return {}


def write_provider_keys(value: object) -> dict[str, bool]:
    incoming = value if isinstance(value, dict) else {}
    keys = {name: str(incoming.get(name, "")).strip() for name in ("osintdog",) if str(incoming.get(name, "")).strip()}
    encrypted = {name: protect_local_key(secret) for name, secret in keys.items()}
    temporary = KEY_VAULT_FILE.with_suffix(".tmp")
    with KEY_VAULT_LOCK:
        temporary.write_text(json.dumps(encrypted, indent=2), encoding="utf-8")
        os.replace(temporary, KEY_VAULT_FILE)
    return {"osintdog": bool(keys.get("osintdog"))}


def clear_local_data() -> None:
    """Remove only Cros-generated local state; never touch user files."""
    for path in (WORKSPACE_STATE_FILE, APPEARANCE_STATE_FILE, LEARNING_PROGRESS_FILE, APP_DIR / "settings.json", KEY_VAULT_FILE):
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass


def redact_sensitive_lookup_data(value: object) -> object:
    """Keep provider responses useful without surfacing credential-like fields."""
    blocked = re.compile(r"password|passwd|secret|token|api.?key|ssn|social.?security|dob|date.?of.?birth", re.I)
    if isinstance(value, dict):
        return {str(key): redact_sensitive_lookup_data(item) for key, item in value.items() if not blocked.search(str(key))}
    if isinstance(value, list):
        return [redact_sensitive_lookup_data(item) for item in value[:200]]
    return value


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


ALLOWED_WEB_HOSTS = {
    "google.com", "www.google.com", "lens.google.com", "bing.com", "www.bing.com", "duckduckgo.com",
    "github.com", "reddit.com", "www.reddit.com", "x.com", "instagram.com", "www.instagram.com",
    "tiktok.com", "www.tiktok.com", "youtube.com", "www.youtube.com", "yandex.com", "yandex.ru",
    "haveibeenpwned.com", "www.haveibeenpwned.com",
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


def scan_uploaded_file(body: dict) -> dict:
    encoded = str(body.get("data", ""))
    if encoded.startswith("data:"):
        encoded = encoded.partition(",")[2]
    if not encoded or len(encoded) > 36_000_000:
        raise ValueError("Choose a file smaller than 25 MB")
    try:
        data = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("The file data is invalid") from exc
    if not data or len(data) > 25_000_000:
        raise ValueError("Choose a file smaller than 25 MB")
    name = Path(_short_text(body.get("name"), 160)).name or "dropped-file"
    suffix = Path(name).suffix.lower()
    risky_extensions = {".exe", ".dll", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta", ".msi", ".jar"}
    result = {"file_name": name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest(),
              "extension": suffix or "(none)", "review": "normal", "defender": "unavailable", "detections": [], "indicators": []}
    if suffix in risky_extensions:
        result["review"] = "review"
    temporary_path = None
    extracted_path = None
    try:
        with tempfile.NamedTemporaryFile(prefix="cros-file-", suffix=suffix or ".bin", delete=False) as temporary:
            temporary.write(data)
            temporary_path = Path(temporary.name)
        scan_target = temporary_path
        if suffix == ".jar":
            extracted_path = Path(tempfile.mkdtemp(prefix="cros-jar-"))
            with zipfile.ZipFile(temporary_path) as archive:
                members = archive.infolist()
                for member in members:
                    target = (extracted_path / member.filename).resolve()
                    if extracted_path.resolve() not in target.parents and target != extracted_path.resolve():
                        raise ValueError("The JAR contains an unsafe archive path")
                archive.extractall(extracted_path)
            result["archive_inspected"] = True
            names = [member.filename.replace("\\", "/") for member in members]
            result["jar_summary"] = {"integrity": "valid", "entries": len(names), "classes": sum(name.endswith(".class") for name in names),
                                      "native_libraries": sum(name.endswith((".dll", ".so", ".dylib")) for name in names),
                                      "nested_archives": sum(name.endswith((".jar", ".zip")) for name in names),
                                      "manifest": "META-INF/MANIFEST.MF" in names}
            signatures = {
                b"java/lang/runtime": "Java Runtime process execution",
                b"java/lang/processbuilder": "Java ProcessBuilder execution",
                b"java/net/socket": "Java socket networking",
                b"java/net/http": "Java HTTP networking",
                b"cmd.exe": "Windows command execution string",
                b"powershell": "PowerShell execution string",
                b"java/lang/reflect": "Java reflection",
                b"getasynckeystate": "Windows async keyboard state access",
                b"setwindowshookex": "Windows keyboard hook API",
                b"java/awt/robot": "Java Robot input capture",
                b"java/awt/event/keyevent": "Java keyboard event capture",
                b"javafx/scene/input/keyevent": "JavaFX keyboard event capture",
                b"jnativehook": "Global keyboard hook library",
                b"clipboard": "Clipboard access",
            }
            checked = 0
            for entry in extracted_path.rglob("*"):
                if not entry.is_file() or checked >= 150:
                    continue
                try:
                    blob = entry.read_bytes()[:2_000_000].lower()
                    checked += 1
                    for needle, label in signatures.items():
                        if needle in blob and label not in result["indicators"]:
                            result["indicators"].append(label)
                except OSError:
                    continue
            if result["indicators"]:
                result["review"] = "suspicious indicators"
                indicator_text = " ".join(result["indicators"]).lower()
                has_execution = "process execution" in indicator_text or "command execution" in indicator_text or "powershell" in indicator_text
                has_network = "networking" in indicator_text
                has_keylogging = "keyboard" in indicator_text or "key state" in indicator_text or "key event" in indicator_text or "keyboard hook" in indicator_text or "input capture" in indicator_text
                result["assessment"] = "likely keylogger behavior" if has_keylogging else "likely RAT-like behavior" if has_execution and has_network else "suspicious behavior"
            else:
                result["assessment"] = "no RAT indicators found"
            scan_target = extracted_path
        if platform.system() == "Windows":
            escaped = str(scan_target).replace("'", "''")
            script = ("$ErrorActionPreference='Stop'; $before=Get-Date; "
                      f"Start-MpScan -ScanPath '{escaped}' -ScanType CustomScan; "
                      "$hits=Get-MpThreatDetection | Where-Object {$_.InitialDetectionTime -ge $before}; "
                      "$hits | Select-Object ThreatName,Severity,Resources | ConvertTo-Json -Compress")
            creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            completed = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
                                       capture_output=True, text=True, timeout=90, creationflags=creationflags)
            if completed.returncode == 0:
                raw = completed.stdout.strip()
                if raw:
                    parsed = json.loads(raw)
                    result["detections"] = parsed if isinstance(parsed, list) else [parsed]
                result["defender"] = "threat detected" if result["detections"] else "no threat detected"
            else:
                result["defender"] = "scan unavailable"
                result["defender_error"] = _short_text(completed.stderr or completed.stdout, 240)
        return result
    except subprocess.TimeoutExpired:
        result["defender"] = "scan timed out"
        return result
    except (OSError, json.JSONDecodeError) as exc:
        result["defender"] = "scan unavailable"
        result["defender_error"] = _short_text(exc, 240)
        return result
    finally:
        if temporary_path:
            try: temporary_path.unlink(missing_ok=True)
            except OSError: pass
        if extracted_path:
            shutil.rmtree(extracted_path, ignore_errors=True)


def free_public_username_search(username: str) -> dict:
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", username):
        raise ValueError("Enter a valid public username.")
    checks = [
        ("GitHub", f"https://api.github.com/users/{urllib.parse.quote(username)}"),
        ("GitLab", f"https://gitlab.com/api/v4/users?username={urllib.parse.quote(username)}"),
    ]
    results = []
    for source, url in checks:
        request = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "Cros-Intelligence-Center/1.0"})
        try:
            with urllib.request.urlopen(request, timeout=12) as response:
                payload = json.loads(response.read().decode("utf-8"))
            if source == "GitHub" and isinstance(payload, dict) and payload.get("login"):
                results.append({"source": source, "found": True, "username": payload.get("login"), "profile": payload.get("html_url"), "public_repos": payload.get("public_repos")})
            elif source == "GitLab" and isinstance(payload, list) and payload:
                user = payload[0]
                results.append({"source": source, "found": True, "username": user.get("username"), "profile": user.get("web_url")})
            else:
                results.append({"source": source, "found": False})
        except urllib.error.HTTPError as exc:
            results.append({"source": source, "found": False, "status": exc.code})
        except (OSError, json.JSONDecodeError) as exc:
            results.append({"source": source, "found": False, "error": type(exc).__name__})
    return {"provider": "Free public APIs", "username": username, "results": results}


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


def _clean_session_text(value: str) -> str:
    value = ANSI_ESCAPE.sub("", value).replace("\x00", "")
    return "".join(char for char in value if char in "\n\r\t" or ord(char) >= 32)


def _append_session_output(session_id: str, text: str) -> None:
    if not text:
        return
    cleaned = _clean_session_text(text)
    with TOOL_SESSIONS_LOCK:
        session = TOOL_SESSIONS.get(session_id)
        if not session:
            return
        session["output"] += cleaned
        lines = [line.strip() for line in cleaned.replace("\r", "\n").splitlines() if line.strip()]
        if lines:
            session["stage"] = lines[-1][:180]
        if len(session["output"]) > 500_000:
            removed = len(session["output"]) - 400_000
            session["output"] = session["output"][removed:]
            session["base_offset"] += removed


def _read_tool_session(session_id: str) -> None:
    with TOOL_SESSIONS_LOCK:
        session = TOOL_SESSIONS.get(session_id)
        process = session.get("process") if session else None
    if not process or not process.stdout:
        return
    decoder = codecs.getincrementaldecoder("utf-8")("replace")
    try:
        while True:
            chunk = process.stdout.read(256)
            if not chunk:
                break
            _append_session_output(session_id, decoder.decode(chunk))
        _append_session_output(session_id, decoder.decode(b"", final=True))
    except (OSError, ValueError) as exc:
        _append_session_output(session_id, f"\nSession output error: {exc}\n")
    finally:
        process.wait()
        with TOOL_SESSIONS_LOCK:
            session = TOOL_SESSIONS.get(session_id)
            if session:
                session["ended"] = time.monotonic()
                session["returncode"] = process.returncode


def start_tool_session(category: str, tool_id: str, *, username: str = "") -> dict:
    category = str(category).lower().strip()
    tool_id = str(tool_id).strip()
    allowed = category == "terminal" and tool_id == "main" or f"{category}:{tool_id}" in TOOL_KEYS
    if not allowed:
        raise ValueError("Tool is not in the local allowlist")
    username = username.strip().lstrip("@")[:64]
    if username and not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", username):
        raise ValueError("Use 1–64 letters, numbers, dots, underscores, or hyphens")
    if username and not (category == "osint" and tool_id in {"1", "2"}):
        raise ValueError("A username can only be supplied to a Blackbird username workflow")

    with TOOL_SESSIONS_LOCK:
        finished = sorted((value for value in TOOL_SESSIONS.values() if value.get("ended")), key=lambda item: item["ended"])
        while len(TOOL_SESSIONS) >= 8 and finished:
            TOOL_SESSIONS.pop(finished.pop(0)["id"], None)
        if len(TOOL_SESSIONS) >= 8:
            raise ValueError("Close or stop an existing tool session first")

    env = os.environ.copy()
    env.update({"PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8", "PYTHONUNBUFFERED": "1",
                "CROS_EMBEDDED": "1", "COLUMNS": "300"})
    if username:
        env["CROS_USERNAME"] = username
        env["CROS_REQUIRE_BLACKBIRD"] = "1"
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    process = subprocess.Popen(
        [console_python(), "-u", str(APP_DIR / "tool_runner.py"), category, tool_id],
        cwd=str(APP_DIR), env=env, creationflags=flags, close_fds=True,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0,
    )
    session_id = uuid.uuid4().hex
    session = {"id": session_id, "category": category, "tool_id": tool_id, "process": process,
               "output": "", "base_offset": 0, "started": time.monotonic(), "ended": None,
               "returncode": None, "stage": "Starting local tool", "username": username}
    with TOOL_SESSIONS_LOCK:
        TOOL_SESSIONS[session_id] = session
    threading.Thread(target=_read_tool_session, args=(session_id,), daemon=True).start()
    return {"id": session_id, "category": category, "tool_id": tool_id}


def tool_session_payload(session_id: str, offset: int = 0) -> dict:
    with TOOL_SESSIONS_LOCK:
        session = TOOL_SESSIONS.get(session_id)
        if not session:
            raise ValueError("Tool session was not found")
        process = session["process"]
        done = session["ended"] is not None or process.poll() is not None
        base_offset = session["base_offset"]
        absolute_offset = max(base_offset, int(offset))
        relative_offset = absolute_offset - base_offset
        output = session["output"][relative_offset:]
        next_offset = base_offset + len(session["output"])
        elapsed = ((session["ended"] or time.monotonic()) - session["started"])
        returncode = session["returncode"] if session["returncode"] is not None else process.poll()
        stage = session["stage"]
        full_output = session["output"]
        username = session.get("username", "")
    social_results = blackbird_social_results(full_output, username)
    email_results = blackbird_email_results(full_output)
    if int(offset) < base_offset:
        output = "[Earlier output was trimmed]\n" + output
    return {"id": session_id, "output": output, "next_offset": next_offset, "done": done,
            "returncode": returncode, "elapsed_ms": int(elapsed * 1000),
            "stage": (("Complete" if returncode == 0 else "Stopped with an error") if done else stage)[:180],
            "social_results": social_results, "email_results": email_results}


def send_tool_session_input(session_id: str, value: object) -> None:
    text = str(value or "").replace("\r", " ").replace("\n", " ")[:4096]
    with TOOL_SESSIONS_LOCK:
        session = TOOL_SESSIONS.get(session_id)
        process = session.get("process") if session else None
    if not process or process.poll() is not None or not process.stdin:
        raise ValueError("That tool session is no longer accepting input")
    process.stdin.write((text + "\n").encode("utf-8"))
    process.stdin.flush()


def _terminate_process_tree(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    if os.name == "nt":
        subprocess.run(
            ["taskkill", "/PID", str(process.pid), "/T", "/F"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0), check=False,
        )
    else:
        process.terminate()


def stop_tool_session(session_id: str) -> None:
    with TOOL_SESSIONS_LOCK:
        session = TOOL_SESSIONS.get(session_id)
        process = session.get("process") if session else None
    if not process:
        raise ValueError("Tool session was not found")
    _terminate_process_tree(process)


def stop_all_tool_sessions() -> None:
    with TOOL_SESSIONS_LOCK:
        processes = [session["process"] for session in TOOL_SESSIONS.values()]
    for process in processes:
        try:
            _terminate_process_tree(process)
        except OSError:
            pass


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


def install_desktop_shortcut() -> None:
    """Create a local Windows shortcut without sending the path anywhere."""
    if os.name != "nt":
        raise OSError("Desktop shortcuts are supported on Windows only")
    launcher = APP_DIR / "start_osint_tool.bat"
    if not launcher.is_file():
        raise OSError("The Cros launcher is missing")
    destinations = [Path.home() / "Desktop"]
    one_drive_desktop = Path(os.environ.get("OneDrive", "")) / "Desktop"
    if one_drive_desktop not in destinations:
        destinations.append(one_drive_desktop)
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders") as key:
            registered = os.path.expandvars(str(winreg.QueryValueEx(key, "Desktop")[0]))
        registered_desktop = Path(registered)
        if registered_desktop not in destinations:
            destinations.append(registered_desktop)
    except (ImportError, OSError):
        pass
    def ps_quote(value: Path) -> str:
        return str(value).replace("'", "''")
    created = []
    for desktop in destinations:
        try:
            desktop.mkdir(parents=True, exist_ok=True)
            shortcut = desktop / "Cros Intelligence Center - Private Dev.lnk"
            script = (
                "$shell=New-Object -ComObject WScript.Shell;"
                f"$shortcut=$shell.CreateShortcut('{ps_quote(shortcut)}');"
                f"$shortcut.TargetPath='{ps_quote(launcher)}';"
                f"$shortcut.WorkingDirectory='{ps_quote(APP_DIR)}';"
                f"$shortcut.IconLocation='{ps_quote(APP_ICON_FILE)},0';"
                "$shortcut.Description='Cros Intelligence Center';$shortcut.Save()"
            )
            result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
                                    capture_output=True, text=True, timeout=15, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            if result.returncode == 0 and shortcut.is_file():
                created.append(shortcut)
        except (OSError, subprocess.SubprocessError):
            continue
    if not created:
        raise OSError("Windows could not create the desktop shortcut")


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
        if route == "/api/appearance":
            if not self.authorized(): self.json_response({"error": "unauthorized"}, 403); return
            self.json_response(read_appearance_state())
            return
        if route == "/api/provider-keys":
            if not self.authorized(): self.json_response({"error": "unauthorized"}, 403); return
            self.json_response(read_provider_keys())
            return
        if route == "/api/session":
            if not self.authorized(): self.json_response({"error": "unauthorized"}, 403); return
            query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
            try:
                session_id = str(query.get("id", [""])[0])
                offset = int(query.get("offset", ["0"])[0])
                self.json_response(tool_session_payload(session_id, offset))
            except (TypeError, ValueError) as exc:
                self.json_response({"error": str(exc)}, 400)
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
        body = self.read_json(36_500_000 if route in {"/api/image-analyze", "/api/file-scan"} else 262_144)
        if route == "/api/session/start":
            try:
                self.json_response(start_tool_session(body.get("category", ""), body.get("id", ""),
                                                      username=str(body.get("username", ""))))
            except (OSError, ValueError) as exc:
                self.json_response({"error": str(exc)}, 400)
            return
        if route == "/api/session/input":
            try:
                send_tool_session_input(str(body.get("session_id", "")), body.get("input", ""))
                self.json_response({"ok": True})
            except (OSError, ValueError) as exc:
                self.json_response({"error": str(exc)}, 400)
            return
        if route == "/api/session/stop":
            try:
                stop_tool_session(str(body.get("session_id", "")))
                self.json_response({"ok": True})
            except ValueError as exc:
                self.json_response({"error": str(exc)}, 400)
            return
        if route == "/api/image-analyze":
            try: self.json_response(analyze_uploaded_image(body))
            except (OSError, RuntimeError, ValueError) as exc: self.json_response({"error": str(exc)}, 400)
            return
        if route == "/api/file-scan":
            try: self.json_response(scan_uploaded_file(body))
            except (OSError, RuntimeError, ValueError) as exc: self.json_response({"error": str(exc)}, 400)
            return
        if route == "/api/free-public-search":
            try: self.json_response(free_public_username_search(str(body.get("username", "")).strip()))
            except (OSError, RuntimeError, ValueError) as exc: self.json_response({"error": str(exc)}, 400)
            return
        if route == "/api/open-url":
            try:
                open_allowed_web_url(body.get("url"))
                self.json_response({"ok": True})
            except ValueError as exc: self.json_response({"error": str(exc)}, 400)
            except OSError as exc: self.json_response({"error": str(exc)}, 500)
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
        if route == "/api/install-desktop":
            try:
                install_desktop_shortcut()
                self.json_response({"ok": True})
            except OSError as exc:
                self.json_response({"error": str(exc)}, 400)
            return
        if route == "/api/appearance":
            try:
                self.json_response(write_appearance_state(body))
            except OSError as exc:
                self.json_response({"error": str(exc)}, 500)
            return
        if route == "/api/provider-keys":
            try:
                self.json_response(write_provider_keys(body))
            except OSError as exc:
                self.json_response({"error": str(exc)}, 500)
            return
        if route == "/api/clear-local-data":
            try:
                clear_local_data()
                self.json_response({"ok": True})
            except OSError as exc:
                self.json_response({"error": str(exc)}, 500)
            return
        if route == "/api/hibp-check":
            email = str(body.get("email", "")).strip()
            api_key = str(body.get("api_key", "")).strip()
            if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
                self.json_response({"error": "Enter a valid email address."}, 400); return
            if not re.fullmatch(r"[0-9a-fA-F]{32}", api_key):
                self.json_response({"error": "HIBP API keys must be 32 hexadecimal characters."}, 400); return
            request = urllib.request.Request("https://haveibeenpwned.com/api/v3/breachedaccount/" + urllib.parse.quote(email), headers={"hibp-api-key": api_key, "user-agent": "Cros-Intelligence-Console"})
            try:
                with urllib.request.urlopen(request, timeout=20) as response:
                    payload = json.loads(response.read().decode("utf-8")) if response.status != 404 else []
                self.json_response({"found": True, "breaches": payload if isinstance(payload, list) else []})
            except urllib.error.HTTPError as exc:
                if exc.code == 404: self.json_response({"found": False, "breaches": []})
                elif exc.code in {401, 403}: self.json_response({"error": "HIBP rejected the API key or request."}, 400)
                else: self.json_response({"error": f"HIBP returned HTTP {exc.code}."}, 502)
            except (OSError, json.JSONDecodeError) as exc:
                self.json_response({"error": f"Could not reach HIBP: {exc}"}, 502)
            return
        if route == "/api/osintdog-search":
            username = str(body.get("username", "")).strip()
            api_key = str(body.get("api_key", "")).strip() or read_provider_keys().get("osintdog", "")
            if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", username):
                self.json_response({"error": "Enter a valid public username."}, 400); return
            if not api_key or len(api_key) > 256:
                self.json_response({"error": "Enter your OSINT Dog API key in Settings."}, 400); return
            request = urllib.request.Request(
                "https://osintdog.com/api/search",
                data=json.dumps({"field": [{"username": username}]}).encode("utf-8"),
                headers={"X-API-Key": api_key, "Content-Type": "application/json", "Accept": "application/json"},
                method="POST",
            )
            try:
                with urllib.request.urlopen(request, timeout=30, context=OSINT_DOG_SSL_CONTEXT) as response:
                    payload = json.loads(response.read().decode("utf-8"))
                self.json_response({"ok": True, "provider": "OSINT Dog", "result": redact_sensitive_lookup_data(payload)})
            except urllib.error.HTTPError as exc:
                if exc.code in {401, 403}: self.json_response({"error": "OSINT Dog rejected the API key or request."}, 400)
                elif exc.code == 429: self.json_response({"error": "OSINT Dog rate limit reached. Try again later."}, 429)
                else: self.json_response({"error": f"OSINT Dog returned HTTP {exc.code}."}, 502)
            except (OSError, json.JSONDecodeError) as exc:
                self.json_response({"error": f"Could not reach OSINT Dog: {exc}"}, 502)
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
            stop_all_tool_sessions()
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
    finally:
        stop_all_tool_sessions()
        server.server_close()


if __name__ == "__main__":
    main()
