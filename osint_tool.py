#!/usr/bin/env python3
"""Cros OSINT Console — customizable public-information research tools."""

from __future__ import annotations

import hashlib
import base64
import difflib
import email.policy
import mimetypes
import uuid
import concurrent.futures
import time
import ipaddress
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import webbrowser
import secrets
import string
import contextlib
import urllib.error
import urllib.parse
import urllib.request
import ctypes
from html.parser import HTMLParser
from email.parser import Parser
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote_plus, urljoin, urlparse

from image_analysis import analyze_image_file

APP_DIR = Path(__file__).resolve().parent
VENDOR_DIR = APP_DIR / "pydeps"
ENGINE_DEPS_DIR = APP_DIR / "engine_deps"


def engine_runtime_dir() -> Path:
    """Keep compiled Blackbird packages isolated by the active Python ABI."""
    return ENGINE_DEPS_DIR / sys.implementation.cache_tag


def engine_dependency_path() -> Path:
    """Return only the ABI-specific dependency directory.

    Never fall back to ``engine_deps`` itself: compiled packages such as Pillow
    and ReportLab are Python-version-specific, and the old shared folder can
    otherwise make Blackbird import a broken _imaging extension.
    """
    return engine_runtime_dir()


def validate_engine_dependencies(path: Path) -> str | None:
    """Explain a missing or incompatible bundled engine environment."""
    if not path.is_dir():
        return f"Blackbird dependencies are not installed for {sys.version.split()[0]}. Run Account Engine Setup."
    pillow = path / "PIL"
    if not (pillow / "__init__.py").is_file():
        return "Blackbird dependencies are incomplete. Run Account Engine Setup to reinstall Pillow and ReportLab."
    try:
        probe = subprocess.run([sys.executable, "-c", "from PIL import Image; from reportlab.pdfgen import canvas"],
                               cwd=str(APP_DIR), env={**os.environ, "PYTHONPATH": str(path)},
                               capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.SubprocessError) as exc:
        return f"Could not validate Blackbird dependencies: {exc}"
    if probe.returncode:
        return "Blackbird dependencies are incompatible with this Python version. Run Account Engine Setup to reinstall them."
    return None

# The console runs with the Python standard library. Rich/Requests are optional
# enhancements, so a locked package folder can never prevent the tool opening.
try:
    import requests  # type: ignore
except ImportError:
    class _Response:
        def __init__(self, response):
            self._response = response
            self.status_code = getattr(response, "status", 200)
            self.headers = response.headers
            self.url = response.geturl()
            self.text = response.read().decode("utf-8", errors="replace")
        @property
        def ok(self): return 200 <= self.status_code < 400
        def close(self): self._response.close()
    class _RequestsFallback:
        class RequestException(Exception): pass
        @staticmethod
        def get(url, timeout=10, allow_redirects=True, stream=False, headers=None):
            try:
                request = urllib.request.Request(url, headers=headers or {})
                return _Response(urllib.request.urlopen(request, timeout=timeout))
            except (urllib.error.URLError, OSError) as exc:
                raise _RequestsFallback.RequestException(str(exc)) from exc
    requests = _RequestsFallback()

try:
    from rich import box
    from rich.columns import Columns
    from rich.console import Console
    from rich.panel import Panel
    from rich.prompt import Confirm, IntPrompt, Prompt
    from rich.table import Table
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    class _Boxes:
        ROUNDED = SQUARE = HEAVY = DOUBLE = None
    box = _Boxes()
    def _plain(value): return re.sub(r"\[/?[^\]]+\]", "", str(value))
    class Panel:
        def __init__(self, renderable, title=None, **kwargs):
            self.renderable, self.title = renderable, title
        @classmethod
        def fit(cls, renderable, **kwargs): return cls(renderable, **kwargs)
        def __str__(self):
            title = f" {self.title} " if self.title else ""
            return f"\n---{title}---\n{_plain(self.renderable)}\n---------------"
    class Table:
        def __init__(self, title=None, **kwargs): self.title, self.columns, self.rows = title, [], []
        def add_column(self, name, **kwargs): self.columns.append(name)
        def add_row(self, *values): self.rows.append(values)
        def __str__(self):
            rows = ([self.columns] if self.columns else []) + self.rows
            widths = [max(len(_plain(str(row[i])) if i < len(row) else "") for row in rows) for i in range(max((len(r) for r in rows), default=0))]
            line = " | ".join("-" * width for width in widths)
            text = [self.title or "", line]
            for row in rows: text.append(" | ".join(_plain(str(row[i])) if i < len(row) else "" for i in range(len(widths))))
            return "\n".join(item for item in text if item)
    class Columns:
        def __init__(self, items, **kwargs): self.items = items
        def __str__(self): return "\n".join(str(item) for item in self.items)
    class Console:
        def print(self, *items, **kwargs): print(*(_plain(item) for item in items))
        def status(self, *args, **kwargs): return contextlib.nullcontext()
    class Prompt:
        @staticmethod
        def ask(label, default=None, choices=None, password=False):
            suffix = f" ({'/'.join(choices)})" if choices else ""
            value = input(f"{_plain(label)}{suffix}" + (f" [{default}]" if default is not None else "") + ": ").strip()
            return value or (default if default is not None else "")
    class IntPrompt:
        @staticmethod
        def ask(label, default=0):
            try: return int(Prompt.ask(label, default=str(default)))
            except ValueError: return default
    class Confirm:
        @staticmethod
        def ask(label, default=False):
            answer = Prompt.ask(label, default="y" if default else "n")
            return answer.lower() in {"y", "yes"}

SETTINGS_FILE = APP_DIR / "settings.json"
DEFAULT_SETTINGS = {
    "theme": "red",
    "panel_color": "cyan",
    "panel_colors": ["cyan", "green", "blue", "magenta"],
    "panel_titles": ["USERNAME TOOLS", "NETWORK TOOLS", "UTILITY TOOLS", "EXTRA TOOLS"],
    "panel_width": 28,
    "box_style": "rounded",
    "title": "CROS OSINT CONSOLE",
    "tagline": "Public-source research and diagnostics",
    "show_wings": True,
    "blackbird_path": "",
    "blackbird_timeout": 30,
    "blackbird_concurrency": 30,
    "blackbird_no_nsfw": True,
    "blackbird_no_update": False,
}
BOXES = {"rounded": box.ROUNDED, "square": box.SQUARE, "heavy": box.HEAVY, "double": box.DOUBLE}
console = Console()


def load_settings() -> dict:
    data = DEFAULT_SETTINGS.copy()
    try:
        saved = json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
        if isinstance(saved, dict):
            data.update({k: v for k, v in saved.items() if k in data})
    except (OSError, ValueError):
        pass
    # Upgrade settings written by older versions without exposing engine branding.
    titles = list(data.get("panel_titles", []))
    colors = list(data.get("panel_colors", []))
    if titles and titles[0].upper() in {"BLACKBIRD", "ACCOUNT SEARCH"}:
        titles[0] = "USERNAME TOOLS"
    if len(titles) > 1 and titles[1].upper() == "NETWORK":
        titles[1] = "NETWORK TOOLS"
    if len(titles) > 2 and titles[2].upper() in {"WEB RESEARCH", "UTILITIES"}:
        titles[2] = "UTILITY TOOLS"
    while len(titles) < 4:
        titles.append(DEFAULT_SETTINGS["panel_titles"][len(titles)])
    while len(colors) < 4:
        colors.append(DEFAULT_SETTINGS["panel_colors"][len(colors)])
    data["panel_titles"] = titles[:4]
    data["panel_colors"] = colors[:4]
    return data


settings = load_settings()


def save_settings() -> None:
    SETTINGS_FILE.write_text(json.dumps(settings, indent=2), encoding="utf-8")


def pause() -> None:
    Prompt.ask("\n[dim]Press Enter to continue[/]", default="")


def run_with_loading(label: str, operation):
    """Run real work in the background while displaying a live progress bar."""
    width = 28; tick = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(operation)
        while not future.done():
            filled = 2 + (tick % (width - 3))
            bar = "#" * filled + "-" * (width - filled)
            sys.stdout.write(f"\r{label:<30} [{bar}]")
            sys.stdout.flush(); tick += 1; time.sleep(0.08)
        result = future.result()
    sys.stdout.write(f"\r{label:<30} [{'#' * width}] complete\n")
    sys.stdout.flush()
    return result


def clean_host(value: str) -> str:
    value = value.strip()
    if "://" in value:
        value = urlparse(value).hostname or ""
    return value.strip(" /.")


def valid_username(value: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", value))


def blackbird_candidates() -> list[Path]:
    custom = str(settings.get("blackbird_path", "")).strip()
    roots = [
        Path(custom).expanduser() if custom else None,
        APP_DIR / "blackbird",
        APP_DIR.parent / "blackbird",
        Path.cwd() / "blackbird",
        Path.home() / "blackbird",
        Path("C:/blackbird"),
    ]
    return [p.resolve() for p in roots if p]


def find_blackbird() -> Path | None:
    for root in blackbird_candidates():
        script = root / "blackbird.py"
        if script.is_file() and (root / "src").is_dir():
            return script
    return None


def clean_engine_output(value: str) -> str:
    """Hide dependency branding/banner while preserving useful search results."""
    hidden = ("blackbird", "p1ngul1n0", "lucas antoniaci")
    lines = []
    for line in value.splitlines():
        lowered = line.lower()
        if any(word in lowered for word in hidden):
            continue
        if sum(ch in "▄█▀▓▒░" for ch in line) > 8:
            continue
        lines.append(line)
    return "\n".join(lines).strip()


def username_variants(value: str) -> list[str]:
    """Build a focused, deduplicated set without inventing personal details."""
    raw = value.strip().lstrip("@").lower()
    chunks = [part for part in re.split(r"[._-]+", raw) if part]
    compact = "".join(chunks) or raw
    candidates = [raw, compact]
    if len(chunks) > 1:
        candidates.extend(separator.join(chunks) for separator in (".", "_", "-"))
        candidates.append("".join(reversed(chunks)))
    candidates.extend([
        f"the{compact}", f"real{compact}", f"official{compact}",
        f"{compact}official", f"{compact}_official", f"{compact}online", f"{compact}1",
    ])
    result = []
    for candidate in candidates:
        if valid_username(candidate) and candidate not in result:
            result.append(candidate)
    return result[:16]


def run_blackbird(kind: str, values: list[str], *, permute: bool = False) -> None:
    script = find_blackbird()
    if not script:
        console.print("[red]Blackbird is not installed in the Cros folder. Use Account Engine Setup, then run this search again.[/]")
        pause()
        return
    flag = "--username" if kind == "username" else "--email"
    command = [sys.executable, "-u", str(script), flag, *values]
    if permute:
        command.append("--permuteall")
    command += ["--timeout", str(settings["blackbird_timeout"]),
                "--max-concurrent-requests", str(settings["blackbird_concurrency"])]
    if settings["blackbird_no_nsfw"]:
        command.append("--no-nsfw")
    if settings["blackbird_no_update"]:
        command.append("--no-update")
    embedded = os.environ.get("CROS_EMBEDDED") == "1"
    exports = "none" if embedded else Prompt.ask("Export", choices=["none", "json", "csv", "pdf"], default="none")
    if exports != "none":
        command.append(f"--{exports}")
    console.print(f"\n[bold {settings['theme']}]Starting account search…[/]\n")
    try:
        child_env = os.environ.copy()
        existing_path = child_env.get("PYTHONPATH", "")
        dependency_dir = engine_dependency_path()
        dependency_error = validate_engine_dependencies(dependency_dir)
        if dependency_error:
            console.print(f"[red]{dependency_error}[/]")
            pause()
            return
        child_env["PYTHONPATH"] = str(dependency_dir) + (os.pathsep + existing_path if existing_path else "")
        child_env["PYTHONUTF8"] = "1"
        child_env["PYTHONIOENCODING"] = "utf-8"
        child_env["COLUMNS"] = "300"
        if embedded:
            console.print("[cyan]Blackbird is checking live public sources. Results will stream here as they arrive.[/]")
            process = subprocess.Popen(command, cwd=script.parent, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                       text=True, errors="replace", env=child_env, bufsize=1)
            if process.stdout:
                for line in process.stdout:
                    output = clean_engine_output(line)
                    if output:
                        console.print(output, markup=False)
            returncode = process.wait()
            if returncode:
                console.print(f"[yellow]The search engine exited with code {returncode}. Run diagnostics for details.[/]")
                raise RuntimeError(f"Blackbird exited with code {returncode}")
        else:
            result = run_with_loading("Searching public sources", lambda: subprocess.run(
                command, cwd=script.parent, check=False, capture_output=True,
                text=True, errors="replace", env=child_env))
            output = clean_engine_output("\n".join(part for part in (result.stdout, result.stderr) if part))
            if output:
                console.print(output, markup=False)
            if result.returncode:
                console.print(f"[yellow]The search engine exited with code {result.returncode}. Run diagnostics for details.[/]")
    except OSError as exc:
        console.print(f"[red]Could not start the account-search engine: {exc}[/]")
    pause()


def username_search(combos: bool = False) -> None:
    raw = os.environ.pop("CROS_USERNAME", "").strip() or Prompt.ask("Username").strip()
    raw = raw.lstrip("@")
    if not valid_username(raw):
        console.print("[red]Use 1–64 letters, numbers, dots, underscores, or hyphens.[/]")
        pause(); return
    if combos:
        parts = username_variants(raw)
        console.print(f"[dim]Prepared {len(parts)} focused variations without inventing dates or personal details.[/]")
        run_blackbird("username", parts, permute=True)
    else:
        run_blackbird("username", [raw])


def email_search() -> None:
    email = os.environ.pop("CROS_EMAIL", "").strip() or Prompt.ask("Email").strip()
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        console.print("[red]That does not look like a valid email address.[/]"); pause(); return
    run_blackbird("email", [email])


def dns_lookup() -> None:
    host = clean_host(Prompt.ask("Domain"))
    table = Table(title=f"Addresses for {host}", box=BOXES.get(settings["box_style"], box.ROUNDED))
    table.add_column("Type"); table.add_column("Address")
    try:
        found = sorted({(fam, addr[0]) for fam, _, _, _, addr in socket.getaddrinfo(host, None)})
        for fam, addr in found:
            table.add_row("IPv6" if fam == socket.AF_INET6 else "IPv4", addr)
        console.print(table)
    except socket.gaierror as exc:
        console.print(f"[red]DNS lookup failed: {exc}[/]")
    pause()


def port_check() -> None:
    host = clean_host(Prompt.ask("Host you own or are authorized to test"))
    ports = [int(x) for x in re.findall(r"\d+", Prompt.ask("Ports (comma separated)", default="22,80,443"))]
    ports = sorted({p for p in ports if 1 <= p <= 65535})[:50]
    table = Table(title=f"TCP check: {host}"); table.add_column("Port"); table.add_column("Status")
    for port in ports:
        try:
            with socket.create_connection((host, port), timeout=0.6): status = "[green]open[/]"
        except (OSError, socket.timeout): status = "[dim]closed/filtered[/]"
        table.add_row(str(port), status)
    console.print(table); pause()


def ssl_check() -> None:
    host = clean_host(Prompt.ask("HTTPS domain"))
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=8) as raw:
            with context.wrap_socket(raw, server_hostname=host) as sock:
                cert = sock.getpeercert()
        expires = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        console.print(Panel.fit(f"Domain: {host}\nIssuer: {dict(x[0] for x in cert['issuer']).get('organizationName', 'Unknown')}\nExpires: {expires:%Y-%m-%d}\nDays remaining: {(expires-datetime.now(timezone.utc)).days}", title="TLS certificate"))
    except Exception as exc:
        console.print(f"[red]TLS check failed: {exc}[/]")
    pause()


def ip_lookup() -> None:
    value = clean_host(Prompt.ask("IP address or domain"))
    try:
        address = socket.gethostbyname(value)
        parsed = ipaddress.ip_address(address)
        console.print(Panel.fit(f"Resolved address: {parsed}\nPrivate: {parsed.is_private}\nGlobal: {parsed.is_global}\nReverse DNS: {socket.getfqdn(address)}", title="IP information"))
    except (ValueError, OSError) as exc:
        console.print(f"[red]Lookup failed: {exc}[/]")
    pause()


def headers_check() -> None:
    target = Prompt.ask("Website URL").strip()
    if not target.startswith(("http://", "https://")): target = "https://" + target
    try:
        response = run_with_loading("Checking HTTP headers", lambda: requests.get(
            target, timeout=10, allow_redirects=True, stream=True,
            headers={"User-Agent": "Cros-OSINT/8.0"}))
        wanted = ["server", "content-type", "strict-transport-security", "content-security-policy", "x-frame-options", "x-content-type-options", "referrer-policy"]
        table = Table(title=f"HTTP {response.status_code} — {response.url}")
        table.add_column("Header"); table.add_column("Value", overflow="fold")
        for name in wanted: table.add_row(name, response.headers.get(name, "[dim]missing[/]"))
        console.print(table); response.close()
    except requests.RequestException as exc:
        console.print(f"[red]Request failed: {exc}[/]")
    pause()


def hash_text() -> None:
    value = Prompt.ask("Text to hash", password=True)
    data = value.encode()
    table = Table(title="Hashes"); table.add_column("Algorithm"); table.add_column("Digest")
    for name in ("md5", "sha1", "sha256", "sha512"):
        table.add_row(name.upper(), hashlib.new(name, data).hexdigest())
    console.print(table); pause()


def web_search() -> None:
    query = Prompt.ask("Search query").strip()
    if query: webbrowser.open("https://www.google.com/search?q=" + quote_plus(query))


def wayback() -> None:
    target = Prompt.ask("Domain or URL").strip()
    webbrowser.open("https://web.archive.org/web/*/" + target)


def install_blackbird_requirements(requirements: Path) -> int:
    target = engine_runtime_dir()
    target.mkdir(parents=True, exist_ok=True)
    command = [sys.executable, "-m", "pip", "install", "--disable-pip-version-check",
               "--target", str(target), "--upgrade"]
    if sys.version_info >= (3, 14):
        packages = []
        try:
            for line in requirements.read_text(encoding="utf-8").splitlines():
                name = re.split(r"[<>=!~\[]", line.strip(), maxsplit=1)[0]
                if re.fullmatch(r"[A-Za-z0-9_.-]+", name):
                    packages.append(name)
        except OSError as exc:
            console.print(f"[red]Could not read Blackbird requirements: {exc}[/]")
            return 1
        command.extend(packages)
        console.print("[yellow]Python 3.14 detected; installing current compatible dependency builds.[/]")
    else:
        command.extend(["-r", str(requirements)])
    return subprocess.run(command, check=False).returncode


def blackbird_setup() -> None:
    script = find_blackbird()
    if script:
        console.print(f"[green]Account-search engine found:[/] {script}")
        if Confirm.ask("Install/update its Python requirements now?", default=False):
            code = install_blackbird_requirements(script.parent / "requirements.txt")
            console.print("[green]Blackbird dependencies are ready.[/]" if code == 0 else "[red]Dependency installation did not finish successfully.[/]")
    else:
        destination = APP_DIR / "blackbird"
        console.print("The account-search engine was not found in the configured/common locations.")
        if Confirm.ask(f"Clone the official repository into {destination}?", default=False):
            if not shutil.which("git"):
                console.print("[red]Git is not installed or not on PATH.[/]")
            else:
                result = subprocess.run(["git", "clone", "https://github.com/p1ngul1n0/blackbird", str(destination)], check=False)
                if result.returncode == 0:
                    code = install_blackbird_requirements(destination / "requirements.txt")
                    console.print("[green]Blackbird is installed and ready.[/]" if code == 0 else "[red]Blackbird was cloned, but dependency installation failed.[/]")
    pause()


def diagnostics() -> None:
    script = find_blackbird()
    rows = [("Python", sys.version.split()[0]), ("Account engine", str(script) if script else "Not found"),
            ("Engine packages", str(engine_runtime_dir())), ("Git", shutil.which("git") or "Not found"),
            ("Settings", str(SETTINGS_FILE))]
    table = Table(title="Diagnostics"); table.add_column("Item"); table.add_column("Value")
    for row in rows: table.add_row(*row)
    console.print(table)
    pause()


def normalize_url(value: str) -> str:
    value = value.strip()
    return value if value.startswith(("http://", "https://")) else "https://" + value


def domain_overview() -> None:
    host = clean_host(Prompt.ask("Domain"))
    if not host:
        console.print("[red]Enter a valid domain.[/]"); pause(); return
    rows: list[tuple[str, str]] = []
    try:
        addresses = sorted({item[4][0] for item in socket.getaddrinfo(host, None)})
        rows.append(("Addresses", "\n".join(addresses)))
    except socket.gaierror as exc:
        rows.append(("DNS", f"Failed: {exc}"))
    try:
        response = requests.get(f"https://{host}", timeout=8, allow_redirects=True,
                                stream=True, headers={"User-Agent": "Cros-OSINT/7.0"})
        rows.extend([("HTTP", str(response.status_code)), ("Final URL", response.url),
                     ("Server", response.headers.get("server", "Not disclosed"))])
        response.close()
    except requests.RequestException as exc:
        rows.append(("Website", f"Failed: {exc}"))
    try:
        with socket.create_connection((host, 443), timeout=6) as raw:
            with ssl.create_default_context().wrap_socket(raw, server_hostname=host) as sock:
                cert = sock.getpeercert()
        rows.append(("TLS expires", cert.get("notAfter", "Unknown")))
    except Exception:
        rows.append(("TLS", "Unavailable"))
    table = Table(title=f"Domain overview — {host}", box=BOXES.get(settings["box_style"], box.ROUNDED))
    table.add_column("Check"); table.add_column("Result", overflow="fold")
    for row in rows: table.add_row(*row)
    console.print(table); pause()


def robots_and_sitemap() -> None:
    host = clean_host(Prompt.ask("Domain"))
    table = Table(title=f"Discovery files — {host}")
    table.add_column("File"); table.add_column("Status"); table.add_column("Address")
    for name in ("robots.txt", "sitemap.xml", ".well-known/security.txt"):
        url = f"https://{host}/{name}"
        try:
            response = requests.get(url, timeout=8, allow_redirects=True,
                                    headers={"User-Agent": "Cros-OSINT/7.0"})
            status = f"[green]{response.status_code}[/]" if response.ok else f"[yellow]{response.status_code}[/]"
            table.add_row(name, status, response.url)
        except requests.RequestException:
            table.add_row(name, "[red]unavailable[/]", url)
    console.print(table); pause()


def url_analyzer() -> None:
    value = normalize_url(Prompt.ask("URL"))
    parsed = urlparse(value)
    host = parsed.hostname or ""
    signals = []
    if parsed.scheme != "https": signals.append("not HTTPS")
    if "@" in parsed.netloc: signals.append("contains @ before the host")
    if host.startswith("xn--") or ".xn--" in host: signals.append("internationalized/punycode host")
    if len(value) > 150: signals.append("very long URL")
    try:
        ipaddress.ip_address(host); signals.append("uses an IP address as the host")
    except ValueError:
        pass
    details = [("Scheme", parsed.scheme), ("Host", host or "Missing"),
               ("Port", str(parsed.port or "default")), ("Path", parsed.path or "/"),
               ("Query fields", str(len([x for x in parsed.query.split("&") if x]))),
               ("Warnings", ", ".join(signals) if signals else "No basic warning signs")]
    table = Table(title="URL breakdown"); table.add_column("Part"); table.add_column("Value", overflow="fold")
    for row in details: table.add_row(*row)
    console.print(table); console.print("[dim]This is a structural check, not a guarantee that a URL is safe.[/]"); pause()


def file_hash() -> None:
    path = Path(Prompt.ask("Full path to a file").strip().strip('"')).expanduser()
    if not path.is_file():
        console.print("[red]File not found.[/]"); pause(); return
    try:
        def calculate_hashes():
            values = {name: hashlib.new(name) for name in ("md5", "sha1", "sha256", "sha512")}
            with path.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    for digest in values.values(): digest.update(chunk)
            return values
        digests = run_with_loading("Hashing file", calculate_hashes)
        table = Table(title=f"Checksums — {path.name}"); table.add_column("Algorithm"); table.add_column("Digest")
        for name, digest in digests.items(): table.add_row(name.upper(), digest.hexdigest())
        console.print(table)
    except OSError as exc:
        console.print(f"[red]Could not read file: {exc}[/]")
    pause()


def password_helper() -> None:
    choice = Prompt.ask("Choose", choices=["check", "generate"], default="generate")
    if choice == "generate":
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
        length = max(16, min(64, IntPrompt.ask("Length", default=24)))
        value = "".join(secrets.choice(alphabet) for _ in range(length))
        console.print(Panel.fit(value, title="Generated password"))
    else:
        value = Prompt.ask("Password", password=True)
        score = sum((len(value) >= 12, len(value) >= 16,
                     bool(re.search(r"[a-z]", value) and re.search(r"[A-Z]", value)),
                     bool(re.search(r"\d", value)), bool(re.search(r"[^A-Za-z0-9]", value))))
        labels = ["very weak", "weak", "fair", "good", "strong", "very strong"]
        console.print(f"Estimated strength: [bold]{labels[score]}[/]")
        console.print("[dim]This estimate stays on your computer and is never sent anywhere.[/]")
    pause()


def breach_hunter() -> None:
    console.print("[cyan]Opening Have I Been Pwned breach notifications.[/]")
    console.print("[dim]Enter your email on the official site and verify it there. Cros does not collect or save it.[/]")
    webbrowser.open("https://haveibeenpwned.com/NotifyMe")
    pause()


def google_dork() -> None:
    target = Prompt.ask("Domain, username, or phrase").strip()
    mode = Prompt.ask("Search type", choices=["site", "files", "mentions", "custom"], default="mentions")
    queries = {
        "site": f"site:{target}",
        "files": f"site:{target} (filetype:pdf OR filetype:docx OR filetype:xlsx)",
        "mentions": f'"{target}"',
        "custom": target,
    }
    webbrowser.open("https://www.google.com/search?q=" + quote_plus(queries[mode]))


def pastebin_checker() -> None:
    term = Prompt.ask("Username, email, domain, or phrase").strip()
    if term:
        query = f'(site:pastebin.com OR site:rentry.co OR site:hastebin.com) "{term}"'
        webbrowser.open("https://www.google.com/search?q=" + quote_plus(query))


class _LinkCollector(HTMLParser):
    def __init__(self):
        super().__init__(); self.links: list[str] = []
    def handle_starttag(self, tag, attrs):
        if tag.lower() == "a":
            href = dict(attrs).get("href")
            if href: self.links.append(href)


def url_scraper() -> None:
    target = normalize_url(Prompt.ask("Public webpage URL"))
    try:
        response = run_with_loading("Collecting page links", lambda: requests.get(
            target, timeout=12, allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 Cros-OSINT/8.0"}))
        parser = _LinkCollector(); parser.feed(response.text)
        links = sorted({urljoin(response.url, link) for link in parser.links
                        if link and not link.lower().startswith(("javascript:", "mailto:", "tel:"))})
        console.print(f"[green]Found {len(links)} unique links.[/]")
        for index, link in enumerate(links[:100], 1): console.print(f"{index:>3}. {link}")
        if len(links) > 100: console.print(f"[dim]Showing the first 100 of {len(links)}.[/]")
        response.close()
    except (requests.RequestException, ValueError) as exc:
        console.print(f"[red]Could not read that page: {exc}[/]")
    pause()


def subdomain_finder() -> None:
    domain = clean_host(Prompt.ask("Domain"))
    if not domain:
        console.print("[red]Enter a valid domain.[/]"); pause(); return
    try:
        response = run_with_loading("Searching certificates", lambda: requests.get(
            "https://crt.sh/?q=" + quote_plus(f"%.{domain}") + "&output=json",
            timeout=20, headers={"User-Agent": "Cros-OSINT/8.0"}))
        records = json.loads(response.text)
        names = sorted({name.strip().lower() for item in records
                        for name in str(item.get("name_value", "")).splitlines()
                        if name.strip().endswith(domain) and "*" not in name})
        console.print(f"[green]Found {len(names)} certificate-listed subdomains.[/]")
        for name in names[:150]: console.print("  " + name)
        if len(names) > 150: console.print(f"[dim]Showing 150 of {len(names)}.[/]")
        response.close()
    except (requests.RequestException, ValueError, TypeError) as exc:
        console.print(f"[red]Subdomain lookup failed: {exc}[/]")
    pause()


def whois_lookup() -> None:
    domain = clean_host(Prompt.ask("Domain"))
    try:
        response = run_with_loading("Requesting RDAP record", lambda: requests.get(
            "https://rdap.org/domain/" + quote_plus(domain), timeout=15,
            headers={"User-Agent": "Cros-OSINT/8.0"}))
        data = json.loads(response.text)
        events = {item.get("eventAction", "event"): item.get("eventDate", "") for item in data.get("events", [])}
        rows = [("Domain", data.get("ldhName", domain)), ("Handle", data.get("handle", "Unknown")),
                ("Status", ", ".join(data.get("status", [])) or "Unknown"),
                ("Registered", events.get("registration", "Unknown")),
                ("Expires", events.get("expiration", "Unknown")),
                ("Updated", events.get("last changed", "Unknown"))]
        table = Table(title=f"WHOIS / RDAP — {domain}"); table.add_column("Field"); table.add_column("Value")
        for row in rows: table.add_row(*row)
        console.print(table); response.close()
    except (requests.RequestException, ValueError, TypeError) as exc:
        console.print(f"[red]WHOIS lookup failed: {exc}[/]")
    pause()


def image_search() -> None:
    source = os.environ.pop("CROS_SELECTED_IMAGE", "").strip() or Prompt.ask("Image path or public image URL").strip().strip('"')
    if not source:
        return
    if source.startswith(("http://", "https://")):
        console.print("[cyan]Opening free reverse-image and scene searches for that URL.[/]")
        webbrowser.open("https://lens.google.com/uploadbyurl?url=" + quote_plus(source))
        webbrowser.open("https://tineye.com/search?url=" + quote_plus(source))
        pause(); return

    path = Path(source).expanduser()
    if not path.is_file():
        console.print("[red]Image file not found.[/]"); pause(); return
    try:
        analysis = run_with_loading("Analyzing image locally", lambda: analyze_image_file(path))
    except (OSError, RuntimeError, ValueError) as exc:
        console.print(f"[red]Could not inspect image: {exc}[/]"); pause(); return
    rows = [
        ("File", analysis["file_name"]),
        ("Size", f"{analysis['size_bytes']:,} bytes"),
        ("Format / MIME", f"{analysis['format']} / {analysis['mime']}"),
        ("Dimensions", f"{analysis['width']} x {analysis['height']} ({analysis['megapixels']} MP)"),
        ("Color / frames", f"{analysis['mode']} / {analysis['frames']}"),
        ("Brightness", f"{analysis['brightness']} / 255"),
        ("Contrast", str(analysis["contrast"])),
        ("Image entropy", f"{analysis['entropy']} bits"),
        ("Edge strength", str(analysis["edge_strength"])),
        ("Average hash", analysis["average_hash"]),
        ("SHA-256", analysis["sha256"]),
    ]
    rows.extend((item["label"], item["value"]) for item in analysis["metadata"])
    gps = analysis.get("gps")
    if gps:
        rows.append(("GPS", f"{gps['latitude']:.6f}, {gps['longitude']:.6f}"))
    table = Table(title="LOCAL PHOTO OSINT"); table.add_column("Field"); table.add_column("Result", overflow="fold")
    for row in rows: table.add_row(*row)
    console.print(table)
    if gps:
        console.print("[green]Embedded GPS found. Opening the coordinates is optional.[/]")
        if Confirm.ask("Open GPS location in Maps?", default=False):
            webbrowser.open(f"https://www.google.com/maps?q={gps['latitude']},{gps['longitude']}")
    else:
        console.print("[yellow]No embedded GPS found. Visual location clues require reverse-image/scene matching.[/]")
    console.print(Panel.fit(
        f"{analysis['generator_note']}\n\n{analysis['ai_note']}\n\n{analysis['face_note']}",
        title="FACE / AI FORENSIC GUIDANCE",
    ))
    if Confirm.ask("Open free Google Lens and TinEye searches?", default=True):
        console.print(f"[cyan]Upload this file in the browser:[/] {path}")
        webbrowser.open("https://lens.google.com/")
        webbrowser.open("https://tineye.com/")
    pause()


def change_color() -> None:
    theme = Prompt.ask("Wing/title color", choices=list(ANSI), default=str(settings.get("theme", "red")))
    panel = Prompt.ask("All three box-border colors", choices=list(ANSI), default=str(settings.get("panel_color", "cyan")))
    settings["theme"] = theme
    settings["panel_color"] = panel
    save_settings()
    console.print(f"[green]Wings/title: {theme}. All box borders: {panel}.[/]"); pause()


def show_about() -> None:
    console.print(Panel.fit("CROS OSINT TOOL\nVersion 8.0\nMade by Cros\n\nPublic-source account, domain, network, archive, photo metadata, reverse-image, analysis, and case-workspace tools.\nUse only on information and systems you are authorized to investigate.", title="About"))
    pause()


def email_header_analyzer() -> None:
    path = Path(Prompt.ask("Path to an .eml or text header file").strip().strip('"')).expanduser()
    if not path.is_file():
        console.print("[red]Header file not found.[/]"); pause(); return
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
        message = Parser(policy=email.policy.default).parsestr(raw, headersonly=True)
        rows = []
        for name in ("From", "To", "Reply-To", "Return-Path", "Subject", "Date", "Message-ID"):
            if message.get(name): rows.append((name, str(message.get(name))))
        received = message.get_all("Received", [])
        ips = []
        for header in received:
            for candidate in re.findall(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])", str(header)):
                try:
                    address = ipaddress.ip_address(candidate)
                    if str(address) not in ips: ips.append(str(address))
                except ValueError:
                    pass
        rows.extend([("Received hops", str(len(received))),
                     ("Observed IPs", ", ".join(ips) or "None found"),
                     ("SPF header", "Present" if message.get("Received-SPF") else "Not present"),
                     ("DKIM signature", "Present" if message.get("DKIM-Signature") else "Not present"),
                     ("Authentication results", str(message.get("Authentication-Results", "Not present")))])
        table = Table(title="EMAIL HEADER ANALYSIS"); table.add_column("Field"); table.add_column("Value", overflow="fold")
        for row in rows: table.add_row(*row)
        console.print(table)
        console.print("[dim]Header fields can be forged. Treat these as leads, not proof.[/]")
    except OSError as exc:
        console.print(f"[red]Could not read headers: {exc}[/]")
    pause()


def redirect_tracer() -> None:
    target = normalize_url(Prompt.ask("URL"))
    hops: list[tuple[int, str]] = []
    class Tracker(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            hops.append((code, newurl))
            return super().redirect_request(req, fp, code, msg, headers, newurl)
    try:
        opener = urllib.request.build_opener(Tracker())
        request = urllib.request.Request(target, headers={"User-Agent": "Cros-OSINT/8.0"})
        def follow():
            response = opener.open(request, timeout=12)
            try: return response.geturl(), getattr(response, "status", 200)
            finally: response.close()
        final, status = run_with_loading("Tracing redirects", follow)
        table = Table(title="REDIRECT CHAIN"); table.add_column("Step"); table.add_column("Status"); table.add_column("URL", overflow="fold")
        table.add_row("0", "start", target)
        for index, (code, url) in enumerate(hops, 1): table.add_row(str(index), str(code), url)
        table.add_row(str(len(hops) + 1), str(status), final)
        console.print(table)
    except (urllib.error.URLError, OSError, ValueError) as exc:
        console.print(f"[red]Redirect check failed: {exc}[/]")
    pause()


class _MetaCollector(HTMLParser):
    def __init__(self):
        super().__init__(); self.in_title = False; self.title = ""; self.meta = {}; self.canonical = ""
    def handle_starttag(self, tag, attrs):
        values = {str(k).lower(): str(v) for k, v in attrs if v is not None}
        if tag.lower() == "title": self.in_title = True
        if tag.lower() == "meta":
            key = values.get("property") or values.get("name")
            if key and values.get("content"): self.meta[key.lower()] = values["content"]
        if tag.lower() == "link" and "canonical" in values.get("rel", "").lower():
            self.canonical = values.get("href", "")
    def handle_endtag(self, tag):
        if tag.lower() == "title": self.in_title = False
    def handle_data(self, data):
        if self.in_title: self.title += data


def web_metadata() -> None:
    target = normalize_url(Prompt.ask("Public webpage URL"))
    try:
        response = run_with_loading("Reading page metadata", lambda: requests.get(
            target, timeout=12, allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 Cros-OSINT/8.0"}))
        parser = _MetaCollector(); parser.feed(response.text[:2_000_000])
        rows = [("Status", str(response.status_code)), ("Final URL", response.url),
                ("Title", parser.title.strip() or "Not found"),
                ("Description", parser.meta.get("description", "Not found")),
                ("OpenGraph title", parser.meta.get("og:title", "Not found")),
                ("OpenGraph image", parser.meta.get("og:image", "Not found")),
                ("Canonical", urljoin(response.url, parser.canonical) if parser.canonical else "Not found")]
        table = Table(title="WEB PAGE METADATA"); table.add_column("Field"); table.add_column("Value", overflow="fold")
        for row in rows: table.add_row(*row)
        console.print(table); response.close()
    except (requests.RequestException, ValueError) as exc:
        console.print(f"[red]Metadata scan failed: {exc}[/]")
    pause()


def reverse_dns() -> None:
    value = clean_host(Prompt.ask("IP address or domain"))
    try:
        address = str(ipaddress.ip_address(value)) if value else ""
    except ValueError:
        try: address = socket.gethostbyname(value)
        except socket.gaierror as exc:
            console.print(f"[red]Resolution failed: {exc}[/]"); pause(); return
    try:
        hostname, aliases, addresses = socket.gethostbyaddr(address)
        console.print(Panel.fit(f"IP: {address}\nHostname: {hostname}\nAliases: {', '.join(aliases) or 'None'}\nAddresses: {', '.join(addresses)}", title="Reverse DNS"))
    except socket.herror:
        console.print(f"[yellow]No reverse-DNS record found for {address}.[/]")
    pause()


def cidr_calculator() -> None:
    value = Prompt.ask("IP/CIDR", default="192.168.1.10/24").strip()
    try:
        network = ipaddress.ip_network(value, strict=False)
        if network.num_addresses > 2:
            first = network.network_address + 1; last = network.broadcast_address - 1
        else:
            first = network.network_address; last = network.broadcast_address
        rows = [("Version", f"IPv{network.version}"), ("Network", str(network.network_address)),
                ("Prefix", f"/{network.prefixlen}"), ("Netmask", str(network.netmask)),
                ("Broadcast / last", str(network.broadcast_address)),
                ("First usable", str(first)), ("Last usable", str(last)),
                ("Total addresses", f"{network.num_addresses:,}"),
                ("Private", str(network.is_private)), ("Global", str(network.is_global))]
        table = Table(title="CIDR / SUBNET CALCULATOR"); table.add_column("Field"); table.add_column("Value")
        for row in rows: table.add_row(*row)
        console.print(table)
    except ValueError as exc:
        console.print(f"[red]Invalid network: {exc}[/]")
    pause()


def base64_tools() -> None:
    mode = Prompt.ask("Mode", choices=["encode", "decode"], default="encode")
    value = Prompt.ask("Text")
    try:
        if mode == "encode": result = base64.b64encode(value.encode("utf-8")).decode("ascii")
        else: result = base64.b64decode(value, validate=True).decode("utf-8", errors="replace")
        console.print(Panel.fit(result, title=f"Base64 {mode}"))
    except (ValueError, UnicodeError) as exc:
        console.print(f"[red]Base64 operation failed: {exc}[/]")
    pause()


def hash_identifier() -> None:
    value = Prompt.ask("Hash value").strip().lower()
    if not re.fullmatch(r"[0-9a-f]+", value):
        console.print("[red]That is not a hexadecimal hash.[/]"); pause(); return
    guesses = {32: "MD5 or NTLM", 40: "SHA-1", 56: "SHA-224", 64: "SHA-256",
               96: "SHA-384", 128: "SHA-512"}
    console.print(Panel.fit(f"Length: {len(value)} hexadecimal characters\nLikely type: {guesses.get(len(value), 'Unknown or application-specific')}", title="Hash Identifier"))
    console.print("[dim]Length identifies possible formats, not a guaranteed algorithm.[/]"); pause()


def timestamp_converter() -> None:
    value = Prompt.ask("Unix timestamp or ISO date", default=str(int(datetime.now(timezone.utc).timestamp()))).strip()
    try:
        if re.fullmatch(r"-?\d+(?:\.\d+)?", value):
            stamp = float(value); moment = datetime.fromtimestamp(stamp, tz=timezone.utc)
        else:
            moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if moment.tzinfo is None: moment = moment.replace(tzinfo=timezone.utc)
            moment = moment.astimezone(timezone.utc); stamp = moment.timestamp()
        local = moment.astimezone()
        console.print(Panel.fit(f"Unix: {stamp:.3f}\nUTC: {moment.isoformat()}\nLocal: {local.isoformat()}", title="Timestamp Converter"))
    except (ValueError, OSError, OverflowError) as exc:
        console.print(f"[red]Could not convert timestamp: {exc}[/]")
    pause()


def json_formatter() -> None:
    value = Prompt.ask("JSON text or path to a .json file").strip().strip('"')
    try:
        path = Path(value).expanduser()
        try: is_file = path.is_file()
        except OSError: is_file = False
        raw = path.read_text(encoding="utf-8") if is_file else value
        parsed = json.loads(raw)
        formatted = json.dumps(parsed, indent=2, ensure_ascii=False, sort_keys=True)
        console.print(formatted, markup=False)
    except (OSError, ValueError, TypeError) as exc:
        console.print(f"[red]Invalid JSON: {exc}[/]")
    pause()


def coordinate_helper() -> None:
    value = Prompt.ask("Latitude, longitude", default="34.0522, -118.2437")
    match = re.fullmatch(r"\s*(-?\d+(?:\.\d+)?)\s*[, ]\s*(-?\d+(?:\.\d+)?)\s*", value)
    if not match:
        console.print("[red]Use latitude, longitude format.[/]"); pause(); return
    lat, lon = map(float, match.groups())
    if not (-90 <= lat <= 90 and -180 <= lon <= 180):
        console.print("[red]Coordinates are outside valid ranges.[/]"); pause(); return
    google = f"https://www.google.com/maps?q={lat},{lon}"
    osm = f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=16/{lat}/{lon}"
    console.print(Panel.fit(f"Latitude: {lat}\nLongitude: {lon}\nGoogle Maps: {google}\nOpenStreetMap: {osm}", title="Coordinate Helper"))
    if Confirm.ask("Open maps?", default=False): webbrowser.open(google); webbrowser.open(osm)
    pause()


def case_notes() -> None:
    name = re.sub(r"[^A-Za-z0-9_.-]+", "_", Prompt.ask("Case name").strip()).strip("_") or "case"
    note = Prompt.ask("Note").strip()
    if not note: return
    case_dir = APP_DIR / "cases"; case_dir.mkdir(exist_ok=True)
    path = case_dir / f"{name}.md"
    entry = f"\n## {datetime.now().astimezone():%Y-%m-%d %H:%M:%S %Z}\n\n{note}\n"
    try:
        with path.open("a", encoding="utf-8") as handle: handle.write(entry)
        console.print(f"[green]Saved locally:[/] {path}")
    except OSError as exc:
        console.print(f"[red]Could not save note: {exc}[/]")
    pause()


def file_type_inspector() -> None:
    path = Path(Prompt.ask("Full path to a file").strip().strip('"')).expanduser()
    if not path.is_file():
        console.print("[red]File not found.[/]"); pause(); return
    signatures = [
        (b"MZ", "Windows PE executable"), (b"%PDF-", "PDF document"),
        (b"PK\x03\x04", "ZIP or Office container"), (b"\x89PNG\r\n\x1a\n", "PNG image"),
        (b"\xff\xd8\xff", "JPEG image"), (b"GIF87a", "GIF image"), (b"GIF89a", "GIF image"),
        (b"Rar!\x1a\x07", "RAR archive"), (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
        (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "Legacy Office/OLE container"),
        (b"SQLite format 3\x00", "SQLite database"), (b"\x7fELF", "ELF executable"),
    ]
    try:
        with path.open("rb") as handle:
            header = handle.read(32)
        detected = next((name for magic, name in signatures if header.startswith(magic)), "Unknown signature")
        mime = mimetypes.guess_type(path.name)[0] or "Unknown"
        extension = path.suffix.lower() or "None"
        warning = "Review extension and signature manually"
        executable_extensions = {".exe", ".dll", ".scr", ".sys", ".com"}
        if detected == "Windows PE executable" and extension not in executable_extensions:
            warning = "MISMATCH: executable bytes use a non-executable extension"
        elif detected != "Unknown signature":
            warning = "Header signature recognized"
        rows = [
            ("File", path.name), ("Extension", extension), ("MIME guess", mime),
            ("Header signature", detected), ("First bytes", header[:16].hex(" ").upper()),
            ("Assessment", warning),
        ]
        result = Table(title="Local File Type Inspector")
        result.add_column("Signal"); result.add_column("Value", overflow="fold")
        for row in rows: result.add_row(*row)
        console.print(result)
        console.print("[dim]No file content was uploaded or executed.[/]")
    except OSError as exc:
        console.print(f"[red]Could not inspect file: {exc}[/]")
    pause()


def ioc_normalizer() -> None:
    value = Prompt.ask("Indicators or path to a text file").strip().strip('"')
    try:
        candidate = Path(value).expanduser()
        raw = candidate.read_text(encoding="utf-8", errors="replace") if candidate.is_file() else value
    except OSError:
        raw = value
    tokens = [token.strip(" \t\r\n,;<>[](){}'\"") for token in re.split(r"[\s,;]+", raw)]
    rows = []
    seen = set()
    for token in filter(None, tokens):
        kind = "Unknown"
        normalized = token
        try:
            normalized = str(ipaddress.ip_address(token.strip("[]")))
            kind = "IPv6" if ":" in normalized else "IPv4"
        except ValueError:
            lower = token.lower()
            if re.fullmatch(r"[0-9a-fA-F]{32}", token): kind, normalized = "MD5 / NTLM shape", lower
            elif re.fullmatch(r"[0-9a-fA-F]{40}", token): kind, normalized = "SHA-1", lower
            elif re.fullmatch(r"[0-9a-fA-F]{64}", token): kind, normalized = "SHA-256", lower
            elif re.fullmatch(r"[0-9a-fA-F]{128}", token): kind, normalized = "SHA-512", lower
            elif re.match(r"^https?://", token, re.I):
                try:
                    parsed = urllib.parse.urlsplit(token)
                    host = (parsed.hostname or "").lower()
                    port = parsed.port
                    netloc = host + (f":{port}" if port else "")
                    normalized = urllib.parse.urlunsplit((parsed.scheme.lower(), netloc, parsed.path or "/", parsed.query, ""))
                    kind = "URL"
                except ValueError:
                    pass
            elif re.fullmatch(r"(?i)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", token.rstrip(".")):
                kind, normalized = "Domain", token.rstrip(".").lower()
        key = (kind, normalized)
        if key in seen: continue
        seen.add(key); rows.append([kind, normalized])
    table_data = Table(title="Normalized Indicators")
    table_data.add_column("Type"); table_data.add_column("Normalized value", overflow="fold")
    for row in rows: table_data.add_row(*row)
    console.print(table_data)
    console.print(f"[dim]{len(rows)} unique value(s). Unknown values are retained instead of guessed.[/]")
    pause()


def text_file_compare() -> None:
    first = Path(Prompt.ask("First text file").strip().strip('"')).expanduser()
    second = Path(Prompt.ask("Second text file").strip().strip('"')).expanduser()
    if not first.is_file() or not second.is_file():
        console.print("[red]Both paths must be existing files.[/]"); pause(); return
    try:
        if first.stat().st_size > 2_000_000 or second.stat().st_size > 2_000_000:
            console.print("[yellow]Files must be 2 MB or smaller for this local comparison.[/]"); pause(); return
        left = first.read_text(encoding="utf-8", errors="replace").splitlines()
        right = second.read_text(encoding="utf-8", errors="replace").splitlines()
        changes = list(difflib.unified_diff(left, right, fromfile=first.name, tofile=second.name, lineterm=""))
        if not changes:
            console.print("[green]The decoded text is identical.[/]")
        else:
            console.print("\n".join(changes[:500]), markup=False)
            if len(changes) > 500: console.print(f"[yellow]Showing 500 of {len(changes)} diff lines.[/]")
    except OSError as exc:
        console.print(f"[red]Could not compare files: {exc}[/]")
    pause()


def jwt_decoder() -> None:
    token = Prompt.ask("JWT value", password=True).strip()
    parts = token.split(".")
    if len(parts) not in {2, 3}:
        console.print("[red]A JWT normally contains two or three dot-separated parts.[/]"); pause(); return
    try:
        decoded = []
        for part in parts[:2]:
            padded = part + "=" * (-len(part) % 4)
            decoded.append(json.loads(base64.urlsafe_b64decode(padded).decode("utf-8")))
        console.print(Panel(json.dumps(decoded[0], indent=2, ensure_ascii=False), title="JWT HEADER"))
        console.print(Panel(json.dumps(decoded[1], indent=2, ensure_ascii=False), title="JWT PAYLOAD"))
        console.print("[yellow]Decoded locally only. The signature was not verified, so claims are untrusted.[/]")
    except (ValueError, UnicodeError, json.JSONDecodeError) as exc:
        console.print(f"[red]Could not decode JWT: {exc}[/]")
    pause()


def open_tutorial() -> None:
    choice = Prompt.ask("Tutorial", choices=["show", "skip"], default="show")
    if choice == "skip":
        return
    console.print(Panel(
        "The complete tutorial now lives inside the Cros desktop app.\n\n"
        "1. Return to the desktop app window.\n"
        "2. Select Guide or Learning Center.\n"
        "3. Choose any of the 92 tool lessons, Guided Paths, or Sources.\n"
        "4. Use Learn on a tool card to jump directly to that lesson.\n\n"
        "Nothing opens in Visual Studio Code.",
        title="IN-APP LEARNING CENTER",
        border_style=str(settings.get("panel_color", "cyan")),
    ))
    pause()


def launch_security_center() -> None:
    try:
        import security_tools
        if os.environ.get("CROS_EMBEDDED") == "1":
            security_tools.webbrowser.open = lambda url, *_args, **_kwargs: (console.print(f"\nExternal research link (copy when needed):\n{url}\n", markup=False) or True)
        security_tools.security_center(str(settings.get("panel_color", "cyan")))
    except ImportError as exc:
        console.print(f"[red]Security Center could not load: {exc}[/]"); pause()


ADVANCED_PANELS = [
    [("1", "HTTP Headers"), ("2", "Domain Overview"), ("3", "Discovery Files"),
     ("4", "URL Analyzer"), ("5", "Redirect Tracer"), ("6", "Web Metadata"),
     ("7", "Email Header Scan")],
    [("8", "File Checksums"), ("9", "Password Helper"), ("10", "Reverse DNS"),
     ("11", "CIDR Calculator"), ("12", "Base64 Tools"), ("13", "Hash Identifier"),
     ("14", "Timestamp Converter")],
    [("15", "JSON Formatter"), ("16", "Coordinate Helper"), ("17", "Case Notes"),
     ("18", "Account Setup"), ("19", "Diagnostics"), ("20", "Full Tutorial"),
     ("21", "File Type Inspector"), ("22", "IOC Normalizer"),
     ("23", "Text File Compare"), ("24", "JWT Decoder"), ("0", "Back")],
]

ADVANCED_ACTIONS = {
    "1": headers_check, "2": domain_overview, "3": robots_and_sitemap,
    "4": url_analyzer, "5": redirect_tracer, "6": web_metadata,
    "7": email_header_analyzer, "8": file_hash, "9": password_helper,
    "10": reverse_dns, "11": cidr_calculator, "12": base64_tools,
    "13": hash_identifier, "14": timestamp_converter, "15": json_formatter,
    "16": coordinate_helper, "17": case_notes, "18": blackbird_setup,
    "19": diagnostics, "20": open_tutorial, "21": file_type_inspector,
    "22": ioc_normalizer, "23": text_file_compare, "24": jwt_decoder,
}


def more_tools() -> None:
    while True:
        os.system("cls" if os.name == "nt" else "clear")
        enable_terminal_colors()
        color = str(settings.get("panel_color", "cyan"))
        print(paint("\n" + "=" * 104, color))
        print(paint("CROS ADVANCED TOOLKIT".center(104), color, bold=True))
        print(paint("=" * 104 + "\n", color))
        boxes = [classic_box(title, items, color) for title, items in zip(
            ("WEB INTELLIGENCE", "NETWORK + DATA", "WORKSPACE"), ADVANCED_PANELS)]
        for row in zip(*boxes): print("   ".join(row))
        choice = Prompt.ask("Select an advanced tool", default="0")
        if choice == "0": return
        action = ADVANCED_ACTIONS.get(choice)
        if action: action()


def customize() -> None:
    console.print("[bold]Customize the small menu boxes[/]")
    settings["theme"] = Prompt.ask("Main color", default=str(settings["theme"]))
    settings["box_style"] = Prompt.ask("Border style", choices=list(BOXES), default=str(settings["box_style"]))
    settings["panel_width"] = IntPrompt.ask("Panel width", default=int(settings["panel_width"]))
    settings["title"] = Prompt.ask("Banner title", default=str(settings["title"]))
    settings["tagline"] = Prompt.ask("Banner subtitle", default=str(settings["tagline"]))
    settings["show_wings"] = Confirm.ask("Show wings?", default=bool(settings["show_wings"]))
    settings["panel_color"] = Prompt.ask("One color for all box borders", choices=list(ANSI), default=str(settings.get("panel_color", "cyan")))
    for i in range(3):
        settings["panel_titles"][i] = Prompt.ask(f"Box {i+1} title", default=settings["panel_titles"][i])
    custom = Prompt.ask("Account engine folder (blank = auto-detect)", default=str(settings["blackbird_path"]))
    settings["blackbird_path"] = custom
    settings["blackbird_timeout"] = IntPrompt.ask("Search timeout", default=int(settings["blackbird_timeout"]))
    settings["blackbird_concurrency"] = IntPrompt.ask("Concurrent searches", default=int(settings["blackbird_concurrency"]))
    settings["blackbird_no_nsfw"] = Confirm.ask("Hide NSFW sites?", default=bool(settings["blackbird_no_nsfw"]))
    save_settings(); console.print(f"[green]Saved to {SETTINGS_FILE}[/]"); pause()


PANELS = [
    [("1", "Username (Single)"), ("2", "Username (Combos)"), ("3", "Search Email"),
     ("4", "Breach Hunter"), ("5", "Port Scanner"), ("6", "Website History"),
     ("7", "Google Dorking"), ("8", "Pastebin Checker"), ("9", "URL Scraper")],
    [("10", "IP Lookup"), ("11", "Subdomain Finder"), ("12", "WHOIS Lookup"),
     ("13", "DNS Lookup"), ("14", "SSL Checker")],
    [("15", "Photo / Face OSINT"), ("16", "Hash Generator"), ("17", "Change Color"),
     ("18", "About"), ("19", "Exit"), ("20", "More Tools"), ("21", "Security Center")],
]


WINGS = r'''
  ⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂                                   ⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂
 ⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂                               ⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂
    ⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂                           ⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂
       ⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂                 ⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂
          ⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂             ⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂
             ⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂       ⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂
                ⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂   ⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂
                  ⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂⠂
'''

def build_wings() -> str:
    rows = [
        "        . . . . . . . .", "      . . . . . . . . . .", "    . . . . . . . . . . . .",
        "   . . . . . . . . . . . . .", "  . . . . . . . . . . . . . .",
        " . . . . . . . . . . . . . . .", ". . . . . . . . . . . . . . . .",
        " . . . . . . . . . . . . . . .", "  . . . . . . . . . . . . . .",
        "   . . . . . . . . . . . . .", "    . . . . . . . . . . . .",
        "      . . . . . . . . . .", "        . . . . . . . .",
    ]
    return "\n".join(left + " " * max(8, 74 - 2 * len(left)) + left[::-1] for left in rows)


# Original Cros wings, preserved as UTF-8 by the Windows launcher.
WINGS = '''
⣆⠈⠳⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡠⠴⠒⢲
⠘⢦⡀⠀⠙⠲⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡤⠖⠉⠀⢀⡴⠋
⠀⢻⣍⠲⢄⡐⠤⣉⠓⠦⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⠴⠚⣁⠀⠀⣀⡴⠟⣪⠇
⠠⡤⠽⢦⣀⠈⠑⠢⢍⣒⠤⣉⡒⠤⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⠴⠚⣉⠤⢒⣩⠴⠒⠉⢁⡠⣚⢥⠀
⠀⠙⢶⡀⠈⠙⠒⠤⣐⡪⠭⣒⡘⢍⡁⢍⣒⠢⢄⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣤⣖⢪⠭⠈⣉⠽⣐⠮⢕⣊⡤⠤⠒⠋⢉⡤⠊⠀
⠀⠀⠰⡛⠓⠢⢤⣀⡀⠬⢝⣒⡪⢏⡈⠝⣒⡨⣿⢿⡑⢦⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣴⠏⡰⢅⣖⡲⠾⠍⣩⢯⣒⣋⠥⢤⣒⠠⠤⠐⢛⡶⠂⠀
⠀⠀⠀⠈⣒⠤⢄⣀⡈⠍⣒⡒⠠⠵⣏⠙⠒⢺⣅⢿⡍⠀⣇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⡏⠀⣹⢥⡗⠶⠌⣉⠯⠔⣒⣊⠩⠁⠀⣀⣠⣖⣏⠀⠀⠀
⠀⠀⠀⠀⠑⢤⡀⠀⠈⠉⠒⠒⠫⠭⢼⣛⠒⠒⡧⣽⣏⡀⢸⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⠁⣈⣷⡲⡏⠉⣙⡯⠭⠥⠒⠒⠊⠉⠉⠀⢀⡴⠃⠀⠀⠀
⠀⠀⠀⠀⠀⠠⡌⠙⠒⠊⠬⠭⠥⠤⠰⣞⡉⠉⣟⡵⣯⣠⠀⠑⢤⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡤⠚⡁⢠⡾⣟⣍⡎⠭⢖⣏⣉⡥⠤⠤⠤⠤⠴⠭⡅⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠙⠲⠤⢀⡀⠀⠀⠀⠴⠦⢍⡉⢿⡜⡽⢸⢾⣦⣤⠉⡕⢲⣒⡆⠀⠀⠀⠀⠀⠀⡖⣺⠻⣏⣰⣄⣿⣟⡼⡿⣾⣞⣉⠿⠭⢐⣀⣀⣀⣀⣤⡴⠚⠁⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠰⢏⣉⠉⠀⣀⣠⢴⠖⠽⡴⣞⢿⣇⣎⠋⡇⢫⢻⡱⣞⣿⡤⡄⠀⠀⠀⠀⡼⣽⣟⡟⢿⢛⣎⡏⣾⢮⣟⣽⡷⡛⠧⢖⣒⣂⢀⣀⣀⠴⠃⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠀⢀⠖⠁⡴⢋⡤⡳⢻⢀⢿⢹⢹⢞⢳⢏⣯⣹⠳⡷  ⣹⡏⢻⣯⣻⢹⢱⣟⢼⢻⣳⡌⠑⠄⠑⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣀⠤⢒⣟⠜⢁⡎⡝⡸⡶⢻⢳⢯⣢⠻⡝⡌⢮⠿⠀⢸⣪⡎⡰⣫⢷⣻⢳⢻⠒⡿⡝⡍⣆⠱⠜⣶⠤⠄⡸⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣊⠴⠻⠜⢠⡇⠃⢸⡸⠀⣧⠃⢸⢆⡼⠀⠀⠀⠘⠦⢞⡇⢪⠇⠘⣸⠀⡗⣧⢳⢸⠙⠦⠼⠆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢫⣠⠋⡇⢠⠎⢧⢂⡜⠢⠎⠀⠀⠀⠀⠀⠀⠀⠈⠧⠾⡄⣠⠋⢧⣠⠎⠣⡼⠀
'''
ANSI = {"red": "91", "blue": "94", "green": "92", "cyan": "96", "magenta": "95", "yellow": "93", "white": "97"}


def paint(value: str, color: str = "white", bold: bool = False) -> str:
    return f"\x1b[{1 if bold else 0};{ANSI.get(color, '97')}m{value}\x1b[0m"


def enable_terminal_colors() -> None:
    if os.name != "nt":
        return
    try:
        handle = ctypes.windll.kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if ctypes.windll.kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            ctypes.windll.kernel32.SetConsoleMode(handle, mode.value | 0x0004)
    except Exception:
        pass


def classic_box(title: str, items: list[tuple[str, str]], color: str, width: int = 31) -> list[str]:
    width = max(26, width)
    label = f"[ {title} ]"
    top = "+-" + label + "-" * max(0, width - len(label) - 2) + "+"
    lines = [top]
    for number, text in items:
        entry = f" {number:>2}  {text}"
        lines.append("|" + entry[:width].ljust(width) + "|")
    # Match the original three-panel layout: nine item rows in every box.
    while len(lines) < 10:
        lines.append("|" + " " * width + "|")
    lines.append("+" + "-" * width + "+")
    return [paint(line, color) if index in (0, len(lines) - 1) else paint(line[:2], color) + line[2:-1] + paint(line[-1], color)
            for index, line in enumerate(lines)]


def classic_menu() -> str:
    if os.name == "nt": os.system("color 0F")
    enable_terminal_colors()
    theme = str(settings.get("theme", "red"))
    print(paint(WINGS, theme))
    title = settings["title"].center(74)
    subtitle = "Made by Cros".center(74)
    print(paint("+" + "=" * 74 + "+", theme))
    print(paint("|", theme) + title + paint("|", theme))
    print(paint("|", "white") + subtitle + paint("|", "white"))
    print(paint("+" + "=" * 74 + "+\n", "white"))
    colors = [str(settings.get("panel_color", "cyan"))] * 3
    boxes = [classic_box(settings["panel_titles"][i], items, colors[i]) for i, items in enumerate(PANELS)]
    for row in zip(*boxes): print("   ".join(row))
    return input("\n[ Select a tool ] > ").strip() or "0"


def menu() -> str:
    os.system("cls" if os.name == "nt" else "clear")
    if not RICH_AVAILABLE:
        return classic_menu()
    theme = settings["theme"]
    if settings.get("show_wings", True):
        console.print(f"[{theme}]{WINGS}[/]", justify="center")
    console.print(Panel.fit(f"[bold]{settings['title']}[/]\n[dim]{settings['tagline']}[/]", border_style=theme, box=BOXES.get(settings["box_style"], box.ROUNDED)), justify="center")
    panels = []
    for i, items in enumerate(PANELS):
        body = "\n".join(f"[bold]{number:>2}[/]  {label}" for number, label in items)
        panels.append(Panel(body, title=settings["panel_titles"][i], border_style=settings.get("panel_color", "cyan"), width=int(settings["panel_width"]), box=BOXES.get(settings["box_style"], box.ROUNDED)))
    console.print(Columns(panels, equal=True, expand=True))
    return Prompt.ask("Choose a tool", default="0").strip()


MAIN_ACTIONS = {
    "1": username_search, "2": lambda: username_search(True), "3": email_search,
    "4": breach_hunter, "5": port_check, "6": wayback, "7": google_dork,
    "8": pastebin_checker, "9": url_scraper, "10": ip_lookup,
    "11": subdomain_finder, "12": whois_lookup, "13": dns_lookup,
    "14": ssl_check, "15": image_search, "16": hash_text,
    "17": change_color, "18": show_about, "20": more_tools,
    "21": launch_security_center,
}


def main() -> None:
    while True:
        try: choice = menu()
        except (KeyboardInterrupt, EOFError): break
        if choice in {"0", "19"}: break
        action = MAIN_ACTIONS.get(choice)
        if action: action()
        else: console.print("[red]Invalid choice.[/]")
    console.print("[bold]Goodbye.[/]")


if __name__ == "__main__":
    main()
