"""Defensive, local-first Windows security utilities for Cros OSINT Tool."""

from __future__ import annotations

import concurrent.futures
import csv
import hashlib
import ipaddress
import json
import math
import os
import re
import secrets
import socket
import stat
import subprocess
import sys
import time
import urllib.parse
import webbrowser
import zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

try:
    import winreg
except ImportError:
    winreg = None

APP_DIR = Path(__file__).resolve().parent
REPORT_DIR = APP_DIR / "security_reports"
BASELINE_DIR = APP_DIR / "security_baselines"

ANSI = {"red": "91", "blue": "94", "green": "92", "cyan": "96",
        "magenta": "95", "yellow": "93", "white": "97"}

REMOTE_TOOL_TERMS = {
    "anydesk", "teamviewer", "rustdesk", "screenconnect", "connectwisecontrol",
    "radmin", "tightvnc", "ultravnc", "winvnc", "realvnc", "dwagent",
    "dwservice", "meshagent", "aeroadmin", "ammyy", "supremo", "remcos",
    "njrat", "quasar", "darkcomet", "asyncrat", "netsupport", "ngrok",
    "cloudflared", "localtonet", "tailscale", "zerotier",
}
SUSPICIOUS_COMMAND_TERMS = {
    "-encodedcommand", " -enc ", "frombase64string", "downloadstring",
    "invoke-expression", "iex(", "windowstyle hidden", "wscript.shell",
    "mshta ", "regsvr32 /s", "rundll32 javascript:", "certutil -decode",
}
RISKY_EXTENSIONS = {
    ".exe", ".scr", ".com", ".msi", ".msp", ".bat", ".cmd", ".ps1",
    ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".lnk", ".iso",
    ".img", ".dll", ".sys", ".jar", ".docm", ".xlsm", ".pptm", ".xll",
}
TEXT_EXTENSIONS = {
    ".txt", ".md", ".py", ".js", ".ts", ".tsx", ".jsx", ".json", ".yaml",
    ".yml", ".toml", ".ini", ".cfg", ".conf", ".env", ".xml", ".html",
    ".css", ".ps1", ".bat", ".cmd", ".sh", ".java", ".cs", ".go", ".rs",
}
SECRET_PATTERNS = {
    "Private key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "AWS access key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "GitHub token": re.compile(r"\bgh[opurs]_[A-Za-z0-9_]{20,255}\b"),
    "Slack token": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"),
    "Google API key": re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    "Possible assigned secret": re.compile(r"(?i)\b(?:api[_-]?key|secret|token|password|passwd)\b\s*[:=]\s*['\"][^'\"\r\n]{8,}['\"]"),
}


def paint(value: str, color: str = "white", bold: bool = False) -> str:
    return f"\x1b[{1 if bold else 0};{ANSI.get(color, '97')}m{value}\x1b[0m"


def pause() -> None:
    input("\nPress Enter to continue...")


def confirm(question: str, default: bool = False) -> bool:
    suffix = "Y/n" if default else "y/N"
    answer = input(f"{question} [{suffix}]: ").strip().lower()
    if not answer: return default
    return answer in {"y", "yes"}


def loading(label: str, operation):
    width = 28; tick = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(operation)
        while not future.done():
            filled = 2 + tick % (width - 3)
            sys.stdout.write(f"\r{label:<30} [{'#' * filled}{'-' * (width - filled)}]")
            sys.stdout.flush(); tick += 1; time.sleep(0.08)
        result = future.result()
    sys.stdout.write(f"\r{label:<30} [{'#' * width}] complete\n"); sys.stdout.flush()
    return result


def command(args: list[str], timeout: int = 45) -> tuple[int, str, str]:
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        result = subprocess.run(args, capture_output=True, text=True, encoding="utf-8",
                                errors="replace", timeout=timeout, creationflags=flags, check=False)
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 1, "", str(exc)


def powershell(script: str, timeout: int = 60) -> tuple[int, str, str]:
    prefix = "$ProgressPreference='SilentlyContinue'; $ErrorActionPreference='Stop'; "
    return command(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", prefix + script], timeout)


def powershell_json(script: str, timeout: int = 60) -> list[dict]:
    code, output, error = powershell(f"@({script}) | ConvertTo-Json -Depth 4 -Compress", timeout)
    if code or not output:
        if error: raise RuntimeError(error.splitlines()[-1])
        return []
    data = json.loads(output)
    if isinstance(data, dict): return [data]
    return data if isinstance(data, list) else []


def table(title: str, headers: list[str], rows: list[list[object]], limit: int = 100) -> None:
    print(paint(f"\n{title}", "cyan", bold=True))
    if not rows:
        print("No entries found."); return
    shown = rows[:limit]
    widths = []
    for index, header in enumerate(headers):
        widths.append(min(55, max(len(header), *(len(str(row[index])) if index < len(row) else 0 for row in shown))))
    print(" | ".join(header.ljust(widths[i]) for i, header in enumerate(headers)))
    print("-+-".join("-" * width for width in widths))
    for row in shown:
        print(" | ".join(str(row[i] if i < len(row) else "")[:widths[i]].ljust(widths[i]) for i in range(len(headers))))
    if len(rows) > limit: print(f"Showing {limit} of {len(rows)} entries.")


def safe_name(value: str, default: str = "report") -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("_") or default


def save_report(prefix: str, content: str) -> Path:
    REPORT_DIR.mkdir(exist_ok=True)
    path = REPORT_DIR / f"{safe_name(prefix)}_{datetime.now():%Y%m%d_%H%M%S}.md"
    path.write_text(content, encoding="utf-8")
    return path


def collect_processes() -> list[dict]:
    script = "Get-CimInstance Win32_Process | Select-Object ProcessId,Name,ExecutablePath,CommandLine"
    try:
        rows = powershell_json(script)
        if rows: return rows
    except Exception:
        pass
    # Win32_Process can be blocked for a standard user. Get-Process still gives
    # a useful read-only inventory, although protected paths may be blank.
    fallback = ("Get-Process | Select-Object "
                "@{N='ProcessId';E={$_.Id}},@{N='Name';E={$_.ProcessName}},"
                "@{N='ExecutablePath';E={$_.Path}},@{N='CommandLine';E={''}}")
    try:
        rows = powershell_json(fallback)
        if rows: return rows
    except Exception:
        pass
    code, output, _ = command(["tasklist", "/FO", "CSV", "/NH"])
    if code: return []
    return [{"Name": row[0], "ProcessId": row[1], "ExecutablePath": "", "CommandLine": ""}
            for row in csv.reader(output.splitlines()) if len(row) >= 2]


def collect_connections() -> list[dict]:
    script = "Get-NetTCPConnection | Select-Object State,LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess"
    try: return powershell_json(script)
    except Exception:
        code, output, _ = command(["netstat", "-ano", "-p", "tcp"])
        if code: return []
        rows = []
        for line in output.splitlines():
            parts = line.split()
            if len(parts) >= 5 and parts[0].upper() == "TCP":
                local, remote = parts[1], parts[2]
                rows.append({"State": parts[3], "LocalAddress": local.rsplit(":", 1)[0],
                             "LocalPort": local.rsplit(":", 1)[-1],
                             "RemoteAddress": remote.rsplit(":", 1)[0],
                             "RemotePort": remote.rsplit(":", 1)[-1], "OwningProcess": parts[4]})
        return rows


def collect_startup() -> list[dict]:
    if winreg is None: return []
    paths = [r"Software\Microsoft\Windows\CurrentVersion\Run",
             r"Software\Microsoft\Windows\CurrentVersion\RunOnce"]
    roots = [(winreg.HKEY_CURRENT_USER, "HKCU"), (winreg.HKEY_LOCAL_MACHINE, "HKLM")]
    results = []
    for root, root_name in roots:
        for path in paths:
            for view in (getattr(winreg, "KEY_WOW64_64KEY", 0), getattr(winreg, "KEY_WOW64_32KEY", 0)):
                try:
                    with winreg.OpenKey(root, path, 0, winreg.KEY_READ | view) as key:
                        for index in range(winreg.QueryInfoKey(key)[1]):
                            name, value, _ = winreg.EnumValue(key, index)
                            item = {"Location": f"{root_name}\\{path}", "Name": name, "Command": str(value)}
                            if item not in results: results.append(item)
                except OSError:
                    pass
    return results


def process_reasons(process: dict, connected_pids: set[str] | None = None) -> list[str]:
    name = str(process.get("Name", "")); path = str(process.get("ExecutablePath") or "")
    cmd = str(process.get("CommandLine") or ""); combined = f"{name} {path} {cmd}".lower()
    reasons = []
    matches = sorted(term for term in REMOTE_TOOL_TERMS if term in combined)
    if matches: reasons.append("remote-access/tool term: " + ", ".join(matches[:3]))
    if any(term in combined for term in SUSPICIOUS_COMMAND_TERMS): reasons.append("review command-line behavior")
    if path and any(part in path.lower() for part in ("\\temp\\", "\\appdata\\local\\temp\\")) and path.lower().endswith((".exe", ".dll")):
        reasons.append("executable launched from temporary folder")
    if connected_pids and str(process.get("ProcessId", "")) in connected_pids and reasons:
        reasons.append("has active TCP connection")
    return reasons


def startup_reasons(item: dict) -> list[str]:
    command_text = str(item.get("Command", "")).lower(); reasons = []
    if any(term in command_text for term in REMOTE_TOOL_TERMS): reasons.append("remote-access/tool term")
    if any(term in command_text for term in SUSPICIOUS_COMMAND_TERMS): reasons.append("review command behavior")
    if any(part in command_text for part in ("\\temp\\", "\\downloads\\")): reasons.append("starts from temporary/download folder")
    return reasons


def rat_scanner() -> None:
    print("This is a defensive heuristic scan. Legitimate remote-support software may be listed.")
    def gather():
        processes = collect_processes(); connections = collect_connections(); startup = collect_startup()
        return processes, connections, startup
    try:
        processes, connections, startup = loading("Scanning remote-access indicators", gather)
        connected = {str(row.get("OwningProcess", "")) for row in connections
                     if str(row.get("State", "")).lower() in {"established", "listen", "listening"}}
        findings = []
        for process in processes:
            reasons = process_reasons(process, connected)
            if reasons:
                findings.append([process.get("ProcessId", ""), process.get("Name", ""),
                                 "; ".join(reasons), process.get("ExecutablePath") or "Unknown"])
        startup_findings = []
        for item in startup:
            reasons = startup_reasons(item)
            if reasons: startup_findings.append([item["Name"], "; ".join(reasons), item["Command"]])
        table("PROCESS LEADS", ["PID", "Name", "Reason", "Path"], findings, 100)
        table("STARTUP LEADS", ["Name", "Reason", "Command"], startup_findings, 100)
        print(f"\nScanned {len(processes)} processes, {len(connections)} TCP entries, and {len(startup)} startup values.")
        if not findings and not startup_findings:
            print(paint("No heuristic RAT/remote-access leads were found.", "green"))
        else:
            print(paint("Review the leads. A match is not proof of malware.", "yellow"))
        content = ["# RAT and Remote-Access Heuristic Report", "", f"Generated: {datetime.now().astimezone().isoformat()}",
                   "", "A listed item is a lead, not proof of malware.", "", "## Process leads"]
        content += [f"- PID {row[0]} - {row[1]} - {row[2]} - `{row[3]}`" for row in findings] or ["- None"]
        content += ["", "## Startup leads"]
        content += [f"- {row[0]} - {row[1]} - `{row[2]}`" for row in startup_findings] or ["- None"]
        report = save_report("rat_scan", "\n".join(content))
        print(f"Report saved: {report}")
    except Exception as exc:
        print(paint(f"RAT scan failed: {exc}", "red"))
    pause()


def process_audit() -> None:
    try:
        processes = loading("Reading running processes", collect_processes)
        mode = input("Show flagged or all processes? [flagged/all]: ").strip().lower() or "flagged"
        rows = []
        for item in processes:
            reasons = process_reasons(item)
            if mode == "all" or reasons:
                rows.append([item.get("ProcessId", ""), item.get("Name", ""),
                             "; ".join(reasons) or "No basic flag", item.get("ExecutablePath") or "Unknown"])
        table("PROCESS AUDIT", ["PID", "Name", "Review reason", "Path"], rows, 200)
    except Exception as exc:
        print(paint(f"Process audit failed: {exc}", "red"))
    pause()


def network_connections() -> None:
    try:
        connections = loading("Reading TCP connections", collect_connections)
        processes = {str(p.get("ProcessId", "")): p.get("Name", "") for p in collect_processes()}
        rows = []
        for item in connections:
            state = str(item.get("State", ""))
            if state.lower() not in {"established", "listen", "listening"}: continue
            pid = str(item.get("OwningProcess", ""))
            local = f"{item.get('LocalAddress', '')}:{item.get('LocalPort', '')}"
            remote = f"{item.get('RemoteAddress', '')}:{item.get('RemotePort', '')}"
            rows.append([state, local, remote, pid, processes.get(pid, "Unknown")])
        table("ACTIVE TCP CONNECTIONS", ["State", "Local", "Remote", "PID", "Process"], rows, 200)
    except Exception as exc:
        print(paint(f"Connection scan failed: {exc}", "red"))
    pause()


def startup_audit() -> None:
    entries = loading("Reading startup persistence", collect_startup)
    rows = [[item["Location"], item["Name"], "; ".join(startup_reasons(item)) or "Review",
             item["Command"]] for item in entries]
    table("STARTUP RUN KEYS", ["Location", "Name", "Reason", "Command"], rows, 200)
    print("Entries are shown for review. Do not delete one until its owner and purpose are confirmed.")
    pause()


def scheduled_tasks() -> None:
    script = "Get-ScheduledTask | Where-Object State -ne 'Disabled' | Select-Object TaskName,TaskPath,State,@{N='Execute';E={$_.Actions.Execute -join ';'}},@{N='Arguments';E={$_.Actions.Arguments -join ';'}}"
    try:
        def collect_tasks():
            try:
                rows = powershell_json(script, 90)
                if rows: return rows
            except Exception:
                pass
            # schtasks is available on older Windows builds and on systems
            # where the ScheduledTasks PowerShell provider is restricted.
            code, output, error = command(["schtasks.exe", "/Query", "/FO", "CSV", "/V"], 90)
            if code or not output:
                raise RuntimeError("Windows blocked scheduled-task inventory. "
                                   "Run the launcher as administrator for this view.")
            fallback_rows = []
            for row in csv.DictReader(output.splitlines()):
                task_name = row.get("TaskName", "")
                status = row.get("Status", "") or row.get("Scheduled Task State", "")
                action = row.get("Task To Run", "")
                if str(status).lower() == "disabled": continue
                fallback_rows.append({"TaskName": task_name.rsplit("\\", 1)[-1],
                                      "TaskPath": task_name.rsplit("\\", 1)[0] or "\\",
                                      "State": status, "Execute": action, "Arguments": ""})
            return fallback_rows
        tasks = loading("Reading scheduled tasks", collect_tasks)
        rows = []
        for item in tasks:
            combined = f"{item.get('Execute','')} {item.get('Arguments','')}".lower()
            reason = []
            if any(term in combined for term in REMOTE_TOOL_TERMS): reason.append("remote-tool term")
            if any(term in combined for term in SUSPICIOUS_COMMAND_TERMS): reason.append("review command")
            if "\\temp\\" in combined or "\\downloads\\" in combined: reason.append("temporary/download path")
            rows.append([item.get("State", ""), item.get("TaskPath", ""), item.get("TaskName", ""),
                         "; ".join(reason) or "", f"{item.get('Execute','')} {item.get('Arguments','')}".strip()])
        rows.sort(key=lambda row: (not bool(row[3]), str(row[2]).lower()))
        table("ENABLED SCHEDULED TASKS", ["State", "Path", "Task", "Review reason", "Action"], rows, 200)
    except Exception as exc:
        print(paint(f"Scheduled-task view unavailable: {exc}", "yellow"))
    pause()


def services_audit() -> None:
    script = "Get-CimInstance Win32_Service | Where-Object State -eq 'Running' | Select-Object Name,DisplayName,StartMode,PathName,State"
    try:
        def collect_services():
            try:
                rows = powershell_json(script, 90)
                if rows: return rows
            except Exception:
                pass
            fallback = ("Get-Service | Where-Object Status -eq 'Running' | Select-Object "
                        "Name,DisplayName,@{N='StartMode';E={$_.StartType.ToString()}},"
                        "@{N='PathName';E={''}},@{N='State';E={$_.Status.ToString()}}")
            return powershell_json(fallback, 90)
        services = loading("Reading running services", collect_services)
        rows = []
        for item in services:
            combined = f"{item.get('Name','')} {item.get('DisplayName','')} {item.get('PathName','')}".lower()
            reason = []
            if any(term in combined for term in REMOTE_TOOL_TERMS): reason.append("remote-tool term")
            if "\\temp\\" in combined: reason.append("temporary path")
            rows.append([item.get("Name", ""), item.get("StartMode", ""),
                         "; ".join(reason), item.get("PathName", "")])
        rows.sort(key=lambda row: (not bool(row[2]), str(row[0]).lower()))
        table("RUNNING SERVICES", ["Name", "Start", "Review reason", "Binary path"], rows, 200)
    except Exception as exc:
        print(paint(f"Service audit failed: {exc}", "red"))
    pause()


def defender_status_data() -> list[dict]:
    script = "Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,BehaviorMonitorEnabled,IoavProtectionEnabled,NISEnabled,IsTamperProtected,AntivirusSignatureLastUpdated,AntivirusSignatureAge,QuickScanAge,FullScanAge,AMRunningMode"
    try:
        rows = powershell_json(script)
        if rows: return rows
    except Exception:
        pass
    # Some Windows policies restrict detailed Defender CIM data for standard
    # users. The service state is still a useful, permission-friendly fallback.
    fallback = ("Get-Service -Name WinDefend -ErrorAction Stop | Select-Object "
                "@{N='DetailedStatusAvailable';E={$false}},"
                "@{N='AntivirusServiceStatus';E={$_.Status.ToString()}},"
                "@{N='ServiceStartType';E={$_.StartType.ToString()}},"
                "@{N='Note';E={'Run as administrator for all Defender fields'}}")
    return powershell_json(fallback)


def defender_status() -> None:
    try:
        items = loading("Reading Defender status", defender_status_data)
        if not items: print("Microsoft Defender status was unavailable.")
        else:
            rows = [[key, value] for key, value in items[0].items()]
            table("MICROSOFT DEFENDER STATUS", ["Setting", "Value"], rows, 100)
    except Exception as exc:
        print(paint(f"Defender status failed: {exc}", "red"))
    pause()


def defender_quick_scan() -> None:
    print("This starts Microsoft Defender's built-in Quick Scan and may take several minutes.")
    if not confirm("Start Quick Scan?", False): return
    code, output, error = loading("Running Defender Quick Scan", lambda: powershell("Start-MpScan -ScanType QuickScan", 3600))
    if code: print(paint(f"Defender scan failed: {error or output}", "red"))
    else: print(paint("Microsoft Defender Quick Scan completed.", "green"))
    pause()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""): digest.update(chunk)
    return digest.hexdigest()


def file_entropy(path: Path, max_bytes: int = 8 * 1024 * 1024) -> float:
    with path.open("rb") as handle: data = handle.read(max_bytes)
    if not data: return 0.0
    counts = Counter(data); length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def signature_status(path: Path) -> str:
    escaped = str(path).replace("'", "''")
    code, output, error = powershell(f"(Get-AuthenticodeSignature -LiteralPath '{escaped}').Status", 30)
    return output.strip() if not code and output else (error or "Unavailable")


def static_file_scan() -> None:
    path = Path(input("Full path to a file: ").strip().strip('"')).expanduser()
    if not path.is_file(): print(paint("File not found.", "red")); pause(); return
    try:
        def analyze():
            with path.open("rb") as handle: sample = handle.read(4 * 1024 * 1024)
            text = sample.decode("latin-1", errors="ignore").lower()
            terms = [term for term in ("powershell", "cmd.exe", "wscript", "mshta", "http://", "https://",
                                       "createremotethread", "writeprocessmemory", "virtualalloc", "webhook") if term in text]
            return sha256_file(path), file_entropy(path), terms, sample[:16]
        digest, entropy, terms, magic = loading("Analyzing file", analyze)
        double_extension = bool(re.search(r"\.(?:pdf|jpg|jpeg|png|docx|xlsx|txt)\.(?:exe|scr|com|bat|cmd|js|vbs)$", path.name, re.I))
        rows = [["File", str(path)], ["Size", f"{path.stat().st_size:,} bytes"],
                ["SHA-256", digest], ["Entropy", f"{entropy:.3f} / 8.000"],
                ["Header bytes", magic.hex(" ")], ["Extension", path.suffix.lower() or "None"],
                ["Double extension", str(double_extension)], ["Signature", signature_status(path)],
                ["Review strings", ", ".join(terms) or "None in first 4 MB"]]
        table("STATIC FILE ANALYSIS", ["Field", "Value"], rows, 100)
        if entropy > 7.3: print(paint("High entropy can indicate compression, encryption, or packing.", "yellow"))
        print("Static indicators are not a malware verdict. Use Defender and reputation checks as additional evidence.")
    except OSError as exc:
        print(paint(f"File analysis failed: {exc}", "red"))
    pause()


def defender_file_scan() -> None:
    path = Path(input("File or folder to scan: ").strip().strip('"')).expanduser()
    if not path.exists(): print(paint("Path not found.", "red")); pause(); return
    if not confirm(f"Ask Microsoft Defender to scan {path}?", False): return
    escaped = str(path).replace("'", "''")
    code, output, error = loading("Running Defender custom scan", lambda: powershell(
        f"Start-MpScan -ScanType CustomScan -ScanPath '{escaped}'", 3600))
    if code: print(paint(f"Defender scan failed: {error or output}", "red"))
    else: print(paint("Microsoft Defender custom scan completed.", "green"))
    pause()


def hash_reputation() -> None:
    value = input("File path or SHA-256: ").strip().strip('"')
    path = Path(value).expanduser()
    if path.is_file():
        try: digest = loading("Hashing file", lambda: sha256_file(path))
        except OSError as exc: print(paint(str(exc), "red")); pause(); return
    elif re.fullmatch(r"[0-9A-Fa-f]{64}", value): digest = value.lower()
    else: print(paint("Enter an existing file or a 64-character SHA-256.", "red")); pause(); return
    url = "https://www.virustotal.com/gui/file/" + digest
    print(f"SHA-256: {digest}\nReputation URL: {url}")
    print("Opening the browser sends only the hash to VirusTotal, not the file.")
    if confirm("Open reputation page?", False): webbrowser.open(url)
    pause()


def iter_files(root: Path, limit: int = 5000):
    count = 0
    for path in root.rglob("*"):
        if path.is_file():
            yield path; count += 1
            if count >= limit: return


def folder_snapshot(root: Path, limit: int = 5000) -> dict[str, dict]:
    results = {}
    for path in iter_files(root, limit):
        try:
            relative = str(path.relative_to(root))
            results[relative] = {"sha256": sha256_file(path), "size": path.stat().st_size,
                                 "mtime": path.stat().st_mtime}
        except (OSError, ValueError):
            pass
    return results


def integrity_baseline() -> None:
    root = Path(input("Folder to baseline: ").strip().strip('"')).expanduser().resolve()
    if not root.is_dir(): print(paint("Folder not found.", "red")); pause(); return
    name = safe_name(input("Baseline name: ").strip(), root.name or "baseline")
    try:
        hashes = loading("Building integrity baseline", lambda: folder_snapshot(root))
        BASELINE_DIR.mkdir(exist_ok=True)
        path = BASELINE_DIR / f"{name}.json"
        path.write_text(json.dumps({"version": 1, "created": datetime.now(timezone.utc).isoformat(),
                                    "root": str(root), "files": hashes}, indent=2), encoding="utf-8")
        print(paint(f"Baseline saved with {len(hashes)} files: {path}", "green"))
        if len(hashes) >= 5000: print(paint("The 5,000-file safety limit was reached.", "yellow"))
    except (OSError, ValueError) as exc:
        print(paint(f"Baseline failed: {exc}", "red"))
    pause()


def integrity_compare() -> None:
    value = input(f"Baseline JSON path (folder: {BASELINE_DIR}): ").strip().strip('"')
    path = Path(value).expanduser()
    if not path.is_file(): print(paint("Baseline file not found.", "red")); pause(); return
    try:
        baseline = json.loads(path.read_text(encoding="utf-8")); root = Path(baseline["root"])
        if not root.is_dir(): raise OSError(f"Original folder is missing: {root}")
        current = loading("Comparing folder integrity", lambda: folder_snapshot(root))
        previous = baseline.get("files", {})
        added = sorted(set(current) - set(previous)); missing = sorted(set(previous) - set(current))
        modified = sorted(name for name in set(current) & set(previous)
                          if current[name].get("sha256") != previous[name].get("sha256"))
        table("INTEGRITY CHANGES", ["Type", "Relative path"],
              [["ADDED", name] for name in added] + [["MODIFIED", name] for name in modified] + [["MISSING", name] for name in missing], 300)
        report = ["# Folder Integrity Comparison", "", f"Baseline: `{path}`", f"Root: `{root}`",
                  f"Compared: {datetime.now().astimezone().isoformat()}", "",
                  f"Added: {len(added)}", f"Modified: {len(modified)}", f"Missing: {len(missing)}", ""]
        for label, names in (("Added", added), ("Modified", modified), ("Missing", missing)):
            report += [f"## {label}"] + ([f"- `{name}`" for name in names] or ["- None"]) + [""]
        saved = save_report("integrity_compare", "\n".join(report)); print(f"Report saved: {saved}")
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(paint(f"Integrity comparison failed: {exc}", "red"))
    pause()


def secret_scanner() -> None:
    root = Path(input("Folder to scan locally for exposed secrets: ").strip().strip('"')).expanduser()
    if not root.is_dir(): print(paint("Folder not found.", "red")); pause(); return
    print("Only file names, line numbers, and match types are reported. Secret values are not printed or transmitted.")
    def scan():
        findings = []; checked = 0
        for path in iter_files(root, 3000):
            if path.suffix.lower() not in TEXT_EXTENSIONS: continue
            try:
                if path.stat().st_size > 2 * 1024 * 1024: continue
                for number, line in enumerate(path.read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
                    for label, pattern in SECRET_PATTERNS.items():
                        if pattern.search(line): findings.append([str(path.relative_to(root)), number, label])
                checked += 1
            except (OSError, ValueError): pass
        return checked, findings
    checked, findings = loading("Scanning for exposed secrets", scan)
    table("POSSIBLE SECRET EXPOSURES", ["File", "Line", "Type"], findings, 300)
    print(f"Checked {checked} text-like files. Matches require manual review.")
    pause()


def office_macro_scan() -> None:
    path = Path(input("Office document path: ").strip().strip('"')).expanduser()
    if not path.is_file(): print(paint("File not found.", "red")); pause(); return
    findings = []
    try:
        with path.open("rb") as handle: header = handle.read(8)
        if zipfile.is_zipfile(path):
            with zipfile.ZipFile(path) as archive:
                names = archive.namelist()
                for name in names:
                    lower = name.lower()
                    if lower.endswith("vbaproject.bin"): findings.append(["Embedded VBA project", name])
                    if "embeddings/" in lower: findings.append(["Embedded object", name])
                    if lower.endswith(".rels"):
                        data = archive.read(name).decode("utf-8", errors="ignore")
                        if 'TargetMode="External"' in data: findings.append(["External relationship", name])
        elif header.startswith(bytes.fromhex("D0CF11E0A1B11AE1")):
            findings.append(["Legacy OLE document", "Macro inspection requires additional tooling"])
        else:
            findings.append(["Format", "Not a recognized Office ZIP/OLE document"])
        table("OFFICE DOCUMENT REVIEW", ["Finding", "Location / detail"], findings, 200)
        print("A macro-capable file is not automatically malicious. Scan it with Defender before opening.")
    except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
        print(paint(f"Office scan failed: {exc}", "red"))
    pause()


def downloads_risk_scan() -> None:
    root = Path.home() / "Downloads"
    if not root.is_dir(): print(paint(f"Downloads folder not found: {root}", "red")); pause(); return
    findings = []
    for path in iter_files(root, 5000):
        try:
            reasons = []
            if path.suffix.lower() in RISKY_EXTENSIONS: reasons.append("active/macro-capable extension")
            if re.search(r"\.(?:pdf|jpg|jpeg|png|docx|xlsx|txt)\.(?:exe|scr|com|bat|cmd|js|vbs)$", path.name, re.I):
                reasons.append("double extension")
            if reasons:
                age_days = max(0, int((time.time() - path.stat().st_mtime) / 86400))
                findings.append([path.name, age_days, "; ".join(reasons), str(path.parent)])
        except OSError: pass
    findings.sort(key=lambda row: row[1])
    table("DOWNLOADS RISK REVIEW", ["File", "Age days", "Reason", "Folder"], findings, 150)
    print(f"Found {len(findings)} file(s) for review. Nothing was deleted or quarantined.")
    pause()


def firewall_status_data() -> list[dict]:
    try:
        rows = powershell_json("Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction,NotifyOnListen,LogAllowed,LogBlocked")
        if rows: return rows
    except Exception:
        pass
    code, output, error = command(["netsh", "advfirewall", "show", "allprofiles", "state"], 45)
    if code: raise RuntimeError(error or output or "Firewall status is unavailable")
    rows = []
    profile = ""
    for line in output.splitlines():
        profile_match = re.match(r"\s*(.+?)\s+Profile Settings\s*:\s*$", line, re.I)
        if profile_match:
            profile = profile_match.group(1).strip()
            continue
        state_match = re.match(r"\s*State\s+(ON|OFF)\s*$", line, re.I)
        if state_match and profile:
            rows.append({"Name": profile, "Enabled": state_match.group(1).upper() == "ON",
                         "DefaultInboundAction": "Unavailable without elevated access",
                         "DefaultOutboundAction": "Unavailable", "LogBlocked": "Unavailable"})
            profile = ""
    if not rows:
        rows.append({"Name": "All profiles", "Enabled": "See netsh output",
                     "DefaultInboundAction": "Unavailable", "DefaultOutboundAction": "Unavailable",
                     "LogBlocked": "Unavailable"})
    return rows


def firewall_status() -> None:
    try:
        profiles = loading("Reading firewall profiles", firewall_status_data)
        rows = [[item.get("Name", ""), item.get("Enabled", ""), item.get("DefaultInboundAction", ""),
                 item.get("DefaultOutboundAction", ""), item.get("LogBlocked", "")] for item in profiles]
        table("WINDOWS FIREWALL PROFILES", ["Profile", "Enabled", "Inbound", "Outbound", "Log blocked"], rows, 20)
    except Exception as exc: print(paint(f"Firewall check failed: {exc}", "red"))
    pause()


def hosts_file_audit() -> None:
    path = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "drivers" / "etc" / "hosts"
    try:
        entries = []
        for number, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            content = line.split("#", 1)[0].strip()
            if not content: continue
            parts = content.split()
            if len(parts) >= 2: entries.append([number, parts[0], ", ".join(parts[1:])])
        table("HOSTS FILE ENTRIES", ["Line", "Address", "Names"], entries, 300)
        print(f"Hosts file: {path}")
    except OSError as exc: print(paint(f"Hosts audit failed: {exc}", "red"))
    pause()


def arp_inventory() -> None:
    code, output, error = loading("Reading ARP neighbor table", lambda: command(["arp", "-a"], 30))
    if code: print(paint(f"ARP inventory failed: {error}", "red"))
    else: print(output or "No ARP entries found.")
    print("ARP entries show recently observed local-network neighbors, not verified device owners.")
    pause()


def dns_cache_review() -> None:
    code, output, error = loading("Reading local DNS cache", lambda: command(["ipconfig", "/displaydns"], 45))
    if code: print(paint(f"DNS cache failed: {error}", "red")); pause(); return
    names = []
    for line in output.splitlines():
        match = re.search(r"Record Name\s*\.\s*:\s*(.+)$", line, re.I)
        if match and match.group(1).strip() not in names: names.append(match.group(1).strip())
    table("CACHED DNS NAMES", ["Record name"], [[name] for name in names], 300)
    print("The cache is temporary and does not prove that a user intentionally visited a domain.")
    pause()


def local_accounts() -> None:
    script = "Get-LocalUser | Select-Object Name,Enabled,LastLogon,PasswordRequired,PasswordExpires,UserMayChangePassword"
    try:
        users = loading("Reading local accounts", lambda: powershell_json(script))
        rows = [[u.get("Name", ""), u.get("Enabled", ""), u.get("LastLogon", ""),
                 u.get("PasswordRequired", ""), u.get("PasswordExpires", "")] for u in users]
        table("LOCAL USER ACCOUNTS", ["Name", "Enabled", "Last logon", "Password required", "Expires"], rows, 100)
    except Exception as exc: print(paint(f"Account review failed: {exc}", "red"))
    pause()


def defender_events() -> None:
    script = "Get-WinEvent -LogName 'Microsoft-Windows-Windows Defender/Operational' -MaxEvents 100 | Where-Object Id -in 1116,1117,5001,5007 | Select-Object TimeCreated,Id,LevelDisplayName,Message"
    try:
        events = loading("Reading Defender events", lambda: powershell_json(script, 90))
        rows = [[e.get("TimeCreated", ""), e.get("Id", ""), e.get("LevelDisplayName", ""),
                 str(e.get("Message", "")).replace("\r", " ").replace("\n", " ")] for e in events]
        table("DEFENDER SECURITY EVENTS", ["Time", "ID", "Level", "Message"], rows, 100)
    except Exception as exc: print(paint(f"Event review failed: {exc}", "red"))
    pause()


def full_security_report() -> None:
    print("This creates a read-only snapshot report. It does not run an antivirus scan or change settings.")
    def gather():
        processes = collect_processes(); connections = collect_connections(); startup = collect_startup()
        try: defender = defender_status_data()
        except Exception: defender = []
        try: firewall = firewall_status_data()
        except Exception: firewall = []
        try: posture = collect_protection_posture()
        except Exception: posture = []
        return processes, connections, startup, defender, firewall, posture
    try:
        processes, connections, startup, defender, firewall, posture = loading("Building security snapshot", gather)
        connected = {str(c.get("OwningProcess", "")) for c in connections}
        process_flags = [(p, process_reasons(p, connected)) for p in processes]
        process_flags = [(p, r) for p, r in process_flags if r]
        startup_flags = [(s, startup_reasons(s)) for s in startup]
        startup_flags = [(s, r) for s, r in startup_flags if r]
        report = ["# Cros Security Snapshot", "", f"Generated: {datetime.now().astimezone().isoformat()}",
                  "", "This report contains heuristic leads, not malware verdicts.", "",
                  "## Summary", f"- Processes: {len(processes)}", f"- TCP entries: {len(connections)}",
                  f"- Startup values: {len(startup)}", f"- Flagged process leads: {len(process_flags)}",
                  f"- Flagged startup leads: {len(startup_flags)}", "", "## Defender status"]
        if defender:
            report += [f"- {key}: {value}" for key, value in defender[0].items()]
        else: report += ["- Unavailable"]
        report += ["", "## Firewall profiles"]
        report += [f"- {f.get('Name')}: enabled={f.get('Enabled')}, inbound={f.get('DefaultInboundAction')}" for f in firewall] or ["- Unavailable"]
        report += ["", "## Protection posture"]
        report += [f"- {row[0]}: {row[1]} - {row[2]}" for row in posture] or ["- Unavailable"]
        report += ["", "## Process leads"]
        report += [f"- PID {p.get('ProcessId')} - {p.get('Name')} - {'; '.join(reasons)} - `{p.get('ExecutablePath') or 'Unknown'}`" for p, reasons in process_flags] or ["- None"]
        report += ["", "## Startup leads"]
        report += [f"- {s.get('Name')} - {'; '.join(reasons)} - `{s.get('Command')}`" for s, reasons in startup_flags] or ["- None"]
        path = save_report("security_snapshot", "\n".join(report)); print(paint(f"Security report saved: {path}", "green"))
    except Exception as exc: print(paint(f"Security report failed: {exc}", "red"))
    pause()


def registry_value(root, path: str, name: str):
    """Read a registry value without changing it, trying both Windows views."""
    if winreg is None: return None
    views = (getattr(winreg, "KEY_WOW64_64KEY", 0),
             getattr(winreg, "KEY_WOW64_32KEY", 0), 0)
    tried = set()
    for view in views:
        if view in tried: continue
        tried.add(view)
        try:
            with winreg.OpenKey(root, path, 0, winreg.KEY_READ | view) as key:
                return winreg.QueryValueEx(key, name)[0]
        except OSError:
            pass
    return None


def collect_protection_posture() -> list[list[object]]:
    rows: list[list[object]] = []
    try:
        defender = defender_status_data()
        item = defender[0] if defender else {}
        realtime = item.get("RealTimeProtectionEnabled")
        service = str(item.get("AntivirusServiceStatus", ""))
        if realtime is True:
            rows.append(["Defender real-time protection", "PASS", "Enabled"])
        elif realtime is False:
            rows.append(["Defender real-time protection", "REVIEW", "Disabled"])
        elif service.lower() == "running":
            rows.append(["Defender antivirus service", "PASS", "Running; detailed fields restricted"])
        else:
            rows.append(["Defender protection", "UNKNOWN", "Status unavailable"])
        tamper = item.get("IsTamperProtected")
        if tamper is not None:
            rows.append(["Defender tamper protection", "PASS" if tamper else "REVIEW",
                         "Enabled" if tamper else "Disabled"])
    except Exception as exc:
        rows.append(["Defender protection", "UNKNOWN", str(exc)])

    try:
        profiles = firewall_status_data()
        enabled = [p for p in profiles if p.get("Enabled") is True]
        rows.append(["Windows Firewall", "PASS" if len(enabled) == len(profiles) and profiles else "REVIEW",
                     f"{len(enabled)} of {len(profiles)} profiles enabled"])
    except Exception as exc:
        rows.append(["Windows Firewall", "UNKNOWN", str(exc)])

    if winreg is None:
        rows += [["User Account Control", "UNKNOWN", "Registry unavailable"],
                 ["Remote Desktop", "UNKNOWN", "Registry unavailable"]]
        return rows

    uac = registry_value(winreg.HKEY_LOCAL_MACHINE,
                         r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA")
    rows.append(["User Account Control", "PASS" if uac == 1 else "REVIEW" if uac == 0 else "UNKNOWN",
                 "Enabled" if uac == 1 else "Disabled" if uac == 0 else "Not readable"])

    rdp = registry_value(winreg.HKEY_LOCAL_MACHINE,
                         r"SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections")
    rows.append(["Remote Desktop inbound", "PASS" if rdp == 1 else "REVIEW" if rdp == 0 else "UNKNOWN",
                 "Disabled" if rdp == 1 else "Enabled" if rdp == 0 else "Not readable"])

    assistance = registry_value(winreg.HKEY_LOCAL_MACHINE,
                                r"SYSTEM\CurrentControlSet\Control\Remote Assistance", "fAllowToGetHelp")
    rows.append(["Remote Assistance", "PASS" if assistance == 0 else "REVIEW" if assistance == 1 else "UNKNOWN",
                 "Disabled" if assistance == 0 else "Enabled" if assistance == 1 else "Not readable"])

    smb1 = registry_value(winreg.HKEY_LOCAL_MACHINE,
                          r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "SMB1")
    rows.append(["SMB1 server protocol", "PASS" if smb1 == 0 else "REVIEW" if smb1 == 1 else "UNKNOWN",
                 "Explicitly disabled" if smb1 == 0 else "Explicitly enabled" if smb1 == 1 else "No explicit registry value"])
    return rows


def security_posture() -> None:
    rows = loading("Checking protection posture", collect_protection_posture)
    table("SECURITY POSTURE SUMMARY", ["Check", "Result", "Detail"], rows, 100)
    counts = Counter(str(row[1]) for row in rows)
    print(f"PASS: {counts['PASS']}   REVIEW: {counts['REVIEW']}   UNKNOWN: {counts['UNKNOWN']}")
    print("REVIEW means inspect the setting; it is not proof of compromise.")
    pause()


def windows_update_audit() -> None:
    service_script = ("Get-Service -Name wuauserv,bits -ErrorAction SilentlyContinue | Select-Object "
                      "Name,DisplayName,@{N='Status';E={$_.Status.ToString()}},"
                      "@{N='StartType';E={$_.StartType.ToString()}}")
    hotfix_script = ("Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 15 "
                     "HotFixID,Description,InstalledOn,InstalledBy")
    try:
        services = loading("Reading Windows Update state", lambda: powershell_json(service_script, 60))
        table("UPDATE SERVICES", ["Service", "Name", "Status", "Start type"],
              [[x.get("DisplayName", ""), x.get("Name", ""), x.get("Status", ""),
                x.get("StartType", "")] for x in services], 20)
    except Exception as exc:
        print(paint(f"Update service state unavailable: {exc}", "yellow"))
    try:
        hotfixes = loading("Reading installed update history", lambda: powershell_json(hotfix_script, 90))
        table("RECENT INSTALLED WINDOWS UPDATES", ["Update", "Description", "Installed", "Installed by"],
              [[x.get("HotFixID", ""), x.get("Description", ""), x.get("InstalledOn", ""),
                x.get("InstalledBy", "")] for x in hotfixes], 15)
    except Exception:
        event_script = ("Get-WinEvent -FilterHashtable @{LogName='System';"
                        "ProviderName='Microsoft-Windows-WindowsUpdateClient';Id=19,20} "
                        "-MaxEvents 15 -ErrorAction SilentlyContinue | Select-Object TimeCreated,Id,Message")
        try:
            events = loading("Trying update event history", lambda: powershell_json(event_script, 90))
            table("RECENT WINDOWS UPDATE EVENTS", ["Time", "Event", "Result"],
                  [[x.get("TimeCreated", ""), x.get("Id", ""),
                    str(x.get("Message", "")).replace("\r", " ").replace("\n", " ")] for x in events], 15)
        except Exception as exc:
            print(paint(f"Installed update history unavailable: {exc}", "yellow"))
    print("This reviews local history. Use Windows Update to perform an online check for new updates.")
    pause()


def secure_boot_tpm_audit() -> None:
    rows = []
    code, output, error = loading("Checking Secure Boot", lambda: powershell(
        "(Confirm-SecureBootUEFI).ToString()", 45))
    if not code and output:
        rows.append(["Secure Boot", "Enabled" if output.strip().lower() == "true" else "Disabled", output.strip()])
    else:
        rows.append(["Secure Boot", "Unavailable", (error or output or "Unsupported firmware / permission required").splitlines()[-1]])
    try:
        tpm = loading("Checking TPM", lambda: powershell_json(
            "Get-Tpm | Select-Object TpmPresent,TpmReady,TpmEnabled,TpmActivated,AutoProvisioning", 45))
        if tpm:
            item = tpm[0]
            for field in ("TpmPresent", "TpmReady", "TpmEnabled", "TpmActivated", "AutoProvisioning"):
                rows.append([field, item.get(field, ""), "TPM status"])
        else:
            rows.append(["TPM", "Unavailable", "No TPM status returned"])
    except Exception as exc:
        rows.append(["TPM", "Unavailable", str(exc)])
    table("SECURE BOOT AND TPM", ["Protection", "State", "Detail"], rows, 30)
    print("Some firmware and TPM details require running the launcher as Administrator.")
    pause()


def bitlocker_audit() -> None:
    script = ("Get-BitLockerVolume | Select-Object MountPoint,VolumeType,ProtectionStatus,"
              "EncryptionPercentage,EncryptionMethod,LockStatus")
    try:
        volumes = loading("Reading BitLocker status", lambda: powershell_json(script, 90))
        if volumes:
            table("BITLOCKER DRIVE PROTECTION",
                  ["Drive", "Type", "Protection", "Encrypted %", "Method", "Lock"],
                  [[x.get("MountPoint", ""), x.get("VolumeType", ""), x.get("ProtectionStatus", ""),
                    x.get("EncryptionPercentage", ""), x.get("EncryptionMethod", ""),
                    x.get("LockStatus", "")] for x in volumes], 50)
        else:
            print("No BitLocker volume information was returned.")
    except Exception:
        code, output, error = loading("Trying BitLocker fallback", lambda: command(
            ["manage-bde.exe", "-status"], 90))
        if code:
            print(paint("BitLocker status requires Administrator access on this system.", "yellow"))
            if error: print(error.splitlines()[-1])
        else:
            print(output)
    print("Recovery keys are never requested or displayed by this tool.")
    pause()


def remote_access_audit() -> None:
    rows = []
    if winreg is not None:
        rdp = registry_value(winreg.HKEY_LOCAL_MACHINE,
                             r"SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections")
        assist = registry_value(winreg.HKEY_LOCAL_MACHINE,
                                r"SYSTEM\CurrentControlSet\Control\Remote Assistance", "fAllowToGetHelp")
        rows += [["Remote Desktop inbound", "Disabled" if rdp == 1 else "Enabled" if rdp == 0 else "Unknown",
                  "Registry setting"],
                 ["Remote Assistance", "Disabled" if assist == 0 else "Enabled" if assist == 1 else "Unknown",
                  "Registry setting"]]
    try:
        services = powershell_json(
            "Get-Service -Name TermService,WinRM,RemoteRegistry -ErrorAction SilentlyContinue | Select-Object Name,@{N='Status';E={$_.Status.ToString()}},@{N='StartType';E={$_.StartType.ToString()}}")
        for service in services:
            rows.append([service.get("Name", ""), service.get("Status", ""),
                         f"Service start: {service.get('StartType', '')}"])
    except Exception as exc:
        rows.append(["Remote services", "Unavailable", str(exc)])
    try:
        smb = powershell_json("Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol,EnableSMB2Protocol", 45)
        if smb:
            rows += [["SMB1 server protocol", smb[0].get("EnableSMB1Protocol", ""), "Legacy protocol"],
                     ["SMB2/3 server protocol", smb[0].get("EnableSMB2Protocol", ""), "Modern protocol"]]
    except Exception:
        if winreg is not None:
            smb1 = registry_value(winreg.HKEY_LOCAL_MACHINE,
                                  r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "SMB1")
            rows.append(["SMB1 server protocol", "Disabled" if smb1 == 0 else "Enabled" if smb1 == 1 else "Unknown",
                         "Registry fallback"])
    table("REMOTE ACCESS EXPOSURE", ["Feature", "State", "Source / detail"], rows, 100)
    print("An enabled feature may be intentional. Confirm who uses it before changing Windows settings.")
    pause()


def defender_exclusions_audit() -> None:
    script = "Get-MpPreference | Select-Object ExclusionPath,ExclusionProcess,ExclusionExtension,ExclusionIpAddress"
    try:
        items = loading("Reading Defender exclusions", lambda: powershell_json(script, 60))
        rows = []
        if items:
            for category in ("ExclusionPath", "ExclusionProcess", "ExclusionExtension", "ExclusionIpAddress"):
                values = items[0].get(category)
                if values is None: continue
                if not isinstance(values, list): values = [values]
                rows.extend([[category, value] for value in values if str(value).strip()])
        table("MICROSOFT DEFENDER EXCLUSIONS", ["Category", "Excluded value"], rows, 200)
        if not rows: print(paint("No configured Defender exclusions were returned.", "green"))
        else: print(paint("Review unfamiliar exclusions. This tool does not remove them.", "yellow"))
    except Exception as exc:
        print(paint(f"Defender exclusions are protected on this system: {exc}", "yellow"))
        print("Run the launcher as Administrator if you are authorized to inspect them.")
    pause()


def collect_browser_extensions() -> tuple[list[list[object]], list[str]]:
    rows = []
    blocked = []
    local = Path(os.environ.get("LOCALAPPDATA", "__missing__"))
    roaming = Path(os.environ.get("APPDATA", "__missing__"))
    chromium_roots = [
        ("Chrome", local / "Google" / "Chrome" / "User Data"),
        ("Edge", local / "Microsoft" / "Edge" / "User Data"),
        ("Brave", local / "BraveSoftware" / "Brave-Browser" / "User Data"),
    ]
    review_permissions = {"debugger", "nativemessaging", "proxy", "management",
                          "webrequestblocking", "<all_urls>"}
    seen = set()
    for browser, root in chromium_roots:
        try:
            if not root.is_dir(): continue
        except OSError:
            blocked.append(browser)
            continue
        try: profiles = [p for p in root.iterdir() if p.is_dir() and (p.name == "Default" or p.name.startswith("Profile "))]
        except OSError:
            blocked.append(browser)
            continue
        for profile in profiles:
            extension_root = profile / "Extensions"
            try:
                if not extension_root.is_dir(): continue
            except OSError:
                blocked.append(browser)
                continue
            try: manifests = extension_root.glob("*/*/manifest.json")
            except OSError: continue
            for manifest in manifests:
                try:
                    data = json.loads(manifest.read_text(encoding="utf-8", errors="replace"))
                    extension_id = manifest.parents[1].name
                    version = str(data.get("version", manifest.parent.name))
                    key = (browser, profile.name, extension_id, version)
                    if key in seen: continue
                    seen.add(key)
                    permissions = data.get("permissions", []) or []
                    hosts = data.get("host_permissions", []) or []
                    if not isinstance(permissions, list): permissions = [permissions]
                    if not isinstance(hosts, list): hosts = [hosts]
                    permissions += hosts
                    permissions = [str(value) for value in permissions]
                    review = sorted(value for value in permissions if value.lower() in review_permissions)
                    if any(value in {"<all_urls>", "*://*/*"} for value in permissions) and "<all_urls>" not in review:
                        review.append("broad site access")
                    rows.append([browser, profile.name, data.get("name", "Unknown"), extension_id,
                                 version, ", ".join(review) or "None flagged"])
                    if len(rows) >= 1500: return rows, blocked
                except (OSError, ValueError, TypeError):
                    pass
    firefox_root = roaming / "Mozilla" / "Firefox" / "Profiles"
    try: firefox_available = firefox_root.is_dir()
    except OSError:
        firefox_available = False
        blocked.append("Firefox")
    if firefox_available:
        try: profile_dirs = list(firefox_root.iterdir())
        except OSError:
            profile_dirs = []
            blocked.append("Firefox")
        for profile in profile_dirs:
            path = profile / "extensions.json"
            try:
                if not path.is_file(): continue
            except OSError:
                blocked.append("Firefox")
                continue
            try:
                data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
                for addon in data.get("addons", []):
                    locale = addon.get("defaultLocale") or {}
                    name = locale.get("name") or addon.get("id", "Unknown")
                    rows.append(["Firefox", profile.name, name, addon.get("id", ""),
                                 addon.get("version", ""), "Active" if addon.get("active") else "Inactive"])
            except (OSError, ValueError, TypeError):
                pass
    return rows, blocked


def browser_extension_audit() -> None:
    rows, blocked = loading("Auditing browser extensions", collect_browser_extensions)
    rows.sort(key=lambda row: (str(row[0]), str(row[1]), str(row[2]).lower()))
    table("INSTALLED BROWSER EXTENSIONS", ["Browser", "Profile", "Name", "Extension ID", "Version", "Review"], rows, 300)
    print(f"Found {len(rows)} installed extension record(s). Broad permissions are leads, not malware verdicts.")
    if blocked:
        print(paint("Windows blocked these browser profile folders: " + ", ".join(sorted(set(blocked))), "yellow"))
        print("Run the launcher as Administrator only if you are authorized to inspect those profiles.")
    pause()


def temp_risk_scan() -> None:
    def scan():
        roots = []
        for value in (os.environ.get("TEMP"), os.environ.get("TMP"),
                      str(Path(os.environ.get("LOCALAPPDATA", "__missing__")) / "Temp")):
            if not value: continue
            path = Path(value).expanduser()
            try:
                resolved = path.resolve()
                available = resolved.is_dir()
            except OSError: continue
            if available and resolved not in roots: roots.append(resolved)
        findings = []
        now = time.time()
        for root in roots:
            try:
                files = iter_files(root, 5000)
                for path in files:
                    try:
                        age_days = max(0, int((now - path.stat().st_mtime) / 86400))
                        if age_days > 30: continue
                        reasons = []
                        if path.suffix.lower() in RISKY_EXTENSIONS: reasons.append("active/script extension")
                        if re.search(r"\.(?:pdf|jpg|jpeg|png|docx|xlsx|txt)\.(?:exe|scr|com|bat|cmd|js|vbs)$", path.name, re.I):
                            reasons.append("double extension")
                        if reasons: findings.append([path.name, age_days, "; ".join(reasons), str(path.parent)])
                    except OSError:
                        pass
            except OSError:
                pass
        return findings
    findings = loading("Scanning temporary folders", scan)
    findings.sort(key=lambda row: (row[1], str(row[0]).lower()))
    table("RECENT TEMP-FOLDER RISK REVIEW", ["File", "Age days", "Reason", "Folder"], findings, 150)
    print(f"Found {len(findings)} recent active file(s) for review. Nothing was opened or deleted.")
    pause()


def collect_wifi_security() -> dict:
    code, output, error = command(["netsh", "wlan", "show", "profiles"], 45)
    if code:
        raise RuntimeError(error or output or "Wi-Fi profile audit unavailable")
    profiles = []
    for line in output.splitlines():
        match = re.search(r"All User Profile\s*:\s*(.+)$", line, re.I)
        if match: profiles.append(match.group(1).strip())
    rows = []
    for name in profiles[:100]:
        p_code, detail, _ = command(["netsh", "wlan", "show", "profile", f"name={name}"], 30)
        if p_code:
            rows.append({"profile": name, "authentication": "Unavailable", "cipher": "Unavailable",
                         "security_key": "Not displayed", "review": "Details unavailable", "status": "unknown"})
            continue
        def field(label: str) -> str:
            match = re.search(rf"^\s*{re.escape(label)}\s*:\s*(.+)$", detail, re.I | re.M)
            return match.group(1).strip() if match else "Unknown"
        authentication = field("Authentication")
        cipher = field("Cipher")
        key_present = field("Security key")
        if "requires elevation" in detail.lower() or authentication == "Unknown":
            review = "Details require Administrator"
        else:
            review = "REVIEW - open network" if authentication.lower() == "open" else "Protected / verify"
        status = "review" if review.startswith("REVIEW") else "unknown" if "require" in review.lower() else "protected"
        rows.append({"profile": name, "authentication": authentication, "cipher": cipher,
                     "security_key": key_present, "review": review, "status": status})
    return {"profiles": rows, "count": len(rows),
            "note": "Wi-Fi passwords are never requested or displayed."}


def wifi_security_audit() -> None:
    try:
        result = loading("Reading saved Wi-Fi profiles", collect_wifi_security)
    except RuntimeError as exc:
        print(paint(f"Wi-Fi profile audit unavailable: {exc}", "yellow")); pause(); return
    rows = [[item["profile"], item["authentication"], item["cipher"], item["security_key"], item["review"]]
            for item in result["profiles"]]
    table("SAVED WI-FI SECURITY", ["Profile", "Authentication", "Cipher", "Security key", "Review"], rows, 100)
    if not rows: print("No saved Wi-Fi profiles were found, or Windows returned localized field names.")
    print("Wi-Fi passwords are never requested or displayed.")
    pause()


def sanitize_proxy(value: object) -> str:
    text = str(value or "")
    return re.sub(r"(?i)(https?://)[^/@\s]+@", r"\1<credentials>@", text)


def proxy_audit() -> None:
    rows = []
    if winreg is not None:
        path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        enabled = registry_value(winreg.HKEY_CURRENT_USER, path, "ProxyEnable")
        server = registry_value(winreg.HKEY_CURRENT_USER, path, "ProxyServer")
        auto = registry_value(winreg.HKEY_CURRENT_USER, path, "AutoConfigURL")
        rows += [["User proxy enabled", enabled if enabled is not None else "Unknown"],
                 ["User proxy server", sanitize_proxy(server) or "None configured"],
                 ["Automatic config URL", sanitize_proxy(auto) or "None configured"]]
    code, output, error = loading("Reading proxy configuration", lambda: command(
        ["netsh", "winhttp", "show", "proxy"], 45))
    table("USER PROXY SETTINGS", ["Setting", "Value"], rows, 30)
    print(paint("\nWINHTTP PROXY", "cyan", bold=True))
    print(sanitize_proxy(output) if not code else paint(error or "Unavailable", "yellow"))
    print("Unexpected proxies can redirect traffic. Corporate, school, VPN, and filtering software may set them legitimately.")
    pause()


def startup_folder_audit() -> None:
    folders = []
    appdata = os.environ.get("APPDATA")
    programdata = os.environ.get("PROGRAMDATA")
    if appdata: folders.append(("Current user", Path(appdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"))
    if programdata: folders.append(("All users", Path(programdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "StartUp"))
    rows = []
    for scope, folder in folders:
        try:
            if not folder.is_dir(): continue
        except OSError:
            continue
        try: paths = list(folder.rglob("*"))
        except OSError: continue
        for path in paths:
            try:
                if not path.is_file(): continue
                suffix = path.suffix.lower()
                reason = "Script/executable" if suffix in RISKY_EXTENSIONS - {".lnk"} else "Shortcut - review target" if suffix == ".lnk" else "Review"
                age_days = max(0, int((time.time() - path.stat().st_mtime) / 86400))
                rows.append([scope, path.name, suffix or "None", age_days, reason, str(path.parent)])
            except OSError:
                pass
    table("STARTUP FOLDER ITEMS", ["Scope", "Item", "Type", "Age days", "Reason", "Folder"], rows, 200)
    print("This complements the registry Startup Persistence audit. Nothing was changed.")
    pause()


def failed_signin_audit() -> None:
    script = ("$events=Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625;"
              "StartTime=(Get-Date).AddDays(-7)} -MaxEvents 100; foreach($event in $events){"
              "$xml=[xml]$event.ToXml();$values=@{};foreach($node in $xml.Event.EventData.Data){"
              "$values[$node.Name]=[string]$node.'#text'};[PSCustomObject]@{"
              "TimeCreated=$event.TimeCreated;User=$values['TargetUserName'];"
              "SourceIP=$values['IpAddress'];LogonType=$values['LogonType'];"
              "Status=$values['Status'];SubStatus=$values['SubStatus']}}")
    try:
        events = loading("Reading failed sign-ins", lambda: powershell_json(script, 90))
        rows = [[x.get("TimeCreated", ""), x.get("User", ""), x.get("SourceIP", ""),
                 x.get("LogonType", ""), x.get("Status", ""), x.get("SubStatus", "")] for x in events]
        table("FAILED WINDOWS SIGN-INS - LAST 7 DAYS", ["Time", "User", "Source IP", "Type", "Status", "Substatus"], rows, 100)
        print(f"Found {len(events)} recorded failure(s), up to the 100-event display limit.")
    except Exception as exc:
        if "NoMatchingEventsFound" in str(exc):
            print(paint("No failed Windows sign-ins were found in the last seven days.", "green"))
        else:
            print(paint(f"The Windows Security log is protected: {exc}", "yellow"))
            print("Run the launcher as Administrator if you are authorized to review sign-in events.")
    pause()


def network_exposure_audit() -> None:
    common = {21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
              80: "HTTP", 135: "RPC", 139: "NetBIOS", 443: "HTTPS",
              445: "SMB", 3389: "RDP", 5900: "VNC", 5985: "WinRM",
              5986: "WinRM TLS", 8080: "Web alternate"}
    def gather():
        connections = collect_connections()
        processes = {str(p.get("ProcessId", "")): p.get("Name", "Unknown") for p in collect_processes()}
        rows = []
        for item in connections:
            if str(item.get("State", "")).lower() not in {"listen", "listening"}: continue
            address = str(item.get("LocalAddress", ""))
            if address in {"127.0.0.1", "::1"}: continue
            try: port = int(item.get("LocalPort", 0))
            except (TypeError, ValueError): port = 0
            pid = str(item.get("OwningProcess", ""))
            scope = "All interfaces" if address in {"0.0.0.0", "::", "*"} else "Network interface"
            rows.append([f"{address}:{port}", common.get(port, "Uncommon / dynamic"),
                         pid, processes.get(pid, "Unknown"), scope])
        return rows
    rows = loading("Checking listening exposure", gather)
    rows.sort(key=lambda row: (row[4] != "All interfaces", str(row[0])))
    table("NON-LOOPBACK LISTENING PORTS", ["Listener", "Service hint", "PID", "Process", "Scope"], rows, 200)
    print("A listening port is not automatically unsafe. Confirm the owning app, firewall profile, and whether the service is needed.")
    pause()


def windows_share_audit() -> None:
    script = "Get-SmbShare | Select-Object Name,Path,Description,Special,FolderEnumerationMode"
    try:
        shares = loading("Reading Windows shares", lambda: powershell_json(script, 60))
        table("WINDOWS FILE SHARES", ["Share", "Path", "Description", "Special", "Enumeration"],
              [[x.get("Name", ""), x.get("Path", ""), x.get("Description", ""),
                x.get("Special", ""), x.get("FolderEnumerationMode", "")] for x in shares], 100)
    except Exception:
        code, output, error = loading("Trying share inventory fallback", lambda: command(["net", "share"], 45))
        if code: print(paint(f"Windows share inventory unavailable: {error or output}", "yellow"))
        else: print(output)
    print("Administrative shares ending in $ are built into Windows. Review unexpected custom shares and their permissions.")
    pause()


def security_services_audit() -> None:
    names = "WinDefend,MpsSvc,BFE,EventLog,SecurityHealthService,wuauserv,Winmgmt"
    script = (f"Get-Service -Name {names} -ErrorAction SilentlyContinue | Select-Object "
              "Name,DisplayName,@{N='Status';E={$_.Status.ToString()}},"
              "@{N='StartType';E={$_.StartType.ToString()}}")
    try:
        services = loading("Checking security services", lambda: powershell_json(script, 60))
        critical = {"WinDefend", "MpsSvc", "BFE", "EventLog", "Winmgmt"}
        rows = []
        for item in services:
            name = str(item.get("Name", ""))
            status = str(item.get("Status", ""))
            result = "PASS" if name not in critical or status.lower() == "running" else "REVIEW"
            rows.append([name, item.get("DisplayName", ""), status, item.get("StartType", ""), result])
        table("WINDOWS SECURITY SERVICE HEALTH", ["Service", "Display name", "Status", "Start type", "Result"], rows, 50)
        print("Demand-start services may normally appear stopped. REVIEW is not a malware verdict.")
    except Exception as exc:
        print(paint(f"Security service audit unavailable: {exc}", "yellow"))
    pause()


def collect_installed_software() -> list[list[object]]:
    if winreg is None: return []
    uninstall = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    roots = [(winreg.HKEY_LOCAL_MACHINE, "All users"), (winreg.HKEY_CURRENT_USER, "Current user")]
    views = (getattr(winreg, "KEY_WOW64_64KEY", 0), getattr(winreg, "KEY_WOW64_32KEY", 0))
    rows = []
    seen = set()
    for root, scope in roots:
        for view in views:
            try:
                with winreg.OpenKey(root, uninstall, 0, winreg.KEY_READ | view) as parent:
                    for index in range(winreg.QueryInfoKey(parent)[0]):
                        try:
                            child_name = winreg.EnumKey(parent, index)
                            with winreg.OpenKey(parent, child_name) as child:
                                def value(name):
                                    try: return winreg.QueryValueEx(child, name)[0]
                                    except OSError: return ""
                                name = str(value("DisplayName")).strip()
                                if not name: continue
                                version = str(value("DisplayVersion")).strip()
                                publisher = str(value("Publisher")).strip()
                                installed = str(value("InstallDate")).strip()
                                key = (name.lower(), version.lower(), scope)
                                if key in seen: continue
                                seen.add(key)
                                rows.append([installed, name, version, publisher, scope])
                        except OSError:
                            pass
            except OSError:
                pass
    rows.sort(key=lambda row: (bool(row[0]), str(row[0])), reverse=True)
    return rows


def recent_software_audit() -> None:
    rows = loading("Reading installed software", collect_installed_software)
    table("INSTALLED SOFTWARE INVENTORY", ["Install date", "Application", "Version", "Publisher", "Scope"], rows, 250)
    print(f"Found {len(rows)} application record(s). Blank or old install dates are common in Windows installer records.")
    print("Review software you do not recognize, but verify its publisher and purpose before uninstalling anything.")
    pause()


def firewall_rule_review() -> None:
    script = (
        "$rules=Get-NetFirewallRule -PolicyStore ActiveStore -Enabled True -Direction Inbound -Action Allow | "
        "Select-Object -First 350; foreach($rule in $rules){$port=@($rule|Get-NetFirewallPortFilter);"
        "$app=@($rule|Get-NetFirewallApplicationFilter);[pscustomobject]@{"
        "Name=$rule.DisplayName;Profile=$rule.Profile;Protocol=($port.Protocol -join ',');"
        "LocalPort=($port.LocalPort -join ',');Program=($app.Program -join ',');"
        "Service=$rule.Service;PolicyStore=$rule.PolicyStoreSourceType}}"
    )
    try:
        items = loading("Reading inbound firewall rules", lambda: powershell_json(script, 150))
        rows = [[x.get("Name", ""), x.get("Profile", ""), x.get("Protocol", ""),
                 x.get("LocalPort", ""), x.get("Program", ""), x.get("Service", "")]
                for x in items]
        table("ENABLED INBOUND ALLOW RULES", ["Rule", "Profile", "Protocol", "Port", "Program", "Service"], rows, 350)
        print("Review broad Any-profile or Any-port rules first. An allow rule is not automatically unsafe.")
    except Exception as exc:
        print(paint(f"Firewall rule review unavailable: {exc}", "yellow"))
    pause()


def network_profile_audit() -> None:
    script = (
        "Get-NetConnectionProfile | ForEach-Object {$ip=Get-NetIPConfiguration -InterfaceIndex $_.InterfaceIndex "
        "-ErrorAction SilentlyContinue;[pscustomobject]@{Name=$_.Name;Category=$_.NetworkCategory;"
        "IPv4=$_.IPv4Connectivity;IPv6=$_.IPv6Connectivity;Interface=$_.InterfaceAlias;"
        "DNS=($ip.DNSServer.ServerAddresses -join ', ')}}"
    )
    try:
        items = loading("Reading network profiles", lambda: powershell_json(script, 60))
        rows = [[x.get("Name", ""), x.get("Category", ""), x.get("Interface", ""),
                 x.get("IPv4", ""), x.get("IPv6", ""), x.get("DNS", "")] for x in items]
        table("WINDOWS NETWORK PROFILES", ["Network", "Category", "Interface", "IPv4", "IPv6", "DNS servers"], rows, 50)
        print("Use Public for networks you do not control. Private enables more local discovery and sharing behavior.")
    except Exception as exc:
        print(paint(f"Network profile audit unavailable: {exc}", "yellow"))
    pause()


def uac_smartscreen_audit() -> None:
    if winreg is None:
        print(paint("Windows registry access is unavailable.", "yellow")); pause(); return
    system = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    smart = r"SOFTWARE\Policies\Microsoft\Windows\System"
    apphost = r"Software\Microsoft\Windows\CurrentVersion\AppHost"
    values = [
        ("UAC enabled", registry_value(winreg.HKEY_LOCAL_MACHINE, system, "EnableLUA"), "1 expected"),
        ("Admin consent prompt", registry_value(winreg.HKEY_LOCAL_MACHINE, system, "ConsentPromptBehaviorAdmin"), "2 or 5 commonly used"),
        ("Secure desktop prompt", registry_value(winreg.HKEY_LOCAL_MACHINE, system, "PromptOnSecureDesktop"), "1 expected"),
        ("SmartScreen policy", registry_value(winreg.HKEY_LOCAL_MACHINE, smart, "EnableSmartScreen"), "1 or Not configured"),
        ("SmartScreen level", registry_value(winreg.HKEY_LOCAL_MACHINE, smart, "ShellSmartScreenLevel"), "Warn or Block"),
        ("User reputation check", registry_value(winreg.HKEY_CURRENT_USER, apphost, "EnableWebContentEvaluation"), "1 or Not configured"),
    ]
    rows = [[name, "Not configured" if value is None else value, expectation] for name, value, expectation in values]
    table("UAC AND SMARTSCREEN SIGNALS", ["Setting", "Observed", "Reference"], rows, 30)
    print("Not configured usually means Windows or organization defaults apply; this tool changes nothing.")
    pause()


def recovery_readiness_audit() -> None:
    code, output, error = loading("Checking Windows Recovery", lambda: command(["reagentc.exe", "/info"], 45))
    print(paint("\nWINDOWS RECOVERY ENVIRONMENT", "cyan", bold=True))
    print(output if not code else paint(error or "REAgentC did not return status.", "yellow"))
    try:
        points = powershell_json("Get-ComputerRestorePoint | Select-Object SequenceNumber,Description,CreationTime,RestorePointType", 60)
        rows = [[x.get("SequenceNumber", ""), x.get("Description", ""), x.get("CreationTime", ""), x.get("RestorePointType", "")] for x in points]
        table("AVAILABLE SYSTEM RESTORE POINTS", ["ID", "Description", "Created", "Type"], rows, 50)
    except Exception as exc:
        print(paint(f"Restore points could not be read: {exc}", "yellow"))
    print("This is a readiness check only. No recovery settings or restore points were changed.")
    pause()


def path_security_audit() -> None:
    sources = [("Process", os.environ.get("PATH", ""))]
    if winreg is not None:
        machine = registry_value(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment", "Path")
        user = registry_value(winreg.HKEY_CURRENT_USER, r"Environment", "Path")
        if machine: sources.append(("Machine", str(machine)))
        if user: sources.append(("User", str(user)))
    rows = []
    seen: set[str] = set()
    user_roots = [value.lower() for value in (os.environ.get("USERPROFILE", ""), os.environ.get("APPDATA", ""), os.environ.get("LOCALAPPDATA", ""), os.environ.get("TEMP", "")) if value]
    for scope, raw in sources:
        for index, entry in enumerate(raw.split(os.pathsep), 1):
            expanded = os.path.expandvars(entry.strip().strip('"'))
            key = os.path.normcase(os.path.normpath(expanded)) if expanded else ""
            reasons = []
            if not expanded: reasons.append("empty/current-directory entry")
            elif not os.path.isabs(expanded): reasons.append("relative path")
            else:
                try:
                    if not Path(expanded).is_dir(): reasons.append("missing folder")
                except OSError:
                    reasons.append("invalid or inaccessible path")
            if key and key in seen: reasons.append("duplicate")
            if key: seen.add(key)
            if expanded and any(os.path.normcase(expanded).lower().startswith(root) for root in user_roots):
                reasons.append("user-writable location")
            rows.append([scope, index, expanded or "<empty>", "; ".join(reasons) or "Normal"])
    table("PATH SEARCH ORDER REVIEW", ["Scope", "Order", "Entry", "Assessment"], rows, 250)
    print("Earlier PATH entries win. Missing, relative, or unexpected writable folders can create search-order risk.")
    pause()


def certificate_expiry_audit() -> None:
    script = (
        "$now=Get-Date;$limit=$now.AddDays(90);foreach($store in 'Cert:\\CurrentUser\\My','Cert:\\LocalMachine\\My'){"
        "if(Test-Path $store){Get-ChildItem $store | Where-Object {$_.NotAfter -le $limit} | ForEach-Object {"
        "[pscustomobject]@{Store=$store;Subject=$_.Subject;Issuer=$_.Issuer;NotAfter=$_.NotAfter;"
        "DaysLeft=[math]::Floor(($_.NotAfter-$now).TotalDays);Thumbprint=$_.Thumbprint}}}}"
    )
    try:
        items = loading("Checking personal certificates", lambda: powershell_json(script, 60))
        def days_left(item: dict) -> int:
            try: return int(item.get("DaysLeft", 999999))
            except (TypeError, ValueError): return 999999
        rows = [[x.get("Store", ""), x.get("Subject", ""), x.get("Issuer", ""),
                 x.get("NotAfter", ""), x.get("DaysLeft", ""), x.get("Thumbprint", "")]
                for x in sorted(items, key=days_left)]
        table("EXPIRED OR EXPIRING PERSONAL CERTIFICATES", ["Store", "Subject", "Issuer", "Expires", "Days", "Thumbprint"], rows, 100)
        print("Only CurrentUser and LocalMachine personal stores are reviewed; trusted-root expiry is intentionally excluded.")
    except Exception as exc:
        print(paint(f"Certificate audit unavailable: {exc}", "yellow"))
    pause()


def event_log_health_audit() -> None:
    script = (
        "$names='Security','System','Application','Microsoft-Windows-Windows Defender/Operational';"
        "foreach($name in $names){$log=Get-WinEvent -ListLog $name -ErrorAction SilentlyContinue;"
        "if($log){[pscustomobject]@{Name=$log.LogName;Enabled=$log.IsEnabled;Records=$log.RecordCount;"
        "MaxMB=[math]::Round($log.MaximumSizeInBytes/1MB,1);Mode=$log.LogMode;LastWrite=$log.LastWriteTime}}}"
    )
    try:
        items = loading("Checking important event logs", lambda: powershell_json(script, 60))
        rows = [[x.get("Name", ""), x.get("Enabled", ""), x.get("Records", ""),
                 x.get("MaxMB", ""), x.get("Mode", ""), x.get("LastWrite", "")] for x in items]
        table("EVENT LOG HEALTH", ["Log", "Enabled", "Records", "Max MB", "Mode", "Last write"], rows, 20)
        print("Disabled, tiny, or unexpectedly inactive security logs may reduce investigation visibility.")
    except Exception as exc:
        print(paint(f"Event log audit unavailable: {exc}", "yellow"))
    pause()


def risky_windows_features_audit() -> None:
    names = ["SMB1Protocol", "TelnetClient", "TFTP", "MicrosoftWindowsPowerShellV2", "IIS-WebServerRole",
             "Windows-Defender-ApplicationGuard", "Containers-DisposableClientVM"]
    quoted = ",".join(f"'{name}'" for name in names)
    script = (f"foreach($name in @({quoted})){{$feature=Get-WindowsOptionalFeature -Online -FeatureName $name "
              "-ErrorAction SilentlyContinue;if($feature){[pscustomobject]@{Feature=$name;State=$feature.State}}}")
    try:
        items = loading("Reviewing optional Windows features", lambda: powershell_json(script, 90))
        risky = {"SMB1Protocol", "TelnetClient", "TFTP", "MicrosoftWindowsPowerShellV2", "IIS-WebServerRole"}
        rows = []
        for item in items:
            name = str(item.get("Feature", "")); state = str(item.get("State", ""))
            assessment = "REVIEW" if name in risky and state.lower() == "enabled" else "OK / informational"
            rows.append([name, state, assessment])
        table("OPTIONAL WINDOWS FEATURES", ["Feature", "State", "Assessment"], rows, 50)
        print("REVIEW means confirm the feature is needed; Cros does not disable Windows components.")
    except Exception as exc:
        print(paint(f"Optional-feature audit unavailable: {exc}", "yellow"))
    pause()


def credential_guard_audit() -> None:
    script = (
        "$item=Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\\Microsoft\\Windows\\DeviceGuard;"
        "[pscustomobject]@{VBS=$item.VirtualizationBasedSecurityStatus;"
        "Configured=($item.SecurityServicesConfigured -join ',');Running=($item.SecurityServicesRunning -join ',');"
        "Required=($item.RequiredSecurityProperties -join ',');Available=($item.AvailableSecurityProperties -join ',')}"
    )
    try:
        items = loading("Checking virtualization security", lambda: powershell_json(script, 60))
        item = items[0] if items else {}
        try: vbs_code = int(item.get("VBS", -1))
        except (TypeError, ValueError): vbs_code = -1
        vbs = {0: "Disabled", 1: "Enabled but not running", 2: "Enabled and running"}.get(vbs_code, str(item.get("VBS", "Unknown")))
        rows = [["VBS status", vbs], ["Services configured", item.get("Configured", "None") or "None"],
                ["Services running", item.get("Running", "None") or "None"],
                ["Required properties", item.get("Required", "None") or "None"],
                ["Available properties", item.get("Available", "None") or "None"]]
        table("CREDENTIAL GUARD AND VBS", ["Signal", "Value"], rows, 20)
        print("Service code 1 commonly represents Credential Guard; code 2 commonly represents memory integrity.")
    except Exception as exc:
        print(paint(f"Credential Guard audit unavailable: {exc}", "yellow"))
    pause()


def powershell_policy_audit() -> None:
    try:
        policies = loading("Reading PowerShell policy", lambda: powershell_json("Get-ExecutionPolicy -List | Select-Object Scope,ExecutionPolicy", 45))
        table("POWERSHELL EXECUTION POLICY", ["Scope", "Policy"],
              [[x.get("Scope", ""), x.get("ExecutionPolicy", "")] for x in policies], 20)
        script = (
            "$base='HKLM:\\Software\\Policies\\Microsoft\\Windows\\PowerShell';"
            "$sb=Get-ItemProperty \"$base\\ScriptBlockLogging\" -ErrorAction SilentlyContinue;"
            "$ml=Get-ItemProperty \"$base\\ModuleLogging\" -ErrorAction SilentlyContinue;"
            "$tr=Get-ItemProperty \"$base\\Transcription\" -ErrorAction SilentlyContinue;"
            "[pscustomobject]@{ScriptBlock=$sb.EnableScriptBlockLogging;Module=$ml.EnableModuleLogging;"
            "Transcription=$tr.EnableTranscripting;Invocation=$sb.EnableScriptBlockInvocationLogging}"
        )
        settings = powershell_json(script, 45)
        item = settings[0] if settings else {}
        rows = [["Script block logging", item.get("ScriptBlock", "Not configured")],
                ["Invocation logging", item.get("Invocation", "Not configured")],
                ["Module logging", item.get("Module", "Not configured")],
                ["Transcription", item.get("Transcription", "Not configured")]]
        table("POWERSHELL DEFENSIVE LOGGING", ["Control", "Policy value"], rows, 20)
        print("Execution policy is not a security boundary. Logging can improve visibility but may record sensitive command data.")
    except Exception as exc:
        print(paint(f"PowerShell policy audit unavailable: {exc}", "yellow"))
    pause()


def _protected_shred_roots() -> tuple[Path, ...]:
    values = [APP_DIR]
    for name in ("SystemRoot", "WINDIR", "ProgramFiles", "ProgramFiles(x86)", "ProgramData"):
        raw = os.environ.get(name)
        if raw:
            values.append(Path(raw))
    roots = []
    for value in values:
        try:
            resolved = value.expanduser().resolve(strict=False)
        except OSError:
            continue
        if resolved not in roots:
            roots.append(resolved)
    return tuple(roots)


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def secure_shred_file(raw_path: str, confirmed: bool = False, passes: int = 3) -> dict:
    """Overwrite and unlink one explicitly confirmed regular file.

    This is a best-effort logical overwrite. SSD wear-leveling, snapshots,
    synchronized copies, and backups are outside the file system's control.
    """
    if not confirmed:
        raise ValueError("Type SHRED and confirm the irreversible deletion first")
    if passes != 3:
        raise ValueError("Cros secure shredding uses exactly three overwrite passes")
    value = str(raw_path or "").strip().strip('"')
    if not value or len(value) > 4096:
        raise ValueError("Enter one complete local file path")
    candidate = Path(value).expanduser()
    try:
        if candidate.is_symlink():
            raise ValueError("Symbolic links and reparse-point files are not accepted")
        target = candidate.resolve(strict=True)
    except FileNotFoundError as exc:
        raise ValueError("The selected file does not exist") from exc
    except OSError as exc:
        raise ValueError(f"Windows could not resolve that file: {exc}") from exc
    if not target.is_file():
        raise ValueError("Choose one file. Folders and devices are blocked")
    if target.parent == Path(target.anchor):
        raise ValueError("Files stored directly in a drive root are protected")
    protected = _protected_shred_roots()
    if any(_is_within(target, root) for root in protected):
        raise ValueError("Cros blocks shredding its own files and protected Windows application folders")
    if target == Path(sys.executable).resolve(strict=False):
        raise ValueError("The active Python runtime is protected")

    before = os.lstat(target)
    if getattr(before, "st_nlink", 1) > 1:
        raise ValueError("Files with multiple hard links are blocked to avoid destroying another linked file")
    size = int(before.st_size)
    if size > 8 * 1024 * 1024 * 1024:
        raise ValueError("Files larger than 8 GB are blocked to prevent an unbounded shred operation")

    try:
        os.chmod(target, stat.S_IREAD | stat.S_IWRITE)
    except OSError:
        pass

    patterns: tuple[int | None, ...] = (None, 0, None)
    chunk_size = 1024 * 1024
    try:
        with target.open("r+b", buffering=0) as stream:
            opened = os.fstat(stream.fileno())
            if (getattr(before, "st_dev", None), getattr(before, "st_ino", None)) != (
                getattr(opened, "st_dev", None), getattr(opened, "st_ino", None)
            ):
                raise OSError("The file changed while Cros was opening it")
            for pattern in patterns:
                stream.seek(0)
                remaining = size
                while remaining:
                    length = min(chunk_size, remaining)
                    block = secrets.token_bytes(length) if pattern is None else bytes([pattern]) * length
                    written = stream.write(block)
                    if written != length:
                        raise OSError("Windows reported an incomplete overwrite")
                    remaining -= written
                stream.flush()
                os.fsync(stream.fileno())
    except PermissionError as exc:
        raise PermissionError("The file is in use or Windows denied write access. Close the owning program and try again") from exc

    current = os.lstat(target)
    if (getattr(before, "st_dev", None), getattr(before, "st_ino", None)) != (
        getattr(current, "st_dev", None), getattr(current, "st_ino", None)
    ):
        raise OSError("The target changed during shredding, so Cros refused to delete the replacement path")
    renamed = target.with_name(f".cros-shred-{secrets.token_hex(12)}")
    try:
        os.replace(target, renamed)
        renamed.unlink()
    except OSError:
        try:
            target.unlink(missing_ok=True)
        except OSError as exc:
            raise OSError("The file data was overwritten, but Windows could not remove the final directory entry") from exc
    if target.exists() or renamed.exists():
        raise OSError("Deletion verification failed; the file still exists")
    return {
        "ok": True,
        "file_name": target.name,
        "size": size,
        "passes": len(patterns),
        "bytes_overwritten": size * len(patterns),
        "deleted": True,
        "verification": "The original and randomized paths no longer exist",
        "storage_note": "Logical overwrite completed. SSD wear-leveling, snapshots, sync services, and backups may retain other physical or copied data.",
    }


def file_shredder() -> None:
    print(paint("\nSECURE FILE SHREDDER", "red", bold=True))
    print("Irreversible: one regular file only. Windows, application, folder, link, and drive-root targets are blocked.")
    path = input("Full path to the file: ").strip()
    confirmation = input("Type SHRED to overwrite and permanently delete this file: ").strip()
    if confirmation != "SHRED":
        print(paint("Shred cancelled.", "yellow"))
        pause()
        return
    try:
        result = secure_shred_file(path, confirmed=True)
        print(paint(f"Deleted {result['file_name']} after {result['passes']} overwrite passes.", "green"))
        print(result["storage_note"])
    except (OSError, ValueError) as exc:
        print(paint(f"File shredder stopped: {exc}", "red"))
    pause()


def open_security_guide() -> None:
    choice = input("Security tutorial [show/skip]: ").strip().lower() or "show"
    if choice == "skip": return
    print("\nIN-APP LEARNING CENTER")
    print("Return to the Cros desktop app and select Guide or Learning Center.")
    print("Choose any defensive lesson for requirements, safe steps, result guidance, sources, and related tools.")
    print("Use Guided Paths for complete workflows. Nothing opens in Visual Studio Code.")
    pause()


SECURITY_PANELS = [
    ("SYSTEM DEFENSE", [
        ("1", "RAT / Remote Scan"), ("2", "Process Audit"), ("3", "TCP Connections"),
        ("4", "Startup Persistence"), ("5", "Scheduled Tasks"), ("6", "Running Services"),
        ("7", "Defender Status"), ("8", "Defender Quick Scan"),
    ]),
    ("FILE DEFENSE", [
        ("9", "Static File Scan"), ("10", "Defender File Scan"), ("11", "Hash Reputation"),
        ("12", "Integrity Baseline"), ("13", "Integrity Compare"), ("14", "Secret Scanner"),
        ("15", "Office Macro Check"), ("16", "Downloads Risk Scan"),
    ]),
    ("WINDOWS + NETWORK", [
        ("17", "Firewall Status"), ("18", "Hosts File Audit"), ("19", "ARP Inventory"),
        ("20", "DNS Cache Review"), ("21", "Local Accounts"), ("22", "Defender Events"),
        ("23", "Full Security Report"), ("24", "Security Tutorial"),
    ]),
    ("PROTECTION AUDITS", [
        ("25", "Security Posture"), ("26", "Windows Update Audit"),
        ("27", "Secure Boot + TPM"), ("28", "BitLocker Status"),
        ("29", "Remote Access Audit"), ("30", "Defender Exclusions"),
        ("31", "Browser Extensions"), ("32", "Temp Risk Scan"),
        ("33", "Wi-Fi Security"), ("34", "Proxy Settings"),
        ("35", "Startup Folders"), ("36", "Failed Sign-ins"),
        ("37", "Network Exposure"), ("38", "Windows Shares"),
        ("39", "Security Services"), ("40", "Installed Software"), ("0", "Back"),
    ]),
    ("HARDENING + RECOVERY", [
        ("41", "Firewall Rule Review"), ("42", "Network Profiles"),
        ("43", "UAC + SmartScreen"), ("44", "Recovery Readiness"),
        ("45", "PATH Security"), ("46", "Certificate Expiry"),
        ("47", "Event Log Health"), ("48", "Risky Windows Features"),
        ("49", "Credential Guard"), ("50", "PowerShell Policy"),
        ("51", "Secure File Shredder"), ("0", "Back"),
    ]),
]


def menu_box(title: str, items: list[tuple[str, str]], color: str,
             width: int = 52, min_items: int | None = None) -> list[str]:
    label = f"[ {title} ]"; lines = ["+-" + label + "-" * max(0, width - len(label) - 2) + "+"]
    for number, name in items:
        text = f" {number:>2}  {name}"; lines.append("|" + text[:width].ljust(width) + "|")
    target_items = max(len(items), min_items or 0)
    while len(lines) < target_items + 1: lines.append("|" + " " * width + "|")
    lines.append("+" + "-" * width + "+")
    return [paint(line, color) for line in lines]


SECURITY_ACTIONS = {
    "1": rat_scanner, "2": process_audit, "3": network_connections,
    "4": startup_audit, "5": scheduled_tasks, "6": services_audit,
    "7": defender_status, "8": defender_quick_scan, "9": static_file_scan,
    "10": defender_file_scan, "11": hash_reputation, "12": integrity_baseline,
    "13": integrity_compare, "14": secret_scanner, "15": office_macro_scan,
    "16": downloads_risk_scan, "17": firewall_status, "18": hosts_file_audit,
    "19": arp_inventory, "20": dns_cache_review, "21": local_accounts,
    "22": defender_events, "23": full_security_report, "24": open_security_guide,
    "25": security_posture, "26": windows_update_audit,
    "27": secure_boot_tpm_audit, "28": bitlocker_audit,
    "29": remote_access_audit, "30": defender_exclusions_audit,
    "31": browser_extension_audit, "32": temp_risk_scan,
    "33": wifi_security_audit, "34": proxy_audit,
    "35": startup_folder_audit, "36": failed_signin_audit,
    "37": network_exposure_audit, "38": windows_share_audit,
    "39": security_services_audit, "40": recent_software_audit,
    "41": firewall_rule_review, "42": network_profile_audit,
    "43": uac_smartscreen_audit, "44": recovery_readiness_audit,
    "45": path_security_audit, "46": certificate_expiry_audit,
    "47": event_log_health_audit, "48": risky_windows_features_audit,
    "49": credential_guard_audit, "50": powershell_policy_audit,
    "51": file_shredder,
}


def security_center(color: str = "cyan") -> None:
    while True:
        os.system("cls" if os.name == "nt" else "clear")
        print(paint("\n" + "=" * 112, color))
        print(paint("CROS DEFENSIVE SECURITY CENTER".center(112), color, bold=True))
        print(paint("51 defensive tools. Read-only by default. Scans and destructive actions require confirmation.".center(112), "white"))
        print(paint("=" * 112 + "\n", color))
        for index in range(0, len(SECURITY_PANELS), 2):
            pair = SECURITY_PANELS[index:index + 2]
            height = max(len(items) for _, items in pair)
            boxes = [menu_box(title, items, color, min_items=height) for title, items in pair]
            for row in zip(*boxes): print("   ".join(row))
            if index + 2 < len(SECURITY_PANELS): print()
        choice = input("\n[ Select a security tool ] > ").strip()
        if choice == "0": return
        action = SECURITY_ACTIONS.get(choice)
        if action:
            try: action()
            except KeyboardInterrupt: print("\nSecurity action cancelled."); time.sleep(1)
            except Exception as exc: print(paint(f"Security tool error: {exc}", "red")); pause()
        else:
            print(paint("Invalid security tool number.", "red")); time.sleep(1)


if __name__ == "__main__":
    security_center()
