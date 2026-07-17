"""Curated tool catalog for the Cros desktop interface."""

from __future__ import annotations


def _rows(category: str, section: str, items: list[tuple[str, str, str, str]]):
    return [
        {
            "category": category,
            "section": section,
            "id": number,
            "name": name,
            "description": description,
            "access": access,
            "key": f"{category}:{number}",
        }
        for number, name, description, access in items
    ]


CATALOG = []

CATALOG += _rows("osint", "Identity Intelligence", [
    ("1", "Username Search", "Check one username across public account sources.", "network"),
    ("2", "Username Combinations", "Build and check structured username variations.", "network"),
    ("3", "Email Search", "Research public references tied to an email address.", "network"),
    ("4", "Breach Notifications", "Check an email with the official Have I Been Pwned notification service.", "browser"),
    ("6", "Website History", "Review archived versions of a public website.", "browser"),
    ("7", "Search Builder", "Create focused public-search queries for an investigation.", "browser"),
    ("8", "Paste Research", "Search public paste references without collecting private data.", "network"),
    ("9", "URL Extractor", "Extract and review links exposed by a public page.", "network"),
])

CATALOG += _rows("osint", "Network Intelligence", [
    ("5", "Port Scanner", "Check authorized hosts for reachable TCP services.", "network"),
    ("10", "IP Intelligence", "Collect public network and location context for an IP.", "network"),
    ("11", "Subdomain Finder", "Discover public subdomains for an authorized domain.", "network"),
    ("12", "WHOIS Lookup", "Review public domain registration records.", "network"),
    ("13", "DNS Lookup", "Inspect common DNS records for a domain.", "network"),
    ("14", "TLS Certificate", "Inspect certificate identity, issuer, and expiry.", "network"),
])

CATALOG += _rows("osint", "Media and Workspace", [
    ("15", "Photo Intelligence", "Read local metadata and prepare reverse-image research.", "local"),
    ("16", "Hash Generator", "Create a local cryptographic hash from text.", "local"),
    ("17", "Interface Appearance", "Customize app colors, borders, titles, and wings.", "local"),
    ("18", "About Cros", "Review scope, privacy boundaries, and responsible-use notes.", "local"),
])

CATALOG += _rows("advanced", "Web Intelligence", [
    ("1", "HTTP Headers", "Inspect response security and cache headers.", "network"),
    ("2", "Domain Overview", "Combine DNS, TLS, and web checks into one domain view.", "network"),
    ("3", "Discovery Files", "Review robots.txt and sitemap discovery files.", "network"),
    ("4", "URL Analyzer", "Break a URL into host, path, query, and risk signals.", "local"),
    ("5", "Redirect Tracer", "Follow a URL redirect chain and inspect each hop.", "network"),
    ("6", "Web Metadata", "Extract title, description, canonical, and social metadata.", "network"),
    ("7", "Email Header Scan", "Analyze routing, authentication, and origin clues in headers.", "local"),
])

CATALOG += _rows("advanced", "Network and Data", [
    ("8", "File Checksums", "Calculate local MD5, SHA-1, SHA-256, and SHA-512 values.", "local"),
    ("9", "Password Helper", "Generate strong passwords or estimate local password strength.", "local"),
    ("10", "Reverse DNS", "Resolve an IP address to its public hostname.", "network"),
    ("11", "CIDR Calculator", "Calculate subnet range, masks, hosts, and broadcast data.", "local"),
    ("12", "Base64 Tools", "Encode or decode Base64 data locally.", "local"),
    ("13", "Hash Identifier", "Estimate a hash family from its structure and length.", "local"),
    ("14", "Timestamp Converter", "Convert Unix timestamps and readable dates.", "local"),
])

CATALOG += _rows("advanced", "Case Workspace", [
    ("15", "JSON Formatter", "Validate and format JSON locally.", "local"),
    ("16", "Coordinate Helper", "Validate coordinates and prepare map links.", "browser"),
    ("17", "Case Notes", "Append timestamped notes to a local case file.", "local"),
    ("18", "Account Engine Setup", "Configure the optional public-account search engine.", "local"),
    ("19", "Diagnostics", "Check local packages, folders, engine state, and connectivity.", "local"),
    ("20", "Full Tutorial", "Open the in-app Cros OSINT learning center.", "local"),
])

CATALOG += _rows("advanced", "Local Analysis Lab", [
    ("21", "File Type Inspector", "Compare file extension, MIME guess, and header signature locally.", "local"),
    ("22", "IOC Normalizer", "Clean, classify, and deduplicate IPs, domains, URLs, and hashes.", "local"),
    ("23", "Text File Compare", "Create a local line-by-line comparison of two text files.", "local"),
    ("24", "JWT Decoder", "Decode JWT header and payload locally without validating or uploading it.", "local"),
])

CATALOG += _rows("security", "System Defense", [
    ("1", "RAT and Remote Scan", "Correlate processes, TCP activity, and startup persistence.", "local"),
    ("2", "Process Audit", "Review visible processes, paths, and heuristic leads.", "local"),
    ("3", "TCP Connections", "Map listening and established TCP sessions to processes.", "local"),
    ("4", "Startup Registry", "Audit Run and RunOnce persistence without changing it.", "local"),
    ("5", "Scheduled Tasks", "Review enabled tasks, commands, and suspicious paths.", "admin"),
    ("6", "Running Services", "Inspect active Windows services and binary paths.", "local"),
    ("7", "Defender Status", "Read Microsoft Defender health and signature status.", "local"),
    ("8", "Defender Quick Scan", "Start a confirmed Microsoft Defender quick scan.", "confirm"),
])

CATALOG += _rows("security", "File Defense", [
    ("9", "Static File Scan", "Inspect hash, entropy, signature, header, and review strings.", "local"),
    ("10", "RAT & Malware File Scan", "Scan a file or JAR locally with Defender and defensive static indicators.", "local"),
    ("11", "Hash Reputation", "Calculate SHA-256 locally and optionally open reputation research.", "browser"),
    ("12", "Integrity Baseline", "Create a known-good SHA-256 folder baseline.", "local"),
    ("13", "Integrity Compare", "Report added, modified, and missing files against a baseline.", "local"),
    ("14", "Secret Scanner", "Find possible exposed keys and tokens without printing values.", "local"),
    ("15", "Office Macro Check", "Inspect Office containers for macros and embedded objects.", "local"),
    ("16", "Downloads Risk Scan", "Review active, macro-capable, and double-extension downloads.", "local"),
])

CATALOG += _rows("security", "Windows and Network", [
    ("17", "Firewall Status", "Review Domain, Private, and Public firewall profiles.", "local"),
    ("18", "Hosts File Audit", "List active local hostname overrides and redirects.", "local"),
    ("19", "ARP Inventory", "Review recently observed local-network neighbors.", "local"),
    ("20", "DNS Cache", "Summarize locally cached DNS record names.", "local"),
    ("21", "Local Accounts", "Audit local accounts, state, and password properties.", "local"),
    ("22", "Defender Events", "Review recent detection and configuration events.", "local"),
    ("23", "Security Report", "Save a timestamped local protection and activity snapshot.", "local"),
    ("24", "Security Tutorial", "Open the in-app defensive security learning center.", "local"),
])

CATALOG += _rows("security", "Protection Audits", [
    ("25", "Security Posture", "Summarize Defender, firewall, UAC, remote access, and SMB1.", "local"),
    ("26", "Windows Update", "Review update services and recent installation history.", "local"),
    ("27", "Secure Boot and TPM", "Inspect firmware trust and TPM readiness.", "admin"),
    ("28", "BitLocker Status", "Review drive encryption without reading recovery keys.", "admin"),
    ("29", "Remote Access", "Audit RDP, Remote Assistance, WinRM, registry, and SMB exposure.", "local"),
    ("30", "Defender Exclusions", "Review protected Defender exclusions for unexpected entries.", "admin"),
    ("31", "Browser Extensions", "Inventory Chrome, Edge, Brave, and Firefox extensions.", "local"),
    ("32", "Temp Risk Scan", "Review recent active files in local temporary folders.", "local"),
    ("33", "Wi-Fi Security", "Review saved profile authentication without exposing passwords.", "admin"),
    ("34", "Proxy Settings", "Inspect user and WinHTTP proxies with credential redaction.", "local"),
    ("35", "Startup Folders", "Audit current-user and all-users Startup folder items.", "local"),
    ("36", "Failed Sign-ins", "Review up to 100 failed Windows logons from seven days.", "admin"),
])

CATALOG += _rows("security", "Exposure and Inventory", [
    ("37", "Network Exposure", "Focus on non-loopback listening ports and owning processes.", "local"),
    ("38", "Windows Shares", "Inventory local SMB shares and unexpected shared paths.", "admin"),
    ("39", "Security Services", "Check Defender, firewall, event log, WMI, and update services.", "local"),
    ("40", "Installed Software", "Inventory installed applications, versions, dates, and publishers.", "local"),
])

CATALOG += _rows("security", "Hardening and Recovery", [
    ("41", "Firewall Rule Review", "Review enabled inbound allow rules, programs, protocols, and ports.", "admin"),
    ("42", "Network Profiles", "Inspect active Windows network categories, adapters, and connectivity.", "local"),
    ("43", "UAC and SmartScreen", "Review account-control and reputation-protection policy signals.", "local"),
    ("44", "Recovery Readiness", "Check Windows Recovery Environment and available restore points.", "admin"),
    ("45", "PATH Security", "Find missing, duplicate, relative, and user-writable PATH entries.", "local"),
    ("46", "Certificate Expiry", "Review personal-machine certificates that are expired or expiring soon.", "local"),
    ("47", "Event Log Health", "Check important Windows log availability, size, mode, and activity.", "admin"),
    ("48", "Risky Windows Features", "Review legacy and high-exposure optional Windows components.", "admin"),
    ("49", "Credential Guard", "Inspect virtualization-based security and Credential Guard state.", "admin"),
    ("50", "PowerShell Policy", "Review execution policy and defensive PowerShell logging settings.", "local"),
])


TOOL_KEYS = {item["key"] for item in CATALOG}
