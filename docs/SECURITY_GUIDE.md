# Cros Defensive Security Center — Complete Guide

## Scope and safety

The Security Center is defensive and local-first. It audits the current Windows computer, files, and folders you choose. It does not create remote-access software, exploit systems, delete files, disable services, or remove registry entries.

Most tools are read-only. Microsoft Defender Quick Scan and Defender File Scan require explicit confirmation because they start antivirus scans; Defender can handle a detection according to your existing Windows security policy. Hash Reputation asks before opening a browser and sends only a SHA-256 hash to VirusTotal, not the file itself.

Heuristic findings are leads, not verdicts. Remote-support software such as AnyDesk, TeamViewer, RustDesk, ScreenConnect, VNC, or Radmin can be installed legitimately. Confirm the owner, installation source, digital signature, file hash, network activity, and business purpose before taking action.

## Opening the Security Center

1. Start **OPEN THIS - Cros OSINT Tool.cmd** from the Desktop.
2. Select **Defense**, use global search, or browse the Security cards.
3. Launch the exact workflow you want from its card.
4. For the original terminal layout, choose **Terminal Mode**, then enter `21` for Security Center and `0` to return.

The Security Center uses the same unified perimeter color as the main menu.

## System Defense

### 1. RAT / Remote Scan

Runs a read-only heuristic review of running processes, active TCP entries, and startup Run keys. It looks for remote-control tool terms, suspicious command-line behavior, executables running from temporary folders, and flagged processes with active connections.

Best use:

1. Close software you do not need.
2. Run the scan.
3. Review every lead's path and reason.
4. Use Static File Scan on an unfamiliar executable.
5. Use Hash Reputation and Defender File Scan.
6. Check Startup Persistence and Scheduled Tasks for the same file.

The report is saved in `outputs/security_reports`.

### 2. Process Audit

Choose `flagged` for a short list or `all` for every visible process. Process paths may be unavailable for protected system processes.

Look for:

- Unknown executables in temporary or Downloads folders.
- Misspelled names imitating Windows processes.
- Unexpected remote-control software.
- A suspicious process that also appears in Network Connections or persistence tools.

### 3. TCP Connections

Lists listening and established TCP connections and maps each PID to a process when possible.

Connections to cloud providers, CDNs, browsers, game launchers, and Windows services are common. Investigate combinations of an unknown process, an unusual path, persistence, and unexplained remote connections.

### 4. Startup Persistence

Reads current-user and machine Run/RunOnce registry values in both registry views. Nothing is changed.

Do not delete startup entries based only on an unfamiliar name. Search the path, inspect its signature, and create a backup or restore point before making changes outside this tool.

### 5. Scheduled Tasks

Lists enabled Windows scheduled tasks, their executable, and arguments. Items with remote-tool terms, suspicious command patterns, or temporary paths are sorted toward the top.

Microsoft, browser, driver, updater, and OEM tasks are normal. Confirm the publisher and path.

Some Windows policies hide task details from standard users. If both built-in task readers are blocked, the tool explains that this view must be opened by running the launcher as Administrator.

### 6. Running Services

Lists running services and binary paths. Remote-tool and temporary-path leads are prioritized.

Never stop or disable a service unless you know its role. Doing so can make Windows or installed software unstable.

### 7. Defender Status

When Windows permits detailed status access, this shows whether Microsoft Defender antivirus, real-time protection, behavior monitoring, network inspection, and downloaded-file scanning are enabled, plus signature and scan ages. If detailed fields are restricted, it falls back to the Defender service status and clearly labels the limited view.

If the command is unavailable, another antivirus product or organizational policy may control protection.

### 8. Defender Quick Scan

Starts Microsoft's built-in Quick Scan only after confirmation. The loading bar remains active while PowerShell waits for completion. Some systems require Administrator access.

## File Defense

### 9. Static File Scan

Performs local, non-executing analysis:

- SHA-256
- File size and header bytes
- Entropy estimate
- Extension and double-extension check
- Authenticode signature status
- Selected review strings from the first 4 MB

High entropy can mean compression, encryption, packing, or ordinary compressed media. Strings and unsigned status are not malware proof.

### 10. Defender File Scan

Asks Microsoft Defender to scan one file or folder. Confirmation is required. The target is not uploaded by Cros Security Center.

### 11. Hash Reputation

Accepts a file or SHA-256. For a file, the hash is calculated locally. If you approve opening the browser, only the hash is included in the VirusTotal URL.

No detection result is perfect. Check detection names, vendors, first-seen date, signatures, and behavior rather than relying on one score.

### 12. Integrity Baseline

Creates SHA-256 records for up to 5,000 files in a selected folder. Baselines are stored in `outputs/security_baselines`.

Create a baseline when a folder is known-good. Keep a protected backup of important baselines.

### 13. Integrity Compare

Loads a baseline, rescans its original folder, and reports added, modified, and missing files. A timestamped report is saved locally.

Expected software updates can change many files. Compare changes with update times and publisher information.

### 14. Secret Scanner

Scans up to 3,000 small text/code files for patterns resembling private keys, API keys, tokens, and assigned secrets. It prints file names, line numbers, and types, but never the secret values.

False positives are expected. If a real secret was committed or exposed, rotate it rather than only deleting the file.

### 15. Office Macro Check

Examines Office ZIP containers for VBA projects, embedded objects, and external relationships. It recognizes legacy OLE documents but does not execute macros.

A macro-enabled document can be legitimate. Scan it with Defender and verify its source before opening.

### 16. Downloads Risk Scan

Reviews the Downloads folder for executable, script, macro-capable, shortcut, disk-image, and double-extension files. Nothing is deleted or quarantined.

Use age, source, signature, static analysis, and Defender results to decide what deserves attention.

## Windows and Network

### 17. Firewall Status

Shows Domain, Private, and Public firewall profile state and default actions. Public profile protection is especially important on untrusted networks.

### 18. Hosts File Audit

Lists active hosts-file entries. Entries may come from local development tools, ad blockers, security products, or unwanted redirection.

### 19. ARP Inventory

Displays recently observed local-network neighbors from the ARP table. An entry does not prove device ownership or current presence.

### 20. DNS Cache Review

Summarizes locally cached DNS record names. Windows and background applications perform DNS lookups automatically, so a cached domain is not proof that a person intentionally visited it.

### 21. Local Accounts

Lists local Windows accounts, enabled state, last logon when available, and password properties. Built-in and service-created accounts can be normal.

### 22. Defender Events

Reads recent Microsoft Defender detection, remediation, disabled-protection, and configuration-change events from the Defender Operational log.

### 23. Full Security Report

Creates a read-only snapshot containing process, TCP, startup, Defender, firewall, protection-posture, and heuristic lead summaries. It does not trigger an antivirus scan or change settings. Reports are stored in `outputs/security_reports`.

### 24. Security Tutorial

Choose `open` to open this guide or `skip` to return immediately.

## Protection Audits

### 25. Security Posture

Builds one compact protection summary from Microsoft Defender, Windows Firewall, User Account Control, Remote Desktop, Remote Assistance, and SMB1 settings. Results are labeled `PASS`, `REVIEW`, or `UNKNOWN`.

`REVIEW` means you should inspect a setting; it does not mean the computer is infected. `UNKNOWN` usually means Windows restricted the detail or the setting is not explicitly stored in the registry.

### 26. Windows Update Audit

Shows the Windows Update and Background Intelligent Transfer Service states plus up to 15 recently installed Windows updates. This is a local history check and does not contact Microsoft to search for new updates.

Use the Windows Update page in Settings for an online update check. A service can stop when idle and start on demand, so service state alone is not a verdict.

### 27. Secure Boot + TPM

Checks Secure Boot and TPM presence, readiness, enabled state, activation, and automatic provisioning when Windows permits access. Firmware and TPM details may require running the launcher as Administrator.

Secure Boot or TPM availability depends on the computer, firmware mode, Windows edition, and configuration.

### 28. BitLocker Status

Reviews drive encryption percentage, protection state, encryption method, and lock state using Windows' built-in BitLocker tools. It never requests, reads, stores, or displays recovery keys.

Some Windows editions or policies require Administrator access for BitLocker details.

### 29. Remote Access Audit

Reviews Remote Desktop, Remote Assistance, WinRM, Remote Registry, Remote Desktop Services, and SMB protocol exposure. An enabled feature can be legitimate on a managed, work, school, gaming, or support computer.

Confirm who uses a feature and create a recovery plan before disabling it outside this tool.

### 30. Defender Exclusions

Lists Microsoft Defender path, process, extension, and IP-address exclusions when Windows permits access. Malware sometimes abuses exclusions, but development tools, virtual machines, games, backup software, and managed security products may add legitimate entries.

The audit is read-only. Defender protects exclusion details on some systems, so Administrator access may be required.

### 31. Browser Extensions

Inventories extensions from local Chrome, Edge, Brave, and Firefox profiles. Chromium extensions with permissions such as debugger access, proxy control, extension management, native messaging, or broad site access are marked for review.

Powerful permissions are not proof of malware. Password managers, blockers, developer tools, accessibility tools, and security extensions often need broad access. Verify the extension ID, publisher, store listing, and whether you intentionally installed it.

### 32. Temp Risk Scan

Reviews up to 5,000 files from local temporary folders and lists recent executables, scripts, shortcuts, disk images, macro-capable files, and double extensions from the last 30 days. Nothing is opened, executed, uploaded, or deleted.

Installers and application updaters commonly use temporary folders. Combine the result with file signatures, hashes, process activity, persistence, and Defender findings.

### 33. Wi-Fi Security

Reviews saved Wi-Fi profile authentication and cipher types with Windows' built-in network tool. Open networks are marked for review. Wi-Fi passwords are never requested or displayed.

Field parsing depends on the Windows display language. A saved profile is not proof that a network is currently nearby or safe.

### 34. Proxy Settings

Shows current-user Internet proxy, automatic configuration URL, and WinHTTP proxy state. Credentials embedded in a proxy URL are redacted before display.

Unexpected proxies can redirect traffic, but VPNs, schools, businesses, parental controls, filtering software, debuggers, and security products may configure them legitimately.

### 35. Startup Folders

Lists current-user and all-users Windows Startup-folder items. This complements option 4, which audits registry Run and RunOnce persistence. Shortcuts and script/executable items are clearly labeled for review.

Nothing is removed or resolved automatically. Check a shortcut's target and publisher before changing it.

### 36. Failed Sign-ins

Reads up to 100 Windows failed-logon events from the last seven days and shows the time, target account, source IP, logon type, and status codes. The Security event log usually requires Administrator access.

Failures can come from mistyped passwords, stale saved credentials, background services, mapped drives, or network attempts. Repeated failures are a lead that needs context, not automatic proof of an attack.

### 37. Network Exposure

Filters the local TCP table to non-loopback listening ports, maps each listener to its owning process, and labels common service ports. Listeners bound to all interfaces are shown first.

A listening port is not automatically unsafe. Confirm the application, Windows Firewall profile, network type, and whether the service is actually needed.

### 38. Windows Shares

Inventories local SMB file shares, shared paths, descriptions, and special-share status. If the primary Windows interface is restricted, the tool tries the built-in share-listing fallback.

Administrative shares ending in `$` are built into Windows. Investigate unexpected custom shares and review their permissions before changing them.

### 39. Security Services

Checks Microsoft Defender, Windows Firewall, Base Filtering Engine, Event Log, Windows Security, Windows Update, WMI, and related service states. Critical stopped services are marked for review.

Demand-start services can normally appear stopped. The result is a health lead, not proof that protection was disabled maliciously.

### 40. Installed Software

Builds a read-only inventory from current-user and all-users Windows installer records, including application name, version, publisher, scope, and install date when available.

Blank and inaccurate install dates are common. Verify an unfamiliar publisher and application purpose before uninstalling anything.

## Hardening and Recovery

### 41. Firewall Rule Review

Lists enabled inbound allow rules with their profile, protocol, local port, program, and service context. Review broad rules first, but remember that a rule does not prove a port is actively listening or internet-reachable.

### 42. Network Profiles

Shows active Windows network categories, adapters, connectivity, and DNS servers. Public is the safer category for networks you do not control.

### 43. UAC and SmartScreen

Reviews User Account Control and SmartScreen policy signals without changing them. A missing registry policy can mean that Windows or organization defaults apply.

### 44. Recovery Readiness

Checks Windows Recovery Environment status and lists available restore points when Windows permits access. Recovery tooling and restore points do not replace tested backups.

### 45. PATH Security

Flags missing, duplicate, relative, empty, and user-writable PATH entries. Confirm the owning application before changing the search order or permissions.

### 46. Certificate Expiry

Lists expired or soon-to-expire certificates in the current-user and local-computer personal stores. Identify the application owner before renewing or removing a certificate.

### 47. Event Log Health

Checks important Windows log availability, enabled state, capacity, retention mode, record count, and recent activity. A quiet log needs context before it is treated as suspicious.

### 48. Risky Windows Features

Reviews selected legacy and high-exposure optional Windows components. Enabled means confirm that the feature is needed; Cros does not disable components.

### 49. Credential Guard

Reads virtualization-based security and Credential Guard configuration and running state when available. Support depends on Windows edition, hardware, and firmware.

### 50. PowerShell Policy

Reviews execution policy by scope and defensive script, module, invocation, and transcription logging policy. Execution policy is not a security boundary, and logging settings may be organization-managed.

## Recommended RAT investigation workflow

1. Disconnect from sensitive accounts if you suspect active compromise, but avoid destroying evidence.
2. Run RAT / Remote Scan.
3. Run Security Posture and Remote Access Audit.
4. Review Process Audit and TCP Connections.
5. Check Startup Persistence, Startup Folders, Scheduled Tasks, and Running Services.
6. Review Defender Exclusions and Browser Extensions.
7. Run Static File Scan on unfamiliar binaries.
8. Check Authenticode signature and hash reputation.
9. Run Defender File Scan or Quick Scan.
10. Review Defender Events and Failed Sign-ins.
11. Save a Full Security Report.
12. If strong evidence remains, use a trusted security professional or Microsoft's offline scan/recovery guidance. Do not enter passwords on a system you believe is actively compromised.

## Recommended suspicious-file workflow

1. Do not open or execute the file.
2. Run Static File Scan.
3. Record the SHA-256.
4. Run Office Macro Check if it is an Office document.
5. Use Hash Reputation.
6. Run Defender File Scan.
7. Keep conclusions proportional to the evidence.

## Recommended integrity workflow

1. Create a baseline for a known-good project or configuration folder.
2. Store a backup of the baseline separately.
3. Compare after suspicious activity or unexpected changes.
4. Review software updates and legitimate edits before escalating.
