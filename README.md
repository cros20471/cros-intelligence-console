# Cros Intelligence Center

![Cros Intelligence Center](docs/assets/banner.svg)

**A local-first Windows workspace for public-information research, investigation notes, and defensive file and system checks.**

Cros keeps the workbench on your computer: tools run inside the app, research notes and maps stay local, and nothing is uploaded unless a workflow clearly says it will use an external service.

## What is included

- 92 guided workflows with search, lessons, local analysis, and defensive checks
- In-app investigation workspace with pins, notes, files, links, and a compact relationship map
- Username and public-source research through the optional Blackbird engine
- Local image metadata/GPS review, reverse-image handoffs, and privacy-safe face-region detection
- Local file triage with hashing, archive/JAR inspection, suspicious-indicator review, and Microsoft Defender integration
- Windows posture, integrity, recovery, network, and privacy utilities
- Resizable workspace panels, saved layout/preferences, fixed visual themes, and a quiet background launcher

## Install on Windows

Requirements: Windows 10/11, Git, and Python 3.11 or newer. The installer can use `winget` to install missing prerequisites.

Open **PowerShell** (the prompt starts with `PS`, not `>>>`) and paste:

```powershell
$p = "$env:TEMP\cros-install.ps1"
Invoke-WebRequest "https://raw.githubusercontent.com/cros20471/cros-intelligence-console/main/install_cros.ps1" -OutFile $p
powershell.exe -NoProfile -ExecutionPolicy Bypass -File $p
```

The installer downloads Cros into your Documents folder, installs the app and Blackbird dependencies, and starts the local app. If you downloaded a ZIP instead, open its folder and run `start_osint_tool.bat` after installing dependencies.

<details>
<summary>Update an existing Git installation</summary>

Close Cros, open PowerShell, and run this from the Cros folder:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\update_cros.ps1
```

If you do not know the folder, run the installer command above again. It finds the existing installation and updates it without replacing local notes, pins, maps, appearance, or operator name.

</details>

<details>
<summary>Quick start</summary>

1. Open the **Tool Index** and choose **Launch Tool** or **Learn**.
2. Use **Pin** to keep a workflow in the workspace.
3. Add notes, links, or evidence to the local map as you work.
4. Use **Settings** to choose a theme, layout, motion, and local provider keys.

See the [Quick Start Tutorial](QUICKSTART.md) for screenshots and the [User Guide](USER_GUIDE.md) for the full workflow reference.

</details>

## Privacy and safety

Cros binds to `127.0.0.1` and stores runtime state locally. Saved pins, notes, maps, reports, appearance settings, API keys, and machine-specific files are excluded from Git by default. Review [SECURITY_GUIDE.md](SECURITY_GUIDE.md) before using external providers or scanning files.

Use only public information and systems you own or are authorized to assess. A local result is not proof of identity, ownership, or malware safety; verify important findings with independent sources.

## Documentation

- [Quick Start Tutorial](QUICKSTART.md)
- [User Guide](USER_GUIDE.md)
- [Security and privacy guide](SECURITY_GUIDE.md)
- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)

## License

MIT — see [LICENSE](LICENSE).
