# Cros Intelligence Console

A local desktop interface for 92 public-information research, local analysis, and defensive Windows security workflows. It includes account search, network checks, web research, photo metadata, reverse-image workflows, file and indicator analysis, RAT/remote-access heuristics, Defender integration, integrity monitoring, Windows hardening checks, recovery readiness, and privacy-friendly utilities.

The ChatGPT-style Investigation Workspace is a collapsible, resizable panel for research, the compact investigation map, and live tool sessions. All 92 workflows show their prompts and output inside Cros instead of opening a terminal window. Image modes include metadata and embedded GPS review, local face-region detection (never identity recognition), file fingerprints, and optional links to third-party reverse-image providers.

## Install and start on Windows

1. Install Python 3.11 or newer and Git.
2. Clone this repository and open its folder.
3. Run `python -m pip install -r requirements.txt`.
4. Double-click `start_osint_tool.bat`. The local app opens in a dedicated Edge or Chrome app window.
5. Search the 92-tool index or use the category, Local, Pinned, and Recent filters. Select **Launch Tool** to run it in the live in-app session, **Learn** for its lesson, or **Pin** to keep it in your workspace.

### Copy and paste into PowerShell

After installing [Python](https://www.python.org/downloads/) and [Git](https://git-scm.com/download/win), open PowerShell and paste this entire block:

```powershell
$url = "https://github.com/cros20471/cros-intelligence-console.git"
$git = Get-Command git -ErrorAction SilentlyContinue
$py = Get-Command py -ErrorAction SilentlyContinue
$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $git) { throw "Git is not installed or is not on PATH. Install Git from https://git-scm.com/download/win, then close and reopen PowerShell." }
if (-not ($py -or $python)) { throw "Python 3.11 or newer is not installed or is not on PATH. Install it from https://www.python.org/downloads/windows/, then close and reopen PowerShell." }
$here = (Get-Location).Path
$documents = [Environment]::GetFolderPath("MyDocuments")
$repo = if ((Test-Path (Join-Path $here ".git")) -or (Test-Path (Join-Path $here "start_osint_tool.bat"))) { $here } else { Join-Path $documents "cros-intelligence-console" }
if (Test-Path (Join-Path $repo ".git")) { git -C $repo pull --ff-only } elseif (-not (Test-Path (Join-Path $repo "start_osint_tool.bat"))) { git clone $url $repo }
Set-Location $repo
if ($py) { py -3 --version; if ($LASTEXITCODE -ne 0) { throw "Python 3 could not be started. Reinstall Python and enable its launcher/PATH option." }; py -3 -m pip install -r requirements.txt } else { python --version; if ($LASTEXITCODE -ne 0) { throw "Python could not be started. Reinstall Python and enable Add Python to PATH." }; python -m pip install -r requirements.txt }
Start-Process -FilePath (Join-Path $repo "start_osint_tool.bat") -WorkingDirectory $repo
```

If `python` is not recognized, try `py -3 -m pip install -r requirements.txt` instead. If `git` is not recognized, close and reopen PowerShell after installing Git.

`install_desktop_launcher.bat` creates a Windows desktop shortcut for Cros. `start_terminal_tool.bat` remains available only for users who deliberately prefer the original text menu.

New here? Follow the small [Quick Start Tutorial](QUICKSTART.md) to install Cros, pin a tool, add a note, and safely run your first workflow.

The Blackbird account-search engine is not bundled in this repository. Run **Account Engine Setup** from the tool index to clone the official Blackbird project and install its dependencies inside the in-app session. Username searches in the Investigation Workspace require that installed engine and stream its live source checks; Cros does not substitute guessed profile URLs.

Select the centered C emblem to open the animated CROS Wing Deck. Appearance settings include six color presets, a custom color picker, glow and motion controls, optional wings and particles, compact cards, three card shapes, and adjustable desktop grid density.

Use **Investigation Workspace** to pin tools for quick access and keep notes, web links, files, and folders beside them. Tool pins and notes are saved locally in `workspace_state.json`, so they remain available after closing and reopening the app—even when Cros starts on a different local port.

Use **Map** in the side workspace to build a compact neuron-style investigation graph. Add people, accounts, domains, locations, evidence, and other entities; connect them with labeled relationships; then drag the smaller nodes into a useful layout. Drag the workspace's left edge to make it narrow or wide, use the square button to maximize it, or close it to a small restore button. The graph is saved in the same local workspace file and is never included in the repository.

Use **Investigate** for username and image workflows that stay in the app. Username Search and Username Combinations run the installed Blackbird engine and display only its live output. Image Investigator accepts files up to 10 MB, analyzes a temporary copy locally, and deletes that copy immediately. Reverse-image buttons open provider upload pages but never upload the selected file automatically.

The app listens only on `127.0.0.1`, uses a random session token, validates and limits uploads, shuts down after inactivity, and does not require an internet-hosted account. In-app tool processes are allowlisted, hidden from the Windows terminal, streamed into Cros in real time, and stopped with their child processes when you select **Stop** or close the app.

Use **Change Color** to set the wing/title color and one shared border color for all three main boxes. Preferences are saved beside the program in `settings.json`.

Select **Guide** or **Learning Center** inside the app for 92 individual lessons. Every lesson explains what the tool is for, what it needs, a safe step-by-step workflow, how to read the result, related lessons, and supporting sources. Learning progress is saved locally.

Select **Guided Paths** for complete username, file-triage, Windows-protection, domain, photo-location, and remote-access-malware workflows. Select **Sources** for the official documentation, standards, and public research services referenced by the lessons. The Markdown guides remain available for terminal-mode users.

Only scan systems you own or have explicit permission to test. Searches and exports may contain personal information; handle results responsibly.

## Privacy for repository owners

The published source contains no personal settings, tool pins, maps, reports, case notes, credentials, or machine-specific absolute paths. Runtime data such as `workspace_state.json`, `settings.json`, `learning_progress.json`, reports, baselines, cases, exports, `.env` files, and common key formats is excluded by `.gitignore`.

Before publishing your own changes, run `git status` and use the built-in **Secret Scanner**. If a real credential is ever committed, rotate it and remove it from Git history; a later deletion does not erase earlier commits.

## License

MIT. See `LICENSE`.
