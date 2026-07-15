# Cros Intelligence Console

A local desktop interface for 92 public-information research, local analysis, and defensive Windows security workflows. It includes account search, network checks, web research, photo metadata, reverse-image workflows, file and indicator analysis, RAT/remote-access heuristics, Defender integration, integrity monitoring, Windows hardening checks, recovery readiness, and privacy-friendly utilities.

The in-app Investigation Lab handles public name/username research and local image analysis without opening a terminal. Image modes include metadata and embedded GPS review, local face-region detection (never identity recognition), file fingerprints, and optional links to third-party reverse-image providers.

## Install and start on Windows

1. Install Python 3.11 or newer and Git.
2. Clone this repository and open its folder.
3. Run `python -m pip install -r requirements.txt`.
4. Double-click `start_osint_tool.bat`. The local app opens in a dedicated Edge or Chrome app window.
5. Search the 92-tool index or use the category, Local, Pinned, and Recent filters. Select **Launch Tool** to open it, **Learn** for its in-app lesson, or **Pin** to keep it in your workspace.

### Copy and paste into PowerShell

After installing [Python](https://www.python.org/downloads/) and [Git](https://git-scm.com/download/win), open PowerShell and paste this entire block:

```powershell
git clone https://github.com/cros20471/cros-intelligence-console.git
cd cros-intelligence-console
python -m pip install -r requirements.txt
.\start_osint_tool.bat
```

If `python` is not recognized, try `py -3 -m pip install -r requirements.txt` instead. If `git` is not recognized, close and reopen PowerShell after installing Git.

`start_terminal_tool.bat` opens the original terminal menus. `install_desktop_launcher.bat` creates a Windows desktop shortcut for the web console.

New here? Follow the small [Quick Start Tutorial](QUICKSTART.md) to install Cros, pin a tool, add a note, and safely run your first workflow.

The Blackbird account-search engine is optional and is not bundled in this repository. In Terminal Mode, choose its setup workflow to clone Blackbird from its official repository and install its dependencies.

Select the centered C emblem to open the animated CROS Wing Deck. Appearance settings include six color presets, a custom color picker, glow and motion controls, optional wings and particles, compact cards, three card shapes, and adjustable desktop grid density.

Use **Investigation Workspace** to pin tools for quick access and keep notes, web links, files, and folders beside them. Tool pins and notes are saved locally in `workspace_state.json`, so they remain available after closing and reopening the app—even when Cros starts on a different local port.

Use **Map** to build a neuron-style investigation graph. Add people, accounts, domains, locations, evidence, and other entities; connect them with labeled relationships; then drag the nodes into a useful layout. The graph is saved in the same local workspace file and is never included in the repository.

Use **Investigate** for name and image workflows that stay in the app. Name search prepares focused username variations, public profile candidates, and targeted web searches. Image Investigator accepts files up to 10 MB, analyzes a temporary copy locally, and deletes that copy immediately. Reverse-image buttons open provider upload pages but never upload the selected file automatically.

The app listens only on `127.0.0.1`, uses a random session token, validates and limits uploads, shuts down after inactivity, and does not require an internet-hosted account. `start_terminal_tool.bat` remains available as a direct terminal fallback for legacy workflows.

Use **Change Color** to set the wing/title color and one shared border color for all three main boxes. Preferences are saved beside the program in `settings.json`.

Select **Guide** or **Learning Center** inside the app for 92 individual lessons. Every lesson explains what the tool is for, what it needs, a safe step-by-step workflow, how to read the result, related lessons, and supporting sources. Learning progress is saved locally.

Select **Guided Paths** for complete username, file-triage, Windows-protection, domain, photo-location, and remote-access-malware workflows. Select **Sources** for the official documentation, standards, and public research services referenced by the lessons. The Markdown guides remain available for terminal-mode users.

Only scan systems you own or have explicit permission to test. Searches and exports may contain personal information; handle results responsibly.

## Privacy for repository owners

The published source contains no personal settings, tool pins, maps, reports, case notes, credentials, or machine-specific absolute paths. Runtime data such as `workspace_state.json`, `settings.json`, `learning_progress.json`, reports, baselines, cases, exports, `.env` files, and common key formats is excluded by `.gitignore`.

Before publishing your own changes, run `git status` and use the built-in **Secret Scanner**. If a real credential is ever committed, rotate it and remove it from Git history; a later deletion does not erase earlier commits.

## License

MIT. See `LICENSE`.
