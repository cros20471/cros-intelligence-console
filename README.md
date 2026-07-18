# Cros Intelligence Console

A local desktop interface for 92 public-information research, local analysis, and defensive Windows security workflows. It includes account search, network checks, web research, photo metadata, reverse-image workflows, file and indicator analysis, RAT/remote-access heuristics, Defender integration, integrity monitoring, Windows hardening checks, recovery readiness, and privacy-friendly utilities.

The ChatGPT-style Investigation Workspace is a collapsible, resizable panel for research, the compact investigation map, and live tool sessions. All 92 workflows show their prompts and output inside Cros instead of opening a terminal window. Image modes include metadata and embedded GPS review, local face-region detection (never identity recognition), file fingerprints, and optional links to third-party reverse-image providers.

## Install and start on Windows

1. Install Python 3.11 or newer and Git.
2. Clone this repository and open its folder.
3. Use the PowerShell block below; it installs Cros dependencies and the Blackbird account-search engine dependencies.
4. Double-click `start_osint_tool.bat`. The local app opens in a dedicated Edge or Chrome app window.
5. Search the 92-tool index or use the category, Local, Pinned, and Recent filters. Select **Launch Tool** to run it in the live in-app session, **Learn** for its lesson, or **Pin** to keep it in your workspace.

### Copy and paste into PowerShell

After installing [Python](https://www.python.org/downloads/) and [Git](https://git-scm.com/download/win), open PowerShell and paste this entire block:

Make sure the window shows a prompt like `PS C:\Users\YourName>` before pasting. If it shows `>>>`, you are inside Python; type `exit()` first, close that window, and open **PowerShell** from the Start menu.

```powershell
$url = "https://github.com/cros20471/cros-intelligence-console.git"
$git = Get-Command git -ErrorAction SilentlyContinue
function Find-CrosPython {
  $candidates = @()
  $launcher = Get-Command py -ErrorAction SilentlyContinue
  if ($launcher) { $candidates += ,@("py", @("-3")) }
  $command = Get-Command python -ErrorAction SilentlyContinue
  if ($command -and $command.Source -notmatch "\\WindowsApps\\") { $candidates += ,@($command.Source, @()) }
  $roots = @((Join-Path $env:LOCALAPPDATA "Programs\Python"), (Join-Path $env:LOCALAPPDATA "Python"), $env:ProgramFiles, ${env:ProgramFiles(x86)})
  foreach ($root in $roots) {
    if (-not $root -or -not (Test-Path $root)) { continue }
    Get-ChildItem -LiteralPath $root -Directory -Filter "Python*" -ErrorAction SilentlyContinue | ForEach-Object {
      $exe = Join-Path $_.FullName "python.exe"
      if (Test-Path $exe) { $candidates += ,@($exe, @()) }
    }
  }
  foreach ($candidate in $candidates) { & $candidate[0] @($candidate[1]) -c "import sys; print(sys.executable)" *> $null; if ($LASTEXITCODE -eq 0) { return [pscustomobject]@{ Command = $candidate[0]; Args = @($candidate[1]) } } }
  return $null
}
$pythonSpec = Find-CrosPython
if ((-not $git) -or (-not $pythonSpec)) {
  if (-not (Get-Command winget -ErrorAction SilentlyContinue)) { throw "Git/Python are missing and winget is unavailable. Install Git from https://git-scm.com/download/win and Python from https://www.python.org/downloads/windows/, then reopen PowerShell." }
  if (-not $git) { winget install --id Git.Git -e --accept-source-agreements --accept-package-agreements }
  if (-not $pythonSpec) { winget install --id Python.Python.3.12 -e --accept-source-agreements --accept-package-agreements }
  $env:Path = [Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [Environment]::GetEnvironmentVariable("Path", "User")
  $git = Get-Command git -ErrorAction SilentlyContinue; $pythonSpec = Find-CrosPython
}
if (-not $git) { throw "Git installation did not finish. Close and reopen PowerShell, then paste this block again." }
if (-not $pythonSpec) { throw "Python is installed but Cros could not find a usable executable. Install Python from python.org with Add Python to PATH enabled, then reopen PowerShell." }
$here = (Get-Location).Path
$documents = [Environment]::GetFolderPath("MyDocuments")
$oneDriveDocuments = Join-Path $HOME "OneDrive\Documents"
$installRoot = if (Test-Path $oneDriveDocuments) { $oneDriveDocuments } else { $documents }
$repo = if ((Test-Path (Join-Path $here ".git")) -or (Test-Path (Join-Path $here "start_osint_tool.bat"))) { $here } else { Join-Path $installRoot "cros-intelligence-console" }
if (Test-Path (Join-Path $repo ".git")) { git -C $repo pull --ff-only } elseif (-not (Test-Path (Join-Path $repo "start_osint_tool.bat"))) { git clone $url $repo }
Set-Location $repo
$pythonExe = $pythonSpec.Command; $pythonArgs = @($pythonSpec.Args)
& $pythonExe @pythonArgs -c "import sys; print('Python', sys.version.split()[0], 'from', sys.executable)"; if ($LASTEXITCODE -ne 0) { throw "Python could not be started. Install Python from python.org and enable the launcher/PATH option." }; & $pythonExe @pythonArgs -m pip install -r requirements.txt
$engine = Join-Path $repo "blackbird"
if (Test-Path (Join-Path $engine ".git")) { git -C $engine pull --ff-only } elseif (-not (Test-Path (Join-Path $engine "blackbird.py"))) { git clone "https://github.com/p1ngul1n0/blackbird.git" $engine }
if (-not (Test-Path (Join-Path $engine "blackbird.py"))) { throw "Blackbird was not downloaded. Check Git and your internet connection, then run the block again." }
$engineRequirements = Join-Path $engine "requirements.txt"
if (-not (Test-Path $engineRequirements)) { throw "Blackbird requirements.txt is missing. Delete the blackbird folder and run the block again." }
$tag = (& $pythonExe @pythonArgs -c "import sys; print(sys.implementation.cache_tag)").Trim(); $target = Join-Path $repo (Join-Path "engine_deps" $tag); New-Item -ItemType Directory -Force $target | Out-Null; $packages = @(Get-Content $engineRequirements | ForEach-Object { $name = ($_ -split '[<>=!~\[]')[0].Trim(); if ($name -match '^[A-Za-z0-9_.-]+$') { $name } }); & $pythonExe @pythonArgs -m pip install --target $target --upgrade @packages; if ($LASTEXITCODE -ne 0) { throw "Blackbird dependencies could not be installed." }
Start-Process -FilePath (Join-Path $repo "start_osint_tool.bat") -WorkingDirectory $repo
```

This block is for a first-time install. If you downloaded a ZIP, use this block instead of the updater because ZIP folders do not contain Git history. If `python` is not recognized, try `py -3 -m pip install -r requirements.txt` instead. If `git` is not recognized, close and reopen PowerShell after installing Git.

### Update an existing installation

Close Cros first, open **PowerShell** (the prompt must start with `PS`, not `>>>`), and paste this block:

```powershell
$roots = @([Environment]::GetFolderPath("MyDocuments"), [Environment]::GetFolderPath("Desktop"), (Join-Path $HOME "Downloads"), $HOME) | Select-Object -Unique
$updateFile = $roots | Where-Object { Test-Path $_ } | ForEach-Object { Get-ChildItem -LiteralPath $_ -Filter "update_cros.ps1" -File -Recurse -ErrorAction SilentlyContinue } | Select-Object -First 1
$repo = if ($updateFile) { $updateFile.Directory.FullName } else { Read-Host "Paste the full path to your Cros folder" }
if (-not (Test-Path (Join-Path $repo "update_cros.ps1"))) { throw "That folder does not contain update_cros.ps1: $repo" }
powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $repo "update_cros.ps1")
```

The updater pulls the newest GitHub version, installs the matching Cros and Blackbird dependencies, then starts the updated local app. It does not upload your saved notes, map, appearance, or operator name.

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
