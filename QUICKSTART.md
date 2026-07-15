# Quick Start Tutorial

## 1. Install Cros

1. Install Python 3.11 or newer from [python.org](https://www.python.org/downloads/). Enable **Add Python to PATH** during setup.
2. Download this repository with **Code → Download ZIP**, then extract it. Git users can clone it instead.
3. Open PowerShell in the extracted folder and run the complete **One-block PowerShell setup** below. It installs Cros and the Blackbird account-search engine dependencies:

   ```powershell
   python -m pip install -r requirements.txt
   ```

4. Double-click `start_osint_tool.bat`.

The console opens as a local web app. It listens only on `127.0.0.1`, so other computers cannot connect to it.

### One-block PowerShell setup

If Python and Git are already installed, paste this whole block into PowerShell:

```powershell
$url = "https://github.com/cros20471/cros-intelligence-console.git"
$git = Get-Command git -ErrorAction SilentlyContinue
$py = Get-Command py -ErrorAction SilentlyContinue
$python = Get-Command python -ErrorAction SilentlyContinue
if ((-not $git) -or (-not ($py -or $python))) {
  if (-not (Get-Command winget -ErrorAction SilentlyContinue)) { throw "Git/Python are missing and winget is unavailable. Install Git from https://git-scm.com/download/win and Python from https://www.python.org/downloads/windows/, then reopen PowerShell." }
  if (-not $git) { winget install --id Git.Git -e --accept-source-agreements --accept-package-agreements }
  if (-not ($py -or $python)) { winget install --id Python.Python.3.12 -e --accept-source-agreements --accept-package-agreements }
  $env:Path = [Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [Environment]::GetEnvironmentVariable("Path", "User")
  $git = Get-Command git -ErrorAction SilentlyContinue; $py = Get-Command py -ErrorAction SilentlyContinue; $python = Get-Command python -ErrorAction SilentlyContinue
}
if (-not $git) { throw "Git installation did not finish. Close and reopen PowerShell, then paste this block again." }
if (-not ($py -or $python)) { throw "Python installation did not finish. Close and reopen PowerShell, then paste this block again." }
$here = (Get-Location).Path
$documents = [Environment]::GetFolderPath("MyDocuments")
$repo = if ((Test-Path (Join-Path $here ".git")) -or (Test-Path (Join-Path $here "start_osint_tool.bat"))) { $here } else { Join-Path $documents "cros-intelligence-console" }
if (Test-Path (Join-Path $repo ".git")) { git -C $repo pull --ff-only } elseif (-not (Test-Path (Join-Path $repo "start_osint_tool.bat"))) { git clone $url $repo }
Set-Location $repo
if ($py) { py -3 --version; if ($LASTEXITCODE -ne 0) { throw "Python 3 could not be started. Reinstall Python and enable its launcher/PATH option." }; py -3 -m pip install -r requirements.txt } else { python --version; if ($LASTEXITCODE -ne 0) { throw "Python could not be started. Reinstall Python and enable Add Python to PATH." }; python -m pip install -r requirements.txt }
$pythonExe = if ($py) { "py" } else { "python" }; $pythonArgs = if ($py) { @("-3") } else { @() }
$engine = Join-Path $repo "blackbird"
if (Test-Path (Join-Path $engine ".git")) { git -C $engine pull --ff-only } elseif (-not (Test-Path (Join-Path $engine "blackbird.py"))) { git clone "https://github.com/p1ngul1n0/blackbird.git" $engine }
if (-not (Test-Path (Join-Path $engine "blackbird.py"))) { throw "Blackbird was not downloaded. Check Git and your internet connection, then run the block again." }
$engineRequirements = Join-Path $engine "requirements.txt"
if (-not (Test-Path $engineRequirements)) { throw "Blackbird requirements.txt is missing. Delete the blackbird folder and run the block again." }
$tag = (& $pythonExe @pythonArgs -c "import sys; print(sys.implementation.cache_tag)").Trim(); $target = Join-Path $repo (Join-Path "engine_deps" $tag); New-Item -ItemType Directory -Force $target | Out-Null; $packages = @(Get-Content $engineRequirements | ForEach-Object { $name = ($_ -split '[<>=!~\[]')[0].Trim(); if ($name -match '^[A-Za-z0-9_.-]+$') { $name } }); & $pythonExe @pythonArgs -m pip install --target $target --upgrade @packages; if ($LASTEXITCODE -ne 0) { throw "Blackbird dependencies could not be installed." }
Start-Process -FilePath (Join-Path $repo "start_osint_tool.bat") -WorkingDirectory $repo
```

If `python` is not recognized, replace the third line with `py -3 -m pip install -r requirements.txt`. If `git` is not recognized, close and reopen PowerShell after installing Git.

## 2. Pin a tool and add a note

1. Open **Tool Index**, choose a useful tool, and select **Pin**. It now appears at the top of **Investigation Workspace** for quick access.
2. In **Durable Notes**, enter a label, an optional web link or local file/folder path, and a short note.
3. Select **Add Pin**. Use **Top** to prioritize the note, **Open** to launch its target, **Copy** to copy it, or **Remove** to delete it.

Pinned tools and notes stay in the local `workspace_state.json` file. They persist after the app closes and are not written into this repository or sent to GitHub.

## 3. Open and resize the investigation workspace

1. Select **Investigate** or **Map** in Cros.
2. Drag the workspace's left edge to make the panel smaller or larger.
3. Use the square button to maximize or restore it. Use **X** to collapse it into the small **Open Workspace** button.

The Research, Map, and Tool Session views share this one panel, so they do not take over the main app.

## 4. Build an investigation map

1. Open **Map** and add your first entity, such as a person, account, domain, location, or piece of evidence.
2. Add related entities.
3. Choose a **From** node and a **To** node, describe their relationship, and select **Connect**.
4. Drag nodes to organize the map. Select a node to inspect its context or remove it.

The map is saved locally with your workspace and excluded from Git.

## 5. Search a username or inspect an image in the app

1. Open **Investigate**.
2. Enter a public username. Cros runs the installed Blackbird engine and streams live source checks in **Tool Session**; it does not invent profile links. If Blackbird is missing, run **Account Engine Setup** from the tool index first.
3. For an image, choose **Complete**, **Face-region**, or **Location & metadata** scan, select a file, and choose **Analyze**.
4. Review the local findings. Reverse-image buttons open third-party services, but Cros never uploads your selected file automatically.

Face-region mode only detects possible face-shaped regions. It does not identify people. Location mode reports embedded GPS when present and does not guess where a person lives.

## 6. Run a tool safely

1. Open **Tool Index** and search for a workflow.
2. Select **Learn** before using an unfamiliar tool.
3. Select **Launch Tool**. Its prompts, live progress bar, elapsed time, and output stay in the resizable Cros workspace; reply with the input field when asked.
4. Save investigation results outside the application folder when they contain personal or sensitive information.

Only scan systems and accounts you own or have explicit permission to test.

## 7. Keep personal data private

- Do not commit `.env` files, reports, case notes, exports, keys, or local settings.
- Review `git status` before every push.
- Run the built-in **Secret Scanner** on the repository before publishing changes.
- If a real credential is ever committed, rotate it immediately and remove it from Git history. Deleting it in a later commit is not enough.

The included `.gitignore` blocks the common local-data and credential file types used by Cros.
