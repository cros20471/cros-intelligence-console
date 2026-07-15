# Quick Start Tutorial

## 1. Install Cros

1. Install Python 3.11 or newer from [python.org](https://www.python.org/downloads/). Enable **Add Python to PATH** during setup.
2. Download this repository with **Code → Download ZIP**, then extract it. Git users can clone it instead.
3. Open PowerShell in the extracted folder and run:

   ```powershell
   python -m pip install -r requirements.txt
   ```

4. Double-click `start_osint_tool.bat`.

The console opens as a local web app. It listens only on `127.0.0.1`, so other computers cannot connect to it.

### One-block PowerShell setup

If Python and Git are already installed, paste this whole block into PowerShell:

```powershell
git clone https://github.com/cros20471/cros-intelligence-console.git
cd cros-intelligence-console
python -m pip install -r requirements.txt
.\start_osint_tool.bat
```

If `python` is not recognized, replace the third line with `py -3 -m pip install -r requirements.txt`. If `git` is not recognized, close and reopen PowerShell after installing Git.

## 2. Pin a tool and add a note

1. Open **Tool Index**, choose a useful tool, and select **Pin**. It now appears at the top of **Investigation Workspace** for quick access.
2. In **Durable Notes**, enter a label, an optional web link or local file/folder path, and a short note.
3. Select **Add Pin**. Use **Top** to prioritize the note, **Open** to launch its target, **Copy** to copy it, or **Remove** to delete it.

Pinned tools and notes stay in the local `workspace_state.json` file. They persist after the app closes and are not written into this repository or sent to GitHub.

## 3. Build an investigation map

1. Open **Map** and add your first entity, such as a person, account, domain, location, or piece of evidence.
2. Add related entities.
3. Choose a **From** node and a **To** node, describe their relationship, and select **Connect**.
4. Drag nodes to organize the map. Select a node to inspect its context or remove it.

The map is saved locally with your workspace and excluded from Git.

## 4. Search a name or inspect an image in the app

1. Open **Investigate**.
2. Enter a public name or username to prepare profile candidates and focused public-web searches.
3. For an image, choose **Complete**, **Face-region**, or **Location & metadata** scan, select a file, and choose **Analyze**.
4. Review the local findings. Reverse-image buttons open third-party services, but Cros never uploads your selected file automatically.

Face-region mode only detects possible face-shaped regions. It does not identify people. Location mode reports embedded GPS when present and does not guess where a person lives.

## 5. Run a tool safely

1. Open **Tool Index** and search for a workflow.
2. Select **Learn** before using an unfamiliar tool.
3. Select **Launch Tool** and provide only data you are authorized to inspect.
4. Save investigation results outside the application folder when they contain personal or sensitive information.

Only scan systems and accounts you own or have explicit permission to test.

## 6. Keep personal data private

- Do not commit `.env` files, reports, case notes, exports, keys, or local settings.
- Review `git status` before every push.
- Run the built-in **Secret Scanner** on the repository before publishing changes.
- If a real credential is ever committed, rotate it immediately and remove it from Git history. Deleting it in a later commit is not enough.

The included `.gitignore` blocks the common local-data and credential file types used by Cros.
