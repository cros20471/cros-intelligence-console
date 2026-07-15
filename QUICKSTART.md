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

## 2. Add your first pin

1. Open **Pinboard**.
2. Enter a label, an optional web link or local file/folder path, and a short note.
3. Select **Add Pin**.
4. Use **Top** to prioritize it, **Open** to launch it, **Copy** to copy its target, or **Remove** to delete it.

Pins stay in the local browser profile. They are not written into this repository or sent to GitHub.

## 3. Run a tool safely

1. Open **Tool Index** and search for a workflow.
2. Select **Learn** before using an unfamiliar tool.
3. Select **Launch Tool** and provide only data you are authorized to inspect.
4. Save investigation results outside the application folder when they contain personal or sensitive information.

Only scan systems and accounts you own or have explicit permission to test.

## 4. Keep personal data private

- Do not commit `.env` files, reports, case notes, exports, keys, or local settings.
- Review `git status` before every push.
- Run the built-in **Secret Scanner** on the repository before publishing changes.
- If a real credential is ever committed, rotate it immediately and remove it from Git history. Deleting it in a later commit is not enough.

The included `.gitignore` blocks the common local-data and credential file types used by Cros.
