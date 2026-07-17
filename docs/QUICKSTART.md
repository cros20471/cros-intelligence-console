# Quick Start Tutorial

## 1. Install Cros

Open **PowerShell**. The prompt should begin with `PS`, not `>>>`.

Paste the single supported installation command:

```powershell
irm https://raw.githubusercontent.com/cros20471/cros-intelligence-console/main/install_cros.ps1 | iex
```

That one command:

1. Finds Git and Python 3.11 or newer.
2. Installs missing prerequisites through Windows Package Manager when available.
3. Downloads Cros into your Documents folder.
4. Installs Cros and its public-account search engines.
5. Starts the local desktop app.

The first setup can take several minutes because Python packages and search-engine data must be downloaded. If Windows installs Git or Python but cannot see it immediately, reopen PowerShell and run the **same command** again—do not use a different install method.

Cros opens as a local app and listens only on `127.0.0.1`, so other computers cannot connect to its local server.

## 2. Pin a tool and add a note

1. Open **Tool Index** and choose a useful workflow.
2. Select **Pin** to keep it in the Investigation Workspace.
3. Add a short label, optional link or local path, and the minimum note needed for your case.
4. Use **Top**, **Open**, **Copy**, or **Remove** to manage the note.

Pins and notes remain in the local `workspace_state.json` file and are excluded from Git.

## 3. Resize the investigation workspace

1. Select **Investigate** or **Map**.
2. Drag the workspace's left edge to resize it.
3. Use the square button to maximize or restore it.
4. Use **X** to collapse it into the small restore button.

Research, Map, and Tool Session share this panel without taking over the main app.

## 4. Build an investigation map

1. Open **Map** and add an entity such as an account, domain, person, location, or evidence item.
2. Add related entities.
3. Choose a **From** node, **To** node, and relationship label.
4. Select **Connect**, then drag nodes into a useful layout.

The map is stored locally with your workspace and is never included in the repository.

## 5. Search a username or inspect an image

1. Open **Investigate**.
2. Enter a public username and choose an included account-search engine.
3. For an image, select Complete, Face-region, or Location & metadata analysis.
4. Review the formatted local findings before opening any third-party provider.

Face-region analysis detects possible face-shaped regions; it never identifies a person. Reverse-image buttons open provider pages but do not upload your selected image automatically.

## 6. Run tools safely

1. Select **Learn** before using an unfamiliar workflow.
2. Use only systems, accounts, and data you own or have explicit permission to examine.
3. Treat public results as leads and verify identities across multiple reliable details.
4. Keep sensitive case material outside the application folder.

## 7. Update or remove Cros

The [main project page](../README.md#update) contains the single update command and the guarded uninstall command. Updating preserves local workspace data. Uninstalling requires typing `DELETE` before removal.

## Privacy checklist

- Never commit `.env` files, reports, case notes, exports, keys, or local settings.
- Review `git status` before publishing a fork.
- Run the built-in Secret Scanner before sharing changes.
- Rotate any real credential that was ever committed; deleting it in a later commit is not enough.

Return to the [Cros project page](../README.md).
