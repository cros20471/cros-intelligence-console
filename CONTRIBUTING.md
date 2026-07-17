# Contributing to Cros

Thanks for helping improve Cros Intelligence Center.

## Before you begin

- Keep contributions focused on lawful public-source research, local analysis, and defensive security.
- Do not add leaked datasets, credential collection, hidden uploads, destructive actions, or targeted harassment features.
- Preserve local-first behavior and clearly disclose any request sent to a third-party provider.

## Development setup

```powershell
python -m pip install -r requirements.txt
python -m unittest -v tests/test_upgrade.py
python app_server.py
```

## Pull requests

1. Create a focused branch.
2. Explain the user-facing problem and your solution.
3. Add or update tests when behavior changes.
4. Include screenshots for interface changes.
5. Confirm that local state, credentials, reports, and generated files are not included.

Small, clear pull requests are easier to review and merge.
