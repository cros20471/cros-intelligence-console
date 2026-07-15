@echo off
setlocal
cd /d "%~dp0"
chcp 65001 >nul
set "PYTHONUTF8=1"
set "PYTHONIOENCODING=utf-8"
set "BUNDLED_PYTHON=%USERPROFILE%\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe"
if exist "%BUNDLED_PYTHON%" (
  "%BUNDLED_PYTHON%" osint_tool.py
  goto :done
)
where py >nul 2>nul
if not errorlevel 1 (
  py -3 osint_tool.py
  goto :done
)
where python >nul 2>nul
if not errorlevel 1 (
  python osint_tool.py
  goto :done
)
echo Python 3 was not found. Install it from https://www.python.org/downloads/
echo During setup, enable "Add Python to PATH", then run this file again.
:done
if errorlevel 1 pause
