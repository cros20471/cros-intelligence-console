@echo off
setlocal
cd /d "%~dp0"
chcp 65001 >nul
set "PYTHONUTF8=1"
set "PYTHONIOENCODING=utf-8"
set "BUNDLED_PYTHONW=%USERPROFILE%\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\pythonw.exe"
if exist "%BUNDLED_PYTHONW%" (
  start "" "%BUNDLED_PYTHONW%" app_server.py
  exit /b 0
)
where pyw >nul 2>nul
if not errorlevel 1 (
  start "" pyw -3 app_server.py
  exit /b 0
)
where pythonw >nul 2>nul
if not errorlevel 1 (
  start "" pythonw app_server.py
  exit /b 0
)
echo Python 3 with pythonw was not found.
echo Run start_terminal_tool.bat for terminal mode or install Python 3.
pause
