@echo off
setlocal
cd /d "%~dp0"
chcp 65001 >nul
set "PYTHONUTF8=1"
set "PYTHONIOENCODING=utf-8"
if exist "%~dp0python\pythonw.exe" ( start "" "%~dp0python\pythonw.exe" app_server.py & exit /b 0 )
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
