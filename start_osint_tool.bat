@echo off
setlocal
cd /d "%~dp0"
chcp 65001 >nul
set "PYTHONUTF8=1"
set "PYTHONIOENCODING=utf-8"
if exist "%~dp0python\pythonw.exe" ( start "" "%~dp0python\pythonw.exe" app_server.py & exit /b 0 )
where pyw >nul 2>nul
if not errorlevel 1 (
  for /f "delims=" %%P in ('py -3 -c "import sys; print(sys.executable)" 2^>nul') do set "PYTHON_EXE=%%P"
  if defined PYTHON_EXE (
    set "PYTHONW_EXE=%PYTHON_EXE:python.exe=pythonw.exe%"
    if exist "%PYTHONW_EXE%" ( start "" "%PYTHONW_EXE%" "%~dp0app_server.py" & exit /b 0 )
  )
)
where pythonw >nul 2>nul
if not errorlevel 1 (
  for /f "delims=" %%P in ('python -c "import sys; print(sys.executable)" 2^>nul') do set "PYTHON_EXE=%%P"
  if defined PYTHON_EXE (
    set "PYTHONW_EXE=%PYTHON_EXE:python.exe=pythonw.exe%"
    if exist "%PYTHONW_EXE%" ( start "" "%PYTHONW_EXE%" "%~dp0app_server.py" & exit /b 0 )
  )
)
echo A working Python 3 installation was not found.
echo Install Python from https://www.python.org/downloads/ and enable the launcher, then run this file again.
pause
