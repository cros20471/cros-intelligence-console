@echo off
setlocal
set "SOURCE=%~dp0start_osint_tool.bat"
set "ICON=%~dp0web\cros.ico"
set "SHORTCUT=%USERPROFILE%\Desktop\Cros OSINT Console.lnk"
powershell -NoProfile -ExecutionPolicy Bypass -Command "$w=New-Object -ComObject WScript.Shell; $s=$w.CreateShortcut('%SHORTCUT%'); $s.TargetPath='%SOURCE%'; $s.WorkingDirectory='%~dp0'; $s.IconLocation='%ICON%,0'; $s.Description='Open Cros OSINT Console'; $s.Save()"
if exist "%SHORTCUT%" (
  echo Desktop shortcut created successfully.
) else (
  echo Could not create the Desktop shortcut.
)
pause
