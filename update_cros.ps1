$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
if (-not (Test-Path (Join-Path $PSScriptRoot ".git"))) {
  throw "This is not a Git checkout. First clone Cros with: git clone https://github.com/cros20471/cros-intelligence-console.git"
}
$gitCommand = Get-Command git -ErrorAction SilentlyContinue
$gitExe = if ($gitCommand) { $gitCommand.Source } else {
  @(
    (Join-Path $env:ProgramFiles "Git\cmd\git.exe"),
    (Join-Path ${env:ProgramFiles(x86)} "Git\cmd\git.exe"),
    (Join-Path $env:LOCALAPPDATA "Programs\Git\cmd\git.exe")
  ) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
}
if (-not $gitExe) { throw "Git is installed but was not found. Install Git from https://git-scm.com/download/win, reopen PowerShell, and run the updater again." }

# Release locked Python extensions before Git/pip replace the engine runtime.
$crosProcesses = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
  $_.CommandLine -match '(?i)(app_server|tool_runner|blackbird\.py)'
}
foreach ($process in $crosProcesses) {
  try { Stop-Process -Id ([int]$process.ProcessId) -Force -ErrorAction SilentlyContinue } catch {}
}
Start-Sleep -Milliseconds 800
$beforeCommit = (& $gitExe rev-parse HEAD).Trim()
& $gitExe pull --ff-only
if ($LASTEXITCODE -ne 0) { throw "Git could not update Cros. Close Git operations and run the updater again." }
$afterCommit = (& $gitExe rev-parse HEAD).Trim()
if ($beforeCommit -ne $afterCommit -and $env:CROS_UPDATER_REEXEC -ne "1") {
  $env:CROS_UPDATER_REEXEC = "1"
  $child = Start-Process -FilePath "powershell.exe" -ArgumentList @(
    "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", (Join-Path $PSScriptRoot "update_cros.ps1")
  ) -WorkingDirectory $PSScriptRoot -Wait -PassThru
  exit $child.ExitCode
}

function Find-CrosPython {
  $candidates = @()
  $launcher = Get-Command py -ErrorAction SilentlyContinue
  if ($launcher) { $candidates += ,@("py", @("-3")) }
  $command = Get-Command python -ErrorAction SilentlyContinue
  if ($command -and $command.Source -notmatch "\\WindowsApps\\") { $candidates += ,@($command.Source, @()) }
  $roots = @((Join-Path $env:LOCALAPPDATA "Programs\Python"), (Join-Path $env:LOCALAPPDATA "Python"), $env:ProgramFiles, ${env:ProgramFiles(x86)})
  foreach ($root in $roots) {
    if (-not $root -or -not (Test-Path $root)) { continue }
    Get-ChildItem -LiteralPath $root -Directory -Filter "Python*" -ErrorAction SilentlyContinue | ForEach-Object {
      $exe = Join-Path $_.FullName "python.exe"
      if (Test-Path $exe) { $candidates += ,@($exe, @()) }
    }
  }
  foreach ($candidate in $candidates) {
    & $candidate[0] @($candidate[1]) -c "import sys; print(sys.executable)" *> $null
    if ($LASTEXITCODE -eq 0) { return [pscustomobject]@{ Command = $candidate[0]; Args = @($candidate[1]) } }
  }
  return $null
}

$pythonSpec = Find-CrosPython
if (-not $pythonSpec) { throw "Python is installed but Cros could not find a usable executable. Reinstall from python.org with the launcher/PATH option enabled." }
$pythonExe = $pythonSpec.Command
$pythonArgs = @($pythonSpec.Args)
& $pythonExe @pythonArgs -m pip install --disable-pip-version-check -r (Join-Path $PSScriptRoot "requirements.txt")

$engine = Join-Path $PSScriptRoot "blackbird"
if (Test-Path (Join-Path $engine ".git")) { & $gitExe -C $engine pull --ff-only }
elseif (-not (Test-Path (Join-Path $engine "blackbird.py"))) { & $gitExe clone "https://github.com/p1ngul1n0/blackbird.git" $engine }
if (-not (Test-Path (Join-Path $engine "blackbird.py"))) { throw "Blackbird was not downloaded." }
$engineRequirements = Join-Path $engine "requirements.txt"
if (-not (Test-Path $engineRequirements)) { throw "Blackbird requirements.txt is missing." }
$tag = (& $pythonExe @pythonArgs -c "import sys; print(sys.implementation.cache_tag)").Trim()
$target = Join-Path $PSScriptRoot (Join-Path "engine_deps" $tag)
New-Item -ItemType Directory -Force $target | Out-Null
$packages = @(Get-Content $engineRequirements | ForEach-Object { $name = ($_ -split '[<>=!~\[]')[0].Trim(); if ($name -match '^[A-Za-z0-9_.-]+$') { $name } })
function Stop-CrosProcesses {
  $running = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
    $_.CommandLine -match '(?i)(app_server|tool_runner|blackbird\.py)'
  }
  foreach ($process in $running) {
    try { Stop-Process -Id ([int]$process.ProcessId) -Force -ErrorAction SilentlyContinue } catch {}
  }
  Start-Sleep -Milliseconds 800
}

Stop-CrosProcesses
& $pythonExe @pythonArgs -m pip install --disable-pip-version-check --target $target --upgrade @packages
if ($LASTEXITCODE -ne 0) {
  # OneDrive/Defender can briefly retain a compiled extension after shutdown.
  # Retry from a clean, verified generated dependency directory.
  Stop-CrosProcesses
  $engineDepsRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot "engine_deps")).TrimEnd([System.IO.Path]::DirectorySeparatorChar)
  $targetPath = [System.IO.Path]::GetFullPath((Resolve-Path -LiteralPath $target).Path).TrimEnd([System.IO.Path]::DirectorySeparatorChar)
  $allowedPrefix = $engineDepsRoot + [System.IO.Path]::DirectorySeparatorChar
  if (-not $targetPath.StartsWith($allowedPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Refusing to clean an engine dependency path outside the Cros folder."
  }
  Remove-Item -LiteralPath $targetPath -Recurse -Force
  New-Item -ItemType Directory -Force $target | Out-Null
  & $pythonExe @pythonArgs -m pip install --disable-pip-version-check --target $target @packages
  if ($LASTEXITCODE -ne 0) { throw "Blackbird dependencies could not be installed. Close Cros and run the updater again." }
}
Start-Process -FilePath (Join-Path $PSScriptRoot "start_osint_tool.bat") -WorkingDirectory $PSScriptRoot
