$ErrorActionPreference = "Stop"

$repoUrl = "https://github.com/cros20471/cros-intelligence-console.git"
$documents = [Environment]::GetFolderPath("MyDocuments")
$oneDriveDocuments = Join-Path $HOME "OneDrive\Documents"
$installRoot = if (Test-Path $oneDriveDocuments) { $oneDriveDocuments } else { $documents }
$repo = Join-Path $installRoot "cros-intelligence-console"

function Refresh-Path {
  $env:Path = [Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [Environment]::GetEnvironmentVariable("Path", "User")
}

function Find-Git {
  $command = Get-Command git -ErrorAction SilentlyContinue
  if ($command) { return $command.Source }
  return @(
    (Join-Path $env:ProgramFiles "Git\cmd\git.exe"),
    (Join-Path ${env:ProgramFiles(x86)} "Git\cmd\git.exe"),
    (Join-Path $env:LOCALAPPDATA "Programs\Git\cmd\git.exe")
  ) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
}

function Find-CrosPython {
  $candidates = @()
  $launcher = Get-Command py -ErrorAction SilentlyContinue
  if ($launcher) { $candidates += ,@($launcher.Source, @("-3")) }
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
    if ($LASTEXITCODE -eq 0) { return $candidate[0] }
  }
  return $null
}

Refresh-Path
$gitExe = Find-Git
$pythonExe = Find-CrosPython
if (-not $gitExe -or -not $pythonExe) {
  if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
    throw "Cros needs Git and Python 3.11+. Install them from git-scm.com and python.org, then run this command again."
  }
  if (-not $gitExe) {
    winget install --id Git.Git -e --accept-source-agreements --accept-package-agreements
  }
  if (-not $pythonExe) {
    winget install --id Python.Python.3.12 -e --scope user --accept-source-agreements --accept-package-agreements
  }
  Refresh-Path
  $gitExe = Find-Git
  $pythonExe = Find-CrosPython
}
if (-not $gitExe) { throw "Git could not be found after installation. Reopen PowerShell and run the Cros command again." }
if (-not $pythonExe) { throw "Python could not be found after installation. Reopen PowerShell and run the Cros command again." }

if (Test-Path (Join-Path $repo ".git")) {
  & $gitExe -C $repo pull --ff-only
  if ($LASTEXITCODE -ne 0) { throw "The existing Cros folder could not be updated: $repo" }
} elseif (Test-Path $repo) {
  throw "The Cros install folder already exists but is not a Git checkout: $repo"
} else {
  & $gitExe clone $repoUrl $repo
  if ($LASTEXITCODE -ne 0 -or -not (Test-Path (Join-Path $repo ".git"))) { throw "Cros could not be downloaded from GitHub." }
}

& powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $repo "update_cros.ps1")
if ($LASTEXITCODE -ne 0) { throw "Cros setup did not complete. Review the error above and run the same install command again." }
