$ErrorActionPreference = "Stop"

$repoUrl = "https://github.com/cros20471/cros-intelligence-console.git"
$documents = [Environment]::GetFolderPath("MyDocuments")
$oneDriveDocuments = Join-Path $HOME "OneDrive\Documents"
$installRoot = if (Test-Path $oneDriveDocuments) { $oneDriveDocuments } else { $documents }
$repo = Join-Path $installRoot "cros-intelligence-console"

if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
  if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
    throw "Git is required. Install it from https://git-scm.com/download/win and run this command again."
  }
  winget install --id Git.Git -e --accept-source-agreements --accept-package-agreements
  $env:Path = [Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [Environment]::GetEnvironmentVariable("Path", "User")
}
if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
  throw "Git was installed. Reopen PowerShell and run the Cros install command again."
}

if (Test-Path (Join-Path $repo ".git")) {
  git -C $repo pull --ff-only
} elseif (Test-Path $repo) {
  throw "The install folder already exists but is not a Git checkout: $repo"
} else {
  git clone $repoUrl $repo
}

& powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $repo "update_cros.ps1")
