param(
  [switch]$KeepLocalData,
  [switch]$Force
)

$ErrorActionPreference = "Stop"
$root = $PSScriptRoot

if (-not $Force) {
  $answer = Read-Host "Delete Cros from this computer? Type DELETE to continue"
  if ($answer -cne "DELETE") {
    Write-Host "Uninstall cancelled."
    exit 0
  }
}

if ($KeepLocalData) {
  $backup = Join-Path ([Environment]::GetFolderPath("Desktop")) ("Cros Local Data " + (Get-Date -Format "yyyyMMdd-HHmmss"))
  New-Item -ItemType Directory -Path $backup -Force | Out-Null
  @("workspace_state.json", "appearance_state.json", "learning_progress.json", "local_key_vault.json") | ForEach-Object {
    $source = Join-Path $root $_
    if (Test-Path $source) { Copy-Item -LiteralPath $source -Destination $backup -Force }
  }
  Write-Host "Local data backup: $backup"
}

Get-CimInstance Win32_Process | Where-Object {
  $_.Name -match '^pythonw?\.exe$' -and $_.CommandLine -like "*$root*app_server.py*"
} | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }

@(
  (Join-Path ([Environment]::GetFolderPath("Desktop")) "Cros Intelligence Center.lnk"),
  (Join-Path ([Environment]::GetFolderPath("Desktop")) "Cros Intelligence Center - Private Dev.lnk"),
  (Join-Path $HOME "OneDrive\Desktop\Cros Intelligence Center.lnk"),
  (Join-Path $HOME "OneDrive\Desktop\Cros Intelligence Center - Private Dev.lnk")
) | Select-Object -Unique | Where-Object { Test-Path $_ } | ForEach-Object { Remove-Item -LiteralPath $_ -Force }

Set-Location $env:TEMP
Remove-Item -LiteralPath $root -Recurse -Force
Write-Host "Cros was removed."
