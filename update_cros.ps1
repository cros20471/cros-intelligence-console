$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
if (-not (Test-Path (Join-Path $PSScriptRoot ".git"))) { throw "This folder is not a Git checkout." }
git pull --ff-only

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
if (Test-Path (Join-Path $engine ".git")) { git -C $engine pull --ff-only }
elseif (-not (Test-Path (Join-Path $engine "blackbird.py"))) { git clone "https://github.com/p1ngul1n0/blackbird.git" $engine }
if (-not (Test-Path (Join-Path $engine "blackbird.py"))) { throw "Blackbird was not downloaded." }
$engineRequirements = Join-Path $engine "requirements.txt"
if (-not (Test-Path $engineRequirements)) { throw "Blackbird requirements.txt is missing." }
$tag = (& $pythonExe @pythonArgs -c "import sys; print(sys.implementation.cache_tag)").Trim()
$target = Join-Path $PSScriptRoot (Join-Path "engine_deps" $tag)
New-Item -ItemType Directory -Force $target | Out-Null
$packages = @(Get-Content $engineRequirements | ForEach-Object { $name = ($_ -split '[<>=!~\[]')[0].Trim(); if ($name -match '^[A-Za-z0-9_.-]+$') { $name } })
& $pythonExe @pythonArgs -m pip install --disable-pip-version-check --target $target --upgrade @packages
if ($LASTEXITCODE -ne 0) { throw "Blackbird dependencies could not be installed." }
Start-Process -FilePath (Join-Path $PSScriptRoot "start_osint_tool.bat") -WorkingDirectory $PSScriptRoot
