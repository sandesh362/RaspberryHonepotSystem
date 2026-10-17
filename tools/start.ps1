param([switch]$SkipBuild,[switch]$NoBrowser)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $projectRoot
$occupied = Get-NetTCPConnection -LocalAddress 127.0.0.1 -LocalPort 8000 -State Listen -ErrorAction SilentlyContinue
if ($occupied) {
    Write-Host 'Port 8000 is already in use. If SentinelPi is running, open http://127.0.0.1:8000.'
    exit 1
}
$pythonExe = Join-Path $projectRoot '.venv/Scripts/python.exe'
if (-not (Test-Path -LiteralPath $pythonExe)) {
    $pythonCommand = Get-Command python -ErrorAction SilentlyContinue
    $bundledPython = Join-Path $env:USERPROFILE '.cache/codex-runtimes/codex-primary-runtime/dependencies/python/python.exe'
    if (Test-Path -LiteralPath $bundledPython) {
        & $bundledPython -m venv .venv
    } elseif (Get-Command py -ErrorAction SilentlyContinue) {
        & py -3 -m venv .venv
    } elseif ($pythonCommand) {
        & $pythonCommand.Source -m venv .venv
    } else { throw 'Install Python 3.11 or newer and run this launcher again.' }
    if ($LASTEXITCODE -ne 0) { throw 'Python environment setup failed.' }
}
$requirements = Join-Path $projectRoot 'backend/requirements.txt'
$stampFile = Join-Path $projectRoot '.venv/dependency-input.sha256'
$inputHash = (Get-FileHash -LiteralPath $requirements -Algorithm SHA256).Hash
if (-not (Test-Path $stampFile) -or (Get-Content $stampFile -Raw).Trim() -ne $inputHash) {
    & $pythonExe -m pip install -r $requirements
    if ($LASTEXITCODE -ne 0) { throw 'Backend dependency installation failed.' }
    Set-Content -LiteralPath $stampFile -Value $inputHash
}
if (-not $SkipBuild -or -not (Test-Path 'frontend/dist/index.html')) {
    if (-not (Get-Command npm -ErrorAction SilentlyContinue)) { throw 'Install Node.js 22 LTS and run the launcher again.' }
    Push-Location frontend
    try {
        $lockHash = (Get-FileHash -LiteralPath package-lock.json -Algorithm SHA256).Hash
        $npmStamp = 'node_modules/.sentinel-lock.sha256'
        if (-not (Test-Path $npmStamp) -or (Get-Content $npmStamp -Raw).Trim() -ne $lockHash) {
            & npm ci
            if ($LASTEXITCODE -ne 0) { throw 'Frontend installation failed.' }
            Set-Content -LiteralPath $npmStamp -Value $lockHash
        }
        & npm run build
        if ($LASTEXITCODE -ne 0) { throw 'Frontend build failed.' }
    } finally { Pop-Location }
}
Write-Host ''
Write-Host 'SentinelPi is starting. Keep this terminal open. Ctrl+C stops it.'
if ($NoBrowser) { & $pythonExe -m backend.cli serve } else { & $pythonExe -m backend.cli serve --open-browser }
exit $LASTEXITCODE
