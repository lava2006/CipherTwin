<#
Run CipherTwin locally on Windows with full Docker, Neo4j, RabbitMQ, Cowrie, and external VM support.

Prerequisites:
  - Docker Desktop running (for Neo4j, RabbitMQ, Cowrie)
  - Python venv
  - Node.js 20+
#>
$ErrorActionPreference = "Stop"
$projectRoot = $PSScriptRoot

# 1. Resolve Python executable
$pythonCandidates = @(
    "C:\Users\LAVANYA\Documents\PROJECT_FINAL\.venv\Scripts\python.exe",
    (Join-Path $projectRoot ".venv\Scripts\python.exe"),
    (Join-Path (Split-Path $projectRoot -Parent) ".venv\Scripts\python.exe")
)
$python = $null
foreach ($cand in $pythonCandidates) {
    if (Test-Path $cand) { $python = $cand; break }
}
if (-not $python) {
    $pythonCmd = Get-Command python -ErrorAction SilentlyContinue
    if ($pythonCmd) { $python = $pythonCmd.Source }
}
if (-not $python) { throw "Python not found in venv or PATH." }

# 2. Resolve npm executable
$npmCmd = Get-Command npm -ErrorAction SilentlyContinue
if ($npmCmd) {
    $npm = $npmCmd.Source
} else {
    $npmCandidates = @(
        "C:\Program Files\nodejs\npm.cmd",
        "$env:APPDATA\npm\npm.cmd"
    )
    foreach ($cand in $npmCandidates) {
        if (Test-Path $cand) { $npm = $cand; break }
    }
}
if (-not $npm) { throw "npm not found." }

# 3. Ensure Docker containers are running (Neo4j, RabbitMQ, Cowrie, Decoy Web)
Write-Host "1/4 Ensuring Docker containers are running (Neo4j, RabbitMQ, Cowrie, Decoy Web)..." -ForegroundColor Cyan
try {
    & docker compose up -d neo4j rabbitmq cowrie decoy-web
    Write-Host "    Docker containers verified healthy." -ForegroundColor Green
} catch {
    Write-Warning "Docker compose returned warning: $_"
}

# 4. Check ML models exist
Write-Host "2/4 Verifying ML models and synthetic baseline..." -ForegroundColor Cyan
Push-Location (Join-Path $projectRoot "backend")
try {
    $rfModel = Join-Path $projectRoot "backend\app\ml\models\random_forest.joblib"
    if (-not (Test-Path $rfModel)) {
        & $python -m app.ml.synthetic_data
        & $python -m app.ml.train_models
    }
} finally {
    Pop-Location
}

# 5. Start FastAPI backend (0.0.0.0:8000 for local + external VM access)
Write-Host "3/4 Starting FastAPI backend on http://0.0.0.0:8000..." -ForegroundColor Green
$backend = Start-Process -FilePath $python `
    -ArgumentList "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000" `
    -WorkingDirectory (Join-Path $projectRoot "backend") -PassThru

# 6. Start React frontend (0.0.0.0:5173 for local + LAN access)
Write-Host "4/4 Starting React frontend on http://0.0.0.0:5173..." -ForegroundColor Green
$frontend = Start-Process -FilePath $npm `
    -ArgumentList "run", "dev", "--", "--host", "0.0.0.0", "--port", "5173" `
    -WorkingDirectory (Join-Path $projectRoot "frontend") -PassThru

Write-Host ""
Write-Host "==========================================================" -ForegroundColor Green
Write-Host "  CipherTwin Autonomous Cyber Defense is LIVE!" -ForegroundColor Green
Write-Host "  Local Dashboard : http://localhost:5173" -ForegroundColor Yellow
Write-Host "  Network Dashboard: http://192.168.1.4:5173" -ForegroundColor Yellow
Write-Host "  API Docs        : http://localhost:8000/docs" -ForegroundColor Yellow
Write-Host "  Honeypot SSH    : 192.168.1.4:2222" -ForegroundColor Yellow
Write-Host "  Ingest API Key  : ciphertwin-remote-vm-key-2026" -ForegroundColor Yellow
Write-Host "==========================================================" -ForegroundColor Green
Write-Host "Press Ctrl+C to stop both processes." -ForegroundColor Yellow

try {
    while ($true) {
        if ($backend.HasExited) { throw "Backend stopped unexpectedly." }
        if ($frontend.HasExited) { throw "Frontend stopped unexpectedly." }
        Start-Sleep -Seconds 1
    }
} finally {
    foreach ($process in @($backend, $frontend)) {
        if ($process -and -not $process.HasExited) {
            Stop-Process -Id $process.Id -Force
        }
    }
}
