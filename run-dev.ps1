<#
Run CipherTwin locally on Windows.

Prerequisites:
  - Python 3.11+
  - Node.js 20+
  - backend dependencies installed
  - frontend dependencies installed
#>
$ErrorActionPreference = "Stop"
$projectRoot = $PSScriptRoot
$python = (Get-Command python -ErrorAction Stop).Source
$npm = (Get-Command npm -ErrorAction Stop).Source

Write-Host "1/4 Generating deterministic domain-grounded synthetic telemetry..." -ForegroundColor Cyan
Push-Location (Join-Path $projectRoot "backend")
try {
    & $python -m app.ml.synthetic_data
    if ($LASTEXITCODE -ne 0) { throw "Synthetic dataset generation failed." }

    Write-Host "2/4 Training and evaluating Random Forest + Isolation Forest..." -ForegroundColor Cyan
    & $python -m app.ml.train_models
    if ($LASTEXITCODE -ne 0) { throw "ML training failed." }
}
finally {
    Pop-Location
}

Write-Host "3/4 Starting FastAPI backend on http://localhost:8000..." -ForegroundColor Green
$backend = Start-Process -FilePath $python `
    -ArgumentList "-m", "uvicorn", "app.main:app", "--reload", "--port", "8000" `
    -WorkingDirectory (Join-Path $projectRoot "backend") -PassThru

Write-Host "4/4 Starting existing React frontend on http://localhost:5173..." -ForegroundColor Green
$frontend = Start-Process -FilePath $npm `
    -ArgumentList "run", "dev", "--", "--host", "127.0.0.1" `
    -WorkingDirectory (Join-Path $projectRoot "frontend") -PassThru

Write-Host ""
Write-Host "CipherTwin is running. Press Ctrl+C to stop both processes." -ForegroundColor Yellow
try {
    while ($true) {
        if ($backend.HasExited) { throw "Backend stopped unexpectedly." }
        if ($frontend.HasExited) { throw "Frontend stopped unexpectedly." }
        Start-Sleep -Seconds 1
    }
}
finally {
    foreach ($process in @($backend, $frontend)) {
        if ($process -and -not $process.HasExited) {
            Stop-Process -Id $process.Id -Force
        }
    }
}
