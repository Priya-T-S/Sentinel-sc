# One-command start (Windows PowerShell): sets up the backend venv, builds the UI if needed, starts the server.
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location "$root\backend"
if (-not (Test-Path ".venv")) { python -m venv .venv; .\.venv\Scripts\python -m pip install -r requirements-dev.txt }
if (-not (Test-Path "$root\frontend\dist\index.html")) { Push-Location "$root\frontend"; npm ci; npm run build; Pop-Location }
Write-Host "SENTINEL-SC on http://127.0.0.1:8000"
.\.venv\Scripts\python -m uvicorn sentinel.app:app --host 127.0.0.1 --port 8000
