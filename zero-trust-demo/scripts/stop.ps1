# Zero-Trust Architecture Demo - Stop Script (PowerShell)

Write-Host "Stopping Zero-Trust Demo..." -ForegroundColor Yellow

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptDir
Set-Location $ProjectRoot

docker compose down

Write-Host "✓ All services stopped" -ForegroundColor Green
