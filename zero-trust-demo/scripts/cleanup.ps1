# Zero-Trust Architecture Demo - Cleanup Script (PowerShell)
# Removes all containers, volumes, and networks

Write-Host "============================================" -ForegroundColor Red
Write-Host "  WARNING: This will delete all data!" -ForegroundColor Red
Write-Host "============================================" -ForegroundColor Red
Write-Host ""

$confirmation = Read-Host "Are you sure you want to continue? (yes/no)"

if ($confirmation -ne "yes") {
    Write-Host "Cleanup cancelled" -ForegroundColor Yellow
    exit 0
}

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptDir
Set-Location $ProjectRoot

Write-Host "Stopping and removing containers..." -ForegroundColor Blue
docker compose down -v --remove-orphans

Write-Host "Removing images..." -ForegroundColor Blue
docker compose down --rmi local

Write-Host "Cleaning up Docker system..." -ForegroundColor Blue
docker system prune -f

Write-Host ""
Write-Host "✓ Cleanup complete" -ForegroundColor Green
