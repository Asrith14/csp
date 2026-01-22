# Zero-Trust Architecture Demo - Setup Script (PowerShell)
# This script initializes and starts all components

$ErrorActionPreference = "Stop"

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  Zero-Trust Security Architecture Demo" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# Check prerequisites
Write-Host "Checking prerequisites..." -ForegroundColor Blue

try {
    docker --version | Out-Null
} catch {
    Write-Host "Error: Docker is not installed" -ForegroundColor Red
    exit 1
}

try {
    docker compose version | Out-Null
} catch {
    Write-Host "Error: Docker Compose is not installed" -ForegroundColor Red
    exit 1
}

Write-Host "✓ Prerequisites met" -ForegroundColor Green
Write-Host ""

# Navigate to project root
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptDir
Set-Location $ProjectRoot

Write-Host "Project root: $ProjectRoot" -ForegroundColor Blue
Write-Host ""

# Create necessary directories
Write-Host "Creating directories..." -ForegroundColor Blue
New-Item -ItemType Directory -Force -Path "certs/step" | Out-Null
New-Item -ItemType Directory -Force -Path "monitoring/prometheus/rules" | Out-Null
Write-Host "✓ Directories created" -ForegroundColor Green
Write-Host ""

# Start infrastructure
Write-Host "Starting Zero-Trust Infrastructure..." -ForegroundColor Yellow
Write-Host "This may take a few minutes on first run..." -ForegroundColor Yellow
Write-Host ""

docker compose up -d

Write-Host ""
Write-Host "✓ Containers started" -ForegroundColor Green
Write-Host ""

# Function to wait for a service
function Wait-ForService {
    param (
        [string]$ServiceName,
        [string]$Url,
        [int]$MaxAttempts = 30
    )

    $attempt = 1
    while ($attempt -le $MaxAttempts) {
        try {
            $response = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 5 -ErrorAction SilentlyContinue
            if ($response.StatusCode -eq 200) {
                Write-Host "✓ $ServiceName is ready" -ForegroundColor Green
                return $true
            }
        } catch {
            # Service not ready yet
        }
        Write-Host "  Waiting for $ServiceName... (attempt $attempt/$MaxAttempts)"
        Start-Sleep -Seconds 5
        $attempt++
    }

    Write-Host "⚠ $ServiceName may not be fully ready" -ForegroundColor Yellow
    return $false
}

Write-Host "Waiting for services to be ready..." -ForegroundColor Blue

# Wait for key services
Wait-ForService -ServiceName "Keycloak" -Url "http://localhost:8080/health/ready" -MaxAttempts 60
Wait-ForService -ServiceName "Vault" -Url "http://localhost:8200/v1/sys/health" -MaxAttempts 30
Wait-ForService -ServiceName "Kong" -Url "http://localhost:8001/status" -MaxAttempts 30
Wait-ForService -ServiceName "OPA" -Url "http://localhost:8181/health" -MaxAttempts 20
Wait-ForService -ServiceName "Prometheus" -Url "http://localhost:9090/-/healthy" -MaxAttempts 20
Wait-ForService -ServiceName "Grafana" -Url "http://localhost:3001/api/health" -MaxAttempts 20

Write-Host ""

# Initialize Vault
Write-Host "Initializing Vault..." -ForegroundColor Blue
$vaultInitScript = Join-Path $ProjectRoot "secrets/vault-config/vault-init.sh"
if (Test-Path $vaultInitScript) {
    try {
        $scriptContent = Get-Content $vaultInitScript -Raw
        docker exec -i zt-vault sh -c $scriptContent 2>$null
        Write-Host "✓ Vault initialized" -ForegroundColor Green
    } catch {
        Write-Host "Vault initialization skipped (may already be initialized)" -ForegroundColor Yellow
    }
}

# Configure Kong
Write-Host "Configuring Kong API Gateway..." -ForegroundColor Blue
$kongConfigScript = Join-Path $ProjectRoot "api-gateway/kong-config.sh"
if (Test-Path $kongConfigScript) {
    try {
        & bash $kongConfigScript 2>$null
        Write-Host "✓ Kong configured" -ForegroundColor Green
    } catch {
        Write-Host "Kong configuration may need manual setup" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  Setup Complete!" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Access the following services:" -ForegroundColor White
Write-Host ""
Write-Host "  Frontend Dashboard:  " -NoNewline -ForegroundColor Blue
Write-Host "http://localhost:3000"
Write-Host "  Keycloak Admin:      " -NoNewline -ForegroundColor Blue
Write-Host "http://localhost:8080/admin"
Write-Host "                       (admin / admin)"
Write-Host "  Vault UI:            " -NoNewline -ForegroundColor Blue
Write-Host "http://localhost:8200"
Write-Host "                       (Token: root-token-zero-trust)"
Write-Host "  Kong Admin:          " -NoNewline -ForegroundColor Blue
Write-Host "http://localhost:8001"
Write-Host "  API Gateway:         " -NoNewline -ForegroundColor Blue
Write-Host "http://localhost:8000"
Write-Host "  Grafana:             " -NoNewline -ForegroundColor Blue
Write-Host "http://localhost:3001"
Write-Host "                       (admin / admin)"
Write-Host "  Prometheus:          " -NoNewline -ForegroundColor Blue
Write-Host "http://localhost:9090"
Write-Host "  Kibana:              " -NoNewline -ForegroundColor Blue
Write-Host "http://localhost:5601"
Write-Host ""
Write-Host "Test Users (in Keycloak zero-trust realm):" -ForegroundColor White
Write-Host "  admin     / Admin@123456    (Full access)"
Write-Host "  developer / Dev@123456      (Developer access)"
Write-Host "  viewer    / View@123456     (Read-only access)"
Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
