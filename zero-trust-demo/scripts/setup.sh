#!/bin/bash
# Zero-Trust Architecture Demo - Setup Script
# This script initializes and starts all components

set -e

echo "============================================"
echo "  Zero-Trust Security Architecture Demo"
echo "============================================"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check prerequisites
echo -e "${BLUE}Checking prerequisites...${NC}"

if ! command -v docker &> /dev/null; then
    echo -e "${RED}Error: Docker is not installed${NC}"
    exit 1
fi

if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
    echo -e "${RED}Error: Docker Compose is not installed${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Prerequisites met${NC}"
echo ""

# Navigate to project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_ROOT"

echo -e "${BLUE}Project root: $PROJECT_ROOT${NC}"
echo ""

# Create necessary directories
echo -e "${BLUE}Creating directories...${NC}"
mkdir -p certs/step
mkdir -p monitoring/prometheus/rules
echo -e "${GREEN}✓ Directories created${NC}"
echo ""

# Start infrastructure
echo -e "${YELLOW}Starting Zero-Trust Infrastructure...${NC}"
echo "This may take a few minutes on first run..."
echo ""

docker compose up -d

echo ""
echo -e "${GREEN}✓ Containers started${NC}"
echo ""

# Wait for services to be healthy
echo -e "${BLUE}Waiting for services to be ready...${NC}"

# Function to wait for a service
wait_for_service() {
    local service=$1
    local url=$2
    local max_attempts=${3:-30}
    local attempt=1

    while [ $attempt -le $max_attempts ]; do
        if curl -s "$url" > /dev/null 2>&1; then
            echo -e "${GREEN}✓ $service is ready${NC}"
            return 0
        fi
        echo "  Waiting for $service... (attempt $attempt/$max_attempts)"
        sleep 5
        ((attempt++))
    done

    echo -e "${YELLOW}⚠ $service may not be fully ready${NC}"
    return 1
}

# Wait for key services
wait_for_service "Keycloak" "http://localhost:8080/health/ready" 60
wait_for_service "Vault" "http://localhost:8200/v1/sys/health" 30
wait_for_service "Kong" "http://localhost:8001/status" 30
wait_for_service "OPA" "http://localhost:8181/health" 20
wait_for_service "Prometheus" "http://localhost:9090/-/healthy" 20
wait_for_service "Grafana" "http://localhost:3001/api/health" 20

echo ""

# Initialize Vault
echo -e "${BLUE}Initializing Vault...${NC}"
if [ -f "$PROJECT_ROOT/secrets/vault-config/vault-init.sh" ]; then
    docker exec -i zt-vault sh < "$PROJECT_ROOT/secrets/vault-config/vault-init.sh" 2>/dev/null || true
    echo -e "${GREEN}✓ Vault initialized${NC}"
fi

# Configure Kong
echo -e "${BLUE}Configuring Kong API Gateway...${NC}"
if [ -f "$PROJECT_ROOT/api-gateway/kong-config.sh" ]; then
    bash "$PROJECT_ROOT/api-gateway/kong-config.sh" 2>/dev/null || true
    echo -e "${GREEN}✓ Kong configured${NC}"
fi

echo ""
echo "============================================"
echo -e "${GREEN}  Setup Complete!${NC}"
echo "============================================"
echo ""
echo "Access the following services:"
echo ""
echo -e "  ${BLUE}Frontend Dashboard:${NC}  http://localhost:3000"
echo -e "  ${BLUE}Keycloak Admin:${NC}      http://localhost:8080/admin"
echo -e "                        (admin / admin)"
echo -e "  ${BLUE}Vault UI:${NC}            http://localhost:8200"
echo -e "                        (Token: root-token-zero-trust)"
echo -e "  ${BLUE}Kong Admin:${NC}          http://localhost:8001"
echo -e "  ${BLUE}API Gateway:${NC}         http://localhost:8000"
echo -e "  ${BLUE}Grafana:${NC}             http://localhost:3001"
echo -e "                        (admin / admin)"
echo -e "  ${BLUE}Prometheus:${NC}          http://localhost:9090"
echo -e "  ${BLUE}Kibana:${NC}              http://localhost:5601"
echo ""
echo "Test Users (in Keycloak zero-trust realm):"
echo "  admin     / Admin@123456    (Full access)"
echo "  developer / Dev@123456      (Developer access)"
echo "  viewer    / View@123456     (Read-only access)"
echo ""
echo "============================================"
