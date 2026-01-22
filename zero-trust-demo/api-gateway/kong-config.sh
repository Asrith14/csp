#!/bin/bash
# Kong API Gateway Configuration for Zero-Trust Architecture
# Configures routes, services, and security plugins

set -e

KONG_ADMIN_URL=${KONG_ADMIN_URL:-"http://localhost:8001"}
KEYCLOAK_URL=${KEYCLOAK_URL:-"http://keycloak:8080"}

echo "=== Kong API Gateway Zero-Trust Configuration ==="
echo "Kong Admin URL: $KONG_ADMIN_URL"

# Wait for Kong to be ready
echo "Waiting for Kong to be ready..."
until curl -s "$KONG_ADMIN_URL/status" > /dev/null 2>&1; do
    sleep 2
done
echo "Kong is ready!"

# ============================================
# Create Services
# ============================================
echo "Creating services..."

# Auth Service
curl -s -X POST "$KONG_ADMIN_URL/services" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "auth-service",
        "url": "http://auth-service:3000",
        "connect_timeout": 60000,
        "read_timeout": 60000,
        "write_timeout": 60000,
        "retries": 3
    }'

# Backend Service
curl -s -X POST "$KONG_ADMIN_URL/services" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "backend-service",
        "url": "http://backend-service:3001",
        "connect_timeout": 60000,
        "read_timeout": 60000,
        "write_timeout": 60000,
        "retries": 3
    }'

# ============================================
# Create Routes
# ============================================
echo "Creating routes..."

# Auth routes (public - for login)
curl -s -X POST "$KONG_ADMIN_URL/services/auth-service/routes" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "auth-public",
        "paths": ["/auth/login", "/auth/register", "/auth/refresh"],
        "methods": ["POST"],
        "strip_path": false
    }'

# Auth routes (protected)
curl -s -X POST "$KONG_ADMIN_URL/services/auth-service/routes" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "auth-protected",
        "paths": ["/auth/profile", "/auth/logout", "/auth/validate"],
        "methods": ["GET", "POST"],
        "strip_path": false
    }'

# Backend API routes (all protected)
curl -s -X POST "$KONG_ADMIN_URL/services/backend-service/routes" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "api-v1",
        "paths": ["/api/v1"],
        "strip_path": false
    }'

# Health check routes (public)
curl -s -X POST "$KONG_ADMIN_URL/services/auth-service/routes" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "health-auth",
        "paths": ["/health/auth"],
        "methods": ["GET"],
        "strip_path": true
    }'

curl -s -X POST "$KONG_ADMIN_URL/services/backend-service/routes" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "health-backend",
        "paths": ["/health/backend"],
        "methods": ["GET"],
        "strip_path": true
    }'

# ============================================
# Configure Security Plugins (Global)
# ============================================
echo "Configuring global security plugins..."

# Rate Limiting - Prevent brute force attacks
curl -s -X POST "$KONG_ADMIN_URL/plugins" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "rate-limiting",
        "config": {
            "minute": 100,
            "hour": 1000,
            "policy": "local",
            "fault_tolerant": true,
            "hide_client_headers": false
        }
    }'

# Request Size Limiting
curl -s -X POST "$KONG_ADMIN_URL/plugins" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "request-size-limiting",
        "config": {
            "allowed_payload_size": 10,
            "size_unit": "megabytes"
        }
    }'

# IP Restriction (example - allow all for demo)
# In production, whitelist specific IPs
curl -s -X POST "$KONG_ADMIN_URL/plugins" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "ip-restriction",
        "config": {
            "allow": ["0.0.0.0/0"]
        },
        "enabled": false
    }'

# CORS Configuration
curl -s -X POST "$KONG_ADMIN_URL/plugins" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "cors",
        "config": {
            "origins": ["http://localhost:3000"],
            "methods": ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
            "headers": ["Authorization", "Content-Type", "X-Request-ID"],
            "exposed_headers": ["X-Request-ID"],
            "credentials": true,
            "max_age": 3600
        }
    }'

# Request/Response Transformer - Add security headers
curl -s -X POST "$KONG_ADMIN_URL/plugins" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "response-transformer",
        "config": {
            "add": {
                "headers": [
                    "X-Content-Type-Options:nosniff",
                    "X-Frame-Options:DENY",
                    "X-XSS-Protection:1; mode=block",
                    "Strict-Transport-Security:max-age=31536000; includeSubDomains",
                    "Content-Security-Policy:default-src '\''self'\''"
                ]
            }
        }
    }'

# Request ID for tracing
curl -s -X POST "$KONG_ADMIN_URL/plugins" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "correlation-id",
        "config": {
            "header_name": "X-Request-ID",
            "generator": "uuid",
            "echo_downstream": true
        }
    }'

# ============================================
# Configure JWT Authentication for Protected Routes
# ============================================
echo "Configuring JWT authentication..."

# Add JWT plugin to protected auth routes
curl -s -X POST "$KONG_ADMIN_URL/routes/auth-protected/plugins" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "jwt",
        "config": {
            "claims_to_verify": ["exp"],
            "key_claim_name": "iss",
            "secret_is_base64": false,
            "run_on_preflight": true
        }
    }'

# Add JWT plugin to API routes
curl -s -X POST "$KONG_ADMIN_URL/routes/api-v1/plugins" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "jwt",
        "config": {
            "claims_to_verify": ["exp"],
            "key_claim_name": "iss",
            "secret_is_base64": false,
            "run_on_preflight": true
        }
    }'

# ============================================
# Configure ACL (Access Control Lists)
# ============================================
echo "Configuring ACL..."

# ACL for API routes - require specific groups
curl -s -X POST "$KONG_ADMIN_URL/routes/api-v1/plugins" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "acl",
        "config": {
            "allow": ["admin", "developer"],
            "hide_groups_header": false
        }
    }'

# ============================================
# Logging Plugins
# ============================================
echo "Configuring logging..."

# HTTP Log - Send to logging service
curl -s -X POST "$KONG_ADMIN_URL/plugins" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "http-log",
        "config": {
            "http_endpoint": "http://elasticsearch:9200/kong-logs/_doc",
            "method": "POST",
            "content_type": "application/json",
            "timeout": 10000,
            "keepalive": 60000,
            "flush_timeout": 2,
            "retry_count": 3
        },
        "enabled": false
    }'

# File Log for debugging
curl -s -X POST "$KONG_ADMIN_URL/plugins" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "file-log",
        "config": {
            "path": "/tmp/kong-access.log",
            "reopen": true
        }
    }'

# ============================================
# Create Consumer for Services
# ============================================
echo "Creating consumers..."

# Create JWT consumer for Keycloak
curl -s -X POST "$KONG_ADMIN_URL/consumers" \
    -H "Content-Type: application/json" \
    -d '{
        "username": "keycloak-jwt",
        "custom_id": "keycloak-identity-provider"
    }'

# Add JWT credential (using Keycloak's public key)
# Note: In production, this should be fetched from Keycloak's JWKS endpoint
curl -s -X POST "$KONG_ADMIN_URL/consumers/keycloak-jwt/jwt" \
    -H "Content-Type: application/json" \
    -d '{
        "key": "http://keycloak:8080/realms/zero-trust",
        "algorithm": "RS256"
    }'

# Add ACL group to consumer
curl -s -X POST "$KONG_ADMIN_URL/consumers/keycloak-jwt/acls" \
    -H "Content-Type: application/json" \
    -d '{"group": "admin"}'

curl -s -X POST "$KONG_ADMIN_URL/consumers/keycloak-jwt/acls" \
    -H "Content-Type: application/json" \
    -d '{"group": "developer"}'

echo ""
echo "=== Kong Configuration Complete ==="
echo ""
echo "API Gateway Endpoints:"
echo "  Proxy: http://localhost:8000"
echo "  Admin: http://localhost:8001"
echo "  Proxy SSL: https://localhost:8443"
echo ""
echo "Available Routes:"
echo "  Public:    POST /auth/login, /auth/register"
echo "  Protected: GET /auth/profile, /api/v1/*"
echo "  Health:    GET /health/auth, /health/backend"
