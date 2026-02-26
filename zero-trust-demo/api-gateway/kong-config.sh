#!/bin/bash
# Kong API Gateway — Declarative/Idempotent Configuration
#
# Every write uses PUT with an explicit name/ID so this script is fully
# idempotent (safe to re-run on restarts without creating duplicates or
# 409 Conflict errors).
#
# Issue D fix: After Kong and Keycloak are both ready, this script fetches
# the Keycloak RS256 public key from the JWKS endpoint, converts it to PEM
# via openssl, and injects the actual key bytes into Kong's JWT consumer.
# Kong Open Source's native jwt plugin requires the raw PEM in rsa_public_key;
# it cannot resolve a URL itself.

set -euo pipefail

KONG_ADMIN_URL=${KONG_ADMIN_URL:-"http://localhost:8001"}
KEYCLOAK_URL=${KEYCLOAK_URL:-"http://keycloak:8080"}
KEYCLOAK_REALM=${KEYCLOAK_REALM:-"zero-trust"}

echo "=== Kong API Gateway Zero-Trust Configuration (idempotent) ==="
echo "Kong Admin URL: $KONG_ADMIN_URL"

# ── Wait for Kong ──────────────────────────────────────────────────────────
echo "Waiting for Kong..."
until curl -sf "$KONG_ADMIN_URL/status" > /dev/null 2>&1; do sleep 2; done
echo "Kong is ready."

# ── Wait for Keycloak JWKS endpoint ───────────────────────────────────────
echo "Waiting for Keycloak JWKS endpoint..."
JWKS_URL="$KEYCLOAK_URL/realms/$KEYCLOAK_REALM/protocol/openid-connect/certs"
until curl -sf "$JWKS_URL" > /dev/null 2>&1; do sleep 3; done
echo "Keycloak is ready."

# ── Extract RS256 public key from JWKS and convert to PEM ─────────────────
# 1. Fetch the JWKS JSON.
# 2. Extract the first n and e values for the RS256 key using python3
#    (available in the alpine-based Kong image).
# 3. Construct an RSA public key from n/e and write it as PEM.
#
# This is the only approach that works with Kong OSS native jwt plugin.

echo "Extracting Keycloak public key..."

JWKS_JSON=$(curl -sf "$JWKS_URL")

# Use python3 to decode the JWK and emit a PEM — available in kong:alpine
KEYCLOAK_PUBLIC_KEY_PEM=$(echo "$JWKS_JSON" | python3 - << 'PYEOF'
import sys, json, base64, struct
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers

data = json.load(sys.stdin)
# Pick the first RS256 key
key = next(k for k in data['keys'] if k.get('alg','') == 'RS256' or k.get('kty','') == 'RSA')

def b64_to_int(b64):
    padded = b64 + '=' * (-len(b64) % 4)
    return int.from_bytes(base64.urlsafe_b64decode(padded), 'big')

n = b64_to_int(key['n'])
e = b64_to_int(key['e'])

pub = RSAPublicNumbers(e, n).public_key()
pem = pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
print(pem.decode(), end='')
PYEOF
)

if [ -z "$KEYCLOAK_PUBLIC_KEY_PEM" ]; then
  echo "ERROR: Failed to extract public key from Keycloak JWKS. Aborting."
  exit 1
fi
echo "Public key extracted successfully."

# ── Helper: idempotent PUT (upsert by name) ────────────────────────────────
put() {
  local url="$1"
  local data="$2"
  # PUT to named routes/services/plugins is idempotent in Kong.
  curl -sf -X PUT "$url" \
    -H "Content-Type: application/json" \
    -d "$data" > /dev/null
}

# ── Services (idempotent PUT) ──────────────────────────────────────────────
echo "Upserting services..."

put "$KONG_ADMIN_URL/services/auth-service" '{
  "name": "auth-service",
  "url": "http://auth-service:3000",
  "connect_timeout": 60000,
  "read_timeout": 60000,
  "write_timeout": 60000,
  "retries": 3
}'

put "$KONG_ADMIN_URL/services/backend-service" '{
  "name": "backend-service",
  "url": "http://backend-service:3001",
  "connect_timeout": 60000,
  "read_timeout": 60000,
  "write_timeout": 60000,
  "retries": 3
}'

# ── Routes (idempotent PUT) ────────────────────────────────────────────────
echo "Upserting routes..."

put "$KONG_ADMIN_URL/routes/auth-public" '{
  "name": "auth-public",
  "service": {"name": "auth-service"},
  "paths": ["/auth/login", "/auth/register", "/auth/refresh"],
  "methods": ["POST"],
  "strip_path": false
}'

put "$KONG_ADMIN_URL/routes/auth-protected" '{
  "name": "auth-protected",
  "service": {"name": "auth-service"},
  "paths": ["/auth/profile", "/auth/logout", "/auth/validate"],
  "methods": ["GET", "POST"],
  "strip_path": false
}'

put "$KONG_ADMIN_URL/routes/api-v1" '{
  "name": "api-v1",
  "service": {"name": "backend-service"},
  "paths": ["/api/v1"],
  "strip_path": false
}'

put "$KONG_ADMIN_URL/routes/health-auth" '{
  "name": "health-auth",
  "service": {"name": "auth-service"},
  "paths": ["/health/auth"],
  "methods": ["GET"],
  "strip_path": true
}'

put "$KONG_ADMIN_URL/routes/health-backend" '{
  "name": "health-backend",
  "service": {"name": "backend-service"},
  "paths": ["/health/backend"],
  "methods": ["GET"],
  "strip_path": true
}'

# ── Global plugins ─────────────────────────────────────────────────────────
echo "Upserting global plugins..."

put "$KONG_ADMIN_URL/plugins/rate-limiting-global" '{
  "name": "rate-limiting",
  "config": {
    "minute": 100,
    "hour": 1000,
    "policy": "local",
    "fault_tolerant": true,
    "hide_client_headers": false
  }
}'

put "$KONG_ADMIN_URL/plugins/request-size-limiting-global" '{
  "name": "request-size-limiting",
  "config": {
    "allowed_payload_size": 10,
    "size_unit": "megabytes"
  }
}'

put "$KONG_ADMIN_URL/plugins/cors-global" '{
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

put "$KONG_ADMIN_URL/plugins/response-transformer-global" '{
  "name": "response-transformer",
  "config": {
    "add": {
      "headers": [
        "X-Content-Type-Options:nosniff",
        "X-Frame-Options:DENY",
        "X-XSS-Protection:1; mode=block",
        "Strict-Transport-Security:max-age=31536000; includeSubDomains"
      ]
    }
  }
}'

put "$KONG_ADMIN_URL/plugins/correlation-id-global" '{
  "name": "correlation-id",
  "config": {
    "header_name": "X-Request-ID",
    "generator": "uuid",
    "echo_downstream": true
  }
}'

# ── JWT plugins on protected routes ───────────────────────────────────────
echo "Upserting JWT plugins..."

put "$KONG_ADMIN_URL/routes/auth-protected/plugins/jwt-auth-protected" '{
  "name": "jwt",
  "config": {
    "claims_to_verify": ["exp"],
    "key_claim_name": "iss",
    "secret_is_base64": false,
    "run_on_preflight": true
  }
}'

put "$KONG_ADMIN_URL/routes/api-v1/plugins/jwt-api-v1" '{
  "name": "jwt",
  "config": {
    "claims_to_verify": ["exp"],
    "key_claim_name": "iss",
    "secret_is_base64": false,
    "run_on_preflight": true
  }
}'

# ── ACL on API routes ──────────────────────────────────────────────────────
put "$KONG_ADMIN_URL/routes/api-v1/plugins/acl-api-v1" '{
  "name": "acl",
  "config": {
    "allow": ["admin", "developer"],
    "hide_groups_header": false
  }
}'

# ── JWT consumer with ACTUAL RSA public key ────────────────────────────────
# Issue D fix: inject the real PEM, not a URL that Kong cannot resolve.
echo "Upserting JWT consumer..."

put "$KONG_ADMIN_URL/consumers/keycloak-jwt" '{
  "username": "keycloak-jwt",
  "custom_id": "keycloak-identity-provider"
}'

# The key value must match the `iss` claim in Keycloak JWTs.
# We delete any existing credential first, then recreate cleanly.
# (Kong does not support upsert on /consumers/:id/jwt by name.)
EXISTING_JWT_ID=$(curl -sf "$KONG_ADMIN_URL/consumers/keycloak-jwt/jwt" | \
  python3 -c "import sys,json; d=json.load(sys.stdin); print(d['data'][0]['id'] if d['data'] else '')" 2>/dev/null || true)

if [ -n "$EXISTING_JWT_ID" ]; then
  curl -sf -X DELETE "$KONG_ADMIN_URL/consumers/keycloak-jwt/jwt/$EXISTING_JWT_ID" > /dev/null
  echo "Removed stale JWT credential ($EXISTING_JWT_ID)."
fi

# Register the Keycloak issuer + real RSA public key PEM.
curl -sf -X POST "$KONG_ADMIN_URL/consumers/keycloak-jwt/jwt" \
  -H "Content-Type: application/json" \
  -d "{
    \"key\": \"$KEYCLOAK_URL/realms/$KEYCLOAK_REALM\",
    \"algorithm\": \"RS256\",
    \"rsa_public_key\": $(echo "$KEYCLOAK_PUBLIC_KEY_PEM" | python3 -c 'import sys,json; print(json.dumps(sys.stdin.read()))')
  }" > /dev/null
echo "JWT credential registered with RS256 public key."

# ── ACL groups for consumer ────────────────────────────────────────────────
for GROUP in admin developer; do
  # Idempotent: POST only adds if not present; ignore 409
  curl -sf -X POST "$KONG_ADMIN_URL/consumers/keycloak-jwt/acls" \
    -H "Content-Type: application/json" \
    -d "{\"group\": \"$GROUP\"}" > /dev/null || true
done

# ── Logging plugins (disabled by default) ─────────────────────────────────
put "$KONG_ADMIN_URL/plugins/file-log-global" '{
  "name": "file-log",
  "enabled": true,
  "config": {
    "path": "/tmp/kong-access.log",
    "reopen": true
  }
}'

echo ""
echo "=== Kong Configuration Complete ==="
echo ""
echo "API Gateway Endpoints:"
echo "  Proxy: http://localhost:8000"
echo "  Admin: http://localhost:8001"
echo ""
echo "Available Routes:"
echo "  Public:    POST /auth/login, /auth/register, /auth/refresh"
echo "  Protected: GET /auth/profile, /api/v1/*"
echo "  Health:    GET /health/auth, /health/backend"
