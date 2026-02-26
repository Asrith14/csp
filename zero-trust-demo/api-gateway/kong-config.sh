#!/bin/bash
# Kong API Gateway — Declarative/Idempotent Configuration
# Fixed: JWKS → PEM extraction uses openssl + jq (available in Kong alpine image)
# All writes use PUT for idempotency.

set -euo pipefail

KONG_ADMIN_URL=${KONG_ADMIN_URL:-"http://localhost:8001"}
KEYCLOAK_URL=${KEYCLOAK_URL:-"http://keycloak:8080"}
KEYCLOAK_REALM=${KEYCLOAK_REALM:-"zero-trust"}

echo "=== Kong Zero-Trust Configuration ==="

# ── Wait for Kong ──────────────────────────────────────────────────────────
echo "Waiting for Kong..."
until curl -sf "$KONG_ADMIN_URL/status" > /dev/null 2>&1; do sleep 2; done
echo "Kong ready."

# ── Wait for Keycloak ──────────────────────────────────────────────────────
JWKS_URL="$KEYCLOAK_URL/realms/$KEYCLOAK_REALM/protocol/openid-connect/certs"
echo "Waiting for Keycloak JWKS..."
until curl -sf "$JWKS_URL" > /dev/null 2>&1; do sleep 3; done
echo "Keycloak ready."

# ── Extract RS256 public key using jq + openssl ────────────────────────────
# Kong OSS jwt plugin needs the actual RSA PEM bytes, not a URL.
# 1. Fetch JWKS, pick the RS256 key, extract n and e (base64url-encoded modulus/exponent)
# 2. Decode them and write a minimal DER-encoded RSA public key
# 3. Convert DER to PEM with openssl

echo "Extracting Keycloak RS256 public key..."

JWKS=$(curl -sf "$JWKS_URL")
# Get the x5c certificate chain (base64 DER) for the RS256 key — simplest extraction path
X5C=$(echo "$JWKS" | jq -r '[.keys[] | select(.use=="sig" or .alg=="RS256")] | first | .x5c[0] // empty')

if [ -n "$X5C" ]; then
  # x5c is a base64-encoded DER certificate — extract public key directly
  KEYCLOAK_PUBLIC_KEY_PEM=$(echo "$X5C" | base64 -d | openssl x509 -inform DER -pubkey -noout 2>/dev/null)
fi

# Fallback: if no x5c, build from n+e modulus/exponent via openssl
if [ -z "${KEYCLOAK_PUBLIC_KEY_PEM:-}" ]; then
  N=$(echo "$JWKS" | jq -r '[.keys[] | select(.use=="sig" or .alg=="RS256")] | first | .n')
  E=$(echo "$JWKS" | jq -r '[.keys[] | select(.use=="sig" or .alg=="RS256")] | first | .e')

  # Write a minimal RSA public key structure using openssl asn1parse trick
  # Pad base64url to standard base64 and decode
  N_HEX=$(echo "$N==" | tr '_-' '/+' | base64 -d | xxd -p | tr -d '\n')
  E_HEX=$(echo "$E==" | tr '_-' '/+' | base64 -d | xxd -p | tr -d '\n')

  # Use openssl to construct PEM from hex-encoded n and e
  KEYCLOAK_PUBLIC_KEY_PEM=$(openssl asn1parse -genconf <(
    printf "[default]\nasn1=SEQUENCE:pubkeyinfo\n\n[pubkeyinfo]\nalgorithm=SEQUENCE:rsa_alg\npubKey=BITWRAP,SEQUENCE:rsapubkey\n\n[rsa_alg]\nalgorithm=OID:rsaEncryption\nparameter=NULL\n\n[rsapubkey]\nn=INTEGER:0x%s\ne=INTEGER:0x%s\n" "$N_HEX" "$E_HEX"
  ) -noout -out /tmp/pubkey.der 2>/dev/null && openssl rsa -pubin -inform DER -in /tmp/pubkey.der -outform PEM 2>/dev/null || echo "")
fi

if [ -z "${KEYCLOAK_PUBLIC_KEY_PEM:-}" ]; then
  echo "WARNING: Could not extract public key. Kong JWT verification will not work until Keycloak has issued a key."
  echo "Re-run this script after Keycloak has fully initialised."
  KEYCLOAK_PUBLIC_KEY_PEM="placeholder-rerun-kong-config-after-keycloak-init"
fi

echo "Public key extracted (${#KEYCLOAK_PUBLIC_KEY_PEM} chars)."

# ── Helper: idempotent PUT ─────────────────────────────────────────────────
put() {
  local url="$1" data="$2"
  curl -sf -X PUT "$url" -H "Content-Type: application/json" -d "$data" > /dev/null
}

# ── Services ───────────────────────────────────────────────────────────────
echo "Upserting services..."
put "$KONG_ADMIN_URL/services/auth-service" \
  '{"name":"auth-service","url":"http://auth-service:3000","retries":3}'
put "$KONG_ADMIN_URL/services/backend-service" \
  '{"name":"backend-service","url":"http://backend-service:3001","retries":3}'

# ── Routes ─────────────────────────────────────────────────────────────────
echo "Upserting routes..."
put "$KONG_ADMIN_URL/routes/auth-public" \
  '{"name":"auth-public","service":{"name":"auth-service"},"paths":["/auth/login","/auth/register","/auth/refresh"],"methods":["POST"],"strip_path":false}'
put "$KONG_ADMIN_URL/routes/auth-protected" \
  '{"name":"auth-protected","service":{"name":"auth-service"},"paths":["/auth/profile","/auth/logout","/auth/validate"],"methods":["GET","POST"],"strip_path":false}'
put "$KONG_ADMIN_URL/routes/api-v1" \
  '{"name":"api-v1","service":{"name":"backend-service"},"paths":["/api/v1"],"strip_path":false}'
put "$KONG_ADMIN_URL/routes/health-auth" \
  '{"name":"health-auth","service":{"name":"auth-service"},"paths":["/health/auth"],"methods":["GET"],"strip_path":true}'
put "$KONG_ADMIN_URL/routes/health-backend" \
  '{"name":"health-backend","service":{"name":"backend-service"},"paths":["/health/backend"],"methods":["GET"],"strip_path":true}'

# ── Global plugins ─────────────────────────────────────────────────────────
echo "Upserting plugins..."
put "$KONG_ADMIN_URL/plugins/rate-limiting-global" \
  '{"name":"rate-limiting","config":{"minute":100,"hour":1000,"policy":"local","fault_tolerant":true}}'
put "$KONG_ADMIN_URL/plugins/cors-global" \
  '{"name":"cors","config":{"origins":["http://localhost:3000"],"methods":["GET","POST","PUT","DELETE","PATCH","OPTIONS"],"headers":["Authorization","Content-Type","X-Request-ID"],"credentials":true,"max_age":3600}}'
put "$KONG_ADMIN_URL/plugins/correlation-id-global" \
  '{"name":"correlation-id","config":{"header_name":"X-Request-ID","generator":"uuid","echo_downstream":true}}'
put "$KONG_ADMIN_URL/plugins/response-transformer-global" \
  '{"name":"response-transformer","config":{"add":{"headers":["X-Content-Type-Options:nosniff","X-Frame-Options:DENY"]}}}'
put "$KONG_ADMIN_URL/plugins/file-log-global" \
  '{"name":"file-log","config":{"path":"/tmp/kong-access.log","reopen":true}}'

# ── JWT on protected routes ────────────────────────────────────────────────
put "$KONG_ADMIN_URL/routes/auth-protected/plugins/jwt-auth-protected" \
  '{"name":"jwt","config":{"claims_to_verify":["exp"],"key_claim_name":"iss","secret_is_base64":false}}'
put "$KONG_ADMIN_URL/routes/api-v1/plugins/jwt-api-v1" \
  '{"name":"jwt","config":{"claims_to_verify":["exp"],"key_claim_name":"iss","secret_is_base64":false}}'

# ── Consumer + JWT credential with real PEM ────────────────────────────────
echo "Registering JWT consumer..."
put "$KONG_ADMIN_URL/consumers/keycloak-jwt" \
  '{"username":"keycloak-jwt","custom_id":"keycloak-identity-provider"}'

# Delete stale credential if exists, then re-create with current key
EXISTING=$(curl -sf "$KONG_ADMIN_URL/consumers/keycloak-jwt/jwt" | jq -r '.data[0].id // empty' 2>/dev/null || true)
[ -n "$EXISTING" ] && curl -sf -X DELETE "$KONG_ADMIN_URL/consumers/keycloak-jwt/jwt/$EXISTING" > /dev/null || true

curl -sf -X POST "$KONG_ADMIN_URL/consumers/keycloak-jwt/jwt" \
  -H "Content-Type: application/json" \
  -d "{\"key\":\"$KEYCLOAK_URL/realms/$KEYCLOAK_REALM\",\"algorithm\":\"RS256\",\"rsa_public_key\":$(echo "$KEYCLOAK_PUBLIC_KEY_PEM" | jq -Rs .)}" > /dev/null

echo "JWT consumer registered."

echo ""
echo "=== Kong Configuration Complete ==="
echo "Proxy: http://localhost:8000 | Admin: http://localhost:8001"
