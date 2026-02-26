#!/bin/sh
# vault-init.sh — Seeds all secrets required by backend-service and auth-service.
# Runs as a one-shot init container AFTER vault is healthy and BEFORE services start.
# Uses Vault's HTTP API directly (no vault CLI needed — just wget which is in alpine).

set -e

VAULT_ADDR="${VAULT_ADDR:-http://vault:8200}"
VAULT_TOKEN="${VAULT_DEV_ROOT_TOKEN:-root}"

echo "=== Vault Init: seeding secrets ==="
echo "Vault: $VAULT_ADDR"

# Wait for Vault to be ready
until wget -qO- "$VAULT_ADDR/v1/sys/health" > /dev/null 2>&1; do
  echo "Waiting for Vault..."
  sleep 2
done
echo "Vault is ready."

# Enable KV v2 secrets engine (idempotent — ignore 400 if already enabled)
wget -qO- --header="X-Vault-Token: $VAULT_TOKEN" \
  --header="Content-Type: application/json" \
  --post-data='{"type":"kv","options":{"version":"2"}}' \
  "$VAULT_ADDR/v1/sys/mounts/secret" > /dev/null 2>&1 || true

echo "KV engine ready."

# ── auth-service secrets ────────────────────────────────────────────────────
# keycloak_client_secret: the OAuth2 client secret for the auth-service client
# in Keycloak. In dev mode we use a known value; in production this would be
# rotated and fetched from Keycloak's admin API.
wget -qO- \
  --header="X-Vault-Token: $VAULT_TOKEN" \
  --header="Content-Type: application/json" \
  --method=POST \
  --body-data='{"data":{"keycloak_client_secret":"auth-service-dev-secret"}}' \
  "$VAULT_ADDR/v1/secret/data/apps/auth-service" > /dev/null

echo "✓ apps/auth-service seeded"

# ── backend-service secrets ─────────────────────────────────────────────────
# db_password: must match POSTGRES_APP_PASSWORD in docker-compose.yml
# We read it from the environment so it stays consistent.
DB_PASSWORD="${POSTGRES_APP_PASSWORD:-ZeroTrust@Demo2024}"

wget -qO- \
  --header="X-Vault-Token: $VAULT_TOKEN" \
  --header="Content-Type: application/json" \
  --method=POST \
  --body-data="{\"data\":{\"db_password\":\"$DB_PASSWORD\"}}" \
  "$VAULT_ADDR/v1/secret/data/apps/backend-service" > /dev/null

echo "✓ apps/backend-service seeded"

# ── api-keys (used by admin route in backend-service) ──────────────────────
wget -qO- \
  --header="X-Vault-Token: $VAULT_TOKEN" \
  --header="Content-Type: application/json" \
  --method=POST \
  --body-data='{"data":{"stripe_key":"demo-stripe-key","sendgrid_key":"demo-sendgrid-key"}}' \
  "$VAULT_ADDR/v1/secret/data/apps/api-keys" > /dev/null

echo "✓ apps/api-keys seeded"

echo ""
echo "=== Vault Init Complete ==="
echo "Secrets written:"
echo "  secret/data/apps/auth-service    (keycloak_client_secret)"
echo "  secret/data/apps/backend-service (db_password)"
echo "  secret/data/apps/api-keys        (stripe_key, sendgrid_key)"
