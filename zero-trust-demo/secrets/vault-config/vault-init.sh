#!/bin/bash
# Vault Initialization Script for Zero-Trust Architecture
# This script configures Vault with secrets, policies, and authentication methods

set -e

VAULT_ADDR=${VAULT_ADDR:-"http://127.0.0.1:8200"}
VAULT_TOKEN=${VAULT_TOKEN:-"root-token-zero-trust"}

export VAULT_ADDR
export VAULT_TOKEN

echo "=== Zero-Trust Vault Configuration ==="
echo "Vault Address: $VAULT_ADDR"

# Wait for Vault to be ready
echo "Waiting for Vault to be ready..."
until vault status > /dev/null 2>&1; do
    sleep 2
done
echo "Vault is ready!"

# Enable secrets engines
echo "Enabling secrets engines..."

# KV v2 for static secrets
vault secrets enable -path=secret kv-v2 2>/dev/null || echo "KV engine already enabled"

# PKI for certificate management
vault secrets enable pki 2>/dev/null || echo "PKI engine already enabled"
vault secrets tune -max-lease-ttl=87600h pki

# Transit for encryption as a service
vault secrets enable transit 2>/dev/null || echo "Transit engine already enabled"

# Database for dynamic credentials
vault secrets enable database 2>/dev/null || echo "Database engine already enabled"

# Configure PKI
echo "Configuring PKI..."
vault write pki/root/generate/internal \
    common_name="Zero-Trust Root CA" \
    ttl=87600h \
    key_bits=4096 2>/dev/null || echo "Root CA already exists"

vault write pki/config/urls \
    issuing_certificates="$VAULT_ADDR/v1/pki/ca" \
    crl_distribution_points="$VAULT_ADDR/v1/pki/crl"

# Create PKI roles for services
vault write pki/roles/service-cert \
    allowed_domains="zerotrust.local,localhost" \
    allow_subdomains=true \
    allow_localhost=true \
    max_ttl=72h \
    require_cn=false \
    generate_lease=true

vault write pki/roles/app-cert \
    allowed_domains="zerotrust.local,localhost" \
    allow_subdomains=true \
    max_ttl=24h

# Configure Transit encryption key
echo "Configuring Transit encryption..."
vault write -f transit/keys/service-key type=aes256-gcm96

# Create policies
echo "Creating policies..."
vault policy write admin /vault/policies/admin-policy.hcl 2>/dev/null || echo "Admin policy exists"
vault policy write app /vault/policies/app-policy.hcl 2>/dev/null || echo "App policy exists"
vault policy write service /vault/policies/service-policy.hcl 2>/dev/null || echo "Service policy exists"

# Store application secrets
echo "Storing application secrets..."
vault kv put secret/apps/database \
    host="postgres-app" \
    port="5432" \
    username="app" \
    password="app_secret" \
    database="appdb"

vault kv put secret/apps/api-keys \
    internal_api_key="zt-internal-key-2024-$(openssl rand -hex 16)" \
    external_api_key="zt-external-key-2024-$(openssl rand -hex 16)"

vault kv put secret/services/auth-service \
    keycloak_client_id="auth-service" \
    keycloak_client_secret="auth-service-secret-2024" \
    jwt_secret="$(openssl rand -base64 32)"

vault kv put secret/services/backend-service \
    keycloak_client_id="backend-service" \
    keycloak_client_secret="backend-service-secret-2024" \
    encryption_key="$(openssl rand -base64 32)"

# Enable authentication methods
echo "Enabling authentication methods..."

# AppRole for services
vault auth enable approle 2>/dev/null || echo "AppRole already enabled"

# Create AppRole for auth-service
vault write auth/approle/role/auth-service \
    token_policies="service" \
    token_ttl=1h \
    token_max_ttl=4h \
    secret_id_ttl=24h \
    secret_id_num_uses=0

# Create AppRole for backend-service
vault write auth/approle/role/backend-service \
    token_policies="service" \
    token_ttl=1h \
    token_max_ttl=4h \
    secret_id_ttl=24h \
    secret_id_num_uses=0

# Get Role IDs and Secret IDs
echo "Generating AppRole credentials..."
AUTH_SERVICE_ROLE_ID=$(vault read -field=role_id auth/approle/role/auth-service/role-id)
AUTH_SERVICE_SECRET_ID=$(vault write -f -field=secret_id auth/approle/role/auth-service/secret-id)

BACKEND_SERVICE_ROLE_ID=$(vault read -field=role_id auth/approle/role/backend-service/role-id)
BACKEND_SERVICE_SECRET_ID=$(vault write -f -field=secret_id auth/approle/role/backend-service/secret-id)

# Store role IDs for reference
vault kv put secret/approle/auth-service \
    role_id="$AUTH_SERVICE_ROLE_ID" \
    secret_id="$AUTH_SERVICE_SECRET_ID"

vault kv put secret/approle/backend-service \
    role_id="$BACKEND_SERVICE_ROLE_ID" \
    secret_id="$BACKEND_SERVICE_SECRET_ID"

# Enable audit logging
echo "Enabling audit logging..."
vault audit enable file file_path=/vault/logs/audit.log 2>/dev/null || echo "Audit logging already enabled"

echo ""
echo "=== Vault Configuration Complete ==="
echo ""
echo "Service Credentials:"
echo "  Auth Service Role ID: $AUTH_SERVICE_ROLE_ID"
echo "  Backend Service Role ID: $BACKEND_SERVICE_ROLE_ID"
echo ""
echo "Access Vault UI at: $VAULT_ADDR"
echo "Root Token: $VAULT_TOKEN (for development only!)"
