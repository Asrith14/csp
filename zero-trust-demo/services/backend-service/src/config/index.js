'use strict';

// Non-secret, non-sensitive config only.
// Database credentials are NOT sourced from environment variables.
// They are fetched from Vault at bootstrap time and passed to initDb().
const config = {
    port: parseInt(process.env.PORT || '3001', 10),
    keycloak: {
        url: process.env.KEYCLOAK_URL || 'http://keycloak:8080',
        realm: 'zero-trust',
    },
    vault: {
        addr: process.env.VAULT_ADDR || 'http://vault:8200',
        // Never fall back to a hardcoded token — fail loudly if not set.
        token: process.env.VAULT_TOKEN,
    },
    opa: {
        // OPA runs as a sidecar — localhost call, sub-millisecond authz.
        url: process.env.OPA_URL || 'http://localhost:8181',
    },
    database: {
        host: process.env.DB_HOST || 'postgres-app',
        port: parseInt(process.env.DB_PORT || '5432', 10),
        name: process.env.DB_NAME || 'appdb',
        user: process.env.DB_USER || 'app',
        // password is fetched from Vault — never injected as an env var.
    },
    serviceName: process.env.SERVICE_NAME || 'backend-service',
};

// Guard: refuse to start if Vault bootstrap cannot proceed.
if (!config.vault.token) {
    console.error('FATAL: VAULT_TOKEN environment variable is not set.');
    process.exit(1);
}

module.exports = config;
