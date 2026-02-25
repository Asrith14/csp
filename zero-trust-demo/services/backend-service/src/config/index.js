'use strict';

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
        url: process.env.OPA_URL || 'http://opa:8181',
    },
    database: {
        // Never fall back to hardcoded credentials — fail loudly if not set.
        url: process.env.DATABASE_URL,
        pool: {
            max: 10,
            idleTimeoutMillis: 30000,
            connectionTimeoutMillis: 2000,
        },
    },
    serviceName: process.env.SERVICE_NAME || 'backend-service',
};

// Guard: refuse to start if critical secrets are missing.
if (!config.vault.token) {
    console.error('FATAL: VAULT_TOKEN environment variable is not set.');
    process.exit(1);
}
if (!config.database.url) {
    console.error('FATAL: DATABASE_URL environment variable is not set.');
    process.exit(1);
}

module.exports = config;
