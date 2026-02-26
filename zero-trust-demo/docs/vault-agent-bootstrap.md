# Vault Agent Bootstrap (Issue E)

## The Problem

Injecting secrets as plain environment variables (`POSTGRES_PASSWORD=${VAR}`)
risks leaking credentials into crash dumps, container inspect output, and
process environment listings (`/proc/self/environ`).

## The Solution: Vault Agent

In production, each service authenticates to Vault using Kubernetes Auth (or
AppRole for Docker environments) and fetches credentials dynamically. The
pattern used here demonstrates AppRole-based bootstrap.

## Docker Compose Bootstrap Flow

```
docker compose up
    │
    ├─▶ vault (starts in dev mode with VAULT_DEV_ROOT_TOKEN)
    │
    ├─▶ vault-init (one-shot init container):
    │       1. Enables the AppRole auth backend
    │       2. Creates a policy granting read on secret/data/apps/*
    │       3. Creates a role for backend-service
    │       4. Writes role-id + secret-id to a shared Docker volume
    │
    └─▶ backend-service:
            1. Reads role-id and secret-id from the shared volume
            2. Calls POST /v1/auth/approle/login → gets a short-lived token
            3. Calls GET /v1/secret/data/apps/db-credentials
            4. Uses the returned username/password to build DATABASE_URL
            5. Vault token expires; next request re-authenticates
```

## Kubernetes Equivalent

```yaml
spec:
  initContainers:
    - name: vault-agent
      image: hashicorp/vault:1.15
      command:
        - vault
        - agent
        - -config=/vault/config/agent.hcl
      volumeMounts:
        - name: vault-config
          mountPath: /vault/config
        - name: secrets-volume
          mountPath: /vault/secrets
  containers:
    - name: backend-service
      env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: db-credentials   # written by vault-agent init
              key: url
```

## Current Status

For this local demo, credentials are injected via `.env` (gitignored).
The architecture document and Kubernetes manifests (Day 8) will use
Vault Agent / Kubernetes Auth for true dynamic secret injection.
