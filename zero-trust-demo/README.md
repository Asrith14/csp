# Zero-Trust Security Architecture Demo

> **Infrastructure as Code**: The cloud infrastructure (`/infrastructure`) is built with **AWS CDK (TypeScript)**, not Terraform.
> The Docker stack in this directory demonstrates the same Zero-Trust principles locally.

A comprehensive demonstration of Zero-Trust Security principles, running entirely in Docker.

## 🎯 Overview

This project implements a complete Zero-Trust architecture with:

- **Identity Provider (Keycloak)** - OIDC/OAuth2 authentication with MFA support
- **Secrets Management (HashiCorp Vault)** - Centralized secrets, PKI, and encryption
- **API Gateway (Kong)** - Rate limiting, JWT validation, and traffic management
- **Policy Engine (OPA)** - Fine-grained RBAC and ABAC authorization
- **Microservices** - Sample services demonstrating secure patterns
- **Monitoring (Prometheus/Grafana)** - Security metrics and alerting
- **Logging (ELK Stack)** - Centralized security event logging

## 🏗️ Architecture

```
                    ┌─────────────────────────────────────────┐
                    │              DMZ Network                 │
                    │         (172.20.0.0/24)                 │
    ┌───────────────┼─────────────────────────────────────────┼───────────────┐
    │               │                                         │               │
    │  ┌────────┐   │   ┌──────────┐      ┌──────────┐       │               │
    │  │Frontend│───┼──▶│   Kong   │─────▶│ Keycloak │       │               │
    │  │ :3000  │   │   │   :8000  │      │  :8080   │       │               │
    │  └────────┘   │   └────┬─────┘      └──────────┘       │               │
    │               │        │                                │               │
    └───────────────┼────────┼────────────────────────────────┼───────────────┘
                    │        │                                │
                    │        ▼                                │
    ┌───────────────┼─────────────────────────────────────────┼───────────────┐
    │               │   Internal Network                      │               │
    │               │   (172.21.0.0/24)                       │               │
    │               │                                         │               │
    │   ┌───────────┴───────────┐     ┌──────────────┐       │               │
    │   │                       │     │              │       │               │
    │   ▼                       ▼     ▼              │       │               │
    │ ┌──────────┐      ┌──────────┐ ┌─────┐  ┌─────┴─┐     │               │
    │ │  Auth    │◀────▶│ Backend  │ │ OPA │  │ Vault │     │               │
    │ │ Service  │      │ Service  │ │:8181│  │ :8200 │     │               │
    │ │  :3000   │      │  :3001   │ └─────┘  └───────┘     │               │
    │ └──────────┘      └────┬─────┘                         │               │
    │                        │                               │               │
    └────────────────────────┼───────────────────────────────┼───────────────┘
                             │                               │
                             ▼                               │
    ┌────────────────────────────────────────────────────────┼───────────────┐
    │                   Data Network                         │               │
    │                 (172.23.0.0/24)                        │               │
    │                                                        │               │
    │   ┌──────────────┐  ┌──────────────┐  ┌─────────────┐ │               │
    │   │  PostgreSQL  │  │  PostgreSQL  │  │ PostgreSQL  │ │               │
    │   │   (App DB)   │  │  (Keycloak)  │  │   (Kong)    │ │               │
    │   └──────────────┘  └──────────────┘  └─────────────┘ │               │
    │                                                        │               │
    └────────────────────────────────────────────────────────┴───────────────┘
```

## 🚀 Quick Start

### Prerequisites

- Docker Desktop (Windows/Mac) or Docker Engine (Linux)
- Docker Compose v2.0+
- 8GB+ RAM available for Docker
- Ports available: 3000, 3001, 5601, 8000, 8001, 8080, 8181, 8200, 9000, 9090, 9200

### Installation

**Windows (PowerShell):**
```powershell
cd zero-trust-demo
.\scripts\setup.ps1
```

**Linux/Mac:**
```bash
cd zero-trust-demo
chmod +x scripts/setup.sh
./scripts/setup.sh
```

**Manual Start:**
```bash
docker compose up -d
```

### Access Services

| Service | URL | Credentials |
|---------|-----|-------------|
| **Frontend Dashboard** | http://localhost:3000 | — |
| **Keycloak Admin** | http://localhost:8080/admin | Set via `KEYCLOAK_ADMIN_PASSWORD` in `.env` |
| **Vault UI** | http://localhost:8200 | Token from `VAULT_DEV_ROOT_TOKEN` in `.env` |
| **Kong Admin** | http://localhost:8001 | — |
| **API Gateway** | http://localhost:8000 | — |
| **Grafana** | http://localhost:3001 | admin / set via `GF_SECURITY_ADMIN_PASSWORD` in `.env` |
| **Prometheus** | http://localhost:9090 | — |
| **Kibana** | http://localhost:5601 | — |

### Test Users

Login at the Frontend Dashboard (http://localhost:3000) with:

| Username | Password | Role | Access Level |
|----------|----------|------|--------------|
| admin | Admin@123456 | Administrator | Full access to all APIs |
| developer | Dev@123456 | Developer | Read/write to most APIs |
| viewer | View@123456 | Viewer | Read-only access |

## 🔐 Zero-Trust Principles Demonstrated

### 1. Never Trust, Always Verify
- Every API request requires JWT authentication
- Tokens are validated against Keycloak's JWKS endpoint
- Short token lifetimes (5 minutes) with refresh capability

### 2. Least Privilege Access
- Role-Based Access Control (RBAC) via Keycloak roles
- Attribute-Based Access Control (ABAC) via OPA policies
- Field-level data masking for sensitive information

### 3. Micro-Segmentation
- Isolated Docker networks (DMZ, Internal, Data, Monitoring)
- Services can only communicate with authorized peers
- Database network is completely internal

### 4. Continuous Monitoring
- Prometheus metrics for all services
- Security-specific alerts (brute force, policy denials)
- Centralized logging to Elasticsearch

### 5. Encrypt Everything
- mTLS configuration ready (Step CA included)
- Vault manages all secrets centrally
- No hardcoded credentials in application code

## 📁 Project Structure

```
zero-trust-demo/
├── docker-compose.yml          # Main infrastructure definition
├── api-gateway/
│   └── kong-config.sh          # Kong routes and plugins
├── identity/
│   └── realm-config/
│       └── zero-trust-realm.json  # Keycloak realm with users/clients
├── secrets/
│   ├── vault-config/
│   │   └── vault-init.sh       # Vault initialization script
│   └── policies/
│       ├── admin-policy.hcl    # Vault admin policy
│       ├── app-policy.hcl      # Application policy
│       └── service-policy.hcl  # Service-to-service policy
├── policy-engine/
│   └── policies/
│       ├── authz.rego          # Authorization policy
│       ├── network.rego        # Network segmentation policy
│       └── data.rego           # Data access policy
├── services/
│   ├── auth-service/           # Authentication microservice
│   ├── backend-service/        # Backend API microservice
│   └── frontend/               # Web dashboard
├── monitoring/
│   ├── prometheus/
│   │   ├── prometheus.yml      # Prometheus configuration
│   │   └── rules/
│   │       └── alerts.yml      # Security alerts
│   └── grafana/
│       ├── provisioning/       # Datasources and dashboards
│       └── dashboards/
│           └── zero-trust-overview.json
├── scripts/
│   ├── setup.ps1               # Windows setup script
│   ├── setup.sh                # Linux/Mac setup script
│   ├── stop.ps1                # Stop all services
│   └── cleanup.ps1             # Remove all data
└── certs/                      # Certificate storage
```

## 🧪 Testing the Architecture

### 1. Test Authentication Flow

```bash
# Get access token
curl -X POST http://localhost:8080/realms/zero-trust/protocol/openid-connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "client_id=frontend-app" \
  -d "username=admin" \
  -d "password=Admin@123456" \
  -d "scope=openid profile email roles"
```

### 2. Test API with Authorization

```bash
# Replace TOKEN with the access_token from above
curl http://localhost:8000/api/v1/users \
  -H "Authorization: Bearer TOKEN"
```

### 3. Test Policy Denial

```bash
# Login as viewer and try to access admin endpoint
# This should return 403 Forbidden
curl http://localhost:8000/api/v1/config \
  -H "Authorization: Bearer VIEWER_TOKEN"
```

### 4. Test OPA Policy Directly

```bash
curl -X POST http://localhost:8181/v1/data/zerotrust/authz/allow \
  -H "Content-Type: application/json" \
  -d '{
    "input": {
      "user": {"id": "test", "roles": ["viewer"]},
      "resource": {"path": "/api/v1/users", "method": "GET"},
      "context": {}
    }
  }'
```

## 📊 Monitoring & Observability

### Grafana Dashboards

1. Open Grafana at http://localhost:3001
2. Login with admin/admin
3. Navigate to Dashboards → Zero Trust
4. View the "Zero-Trust Security Overview" dashboard

### Key Metrics

- `auth_attempts_total` - Authentication attempts (success/failure)
- `policy_decisions_total` - OPA policy decisions (allow/deny)
- `http_request_duration_seconds` - API latency

### Security Alerts

Configured alerts in Prometheus:
- High authentication failure rate
- Possible brute force attack
- High policy denials
- Service down

## 🛑 Stopping the Demo

**Stop services (keep data):**
```powershell
.\scripts\stop.ps1
```

**Remove everything (delete all data):**
```powershell
.\scripts\cleanup.ps1
```

## 🔧 Customization

### Adding New Users

1. Open Keycloak Admin (http://localhost:8080/admin)
2. Select "zero-trust" realm
3. Go to Users → Add user
4. Assign roles under Role Mappings

### Modifying Policies

Edit files in `policy-engine/policies/` and restart OPA:
```bash
docker compose restart opa
```

### Adding New API Endpoints

1. Add route in `services/backend-service/src/index.js`
2. Update Kong configuration in `api-gateway/kong-config.sh`
3. Add policy rules in `policy-engine/policies/authz.rego`

## 📚 Additional Resources

- [NIST Zero Trust Architecture](https://www.nist.gov/publications/zero-trust-architecture)
- [Keycloak Documentation](https://www.keycloak.org/documentation)
- [HashiCorp Vault](https://www.vaultproject.io/docs)
- [Open Policy Agent](https://www.openpolicyagent.org/docs/latest/)
- [Kong Gateway](https://docs.konghq.com/)

## ⚠️ Production Considerations

This demo is for **learning purposes**. For production:

1. **Never use dev mode** - Vault and Keycloak are in dev mode
2. **Use proper secrets** - Replace all hardcoded passwords
3. **Enable TLS everywhere** - Configure real certificates
4. **High Availability** - Deploy multiple replicas
5. **Network security** - Use proper firewall rules
6. **Regular updates** - Keep all components updated
7. **Backup** - Implement backup strategies for all data

## 📄 License

MIT License - Feel free to use and modify for your projects.
