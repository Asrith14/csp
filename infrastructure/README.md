# Zero-Trust Security Architecture for Hybrid and Multi-Cloud Networks

AWS CDK (TypeScript) implementation of a Zero Trust security layer for cloud and hybrid network environments.

## Architecture

| Component | Technology | Purpose |
|-----------|-----------|---------|
| Identity | Amazon Cognito + TOTP MFA | Authentication & RBAC |
| Edge Protection | AWS WAF v2 | SQLi / XSS / Rate Limiting |
| API Layer | API Gateway (REST) + Cognito Authorizer | Zero Trust enforcement point |
| Compute | AWS Lambda (Node 20) | Stateless business logic |
| Secrets | AWS Secrets Manager + KMS CMK | Encryption & runtime secret retrieval |
| Observability | CloudWatch + X-Ray + Budgets | Metrics, tracing, cost alerting |

## Prerequisites

- AWS CLI configured (`aws configure`)
- Node.js 20+
- AWS CDK CLI (`npm install -g aws-cdk`)

## Setup

```bash
npm install
npx cdk bootstrap   # One-time per account/region
```

## Deploy

```bash
ALERT_EMAIL=you@example.com npx cdk deploy --all
```

## Test Scripts (run after deploy)

```bash
# Verify auth flow
USER_POOL_ID=<...> CLIENT_ID=<...> npx ts-node scripts/test-auth.ts

# WAF attack simulation
API_URL=<...> npx ts-node scripts/attack-simulation.ts

# Rate limit load test
API_URL=<...> npx ts-node scripts/load-test.ts
```

## Useful Commands

| Command | Description |
|---------|-------------|
| `npm run build` | Compile TypeScript |
| `npm test` | Run unit tests |
| `npx cdk synth` | Emit CloudFormation templates |
| `npx cdk diff` | Compare deployed vs local |
| `npx cdk deploy --all` | Deploy all stacks |
