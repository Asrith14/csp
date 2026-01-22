# Service Policy - For microservices
# Each service gets access only to its own secrets

# Auth Service Policy
path "secret/data/services/auth-service/*" {
  capabilities = ["read", "list"]
}

# PKI - request service certificates for mTLS
path "pki/issue/service-cert" {
  capabilities = ["create", "update"]
}

path "pki/cert/ca" {
  capabilities = ["read"]
}

# Transit encryption for sensitive data
path "transit/encrypt/service-key" {
  capabilities = ["update"]
}

path "transit/decrypt/service-key" {
  capabilities = ["update"]
}

# Token self-lookup
path "auth/token/lookup-self" {
  capabilities = ["read"]
}

path "auth/token/renew-self" {
  capabilities = ["update"]
}
