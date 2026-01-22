# Application Policy - Limited access following least privilege
# Read-only access to application secrets
path "secret/data/apps/*" {
  capabilities = ["read", "list"]
}

path "secret/metadata/apps/*" {
  capabilities = ["read", "list"]
}

# Database credentials - dynamic secrets
path "database/creds/app-role" {
  capabilities = ["read"]
}

# PKI - request certificates
path "pki/issue/app-cert" {
  capabilities = ["create", "update"]
}

# No access to other services' secrets
path "secret/data/services/*" {
  capabilities = ["deny"]
}
