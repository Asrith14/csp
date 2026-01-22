# Zero-Trust Authorization Policy
# Open Policy Agent (OPA) Rego Policy

package zerotrust.authz

import future.keywords.if
import future.keywords.in

# Default deny - Zero Trust principle
default allow := false

# Input structure expected:
# {
#   "user": {
#     "id": "user-123",
#     "roles": ["admin", "developer"],
#     "groups": ["/administrators"],
#     "email": "user@example.com"
#   },
#   "resource": {
#     "type": "api",
#     "path": "/api/v1/users",
#     "method": "GET"
#   },
#   "context": {
#     "ip": "192.168.1.1",
#     "user_agent": "Mozilla/5.0",
#     "timestamp": "2024-01-01T00:00:00Z",
#     "request_id": "req-123"
#   }
# }

# ============================================
# Role-Based Access Control (RBAC)
# ============================================

# Admin has full access
allow if {
    "admin" in input.user.roles
}

# Developers can access development resources
allow if {
    "developer" in input.user.roles
    allowed_developer_paths[input.resource.path]
}

# Viewers have read-only access
allow if {
    "viewer" in input.user.roles
    input.resource.method == "GET"
    not sensitive_paths[input.resource.path]
}

# ============================================
# Path-Based Policies
# ============================================

# Paths developers can access
allowed_developer_paths := {
    "/api/v1/users",
    "/api/v1/products",
    "/api/v1/orders",
    "/api/v1/debug",
    "/api/v1/logs"
}

# Sensitive paths requiring admin
sensitive_paths := {
    "/api/v1/admin",
    "/api/v1/secrets",
    "/api/v1/audit",
    "/api/v1/config"
}

# Public paths (no auth required)
public_paths := {
    "/health",
    "/metrics",
    "/auth/login",
    "/auth/register"
}

# Allow public paths without authentication
allow if {
    public_paths[input.resource.path]
}

# ============================================
# Attribute-Based Access Control (ABAC)
# ============================================

# Users can only access their own data
allow if {
    input.resource.type == "user_data"
    input.resource.owner_id == input.user.id
}

# Allow access during business hours only for certain resources
allow if {
    input.resource.type == "business_critical"
    is_business_hours
    "developer" in input.user.roles
}

is_business_hours if {
    time.now_ns() > 0  # Placeholder - would check actual time
}

# ============================================
# Service-to-Service Authorization
# ============================================

# Service accounts can access inter-service endpoints
allow if {
    "service-account" in input.user.roles
    startswith(input.resource.path, "/internal/")
    valid_service_token
}

valid_service_token if {
    input.context.service_token != ""
    # Additional validation would go here
}

# ============================================
# Rate Limiting Policy
# ============================================

# Deny if rate limit exceeded
deny[msg] if {
    input.context.rate_limit_exceeded
    msg := "Rate limit exceeded"
}

# ============================================
# IP-Based Restrictions
# ============================================

# Block requests from blacklisted IPs
deny[msg] if {
    blacklisted_ips[input.context.ip]
    msg := sprintf("IP %v is blacklisted", [input.context.ip])
}

blacklisted_ips := {
    "10.0.0.1",  # Example blocked IP
}

# Allow only whitelisted IPs for admin endpoints
allow if {
    startswith(input.resource.path, "/api/v1/admin")
    "admin" in input.user.roles
    admin_whitelisted_ips[input.context.ip]
}

admin_whitelisted_ips := {
    "127.0.0.1",
    "172.20.0.0/24",  # DMZ network
    "172.21.0.0/24",  # Internal network
}

# ============================================
# Audit Logging Decision
# ============================================

# Determine if request should be logged
audit_log if {
    sensitive_paths[input.resource.path]
}

audit_log if {
    input.resource.method in ["POST", "PUT", "DELETE", "PATCH"]
}

audit_log if {
    "admin" in input.user.roles
}

# ============================================
# Response with Reasons
# ============================================

# Collect all deny reasons
reasons[msg] if {
    deny[msg]
}

reasons["No matching allow rule"] if {
    not allow
    count(deny) == 0
}

# Final decision object
decision := {
    "allow": allow,
    "audit": audit_log,
    "reasons": reasons,
    "user": input.user.id,
    "resource": input.resource.path,
    "method": input.resource.method
}
