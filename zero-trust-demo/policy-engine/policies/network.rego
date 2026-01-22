# Zero-Trust Network Policy
# Controls service-to-service communication

package zerotrust.network

import future.keywords.if
import future.keywords.in

default allow := false

# Input structure:
# {
#   "source": {
#     "service": "auth-service",
#     "namespace": "default",
#     "ip": "172.21.0.10"
#   },
#   "destination": {
#     "service": "backend-service",
#     "namespace": "default",
#     "port": 3001,
#     "ip": "172.21.0.11"
#   },
#   "mtls": {
#     "enabled": true,
#     "client_cert_valid": true,
#     "server_cert_valid": true
#   }
# }

# ============================================
# mTLS Enforcement
# ============================================

# Require mTLS for all internal communication
deny[msg] if {
    not input.mtls.enabled
    msg := "mTLS is required for service communication"
}

deny[msg] if {
    input.mtls.enabled
    not input.mtls.client_cert_valid
    msg := "Invalid client certificate"
}

deny[msg] if {
    input.mtls.enabled
    not input.mtls.server_cert_valid
    msg := "Invalid server certificate"
}

# ============================================
# Service Communication Matrix
# ============================================

# Define allowed service-to-service communication
allowed_communications := {
    # Frontend can talk to API Gateway
    {"source": "frontend", "destination": "kong", "ports": [8000, 8443]},

    # API Gateway can talk to all backend services
    {"source": "kong", "destination": "auth-service", "ports": [3000]},
    {"source": "kong", "destination": "backend-service", "ports": [3001]},

    # Auth service can talk to Keycloak and Vault
    {"source": "auth-service", "destination": "keycloak", "ports": [8080]},
    {"source": "auth-service", "destination": "vault", "ports": [8200]},
    {"source": "auth-service", "destination": "opa", "ports": [8181]},

    # Backend service can talk to database and other services
    {"source": "backend-service", "destination": "postgres-app", "ports": [5432]},
    {"source": "backend-service", "destination": "vault", "ports": [8200]},
    {"source": "backend-service", "destination": "opa", "ports": [8181]},
    {"source": "backend-service", "destination": "auth-service", "ports": [3000]},

    # Monitoring can scrape all services
    {"source": "prometheus", "destination": "auth-service", "ports": [3000]},
    {"source": "prometheus", "destination": "backend-service", "ports": [3001]},
    {"source": "prometheus", "destination": "kong", "ports": [8001]},
    {"source": "prometheus", "destination": "keycloak", "ports": [8080]},
    {"source": "prometheus", "destination": "vault", "ports": [8200]},
}

# Check if communication is allowed
allow if {
    some comm in allowed_communications
    comm.source == input.source.service
    comm.destination == input.destination.service
    input.destination.port in comm.ports
    count(deny) == 0
}

# ============================================
# Network Segmentation Rules
# ============================================

# Define network zones
network_zones := {
    "dmz": "172.20.0.0/24",
    "internal": "172.21.0.0/24",
    "monitoring": "172.22.0.0/24",
    "data": "172.23.0.0/24"
}

# Services and their allowed zones
service_zones := {
    "frontend": ["dmz"],
    "kong": ["dmz", "internal"],
    "keycloak": ["dmz", "data"],
    "auth-service": ["internal"],
    "backend-service": ["internal", "data"],
    "vault": ["dmz", "internal"],
    "opa": ["internal", "dmz"],
    "prometheus": ["monitoring", "internal"],
    "grafana": ["monitoring"],
    "elasticsearch": ["monitoring"],
    "postgres-app": ["data"],
    "postgres-keycloak": ["data"],
    "postgres-kong": ["data"]
}

# Check if source service can access destination zone
zone_allowed if {
    source_zones := service_zones[input.source.service]
    dest_zones := service_zones[input.destination.service]
    some zone in source_zones
    zone in dest_zones
}

deny[msg] if {
    not zone_allowed
    msg := sprintf("Service %v cannot access zone of %v", [input.source.service, input.destination.service])
}

# ============================================
# Egress Control
# ============================================

# Allowed external destinations (for services that need internet access)
allowed_egress := {
    "keycloak": ["*.microsoft.com", "*.google.com"],  # For social login
    "vault": [],  # No egress allowed
    "backend-service": ["api.external-service.com"]
}

# Check egress rules
egress_allowed if {
    input.destination.external == true
    allowed_hosts := allowed_egress[input.source.service]
    some pattern in allowed_hosts
    glob.match(pattern, [], input.destination.host)
}

deny[msg] if {
    input.destination.external == true
    not egress_allowed
    msg := sprintf("Egress to %v not allowed for %v", [input.destination.host, input.source.service])
}

# ============================================
# Decision Output
# ============================================

decision := {
    "allow": allow,
    "deny_reasons": deny,
    "source": input.source.service,
    "destination": input.destination.service,
    "port": input.destination.port
}
