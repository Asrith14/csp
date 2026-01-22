# Zero-Trust Data Access Policy
# Controls access to sensitive data

package zerotrust.data

import future.keywords.if
import future.keywords.in

default allow := false

# Input structure:
# {
#   "user": {
#     "id": "user-123",
#     "roles": ["developer"],
#     "clearance_level": 2,
#     "department": "engineering"
#   },
#   "data": {
#     "type": "pii",
#     "classification": "confidential",
#     "owner_department": "engineering",
#     "fields": ["name", "email", "ssn"]
#   },
#   "action": "read",
#   "purpose": "customer_support"
# }

# ============================================
# Data Classification Levels
# ============================================

classification_levels := {
    "public": 0,
    "internal": 1,
    "confidential": 2,
    "restricted": 3,
    "top_secret": 4
}

# Role clearance levels
role_clearance := {
    "viewer": 1,
    "developer": 2,
    "admin": 3,
    "security_officer": 4
}

# ============================================
# Classification-Based Access
# ============================================

# User clearance must meet data classification
allow if {
    user_clearance := max_clearance(input.user.roles)
    data_level := classification_levels[input.data.classification]
    user_clearance >= data_level
    valid_purpose
    not denied_fields
}

# Get maximum clearance from user roles
max_clearance(roles) := max_level if {
    levels := [role_clearance[r] | some r in roles; role_clearance[r]]
    max_level := max(levels)
}

max_clearance(roles) := 0 if {
    count([r | some r in roles; role_clearance[r]]) == 0
}

# ============================================
# Purpose Limitation
# ============================================

valid_purposes := {
    "customer_support",
    "analytics",
    "security_audit",
    "legal_compliance",
    "system_maintenance"
}

valid_purpose if {
    input.purpose in valid_purposes
}

deny[msg] if {
    not valid_purpose
    msg := sprintf("Invalid purpose: %v", [input.purpose])
}

# ============================================
# Field-Level Access Control
# ============================================

# PII fields requiring extra protection
pii_fields := {
    "ssn",
    "credit_card",
    "bank_account",
    "medical_record",
    "biometric_data"
}

# Fields that require specific roles
field_requirements := {
    "ssn": ["admin", "security_officer"],
    "credit_card": ["admin", "security_officer"],
    "bank_account": ["admin", "security_officer"],
    "medical_record": ["security_officer"],
    "biometric_data": ["security_officer"]
}

# Check if user can access all requested fields
denied_fields if {
    some field in input.data.fields
    field in pii_fields
    required_roles := field_requirements[field]
    not has_required_role(input.user.roles, required_roles)
}

has_required_role(user_roles, required_roles) if {
    some role in user_roles
    role in required_roles
}

# ============================================
# Department-Based Access
# ============================================

# Same department access
allow if {
    input.data.owner_department == input.user.department
    input.action == "read"
    input.data.classification in ["public", "internal"]
}

# ============================================
# Action-Based Rules
# ============================================

# Write actions require higher clearance
deny[msg] if {
    input.action in ["write", "delete", "modify"]
    user_clearance := max_clearance(input.user.roles)
    data_level := classification_levels[input.data.classification]
    user_clearance < data_level + 1
    msg := "Insufficient clearance for write operation"
}

# Delete requires admin
deny[msg] if {
    input.action == "delete"
    not "admin" in input.user.roles
    msg := "Only admins can delete data"
}

# ============================================
# Data Masking Rules
# ============================================

# Determine which fields should be masked
masked_fields[field] if {
    some field in input.data.fields
    field in pii_fields
    not has_required_role(input.user.roles, field_requirements[field])
}

# Masking format for different field types
masking_format := {
    "ssn": "***-**-####",
    "credit_card": "****-****-****-####",
    "bank_account": "****####",
    "email": "****@domain.com",
    "phone": "***-***-####"
}

# ============================================
# Audit Requirements
# ============================================

requires_audit if {
    input.data.type == "pii"
}

requires_audit if {
    classification_levels[input.data.classification] >= 2
}

requires_audit if {
    input.action in ["write", "delete", "modify"]
}

# ============================================
# Decision Output
# ============================================

decision := {
    "allow": allow,
    "masked_fields": masked_fields,
    "requires_audit": requires_audit,
    "deny_reasons": deny,
    "data_classification": input.data.classification,
    "user_clearance": max_clearance(input.user.roles)
}
