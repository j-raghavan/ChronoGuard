# HIPAA Audit Requirements Policy
#
# This policy ensures all PHI access is properly logged and auditable.
# Enforces HIPAA audit control requirements.
#
# Compliance: HIPAA §164.312(b) - Audit Controls

package chronoguard.healthcare.audit_requirements

import future.keywords.if
import future.keywords.in

default allow := false

# This policy focuses on ensuring proper audit metadata is captured
# It works in conjunction with ChronoGuard's audit logging

# Require specific metadata for PHI access
allow if {
    # Standard authorization checks pass
    basic_authorization
    # Audit metadata requirements satisfied
    audit_metadata_complete
}

# Basic authorization (defer to other policies)
basic_authorization if {
    # This would typically import phi-protection.rego
    # For standalone testing, implement basic check
    agent_id := input.attributes.source.principal
    agent_data := data.agents[agent_id]
    agent_data.status == "active"
}

# Verify all required audit metadata is present
audit_metadata_complete if {
    # Agent identity (from mTLS certificate)
    input.attributes.source.principal

    # Request details
    input.attributes.request.http.host
    input.attributes.request.http.method
    input.attributes.request.http.path

    # Timestamp (OPA provides this)
    time.now_ns()

    # Source IP (for HIPAA audit trail)
    input.attributes.source.address.socketAddress.address
}

# Enhanced audit metadata for PHI access
phi_audit_metadata := metadata if {
    agent_id := input.attributes.source.principal
    agent_data := data.agents[agent_id]
    request := input.attributes.request.http

    metadata := {
        "agent_id": agent_id,
        "agent_name": agent_data.name,
        "agent_roles": agent_data.roles,
        "department": agent_data.department,
        "facility": agent_data.facility,
        "access_reason": agent_data.access_reason,  # Required for PHI access
        "domain": request.host,
        "method": request.method,
        "path": request.path,
        "source_ip": input.attributes.source.address.socketAddress.address,
        "timestamp": time.now_ns(),
        "hipaa_training_current": has_current_training(agent_data),
        "emergency_access": agent_data.emergency_override == true,
    }
}

# Verify HIPAA training is current
has_current_training(agent_data) if {
    training_date := agent_data.hipaa_training_date
    training_timestamp := time.parse_rfc3339_ns(training_date)
    now_ns := time.now_ns()
    age_ns := now_ns - training_timestamp
    max_age_ns := 365 * 24 * 60 * 60 * 1000000000  # 1 year
    age_ns < max_age_ns
}

# Retention policy marker (used by audit cleanup processes)
audit_retention_years := 6  # HIPAA requires 6 years

# Require access reason for PHI
require_access_reason if {
    domain := input.attributes.request.http.host
    phi_domains := {
        "ehr.hospital.internal",
        "pacs.hospital.internal",
        "lab.hospital.internal",
    }

    domain in phi_domains

    # Access reason must be provided
    agent_id := input.attributes.source.principal
    agent_data := data.agents[agent_id]
    agent_data.access_reason != null
    agent_data.access_reason != ""
}

# Audit alert conditions
audit_alert := alert if {
    agent_id := input.attributes.source.principal
    agent_data := data.agents[agent_id]
    path := input.attributes.request.http.path

    # Alert on sensitive PHI access
    sensitive_paths := [
        "/api/patients/mental-health",
        "/api/patients/hiv",
        "/api/patients/genetic",
    ]

    some sensitive in sensitive_paths
    startswith(path, sensitive)

    alert := {
        "level": "high",
        "reason": "Sensitive PHI accessed",
        "agent_id": agent_id,
        "path": path,
        "requires_review": true,
    }
}

# Batch access detection (potential bulk PHI export)
audit_alert := alert if {
    path := input.attributes.request.http.path

    # Detect bulk export requests
    contains(path, "/export")

    alert := {
        "level": "critical",
        "reason": "Bulk PHI export detected",
        "requires_immediate_review": true,
        "compliance_review": true,
    }
}

audit_alert := alert if {
    path := input.attributes.request.http.path

    # Detect batch requests
    contains(path, "/batch")

    alert := {
        "level": "critical",
        "reason": "Batch PHI access detected",
        "requires_immediate_review": true,
        "compliance_review": true,
    }
}

# Deny reasons
deny_reason := "Access denied: Required audit metadata missing" if {
    not audit_metadata_complete
}

deny_reason := "Access denied: Access reason required for PHI (HIPAA Minimum Necessary)" if {
    domain := input.attributes.request.http.host
    phi_domains := {"ehr.hospital.internal", "pacs.hospital.internal", "lab.hospital.internal"}
    domain in phi_domains
    not require_access_reason
}

# Example agent data structure expected:
# {
#   "agent_id": "uuid",
#   "name": "Dr. Smith",
#   "roles": ["physician"],
#   "department": "clinical",
#   "facility": "General Hospital",
#   "status": "active",
#   "hipaa_training_date": "2024-06-01T00:00:00Z",
#   "access_reason": "Patient care - reviewing lab results",
#   "emergency_override": false,
#   "on_call_schedule": {...},
#   "currently_on_call": false
# }
