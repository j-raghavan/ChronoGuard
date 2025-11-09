# PHI Protection Policy
#
# Protected Health Information (PHI) access control policy.
# Implements HIPAA Privacy Rule requirements for minimum necessary access.
#
# Compliance: HIPAA §164.502(b), §164.514(d)

package chronoguard.healthcare.phi_protection

import future.keywords.if
import future.keywords.in

default allow := false

# PHI-containing systems (extra protection required)
phi_systems := {
    "ehr.hospital.internal",          # Electronic Health Records
    "pacs.hospital.internal",          # Medical imaging
    "lab.hospital.internal",           # Laboratory results
    "pharmacy.hospital.internal",      # Prescription systems
    "billing.hospital.internal",       # Contains PHI in billing records
}

# Authorized PHI access roles
phi_authorized_roles := {
    "physician",
    "nurse",
    "physician_assistant",
    "medical_assistant",
    "lab_technician",
    "pharmacist",
    "billing_specialist",
    "compliance_officer",
}

# Allow PHI access if agent has authorized role
allow if {
    domain := input.attributes.request.http.host
    domain in phi_systems

    agent_id := input.attributes.source.principal
    agent_data := data.agents[agent_id]

    # Must have authorized role
    has_phi_access_role(agent_data)

    # Must have active HIPAA training
    has_current_hipaa_training(agent_data)

    # Must not be on leave/suspended
    agent_data.status == "active"

    # Check minimum necessary for specific request
    minimum_necessary_satisfied(agent_data, input.attributes.request)
}

# Check if agent has PHI access role
has_phi_access_role(agent_data) if {
    some role in agent_data.roles
    role in phi_authorized_roles
}

# Verify HIPAA training is current (required annually)
has_current_hipaa_training(agent_data) if {
    training_date := agent_data.hipaa_training_date

    # Training must be within last 365 days
    training_timestamp := time.parse_rfc3339_ns(training_date)
    now_ns := time.now_ns()
    age_ns := now_ns - training_timestamp

    # 365 days in nanoseconds
    max_age_ns := 365 * 24 * 60 * 60 * 1000000000

    age_ns < max_age_ns
}

# Minimum Necessary Rule: Agent should only access what's needed for their role
minimum_necessary_satisfied(agent_data, request) if {
    path := request.http.path
    method := request.http.method

    # Physicians can access full patient records
    some role in agent_data.roles
    role == "physician"
}

minimum_necessary_satisfied(agent_data, request) if {
    path := request.http.path
    method := request.http.method

    # Billing staff can only access billing data
    some role in agent_data.roles
    role == "billing_specialist"
    startswith(path, "/api/billing")
    not startswith(path, "/api/patients/clinical")
}

minimum_necessary_satisfied(agent_data, request) if {
    path := request.http.path
    method := request.http.method

    # Pharmacists can access pharmacy records only
    some role in agent_data.roles
    role == "pharmacist"
    startswith(path, "/api/pharmacy")
}

# Break-glass emergency access (logged and reviewed)
allow if {
    agent_id := input.attributes.source.principal
    agent_data := data.agents[agent_id]

    # Emergency override flag (must be explicitly set)
    agent_data.emergency_override == true

    # Emergency access expires after 1 hour
    override_timestamp := time.parse_rfc3339_ns(agent_data.emergency_override_at)
    now_ns := time.now_ns()
    age_ns := now_ns - override_timestamp

    # 1 hour in nanoseconds
    max_age_ns := 60 * 60 * 1000000000

    age_ns < max_age_ns
}

# Sensitive PHI categories requiring additional authorization
sensitive_phi_paths := {
    "/api/patients/mental-health",     # Mental health records
    "/api/patients/substance-abuse",   # Substance abuse treatment
    "/api/patients/hiv",               # HIV status
    "/api/patients/genetic",           # Genetic testing
    "/api/patients/reproductive",      # Reproductive health
}

# Extra authorization required for sensitive PHI
allow_sensitive_phi if {
    agent_id := input.attributes.source.principal
    agent_data := data.agents[agent_id]
    path := input.attributes.request.http.path

    # Check if path is sensitive
    some sensitive_path in sensitive_phi_paths
    startswith(path, sensitive_path)

    # Requires explicit authorization
    agent_data.sensitive_phi_authorized == true

    # And treating provider role
    some role in agent_data.roles
    role in {"physician", "psychologist", "psychiatrist", "counselor"}
}

# Deny reasons for audit trail (HIPAA requires detailed logs)
deny_reason := reason if {
    agent_id := input.attributes.source.principal
    agent_data := data.agents[agent_id]
    not has_phi_access_role(agent_data)
    reason := sprintf("Access denied: Agent role not authorized for PHI access (current roles: %v)", [agent_data.roles])
}

deny_reason := "Access denied: HIPAA training expired (annual training required)" if {
    agent_id := input.attributes.source.principal
    agent_data := data.agents[agent_id]
    not has_current_hipaa_training(agent_data)
}

deny_reason := "Access denied: Agent status is not active (suspended or on leave)" if {
    agent_id := input.attributes.source.principal
    agent_data := data.agents[agent_id]
    agent_data.status != "active"
}

deny_reason := reason if {
    path := input.attributes.request.http.path
    some sensitive_path in sensitive_phi_paths
    startswith(path, sensitive_path)
    not allow_sensitive_phi
    reason := sprintf("Access denied: Sensitive PHI requires additional authorization (path: %s)", [path])
}
