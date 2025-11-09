# Healthcare Operational Hours Policy
#
# HIPAA-compliant access control policy for healthcare systems.
# Restricts PHI access to operational hours with emergency override.
#
# Compliance: HIPAA §164.308(a)(3) - Workforce access controls

package chronoguard.healthcare.operational_hours

import future.keywords.if

default allow := false

# Standard operational hours: 6:00 AM - 10:00 PM local time (UTC offsets below)
operational_hours := {
    "start_hour_utc": 11,  # 6:00 AM EST = 11:00 UTC
    "end_hour_utc": 3,     # 10:00 PM EST = 03:00 UTC (next day)
    "timezone": "America/New_York",
}

# Allow during operational hours
allow if {
    is_operational_hours
    not is_emergency_only_domain
}

# Allow emergency access 24/7
allow if {
    agent_has_emergency_access
    is_emergency_only_domain
}

# Allow on-call staff 24/7
allow if {
    agent_is_on_call
}

# Check if current time is within operational hours
is_operational_hours if {
    now_ns := time.now_ns()
    [hour, _, _] := time.clock(now_ns)

    # After start hour
    hour >= operational_hours.start_hour_utc
}

is_operational_hours if {
    now_ns := time.now_ns()
    [hour, _, _] := time.clock(now_ns)

    # Before end hour (wraps midnight)
    hour < operational_hours.end_hour_utc
}

# Emergency-only domains (e.g., emergency department systems)
is_emergency_only_domain if {
    domain := input.attributes.request.http.host
    emergency_domains := {
        "emergency.hospital.internal",
        "trauma.hospital.internal",
        "icu.hospital.internal",
    }
    domain in emergency_domains
}

# Check if agent has emergency access role
agent_has_emergency_access if {
    agent_id := input.attributes.source.principal
    agent_data := data.agents[agent_id]
    agent_data.roles[_] == "emergency_responder"
}

# Check if agent is currently on-call
agent_is_on_call if {
    agent_id := input.attributes.source.principal
    agent_data := data.agents[agent_id]

    # Check on-call schedule (would query external system in production)
    agent_data.on_call_schedule != null

    # Verify current time is within on-call window
    # In production: query on-call rotation system
    agent_data.currently_on_call == true
}

# HIPAA Minimum Necessary Rule: Limit access scope
minimum_necessary_check if {
    agent_id := input.attributes.source.principal
    agent_data := data.agents[agent_id]
    path := input.attributes.request.http.path

    # Check if requested resource is within agent's authorized scope
    # Example: Billing staff cannot access clinical data
    scope_allowed(agent_data.department, path)
}

scope_allowed(department, path) if {
    department == "clinical"
    # Clinical staff can access patient records
    startswith(path, "/api/patients")
}

scope_allowed(department, path) if {
    department == "billing"
    # Billing staff can only access billing data
    startswith(path, "/api/billing")
    not startswith(path, "/api/patients/clinical")
}

scope_allowed(department, path) if {
    department == "admin"
    # Admin can access administrative systems only
    startswith(path, "/api/admin")
}

# Deny reasons for audit trail
deny_reason := "Access denied: Outside operational hours (emergency access required)" if {
    not is_operational_hours
    not agent_has_emergency_access
    not agent_is_on_call
}

deny_reason := "Access denied: Emergency-only domain (requires emergency_responder role)" if {
    is_emergency_only_domain
    not agent_has_emergency_access
}

deny_reason := reason if {
    agent_id := input.attributes.source.principal
    path := input.attributes.request.http.path
    agent_data := data.agents[agent_id]
    not scope_allowed(agent_data.department, path)
    reason := sprintf(
        "Access denied: Department '%s' not authorized for path '%s' (Minimum Necessary Rule)",
        [agent_data.department, path]
    )
}
