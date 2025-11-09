# configs/opa/policies/chronoguard.rego
package chronoguard.authz

import future.keywords.if
import future.keywords.in

# Default deny
default allow := false

# Allow if all conditions pass
allow if {
    agent_authenticated
    domain_allowed
    time_window_valid
    rate_limit_ok
}

# Check agent authentication via mTLS certificate
agent_authenticated if {
    # Extract agent ID from mTLS certificate subject
    # This will be populated by Envoy from client certificate
    input.attributes.source.principal
}

# Check if domain is in allowed list
domain_allowed if {
    # Get policy for this agent from FastAPI
    policy := get_agent_policy(input.attributes.source.principal)

    # Check if domain is in allowed_domains
    requested_domain := input.attributes.request.http.host
    requested_domain in policy.allowed_domains

    # AND domain is NOT in blocked_domains
    not requested_domain in policy.blocked_domains
}

# Check time window restrictions
time_window_valid if {
    # Get current time
    now := time.now_ns()

    # Get policy time restrictions
    policy := get_agent_policy(input.attributes.source.principal)

    # If no time restrictions, allow
    not policy.time_restrictions
}

time_window_valid if {
    policy := get_agent_policy(input.attributes.source.principal)
    restrictions := policy.time_restrictions

    # Check if current time is within allowed windows
    # TODO: Implement time window logic
    true  # Placeholder for MVP
}

# Check rate limits
rate_limit_ok if {
    # Get policy rate limits
    policy := get_agent_policy(input.attributes.source.principal)

    # If no rate limits, allow
    not policy.rate_limits
}

rate_limit_ok if {
    # TODO: Implement rate limit checks with Redis
    # For MVP, allow if rate_limits exist but checks not implemented
    true
}

# Helper: Get agent policy from data bundle
get_agent_policy(agent_id) := policy if {
    # Policies will be loaded into OPA data by FastAPI
    # via bundle or data API
    policy := data.policies[agent_id]
}

# Decision logging metadata
decision_metadata := {
    "agent_id": input.attributes.source.principal,
    "domain": input.attributes.request.http.host,
    "method": input.attributes.request.http.method,
    "path": input.attributes.request.http.path,
    "timestamp": time.now_ns(),
    "decision": allow
}
