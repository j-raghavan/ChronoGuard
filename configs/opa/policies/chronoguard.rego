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

    restrictions.enabled

    local_weekday := ((time.weekday(time.now_ns()) + 6) % 7)
    local_weekday in restrictions.allowed_days

    utc_clock := time.clock(time.now_ns())
    utc_minutes := (utc_clock[0] * 60) + utc_clock[1]
    local_minutes := (((utc_minutes + restrictions.timezone_offset_minutes) % 1440) + 1440) % 1440

    some range in restrictions.time_ranges
    within_time_range(range, local_minutes)
}

within_time_range(range, minute) if {
    start_time := (range.start_hour * 60) + range.start_minute
    end_time := (range.end_hour * 60) + range.end_minute
    start_time <= end_time
    minute >= start_time
    minute <= end_time
}

within_time_range(range, minute) if {
    start_time := (range.start_hour * 60) + range.start_minute
    end_time := (range.end_hour * 60) + range.end_minute
    start_time > end_time
    (
        minute >= start_time
        or minute <= end_time
    )
}

# Check rate limits
rate_limit_ok if {
    # Get policy rate limits
    policy := get_agent_policy(input.attributes.source.principal)

    # If no rate limits, allow
    not policy.rate_limits
}

rate_limit_ok if {
    policy := get_agent_policy(input.attributes.source.principal)
    policy.rate_limits
    context := object.get(input, "rate_limit_context", null)
    context != null

    minute_count := object.get(context, "minute_count", 0)
    hour_count := object.get(context, "hour_count", 0)
    day_count := object.get(context, "day_count", 0)
    burst_count := object.get(context, "burst_count", 0)

    minute_count < policy.rate_limits.requests_per_minute
    hour_count < policy.rate_limits.requests_per_hour
    day_count < policy.rate_limits.requests_per_day
    burst_count < policy.rate_limits.burst_limit
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
