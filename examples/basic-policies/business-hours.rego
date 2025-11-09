# Business Hours Access Control Policy
#
# This policy restricts agent access to business hours only (Monday-Friday, 9am-5pm).
# Requests outside these hours are automatically denied.
#
# Usage:
#   - Deploy to OPA: opa run --server --bundle /path/to/this/policy
#   - Test: opa eval -d business-hours.rego "data.chronoguard.business_hours.allow"

package chronoguard.business_hours

import future.keywords.if
import future.keywords.in

# Default deny
default allow := false

# Allow if within business hours
allow if {
    is_business_hours
}

# Check if current time is within business hours (Monday-Friday, 9am-5pm UTC)
is_business_hours if {
    # Get current time
    now_ns := time.now_ns()

    # Convert to datetime for day-of-week and hour checks
    # Note: time.weekday() returns 0-6 (Monday-Sunday)
    weekday := time.weekday(now_ns)

    # Check: Monday-Friday (0-4)
    weekday >= 0
    weekday <= 4

    # Get hour in UTC
    [hour, _, _] := time.clock(now_ns)

    # Check: 9am-5pm (09:00-17:00)
    hour >= 9
    hour < 17
}

# Deny reason for debugging
deny_reason := reason if {
    not is_business_hours
    now_ns := time.now_ns()
    weekday := time.weekday(now_ns)
    [hour, _, _] := time.clock(now_ns)

    # Weekend
    weekday > 4
    reason := "Access denied: Weekend access not allowed"
}

deny_reason := reason if {
    not is_business_hours
    now_ns := time.now_ns()
    weekday := time.weekday(now_ns)
    [hour, _, _] := time.clock(now_ns)

    # Weekday but before business hours
    weekday <= 4
    hour < 9
    reason := sprintf("Access denied: Before business hours (current hour: %d UTC)", [hour])
}

deny_reason := reason if {
    not is_business_hours
    now_ns := time.now_ns()
    weekday := time.weekday(now_ns)
    [hour, _, _] := time.clock(now_ns)

    # Weekday but after business hours
    weekday <= 4
    hour >= 17
    reason := sprintf("Access denied: After business hours (current hour: %d UTC)", [hour])
}

# Example usage in combined policy:
# allow if {
#     agent_authenticated
#     domain_allowed
#     chronoguard.business_hours.allow  # Import this policy
# }
