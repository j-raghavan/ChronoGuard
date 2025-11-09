# Rate Limiting Policy
#
# This policy implements simple rate limiting using OPA's built-in time functions.
# For production, integrate with Redis for distributed rate limiting.
#
# Usage:
#   - Configure rate limits below
#   - Deploy to OPA: opa run --server --bundle /path/to/this/policy
#   - Note: This is a stateless example. For stateful rate limiting, use Redis.

package chronoguard.rate_limiting

import future.keywords.if
import future.keywords.in

# Default: No rate limit violation
default rate_limit_exceeded := false

# Rate limit configuration (requests per minute per agent)
rate_limit_config := {
    "requests_per_minute": 60,
    "requests_per_hour": 1000,
    "burst_allowance": 10,
}

# Example: Check if rate limit is exceeded
# Note: This is a demonstration. Real rate limiting requires external state (Redis)
rate_limit_exceeded if {
    # In a real implementation, this would:
    # 1. Query Redis for current count: GET rate_limit:{agent_id}:{minute}
    # 2. Increment counter: INCR rate_limit:{agent_id}:{minute}
    # 3. Set expiration: EXPIRE rate_limit:{agent_id}:{minute} 60
    # 4. Compare count to limit

    # For this example, we'll demonstrate the structure only
    agent_id := input.attributes.source.principal
    current_minute := time.clock(time.now_ns())[1]

    # Placeholder: Would check Redis here
    # count := http.send({
    #     "method": "GET",
    #     "url": sprintf("http://redis:6379/GET/rate_limit:%s:%d", [agent_id, current_minute])
    # }).body

    # Simulate: Always allow (no actual state tracking)
    false
}

# Rate limit metadata for decision logs
rate_limit_metadata := metadata if {
    agent_id := input.attributes.source.principal
    now_ns := time.now_ns()
    [hour, minute, _] := time.clock(now_ns)

    metadata := {
        "agent_id": agent_id,
        "timestamp": now_ns,
        "window": sprintf("%02d:%02d", [hour, minute]),
        "limit": rate_limit_config.requests_per_minute,
        "burst": rate_limit_config.burst_allowance,
    }
}

# Deny reason if rate limited
deny_reason := reason if {
    rate_limit_exceeded
    agent_id := input.attributes.source.principal
    reason := sprintf(
        "Rate limit exceeded for agent %s (limit: %d req/min)",
        [agent_id, rate_limit_config.requests_per_minute]
    )
}

# Example Redis-based rate limiting (requires http.send or external data)
#
# rate_limit_check(agent_id) := {"allowed": allowed, "remaining": remaining} if {
#     current_minute_key := sprintf("rate_limit:%s:%d", [agent_id, current_minute])
#
#     # Get current count from Redis
#     count_response := http.send({
#         "method": "GET",
#         "url": sprintf("http://redis:6379/%s", [current_minute_key]),
#         "raise_error": false
#     })
#
#     count := to_number(count_response.body)
#     limit := rate_limit_config.requests_per_minute
#
#     allowed := count < limit
#     remaining := limit - count
# }

# Integration with main policy:
#
# allow if {
#     agent_authenticated
#     domain_allowed
#     not chronoguard.rate_limiting.rate_limit_exceeded
# }

# Note for Production:
# ====================
# This example demonstrates the structure, but real rate limiting should:
# 1. Use Redis for distributed state
# 2. Implement token bucket or sliding window algorithm
# 3. Handle race conditions with atomic operations (INCR, EXPIRE)
# 4. Support per-agent, per-domain, and global limits
# 5. Provide graceful degradation if Redis unavailable
#
# Recommended implementation:
# - Use Envoy's rate limit service (RLS) instead of OPA for better performance
# - Or implement rate limiting in FastAPI middleware
# - Or use Redis with Lua scripts for atomic operations
