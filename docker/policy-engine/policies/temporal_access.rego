package envoy.authz

import rego.v1

# Default decision: deny
default allow := false

# Allow decision with temporal access control
allow if {
    # Basic authentication check
    valid_agent

    # Time-based access control
    within_allowed_time

    # Domain access control
    allowed_domain

    # Rate limiting check
    within_rate_limits
}

# Agent validation
valid_agent if {
    # Check if agent certificate is present and valid
    input.attributes.request.http.headers["x-client-cert"]

    # Check agent is active (would query ChronoGuard API)
    # For now, simplified check
    input.attributes.request.http.headers["x-agent-id"]
}

# Time-based access control
within_allowed_time if {
    # Get current time context
    now := time.now_ns()
    current_hour := time.date(now)[3]  # Get hour
    current_day := time.weekday(now)   # Get day of week

    # Business hours: Monday-Friday, 9 AM - 5 PM UTC
    current_day >= 1  # Monday
    current_day <= 5  # Friday
    current_hour >= 9
    current_hour < 17
}

# Alternative: Allow access during configured time windows
within_allowed_time if {
    # Check against policy-defined time windows
    some window in input.attributes.metadata_context.filter_metadata.chronoguard.time_windows
    time_in_window(window)
}

# Domain access control
allowed_domain if {
    domain := input.attributes.request.http.host

    # Check against allowed domains list
    domain in input.attributes.metadata_context.filter_metadata.chronoguard.allowed_domains
}

# Block known malicious domains
allowed_domain if {
    domain := input.attributes.request.http.host

    # Ensure domain is not in blocked list
    not domain in input.attributes.metadata_context.filter_metadata.chronoguard.blocked_domains

    # Additional security checks
    not is_ip_address(domain)
    not is_localhost(domain)
    not is_private_ip(domain)
}

# Rate limiting check
within_rate_limits if {
    # Check agent rate limits
    agent_id := input.attributes.request.http.headers["x-agent-id"]

    # Get current request count for agent (would query Redis/API)
    # For now, simplified implementation
    count := 0  # Would be actual count from rate limiter
    count < 60  # 60 requests per minute limit
}

# Helper functions
time_in_window(window) if {
    now := time.now_ns()
    current_time := time.date(now)

    # Check if current time falls within window
    # Simplified implementation
    window.start_hour <= current_time[3]
    current_time[3] < window.end_hour
}

is_ip_address(domain) if {
    # IPv4 pattern check
    regex.match(`^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$`, domain)
}

is_ip_address(domain) if {
    # IPv6 pattern check (simplified)
    contains(domain, ":")
    regex.match(`^[0-9a-fA-F:]+$`, domain)
}

is_localhost(domain) if {
    domain == "localhost"
}

is_localhost(domain) if {
    startswith(domain, "127.")
}

is_private_ip(domain) if {
    startswith(domain, "192.168.")
}

is_private_ip(domain) if {
    startswith(domain, "10.")
}

is_private_ip(domain) if {
    startswith(domain, "172.")
}

# Audit decision logging
decision_log := {
    "timestamp": time.now_ns(),
    "agent_id": input.attributes.request.http.headers["x-agent-id"],
    "domain": input.attributes.request.http.host,
    "method": input.attributes.request.http.method,
    "path": input.attributes.request.http.path,
    "decision": allow,
    "reason": decision_reason,
    "user_agent": input.attributes.request.http.headers["user-agent"],
    "source_ip": input.attributes.source.address.Address.SocketAddress.address
}

decision_reason := "temporal_access_denied" if {
    not within_allowed_time
}

decision_reason := "domain_blocked" if {
    not allowed_domain
}

decision_reason := "rate_limited" if {
    not within_rate_limits
}

decision_reason := "invalid_agent" if {
    not valid_agent
}

decision_reason := "access_granted" if {
    allow
}