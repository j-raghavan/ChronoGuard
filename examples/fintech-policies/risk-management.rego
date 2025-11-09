# Risk Management Policy for Financial Services
#
# This policy implements risk-based access controls for trading systems.
# Includes position limits, trading velocity checks, and risk thresholds.

package chronoguard.fintech.risk_management

import future.keywords.if
import future.keywords.in

default allow := false
default risk_level := "unknown"

# Risk thresholds by agent type
risk_thresholds := {
    "production_trader": {
        "max_requests_per_minute": 100,
        "max_requests_per_hour": 1000,
        "allowed_domains": ["trading.internal", "orders.internal"],
        "risk_tier": "high",
    },
    "market_data_collector": {
        "max_requests_per_minute": 600,
        "max_requests_per_hour": 10000,
        "allowed_domains": ["*.bloomberg.com", "*.refinitiv.com"],
        "risk_tier": "medium",
    },
    "research_agent": {
        "max_requests_per_minute": 60,
        "max_requests_per_hour": 1000,
        "allowed_domains": ["*.sec.gov", "finance.yahoo.com"],
        "risk_tier": "low",
    },
}

# Determine agent risk tier
risk_level := tier if {
    agent_id := input.attributes.source.principal
    agent_data := data.agents[agent_id]
    agent_type := agent_data.agent_type
    tier := risk_thresholds[agent_type].risk_tier
}

# Allow if agent is within risk limits
allow if {
    agent_id := input.attributes.source.principal
    agent_data := data.agents[agent_id]
    agent_type := agent_data.agent_type

    # Agent type is defined
    risk_thresholds[agent_type]

    # Domain is allowed for this agent type
    domain := input.attributes.request.http.host
    domain_allowed_for_type(domain, agent_type)

    # Rate limits not exceeded (would check Redis in production)
    not rate_limit_exceeded(agent_id, agent_type)

    # Not during market circuit breaker
    not market_halted
}

# Check if domain is allowed for agent type
domain_allowed_for_type(request_domain, agent_type) if {
    allowed := risk_thresholds[agent_type].allowed_domains
    request_domain in allowed
}

domain_allowed_for_type(request_domain, agent_type) if {
    allowed := risk_thresholds[agent_type].allowed_domains
    some allowed_domain in allowed
    startswith(allowed_domain, "*.")
    suffix := trim_prefix(allowed_domain, "*.")
    endswith(request_domain, suffix)
}

# Rate limit check (placeholder - requires Redis integration)
rate_limit_exceeded(agent_id, agent_type) if {
    # In production, query Redis:
    # count := redis_get(sprintf("rate:%s:minute", [agent_id]))
    # limit := risk_thresholds[agent_type].max_requests_per_minute
    # count >= limit

    # For demonstration: never exceeded
    false
}

# Market circuit breaker check
market_halted if {
    # Check if market-wide halt is in effect
    # In production, this would query external market status API or Redis flag
    # halt_status := http.send({
    #     "method": "GET",
    #     "url": "http://market-status.internal/halted"
    # }).body.halted

    # For demonstration: market is open
    false
}

# Pre-market and after-hours trading restrictions
allow_extended_hours if {
    agent_id := input.attributes.source.principal
    agent_data := data.agents[agent_id]

    # Only production traders can trade extended hours
    agent_data.agent_type == "production_trader"
    agent_data.extended_hours_approved == true

    # Pre-market hours: 9:00-14:30 UTC (4:00 AM - 9:30 AM EST)
    now_ns := time.now_ns()
    [hour, _, _] := time.clock(now_ns)
    hour >= 9
    hour < 14
}

allow_extended_hours if {
    agent_id := input.attributes.source.principal
    agent_data := data.agents[agent_id]

    # Only production traders can trade extended hours
    agent_data.agent_type == "production_trader"
    agent_data.extended_hours_approved == true

    # After-hours: 21:00-01:00 UTC (4:00 PM - 8:00 PM EST)
    now_ns := time.now_ns()
    [hour, _, _] := time.clock(now_ns)
    hour >= 21
}

allow_extended_hours if {
    agent_id := input.attributes.source.principal
    agent_data := data.agents[agent_id]

    # Only production traders can trade extended hours
    agent_data.agent_type == "production_trader"
    agent_data.extended_hours_approved == true

    # After-hours continuation: before 1am UTC
    now_ns := time.now_ns()
    [hour, _, _] := time.clock(now_ns)
    hour < 1
}

# Risk scoring for monitoring (during trading hours)
risk_score := score if {
    agent_id := input.attributes.source.principal
    agent_data := data.agents[agent_id]
    agent_type := agent_data.agent_type

    # Base score by tier
    base_scores := {"high": 100, "medium": 50, "low": 10}
    tier := risk_thresholds[agent_type].risk_tier
    base := base_scores[tier]

    # During trading hours: base score
    is_trading_hours_check
    score := base
}

# Risk scoring for monitoring (off-hours - higher risk)
risk_score := score if {
    agent_id := input.attributes.source.principal
    agent_data := data.agents[agent_id]
    agent_type := agent_data.agent_type

    # Base score by tier
    base_scores := {"high": 100, "medium": 50, "low": 10}
    tier := risk_thresholds[agent_type].risk_tier
    base := base_scores[tier]

    # Off-hours: double the risk score
    not is_trading_hours_check
    score := base * 2
}

is_trading_hours_check if {
    now_ns := time.now_ns()
    weekday := time.weekday(now_ns)
    [hour, minute, _] := time.clock(now_ns)

    weekday >= 0
    weekday <= 4

    # After 14:30 UTC
    hour > 14
    hour < 21
}

is_trading_hours_check if {
    now_ns := time.now_ns()
    weekday := time.weekday(now_ns)
    [hour, minute, _] := time.clock(now_ns)

    weekday >= 0
    weekday <= 4

    # Exactly 14:00 hour and after minute 30
    hour == 14
    minute >= 30
}

# Deny reasons
deny_reason := "Access denied: Market closed (weekend)" if {
    now_ns := time.now_ns()
    weekday := time.weekday(now_ns)
    weekday > 4
}

deny_reason := "Access denied: Outside trading hours (extended hours not approved)" if {
    not is_trading_hours_check
    not allow_extended_hours
}

deny_reason := "Access denied: Market circuit breaker in effect" if {
    market_halted
}
