# Financial Compliance Domain Policy
#
# This policy enforces domain access rules for financial services compliance.
# Implements SOX, FINRA, and SEC requirements for system access control.

package chronoguard.fintech.compliance_domains

import future.keywords.if
import future.keywords.in

default allow := false

# Production trading systems (highest security)
production_trading_domains := {
    "trading.internal.company.com",
    "orders.internal.company.com",
    "execution.internal.company.com",
}

# Market data providers (approved vendors only)
approved_market_data_providers := {
    "data.bloomberg.com",
    "api.refinitiv.com",
    "*.iexcloud.io",
    "api.polygon.io",
    "api.alpaca.markets",
}

# Research and analysis (read-only access)
research_domains := {
    "*.sec.gov",           # SEC EDGAR filings
    "*.finra.org",         # FINRA regulatory
    "www.federalreserve.gov",
    "fred.stlouisfed.org", # Economic data
    "finance.yahoo.com",   # Public market data
}

# Blocked domains (compliance violations)
prohibited_domains := {
    "*.reddit.com",        # Social media trading signals
    "*.twitter.com",
    "*.discord.com",
    "*.telegram.org",
    "*.whatsapp.com",
    "*crypto-pump*.com",   # Pump and dump schemes
    "*insider-trading*.com",
}

# Allow production trading (restricted to trading hours)
allow if {
    domain := input.attributes.request.http.host
    domain in production_trading_domains
    is_trading_hours  # Requires trading-hours.rego
}

# Allow market data providers (anytime for data collection)
allow if {
    domain := input.attributes.request.http.host
    domain_matches(domain, approved_market_data_providers)
    not domain_matches(domain, prohibited_domains)
}

# Allow research domains (anytime for analysis)
allow if {
    domain := input.attributes.request.http.host
    domain_matches(domain, research_domains)
}

# Domain matching with wildcard support
domain_matches(request_domain, domain_set) if {
    request_domain in domain_set
}

domain_matches(request_domain, domain_set) if {
    some allowed in domain_set
    startswith(allowed, "*.")
    suffix := trim_prefix(allowed, "*.")
    endswith(request_domain, suffix)
}

# Check if current time is trading hours
is_trading_hours if {
    # Import from trading-hours policy if available
    # Otherwise, inline check
    now_ns := time.now_ns()
    weekday := time.weekday(now_ns)
    [hour, _, _] := time.clock(now_ns)

    # Monday-Friday, 14:30-21:00 UTC (9:30am-4pm EST)
    weekday >= 0
    weekday <= 4
    hour >= 14
    hour < 21
}

# SOX Compliance: Segregation of duties
# Production access requires additional approval
production_access_requires_approval if {
    domain := input.attributes.request.http.host
    domain in production_trading_domains

    # Check if agent has production approval flag
    agent_id := input.attributes.source.principal
    agent_data := data.agents[agent_id]
    agent_data.production_approved == true
}

# Deny reasons for audit trail
deny_reason := "Access denied: Production trading system requires approval" if {
    domain := input.attributes.request.http.host
    domain in production_trading_domains
    not production_access_requires_approval
}

deny_reason := reason if {
    domain := input.attributes.request.http.host
    domain_matches(domain, prohibited_domains)
    reason := sprintf("Access denied: Domain '%s' violates compliance policy (social media/pump schemes)", [domain])
}

deny_reason := reason if {
    domain := input.attributes.request.http.host
    not domain_matches(domain, production_trading_domains)
    not domain_matches(domain, approved_market_data_providers)
    not domain_matches(domain, research_domains)
    reason := sprintf("Access denied: Domain '%s' not approved for financial operations", [domain])
}
