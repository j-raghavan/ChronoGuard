# Domain Allowlist Policy
#
# This policy implements a simple domain allowlist with wildcard support.
# Only requests to explicitly allowed domains are permitted.
#
# Usage:
#   - Customize allowed_domains set below
#   - Deploy to OPA: opa run --server --bundle /path/to/this/policy
#   - Test: opa eval -d domain-allowlist.rego -i input.json "data.chronoguard.domain_allowlist.allow"

package chronoguard.domain_allowlist

import future.keywords.if
import future.keywords.in

# Default deny
default allow := false

# Example allowed domains (customize for your use case)
allowed_domains := {
    "example.com",
    "api.example.com",
    "*.github.com",      # Wildcard: any subdomain of github.com
    "*.google.com",
    "stackoverflow.com",
    "docs.python.org",
}

# Blocked domains (takes precedence over allowed)
blocked_domains := {
    "malicious.com",
    "phishing-site.com",
    "social-media.com",  # Block distractions
}

# Allow if domain is in allowlist and not in blocklist
allow if {
    domain := input.attributes.request.http.host
    domain_in_allowlist(domain)
    not domain_in_blocklist(domain)
}

# Check if domain matches any allowed domain (with wildcard support)
domain_in_allowlist(request_domain) if {
    # Exact match
    request_domain in allowed_domains
}

domain_in_allowlist(request_domain) if {
    # Wildcard match: *.github.com matches api.github.com
    some allowed_domain in allowed_domains
    startswith(allowed_domain, "*.")
    suffix := trim_prefix(allowed_domain, "*.")
    endswith(request_domain, suffix)
}

# Check if domain is in blocklist
domain_in_blocklist(request_domain) if {
    request_domain in blocked_domains
}

domain_in_blocklist(request_domain) if {
    # Wildcard match for blocked domains
    some blocked_domain in blocked_domains
    startswith(blocked_domain, "*.")
    suffix := trim_prefix(blocked_domain, "*.")
    endswith(request_domain, suffix)
}

# Deny reason for debugging
deny_reason := reason if {
    domain := input.attributes.request.http.host
    domain_in_blocklist(domain)
    reason := sprintf("Access denied: Domain '%s' is blocked", [domain])
}

deny_reason := reason if {
    domain := input.attributes.request.http.host
    not domain_in_allowlist(domain)
    not domain_in_blocklist(domain)
    reason := sprintf("Access denied: Domain '%s' not in allowlist", [domain])
}

# Test input example:
# {
#   "attributes": {
#     "request": {
#       "http": {
#         "host": "api.github.com",
#         "method": "GET",
#         "path": "/repos"
#       }
#     }
#   }
# }
#
# Expected result:
# {
#   "allow": true  // Matches *.github.com
# }
