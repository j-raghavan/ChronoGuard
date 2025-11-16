# Demo Policy for ChronoGuard Playground
# This policy allows example.com and blocks google.com

package chronoguard.authz.demo

import future.keywords.if
import future.keywords.in

# Default deny
default allow := false

# Allow example.com (used in demo-allowed.py)
allow if {
    input.attributes.request.http.host == "example.com"
}

allow if {
    input.attributes.request.http.host == "www.example.com"
}

# Explicitly block google.com (used in demo-blocked.py)
deny if {
    regex.match(".*google\\.com$", input.attributes.request.http.host)
}

# Decision metadata for logging
decision_metadata := {
    "agent_id": input.attributes.source.principal,
    "domain": input.attributes.request.http.host,
    "decision": allow,
    "timestamp": time.now_ns(),
}
