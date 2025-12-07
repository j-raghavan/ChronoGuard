#!/bin/bash
# scripts/seed_opa_policies.sh
#
# Seeds OPA with demo policy data for the demo-agent-001 agent.
# This script should be run after OPA is healthy to ensure policies persist.

set -e

OPA_URL="${OPA_URL:-http://localhost:8181}"

# Color codes
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${YELLOW}Seeding OPA with demo policy data...${NC}"

# Wait for OPA to be ready
MAX_RETRIES=30
RETRY_COUNT=0
while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
    if curl -sf "${OPA_URL}/health" > /dev/null 2>&1; then
        echo -e "${GREEN}OPA is healthy${NC}"
        break
    fi
    RETRY_COUNT=$((RETRY_COUNT + 1))
    echo "Waiting for OPA... (${RETRY_COUNT}/${MAX_RETRIES})"
    sleep 2
done

if [ $RETRY_COUNT -eq $MAX_RETRIES ]; then
    echo -e "${RED}OPA did not become healthy in time${NC}"
    exit 1
fi

# Seed demo policy data
# demo-agent-001: Can access example.com and httpbin.org, but NOT google.com
curl -sf -X PUT "${OPA_URL}/v1/data/policies" \
    -H "Content-Type: application/json" \
    -d '{
  "demo-agent-001": {
    "allowed_domains": ["example.com", "httpbin.org", "api.github.com"],
    "blocked_domains": [],
    "rate_limits": {
      "requests_per_minute": 60,
      "requests_per_hour": 1000,
      "requests_per_day": 10000,
      "burst_limit": 10
    }
  },
  "demo-agent-002": {
    "allowed_domains": ["example.com"],
    "blocked_domains": ["malware.com", "phishing.com"],
    "rate_limits": {
      "requests_per_minute": 30,
      "requests_per_hour": 500,
      "requests_per_day": 5000,
      "burst_limit": 5
    },
    "time_restrictions": {
      "enabled": true,
      "allowed_days": [0, 1, 2, 3, 4],
      "timezone_offset_minutes": 0,
      "time_ranges": [
        {
          "start_hour": 9,
          "start_minute": 0,
          "end_hour": 17,
          "end_minute": 0
        }
      ]
    }
  }
}' > /dev/null

if [ $? -eq 0 ]; then
    echo -e "${GREEN}Demo policy data seeded successfully${NC}"
    echo ""
    echo "Configured agents:"
    echo "  - demo-agent-001: Allowed domains: example.com, httpbin.org, api.github.com"
    echo "  - demo-agent-002: Allowed domains: example.com (business hours only)"
    echo ""
    echo "Blocked by default (not in allowlist):"
    echo "  - google.com, facebook.com, twitter.com, etc."
else
    echo -e "${RED}Failed to seed OPA policy data${NC}"
    exit 1
fi
