# Basic Policy Examples

This directory contains starter OPA policies for common access control scenarios.

## Policies

### 1. business-hours.rego

Restricts access to business hours only (Monday-Friday, 9am-5pm UTC).

**Use Case**: Prevent agents from running outside work hours to reduce costs or limit exposure.

**Test**:
```bash
docker run --rm -v $(pwd):/policies openpolicyagent/opa eval \
  -d /policies/business-hours.rego \
  -i <(echo '{}') \
  'data.chronoguard.business_hours.allow'
```

### 2. domain-allowlist.rego

Allows access only to explicitly listed domains with wildcard support.

**Use Case**: Whitelist-based access control for known-good domains.

**Features**:
- Exact domain matching
- Wildcard subdomain matching (`*.github.com`)
- Blocklist takes precedence over allowlist

**Test**:
```bash
docker run --rm -v $(pwd):/policies openpolicyagent/opa eval \
  -d /policies/domain-allowlist.rego \
  -i <(echo '{"attributes":{"request":{"http":{"host":"api.github.com"}}}}') \
  'data.chronoguard.domain_allowlist.allow'
```

### 3. rate-limiting.rego

Demonstrates rate limiting structure (requires Redis for production use).

**Use Case**: Prevent agent abuse by limiting requests per minute.

**Note**: This is a structural example. Production rate limiting should use:
- Redis for distributed state
- Envoy Rate Limit Service (RLS) for better performance
- Or FastAPI middleware with Redis backend

---

## Combining Policies

Combine multiple policies for comprehensive access control:

```rego
package chronoguard.combined

import data.chronoguard.business_hours
import data.chronoguard.domain_allowlist
import data.chronoguard.rate_limiting

# Allow only if ALL conditions pass
allow if {
    business_hours.allow        # Within business hours
    domain_allowlist.allow      # Domain is allowed
    not rate_limiting.rate_limit_exceeded  # Under rate limit
}

# Collect deny reasons
deny_reasons := reasons if {
    reasons := array.concat(
        deny_reasons_business_hours,
        deny_reasons_domain
    )
}

deny_reasons_business_hours := [business_hours.deny_reason] if {
    not business_hours.allow
}
deny_reasons_business_hours := [] if {
    business_hours.allow
}

deny_reasons_domain := [domain_allowlist.deny_reason] if {
    not domain_allowlist.allow
}
deny_reasons_domain := [] if {
    domain_allowlist.allow
}
```

---

## Integration with ChronoGuard

These policies can be deployed to OPA and referenced by ChronoGuard:

```bash
# 1. Copy policies to ChronoGuard config
cp *.rego /path/to/ChronoGuard/configs/opa/policies/

# 2. Restart OPA to load policies
docker compose restart chronoguard-policy-engine

# 3. Verify policies loaded
curl http://localhost:8181/v1/policies
```

---

## Testing Policies

### Unit Test with OPA

```bash
# Create test input
cat > test_input.json <<EOF
{
  "attributes": {
    "source": {
      "principal": "agent-123"
    },
    "request": {
      "http": {
        "host": "api.github.com",
        "method": "GET",
        "path": "/repos"
      }
    }
  }
}
EOF

# Test policy
docker run --rm -v $(pwd):/policies openpolicyagent/opa eval \
  -d /policies/ \
  -i test_input.json \
  'data.chronoguard.domain_allowlist.allow'
```

### Expected Output

```json
{
  "result": [
    {
      "expressions": [
        {
          "value": true,
          "text": "data.chronoguard.domain_allowlist.allow",
          "location": {...}
        }
      ]
    }
  ]
}
```

---

## Customization

Edit the policies to match your requirements:

**business-hours.rego**:
- Change hours: Modify `hour >= 9` and `hour < 17`
- Change days: Modify `weekday >= 0` and `weekday <= 4`
- Add timezone support: Use `time.add_date()` for conversions

**domain-allowlist.rego**:
- Add domains: Add to `allowed_domains` set
- Block domains: Add to `blocked_domains` set
- Complex patterns: Use regex with `regex.match()`

**rate-limiting.rego**:
- Adjust limits: Modify `rate_limit_config`
- Add Redis: Implement `http.send()` calls to Redis
- Per-domain limits: Add domain-specific limits

---

## License

These examples are provided as-is for reference and can be freely modified for your use case.
