# OPA Rate Limit Context Example

**Purpose:** Demonstrates how to properly populate `rate_limit_context` when calling OPA policy evaluation.

---

## Required Input Structure

OPA policies in ChronoGuard **require** `rate_limit_context` to enforce time windows and rate limits.

### Minimal Required Input

```json
{
  "attributes": {
    "source": {
      "principal": "agent-550e8400-e29b-41d4-a716-446655440003"
    },
    "request": {
      "http": {
        "host": "example.com",
        "path": "/api/v1/data",
        "method": "GET"
      },
      "time": "2025-11-10T14:30:00Z"
    }
  },
  "rate_limit_context": {
    "minute_count": 15,
    "hour_count": 250,
    "day_count": 3200,
    "burst_count": 3
  }
}
```

---

## Rate Limit Counter Meanings

| Counter | Description | Typical Source |
|---------|-------------|----------------|
| `minute_count` | Requests in last 60 seconds | Redis INCR with 60s TTL |
| `hour_count` | Requests in last 3600 seconds | Redis INCR with 3600s TTL |
| `day_count` | Requests in last 86400 seconds | Redis INCR with 86400s TTL |
| `burst_count` | Requests in last 10 seconds | Redis INCR with 10s TTL |

---

## Integration Examples

### Example 1: Envoy Proxy ext_authz

**Scenario:** Envoy queries OPA for each request via ext_authz filter.

**Envoy Configuration:**

```yaml
# envoy.yaml
http_filters:
  - name: envoy.filters.http.ext_authz
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
      grpc_service:
        envoy_grpc:
          cluster_name: opa_cluster
        timeout: 1s
      failure_mode_allow: false  # Fail closed
      # Metadata for rate limiting
      metadata_context_namespaces:
        - chronoguard
```

**External Rate Limit Service (separate sidecar):**

```python
# rate_limiter.py - Envoy ext_authz gRPC service
import grpc
import redis
from envoy.service.auth.v3 import external_auth_pb2_grpc

class RateLimitService(external_auth_pb2_grpc.AuthorizationServicer):
    def __init__(self, redis_client):
        self.redis = redis_client

    async def Check(self, request, context):
        agent_id = request.attributes.source.principal

        # Get counters from Redis
        minute_count = self.redis.get(f"rate:{agent_id}:minute") or 0
        hour_count = self.redis.get(f"rate:{agent_id}:hour") or 0
        day_count = self.redis.get(f"rate:{agent_id}:day") or 0
        burst_count = self.redis.get(f"rate:{agent_id}:burst") or 0

        # Increment counters
        pipe = self.redis.pipeline()
        pipe.incr(f"rate:{agent_id}:minute").expire(f"rate:{agent_id}:minute", 60)
        pipe.incr(f"rate:{agent_id}:hour").expire(f"rate:{agent_id}:hour", 3600)
        pipe.incr(f"rate:{agent_id}:day").expire(f"rate:{agent_id}:day", 86400)
        pipe.incr(f"rate:{agent_id}:burst").expire(f"rate:{agent_id}:burst", 10)
        pipe.execute()

        # Call OPA with rate_limit_context
        opa_input = {
            "attributes": request.attributes,
            "rate_limit_context": {
                "minute_count": int(minute_count),
                "hour_count": int(hour_count),
                "day_count": int(day_count),
                "burst_count": int(burst_count),
            }
        }

        # Query OPA...
```

---

### Example 2: Direct OPA API Call

**Scenario:** Custom API gateway directly calls OPA HTTP API.

```python
import httpx
import redis
from datetime import datetime

class OPAClient:
    def __init__(self, opa_url: str, redis_client):
        self.opa_url = opa_url
        self.redis = redis_client

    async def check_policy(self, agent_id: str, domain: str, method: str):
        # Get current counts from Redis
        minute_count = int(self.redis.get(f"rate:{agent_id}:minute") or 0)
        hour_count = int(self.redis.get(f"rate:{agent_id}:hour") or 0)
        day_count = int(self.redis.get(f"rate:{agent_id}:day") or 0)
        burst_count = int(self.redis.get(f"rate:{agent_id}:burst") or 0)

        # Build OPA input
        opa_input = {
            "input": {
                "attributes": {
                    "source": {
                        "principal": agent_id
                    },
                    "request": {
                        "http": {
                            "host": domain,
                            "method": method
                        },
                        "time": datetime.utcnow().isoformat() + "Z"
                    }
                },
                "rate_limit_context": {
                    "minute_count": minute_count,
                    "hour_count": hour_count,
                    "day_count": day_count,
                    "burst_count": burst_count
                }
            }
        }

        # Query OPA
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.opa_url}/v1/data/chronoguard/authz/allow",
                json=opa_input,
                timeout=1.0
            )
            result = response.json()

        # If allowed, increment counters
        if result.get("result"):
            pipe = self.redis.pipeline()
            pipe.incr(f"rate:{agent_id}:minute").expire(f"rate:{agent_id}:minute", 60)
            pipe.incr(f"rate:{agent_id}:hour").expire(f"rate:{agent_id}:hour", 3600)
            pipe.incr(f"rate:{agent_id}:day").expire(f"rate:{agent_id}:day", 86400)
            pipe.incr(f"rate:{agent_id}:burst").expire(f"rate:{agent_id}:burst", 10)
            pipe.execute()

        return result.get("result", False)
```

---

### Example 3: Testing with `curl`

**Manual OPA query** (for testing):

```bash
# Test OPA policy with rate_limit_context
curl -X POST http://localhost:8181/v1/data/chronoguard/authz/allow \
  -H "Content-Type: application/json" \
  -d '{
    "input": {
      "attributes": {
        "source": {
          "principal": "agent-550e8400-e29b-41d4-a716-446655440003"
        },
        "request": {
          "http": {
            "host": "example.com",
            "path": "/api/v1/data",
            "method": "GET"
          },
          "time": "2025-11-10T14:30:00Z"
        }
      },
      "rate_limit_context": {
        "minute_count": 5,
        "hour_count": 120,
        "day_count": 1500,
        "burst_count": 1
      }
    }
  }' | jq '.'
```

**Expected Response:**

```json
{
  "result": true
}
```

**Without `rate_limit_context` (will DENY):**

```bash
curl -X POST http://localhost:8181/v1/data/chronoguard/authz/allow \
  -H "Content-Type: application/json" \
  -d '{
    "input": {
      "attributes": {
        "source": {
          "principal": "agent-550e8400-e29b-41d4-a716-446655440003"
        },
        "request": {
          "http": {
            "host": "example.com"
          }
        }
      }
    }
  }' | jq '.'
```

**Response:**

```json
{
  "result": false
}
```

---

## Redis Schema for Rate Limiting

```
Key Pattern: rate:{agent_id}:{window}
Examples:
  - rate:agent-550e8400:minute  (TTL: 60s)
  - rate:agent-550e8400:hour    (TTL: 3600s)
  - rate:agent-550e8400:day     (TTL: 86400s)
  - rate:agent-550e8400:burst   (TTL: 10s)

Value: Integer (request count)
```

**Redis Commands:**

```bash
# Check current counts
redis-cli GET "rate:agent-550e8400:minute"
redis-cli GET "rate:agent-550e8400:hour"

# Manually reset (for testing)
redis-cli DEL "rate:agent-550e8400:minute"
redis-cli DEL "rate:agent-550e8400:hour"
redis-cli DEL "rate:agent-550e8400:day"
redis-cli DEL "rate:agent-550e8400:burst"

# Increment and set TTL
redis-cli INCR "rate:agent-550e8400:minute"
redis-cli EXPIRE "rate:agent-550e8400:minute" 60
```

---

## Policy Limits Configuration

Policy limits are defined in the Policy entity:

```json
{
  "policy_id": "policy-123",
  "name": "Standard Agent Policy",
  "rate_limits": {
    "requests_per_minute": 100,
    "requests_per_hour": 5000,
    "requests_per_day": 50000,
    "burst_size": 10
  }
}
```

OPA Rego evaluates these limits against the `rate_limit_context` counters.

---

## Troubleshooting

### Issue: All requests denied

**Check:**
```bash
# 1. Verify input includes rate_limit_context
echo $OPA_INPUT | jq '.input.rate_limit_context'
# Should show: {"minute_count": N, "hour_count": N, ...}

# 2. Check OPA logs
docker compose logs opa | grep rate_limit

# 3. Test with minimal counters
curl -X POST http://localhost:8181/v1/data/chronoguard/authz/allow \
  -d '{"input": {..., "rate_limit_context": {"minute_count": 0, "hour_count": 0, "day_count": 0, "burst_count": 0}}}'
```

### Issue: Counters not incrementing

**Check Redis:**
```bash
# Monitor Redis commands
redis-cli MONITOR

# Check keys exist
redis-cli KEYS "rate:*"

# Check TTL
redis-cli TTL "rate:agent-550e8400:minute"
```

---

## Related Documentation

- [Deployment Security Guide](../docs/DEPLOYMENT_SECURITY.md)
- [OPA Policy Compiler](../backend/src/infrastructure/opa/policy_compiler.py)
- [Base Policy Template](../backend/templates/rego/base_policy.rego.j2)
- [Packaged Policy](../configs/opa/policies/chronoguard.rego)

---

**Built with ❤️ for secure browser automation**
