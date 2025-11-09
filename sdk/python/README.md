# ChronoGuard Python SDK

Official Python SDK for ChronoGuard - Zero-trust proxy for browser automation with temporal controls.

## Installation

```bash
pip install chronoguard-sdk
```

## Quick Start

### Async Usage (Recommended)

```python
import asyncio
from chronoguard_sdk import ChronoGuard

async def main():
    # Initialize client
    client = ChronoGuard(api_url="http://localhost:8000")

    # Agent management
    agents = await client.agents.list()

    # Create new agent
    agent = await client.agents.create(
        name="qa-agent-01",
        certificate_pem="-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
        metadata={"environment": "production"}
    )

    # Get agent by ID
    agent = await client.agents.get(agent_id="550e8400-e29b-41d4-a716-446655440000")

    # Update agent
    updated_agent = await client.agents.update(
        agent_id=agent.agent_id,
        name="qa-agent-updated"
    )

    # Policy management
    policies = await client.policies.list()

    # Create new policy
    policy = await client.policies.create(
        name="production-policy",
        description="Access policy for production agents",
        priority=500,
        allowed_domains=["example.com"],
        metadata={"team": "qa"}
    )

    # Audit log queries
    from datetime import datetime, timedelta

    end_time = datetime.utcnow()
    start_time = end_time - timedelta(days=7)

    audit_logs = await client.audit.query(
        tenant_id="550e8400-e29b-41d4-a716-446655440001",
        start_time=start_time,
        end_time=end_time,
        decision="allow",
        page=1,
        page_size=50
    )

    # Temporal analytics
    analytics = await client.analytics.get_temporal_patterns(
        tenant_id="550e8400-e29b-41d4-a716-446655440001",
        start_time=start_time,
        end_time=end_time
    )

    # Export audit logs
    csv_content = await client.audit.export(
        tenant_id="550e8400-e29b-41d4-a716-446655440001",
        start_time=start_time,
        end_time=end_time,
        format="csv"
    )

    # Close client when done
    await client.close()

if __name__ == "__main__":
    asyncio.run(main())
```

### Sync Usage

```python
from chronoguard_sdk import ChronoGuardSync

# Initialize sync client
client = ChronoGuardSync(api_url="http://localhost:8000")

# All operations work the same way but without async/await
agents = client.agents.list()
agent = client.agents.create(
    name="qa-agent-01",
    certificate_pem="-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
)

# Close client when done
client.close()
```

### Context Manager Support

```python
# Async context manager
async with ChronoGuard(api_url="http://localhost:8000") as client:
    agents = await client.agents.list()

# Sync context manager
with ChronoGuardSync(api_url="http://localhost:8000") as client:
    agents = client.agents.list()
```

## Features

- **Full API Coverage**: Complete support for all ChronoGuard API endpoints
- **Type Safety**: Full type hints with Pydantic models
- **Async & Sync**: Both async and sync clients available
- **Error Handling**: Comprehensive exception hierarchy
- **Authentication**: Built-in support for tenant/user authentication headers
- **Pagination**: Automatic pagination support for list operations
- **Export**: Audit log export in CSV and JSON formats
- **Analytics**: Temporal pattern analysis and compliance scoring

## API Reference

### ChronoGuard Client

#### Initialization

```python
ChronoGuard(
    api_url: str,
    tenant_id: str | None = None,
    user_id: str | None = None,
    timeout: float = 30.0
)
```

#### Agent Management

- `agents.list(page: int = 1, page_size: int = 50, status_filter: str | None = None)`
- `agents.get(agent_id: str)`
- `agents.create(name: str, certificate_pem: str, metadata: dict[str, Any] = {})`
- `agents.update(agent_id: str, name: str | None = None, certificate_pem: str | None = None, metadata: dict[str, Any] | None = None)`

#### Policy Management

- `policies.list(page: int = 1, page_size: int = 50, status_filter: str | None = None)`
- `policies.get(policy_id: str)`
- `policies.create(name: str, description: str, priority: int = 500, allowed_domains: list[str] = [], blocked_domains: list[str] = [], metadata: dict[str, str] = {})`
- `policies.update(policy_id: str, ...)`
- `policies.delete(policy_id: str)`

#### Audit Queries

- `audit.query(tenant_id: str, agent_id: str | None = None, domain: str | None = None, decision: str | None = None, start_time: datetime | None = None, end_time: datetime | None = None, page: int = 1, page_size: int = 50)`
- `audit.export(tenant_id: str, start_time: datetime, end_time: datetime, format: str = "csv", include_metadata: bool = True, pretty_json: bool = False)`

#### Analytics

- `analytics.get_temporal_patterns(tenant_id: str, start_time: datetime, end_time: datetime)`

## Error Handling

The SDK provides a comprehensive exception hierarchy:

```python
from chronoguard_sdk.exceptions import (
    ChronoGuardError,          # Base exception
    APIError,                  # API-related errors
    ValidationError,           # Request validation errors
    NotFoundError,            # Resource not found (404)
    ConflictError,            # Resource conflict (409)
    AuthenticationError,      # Authentication failures
    RateLimitError,          # Rate limit exceeded
    TimeoutError,            # Request timeout
)

try:
    agent = await client.agents.get("non-existent-id")
except NotFoundError as e:
    print(f"Agent not found: {e}")
except APIError as e:
    print(f"API error: {e.status_code} - {e.detail}")
```

## Models

All API responses are returned as Pydantic models:

```python
from chronoguard_sdk.models import (
    Agent,
    AgentListResponse,
    Policy,
    PolicyListResponse,
    AuditEntry,
    AuditListResponse,
    TemporalPattern,
)
```

## Development

### Setup

```bash
# Clone repository
git clone https://github.com/chronoguard/chronoguard.git
cd chronoguard/sdk/python

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install development dependencies
pip install -e ".[dev]"
```

### Testing

```bash
# Run tests
pytest

# Run tests with coverage
pytest --cov=chronoguard_sdk --cov-report=html

# Run specific test
pytest tests/test_client.py::TestChronoGuard::test_create_agent
```

### Code Quality

```bash
# Type checking
mypy chronoguard_sdk

# Linting
ruff check chronoguard_sdk

# Formatting
black chronoguard_sdk
isort chronoguard_sdk
```

## License

Apache-2.0 License. See [LICENSE](../../LICENSE) for details.

## Support

- Documentation: https://docs.chronoguard.com
- Issues: https://github.com/chronoguard/chronoguard/issues
- Discussions: https://github.com/chronoguard/chronoguard/discussions
