"""Database seeding script for development and demo purposes.

This script populates the database with sample agents, policies, and audit entries
to make the frontend dashboard functional and visually appealing.
"""

import asyncio
import random
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from core.database import get_database_url
from domain.agent.entity import AgentStatus
from domain.audit.entity import AccessDecision
from domain.policy.entity import PolicyStatus
from infrastructure.persistence.models import AgentModel, AuditEntryModel, PolicyModel


# Sample certificate for agents (valid self-signed certificate for development)
SAMPLE_CERTIFICATE = """-----BEGIN CERTIFICATE-----
MIIDmTCCAoGgAwIBAgIUVzCzzoj3dE8QMg+I1ucQsVWqg5QwDQYJKoZIhvcNAQEL
BQAwXDELMAkGA1UEBhMCVVMxDTALBgNVBAgMBFRlc3QxDTALBgNVBAcMBFRlc3Qx
FDASBgNVBAoMC0Nocm9ub0d1YXJkMRkwFwYDVQQDDBB0ZXN0LWFnZW50LmxvY2Fs
MB4XDTI1MTEwOTA3MDczM1oXDTI2MTEwOTA3MDczM1owXDELMAkGA1UEBhMCVVMx
DTALBgNVBAgMBFRlc3QxDTALBgNVBAcMBFRlc3QxFDASBgNVBAoMC0Nocm9ub0d1
YXJkMRkwFwYDVQQDDBB0ZXN0LWFnZW50LmxvY2FsMIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEAo39GuLgTnDBVYNqjGEDbuuq+/zl97ELxWaZAbHKu1ehQ
NOLn3+CqNDcVVnZaEMQWEKAucJZLD92egLZ+GOCKf+k4q3svbcg2K1gGMFnmdGcl
2ueM1yuduC0PJfx7+lF3QtEhYsHunToUDc8nSP4fVmncvM0TJbdRDRKiTnYZ7+E2
B/EegdmgQwphHyG9eXNi7n3gLWGcp8zY388rVWVSs3nHiVN59M+BQcdQF+UGEdaN
i11XOUBJynhCOMgWEnp52ROAvbpsmue+g2Eo5Q04ggXnkhLrnxkEJ/5CiGBgJaGo
YsbAfPCowG3JpRmNUGk3rkg8/Hpy88X1/RapJ1isNwIDAQABo1MwUTAdBgNVHQ4E
FgQU/FIZBclstLAq6NDO4cwzYVxaL1wwHwYDVR0jBBgwFoAU/FIZBclstLAq6NDO
4cwzYVxaL1wwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAjihn
1XhxHDMwoShHLS4r9Z9SaLTU/uNT2lzR1mzTehwHcch9U3oeQN9NOu/6VVe2cNYh
f0ZPrbXpOHJM3kOd3DaMVaIyxS1WhrKkBIX5jfAI5H5V8iweb5X6dTsjzeKzN7YX
4606otcZ5nM7TUszZXn/C8U+hc/MMhkMQv+JRyuZCj6vXV//Z7C/Xpf1q6jWsZcJ
cHK0V6PC/gJEm/c6kW5BaM6NVZufZ4pIPdn7/Srbvj5uc1DPKkEaBEr8WUMj63sE
Zu8qdGp0ahoIioV1FjY0ES6S2Od5xDktDuw/dmT1Lu2smoX8fC0d8QMxhuQXJey3
7RjLHmsOMWx00eg/Xw==
-----END CERTIFICATE-----"""

# Sample domains for policies and audit entries
SAMPLE_DOMAINS = [
    "example.com",
    "test.example.com",
    "api.example.com",
    "staging.example.com",
    "production.example.com",
    "admin.example.com",
    "dashboard.example.com",
    "monitoring.example.com",
    "analytics.example.com",
    "secure.example.com",
]

# Sample agent names - demo-agent-001 MUST be first to match demo certificates
AGENT_NAMES = [
    "demo-agent-001",  # Primary demo agent - matches playground/demo-certs
    "demo-agent-002",  # Secondary demo agent with time restrictions
    "qa-agent-prod-01",
    "qa-agent-staging-01",
    "monitoring-agent-01",
    "analytics-agent-01",
]

# Sample policy data - Demo Policy MUST be first to match OPA seed
POLICIES = [
    {
        "name": "Demo Agent Policy",
        "description": "Demo policy for demo-agent-001",
        "allowed_domains": [
            "example.com",
            "httpbin.org",
            "api.github.com",
            "api.openai.com",
        ],
        "blocked_domains": [],
        "priority": 50,
    },
    {
        "name": "Production Access Policy",
        "description": "Allows access to production domains during business hours",
        "allowed_domains": ["production.example.com", "api.example.com", "secure.example.com"],
        "blocked_domains": ["admin.example.com"],
        "priority": 100,
    },
    {
        "name": "Staging Environment Policy",
        "description": "Access policy for staging and testing environments",
        "allowed_domains": ["staging.example.com", "test.example.com"],
        "blocked_domains": [],
        "priority": 200,
    },
    {
        "name": "Monitoring Dashboard Policy",
        "description": "Allows access to monitoring and analytics dashboards",
        "allowed_domains": [
            "monitoring.example.com",
            "analytics.example.com",
            "dashboard.example.com",
        ],
        "blocked_domains": [],
        "priority": 300,
    },
]


async def create_sample_agents(session: AsyncSession, tenant_id: UUID, user_id: UUID) -> list[UUID]:
    """Create sample agents.

    Args:
        session: Database session
        tenant_id: Tenant ID
        user_id: User ID for created_by

    Returns:
        List of created agent IDs
    """
    agent_ids = []
    now = datetime.now(UTC)

    for i, name in enumerate(AGENT_NAMES):
        agent_id = uuid4()
        # Mix of statuses
        if i < 3:
            status = AgentStatus.ACTIVE
        elif i < 5:
            status = AgentStatus.PENDING
        else:
            status = AgentStatus.SUSPENDED

        # Calculate last_seen_at based on status
        last_seen = None
        if status == AgentStatus.ACTIVE:
            last_seen = now - timedelta(hours=random.randint(0, 24))  # noqa: S311

        agent = AgentModel(
            agent_id=agent_id,
            tenant_id=tenant_id,
            name=name,
            certificate_pem=SAMPLE_CERTIFICATE,
            status=status,
            policy_ids=[],
            created_at=now - timedelta(days=random.randint(1, 30)),  # noqa: S311
            updated_at=now - timedelta(days=random.randint(0, 7)),  # noqa: S311
            last_seen_at=last_seen,
            agent_metadata={
                "environment": "production" if i < 3 else "staging",
                "team": "qa",
            },
            version=1,
        )
        session.add(agent)
        agent_ids.append(agent_id)

    await session.commit()
    print(f"✓ Created {len(agent_ids)} agents")
    return agent_ids


async def create_sample_policies(
    session: AsyncSession, tenant_id: UUID, user_id: UUID, agent_ids: list[UUID]
) -> list[UUID]:
    """Create sample policies.

    Args:
        session: Database session
        tenant_id: Tenant ID
        user_id: User ID for created_by
        agent_ids: List of agent IDs to associate with policies

    Returns:
        List of created policy IDs
    """
    policy_ids = []
    now = datetime.now(UTC)

    for policy_data in POLICIES:
        policy_id = uuid4()
        policy = PolicyModel(
            policy_id=policy_id,
            tenant_id=tenant_id,
            name=policy_data["name"],
            description=policy_data["description"],
            rules=[],
            time_restrictions=None,
            rate_limits=None,
            priority=policy_data["priority"],
            status=PolicyStatus.ACTIVE,
            allowed_domains=policy_data["allowed_domains"],
            blocked_domains=policy_data["blocked_domains"],
            created_at=now - timedelta(days=random.randint(1, 60)),  # noqa: S311
            updated_at=now - timedelta(days=random.randint(0, 14)),  # noqa: S311
            created_by=user_id,
            version=1,
            policy_metadata={"environment": "production"},
        )
        session.add(policy)
        policy_ids.append(policy_id)

    await session.commit()
    print(f"✓ Created {len(policy_ids)} policies")

    # Associate some agents with policies
    for agent_id in agent_ids[:4]:  # First 4 agents
        agent = await session.get(AgentModel, agent_id)
        if agent:
            agent.policy_ids = [policy_ids[0], policy_ids[1]]  # Associate with first 2 policies
    await session.commit()
    print("✓ Associated agents with policies")

    return policy_ids


async def create_sample_audit_entries(
    session: AsyncSession,
    tenant_id: UUID,
    agent_ids: list[UUID],
    policy_ids: list[UUID],
    days_back: int = 7,
) -> None:
    """Create sample audit entries for analytics.

    Args:
        session: Database session
        tenant_id: Tenant ID
        agent_ids: List of agent IDs
        policy_ids: List of policy IDs
        days_back: Number of days to generate data for
    """
    now = datetime.now(UTC)
    entries_created = 0

    # Generate entries for the last N days
    for day_offset in range(days_back):
        base_time = now - timedelta(days=day_offset)

        # Generate entries throughout the day (more during business hours)
        for hour in range(24):
            # More activity during business hours (9 AM - 5 PM)
            entries_per_hour = (
                random.randint(15, 40)  # noqa: S311
                if 9 <= hour <= 17
                else random.randint(2, 10)  # noqa: S311
            )

            for _ in range(entries_per_hour):
                minute = random.randint(0, 59)  # noqa: S311
                second = random.randint(0, 59)  # noqa: S311
                entry_time = base_time.replace(hour=hour, minute=minute, second=second)
                agent_id = random.choice(agent_ids)  # noqa: S311
                has_policy = random.random() > 0.2  # noqa: S311
                policy_id = random.choice(policy_ids) if has_policy else None  # noqa: S311

                # 90% allow, 10% deny
                is_allowed = random.random() > 0.1  # noqa: S311
                decision = AccessDecision.ALLOW if is_allowed else AccessDecision.DENY
                domain = random.choice(SAMPLE_DOMAINS)  # noqa: S311

                # Deny blocked domains
                if domain in ["admin.example.com"] and decision == AccessDecision.ALLOW:
                    decision = AccessDecision.DENY

                # Create complete timed access metadata
                is_business_hours = 9 <= hour < 17 and entry_time.weekday() < 5
                is_weekend = entry_time.weekday() >= 5
                timed_metadata = {
                    "request_timestamp": entry_time.isoformat(),
                    "processing_timestamp": entry_time.isoformat(),
                    "timezone_offset": 0,
                    "day_of_week": entry_time.weekday(),
                    "hour_of_day": hour,
                    "is_business_hours": is_business_hours,
                    "is_weekend": is_weekend,
                    "week_of_year": entry_time.isocalendar()[1],
                    "month_of_year": entry_time.month,
                    "quarter_of_year": (entry_time.month - 1) // 3 + 1,
                }

                # Generate random request details
                method = random.choice(["GET", "POST", "PUT", "DELETE"])  # noqa: S311
                paths = ["users", "products", "orders", "analytics"]
                path = random.choice(paths)  # noqa: S311
                ip_suffix = random.randint(1, 255)  # noqa: S311
                resp_size = random.randint(100, 10000)  # noqa: S311
                proc_time = random.uniform(10, 500)  # noqa: S311

                # Determine reason based on decision
                if decision == AccessDecision.ALLOW:
                    reason = "Policy rule matched"
                else:
                    reason = "Domain blocked"

                entry = AuditEntryModel(
                    entry_id=uuid4(),
                    tenant_id=tenant_id,
                    agent_id=agent_id,
                    timestamp=entry_time,
                    timestamp_nanos=int(entry_time.timestamp() * 1e9),
                    domain=domain,
                    decision=decision,
                    reason=reason,
                    policy_id=policy_id,
                    rule_id=None,
                    request_method=method,
                    request_path=f"/api/v1/{path}",
                    user_agent="ChronoGuard-Agent/1.0",
                    source_ip=f"192.168.1.{ip_suffix}",
                    response_status=200 if decision == AccessDecision.ALLOW else 403,
                    response_size_bytes=resp_size,
                    processing_time_ms=proc_time,
                    timed_access_metadata=timed_metadata,
                    previous_hash="",
                    current_hash="",
                    sequence_number=entries_created,
                    entry_metadata={"source": "seed_script"},
                )
                session.add(entry)
                entries_created += 1

    await session.commit()
    print(f"✓ Created {entries_created} audit entries")


async def seed_database() -> None:
    """Main seeding function."""
    # Default tenant and user IDs (can be overridden via environment)
    tenant_id = UUID("550e8400-e29b-41d4-a716-446655440001")
    user_id = UUID("550e8400-e29b-41d4-a716-446655440002")

    # Get database URL
    db_url = get_database_url()
    if db_url.startswith("postgresql://"):
        db_url = db_url.replace("postgresql://", "postgresql+asyncpg://", 1)

    engine = create_async_engine(db_url, echo=False)
    async_session = async_sessionmaker(engine, expire_on_commit=False)

    print("🌱 Starting database seeding...")
    print(f"   Tenant ID: {tenant_id}")
    print(f"   User ID: {user_id}")

    async with async_session() as session:
        try:
            # Check if data already exists
            result = await session.execute(text("SELECT COUNT(*) FROM agents"))
            agent_count = result.scalar() or 0
            if agent_count > 0:
                print(f"⚠️  Database already contains {agent_count} agents. Skipping seed.")
                print("   To re-seed, clear the database first.")
                return

            # Create agents
            agent_ids = await create_sample_agents(session, tenant_id, user_id)

            # Create policies
            policy_ids = await create_sample_policies(session, tenant_id, user_id, agent_ids)

            # Create audit entries
            await create_sample_audit_entries(
                session, tenant_id, agent_ids, policy_ids, days_back=7
            )

            print("\n✅ Database seeding completed successfully!")
            print(f"   - {len(agent_ids)} agents")
            print(f"   - {len(policy_ids)} policies")
            print("   - ~2000+ audit entries")
            print("\n💡 Make sure to set these IDs in your frontend localStorage:")
            print(f"   localStorage.setItem('tenantId', '{tenant_id}')")
            print(f"   localStorage.setItem('userId', '{user_id}')")

        except Exception as e:
            print(f"\n❌ Error seeding database: {e}")
            await session.rollback()
            raise
        finally:
            await engine.dispose()


if __name__ == "__main__":
    asyncio.run(seed_database())
