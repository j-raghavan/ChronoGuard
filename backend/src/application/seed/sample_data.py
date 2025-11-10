"""Sample data seeding utilities."""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID

from loguru import logger
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from domain.agent.entity import AgentStatus
from domain.audit.entity import AccessDecision
from domain.policy.entity import PolicyStatus
from infrastructure.persistence.models import AgentModel, AuditEntryModel, PolicyModel


DEFAULT_TENANT_ID = UUID("550e8400-e29b-41d4-a716-446655440001")
DEFAULT_USER_ID = UUID("550e8400-e29b-41d4-a716-446655440002")

SAMPLE_CERT = """-----BEGIN CERTIFICATE-----
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


@dataclass(slots=True)
class SeedStats:
    """Summary of created records."""

    agents_created: int
    policies_created: int
    audit_entries_created: int


class SeedPreconditionError(RuntimeError):
    """Raised when the database already contains data."""


async def seed_sample_data(
    session_factory: async_sessionmaker[AsyncSession],
) -> SeedStats:
    """Populate the database with deterministic demo data."""

    async with session_factory() as session:
        await _ensure_database_empty(session)

        now = datetime.now(UTC)
        agent_ids = await _seed_agents(session, now)
        policy_ids = await _seed_policies(session, now)
        await _assign_policies_to_agents(session, agent_ids, policy_ids)
        entries_created = await _seed_audit_entries(session, now, agent_ids, policy_ids)

    logger.info(
        "Database seeded with sample data",
        agents=len(agent_ids),
        policies=len(policy_ids),
        audit_entries=entries_created,
    )

    return SeedStats(
        agents_created=len(agent_ids),
        policies_created=len(policy_ids),
        audit_entries_created=entries_created,
    )


async def _ensure_database_empty(session: AsyncSession) -> None:
    result = await session.execute(text("SELECT COUNT(*) FROM agents"))
    agent_count = result.scalar() or 0
    if agent_count > 0:
        raise SeedPreconditionError(
            f"Database already contains {agent_count} agents. Clear it before seeding."
        )


async def _seed_agents(session: AsyncSession, now: datetime) -> list[UUID]:
    agent_names = [
        "qa-agent-prod-01",
        "qa-agent-prod-02",
        "qa-agent-staging-01",
        "monitoring-agent-01",
        "analytics-agent-01",
        "test-agent-dev-01",
        "test-agent-dev-02",
        "production-scraper-01",
    ]

    agent_ids: list[UUID] = []
    for index, name in enumerate(agent_names):
        agent_id = UUID(int=secrets.randbits(128))
        status = (
            AgentStatus.ACTIVE
            if index < 3
            else AgentStatus.PENDING
            if index < 5
            else AgentStatus.SUSPENDED
        )

        agent = AgentModel(
            agent_id=agent_id,
            tenant_id=DEFAULT_TENANT_ID,
            name=name,
            certificate_pem=SAMPLE_CERT,
            status=status,
            policy_ids=[],
            created_at=now - timedelta(days=secrets.randbelow(30) + 1),
            updated_at=now - timedelta(days=secrets.randbelow(8)),
            last_seen_at=(
                now - timedelta(hours=secrets.randbelow(25))
                if status == AgentStatus.ACTIVE
                else None
            ),
            agent_metadata={
                "environment": "production" if index < 3 else "staging",
                "team": "qa",
            },
            version=1,
        )
        session.add(agent)
        agent_ids.append(agent_id)

    await session.commit()
    return agent_ids


async def _seed_policies(session: AsyncSession, now: datetime) -> list[UUID]:
    policies_data = [
        {
            "name": "Production Access Policy",
            "description": "Allows access to production domains during business hours",
            "allowed_domains": [
                "production.example.com",
                "api.example.com",
                "secure.example.com",
            ],
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
        {
            "name": "Development Policy",
            "description": "Open access policy for development environments",
            "allowed_domains": ["example.com", "test.example.com", "staging.example.com"],
            "blocked_domains": ["production.example.com"],
            "priority": 500,
        },
    ]

    policy_ids: list[UUID] = []
    for policy_data in policies_data:
        policy_id = UUID(int=secrets.randbits(128))
        policy = PolicyModel(
            policy_id=policy_id,
            tenant_id=DEFAULT_TENANT_ID,
            name=policy_data["name"],
            description=policy_data["description"],
            rules=[],
            time_restrictions=None,
            rate_limits=None,
            priority=policy_data["priority"],
            status=PolicyStatus.ACTIVE,
            allowed_domains=policy_data["allowed_domains"],
            blocked_domains=policy_data["blocked_domains"],
            created_at=now - timedelta(days=secrets.randbelow(60) + 1),
            updated_at=now - timedelta(days=secrets.randbelow(15)),
            created_by=DEFAULT_USER_ID,
            version=1,
            policy_metadata={"environment": "production"},
        )
        session.add(policy)
        policy_ids.append(policy_id)

    await session.commit()
    return policy_ids


async def _assign_policies_to_agents(
    session: AsyncSession, agent_ids: list[UUID], policy_ids: list[UUID]
) -> None:
    for agent_id in agent_ids[:4]:
        agent = await session.get(AgentModel, agent_id)
        if agent:
            agent.policy_ids = policy_ids[:2]

    await session.commit()


async def _seed_audit_entries(
    session: AsyncSession,
    now: datetime,
    agent_ids: list[UUID],
    policy_ids: list[UUID],
) -> int:
    domains = [
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

    entries_created = 0
    for day_offset in range(7):
        base_time = now - timedelta(days=day_offset)
        for hour in range(24):
            entries_per_hour = (
                secrets.randbelow(26) + 15 if 9 <= hour <= 17 else secrets.randbelow(9) + 2
            )

            for _ in range(entries_per_hour):
                entry_time = base_time.replace(
                    hour=hour,
                    minute=secrets.randbelow(60),
                    second=secrets.randbelow(60),
                )
                agent_id = secrets.choice(agent_ids)
                selected_policy_id: UUID | None = (
                    secrets.choice(policy_ids) if secrets.randbelow(100) > 20 else None
                )
                decision = (
                    AccessDecision.ALLOW if secrets.randbelow(100) > 10 else AccessDecision.DENY
                )
                domain = secrets.choice(domains)

                if domain == "admin.example.com" and decision == AccessDecision.ALLOW:
                    decision = AccessDecision.DENY

                timed_metadata = _build_timed_access_metadata(entry_time, hour)

                entry = AuditEntryModel(
                    entry_id=UUID(int=secrets.randbits(128)),
                    tenant_id=DEFAULT_TENANT_ID,
                    agent_id=agent_id,
                    timestamp=entry_time,
                    timestamp_nanos=int(entry_time.timestamp() * 1e9),
                    domain=domain,
                    decision=decision,
                    reason=(
                        "Policy rule matched"
                        if decision == AccessDecision.ALLOW
                        else "Domain blocked"
                    ),
                    policy_id=selected_policy_id,
                    rule_id=None,
                    request_method=secrets.choice(["GET", "POST", "PUT", "DELETE"]),
                    request_path=(
                        f"/api/v1/{secrets.choice(['users', 'products', 'orders', 'analytics'])}"
                    ),
                    user_agent="ChronoGuard-Agent/1.0",
                    source_ip=f"192.168.1.{secrets.randbelow(255) + 1}",
                    response_status=200 if decision == AccessDecision.ALLOW else 403,
                    response_size_bytes=secrets.randbelow(9901) + 100,
                    processing_time_ms=secrets.randbelow(49001) / 100 + 10,
                    timed_access_metadata=timed_metadata,
                    previous_hash="",
                    current_hash="",
                    sequence_number=entries_created,
                    entry_metadata={"source": "api_seed"},
                )
                session.add(entry)
                entries_created += 1

    await session.commit()
    return entries_created


def _build_timed_access_metadata(entry_time: datetime, hour: int) -> dict[str, int | bool | str]:
    is_business_hours = 9 <= hour < 17 and entry_time.weekday() < 5
    is_weekend = entry_time.weekday() >= 5
    return {
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
