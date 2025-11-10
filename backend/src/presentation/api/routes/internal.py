"""Internal API routes for system-to-system communication.

These endpoints are not exposed to end users, only to internal services like OPA.
"""

from __future__ import annotations

import os
from typing import Annotated
from uuid import UUID

from application.dto.opa_dto import OPADecisionBatch, OPADecisionLog
from domain.audit.entity import AccessDecision
from domain.audit.service import AccessRequest, AuditService
from fastapi import APIRouter, Depends, Header, HTTPException, status
from loguru import logger
from presentation.api.dependencies import get_audit_service
from pydantic import BaseModel

router = APIRouter(prefix="/api/v1/internal", tags=["internal"])


class SeedResponse(BaseModel):
    """Response model for database seeding."""

    success: bool
    message: str
    agents_created: int = 0
    policies_created: int = 0
    audit_entries_created: int = 0


def verify_internal_auth(
    authorization: Annotated[str | None, Header()] = None,
) -> None:
    """Verify internal service authentication.

    Args:
        authorization: Bearer token from Authorization header

    Raises:
        HTTPException: 401 if authentication fails, 503 if auth not configured
    """
    expected_token = os.getenv("CHRONOGUARD_INTERNAL_SECRET")

    # SECURITY: Fail closed if secret is not configured
    if not expected_token:
        logger.error(
            "CHRONOGUARD_INTERNAL_SECRET not set - internal endpoints are disabled for security"
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "Internal service authentication not configured. "
                "Set CHRONOGUARD_INTERNAL_SECRET to enable."
            ),
        )

    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header",
        )

    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Authorization header format",
        )

    token = authorization[7:]  # Remove "Bearer " prefix

    if token != expected_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
        )


@router.post("/opa/decisions", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
async def ingest_opa_decision(
    decision: OPADecisionLog,
    audit_service: AuditService = Depends(get_audit_service),
    _auth: None = Depends(verify_internal_auth),
) -> None:
    """Ingest OPA decision log and create audit entry.

    This endpoint is called by OPA's decision_logs plugin to send
    authorization decisions for audit logging.

    Args:
        decision: OPA decision log entry
        audit_service: Injected audit service
        _auth: Authentication verification (dependency)

    Raises:
        HTTPException: 400 if decision format is invalid
    """
    try:
        # Extract data from OPA decision
        attrs = decision.input.attributes

        # Get agent ID from mTLS principal
        agent_id_str = attrs.source.get("principal", "unknown")

        # Get domain from request
        domain_str = attrs.request.get("http", {}).get("host", "unknown")

        # Get tenant ID from labels or metadata
        tenant_id_str = (
            decision.labels.get("tenant_id")
            or decision.envoy_metadata.get("tenant_id", "00000000-0000-0000-0000-000000000000")
            if decision.envoy_metadata
            else "00000000-0000-0000-0000-000000000000"
        )

        # Determine decision
        allow = decision.result.get("allow", False)
        access_decision = AccessDecision.ALLOW if allow else AccessDecision.DENY

        # Get reason from decision metadata
        reason = decision.result.get("reason", "Policy evaluation")

        # Create access request
        access_request = AccessRequest(
            tenant_id=UUID(tenant_id_str),
            agent_id=UUID(agent_id_str),
            domain=domain_str,
            decision=access_decision,
            reason=reason,
            request_method=attrs.request.get("http", {}).get("method", "GET"),
            request_path=attrs.request.get("http", {}).get("path", "/"),
            user_agent=attrs.request.get("http", {}).get("headers", {}).get("user-agent"),
            source_ip=attrs.source.get("address", {}).get("socketAddress", {}).get("address"),
        )

        # Record audit entry
        await audit_service.record_access(access_request)

        logger.debug(
            f"Recorded OPA decision: agent={agent_id_str}, "
            f"domain={domain_str}, decision={access_decision.value}"
        )

    except Exception as e:
        logger.opt(exception=True).error(f"Failed to ingest OPA decision: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to process OPA decision: {str(e)}",
        ) from e


@router.post("/opa/decisions/batch", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
async def ingest_opa_decision_batch(
    batch: OPADecisionBatch,
    audit_service: AuditService = Depends(get_audit_service),
    _auth: None = Depends(verify_internal_auth),
) -> None:
    """Ingest batch of OPA decision logs.

    Args:
        batch: Batch of OPA decision logs
        audit_service: Injected audit service
        _auth: Authentication verification

    Raises:
        HTTPException: 400 if any decision fails to process
    """
    errors = []

    for decision in batch.decisions:
        try:
            await ingest_opa_decision(decision, audit_service, _auth=None)
        except Exception as e:
            errors.append({"decision_id": decision.decision_id, "error": str(e)})

    if errors:
        logger.warning(f"Failed to process {len(errors)} decisions out of {len(batch.decisions)}")
        raise HTTPException(
            status_code=status.HTTP_207_MULTI_STATUS,
            detail={"processed": len(batch.decisions) - len(errors), "errors": errors},
        )


@router.post("/seed", response_model=SeedResponse)
async def seed_database(
    _auth: None = Depends(verify_internal_auth),
) -> SeedResponse:
    """Seed database with sample data for development.

    This endpoint is protected by internal service authentication only.
    Requires CHRONOGUARD_INTERNAL_SECRET to be set and provided via Authorization header.

    Args:
        tenant_id: Tenant ID from X-Tenant-ID header (uses default tenant)

    Returns:
        Seed operation results

    Raises:
        HTTPException: 500 if seeding fails
    """
    try:
        import secrets
        from datetime import UTC, datetime, timedelta

        from domain.agent.entity import AgentStatus
        from domain.audit.entity import AccessDecision
        from domain.policy.entity import PolicyStatus
        from infrastructure.persistence.models import AgentModel, AuditEntryModel, PolicyModel
        from presentation.api.dependencies import get_agent_repository
        from sqlalchemy import text

        # Use the default tenant and user IDs
        default_tenant_id = UUID("550e8400-e29b-41d4-a716-446655440001")
        user_id = UUID("550e8400-e29b-41d4-a716-446655440002")

        # Use the existing repository's session factory to ensure correct DB connection
        agent_repo = get_agent_repository()
        session_factory = agent_repo._session_factory

        # Valid certificate
        sample_cert = """-----BEGIN CERTIFICATE-----
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

        async with session_factory() as session:
            # Check if data already exists
            result = await session.execute(text("SELECT COUNT(*) FROM agents"))
            agent_count = result.scalar()
            if agent_count and agent_count > 0:
                return SeedResponse(
                    success=False,
                    message=f"Database already contains {agent_count} agents. Clear it first.",
                )

            # Create 8 agents
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
            agent_ids = []
            now = datetime.now(UTC)

            for i, name in enumerate(agent_names):
                agent_id = UUID(int=secrets.randbits(128))
                status = (
                    AgentStatus.ACTIVE
                    if i < 3
                    else AgentStatus.PENDING if i < 5 else AgentStatus.SUSPENDED
                )

                agent = AgentModel(
                    agent_id=agent_id,
                    tenant_id=default_tenant_id,
                    name=name,
                    certificate_pem=sample_cert,
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
                        "environment": "production" if i < 3 else "staging",
                        "team": "qa",
                    },
                    version=1,
                )
                session.add(agent)
                agent_ids.append(agent_id)

            await session.commit()

            # Create 4 policies
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

            policy_ids = []
            for policy_data in policies_data:
                policy_id = UUID(int=secrets.randbits(128))
                policy = PolicyModel(
                    policy_id=policy_id,
                    tenant_id=default_tenant_id,
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
                    created_by=user_id,
                    version=1,
                    policy_metadata={"environment": "production"},
                )
                session.add(policy)
                policy_ids.append(policy_id)

            await session.commit()

            # Associate first 4 agents with first 2 policies
            for agent_id in agent_ids[:4]:
                agent = await session.get(AgentModel, agent_id)
                if agent:
                    agent.policy_ids = [policy_ids[0], policy_ids[1]]
            await session.commit()

            # Create ~2000 audit entries
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
                            AccessDecision.ALLOW
                            if secrets.randbelow(100) > 10
                            else AccessDecision.DENY
                        )
                        domain = secrets.choice(domains)

                        if domain in ["admin.example.com"] and decision == AccessDecision.ALLOW:
                            decision = AccessDecision.DENY

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

                        api_endpoints = ["users", "products", "orders", "analytics"]
                        chosen_endpoint = secrets.choice(api_endpoints)
                        request_methods = ["GET", "POST", "PUT", "DELETE"]

                        entry = AuditEntryModel(
                            entry_id=UUID(int=secrets.randbits(128)),
                            tenant_id=default_tenant_id,
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
                            request_method=secrets.choice(request_methods),
                            request_path=f"/api/v1/{chosen_endpoint}",
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

            logger.info(
                f"Database seeded successfully: {len(agent_ids)} agents, "
                f"{len(policy_ids)} policies, {entries_created} audit entries"
            )

            return SeedResponse(
                success=True,
                message="Database seeded successfully with sample data",
                agents_created=len(agent_ids),
                policies_created=len(policy_ids),
                audit_entries_created=entries_created,
            )

    except Exception as e:
        logger.opt(exception=True).error(f"Failed to seed database: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to seed database: {str(e)}",
        ) from e
