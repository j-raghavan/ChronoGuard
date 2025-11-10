"""Internal API routes for system-to-system communication.

These endpoints are not exposed to end users, only to internal services like OPA.
"""

from __future__ import annotations

import os
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, status
from loguru import logger
from pydantic import BaseModel

from application.dto.opa_dto import OPADecisionBatch, OPADecisionLog
from application.seed import SeedPreconditionError, seed_sample_data
from domain.audit.entity import AccessDecision
from domain.audit.service import AccessRequest, AuditService
from presentation.api.dependencies import get_audit_service


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
    """Seed database with sample data for development."""

    try:
        from presentation.api.dependencies import get_agent_repository

        agent_repo = get_agent_repository()
        stats = await seed_sample_data(agent_repo.session_factory)
        return SeedResponse(
            success=True,
            message="Database seeded successfully with sample data",
            agents_created=stats.agents_created,
            policies_created=stats.policies_created,
            audit_entries_created=stats.audit_entries_created,
        )
    except SeedPreconditionError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc
    except Exception as e:
        logger.opt(exception=True).error(f"Failed to seed database: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to seed database: {str(e)}",
        ) from e
