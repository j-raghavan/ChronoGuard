"""Audit query handlers for read operations.

This module implements query handlers for audit log retrieval, following CQRS principles
and Clean Architecture.
"""

from __future__ import annotations

from domain.audit.entity import AccessDecision
from domain.audit.repository import AuditRepository

from ..dto import AuditListResponse, AuditMapper, AuditQueryRequest


class GetAuditEntriesQuery:
    """Query handler for retrieving audit entries with filtering."""

    def __init__(self, audit_repository: AuditRepository) -> None:
        """Initialize get audit entries query.

        Args:
            audit_repository: Repository for audit persistence
        """
        self._repository = audit_repository

    async def execute(self, request: AuditQueryRequest) -> AuditListResponse:
        """Retrieve audit entries with filtering and pagination.

        Args:
            request: Query request with filters and pagination

        Returns:
            Paginated list of audit entries

        Raises:
            ValueError: If query parameters are invalid
        """
        # Validate pagination
        if request.page < 1:
            raise ValueError(f"Page must be >= 1, got {request.page}")
        if request.page_size < 1 or request.page_size > 1000:
            raise ValueError(f"Page size must be between 1 and 1000, got {request.page_size}")

        # Calculate offset
        offset = (request.page - 1) * request.page_size

        # Determine query strategy based on filters
        entries = await self._query_with_filters(request, offset)

        # Get total count
        total_count = await self._count_with_filters(request)

        # Convert to DTOs
        entry_dtos = [AuditMapper.to_dto(entry) for entry in entries]

        # Calculate has_more
        has_more = (offset + len(entry_dtos)) < total_count

        return AuditListResponse(
            entries=entry_dtos,
            total_count=total_count,
            page=request.page,
            page_size=request.page_size,
            has_more=has_more,
        )

    async def _query_with_filters(self, request: AuditQueryRequest, offset: int) -> list:
        """Query audit entries with applied filters.

        Args:
            request: Query request with filters
            offset: Pagination offset

        Returns:
            List of audit entries matching filters
        """
        # Time-based query (most common)
        if request.start_time and request.end_time:
            if request.agent_id:
                return await self._repository.find_by_agent_time_range(
                    agent_id=request.agent_id,
                    start_time=request.start_time,
                    end_time=request.end_time,
                    limit=request.page_size,
                    offset=offset,
                )
            if request.tenant_id:
                return await self._repository.find_by_tenant_time_range(
                    tenant_id=request.tenant_id,
                    start_time=request.start_time,
                    end_time=request.end_time,
                    limit=request.page_size,
                    offset=offset,
                )

        # Decision-based query
        if request.decision and request.tenant_id:
            decision = AccessDecision(request.decision)
            return await self._repository.find_by_decision(
                tenant_id=request.tenant_id,
                decision=decision,
                limit=request.page_size,
                offset=offset,
            )

        # Default: query by tenant with time range
        if request.tenant_id and request.start_time and request.end_time:
            return await self._repository.find_by_tenant_time_range(
                tenant_id=request.tenant_id,
                start_time=request.start_time,
                end_time=request.end_time,
                limit=request.page_size,
                offset=offset,
            )

        return []

    async def _count_with_filters(self, request: AuditQueryRequest) -> int:
        """Count audit entries with applied filters.

        Args:
            request: Query request with filters

        Returns:
            Total count of entries matching filters
        """
        # Time-based counts (most common)
        if request.start_time and request.end_time:
            if request.agent_id and request.tenant_id:
                return await self._repository.count_entries_by_agent_time_range(
                    tenant_id=request.tenant_id,
                    agent_id=request.agent_id,
                    start_time=request.start_time,
                    end_time=request.end_time,
                )

            if request.tenant_id:
                return await self._repository.count_entries_by_tenant(
                    request.tenant_id,
                    start_time=request.start_time,
                    end_time=request.end_time,
                )

        # Decision-based counts (supports optional time filters)
        if request.decision and request.tenant_id:
            decision = AccessDecision(request.decision)
            return await self._repository.count_entries_by_decision(
                tenant_id=request.tenant_id,
                decision=decision,
                start_time=request.start_time,
                end_time=request.end_time,
            )

        # Fallback to tenant-wide total when no filters supplied
        if request.tenant_id:
            return await self._repository.count_entries_by_tenant(request.tenant_id)

        return 0
