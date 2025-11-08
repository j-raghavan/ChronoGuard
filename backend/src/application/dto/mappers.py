"""Mappers for converting between domain entities and DTOs.

This module provides bidirectional mapping functions that transform domain entities
to DTOs for API responses and vice versa, following Clean Architecture principles.
"""

from __future__ import annotations

from uuid import UUID

from domain.agent.entity import Agent
from domain.audit.entity import AuditEntry
from domain.common.value_objects import X509Certificate
from domain.policy.entity import Policy, PolicyRule, RateLimit, TimeRestriction

from .agent_dto import AgentDTO, CreateAgentRequest
from .audit_dto import AuditEntryDTO, TimedAccessContextDTO
from .policy_dto import (
    CreatePolicyRequest,
    PolicyDTO,
    PolicyRuleDTO,
    RateLimitDTO,
    RuleConditionDTO,
    TimeRangeDTO,
    TimeRestrictionDTO,
)


class AgentMapper:
    """Mapper for Agent domain entity and DTOs."""

    @staticmethod
    def to_dto(agent: Agent) -> AgentDTO:
        """Convert Agent domain entity to AgentDTO.

        Args:
            agent: Domain agent entity

        Returns:
            AgentDTO for API response
        """
        return AgentDTO(
            agent_id=agent.agent_id,
            tenant_id=agent.tenant_id,
            name=agent.name,
            status=agent.status,  # Already a string due to use_enum_values=True
            certificate_fingerprint=agent.certificate.fingerprint_sha256,
            certificate_subject=agent.certificate.subject_common_name,
            certificate_expiry=agent.certificate.not_valid_after,
            policy_ids=agent.policy_ids.copy(),
            created_at=agent.created_at,
            updated_at=agent.updated_at,
            last_seen_at=agent.last_seen_at,
            metadata=agent.metadata.copy(),
            version=agent.version,
        )

    @staticmethod
    def from_create_request(request: CreateAgentRequest, tenant_id: UUID) -> Agent:
        """Convert CreateAgentRequest to Agent domain entity.

        Args:
            request: Create agent request from API
            tenant_id: Tenant ID for the new agent

        Returns:
            Agent domain entity ready to be persisted

        Raises:
            ValueError: If certificate PEM is invalid
        """
        certificate = X509Certificate(pem_data=request.certificate_pem)

        return Agent(
            tenant_id=tenant_id,
            name=request.name,
            certificate=certificate,
            metadata=request.metadata.copy(),
        )


class PolicyMapper:
    """Mapper for Policy domain entity and DTOs."""

    @staticmethod
    def to_dto(policy: Policy) -> PolicyDTO:
        """Convert Policy domain entity to PolicyDTO.

        Args:
            policy: Domain policy entity

        Returns:
            PolicyDTO for API response
        """
        # Convert rules
        rules_dto = [PolicyMapper._rule_to_dto(rule) for rule in policy.rules]

        # Convert time restrictions
        time_restrictions_dto = None
        if policy.time_restrictions:
            time_restrictions_dto = PolicyMapper._time_restriction_to_dto(policy.time_restrictions)

        # Convert rate limits
        rate_limits_dto = None
        if policy.rate_limits:
            rate_limits_dto = PolicyMapper._rate_limit_to_dto(policy.rate_limits)

        return PolicyDTO(
            policy_id=policy.policy_id,
            tenant_id=policy.tenant_id,
            name=policy.name,
            description=policy.description,
            rules=rules_dto,
            time_restrictions=time_restrictions_dto,
            rate_limits=rate_limits_dto,
            priority=policy.priority,
            status=policy.status,  # Already a string due to use_enum_values=True
            allowed_domains=sorted(policy.allowed_domains),  # Sort for consistency
            blocked_domains=sorted(policy.blocked_domains),
            created_at=policy.created_at,
            updated_at=policy.updated_at,
            created_by=policy.created_by,
            version=policy.version,
            metadata=policy.metadata.copy(),
        )

    @staticmethod
    def from_create_request(
        request: CreatePolicyRequest, tenant_id: UUID, created_by: UUID
    ) -> Policy:
        """Convert CreatePolicyRequest to Policy domain entity.

        Args:
            request: Create policy request from API
            tenant_id: Tenant ID for the new policy
            created_by: User ID creating the policy

        Returns:
            Policy domain entity ready to be persisted
        """
        return Policy(
            tenant_id=tenant_id,
            name=request.name,
            description=request.description,
            priority=request.priority,
            allowed_domains=set(request.allowed_domains),
            blocked_domains=set(request.blocked_domains),
            created_by=created_by,
            metadata=request.metadata.copy(),
        )

    @staticmethod
    def _rule_to_dto(rule: PolicyRule) -> PolicyRuleDTO:
        """Convert PolicyRule to PolicyRuleDTO.

        Args:
            rule: Domain policy rule

        Returns:
            PolicyRuleDTO for API response
        """
        conditions_dto = [
            RuleConditionDTO(
                field=cond.field,
                operator=cond.operator,
                value=cond.value,
            )
            for cond in rule.conditions
        ]

        return PolicyRuleDTO(
            rule_id=rule.rule_id,
            name=rule.name,
            description=rule.description,
            conditions=conditions_dto,
            action=rule.action,  # Already a string due to use_enum_values=True
            priority=rule.priority,
            enabled=rule.enabled,
            metadata=rule.metadata.copy(),
        )

    @staticmethod
    def _time_restriction_to_dto(restriction: TimeRestriction) -> TimeRestrictionDTO:
        """Convert TimeRestriction to TimeRestrictionDTO.

        Args:
            restriction: Domain time restriction

        Returns:
            TimeRestrictionDTO for API response
        """
        time_ranges_dto = [
            TimeRangeDTO(
                start_hour=tr.start_hour,
                start_minute=tr.start_minute,
                end_hour=tr.end_hour,
                end_minute=tr.end_minute,
            )
            for tr in restriction.allowed_time_ranges
        ]

        return TimeRestrictionDTO(
            allowed_time_ranges=time_ranges_dto,
            allowed_days_of_week=sorted(restriction.allowed_days_of_week),
            timezone=restriction.timezone,
            enabled=restriction.enabled,
        )

    @staticmethod
    def _rate_limit_to_dto(rate_limit: RateLimit) -> RateLimitDTO:
        """Convert RateLimit to RateLimitDTO.

        Args:
            rate_limit: Domain rate limit

        Returns:
            RateLimitDTO for API response
        """
        return RateLimitDTO(
            requests_per_minute=rate_limit.requests_per_minute,
            requests_per_hour=rate_limit.requests_per_hour,
            requests_per_day=rate_limit.requests_per_day,
            burst_limit=rate_limit.burst_limit,
            enabled=rate_limit.enabled,
        )


class AuditMapper:
    """Mapper for AuditEntry domain entity and DTOs."""

    @staticmethod
    def to_dto(entry: AuditEntry) -> AuditEntryDTO:
        """Convert AuditEntry domain entity to AuditEntryDTO.

        Args:
            entry: Domain audit entry entity

        Returns:
            AuditEntryDTO for API response
        """
        timed_context_dto = TimedAccessContextDTO(
            request_timestamp=entry.timed_access_metadata.request_timestamp,
            processing_timestamp=entry.timed_access_metadata.processing_timestamp,
            timezone_offset=entry.timed_access_metadata.timezone_offset,
            day_of_week=entry.timed_access_metadata.day_of_week,
            hour_of_day=entry.timed_access_metadata.hour_of_day,
            is_business_hours=entry.timed_access_metadata.is_business_hours,
            is_weekend=entry.timed_access_metadata.is_weekend,
            week_of_year=entry.timed_access_metadata.week_of_year,
            month_of_year=entry.timed_access_metadata.month_of_year,
            quarter_of_year=entry.timed_access_metadata.quarter_of_year,
        )

        return AuditEntryDTO(
            entry_id=entry.entry_id,
            tenant_id=entry.tenant_id,
            agent_id=entry.agent_id,
            timestamp=entry.timestamp,
            timestamp_nanos=entry.timestamp_nanos,
            domain=str(entry.domain),  # Convert DomainName to string
            decision=entry.decision,  # Already a string due to use_enum_values=True
            reason=entry.reason,
            policy_id=entry.policy_id,
            rule_id=entry.rule_id,
            request_method=entry.request_method,
            request_path=entry.request_path,
            user_agent=entry.user_agent,
            source_ip=entry.source_ip,
            response_status=entry.response_status,
            response_size_bytes=entry.response_size_bytes,
            processing_time_ms=entry.processing_time_ms,
            timed_access_metadata=timed_context_dto,
            previous_hash=entry.previous_hash,
            current_hash=entry.current_hash,
            sequence_number=entry.sequence_number,
            metadata=entry.metadata.copy(),
        )
