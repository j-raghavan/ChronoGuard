"""SQLAlchemy models for ChronoGuard persistence layer.

This module defines database models with TimescaleDB support for time-series optimization.
These models are tested via integration tests with real PostgreSQL/TimescaleDB.
"""

from sqlalchemy import BigInteger, Column, DateTime, Enum, Float, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import DeclarativeBase

from domain.agent.entity import AgentStatus
from domain.audit.entity import AccessDecision
from domain.policy.entity import PolicyStatus


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy models."""

    pass


class AgentModel(Base):
    """SQLAlchemy model for Agent entity.

    Tested via integration tests in tests/integration/test_agent_repository_integration.py
    """

    __tablename__ = "agents"

    agent_id = Column(PG_UUID(as_uuid=True), primary_key=True)
    tenant_id = Column(PG_UUID(as_uuid=True), nullable=False, index=True)
    name = Column(String(100), nullable=False)
    certificate_pem = Column(Text, nullable=False)
    status: Column[AgentStatus] = Column(
        Enum(AgentStatus), nullable=False, default=AgentStatus.PENDING, index=True
    )
    policy_ids: Column[list] = Column(ARRAY(PG_UUID(as_uuid=True)), nullable=False, default=list)
    created_at = Column(DateTime(timezone=True), nullable=False)
    updated_at = Column(DateTime(timezone=True), nullable=False)
    last_seen_at = Column(DateTime(timezone=True), nullable=True)
    agent_metadata = Column(JSONB, nullable=False, default=dict)
    version = Column(Integer, nullable=False, default=1)

    __table_args__ = (
        Index("ix_agent_tenant_name", "tenant_id", "name", unique=True),
        Index("ix_agent_tenant_status", "tenant_id", "status"),
        Index("ix_agent_metadata_gin", "agent_metadata", postgresql_using="gin"),
    )


class PolicyModel(Base):
    """SQLAlchemy model for Policy entity.

    Tested via integration tests in tests/integration/test_policy_repository_integration.py
    """

    __tablename__ = "policies"

    policy_id = Column(PG_UUID(as_uuid=True), primary_key=True)
    tenant_id = Column(PG_UUID(as_uuid=True), nullable=False, index=True)
    name = Column(String(100), nullable=False)
    description = Column(Text, nullable=False)
    rules = Column(JSONB, nullable=False, default=list)
    time_restrictions = Column(JSONB, nullable=True)
    rate_limits = Column(JSONB, nullable=True)
    priority = Column(Integer, nullable=False, default=500)
    status: Column[PolicyStatus] = Column(
        Enum(PolicyStatus), nullable=False, default=PolicyStatus.DRAFT, index=True
    )
    allowed_domains: Column[list] = Column(ARRAY(String(255)), nullable=False, default=list)
    blocked_domains: Column[list] = Column(ARRAY(String(255)), nullable=False, default=list)
    created_at = Column(DateTime(timezone=True), nullable=False)
    updated_at = Column(DateTime(timezone=True), nullable=False)
    created_by = Column(PG_UUID(as_uuid=True), nullable=False)
    version = Column(Integer, nullable=False, default=1)
    policy_metadata = Column(JSONB, nullable=False, default=dict)

    __table_args__ = (
        Index("ix_policy_tenant_name", "tenant_id", "name", unique=True),
        Index("ix_policy_tenant_status", "tenant_id", "status"),
        Index("ix_policy_tenant_priority", "tenant_id", "priority"),
        Index("ix_policy_metadata_gin", "policy_metadata", postgresql_using="gin"),
        Index("ix_policy_rules_gin", "rules", postgresql_using="gin"),
    )


class AuditEntryModel(Base):
    """SQLAlchemy model for AuditEntry entity with TimescaleDB hypertable support.

    This table is converted to a TimescaleDB hypertable for efficient time-series queries.
    Tested via integration tests in tests/integration/test_audit_repository_integration.py
    """

    __tablename__ = "audit_entries"

    entry_id = Column(PG_UUID(as_uuid=True), primary_key=True)
    tenant_id = Column(PG_UUID(as_uuid=True), nullable=False, index=True)
    agent_id = Column(PG_UUID(as_uuid=True), nullable=False, index=True)
    timestamp = Column(DateTime(timezone=True), nullable=False, primary_key=True)
    timestamp_nanos = Column(BigInteger, nullable=False)
    domain = Column(String(500), nullable=False)
    decision: Column[AccessDecision] = Column(Enum(AccessDecision), nullable=False, index=True)
    reason = Column(Text, nullable=True)
    policy_id = Column(PG_UUID(as_uuid=True), nullable=True, index=True)
    rule_id = Column(PG_UUID(as_uuid=True), nullable=True)
    request_method = Column(String(10), nullable=True)
    request_path = Column(String(2000), nullable=True)
    user_agent = Column(String(500), nullable=True)
    source_ip = Column(String(45), nullable=True)
    response_status = Column(Integer, nullable=True)
    response_size_bytes = Column(BigInteger, nullable=True)
    processing_time_ms = Column(Float, nullable=True)
    timed_access_metadata = Column(JSONB, nullable=False)
    previous_hash = Column(String(64), nullable=False, default="")
    current_hash = Column(String(64), nullable=False, default="")
    sequence_number = Column(BigInteger, nullable=False, default=0)
    entry_metadata = Column(JSONB, nullable=False, default=dict)

    __table_args__ = (
        Index("ix_audit_tenant_timestamp", "tenant_id", "timestamp"),
        Index("ix_audit_agent_timestamp", "agent_id", "timestamp"),
        Index("ix_audit_tenant_decision", "tenant_id", "decision", "timestamp"),
        Index("ix_audit_hash_chain", "tenant_id", "sequence_number"),
        Index("ix_audit_entry_metadata_gin", "entry_metadata", postgresql_using="gin"),
        Index("ix_audit_timed_metadata_gin", "timed_access_metadata", postgresql_using="gin"),
    )
