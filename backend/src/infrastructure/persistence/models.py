"""SQLAlchemy models for ChronoGuard persistence layer.

This module defines database models with TimescaleDB support for time-series optimization.
These models are tested via integration tests with real PostgreSQL/TimescaleDB.
"""

from domain.audit.entity import AccessDecision
from sqlalchemy import JSON, BigInteger, Column, DateTime, Enum, Float, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy models."""

    pass


class AuditEntryModel(Base):
    """SQLAlchemy model for AuditEntry entity with TimescaleDB hypertable support.

    This table is converted to a TimescaleDB hypertable for efficient time-series queries.
    Tested via integration tests in tests/integration/test_audit_repository_integration.py
    """

    __tablename__ = "audit_entries"

    entry_id = Column(PG_UUID(as_uuid=True), primary_key=True)
    tenant_id = Column(PG_UUID(as_uuid=True), nullable=False, index=True)
    agent_id = Column(PG_UUID(as_uuid=True), nullable=False, index=True)
    timestamp = Column(DateTime, nullable=False, index=True)
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
    timed_access_metadata = Column(JSON, nullable=False)
    previous_hash = Column(String(64), nullable=False, default="")
    current_hash = Column(String(64), nullable=False, default="")
    sequence_number = Column(BigInteger, nullable=False, default=0)
    entry_metadata = Column(JSON, nullable=False, default=dict)

    __table_args__ = (
        Index("ix_audit_tenant_timestamp", "tenant_id", "timestamp"),
        Index("ix_audit_agent_timestamp", "agent_id", "timestamp"),
        Index("ix_audit_tenant_decision", "tenant_id", "decision", "timestamp"),
        Index("ix_audit_hash_chain", "tenant_id", "sequence_number"),
        Index("ix_audit_entry_metadata_gin", "entry_metadata", postgresql_using="gin"),
        Index("ix_audit_timed_metadata_gin", "timed_access_metadata", postgresql_using="gin"),
    )
