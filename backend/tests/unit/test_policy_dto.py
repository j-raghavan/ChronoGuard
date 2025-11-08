"""Tests for Policy DTOs and mappers."""

from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from application.dto import (
    CreatePolicyRequest,
    PolicyDTO,
    PolicyMapper,
    RateLimitDTO,
    UpdatePolicyRequest,
)
from domain.policy.entity import Policy, PolicyStatus, RateLimit
from pydantic import ValidationError


class TestPolicyDTO:
    """Test PolicyDTO data transfer object."""

    def test_policy_dto_creation_with_all_fields(self) -> None:
        """Test creating PolicyDTO with all fields."""
        policy_id = uuid4()
        tenant_id = uuid4()
        created_by = uuid4()
        now = datetime.now(UTC)

        dto = PolicyDTO(
            policy_id=policy_id,
            tenant_id=tenant_id,
            name="test-policy",
            description="Test policy description",
            priority=500,
            status="active",
            allowed_domains=["example.com"],
            blocked_domains=["malicious.com"],
            created_at=now,
            updated_at=now,
            created_by=created_by,
            version=1,
        )

        assert dto.policy_id == policy_id
        assert dto.name == "test-policy"
        assert dto.priority == 500
        assert dto.status == "active"

    def test_policy_dto_is_immutable(self) -> None:
        """Test that PolicyDTO is immutable."""
        dto = PolicyDTO(
            policy_id=uuid4(),
            tenant_id=uuid4(),
            name="test-policy",
            description="Test",
            priority=500,
            status="draft",
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
            created_by=uuid4(),
            version=1,
        )

        with pytest.raises((ValidationError, AttributeError)):
            dto.name = "new-name"


class TestCreatePolicyRequest:
    """Test CreatePolicyRequest validation."""

    def test_create_policy_request_with_valid_data(self) -> None:
        """Test creating valid CreatePolicyRequest."""
        request = CreatePolicyRequest(
            name="test-policy",
            description="Test policy description",
            priority=600,
            allowed_domains=["example.com", "test.com"],
            metadata={"env": "test"},
        )

        assert request.name == "test-policy"
        assert request.priority == 600
        assert len(request.allowed_domains) == 2

    def test_create_policy_request_validates_name_length(self) -> None:
        """Test name length validation."""
        # Too short
        with pytest.raises(ValidationError) as exc_info:
            CreatePolicyRequest(name="ab", description="Test")
        assert "at least 3 characters" in str(exc_info.value).lower()

        # Too long
        with pytest.raises(ValidationError) as exc_info:
            CreatePolicyRequest(name="a" * 101, description="Test")
        assert "at most 100 characters" in str(exc_info.value).lower()

    def test_create_policy_request_validates_priority_range(self) -> None:
        """Test priority must be in valid range."""
        # Too low
        with pytest.raises(ValidationError) as exc_info:
            CreatePolicyRequest(name="test-policy", description="Test", priority=0)
        assert "greater than or equal to 1" in str(exc_info.value).lower()

        # Too high
        with pytest.raises(ValidationError) as exc_info:
            CreatePolicyRequest(name="test-policy", description="Test", priority=1001)
        assert "less than or equal to 1000" in str(exc_info.value).lower()

    def test_create_policy_request_validates_domain_count(self) -> None:
        """Test maximum domain count validation."""
        with pytest.raises(ValidationError) as exc_info:
            CreatePolicyRequest(
                name="test-policy", description="Test", allowed_domains=["domain.com"] * 1001
            )
        assert "too many domains" in str(exc_info.value).lower()

    def test_create_policy_request_trims_domain_whitespace(self) -> None:
        """Test domain whitespace is trimmed."""
        request = CreatePolicyRequest(
            name="test-policy",
            description="Test",
            allowed_domains=["  example.com  ", " test.com ", "  "],
        )
        # Empty string should be filtered out
        assert "example.com" in request.allowed_domains
        assert "test.com" in request.allowed_domains
        assert len(request.allowed_domains) == 2


class TestUpdatePolicyRequest:
    """Test UpdatePolicyRequest validation."""

    def test_update_policy_request_all_fields_optional(self) -> None:
        """Test all fields are optional."""
        request = UpdatePolicyRequest()
        assert request.name is None
        assert request.description is None
        assert request.priority is None

    def test_update_policy_request_validates_fields_if_provided(self) -> None:
        """Test validation applies when fields are provided."""
        # Valid update
        request = UpdatePolicyRequest(name="new-name", priority=700)
        assert request.name == "new-name"
        assert request.priority == 700

        # Invalid priority
        with pytest.raises(ValidationError):
            UpdatePolicyRequest(priority=2000)


class TestPolicyMapper:
    """Test PolicyMapper conversion functions."""

    def test_policy_mapper_to_dto(self) -> None:
        """Test mapping Policy entity to PolicyDTO."""
        policy = Policy(
            tenant_id=uuid4(),
            name="test-policy",
            description="Test description",
            created_by=uuid4(),
            priority=500,
            status=PolicyStatus.ACTIVE,
            allowed_domains={"example.com", "test.com"},
        )

        dto = PolicyMapper.to_dto(policy)

        assert isinstance(dto, PolicyDTO)
        assert dto.policy_id == policy.policy_id
        assert dto.name == policy.name
        assert dto.status == "active"
        assert sorted(dto.allowed_domains) == ["example.com", "test.com"]

    def test_policy_mapper_from_create_request(self) -> None:
        """Test mapping CreatePolicyRequest to Policy entity."""
        tenant_id = uuid4()
        created_by = uuid4()
        request = CreatePolicyRequest(
            name="new-policy",
            description="New policy description",
            priority=600,
            allowed_domains=["example.com"],
            metadata={"env": "production"},
        )

        policy = PolicyMapper.from_create_request(request, tenant_id, created_by)

        assert isinstance(policy, Policy)
        assert policy.tenant_id == tenant_id
        assert policy.created_by == created_by
        assert policy.name == "new-policy"
        assert policy.priority == 600
        assert "example.com" in policy.allowed_domains

    def test_policy_mapper_with_rate_limits(self) -> None:
        """Test mapping policy with rate limits."""
        policy = Policy(
            tenant_id=uuid4(),
            name="test-policy",
            description="Test",
            created_by=uuid4(),
        )
        rate_limit = RateLimit(
            requests_per_minute=60,
            requests_per_hour=3600,
            requests_per_day=86400,
            burst_limit=100,
        )
        policy.set_rate_limits(rate_limit)

        dto = PolicyMapper.to_dto(policy)

        assert dto.rate_limits is not None
        assert isinstance(dto.rate_limits, RateLimitDTO)
        assert dto.rate_limits.requests_per_minute == 60
        assert dto.rate_limits.requests_per_hour == 3600
