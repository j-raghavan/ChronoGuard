"""Tests for policies API module."""

import pytest
import respx
from httpx import Response

from chronoguard_sdk import ChronoGuard, ChronoGuardSync
from chronoguard_sdk.exceptions import NotFoundError, ValidationError
from chronoguard_sdk.models import Policy, PolicyListResponse


class TestPoliciesAPI:
    """Tests for async policies API."""

    @pytest.mark.asyncio
    @respx.mock
    async def test_list_policies(self, base_url, sample_policy):
        """Test listing policies."""
        response_data = {
            "policies": [sample_policy.model_dump(mode="json")],
            "total_count": 1,
            "page": 1,
            "page_size": 50,
        }

        respx.get(f"{base_url}/api/v1/policies/").mock(
            return_value=Response(200, json=response_data)
        )

        async with ChronoGuard(api_url=base_url) as client:
            result = await client.policies.list()

            assert isinstance(result, PolicyListResponse)
            assert len(result.policies) == 1
            assert result.total_count == 1
            assert result.policies[0].name == "test-policy"

    @pytest.mark.asyncio
    @respx.mock
    async def test_list_policies_with_pagination(self, base_url, sample_policy):
        """Test listing policies with pagination."""
        response_data = {
            "policies": [sample_policy.model_dump(mode="json")],
            "total_count": 50,
            "page": 3,
            "page_size": 20,
        }

        respx.get(f"{base_url}/api/v1/policies/").mock(
            return_value=Response(200, json=response_data)
        )

        async with ChronoGuard(api_url=base_url) as client:
            result = await client.policies.list(page=3, page_size=20)

            assert result.page == 3
            assert result.page_size == 20

    @pytest.mark.asyncio
    @respx.mock
    async def test_get_policy(self, base_url, policy_id, sample_policy):
        """Test getting a specific policy."""
        respx.get(f"{base_url}/api/v1/policies/{policy_id}").mock(
            return_value=Response(200, json=sample_policy.model_dump(mode="json"))
        )

        async with ChronoGuard(api_url=base_url) as client:
            result = await client.policies.get(policy_id)

            assert isinstance(result, Policy)
            assert str(result.policy_id) == policy_id
            assert result.name == "test-policy"

    @pytest.mark.asyncio
    @respx.mock
    async def test_get_policy_not_found(self, base_url):
        """Test getting non-existent policy."""
        respx.get(f"{base_url}/api/v1/policies/invalid").mock(
            return_value=Response(404, json={"detail": "Policy not found"})
        )

        async with ChronoGuard(api_url=base_url) as client:
            with pytest.raises(NotFoundError):
                await client.policies.get("invalid")

    @pytest.mark.asyncio
    @respx.mock
    async def test_create_policy(self, base_url, sample_policy):
        """Test creating a new policy."""
        respx.post(f"{base_url}/api/v1/policies/").mock(
            return_value=Response(201, json=sample_policy.model_dump(mode="json"))
        )

        async with ChronoGuard(api_url=base_url) as client:
            result = await client.policies.create(
                name="test-policy",
                description="Test policy",
                priority=500,
                allowed_domains=["example.com"],
            )

            assert isinstance(result, Policy)
            assert result.name == "test-policy"

    @pytest.mark.asyncio
    @respx.mock
    async def test_create_policy_with_all_options(self, base_url, sample_policy):
        """Test creating policy with all options."""
        respx.post(f"{base_url}/api/v1/policies/").mock(
            return_value=Response(201, json=sample_policy.model_dump(mode="json"))
        )

        async with ChronoGuard(api_url=base_url) as client:
            result = await client.policies.create(
                name="test-policy",
                description="Test policy",
                priority=700,
                allowed_domains=["example.com", "test.com"],
                blocked_domains=["blocked.com"],
                metadata={"env": "prod"},
            )

            assert isinstance(result, Policy)

    @pytest.mark.asyncio
    async def test_create_policy_invalid_name(self, base_url):
        """Test creating policy with invalid name."""
        from pydantic import ValidationError as PydanticValidationError

        async with ChronoGuard(api_url=base_url) as client:
            with pytest.raises(PydanticValidationError):
                await client.policies.create(name="", description="Test")

    @pytest.mark.asyncio
    async def test_create_policy_invalid_description(self, base_url):
        """Test creating policy with invalid description."""
        from pydantic import ValidationError as PydanticValidationError

        async with ChronoGuard(api_url=base_url) as client:
            with pytest.raises(PydanticValidationError):
                await client.policies.create(name="test", description="")

    @pytest.mark.asyncio
    async def test_create_policy_invalid_priority(self, base_url):
        """Test creating policy with invalid priority."""
        from pydantic import ValidationError as PydanticValidationError

        async with ChronoGuard(api_url=base_url) as client:
            with pytest.raises(PydanticValidationError):
                await client.policies.create(
                    name="test",
                    description="Test",
                    priority=1001,  # Over max
                )

    @pytest.mark.asyncio
    @respx.mock
    async def test_update_policy(self, base_url, policy_id, sample_policy):
        """Test updating a policy."""
        updated_policy = sample_policy.model_copy(update={"name": "updated-policy"})

        respx.put(f"{base_url}/api/v1/policies/{policy_id}").mock(
            return_value=Response(200, json=updated_policy.model_dump(mode="json"))
        )

        async with ChronoGuard(api_url=base_url) as client:
            result = await client.policies.update(policy_id, name="updated-policy")

            assert isinstance(result, Policy)
            assert result.name == "updated-policy"

    @pytest.mark.asyncio
    @respx.mock
    async def test_update_policy_priority(self, base_url, policy_id, sample_policy):
        """Test updating policy priority."""
        respx.put(f"{base_url}/api/v1/policies/{policy_id}").mock(
            return_value=Response(200, json=sample_policy.model_dump(mode="json"))
        )

        async with ChronoGuard(api_url=base_url) as client:
            result = await client.policies.update(policy_id, priority=800)

            assert isinstance(result, Policy)

    @pytest.mark.asyncio
    @respx.mock
    async def test_update_policy_domains(self, base_url, policy_id, sample_policy):
        """Test updating policy domains."""
        respx.put(f"{base_url}/api/v1/policies/{policy_id}").mock(
            return_value=Response(200, json=sample_policy.model_dump(mode="json"))
        )

        async with ChronoGuard(api_url=base_url) as client:
            result = await client.policies.update(
                policy_id,
                allowed_domains=["new.com"],
                blocked_domains=["bad.com"],
            )

            assert isinstance(result, Policy)

    @pytest.mark.asyncio
    @respx.mock
    async def test_delete_policy(self, base_url, policy_id):
        """Test deleting a policy."""
        respx.delete(f"{base_url}/api/v1/policies/{policy_id}").mock(
            return_value=Response(204)
        )

        async with ChronoGuard(api_url=base_url) as client:
            result = await client.policies.delete(policy_id)

            assert result is True

    @pytest.mark.asyncio
    @respx.mock
    async def test_delete_policy_not_found(self, base_url):
        """Test deleting non-existent policy."""
        respx.delete(f"{base_url}/api/v1/policies/invalid").mock(
            return_value=Response(404, json={"detail": "Policy not found"})
        )

        async with ChronoGuard(api_url=base_url) as client:
            with pytest.raises(NotFoundError):
                await client.policies.delete("invalid")


class TestPoliciesSyncAPI:
    """Tests for sync policies API."""

    @respx.mock
    def test_sync_list_policies(self, base_url, sample_policy):
        """Test sync listing policies."""
        response_data = {
            "policies": [sample_policy.model_dump(mode="json")],
            "total_count": 1,
            "page": 1,
            "page_size": 50,
        }

        respx.get(f"{base_url}/api/v1/policies/").mock(
            return_value=Response(200, json=response_data)
        )

        with ChronoGuardSync(api_url=base_url) as client:
            result = client.policies.list()

            assert isinstance(result, PolicyListResponse)
            assert len(result.policies) == 1

    @respx.mock
    def test_sync_get_policy(self, base_url, policy_id, sample_policy):
        """Test sync getting policy."""
        respx.get(f"{base_url}/api/v1/policies/{policy_id}").mock(
            return_value=Response(200, json=sample_policy.model_dump(mode="json"))
        )

        with ChronoGuardSync(api_url=base_url) as client:
            result = client.policies.get(policy_id)

            assert isinstance(result, Policy)

    @respx.mock
    def test_sync_create_policy(self, base_url, sample_policy):
        """Test sync creating policy."""
        respx.post(f"{base_url}/api/v1/policies/").mock(
            return_value=Response(201, json=sample_policy.model_dump(mode="json"))
        )

        with ChronoGuardSync(api_url=base_url) as client:
            result = client.policies.create(name="test-policy", description="Test")

            assert isinstance(result, Policy)

    @respx.mock
    def test_sync_update_policy(self, base_url, policy_id, sample_policy):
        """Test sync updating policy."""
        respx.put(f"{base_url}/api/v1/policies/{policy_id}").mock(
            return_value=Response(200, json=sample_policy.model_dump(mode="json"))
        )

        with ChronoGuardSync(api_url=base_url) as client:
            result = client.policies.update(policy_id, name="updated")

            assert isinstance(result, Policy)

    @respx.mock
    def test_sync_delete_policy(self, base_url, policy_id):
        """Test sync deleting policy."""
        respx.delete(f"{base_url}/api/v1/policies/{policy_id}").mock(
            return_value=Response(204)
        )

        with ChronoGuardSync(api_url=base_url) as client:
            result = client.policies.delete(policy_id)

            assert result is True
