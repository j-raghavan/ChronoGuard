"""Tests for agents API module."""

import pytest
import respx
from chronoguard_sdk import ChronoGuard, ChronoGuardSync
from chronoguard_sdk.exceptions import NotFoundError, ValidationError
from chronoguard_sdk.models import Agent, AgentListResponse
from httpx import Response


class TestAgentsAPI:
    """Tests for async agents API."""

    @pytest.mark.asyncio
    @respx.mock
    async def test_list_agents(self, base_url, sample_agent):
        """Test listing agents."""
        response_data = {
            "agents": [sample_agent.model_dump(mode="json")],
            "total_count": 1,
            "page": 1,
            "page_size": 50,
        }

        respx.get(f"{base_url}/api/v1/agents/").mock(return_value=Response(200, json=response_data))

        async with ChronoGuard(api_url=base_url) as client:
            result = await client.agents.list()

            assert isinstance(result, AgentListResponse)
            assert len(result.agents) == 1
            assert result.total_count == 1
            assert result.agents[0].name == "test-agent"

    @pytest.mark.asyncio
    @respx.mock
    async def test_list_agents_with_pagination(self, base_url, sample_agent):
        """Test listing agents with pagination."""
        response_data = {
            "agents": [sample_agent.model_dump(mode="json")],
            "total_count": 100,
            "page": 2,
            "page_size": 10,
        }

        respx.get(f"{base_url}/api/v1/agents/").mock(return_value=Response(200, json=response_data))

        async with ChronoGuard(api_url=base_url) as client:
            result = await client.agents.list(page=2, page_size=10)

            assert result.page == 2
            assert result.page_size == 10
            assert result.total_count == 100

    @pytest.mark.asyncio
    @respx.mock
    async def test_list_agents_with_status_filter(self, base_url, sample_agent):
        """Test listing agents with status filter."""
        response_data = {
            "agents": [sample_agent.model_dump(mode="json")],
            "total_count": 1,
            "page": 1,
            "page_size": 50,
        }

        respx.get(f"{base_url}/api/v1/agents/").mock(return_value=Response(200, json=response_data))

        async with ChronoGuard(api_url=base_url) as client:
            result = await client.agents.list(status_filter="active")

            assert len(result.agents) == 1

    @pytest.mark.asyncio
    @respx.mock
    async def test_get_agent(self, base_url, agent_id, sample_agent):
        """Test getting a specific agent."""
        respx.get(f"{base_url}/api/v1/agents/{agent_id}").mock(
            return_value=Response(200, json=sample_agent.model_dump(mode="json"))
        )

        async with ChronoGuard(api_url=base_url) as client:
            result = await client.agents.get(agent_id)

            assert isinstance(result, Agent)
            assert str(result.agent_id) == agent_id
            assert result.name == "test-agent"

    @pytest.mark.asyncio
    @respx.mock
    async def test_get_agent_not_found(self, base_url):
        """Test getting non-existent agent."""
        respx.get(f"{base_url}/api/v1/agents/invalid").mock(
            return_value=Response(404, json={"detail": "Agent not found"})
        )

        async with ChronoGuard(api_url=base_url) as client:
            with pytest.raises(NotFoundError):
                await client.agents.get("invalid")

    @pytest.mark.asyncio
    @respx.mock
    async def test_create_agent(self, base_url, sample_agent):
        """Test creating a new agent."""
        respx.post(f"{base_url}/api/v1/agents/").mock(
            return_value=Response(201, json=sample_agent.model_dump(mode="json"))
        )

        async with ChronoGuard(api_url=base_url) as client:
            result = await client.agents.create(
                name="test-agent",
                certificate_pem="-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
                metadata={"env": "test"},
            )

            assert isinstance(result, Agent)
            assert result.name == "test-agent"

    @pytest.mark.asyncio
    async def test_create_agent_invalid_name(self, base_url):
        """Test creating agent with invalid name."""
        from pydantic import ValidationError as PydanticValidationError

        async with ChronoGuard(api_url=base_url) as client:
            with pytest.raises(PydanticValidationError):
                await client.agents.create(
                    name="",
                    certificate_pem="-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
                )

    @pytest.mark.asyncio
    async def test_create_agent_invalid_certificate(self, base_url):
        """Test creating agent with invalid certificate."""
        from pydantic import ValidationError as PydanticValidationError

        async with ChronoGuard(api_url=base_url) as client:
            with pytest.raises(PydanticValidationError):
                await client.agents.create(
                    name="test-agent",
                    certificate_pem="invalid-certificate",
                )

    @pytest.mark.asyncio
    @respx.mock
    async def test_update_agent(self, base_url, agent_id, sample_agent):
        """Test updating an agent."""
        updated_agent = sample_agent.model_copy(update={"name": "updated-agent"})

        respx.put(f"{base_url}/api/v1/agents/{agent_id}").mock(
            return_value=Response(200, json=updated_agent.model_dump(mode="json"))
        )

        async with ChronoGuard(api_url=base_url) as client:
            result = await client.agents.update(agent_id, name="updated-agent")

            assert isinstance(result, Agent)
            assert result.name == "updated-agent"

    @pytest.mark.asyncio
    @respx.mock
    async def test_update_agent_certificate(self, base_url, agent_id, sample_agent):
        """Test updating agent certificate."""
        respx.put(f"{base_url}/api/v1/agents/{agent_id}").mock(
            return_value=Response(200, json=sample_agent.model_dump(mode="json"))
        )

        async with ChronoGuard(api_url=base_url) as client:
            result = await client.agents.update(
                agent_id,
                certificate_pem="-----BEGIN CERTIFICATE-----\nnew\n-----END CERTIFICATE-----",
            )

            assert isinstance(result, Agent)

    @pytest.mark.asyncio
    @respx.mock
    async def test_update_agent_metadata(self, base_url, agent_id, sample_agent):
        """Test updating agent metadata."""
        respx.put(f"{base_url}/api/v1/agents/{agent_id}").mock(
            return_value=Response(200, json=sample_agent.model_dump(mode="json"))
        )

        async with ChronoGuard(api_url=base_url) as client:
            result = await client.agents.update(agent_id, metadata={"env": "prod"})

            assert isinstance(result, Agent)


class TestAgentsSyncAPI:
    """Tests for sync agents API."""

    @respx.mock
    def test_sync_list_agents(self, base_url, sample_agent):
        """Test sync listing agents."""
        response_data = {
            "agents": [sample_agent.model_dump(mode="json")],
            "total_count": 1,
            "page": 1,
            "page_size": 50,
        }

        respx.get(f"{base_url}/api/v1/agents/").mock(return_value=Response(200, json=response_data))

        with ChronoGuardSync(api_url=base_url) as client:
            result = client.agents.list()

            assert isinstance(result, AgentListResponse)
            assert len(result.agents) == 1

    @respx.mock
    def test_sync_get_agent(self, base_url, agent_id, sample_agent):
        """Test sync getting agent."""
        respx.get(f"{base_url}/api/v1/agents/{agent_id}").mock(
            return_value=Response(200, json=sample_agent.model_dump(mode="json"))
        )

        with ChronoGuardSync(api_url=base_url) as client:
            result = client.agents.get(agent_id)

            assert isinstance(result, Agent)

    @respx.mock
    def test_sync_create_agent(self, base_url, sample_agent):
        """Test sync creating agent."""
        respx.post(f"{base_url}/api/v1/agents/").mock(
            return_value=Response(201, json=sample_agent.model_dump(mode="json"))
        )

        with ChronoGuardSync(api_url=base_url) as client:
            result = client.agents.create(
                name="test-agent",
                certificate_pem="-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
            )

            assert isinstance(result, Agent)

    @respx.mock
    def test_sync_update_agent(self, base_url, agent_id, sample_agent):
        """Test sync updating agent."""
        respx.put(f"{base_url}/api/v1/agents/{agent_id}").mock(
            return_value=Response(200, json=sample_agent.model_dump(mode="json"))
        )

        with ChronoGuardSync(api_url=base_url) as client:
            result = client.agents.update(agent_id, name="updated")

            assert isinstance(result, Agent)
