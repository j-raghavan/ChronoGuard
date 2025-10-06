"""Agent-specific domain exceptions."""

from uuid import UUID

from domain.common.exceptions import DomainError


class AgentError(DomainError):
    """Base class for agent-specific domain exceptions."""

    pass


class AgentNotFoundError(AgentError):
    """Raised when a requested agent cannot be found."""

    def __init__(self, agent_id: UUID) -> None:
        """Initialize agent not found error.

        Args:
            agent_id: ID of the agent that was not found
        """
        super().__init__(
            f"Agent with ID {agent_id} not found",
            error_code="AGENT_NOT_FOUND",
        )
        self.agent_id = agent_id


class AgentNameExistsError(AgentError):
    """Raised when attempting to create an agent with a name that already exists."""

    def __init__(self, tenant_id: UUID, name: str) -> None:
        """Initialize agent name exists error.

        Args:
            tenant_id: Tenant ID where the name conflict occurs
            name: Agent name that already exists
        """
        super().__init__(
            f"Agent with name '{name}' already exists for tenant {tenant_id}",
            error_code="AGENT_NAME_EXISTS",
        )
        self.tenant_id = tenant_id
        self.name = name


class AgentCertificateExistsError(AgentError):
    """Raised when attempting to create an agent with a certificate that already exists."""

    def __init__(self, fingerprint: str) -> None:
        """Initialize agent certificate exists error.

        Args:
            fingerprint: Certificate fingerprint that already exists
        """
        super().__init__(
            f"Agent with certificate fingerprint {fingerprint} already exists",
            error_code="AGENT_CERTIFICATE_EXISTS",
        )
        self.fingerprint = fingerprint


class AgentCertificateExpiredError(AgentError):
    """Raised when attempting operations on an agent with an expired certificate."""

    def __init__(self, agent_id: UUID, expiry_date: str) -> None:
        """Initialize agent certificate expired error.

        Args:
            agent_id: ID of the agent with expired certificate
            expiry_date: Certificate expiry date (ISO format)
        """
        super().__init__(
            f"Agent {agent_id} has expired certificate (expired on {expiry_date})",
            error_code="AGENT_CERTIFICATE_EXPIRED",
        )
        self.agent_id = agent_id
        self.expiry_date = expiry_date


class AgentLimitExceededError(AgentError):
    """Raised when tenant agent limits are exceeded."""

    def __init__(self, tenant_id: UUID, current_count: int, max_allowed: int) -> None:
        """Initialize agent limit exceeded error.

        Args:
            tenant_id: Tenant ID that exceeded the limit
            current_count: Current number of agents
            max_allowed: Maximum allowed agents
        """
        super().__init__(
            f"Agent limit exceeded for tenant {tenant_id}: {current_count}/{max_allowed}",
            error_code="AGENT_LIMIT_EXCEEDED",
        )
        self.tenant_id = tenant_id
        self.current_count = current_count
        self.max_allowed = max_allowed


class AgentPolicyLimitExceededError(AgentError):
    """Raised when agent policy assignment limits are exceeded."""

    def __init__(self, agent_id: UUID, current_count: int, max_allowed: int) -> None:
        """Initialize agent policy limit exceeded error.

        Args:
            agent_id: Agent ID that exceeded policy limit
            current_count: Current number of policies
            max_allowed: Maximum allowed policies
        """
        super().__init__(
            f"Policy limit exceeded for agent {agent_id}: {current_count}/{max_allowed}",
            error_code="AGENT_POLICY_LIMIT_EXCEEDED",
        )
        self.agent_id = agent_id
        self.current_count = current_count
        self.max_allowed = max_allowed


class RepositoryError(DomainError):
    """Raised when repository operations fail."""

    def __init__(self, message: str, operation: str) -> None:
        """Initialize repository error.

        Args:
            message: Error message
            operation: Repository operation that failed
        """
        super().__init__(message, error_code="REPOSITORY_ERROR")
        self.operation = operation
