"""Policy-specific domain exceptions."""

from uuid import UUID

from domain.common.exceptions import DomainError


class PolicyError(DomainError):
    """Base class for policy-specific domain exceptions."""

    pass


class PolicyNotFoundError(PolicyError):
    """Raised when a requested policy cannot be found."""

    def __init__(self, policy_id: UUID) -> None:
        """Initialize policy not found error.

        Args:
            policy_id: ID of the policy that was not found
        """
        super().__init__(
            f"Policy with ID {policy_id} not found",
            error_code="POLICY_NOT_FOUND",
        )
        self.policy_id = policy_id


class PolicyNameExistsError(PolicyError):
    """Raised when attempting to create a policy with a name that already exists."""

    def __init__(self, tenant_id: UUID, name: str) -> None:
        """Initialize policy name exists error.

        Args:
            tenant_id: Tenant ID where the name conflict occurs
            name: Policy name that already exists
        """
        super().__init__(
            f"Policy with name '{name}' already exists for tenant {tenant_id}",
            error_code="POLICY_NAME_EXISTS",
        )
        self.tenant_id = tenant_id
        self.name = name


class PolicyPriorityConflictError(PolicyError):
    """Raised when attempting to create a policy with a priority that already exists."""

    def __init__(self, tenant_id: UUID, priority: int, existing_policy_ids: list[UUID]) -> None:
        """Initialize policy priority conflict error.

        Args:
            tenant_id: Tenant ID where the priority conflict occurs
            priority: Priority value that conflicts
            existing_policy_ids: List of existing policy IDs with same priority
        """
        super().__init__(
            f"Policy priority {priority} already in use by {len(existing_policy_ids)} policies",
            error_code="POLICY_PRIORITY_CONFLICT",
        )
        self.tenant_id = tenant_id
        self.priority = priority
        self.existing_policy_ids = existing_policy_ids


class PolicyLimitExceededError(PolicyError):
    """Raised when tenant policy limits are exceeded."""

    def __init__(self, tenant_id: UUID, current_count: int, max_allowed: int) -> None:
        """Initialize policy limit exceeded error.

        Args:
            tenant_id: Tenant ID that exceeded the limit
            current_count: Current number of policies
            max_allowed: Maximum allowed policies
        """
        super().__init__(
            f"Policy limit exceeded for tenant {tenant_id}: {current_count}/{max_allowed}",
            error_code="POLICY_LIMIT_EXCEEDED",
        )
        self.tenant_id = tenant_id
        self.current_count = current_count
        self.max_allowed = max_allowed


class PolicyRuleLimitExceededError(PolicyError):
    """Raised when policy rule limits are exceeded."""

    def __init__(self, policy_id: UUID, current_count: int, max_allowed: int) -> None:
        """Initialize policy rule limit exceeded error.

        Args:
            policy_id: Policy ID that exceeded rule limit
            current_count: Current number of rules
            max_allowed: Maximum allowed rules
        """
        super().__init__(
            f"Rule limit exceeded for policy {policy_id}: {current_count}/{max_allowed}",
            error_code="POLICY_RULE_LIMIT_EXCEEDED",
        )
        self.policy_id = policy_id
        self.current_count = current_count
        self.max_allowed = max_allowed


class PolicyStatusTransitionError(PolicyError):
    """Raised when an invalid policy status transition is attempted."""

    def __init__(self, policy_id: UUID, current_status: str, requested_status: str) -> None:
        """Initialize policy status transition error.

        Args:
            policy_id: Policy ID with invalid transition
            current_status: Current policy status
            requested_status: Requested status that is invalid
        """
        super().__init__(
            f"Invalid status transition for policy {policy_id}: "
            f"{current_status} -> {requested_status}",
            error_code="POLICY_INVALID_STATUS_TRANSITION",
        )
        self.policy_id = policy_id
        self.current_status = current_status
        self.requested_status = requested_status


class PolicyEvaluationError(PolicyError):
    """Raised when policy evaluation fails."""

    def __init__(self, policy_id: UUID, reason: str) -> None:
        """Initialize policy evaluation error.

        Args:
            policy_id: Policy ID that failed evaluation
            reason: Reason for evaluation failure
        """
        super().__init__(
            f"Policy evaluation failed for {policy_id}: {reason}",
            error_code="POLICY_EVALUATION_FAILED",
        )
        self.policy_id = policy_id
        self.reason = reason


class PolicyRuleNotFoundError(PolicyError):
    """Raised when a requested policy rule cannot be found."""

    def __init__(self, policy_id: UUID, rule_id: UUID) -> None:
        """Initialize policy rule not found error.

        Args:
            policy_id: Policy ID containing the rule
            rule_id: Rule ID that was not found
        """
        super().__init__(
            f"Rule {rule_id} not found in policy {policy_id}",
            error_code="POLICY_RULE_NOT_FOUND",
        )
        self.policy_id = policy_id
        self.rule_id = rule_id


class PolicyDomainConflictError(PolicyError):
    """Raised when domain conflicts occur in policy configuration."""

    def __init__(self, policy_id: UUID, domain: str, conflict_type: str) -> None:
        """Initialize policy domain conflict error.

        Args:
            policy_id: Policy ID with domain conflict
            domain: Domain that conflicts
            conflict_type: Type of conflict (e.g., "already_allowed", "already_blocked")
        """
        super().__init__(
            f"Domain conflict in policy {policy_id}: {domain} ({conflict_type})",
            error_code="POLICY_DOMAIN_CONFLICT",
        )
        self.policy_id = policy_id
        self.domain = domain
        self.conflict_type = conflict_type


class PolicyReferencedByAgentsError(PolicyError):
    """Raised when attempting to delete/archive a policy that is referenced by agents."""

    def __init__(self, policy_id: UUID, referencing_agent_count: int) -> None:
        """Initialize policy referenced by agents error.

        Args:
            policy_id: Policy ID that is referenced
            referencing_agent_count: Number of agents referencing the policy
        """
        super().__init__(
            f"Policy {policy_id} is referenced by {referencing_agent_count} agents "
            f"and cannot be deleted",
            error_code="POLICY_REFERENCED_BY_AGENTS",
        )
        self.policy_id = policy_id
        self.referencing_agent_count = referencing_agent_count


class PolicyActivationError(PolicyError):
    """Raised when policy cannot be activated due to business rules."""

    def __init__(self, policy_id: UUID, reason: str) -> None:
        """Initialize policy activation error.

        Args:
            policy_id: Policy ID that cannot be activated
            reason: Reason why activation failed
        """
        super().__init__(
            f"Cannot activate policy {policy_id}: {reason}",
            error_code="POLICY_ACTIVATION_FAILED",
        )
        self.policy_id = policy_id
        self.reason = reason


class PolicyCompilationError(PolicyError):
    """Raised when policy compilation to Rego format fails."""

    def __init__(self, reason: str) -> None:
        """Initialize policy compilation error.

        Args:
            reason: Reason why compilation failed
        """
        super().__init__(
            f"Policy compilation failed: {reason}",
            error_code="POLICY_COMPILATION_FAILED",
        )
        self.reason = reason
