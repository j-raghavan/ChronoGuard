"""Policy domain service for business operations and policy evaluation."""

import time
from datetime import UTC, datetime
from uuid import UUID

from loguru import logger
from opentelemetry import trace

from domain.agent.repository import AgentRepository
from domain.common.exceptions import (
    BusinessRuleViolationError,
    DuplicateEntityError,
    EntityNotFoundError,
)
from domain.policy.entity import (
    Policy,
    PolicyRule,
    PolicyStatus,
    RateLimit,
    RuleCondition,
    TimeRestriction,
)
from domain.policy.repository import PolicyRepository


tracer = trace.get_tracer(__name__)


class PolicyEvaluationResult:
    """Result of policy evaluation for access control decisions."""

    def __init__(
        self,
        allowed: bool,
        policy_id: UUID,
        rule_id: UUID | None = None,
        reason: str = "",
        rate_limit_info: dict[str, int] | None = None,
    ) -> None:
        """Initialize policy evaluation result.

        Args:
            allowed: Whether access is allowed
            policy_id: ID of the policy that made the decision
            rule_id: ID of the specific rule that matched (if any)
            reason: Human-readable reason for the decision
            rate_limit_info: Rate limiting information if applicable
        """
        self.allowed = allowed
        self.policy_id = policy_id
        self.rule_id = rule_id
        self.reason = reason
        self.rate_limit_info = rate_limit_info or {}


class AccessRequest:
    """Access request context for policy evaluation."""

    def __init__(
        self,
        domain: str,
        method: str = "GET",
        path: str = "/",
        user_agent: str | None = None,
        source_ip: str | None = None,
        timestamp: datetime | None = None,
        agent_id: UUID | None = None,
        tenant_id: UUID | None = None,
        additional_context: dict[str, str] | None = None,
    ) -> None:
        """Initialize access request.

        Args:
            domain: Target domain for the request
            method: HTTP method
            path: Request path
            user_agent: User agent string
            source_ip: Source IP address
            timestamp: Request timestamp
            agent_id: ID of the requesting agent
            tenant_id: Tenant ID
            additional_context: Additional context for evaluation
        """
        self.domain = domain
        self.method = method
        self.path = path
        self.user_agent = user_agent
        self.source_ip = source_ip
        self.timestamp = timestamp or datetime.now(UTC)
        self.agent_id = agent_id
        self.tenant_id = tenant_id
        self.additional_context = additional_context or {}


class PolicyService:
    """Domain service for policy business operations and evaluation."""

    def __init__(
        self,
        policy_repository: PolicyRepository,
        agent_repository: AgentRepository | None = None,
    ) -> None:
        """Initialize policy service.

        Args:
            policy_repository: Repository for policy persistence
            agent_repository: Optional repository for agent operations
        """
        self._policy_repository = policy_repository
        self._agent_repository = agent_repository

    async def create_policy(
        self,
        tenant_id: UUID,
        name: str,
        description: str,
        created_by: UUID,
        priority: int = 500,
    ) -> Policy:
        """Create a new policy with validation.

        Args:
            tenant_id: Tenant identifier
            name: Policy name
            description: Policy description
            created_by: User who created the policy
            priority: Policy priority (1-1000)

        Returns:
            Created policy entity

        Raises:
            DuplicateEntityError: If policy name already exists for tenant
            BusinessRuleViolationError: If business rules are violated
        """
        # Check for duplicate name
        if await self._policy_repository.exists_by_name(tenant_id, name):
            raise DuplicateEntityError("Policy", "name", name)

        # Check tenant policy limits
        policy_count = await self._policy_repository.count_by_tenant(tenant_id)
        if policy_count >= 500:  # Configurable limit
            raise BusinessRuleViolationError(
                f"Tenant has reached maximum policy limit: {policy_count}",
                rule_name="max_policies_per_tenant",
                context={"tenant_id": str(tenant_id), "current_count": policy_count},
            )

        # Check for priority conflicts
        duplicate_priorities = await self._policy_repository.find_duplicate_priority(
            tenant_id, priority
        )
        if duplicate_priorities:
            raise BusinessRuleViolationError(
                f"Policy priority {priority} already in use",
                rule_name="unique_policy_priority",
                context={
                    "tenant_id": str(tenant_id),
                    "priority": priority,
                    "existing_policies": [str(p.policy_id) for p in duplicate_priorities],
                },
            )

        # Create policy
        policy = Policy(
            tenant_id=tenant_id,
            name=name,
            description=description,
            created_by=created_by,
            priority=priority,
            status=PolicyStatus.DRAFT,
        )

        await self._policy_repository.save(policy)
        return policy

    async def activate_policy(self, policy_id: UUID) -> Policy:
        """Activate a policy after validation.

        Args:
            policy_id: Policy identifier

        Returns:
            Activated policy entity

        Raises:
            EntityNotFoundError: If policy doesn't exist
            BusinessRuleViolationError: If activation rules are violated
        """
        policy = await self._get_policy_or_raise(policy_id)

        # Validate policy has meaningful content
        if not policy.rules and not policy.allowed_domains and not policy.blocked_domains:
            raise BusinessRuleViolationError(
                "Cannot activate policy without rules or domain restrictions",
                rule_name="policy_must_have_content",
                context={"policy_id": str(policy_id)},
            )

        policy.activate()
        await self._policy_repository.save(policy)
        return policy

    async def suspend_policy(self, policy_id: UUID) -> Policy:
        """Suspend a policy.

        Args:
            policy_id: Policy identifier

        Returns:
            Suspended policy entity

        Raises:
            EntityNotFoundError: If policy doesn't exist
        """
        policy = await self._get_policy_or_raise(policy_id)
        policy.suspend()
        await self._policy_repository.save(policy)
        return policy

    async def archive_policy(self, policy_id: UUID) -> Policy:
        """Archive a policy permanently.

        Args:
            policy_id: Policy identifier

        Returns:
            Archived policy entity

        Raises:
            EntityNotFoundError: If policy doesn't exist
            BusinessRuleViolationError: If policy is referenced by agents
        """
        policy = await self._get_policy_or_raise(policy_id)

        # Check if policy is referenced by any agents
        if self._agent_repository:
            agents_with_policy = await self._agent_repository.find_with_policy(
                policy.tenant_id, policy_id
            )
            if agents_with_policy:
                raise BusinessRuleViolationError(
                    f"Cannot archive policy referenced by {len(agents_with_policy)} agents",
                    rule_name="policy_cannot_be_archived_with_references",
                    context={
                        "policy_id": str(policy_id),
                        "referencing_agents": len(agents_with_policy),
                    },
                )

        policy.archive()
        await self._policy_repository.save(policy)
        return policy

    async def add_rule_to_policy(self, policy_id: UUID, rule: PolicyRule) -> Policy:
        """Add a rule to a policy.

        Args:
            policy_id: Policy identifier
            rule: Rule to add

        Returns:
            Updated policy entity

        Raises:
            EntityNotFoundError: If policy doesn't exist
            BusinessRuleViolationError: If rule addition violates business rules
        """
        policy = await self._get_policy_or_raise(policy_id)

        # Business rule: cannot modify active policies directly
        if policy.status == PolicyStatus.ACTIVE:
            raise BusinessRuleViolationError(
                "Cannot modify active policy rules",
                rule_name="active_policy_immutable",
                context={"policy_id": str(policy_id), "status": policy.status},
            )

        policy.add_rule(rule)
        await self._policy_repository.save(policy)
        return policy

    async def remove_rule_from_policy(self, policy_id: UUID, rule_id: UUID) -> Policy:
        """Remove a rule from a policy.

        Args:
            policy_id: Policy identifier
            rule_id: Rule identifier

        Returns:
            Updated policy entity

        Raises:
            EntityNotFoundError: If policy doesn't exist
            BusinessRuleViolationError: If rule removal violates business rules
        """
        policy = await self._get_policy_or_raise(policy_id)

        # Business rule: cannot modify active policies directly
        if policy.status == PolicyStatus.ACTIVE:
            raise BusinessRuleViolationError(
                "Cannot modify active policy rules",
                rule_name="active_policy_immutable",
                context={"policy_id": str(policy_id), "status": policy.status},
            )

        if not policy.remove_rule(rule_id):
            raise EntityNotFoundError("PolicyRule", rule_id)

        await self._policy_repository.save(policy)
        return policy

    async def add_domain_to_policy(
        self, policy_id: UUID, domain: str, allowed: bool = True
    ) -> Policy:
        """Add a domain to policy's allowed or blocked list.

        Args:
            policy_id: Policy identifier
            domain: Domain to add
            allowed: True for allowed list, False for blocked list

        Returns:
            Updated policy entity

        Raises:
            EntityNotFoundError: If policy doesn't exist
        """
        policy = await self._get_policy_or_raise(policy_id)

        if allowed:
            policy.add_allowed_domain(domain)
        else:
            policy.add_blocked_domain(domain)

        await self._policy_repository.save(policy)
        return policy

    async def set_time_restrictions(
        self, policy_id: UUID, time_restrictions: TimeRestriction
    ) -> Policy:
        """Set time restrictions for a policy.

        Args:
            policy_id: Policy identifier
            time_restrictions: Time restrictions to apply

        Returns:
            Updated policy entity

        Raises:
            EntityNotFoundError: If policy doesn't exist
        """
        policy = await self._get_policy_or_raise(policy_id)
        policy.set_time_restrictions(time_restrictions)
        await self._policy_repository.save(policy)
        return policy

    async def set_rate_limits(self, policy_id: UUID, rate_limits: RateLimit) -> Policy:
        """Set rate limits for a policy.

        Args:
            policy_id: Policy identifier
            rate_limits: Rate limits to apply

        Returns:
            Updated policy entity

        Raises:
            EntityNotFoundError: If policy doesn't exist
        """
        policy = await self._get_policy_or_raise(policy_id)
        policy.set_rate_limits(rate_limits)
        await self._policy_repository.save(policy)
        return policy

    async def evaluate_access_request(self, request: AccessRequest) -> PolicyEvaluationResult:
        """Evaluate an access request against policies.

        Args:
            request: Access request to evaluate

        Returns:
            Policy evaluation result

        Raises:
            BusinessRuleViolationError: If request cannot be evaluated
        """
        # Start OpenTelemetry span for tracing
        with tracer.start_as_current_span(
            "policy.evaluate_access",
            attributes={
                "tenant.id": str(request.tenant_id),
                "agent.id": str(request.agent_id),
                "domain": request.domain,
            },
        ) as span:
            start_time = time.time()

            try:
                if not request.tenant_id:
                    raise BusinessRuleViolationError(
                        "Cannot evaluate request without tenant context",
                        rule_name="tenant_required_for_evaluation",
                    )

                # Get active policies for the domain
                policies = await self._policy_repository.find_policies_for_evaluation(
                    request.tenant_id, request.domain
                )

                span.set_attribute("policies.count", len(policies))

                if not policies:
                    # Default deny if no policies
                    result = PolicyEvaluationResult(
                        allowed=False,
                        policy_id=UUID("00000000-0000-0000-0000-000000000000"),
                        reason="No policies found for domain",
                    )
                    self._record_evaluation_metrics(request, result, time.time() - start_time)
                    span.set_attribute("decision", "deny")
                    span.set_attribute("reason", "no_policies")
                    return result

                # Evaluate policies in priority order
                for policy in sorted(policies, key=lambda p: p.priority):
                    with tracer.start_as_current_span("policy.evaluate_single") as policy_span:
                        policy_span.set_attribute("policy.id", str(policy.policy_id))
                        policy_span.set_attribute("policy.name", policy.name)
                        policy_result = await self._evaluate_policy(policy, request)
                        if policy_result:
                            self._record_evaluation_metrics(
                                request, policy_result, time.time() - start_time
                            )
                            decision_str = "allow" if policy_result.allowed else "deny"
                            span.set_attribute("decision", decision_str)
                            span.set_attribute("matched_policy", str(policy_result.policy_id))
                            logger.info(
                                "Policy evaluation complete",
                                tenant_id=str(request.tenant_id),
                                agent_id=str(request.agent_id),
                                decision="allow" if policy_result.allowed else "deny",
                                policy_id=str(policy_result.policy_id),
                                duration_seconds=round(time.time() - start_time, 3),
                            )
                            return policy_result

                # Default deny if no policy matched
                result = PolicyEvaluationResult(
                    allowed=False,
                    policy_id=(
                        policies[0].policy_id
                        if policies
                        else UUID("00000000-0000-0000-0000-000000000000")
                    ),
                    reason="No matching policy rules",
                )
                self._record_evaluation_metrics(request, result, time.time() - start_time)
                span.set_attribute("decision", "deny")
                span.set_attribute("reason", "no_matching_rules")
                return result

            except Exception as e:
                span.record_exception(e)
                span.set_status(trace.Status(trace.StatusCode.ERROR, str(e)))
                logger.error(
                    "Policy evaluation failed",
                    tenant_id=str(request.tenant_id),
                    agent_id=str(request.agent_id),
                    error=str(e),
                )
                raise

    def _record_evaluation_metrics(
        self, request: AccessRequest, result: PolicyEvaluationResult, duration: float
    ) -> None:
        """Record metrics for policy evaluation.

        Args:
            request: Access request
            result: Evaluation result
            duration: Evaluation duration in seconds
        """
        # Metrics recording moved to infrastructure layer
        pass

    async def _evaluate_policy(
        self, policy: Policy, request: AccessRequest
    ) -> PolicyEvaluationResult | None:
        """Evaluate a single policy against a request.

        Args:
            policy: Policy to evaluate
            request: Access request

        Returns:
            Evaluation result if policy matches, None otherwise
        """
        # Check domain lists first
        if policy.blocked_domains and request.domain in policy.blocked_domains:
            return PolicyEvaluationResult(
                allowed=False,
                policy_id=policy.policy_id,
                reason=f"Domain {request.domain} is blocked by policy",
            )

        if policy.allowed_domains and request.domain not in policy.allowed_domains:
            return PolicyEvaluationResult(
                allowed=False,
                policy_id=policy.policy_id,
                reason=f"Domain {request.domain} not in allowed list",
            )

        # Check time restrictions
        if (
            policy.time_restrictions
            and policy.time_restrictions.enabled
            and not self._check_time_restrictions(policy.time_restrictions, request)
        ):
            return PolicyEvaluationResult(
                allowed=False,
                policy_id=policy.policy_id,
                reason="Request outside allowed time window",
            )

        # Evaluate rules
        for rule in policy.rules:
            if not rule.enabled:
                continue

            if self._evaluate_rule(rule, request):
                return PolicyEvaluationResult(
                    allowed=rule.action.value == "allow",
                    policy_id=policy.policy_id,
                    rule_id=rule.rule_id,
                    reason=f"Matched rule: {rule.name}",
                )

        return None

    def _evaluate_rule(self, rule: PolicyRule, request: AccessRequest) -> bool:
        """Evaluate a single rule against a request.

        Args:
            rule: Rule to evaluate
            request: Access request

        Returns:
            True if rule matches the request
        """
        # Simplified rule evaluation - production implementation would be more comprehensive
        return all(self._evaluate_condition(condition, request) for condition in rule.conditions)

    def _evaluate_condition(self, condition: RuleCondition, request: AccessRequest) -> bool:
        """Evaluate a single condition against a request.

        Args:
            condition: Condition to evaluate
            request: Access request

        Returns:
            True if condition matches
        """
        # Simplified condition evaluation
        request_value = getattr(request, condition.field, "")

        if condition.operator == "equals":
            return str(request_value) == condition.value
        if condition.operator == "contains":
            return condition.value in str(request_value)
        # Add more operators as needed

        return False

    def _check_time_restrictions(
        self, restrictions: TimeRestriction, request: AccessRequest
    ) -> bool:
        """Check if request falls within allowed time restrictions.

        Args:
            restrictions: Time restrictions to check
            request: Access request

        Returns:
            True if request is within allowed time
        """
        request_time = request.timestamp

        # Check day of week
        if request_time.weekday() not in restrictions.allowed_days_of_week:
            return False

        # Check time ranges
        for time_range in restrictions.allowed_time_ranges:
            if time_range.contains_time(request_time, restrictions.timezone):
                return True

        return False

    async def get_tenant_policy_statistics(self, tenant_id: UUID) -> dict[str, int]:
        """Get policy statistics for a tenant.

        Args:
            tenant_id: Tenant identifier

        Returns:
            Dictionary with policy statistics
        """
        total_policies = await self._policy_repository.count_by_tenant(tenant_id)
        draft_policies = await self._policy_repository.count_by_status(
            tenant_id, PolicyStatus.DRAFT
        )
        active_policies = await self._policy_repository.count_by_status(
            tenant_id, PolicyStatus.ACTIVE
        )
        suspended_policies = await self._policy_repository.count_by_status(
            tenant_id, PolicyStatus.SUSPENDED
        )
        archived_policies = await self._policy_repository.count_by_status(
            tenant_id, PolicyStatus.ARCHIVED
        )

        return {
            "total": total_policies,
            "draft": draft_policies,
            "active": active_policies,
            "suspended": suspended_policies,
            "archived": archived_policies,
        }

    async def bulk_archive_policies(self, policy_ids: list[UUID]) -> int:
        """Bulk archive multiple policies.

        Args:
            policy_ids: List of policy IDs to archive

        Returns:
            Number of policies successfully archived
        """
        return await self._policy_repository.bulk_update_status(policy_ids, PolicyStatus.ARCHIVED)

    async def search_policies(
        self,
        tenant_id: UUID,
        search_term: str,
        status_filter: PolicyStatus | None = None,
        limit: int = 50,
    ) -> list[Policy]:
        """Search policies by various criteria.

        Args:
            tenant_id: Tenant identifier
            search_term: Search term to match
            status_filter: Optional status filter
            limit: Maximum results to return

        Returns:
            List of matching policies
        """
        return await self._policy_repository.search_policies(
            tenant_id, search_term, status_filter, limit
        )

    async def _get_policy_or_raise(self, policy_id: UUID) -> Policy:
        """Get policy by ID or raise EntityNotFoundError.

        Args:
            policy_id: Policy identifier

        Returns:
            Policy entity

        Raises:
            EntityNotFoundError: If policy doesn't exist
        """
        policy = await self._policy_repository.find_by_id(policy_id)
        if not policy:
            raise EntityNotFoundError("Policy", policy_id)
        return policy
