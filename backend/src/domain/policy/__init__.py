"""Policy domain module."""

from .entity import (
    Policy,
    PolicyRule,
    PolicyStatus,
    RateLimit,
    RuleAction,
    RuleCondition,
    TimeRestriction,
)
from .exceptions import (
    PolicyActivationError,
    PolicyDomainConflictError,
    PolicyError,
    PolicyEvaluationError,
    PolicyLimitExceededError,
    PolicyNameExistsError,
    PolicyNotFoundError,
    PolicyPriorityConflictError,
    PolicyReferencedByAgentsError,
    PolicyRuleLimitExceededError,
    PolicyRuleNotFoundError,
    PolicyStatusTransitionError,
)
from .repository import PolicyRepository
from .service import PolicyEvaluationResult, PolicyService
from .validator import PolicyValidator

__all__ = [
    # Entities and Value Objects
    "Policy",
    "PolicyRule",
    "PolicyStatus",
    "RateLimit",
    "TimeRestriction",
    "RuleAction",
    "RuleCondition",
    # Services
    "PolicyService",
    "PolicyValidator",
    "PolicyEvaluationResult",
    # Repository
    "PolicyRepository",
    # Exceptions
    "PolicyError",
    "PolicyNotFoundError",
    "PolicyNameExistsError",
    "PolicyPriorityConflictError",
    "PolicyLimitExceededError",
    "PolicyRuleLimitExceededError",
    "PolicyStatusTransitionError",
    "PolicyEvaluationError",
    "PolicyRuleNotFoundError",
    "PolicyDomainConflictError",
    "PolicyReferencedByAgentsError",
    "PolicyActivationError",
]
