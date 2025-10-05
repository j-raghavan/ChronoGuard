"""Policy validation service for business rule enforcement."""

from uuid import UUID

from domain.common.exceptions import ValidationError
from domain.common.value_objects import DomainName, TimeRange
from domain.policy.entity import Policy, PolicyRule, RateLimit, RuleCondition, TimeRestriction


class PolicyValidator:
    """Domain service for comprehensive policy validation."""

    def validate_policy_for_activation(self, policy: Policy) -> None:
        """Validate policy can be activated.

        Args:
            policy: Policy to validate

        Raises:
            ValidationError: If policy cannot be activated
        """
        errors = []

        # Must have at least one enforcement mechanism
        if (
            not policy.rules
            and not policy.allowed_domains
            and not policy.blocked_domains
            and not policy.time_restrictions
            and not policy.rate_limits
        ):
            errors.append(
                "Policy must have at least one rule, domain restriction, "
                "time restriction, or rate limit"
            )

        # Validate rules if present
        if policy.rules:
            for rule in policy.rules:
                try:
                    self._validate_rule_completeness(rule)
                except ValidationError as e:
                    errors.append(f"Rule '{rule.name}': {e.message}")

        # Validate domain restrictions
        if policy.allowed_domains and policy.blocked_domains:
            overlap = policy.allowed_domains.intersection(policy.blocked_domains)
            if overlap:
                errors.append(f"Domains cannot be both allowed and blocked: {', '.join(overlap)}")

        # Validate time restrictions
        if policy.time_restrictions:
            try:
                self._validate_time_restrictions(policy.time_restrictions)
            except ValidationError as e:
                errors.append(f"Time restrictions: {e.message}")

        # Validate rate limits
        if policy.rate_limits:
            try:
                self._validate_rate_limits(policy.rate_limits)
            except ValidationError as e:
                errors.append(f"Rate limits: {e.message}")

        if errors:
            raise ValidationError(
                f"Policy validation failed: {'; '.join(errors)}",
                field="policy_validation",
                value=str(policy.policy_id),
            )

    def validate_rule_logic(self, rule: PolicyRule) -> None:
        """Validate rule logic and conditions.

        Args:
            rule: Rule to validate

        Raises:
            ValidationError: If rule logic is invalid
        """
        self._validate_rule_completeness(rule)
        self._validate_condition_combinations(rule)
        self._validate_condition_values(rule)

    def validate_domain_list_consistency(
        self, allowed_domains: set[str], blocked_domains: set[str]
    ) -> None:
        """Validate domain list consistency.

        Args:
            allowed_domains: Set of allowed domains
            blocked_domains: Set of blocked domains

        Raises:
            ValidationError: If domain lists are inconsistent
        """
        if not allowed_domains and not blocked_domains:
            return

        # Check for overlaps
        overlap = allowed_domains.intersection(blocked_domains)
        if overlap:
            raise ValidationError(
                f"Domains cannot be both allowed and blocked: {', '.join(sorted(overlap))}",
                field="domain_overlap",
                value=overlap,
            )

        # Validate domain formats
        all_domains = allowed_domains.union(blocked_domains)
        invalid_domains = []

        for domain in all_domains:
            try:
                DomainName(value=domain)
            except ValidationError:
                invalid_domains.append(domain)

        if invalid_domains:
            raise ValidationError(
                f"Invalid domain formats: {', '.join(invalid_domains)}",
                field="invalid_domains",
                value=invalid_domains,
            )

    def validate_time_restriction_logic(self, time_restrictions: TimeRestriction) -> None:
        """Validate time restriction logic.

        Args:
            time_restrictions: Time restrictions to validate

        Raises:
            ValidationError: If time restrictions are invalid
        """
        self._validate_time_restrictions(time_restrictions)

    def validate_rate_limit_consistency(self, rate_limits: RateLimit) -> None:
        """Validate rate limit consistency.

        Args:
            rate_limits: Rate limits to validate

        Raises:
            ValidationError: If rate limits are inconsistent
        """
        self._validate_rate_limits(rate_limits)

    def validate_policy_priority_conflicts(
        self, policies: list[Policy], new_priority: int, exclude_policy_id: UUID | None = None
    ) -> None:
        """Validate policy priority doesn't conflict with existing policies.

        Args:
            policies: Existing policies to check against
            new_priority: New priority to validate
            exclude_policy_id: Policy ID to exclude from conflict check

        Raises:
            ValidationError: If priority conflicts exist
        """
        conflicting_policies = [
            p for p in policies if p.priority == new_priority and p.policy_id != exclude_policy_id
        ]

        if conflicting_policies:
            raise ValidationError(
                f"Priority {new_priority} conflicts with "
                f"{len(conflicting_policies)} existing policies",
                field="priority_conflict",
                value=new_priority,
            )

    def validate_policy_rule_limits(self, policy: Policy, new_rule_count: int = 0) -> None:
        """Validate policy doesn't exceed rule limits.

        Args:
            policy: Policy to validate
            new_rule_count: Number of new rules being added

        Raises:
            ValidationError: If rule limits would be exceeded
        """
        total_rules = len(policy.rules) + new_rule_count
        max_rules = 100  # Configurable limit

        if total_rules > max_rules:
            raise ValidationError(
                f"Policy would exceed maximum rule limit: {total_rules}/{max_rules}",
                field="rule_limit",
                value=total_rules,
            )

    def _validate_rule_completeness(self, rule: PolicyRule) -> None:
        """Validate rule has complete configuration.

        Args:
            rule: Rule to validate

        Raises:
            ValidationError: If rule is incomplete
        """
        if not rule.conditions:
            raise ValidationError(
                "Rule must have at least one condition",
                field="rule_conditions",
                value=rule.name,
            )

        if not rule.action:
            raise ValidationError(
                "Rule must have an action",
                field="rule_action",
                value=rule.name,
            )

        # Validate each condition
        for i, condition in enumerate(rule.conditions):
            if not condition.field:
                raise ValidationError(
                    f"Condition {i + 1} missing field",
                    field="condition_field",
                    value=rule.name,
                )

            if not condition.operator:
                raise ValidationError(
                    f"Condition {i + 1} missing operator",
                    field="condition_operator",
                    value=rule.name,
                )

            if not condition.value:
                raise ValidationError(
                    f"Condition {i + 1} missing value",
                    field="condition_value",
                    value=rule.name,
                )

    def _validate_condition_combinations(self, rule: PolicyRule) -> None:
        """Validate condition combinations make logical sense.

        Args:
            rule: Rule to validate

        Raises:
            ValidationError: If condition combinations are illogical
        """
        # Check for contradictory conditions on same field
        field_conditions: dict[str, list[RuleCondition]] = {}
        for condition in rule.conditions:
            if condition.field not in field_conditions:
                field_conditions[condition.field] = []
            field_conditions[condition.field].append(condition)

        for field, conditions in field_conditions.items():
            if len(conditions) > 1:
                self._validate_field_condition_consistency(field, conditions, rule.name)

    def _validate_field_condition_consistency(
        self, field: str, conditions: list[RuleCondition], rule_name: str
    ) -> None:
        """Validate conditions on the same field are consistent.

        Args:
            field: Field name
            conditions: List of conditions on the field
            rule_name: Name of the rule (for error messages)

        Raises:
            ValidationError: If conditions are inconsistent
        """
        # Look for obvious contradictions
        equals_values = []
        not_equals_values = []

        for condition in conditions:
            if condition.operator == "equals":
                equals_values.append(condition.value)
            elif condition.operator == "not_equals":
                not_equals_values.append(condition.value)

        # Cannot equal multiple different values
        if len(set(equals_values)) > 1:
            raise ValidationError(
                f"Rule '{rule_name}' has contradictory equals conditions "
                f"on field '{field}': {equals_values}",
                field="contradictory_conditions",
                value=rule_name,
            )

        # Cannot equal a value and not equal the same value
        overlap = set(equals_values).intersection(set(not_equals_values))
        if overlap:
            raise ValidationError(
                f"Rule '{rule_name}' has contradictory equals/not_equals "
                f"conditions on field '{field}': {overlap}",
                field="contradictory_conditions",
                value=rule_name,
            )

    def _validate_condition_values(self, rule: PolicyRule) -> None:
        """Validate condition values are appropriate for their fields.

        Args:
            rule: Rule to validate

        Raises:
            ValidationError: If condition values are invalid
        """
        for condition in rule.conditions:
            if condition.field == "domain":
                try:
                    DomainName(value=condition.value)
                except ValidationError as e:
                    raise ValidationError(
                        f"Rule '{rule.name}' has invalid domain value: {e.message}",
                        field="invalid_condition_value",
                        value=condition.value,
                    ) from e

            elif condition.field == "method":
                valid_methods = {
                    "GET",
                    "POST",
                    "PUT",
                    "DELETE",
                    "PATCH",
                    "HEAD",
                    "OPTIONS",
                    "CONNECT",
                }
                if condition.value.upper() not in valid_methods:
                    raise ValidationError(
                        f"Rule '{rule.name}' has invalid HTTP method: {condition.value}",
                        field="invalid_condition_value",
                        value=condition.value,
                    )

    def _validate_time_restrictions(self, time_restrictions: TimeRestriction) -> None:
        """Validate time restrictions are logical.

        Args:
            time_restrictions: Time restrictions to validate

        Raises:
            ValidationError: If time restrictions are invalid
        """
        if not time_restrictions.allowed_time_ranges:
            raise ValidationError(
                "Time restrictions must have at least one allowed time range",
                field="time_ranges",
                value=len(time_restrictions.allowed_time_ranges),
            )

        if not time_restrictions.allowed_days_of_week:
            raise ValidationError(
                "Time restrictions must allow at least one day of the week",
                field="allowed_days",
                value=len(time_restrictions.allowed_days_of_week),
            )

        # Validate timezone
        try:
            import zoneinfo

            zoneinfo.ZoneInfo(time_restrictions.timezone)
        except Exception as e:
            raise ValidationError(
                f"Invalid timezone: {time_restrictions.timezone}",
                field="timezone",
                value=time_restrictions.timezone,
            ) from e

        # Check for overlapping time ranges
        self._validate_time_range_overlaps(time_restrictions.allowed_time_ranges)

    def _validate_time_range_overlaps(self, time_ranges: list[TimeRange]) -> None:
        """Validate time ranges don't have problematic overlaps.

        Args:
            time_ranges: List of time ranges to validate

        Raises:
            ValidationError: If overlaps are problematic
        """
        for i, range1 in enumerate(time_ranges):
            for _j, range2 in enumerate(time_ranges[i + 1 :], i + 1):
                if range1.overlaps_with(range2):
                    # Overlaps are allowed but log a warning in production
                    pass  # Could add warning logging here

    def _validate_rate_limits(self, rate_limits: RateLimit) -> None:
        """Validate rate limits are consistent.

        Args:
            rate_limits: Rate limits to validate

        Raises:
            ValidationError: If rate limits are inconsistent
        """
        # Validate rate hierarchy makes sense
        if rate_limits.requests_per_minute * 60 > rate_limits.requests_per_hour:
            raise ValidationError(
                "Hourly rate limit must be >= (per-minute limit * 60)",
                field="rate_limit_consistency",
                value=(
                    f"minute: {rate_limits.requests_per_minute}, "
                    f"hour: {rate_limits.requests_per_hour}"
                ),
            )

        if rate_limits.requests_per_hour * 24 > rate_limits.requests_per_day:
            raise ValidationError(
                "Daily rate limit must be >= (per-hour limit * 24)",
                field="rate_limit_consistency",
                value=f"hour: {rate_limits.requests_per_hour}, day: {rate_limits.requests_per_day}",
            )

        # Burst limit should be reasonable
        if rate_limits.burst_limit > rate_limits.requests_per_minute * 2:
            raise ValidationError(
                "Burst limit should not exceed twice the per-minute rate",
                field="burst_limit",
                value=rate_limits.burst_limit,
            )
