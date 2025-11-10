"""OPA policy compiler for converting domain policies to Rego.

This module compiles ChronoGuard domain policies into Open Policy Agent (OPA)
Rego policies. It translates high-level policy rules, time restrictions, and
rate limits into executable Rego code for runtime policy evaluation.
"""

from __future__ import annotations

import hashlib
import time
import zoneinfo
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any

import aiohttp
from domain.policy.exceptions import PolicyCompilationError
from jinja2 import Environment, FileSystemLoader
from loguru import logger

if TYPE_CHECKING:
    from domain.policy.entity import Policy, RateLimit, TimeRestriction


class PolicyCompiler:
    """Compiles domain policies to OPA Rego format.

    This class converts ChronoGuard policy domain models into Rego policies
    that can be loaded into OPA for runtime evaluation. It handles:
    - Policy rule compilation
    - Time restriction conversion
    - Rate limit specification
    - Policy bundle generation
    - Rego syntax validation

    The compiler uses Jinja2 templates to generate syntactically correct
    Rego code from policy domain models.

    Example:
        >>> compiler = PolicyCompiler(
        ...     template_dir=Path("/templates"),
        ...     opa_url="http://localhost:8181"
        ... )
        >>> policy = Policy(...)
        >>> rego = await compiler.compile_policy(policy)
        >>> await compiler.deploy_policy(policy)
    """

    def __init__(self, template_dir: Path, opa_url: str = "http://localhost:8181") -> None:
        """Initialize policy compiler.

        Args:
            template_dir: Directory containing Rego templates
            opa_url: OPA server URL for REST API (port 8181)

        Raises:
            ValueError: If template directory doesn't exist
        """
        if not template_dir.exists():
            raise ValueError(f"Template directory does not exist: {template_dir}")

        self.env = Environment(
            loader=FileSystemLoader(str(template_dir)),
            trim_blocks=True,
            lstrip_blocks=True,
            autoescape=False,  # noqa: S701  # nosec B701 - Rego generation, not HTML
        )
        self.opa_url = opa_url.rstrip("/")
        self.session: aiohttp.ClientSession | None = None

    async def compile_policy(self, policy: Policy) -> str:
        """Convert domain policy to Rego.

        Compiles a policy domain model into Rego code suitable for OPA
        evaluation. The generated Rego includes:
        - Access control rules
        - Domain allow/deny lists
        - Time-based restrictions
        - Rate limiting logic

        Args:
            policy: Domain policy to compile

        Returns:
            Compiled Rego policy as string

        Raises:
            PolicyCompilationError: If compilation fails
        """
        try:
            # Load base policy template
            template = self.env.get_template("base_policy.rego.j2")

            # Prepare template context
            context = {
                "policy_id": str(policy.policy_id),
                "policy_name": self._sanitize_name(policy.name),
                "tenant_id": str(policy.tenant_id),
                "allowed_domains": sorted(policy.allowed_domains),
                "blocked_domains": sorted(policy.blocked_domains),
                "time_restrictions": self._format_time_restrictions(policy.time_restrictions),
                "rate_limits": self._format_rate_limits(policy.rate_limits),
                "rules": self._format_rules(policy),
                "priority": policy.priority,
                "status": policy.status,
            }

            # Render Rego
            rego = template.render(**context)

            # Validate Rego syntax
            await self._validate_rego(rego)

            logger.info(f"Compiled policy '{policy.name}' to Rego successfully")
            return rego

        except Exception as e:
            logger.error(f"Failed to compile policy '{policy.name}': {e}", exc_info=True)
            raise PolicyCompilationError(
                f"Policy compilation failed for '{policy.name}': {e}"
            ) from e

    async def deploy_policy(self, policy: Policy) -> None:
        """Deploy compiled policy to OPA.

        Compiles the policy and deploys it to the OPA server via REST API.

        Args:
            policy: Policy to deploy

        Raises:
            PolicyCompilationError: If deployment fails
        """
        try:
            # Compile policy
            rego = await self.compile_policy(policy)

            # Deploy to OPA
            policy_path = f"chronoguard/policies/{self._sanitize_name(policy.name)}"

            if not self.session:
                self.session = aiohttp.ClientSession()

            async with self.session.put(
                f"{self.opa_url}/v1/policies/{policy_path}",
                data=rego,
                headers={"Content-Type": "text/plain"},
                timeout=aiohttp.ClientTimeout(total=10),
            ) as response:
                if response.status not in (200, 201):
                    error_text = await response.text()
                    raise PolicyCompilationError(f"Failed to deploy policy to OPA: {error_text}")

            logger.info(f"Deployed policy '{policy.name}' to OPA at {policy_path}")

        except aiohttp.ClientError as e:
            raise PolicyCompilationError(f"OPA deployment failed: {e}") from e
        except Exception as e:
            raise PolicyCompilationError(f"Policy deployment failed: {e}") from e

    async def generate_bundle(self, policies: list[Policy]) -> dict[str, Any]:
        """Generate OPA bundle for all policies.

        Creates a complete OPA bundle containing all policies, their data,
        and manifest information. The bundle can be served via OPA's bundle
        API for atomic policy updates.

        Args:
            policies: List of policies to bundle

        Returns:
            OPA bundle as dictionary with manifest, data, and policies

        Example:
            >>> bundle = await compiler.generate_bundle([policy1, policy2])
            >>> bundle.keys()
            dict_keys(['manifest', 'data', 'policies'])
        """
        bundle: dict[str, Any] = {
            "manifest": {
                "revision": self._generate_revision(),
                "roots": ["chronoguard"],
            },
            "data": {"chronoguard": {"policies": {}}},
            "policies": [],
        }

        for policy in policies:
            # Compile policy to Rego
            rego = await self.compile_policy(policy)
            policy_name = self._sanitize_name(policy.name)

            # Add to bundle
            bundle["policies"].append(
                {
                    "path": f"chronoguard/policies/{policy_name}.rego",
                    "raw": rego,
                }
            )

            # Add policy metadata
            bundle["data"]["chronoguard"]["policies"][policy_name] = {
                "id": str(policy.policy_id),
                "tenant_id": str(policy.tenant_id),
                "priority": policy.priority,
                "status": policy.status,
                "version": policy.version,
            }

        logger.info(
            f"Generated OPA bundle with {len(policies)} policies, "
            f"revision {bundle['manifest']['revision']}"
        )
        return bundle

    async def evaluate_policy(
        self, policy_input: dict[str, Any], policy_path: str = "chronoguard/allow"
    ) -> bool:
        """Evaluate policy using OPA data API.

        Sends an input to OPA for policy evaluation and returns the decision.

        Args:
            policy_input: Input data for policy evaluation
            policy_path: OPA data path for evaluation (default: chronoguard/allow)

        Returns:
            Policy decision (True for allow, False for deny)

        Raises:
            PolicyCompilationError: If evaluation fails
        """
        try:
            if not self.session:
                self.session = aiohttp.ClientSession()

            async with self.session.post(
                f"{self.opa_url}/v1/data/{policy_path}",
                json={"input": policy_input},
                timeout=aiohttp.ClientTimeout(total=5),
            ) as response:
                if response.status != 200:
                    error_text = await response.text()
                    raise PolicyCompilationError(
                        f"OPA policy evaluation failed (HTTP {response.status}): {error_text}"
                    )

                result = await response.json()
                return bool(result.get("result", False))

        except aiohttp.ClientError as e:
            raise PolicyCompilationError(f"OPA request failed: {e}") from e
        except Exception as e:
            raise PolicyCompilationError(f"Policy evaluation failed: {e}") from e

    async def _validate_rego(self, rego: str) -> None:
        """Validate Rego syntax using OPA compile API.

        Args:
            rego: Rego code to validate

        Raises:
            PolicyCompilationError: If Rego syntax is invalid
        """
        try:
            if not self.session:
                self.session = aiohttp.ClientSession()

            compile_payload = {"query": "data.chronoguard.allow", "input": {}}

            async with self.session.post(
                f"{self.opa_url}/v1/compile",
                json=compile_payload,
                timeout=aiohttp.ClientTimeout(total=10),
            ) as response:
                if response.status != 200:
                    error_text = await response.text()
                    raise PolicyCompilationError(f"OPA syntax validation failed: {error_text}")

                result = await response.json()
                if "result" not in result:
                    raise PolicyCompilationError("Invalid response from OPA compile API")

        except aiohttp.ClientError as e:
            raise PolicyCompilationError(f"OPA validation request failed: {e}") from e

    def _format_time_restrictions(self, restrictions: TimeRestriction | None) -> dict[str, Any]:
        """Format time restrictions for Rego template.

        Args:
            restrictions: Time restrictions to format

        Returns:
            Formatted restrictions dictionary
        """
        if not restrictions or not restrictions.enabled:
            return {"enabled": False}

        offset_minutes = self._calculate_timezone_offset(restrictions.timezone)

        return {
            "enabled": True,
            "timezone": restrictions.timezone,
            "allowed_days": sorted(restrictions.allowed_days_of_week),
            "timezone_offset_minutes": offset_minutes,
            "time_ranges": [
                {
                    "start_hour": tr.start_hour,
                    "start_minute": tr.start_minute,
                    "end_hour": tr.end_hour,
                    "end_minute": tr.end_minute,
                }
                for tr in restrictions.allowed_time_ranges
            ],
        }

    def _format_rate_limits(self, limits: RateLimit | None) -> dict[str, Any]:
        """Format rate limits for Rego template.

        Args:
            limits: Rate limits to format

        Returns:
            Formatted rate limits dictionary
        """
        if not limits or not limits.enabled:
            return {"enabled": False}

        return {
            "enabled": True,
            "requests_per_minute": limits.requests_per_minute,
            "requests_per_hour": limits.requests_per_hour,
            "requests_per_day": limits.requests_per_day,
            "burst_limit": limits.burst_limit,
        }

    def _format_rules(self, policy: Policy) -> list[dict[str, Any]]:
        """Format policy rules for Rego template.

        Args:
            policy: Policy containing rules

        Returns:
            Formatted rules list
        """
        formatted_rules = []

        for rule in policy.rules:
            if not rule.enabled:
                continue

            formatted_rules.append(
                {
                    "rule_id": str(rule.rule_id),
                    "name": rule.name,
                    "action": rule.action,
                    "priority": rule.priority,
                    "conditions": [
                        {
                            "field": cond.field,
                            "operator": cond.operator,
                            "value": cond.value,
                        }
                        for cond in rule.conditions
                    ],
                }
            )

        return sorted(formatted_rules, key=lambda r: r["priority"])

    def _calculate_timezone_offset(self, timezone_name: str) -> int:
        """Convert timezone to UTC offset in minutes."""

        try:
            tz = zoneinfo.ZoneInfo(timezone_name)
        except Exception:
            return 0

        now_utc = datetime.now(UTC)
        offset = now_utc.astimezone(tz).utcoffset() or timedelta()
        return int(offset.total_seconds() // 60)

    def _sanitize_name(self, name: str) -> str:
        """Sanitize policy name for use in Rego identifiers.

        Args:
            name: Policy name to sanitize

        Returns:
            Sanitized name suitable for Rego identifiers
        """
        # Replace spaces and special chars with underscores
        sanitized = "".join(c if c.isalnum() else "_" for c in name)
        # Remove consecutive underscores
        while "__" in sanitized:
            sanitized = sanitized.replace("__", "_")
        # Remove leading/trailing underscores
        return sanitized.strip("_").lower()

    def _generate_revision(self) -> str:
        """Generate unique revision ID for bundles.

        Returns:
            Revision ID as hex string
        """
        timestamp = str(time.time()).encode()
        return hashlib.sha256(timestamp).hexdigest()[:12]

    async def push_policies(self, policies: list[Policy]) -> None:
        """Push policies to OPA using policy API.

        Compiles and deploys each policy individually to OPA. For production
        deployments, consider using bundle-based deployment with generate_bundle.

        Args:
            policies: List of policies to push to OPA

        Raises:
            PolicyCompilationError: If pushing policies fails

        Note:
            Uses /v1/policies endpoint for individual policy updates.
            For bundle-based deployment, serve bundles via HTTP server
            and configure OPA to pull from bundle server.
        """
        try:
            for policy in policies:
                await self.deploy_policy(policy)

            logger.info(f"Successfully pushed {len(policies)} policies to OPA")

        except Exception as e:
            logger.error(f"Failed to push policies to OPA: {e}", exc_info=True)
            raise PolicyCompilationError(f"Failed to push policies: {e}") from e

    async def close(self) -> None:
        """Close HTTP session."""
        if self.session:
            await self.session.close()
            self.session = None
            logger.debug("Closed OPA policy compiler session")

    async def __aenter__(self) -> PolicyCompiler:
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Async context manager exit."""
        await self.close()
