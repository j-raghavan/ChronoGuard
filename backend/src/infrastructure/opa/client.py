"""OPA HTTP client for policy evaluation and management.

This module provides an async HTTP client for interacting with Open Policy Agent (OPA)
via its REST API. It handles policy evaluation, policy upload/updates, health checks,
and includes retry logic with timeout support.
"""

from __future__ import annotations

import asyncio
from typing import Any

import aiohttp
from core.config import ProxySettings
from loguru import logger


class OPAClientError(Exception):
    """Base exception for OPA client errors."""

    pass


class OPAConnectionError(OPAClientError):
    """Exception raised when unable to connect to OPA."""

    pass


class OPAPolicyError(OPAClientError):
    """Exception raised for policy-related errors."""

    pass


class OPAEvaluationError(OPAClientError):
    """Exception raised for policy evaluation errors."""

    pass


class OPAClient:
    """Async HTTP client for OPA REST API.

    This client provides methods for interacting with OPA's REST API (port 8181)
    including policy evaluation, policy management, and health checks. It integrates
    with core configuration and includes retry logic with configurable timeouts.

    Example:
        >>> settings = ProxySettings()
        >>> async with OPAClient(settings) as client:
        ...     allowed = await client.check_policy({"domain": "example.com"})
        ...     health = await client.health_check()
    """

    def __init__(
        self,
        settings: ProxySettings | None = None,
        max_retries: int = 3,
        retry_delay: float = 1.0,
    ) -> None:
        """Initialize OPA client.

        Args:
            settings: Proxy settings with OPA configuration. If None, uses defaults.
            max_retries: Maximum number of retry attempts for failed requests
            retry_delay: Delay in seconds between retry attempts

        Raises:
            ValueError: If settings are invalid
        """
        if settings is None:
            settings = ProxySettings()

        self.opa_url = settings.opa_url.rstrip("/")
        self.policy_path = settings.opa_policy_path.lstrip("/")
        self.timeout = settings.opa_timeout
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.session: aiohttp.ClientSession | None = None

        logger.debug(
            f"Initialized OPA client: url={self.opa_url}, timeout={self.timeout}s, "
            f"max_retries={self.max_retries}"
        )

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create HTTP session.

        Returns:
            Active HTTP session
        """
        if self.session is None or self.session.closed:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            self.session = aiohttp.ClientSession(timeout=timeout)
        return self.session

    async def check_policy(
        self,
        policy_input: dict[str, Any],
        policy_path: str | None = None,
    ) -> bool:
        """Evaluate policy using OPA data API.

        Sends an input to OPA for policy evaluation and returns the decision.
        Includes retry logic for transient failures.

        Args:
            policy_input: Input data for policy evaluation
            policy_path: Optional OPA data path (default: from settings)

        Returns:
            Policy decision (True for allow, False for deny)

        Raises:
            OPAEvaluationError: If evaluation fails after retries
            OPAConnectionError: If unable to connect to OPA

        Example:
            >>> result = await client.check_policy({
            ...     "agent_id": "agent-123",
            ...     "domain": "example.com",
            ...     "timestamp": "2024-01-01T12:00:00Z"
            ... })
        """
        path = policy_path or self.policy_path
        url = f"{self.opa_url}/{path}"

        for attempt in range(1, self.max_retries + 1):
            try:
                session = await self._get_session()

                async with session.post(
                    url,
                    json={"input": policy_input},
                ) as response:
                    if response.status == 200:
                        result = await response.json()
                        decision = bool(result.get("result", False))

                        logger.debug(
                            f"Policy evaluation: decision={decision}, "
                            f"input={policy_input}, attempt={attempt}"
                        )
                        return decision

                    # Log error response
                    error_text = await response.text()
                    logger.warning(
                        f"OPA evaluation failed (HTTP {response.status}): {error_text}, "
                        f"attempt={attempt}/{self.max_retries}"
                    )

                    # Retry on server errors (5xx) or rate limiting (429)
                    if (
                        response.status >= 500 or response.status == 429
                    ) and attempt < self.max_retries:
                        await asyncio.sleep(self.retry_delay * attempt)
                        continue

                    # Don't retry on client errors (4xx)
                    raise OPAEvaluationError(
                        f"Policy evaluation failed (HTTP {response.status}): {error_text}"
                    )

            except aiohttp.ClientError as e:
                logger.warning(f"OPA connection error: {e}, attempt={attempt}/{self.max_retries}")

                if attempt < self.max_retries:
                    await asyncio.sleep(self.retry_delay * attempt)
                    continue

                raise OPAConnectionError(
                    f"Failed to connect to OPA after {attempt} attempts: {e}"
                ) from e

            except Exception as e:
                logger.error(f"Unexpected error during OPA evaluation: {e}", exc_info=True)
                raise OPAEvaluationError(f"Policy evaluation failed: {e}") from e

        raise OPAEvaluationError(f"Policy evaluation failed after {self.max_retries} attempts")

    async def update_policy(
        self,
        policy_name: str,
        rego_code: str,
    ) -> None:
        """Upload or update a policy in OPA.

        Uses OPA's policy API to upload or update Rego policy code.
        Includes retry logic for transient failures.

        Args:
            policy_name: Name/identifier for the policy
            rego_code: Rego policy code as string

        Raises:
            OPAPolicyError: If policy update fails after retries
            OPAConnectionError: If unable to connect to OPA

        Example:
            >>> rego = "package chronoguard\\nallow { true }"
            >>> await client.update_policy("test_policy", rego)
        """
        policy_path = f"chronoguard/policies/{policy_name}"
        url = f"{self.opa_url}/v1/policies/{policy_path}"

        for attempt in range(1, self.max_retries + 1):
            try:
                session = await self._get_session()

                async with session.put(
                    url,
                    data=rego_code,
                    headers={"Content-Type": "text/plain"},
                ) as response:
                    if response.status in (200, 201):
                        logger.info(
                            f"Successfully updated policy '{policy_name}' in OPA, "
                            f"attempt={attempt}"
                        )
                        return

                    # Log error response
                    error_text = await response.text()
                    logger.warning(
                        f"OPA policy update failed (HTTP {response.status}): {error_text}, "
                        f"attempt={attempt}/{self.max_retries}"
                    )

                    # Retry on server errors or rate limiting
                    if (
                        response.status >= 500 or response.status == 429
                    ) and attempt < self.max_retries:
                        await asyncio.sleep(self.retry_delay * attempt)
                        continue

                    # Don't retry on client errors
                    raise OPAPolicyError(
                        f"Policy update failed (HTTP {response.status}): {error_text}"
                    )

            except aiohttp.ClientError as e:
                logger.warning(
                    f"OPA connection error during policy update: {e}, "
                    f"attempt={attempt}/{self.max_retries}"
                )

                if attempt < self.max_retries:
                    await asyncio.sleep(self.retry_delay * attempt)
                    continue

                raise OPAConnectionError(
                    f"Failed to connect to OPA after {attempt} attempts: {e}"
                ) from e

            except OPAPolicyError:
                # Don't wrap OPAPolicyError
                raise

            except Exception as e:
                logger.error(f"Unexpected error during OPA policy update: {e}", exc_info=True)
                raise OPAPolicyError(f"Policy update failed: {e}") from e

        raise OPAPolicyError(f"Policy update failed after {self.max_retries} attempts")

    async def health_check(self) -> dict[str, Any]:
        """Check OPA server health.

        Queries OPA's health endpoint to verify server availability and status.

        Returns:
            Health status dictionary containing server information

        Raises:
            OPAConnectionError: If health check fails

        Example:
            >>> health = await client.health_check()
            >>> health['status']
            'ok'
        """
        url = f"{self.opa_url}/health"

        try:
            session = await self._get_session()

            async with session.get(url) as response:
                if response.status == 200:
                    health_data = await response.json()
                    logger.debug(f"OPA health check successful: {health_data}")
                    return health_data

                error_text = await response.text()
                logger.warning(f"OPA health check failed (HTTP {response.status}): {error_text}")

                raise OPAConnectionError(
                    f"OPA health check failed (HTTP {response.status}): {error_text}"
                )

        except aiohttp.ClientError as e:
            logger.error(f"Failed to connect to OPA health endpoint: {e}")
            raise OPAConnectionError(f"OPA health check failed: {e}") from e

        except Exception as e:
            logger.error(f"Unexpected error during OPA health check: {e}", exc_info=True)
            raise OPAConnectionError(f"OPA health check failed: {e}") from e

    async def get_policy(self, policy_name: str) -> str:
        """Retrieve a policy from OPA.

        Gets the Rego code for a specific policy from OPA.

        Args:
            policy_name: Name/identifier of the policy to retrieve

        Returns:
            Rego policy code as string

        Raises:
            OPAPolicyError: If policy retrieval fails
            OPAConnectionError: If unable to connect to OPA
        """
        policy_path = f"chronoguard/policies/{policy_name}"
        url = f"{self.opa_url}/v1/policies/{policy_path}"

        try:
            session = await self._get_session()

            async with session.get(url) as response:
                if response.status == 200:
                    result = await response.json()
                    rego_code = result.get("result", {}).get("raw", "")
                    logger.debug(f"Retrieved policy '{policy_name}' from OPA")
                    return str(rego_code)

                if response.status == 404:
                    raise OPAPolicyError(f"Policy '{policy_name}' not found in OPA")

                error_text = await response.text()
                raise OPAPolicyError(
                    f"Policy retrieval failed (HTTP {response.status}): {error_text}"
                )

        except aiohttp.ClientError as e:
            raise OPAConnectionError(f"Failed to connect to OPA: {e}") from e

        except OPAPolicyError:
            raise

        except Exception as e:
            logger.error(f"Unexpected error during OPA policy retrieval: {e}", exc_info=True)
            raise OPAPolicyError(f"Policy retrieval failed: {e}") from e

    async def delete_policy(self, policy_name: str) -> None:
        """Delete a policy from OPA.

        Removes a policy from OPA's policy store.

        Args:
            policy_name: Name/identifier of the policy to delete

        Raises:
            OPAPolicyError: If policy deletion fails
            OPAConnectionError: If unable to connect to OPA
        """
        policy_path = f"chronoguard/policies/{policy_name}"
        url = f"{self.opa_url}/v1/policies/{policy_path}"

        try:
            session = await self._get_session()

            async with session.delete(url) as response:
                if response.status in (200, 204):
                    logger.info(f"Successfully deleted policy '{policy_name}' from OPA")
                    return

                if response.status == 404:
                    logger.warning(f"Policy '{policy_name}' not found in OPA (already deleted)")
                    return

                error_text = await response.text()
                raise OPAPolicyError(
                    f"Policy deletion failed (HTTP {response.status}): {error_text}"
                )

        except aiohttp.ClientError as e:
            raise OPAConnectionError(f"Failed to connect to OPA: {e}") from e

        except OPAPolicyError:
            raise

        except Exception as e:
            logger.error(f"Unexpected error during OPA policy deletion: {e}", exc_info=True)
            raise OPAPolicyError(f"Policy deletion failed: {e}") from e

    async def close(self) -> None:
        """Close HTTP session and cleanup resources."""
        if self.session and not self.session.closed:
            await self.session.close()
            self.session = None
            logger.debug("Closed OPA client session")

    async def __aenter__(self) -> OPAClient:
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Async context manager exit."""
        await self.close()
