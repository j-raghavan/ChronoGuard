"""Domain name value object with validation and security features."""

from __future__ import annotations

import re

from domain.common.exceptions import SecurityViolationError, ValidationError
from pydantic import BaseModel, field_validator


class DomainName(BaseModel):
    """Immutable domain name value object with security validation."""

    value: str

    class Config:
        """Pydantic configuration."""

        frozen = True

    @field_validator("value", mode="before")
    @classmethod
    def validate_domain_name(cls, v: str) -> str:
        """Validate domain name format and security constraints.

        Args:
            v: Domain name to validate

        Returns:
            Validated domain name

        Raises:
            ValidationError: If domain format is invalid
            SecurityViolationError: If domain violates security rules
        """
        if not v:
            raise ValidationError("Domain name cannot be empty", field="value", value=v)

        # Normalize to lowercase
        v = v.lower().strip()

        # Basic length check
        if len(v) > 253:
            raise ValidationError(
                f"Domain name too long: {len(v)} characters (max 253)",
                field="value",
                value=v,
            )

        # Check for IP addresses (security concern)
        if cls._is_ip_address(v):
            raise SecurityViolationError(
                f"IP addresses not allowed as domain names: {v}",
                violation_type="IP_LITERAL",
                context={"domain": v},
            )

        # Validate domain format
        if not cls._is_valid_domain_format(v):
            raise ValidationError(
                f"Invalid domain name format: {v}",
                field="value",
                value=v,
            )

        # Check for suspicious patterns
        cls._check_security_patterns(v)

        return v

    @staticmethod
    def _is_ip_address(value: str) -> bool:
        """Check if value is an IP address.

        Args:
            value: String to check

        Returns:
            True if value appears to be an IP address
        """
        # IPv4 pattern
        ipv4_pattern = (
            r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
            r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
        )
        if re.match(ipv4_pattern, value):
            return True

        # IPv6 pattern (simplified)
        return ":" in value and re.match(r"^[0-9a-fA-F:]+$", value) is not None

    @staticmethod
    def _is_valid_domain_format(value: str) -> bool:
        """Validate domain name format according to RFC standards.

        Args:
            value: Domain name to validate

        Returns:
            True if format is valid
        """
        # Domain name pattern (simplified RFC compliance)
        domain_pattern = (
            r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
            r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$"
        )

        # Allow single label domains for internal use
        single_label_pattern = r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$"

        return bool(re.match(domain_pattern, value) or re.match(single_label_pattern, value))

    @staticmethod
    def _check_security_patterns(value: str) -> None:
        """Check for suspicious domain patterns.

        Args:
            value: Domain name to check

        Raises:
            SecurityViolationError: If suspicious patterns are detected
        """
        # Check for suspicious TLDs or patterns
        suspicious_patterns = {
            "localhost": "Local addresses not allowed",
            "127.": "Loopback addresses not allowed",
            "192.168.": "Private IP ranges not allowed",
            "10.": "Private IP ranges not allowed",
            "172.": "Private IP ranges not allowed",
        }

        for pattern, message in suspicious_patterns.items():
            if pattern in value:
                raise SecurityViolationError(
                    f"{message}: {value}",
                    violation_type="SUSPICIOUS_DOMAIN",
                    context={"domain": value, "pattern": pattern},
                )

        # Check for excessive subdomain nesting (potential DGA)
        if value.count(".") > 5:
            raise SecurityViolationError(
                f"Excessive subdomain nesting detected: {value}",
                violation_type="SUSPICIOUS_NESTING",
                context={"domain": value, "levels": value.count(".") + 1},
            )

    @property
    def root_domain(self) -> str:
        """Get the root domain (last two parts).

        Returns:
            Root domain string
        """
        parts = self.value.split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return self.value

    @property
    def subdomain(self) -> str:
        """Get the subdomain part.

        Returns:
            Subdomain string, empty if none
        """
        parts = self.value.split(".")
        if len(parts) > 2:
            return ".".join(parts[:-2])
        return ""

    @property
    def tld(self) -> str:
        """Get the top-level domain.

        Returns:
            TLD string
        """
        parts = self.value.split(".")
        return parts[-1] if parts else ""

    def is_subdomain_of(self, parent: DomainName) -> bool:
        """Check if this domain is a subdomain of another.

        Args:
            parent: Parent domain to check against

        Returns:
            True if this is a subdomain of parent
        """
        return self.value.endswith(f".{parent.value}")

    def matches_wildcard(self, pattern: str) -> bool:
        """Check if domain matches a wildcard pattern.

        Args:
            pattern: Wildcard pattern (e.g., "*.example.com")

        Returns:
            True if domain matches pattern
        """
        if not pattern.startswith("*."):
            return self.value == pattern

        # Remove the "*." prefix and check if domain ends with the pattern
        suffix = pattern[2:]
        return self.value.endswith(f".{suffix}") or self.value == suffix

    @classmethod
    def from_url(cls, url: str) -> DomainName:
        """Extract domain name from URL.

        Args:
            url: URL to extract domain from

        Returns:
            DomainName instance

        Raises:
            ValidationError: If URL format is invalid
        """
        import urllib.parse

        try:
            parsed = urllib.parse.urlparse(url)
        except Exception as e:
            raise ValidationError(f"Invalid URL format: {url}", field="url", value=url) from e

        if not parsed.netloc:
            raise ValidationError(f"No domain found in URL: {url}", field="url", value=url)

        # Remove port if present
        domain = parsed.netloc.split(":")[0]
        return cls(value=domain)

    def to_punycode(self) -> str:
        """Convert domain to punycode if needed.

        Returns:
            Punycode representation of domain
        """
        try:
            return self.value.encode("idna").decode("ascii")
        except UnicodeError:
            return self.value

    def __str__(self) -> str:
        """String representation.

        Returns:
            Domain name string
        """
        return self.value

    def __hash__(self) -> int:
        """Hash for use in sets and dicts.

        Returns:
            Hash of domain name
        """
        return hash(self.value)
