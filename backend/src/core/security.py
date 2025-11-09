"""Security utilities for authentication and cryptography.

This module provides password hashing, JWT token management, and certificate validation
utilities for ChronoGuard's security infrastructure.
"""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta, UTC
from typing import Any

from core.config import SecuritySettings, get_settings
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.x509 import Certificate
from jose import JWTError, jwt
from passlib.context import CryptContext


class SecurityError(Exception):
    """Base exception for security operations."""

    pass


class PasswordHashingError(SecurityError):
    """Raised when password hashing fails."""

    pass


class TokenError(SecurityError):
    """Raised when token operations fail."""

    pass


class CertificateValidationError(SecurityError):
    """Raised when certificate validation fails."""

    pass


# Password hashing context with bcrypt
_pwd_context: CryptContext | None = None


def get_password_context(security_settings: SecuritySettings | None = None) -> CryptContext:
    """Get or create password hashing context.

    Args:
        security_settings: Security settings. Uses global settings if None.

    Returns:
        Configured CryptContext instance
    """
    global _pwd_context

    if _pwd_context is None:
        if security_settings is None:
            security_settings = get_settings().security

        _pwd_context = CryptContext(
            schemes=["bcrypt"],
            deprecated="auto",
            bcrypt__rounds=security_settings.bcrypt_rounds,
        )

    return _pwd_context


def hash_password(password: str, security_settings: SecuritySettings | None = None) -> str:
    """Hash a password using bcrypt.

    Args:
        password: Plain text password to hash
        security_settings: Security settings. Uses global settings if None.

    Returns:
        Hashed password string

    Raises:
        PasswordHashingError: If hashing fails

    Example:
        >>> hashed = hash_password("secure_password123")
        >>> assert hashed.startswith("$2b$")
    """
    try:
        ctx = get_password_context(security_settings)
        return ctx.hash(password)
    except Exception as e:
        raise PasswordHashingError(f"Failed to hash password: {e}") from e


def verify_password(
    plain_password: str,
    hashed_password: str,
    security_settings: SecuritySettings | None = None,
) -> bool:
    """Verify a password against its hash.

    Args:
        plain_password: Plain text password to verify
        hashed_password: Hashed password to verify against
        security_settings: Security settings. Uses global settings if None.

    Returns:
        True if password matches, False otherwise

    Example:
        >>> hashed = hash_password("secret")
        >>> assert verify_password("secret", hashed)
        >>> assert not verify_password("wrong", hashed)
    """
    try:
        ctx = get_password_context(security_settings)
        return ctx.verify(plain_password, hashed_password)
    except Exception:
        return False


def validate_password_strength(
    password: str, security_settings: SecuritySettings | None = None
) -> tuple[bool, list[str]]:
    """Validate password strength against security requirements.

    Args:
        password: Password to validate
        security_settings: Security settings. Uses global settings if None.

    Returns:
        Tuple of (is_valid, list of error messages)

    Example:
        >>> valid, errors = validate_password_strength("Abc123!@#")
        >>> assert valid
        >>> assert len(errors) == 0
    """
    if security_settings is None:
        security_settings = get_settings().security

    errors: list[str] = []

    # Check minimum length
    if len(password) < security_settings.password_min_length:
        errors.append(
            f"Password must be at least {security_settings.password_min_length} characters"
        )

    # Check uppercase requirement
    if security_settings.password_require_uppercase and not any(c.isupper() for c in password):
        errors.append("Password must contain at least one uppercase letter")

    # Check lowercase requirement
    if security_settings.password_require_lowercase and not any(c.islower() for c in password):
        errors.append("Password must contain at least one lowercase letter")

    # Check digits requirement
    if security_settings.password_require_digits and not any(c.isdigit() for c in password):
        errors.append("Password must contain at least one digit")

    # Check special characters requirement
    if security_settings.password_require_special:
        special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        if not any(c in special_chars for c in password):
            errors.append("Password must contain at least one special character")

    return (len(errors) == 0, errors)


def create_access_token(
    data: dict[str, Any],
    expires_delta: timedelta | None = None,
    security_settings: SecuritySettings | None = None,
) -> str:
    """Create a JWT access token.

    Args:
        data: Data to encode in the token
        expires_delta: Token expiration time. Uses default if None.
        security_settings: Security settings. Uses global settings if None.

    Returns:
        Encoded JWT token string

    Raises:
        TokenError: If token creation fails

    Example:
        >>> token = create_access_token({"sub": "user123"})
        >>> assert isinstance(token, str)
    """
    if security_settings is None:
        security_settings = get_settings().security

    try:
        to_encode = data.copy()

        # Set expiration
        now = datetime.now(UTC)
        if expires_delta:
            expire = now + expires_delta
        else:
            expire = now + timedelta(minutes=security_settings.access_token_expire_minutes)

        to_encode.update({"exp": expire, "iat": now})

        # Encode token
        return jwt.encode(
            to_encode, security_settings.secret_key, algorithm=security_settings.algorithm
        )

    except Exception as e:
        raise TokenError(f"Failed to create access token: {e}") from e


def create_refresh_token(
    data: dict[str, Any],
    security_settings: SecuritySettings | None = None,
) -> str:
    """Create a JWT refresh token.

    Args:
        data: Data to encode in the token
        security_settings: Security settings. Uses global settings if None.

    Returns:
        Encoded JWT refresh token string

    Raises:
        TokenError: If token creation fails
    """
    if security_settings is None:
        security_settings = get_settings().security

    expires_delta = timedelta(days=security_settings.refresh_token_expire_days)
    return create_access_token(data, expires_delta, security_settings)


def decode_token(token: str, security_settings: SecuritySettings | None = None) -> dict[str, Any]:
    """Decode and validate a JWT token.

    Args:
        token: JWT token to decode
        security_settings: Security settings. Uses global settings if None.

    Returns:
        Decoded token payload

    Raises:
        TokenError: If token is invalid or expired

    Example:
        >>> token = create_access_token({"sub": "user123"})
        >>> payload = decode_token(token)
        >>> assert payload["sub"] == "user123"
    """
    if security_settings is None:
        security_settings = get_settings().security

    try:
        return jwt.decode(
            token, security_settings.secret_key, algorithms=[security_settings.algorithm]
        )
    except JWTError as e:
        raise TokenError(f"Invalid token: {e}") from e


def generate_secret_key(length: int = 32) -> str:
    """Generate a cryptographically secure secret key.

    Args:
        length: Length of the secret key in bytes. Defaults to 32.

    Returns:
        URL-safe base64-encoded secret key

    Example:
        >>> key = generate_secret_key()
        >>> assert len(key) >= 32
    """
    return secrets.token_urlsafe(length)


def load_certificate_from_pem(pem_data: str | bytes) -> Certificate:
    """Load an X.509 certificate from PEM format.

    Args:
        pem_data: PEM-encoded certificate data

    Returns:
        X.509 Certificate object

    Raises:
        CertificateValidationError: If certificate loading fails

    Example:
        >>> pem = "-----BEGIN CERTIFICATE-----\\n...\\n-----END CERTIFICATE-----"
        >>> cert = load_certificate_from_pem(pem)
    """
    try:
        if isinstance(pem_data, str):
            pem_data = pem_data.encode("utf-8")

        return x509.load_pem_x509_certificate(pem_data, default_backend())

    except Exception as e:
        raise CertificateValidationError(f"Failed to load certificate: {e}") from e


def validate_certificate(
    cert: Certificate,
    check_expiration: bool = True,
    trusted_ca_cert: Certificate | None = None,
) -> tuple[bool, list[str]]:
    """Validate an X.509 certificate.

    Args:
        cert: Certificate to validate
        check_expiration: Whether to check expiration dates. Defaults to True.
        trusted_ca_cert: CA certificate to verify against. Optional.

    Returns:
        Tuple of (is_valid, list of error messages)

    Note:
        For full cryptographic verification, use external libraries like
        pyOpenSSL or certifi. This provides basic validation only.

    Example:
        >>> cert = load_certificate_from_pem(pem_data)
        >>> is_valid, errors = validate_certificate(cert)
    """
    errors: list[str] = []

    # Check expiration
    if check_expiration:
        now = datetime.now(UTC)
        if cert.not_valid_before > now:
            errors.append(f"Certificate not yet valid (valid from {cert.not_valid_before})")
        if cert.not_valid_after < now:
            errors.append(f"Certificate expired on {cert.not_valid_after}")

    # Verify issuer matches CA subject if CA cert provided
    if trusted_ca_cert and cert.issuer != trusted_ca_cert.subject:
        errors.append(
            f"Certificate issuer does not match CA subject: "
            f"{cert.issuer.rfc4514_string()} != {trusted_ca_cert.subject.rfc4514_string()}"
        )

    return (len(errors) == 0, errors)


def extract_certificate_info(cert: Certificate) -> dict[str, Any]:
    """Extract information from an X.509 certificate.

    Args:
        cert: Certificate to extract information from

    Returns:
        Dictionary containing certificate information

    Example:
        >>> cert = load_certificate_from_pem(pem_data)
        >>> info = extract_certificate_info(cert)
        >>> assert "subject" in info
        >>> assert "issuer" in info
    """
    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "serial_number": cert.serial_number,
        "version": cert.version.name,
        "not_valid_before": cert.not_valid_before.isoformat(),
        "not_valid_after": cert.not_valid_after.isoformat(),
        "signature_algorithm": cert.signature_algorithm_oid._name,
        "public_key_algorithm": cert.public_key().__class__.__name__,
    }


def get_certificate_fingerprint(cert: Certificate, algorithm: str = "sha256") -> str:
    """Get certificate fingerprint (hash).

    Args:
        cert: Certificate to get fingerprint for
        algorithm: Hash algorithm to use. Defaults to "sha256".

    Returns:
        Hex-encoded fingerprint string

    Raises:
        CertificateValidationError: If algorithm is unsupported

    Example:
        >>> cert = load_certificate_from_pem(pem_data)
        >>> fingerprint = get_certificate_fingerprint(cert)
        >>> assert len(fingerprint) == 64  # SHA256 produces 64 hex chars
    """
    # Only secure hash algorithms - SHA1 removed due to cryptographic weakness
    hash_algorithms = {
        "sha256": hashes.SHA256(),
        "sha384": hashes.SHA384(),
        "sha512": hashes.SHA512(),
    }

    if algorithm.lower() not in hash_algorithms:
        raise CertificateValidationError(
            f"Unsupported hash algorithm: {algorithm}. Use sha256, sha384, or sha512."
        )

    fingerprint = cert.fingerprint(hash_algorithms[algorithm.lower()])
    return fingerprint.hex()


def constant_time_compare(val1: str, val2: str) -> bool:
    """Compare two strings in constant time to prevent timing attacks.

    Args:
        val1: First string to compare
        val2: Second string to compare

    Returns:
        True if strings are equal, False otherwise

    Example:
        >>> assert constant_time_compare("secret", "secret")
        >>> assert not constant_time_compare("secret", "SECRET")
    """
    return secrets.compare_digest(val1.encode(), val2.encode())
