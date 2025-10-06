"""X.509 certificate value object with validation and security features."""

from __future__ import annotations

from datetime import UTC, datetime

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from domain.common.exceptions import SecurityViolationError, ValidationError
from pydantic import BaseModel, field_validator


class X509Certificate(BaseModel):
    """Immutable X.509 certificate value object with security validation."""

    pem_data: str

    class Config:
        """Pydantic configuration."""

        frozen = True

    @field_validator("pem_data")
    @classmethod
    def validate_certificate(cls, v: str) -> str:
        """Validate X.509 certificate format and security constraints.

        Args:
            v: PEM-encoded certificate data

        Returns:
            Validated PEM data

        Raises:
            ValidationError: If certificate format is invalid
            SecurityViolationError: If certificate violates security rules
        """
        if not v or not v.strip():
            raise ValidationError("Certificate data cannot be empty", field="pem_data", value="")

        try:
            # Parse the certificate
            cert = x509.load_pem_x509_certificate(v.encode(), default_backend())

            # Security validations
            cls._validate_certificate_security(cert)

            return v.strip()

        except SecurityViolationError:
            # Re-raise security violations as-is
            raise
        except ValueError as e:
            raise ValidationError(
                f"Invalid certificate format: {str(e)}",
                field="pem_data",
                value=v[:100] + "..." if len(v) > 100 else v,
            ) from e
        except Exception as e:
            raise ValidationError(
                f"Certificate parsing failed: {str(e)}",
                field="pem_data",
                value="<certificate_data>",
            ) from e

    @staticmethod
    def _validate_certificate_security(cert: x509.Certificate) -> None:
        """Validate certificate security properties.

        Args:
            cert: Parsed X.509 certificate

        Raises:
            SecurityViolationError: If security violations are detected
        """
        now = datetime.now(UTC)

        # Ensure certificate dates are timezone-aware for comparison
        not_valid_after = (
            cert.not_valid_after.replace(tzinfo=UTC)
            if cert.not_valid_after.tzinfo is None
            else cert.not_valid_after
        )
        not_valid_before = (
            cert.not_valid_before.replace(tzinfo=UTC)
            if cert.not_valid_before.tzinfo is None
            else cert.not_valid_before
        )

        # Check expiration
        if not_valid_after < now:
            raise SecurityViolationError(
                f"Certificate expired on {not_valid_after}",
                violation_type="EXPIRED_CERTIFICATE",
                context={"expiry_date": not_valid_after.isoformat()},
            )

        # Check not valid before
        if not_valid_before > now:
            raise SecurityViolationError(
                f"Certificate not yet valid (valid from {not_valid_before})",
                violation_type="PREMATURE_CERTIFICATE",
                context={"valid_from": not_valid_before.isoformat()},
            )

        # Check key size for RSA keys
        public_key = cert.public_key()
        if hasattr(public_key, "key_size") and public_key.key_size < 2048:
            raise SecurityViolationError(
                f"RSA key size too small: {public_key.key_size} bits (minimum 2048)",
                violation_type="WEAK_KEY",
                context={"key_size": public_key.key_size},
            )

        # Check for weak signature algorithms
        signature_alg = cert.signature_algorithm_oid._name
        weak_algorithms = {"md5", "sha1"}
        if any(weak_alg in signature_alg.lower() for weak_alg in weak_algorithms):
            raise SecurityViolationError(
                f"Weak signature algorithm: {signature_alg}",
                violation_type="WEAK_SIGNATURE_ALGORITHM",
                context={"algorithm": signature_alg},
            )

    @property
    def certificate(self) -> x509.Certificate:
        """Get the parsed X.509 certificate object.

        Returns:
            Cryptography X509Certificate object
        """
        return x509.load_pem_x509_certificate(self.pem_data.encode(), default_backend())

    @property
    def subject_common_name(self) -> str | None:
        """Get the subject common name from the certificate.

        Returns:
            Subject common name if present, None otherwise
        """
        cert = self.certificate
        try:
            cn_oid = x509.NameOID.COMMON_NAME
            return cert.subject.get_attributes_for_oid(cn_oid)[0].value
        except (IndexError, AttributeError):
            return None

    @property
    def subject_alt_names(self) -> list[str]:
        """Get subject alternative names from the certificate.

        Returns:
            List of subject alternative names
        """
        cert = self.certificate
        try:
            san_ext = cert.extensions.get_extension_for_oid(
                x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            return [name.value for name in san_ext.value]
        except x509.ExtensionNotFound:
            return []

    @property
    def issuer_common_name(self) -> str | None:
        """Get the issuer common name from the certificate.

        Returns:
            Issuer common name if present, None otherwise
        """
        cert = self.certificate
        try:
            cn_oid = x509.NameOID.COMMON_NAME
            return cert.issuer.get_attributes_for_oid(cn_oid)[0].value
        except (IndexError, AttributeError):
            return None

    @property
    def serial_number(self) -> str:
        """Get the certificate serial number.

        Returns:
            Certificate serial number as hex string
        """
        return hex(self.certificate.serial_number)[2:].upper()

    @property
    def fingerprint_sha256(self) -> str:
        """Get SHA256 fingerprint of the certificate.

        Returns:
            SHA256 fingerprint as hex string
        """
        from cryptography.hazmat.primitives import hashes, serialization

        digest = hashes.Hash(hashes.SHA256())
        digest.update(self.certificate.public_bytes(serialization.Encoding.DER))
        return digest.finalize().hex().upper()

    @property
    def not_valid_before(self) -> datetime:
        """Get the certificate's not-valid-before date.

        Returns:
            Not-valid-before datetime in UTC
        """
        return self.certificate.not_valid_before.replace(tzinfo=UTC)

    @property
    def not_valid_after(self) -> datetime:
        """Get the certificate's not-valid-after date.

        Returns:
            Not-valid-after datetime in UTC
        """
        return self.certificate.not_valid_after.replace(tzinfo=UTC)

    @property
    def is_valid_now(self) -> bool:
        """Check if certificate is currently valid (time-wise).

        Returns:
            True if certificate is currently valid
        """
        now = datetime.now(UTC)
        return self.not_valid_before <= now <= self.not_valid_after

    @property
    def days_until_expiry(self) -> int:
        """Get number of days until certificate expires.

        Returns:
            Days until expiry (negative if already expired)
        """
        now = datetime.now(UTC)
        delta = self.not_valid_after - now
        return delta.days

    def matches_domain(self, domain: str) -> bool:
        """Check if certificate is valid for a given domain.

        Args:
            domain: Domain name to check

        Returns:
            True if certificate is valid for the domain
        """
        domain = domain.lower()

        # Check common name
        if self.subject_common_name and self.subject_common_name.lower() == domain:
            return True

        # Check subject alternative names
        for san in self.subject_alt_names:
            san_lower = san.lower()
            if san_lower == domain:
                return True

            # Check wildcard matches
            if san_lower.startswith("*."):
                wildcard_domain = san_lower[2:]
                if domain.endswith(f".{wildcard_domain}") or domain == wildcard_domain:
                    return True

        return False

    def verify_chain(self, ca_certificates: list[X509Certificate]) -> bool:
        """Verify certificate chain against provided CA certificates.

        Args:
            ca_certificates: List of CA certificates to verify against

        Returns:
            True if chain verification succeeds

        Note:
            This is a simplified verification. Production systems should use
            a full certificate validation library.
        """
        # This is a placeholder for proper chain validation
        # In production, use a proper certificate validation library
        try:
            # Basic issuer check
            cert = self.certificate
            for ca_cert_obj in ca_certificates:
                ca_cert = ca_cert_obj.certificate
                if cert.issuer == ca_cert.subject:
                    return True
            return False
        except Exception:
            return False

    @classmethod
    def from_der(cls, der_data: bytes) -> X509Certificate:
        """Create certificate from DER-encoded data.

        Args:
            der_data: DER-encoded certificate bytes

        Returns:
            X509Certificate instance

        Raises:
            ValidationError: If DER data is invalid
        """
        from cryptography.hazmat.primitives import serialization

        try:
            cert = x509.load_der_x509_certificate(der_data, default_backend())
            pem_data = cert.public_bytes(serialization.Encoding.PEM).decode()
            return cls(pem_data=pem_data)
        except Exception as e:
            raise ValidationError(
                f"Invalid DER certificate data: {str(e)}",
                field="der_data",
                value="<der_bytes>",
            ) from e

    def to_der(self) -> bytes:
        """Convert certificate to DER format.

        Returns:
            DER-encoded certificate bytes
        """
        from cryptography.hazmat.primitives import serialization

        cert = self.certificate
        return cert.public_bytes(serialization.Encoding.DER)

    def __str__(self) -> str:
        """String representation of certificate.

        Returns:
            Human-readable certificate information
        """
        return (
            f"X509Certificate(subject={self.subject_common_name}, "
            f"issuer={self.issuer_common_name}, "
            f"serial={self.serial_number}, "
            f"expires={self.not_valid_after.strftime('%Y-%m-%d')})"
        )
