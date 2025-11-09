"""Cryptographic signing infrastructure for audit system.

This module provides RSA and ECDSA digital signature capabilities for audit entries,
including key management, rotation, and HSM/KMS integration hooks.
"""

from __future__ import annotations

from abc import abstractmethod
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from domain.common.exceptions import SecurityViolationError
from loguru import logger


class SignerError(SecurityViolationError):
    """Raised when signature operations fail."""

    def __init__(self, message: str) -> None:
        """Initialize signer error.

        Args:
            message: Error message
        """
        super().__init__(
            message,
            violation_type="SIGNER_ERROR",
        )


class Signer(Protocol):
    """Abstract interface for cryptographic signers."""

    @abstractmethod
    def sign(self, data: bytes) -> bytes:
        """Sign data with private key.

        Args:
            data: Data to sign

        Returns:
            Signature bytes

        Raises:
            SignerError: If signing fails
        """
        ...

    @abstractmethod
    def verify(self, data: bytes, signature: bytes) -> bool:
        """Verify signature with public key.

        Args:
            data: Original data
            signature: Signature to verify

        Returns:
            True if signature is valid

        Raises:
            SignerError: If verification fails
        """
        ...

    @abstractmethod
    def generate_key(self) -> None:
        """Generate a new key pair.

        Raises:
            SignerError: If key generation fails
        """
        ...

    @abstractmethod
    def load_key(self, path: Path) -> None:
        """Load private key from file.

        Args:
            path: Path to private key file

        Raises:
            SignerError: If key loading fails
        """
        ...

    @abstractmethod
    def save_key(self, path: Path, password: bytes | None = None) -> None:
        """Save private key to file.

        Args:
            path: Path to save private key
            password: Optional password for key encryption

        Raises:
            SignerError: If key saving fails
        """
        ...

    @abstractmethod
    def export_public_key(self) -> bytes:
        """Export public key in PEM format.

        Returns:
            Public key bytes in PEM format

        Raises:
            SignerError: If export fails
        """
        ...


class RSASigner:
    """RSA digital signature implementation.

    Uses RSA-PSS padding with SHA-256 hash for secure signatures.
    Default key size is 2048 bits for production use.
    """

    def __init__(self, key_size: int = 2048) -> None:
        """Initialize RSA signer.

        Args:
            key_size: RSA key size in bits (minimum 2048)

        Raises:
            SignerError: If key size is invalid
        """
        if key_size < 2048:
            raise SignerError("RSA key size must be at least 2048 bits for security")

        self._key_size = key_size
        self._private_key: rsa.RSAPrivateKey | None = None
        self._public_key: rsa.RSAPublicKey | None = None
        self._hash_algorithm = hashes.SHA256()

    def generate_key(self) -> None:
        """Generate a new RSA key pair.

        Raises:
            SignerError: If key generation fails
        """
        try:
            logger.info(f"Generating RSA key pair with {self._key_size} bits")
            self._private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=self._key_size,
                backend=default_backend(),
            )
            self._public_key = self._private_key.public_key()
            logger.info("RSA key pair generated successfully")
        except Exception as e:
            raise SignerError(f"Failed to generate RSA key: {e}") from e

    def load_key(self, path: Path) -> None:
        """Load private key from PEM file.

        Args:
            path: Path to private key file

        Raises:
            SignerError: If key loading fails
        """
        try:
            logger.info(f"Loading RSA private key from {path}")

            if not path.exists():
                raise SignerError(f"Key file not found: {path}")

            with open(path, "rb") as key_file:
                key_data = key_file.read()

            loaded_key: Any = serialization.load_pem_private_key(
                key_data,
                password=None,
                backend=default_backend(),
            )

            if not isinstance(loaded_key, rsa.RSAPrivateKey):
                raise SignerError(f"Invalid RSA key format in {path}")

            self._private_key = loaded_key

            self._public_key = self._private_key.public_key()
            logger.info("RSA private key loaded successfully")
        except Exception as e:
            if isinstance(e, SignerError):
                raise
            raise SignerError(f"Failed to load RSA key: {e}") from e

    def save_key(self, path: Path, password: bytes | None = None) -> None:
        """Save private key to PEM file.

        Args:
            path: Path to save private key
            password: Optional password for key encryption

        Raises:
            SignerError: If key saving fails
        """
        if self._private_key is None:
            raise SignerError("No private key to save. Generate or load a key first.")

        try:
            logger.info(f"Saving RSA private key to {path}")

            # Ensure parent directory exists
            path.parent.mkdir(parents=True, exist_ok=True)

            encryption_algorithm: serialization.KeySerializationEncryption
            if password:
                encryption_algorithm = serialization.BestAvailableEncryption(password)
            else:
                encryption_algorithm = serialization.NoEncryption()

            pem = self._private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=encryption_algorithm,
            )

            with open(path, "wb") as key_file:
                key_file.write(pem)

            # Set restrictive permissions (owner read/write only)
            path.chmod(0o600)
            logger.info("RSA private key saved successfully")
        except Exception as e:
            if isinstance(e, SignerError):
                raise
            raise SignerError(f"Failed to save RSA key: {e}") from e

    def sign(self, data: bytes) -> bytes:
        """Sign data using RSA-PSS with SHA-256.

        Args:
            data: Data to sign

        Returns:
            Signature bytes

        Raises:
            SignerError: If signing fails
        """
        if self._private_key is None:
            raise SignerError("No private key loaded. Generate or load a key first.")

        try:
            return self._private_key.sign(
                data,
                padding.PSS(
                    mgf=padding.MGF1(self._hash_algorithm),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                self._hash_algorithm,
            )
        except Exception as e:
            raise SignerError(f"Failed to sign data: {e}") from e

    def verify(self, data: bytes, signature: bytes) -> bool:
        """Verify RSA-PSS signature.

        Args:
            data: Original data
            signature: Signature to verify

        Returns:
            True if signature is valid

        Raises:
            SignerError: If verification fails due to errors (not invalid signature)
        """
        if self._public_key is None:
            raise SignerError("No public key available. Generate or load a key first.")

        try:
            self._public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(self._hash_algorithm),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                self._hash_algorithm,
            )
            return True
        except Exception as e:
            # Invalid signature is not an error, return False
            logger.debug(f"Signature verification failed: {e}")
            return False

    def export_public_key(self) -> bytes:
        """Export public key in PEM format.

        Returns:
            Public key bytes in PEM format

        Raises:
            SignerError: If export fails
        """
        if self._public_key is None:
            raise SignerError("No public key available. Generate or load a key first.")

        try:
            return self._public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        except Exception as e:
            raise SignerError(f"Failed to export public key: {e}") from e

    def load_public_key(self, pem_data: bytes) -> None:
        """Load public key from PEM data.

        Args:
            pem_data: PEM-encoded public key

        Raises:
            SignerError: If loading fails
        """
        try:
            key = serialization.load_pem_public_key(pem_data, backend=default_backend())

            if not isinstance(key, rsa.RSAPublicKey):
                raise SignerError("Invalid RSA public key format")

            self._public_key = key
            logger.info("RSA public key loaded successfully")
        except Exception as e:
            if isinstance(e, SignerError):
                raise
            raise SignerError(f"Failed to load RSA public key: {e}") from e


class ECDSASigner:
    """ECDSA digital signature implementation.

    Uses ECDSA with SHA-256 hash and SECP256R1 curve (also known as P-256).
    This provides 128-bit security level with smaller key sizes than RSA.
    """

    def __init__(self, curve: ec.EllipticCurve | None = None) -> None:
        """Initialize ECDSA signer.

        Args:
            curve: Elliptic curve to use (default: SECP256R1/P-256)
        """
        self._curve = curve if curve is not None else ec.SECP256R1()
        self._private_key: ec.EllipticCurvePrivateKey | None = None
        self._public_key: ec.EllipticCurvePublicKey | None = None
        self._hash_algorithm = hashes.SHA256()

    def generate_key(self) -> None:
        """Generate a new ECDSA key pair.

        Raises:
            SignerError: If key generation fails
        """
        try:
            logger.info(f"Generating ECDSA key pair with curve {self._curve.name}")
            self._private_key = ec.generate_private_key(self._curve, default_backend())
            self._public_key = self._private_key.public_key()
            logger.info("ECDSA key pair generated successfully")
        except Exception as e:
            raise SignerError(f"Failed to generate ECDSA key: {e}") from e

    def load_key(self, path: Path) -> None:
        """Load private key from PEM file.

        Args:
            path: Path to private key file

        Raises:
            SignerError: If key loading fails
        """
        try:
            logger.info(f"Loading ECDSA private key from {path}")

            if not path.exists():
                raise SignerError(f"Key file not found: {path}")

            with open(path, "rb") as key_file:
                key_data = key_file.read()

            loaded_key: Any = serialization.load_pem_private_key(
                key_data,
                password=None,
                backend=default_backend(),
            )

            if not isinstance(loaded_key, ec.EllipticCurvePrivateKey):
                raise SignerError(f"Invalid ECDSA key format in {path}")

            self._private_key = loaded_key

            self._public_key = self._private_key.public_key()
            logger.info("ECDSA private key loaded successfully")
        except Exception as e:
            if isinstance(e, SignerError):
                raise
            raise SignerError(f"Failed to load ECDSA key: {e}") from e

    def save_key(self, path: Path, password: bytes | None = None) -> None:
        """Save private key to PEM file.

        Args:
            path: Path to save private key
            password: Optional password for key encryption

        Raises:
            SignerError: If key saving fails
        """
        if self._private_key is None:
            raise SignerError("No private key to save. Generate or load a key first.")

        try:
            logger.info(f"Saving ECDSA private key to {path}")

            # Ensure parent directory exists
            path.parent.mkdir(parents=True, exist_ok=True)

            encryption_algorithm: serialization.KeySerializationEncryption
            if password:
                encryption_algorithm = serialization.BestAvailableEncryption(password)
            else:
                encryption_algorithm = serialization.NoEncryption()

            pem = self._private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=encryption_algorithm,
            )

            with open(path, "wb") as key_file:
                key_file.write(pem)

            # Set restrictive permissions (owner read/write only)
            path.chmod(0o600)
            logger.info("ECDSA private key saved successfully")
        except Exception as e:
            if isinstance(e, SignerError):
                raise
            raise SignerError(f"Failed to save ECDSA key: {e}") from e

    def sign(self, data: bytes) -> bytes:
        """Sign data using ECDSA with SHA-256.

        Args:
            data: Data to sign

        Returns:
            Signature bytes

        Raises:
            SignerError: If signing fails
        """
        if self._private_key is None:
            raise SignerError("No private key loaded. Generate or load a key first.")

        try:
            return self._private_key.sign(data, ec.ECDSA(self._hash_algorithm))
        except Exception as e:
            raise SignerError(f"Failed to sign data: {e}") from e

    def verify(self, data: bytes, signature: bytes) -> bool:
        """Verify ECDSA signature.

        Args:
            data: Original data
            signature: Signature to verify

        Returns:
            True if signature is valid

        Raises:
            SignerError: If verification fails due to errors (not invalid signature)
        """
        if self._public_key is None:
            raise SignerError("No public key available. Generate or load a key first.")

        try:
            self._public_key.verify(signature, data, ec.ECDSA(self._hash_algorithm))
            return True
        except Exception as e:
            # Invalid signature is not an error, return False
            logger.debug(f"Signature verification failed: {e}")
            return False

    def export_public_key(self) -> bytes:
        """Export public key in PEM format.

        Returns:
            Public key bytes in PEM format

        Raises:
            SignerError: If export fails
        """
        if self._public_key is None:
            raise SignerError("No public key available. Generate or load a key first.")

        try:
            return self._public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        except Exception as e:
            raise SignerError(f"Failed to export public key: {e}") from e

    def load_public_key(self, pem_data: bytes) -> None:
        """Load public key from PEM data.

        Args:
            pem_data: PEM-encoded public key

        Raises:
            SignerError: If loading fails
        """
        try:
            key = serialization.load_pem_public_key(pem_data, backend=default_backend())

            if not isinstance(key, ec.EllipticCurvePublicKey):
                raise SignerError("Invalid ECDSA public key format")

            self._public_key = key
            logger.info("ECDSA public key loaded successfully")
        except Exception as e:
            if isinstance(e, SignerError):
                raise
            raise SignerError(f"Failed to load ECDSA public key: {e}") from e


class KeyManager:
    """Key management with rotation and versioning support.

    Manages multiple key versions for key rotation without breaking existing signatures.
    Provides hooks for HSM/KMS integration.
    """

    def __init__(
        self,
        storage_path: Path,
        signer_type: type[RSASigner] | type[ECDSASigner] = RSASigner,
        rotation_days: int = 90,
    ) -> None:
        """Initialize key manager.

        Args:
            storage_path: Base directory for key storage
            signer_type: Signer class to use (RSASigner or ECDSASigner)
            rotation_days: Days before recommending key rotation

        Raises:
            SignerError: If initialization fails
        """
        self._storage_path = Path(storage_path)
        self._signer_type = signer_type
        self._rotation_days = rotation_days
        self._current_key_version = 0
        self._signers: dict[int, RSASigner | ECDSASigner] = {}
        self._key_metadata: dict[int, dict[str, str]] = {}

        # Create storage directory
        try:
            self._storage_path.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            raise SignerError(f"Failed to create key storage directory: {e}") from e

    def generate_key(self) -> None:
        """Generate new key version and set as current.

        Raises:
            SignerError: If key generation fails
        """
        try:
            # Increment version
            new_version = self._current_key_version + 1

            # Create signer and generate key
            signer = self._signer_type()
            signer.generate_key()

            # Save key
            key_path = self._get_key_path(new_version)
            signer.save_key(key_path)

            # Store signer and metadata
            self._signers[new_version] = signer
            self._key_metadata[new_version] = {
                "created_at": datetime.now(UTC).isoformat(),
                "algorithm": type(signer).__name__,
                "status": "active",
            }

            # Update current version
            self._current_key_version = new_version

            logger.info(f"Generated new key version {new_version} using {type(signer).__name__}")
        except Exception as e:
            raise SignerError(f"Failed to generate new key: {e}") from e

    def load_key(self, path: Path) -> None:
        """Load existing key as current version.

        Args:
            path: Path to private key file

        Raises:
            SignerError: If key loading fails
        """
        try:
            signer = self._signer_type()
            signer.load_key(path)

            # Increment version for loaded key
            new_version = self._current_key_version + 1
            self._signers[new_version] = signer
            self._key_metadata[new_version] = {
                "created_at": datetime.now(UTC).isoformat(),
                "algorithm": type(signer).__name__,
                "status": "active",
                "loaded_from": str(path),
            }

            self._current_key_version = new_version
            logger.info(f"Loaded key from {path} as version {new_version}")
        except Exception as e:
            raise SignerError(f"Failed to load key: {e}") from e

    def rotate_key(self) -> None:
        """Rotate to new key version while keeping old keys for verification.

        Marks old key as deprecated but keeps it for signature verification.

        Raises:
            SignerError: If rotation fails
        """
        try:
            if self._current_key_version > 0:
                # Mark current key as deprecated
                self._key_metadata[self._current_key_version]["status"] = "deprecated"
                self._key_metadata[self._current_key_version]["deprecated_at"] = datetime.now(
                    UTC
                ).isoformat()

            # Generate new key
            self.generate_key()

            logger.info(f"Rotated to new key version {self._current_key_version}")
        except Exception as e:
            raise SignerError(f"Failed to rotate key: {e}") from e

    def sign(self, data: bytes) -> bytes:
        """Sign data with current key version.

        Args:
            data: Data to sign

        Returns:
            Signature bytes

        Raises:
            SignerError: If signing fails
        """
        if self._current_key_version == 0:
            raise SignerError("No key available. Generate or load a key first.")

        signer = self._signers[self._current_key_version]
        return signer.sign(data)

    def verify(self, data: bytes, signature: bytes, key_version: int | None = None) -> bool:
        """Verify signature with specified or current key version.

        Args:
            data: Original data
            signature: Signature to verify
            key_version: Key version to use (None for current)

        Returns:
            True if signature is valid

        Raises:
            SignerError: If verification fails
        """
        version = key_version if key_version is not None else self._current_key_version

        if version not in self._signers:
            raise SignerError(f"Key version {version} not found")

        signer = self._signers[version]
        return signer.verify(data, signature)

    def should_rotate(self) -> bool:
        """Check if key should be rotated based on age.

        Returns:
            True if key rotation is recommended
        """
        if self._current_key_version == 0:
            return True

        metadata = self._key_metadata[self._current_key_version]
        created_at = datetime.fromisoformat(metadata["created_at"])
        age_days = (datetime.now(UTC) - created_at).days

        return age_days >= self._rotation_days

    def get_key_metadata(self, version: int | None = None) -> dict[str, str]:
        """Get metadata for specified or current key version.

        Args:
            version: Key version (None for current)

        Returns:
            Key metadata dictionary

        Raises:
            SignerError: If key version not found
        """
        ver = version if version is not None else self._current_key_version

        if ver not in self._key_metadata:
            raise SignerError(f"Key version {ver} not found")

        return self._key_metadata[ver].copy()

    def export_public_key(self, version: int | None = None) -> bytes:
        """Export public key for specified or current version.

        Args:
            version: Key version (None for current)

        Returns:
            Public key bytes in PEM format

        Raises:
            SignerError: If export fails
        """
        ver = version if version is not None else self._current_key_version

        if ver not in self._signers:
            raise SignerError(f"Key version {ver} not found")

        return self._signers[ver].export_public_key()

    def hsm_integration_hook(self, hsm_config: dict[str, Any]) -> None:
        """Hook for HSM/KMS integration (placeholder).

        Args:
            hsm_config: HSM/KMS configuration

        Note:
            This is a placeholder for future HSM/KMS integration.
            Actual implementation would connect to HSM/KMS service.
        """
        logger.warning("HSM/KMS integration not yet implemented")
        logger.debug(f"HSM config received: {hsm_config}")

    def _get_key_path(self, version: int) -> Path:
        """Get file path for key version.

        Args:
            version: Key version number

        Returns:
            Path to key file
        """
        return self._storage_path / f"key_v{version}.pem"
