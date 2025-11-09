"""Unit tests for infrastructure.security.signer module.

This module provides comprehensive tests for RSA and ECDSA digital signatures,
key management, rotation, and cryptographic operations.
"""

from __future__ import annotations

import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from infrastructure.security.signer import (
    ECDSASigner,
    KeyManager,
    RSASigner,
    SignerError,
)


class TestSignerError:
    """Tests for SignerError exception class."""

    def test_signer_error_creation(self) -> None:
        """Test creating SignerError with message."""
        error = SignerError("Signature failed")
        assert str(error) == "Signature failed"
        assert error.violation_type == "SIGNER_ERROR"

    def test_signer_error_inheritance(self) -> None:
        """Test that SignerError inherits from SecurityViolationError."""
        from domain.common.exceptions import SecurityViolationError

        error = SignerError("Test error")
        assert isinstance(error, SecurityViolationError)


class TestRSASigner:
    """Tests for RSA digital signature implementation."""

    def test_rsa_signer_initialization_default_key_size(self) -> None:
        """Test RSA signer initialization with default key size."""
        signer = RSASigner()
        assert signer._key_size == 2048
        assert signer._private_key is None
        assert signer._public_key is None

    def test_rsa_signer_initialization_custom_key_size(self) -> None:
        """Test RSA signer initialization with custom key size."""
        signer = RSASigner(key_size=4096)
        assert signer._key_size == 4096

    def test_rsa_signer_initialization_invalid_key_size(self) -> None:
        """Test that small key sizes raise error."""
        with pytest.raises(SignerError, match="at least 2048 bits"):
            RSASigner(key_size=1024)

    def test_rsa_generate_key_success(self) -> None:
        """Test successful RSA key generation."""
        signer = RSASigner(key_size=2048)
        signer.generate_key()

        assert signer._private_key is not None
        assert signer._public_key is not None
        assert isinstance(signer._private_key, rsa.RSAPrivateKey)
        assert isinstance(signer._public_key, rsa.RSAPublicKey)

    def test_rsa_generate_key_error_handling(self) -> None:
        """Test error handling during key generation."""
        signer = RSASigner()

        with patch("infrastructure.security.signer.rsa.generate_private_key") as mock_gen:
            mock_gen.side_effect = Exception("Key generation failed")

            with pytest.raises(SignerError, match="Failed to generate RSA key"):
                signer.generate_key()

    def test_rsa_sign_success(self) -> None:
        """Test successful data signing with RSA."""
        signer = RSASigner(key_size=2048)
        signer.generate_key()

        data = b"Test data to sign"
        signature = signer.sign(data)

        assert signature is not None
        assert isinstance(signature, bytes)
        assert len(signature) > 0

    def test_rsa_sign_without_key(self) -> None:
        """Test signing without generating key raises error."""
        signer = RSASigner()

        with pytest.raises(SignerError, match="No private key loaded"):
            signer.sign(b"test data")

    def test_rsa_sign_error_handling(self) -> None:
        """Test error handling during signing."""
        signer = RSASigner(key_size=2048)
        signer.generate_key()

        with patch.object(signer._private_key, "sign") as mock_sign:
            mock_sign.side_effect = Exception("Signing failed")

            with pytest.raises(SignerError, match="Failed to sign data"):
                signer.sign(b"test data")

    def test_rsa_verify_valid_signature(self) -> None:
        """Test verifying valid RSA signature."""
        signer = RSASigner(key_size=2048)
        signer.generate_key()

        data = b"Test data to verify"
        signature = signer.sign(data)

        assert signer.verify(data, signature) is True

    def test_rsa_verify_invalid_signature(self) -> None:
        """Test verifying invalid RSA signature returns False."""
        signer = RSASigner(key_size=2048)
        signer.generate_key()

        data = b"Test data"
        wrong_signature = b"invalid signature bytes"

        assert signer.verify(data, wrong_signature) is False

    def test_rsa_verify_tampered_data(self) -> None:
        """Test that tampered data fails verification."""
        signer = RSASigner(key_size=2048)
        signer.generate_key()

        original_data = b"Original data"
        signature = signer.sign(original_data)

        tampered_data = b"Tampered data"
        assert signer.verify(tampered_data, signature) is False

    def test_rsa_verify_without_key(self) -> None:
        """Test verifying without key raises error."""
        signer = RSASigner()

        with pytest.raises(SignerError, match="No public key available"):
            signer.verify(b"data", b"signature")

    def test_rsa_save_key_success(self) -> None:
        """Test saving RSA private key to file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            signer = RSASigner(key_size=2048)
            signer.generate_key()

            key_path = Path(tmpdir) / "test_key.pem"
            signer.save_key(key_path)

            assert key_path.exists()
            assert key_path.stat().st_mode & 0o777 == 0o600

    def test_rsa_save_key_with_password(self) -> None:
        """Test saving RSA private key with password encryption."""
        with tempfile.TemporaryDirectory() as tmpdir:
            signer = RSASigner(key_size=2048)
            signer.generate_key()

            key_path = Path(tmpdir) / "encrypted_key.pem"
            password = b"strong_password"
            signer.save_key(key_path, password=password)

            assert key_path.exists()

    def test_rsa_save_key_without_generating(self) -> None:
        """Test saving without generating key raises error."""
        with tempfile.TemporaryDirectory() as tmpdir:
            signer = RSASigner()
            key_path = Path(tmpdir) / "key.pem"

            with pytest.raises(SignerError, match="No private key to save"):
                signer.save_key(key_path)

    def test_rsa_save_key_creates_parent_directory(self) -> None:
        """Test that save_key creates parent directories."""
        with tempfile.TemporaryDirectory() as tmpdir:
            signer = RSASigner(key_size=2048)
            signer.generate_key()

            key_path = Path(tmpdir) / "subdir" / "key.pem"
            signer.save_key(key_path)

            assert key_path.exists()
            assert key_path.parent.exists()

    def test_rsa_load_key_success(self) -> None:
        """Test loading RSA private key from file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Generate and save key
            signer1 = RSASigner(key_size=2048)
            signer1.generate_key()
            key_path = Path(tmpdir) / "key.pem"
            signer1.save_key(key_path)

            # Load key in new signer
            signer2 = RSASigner()
            signer2.load_key(key_path)

            assert signer2._private_key is not None
            assert signer2._public_key is not None

            # Verify signatures work
            data = b"test data"
            signature = signer1.sign(data)
            assert signer2.verify(data, signature) is True

    def test_rsa_load_key_nonexistent_file(self) -> None:
        """Test loading from nonexistent file raises error."""
        signer = RSASigner()
        key_path = Path("/nonexistent/path/key.pem")

        with pytest.raises(SignerError, match="Key file not found"):
            signer.load_key(key_path)

    def test_rsa_load_key_invalid_format(self) -> None:
        """Test loading invalid key format raises error."""
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / "invalid_key.pem"
            key_path.write_text("not a valid key")

            signer = RSASigner()
            with pytest.raises(SignerError, match="Failed to load RSA key"):
                signer.load_key(key_path)

    def test_rsa_export_public_key_success(self) -> None:
        """Test exporting RSA public key in PEM format."""
        signer = RSASigner(key_size=2048)
        signer.generate_key()

        public_key_pem = signer.export_public_key()

        assert isinstance(public_key_pem, bytes)
        assert b"BEGIN PUBLIC KEY" in public_key_pem
        assert b"END PUBLIC KEY" in public_key_pem

    def test_rsa_export_public_key_without_generating(self) -> None:
        """Test exporting public key without generating raises error."""
        signer = RSASigner()

        with pytest.raises(SignerError, match="No public key available"):
            signer.export_public_key()

    def test_rsa_load_public_key_success(self) -> None:
        """Test loading RSA public key from PEM."""
        signer1 = RSASigner(key_size=2048)
        signer1.generate_key()
        public_key_pem = signer1.export_public_key()

        signer2 = RSASigner()
        signer2.load_public_key(public_key_pem)

        assert signer2._public_key is not None

        # Verify can verify signatures
        data = b"test data"
        signature = signer1.sign(data)
        assert signer2.verify(data, signature) is True

    def test_rsa_load_public_key_invalid_format(self) -> None:
        """Test loading invalid public key raises error."""
        signer = RSASigner()

        with pytest.raises(SignerError, match="Failed to load RSA public key"):
            signer.load_public_key(b"invalid key data")

    def test_rsa_signature_uniqueness(self) -> None:
        """Test that RSA-PSS produces different signatures for same data."""
        signer = RSASigner(key_size=2048)
        signer.generate_key()

        data = b"Same data"
        signature1 = signer.sign(data)
        signature2 = signer.sign(data)

        # RSA-PSS with random salt produces different signatures
        assert signature1 != signature2
        # But both should verify
        assert signer.verify(data, signature1) is True
        assert signer.verify(data, signature2) is True


class TestECDSASigner:
    """Tests for ECDSA digital signature implementation."""

    def test_ecdsa_signer_initialization_default_curve(self) -> None:
        """Test ECDSA signer initialization with default curve."""
        signer = ECDSASigner()
        assert isinstance(signer._curve, ec.SECP256R1)
        assert signer._private_key is None
        assert signer._public_key is None

    def test_ecdsa_signer_initialization_custom_curve(self) -> None:
        """Test ECDSA signer initialization with custom curve."""
        signer = ECDSASigner(curve=ec.SECP384R1())
        assert isinstance(signer._curve, ec.SECP384R1)

    def test_ecdsa_generate_key_success(self) -> None:
        """Test successful ECDSA key generation."""
        signer = ECDSASigner()
        signer.generate_key()

        assert signer._private_key is not None
        assert signer._public_key is not None
        assert isinstance(signer._private_key, ec.EllipticCurvePrivateKey)
        assert isinstance(signer._public_key, ec.EllipticCurvePublicKey)

    def test_ecdsa_generate_key_error_handling(self) -> None:
        """Test error handling during key generation."""
        signer = ECDSASigner()

        with patch("infrastructure.security.signer.ec.generate_private_key") as mock_gen:
            mock_gen.side_effect = Exception("Key generation failed")

            with pytest.raises(SignerError, match="Failed to generate ECDSA key"):
                signer.generate_key()

    def test_ecdsa_sign_success(self) -> None:
        """Test successful data signing with ECDSA."""
        signer = ECDSASigner()
        signer.generate_key()

        data = b"Test data to sign"
        signature = signer.sign(data)

        assert signature is not None
        assert isinstance(signature, bytes)
        assert len(signature) > 0

    def test_ecdsa_sign_without_key(self) -> None:
        """Test signing without generating key raises error."""
        signer = ECDSASigner()

        with pytest.raises(SignerError, match="No private key loaded"):
            signer.sign(b"test data")

    def test_ecdsa_sign_error_handling(self) -> None:
        """Test error handling during signing."""
        signer = ECDSASigner()
        signer.generate_key()

        with patch.object(signer._private_key, "sign") as mock_sign:
            mock_sign.side_effect = Exception("Signing failed")

            with pytest.raises(SignerError, match="Failed to sign data"):
                signer.sign(b"test data")

    def test_ecdsa_verify_valid_signature(self) -> None:
        """Test verifying valid ECDSA signature."""
        signer = ECDSASigner()
        signer.generate_key()

        data = b"Test data to verify"
        signature = signer.sign(data)

        assert signer.verify(data, signature) is True

    def test_ecdsa_verify_invalid_signature(self) -> None:
        """Test verifying invalid ECDSA signature returns False."""
        signer = ECDSASigner()
        signer.generate_key()

        data = b"Test data"
        wrong_signature = b"invalid signature bytes"

        assert signer.verify(data, wrong_signature) is False

    def test_ecdsa_verify_tampered_data(self) -> None:
        """Test that tampered data fails verification."""
        signer = ECDSASigner()
        signer.generate_key()

        original_data = b"Original data"
        signature = signer.sign(original_data)

        tampered_data = b"Tampered data"
        assert signer.verify(tampered_data, signature) is False

    def test_ecdsa_verify_without_key(self) -> None:
        """Test verifying without key raises error."""
        signer = ECDSASigner()

        with pytest.raises(SignerError, match="No public key available"):
            signer.verify(b"data", b"signature")

    def test_ecdsa_save_key_success(self) -> None:
        """Test saving ECDSA private key to file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            signer = ECDSASigner()
            signer.generate_key()

            key_path = Path(tmpdir) / "test_key.pem"
            signer.save_key(key_path)

            assert key_path.exists()
            assert key_path.stat().st_mode & 0o777 == 0o600

    def test_ecdsa_save_key_with_password(self) -> None:
        """Test saving ECDSA private key with password encryption."""
        with tempfile.TemporaryDirectory() as tmpdir:
            signer = ECDSASigner()
            signer.generate_key()

            key_path = Path(tmpdir) / "encrypted_key.pem"
            password = b"strong_password"
            signer.save_key(key_path, password=password)

            assert key_path.exists()

    def test_ecdsa_save_key_without_generating(self) -> None:
        """Test saving without generating key raises error."""
        with tempfile.TemporaryDirectory() as tmpdir:
            signer = ECDSASigner()
            key_path = Path(tmpdir) / "key.pem"

            with pytest.raises(SignerError, match="No private key to save"):
                signer.save_key(key_path)

    def test_ecdsa_load_key_success(self) -> None:
        """Test loading ECDSA private key from file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Generate and save key
            signer1 = ECDSASigner()
            signer1.generate_key()
            key_path = Path(tmpdir) / "key.pem"
            signer1.save_key(key_path)

            # Load key in new signer
            signer2 = ECDSASigner()
            signer2.load_key(key_path)

            assert signer2._private_key is not None
            assert signer2._public_key is not None

            # Verify signatures work
            data = b"test data"
            signature = signer1.sign(data)
            assert signer2.verify(data, signature) is True

    def test_ecdsa_load_key_nonexistent_file(self) -> None:
        """Test loading from nonexistent file raises error."""
        signer = ECDSASigner()
        key_path = Path("/nonexistent/path/key.pem")

        with pytest.raises(SignerError, match="Key file not found"):
            signer.load_key(key_path)

    def test_ecdsa_load_key_invalid_format(self) -> None:
        """Test loading invalid key format raises error."""
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / "invalid_key.pem"
            key_path.write_text("not a valid key")

            signer = ECDSASigner()
            with pytest.raises(SignerError, match="Failed to load ECDSA key"):
                signer.load_key(key_path)

    def test_ecdsa_export_public_key_success(self) -> None:
        """Test exporting ECDSA public key in PEM format."""
        signer = ECDSASigner()
        signer.generate_key()

        public_key_pem = signer.export_public_key()

        assert isinstance(public_key_pem, bytes)
        assert b"BEGIN PUBLIC KEY" in public_key_pem
        assert b"END PUBLIC KEY" in public_key_pem

    def test_ecdsa_export_public_key_without_generating(self) -> None:
        """Test exporting public key without generating raises error."""
        signer = ECDSASigner()

        with pytest.raises(SignerError, match="No public key available"):
            signer.export_public_key()

    def test_ecdsa_load_public_key_success(self) -> None:
        """Test loading ECDSA public key from PEM."""
        signer1 = ECDSASigner()
        signer1.generate_key()
        public_key_pem = signer1.export_public_key()

        signer2 = ECDSASigner()
        signer2.load_public_key(public_key_pem)

        assert signer2._public_key is not None

        # Verify can verify signatures
        data = b"test data"
        signature = signer1.sign(data)
        assert signer2.verify(data, signature) is True

    def test_ecdsa_load_public_key_invalid_format(self) -> None:
        """Test loading invalid public key raises error."""
        signer = ECDSASigner()

        with pytest.raises(SignerError, match="Failed to load ECDSA public key"):
            signer.load_public_key(b"invalid key data")

    def test_ecdsa_signature_uniqueness(self) -> None:
        """Test that ECDSA produces different signatures for same data."""
        signer = ECDSASigner()
        signer.generate_key()

        data = b"Same data"
        signature1 = signer.sign(data)
        signature2 = signer.sign(data)

        # ECDSA with random nonce produces different signatures
        assert signature1 != signature2
        # But both should verify
        assert signer.verify(data, signature1) is True
        assert signer.verify(data, signature2) is True


class TestKeyManager:
    """Tests for key management with rotation and versioning."""

    def test_key_manager_initialization_rsa(self) -> None:
        """Test KeyManager initialization with RSA."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = KeyManager(Path(tmpdir), RSASigner)

            assert manager._storage_path == Path(tmpdir)
            assert manager._signer_type == RSASigner
            assert manager._current_key_version == 0
            assert len(manager._signers) == 0

    def test_key_manager_initialization_ecdsa(self) -> None:
        """Test KeyManager initialization with ECDSA."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = KeyManager(Path(tmpdir), ECDSASigner)

            assert manager._signer_type == ECDSASigner

    def test_key_manager_initialization_creates_directory(self) -> None:
        """Test that KeyManager creates storage directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            storage_path = Path(tmpdir) / "keys"
            manager = KeyManager(storage_path)

            assert storage_path.exists()
            assert storage_path.is_dir()

    def test_key_manager_generate_key_success(self) -> None:
        """Test generating first key version."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = KeyManager(Path(tmpdir), RSASigner, rotation_days=90)
            manager.generate_key()

            assert manager._current_key_version == 1
            assert 1 in manager._signers
            assert 1 in manager._key_metadata
            assert manager._key_metadata[1]["status"] == "active"

    def test_key_manager_generate_multiple_versions(self) -> None:
        """Test generating multiple key versions."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = KeyManager(Path(tmpdir), RSASigner)

            manager.generate_key()
            assert manager._current_key_version == 1

            manager.generate_key()
            assert manager._current_key_version == 2

            assert len(manager._signers) == 2

    def test_key_manager_sign_with_current_version(self) -> None:
        """Test signing data with current key version."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = KeyManager(Path(tmpdir), RSASigner)
            manager.generate_key()

            data = b"Test data"
            signature = manager.sign(data)

            assert signature is not None
            assert isinstance(signature, bytes)

    def test_key_manager_sign_without_key(self) -> None:
        """Test signing without key raises error."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = KeyManager(Path(tmpdir), RSASigner)

            with pytest.raises(SignerError, match="No key available"):
                manager.sign(b"test data")

    def test_key_manager_verify_with_current_version(self) -> None:
        """Test verifying signature with current version."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = KeyManager(Path(tmpdir), RSASigner)
            manager.generate_key()

            data = b"Test data"
            signature = manager.sign(data)

            assert manager.verify(data, signature) is True

    def test_key_manager_verify_with_specific_version(self) -> None:
        """Test verifying signature with specific key version."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = KeyManager(Path(tmpdir), RSASigner)

            manager.generate_key()
            data = b"Test data"
            signature_v1 = manager.sign(data)

            manager.generate_key()

            # Should be able to verify v1 signature with v1 key
            assert manager.verify(data, signature_v1, key_version=1) is True

    def test_key_manager_verify_invalid_version(self) -> None:
        """Test verifying with invalid version raises error."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = KeyManager(Path(tmpdir), RSASigner)
            manager.generate_key()

            with pytest.raises(SignerError, match="Key version 99 not found"):
                manager.verify(b"data", b"sig", key_version=99)

    def test_key_manager_rotate_key_success(self) -> None:
        """Test key rotation marks old key as deprecated."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = KeyManager(Path(tmpdir), RSASigner)

            manager.generate_key()
            old_version = manager._current_key_version

            manager.rotate_key()
            new_version = manager._current_key_version

            assert new_version == old_version + 1
            assert manager._key_metadata[old_version]["status"] == "deprecated"
            assert manager._key_metadata[new_version]["status"] == "active"
            assert "deprecated_at" in manager._key_metadata[old_version]

    def test_key_manager_rotate_without_existing_key(self) -> None:
        """Test rotating when no existing key creates first key."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = KeyManager(Path(tmpdir), RSASigner)

            manager.rotate_key()

            assert manager._current_key_version == 1
            assert manager._key_metadata[1]["status"] == "active"

    def test_key_manager_should_rotate_new_manager(self) -> None:
        """Test should_rotate returns True for new manager."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = KeyManager(Path(tmpdir), RSASigner, rotation_days=90)

            assert manager.should_rotate() is True

    def test_key_manager_should_rotate_fresh_key(self) -> None:
        """Test should_rotate returns False for fresh key."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = KeyManager(Path(tmpdir), RSASigner, rotation_days=90)
            manager.generate_key()

            assert manager.should_rotate() is False

    def test_key_manager_should_rotate_old_key(self) -> None:
        """Test should_rotate returns True for old key."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = KeyManager(Path(tmpdir), RSASigner, rotation_days=90)
            manager.generate_key()

            # Mock old creation time
            old_time = (datetime.now(UTC) - timedelta(days=91)).isoformat()
            manager._key_metadata[1]["created_at"] = old_time

            assert manager.should_rotate() is True

    def test_key_manager_load_key_success(self) -> None:
        """Test loading existing key file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a key file
            signer = RSASigner()
            signer.generate_key()
            key_path = Path(tmpdir) / "existing_key.pem"
            signer.save_key(key_path)

            # Load it with KeyManager
            manager = KeyManager(Path(tmpdir), RSASigner)
            manager.load_key(key_path)

            assert manager._current_key_version == 1
            assert 1 in manager._signers

            # Verify can sign with loaded key
            data = b"test"
            signature = manager.sign(data)
            assert signer.verify(data, signature) is True

    def test_key_manager_get_key_metadata_current(self) -> None:
        """Test getting metadata for current key."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = KeyManager(Path(tmpdir), RSASigner)
            manager.generate_key()

            metadata = manager.get_key_metadata()

            assert "created_at" in metadata
            assert metadata["algorithm"] == "RSASigner"
            assert metadata["status"] == "active"

    def test_key_manager_get_key_metadata_specific_version(self) -> None:
        """Test getting metadata for specific version."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = KeyManager(Path(tmpdir), RSASigner)

            manager.generate_key()
            manager.generate_key()

            metadata_v1 = manager.get_key_metadata(version=1)
            assert metadata_v1["algorithm"] == "RSASigner"

    def test_key_manager_get_key_metadata_invalid_version(self) -> None:
        """Test getting metadata for invalid version raises error."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = KeyManager(Path(tmpdir), RSASigner)
            manager.generate_key()

            with pytest.raises(SignerError, match="Key version 99 not found"):
                manager.get_key_metadata(version=99)

    def test_key_manager_export_public_key_current(self) -> None:
        """Test exporting public key for current version."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = KeyManager(Path(tmpdir), RSASigner)
            manager.generate_key()

            public_key = manager.export_public_key()

            assert isinstance(public_key, bytes)
            assert b"BEGIN PUBLIC KEY" in public_key

    def test_key_manager_export_public_key_specific_version(self) -> None:
        """Test exporting public key for specific version."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = KeyManager(Path(tmpdir), RSASigner)

            manager.generate_key()
            manager.generate_key()

            public_key_v1 = manager.export_public_key(version=1)
            assert isinstance(public_key_v1, bytes)

    def test_key_manager_export_public_key_invalid_version(self) -> None:
        """Test exporting public key for invalid version raises error."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = KeyManager(Path(tmpdir), RSASigner)
            manager.generate_key()

            with pytest.raises(SignerError, match="Key version 99 not found"):
                manager.export_public_key(version=99)

    def test_key_manager_hsm_integration_hook(self) -> None:
        """Test HSM integration hook (placeholder)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = KeyManager(Path(tmpdir), RSASigner)

            # Should not raise error, just log warning
            manager.hsm_integration_hook({"provider": "aws-kms", "key_id": "test-key"})

    def test_key_manager_key_path_generation(self) -> None:
        """Test internal key path generation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = KeyManager(Path(tmpdir), RSASigner)

            path = manager._get_key_path(1)
            assert path == Path(tmpdir) / "key_v1.pem"

            path = manager._get_key_path(42)
            assert path == Path(tmpdir) / "key_v42.pem"


class TestIntegration:
    """Integration tests for signing infrastructure."""

    def test_rsa_signer_full_workflow(self) -> None:
        """Test complete RSA signing workflow."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Generate key
            signer = RSASigner(key_size=2048)
            signer.generate_key()

            # Save key
            key_path = Path(tmpdir) / "rsa_key.pem"
            signer.save_key(key_path)

            # Export public key
            public_key = signer.export_public_key()

            # Sign data
            data = b"Important audit entry data"
            signature = signer.sign(data)

            # Load key in new signer
            verifier = RSASigner()
            verifier.load_key(key_path)

            # Verify signature
            assert verifier.verify(data, signature) is True

            # Load public key in another signer
            pub_only_verifier = RSASigner()
            pub_only_verifier.load_public_key(public_key)

            # Verify with public key only
            assert pub_only_verifier.verify(data, signature) is True

    def test_ecdsa_signer_full_workflow(self) -> None:
        """Test complete ECDSA signing workflow."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Generate key
            signer = ECDSASigner()
            signer.generate_key()

            # Save key
            key_path = Path(tmpdir) / "ecdsa_key.pem"
            signer.save_key(key_path)

            # Export public key
            public_key = signer.export_public_key()

            # Sign data
            data = b"Audit log entry hash"
            signature = signer.sign(data)

            # Load key in new signer
            verifier = ECDSASigner()
            verifier.load_key(key_path)

            # Verify signature
            assert verifier.verify(data, signature) is True

            # Load public key in another signer
            pub_only_verifier = ECDSASigner()
            pub_only_verifier.load_public_key(public_key)

            # Verify with public key only
            assert pub_only_verifier.verify(data, signature) is True

    def test_key_manager_rotation_workflow(self) -> None:
        """Test key rotation and verification workflow."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = KeyManager(Path(tmpdir), RSASigner, rotation_days=90)

            # Generate initial key
            manager.generate_key()
            data1 = b"First entry"
            sig1 = manager.sign(data1)

            # Rotate key
            manager.rotate_key()
            data2 = b"Second entry"
            sig2 = manager.sign(data2)

            # Should verify both signatures
            assert manager.verify(data1, sig1, key_version=1) is True
            assert manager.verify(data2, sig2, key_version=2) is True

            # Current version should verify newest signature
            assert manager.verify(data2, sig2) is True

    def test_key_manager_ecdsa_workflow(self) -> None:
        """Test KeyManager with ECDSA signers."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = KeyManager(Path(tmpdir), ECDSASigner)

            manager.generate_key()
            data = b"ECDSA signed data"
            signature = manager.sign(data)

            assert manager.verify(data, signature) is True

    def test_cross_signer_type_incompatibility(self) -> None:
        """Test that RSA and ECDSA keys are not compatible."""
        rsa_signer = RSASigner(key_size=2048)
        rsa_signer.generate_key()

        ecdsa_signer = ECDSASigner()
        ecdsa_signer.generate_key()

        data = b"test data"
        rsa_signature = rsa_signer.sign(data)

        # ECDSA verifier should not verify RSA signature
        assert ecdsa_signer.verify(data, rsa_signature) is False


class TestEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_rsa_sign_empty_data(self) -> None:
        """Test signing empty data."""
        signer = RSASigner(key_size=2048)
        signer.generate_key()

        signature = signer.sign(b"")
        assert signature is not None
        assert signer.verify(b"", signature) is True

    def test_ecdsa_sign_empty_data(self) -> None:
        """Test ECDSA signing empty data."""
        signer = ECDSASigner()
        signer.generate_key()

        signature = signer.sign(b"")
        assert signature is not None
        assert signer.verify(b"", signature) is True

    def test_rsa_sign_large_data(self) -> None:
        """Test signing large data."""
        signer = RSASigner(key_size=2048)
        signer.generate_key()

        large_data = b"x" * 1000000  # 1MB
        signature = signer.sign(large_data)
        assert signer.verify(large_data, signature) is True

    def test_key_manager_metadata_preserved_after_rotation(self) -> None:
        """Test that old key metadata is preserved after rotation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = KeyManager(Path(tmpdir), RSASigner)

            manager.generate_key()
            v1_metadata_before = manager.get_key_metadata(version=1).copy()

            manager.rotate_key()

            v1_metadata_after = manager.get_key_metadata(version=1)

            # Check that created_at is preserved
            assert v1_metadata_after["created_at"] == v1_metadata_before["created_at"]
            # Status should be updated
            assert v1_metadata_after["status"] == "deprecated"

    def test_rsa_load_key_wrong_key_type(self) -> None:
        """Test loading non-RSA key into RSA signer raises error."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create ECDSA key
            ecdsa_signer = ECDSASigner()
            ecdsa_signer.generate_key()
            key_path = Path(tmpdir) / "ecdsa_key.pem"
            ecdsa_signer.save_key(key_path)

            # Try to load into RSA signer
            rsa_signer = RSASigner()
            with pytest.raises(SignerError, match="Invalid RSA key format"):
                rsa_signer.load_key(key_path)

    def test_ecdsa_load_key_wrong_key_type(self) -> None:
        """Test loading non-ECDSA key into ECDSA signer raises error."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create RSA key
            rsa_signer = RSASigner(key_size=2048)
            rsa_signer.generate_key()
            key_path = Path(tmpdir) / "rsa_key.pem"
            rsa_signer.save_key(key_path)

            # Try to load into ECDSA signer
            ecdsa_signer = ECDSASigner()
            with pytest.raises(SignerError, match="Invalid ECDSA key format"):
                ecdsa_signer.load_key(key_path)

    def test_rsa_save_key_error_handling(self) -> None:
        """Test error handling when saving RSA key fails."""
        with tempfile.TemporaryDirectory() as tmpdir:
            signer = RSASigner(key_size=2048)
            signer.generate_key()

            # Try to save to read-only directory
            key_path = Path(tmpdir) / "readonly" / "key.pem"
            key_path.parent.mkdir()
            key_path.parent.chmod(0o444)

            try:
                with pytest.raises(SignerError, match="Failed to save RSA key"):
                    signer.save_key(key_path)
            finally:
                # Clean up
                key_path.parent.chmod(0o755)

    def test_ecdsa_save_key_error_handling(self) -> None:
        """Test error handling when saving ECDSA key fails."""
        with tempfile.TemporaryDirectory() as tmpdir:
            signer = ECDSASigner()
            signer.generate_key()

            # Try to save to read-only directory
            key_path = Path(tmpdir) / "readonly" / "key.pem"
            key_path.parent.mkdir()
            key_path.parent.chmod(0o444)

            try:
                with pytest.raises(SignerError, match="Failed to save ECDSA key"):
                    signer.save_key(key_path)
            finally:
                # Clean up
                key_path.parent.chmod(0o755)

    def test_rsa_export_public_key_error_handling(self) -> None:
        """Test error handling when exporting RSA public key fails."""
        signer = RSASigner(key_size=2048)
        signer.generate_key()

        with patch.object(signer._public_key, "public_bytes") as mock_export:
            mock_export.side_effect = Exception("Export failed")

            with pytest.raises(SignerError, match="Failed to export public key"):
                signer.export_public_key()

    def test_ecdsa_export_public_key_error_handling(self) -> None:
        """Test error handling when exporting ECDSA public key fails."""
        signer = ECDSASigner()
        signer.generate_key()

        with patch.object(signer._public_key, "public_bytes") as mock_export:
            mock_export.side_effect = Exception("Export failed")

            with pytest.raises(SignerError, match="Failed to export public key"):
                signer.export_public_key()

    def test_rsa_load_public_key_wrong_type(self) -> None:
        """Test loading non-RSA public key raises error."""
        ecdsa_signer = ECDSASigner()
        ecdsa_signer.generate_key()
        ecdsa_public_key = ecdsa_signer.export_public_key()

        rsa_signer = RSASigner()
        with pytest.raises(SignerError, match="Invalid RSA public key format"):
            rsa_signer.load_public_key(ecdsa_public_key)

    def test_ecdsa_load_public_key_wrong_type(self) -> None:
        """Test loading non-ECDSA public key raises error."""
        rsa_signer = RSASigner(key_size=2048)
        rsa_signer.generate_key()
        rsa_public_key = rsa_signer.export_public_key()

        ecdsa_signer = ECDSASigner()
        with pytest.raises(SignerError, match="Invalid ECDSA public key format"):
            ecdsa_signer.load_public_key(rsa_public_key)

    def test_key_manager_generate_key_error_handling(self) -> None:
        """Test error handling when key generation fails in KeyManager."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = KeyManager(Path(tmpdir), RSASigner)

            with patch.object(RSASigner, "generate_key") as mock_gen:
                mock_gen.side_effect = Exception("Key generation failed")

                with pytest.raises(SignerError, match="Failed to generate new key"):
                    manager.generate_key()

    def test_key_manager_load_key_error_handling(self) -> None:
        """Test error handling when loading key fails in KeyManager."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = KeyManager(Path(tmpdir), RSASigner)

            with pytest.raises(SignerError, match="Failed to load key"):
                manager.load_key(Path("/nonexistent/key.pem"))

    def test_key_manager_rotate_key_error_handling(self) -> None:
        """Test error handling when rotation fails."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = KeyManager(Path(tmpdir), RSASigner)
            manager.generate_key()

            with patch.object(manager, "generate_key") as mock_gen:
                mock_gen.side_effect = Exception("Generation failed during rotation")

                with pytest.raises(SignerError, match="Failed to rotate key"):
                    manager.rotate_key()

    def test_key_manager_initialization_error_handling(self) -> None:
        """Test error handling during KeyManager initialization."""
        # Try to create manager with invalid path (file instead of directory)
        with tempfile.NamedTemporaryFile() as tmp_file:
            # This should fail when trying to create storage directory
            with pytest.raises(SignerError, match="Failed to create key storage directory"):
                KeyManager(Path(tmp_file.name), RSASigner)
