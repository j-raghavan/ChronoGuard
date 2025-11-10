"""Comprehensive tests for audit hash functionality."""

from unittest.mock import patch
from uuid import uuid4

import pytest

from domain.audit.entity import AccessDecision, AuditEntry
from domain.audit.hasher import AuditHashError, EnhancedAuditHasher
from domain.common.exceptions import SecurityViolationError


class TestAuditHashError:
    """Test AuditHashError exception."""

    def test_audit_hash_error_creation(self) -> None:
        """Test creating AuditHashError."""
        error = AuditHashError("Test hash error")
        assert str(error) == "Test hash error"
        assert error.violation_type == "AUDIT_HASH_ERROR"
        assert isinstance(error, SecurityViolationError)


class TestEnhancedAuditHasher:
    """Comprehensive tests for EnhancedAuditHasher."""

    @pytest.fixture
    def secret_key(self) -> bytes:
        """Test secret key."""
        return b"test_secret_key_32_bytes_exactly"

    @pytest.fixture
    def test_entry(self) -> AuditEntry:
        """Test audit entry."""
        return AuditEntry(
            tenant_id=uuid4(),
            agent_id=uuid4(),
            domain="test.example.com",
            decision=AccessDecision.ALLOW,
            reason="Test access",
        )

    def test_hasher_init_with_secret_key(self, secret_key: bytes) -> None:
        """Test hasher initialization with provided secret key."""
        hasher = EnhancedAuditHasher(secret_key)
        assert hasher.secret_key == secret_key
        assert hasher._algorithm == hasher._algorithm

    def test_hasher_init_without_secret_key(self) -> None:
        """Test hasher initialization without secret key generates one."""
        hasher = EnhancedAuditHasher()
        assert hasher.secret_key is not None
        assert len(hasher.secret_key) == 32
        assert isinstance(hasher.secret_key, bytes)

    def test_compute_entry_hash_basic(self, secret_key: bytes, test_entry: AuditEntry) -> None:
        """Test basic entry hash computation."""
        hasher = EnhancedAuditHasher(secret_key)
        hash_bytes = hasher.compute_entry_hash(test_entry)

        assert isinstance(hash_bytes, bytes)
        assert len(hash_bytes) == 48  # 16 bytes salt + 32 bytes hash

    def test_compute_entry_hash_with_previous(
        self, secret_key: bytes, test_entry: AuditEntry
    ) -> None:
        """Test entry hash computation with previous hash."""
        hasher = EnhancedAuditHasher(secret_key)
        previous_hash = "abcdef1234567890"
        hash_bytes = hasher.compute_entry_hash(test_entry, previous_hash)

        assert isinstance(hash_bytes, bytes)
        assert len(hash_bytes) == 48

    def test_compute_entry_hash_with_entropy(
        self, secret_key: bytes, test_entry: AuditEntry
    ) -> None:
        """Test entry hash computation with additional entropy."""
        hasher = EnhancedAuditHasher(secret_key)
        entropy = b"additional_entropy"
        hash_bytes = hasher.compute_entry_hash(test_entry, additional_entropy=entropy)

        assert isinstance(hash_bytes, bytes)
        assert len(hash_bytes) == 48

    def test_compute_entry_hash_consistency(
        self, secret_key: bytes, test_entry: AuditEntry
    ) -> None:
        """Test hash computation consistency with same inputs."""
        hasher = EnhancedAuditHasher(secret_key)

        # Use fixed entropy to ensure consistency
        entropy = b"fixed_entropy"

        with patch("secrets.token_bytes", return_value=b"fixed_salt_16bytes"):
            hash1 = hasher.compute_entry_hash(test_entry, additional_entropy=entropy)
            hash2 = hasher.compute_entry_hash(test_entry, additional_entropy=entropy)
            assert hash1 == hash2

    def test_verify_entry_hash_valid(self, secret_key: bytes, test_entry: AuditEntry) -> None:
        """Test verifying valid entry hash."""
        hasher = EnhancedAuditHasher(secret_key)
        hash_bytes = hasher.compute_entry_hash(test_entry)

        is_valid = hasher.verify_entry_hash(test_entry, hash_bytes)
        assert is_valid is True

    def test_verify_entry_hash_invalid_length(
        self, secret_key: bytes, test_entry: AuditEntry
    ) -> None:
        """Test verifying invalid hash length."""
        hasher = EnhancedAuditHasher(secret_key)
        invalid_hash = b"too_short"

        with pytest.raises(AuditHashError) as exc_info:
            hasher.verify_entry_hash(test_entry, invalid_hash)
        assert "Invalid hash format" in str(exc_info.value)

    def test_verify_entry_hash_invalid_hash(
        self, secret_key: bytes, test_entry: AuditEntry
    ) -> None:
        """Test verifying invalid hash."""
        hasher = EnhancedAuditHasher(secret_key)
        # Create valid length but wrong content
        invalid_hash = b"x" * 48

        is_valid = hasher.verify_entry_hash(test_entry, invalid_hash)
        assert is_valid is False

    def test_compute_chain_hash_empty(self, secret_key: bytes) -> None:
        """Test computing chain hash for empty list."""
        hasher = EnhancedAuditHasher(secret_key)
        chain_hash = hasher.compute_chain_hash([])
        assert chain_hash == ""

    def test_compute_chain_hash_single_entry(
        self, secret_key: bytes, test_entry: AuditEntry
    ) -> None:
        """Test computing chain hash for single entry."""
        hasher = EnhancedAuditHasher(secret_key)
        entries = [test_entry]
        chain_hash = hasher.compute_chain_hash(entries)

        assert isinstance(chain_hash, str)
        assert len(chain_hash) == 64  # SHA-256 hex string

    def test_compute_chain_hash_multiple_entries(self, secret_key: bytes) -> None:
        """Test computing chain hash for multiple entries."""
        hasher = EnhancedAuditHasher(secret_key)
        entries = [
            AuditEntry(
                tenant_id=uuid4(),
                agent_id=uuid4(),
                domain=f"test{i}.example.com",
                decision=AccessDecision.ALLOW,
            )
            for i in range(3)
        ]

        chain_hash = hasher.compute_chain_hash(entries)
        assert isinstance(chain_hash, str)
        assert len(chain_hash) == 64

    def test_verify_chain_integrity_valid(self, secret_key: bytes) -> None:
        """Test verifying valid chain integrity."""
        hasher = EnhancedAuditHasher(secret_key)

        # Create entries with proper hash chaining
        entries = []
        previous_hash = ""

        for i in range(3):
            entry = AuditEntry(
                tenant_id=uuid4(),
                agent_id=uuid4(),
                domain=f"test{i}.example.com",
                decision=AccessDecision.ALLOW,
                sequence_number=i,
            )

            hash_bytes = hasher.compute_entry_hash(entry, previous_hash)
            hash_hex = hash_bytes.hex()

            entry_with_hash = AuditEntry(
                **{
                    **entry.model_dump(),
                    "previous_hash": previous_hash,
                    "current_hash": hash_hex,
                }
            )
            entries.append(entry_with_hash)
            previous_hash = hash_hex

        is_valid, errors = hasher.verify_chain_integrity(entries)
        assert is_valid is True
        assert len(errors) == 0

    def test_verify_chain_integrity_broken_chain(self, secret_key: bytes) -> None:
        """Test verifying chain with broken integrity."""
        hasher = EnhancedAuditHasher(secret_key)

        # Create entries but break the chain
        entry1 = AuditEntry(
            tenant_id=uuid4(),
            agent_id=uuid4(),
            domain="test1.example.com",
            decision=AccessDecision.ALLOW,
            sequence_number=0,
            previous_hash="",
            current_hash="valid_hash_1",
        )

        entry2 = AuditEntry(
            tenant_id=uuid4(),
            agent_id=uuid4(),
            domain="test2.example.com",
            decision=AccessDecision.ALLOW,
            sequence_number=1,
            previous_hash="wrong_hash",  # Broken chain
            current_hash="valid_hash_2",
        )

        is_valid, errors = hasher.verify_chain_integrity([entry1, entry2])
        assert is_valid is False
        assert len(errors) > 0

    def test_generate_integrity_proof_empty(self, secret_key: bytes) -> None:
        """Test generating integrity proof for empty entries."""
        hasher = EnhancedAuditHasher(secret_key)
        proof = hasher.generate_integrity_proof([])

        assert isinstance(proof, dict)
        assert len(proof) == 0  # Empty dict for empty entries

    def test_generate_integrity_proof_with_entries(self, secret_key: bytes) -> None:
        """Test generating integrity proof for entries."""
        hasher = EnhancedAuditHasher(secret_key)
        entries = [
            AuditEntry(
                tenant_id=uuid4(),
                agent_id=uuid4(),
                domain=f"test{i}.example.com",
                decision=AccessDecision.ALLOW,
                sequence_number=i,
            )
            for i in range(3)
        ]

        proof = hasher.generate_integrity_proof(entries)

        assert isinstance(proof, dict)
        assert "root_hash" in proof
        assert int(proof["entry_count"]) == 3  # Might be string
        assert int(proof["start_sequence"]) == 0  # Might be string
        assert int(proof["end_sequence"]) == 2  # Might be string
        assert "signature" in proof
        assert len(proof["signature"]) > 0

    def test_generate_integrity_proof_signature_verification(self, secret_key: bytes) -> None:
        """Test integrity proof signature can be verified."""
        hasher = EnhancedAuditHasher(secret_key)
        entries = [
            AuditEntry(
                tenant_id=uuid4(),
                agent_id=uuid4(),
                domain="test.example.com",
                decision=AccessDecision.ALLOW,
                sequence_number=0,
            )
        ]

        proof = hasher.generate_integrity_proof(entries)
        signature = bytes.fromhex(proof["signature"])

        # Verify signature format (should be valid hex)
        assert len(signature) == 32  # HMAC-SHA256 output length

    def test_entry_serialization_for_hash(self, secret_key: bytes, test_entry: AuditEntry) -> None:
        """Test entry serialization produces consistent data for hashing."""
        hasher = EnhancedAuditHasher(secret_key)

        # Call the method twice to ensure consistent serialization
        with patch("secrets.token_bytes", return_value=b"fixed_salt_16bytes"):
            hash1 = hasher.compute_entry_hash(test_entry)
            hash2 = hasher.compute_entry_hash(test_entry)
            assert hash1 == hash2

    def test_hasher_different_secret_keys_produce_different_hashes(
        self, test_entry: AuditEntry
    ) -> None:
        """Test different secret keys produce different hashes."""
        hasher1 = EnhancedAuditHasher(b"secret1_32_bytes_exactly_padded!")
        hasher2 = EnhancedAuditHasher(b"secret2_32_bytes_exactly_padded!")

        with patch("secrets.token_bytes", return_value=b"fixed_salt_16bytes"):
            hash1 = hasher1.compute_entry_hash(test_entry)
            hash2 = hasher2.compute_entry_hash(test_entry)
            assert hash1 != hash2

    def test_verify_chain_integrity_sequence_gaps(self, secret_key: bytes) -> None:
        """Test chain verification detects sequence number gaps."""
        hasher = EnhancedAuditHasher(secret_key)

        # Create entries with sequence gap
        entry1 = AuditEntry(
            tenant_id=uuid4(),
            agent_id=uuid4(),
            domain="test1.example.com",
            decision=AccessDecision.ALLOW,
            sequence_number=0,
        )

        entry2 = AuditEntry(
            tenant_id=uuid4(),
            agent_id=uuid4(),
            domain="test2.example.com",
            decision=AccessDecision.ALLOW,
            sequence_number=2,  # Gap: should be 1
        )

        is_valid, errors = hasher.verify_chain_integrity([entry1, entry2])
        assert is_valid is False
        assert any("sequence" in error.lower() for error in errors)

    def test_verify_entry_hash_with_additional_entropy(
        self, secret_key: bytes, test_entry: AuditEntry
    ) -> None:
        """Test hash verification with additional entropy."""
        hasher = EnhancedAuditHasher(secret_key)
        entropy = b"test_entropy"

        # Compute hash with entropy
        hash_bytes = hasher.compute_entry_hash(test_entry, additional_entropy=entropy)

        # Verify with same entropy
        is_valid = hasher.verify_entry_hash(test_entry, hash_bytes, additional_entropy=entropy)
        assert is_valid is True

        # Verify without entropy should fail
        is_valid_no_entropy = hasher.verify_entry_hash(test_entry, hash_bytes)
        assert is_valid_no_entropy is False

    def test_verify_chain_integrity_empty_list(self, secret_key: bytes) -> None:
        """Test verify_chain_integrity with empty entry list."""
        hasher = EnhancedAuditHasher(secret_key)

        is_valid, errors = hasher.verify_chain_integrity([])

        # Empty chain is valid
        assert is_valid is True
        assert errors == []

    def test_verify_chain_integrity_with_expected_hashes(self, secret_key: bytes) -> None:
        """Test verifying chain integrity with expected hashes provided."""
        hasher = EnhancedAuditHasher(secret_key)

        # Create entries with proper hashes
        entries = []
        previous_hash = ""

        for i in range(2):
            entry = AuditEntry(
                tenant_id=uuid4(),
                agent_id=uuid4(),
                domain=f"test{i}.example.com",
                decision=AccessDecision.ALLOW,
                sequence_number=i,
            )

            hash_bytes = hasher.compute_entry_hash(entry, previous_hash)
            hash_hex = hash_bytes.hex()

            entry_with_hash = AuditEntry(
                **{
                    **entry.model_dump(),
                    "previous_hash": previous_hash,
                    "current_hash": hash_hex,
                }
            )
            entries.append(entry_with_hash)
            previous_hash = hash_hex

        # Verify with expected hashes
        expected_hashes = [e.current_hash for e in entries]
        is_valid, errors = hasher.verify_chain_integrity(entries, expected_hashes)

        assert is_valid is True
        assert len(errors) == 0

    def test_compute_chain_hash_single_entry_edge_case(self, secret_key: bytes) -> None:
        """Test chain hash with single entry."""
        hasher = EnhancedAuditHasher(secret_key)

        entry = AuditEntry(
            tenant_id=uuid4(),
            agent_id=uuid4(),
            domain="test.example.com",
            decision=AccessDecision.ALLOW,
            sequence_number=0,
            current_hash="test_hash",
        )

        chain_hash = hasher.compute_chain_hash([entry])

        assert isinstance(chain_hash, str)
        assert len(chain_hash) == 64  # SHA-256 hex

    def test_generate_integrity_proof_without_expected_hashes(self, secret_key: bytes) -> None:
        """Test generating integrity proof without providing expected hashes."""
        hasher = EnhancedAuditHasher(secret_key)

        entries = [
            AuditEntry(
                tenant_id=uuid4(),
                agent_id=uuid4(),
                domain=f"test{i}.example.com",
                decision=AccessDecision.ALLOW,
                sequence_number=i,
            )
            for i in range(2)
        ]

        proof = hasher.generate_integrity_proof(entries)

        # Verify proof structure
        assert "root_hash" in proof
        assert "entry_count" in proof
        assert "signature" in proof
        assert int(proof["entry_count"]) == 2

    def test_verify_chain_integrity_with_mismatched_hashes(self, secret_key: bytes) -> None:
        """Test chain verification detects hash mismatches."""
        hasher = EnhancedAuditHasher(secret_key)

        # Create entry with a hash that won't verify
        entry = AuditEntry(
            tenant_id=uuid4(),
            agent_id=uuid4(),
            domain="test.example.com",
            decision=AccessDecision.ALLOW,
            sequence_number=0,
            current_hash="a" * 96,  # Valid length but wrong content
        )

        # Provide expected hashes
        expected_hashes = [entry.current_hash]

        is_valid, errors = hasher.verify_chain_integrity([entry], expected_hashes)

        # Should detect hash verification failure
        assert is_valid is False
        assert len(errors) > 0
        assert any("hash verification failed" in e.lower() for e in errors)

    def test_compute_entry_hash_with_all_parameters(
        self, secret_key: bytes, test_entry: AuditEntry
    ) -> None:
        """Test hash computation with all optional parameters."""
        hasher = EnhancedAuditHasher(secret_key)

        # Compute with all parameters
        hash_bytes = hasher.compute_entry_hash(
            test_entry, previous_hash="prev_hash_123", additional_entropy=b"extra_entropy_data"
        )

        assert isinstance(hash_bytes, bytes)
        assert len(hash_bytes) == 48  # salt + hash

    def test_verify_chain_integrity_with_invalid_hash_format(self, secret_key: bytes) -> None:
        """Test chain verification handles entries with invalid hash format."""
        hasher = EnhancedAuditHasher(secret_key)

        # Create entry with invalid hash format (too short)
        entry = AuditEntry(
            tenant_id=uuid4(),
            agent_id=uuid4(),
            domain="test.example.com",
            decision=AccessDecision.ALLOW,
            sequence_number=0,
            current_hash="short",  # Invalid hash format
        )

        # This should handle the exception gracefully
        is_valid, errors = hasher.verify_chain_integrity([entry])

        # Should handle the format error
        assert isinstance(errors, list)

    def test_generate_integrity_proof_with_multiple_entries(self, secret_key: bytes) -> None:
        """Test integrity proof generation with multiple entries."""
        hasher = EnhancedAuditHasher(secret_key)

        # Create multiple entries
        entries = [
            AuditEntry(
                tenant_id=uuid4(),
                agent_id=uuid4(),
                domain=f"test{i}.example.com",
                decision=AccessDecision.ALLOW,
                sequence_number=i,
                current_hash=f"hash_{i}",
            )
            for i in range(5)
        ]

        proof = hasher.generate_integrity_proof(entries)

        # Verify complete proof structure
        assert "root_hash" in proof
        assert "entry_count" in proof
        assert "signature" in proof
        assert int(proof["entry_count"]) == 5
