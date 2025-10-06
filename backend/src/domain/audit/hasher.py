"""Cryptographic hash chaining for audit log integrity."""

import hashlib
import hmac
import secrets
import time

from domain.audit.entity import AuditEntry
from domain.common.exceptions import SecurityViolationError


class AuditHashError(SecurityViolationError):
    """Raised when audit hash operations fail."""

    def __init__(self, message: str) -> None:
        """Initialize audit hash error.

        Args:
            message: Error message
        """
        super().__init__(
            message,
            violation_type="AUDIT_HASH_ERROR",
        )


class EnhancedAuditHasher:
    """Enhanced audit hash chaining with additional entropy and security."""

    def __init__(self, secret_key: bytes | None = None) -> None:
        """Initialize enhanced audit hasher.

        Args:
            secret_key: Secret key for HMAC (generates random if None)
        """
        self.secret_key = secret_key or secrets.token_bytes(32)
        self._algorithm = hashlib.sha256

    def compute_entry_hash(
        self,
        entry: AuditEntry,
        previous_hash: str = "",
        additional_entropy: bytes | None = None,
    ) -> bytes:
        """Compute cryptographically secure hash for audit entry.

        Args:
            entry: Audit entry to hash
            previous_hash: Previous entry hash for chaining
            additional_entropy: Additional entropy for security

        Returns:
            Computed hash bytes

        Raises:
            AuditHashError: If hash computation fails
        """
        try:
            # Generate salt for this entry
            salt = secrets.token_bytes(16)

            # Serialize entry data deterministically
            entry_data = self._serialize_entry_for_hashing(entry)

            # Start with HMAC of entry data
            hasher = hmac.new(self.secret_key, digestmod=self._algorithm)
            hasher.update(entry_data)

            # Add previous hash for chaining
            if previous_hash:
                hasher.update(previous_hash.encode("utf-8"))

            # Add timestamp with nanosecond precision
            timestamp_bytes = str(entry.timestamp_nanos).encode("utf-8")
            hasher.update(timestamp_bytes)

            # Add additional entropy if provided
            if additional_entropy:
                hasher.update(additional_entropy)

            # Add salt
            hasher.update(salt)

            # Get HMAC result
            audit_hash = hasher.digest()

            # Return hash with salt prepended for verification
            return salt + audit_hash

        except Exception as e:
            raise AuditHashError(f"Hash computation failed: {e}") from e

    def verify_entry_hash(
        self,
        entry: AuditEntry,
        stored_hash: bytes,
        previous_hash: str = "",
        additional_entropy: bytes | None = None,
    ) -> bool:
        """Verify audit hash integrity.

        Args:
            entry: Audit entry to verify
            stored_hash: Hash to verify (includes salt)
            previous_hash: Previous entry hash
            additional_entropy: Additional entropy used in original hash

        Returns:
            True if hash is valid, False otherwise

        Raises:
            AuditHashError: If verification fails due to errors
        """
        try:
            if len(stored_hash) < 48:  # 16 bytes salt + 32 bytes SHA256
                raise AuditHashError("Invalid hash format: too short")

            # Extract salt and hash
            salt = stored_hash[:16]
            original_hash = stored_hash[16:]

            # Serialize entry data
            entry_data = self._serialize_entry_for_hashing(entry)

            # Recompute hash with same parameters
            hasher = hmac.new(self.secret_key, digestmod=self._algorithm)
            hasher.update(entry_data)

            if previous_hash:
                hasher.update(previous_hash.encode("utf-8"))

            timestamp_bytes = str(entry.timestamp_nanos).encode("utf-8")
            hasher.update(timestamp_bytes)

            if additional_entropy:
                hasher.update(additional_entropy)

            hasher.update(salt)

            computed_hash = hasher.digest()

            # Use constant-time comparison
            return hmac.compare_digest(original_hash, computed_hash)

        except Exception as e:
            raise AuditHashError(f"Hash verification failed: {e}") from e

    def compute_chain_hash(
        self,
        entries: list[AuditEntry],
        additional_entropy: bytes | None = None,
    ) -> str:
        """Compute hash for an entire chain of audit entries.

        Args:
            entries: List of audit entries in chronological order
            additional_entropy: Additional entropy for security

        Returns:
            Chain hash as hex string

        Raises:
            AuditHashError: If chain hash computation fails
        """
        try:
            if not entries:
                return ""

            # Sort by sequence number to ensure correct order
            sorted_entries = sorted(entries, key=lambda e: e.sequence_number)

            chain_hasher = hmac.new(self.secret_key, digestmod=self._algorithm)

            # Hash each entry in sequence
            previous_hash = ""
            for entry in sorted_entries:
                entry_hash_bytes = self.compute_entry_hash(entry, previous_hash, additional_entropy)
                entry_hash_hex = entry_hash_bytes.hex()

                chain_hasher.update(entry_hash_hex.encode("utf-8"))
                previous_hash = entry_hash_hex

            # Add chain metadata
            chain_metadata = (
                f"entries:{len(entries)}|"
                f"start_seq:{sorted_entries[0].sequence_number}|"
                f"end_seq:{sorted_entries[-1].sequence_number}|"
                f"timestamp:{time.time_ns()}"
            )
            chain_hasher.update(chain_metadata.encode("utf-8"))

            return chain_hasher.hexdigest()

        except Exception as e:
            raise AuditHashError(f"Chain hash computation failed: {e}") from e

    def verify_chain_integrity(
        self,
        entries: list[AuditEntry],
        expected_hashes: list[str] | None = None,
        additional_entropy: bytes | None = None,
    ) -> tuple[bool, list[str]]:
        """Verify integrity of an entire audit chain.

        Args:
            entries: List of audit entries to verify
            expected_hashes: Expected hash values for each entry
            additional_entropy: Additional entropy used in original hashes

        Returns:
            Tuple of (is_valid, error_messages)

        Raises:
            AuditHashError: If verification process fails
        """
        try:
            if not entries:
                return True, []

            errors = []
            sorted_entries = sorted(entries, key=lambda e: e.sequence_number)

            # Verify sequence continuity
            for i in range(1, len(sorted_entries)):
                expected_seq = sorted_entries[i - 1].sequence_number + 1
                actual_seq = sorted_entries[i].sequence_number

                if actual_seq != expected_seq:
                    errors.append(f"Sequence gap: expected {expected_seq}, got {actual_seq}")

            # Verify individual hashes and chaining
            previous_hash = ""
            for i, entry in enumerate(sorted_entries):
                # Verify individual entry hash if provided
                if expected_hashes and i < len(expected_hashes):
                    expected_hash = expected_hashes[i]
                    if entry.current_hash != expected_hash:
                        errors.append(
                            f"Entry {entry.entry_id} hash mismatch: "
                            f"expected {expected_hash}, got {entry.current_hash}"
                        )

                # Verify hash chaining
                if entry.previous_hash != previous_hash:
                    errors.append(
                        f"Entry {entry.entry_id} chain broken: "
                        f"expected previous hash {previous_hash}, "
                        f"got {entry.previous_hash}"
                    )

                # Verify hash computation
                try:
                    stored_hash = bytes.fromhex(entry.current_hash)
                    if not self.verify_entry_hash(
                        entry, stored_hash, previous_hash, additional_entropy
                    ):
                        errors.append(f"Entry {entry.entry_id} hash verification failed")
                except Exception as e:
                    errors.append(f"Entry {entry.entry_id} hash format error: {e}")

                previous_hash = entry.current_hash

            return len(errors) == 0, errors

        except Exception as e:
            raise AuditHashError(f"Chain verification failed: {e}") from e

    def generate_integrity_proof(
        self,
        entries: list[AuditEntry],
        additional_entropy: bytes | None = None,
    ) -> dict[str, str]:
        """Generate integrity proof for audit entries.

        Args:
            entries: List of audit entries
            additional_entropy: Additional entropy for security

        Returns:
            Dictionary containing integrity proof data

        Raises:
            AuditHashError: If proof generation fails
        """
        try:
            if not entries:
                return {}

            sorted_entries = sorted(entries, key=lambda e: e.sequence_number)

            # Compute merkle-style tree hash
            entry_hashes = []
            previous_hash = ""

            for entry in sorted_entries:
                entry_hash_bytes = self.compute_entry_hash(entry, previous_hash, additional_entropy)
                entry_hash_hex = entry_hash_bytes.hex()
                entry_hashes.append(entry_hash_hex)
                previous_hash = entry_hash_hex

            # Compute root hash
            root_hash = self._compute_merkle_root(entry_hashes)

            # Generate proof metadata
            proof = {
                "root_hash": root_hash,
                "entry_count": str(len(entries)),
                "start_sequence": str(sorted_entries[0].sequence_number),
                "end_sequence": str(sorted_entries[-1].sequence_number),
                "start_timestamp": sorted_entries[0].timestamp.isoformat(),
                "end_timestamp": sorted_entries[-1].timestamp.isoformat(),
                "generation_time": str(time.time_ns()),
                "algorithm": "HMAC-SHA256",
            }

            # Sign the proof
            proof_signature = self._sign_proof(proof)
            proof["signature"] = proof_signature

            return proof

        except Exception as e:
            raise AuditHashError(f"Integrity proof generation failed: {e}") from e

    def _serialize_entry_for_hashing(self, entry: AuditEntry) -> bytes:
        """Serialize audit entry for hashing in a deterministic way.

        Args:
            entry: Audit entry to serialize

        Returns:
            Serialized entry bytes
        """
        # Create deterministic serialization
        data_string = (
            f"{entry.entry_id}|"
            f"{entry.tenant_id}|"
            f"{entry.agent_id}|"
            f"{entry.timestamp.isoformat()}|"
            f"{entry.domain.value}|"
            f"{entry.decision.value}|"
            f"{entry.reason}|"
            f"{entry.policy_id or ''}|"
            f"{entry.rule_id or ''}|"
            f"{entry.request_method}|"
            f"{entry.request_path}|"
            f"{entry.user_agent or ''}|"
            f"{entry.source_ip or ''}|"
            f"{entry.response_status or ''}|"
            f"{entry.response_size_bytes or ''}|"
            f"{entry.processing_time_ms or ''}|"
            f"{entry.sequence_number}"
        )

        return data_string.encode("utf-8")

    def _compute_merkle_root(self, hashes: list[str]) -> str:
        """Compute merkle tree root hash.

        Args:
            hashes: List of hash strings

        Returns:
            Root hash as hex string
        """
        if not hashes:
            return ""

        if len(hashes) == 1:
            return hashes[0]

        # Build merkle tree
        current_level = hashes[:]

        while len(current_level) > 1:
            next_level = []

            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1] if i + 1 < len(current_level) else left

                combined = f"{left}{right}"
                parent_hash = hashlib.sha256(combined.encode("utf-8")).hexdigest()
                next_level.append(parent_hash)

            current_level = next_level

        return current_level[0]

    def _sign_proof(self, proof: dict[str, str]) -> str:
        """Sign integrity proof with HMAC.

        Args:
            proof: Proof dictionary to sign

        Returns:
            Signature as hex string
        """
        # Create canonical representation of proof
        sorted_items = sorted(proof.items())
        proof_string = "|".join(f"{k}:{v}" for k, v in sorted_items if k != "signature")

        # Sign with HMAC
        return hmac.new(self.secret_key, proof_string.encode("utf-8"), self._algorithm).hexdigest()
