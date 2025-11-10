"""Domain interfaces for audit infrastructure dependencies.

This module defines abstract interfaces for infrastructure components
that the audit domain layer depends on, maintaining Clean Architecture.
"""

from abc import abstractmethod
from typing import Protocol


class Signer(Protocol):
    """Abstract interface for cryptographic signers.

    This protocol defines the contract for signing audit entries.
    Infrastructure implementations provide concrete signing mechanisms.
    """

    @abstractmethod
    def sign(self, data: bytes) -> bytes:
        """Sign data with private key.

        Args:
            data: Data to sign

        Returns:
            Signature bytes

        Raises:
            SecurityViolationError: If signing fails
        """
        ...

    @abstractmethod
    def verify(self, data: bytes, signature: bytes) -> bool:
        """Verify signature of data.

        Args:
            data: Original data
            signature: Signature to verify

        Returns:
            True if signature is valid

        Raises:
            SecurityViolationError: If verification fails
        """
        ...
