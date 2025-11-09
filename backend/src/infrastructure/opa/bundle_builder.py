"""OPA bundle builder for creating policy bundles.

This module provides functionality to create OPA bundles in .tar.gz format.
It handles bundle manifest generation, Rego file packaging, data file packaging,
and optional bundle signing.
"""

from __future__ import annotations

import hashlib
import io
import json
import tarfile
import time
from pathlib import Path
from typing import Any

from loguru import logger


class BundleBuilderError(Exception):
    """Base exception for bundle builder errors."""

    pass


class BundleValidationError(BundleBuilderError):
    """Exception raised for bundle validation errors."""

    pass


class BundleBuilder:
    """Builder for creating OPA policy bundles.

    This builder creates OPA bundles in .tar.gz format containing policies,
    data files, and manifests. Bundles can be served via HTTP and loaded
    by OPA for atomic policy updates.

    Example:
        >>> builder = BundleBuilder(bundle_name="chronoguard_policies")
        >>> builder.add_policy("policy1.rego", rego_code)
        >>> builder.add_data("data.json", {"key": "value"})
        >>> bundle_bytes = builder.build()
        >>> with open("bundle.tar.gz", "wb") as f:
        ...     f.write(bundle_bytes)
    """

    def __init__(
        self,
        bundle_name: str = "chronoguard",
        revision: str | None = None,
        roots: list[str] | None = None,
    ) -> None:
        """Initialize bundle builder.

        Args:
            bundle_name: Name of the bundle
            revision: Optional bundle revision (auto-generated if None)
            roots: Optional OPA data roots (defaults to [bundle_name])

        Raises:
            ValueError: If bundle_name is empty
        """
        if not bundle_name:
            raise ValueError("Bundle name cannot be empty")

        self.bundle_name = bundle_name
        self.revision = revision or self._generate_revision()
        self.roots = roots or [bundle_name]

        # Bundle contents
        self._policies: dict[str, str] = {}
        self._data: dict[str, Any] = {}
        self._metadata: dict[str, Any] = {}

        logger.debug(
            f"Initialized BundleBuilder: name={bundle_name}, "
            f"revision={self.revision}, roots={self.roots}"
        )

    def add_policy(self, policy_path: str, rego_code: str) -> BundleBuilder:
        """Add a Rego policy to the bundle.

        Args:
            policy_path: Path within bundle (e.g., "policies/allow.rego")
            rego_code: Rego policy code as string

        Returns:
            Self for method chaining

        Raises:
            ValueError: If policy_path or rego_code is empty
            BundleValidationError: If policy already exists

        Example:
            >>> builder.add_policy("policies/allow.rego", "package chronoguard...")
        """
        if not policy_path:
            raise ValueError("Policy path cannot be empty")

        if not rego_code:
            raise ValueError("Rego code cannot be empty")

        # Ensure .rego extension
        if not policy_path.endswith(".rego"):
            policy_path = f"{policy_path}.rego"

        # Check for duplicates
        if policy_path in self._policies:
            raise BundleValidationError(f"Policy already exists: {policy_path}")

        self._policies[policy_path] = rego_code
        logger.debug(f"Added policy to bundle: {policy_path} ({len(rego_code)} bytes)")

        return self

    def add_data(self, data_path: str, data: Any) -> BundleBuilder:
        """Add data file to the bundle.

        Data can be a dictionary (serialized as JSON) or a string.

        Args:
            data_path: Path within bundle (e.g., "data/config.json")
            data: Data to add (dict or string)

        Returns:
            Self for method chaining

        Raises:
            ValueError: If data_path is empty
            BundleValidationError: If data file already exists

        Example:
            >>> builder.add_data("data/config.json", {"setting": "value"})
        """
        if not data_path:
            raise ValueError("Data path cannot be empty")

        # Ensure .json extension for dict data
        if isinstance(data, dict) and not data_path.endswith(".json"):
            data_path = f"{data_path}.json"

        # Check for duplicates
        if data_path in self._data:
            raise BundleValidationError(f"Data file already exists: {data_path}")

        self._data[data_path] = data
        logger.debug(f"Added data to bundle: {data_path}")

        return self

    def set_metadata(self, key: str, value: Any) -> BundleBuilder:
        """Set custom metadata in the bundle manifest.

        Args:
            key: Metadata key
            value: Metadata value (must be JSON-serializable)

        Returns:
            Self for method chaining

        Example:
            >>> builder.set_metadata("version", "1.0.0")
            >>> builder.set_metadata("author", "ChronoGuard Team")
        """
        self._metadata[key] = value
        logger.debug(f"Set bundle metadata: {key}={value}")

        return self

    def build(self, sign: bool = False, signing_key: bytes | None = None) -> bytes:
        """Build the OPA bundle as .tar.gz bytes.

        Creates a complete OPA bundle with manifest, policies, and data files.

        Args:
            sign: Whether to sign the bundle (requires signing_key)
            signing_key: Optional signing key for bundle signatures

        Returns:
            Bundle as bytes (tar.gz format)

        Raises:
            BundleValidationError: If bundle is invalid or signing fails

        Example:
            >>> bundle_bytes = builder.build()
            >>> # Or with signing
            >>> bundle_bytes = builder.build(sign=True, signing_key=b"secret")
        """
        if not self._policies and not self._data:
            raise BundleValidationError("Bundle must contain at least one policy or data file")

        if sign and not signing_key:
            raise BundleValidationError("Signing key required when sign=True")

        try:
            # Create tar.gz in memory
            buffer = io.BytesIO()

            with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
                # Add manifest
                manifest_data = self._create_manifest()
                self._add_json_to_tar(tar, ".manifest", manifest_data)

                # Add policies
                for policy_path, rego_code in self._policies.items():
                    self._add_text_to_tar(tar, policy_path, rego_code)

                # Add data files
                for data_path, data in self._data.items():
                    if isinstance(data, dict):
                        self._add_json_to_tar(tar, data_path, data)
                    else:
                        self._add_text_to_tar(tar, data_path, str(data))

                # Add signature if requested
                if sign and signing_key:
                    signature = self._create_signature(manifest_data, signing_key)
                    self._add_json_to_tar(tar, ".signatures.json", signature)

            bundle_bytes = buffer.getvalue()
            logger.info(
                f"Built OPA bundle: name={self.bundle_name}, "
                f"revision={self.revision}, size={len(bundle_bytes)} bytes, "
                f"policies={len(self._policies)}, data_files={len(self._data)}, "
                f"signed={sign}"
            )

            return bundle_bytes

        except Exception as e:
            logger.error(f"Failed to build OPA bundle: {e}", exc_info=True)
            raise BundleBuilderError(f"Bundle build failed: {e}") from e

    def save(
        self,
        output_path: Path | str,
        sign: bool = False,
        signing_key: bytes | None = None,
    ) -> None:
        """Build and save the bundle to a file.

        Args:
            output_path: Path to save the bundle file
            sign: Whether to sign the bundle
            signing_key: Optional signing key

        Raises:
            BundleValidationError: If bundle is invalid
            OSError: If file cannot be written

        Example:
            >>> builder.save("/var/lib/opa/bundles/chronoguard.tar.gz")
        """
        output_path = Path(output_path)

        # Ensure parent directory exists
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Build bundle
        bundle_bytes = self.build(sign=sign, signing_key=signing_key)

        # Write to file
        output_path.write_bytes(bundle_bytes)

        logger.info(f"Saved OPA bundle to: {output_path} ({len(bundle_bytes)} bytes)")

    def _create_manifest(self) -> dict[str, Any]:
        """Create bundle manifest.

        Returns:
            Manifest dictionary
        """
        manifest: dict[str, Any] = {
            "revision": self.revision,
            "roots": self.roots,
        }

        # Add custom metadata
        if self._metadata:
            manifest["metadata"] = self._metadata.copy()

        return manifest

    def _create_signature(
        self,
        manifest: dict[str, Any],
        signing_key: bytes,
    ) -> dict[str, Any]:
        """Create bundle signature.

        Args:
            manifest: Bundle manifest
            signing_key: Signing key

        Returns:
            Signature dictionary
        """
        # Create signature of manifest
        manifest_bytes = json.dumps(manifest, sort_keys=True).encode()
        signature_hash = hashlib.sha256(manifest_bytes + signing_key).hexdigest()

        return {
            "signatures": [
                {
                    "signature": signature_hash,
                    "algorithm": "SHA-256",
                    "timestamp": time.time(),
                }
            ]
        }

    def _add_json_to_tar(
        self,
        tar: tarfile.TarFile,
        path: str,
        data: dict[str, Any],
    ) -> None:
        """Add JSON data to tar archive.

        Args:
            tar: Tar archive
            path: File path within archive
            data: Data to serialize as JSON
        """
        json_bytes = json.dumps(data, indent=2).encode("utf-8")
        info = tarfile.TarInfo(name=path)
        info.size = len(json_bytes)
        info.mtime = int(time.time())
        tar.addfile(info, io.BytesIO(json_bytes))

    def _add_text_to_tar(
        self,
        tar: tarfile.TarFile,
        path: str,
        content: str,
    ) -> None:
        """Add text file to tar archive.

        Args:
            tar: Tar archive
            path: File path within archive
            content: Text content
        """
        content_bytes = content.encode("utf-8")
        info = tarfile.TarInfo(name=path)
        info.size = len(content_bytes)
        info.mtime = int(time.time())
        tar.addfile(info, io.BytesIO(content_bytes))

    def _generate_revision(self) -> str:
        """Generate unique revision ID.

        Returns:
            Revision ID as hex string
        """
        timestamp = str(time.time()).encode()
        return hashlib.sha256(timestamp).hexdigest()[:12]


def create_bundle_from_policies(
    policies: dict[str, str],
    bundle_name: str = "chronoguard",
    data: dict[str, Any] | None = None,
    metadata: dict[str, Any] | None = None,
) -> bytes:
    """Factory function to create bundle from policies.

    Convenience function for creating bundles from policy dictionaries.

    Args:
        policies: Dictionary of policy_path -> rego_code
        bundle_name: Name of the bundle
        data: Optional data dictionary (path -> data)
        metadata: Optional metadata dictionary

    Returns:
        Bundle as bytes (tar.gz format)

    Example:
        >>> policies = {
        ...     "policies/allow.rego": "package chronoguard\\nallow { true }",
        ...     "policies/deny.rego": "package chronoguard\\ndeny { false }"
        ... }
        >>> bundle = create_bundle_from_policies(policies)
    """
    builder = BundleBuilder(bundle_name=bundle_name)

    # Add policies
    for policy_path, rego_code in policies.items():
        builder.add_policy(policy_path, rego_code)

    # Add data if provided
    if data:
        for data_path, data_content in data.items():
            builder.add_data(data_path, data_content)

    # Add metadata if provided
    if metadata:
        for key, value in metadata.items():
            builder.set_metadata(key, value)

    return builder.build()
