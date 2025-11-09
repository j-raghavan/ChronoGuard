"""Comprehensive tests for OPA bundle builder."""

import io
import json
import tarfile
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, mock_open, patch

import pytest
from infrastructure.opa.bundle_builder import (
    BundleBuilder,
    BundleBuilderError,
    BundleValidationError,
    create_bundle_from_policies,
)


class TestBundleBuilder:
    """Test suite for BundleBuilder."""

    @pytest.fixture
    def builder(self) -> BundleBuilder:
        """Create bundle builder instance."""
        return BundleBuilder(bundle_name="test_bundle", revision="rev123")

    @pytest.fixture
    def sample_rego(self) -> str:
        """Sample Rego policy code."""
        return """
        package chronoguard

        default allow = false

        allow {
            input.domain == "example.com"
        }
        """

    @pytest.fixture
    def sample_data(self) -> dict[str, Any]:
        """Sample data for bundle."""
        return {
            "allowed_domains": ["example.com", "test.com"],
            "rate_limit": 100,
        }

    def test_init_minimal(self) -> None:
        """Test BundleBuilder initialization with minimal args."""
        builder = BundleBuilder(bundle_name="test")

        assert builder.bundle_name == "test"
        assert builder.revision is not None
        assert len(builder.revision) == 12  # SHA256 hash truncated to 12 chars
        assert builder.roots == ["test"]
        assert builder._policies == {}
        assert builder._data == {}
        assert builder._metadata == {}

    def test_init_full(self) -> None:
        """Test BundleBuilder initialization with all args."""
        builder = BundleBuilder(
            bundle_name="chronoguard",
            revision="custom-rev",
            roots=["chronoguard", "policies"],
        )

        assert builder.bundle_name == "chronoguard"
        assert builder.revision == "custom-rev"
        assert builder.roots == ["chronoguard", "policies"]

    def test_init_empty_name_raises(self) -> None:
        """Test initialization with empty name raises ValueError."""
        with pytest.raises(ValueError, match="Bundle name cannot be empty"):
            BundleBuilder(bundle_name="")

    def test_add_policy(self, builder: BundleBuilder, sample_rego: str) -> None:
        """Test adding a policy to bundle."""
        result = builder.add_policy("policies/allow.rego", sample_rego)

        assert result is builder  # Method chaining
        assert "policies/allow.rego" in builder._policies
        assert builder._policies["policies/allow.rego"] == sample_rego

    def test_add_policy_auto_extension(self, builder: BundleBuilder, sample_rego: str) -> None:
        """Test adding policy auto-adds .rego extension."""
        builder.add_policy("policies/allow", sample_rego)

        assert "policies/allow.rego" in builder._policies

    def test_add_policy_empty_path_raises(self, builder: BundleBuilder) -> None:
        """Test adding policy with empty path raises ValueError."""
        with pytest.raises(ValueError, match="Policy path cannot be empty"):
            builder.add_policy("", "package chronoguard")

    def test_add_policy_empty_code_raises(self, builder: BundleBuilder) -> None:
        """Test adding policy with empty code raises ValueError."""
        with pytest.raises(ValueError, match="Rego code cannot be empty"):
            builder.add_policy("policies/allow.rego", "")

    def test_add_policy_duplicate_raises(self, builder: BundleBuilder, sample_rego: str) -> None:
        """Test adding duplicate policy raises BundleValidationError."""
        builder.add_policy("policies/allow.rego", sample_rego)

        with pytest.raises(BundleValidationError, match="Policy already exists"):
            builder.add_policy("policies/allow.rego", sample_rego)

    def test_add_data_dict(self, builder: BundleBuilder, sample_data: dict[str, Any]) -> None:
        """Test adding data dictionary to bundle."""
        result = builder.add_data("data/config.json", sample_data)

        assert result is builder  # Method chaining
        assert "data/config.json" in builder._data
        assert builder._data["data/config.json"] == sample_data

    def test_add_data_string(self, builder: BundleBuilder) -> None:
        """Test adding string data to bundle."""
        builder.add_data("data/notes.txt", "Some notes")

        assert "data/notes.txt" in builder._data
        assert builder._data["data/notes.txt"] == "Some notes"

    def test_add_data_auto_json_extension(
        self,
        builder: BundleBuilder,
        sample_data: dict[str, Any],
    ) -> None:
        """Test adding dict data auto-adds .json extension."""
        builder.add_data("data/config", sample_data)

        assert "data/config.json" in builder._data

    def test_add_data_empty_path_raises(self, builder: BundleBuilder) -> None:
        """Test adding data with empty path raises ValueError."""
        with pytest.raises(ValueError, match="Data path cannot be empty"):
            builder.add_data("", {"key": "value"})

    def test_add_data_duplicate_raises(
        self,
        builder: BundleBuilder,
        sample_data: dict[str, Any],
    ) -> None:
        """Test adding duplicate data raises BundleValidationError."""
        builder.add_data("data/config.json", sample_data)

        with pytest.raises(BundleValidationError, match="Data file already exists"):
            builder.add_data("data/config.json", sample_data)

    def test_set_metadata(self, builder: BundleBuilder) -> None:
        """Test setting custom metadata."""
        result = builder.set_metadata("version", "1.0.0")

        assert result is builder  # Method chaining
        assert builder._metadata["version"] == "1.0.0"

    def test_set_metadata_multiple(self, builder: BundleBuilder) -> None:
        """Test setting multiple metadata fields."""
        builder.set_metadata("version", "1.0.0")
        builder.set_metadata("author", "ChronoGuard Team")

        assert builder._metadata["version"] == "1.0.0"
        assert builder._metadata["author"] == "ChronoGuard Team"

    def test_build_success(
        self,
        builder: BundleBuilder,
        sample_rego: str,
        sample_data: dict[str, Any],
    ) -> None:
        """Test successful bundle build."""
        builder.add_policy("policies/allow.rego", sample_rego)
        builder.add_data("data/config.json", sample_data)
        builder.set_metadata("version", "1.0.0")

        bundle_bytes = builder.build()

        assert isinstance(bundle_bytes, bytes)
        assert len(bundle_bytes) > 0

        # Verify it's a valid tar.gz
        buffer = io.BytesIO(bundle_bytes)
        with tarfile.open(fileobj=buffer, mode="r:gz") as tar:
            members = tar.getnames()
            assert ".manifest" in members
            assert "policies/allow.rego" in members
            assert "data/config.json" in members

    def test_build_empty_raises(self, builder: BundleBuilder) -> None:
        """Test building empty bundle raises BundleValidationError."""
        with pytest.raises(BundleValidationError, match="must contain at least one"):
            builder.build()

    def test_build_with_only_policy(self, builder: BundleBuilder, sample_rego: str) -> None:
        """Test building bundle with only policy."""
        builder.add_policy("policies/allow.rego", sample_rego)

        bundle_bytes = builder.build()

        assert isinstance(bundle_bytes, bytes)
        assert len(bundle_bytes) > 0

    def test_build_with_only_data(
        self, builder: BundleBuilder, sample_data: dict[str, Any]
    ) -> None:
        """Test building bundle with only data."""
        builder.add_data("data/config.json", sample_data)

        bundle_bytes = builder.build()

        assert isinstance(bundle_bytes, bytes)
        assert len(bundle_bytes) > 0

    def test_build_manifest_content(
        self,
        builder: BundleBuilder,
        sample_rego: str,
    ) -> None:
        """Test bundle manifest contains correct data."""
        builder.add_policy("policies/allow.rego", sample_rego)
        builder.set_metadata("version", "1.0.0")

        bundle_bytes = builder.build()

        # Extract and verify manifest
        buffer = io.BytesIO(bundle_bytes)
        with tarfile.open(fileobj=buffer, mode="r:gz") as tar:
            manifest_file = tar.extractfile(".manifest")
            assert manifest_file is not None
            manifest = json.loads(manifest_file.read())

            assert manifest["revision"] == "rev123"
            assert manifest["roots"] == ["test_bundle"]
            assert manifest["metadata"]["version"] == "1.0.0"

    def test_build_policy_content(self, builder: BundleBuilder, sample_rego: str) -> None:
        """Test policy content in bundle."""
        builder.add_policy("policies/allow.rego", sample_rego)

        bundle_bytes = builder.build()

        # Extract and verify policy
        buffer = io.BytesIO(bundle_bytes)
        with tarfile.open(fileobj=buffer, mode="r:gz") as tar:
            policy_file = tar.extractfile("policies/allow.rego")
            assert policy_file is not None
            policy_content = policy_file.read().decode("utf-8")

            assert policy_content == sample_rego

    def test_build_data_content(
        self,
        builder: BundleBuilder,
        sample_data: dict[str, Any],
    ) -> None:
        """Test data content in bundle."""
        builder.add_data("data/config.json", sample_data)

        bundle_bytes = builder.build()

        # Extract and verify data
        buffer = io.BytesIO(bundle_bytes)
        with tarfile.open(fileobj=buffer, mode="r:gz") as tar:
            data_file = tar.extractfile("data/config.json")
            assert data_file is not None
            data_content = json.loads(data_file.read())

            assert data_content == sample_data

    def test_build_with_signing(self, builder: BundleBuilder, sample_rego: str) -> None:
        """Test building bundle with signature."""
        builder.add_policy("policies/allow.rego", sample_rego)
        signing_key = b"secret_key_12345"

        bundle_bytes = builder.build(sign=True, signing_key=signing_key)

        # Verify signature file exists
        buffer = io.BytesIO(bundle_bytes)
        with tarfile.open(fileobj=buffer, mode="r:gz") as tar:
            members = tar.getnames()
            assert ".signatures.json" in members

            # Verify signature content
            sig_file = tar.extractfile(".signatures.json")
            assert sig_file is not None
            sig_data = json.loads(sig_file.read())

            assert "signatures" in sig_data
            assert len(sig_data["signatures"]) == 1
            assert sig_data["signatures"][0]["algorithm"] == "SHA-256"
            assert "signature" in sig_data["signatures"][0]
            assert "timestamp" in sig_data["signatures"][0]

    def test_build_sign_without_key_raises(self, builder: BundleBuilder, sample_rego: str) -> None:
        """Test building with sign=True but no key raises error."""
        builder.add_policy("policies/allow.rego", sample_rego)

        with pytest.raises(BundleValidationError, match="Signing key required"):
            builder.build(sign=True, signing_key=None)

    def test_build_error_handling(self, builder: BundleBuilder) -> None:
        """Test build error handling for unexpected errors."""
        builder.add_policy("test.rego", "package test")

        with patch("tarfile.open", side_effect=RuntimeError("Unexpected error")):
            with pytest.raises(BundleBuilderError, match="Bundle build failed"):
                builder.build()

    def test_save(
        self,
        builder: BundleBuilder,
        sample_rego: str,
        tmp_path: Path,
    ) -> None:
        """Test saving bundle to file."""
        builder.add_policy("policies/allow.rego", sample_rego)
        output_path = tmp_path / "bundle.tar.gz"

        builder.save(output_path)

        assert output_path.exists()
        assert output_path.stat().st_size > 0

        # Verify it's a valid tar.gz
        with tarfile.open(output_path, mode="r:gz") as tar:
            members = tar.getnames()
            assert ".manifest" in members
            assert "policies/allow.rego" in members

    def test_save_creates_parent_dir(
        self,
        builder: BundleBuilder,
        sample_rego: str,
        tmp_path: Path,
    ) -> None:
        """Test save creates parent directory if needed."""
        builder.add_policy("policies/allow.rego", sample_rego)
        output_path = tmp_path / "nested" / "dir" / "bundle.tar.gz"

        builder.save(output_path)

        assert output_path.exists()
        assert output_path.parent.exists()

    def test_save_with_signing(
        self,
        builder: BundleBuilder,
        sample_rego: str,
        tmp_path: Path,
    ) -> None:
        """Test saving signed bundle."""
        builder.add_policy("policies/allow.rego", sample_rego)
        output_path = tmp_path / "bundle.tar.gz"
        signing_key = b"secret_key"

        builder.save(output_path, sign=True, signing_key=signing_key)

        assert output_path.exists()

        # Verify signature exists
        with tarfile.open(output_path, mode="r:gz") as tar:
            assert ".signatures.json" in tar.getnames()

    def test_create_manifest(self, builder: BundleBuilder) -> None:
        """Test _create_manifest method."""
        builder.set_metadata("version", "1.0.0")
        builder.set_metadata("author", "Test")

        manifest = builder._create_manifest()

        assert manifest["revision"] == "rev123"
        assert manifest["roots"] == ["test_bundle"]
        assert manifest["metadata"]["version"] == "1.0.0"
        assert manifest["metadata"]["author"] == "Test"

    def test_create_manifest_no_metadata(self, builder: BundleBuilder) -> None:
        """Test _create_manifest without custom metadata."""
        manifest = builder._create_manifest()

        assert manifest["revision"] == "rev123"
        assert manifest["roots"] == ["test_bundle"]
        assert "metadata" not in manifest

    def test_create_signature(self, builder: BundleBuilder) -> None:
        """Test _create_signature method."""
        manifest = {"revision": "test", "roots": ["chronoguard"]}
        signing_key = b"secret_key_12345"

        signature = builder._create_signature(manifest, signing_key)

        assert "signatures" in signature
        assert len(signature["signatures"]) == 1
        assert signature["signatures"][0]["algorithm"] == "SHA-256"
        assert "signature" in signature["signatures"][0]
        assert "timestamp" in signature["signatures"][0]
        assert isinstance(signature["signatures"][0]["signature"], str)
        assert len(signature["signatures"][0]["signature"]) == 64  # SHA256 hex

    def test_generate_revision(self, builder: BundleBuilder) -> None:
        """Test _generate_revision method."""
        rev1 = builder._generate_revision()
        rev2 = builder._generate_revision()

        assert isinstance(rev1, str)
        assert len(rev1) == 12
        assert rev1 != rev2  # Should be different due to timestamp

    def test_method_chaining(self, builder: BundleBuilder, sample_rego: str) -> None:
        """Test method chaining for fluent API."""
        result = (
            builder.add_policy("test.rego", sample_rego)
            .add_data("data.json", {"key": "value"})
            .set_metadata("version", "1.0.0")
        )

        assert result is builder
        assert len(builder._policies) == 1
        assert len(builder._data) == 1
        assert len(builder._metadata) == 1


class TestCreateBundleFromPolicies:
    """Test suite for create_bundle_from_policies factory function."""

    @pytest.fixture
    def sample_policies(self) -> dict[str, str]:
        """Sample policies dictionary."""
        return {
            "policies/allow.rego": "package chronoguard\nallow { true }",
            "policies/deny.rego": "package chronoguard\ndeny { false }",
        }

    def test_create_minimal(self, sample_policies: dict[str, str]) -> None:
        """Test creating bundle with minimal args."""
        bundle_bytes = create_bundle_from_policies(sample_policies)

        assert isinstance(bundle_bytes, bytes)
        assert len(bundle_bytes) > 0

        # Verify bundle contents
        buffer = io.BytesIO(bundle_bytes)
        with tarfile.open(fileobj=buffer, mode="r:gz") as tar:
            members = tar.getnames()
            assert ".manifest" in members
            assert "policies/allow.rego" in members
            assert "policies/deny.rego" in members

    def test_create_with_custom_name(self, sample_policies: dict[str, str]) -> None:
        """Test creating bundle with custom name."""
        bundle_bytes = create_bundle_from_policies(
            sample_policies,
            bundle_name="custom_bundle",
        )

        # Verify bundle name in manifest
        buffer = io.BytesIO(bundle_bytes)
        with tarfile.open(fileobj=buffer, mode="r:gz") as tar:
            manifest_file = tar.extractfile(".manifest")
            assert manifest_file is not None
            manifest = json.loads(manifest_file.read())

            assert manifest["roots"] == ["custom_bundle"]

    def test_create_with_data(self, sample_policies: dict[str, str]) -> None:
        """Test creating bundle with data files."""
        data = {
            "data/config.json": {"setting": "value"},
            "data/values.json": {"key": "value"},
        }

        bundle_bytes = create_bundle_from_policies(
            sample_policies,
            data=data,
        )

        # Verify data files in bundle
        buffer = io.BytesIO(bundle_bytes)
        with tarfile.open(fileobj=buffer, mode="r:gz") as tar:
            members = tar.getnames()
            assert "data/config.json" in members
            assert "data/values.json" in members

    def test_create_with_metadata(self, sample_policies: dict[str, str]) -> None:
        """Test creating bundle with metadata."""
        metadata = {
            "version": "1.0.0",
            "author": "ChronoGuard Team",
        }

        bundle_bytes = create_bundle_from_policies(
            sample_policies,
            metadata=metadata,
        )

        # Verify metadata in manifest
        buffer = io.BytesIO(bundle_bytes)
        with tarfile.open(fileobj=buffer, mode="r:gz") as tar:
            manifest_file = tar.extractfile(".manifest")
            assert manifest_file is not None
            manifest = json.loads(manifest_file.read())

            assert manifest["metadata"]["version"] == "1.0.0"
            assert manifest["metadata"]["author"] == "ChronoGuard Team"

    def test_create_full(self, sample_policies: dict[str, str]) -> None:
        """Test creating bundle with all options."""
        data = {"data/config.json": {"setting": "value"}}
        metadata = {"version": "1.0.0"}

        bundle_bytes = create_bundle_from_policies(
            sample_policies,
            bundle_name="full_bundle",
            data=data,
            metadata=metadata,
        )

        assert isinstance(bundle_bytes, bytes)
        assert len(bundle_bytes) > 0

        # Verify all components
        buffer = io.BytesIO(bundle_bytes)
        with tarfile.open(fileobj=buffer, mode="r:gz") as tar:
            members = tar.getnames()
            assert ".manifest" in members
            assert "policies/allow.rego" in members
            assert "data/config.json" in members

            manifest_file = tar.extractfile(".manifest")
            assert manifest_file is not None
            manifest = json.loads(manifest_file.read())
            assert manifest["roots"] == ["full_bundle"]
            assert manifest["metadata"]["version"] == "1.0.0"


class TestBundleBuilderExceptions:
    """Test bundle builder exception hierarchy."""

    def test_bundle_builder_error_base(self) -> None:
        """Test BundleBuilderError is base exception."""
        error = BundleBuilderError("Test error")
        assert isinstance(error, Exception)
        assert str(error) == "Test error"

    def test_bundle_validation_error(self) -> None:
        """Test BundleValidationError inherits from base."""
        error = BundleValidationError("Validation failed")
        assert isinstance(error, BundleBuilderError)
        assert str(error) == "Validation failed"
