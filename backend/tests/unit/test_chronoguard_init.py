"""Tests for chronoguard module initialization."""

import chronoguard
from core.container import DependencyContainer
from core.features import FeatureManager


class TestChronoGuardInit:
    """Test chronoguard module initialization."""

    def test_version_info(self) -> None:
        """Test version information is available."""
        assert hasattr(chronoguard, "__version__")
        assert hasattr(chronoguard, "__author__")
        assert hasattr(chronoguard, "__email__")

        assert chronoguard.__version__ == "1.0.0"
        assert chronoguard.__author__ == "ChronoGuard Team"
        assert chronoguard.__email__ == "team@chronoguard.com"

    def test_exported_components(self) -> None:
        """Test that main components are exported."""
        assert hasattr(chronoguard, "FeatureManager")
        assert hasattr(chronoguard, "DependencyContainer")

        # Verify they're the correct classes
        assert chronoguard.FeatureManager is FeatureManager
        assert chronoguard.DependencyContainer is DependencyContainer

    def test_all_attribute(self) -> None:
        """Test __all__ attribute contains expected exports."""
        expected_exports = ["FeatureManager", "DependencyContainer", "__version__"]
        assert chronoguard.__all__ == expected_exports

        # Verify all exported items actually exist
        for item in chronoguard.__all__:
            assert hasattr(chronoguard, item)
