"""ChronoGuard - Agent Identity & Compliance Platform for AI agents."""

__version__ = "1.0.0"
__author__ = "ChronoGuard Team"
__email__ = "team@chronoguard.com"

# Re-export main components for easy access
from core.container import DependencyContainer
from core.features import FeatureManager


__all__ = ["FeatureManager", "DependencyContainer", "__version__"]
