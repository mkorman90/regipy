"""
Plugin validation status tracking.

This module tracks which plugins have been validated with test cases.
Plugins without validation may return invalid or incomplete data.

Validation status is stored in validated_plugins.json, which is generated
by the validation test framework and shipped with the package.
"""

import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

# Load validated plugins from JSON file shipped with the package
_VALIDATED_PLUGINS_FILE = Path(__file__).parent / "validated_plugins.json"

try:
    with open(_VALIDATED_PLUGINS_FILE) as f:
        VALIDATED_PLUGINS: set[str] = set(json.load(f))
except FileNotFoundError:
    logger.warning(f"Validated plugins file not found: {_VALIDATED_PLUGINS_FILE}")
    VALIDATED_PLUGINS = set()


def is_plugin_validated(plugin_name: str) -> bool:
    """Check if a plugin has validation test cases."""
    return plugin_name in VALIDATED_PLUGINS


def get_validated_plugins() -> set[str]:
    """Get set of all validated plugin names."""
    return VALIDATED_PLUGINS.copy()


def get_unvalidated_plugins(plugin_names: list[str]) -> list[str]:
    """Get list of plugin names that don't have validation."""
    return [name for name in plugin_names if name not in VALIDATED_PLUGINS]


def warn_unvalidated_plugin(plugin_name: str) -> None:
    """Log a warning for an unvalidated plugin."""
    logger.warning(
        f"Plugin '{plugin_name}' does not have a validation test case. "
        "Results may be incomplete or inaccurate. Use at your own discretion."
    )
