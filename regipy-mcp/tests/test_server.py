"""Tests for regipy-mcp server."""

from regipy_mcp.server import (
    _hive_paths,
    _hives_by_type,
    get_key,
    list_hives,
    list_plugins,
    run_plugin,
)


class TestListPlugins:
    """Tests for list_plugins tool."""

    def test_returns_list_of_plugins(self):
        """Should return plugins grouped by hive type."""
        result = list_plugins()

        assert isinstance(result, list)
        assert len(result) > 0

        # Check structure - now grouped by hive type
        plugin_group = result[0]
        assert "hive_type" in plugin_group
        assert "hive_available" in plugin_group
        assert "plugins" in plugin_group

    def test_includes_common_plugins(self):
        """Should include well-known plugins."""
        result = list_plugins()

        # Flatten plugin names from all groups
        plugin_names = []
        for group in result:
            for p in group["plugins"]:
                plugin_names.append(p["name"])

        assert "shimcache" in plugin_names
        assert "usbstor_plugin" in plugin_names


class TestListHives:
    """Tests for list_hives tool."""

    def test_returns_hives_or_error(self):
        """Should return hives list or error when no directory configured."""
        # Clear any loaded hives to test empty state
        _hives_by_type.clear()
        _hive_paths.clear()

        result = list_hives()

        # Should return either hives or error
        assert "hives" in result or "error" in result


class TestRunPlugin:
    """Tests for run_plugin tool."""

    def test_returns_error_for_unknown_plugin(self):
        """Should return error for non-existent plugin."""
        result = run_plugin("nonexistent_plugin")

        assert "error" in result
        assert "not found" in result["error"]

    def test_returns_error_when_no_compatible_hive(self):
        """Should return error when no hive is available for plugin."""
        # Clear hives
        _hives_by_type.clear()
        _hive_paths.clear()

        # shimcache requires SYSTEM hive
        result = run_plugin("shimcache")

        assert "error" in result
        assert "No compatible hive" in result["error"]


class TestGetKey:
    """Tests for get_key tool."""

    def test_returns_error_when_key_not_found(self):
        """Should return error for non-existent key."""
        # Clear hives so key won't be found
        _hives_by_type.clear()
        _hive_paths.clear()

        result = get_key("\\Invalid\\Key\\Path")

        assert "error" in result
