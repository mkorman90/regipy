"""Unit tests for regipy.plugins.utils module"""

from unittest.mock import MagicMock

from regipy.plugins.utils import extract_values


def _make_mock_value(name, value):
    """Helper to create a mock registry value"""
    mock = MagicMock()
    mock.name = name
    mock.value = value
    return mock


def _make_mock_key(values):
    """Helper to create a mock registry key with values"""
    mock = MagicMock()
    mock.iter_values.return_value = [_make_mock_value(name, val) for name, val in values]
    return mock


class TestExtractValues:
    """Tests for extract_values utility function"""

    def test_simple_rename(self):
        """Test simple string rename mapping"""
        key = _make_mock_key([("ProfileName", "MyNetwork")])
        entry = {}

        extract_values(key, {"ProfileName": "profile_name"}, entry)

        assert entry == {"profile_name": "MyNetwork"}

    def test_multiple_simple_renames(self):
        """Test multiple string rename mappings"""
        key = _make_mock_key([
            ("ProfileName", "MyNetwork"),
            ("Description", "Home WiFi"),
        ])
        entry = {}

        extract_values(key, {
            "ProfileName": "profile_name",
            "Description": "description",
        }, entry)

        assert entry == {
            "profile_name": "MyNetwork",
            "description": "Home WiFi",
        }

    def test_callable_converter(self):
        """Test tuple with callable converter"""
        key = _make_mock_key([("Enabled", 1)])
        entry = {}

        extract_values(key, {
            "Enabled": ("enabled", lambda v: v == 1),
        }, entry)

        assert entry == {"enabled": True}

    def test_callable_converter_false(self):
        """Test callable converter returning False"""
        key = _make_mock_key([("Enabled", 0)])
        entry = {}

        extract_values(key, {
            "Enabled": ("enabled", lambda v: v == 1),
        }, entry)

        assert entry == {"enabled": False}

    def test_lookup_converter(self):
        """Test callable that performs lookup"""
        categories = {0: "Public", 1: "Private", 2: "Domain"}
        key = _make_mock_key([("Category", 1)])
        entry = {}

        extract_values(key, {
            "Category": ("category", lambda v: categories.get(v, f"Unknown ({v})")),
        }, entry)

        assert entry == {"category": "Private"}

    def test_lookup_converter_unknown(self):
        """Test lookup converter with unknown value"""
        categories = {0: "Public", 1: "Private", 2: "Domain"}
        key = _make_mock_key([("Category", 99)])
        entry = {}

        extract_values(key, {
            "Category": ("category", lambda v: categories.get(v, f"Unknown ({v})")),
        }, entry)

        assert entry == {"category": "Unknown (99)"}

    def test_unmapped_values_ignored(self):
        """Test that values not in value_map are ignored"""
        key = _make_mock_key([
            ("ProfileName", "MyNetwork"),
            ("UnknownField", "SomeValue"),
        ])
        entry = {}

        extract_values(key, {"ProfileName": "profile_name"}, entry)

        assert entry == {"profile_name": "MyNetwork"}
        assert "UnknownField" not in entry

    def test_preserves_existing_entry_values(self):
        """Test that existing entry values are preserved"""
        key = _make_mock_key([("ProfileName", "MyNetwork")])
        entry = {"type": "profile", "key_path": "/some/path"}

        extract_values(key, {"ProfileName": "profile_name"}, entry)

        assert entry == {
            "type": "profile",
            "key_path": "/some/path",
            "profile_name": "MyNetwork",
        }

    def test_empty_value_map(self):
        """Test with empty value_map"""
        key = _make_mock_key([("ProfileName", "MyNetwork")])
        entry = {}

        extract_values(key, {}, entry)

        assert entry == {}

    def test_empty_registry_key(self):
        """Test with registry key that has no values"""
        key = _make_mock_key([])
        entry = {}

        extract_values(key, {"ProfileName": "profile_name"}, entry)

        assert entry == {}

    def test_mixed_simple_and_callable(self):
        """Test mixing simple rename and callable converters"""
        key = _make_mock_key([
            ("ProfileName", "MyNetwork"),
            ("Enabled", 1),
            ("Category", 2),
        ])
        entry = {}

        extract_values(key, {
            "ProfileName": "profile_name",
            "Enabled": ("enabled", lambda v: v != 0),
            "Category": ("category", lambda v: {0: "Public", 1: "Private", 2: "Domain"}.get(v)),
        }, entry)

        assert entry == {
            "profile_name": "MyNetwork",
            "enabled": True,
            "category": "Domain",
        }

    def test_converter_with_bytes(self):
        """Test converter that handles bytes (like MAC address)"""
        def format_mac(val):
            if isinstance(val, bytes) and len(val) == 6:
                return ":".join(f"{b:02X}" for b in val)
            return val

        key = _make_mock_key([("MacAddress", b"\x00\x1A\x2B\x3C\x4D\x5E")])
        entry = {}

        extract_values(key, {
            "MacAddress": ("mac_address", format_mac),
        }, entry)

        assert entry == {"mac_address": "00:1A:2B:3C:4D:5E"}

    def test_converter_returns_none(self):
        """Test converter that returns None"""
        key = _make_mock_key([("DateCreated", b"\x00")])
        entry = {}

        extract_values(key, {
            "DateCreated": ("date_created", lambda v: None if len(v) < 16 else "parsed"),
        }, entry)

        assert entry == {"date_created": None}

    def test_converter_with_integer_values(self):
        """Test various integer value conversions"""
        key = _make_mock_key([
            ("Bias", -300),
            ("DaylightBias", -60),
        ])
        entry = {}

        extract_values(key, {
            "Bias": ("bias_minutes", lambda v: v),
            "DaylightBias": ("daylight_bias_minutes", lambda v: v),
        }, entry)

        assert entry == {
            "bias_minutes": -300,
            "daylight_bias_minutes": -60,
        }
