from regipy.plugins.system.timezone_data import TimezoneDataPlugin
from regipy_tests.validation.validation import ValidationCase


def test_timezone_data(c: ValidationCase):
    assert {(x["name"], x["value"]) for x in c.plugin_output["\\ControlSet001\\Control\\TimeZoneInformation"]} == {
        ("DaylightBias", 4294967236),
        ("Bias", 300),
        ("StandardBias", 0),
        ("TimeZoneKeyName", "Eastern Standard Time"),
        ("ActiveTimeBias", 240),
        ("StandardStart", "00000b00010002000000000000000000"),
        ("DaylightStart", "00000300020002000000000000000000"),
        ("StandardName", "@tzres.dll,-112"),
        ("DynamicDaylightTimeDisabled", 0),
        ("DaylightName", "@tzres.dll,-111"),
    }


class TimezoneDataPluginValidationCase(ValidationCase):
    plugin = TimezoneDataPlugin
    test_hive_file_name = "SYSTEM.xz"
    custom_test = test_timezone_data
    expected_entries_count = 2
