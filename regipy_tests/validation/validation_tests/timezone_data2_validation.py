from regipy.plugins.system.timezone_data2 import TimezoneDataPlugin2
from regipy_tests.validation.validation import ValidationCase


def test_tz2_plugin_output(c: ValidationCase):
    assert c.plugin_output["\\ControlSet001\\Control\\TimeZoneInformation"] == {
        "last_write": "2012-03-11T07:00:00.000642+00:00",
        "Bias": 300,
        "DaylightBias": -60,
        "DaylightName": "@tzres.dll,-111",
        "DaylightStart": "00000300020002000000000000000000",
        "StandardBias": 0,
        "StandardName": "@tzres.dll,-112",
        "StandardStart": "00000b00010002000000000000000000",
        "TimeZoneKeyName": "Eastern Standard Time",
        "DynamicDaylightTimeDisabled": 0,
        "ActiveTimeBias": 240,
    }


class TimezoneDataPlugin2ValidationCase(ValidationCase):
    plugin = TimezoneDataPlugin2
    test_hive_file_name = "SYSTEM.xz"
    custom_test = test_tz2_plugin_output
    expected_entries_count = 2
