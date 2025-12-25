from regipy.plugins.system.timezone_data import TimezoneDataPlugin
from regipy_tests.validation.validation import ValidationCase


def test_timezone_data(c: ValidationCase):
    assert {(x["name"], x["value"]) for x in c.plugin_output["\\ControlSet001\\Control\\TimeZoneInformation"]} == {
        ("DaylightBias", 4294967236),
        ("Bias", 300),
        ("StandardBias", 0),
        (
            "TimeZoneKeyName",
            "4500610073007400650072006e0020005300740061006e00640061007200640020"
            "00540069006d00650000001963747614060136f408f101000000000000000000000"
            "00000000000940af101a80af10102000000040bf101000000007c0bf10100000000"
            "c80bf1010000000000000000d007f10110df0900d8717476d007f101",
        ),
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
