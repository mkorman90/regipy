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
        # UTF-16-LE "Eastern Standard Time" followed by garbage bytes, converted to hex
        "TimeZoneKeyName": "4500610073007400650072006e0020005300740061006e0064006100720064002000540069006d00650000001963747614060136f408f10100000000000000000000000000000000940af101a80af10102000000040bf101000000007c0bf10100000000c80bf1010000000000000000d007f10110df0900d8717476d007f1010000000084e00900fb9373760200000000000000e98b73761406013610000000002000000200000000000000010000000000000000000000f4df090010a6f101000000000000000013000000304514001406013641919676a80af1012f000000d007f1010000000000000000020000000e0000001051140000000e00a0511400",
        "DynamicDaylightTimeDisabled": 0,
        "ActiveTimeBias": 240,
    }


class TimezoneDataPlugin2ValidationCase(ValidationCase):
    plugin = TimezoneDataPlugin2
    test_hive_file_name = "SYSTEM.xz"
    custom_test = test_tz2_plugin_output
    expected_entries_count = 2
