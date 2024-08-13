from regipy.plugins.system.active_controlset import ActiveControlSetPlugin
from regipy_tests.validation.validation import ValidationCase


class ActiveControlSetPluginValidationCase(ValidationCase):
    plugin = ActiveControlSetPlugin
    test_hive_file_name = "SYSTEM_WIN_10_1709.xz"

    exact_expected_result = [
        {
            "name": "Current",
            "value": 1,
            "value_type": "REG_DWORD",
            "is_corrupted": False,
        },
        {
            "name": "Default",
            "value": 1,
            "value_type": "REG_DWORD",
            "is_corrupted": False,
        },
        {
            "name": "Failed",
            "value": 0,
            "value_type": "REG_DWORD",
            "is_corrupted": False,
        },
        {
            "name": "LastKnownGood",
            "value": 1,
            "value_type": "REG_DWORD",
            "is_corrupted": False,
        },
    ]
