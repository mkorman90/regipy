from regipy.plugins.software.installed_programs import InstalledProgramsSoftwarePlugin
from regipy_tests.validation.validation import ValidationCase


class InstalledProgramsSoftwarePluginValidationCase(ValidationCase):
    plugin = InstalledProgramsSoftwarePlugin
    test_hive_file_name = "SOFTWARE.xz"

    expected_entries_count = 67
    expected_entries = [
        {
            "registry_path": "\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
            "service_name": "AddressBook",
            "timestamp": "2009-07-14T04:41:12.758808+00:00",
        },
        {
            "service_name": "Connection Manager",
            "timestamp": "2009-07-14T04:41:12.758808+00:00",
            "registry_path": "\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
            "SystemComponent": 1,
        },
    ]
