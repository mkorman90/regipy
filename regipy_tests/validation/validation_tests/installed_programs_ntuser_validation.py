
from regipy.plugins.ntuser.installed_programs_ntuser import InstalledProgramsNTUserPlugin
from regipy_tests.validation.validation import ValidationCase


class InstalledProgramsNTUserPluginValidationCase(ValidationCase):
    plugin = InstalledProgramsNTUserPlugin
    test_hive_file_name = "ntuser.xz"
    exact_expected_result = None

            