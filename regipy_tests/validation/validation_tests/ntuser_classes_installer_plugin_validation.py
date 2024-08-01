
from regipy.plugins.ntuser.classes_installer import NtuserClassesInstallerPlugin
from regipy_tests.validation.validation import ValidationCase


class NtuserClassesInstallerPluginValidationCase(ValidationCase):
    plugin = NtuserClassesInstallerPlugin
    test_hive_file_name = "NTUSER_with_winscp.DAT.xz"
    expected_entries = [{'identifier': '8A4152964845CF540BEAEBD27F7A8519', 'is_hidden': False, 'product_name': 'Microsoft Visual C++ Compiler Package for Python 2.7', 'timestamp': '2022-02-15T07:00:07.245646+00:00'}]

    expected_entries_count = 1