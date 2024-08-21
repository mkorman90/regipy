
from regipy.plugins.system.backuprestore import BackupRestorePlugin
from regipy_tests.validation.validation import ValidationCase


class BackupRestorePluginValidationCase(ValidationCase):
    plugin = BackupRestorePlugin
    test_hive_file_name = "SYSTEM.xz"
    exact_expected_result = None

            