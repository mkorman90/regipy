
from regipy.plugins.sam.local_sid import LocalSidPlugin
from regipy_tests.validation.validation import ValidationCase


class LocalSidPluginValidationCase(ValidationCase):
    plugin = LocalSidPlugin
    test_hive_file_name = "sam_hive.xz"

    exact_expected_result = [{'machine_sid': 'S-1-5-21-1760460187-1592185332-161725925', 'timestamp': '2014-09-24T03:36:43.549302+00:00'}]
