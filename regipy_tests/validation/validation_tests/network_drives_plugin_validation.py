
from regipy.plugins.ntuser.network_drives import NetworkDrivesPlugin
from regipy_tests.validation.validation import ValidationCase


class NetworkDrivesPluginValidationCase(ValidationCase):
    plugin = NetworkDrivesPlugin
    test_hive_file_name = "NTUSER.DAT.xz"
    exact_expected_result = [{'drive_letter': 'p', 'last_write': '2012-04-03T22:08:18.840132+00:00', 'network_path': '\\\\controller\\public'}]