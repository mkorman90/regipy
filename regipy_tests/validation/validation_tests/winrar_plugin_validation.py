
from regipy.plugins.ntuser.winrar import WinRARPlugin
from regipy_tests.validation.validation import ValidationCase


class WinRARPluginValidationCase(ValidationCase):
    plugin = WinRARPlugin
    test_hive_file_name = "NTUSER.DAT.xz"
    exact_expected_result = [{'last_write': '2021-11-18T13:59:04.888952+00:00', 'file_path': 'C:\\Users\\tony\\Downloads\\RegistryFinder64.zip', 'operation': 'archive_opened', 'value_name': '0'}, {'last_write': '2021-11-18T13:59:04.888952+00:00', 'file_path': 'C:\\temp\\token.zip', 'operation': 'archive_opened', 'value_name': '1'}, {'last_write': '2021-11-18T13:59:50.023788+00:00', 'file_name': 'Tools.zip', 'operation': 'archive_created', 'value_name': '0'}, {'last_write': '2021-11-18T13:59:50.023788+00:00', 'file_name': 'data.zip', 'operation': 'archive_created', 'value_name': '1'}, {'last_write': '2021-11-18T14:00:44.180468+00:00', 'file_path': 'C:\\Users\\tony\\Downloads', 'operation': 'archive_extracted', 'value_name': '0'}, {'last_write': '2021-11-18T14:00:44.180468+00:00', 'file_path': 'C:\\temp', 'operation': 'archive_extracted', 'value_name': '1'}]
    