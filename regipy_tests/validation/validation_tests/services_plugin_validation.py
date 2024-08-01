
from regipy.plugins.system.services import ServicesPlugin
from regipy_tests.validation.validation import ValidationCase


class ServicesPluginValidationCase(ValidationCase):
    plugin = ServicesPlugin
    test_hive_file_name = "corrupted_system_hive.xz"

    custom_test = self.plugin_output['\\ControlSet001\\Services']['services'][0] == {'last_modified': '2008-10-21T17:48:29.328124+00:00', 'name': 'Abiosdsk', 'parameters': [], 'values': [{'is_corrupted': False, 'name': 'ErrorControl', 'value': 0, 'value_type': 'REG_DWORD'}, {'is_corrupted': False, 'name': 'Group', 'value': 'Primary disk', 'value_type': 'REG_SZ'}, {'is_corrupted': False, 'name': 'Start', 'value': 4, 'value_type': 'REG_DWORD'}, {'is_corrupted': False, 'name': 'Tag', 'value': 3, 'value_type': 'REG_DWORD'}, {'is_corrupted': False, 'name': 'Type', 'value': 1, 'value_type': 'REG_DWORD'}]}
    

    # expected_entries = [{'a':'b'}]

    # assert plugin_instance.entries['\\ControlSet001\\Services']['services'][0] == {'last_modified': '2008-10-21T17:48:29.328124+00:00', 'name': 'Abiosdsk', 'parameters': [], 'values': [{'is_corrupted': False, 'name': 'ErrorControl', 'value': 0, 'value_type': 'REG_DWORD'}, {'is_corrupted': False, 'name': 'Group', 'value': 'Primary disk', 'value_type': 'REG_SZ'}, {'is_corrupted': False, 'name': 'Start', 'value': 4, 'value_type': 'REG_DWORD'}, {'is_corrupted': False, 'name': 'Tag', 'value': 3, 'value_type': 'REG_DWORD'}, {'is_corrupted': False, 'name': 'Type', 'value': 1, 'value_type': 'REG_DWORD'}]}
    