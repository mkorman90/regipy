
from regipy.plugins.usrclass.shellbags_usrclass import ShellBagUsrclassPlugin
from regipy_tests.validation.validation import ValidationCase


class ShellBagUsrclassPluginValidationCase(ValidationCase):
    plugin = ShellBagUsrclassPlugin
    test_hive_file_name = "UsrClass.dat.xz"

    expected_entries_count = 29
    expected_entries = [{'value': 'Dropbox', 'slot': '9', 'reg_path': '\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU', 'value_name': '9', 'node_slot': '20', 'shell_type': 'Root Folder', 'path': 'Dropbox', 'creation_time': None, 'full path': None, 'access_time': None, 'modification_time': None, 'last_write': '2018-04-05T02:13:26.843024+00:00', 'location description': None, 'mru_order': '4-8-7-6-9-0-1-5-3-2', 'mru_order_location': 4}]