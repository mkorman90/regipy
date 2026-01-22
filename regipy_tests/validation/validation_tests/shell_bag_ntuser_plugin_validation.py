import datetime as dt

from regipy.plugins.ntuser.shellbags_ntuser import ShellBagNtuserPlugin
from regipy_tests.validation.validation import ValidationCase


class ShellBagNtuserPluginValidationCase(ValidationCase):
    plugin = ShellBagNtuserPlugin
    test_hive_file_name = "NTUSER_BAGMRU.DAT.xz"

    expected_entries_count = 102
    expected_entries = [
        {
            "value": "rekall",
            "slot": "0",
            "reg_path": "\\Software\\Microsoft\\Windows\\Shell\\BagMRU\\2\\0",
            "value_name": "0",
            "node_slot": "11",
            "shell_type": "Directory",
            "path": "Search Folder\\tmp\\rekall",
            "creation_time": dt.datetime(2021, 8, 16, 9, 41, 32).isoformat(),
            "full path": None,
            "access_time": dt.datetime(2021, 8, 16, 9, 43, 22).isoformat(),
            "modification_time": dt.datetime(2021, 8, 16, 9, 41, 32).isoformat(),
            "last_write": "2021-08-16T09:44:39.333110+00:00",
            "location description": None,
            "mru_order": "0",
            "mru_order_location": 0,
            "first_interacted": None,
        }
    ]

