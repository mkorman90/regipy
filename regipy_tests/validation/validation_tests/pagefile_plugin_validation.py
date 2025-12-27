from regipy.plugins.system.pagefile import PagefilePlugin
from regipy_tests.validation.validation import ValidationCase


class PagefilePluginValidationCase(ValidationCase):
    plugin = PagefilePlugin
    test_hive_file_name = "SYSTEM.xz"

    expected_entries = [
        {
            "key_path": "\\ControlSet001\\Control\\Session Manager\\Memory Management",
            "last_write": "2012-04-04T11:47:44.093750+00:00",
            "clear_pagefile_at_shutdown": False,
            "paging_files": ["?:\\pagefile.sys"],
            "parsed_paging_files": [{"path": "?:\\pagefile.sys"}],
            "existing_page_files": ["\\??\\C:\\pagefile.sys"],
        }
    ]
    expected_entries_count = 2
