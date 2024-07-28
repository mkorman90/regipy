from regipy.plugins.system.bam import BAMPlugin
from regipy_tests.validation.validation import ValidationCase


class BamValidationCase(ValidationCase):
    plugin = BAMPlugin
    test_hive_file_name = "SYSTEM_WIN_10_1709.xz"

    expected_entries = [
        {
            "sequence_number": 9,
            "version": 1,
            "sid": "S-1-5-90-0-1",
            "executable": "\\Device\\HarddiskVolume2\\Windows\\System32\\dwm.exe",
            "timestamp": "2020-04-19T09:09:35.731816+00:00",
            "key_path": "\\ControlSet001\\Services\\bam\\state\\UserSettings\\S-1-5-90-0-1",
        }
    ]
    expected_entries_count = 55
