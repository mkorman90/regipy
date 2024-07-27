from regipy.plugins.system.shimcache import ShimCachePlugin
from regipy_tests.validation.validation import ValidationCase

class AmCacheValidationCase(ValidationCase):
    plugin = ShimCachePlugin
    test_hive_file_name = 'SYSTEM.xz'

    expected_entries = [
        {
        'last_mod_date': '2011-01-12T12:08:00+00:00',
        'path': '\\??\\C:\\Program Files\\McAfee\\VirusScan Enterprise\\mfeann.exe',
        'exec_flag': 'True'
    }
    ]
    expected_entries_count = 660

