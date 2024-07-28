from regipy.plugins.amcache.amcache import AmCachePlugin
from regipy_tests.validation.validation import ValidationCase


class AmCachePluginValidationCase(ValidationCase):
    plugin = AmCachePlugin
    test_hive_file_name = "amcache.hve.xz"

    expected_entries = [
        {
            "full_path": "C:\\Windows\\system32\\TPVMMondeu.dll",
            "last_modified_timestamp_2": "2017-03-17T05:06:04.002722+00:00",
            "program_id": "75a010066bb612ca7357ce31df8e9f0300000904",
            "sha1": "056f4b9d9ec9b5dc548e1b460da889e44089d76f",
            "timestamp": "2017-08-03T11:34:02.263418+00:00",
        }
    ]
    expected_entries_count = 1367
