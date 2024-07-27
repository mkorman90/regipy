from regipy.plugins.ntuser.word_wheel_query import WordWheelQueryPlugin
from regipy_tests.validation.validation import ValidationCase


class NTUserUserAssistValidationCase(ValidationCase):
    plugin = WordWheelQueryPlugin
    test_hive_file_name = "NTUSER.DAT.xz"

    expected_entries = [
       {
        "last_write": "2012-04-04T15:45:18.551340+00:00",
        "mru_id": 1,
        "name": "alloy",
        "order": 0,
        }
    ]
    expected_entries_count = 6
