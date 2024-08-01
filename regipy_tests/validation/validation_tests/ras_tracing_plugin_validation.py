from regipy.plugins.software.tracing import RASTracingPlugin
from regipy_tests.validation.validation import ValidationCase


class RASTracingPluginValidationCase(ValidationCase):
    plugin = RASTracingPlugin
    test_hive_file_name = "SOFTWARE.xz"

    expected_entries = [
        {
            "key": "\\Microsoft\\Tracing",
            "name": "AcroRd32_RASAPI32",
            "timestamp": "2012-03-16T21:31:26.613878+00:00",
        },
        {
            "key": "\\Microsoft\\Tracing",
            "name": "wmplayer_RASMANCS",
            "timestamp": "2012-03-12T20:58:55.476336+00:00",
        },
    ]
    expected_entries_count = 70
