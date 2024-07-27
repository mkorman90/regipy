from regipy.plugins.ntuser.user_assist import UserAssistPlugin
from regipy_tests.validation.validation import ValidationCase


class NTUserUserAssistValidationCase(ValidationCase):
    plugin = UserAssistPlugin
    test_hive_file_name = "NTUSER.DAT.xz"

    expected_entries = [
        {
            "focus_count": 1,
            "name": "%PROGRAMFILES(X86)%\\Microsoft Office\\Office14\\EXCEL.EXE",
            "run_counter": 4,
            "session_id": 0,
            "timestamp": "2012-04-04T15:43:14.785000+00:00",
            "total_focus_time_ms": 47673,
        },
        {
            "focus_count": 9,
            "name": "Microsoft.Windows.RemoteDesktop",
            "run_counter": 8,
            "session_id": 0,
            "timestamp": "2012-04-03T22:06:58.124282+00:00",
            "total_focus_time_ms": 180000,
        },
    ]
    expected_entries_count = 62
