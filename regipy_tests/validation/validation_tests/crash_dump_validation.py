from regipy.plugins.system.crash_dump import CrashDumpPlugin
from regipy_tests.validation.validation import ValidationCase


class CrashDumpPluginValidationCase(ValidationCase):
    plugin = CrashDumpPlugin
    test_hive_file_name = "SYSTEM.xz"
    exact_expected_result = {
        "\\ControlSet001\\Control\\CrashControl": {
            "last_write": "2012-04-04T11:47:36.984376+00:00",
            "CrashDumpEnabled": 2,
            "CrashDumpEnabledStr": "Kernel memory dump",
            "LogEvent": 1,
            "DumpFile": "%SystemRoot%\\MEMORY.DMP",
            "MinidumpDir": "%SystemRoot%\\Minidump",
        },
        "\\ControlSet002\\Control\\CrashControl": {
            "last_write": "2012-04-04T11:47:36.984376+00:00",
            "CrashDumpEnabled": 2,
            "CrashDumpEnabledStr": "Kernel memory dump",
            "LogEvent": 1,
            "DumpFile": "%SystemRoot%\\MEMORY.DMP",
            "MinidumpDir": "%SystemRoot%\\Minidump",
        },
    }
