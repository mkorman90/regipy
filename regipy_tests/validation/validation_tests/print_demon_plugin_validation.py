from regipy.plugins.software.printdemon import PrintDemonPlugin
from regipy_tests.validation.validation import ValidationCase


class PrintDemonPluginValidationCase(ValidationCase):
    plugin = PrintDemonPlugin
    test_hive_file_name = "SOFTWARE.xz"

    exact_expected_result = [
        {
            "parameters": ["9600", "n", "8", "1"],
            "port_name": "COM1:",
            "timestamp": "2010-11-10T10:35:02.448040+00:00",
        },
        {
            "parameters": ["9600", "n", "8", "1"],
            "port_name": "COM2:",
            "timestamp": "2010-11-10T10:35:02.448040+00:00",
        },
        {
            "parameters": ["9600", "n", "8", "1"],
            "port_name": "COM3:",
            "timestamp": "2010-11-10T10:35:02.448040+00:00",
        },
        {
            "parameters": ["9600", "n", "8", "1"],
            "port_name": "COM4:",
            "timestamp": "2010-11-10T10:35:02.448040+00:00",
        },
        {
            "parameters": 0,
            "port_name": "FILE:",
            "timestamp": "2010-11-10T10:35:02.448040+00:00",
        },
        {
            "parameters": 0,
            "port_name": "LPT1:",
            "timestamp": "2010-11-10T10:35:02.448040+00:00",
        },
        {
            "parameters": 0,
            "port_name": "LPT2:",
            "timestamp": "2010-11-10T10:35:02.448040+00:00",
        },
        {
            "parameters": 0,
            "port_name": "LPT3:",
            "timestamp": "2010-11-10T10:35:02.448040+00:00",
        },
        {
            "parameters": 0,
            "port_name": "XPSPort:",
            "timestamp": "2010-11-10T10:35:02.448040+00:00",
        },
        {
            "parameters": 0,
            "port_name": "Ne00:",
            "timestamp": "2010-11-10T10:35:02.448040+00:00",
        },
        {
            "parameters": 0,
            "port_name": "Ne01:",
            "timestamp": "2010-11-10T10:35:02.448040+00:00",
        },
        {
            "parameters": 0,
            "port_name": "nul:",
            "timestamp": "2010-11-10T10:35:02.448040+00:00",
        },
    ]

    expected_entries_count = 12
