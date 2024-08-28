from regipy.plugins.system.processor_architecture import ProcessorArchitecturePlugin
from regipy_tests.validation.validation import ValidationCase


class ProcessorArchitecturePluginValidationCase(ValidationCase):
    plugin = ProcessorArchitecturePlugin
    test_hive_file_name = "SYSTEM.xz"
    exact_expected_result = {
        "\\ControlSet001\\Control\\Session Manager\\Environment": {
            "PROCESSOR_ARCHITECTURE": "x86",
            "NUMBER_OF_PROCESSORS": 49,
            "PROCESSOR_IDENTIFIER": "x86 Family 16 Model 8 Stepping 0, AuthenticAMD",
            "PROCESSOR_REVISION": "0800",
        },
        "\\ControlSet002\\Control\\Session Manager\\Environment": {
            "PROCESSOR_ARCHITECTURE": "x86",
            "NUMBER_OF_PROCESSORS": 49,
            "PROCESSOR_IDENTIFIER": "x86 Family 16 Model 8 Stepping 0, AuthenticAMD",
            "PROCESSOR_REVISION": "0800",
        },
    }
