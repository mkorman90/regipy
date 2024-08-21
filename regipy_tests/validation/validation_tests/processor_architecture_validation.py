
from regipy.plugins.system.processor_architecture import ProcessorArchitecturePlugin
from regipy_tests.validation.validation import ValidationCase


class ProcessorArchitecturePluginValidationCase(ValidationCase):
    plugin = ProcessorArchitecturePlugin
    test_hive_file_name = "SYSTEM.xz"
    exact_expected_result = None

            