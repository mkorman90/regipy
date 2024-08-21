
from regipy.plugins.software.image_file_execution_options import ImageFileExecutionOptions
from regipy_tests.validation.validation import ValidationCase


class ImageFileExecutionOptionsValidationCase(ValidationCase):
    plugin = ImageFileExecutionOptions
    test_hive_file_name = "software.xz"
    exact_expected_result = None

            