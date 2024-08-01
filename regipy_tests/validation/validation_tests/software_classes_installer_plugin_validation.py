
from regipy.plugins.software.classes_installer import SoftwareClassesInstallerPlugin
from regipy_tests.validation.validation import ValidationCase


class SoftwareClassesInstallerPluginValidationCase(ValidationCase):
    plugin = SoftwareClassesInstallerPlugin
    test_hive_file_name = "SOFTWARE.xz"

    expected_entries = [{'identifier': '000041091A0090400000000000F01FEC', 'is_hidden': False, 'product_name': 'Microsoft Office OneNote MUI (English) 2010', 'timestamp': '2010-11-10T10:31:06.573040+00:00'}]
    # TODO: add support to test such thing
    # assert not any([x['is_hidden'] for x in plugin_instance.entries])
