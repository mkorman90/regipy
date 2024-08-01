
from regipy.plugins.system.bootkey import BootKeyPlugin
from regipy_tests.validation.validation import ValidationCase


class BootKeyPluginValidationCase(ValidationCase):
    plugin = BootKeyPlugin
    test_hive_file_name = "SYSTEM.xz"
    exact_expected_result = [{'key': 'e7f28d88f470cfed67dbcdb62ed1275b', 'timestamp': '2012-04-04T11:47:46.203124+00:00'}, {'key': 'e7f28d88f470cfed67dbcdb62ed1275b', 'timestamp': '2012-04-04T11:47:46.203124+00:00'}]