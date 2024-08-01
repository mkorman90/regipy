
from regipy.plugins.system.network_data import NetworkDataPlugin
from regipy_tests.validation.validation import ValidationCase


class NetworkDataPluginValidationCase(ValidationCase):
    plugin = NetworkDataPlugin
    test_hive_file_name = "SYSTEM.xz"
    expected_entries = [{'interface_name': '{698E50A9-4F58-4D86-B61D-F42E58DCACF6}', 'last_modified': '2011-09-17T13:43:23.770078+00:00', 'dhcp_enabled': False, 'ip_address': ['10.3.58.5'], 'subnet_mask': ['255.255.255.0'], 'default_gateway': ['10.3.58.1'], 'name_server': '10.3.58.4', 'domain': 0}]