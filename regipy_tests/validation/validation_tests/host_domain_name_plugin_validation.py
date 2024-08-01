
from regipy.plugins.system.host_domain_name import HostDomainNamePlugin
from regipy_tests.validation.validation import ValidationCase


class HostDomainNamePluginValidationCase(ValidationCase):
    plugin = HostDomainNamePlugin
    test_hive_file_name = "SYSTEM.xz"
    exact_expected_result = [{'hostname': 'WKS-WIN732BITA', 'domain': 'shieldbase.local', 'timestamp': '2011-09-17T13:43:23.770078+00:00'}, {'hostname': 'WKS-WIN732BITA', 'domain': 'shieldbase.local', 'timestamp': '2011-09-17T13:43:23.770078+00:00'}]
    expected_entries_count = 2