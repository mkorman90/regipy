from regipy.plugins.security.domain_sid import DomainSidPlugin
from regipy_tests.validation.validation import ValidationCase


class DomainSidPluginValidationCase(ValidationCase):
    plugin = DomainSidPlugin
    test_hive_file_name = "SECURITY.xz"
    exact_expected_result = [
        {
            "domain_name": "WORKGROUP",
            "domain_sid": None,
            "machine_sid": None,
            "timestamp": "2021-08-05T10:43:08.911000+00:00",
        }
    ]
