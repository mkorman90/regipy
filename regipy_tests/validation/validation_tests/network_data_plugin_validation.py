from regipy.plugins.system.network_data import NetworkDataPlugin
from regipy_tests.validation.validation import ValidationCase


class NetworkDataPluginValidationCase(ValidationCase):
    plugin = NetworkDataPlugin
    test_hive_file_name = "SYSTEM.xz"
    exact_expected_result = {
        "\\ControlSet001\\Services\\Tcpip\\Parameters\\Interfaces": {
            "timestamp": "2011-09-17T13:43:23.770078+00:00",
            "interfaces": [
                {
                    "interface_name": "{698E50A9-4F58-4D86-B61D-F42E58DCACF6}",
                    "last_modified": "2011-09-17T13:43:23.770078+00:00",
                    "incomplete_data": False,
                    "dhcp_enabled": False,
                    "ip_address": ["10.3.58.5"],
                    "subnet_mask": ["255.255.255.0"],
                    "default_gateway": ["10.3.58.1"],
                    "name_server": "10.3.58.4",
                    "domain": 0,
                },
                {
                    "interface_name": "{6AAFC9A9-0542-4DB2-8760-CCFFA953737C}",
                    "last_modified": "2011-09-17T13:43:23.770078+00:00",
                    "incomplete_data": False,
                    "dhcp_enabled": False,
                    "ip_address": ["192.168.1.123"],
                    "subnet_mask": ["255.255.255.0"],
                    "default_gateway": ["192.168.1.1"],
                    "name_server": "192.168.1.112",
                    "domain": 0,
                },
                {
                    "interface_name": "{e29ac6c2-7037-11de-816d-806e6f6e6963}",
                    "last_modified": "2011-09-17T13:43:23.770078+00:00",
                    "incomplete_data": False,
                    "dhcp_enabled": False,
                    "ip_address": None,
                    "subnet_mask": None,
                    "default_gateway": None,
                    "name_server": None,
                    "domain": None,
                },
            ],
        },
        "\\ControlSet002\\Services\\Tcpip\\Parameters\\Interfaces": {
            "timestamp": "2011-09-17T13:43:23.770078+00:00",
            "interfaces": [
                {
                    "interface_name": "{698E50A9-4F58-4D86-B61D-F42E58DCACF6}",
                    "last_modified": "2011-09-17T13:43:23.770078+00:00",
                    "incomplete_data": False,
                    "dhcp_enabled": False,
                    "ip_address": ["10.3.58.5"],
                    "subnet_mask": ["255.255.255.0"],
                    "default_gateway": ["10.3.58.1"],
                    "name_server": "10.3.58.4",
                    "domain": 0,
                },
                {
                    "interface_name": "{6AAFC9A9-0542-4DB2-8760-CCFFA953737C}",
                    "last_modified": "2011-09-17T13:43:23.770078+00:00",
                    "incomplete_data": False,
                    "dhcp_enabled": False,
                    "ip_address": ["192.168.1.123"],
                    "subnet_mask": ["255.255.255.0"],
                    "default_gateway": ["192.168.1.1"],
                    "name_server": "192.168.1.112",
                    "domain": 0,
                },
                {
                    "interface_name": "{e29ac6c2-7037-11de-816d-806e6f6e6963}",
                    "last_modified": "2011-09-17T13:43:23.770078+00:00",
                    "incomplete_data": False,
                    "dhcp_enabled": False,
                    "ip_address": None,
                    "subnet_mask": None,
                    "default_gateway": None,
                    "name_server": None,
                    "domain": None,
                },
            ],
        },
    }
