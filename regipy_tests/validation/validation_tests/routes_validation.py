from regipy.plugins.system.routes import RoutesPlugin
from regipy_tests.validation.validation import ValidationCase


class RoutesPluginValidationCase(ValidationCase):
    plugin = RoutesPlugin
    test_hive_file_name = "SYSTEM.xz"
    exact_expected_result = {
        "\\ControlSet001\\Services\\Tcpip\\Parameters\\PersistentRoutes": {
            "timestamp": "2011-09-17T13:43:23.770078+00:00",
            "values": [
                {
                    "name": "0.0.0.0,0.0.0.0,192.168.1.1,-1",
                    "value": 0,
                    "value_type": "REG_SZ",
                    "is_corrupted": False,
                },
                {
                    "name": "0.0.0.0,0.0.0.0,10.3.58.1,-1",
                    "value": 0,
                    "value_type": "REG_SZ",
                    "is_corrupted": False,
                },
            ],
        },
        "\\ControlSet002\\Services\\Tcpip\\Parameters\\PersistentRoutes": {
            "timestamp": "2011-09-17T13:43:23.770078+00:00",
            "values": [
                {
                    "name": "0.0.0.0,0.0.0.0,192.168.1.1,-1",
                    "value": 0,
                    "value_type": "REG_SZ",
                    "is_corrupted": False,
                },
                {
                    "name": "0.0.0.0,0.0.0.0,10.3.58.1,-1",
                    "value": 0,
                    "value_type": "REG_SZ",
                    "is_corrupted": False,
                },
            ],
        },
    }
