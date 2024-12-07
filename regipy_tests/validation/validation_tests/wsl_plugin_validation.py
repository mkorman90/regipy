from regipy.plugins.ntuser.wsl import WSLPlugin
from regipy_tests.validation.validation import ValidationCase


class WSLPluginValidationCase(ValidationCase):
    plugin = WSLPlugin
    test_hive_file_name = "NTUSER-WSL.DAT.xz"
    exact_expected_result = {
        "\\Software\\Microsoft\\Windows\\CurrentVersion\\Lxss": {
            "last_modified": "2024-11-26T23:13:44.535966+00:00",
            "number_of_distrib": 4,
            "default_distrib_GUID": "{e3986a51-3357-4c37-8a3e-1a83d995a3da}",
            "wsl_version": "WSL2",
            "nat_ip_address": None,
            "distributions": [
                {
                    "GUID": "{e3986a51-3357-4c37-8a3e-1a83d995a3da}",
                    "last_modified": "2024-11-26T23:06:39.553058+00:00",
                    "wsl_distribution_source_location": "C:\\Users\\admin\\AppData\\Local\\Packages\\CanonicalGroupLimited.Ubuntu20.04onWindows_79rhkp1fndgsc\\LocalState",
                    "default_uid": 0,
                    "distribution_name": "Ubuntu-20.04",
                    "default_environment": None,
                    "flags": 7,
                    "kernel_command_line": None,
                    "package_family_name": "CanonicalGroupLimited.Ubuntu20.04onWindows_79rhkp1fndgsc",
                    "state": "Normal",
                    "filesystem": "wslfs",
                    "enable_interop": True,
                    "append_nt_path": True,
                    "enable_drive_mounting": True,
                }
            ],
        }
    }