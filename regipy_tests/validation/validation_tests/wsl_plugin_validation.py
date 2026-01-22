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
                    "GUID": "AppxInstallerCache",
                    "last_modified": "2024-11-26T22:25:52.048876+00:00",
                    "wsl_distribution_source_location": None,
                    "default_uid": None,
                    "distribution_name": None,
                    "default_environment": None,
                    "flags": None,
                    "kernel_command_line": None,
                    "package_family_name": None,
                    "state": None,
                    "filesystem": "Unknown",
                },
                {
                    "GUID": "{17a1ba00-e5d7-44ba-af5f-194a2677fbb6}",
                    "last_modified": "2024-11-26T23:13:35.817050+00:00",
                    "wsl_distribution_source_location": "C:\\Users\\admin\\AppData\\Local\\Packages\\TheDebianProject.DebianGNULinux_76v4gfsz19hv4\\LocalState",
                    "default_uid": 1000,
                    "distribution_name": "Debian",
                    "default_environment": [
                        "HOSTTYPE=x86_64",
                        "LANG=en_US.UTF-8",
                        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games",
                        "TERM=xterm-256color",
                    ],
                    "flags": 7,
                    "kernel_command_line": "BOOT_IMAGE=/kernel init=/init",
                    "package_family_name": "TheDebianProject.DebianGNULinux_76v4gfsz19hv4",
                    "state": "Normal",
                    "filesystem": "wslfs",
                    "enable_interop": True,
                    "append_nt_path": True,
                    "enable_drive_mounting": True,
                },
                {
                    "GUID": "{3f702114-dc8d-44dc-9903-642eb650ec4b}",
                    "last_modified": "2024-11-26T23:12:56.145376+00:00",
                    "wsl_distribution_source_location": "C:\\Users\\admin\\AppData\\Local\\Packages\\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\\LocalState",
                    "default_uid": 1000,
                    "distribution_name": "Ubuntu",
                    "default_environment": [
                        "HOSTTYPE=x86_64",
                        "LANG=en_US.UTF-8",
                        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games",
                        "TERM=xterm-256color",
                    ],
                    "flags": 7,
                    "kernel_command_line": "BOOT_IMAGE=/kernel init=/init",
                    "package_family_name": "CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc",
                    "state": "Normal",
                    "filesystem": "wslfs",
                    "enable_interop": True,
                    "append_nt_path": True,
                    "enable_drive_mounting": True,
                },
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
                },
            ],
        }
    }
