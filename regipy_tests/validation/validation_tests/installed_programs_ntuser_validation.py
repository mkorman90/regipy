from regipy.plugins.ntuser.installed_programs_ntuser import (
    InstalledProgramsNTUserPlugin,
)
from regipy_tests.validation.validation import ValidationCase


class InstalledProgramsNTUserPluginValidationCase(ValidationCase):
    plugin = InstalledProgramsNTUserPlugin
    test_hive_file_name = "NTUSER_with_winscp.DAT.xz"
    expected_entries = [
        {
            "service_name": "ZoomUMX",
            "timestamp": "2022-02-28T09:05:31.141524+00:00",
            "registry_path": "\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
            "DisplayIcon": "C:\\Users\\tony\\AppData\\Roaming\\Zoom\\bin\\Zoom.exe",
            "DisplayName": "Zoom",
            "DisplayVersion": "5.9.3 (3169)",
            "EstimatedSize": 10000,
            "HelpLink": "https://support.zoom.us/home",
            "URLInfoAbout": "https://zoom.us",
            "URLUpdateInfo": "https://zoom.us",
            "Publisher": "Zoom Video Communications, Inc.",
            "UninstallString": '"C:\\Users\\tony\\AppData\\Roaming\\Zoom\\uninstall\\Installer.exe" /uninstall',
            "InstallLocation": "C:\\Users\\tony\\AppData\\Roaming\\Zoom\\bin",
            "NoModify": 1,
            "NoRepair": 1,
        },
    ]
    expected_entries_count = 4
