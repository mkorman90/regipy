from regipy.plugins.system.previous_winver import PreviousWinVersionPlugin
from regipy_tests.validation.validation import ValidationCase


class PreviousWinVersionPluginValidationCase(ValidationCase):
    plugin = PreviousWinVersionPlugin
    test_hive_file_name = "SYSTEM_WIN_10_1709.xz"
    exact_expected_result = [
        {
            "key": "\\Setup\\Source OS (Updated on 1/6/2019 02:18:37)",
            "update_date": "2019-01-06 02:18:37",
            "BuildLab": "15063.rs2_release.170317-1834",
            "BuildLabEx": "15063.0.amd64fre.rs2_release.170317-1834",
            "CompositionEditionID": "Professional",
            "CurrentBuild": "15063",
            "CurrentBuildNumber": "15063",
            "CurrentVersion": "6.3",
            "EditionID": "Professional",
            "InstallationType": "Client",
            "InstallDate": "2017-07-12 07:18:28",
            "ProductId": "00330-80111-62153-AA362",
            "ProductName": "Windows 10 Pro",
            "RegisteredOrganization": 0,
            "RegisteredOwner": "Windows User",
        },
        {
            "key": "\\Setup\\Source OS (Updated on 5/16/2019 00:55:20)",
            "update_date": "2019-05-16 00:55:20",
            "BuildLab": "17134.rs4_release.180410-1804",
            "BuildLabEx": "17134.1.amd64fre.rs4_release.180410-1804",
            "CompositionEditionID": "Enterprise",
            "CurrentBuild": "17134",
            "CurrentBuildNumber": "17134",
            "CurrentVersion": "6.3",
            "EditionID": "Professional",
            "InstallationType": "Client",
            "InstallDate": "2019-01-27 10:39:32",
            "ProductId": "00330-80111-62153-AA442",
            "ProductName": "Windows 10 Pro",
            "RegisteredOrganization": 0,
            "RegisteredOwner": "Windows User",
        },
    ]
