from regipy.plugins.software.winver import WinVersionPlugin
from regipy_tests.validation.validation import ValidationCase


class WinVersionPluginValidationCase(ValidationCase):
    plugin = WinVersionPlugin
    test_hive_file_name = "SOFTWARE.xz"
    exact_expected_result = {
        "\\Microsoft\\Windows NT\\CurrentVersion": {
            "last_write": "2012-03-14T07:09:21.562500+00:00",
            "CurrentVersion": "6.1",
            "CurrentBuild": "7601",
            "InstallDate": "2010-11-10 16:28:55",
            "RegisteredOrganization": 0,
            "RegisteredOwner": "Windows User",
            "InstallationType": "Client",
            "EditionID": "Ultimate",
            "ProductName": "Windows 7 Ultimate",
            "ProductId": "00426-067-1817155-86250",
            "CurrentBuildNumber": "7601",
            "BuildLab": "7601.win7sp1_gdr.111118-2330",
            "BuildLabEx": "7601.17727.x86fre.win7sp1_gdr.111118-2330",
            "CSDVersion": "Service Pack 1",
        }
    }
