from regipy.plugins.ntuser.typed_paths import TypedPathsPlugin
from regipy_tests.validation.validation import ValidationCase


class TypedPathsPluginValidationCase(ValidationCase):
    plugin = TypedPathsPlugin

    test_hive_file_name = "NTUSER_BAGMRU.DAT.xz"
    exact_expected_result = {
        "last_write": "2022-02-06T13:46:04.945080+00:00",
        "entries": [
            {"url1": "cmd"},
            {"url2": "C:\\Offline\\AD"},
            {"url3": "git"},
            {"url4": "powershell"},
            {"url5": "C:\\Program Files"},
            {"url6": "Network"},
            {"url7": "\\\\wsl$\\Ubuntu\\projects\\CAD316_001\\partition_p1"},
            {"url8": "\\\\wsl$\\Ubuntu\\projects"},
            {"url9": "\\\\wsl$\\Ubuntu"},
            {"url10": "C:\\Users\\tony\\Github"},
            {"url11": "C:\\Users\\tony\\Github\\velocity-client-master"},
            {"url12": "C:\\Users\\tony\\Github\\cogz"},
            {"url13": "C:\\Users\\tony\\Github\\cogz\\cogz"},
            {"url14": "Quick access"},
            {"url15": "C:\\ProgramData\\chocolatey\\lib\\yara\\tools"},
            {"url16": "C:\\Training\\MT01\\exercise"},
        ],
    }
