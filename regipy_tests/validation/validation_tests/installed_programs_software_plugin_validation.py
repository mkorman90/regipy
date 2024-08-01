
from regipy.plugins.software.installed_programs import InstalledProgramsSoftwarePlugin
from regipy_tests.validation.validation import ValidationCase


class InstalledProgramsSoftwarePluginValidationCase(ValidationCase):
    plugin = InstalledProgramsSoftwarePlugin
    test_hive_file_name = "SOFTWARE.xz"

    expected_entries_count = 67
    expected_entries = [
        {'registry_path': '\\Microsoft\\Windows\\CurrentVersion\\Uninstall', 'service_name': 'AddressBook', 'timestamp': '2009-07-14T04:41:12.758808+00:00'},
        {'service_name': '{FE2F6A2C-196E-4210-9C04-2B1BC21F07EF}', 'timestamp': '2011-07-05T22:58:57.996094+00:00', 'registry_path': '\\Microsoft\\Windows\\CurrentVersion\\Uninstall', 'UninstallString': 'MsiExec.exe /X{FE2F6A2C-196E-4210-9C04-2B1BC21F07EF}', 'URLInfoAbout': 'http://www.vmware.com', 'DisplayName': 'VMware Tools'}
    ]