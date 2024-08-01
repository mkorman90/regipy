
from regipy.plugins.software.last_logon import LastLogonPlugin
from regipy_tests.validation.validation import ValidationCase


class LastLogonPluginValidationCase(ValidationCase):
    plugin = LastLogonPlugin
    test_hive_file_name = "SOFTWARE.xz"

    exact_expected_result = {'last_logged_on_provider': '{6F45DC1E-5384-457A-BC13-2CD81B0D28ED}', 'last_logged_on_sam_user': 'SHIELDBASE\\rsydow', 'last_logged_on_user': 'SHIELDBASE\\rsydow', 'last_write': '2012-04-04T12:20:41.453654+00:00', 'show_tablet_keyboard': 0}
    
    expected_entries_count = 5