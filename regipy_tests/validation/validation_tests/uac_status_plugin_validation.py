
from regipy.plugins.software.uac import UACStatusPlugin
from regipy_tests.validation.validation import ValidationCase


class UACStatusPluginValidationCase(ValidationCase):
    plugin = UACStatusPlugin
    test_hive_file_name = "SOFTWARE.xz"

    exact_expected_result = {'consent_prompt_admin': 5, 'consent_prompt_user': 3, 'enable_limited_user_accounts': 1, 'enable_virtualization': 1, 'filter_admin_token': 0, 'last_write': '2011-08-30T18:47:10.734144+00:00'}
    