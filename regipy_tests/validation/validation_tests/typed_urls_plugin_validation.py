
from regipy.plugins.ntuser.typed_urls import TypedUrlsPlugin
from regipy_tests.validation.validation import ValidationCase


class TypedUrlsPluginValidationCase(ValidationCase):
    plugin = TypedUrlsPlugin
    test_hive_file_name = "NTUSER.DAT.xz"

    exact_expected_result = {'last_write': '2012-04-03T22:37:55.411500+00:00', 'entries': [{'url1': 'http://199.73.28.114:53/'}, {'url2': 'http://go.microsoft.com/fwlink/?LinkId=69157'}]}
