
from regipy.plugins.system.usbstor import USBSTORPlugin
from regipy_tests.validation.validation import ValidationCase


class USBSTORPluginValidationCase(ValidationCase):
    plugin = USBSTORPlugin
    test_hive_file_name = "SYSTEM_WIN_10_1709.xz"
    exact_expected_result = [
        {'device_name': 'SanDisk Cruzer USB Device', 'disk_guid': '{fc416b61-6437-11ea-bd0c-a483e7c21469}', 'first_installed': '2020-03-17T14:02:38.955490+00:00', 'key_path': '\\ControlSet001\\Enum\\USBSTOR\\Disk&Ven_SanDisk&Prod_Cruzer&Rev_1.20\\200608767007B7C08A6A&0', 'last_connected': '2020-03-17T14:02:38.946628+00:00', 'last_installed': '2020-03-17T14:02:38.955490+00:00', 'last_removed': '2020-03-17T14:23:45.504690+00:00', 'last_write': '2020-03-17T14:02:38.965050+00:00', 'manufacturer': 'Ven_SanDisk', 'serial_number': '200608767007B7C08A6A&0', 'title': 'Prod_Cruzer', 'version': 'Rev_1.20'}
    ]
    
    