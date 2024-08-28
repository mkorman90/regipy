from regipy.plugins.system.backuprestore import BackupRestorePlugin
from regipy_tests.validation.validation import ValidationCase


def test_backup_restore_plugin_output(c: ValidationCase):
    assert c.plugin_output.keys() == {
        "\\ControlSet002\\Control\\BackupRestore\\FilesNotToBackup",
        "\\ControlSet002\\Control\\BackupRestore\\KeysNotToRestore",
        "\\ControlSet001\\Control\\BackupRestore\\KeysNotToRestore",
        "\\ControlSet002\\Control\\BackupRestore\\FilesNotToSnapshot",
        "\\ControlSet001\\Control\\BackupRestore\\FilesNotToSnapshot",
        "\\ControlSet001\\Control\\BackupRestore\\FilesNotToBackup",
    }

    assert set(
        c.plugin_output[
            "\\ControlSet001\\Control\\BackupRestore\\FilesNotToBackup"
        ].keys()
    ) == {
        "BITS_metadata",
        "Temporary Files",
        "last_write",
        "MS Distributed Transaction Coordinator",
        "Kernel Dumps",
        "BITS_BAK",
        "Mount Manager",
        "WER",
        "VSS Service DB",
        "Memory Page File",
        "FVE_Log",
        "Power Management",
        "WUA",
        "FVE_Wipe",
        "Internet Explorer",
        "BITS_LOG",
        "FVE_Control",
        "Netlogon",
        "Offline Files Cache",
        "ETW",
        "VSS Service Alternate DB",
        "VSS Default Provider",
        "RAC",
    }


class BackupRestorePluginValidationCase(ValidationCase):
    plugin = BackupRestorePlugin
    test_hive_file_name = "SYSTEM.xz"
    custom_test = test_backup_restore_plugin_output
    expected_entries_count = 6
