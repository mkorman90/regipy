import logbook

from regipy.hive_types import NTUSER_HIVE_TYPE
from regipy.plugins.plugin import Plugin
from regipy.utils import get_subkey_values_from_list

logger = logbook.Logger(__name__)

PERSISTENCE_ENTRIES = [
    r'\Software\Microsoft\Windows NT\CurrentVersion\Run',
    r'\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run',
    r'\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    r'\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
    r'\Software\Microsoft\Windows\CurrentVersion\Run',
    r'\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    r'\Software\Microsoft\Windows\CurrentVersion\RunOnceEx',
    r'\Software\Microsoft\Windows\CurrentVersion\RunOnce\Setup',
    r'\Software\Microsoft\Windows\CurrentVersion\RunServices',
    r'\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce',
    r'\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
    r'\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run',
    r'\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
    r'\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx',
    r'\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce\Setup',
    r'\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify',
]


class NTUserPersistencePlugin(Plugin):
    NAME = 'ntuser_persistence'
    DESCRIPTION = 'Retrieve values from known persistence subkeys in NTUSER hive'
    COMPATIBLE_HIVE = NTUSER_HIVE_TYPE

    def run(self):
        return get_subkey_values_from_list(self.registry_hive, PERSISTENCE_ENTRIES, as_json=self.as_json)
