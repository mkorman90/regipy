import logbook

from regipy.hive_types import SOFTWARE_HIVE_TYPE
from regipy.plugins.plugin import Plugin
from regipy.utils import get_subkey_values_from_list

logger = logbook.Logger(__name__)

PERSISTENCE_ENTRIES = [
    r'\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
    r'\Microsoft\Windows\CurrentVersion\Run',
    r'\Microsoft\Windows\CurrentVersion\RunOnce',
    r'\Microsoft\Windows\CurrentVersion\RunOnce\Setup',
    r'\Microsoft\Windows\CurrentVersion\RunOnceEx',
    r'\Wow6432Node\Microsoft\Windows\CurrentVersion\Run',
    r'\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
    r'\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce\Setup',
    r'\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx',
    r'\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
    r'\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify'
]


class SoftwarePersistencePlugin(Plugin):
    NAME = 'software_plugin'
    DESCRIPTION = 'Retrieve values from known persistence subkeys in Software hive'
    COMPATIBLE_HIVE = SOFTWARE_HIVE_TYPE

    def run(self):
        self.entries = get_subkey_values_from_list(self.registry_hive, PERSISTENCE_ENTRIES, as_json=self.as_json)
