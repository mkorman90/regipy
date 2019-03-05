import logbook

from regipy.hive_types import NTUSER_HIVE_TYPE
from regipy.plugins.plugin import Plugin
from regipy.utils import get_subkey_values_from_list

logger = logbook.Logger(__name__)

PERSISTENCE_ENTRIES = [
    r'Software\Microsoft\Windows\CurrentVersion\Run',
    r'Software\Microsoft\Windows\CurrentVersion\RunOnce',
    r'Software\Microsoft\Windows\CurrentVersion\RunServices',
    r'Software\Microsoft\Windows\CurrentVersion\RunServicesOnce',
    r'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
    r'Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows'
    r'\CurrentVersion\Run',
    r'Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows'
    r'\CurrentVersion\RunOnce',
    r'Software\Microsoft\Windows NT\CurrentVersion\Run',
    r'Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
    r'Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run',
]


class TemplatePlugin(Plugin):
    NAME = 'template_plugin'
    DESCRIPTION = 'template_description'

    def can_run(self):
        # TODO: Choose the relevant condition - to determine if the plugin is relevant for the given hive
        return self.registry_hive.hive_type == NTUSER_HIVE_TYPE

    def run(self):
        # TODO: Return the relevant values
        return get_subkey_values_from_list(self.registry_hive, PERSISTENCE_ENTRIES, as_json=self.as_json)
