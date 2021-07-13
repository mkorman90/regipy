import logging

from regipy import RegistryKeyNotFoundException, convert_wintime
from regipy.hive_types import SOFTWARE_HIVE_TYPE
from regipy.plugins.plugin import Plugin

logger = logging.getLogger(__name__)

UAC_KEY_PATH = r'\Microsoft\Windows\CurrentVersion\Policies\System'


class UACStatusPlugin(Plugin):
    NAME = 'uac_plugin'
    DESCRIPTION = 'Get the status of User Access Control'
    COMPATIBLE_HIVE = SOFTWARE_HIVE_TYPE

    def run(self):
        """
        This plugin checks the following parameters:
        EnableLUA - Windows notifies the user when programs try to make changes to the computer
        EnableVirtualization - enables the redirection of legacy application File and Registry writes
                               that would normally fail as standard user to a user-writable data location.
        FilterAdministratorToken - If enabled approval is required when performing administrative tasks.
        ConsentPromptBehaviorAdmin - This option allows the Consent Admin to perform an
                                     operation that requires elevation without consent or credentials.
        ConsentPromptBehaviorUser - If enabled,  a standard user that needs to perform an operation that requires
                                    elevation of privilege will be prompted for an administrative user name and password
        """
        try:
            subkey = self.registry_hive.get_key(UAC_KEY_PATH)
        except RegistryKeyNotFoundException as ex:
            logger.error(f'Could not find {self.NAME} subkey at {UAC_KEY_PATH}: {ex}')
            return None

        self.entries = {
            'last_write': convert_wintime(subkey.header.last_modified, as_json=self.as_json),
            'enable_limited_user_accounts': subkey.get_value('EnableLUA', as_json=self.as_json),
            'enable_virtualization': subkey.get_value('EnableVirtualization', as_json=self.as_json),
            'filter_admin_token': subkey.get_value('FilterAdministratorToken', as_json=self.as_json),
            'consent_prompt_admin': subkey.get_value('ConsentPromptBehaviorAdmin', as_json=self.as_json),
            'consent_prompt_user': subkey.get_value('ConsentPromptBehaviorUser', as_json=self.as_json)
        }


