import logging

from regipy.hive_types import SYSTEM_HIVE_TYPE
from regipy.plugins.plugin import Plugin
from regipy.utils import convert_wintime

logger = logging.getLogger(__name__)

HOST_PARAMETERS_PATH = r'Services\Tcpip\Parameters'


class HostDomainNamePlugin(Plugin):
    NAME = 'host_domain_name'
    DESCRIPTION = 'Get the computer host and domain names'
    COMPATIBLE_HIVE = SYSTEM_HIVE_TYPE

    def run(self):
        logger.info('Started Host and Domain Name Plugin...')

        for subkey_path in self.registry_hive.get_control_sets(HOST_PARAMETERS_PATH):
            subkey = self.registry_hive.get_key(subkey_path)

            hostname = subkey.get_value('Hostname', as_json=self.as_json)
            domain = subkey.get_value('Domain', as_json=self.as_json)

            # The default key value is 0x00000000 (REG_DWORD) when
            # the Windows machine is not in an AD domain.
            if not isinstance(domain, str):
                domain = None

            self.entries.append({
                'hostname': hostname,
                'domain': domain,
                'timestamp': convert_wintime(subkey.header.last_modified, as_json=self.as_json)
            })


