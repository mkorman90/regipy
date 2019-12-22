import logbook

import attr
from regipy.exceptions import RegistryKeyNotFoundException, NoRegistryValuesException
from regipy.hive_types import SYSTEM_HIVE_TYPE
from regipy.plugins.plugin import Plugin
from regipy.utils import convert_wintime

logger = logbook.Logger(__name__)

SERVICES_PATH = r'Services'


class ServicesPlugin(Plugin):
    NAME = 'services'
    DESCRIPTION = 'Enumerate the services in the SYSTEM hive'
    COMPATIBLE_HIVE = SYSTEM_HIVE_TYPE

    def run(self):
        self.entries = {}
        logger.info('Started Services enumeration Plugin...')
        for control_set_services_path in self.registry_hive.get_control_sets(SERVICES_PATH):
            try:
                subkey = self.registry_hive.get_key(control_set_services_path)
            except RegistryKeyNotFoundException as ex:
                logger.error(ex)
                continue
            self.entries[control_set_services_path] = {
                'timestamp': convert_wintime(subkey.header.last_modified, as_json=self.as_json)        
            }
            services = []
            for service in subkey.iter_subkeys():
                values = None
                if service.values_count > 0:
                    values = [attr.asdict(x) for x in service.iter_values(as_json=True)]
                entry = {
                    'name': service.name,
                    'last_modified': convert_wintime(service.header.last_modified, as_json=self.as_json),
                    'values': values,
                    'parameters': [attr.asdict(x) for x in self.registry_hive.recurse_subkeys(nk_record=service, path=r'{}\{}'.format(
                        control_set_services_path, service.name), as_json=True)] if service.subkey_count else None
                }
                services.append(entry)
            self.entries[control_set_services_path]['services'] = services

