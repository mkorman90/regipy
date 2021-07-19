import logging

import attr
from regipy.exceptions import RegistryKeyNotFoundException, NoRegistryValuesException, RegistryParsingException
from regipy.hive_types import SYSTEM_HIVE_TYPE
from regipy.plugins.plugin import Plugin
from regipy.utils import convert_wintime

logger = logging.getLogger(__name__)

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
                parameters = []
                if service.values_count > 0:
                    try:
                        values = [attr.asdict(x) for x in service.iter_values(as_json=True)]
                    except RegistryParsingException as ex:
                        logger.info(f'Exception while parsing data for service {service.name}: {ex}')

                    if service.subkey_count:
                        try:
                            service_parameters_path = r'{}\{}'.format(control_set_services_path, service.name)
                            for parameter in self.registry_hive.recurse_subkeys(nk_record=service,
                                                                                path_root=service_parameters_path,
                                                                                as_json=True):
                                parameters.append(attr.asdict(parameter))
                        except RegistryParsingException as ex:
                            logger.info(f'Exception while parsing parameters for service {service.name}: {ex}')

                entry = {
                    'name': service.name,
                    'last_modified': convert_wintime(service.header.last_modified, as_json=self.as_json),
                    'values': values,
                    'parameters': parameters
                }
                services.append(entry)
            self.entries[control_set_services_path]['services'] = services
