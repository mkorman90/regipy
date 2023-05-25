import datetime
from regipy.exceptions import RegistryKeyNotFoundException

import logging

from regipy.hive_types import SYSTEM_HIVE_TYPE
from regipy.plugins.plugin import Plugin
from regipy.utils import convert_wintime

logger = logging.getLogger(__name__)

INTERFACES_PATH = r'Services\Tcpip\Parameters\Interfaces'

class NetworkDataPlugin(Plugin):
    NAME = 'network_data'
    DESCRIPTION = 'Get network data from many interfaces'
    COMPATIBLE_HIVE = SYSTEM_HIVE_TYPE

    def get_network_info(self, subkey, interfaces=None):
        if interfaces is None:
            interfaces = []

        for interface in subkey.iter_subkeys():
            entries = {
                "interface_name": interface.name,
                "last_modified": convert_wintime(interface.header.last_modified, as_json=self.as_json),
                "dhcp_enabled": interface.get_value("EnableDHCP") == 1,  # Boolean value
            }

            if entries["dhcp_enabled"]:
                entries.update({
                    "dhcp_server": interface.get_value("DhcpServer"),
                    "dhcp_ip_address": interface.get_value("DhcpIPAddress"),
                    "dhcp_subnet_mask": interface.get_value("DhcpSubnetMask"),
                    "dhcp_default_gateway": interface.get_value("DhcpDefaultGateway"),
                    "dhcp_name_server": interface.get_value("DhcpNameServer"),
                    "dhcp_domain": interface.get_value("DhcpDomain"),
                })

                lease_obtained_time = interface.get_value("LeaseObtainedTime")
                if lease_obtained_time is not None:
                    lease_obtained_time_str = datetime.datetime.utcfromtimestamp(lease_obtained_time).strftime("%Y-%m-%d %H:%M:%S")
                    entries["dhcp_lease_obtained_time"] = lease_obtained_time_str

                lease_terminates_time = interface.get_value("LeaseTerminatesTime")
                if lease_terminates_time is not None:
                    lease_terminates_time_str = datetime.datetime.utcfromtimestamp(lease_terminates_time).strftime("%Y-%m-%d %H:%M:%S")
                    entries["dhcp_lease_terminates_time"] = lease_terminates_time_str

            else:
                entries.update({
                    "ip_address": interface.get_value("IPAddress"),
                    "subnet_mask": interface.get_value("SubnetMask"),
                    "default_gateway": interface.get_value("DefaultGateway"),
                    "name_server": interface.get_value("NameServer"),
                    "domain": interface.get_value("Domain"),
                })

            if interface.subkey_count:
                sub_interfaces = []
                self.get_network_info(self, interface, sub_interfaces)
                entries["sub_interface"] = sub_interfaces

            interfaces.append(entries)

        return interfaces
        
    def run(self):
        self.entries = {}

        for control_set_interfaces_path in self.registry_hive.get_control_sets(INTERFACES_PATH):
            try:
                subkey = self.registry_hive.get_key(control_set_interfaces_path)
            except RegistryKeyNotFoundException as ex:
                logger.error(ex)
                continue

            self.entries[control_set_interfaces_path] = {
                'timestamp': convert_wintime(subkey.header.last_modified, as_json=self.as_json)
            }
            interfaces = []
            interfaces = self.get_network_info(subkey, interfaces)
            self.entries[control_set_interfaces_path]['interfaces'] = interfaces
