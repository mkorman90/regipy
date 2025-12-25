import logging
from datetime import datetime, timezone

from regipy.exceptions import RegistryKeyNotFoundException
from regipy.hive_types import SYSTEM_HIVE_TYPE
from regipy.plugins.plugin import Plugin
from regipy.utils import convert_wintime

logger = logging.getLogger(__name__)

INTERFACES_PATH = r"Services\Tcpip\Parameters\Interfaces"


class NetworkDataPlugin(Plugin):
    NAME = "network_data"
    DESCRIPTION = "Get network data from many interfaces"
    COMPATIBLE_HIVE = SYSTEM_HIVE_TYPE

    def get_network_info(self, subkey, interfaces=None):
        if interfaces is None:
            interfaces = []

        try:
            for interface in subkey.iter_subkeys():
                entries = {
                    "interface_name": interface.name,
                    "last_modified": convert_wintime(interface.header.last_modified, as_json=self.as_json),
                    "incomplete_data": False,  # New key to indicate incomplete data
                    "dhcp_enabled": interface.get_value("EnableDHCP") == 1,  # Boolean value
                }

                if entries["dhcp_enabled"]:
                    entries.update(
                        {
                            "dhcp_server": interface.get_value("DhcpServer"),
                            "dhcp_ip_address": interface.get_value("DhcpIPAddress"),
                            "dhcp_subnet_mask": interface.get_value("DhcpSubnetMask"),
                            "dhcp_default_gateway": interface.get_value("DhcpDefaultGateway"),
                            "dhcp_name_server": interface.get_value("DhcpNameServer"),
                            "dhcp_domain": interface.get_value("DhcpDomain"),
                        }
                    )

                    # Lease Obtained Time
                    lease_obtained_time = interface.get_value("LeaseObtainedTime")
                    if lease_obtained_time is not None:
                        try:
                            lease_obtained_time_str = datetime.fromtimestamp(lease_obtained_time, timezone.utc).strftime(
                                "%Y-%m-%d %H:%M:%S"
                            )
                            entries["dhcp_lease_obtained_time"] = lease_obtained_time_str
                        except (OSError, ValueError) as e:
                            logger.error(f"Error converting DHCP lease obtained time for interface {interface.name}: {e}")
                            entries["incomplete_data"] = True

                    # Lease Terminates Time
                    lease_terminates_time = interface.get_value("LeaseTerminatesTime")
                    if lease_terminates_time is not None:
                        try:
                            lease_terminates_time_str = datetime.fromtimestamp(lease_terminates_time, timezone.utc).strftime(
                                "%Y-%m-%d %H:%M:%S"
                            )
                            entries["dhcp_lease_terminates_time"] = lease_terminates_time_str
                        except (OSError, ValueError) as e:
                            logger.error(f"Error converting DHCP lease terminates time for interface {interface.name}: {e}")
                            entries["incomplete_data"] = True

                else:
                    entries.update(
                        {
                            "ip_address": interface.get_value("IPAddress"),
                            "subnet_mask": interface.get_value("SubnetMask"),
                            "default_gateway": interface.get_value("DefaultGateway"),
                            "name_server": interface.get_value("NameServer"),
                            "domain": interface.get_value("Domain"),
                        }
                    )

                try:
                    if interface.subkey_count:
                        sub_interfaces = []
                        sub_interfaces = self.get_network_info(interface, sub_interfaces)
                        entries["sub_interface"] = sub_interfaces
                except Exception as e:
                    logger.error(f"Error processing sub-interfaces for interface {interface.name}: {e}")
                    entries["incomplete_data"] = True

                interfaces.append(entries)

        except Exception as e:
            logger.error(f"Error iterating over subkeys in {subkey.path}: {e}")

        return interfaces

    def run(self):
        self.entries = {}

        for control_set_interfaces_path in self.registry_hive.get_control_sets(INTERFACES_PATH):
            try:
                subkey = self.registry_hive.get_key(control_set_interfaces_path)
            except RegistryKeyNotFoundException as ex:
                logger.error(f"Registry key not found at path {control_set_interfaces_path}: {ex}")
                continue  # Skip to the next path if the key is not found

            try:
                self.entries[control_set_interfaces_path] = {
                    "timestamp": convert_wintime(subkey.header.last_modified, as_json=self.as_json)
                }
                interfaces = []
                interfaces = self.get_network_info(subkey, interfaces)
                self.entries[control_set_interfaces_path]["interfaces"] = interfaces
            except Exception as ex:
                logger.error(f"Error processing registry key {control_set_interfaces_path}: {ex}")
                self.entries[control_set_interfaces_path]["incomplete_data"] = True
