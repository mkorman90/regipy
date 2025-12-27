"""
Pending File Rename plugin - Parses pending file rename operations
"""

import logging

from regipy.exceptions import RegistryKeyNotFoundException
from regipy.hive_types import SYSTEM_HIVE_TYPE
from regipy.plugins.plugin import Plugin
from regipy.utils import convert_wintime

logger = logging.getLogger(__name__)

SESSION_MANAGER_PATH = r"Control\Session Manager"


class PendingFileRenamePlugin(Plugin):
    """
    Parses Pending File Rename Operations from SYSTEM hive

    This registry value contains files scheduled for rename/delete on reboot.
    This is commonly used by installers and can also be abused by malware.

    Registry Key: Control\\Session Manager
    Values:
    - PendingFileRenameOperations
    - PendingFileRenameOperations2

    Format: Source path, destination path (or empty for delete), repeating
    """

    NAME = "pending_file_rename"
    DESCRIPTION = "Parses pending file rename operations"
    COMPATIBLE_HIVE = SYSTEM_HIVE_TYPE

    def run(self):
        logger.debug("Started Pending File Rename Plugin...")

        for controlset_path in self.registry_hive.get_control_sets(SESSION_MANAGER_PATH):
            try:
                sm_key = self.registry_hive.get_key(controlset_path)
            except RegistryKeyNotFoundException:
                logger.debug(f"Could not find Session Manager at: {controlset_path}")
                continue

            entry = {
                "key_path": controlset_path,
                "last_write": convert_wintime(sm_key.header.last_modified, as_json=self.as_json),
                "operations": [],
            }

            for value in sm_key.iter_values():
                if value.name in ["PendingFileRenameOperations", "PendingFileRenameOperations2"]:
                    operations = self._parse_operations(value.value, value.name)
                    entry["operations"].extend(operations)

            if entry["operations"]:
                self.entries.append(entry)

    def _parse_operations(self, data, value_name: str) -> list:
        """Parse pending file rename operations"""
        operations = []

        if not data:
            return operations

        # Data is REG_MULTI_SZ - list of strings
        if isinstance(data, list):
            items = data
        elif isinstance(data, str):
            items = [data]
        else:
            return operations

        # Operations come in pairs: source, destination (or empty for delete)
        i = 0
        while i < len(items):
            source = items[i] if i < len(items) else None
            destination = items[i + 1] if i + 1 < len(items) else None

            if source:
                # Remove NT path prefix if present
                if source.startswith("\\??\\"):
                    source = source[4:]

                op = {
                    "source": source,
                    "value_name": value_name,
                }

                if destination:
                    if destination.startswith("\\??\\"):
                        destination = destination[4:]
                    op["destination"] = destination
                    op["operation"] = "rename"
                else:
                    op["operation"] = "delete"

                operations.append(op)

            i += 2

        return operations
