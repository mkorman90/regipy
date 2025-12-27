"""
Pagefile plugin - Parses pagefile configuration
"""

import logging

from regipy.exceptions import RegistryKeyNotFoundException
from regipy.hive_types import SYSTEM_HIVE_TYPE
from regipy.plugins.plugin import Plugin
from regipy.utils import convert_wintime

logger = logging.getLogger(__name__)

MEMORY_MANAGEMENT_PATH = r"Control\Session Manager\Memory Management"


class PagefilePlugin(Plugin):
    """
    Parses pagefile configuration from SYSTEM hive

    Provides information about:
    - Pagefile locations
    - Pagefile sizes
    - ClearPageFileAtShutdown setting

    Registry Key: Control\\Session Manager\\Memory Management
    """

    NAME = "pagefile"
    DESCRIPTION = "Parses pagefile configuration"
    COMPATIBLE_HIVE = SYSTEM_HIVE_TYPE

    def run(self):
        logger.debug("Started Pagefile Plugin...")

        for controlset_path in self.registry_hive.get_control_sets(MEMORY_MANAGEMENT_PATH):
            try:
                mm_key = self.registry_hive.get_key(controlset_path)
            except RegistryKeyNotFoundException:
                logger.debug(f"Could not find Memory Management at: {controlset_path}")
                continue

            entry = {
                "key_path": controlset_path,
                "last_write": convert_wintime(mm_key.header.last_modified, as_json=self.as_json),
            }

            for value in mm_key.iter_values():
                name = value.name
                val = value.value

                if name == "PagingFiles":
                    # REG_MULTI_SZ containing pagefile paths and sizes
                    # Format: "C:\pagefile.sys min_size max_size"
                    if isinstance(val, list):
                        entry["paging_files"] = val
                        entry["parsed_paging_files"] = []
                        for pf in val:
                            if pf:
                                parts = pf.split()
                                pf_entry = {"path": parts[0]}
                                if len(parts) >= 2:
                                    pf_entry["min_size_mb"] = int(parts[1]) if parts[1].isdigit() else parts[1]
                                if len(parts) >= 3:
                                    pf_entry["max_size_mb"] = int(parts[2]) if parts[2].isdigit() else parts[2]
                                entry["parsed_paging_files"].append(pf_entry)
                    else:
                        entry["paging_files"] = val
                elif name == "ExistingPageFiles":
                    entry["existing_page_files"] = val
                elif name == "ClearPageFileAtShutdown":
                    entry["clear_pagefile_at_shutdown"] = val == 1
                elif name == "PagefileOnOsVolume":
                    entry["pagefile_on_os_volume"] = val
                elif name == "TempPageFile":
                    entry["temp_page_file"] = val

            if "paging_files" in entry or "existing_page_files" in entry:
                self.entries.append(entry)
