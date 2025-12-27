"""
AppCompatFlags plugin - Parses application compatibility flags and layers
"""

import logging

from regipy.exceptions import RegistryKeyNotFoundException
from regipy.hive_types import SOFTWARE_HIVE_TYPE
from regipy.plugins.plugin import Plugin
from regipy.utils import convert_wintime

logger = logging.getLogger(__name__)

APPCOMPAT_FLAGS_PATH = r"\Microsoft\Windows NT\CurrentVersion\AppCompatFlags"
APPCOMPAT_LAYERS_PATH = r"\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers"
APPCOMPAT_CUSTOM_PATH = r"\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom"


class AppCompatFlagsPlugin(Plugin):
    """
    Parses Application Compatibility Flags from SOFTWARE hive

    Provides information about:
    - Compatibility layers (e.g., RunAsAdmin, WinXP compatibility mode)
    - Custom compatibility shims applied to applications
    - Evidence of application execution

    Registry Keys:
    - Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags
    - Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Layers
    - Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Custom
    """

    NAME = "appcompat_flags"
    DESCRIPTION = "Parses application compatibility flags and layers"
    COMPATIBLE_HIVE = SOFTWARE_HIVE_TYPE

    def run(self):
        logger.debug("Started AppCompatFlags Plugin...")

        self._parse_layers()
        self._parse_custom()

    def _parse_layers(self):
        """Parse compatibility layers applied to applications"""
        try:
            layers_key = self.registry_hive.get_key(APPCOMPAT_LAYERS_PATH)
        except RegistryKeyNotFoundException:
            logger.debug(f"Could not find AppCompatFlags Layers at: {APPCOMPAT_LAYERS_PATH}")
            return

        entry = {
            "type": "layers",
            "key_path": APPCOMPAT_LAYERS_PATH,
            "last_write": convert_wintime(layers_key.header.last_modified, as_json=self.as_json),
            "applications": [],
        }

        for value in layers_key.iter_values():
            # Value name is the application path
            # Value data is the compatibility settings (e.g., "~ RUNASADMIN")
            app_entry = {
                "path": value.name,
                "layers": value.value,
            }

            # Parse the layers string
            if isinstance(value.value, str):
                layers = [layer.strip() for layer in value.value.split() if layer.strip() and layer.strip() != "~"]
                app_entry["parsed_layers"] = layers

            entry["applications"].append(app_entry)

        if entry["applications"]:
            self.entries.append(entry)

    def _parse_custom(self):
        """Parse custom compatibility shims"""
        try:
            custom_key = self.registry_hive.get_key(APPCOMPAT_CUSTOM_PATH)
        except RegistryKeyNotFoundException:
            logger.debug(f"Could not find AppCompatFlags Custom at: {APPCOMPAT_CUSTOM_PATH}")
            return

        for subkey in custom_key.iter_subkeys():
            # Each subkey is an application name (e.g., "program.exe")
            app_name = subkey.name
            subkey_path = f"{APPCOMPAT_CUSTOM_PATH}\\{app_name}"

            entry = {
                "type": "custom",
                "key_path": subkey_path,
                "application": app_name,
                "last_write": convert_wintime(subkey.header.last_modified, as_json=self.as_json),
                "shims": [],
            }

            for value in subkey.iter_values():
                # Value names are shim database identifiers
                entry["shims"].append(
                    {
                        "name": value.name,
                        "value": value.value,
                    }
                )

            if entry["shims"]:
                self.entries.append(entry)
