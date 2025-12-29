import logging
import struct

from regipy.exceptions import RegistryKeyNotFoundException
from regipy.hive_types import SYSTEM_HIVE_TYPE
from regipy.plugins.plugin import Plugin
from regipy.utils import convert_wintime

logger = logging.getLogger(__name__)

TZ_DATA_PATH = r"Control\TimeZoneInformation"


class TimezoneDataPlugin2(Plugin):
    NAME = "timezone_data2"
    DESCRIPTION = "Get timezone data"
    COMPATIBLE_HIVE = SYSTEM_HIVE_TYPE

    def run(self):
        self.entries = {}
        tzdata_subkeys = self.registry_hive.get_control_sets(TZ_DATA_PATH)
        for tzdata_subkey in tzdata_subkeys:
            try:
                tzdata = self.registry_hive.get_key(tzdata_subkey)
            except RegistryKeyNotFoundException as ex:
                logger.error(f"Could not find {self.NAME} subkey at {tzdata_subkey}: {ex}")
                continue
            self.entries[tzdata_subkey] = list(tzdata.iter_values(as_json=self.as_json))
            self.entries[tzdata_subkey] = {"last_write": convert_wintime(tzdata.header.last_modified).isoformat()}
            for val in tzdata.iter_values():
                if val.name in ("ActiveTimeBias", "Bias", "DaylightBias"):
                    self.entries[tzdata_subkey][val.name] = struct.unpack(">l", struct.pack(">L", val.value & 0xFFFFFFFF))[0]
                elif isinstance(val.value, bytes):
                    # Decode bytes (often UTF-16 encoded strings like TimeZoneKeyName)
                    try:
                        self.entries[tzdata_subkey][val.name] = val.value.decode("utf-16-le").rstrip("\x00")
                    except UnicodeDecodeError:
                        self.entries[tzdata_subkey][val.name] = val.value.hex()
                else:
                    self.entries[tzdata_subkey][val.name] = val.value
