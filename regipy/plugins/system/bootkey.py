"""
The boot key is an encryption key that is stored in
the Windows SYSTEM registry hive.

This key is used by several Windows components to encrypt
sensitive information like the AD database,
machine account password or system certificates etc.
"""

import logging

from regipy.registry import NKRecord
from regipy.hive_types import SYSTEM_HIVE_TYPE
from regipy.plugins.plugin import Plugin
from regipy.utils import convert_wintime

logger = logging.getLogger(__name__)

LSA_KEY_PATH = r"Control\Lsa"


def _collect_bootkey(lsa_key: NKRecord) -> str:
    """
    Extracts the 128-bit scrambled boot key from four "secret"
    LSA subkeys as a 32-character hex string.
    """

    # The boot key is taken from four separate keys:
    # SYSTEM\CurrentControlSet\Control\Lsa\{JD,Skew1,GBG,Data}.
    # However, the actual data needed is stored in a hidden field of the key
    # that cannot be seen using tools like regedit.
    # Specifically, each part of the key is stored in the key's Class attribute,
    # and is stored as a Unicode string giving the hex value of that piece of the key.

    bootkey_subkeys = {
        "JD": '',
        "Skew1": '',
        "GBG": '',
        "Data": '',
    }

    for subkey in lsa_key.iter_subkeys():
        if subkey.name in bootkey_subkeys:
            bootkey_subkeys[subkey.name] = subkey.get_class_name()

    return ''.join(bootkey_subkeys.values())


# Permutation matrix for the boot key
_BOOTKEY_PBOX = [
    0x8, 0x5, 0x4, 0x2,
    0xB, 0x9, 0xD, 0x3,
    0x0, 0x6, 0x1, 0xC,
    0xE, 0xA, 0xF, 0x7,
]


def _descramble_bootkey(key: str) -> bytes:
    """
    Parses the 128-bit binary boot key from a hex string
    and reverses the bytewise scrambling transform.
    """

    binkey = bytes.fromhex(key)

    return bytes([binkey[i] for i in _BOOTKEY_PBOX])


class BootKeyPlugin(Plugin):
    """
    The boot key is an encryption key that is stored in
    the Windows SYSTEM registry hive.
    """

    NAME = "bootkey"
    DESCRIPTION = "Get the Windows boot key"
    COMPATIBLE_HIVE = SYSTEM_HIVE_TYPE

    def run(self):
        logger.info("Started BootKey Plugin...")

        for subkey_path in self.registry_hive.get_control_sets(LSA_KEY_PATH):
            lsa_key = self.registry_hive.get_key(subkey_path)

            bootkey = _descramble_bootkey(_collect_bootkey(lsa_key))

            self.entries.append(
                {
                    "key": bootkey.hex() if self.as_json else bootkey,
                    'timestamp': convert_wintime(lsa_key.header.last_modified, as_json=self.as_json)
                }
            )
