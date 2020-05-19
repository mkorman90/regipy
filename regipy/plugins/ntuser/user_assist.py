import binascii
import codecs

import logbook

from construct import *

from regipy.exceptions import RegistryKeyNotFoundException
from regipy.hive_types import NTUSER_HIVE_TYPE
from regipy.plugins.plugin import Plugin
from regipy.utils import convert_wintime

logger = logbook.Logger(__name__)

USER_ASSIST_KEY_PATH = r'\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist'

# guids for the various Operating Systems
GUIDS = [
    '{75048700-EF1F-11D0-9888-006097DEACF9}',  # Windows XP GUIDs
    '{5E6AB780-7743-11CF-A12B-00AA004AE837}',
    '{75048700-EF1F-11D0-9888-006097DEACF9}',  # Windows vista
    '{5E6AB780-7743-11CF-A12B-00AA004AE837}',
    '{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}',  # Windows 7
    '{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}',
    '{FA99DFC7-6AC2-453A-A5E2-5E2AFF4507BD}',  # Windows 8
    '{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}',
    '{F2A1CB5A-E3CC-4A2E-AF9D-505A7009D442}',
    '{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}',
    '{CAA59E3C-4792-41A5-9909-6A6A8D32490E}',
    '{B267E3AD-A825-4A09-82B9-EEC22AA3B847}',
    '{A3D53349-6E61-4557-8FC7-0028EDCEEBF6}',
    '{9E04CAB2-CC14-11DF-BB8C-A2F1DED72085}'
]

GUID_TO_PATH_MAPPINGS = {
    '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}': r'%SYSTEM32%',
    '{6D809377-6AF0-444B-8957-A3773F02200E}': r'%PROGRAMFILES%',
    '{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}': r'%PROGRAMFILES(X86)%',
    '{F38BF404-1D43-42F2-9305-67DE0B28FC23}': r'%WINDIR%',
    '{0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8}': r'%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs',
    '{9E3995AB-1F9C-4F13-B827-48B24B6C7174}': r'%AppData%\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned',
    '{A77F5D77-2E2B-44C3-A6A2-ABA601054A51}': r'%AppData%\Roaming\Microsoft\Windows\Start Menu\Programs',
    '{D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27}': r'%WINDIR%\SysWOW64'
}

WHITELISTED_NAMES = ['UEME_CTLSESSION']

WIN_XP_USER_ASSIST = Struct(
    'session_id' / Int32ul,
    'run_counter' / Int32ul,
    'last_execution_timestamp' / Int64ul
)

WIN7_USER_ASSIST = Struct(
    'session_id' / Int32ul,
    'run_counter' / Int32ul,
    'focus_count' / Int32ul,
    'total_focus_time_ms' / Int32ul,
    'unknown' * Bytes(44),
    'last_execution_timestamp' / Int64ul,
    'Const' * Const(b'\x00\x00\x00\x00')
)


class UserAssistPlugin(Plugin):
    NAME = 'user_assist'
    DESCRIPTION = 'Parse User Assist artifact'
    COMPATIBLE_HIVE = NTUSER_HIVE_TYPE

    def run(self):
        for guid in GUIDS:
            try:
                subkey = self.registry_hive.get_key(r'{}\{}'.format(USER_ASSIST_KEY_PATH, guid))
                count_subkey = subkey.get_key('Count')

                if not count_subkey.values_count:
                    logger.debug('Skipping {}'.format(guid))
                    continue

                for value in count_subkey.iter_values():
                    name = codecs.decode(value.name, encoding='rot-13')

                    if name in WHITELISTED_NAMES:
                        continue

                    for k, v in GUID_TO_PATH_MAPPINGS.items():
                        if k in name:
                            name = name.replace(k, v)
                            break

                    entry = None
                    data = value.value
                    if len(data) == 72:
                        try:
                            parsed_entry = WIN7_USER_ASSIST.parse(data)
                        except ConstError as ex:
                            logger.error(f'Could not parse user assist entry named {name}: {ex}')
                            continue

                        entry = {
                            'name': name,
                            'timestamp': convert_wintime(parsed_entry.last_execution_timestamp, as_json=self.as_json),
                            'run_counter': parsed_entry.run_counter,
                            'focus_count': parsed_entry.focus_count,
                            'total_focus_time_ms': parsed_entry.total_focus_time_ms,
                            'session_id': parsed_entry.session_id
                        }

                    elif len(data) == 16:
                        try:
                            parsed_entry = WIN_XP_USER_ASSIST.parse(data)
                        except ConstError as ex:
                            logger.error(f'Could not parse user assist entry named {name}: {ex}')
                            continue

                        entry = {
                            'name': name,
                            'timestamp': convert_wintime(parsed_entry.last_execution_timestamp, as_json=self.as_json),
                            'session_id': parsed_entry.session_id,
                            'run_counter': parsed_entry.run_counter - 5
                        }

                    if entry:
                        self.entries.append(entry)
            except RegistryKeyNotFoundException:
                continue
