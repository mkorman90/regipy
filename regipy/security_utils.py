import struct

from regipy.structs import ACL, ACE, SID, Int64ub


def convert_sid(sid: SID) -> str:
    identifier_authority = Int64ub.parse(b'\x00\x00' + sid.identifier_authority)
    sub_identifier_authorities = '-'.join(str(x) for x in sid.subauthority)
    return f'S-{sid.revision}-{identifier_authority}-{sub_identifier_authorities}'


def get_acls(s):
    aces = []
    dacl = ACL.parse_stream(s)
    for _ in range(dacl.ace_count):
        parsed_ace = ACE.parse_stream(s)
        ace_sid = SID.parse(parsed_ace.sid)

        aces.append({
            'ace_type': str(parsed_ace.type),
            'flags': dict(parsed_ace.flags),
            'access_mask': dict(parsed_ace.access_mask),
            'sid': convert_sid(ace_sid)
        })
    return aces