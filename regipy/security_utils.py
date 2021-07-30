from regipy.structs import  ACL, ACE, SID

def convert_sid(sid) -> str:
    parsed_sid = f'S-{sid.revision}-{sid.identifier_authority[-1]}-'
    if sub_auth := '-'.join([str(s) for s in sid.identifier_authority[:-1] if s]):
        parsed_sid += sub_auth
    parsed_sid += str(sid.subauthority[0])
    return parsed_sid

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