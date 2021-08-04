from construct import *

REGF_HEADER = Struct(
    'signature' / Const(b'regf'),
    'primary_sequence_num' / Int32ul,
    'secondary_sequence_num' / Int32ul,
    'last_modification_time' / Int64ul,
    'major_version' / Int32ul,
    'minor_version' / Int32ul,
    'file_type' / Int32ul,
    'file_format' / Int32ul,
    'root_key_offset' / Int32ul,
    'hive_bins_data_size' / Int32ul,
    'clustering_factor' / Int32ul,
    'file_name' / CString('utf-16-le'),
    'padding' * Bytes(396),
    'checksum' / Int32ul

).compile()

REGF_HEADER_SIZE = 4096

HBIN_HEADER = Struct(
    'signature' / Const(b'hbin'),
    'offset' / Int32ul,
    'size' / Int32ul,
    'unknown' * Int32ul,
    'unknown' * Int32ul,
    'timestamp' / Int64ul,
    'unknown' * Int32ul
).compile()

CM_KEY_NODE_SIZE = 76
CM_KEY_NODE = Struct(
    'flags' / FlagsEnum(Int16ul,
                        KEY_VOLATILE=0x0001,
                        KEY_HIVE_EXIT=0x0002,
                        KEY_HIVE_ENTRY=0x0004,
                        KEY_NO_DELETE=0x0008,
                        KEY_SYM_LINK=0x0010,
                        KEY_COMP_NAME=0x0020,
                        KEY_PREDEF_HANDLE=0x0040
                        ),
    'last_modified' / Int64ul,
    'access_bits' / Bytes(4),
    'parent_key_offset' / Int32ul,
    'subkey_count' / Int32ul,
    'volatile_subkey_count' / Int32ul,
    'subkeys_list_offset' / Int32ul,
    'volatile_subkeys_list_offset' / Int32ul,
    'values_count' / Int32ul,
    'values_list_offset' / Int32ul,
    'security_key_offset' / Int32ul,
    'class_name_offset' / Int32ul,
    'largest_sk_name' / Int32ul,
    'largest_sk_class_name' / Int32ul,
    'largest_value_name' / Int32ul,
    'largest_value_data' / Int32ul,
    'unknown' * Bytes(4),
    'key_name_size' / Int16ul,
    'class_name_size' / Int16ul,
    'key_name_string' / Bytes(this.key_name_size)

).compile()

SUBKEY_LIST_HEADER = Struct(
    'signature' / Bytes(2),
    'element_count' / Int16ul,
).compile()

HASH_LEAF = Struct(
    'element_count' / Int16ul,
    'elements' / Array(
        this.element_count,
        Struct(
            'key_node_offset' / Int32ul,
            'name_hash' / Int32ul,
        )
    )
).compile()

FAST_LEAF = Struct(
    'element_count' / Int16ul,
    'elements' / Array(
        this.element_count,
        Struct(
            'key_node_offset' / Int32ul,
            'name_hint' / Int32ul,
        )
    )
).compile()

LEAF_INDEX_SIGNATURE = b'li'
INDEX_LEAF = Struct(
    'element_count' / Int16ul,
    'elements' / Array(
        this.element_count,
        Struct(
            'key_node_offset' / Int32ul,
        )
    )
).compile()

INDEX_ROOT_SIGNATURE = b'ri'
INDEX_ROOT = Struct(
    'element_count' / Int16ul,
    'elements' / Array(
        this.element_count,
        Struct(
            'subkey_list_offset' / Int32ul,
        )
    )
).compile()

KEY_SECURITY = Struct(
    'reserved' * Bytes(2),
    'forward_link' / Int32ul,
    'static_link' / Int32ul,
    'reference_count' / Int32ul,
    'security_descriptor_size' / Int32ul,
    'security_descriptor' / Bytes(this.security_descriptor_size)
).compile()

VALUE_TYPE_ENUM = Enum(Int32ul,
                       REG_NONE=0,
                       REG_SZ=1,
                       REG_EXPAND_SZ=2,
                       REG_BINARY=3,
                       REG_DWORD=4,
                       REG_DWORD_BIG_ENDIAN=5,
                       REG_LINK=6,
                       REG_MULTI_SZ=7,
                       REG_RESOURCE_LIST=8,
                       REG_FULL_RESOURCE_DESCRIPTOR=9,
                       REG_RESOURCE_REQUIREMENTS_LIST=10,
                       REG_QWORD=11,
                       REG_FILETIME=16)

VALUE_KEY = Struct(
    'signature' / Const(b'vk'),
    'name_size' / Int16ul,
    'data_size' / Int32ul,
    'data_offset' / Int32ul,
    'data_type' / VALUE_TYPE_ENUM,
    'flags' / FlagsEnum(Int16ul, VALUE_COMP_NAME=0x0001),
    'padding' * Int16ul,
    'name' / Bytes(this.name_size)
).compile()

HASH_LEAF_SIGNATURE = b'lh'
FAST_LEAF_SIGNATURE = b'lf'
LF_LH_SK_ELEMENT = Struct(
    'element_count' / Int16ul,
    'elements' / Array(
        this.element_count,
        Struct(
            'key_node_offset' / Int32ul,
            'hash_value' / Int32ul
        )
    )
).compile()

DIRTY_PAGES_REFERENCES = Struct(
    'offset' / Int32ul,
    'size' / Int32ul
)

TRANSACTION_LOG = Struct(
    'signature' / Const(b'HvLE'),
    'log_size' / Int32ul,
    'flags' / Int32ul,
    'sequence_number' / Int32ul,
    'hive_bin_size' / Int32ul,
    'dirty_pages_count' / Int32ul,
    'hash_1' / Int64ul,
    'hash_2' / Int64ul,
    'dirty_pages_references' / Array(
        this.dirty_pages_count,
        DIRTY_PAGES_REFERENCES
    )
)

BIG_DATA_SIGNATURE = b'db'
BIG_DATA_BLOCK = Struct(
    'signature' / Const(BIG_DATA_SIGNATURE),
    'number_of_segments' / Int16ul,
    'offset_to_list_of_segments' / Int32ul,
)

# This is the default name of a registry subkey
DEFAULT_VALUE = '(default)'

SECURITY_KEY_v1_1 = Struct(
    'unknown' * Bytes(4),
    'signature' / Const(b'sk'),
    'unknown' * Bytes(2),
    'prev_sk_offset' / Int32ul,
    'next_sk_offset' / Int32ul,
    'reference_count' / Int32ul,
    'security_descriptor_size' / Int32ul,
    'security_descriptor' / Bytes(this.security_descriptor_size)

)

SECURITY_KEY_v1_2 = Struct(
    'signature' / Const(b'sk'),
    'unknown' * Bytes(2),
    'prev_sk_offset' / Int32ul,
    'next_sk_offset' / Int32ul,
    'reference_count' / Int32ul,
    'security_descriptor_size' / Int32ul,
    'security_descriptor' / Bytes(this.security_descriptor_size),
    'ref_count' / Int32ul,
    'sdlen' / Int32ul

)

# References:
# https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-security_descriptor
# https://docs.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-control
SECURITY_DESCRIPTOR = Struct(
    'revision' / Bytes(1),
    'sbz1' / Bytes(1),
    'control' / FlagsEnum(Int16ul,
                          SE_DACL_AUTO_INHERIT_REQ=0x0100,
                          SE_DACL_AUTO_INHERITED=0x0400,
                          SE_DACL_DEFAULTED=0x0008,
                          SE_DACL_PRESENT=0x0004,
                          SE_DACL_PROTECTED=0x1000,
                          SE_GROUP_DEFAULTED=0x0002,
                          SE_OWNER_DEFAULTED=0x0001,
                          SE_RM_CONTROL_VALID=0x4000,
                          SE_SACL_AUTO_INHERIT_REQ=0x0200,
                          SE_SACL_AUTO_INHERITED=0x0800,
                          SE_SACL_DEFAULTED=0x0008,
                          SE_SACL_PRESENT=0x0010,
                          SE_SACL_PROTECTED=0x2000,
                          SE_SELF_RELATIVE=0x8000
                          ),
    'owner' / Int32ul,
    'group' / Int32ul,
    'offset_sacl' / Int32ul,
    'offset_dacl' / Int32ul,

)

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/c6ce4275-3d90-4890-ab3a-514745e4637e
# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/f992ad60-0fe4-4b87-9fed-beb478836861
# https://flatcap.org/linux-ntfs/ntfs/attributes/security_descriptor.html
SID = Struct(
    'revision' / Int8ul,
    'sub_authority_count' / Int8ul,
    'identifier_authority' / Bytes(6),
    'subauthority' / Int32ul[this.sub_authority_count],
)

ACL = Struct(
    "revision" / Int8ul,
    "sbz1" * Int8ul,
    "acl_size" / Int16ul,
    "ace_count" / Int16ul, "sbz2" * Int16ul
).compile()

ACE = Struct(
    "type" / Enum(Int8ul,
        ACCESS_ALLOWED=0,
        ACCESS_DENIED=1,
        SYSTEM_AUDIT=2,
        SYSTEM_ALARM=3,
        ACCESS_ALLOWED_COMPOUND=4,
        ACCESS_ALLOWED_OBJECT=5,
        ACCESS_DENIED_OBJECT=6,
        SYSTEM_AUDIT_OBJECT=7,
        SYSTEM_ALARM_OBJECT=8,
        ACCESS_ALLOWED_CALLBACK=9,
        ACCESS_DENIED_CALLBACK=10,
        ACCESS_ALLOWED_CALLBACK_OBJECT=11,
        ACCESS_DENIED_CALLBACK_OBJECT=12,
        SYSTEM_ALARM_CALLBACK=14,
        SYSTEM_AUDIT_CALLBACK_OBJECT=15,
        SYSTEM_ALARM_CALLBACK_OBJECT=16
    ),
    "flags" / FlagsEnum(Int8ul,
        OBJECT_INHERIT_ACE=0x1,
        CONTAINER_INHERIT_ACE = 0x2,
        NO_PROPAGATE_INHERIT_ACE = 0x4,
        INHERIT_ONLY_ACE = 0x8
    ),
    "size" / Int16ul,
    "access_mask" / FlagsEnum(Int32ul,
        DELETE=0x00010000,
        READ_CONTROL = 0x00020000,
        WRITE_DAC = 0x00040000,
        WRITE_OWNER = 0x00080000,
        SYNCHRONIZE = 0x00100000,
        ACCESS_SYSTEM_SECURITY = 0x01000000,
        MAXIMUM_ALLOWED = 0x02000000,
        GENERIC_ALL = 0x10000000,
        GENERIC_EXECUTE = 0x20000000,
        GENERIC_WRITE = 0x40000000,
        GENERIC_READ = 0x80000000
     ),
    "sid" / Bytes(this.size - 8)
).compile()
