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
    'flags' / Bytes(2),
    'last_modified' / Int64ul,
    'access_bits' / Bytes(4),
    'parent_key_offset' / Int32ul,
    'subkey_count' / Int32ul,
    'volatile_subkey_count' / Int32ul,
    'subkeys_list_offset' / Int32ul,
    'volatile_subkeys_list_offset' / Int32ul,
    'values_count' / Int32ul,
    'values_list_offset' / Int32ul,
    'security_list_offset' / Int32ul,
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
                       REG_QWORD=11)

VALUE_KEY = Struct(
    'signature' / Const(b'vk'),
    'name_size' / Int16ul,
    'data_size' / Int32ul,
    'data_offset' / Int32ul,
    'data_type' / VALUE_TYPE_ENUM,
    'flags' / Int16ul,
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
            'named_key_offset' / Int32ul,
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
