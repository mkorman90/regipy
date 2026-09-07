"""Type stubs for the construct library (partial - only what regipy uses).

The construct library uses dynamic class creation and metaclasses that
the type checker cannot resolve. This stub declares the interface that
regipy actually uses.
"""

from io import BytesIO
from typing import Any

class Construct:
    """Base class for all construct objects."""

    def parse_stream(self, stream: BytesIO, **context: Any) -> Any: ...
    def parse(self, data: bytes, **context: Any) -> Any: ...
    def build(self, obj: Any, **context: Any) -> bytes: ...
    def build_stream(self, stream: BytesIO, obj: Any, **context: Any) -> None: ...
    def sizeof(self) -> int: ...
    def compile(self) -> Construct: ...

class Int32ul(Construct):
    """32-bit unsigned little-endian integer."""

    ...

class Int32sl(Construct):
    """32-bit signed little-endian integer."""

    ...

class Int64ul(Construct):
    """64-bit unsigned little-endian integer."""

    ...

class Int16ul(Construct):
    """16-bit unsigned little-endian integer."""

    ...

class Int8ul(Construct):
    """8-bit unsigned little-endian integer."""

    ...

class Bytes(Construct):
    """Fixed-length byte sequence."""

    def __init__(self, length: int): ...

class Struct(Construct):
    """Composite structure of sub-constructs."""

    def __init__(self, *subconstructs: Any): ...

class Const(Construct):
    """Constant value check."""

    def __init__(self, value: Any): ...

class Enum(Construct):
    """Enumeration construct."""

    def __init__(self, subconstruct: Any, **enums: Any): ...

class FlagsEnum(Construct):
    """Flags enumeration construct."""

    def __init__(self, subconstruct: Any, **flags: Any): ...

class PaddedString(Construct):
    """Fixed-width padded string."""

    def __init__(self, length: int, encoding: str): ...

class CString(Construct):
    """Null-terminated C string."""

    def __init__(self, encoding: str = "utf-8"): ...

class EnumIntegerString(Construct):
    """String that can also be parsed as an integer."""

    def __init__(self, encoding: str = "utf-8"): ...

class GreedyRange(Construct):
    """Repeat a sub-construct as many times as possible."""

    def __init__(self, subconstruct: Any): ...

class Array(Construct):
    """Fixed-length array of sub-constructs."""

    def __init__(self, count: int, subconstruct: Any): ...

class StreamError(Exception):
    """Raised when a stream operation fails."""

    ...

class ConstError(Exception):
    """Raised when a constant value check fails."""

    ...

class this:
    """Placeholder for self-referential struct fields."""

    ...
