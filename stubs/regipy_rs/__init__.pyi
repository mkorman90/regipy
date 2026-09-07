"""Type stubs for the regipy_rs Rust extension package.

The regipy_rs module is a compiled Rust extension (PyO3) that exposes
the registry parsing API. This stub declares the interface that
regipy.registry_rs actually uses.
"""

from typing import Any

class ParsingError(Exception):
    """Raised when hive parsing fails."""

    ...

class NKRecord:
    """Wrapper for a registry key (NK record)."""

    name: str
    header: Any
    subkey_count: int
    values_count: int
    volatile_subkeys_count: int

    def subkeys(self) -> Any: ...
    def find_subkey(self, key_name: str) -> NKRecord | None: ...
    def values(
        self, *, as_json: bool, trim_values: bool, max_len: int
    ) -> tuple[list[tuple[str, str, Any, bool, bool]], str | None]: ...
    def class_name(self) -> str: ...
    def security_info(self) -> Any: ...

class RegistryHive:
    """Rust-backed registry hive parser."""

    header: Any

    def __init__(self, path: str) -> None: ...
    def root(self) -> NKRecord: ...
    def recurse(
        self,
        *,
        start: Any,
        path_root: str | None,
        as_json: bool,
        fetch_values: bool,
        is_init: bool,
    ) -> Any: ...

__all__ = ["NKRecord", "ParsingError", "RegistryHive"]
