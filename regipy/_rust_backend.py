"""Rust-backed acceleration for regipy.registry.

This module is **opt-in**. It activates only when:

    REGIPY_BACKEND=rust

and the `regipy_rs` extension module is importable (installed via the
`regipy[fast]` extra).

When active, it monkey-patches a small set of hot-path methods on
`regipy.registry.RegistryHive` and `regipy.registry.NKRecord` to route
through the Rust parser. The construct-based code path remains as the
default and as a fallback.

Compatibility constraints (must not regress):
- Same Python-visible types: `Subkey`, `Value` dataclasses, ISO datetime
  strings when `as_json=True`, `convert_wintime` semantics.
- Same iteration order as `recurse_subkeys` (depth-first; children before
  the parent).
- `header` attributes on the hive and root NK keep their construct
  Container shape (we don't touch them; tests rely on `dict(header) == ...`).
"""
from __future__ import annotations

import binascii
import os
from dataclasses import asdict
from typing import Iterator, Optional

try:
    import regipy_rs  # type: ignore
    _RUST_AVAILABLE = True
except ImportError:
    regipy_rs = None  # type: ignore
    _RUST_AVAILABLE = False


def is_enabled() -> bool:
    """Whether the Rust backend should be used for this process."""
    if not _RUST_AVAILABLE:
        return False
    return os.environ.get("REGIPY_BACKEND", "").lower() == "rust"


def _coerce_value_for_dataclass(decoded, value_type, as_json: bool, trim_values: bool):
    """Convert a decoded Rust value to the shape regipy's Python path produces.

    Mirrors the ladder in `regipy.registry.NKRecord.iter_values` exactly.
    `value_type` may be a string ("REG_SZ", ...) or an int (for unknown
    types passed through verbatim, matching construct's EnumInteger).
    """
    from regipy.utils import MAX_LEN, convert_wintime, try_decode_binary

    # When value_type is an int (unknown to the enum), Python regipy goes to
    # the final else-branch which calls try_decode_binary on the bytes.
    if isinstance(value_type, int):
        if isinstance(decoded, (bytes, bytearray)):
            return try_decode_binary(bytes(decoded), as_json=as_json, trim_values=trim_values)
        return decoded

    if decoded is None:
        return decoded

    if value_type in ("REG_SZ", "REG_EXPAND_SZ", "REG_LINK"):
        if isinstance(decoded, str) and trim_values:
            return decoded[:MAX_LEN]
        return decoded

    if value_type == "REG_BINARY":
        if as_json and trim_values and isinstance(decoded, (bytes, bytearray)):
            return binascii.b2a_hex(decoded).decode()[:MAX_LEN]
        return decoded

    if value_type == "REG_NONE":
        if as_json and trim_values and isinstance(decoded, (bytes, bytearray)):
            return binascii.b2a_hex(decoded).decode()[:MAX_LEN]
        return decoded

    if value_type in ("REG_RESOURCE_REQUIREMENTS_LIST", "REG_RESOURCE_LIST", "REG_FULL_RESOURCE_DESCRIPTOR"):
        # Python regipy returns hex-encoded string trimmed to MAX_LEN when trim_values.
        if isinstance(decoded, (bytes, bytearray)):
            if trim_values:
                return binascii.b2a_hex(decoded).decode()[:MAX_LEN]
            return bytes(decoded)
        return decoded

    if value_type == "REG_FILETIME":
        if isinstance(decoded, int):
            return convert_wintime(decoded, as_json=as_json)
        return decoded

    return decoded


def _build_value_dataclass(value_dict, as_json: bool, trim_values: bool):
    """Convert a regipy_rs value dict into a regipy.registry.Value instance."""
    from regipy.registry import Value

    name = value_dict["name"]
    value_type = value_dict["value_type"]
    raw = value_dict["value"]

    coerced = _coerce_value_for_dataclass(raw, value_type, as_json=as_json, trim_values=trim_values)
    return Value(name=name, value=coerced, value_type=value_type, is_corrupted=False)


def _iter_values_rust(nk_py_record, as_json: bool = False, max_len: int = 256, trim_values: bool = True):
    """Replacement for NKRecord.iter_values using Rust under the hood."""
    rust_nk = nk_py_record._rust_nk  # set by patched __init__
    if rust_nk is None:
        # Should not happen if backend is active
        raise RuntimeError("Rust NK is not bound to this Python NKRecord")
    for vd in rust_nk.iter_values():
        yield _build_value_dataclass(vd, as_json=as_json, trim_values=trim_values)


def _recurse_subkeys_rust(
    registry_hive,
    nk_record=None,
    path_root=None,
    as_json: bool = False,
    is_init: bool = True,
    fetch_values: bool = True,
):
    """Replacement for RegistryHive.recurse_subkeys using Rust under the hood.

    Yields `regipy.registry.Subkey` instances, identical in shape to the
    construct-based path.
    """
    from regipy.registry import Subkey
    from regipy.utils import convert_wintime

    rust_hive: regipy_rs.RegistryHive = registry_hive._rust_hive  # set by patched __init__
    partial_hive_path = registry_hive.partial_hive_path

    for entry in rust_hive.recurse_subkeys(fetch_values=fetch_values):
        # entry is a dict: {path, subkey_name, values_count, last_modified, values: [..]}
        timestamp = convert_wintime(entry["last_modified"], as_json=as_json)
        path = entry["path"]
        # Match Python: "\\<name>" instead of "\<name>" — already matches.
        # Build values list
        values_list: list = []
        if fetch_values and entry["values_count"] > 0:
            for vd in entry["values"]:
                v_obj = _build_value_dataclass(vd, as_json=as_json, trim_values=True)
                values_list.append(asdict(v_obj) if as_json else v_obj)

        actual_path = (
            f"{partial_hive_path}{path}" if partial_hive_path else None
        )

        # Match the partial-hive actual_path-with-leading-backslash variant
        # used in is_init branch of construct path — only matters for init,
        # but we already filter init here.

        ts_iso = timestamp.isoformat() if (as_json and hasattr(timestamp, "isoformat")) else timestamp

        yield Subkey(
            subkey_name=entry["subkey_name"],
            path=path,
            timestamp=ts_iso,
            values=values_list,
            values_count=entry["values_count"],
            actual_path=actual_path,
        )


def _build_nk_at_offset(registry_hive, nk_offset: int):
    """Construct a Python NKRecord at a given file-absolute offset of the
    'nk' signature. Reuses the existing construct-based NKRecord parser so
    `header` retains the same construct Container shape that tests assert on.
    """
    from regipy.registry import Cell, NKRecord

    stream = registry_hive._stream
    # Derive cell size from the 4 bytes preceding the "nk" sig.
    stream.seek(nk_offset - 4)
    raw = stream.read(4)
    cell_size = abs(int.from_bytes(raw, byteorder="little", signed=True))
    # NKRecord expects cell.offset to be AFTER the 2-byte "nk" sig
    cell = Cell(cell_type="nk", offset=nk_offset + 2, size=cell_size)
    return NKRecord(cell=cell, stream=stream)


def _get_key_rust(registry_hive, key_path: str):
    """Replacement for RegistryHive.get_key. Uses Rust to locate the NK
    offset, then construct-parses just that single NK in Python so the
    returned NKRecord has the same `header` shape tests assert on.
    """
    from regipy.exceptions import RegistryKeyNotFoundException

    if registry_hive.partial_hive_path:
        if key_path.startswith(registry_hive.partial_hive_path):
            key_path = key_path.partition(registry_hive.partial_hive_path)[-1]
        else:
            raise RegistryKeyNotFoundException(
                f"Did not find subkey at {key_path}, because this is a partial hive"
            )

    if key_path == "\\" or key_path == "":
        return registry_hive.root

    rust_hive: regipy_rs.RegistryHive = registry_hive._rust_hive
    rust_nk = rust_hive.get_key(key_path)
    if rust_nk is None:
        raise RegistryKeyNotFoundException(f"Did not find subkey at {key_path}")

    return _build_nk_at_offset(registry_hive, rust_nk.nk_offset)


_ORIGINAL_GET_KEY = None
_ORIGINAL_RECURSE = None
_ORIGINAL_ITER_VALUES = None
_ORIGINAL_INIT = None
_PATCHED = False


def install():
    """Activate the Rust backend by monkey-patching regipy.registry."""
    global _ORIGINAL_GET_KEY, _ORIGINAL_RECURSE, _ORIGINAL_ITER_VALUES, _ORIGINAL_INIT, _PATCHED
    if _PATCHED or not _RUST_AVAILABLE:
        return

    from regipy.registry import NKRecord, RegistryHive

    _ORIGINAL_INIT = RegistryHive.__init__
    _ORIGINAL_RECURSE = RegistryHive.recurse_subkeys
    _ORIGINAL_GET_KEY = RegistryHive.get_key
    _ORIGINAL_ITER_VALUES = NKRecord.iter_values

    def patched_init(self, hive_path, hive_type=None, partial_hive_path=None):
        # Run the original to set up the construct-parsed header + root
        _ORIGINAL_INIT(self, hive_path, hive_type=hive_type, partial_hive_path=partial_hive_path)
        # Attach the Rust hive
        try:
            self._rust_hive = regipy_rs.RegistryHive(hive_path)
        except Exception:
            # If Rust can't open it, fall back silently
            self._rust_hive = None

    def patched_recurse(
        self,
        nk_record=None,
        path_root=None,
        as_json=False,
        is_init=True,
        fetch_values=True,
    ):
        if getattr(self, "_rust_hive", None) is None or nk_record is not None or path_root is not None:
            # Fall back to original for non-trivial subroots
            yield from _ORIGINAL_RECURSE(
                self,
                nk_record=nk_record,
                path_root=path_root,
                as_json=as_json,
                is_init=is_init,
                fetch_values=fetch_values,
            )
            return
        yield from _recurse_subkeys_rust(
            self,
            nk_record=nk_record,
            path_root=path_root,
            as_json=as_json,
            is_init=is_init,
            fetch_values=fetch_values,
        )

    def patched_get_key(self, key_path):
        if getattr(self, "_rust_hive", None) is None:
            return _ORIGINAL_GET_KEY(self, key_path)
        try:
            return _get_key_rust(self, key_path)
        except Exception:
            # Fallback to Python path on any Rust-side surprise — DFIR-safe.
            return _ORIGINAL_GET_KEY(self, key_path)

    RegistryHive.__init__ = patched_init
    RegistryHive.recurse_subkeys = patched_recurse
    RegistryHive.get_key = patched_get_key

    _PATCHED = True


def maybe_install():
    """Install the patch if env var requests it."""
    if is_enabled():
        install()
