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

import os

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


def _recurse_subkeys_rust(
    registry_hive,
    nk_record=None,
    path_root=None,
    as_json: bool = False,
    is_init: bool = True,
    fetch_values: bool = True,
):
    """Wrap regipy_rs.RegistryHive.recurse_subkeys output in regipy's
    Subkey/Value dataclasses. The Rust side has already produced the exact
    output shape; this wrapper only does:
        1. Subkey(**dict) instantiation per row
        2. Value dataclass wrapping (only when as_json=False)
        3. convert_wintime for FILETIME values (only when as_json=False,
           because pytz-aware datetime can't be produced in Rust)
    """
    from regipy.registry import Subkey, Value
    from regipy.utils import convert_wintime

    rust_hive: regipy_rs.RegistryHive = registry_hive._rust_hive
    partial = registry_hive.partial_hive_path

    if as_json:
        # Rust emits the exact final shape (ISO timestamps, value dicts).
        # Just wrap each entry in the Subkey dataclass.
        for d in rust_hive.recurse_subkeys(fetch_values=fetch_values, as_json=True, partial_hive_path=partial):
            yield Subkey(**d)
        return

    # Non-as_json branch: convert Rust int timestamps to datetime, wrap
    # value dicts in the Value dataclass.
    for d in rust_hive.recurse_subkeys(fetch_values=fetch_values, as_json=False, partial_hive_path=partial):
        d["timestamp"] = convert_wintime(d["timestamp"], as_json=False)
        if d["values"]:
            new_values = []
            for vd in d["values"]:
                val = vd["value"]
                vt = vd["value_type"]
                if vt == "REG_FILETIME" and isinstance(val, int):
                    val = convert_wintime(val, as_json=False)
                new_values.append(Value(
                    name=vd["name"],
                    value=val,
                    value_type=vt,
                    is_corrupted=vd["is_corrupted"],
                ))
            d["values"] = new_values
        yield Subkey(**d)


def _build_nk_at_offset(registry_hive, nk_offset: int):
    """Construct a Python NKRecord at a given file-absolute offset of the
    'nk' signature. Reuses the existing construct-based NKRecord parser so
    `header` retains the same construct Container shape that tests assert on.
    Attaches `_rust_offset` and `_rust_hive_obj` so subsequent iter_values /
    iter_subkeys / get_subkey calls on this NK go through Rust too.
    """
    from regipy.registry import Cell, NKRecord

    stream = registry_hive._stream
    stream.seek(nk_offset - 4)
    raw = stream.read(4)
    cell_size = abs(int.from_bytes(raw, byteorder="little", signed=True))
    cell = Cell(cell_type="nk", offset=nk_offset + 2, size=cell_size)
    nk = NKRecord(cell=cell, stream=stream)
    # Tag with Rust offset for the patched per-NK methods.
    nk._rust_offset = nk_offset
    nk._rust_hive_obj = registry_hive._rust_hive
    nk._rust_registry_hive = registry_hive
    return nk


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
_ORIGINAL_NK_ITER_SUBKEYS = None
_ORIGINAL_NK_GET_SUBKEY = None
_PATCHED = False


def install():
    """Activate the Rust backend by monkey-patching regipy.registry."""
    global _ORIGINAL_GET_KEY, _ORIGINAL_RECURSE, _ORIGINAL_ITER_VALUES, _ORIGINAL_INIT
    global _ORIGINAL_NK_ITER_SUBKEYS, _ORIGINAL_NK_GET_SUBKEY, _PATCHED
    if _PATCHED or not _RUST_AVAILABLE:
        return

    from regipy.registry import NKRecord, RegistryHive, Value
    from regipy.utils import convert_wintime, MAX_LEN

    _ORIGINAL_INIT = RegistryHive.__init__
    _ORIGINAL_RECURSE = RegistryHive.recurse_subkeys
    _ORIGINAL_GET_KEY = RegistryHive.get_key
    _ORIGINAL_ITER_VALUES = NKRecord.iter_values
    _ORIGINAL_NK_ITER_SUBKEYS = NKRecord.iter_subkeys
    _ORIGINAL_NK_GET_SUBKEY = NKRecord.get_subkey

    def patched_init(self, hive_path, hive_type=None, partial_hive_path=None):
        _ORIGINAL_INIT(self, hive_path, hive_type=hive_type, partial_hive_path=partial_hive_path)
        try:
            self._rust_hive = regipy_rs.RegistryHive(hive_path)
        except Exception:
            self._rust_hive = None
        # Tag the root NK so plugins iterating from root get Rust speedup.
        try:
            if self._rust_hive is not None:
                self.root._rust_offset = self._rust_hive.root.nk_offset
                self.root._rust_hive_obj = self._rust_hive
                self.root._rust_registry_hive = self
        except Exception:
            pass

    def patched_recurse(
        self,
        nk_record=None,
        path_root=None,
        as_json=False,
        is_init=True,
        fetch_values=True,
    ):
        if getattr(self, "_rust_hive", None) is None or nk_record is not None or path_root is not None:
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
            return _ORIGINAL_GET_KEY(self, key_path)

    def patched_iter_values(self, as_json=False, max_len=MAX_LEN, trim_values=True):
        rust_offset = getattr(self, "_rust_offset", None)
        rust_hive = getattr(self, "_rust_hive_obj", None)
        if rust_offset is None or rust_hive is None or not trim_values:
            # Fall back to original when not Rust-tagged or when caller wants
            # untrimmed bytes (Rust always emits trimmed/hex-shaped form).
            yield from _ORIGINAL_ITER_VALUES(self, as_json=as_json, max_len=max_len, trim_values=trim_values)
            return
        try:
            value_dicts = rust_hive.iter_values_at(rust_offset, as_json)
        except Exception:
            yield from _ORIGINAL_ITER_VALUES(self, as_json=as_json, max_len=max_len, trim_values=trim_values)
            return
        for vd in value_dicts:
            val = vd["value"]
            vt = vd["value_type"]
            # Non-as_json FILETIME → datetime via pytz
            if not as_json and vt == "REG_FILETIME" and isinstance(val, int):
                val = convert_wintime(val, as_json=False)
            yield Value(name=vd["name"], value=val, value_type=vt, is_corrupted=vd["is_corrupted"])

    def patched_nk_iter_subkeys(self):
        rust_offset = getattr(self, "_rust_offset", None)
        rust_hive = getattr(self, "_rust_hive_obj", None)
        registry_hive = getattr(self, "_rust_registry_hive", None)
        if rust_offset is None or rust_hive is None or registry_hive is None:
            return _ORIGINAL_NK_ITER_SUBKEYS(self)
        try:
            pairs = rust_hive.iter_subkeys_at(rust_offset)
        except Exception:
            return _ORIGINAL_NK_ITER_SUBKEYS(self)
        return _yield_subkeys_from_pairs(registry_hive, pairs)

    def patched_nk_get_subkey(self, key_name, raise_on_missing=True):
        from regipy.exceptions import NoRegistrySubkeysException
        rust_offset = getattr(self, "_rust_offset", None)
        rust_hive = getattr(self, "_rust_hive_obj", None)
        registry_hive = getattr(self, "_rust_registry_hive", None)
        if rust_offset is None or rust_hive is None or registry_hive is None:
            return _ORIGINAL_NK_GET_SUBKEY(self, key_name, raise_on_missing=raise_on_missing)
        if not self.subkey_count and raise_on_missing:
            raise NoRegistrySubkeysException(f"No subkeys for {self.header.key_name_string}")
        try:
            res = rust_hive.get_subkey_at(rust_offset, key_name)
        except Exception:
            return _ORIGINAL_NK_GET_SUBKEY(self, key_name, raise_on_missing=raise_on_missing)
        if res is None:
            if raise_on_missing:
                raise NoRegistrySubkeysException(f"No subkey {key_name} for {self.header.key_name_string}")
            return None
        _name, off = res
        return _build_nk_at_offset(registry_hive, off)

    RegistryHive.__init__ = patched_init
    RegistryHive.recurse_subkeys = patched_recurse
    RegistryHive.get_key = patched_get_key
    # Per-NK method patches kept disabled: although they pass byte-exact
    # parity on the per-key iter_values output (verified by parity_check.py),
    # routing them through Rust at *import time* causes the existing
    # `test_system_apply_transaction_logs_2` regdiff test to compute a
    # different *count* of differences (231 vs 225) on the recovered hive.
    # The per-key iter_values output is identical between backends, but
    # `compare_hives`' set-difference loop produces a different number of
    # entries. Until we pinpoint the cause, only the bulk `recurse_subkeys`
    # and `get_key` paths are routed through Rust.
    # NKRecord.iter_values = patched_iter_values
    # NKRecord.iter_subkeys = patched_nk_iter_subkeys
    # NKRecord.get_subkey = patched_nk_get_subkey

    _PATCHED = True


def _yield_subkeys_from_pairs(registry_hive, pairs):
    """Yield NKRecord instances built at offsets from (name, offset) pairs."""
    for _name, off in pairs:
        yield _build_nk_at_offset(registry_hive, off)


def maybe_install():
    """Install the patch if env var requests it."""
    if is_enabled():
        install()
