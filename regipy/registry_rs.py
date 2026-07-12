"""
Rust-backed RegistryHive — a drop-in replacement for regipy.registry.RegistryHive.

The heavy lifting (hive parsing, key navigation, recursive traversal, value
decoding) is done by the ``regipy_rs`` native extension (see the regipy-rs
crate). This module is a thin adapter that exposes the exact same API and
dataclasses as the pure-Python implementation, so plugins and user code work
unchanged:

    from regipy.registry_rs import RegistryHive  # instead of regipy.registry

    reg = RegistryHive("/path/to/NTUSER.DAT")
    key = reg.get_key(r"\\Software\\Microsoft\\Windows\\CurrentVersion\\Run")
    for value in key.iter_values(as_json=True):
        ...

Output parity with the Python parser is enforced by
``regipy_tests/comparison_test.py``, which compares both backends key-by-key
and value-by-value over every test hive.

Timestamps are converted in Python (``convert_wintime``) from the raw FILETIME
integers the Rust core returns, so timestamp arithmetic is bit-identical
between backends.
"""

import logging

try:
    import regipy_rs
except ImportError as ex:  # pragma: no cover
    raise ImportError("The Rust backend requires the regipy-rs package. Install it with: pip install regipy[rust]") from ex

from regipy.exceptions import (
    NoRegistrySubkeysException,
    RegistryKeyNotFoundException,
    RegistryParsingException,
    RegistryValueNotFoundException,
    UnidentifiedHiveException,
)
from regipy.hive_types import SUPPORTED_HIVE_TYPES
from regipy.registry import Subkey, Value
from regipy.structs import DEFAULT_VALUE
from regipy.utils import MAX_LEN, convert_wintime, identify_hive_type

logger = logging.getLogger(__name__)


def _make_value(raw, as_json):
    """Build a Value dataclass from a raw (name, type, value, corrupted, is_filetime) tuple."""
    name, value_type, value, is_corrupted, is_filetime = raw
    if is_filetime:
        value = convert_wintime(value, as_json=as_json)
    return Value(name=name, value_type=value_type, value=value, is_corrupted=is_corrupted)


class NKRecord:
    """
    Wrapper over the Rust NK record exposing regipy's NKRecord API.
    """

    __slots__ = ("_nk",)

    def __init__(self, rust_nk):
        self._nk = rust_nk

    @property
    def name(self):
        return self._nk.name

    @property
    def header(self):
        return self._nk.header

    @property
    def subkey_count(self):
        return self._nk.subkey_count

    @property
    def values_count(self):
        return self._nk.values_count

    @property
    def volatile_subkeys_count(self):
        return self._nk.volatile_subkeys_count

    def iter_subkeys(self):
        if not self.subkey_count:
            return
        try:
            for rust_nk in self._nk.subkeys():
                yield NKRecord(rust_nk)
        except regipy_rs.ParsingError as ex:
            raise RegistryParsingException(str(ex))

    def get_subkey(self, key_name, raise_on_missing=True):
        if not self.subkey_count and raise_on_missing:
            raise NoRegistrySubkeysException(f"No subkeys for {self.header.key_name_string}")

        try:
            found = self._nk.find_subkey(key_name)
        except regipy_rs.ParsingError as ex:
            raise RegistryParsingException(str(ex))

        if found is not None:
            return NKRecord(found)

        if raise_on_missing:
            raise NoRegistrySubkeysException(f"No subkey {key_name} for {self.header.key_name_string}")
        return None

    def iter_values(self, as_json=False, max_len=MAX_LEN, trim_values=True):
        """
        Get the values of a subkey.
        :param as_json: Whether to normalize the data as JSON or not
        :param max_len: Max length of hex-dumped values
        :param trim_values: Whether to trim values to MAX_LEN
        """
        if not self.values_count:
            return
        values, error = self._nk.values(as_json=as_json, trim_values=trim_values, max_len=max_len)
        for raw in values:
            yield _make_value(raw, as_json)
        if error is not None:
            raise RegistryParsingException(error)

    def get_value(
        self,
        value_name=DEFAULT_VALUE,
        as_json=False,
        raise_on_missing=False,
        case_sensitive=True,
    ):
        value_name = value_name if case_sensitive else value_name.lower()
        for value in self.iter_values(as_json=as_json, trim_values=False):
            v = value.name if case_sensitive else value.name.lower()
            if v == value_name:
                return value.value

        if raise_on_missing:
            raise RegistryValueNotFoundException(f"Did not find the value {value_name} on subkey {self.name}")
        return None

    def get_values(self, as_json=False, trim_values=False):
        return list(self.iter_values(as_json=as_json, trim_values=trim_values))

    def get_class_name(self) -> str:
        """
        Gets the key class name as would be returned via
        the `lpClass` argument of the `RegQueryInfoKey()` function.
        """
        return self._nk.class_name()

    def get_security_key_info(self):
        try:
            return self._nk.security_info()
        except regipy_rs.ParsingError as ex:
            raise RegistryParsingException(str(ex))

    def __repr__(self):
        return repr(self._nk)


class RegistryHive:
    CONTROL_SETS = [r"\ControlSet001", r"\ControlSet002"]

    def __init__(self, hive_path, hive_type=None, partial_hive_path=None):
        """
        Represents a registry hive, parsed by the Rust backend.
        :param hive_path: Path to the registry hive
        :param hive_type: The hive type can be specified if this is a partial hive,
                          or for some other reason regipy cannot identify the hive type
        :param partial_hive_path: The path from which the partial hive actually starts
        """
        self.partial_hive_path = None
        self.hive_type = None

        try:
            self._hive = regipy_rs.RegistryHive(str(hive_path))
        except regipy_rs.ParsingError as ex:
            raise RegistryParsingException(str(ex))

        self.header = self._hive.header
        self.root = NKRecord(self._hive.root())
        self.name = self.header.file_name

        if hive_type:
            if hive_type.lower() in SUPPORTED_HIVE_TYPES:
                self.hive_type = hive_type
            else:
                raise UnidentifiedHiveException(
                    f"{hive_type} is not a supported hive type: only the following are supported: {SUPPORTED_HIVE_TYPES}"
                )
        else:
            try:
                self.hive_type = identify_hive_type(self.name)
            except UnidentifiedHiveException:
                logger.info(f"Hive type for {hive_path} was not identified: {self.name}")

        if partial_hive_path:
            self.partial_hive_path = partial_hive_path

    def recurse_subkeys(
        self,
        nk_record=None,
        path_root=None,
        as_json=False,
        is_init=True,
        fetch_values=True,
    ):
        """
        Recurse over a subkey, and yield all of its subkeys and values
        :param nk_record: an instance of NKRecord from which to start iterating, if None, will start from Root
        :param path_root: If we are iterating an incomplete hive, for example a hive tree starting
                          from ControlSet001 and not SYSTEM, there is no way to know that.
                          This string will be added as prefix to all paths.
        :param as_json: Whether to normalize the data as JSON or not
        :param fetch_values: If False, subkey values will not be returned, but the iteration will be faster
        """
        start = nk_record._nk if nk_record is not None else None
        iterator = self._hive.recurse(
            start=start,
            path_root=path_root,
            as_json=as_json,
            fetch_values=fetch_values,
            is_init=is_init,
        )
        try:
            for name, path, timestamp, values_count, raw_values, values_err, is_root in iterator:
                if values_err:
                    logger.error(f"Failed to parse hive value at path: {path}")
                if as_json:
                    # Build the dicts directly (same shape as asdict(Value(...));
                    # asdict deep-copies and dominates traversal time otherwise).
                    values = [
                        {
                            "name": vname,
                            "value": (convert_wintime(val, as_json=True) if is_filetime else val),
                            "value_type": vtype,
                            "is_corrupted": is_corrupted,
                        }
                        for vname, vtype, val, is_corrupted, is_filetime in raw_values
                    ]
                else:
                    values = [_make_value(raw, as_json) for raw in raw_values]

                if is_root:
                    actual_path = f"{self.partial_hive_path}\\{path}" if self.partial_hive_path else None
                    entry_values_count = len(values)
                else:
                    actual_path = f"{self.partial_hive_path}{path}" if self.partial_hive_path else None
                    entry_values_count = values_count
                yield Subkey(
                    subkey_name=name,
                    path=path,
                    # ISO string (as_json) or pytz.utc datetime, converted in
                    # Rust with convert_wintime-identical arithmetic.
                    timestamp=timestamp,
                    values=values,
                    values_count=entry_values_count,
                    actual_path=actual_path,
                )
        except regipy_rs.ParsingError as ex:
            raise RegistryParsingException(str(ex))

    def get_key(self, key_path):
        if self.partial_hive_path:
            if key_path.startswith(self.partial_hive_path):
                key_path = key_path.partition(self.partial_hive_path)[-1]
            else:
                raise RegistryKeyNotFoundException(f"Did not find subkey at {key_path}, because this is a partial hive")

        logger.debug(f"Getting key: {key_path}")

        # If the key path is \ we are just refering to root
        if key_path == "\\":
            return self.root

        # If the path contain slashes, this is a full path. Split it
        if "\\" in key_path:
            key_path_parts = key_path.split("\\")[1:]
        else:
            key_path_parts = [key_path]

        previous_key_name = []

        subkey = self.root.get_subkey(key_path_parts.pop(0), raise_on_missing=False)

        if not subkey:
            raise RegistryKeyNotFoundException(f"Did not find subkey at {key_path}")

        if not key_path_parts:
            return subkey

        for path_part in key_path_parts:
            new_path = "\\".join(previous_key_name)
            previous_key_name.append(subkey.name)
            subkey = subkey.get_subkey(path_part, raise_on_missing=False)

            if not subkey:
                raise RegistryKeyNotFoundException(f"Did not find {path_part} at {new_path}")
        return subkey

    def get_control_sets(self, registry_path):
        """
        Get the optional control sets for a registry hive
        :param registry_path:
        :return: A list of paths, including the control sets
        """
        found_control_sets = []
        for cs in self.CONTROL_SETS:
            try:
                found_control_sets.append(self.get_key(cs))
            except RegistryKeyNotFoundException:
                continue
        result = [rf"\{subkey.name}\{registry_path}" for subkey in found_control_sets]
        logger.debug(f"Found control sets: {result}")
        return result
