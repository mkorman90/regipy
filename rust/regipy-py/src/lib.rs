//! PyO3 bindings for regipy-core.
//!
//! Goal: provide the surface needed for `regipy.registry` to delegate to Rust
//! while keeping the same Python-visible behavior. We expose the parsed REGF
//! header as a Python dict, NK records with a header dict matching construct's
//! field set, type-aware value decoding, and key navigation.

use std::sync::Arc;

use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};

use regipy_core::{value_type_name, DecodedValue, Hive, NkHeader, NkRecord, RegfHeader};

fn map_err<E: std::fmt::Display>(e: E) -> PyErr {
    PyRuntimeError::new_err(e.to_string())
}

fn data_of(hive: &Hive) -> &[u8] {
    hive.bytes()
}

fn header_to_dict<'py>(py: Python<'py>, h: &RegfHeader) -> PyResult<Bound<'py, PyDict>> {
    let d = PyDict::new_bound(py);
    d.set_item("primary_sequence_num", h.primary_sequence_num)?;
    d.set_item("secondary_sequence_num", h.secondary_sequence_num)?;
    d.set_item("last_modification_time", h.last_modification_time)?;
    d.set_item("major_version", h.major_version)?;
    d.set_item("minor_version", h.minor_version)?;
    d.set_item("file_type", h.file_type)?;
    d.set_item("file_format", h.file_format)?;
    d.set_item("root_key_offset", h.root_key_offset)?;
    d.set_item("hive_bins_data_size", h.hive_bins_data_size)?;
    d.set_item("clustering_factor", h.clustering_factor)?;
    d.set_item("file_name", &h.file_name)?;
    d.set_item("checksum", h.checksum)?;
    Ok(d)
}

fn nk_header_to_dict<'py>(py: Python<'py>, h: &NkHeader) -> PyResult<Bound<'py, PyDict>> {
    let d = PyDict::new_bound(py);
    let flags = PyDict::new_bound(py);
    flags.set_item("KEY_VOLATILE", (h.flags & 0x0001) != 0)?;
    flags.set_item("KEY_HIVE_EXIT", (h.flags & 0x0002) != 0)?;
    flags.set_item("KEY_HIVE_ENTRY", (h.flags & 0x0004) != 0)?;
    flags.set_item("KEY_NO_DELETE", (h.flags & 0x0008) != 0)?;
    flags.set_item("KEY_SYM_LINK", (h.flags & 0x0010) != 0)?;
    flags.set_item("KEY_COMP_NAME", (h.flags & 0x0020) != 0)?;
    flags.set_item("KEY_PREDEF_HANDLE", (h.flags & 0x0040) != 0)?;
    d.set_item("flags", flags)?;
    d.set_item("last_modified", h.last_modified)?;
    d.set_item("access_bits", PyBytes::new_bound(py, &h.access_bits))?;
    d.set_item("parent_key_offset", h.parent_key_offset)?;
    d.set_item("subkey_count", h.subkey_count)?;
    d.set_item("volatile_subkey_count", h.volatile_subkey_count)?;
    d.set_item("subkeys_list_offset", h.subkeys_list_offset)?;
    d.set_item("volatile_subkeys_list_offset", h.volatile_subkeys_list_offset)?;
    d.set_item("values_count", h.values_count)?;
    d.set_item("values_list_offset", h.values_list_offset)?;
    d.set_item("security_key_offset", h.security_key_offset)?;
    d.set_item("class_name_offset", h.class_name_offset)?;
    d.set_item("largest_sk_name", h.largest_sk_name)?;
    d.set_item("largest_sk_class_name", h.largest_sk_class_name)?;
    d.set_item("largest_value_name", h.largest_value_name)?;
    d.set_item("largest_value_data", h.largest_value_data)?;
    d.set_item("key_name_size", h.key_name_size)?;
    d.set_item("class_name_size", h.class_name_size)?;
    d.set_item("key_name_string", PyBytes::new_bound(py, &h.key_name_string))?;
    Ok(d)
}

fn decoded_value_to_py<'py>(
    py: Python<'py>,
    v: &DecodedValue,
) -> PyResult<PyObject> {
    let obj: PyObject = match v {
        DecodedValue::None => py.None(),
        DecodedValue::String(s) | DecodedValue::ExpandString(s) | DecodedValue::Link(s) => {
            s.into_py(py)
        }
        DecodedValue::Binary(b) | DecodedValue::Raw(b) => PyBytes::new_bound(py, b).into(),
        DecodedValue::Dword(n) => n.into_py(py),
        DecodedValue::DwordBE(n) => n.into_py(py),
        DecodedValue::Qword(n) => n.into_py(py),
        DecodedValue::Filetime(n) => n.into_py(py),
        DecodedValue::MultiString(items) => {
            let list = PyList::empty_bound(py);
            for s in items {
                list.append(s)?;
            }
            list.into()
        }
    };
    Ok(obj)
}

#[pyclass(name = "RegistryHive", module = "regipy_rs")]
pub struct PyHive {
    inner: Arc<Hive>,
}

#[pymethods]
impl PyHive {
    #[new]
    fn new(path: &str) -> PyResult<Self> {
        let h = Hive::open(path).map_err(map_err)?;
        Ok(Self { inner: Arc::new(h) })
    }

    /// Return the REGF header as a dict.
    fn header_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let h = self.inner.header();
        header_to_dict(py, &h)
    }

    #[getter]
    fn root(&self) -> PyResult<PyKey> {
        let nk = self.inner.root().map_err(map_err)?;
        Ok(PyKey::from_offset(self.inner.clone(), nk.offset()))
    }

    /// Return the NK at `key_path` or None if not found.
    fn get_key(&self, key_path: &str) -> PyResult<Option<PyKey>> {
        match self.inner.get_key(key_path).map_err(map_err)? {
            Some(nk) => Ok(Some(PyKey::from_offset(self.inner.clone(), nk.offset()))),
            None => Ok(None),
        }
    }

    /// Recursive walk yielding dicts.
    #[pyo3(signature = (fetch_values = true, as_json = false))]
    fn recurse_subkeys(&self, fetch_values: bool, as_json: bool) -> PyResult<PyWalkIter> {
        let root = self.inner.root().map_err(map_err)?;
        let mut entries: Vec<WalkEntry> = Vec::new();
        push_walk(&root, String::from("\\"), &mut entries, true);
        Ok(PyWalkIter {
            hive: self.inner.clone(),
            entries,
            idx: 0,
            fetch_values,
            as_json,
        })
    }

    fn walk_stats(&self) -> PyResult<(u64, u64, u32)> {
        let s = regipy_core::walk(&self.inner).map_err(map_err)?;
        Ok((s.keys, s.values, s.max_depth))
    }
}

struct WalkEntry {
    path: String,
    nk_offset: usize,
    subkey_name: String,
    values_count: u32,
    last_modified: u64,
}

fn push_walk(nk: &NkRecord<'_>, path: String, out: &mut Vec<WalkEntry>, is_root: bool) {
    // Match Python regipy's recurse_subkeys ordering:
    //   For each subkey, recurse first, then yield. After all subkeys: yield root.
    // For non-root nodes, the "yield self after recursing into self" happens
    // at the parent level.
    if nk.subkey_count > 0 {
        for sk in nk.iter_subkeys() {
            let sk_name = sk.name();
            let child = if path == "\\" {
                format!("\\{}", sk_name)
            } else {
                format!("{}\\{}", path, sk_name)
            };
            // Recurse children first (depth-first), then yield this child
            if sk.subkey_count > 0 {
                push_walk(&sk, child.clone(), out, false);
            }
            out.push(WalkEntry {
                path: child,
                nk_offset: sk.offset(),
                subkey_name: sk_name,
                values_count: sk.values_count,
                last_modified: sk.last_modified,
            });
        }
    }
    if is_root {
        out.push(WalkEntry {
            path,
            nk_offset: nk.offset(),
            subkey_name: nk.name(),
            values_count: nk.values_count,
            last_modified: nk.last_modified,
        });
    }
}

#[pyclass(name = "WalkIter", module = "regipy_rs")]
pub struct PyWalkIter {
    hive: Arc<Hive>,
    entries: Vec<WalkEntry>,
    idx: usize,
    fetch_values: bool,
    as_json: bool,
}

#[pymethods]
impl PyWalkIter {
    fn __iter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    fn __next__<'py>(mut slf: PyRefMut<'py, Self>, py: Python<'py>) -> PyResult<Option<PyObject>> {
        if slf.idx >= slf.entries.len() {
            return Ok(None);
        }
        let idx = slf.idx;
        slf.idx += 1;
        let (path, subkey_name, values_count, nk_offset, last_modified) = {
            let e = &slf.entries[idx];
            (e.path.clone(), e.subkey_name.clone(), e.values_count, e.nk_offset, e.last_modified)
        };

        let dict = PyDict::new_bound(py);
        dict.set_item("path", &path)?;
        dict.set_item("subkey_name", &subkey_name)?;
        dict.set_item("values_count", values_count)?;
        dict.set_item("last_modified", last_modified)?;

        if slf.fetch_values && values_count > 0 {
            let values_list = PyList::empty_bound(py);
            let data = data_of(&slf.hive);
            if let Ok(nk) = NkRecord::parse_at(data, nk_offset) {
                for v in nk.iter_values() {
                    // Python regipy: `elif int(vk.data_type) == 0x200000: continue`
                    // Skip these unknown values entirely.
                    if v.data_type == 0x200000 {
                        continue;
                    }
                    let vd = PyDict::new_bound(py);
                    vd.set_item("name", v.name())?;
                    let decoded = v.decode();
                    // Match Python regipy's value_type rendering exactly:
                    //   - data_type > 0xFFFF_0000 (DEVPROP): strip to lower 16 bits
                    //     and re-parse via VALUE_TYPE_ENUM. Known → str name;
                    //     unknown → int (EnumInteger).
                    //   - else: str(vk.data_type). Known → str enum name;
                    //     unknown → str of the integer ("131076" etc).
                    if v.data_type > 0xFFFF_0000 {
                        let stripped = v.data_type & 0xFFFF;
                        let name = value_type_name(stripped);
                        if name == "UNKNOWN" {
                            // Emit as Python int (EnumInteger)
                            vd.set_item("value_type", stripped)?;
                        } else {
                            vd.set_item("value_type", name)?;
                        }
                    } else {
                        let name = value_type_name(v.data_type);
                        if name == "UNKNOWN" {
                            // Python str(EnumInteger) → str-form of int
                            vd.set_item("value_type", v.data_type.to_string())?;
                        } else {
                            vd.set_item("value_type", name)?;
                        }
                    }
                    vd.set_item("data_type_int", v.data_type)?;
                    vd.set_item("value", decoded_value_to_py(py, &decoded)?)?;
                    vd.set_item("size", v.data_size)?;
                    let _ = slf.as_json;
                    values_list.append(vd)?;
                }
            }
            dict.set_item("values", values_list)?;
        } else {
            dict.set_item("values", PyList::empty_bound(py))?;
        }

        Ok(Some(dict.into()))
    }
}

#[pyclass(name = "NKRecord", module = "regipy_rs")]
pub struct PyKey {
    hive: Arc<Hive>,
    nk_offset: usize,
}

impl PyKey {
    fn from_offset(hive: Arc<Hive>, nk_offset: usize) -> Self {
        Self { hive, nk_offset }
    }

    fn parse(&self) -> PyResult<NkRecord<'_>> {
        let data = data_of(&self.hive);
        NkRecord::parse_at(data, self.nk_offset).map_err(map_err)
    }
}

#[pymethods]
impl PyKey {
    #[getter]
    fn name(&self) -> PyResult<String> {
        Ok(self.parse()?.name())
    }

    #[getter]
    fn subkey_count(&self) -> PyResult<u32> {
        Ok(self.parse()?.subkey_count)
    }

    #[getter]
    fn values_count(&self) -> PyResult<u32> {
        Ok(self.parse()?.values_count)
    }

    #[getter]
    fn last_modified(&self) -> PyResult<u64> {
        Ok(self.parse()?.last_modified)
    }

    /// File-absolute offset of the "nk" signature for this record.
    /// Useful for building a Python construct-parsed NKRecord at this exact
    /// position without re-walking the tree.
    #[getter]
    fn nk_offset(&self) -> usize {
        self.nk_offset
    }

    /// Header as a dict (matches CM_KEY_NODE construct field set).
    fn header_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let nk = self.parse()?;
        let h = nk.header_fields();
        nk_header_to_dict(py, &h)
    }

    fn class_name(&self) -> PyResult<String> {
        Ok(self.parse()?.class_name())
    }

    fn iter_subkeys(&self) -> PyResult<PyKeyIter> {
        let nk = self.parse()?;
        let mut offsets = Vec::with_capacity(nk.subkey_count as usize);
        for sk in nk.iter_subkeys() {
            offsets.push(sk.offset());
        }
        Ok(PyKeyIter {
            hive: self.hive.clone(),
            offsets,
            idx: 0,
        })
    }

    fn get_subkey(&self, name: &str) -> PyResult<Option<PyKey>> {
        let nk = self.parse()?;
        Ok(nk.get_subkey(name).map(|sk| PyKey::from_offset(self.hive.clone(), sk.offset())))
    }

    fn iter_values<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        let list = PyList::empty_bound(py);
        let nk = self.parse()?;
        for v in nk.iter_values() {
            let d = PyDict::new_bound(py);
            d.set_item("name", v.name())?;
            // Match Python's `data_type = str(vk.data_type)` quirk:
            // known enum members render as the construct symbol name
            // ("REG_SZ", "REG_DWORD", ...). Unknown values pass through as
            // the integer, matching construct's EnumInteger fallback.
            let raw_type = v.data_type & 0xFFFF;
            let name = value_type_name(raw_type);
            if name == "UNKNOWN" {
                d.set_item("value_type", raw_type)?;
            } else {
                d.set_item("value_type", name)?;
            }
            d.set_item("data_type_int", v.data_type)?;
            let decoded = v.decode();
            d.set_item("value", decoded_value_to_py(py, &decoded)?)?;
            d.set_item("size", v.data_size)?;
            list.append(d)?;
        }
        Ok(list)
    }

    /// Look up a single value by name (case-insensitive). Returns None if absent.
    fn get_value<'py>(&self, py: Python<'py>, value_name: &str) -> PyResult<PyObject> {
        let want = value_name.to_ascii_lowercase();
        let nk = self.parse()?;
        for v in nk.iter_values() {
            let n = v.name();
            let n_lc = n.to_ascii_lowercase();
            if n_lc == want || (want == "(default)" && n.is_empty()) {
                let decoded = v.decode();
                return decoded_value_to_py(py, &decoded);
            }
        }
        Ok(py.None())
    }
}

#[pyclass(name = "KeyIter", module = "regipy_rs")]
pub struct PyKeyIter {
    hive: Arc<Hive>,
    offsets: Vec<usize>,
    idx: usize,
}

#[pymethods]
impl PyKeyIter {
    fn __iter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    fn __next__(mut slf: PyRefMut<'_, Self>) -> Option<PyKey> {
        if slf.idx >= slf.offsets.len() {
            return None;
        }
        let off = slf.offsets[slf.idx];
        slf.idx += 1;
        Some(PyKey::from_offset(slf.hive.clone(), off))
    }
}

#[pymodule]
fn regipy_rs(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyHive>()?;
    m.add_class::<PyKey>()?;
    m.add_class::<PyKeyIter>()?;
    m.add_class::<PyWalkIter>()?;
    Ok(())
}
