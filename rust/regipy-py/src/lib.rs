//! PyO3 bindings for regipy-core.
//!
//! Goal: drop the Python construct-based parser without changing the regipy
//! plugin layer. We expose objects shaped like regipy.registry's RegistryHive,
//! NKRecord, and Value, and make the *iteration* run in Rust so per-step
//! Python overhead is one PyO3 boundary crossing per yielded item.

use std::sync::Arc;

use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};

use regipy_core::{Hive, NkRecord};

fn map_err<E: std::fmt::Display>(e: E) -> PyErr {
    PyRuntimeError::new_err(e.to_string())
}

/// `RegistryHive` — minimal API parity with regipy.registry.RegistryHive.
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

    /// Root NK as a PyKey.
    #[getter]
    fn root(&self) -> PyResult<PyKey> {
        let nk = self.inner.root().map_err(map_err)?;
        Ok(PyKey::from_offset(self.inner.clone(), nk_offset(&nk)))
    }

    /// Recursive walk. Returns an iterator yielding dicts shaped roughly like
    /// regipy's `Subkey`: {"path","subkey_name","values_count","values"}.
    /// `fetch_values=False` skips the per-value decoding.
    #[pyo3(signature = (fetch_values = true))]
    fn recurse_subkeys(&self, fetch_values: bool) -> PyResult<PyWalkIter> {
        // Pre-walk to collect (path, nk_offset) pairs in Rust, then yield from
        // Python one item at a time. This minimizes Python<->Rust crossings.
        let root = self.inner.root().map_err(map_err)?;
        let mut entries: Vec<WalkEntry> = Vec::new();
        push_walk(&root, String::from("\\"), &mut entries);
        Ok(PyWalkIter {
            hive: self.inner.clone(),
            entries,
            idx: 0,
            fetch_values,
        })
    }

    /// Convenience: bench-style stats. No Python objects per key.
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
}

fn push_walk(nk: &NkRecord<'_>, path: String, out: &mut Vec<WalkEntry>) {
    let name = nk.name();
    out.push(WalkEntry {
        path: path.clone(),
        nk_offset: nk_offset(nk),
        subkey_name: name,
        values_count: nk.values_count,
    });
    if nk.subkey_count == 0 {
        return;
    }
    for sk in nk.iter_subkeys() {
        let sk_name = sk.name();
        let child = if path == "\\" {
            format!("\\{}", sk_name)
        } else {
            format!("{}\\{}", path, sk_name)
        };
        push_walk(&sk, child, out);
    }
}

#[pyclass(name = "WalkIter", module = "regipy_rs")]
pub struct PyWalkIter {
    hive: Arc<Hive>,
    entries: Vec<WalkEntry>,
    idx: usize,
    fetch_values: bool,
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

        // Borrow entry fields without holding a reference into slf
        let (path, subkey_name, values_count, nk_offset) = {
            let e = &slf.entries[idx];
            (e.path.clone(), e.subkey_name.clone(), e.values_count, e.nk_offset)
        };

        let dict = PyDict::new_bound(py);
        dict.set_item("path", &path)?;
        dict.set_item("subkey_name", &subkey_name)?;
        dict.set_item("values_count", values_count)?;

        if slf.fetch_values && values_count > 0 {
            let values_list = PyList::empty_bound(py);
            let data = data_of(&slf.hive);
            if let Ok(nk) = NkRecord::parse_at(data, nk_offset) {
                for v in nk.iter_values() {
                    let vd = PyDict::new_bound(py);
                    vd.set_item("name", v.name())?;
                    vd.set_item("data_type", v.data_type)?;
                    vd.set_item("size", v.data_size)?;
                    vd.set_item("value", PyBytes::new_bound(py, v.raw_value()))?;
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
    /// Offset of the "nk" signature.
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

    fn iter_subkeys(&self) -> PyResult<PyKeyIter> {
        let nk = self.parse()?;
        let mut offsets = Vec::with_capacity(nk.subkey_count as usize);
        for sk in nk.iter_subkeys() {
            offsets.push(nk_offset(&sk));
        }
        Ok(PyKeyIter {
            hive: self.hive.clone(),
            offsets,
            idx: 0,
        })
    }

    fn iter_values<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        let list = PyList::empty_bound(py);
        let nk = self.parse()?;
        for v in nk.iter_values() {
            let d = PyDict::new_bound(py);
            d.set_item("name", v.name())?;
            d.set_item("data_type", v.data_type)?;
            d.set_item("size", v.data_size)?;
            d.set_item("value", PyBytes::new_bound(py, v.raw_value()))?;
            list.append(d)?;
        }
        Ok(list)
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

/// Helper: get the byte slice from an Arc<Hive>. Since Hive's data() takes &self,
/// we go through a small unsafe-free wrapper.
fn data_of(hive: &Hive) -> &[u8] {
    // Hive::data() is private; expose via a free fn that uses a public-ish
    // path. We rely on `walk` to be able to hand out slices, but for the
    // bindings we re-read via NkRecord::parse_at which only needs &[u8].
    // To get the slice we use an inline trick: we re-implement here using
    // the exposed root() reads through the buffer indirectly.
    //
    // Simpler: add a pub method. Done in regipy-core via `bytes()`.
    hive.bytes()
}

/// Compute the file-absolute offset of an NK's "nk" signature.
fn nk_offset(nk: &NkRecord<'_>) -> usize {
    nk.offset()
}

#[pymodule]
fn regipy_rs(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyHive>()?;
    m.add_class::<PyKey>()?;
    m.add_class::<PyKeyIter>()?;
    m.add_class::<PyWalkIter>()?;
    Ok(())
}
