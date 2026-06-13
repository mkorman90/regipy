use pyo3::prelude::*;

use crate::hive::RegistryHive;

/// Python bindings for the regipy-rs registry parser.
/// 
/// This module exposes the Rust parser to Python, providing a drop-in
/// replacement for the Python parser with identical output format.
/// 
/// Usage:
/// ```python
/// from regipy_rs import RegistryHive
/// hive = RegistryHive("path/to/hive")
/// key = hive.get_key("Software\\Microsoft\\Windows")
/// for value in key.values():
///     print(value.name, value.value)
/// ```

#[pyclass]
struct PyNkRecord {
    #[pyo3(get)]
    name: String,
    #[pyo3(get)]
    path: String,
    #[pyo3(get)]
    subkey_count: u32,
    #[pyo3(get)]
    values_count: u32,
    #[pyo3(get)]
    last_modified: i64,
    #[pyo3(get)]
    volatile_subkey_count: u32,
}

#[pymethods]
impl PyNkRecord {
    fn __repr__(&self) -> String {
        format!(
            "NkRecord(name={}, path={}, {} subkeys, {} values)",
            self.name, self.path, self.subkey_count, self.values_count
        )
    }
}

#[pyclass]
struct PyRegistryHive {
    hive: RegistryHive,
}

#[pymethods]
impl PyRegistryHive {
    #[new]
    fn new(path: &str) -> PyResult<Self> {
        let hive = RegistryHive::from_path(std::path::Path::new(path))
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))?;
        Ok(PyRegistryHive { hive })
    }

    fn get_key(&self, path: &str) -> PyResult<PyNkRecord> {
        let nk = self.hive.get_key(path)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))?;
        
        Ok(PyNkRecord {
            name: nk.name.clone(),
            path: format!("\\{}", nk.name),
            subkey_count: nk.subkey_count,
            values_count: nk.values_count,
            last_modified: nk.header.last_modified,
            volatile_subkey_count: nk.header.volatile_subkey_count,
        })
    }

    fn recurse_subkeys(&self) -> PyResult<Vec<PyNkRecord>> {
        let mut entries = Vec::new();
        for entry in self.hive.recurse_subkeys() {
            match entry {
                Ok(nk) => {
                    entries.push(PyNkRecord {
                        name: nk.name.clone(),
                        path: format!("\\{}", nk.name),
                        subkey_count: nk.subkey_count,
                        values_count: nk.values_count,
                        last_modified: nk.header.last_modified,
                        volatile_subkey_count: nk.header.volatile_subkey_count,
                    });
                }
                Err(e) => {
                    return Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()));
                }
            }
        }
        Ok(entries)
    }

    fn hive_type(&self) -> PyResult<String> {
        Ok(format!("{:?}", self.hive.hive_type))
    }

    fn __repr__(&self) -> String {
        format!("RegistryHive(type={:?})", self.hive.hive_type)
    }
}

/// A Python module for parsing Windows registry hives using the regipy-rs engine.
#[pymodule]
fn regipy_rs(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyRegistryHive>()?;
    m.add_class::<PyNkRecord>()?;
    Ok(())
}
