//! PyO3 bindings for the Rust REGF parser core.
//!
//! The Python-facing drop-in API lives in `regipy/registry_rs.py`; this module
//! exposes the raw building blocks: `RegistryHive`, `NKRecord`, iterators and
//! a `ParsingError` exception. Timestamps are surfaced as raw FILETIME ints —
//! conversion to datetime happens in Python (regipy.utils.convert_wintime) so
//! both backends share the exact same arithmetic.

mod parser;

use std::sync::Arc;

use pyo3::create_exception;
use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use pyo3::sync::GILOnceCell;
use pyo3::types::{PyBytes, PyDict, PyList, PyString, PyTuple};

use parser::{
    class_name, find_subkey, list_subkeys, list_values, security_info, Ace, Hive, NkRecord,
    ParseError, ParsedValue, SubkeyList, VData, VType, MAX_LEN,
};

create_exception!(
    regipy_rs,
    ParsingError,
    PyException,
    "Raised on registry parsing errors (maps to regipy's RegistryParsingException)."
);

fn to_pyerr(e: ParseError) -> PyErr {
    ParsingError::new_err(e.to_string())
}

/// (datetime.datetime, pytz.utc), cached. The datetime C-API is not part of
/// the limited API (abi3), so datetimes are built by calling the constructor;
/// pytz.utc is attached so timestamps are indistinguishable from the ones
/// regipy.utils.convert_wintime produces.
static DATETIME_CTOR: GILOnceCell<(Py<PyAny>, Py<PyAny>)> = GILOnceCell::new();

fn datetime_ctor(py: Python<'_>) -> PyResult<&'static (Py<PyAny>, Py<PyAny>)> {
    DATETIME_CTOR.get_or_try_init(py, || {
        let datetime_type = py.import_bound("datetime")?.getattr("datetime")?.unbind();
        let utc = py.import_bound("pytz")?.getattr("utc")?.unbind();
        Ok((datetime_type, utc))
    })
}

/// Build the timestamp exactly like regipy.utils.convert_wintime: ISO string
/// when as_json, else a pytz.utc-aware datetime.
fn filetime_to_py(py: Python<'_>, wintime: u64, as_json: bool) -> PyResult<PyObject> {
    if as_json {
        return Ok(PyString::new_bound(py, &parser::filetime_to_iso(wintime)).into_py(py));
    }
    let c = parser::filetime_to_civil(wintime);
    let (datetime_type, utc) = datetime_ctor(py)?;
    let dt = datetime_type.bind(py).call1((
        c.year,
        c.month,
        c.day,
        c.hour,
        c.minute,
        c.second,
        c.microsecond,
        utc.bind(py),
    ))?;
    Ok(dt.into_py(py))
}

// ─── REGF header ─────────────────────────────────────────────────────────────

/// The REGF file header, attribute-compatible with regipy's construct Container.
#[pyclass(frozen, name = "RegfHeader", module = "regipy_rs")]
pub struct PyRegfHeader {
    #[pyo3(get)]
    primary_sequence_num: u32,
    #[pyo3(get)]
    secondary_sequence_num: u32,
    #[pyo3(get)]
    last_modification_time: u64,
    #[pyo3(get)]
    major_version: u32,
    #[pyo3(get)]
    minor_version: u32,
    #[pyo3(get)]
    file_type: u32,
    #[pyo3(get)]
    file_format: u32,
    #[pyo3(get)]
    root_key_offset: u32,
    #[pyo3(get)]
    hive_bins_data_size: u32,
    #[pyo3(get)]
    clustering_factor: u32,
    #[pyo3(get)]
    file_name: String,
    #[pyo3(get)]
    checksum: u32,
}

#[pymethods]
impl PyRegfHeader {
    fn keys(&self) -> Vec<&'static str> {
        vec![
            "primary_sequence_num",
            "secondary_sequence_num",
            "last_modification_time",
            "major_version",
            "minor_version",
            "file_type",
            "file_format",
            "root_key_offset",
            "hive_bins_data_size",
            "clustering_factor",
            "file_name",
            "checksum",
        ]
    }

    fn __getitem__(&self, py: Python<'_>, key: &str) -> PyResult<PyObject> {
        let v: PyObject = match key {
            "primary_sequence_num" => self.primary_sequence_num.into_py(py),
            "secondary_sequence_num" => self.secondary_sequence_num.into_py(py),
            "last_modification_time" => self.last_modification_time.into_py(py),
            "major_version" => self.major_version.into_py(py),
            "minor_version" => self.minor_version.into_py(py),
            "file_type" => self.file_type.into_py(py),
            "file_format" => self.file_format.into_py(py),
            "root_key_offset" => self.root_key_offset.into_py(py),
            "hive_bins_data_size" => self.hive_bins_data_size.into_py(py),
            "clustering_factor" => self.clustering_factor.into_py(py),
            "file_name" => self.file_name.clone().into_py(py),
            "checksum" => self.checksum.into_py(py),
            other => return Err(pyo3::exceptions::PyKeyError::new_err(other.to_string())),
        };
        Ok(v)
    }

    fn __repr__(&self) -> String {
        format!(
            "RegfHeader(file_name={:?}, primary_sequence_num={}, secondary_sequence_num={})",
            self.file_name, self.primary_sequence_num, self.secondary_sequence_num
        )
    }
}

// ─── NK header + flags ───────────────────────────────────────────────────────

/// CM_KEY_NODE flags, attribute-compatible with construct's FlagsEnum container.
#[pyclass(frozen, name = "NkFlags", module = "regipy_rs")]
pub struct PyNkFlags {
    value: u16,
}

const NK_FLAG_NAMES: [(&str, u16); 7] = [
    ("KEY_VOLATILE", parser::KEY_VOLATILE),
    ("KEY_HIVE_EXIT", parser::KEY_HIVE_EXIT),
    ("KEY_HIVE_ENTRY", parser::KEY_HIVE_ENTRY),
    ("KEY_NO_DELETE", parser::KEY_NO_DELETE),
    ("KEY_SYM_LINK", parser::KEY_SYM_LINK),
    ("KEY_COMP_NAME", parser::KEY_COMP_NAME),
    ("KEY_PREDEF_HANDLE", parser::KEY_PREDEF_HANDLE),
];

#[pymethods]
impl PyNkFlags {
    fn __getattr__(&self, name: &str) -> PyResult<bool> {
        for (flag, bit) in NK_FLAG_NAMES {
            if flag == name {
                return Ok(self.value & bit != 0);
            }
        }
        Err(pyo3::exceptions::PyAttributeError::new_err(name.to_string()))
    }

    fn keys(&self) -> Vec<&'static str> {
        NK_FLAG_NAMES.iter().map(|(n, _)| *n).collect()
    }

    fn __getitem__(&self, key: &str) -> PyResult<bool> {
        self.__getattr__(key)
    }

    fn __eq__(&self, py: Python<'_>, other: PyObject) -> PyResult<bool> {
        // Compare against another NkFlags or a {name: bool} mapping
        // (ignoring underscore keys, like construct Containers do).
        if let Ok(o) = other.extract::<PyRef<PyNkFlags>>(py) {
            return Ok(self.value == o.value);
        }
        if let Ok(d) = other.downcast_bound::<PyDict>(py) {
            for (flag, bit) in NK_FLAG_NAMES {
                match d.get_item(flag)? {
                    Some(v) => {
                        if v.extract::<bool>()? != (self.value & bit != 0) {
                            return Ok(false);
                        }
                    }
                    None => return Ok(false),
                }
            }
            return Ok(true);
        }
        Ok(false)
    }

    fn __repr__(&self) -> String {
        let set: Vec<&str> =
            NK_FLAG_NAMES.iter().filter(|(_, b)| self.value & b != 0).map(|(n, _)| *n).collect();
        format!("NkFlags({})", set.join("|"))
    }
}

/// CM_KEY_NODE header, attribute-compatible with regipy's `NKRecord.header`.
#[pyclass(frozen, name = "NkHeader", module = "regipy_rs")]
pub struct PyNkHeader {
    rec: NkRecord,
}

#[pymethods]
impl PyNkHeader {
    #[getter]
    fn flags(&self) -> PyNkFlags {
        PyNkFlags { value: self.rec.flags }
    }

    #[getter]
    fn last_modified(&self) -> u64 {
        self.rec.last_modified
    }

    #[getter]
    fn access_bits<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new_bound(py, &self.rec.access_bits)
    }

    #[getter]
    fn parent_key_offset(&self) -> u32 {
        self.rec.parent_key_offset
    }

    #[getter]
    fn subkey_count(&self) -> u32 {
        self.rec.subkey_count
    }

    #[getter]
    fn volatile_subkey_count(&self) -> u32 {
        self.rec.volatile_subkey_count
    }

    #[getter]
    fn subkeys_list_offset(&self) -> u32 {
        self.rec.subkeys_list_offset
    }

    #[getter]
    fn volatile_subkeys_list_offset(&self) -> u32 {
        self.rec.volatile_subkeys_list_offset
    }

    #[getter]
    fn values_count(&self) -> u32 {
        self.rec.values_count
    }

    #[getter]
    fn values_list_offset(&self) -> u32 {
        self.rec.values_list_offset
    }

    #[getter]
    fn security_key_offset(&self) -> u32 {
        self.rec.security_key_offset
    }

    #[getter]
    fn class_name_offset(&self) -> u32 {
        self.rec.class_name_offset
    }

    #[getter]
    fn largest_sk_name(&self) -> u32 {
        self.rec.largest_sk_name
    }

    #[getter]
    fn largest_sk_class_name(&self) -> u32 {
        self.rec.largest_sk_class_name
    }

    #[getter]
    fn largest_value_name(&self) -> u32 {
        self.rec.largest_value_name
    }

    #[getter]
    fn largest_value_data(&self) -> u32 {
        self.rec.largest_value_data
    }

    #[getter]
    fn key_name_size(&self) -> u16 {
        self.rec.key_name_size
    }

    #[getter]
    fn class_name_size(&self) -> u16 {
        self.rec.class_name_size
    }

    #[getter]
    fn key_name_string<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new_bound(py, &self.rec.key_name_raw)
    }

    /// Support dict(header), like construct Containers.
    fn keys(&self) -> Vec<&'static str> {
        vec![
            "flags",
            "last_modified",
            "access_bits",
            "parent_key_offset",
            "subkey_count",
            "volatile_subkey_count",
            "subkeys_list_offset",
            "volatile_subkeys_list_offset",
            "values_count",
            "values_list_offset",
            "security_key_offset",
            "class_name_offset",
            "largest_sk_name",
            "largest_sk_class_name",
            "largest_value_name",
            "largest_value_data",
            "key_name_size",
            "class_name_size",
            "key_name_string",
        ]
    }

    fn __getitem__(&self, py: Python<'_>, key: &str) -> PyResult<PyObject> {
        let r = &self.rec;
        let v: PyObject = match key {
            "flags" => Py::new(py, PyNkFlags { value: r.flags })?.into_py(py),
            "last_modified" => r.last_modified.into_py(py),
            "access_bits" => PyBytes::new_bound(py, &r.access_bits).into_py(py),
            "parent_key_offset" => r.parent_key_offset.into_py(py),
            "subkey_count" => r.subkey_count.into_py(py),
            "volatile_subkey_count" => r.volatile_subkey_count.into_py(py),
            "subkeys_list_offset" => r.subkeys_list_offset.into_py(py),
            "volatile_subkeys_list_offset" => r.volatile_subkeys_list_offset.into_py(py),
            "values_count" => r.values_count.into_py(py),
            "values_list_offset" => r.values_list_offset.into_py(py),
            "security_key_offset" => r.security_key_offset.into_py(py),
            "class_name_offset" => r.class_name_offset.into_py(py),
            "largest_sk_name" => r.largest_sk_name.into_py(py),
            "largest_sk_class_name" => r.largest_sk_class_name.into_py(py),
            "largest_value_name" => r.largest_value_name.into_py(py),
            "largest_value_data" => r.largest_value_data.into_py(py),
            "key_name_size" => r.key_name_size.into_py(py),
            "class_name_size" => r.class_name_size.into_py(py),
            "key_name_string" => PyBytes::new_bound(py, &r.key_name_raw).into_py(py),
            other => return Err(pyo3::exceptions::PyKeyError::new_err(other.to_string())),
        };
        Ok(v)
    }

    fn __eq__(&self, py: Python<'_>, other: PyObject) -> PyResult<bool> {
        if let Ok(o) = other.extract::<PyRef<PyNkHeader>>(py) {
            let a = &self.rec;
            let b = &o.rec;
            return Ok(a.flags == b.flags
                && a.last_modified == b.last_modified
                && a.access_bits == b.access_bits
                && a.parent_key_offset == b.parent_key_offset
                && a.subkey_count == b.subkey_count
                && a.volatile_subkey_count == b.volatile_subkey_count
                && a.subkeys_list_offset == b.subkeys_list_offset
                && a.volatile_subkeys_list_offset == b.volatile_subkeys_list_offset
                && a.values_count == b.values_count
                && a.values_list_offset == b.values_list_offset
                && a.security_key_offset == b.security_key_offset
                && a.class_name_offset == b.class_name_offset
                && a.key_name_raw == b.key_name_raw);
        }
        Ok(false)
    }

    fn __repr__(&self) -> String {
        format!(
            "NkHeader(name={:?}, subkey_count={}, values_count={})",
            self.rec.name, self.rec.subkey_count, self.rec.values_count
        )
    }
}

// ─── Value conversion ────────────────────────────────────────────────────────

fn vtype_to_py(py: Python<'_>, vt: &VType) -> PyObject {
    match vt {
        VType::Named(n) => PyString::new_bound(py, n).into_py(py),
        VType::NumStr(n) => PyString::new_bound(py, &n.to_string()).into_py(py),
        VType::Num(n) => n.into_py(py),
    }
}

fn vdata_to_py(py: Python<'_>, d: &VData) -> PyObject {
    match d {
        VData::Str(s) => PyString::new_bound(py, s).into_py(py),
        VData::Bytes(b) => PyBytes::new_bound(py, b).into_py(py),
        VData::U32(v) => v.into_py(py),
        VData::U64(v) => v.into_py(py),
        VData::List(items) => PyList::new_bound(py, items.iter()).into_py(py),
        VData::Filetime(v) => v.into_py(py),
    }
}

/// (name, value_type, value, is_corrupted, is_filetime)
fn value_to_tuple(py: Python<'_>, v: &ParsedValue) -> PyObject {
    let is_filetime = matches!(v.data, VData::Filetime(_));
    PyTuple::new_bound(
        py,
        [
            PyString::new_bound(py, &v.name).into_py(py),
            vtype_to_py(py, &v.vtype),
            vdata_to_py(py, &v.data),
            v.is_corrupted.into_py(py),
            is_filetime.into_py(py),
        ],
    )
    .into_py(py)
}

// ─── NKRecord ────────────────────────────────────────────────────────────────

#[pyclass(frozen, name = "NKRecord", module = "regipy_rs")]
pub struct PyNkRecord {
    hive: Arc<Hive>,
    rec: NkRecord,
}

#[pymethods]
impl PyNkRecord {
    #[getter]
    fn name(&self) -> &str {
        &self.rec.name
    }

    #[getter]
    fn subkey_count(&self) -> u32 {
        self.rec.subkey_count
    }

    #[getter]
    fn values_count(&self) -> u32 {
        self.rec.values_count
    }

    #[getter]
    fn volatile_subkeys_count(&self) -> u32 {
        self.rec.volatile_subkey_count
    }

    #[getter]
    fn offset(&self) -> usize {
        self.rec.offset
    }

    #[getter]
    fn header(&self) -> PyNkHeader {
        PyNkHeader { rec: self.rec.clone() }
    }

    /// Iterate direct subkeys lazily; raises ParsingError after yielding the
    /// successfully parsed prefix if the subkey list is corrupt (mirroring
    /// Python generator semantics).
    fn subkeys(&self) -> PySubkeyIter {
        let SubkeyList { subkeys, error } = list_subkeys(&self.hive, &self.rec);
        PySubkeyIter {
            hive: self.hive.clone(),
            subkeys,
            error: error.map(|e| e.to_string()),
            idx: 0,
        }
    }

    /// Case-insensitive subkey lookup. Returns None when missing.
    fn find_subkey(&self, name: &str) -> PyResult<Option<PyNkRecord>>{
        match find_subkey(&self.hive, &self.rec, name) {
            Ok(Some(rec)) => Ok(Some(PyNkRecord { hive: self.hive.clone(), rec })),
            Ok(None) => Ok(None),
            Err(e) => Err(to_pyerr(e)),
        }
    }

    /// Parse the key's values. Returns (values, error_message_or_None) where
    /// values is the successfully parsed prefix.
    #[pyo3(signature = (as_json = false, trim_values = true, max_len = MAX_LEN))]
    fn values(&self, py: Python<'_>, as_json: bool, trim_values: bool, max_len: usize) -> PyObject {
        let result = list_values(&self.hive, &self.rec, as_json, trim_values, max_len);
        let values: Vec<PyObject> = result.values.iter().map(|v| value_to_tuple(py, v)).collect();
        let err: PyObject = match result.error {
            Some(e) => PyString::new_bound(py, &e.to_string()).into_py(py),
            None => py.None(),
        };
        PyTuple::new_bound(py, [PyList::new_bound(py, values).into_py(py), err]).into_py(py)
    }

    fn class_name(&self) -> String {
        class_name(&self.hive, &self.rec)
    }

    fn security_info(&self, py: Python<'_>) -> PyResult<PyObject>{
        let info = security_info(&self.hive, &self.rec).map_err(to_pyerr)?;
        let dict = PyDict::new_bound(py);
        dict.set_item("owner", &info.owner)?;
        dict.set_item("group", &info.group)?;
        dict.set_item("dacl", acl_to_py(py, info.dacl.as_deref())?)?;
        dict.set_item("sacl", acl_to_py(py, info.sacl.as_deref())?)?;
        Ok(dict.into_py(py))
    }

    fn __repr__(&self) -> String {
        format!(
            "NKRecord(name={:?}, subkey_count={}, values_count={})",
            self.rec.name, self.rec.subkey_count, self.rec.values_count
        )
    }
}

fn acl_to_py(py: Python<'_>, acl: Option<&[Ace]>) -> PyResult<PyObject> {
    let Some(aces) = acl else { return Ok(py.None()) };
    let list = PyList::empty_bound(py);
    for ace in aces {
        let d = PyDict::new_bound(py);
        d.set_item("ace_type", &ace.ace_type)?;
        // Match dict(construct FlagsEnum container) from compiled structs,
        // which contains only the flag names.
        let flags = PyDict::new_bound(py);
        for (name, bit) in parser::ACE_FLAG_NAMES {
            flags.set_item(name, ace.flags.value & bit != 0)?;
        }
        d.set_item("flags", flags)?;
        let mask = PyDict::new_bound(py);
        for (name, bit) in parser::ACCESS_MASK_NAMES {
            mask.set_item(name, ace.access_mask.value & bit != 0)?;
        }
        d.set_item("access_mask", mask)?;
        d.set_item("sid", &ace.sid)?;
        list.append(d)?;
    }
    Ok(list.into_py(py))
}

// ─── Subkey iterator ─────────────────────────────────────────────────────────

#[pyclass(name = "SubkeyIter", module = "regipy_rs")]
pub struct PySubkeyIter {
    hive: Arc<Hive>,
    subkeys: Vec<NkRecord>,
    error: Option<String>,
    idx: usize,
}

#[pymethods]
impl PySubkeyIter {
    fn __iter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    fn __next__(mut slf: PyRefMut<'_, Self>) -> PyResult<Option<PyNkRecord>> {
        if slf.idx < slf.subkeys.len() {
            let rec = slf.subkeys[slf.idx].clone();
            slf.idx += 1;
            return Ok(Some(PyNkRecord { hive: slf.hive.clone(), rec }));
        }
        if let Some(msg) = slf.error.take() {
            return Err(ParsingError::new_err(msg));
        }
        Ok(None)
    }
}

// ─── Recursive traversal iterator ────────────────────────────────────────────

enum Task {
    Expand { rec: NkRecord, path_root: String, depth: u32 },
    Emit { rec: NkRecord, path: String },
    EmitRoot { rec: NkRecord, path: String },
    RaiseError(String),
}

/// Guard against subkey-list cycles in corrupted/malicious hives: the Python
/// implementation is incidentally protected by the interpreter recursion limit
/// (~1000); mirror that bound here instead of looping forever.
const MAX_KEY_DEPTH: u32 = 1000;

/// Depth-first traversal matching RegistryHive.recurse_subkeys exactly:
/// for each subkey, its subtree is yielded before the subkey itself, and the
/// starting key is yielded last (when is_init is set).
#[pyclass(name = "RecurseIter", module = "regipy_rs")]
pub struct PyRecurseIter {
    hive: Arc<Hive>,
    stack: Vec<Task>,
    as_json: bool,
    fetch_values: bool,
}

impl PyRecurseIter {
    /// (name, path, timestamp, header_values_count, values, values_err, is_root)
    fn make_entry(&self, py: Python<'_>, rec: &NkRecord, path: &str, is_root: bool) -> PyResult<PyObject> {
        // Quirk preserved: the starting key's values are fetched even when
        // fetch_values=False (Python's is_init branch has no fetch_values guard).
        let fetch = if is_root { rec.values_count > 0 } else { self.fetch_values && rec.values_count > 0 };
        let (values, err): (Vec<PyObject>, bool) = if fetch {
            let result = list_values(&self.hive, rec, self.as_json, true, MAX_LEN);
            match result.error {
                // Python: the exception discards the partially built list.
                Some(_) => (Vec::new(), true),
                None => (result.values.iter().map(|v| value_to_tuple(py, v)).collect(), false),
            }
        } else {
            (Vec::new(), false)
        };
        Ok(PyTuple::new_bound(
            py,
            [
                PyString::new_bound(py, &rec.name).into_py(py),
                PyString::new_bound(py, path).into_py(py),
                filetime_to_py(py, rec.last_modified, self.as_json)?,
                rec.values_count.into_py(py),
                PyList::new_bound(py, values).into_py(py),
                err.into_py(py),
                is_root.into_py(py),
            ],
        )
        .into_py(py))
    }
}

#[pymethods]
impl PyRecurseIter {
    fn __iter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    fn __next__(mut slf: PyRefMut<'_, Self>, py: Python<'_>) -> PyResult<Option<PyObject>> {
        loop {
            let Some(task) = slf.stack.pop() else { return Ok(None) };
            match task {
                Task::Expand { rec, path_root, depth } => {
                    if rec.subkey_count == 0 {
                        continue;
                    }
                    if depth >= MAX_KEY_DEPTH {
                        return Err(ParsingError::new_err(format!(
                            "Maximum key depth ({MAX_KEY_DEPTH}) exceeded at {path_root} — subkey list cycle?"
                        )));
                    }
                    let SubkeyList { subkeys, error } = list_subkeys(&slf.hive, &rec);
                    // Python pulls the subkey generator lazily: elements parsed
                    // before a corrupt one are fully processed, then the error
                    // propagates. Push the error sentinel first (deepest).
                    if let Some(e) = error {
                        slf.stack.push(Task::RaiseError(e.to_string()));
                    }
                    for child in subkeys.into_iter().rev() {
                        let child_path = if path_root.is_empty() {
                            format!("\\{}", child.name)
                        } else {
                            format!("{}\\{}", path_root, child.name)
                        };
                        slf.stack.push(Task::Emit { rec: child.clone(), path: child_path.clone() });
                        if child.subkey_count > 0 {
                            slf.stack.push(Task::Expand { rec: child, path_root: child_path, depth: depth + 1 });
                        }
                    }
                }
                Task::Emit { rec, path } => return Ok(Some(slf.make_entry(py, &rec, &path, false)?)),
                Task::EmitRoot { rec, path } => {
                    return Ok(Some(slf.make_entry(py, &rec, &path, true)?))
                }
                Task::RaiseError(msg) => return Err(ParsingError::new_err(msg)),
            }
        }
    }
}

// ─── RegistryHive ────────────────────────────────────────────────────────────

#[pyclass(frozen, name = "RegistryHive", module = "regipy_rs")]
pub struct PyRegistryHive {
    hive: Arc<Hive>,
}

#[pymethods]
impl PyRegistryHive {
    #[new]
    fn new(hive_path: &str) -> PyResult<Self> {
        let hive = Hive::from_file(hive_path).map_err(to_pyerr)?;
        Ok(Self { hive })
    }

    #[getter]
    fn header(&self) -> PyRegfHeader {
        let h = &self.hive.header;
        PyRegfHeader {
            primary_sequence_num: h.primary_sequence_num,
            secondary_sequence_num: h.secondary_sequence_num,
            last_modification_time: h.last_modification_time,
            major_version: h.major_version,
            minor_version: h.minor_version,
            file_type: h.file_type,
            file_format: h.file_format,
            root_key_offset: h.root_key_offset,
            hive_bins_data_size: h.hive_bins_data_size,
            clustering_factor: h.clustering_factor,
            file_name: h.file_name.clone(),
            checksum: h.checksum,
        }
    }

    #[getter]
    fn name(&self) -> &str {
        &self.hive.header.file_name
    }

    fn root(&self) -> PyNkRecord {
        PyNkRecord { hive: self.hive.clone(), rec: self.hive.root.clone() }
    }

    /// Raw REGF header bytes (for checksum validation in the CLI).
    fn header_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        let end = self.hive.data.len().min(REGF_RAW_HEADER_LEN);
        PyBytes::new_bound(py, &self.hive.data[..end])
    }

    #[pyo3(signature = (start = None, path_root = None, as_json = false, fetch_values = true, is_init = true))]
    fn recurse(
        &self,
        start: Option<PyRef<PyNkRecord>>,
        path_root: Option<String>,
        as_json: bool,
        fetch_values: bool,
        is_init: bool,
    ) -> PyRecurseIter {
        let rec = match &start {
            Some(nk) => nk.rec.clone(),
            None => self.hive.root.clone(),
        };
        let path_root = path_root.unwrap_or_default();
        let mut stack = Vec::new();
        if is_init {
            let root_path = if path_root.is_empty() { "\\".to_string() } else { path_root.clone() };
            stack.push(Task::EmitRoot { rec: rec.clone(), path: root_path });
        }
        stack.push(Task::Expand { rec, path_root, depth: 0 });
        PyRecurseIter { hive: self.hive.clone(), stack, as_json, fetch_values }
    }

    fn __repr__(&self) -> String {
        format!("RegistryHive(name={:?})", self.hive.header.file_name)
    }
}

const REGF_RAW_HEADER_LEN: usize = 512;

// ─── Module ──────────────────────────────────────────────────────────────────

/// FILETIME → ISO string (regipy.utils.convert_wintime(x, as_json=True) semantics).
#[pyfunction]
fn convert_wintime_iso(wintime: u64) -> String {
    parser::filetime_to_iso(wintime)
}

/// FILETIME → pytz.utc-aware datetime (convert_wintime(x, as_json=False) semantics).
#[pyfunction]
fn convert_wintime_datetime(py: Python<'_>, wintime: u64) -> PyResult<PyObject> {
    filetime_to_py(py, wintime, false)
}

#[pymodule]
fn regipy_rs(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyRegistryHive>()?;
    m.add_class::<PyNkRecord>()?;
    m.add_class::<PyNkHeader>()?;
    m.add_class::<PyNkFlags>()?;
    m.add_class::<PyRegfHeader>()?;
    m.add_class::<PySubkeyIter>()?;
    m.add_class::<PyRecurseIter>()?;
    m.add("ParsingError", py.get_type_bound::<ParsingError>())?;
    m.add_function(wrap_pyfunction!(convert_wintime_iso, m)?)?;
    m.add_function(wrap_pyfunction!(convert_wintime_datetime, m)?)?;
    // Keep in sync with [project].version in pyproject.toml (the wheel version;
    // Cargo's own version stays plain semver).
    m.add("__version__", "0.1.0a1")?;
    Ok(())
}
