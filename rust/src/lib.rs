//! python-sbom's core: everything between the options and the content provider, in Rust.

mod addresses;
mod archive;
mod check;
mod email;
mod error;
mod facts;
mod hashes;
mod json;
mod licenses;
mod model;
mod names;
mod pep508;
mod pyrepr;
mod record;
mod spdx;
mod spdx_data;
mod validate;
mod wheel;
mod zip;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use pyo3::exceptions::{PyIndexError, PyTypeError};
use pyo3::prelude::*;
use pyo3::types::{PyBool, PyBytes, PyDict, PyFloat, PyInt, PyList, PySlice, PyString, PyTuple};

use crate::email::Metadata;
use crate::error::Error;
use crate::json::{Json, Obj};
use crate::record::RecordRow;

/// core metadata headers, with the read API of `email.message.Message`
#[pyclass(name = "Metadata", module = "python_sbom._core", frozen)]
struct PyMetadata(Arc<Metadata>);

#[pymethods]
impl PyMetadata {
    #[staticmethod]
    fn parse(text: &str) -> Self {
        Self(Arc::new(Metadata::parse(text)))
    }

    fn __getitem__(&self, name: &str) -> Option<&str> {
        self.0.get(name)
    }

    #[pyo3(signature = (name, failobj=None))]
    fn get<'py>(&self, py: Python<'py>, name: &str, failobj: Option<Bound<'py, PyAny>>) -> PyResult<Bound<'py, PyAny>> {
        match self.0.get(name) {
            Some(value) => Ok(PyString::new(py, value).into_any()),
            None => Ok(failobj.unwrap_or_else(|| py.None().into_bound(py))),
        }
    }

    #[pyo3(signature = (name, failobj=None))]
    fn get_all<'py>(&self, py: Python<'py>, name: &str, failobj: Option<Bound<'py, PyAny>>) -> PyResult<Bound<'py, PyAny>> {
        let values: Vec<&str> = self.0.get_all(name).collect();
        if values.is_empty() {
            return Ok(failobj.unwrap_or_else(|| py.None().into_bound(py)));
        }
        Ok(PyList::new(py, values)?.into_any())
    }

    fn items(&self) -> Vec<(String, String)> {
        self.0.headers.clone()
    }

    fn keys(&self) -> Vec<String> {
        self.0.headers.iter().map(|(key, _)| key.clone()).collect()
    }

    fn values(&self) -> Vec<String> {
        self.0.headers.iter().map(|(_, value)| value.clone()).collect()
    }

    fn __contains__(&self, name: &str) -> bool {
        self.0.contains(name)
    }

    /// `Message.as_string()` under compat32, for headers that need no folding
    fn __str__(&self) -> String {
        let mut out = String::new();
        for (key, value) in &self.0.headers {
            out.push_str(key);
            out.push_str(": ");
            out.push_str(value);
            out.push('\n');
        }
        out.push('\n');
        out
    }

    fn __len__(&self) -> usize {
        self.0.headers.len()
    }

    fn __iter__<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        PyList::new(py, self.keys())?.try_iter().map(Bound::into_any)
    }
}

/// a RECORD's rows, kept in Rust; each read builds the `RecordRow` dataclass
#[pyclass(name = "RecordRows", module = "python_sbom._core", frozen, sequence)]
struct PyRecordRows(Arc<Vec<RecordRow>>);

fn row_object<'py>(py: Python<'py>, row: &RecordRow) -> PyResult<Bound<'py, PyAny>> {
    let class = py.import("python_sbom._model._inputs")?.getattr("RecordRow")?;
    let kwargs = PyDict::new(py);
    kwargs.set_item("path", &row.path)?;
    kwargs.set_item("algorithm", &row.algorithm)?;
    kwargs.set_item("digest", &row.digest)?;
    kwargs.set_item("size", &row.size)?;
    class.call((), Some(&kwargs))
}

#[pymethods]
impl PyRecordRows {
    fn __len__(&self) -> usize {
        self.0.len()
    }

    fn __getitem__<'py>(&self, py: Python<'py>, index: &Bound<'py, PyAny>) -> PyResult<Bound<'py, PyAny>> {
        if let Ok(slice) = index.cast::<PySlice>() {
            let indices = slice.indices(self.0.len() as isize)?;
            let mut out = Vec::new();
            let mut at = indices.start;
            while (indices.step > 0 && at < indices.stop) || (indices.step < 0 && at > indices.stop) {
                out.push(row_object(py, &self.0[at as usize])?);
                at += indices.step;
            }
            return Ok(PyList::new(py, out)?.into_any());
        }
        let position: isize = index.extract()?;
        let length = self.0.len() as isize;
        let resolved = if position < 0 { position + length } else { position };
        if !(0..length).contains(&resolved) {
            return Err(PyIndexError::new_err("list index out of range"));
        }
        row_object(py, &self.0[resolved as usize])
    }

    fn __iter__<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        PyList::new(py, self.0.iter().map(|row| row_object(py, row)).collect::<PyResult<Vec<_>>>()?)?.try_iter().map(Bound::into_any)
    }

    fn __eq__<'py>(&self, py: Python<'py>, other: &Bound<'py, PyAny>) -> PyResult<bool> {
        if let Ok(other) = other.cast::<PyRecordRows>() {
            return Ok(*self.0 == *other.get().0);
        }
        let mine = PyList::new(py, self.0.iter().map(|row| row_object(py, row)).collect::<PyResult<Vec<_>>>()?)?;
        mine.eq(other)
    }

    fn __repr__(&self) -> String {
        format!("<RecordRows of {}>", self.0.len())
    }
}

/// a document built in Rust, turned into Python objects or JSON bytes only when asked
#[pyclass(name = "Document", module = "python_sbom._core", frozen)]
struct PyDocument(Json);

#[pymethods]
impl PyDocument {
    fn to_python<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        to_python(py, &self.0)
    }

    fn dumps<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        let bytes = py.detach(|| json::dumps_pretty(&self.0));
        PyBytes::new(py, &bytes)
    }
}

fn to_python<'py>(py: Python<'py>, value: &Json) -> PyResult<Bound<'py, PyAny>> {
    Ok(match value {
        Json::Null => py.None().into_bound(py),
        Json::Bool(flag) => PyBool::new(py, *flag).to_owned().into_any(),
        Json::Num(text) => {
            if text.bytes().all(|byte| byte.is_ascii_digit() || byte == b'-') {
                py.import("builtins")?.getattr("int")?.call1((text.as_str(),))?
            } else {
                py.import("builtins")?.getattr("float")?.call1((text.as_str(),))?
            }
        }
        Json::Str(text) => PyString::new(py, text).into_any(),
        Json::Arr(items) => PyList::new(py, items.iter().map(|item| to_python(py, item)).collect::<PyResult<Vec<_>>>()?)?.into_any(),
        Json::Obj(object) => {
            let dict = PyDict::new(py);
            for (key, item) in &object.0 {
                dict.set_item(key, to_python(py, item)?)?;
            }
            dict.into_any()
        }
    })
}

/// a Python value as `json.dumps` would write it
fn from_python(value: &Bound<'_, PyAny>) -> PyResult<Json> {
    if let Ok(text) = value.cast::<PyString>() {
        return Ok(Json::Str(text.to_str()?.to_owned()));
    }
    if value.is_none() {
        return Ok(Json::Null);
    }
    if let Ok(flag) = value.cast::<PyBool>() {
        return Ok(Json::Bool(flag.is_true()));
    }
    if let Ok(integer) = value.cast::<PyInt>() {
        return Ok(Json::Num(value.py().import("builtins")?.getattr("int")?.getattr("__repr__")?.call1((integer,))?.extract()?));
    }
    if let Ok(float) = value.cast::<PyFloat>() {
        return Ok(Json::Num(json::float_repr(float.value())));
    }
    if let Ok(dict) = value.cast::<PyDict>() {
        let mut object = Obj::with_capacity(dict.len());
        for (key, item) in dict.iter() {
            let key = key.cast::<PyString>().map_err(|_| PyTypeError::new_err(format!("keys must be str, not {}", key.get_type().name().map(|name| name.to_string()).unwrap_or_default())))?;
            object.push(key.to_str()?, from_python(&item)?);
        }
        return Ok(Json::Obj(object));
    }
    if let Ok(list) = value.cast::<PyList>() {
        return Ok(Json::Arr(list.iter().map(|item| from_python(&item)).collect::<PyResult<_>>()?));
    }
    if let Ok(tuple) = value.cast::<PyTuple>() {
        return Ok(Json::Arr(tuple.iter().map(|item| from_python(&item)).collect::<PyResult<_>>()?));
    }
    if let Ok(document) = value.cast::<PyDocument>() {
        return Ok(document.get().0.clone());
    }
    Err(PyTypeError::new_err(format!("Object of type {} is not JSON serializable", value.get_type().name()?)))
}

fn json_list(value: &Bound<'_, PyAny>) -> PyResult<Vec<Json>> {
    match from_python(value)? {
        Json::Arr(items) => Ok(items),
        _ => Err(PyTypeError::new_err("expected a list")),
    }
}

fn optional_json(value: &Bound<'_, PyAny>) -> PyResult<Option<Json>> {
    if value.is_none() { Ok(None) } else { from_python(value).map(Some) }
}

fn metadata_of(value: &Bound<'_, PyAny>) -> PyResult<Arc<Metadata>> {
    if let Ok(metadata) = value.cast::<PyMetadata>() {
        return Ok(metadata.get().0.clone());
    }
    let mut headers = Vec::new();
    for pair in value.call_method0("items")?.try_iter()? {
        let (key, item): (Bound<'_, PyAny>, Bound<'_, PyAny>) = pair?.extract()?;
        headers.push((key.str()?.to_str()?.to_owned(), item.str()?.to_str()?.to_owned()));
    }
    Ok(Arc::new(Metadata { headers }))
}

fn rows_of(value: &Bound<'_, PyAny>) -> PyResult<Arc<Vec<RecordRow>>> {
    if let Ok(rows) = value.cast::<PyRecordRows>() {
        return Ok(rows.get().0.clone());
    }
    let mut rows = Vec::new();
    for row in value.try_iter()? {
        let row = row?;
        let text = |name: &str| -> PyResult<String> { Ok(row.getattr(name)?.str()?.to_str()?.to_owned()) };
        rows.push(RecordRow { path: text("path")?, algorithm: text("algorithm")?, digest: text("digest")?, size: text("size")? });
    }
    Ok(Arc::new(rows))
}

fn string_of(value: &Bound<'_, PyAny>, name: &str) -> PyResult<String> {
    Ok(value.getattr(name)?.str()?.to_str()?.to_owned())
}

fn optional_string(value: &Bound<'_, PyAny>, name: &str) -> PyResult<Option<String>> {
    let found = value.getattr(name)?;
    if found.is_none() { Ok(None) } else { Ok(Some(found.str()?.to_str()?.to_owned())) }
}

fn settings_of(value: &Bound<'_, PyAny>) -> PyResult<model::Settings> {
    Ok(model::Settings {
        supplier: optional_json(&value.getattr("supplier")?)?,
        repository: optional_string(value, "repository")?,
        default_branch: string_of(value, "default_branch")?,
        bundled_wheels: value.getattr("bundled_wheels")?.extract()?,
    })
}

fn facts_of(value: &Bound<'_, PyAny>) -> PyResult<model::Facts> {
    let interpreter = value.getattr("interpreter")?;
    let revision = value.getattr("revision")?;
    let mut distributions = Vec::new();
    for distribution in value.getattr("distributions")?.try_iter()? {
        let distribution = distribution?;
        distributions.push(Arc::new(facts::Distribution {
            name: string_of(&distribution, "name")?,
            metadata: metadata_of(&distribution.getattr("metadata")?)?,
            files: rows_of(&distribution.getattr("files")?)?,
            depends_on: distribution.getattr("depends_on")?.extract()?,
        }));
    }
    Ok(model::Facts {
        epoch: value.getattr("epoch")?.extract()?,
        epoch_from_environment: value.getattr("epoch_from_environment")?.extract()?,
        revision: if revision.is_none() {
            None
        } else {
            Some(model::Revision { commit: string_of(&revision, "commit")?, dirty: revision.getattr("dirty")?.extract()? })
        },
        interpreter: model::Interpreter {
            name: string_of(&interpreter, "name")?,
            version: string_of(&interpreter, "version")?,
            implementation: string_of(&interpreter, "implementation")?,
        },
        distributions,
    })
}

fn bundled_of(value: &Bound<'_, PyAny>) -> PyResult<Arc<wheel::BundledWheel>> {
    let mut vendored = Vec::new();
    for pair in value.getattr("vendored")?.try_iter()? {
        let (source, metadata): (String, Bound<'_, PyAny>) = pair?.extract()?;
        vendored.push((source, metadata_of(&metadata)?));
    }
    Ok(Arc::new(wheel::BundledWheel {
        path: string_of(value, "path")?,
        sha256: string_of(value, "sha256")?,
        metadata_name: string_of(value, "metadata_name")?,
        metadata: metadata_of(&value.getattr("metadata")?)?,
        files: rows_of(&value.getattr("files")?)?,
        vendored,
    }))
}

fn info_of(value: &Bound<'_, PyAny>) -> PyResult<model::BundledInfo> {
    Ok(model::BundledInfo { properties: json_list(&value.getattr("properties")?)?, supplier: optional_json(&value.getattr("supplier")?)? })
}

fn contributions_of(value: &Bound<'_, PyAny>) -> PyResult<model::Contributions> {
    Ok(model::Contributions {
        components: json_list(&value.getattr("components")?)?,
        dependencies: json_list(&value.getattr("dependencies")?)?,
        root_properties: json_list(&value.getattr("root_properties")?)?,
        tools: json_list(&value.getattr("tools")?)?,
    })
}

/// a bundled wheel as the `BundledWheel` dataclass, its metadata and rows left in Rust
fn bundled_object<'py>(py: Python<'py>, wheel: wheel::BundledWheel) -> PyResult<Bound<'py, PyAny>> {
    let class = py.import("python_sbom._model._inputs")?.getattr("BundledWheel")?;
    let kwargs = PyDict::new(py);
    kwargs.set_item("path", &wheel.path)?;
    kwargs.set_item("sha256", &wheel.sha256)?;
    kwargs.set_item("metadata_name", &wheel.metadata_name)?;
    kwargs.set_item("metadata", PyMetadata(wheel.metadata))?;
    kwargs.set_item("files", PyRecordRows(wheel.files))?;
    let vendored = PyList::empty(py);
    for (source, metadata) in wheel.vendored {
        vendored.append((source, PyMetadata(metadata)))?;
    }
    kwargs.set_item("vendored", vendored)?;
    class.call((), Some(&kwargs))
}

#[pyfunction]
fn parse_metadata(text: &str) -> PyMetadata {
    PyMetadata::parse(text)
}

/// the built wheel's METADATA, as `wheel_request` reads it
#[pyfunction]
fn wheel_metadata(py: Python<'_>, wheel: PathBuf) -> PyResult<PyMetadata> {
    let location = wheel.to_string_lossy().into_owned();
    let metadata = py.detach(|| wheel::Opened::path(&wheel, &location).and_then(|opened| opened.wheel_metadata()))?;
    Ok(PyMetadata(Arc::new(metadata.1)))
}

#[pyfunction]
fn read_bundled_wheel<'py>(py: Python<'py>, data: Vec<u8>, path: &str) -> PyResult<Bound<'py, PyAny>> {
    let wheel = py.detach(|| wheel::read_bundled_wheel(data, path))?;
    bundled_object(py, wheel)
}

/// the wheels a project bundles, read and verified in parallel; `items` pairs each file with its path in the project
#[pyfunction]
fn read_bundled_wheels<'py>(py: Python<'py>, items: Vec<(PathBuf, String)>) -> PyResult<Vec<Bound<'py, PyAny>>> {
    use rayon::prelude::*;
    let read: Vec<error::Result<wheel::BundledWheel>> = py.detach(|| {
        items.par_iter().map(|(file, relative)| wheel::read_bundled_wheel(std::fs::read(file)?, relative)).collect()
    });
    read.into_iter().map(|wheel| bundled_object(py, wheel?)).collect()
}

#[pyfunction]
fn whl_member_digests(py: Python<'_>, wheel: PathBuf) -> PyResult<Vec<(String, String)>> {
    Ok(py.detach(|| wheel::whl_member_digests(&wheel))?)
}

#[pyfunction]
fn write_sbom(py: Python<'_>, wheel: PathBuf, name: &str, content: &[u8], epoch: i64) -> PyResult<String> {
    Ok(py.detach(|| wheel::write_sbom(&wheel, name, content, epoch))?)
}

/// the distributions on `paths`, as `InstalledDistribution` field tuples, and the warnings each raised
#[pyfunction]
fn collect_distributions<'py>(
    py: Python<'py>,
    paths: Vec<String>,
    environment: HashMap<String, String>,
) -> PyResult<(Vec<(String, PyMetadata, PyRecordRows, Vec<String>)>, Vec<Vec<Bound<'py, PyAny>>>)> {
    let (distributions, warnings) = py.detach(|| facts::collect(&paths, &environment))?;
    let found = distributions
        .into_iter()
        .map(|distribution| (distribution.name, PyMetadata(distribution.metadata), PyRecordRows(distribution.files), distribution.depends_on))
        .collect();
    let warned = warnings
        .into_iter()
        .map(|raised| {
            raised
                .into_iter()
                .map(|warning| match warning {
                    facts::Warning::Message(message) => Ok(PyString::new(py, &message).into_any()),
                    facts::Warning::DirectUrlNotJson { name, text } => Ok(PyTuple::new(py, [name, text])?.into_any()),
                })
                .collect::<PyResult<Vec<_>>>()
        })
        .collect::<PyResult<Vec<_>>>()?;
    Ok((found, warned))
}

/// `project_identity`: the property prefix, the repository and the serial namespace as text
#[pyfunction]
fn project_identity(metadata: &Bound<'_, PyAny>, settings: &Bound<'_, PyAny>) -> PyResult<(String, Option<String>, String)> {
    let identity = model::project_identity(&*metadata_of(metadata)?, &settings_of(settings)?);
    Ok((identity.property_prefix, identity.repository, identity.serial_namespace.to_string()))
}

#[pyfunction]
fn describe(
    py: Python<'_>,
    request: &Bound<'_, PyAny>,
    source: &Bound<'_, PyAny>,
    facts: &Bound<'_, PyAny>,
    bundled_info: &Bound<'_, PyDict>,
    contributions: &Bound<'_, PyAny>,
) -> PyResult<PyDocument> {
    let request = model::Request {
        metadata: metadata_of(&request.getattr("metadata")?)?,
        wheel_name: string_of(request, "wheel_name")?,
        settings: settings_of(&request.getattr("settings")?)?,
    };
    let copyright = source.getattr("copyright")?;
    let mut build_scripts = Vec::new();
    for script in source.getattr("build_scripts")?.try_iter()? {
        let script = script?;
        build_scripts.push(model::BuildScript { path: string_of(&script, "path")?, sha256: string_of(&script, "sha256")? });
    }
    let source = model::Source {
        copyright: if copyright.is_none() { None } else { Some(copyright.str()?.to_str()?.to_owned()) },
        bundled: source.getattr("bundled")?.try_iter()?.map(|wheel| bundled_of(&wheel?)).collect::<PyResult<_>>()?,
        build_scripts,
    };
    let facts = facts_of(facts)?;
    let mut infos = HashMap::with_capacity(bundled_info.len());
    for (path, info) in bundled_info.iter() {
        infos.insert(path.str()?.to_str()?.to_owned(), info_of(&info)?);
    }
    let contributions = contributions_of(contributions)?;
    Ok(PyDocument(py.detach(|| model::describe(&request, &source, &facts, &infos, contributions))?))
}

/// `json.dumps(value, indent=2)` plus a newline, as bytes
#[pyfunction]
fn dumps<'py>(py: Python<'py>, value: &Bound<'py, PyAny>) -> PyResult<Bound<'py, PyBytes>> {
    let value = from_python(value)?;
    Ok(PyBytes::new(py, &json::dumps_pretty(&value)))
}

#[pyfunction]
fn component_from_metadata<'py>(py: Python<'py>, metadata: &Bound<'py, PyAny>) -> PyResult<Bound<'py, PyAny>> {
    to_python(py, &Json::Obj(model::component_from_metadata(&*metadata_of(metadata)?)))
}

#[pyfunction(name = "licenses")]
fn declared_licenses<'py>(py: Python<'py>, metadata: &Bound<'py, PyAny>) -> PyResult<Bound<'py, PyAny>> {
    to_python(py, &Json::Arr(model::licenses(&*metadata_of(metadata)?)))
}

#[pyfunction]
fn tool_components<'py>(py: Python<'py>, facts: &Bound<'py, PyAny>) -> PyResult<(Bound<'py, PyAny>, Bound<'py, PyAny>)> {
    let (tools, dependencies) = model::tool_components(&facts_of(facts)?);
    Ok((to_python(py, &Json::Arr(tools))?, to_python(py, &Json::Arr(dependencies))?))
}

#[pyfunction]
fn with_header<'py>(py: Python<'py>, body: &Bound<'py, PyAny>, namespace: &str) -> PyResult<Bound<'py, PyAny>> {
    let Json::Obj(body) = from_python(body)? else { return Err(PyTypeError::new_err("the body must be a dict")) };
    let namespace = uuid::Uuid::parse_str(namespace).map_err(|error| PyTypeError::new_err(error.to_string()))?;
    to_python(py, &model::with_header(body, &namespace)?)
}

#[pyfunction]
fn contributed_properties<'py>(py: Python<'py>, properties: &Bound<'py, PyAny>, prefix: &str) -> PyResult<Bound<'py, PyAny>> {
    to_python(py, &Json::Arr(model::contributed_properties(&json_list(properties)?, prefix)?))
}

#[pyfunction]
#[pyo3(signature = (wheel, namespace, properties, supplier))]
fn bundled_wheel_component<'py>(
    py: Python<'py>,
    wheel: &Bound<'py, PyAny>,
    namespace: &str,
    properties: &Bound<'py, PyAny>,
    supplier: &Bound<'py, PyAny>,
) -> PyResult<Bound<'py, PyAny>> {
    let component = model::bundled_wheel_component(&*bundled_of(wheel)?, namespace, &json_list(properties)?, optional_json(supplier)?.as_ref());
    to_python(py, &component)
}

#[pyfunction]
fn file_component_from_bytes<'py>(py: Python<'py>, parent: &str, name: &str, content: &[u8]) -> PyResult<Bound<'py, PyAny>> {
    let row = RecordRow { path: name.to_owned(), algorithm: "SHA-256".to_owned(), digest: hashes::sha256_hex(content), size: content.len().to_string() };
    to_python(py, &model::file_component(parent, &row))
}

#[pyfunction]
#[pyo3(signature = (path, sha256, version, link))]
fn script_tool<'py>(py: Python<'py>, path: &Bound<'py, PyAny>, sha256: &str, version: Option<&str>, link: Option<String>) -> PyResult<Bound<'py, PyAny>> {
    to_python(py, &model::script_tool(path.str()?.to_str()?, sha256, version, link))
}

#[pyfunction]
fn schema_error(raw: &str) -> PyResult<Option<String>> {
    let value: serde_json::Value = serde_json::from_str(raw).map_err(|error| Error::Value(error.to_string()))?;
    Ok(validate::schema_error(&value))
}

#[pyfunction]
fn spdx_problems(spdx: &Bound<'_, PyAny>) -> PyResult<Vec<String>> {
    Ok(validate::spdx_problems(&check::to_serde(&from_python(spdx)?)))
}

#[pyfunction]
fn license_problems(components: &Bound<'_, PyAny>, allowed: Vec<String>) -> PyResult<Vec<String>> {
    let components: Vec<serde_json::Value> = json_list(components)?.iter().map(check::to_serde).collect();
    Ok(validate::license_problems(&components, &allowed))
}

#[pyfunction]
fn applies_without_extras(requirement: &str) -> PyResult<bool> {
    let parsed = pep508::parse_requirement(requirement).map_err(Error::InvalidRequirement)?;
    Ok(parsed.marker.as_deref().is_none_or(pep508::applies_without_extras))
}

#[pyfunction]
fn decode_digest(digest: &str, location: &str) -> PyResult<(String, String)> {
    let (algorithm, hex) = record::decode_digest(digest, location)?;
    Ok((algorithm.to_owned(), hex))
}

#[pyfunction]
fn render_spdx<'py>(py: Python<'py>, document: &Bound<'py, PyAny>, version: &str) -> PyResult<Bound<'py, PyAny>> {
    to_python(py, &spdx::render(&from_python(document)?, version)?)
}

/// the SPDX JSON text of a document, or the `KeyError`/`TypeError` text of why it does not render
#[pyfunction]
fn spdx_text(py: Python<'_>, document: &Bound<'_, PyAny>, version: &str) -> PyResult<String> {
    let document = from_python(document)?;
    let rendered = py.detach(|| spdx::render(&document, version))?;
    Ok(String::from_utf8(json::dumps_pretty(&rendered)).expect("ASCII"))
}

/// `python-sbom spdx`: render a document file into another, `None` when it renders, else why not
#[pyfunction]
fn spdx_file(py: Python<'_>, source: PathBuf, target: PathBuf, version: &str) -> PyResult<Option<String>> {
    py.detach(|| -> error::Result<Option<String>> {
        let raw = std::fs::read_to_string(&source)?;
        let raw = if raw.contains('\r') { raw.replace("\r\n", "\n").replace('\r', "\n") } else { raw };
        let parsed: serde_json::Value = serde_json::from_str(&raw).map_err(|error| Error::Value(error.to_string()))?;
        if !check::is_document(&parsed) {
            return Ok(Some(String::new()));
        }
        match spdx::render(&json::from_serde(&parsed), version) {
            Ok(rendered) => {
                std::fs::write(&target, json::dumps_pretty(&rendered))?;
                Ok(None)
            }
            Err(Error::Key(key)) => Ok(Some(format!("KeyError({key})"))),
            Err(Error::Type(message)) => Ok(Some(format!("TypeError({})", pyrepr::repr(&message)))),
            Err(other) => Err(other),
        }
    })
    .map_err(PyErr::from)
}

#[pyfunction]
#[pyo3(signature = (raw, allowed, max_components, version))]
fn validate_document(py: Python<'_>, raw: &str, allowed: Option<Vec<String>>, max_components: usize, version: &str) -> Vec<String> {
    py.detach(|| check::validate_document(raw, allowed.as_deref(), max_components, version))
}

#[pyfunction]
#[pyo3(signature = (path, allowed, max_components, version))]
fn validate_artifact(py: Python<'_>, path: PathBuf, allowed: Option<Vec<String>>, max_components: usize, version: &str) -> PyResult<Vec<String>> {
    Ok(py.detach(|| check::validate_artifact(&path, allowed.as_deref(), max_components, version))?)
}

#[pyfunction]
fn warm_up(py: Python<'_>) {
    py.detach(validate::warm_up);
}

/// an archive read for `python-sbom archive`: the provider's queries in `queries`, then `finish`
#[pyclass(name = "ArchiveScan", module = "python_sbom._core", frozen)]
struct PyArchiveScan(Mutex<archive::Scan>);

#[pymethods]
impl PyArchiveScan {
    #[new]
    fn new(py: Python<'_>, archive: PathBuf, unpacked: PathBuf, settings: &Bound<'_, PyAny>) -> PyResult<Self> {
        let settings = settings_of(settings)?;
        Ok(Self(Mutex::new(py.detach(|| archive::Scan::open(&archive, &unpacked, settings))?)))
    }

    #[getter]
    fn queries(&self) -> Vec<String> {
        self.0.lock().expect("unpoisoned").queries.clone()
    }

    #[getter]
    fn identity(&self) -> (String, Option<String>, String) {
        let scan = self.0.lock().expect("unpoisoned");
        (scan.identity.property_prefix.clone(), scan.identity.repository.clone(), scan.identity.serial_namespace.to_string())
    }

    /// the document, given each query's `BundledWheelInfo`, the contributions, the facts and the build scripts as
    /// (path relative to the project, file) pairs
    fn finish(
        &self,
        py: Python<'_>,
        infos: &Bound<'_, PyAny>,
        contributions: &Bound<'_, PyAny>,
        facts: &Bound<'_, PyAny>,
        scripts: Vec<(String, PathBuf)>,
    ) -> PyResult<PyDocument> {
        let infos: Vec<model::BundledInfo> = infos.try_iter()?.map(|info| info_of(&info?)).collect::<PyResult<_>>()?;
        let contributions = contributions_of(contributions)?;
        let facts = facts_of(facts)?;
        let scan = self.0.lock().expect("unpoisoned");
        let document = py.detach(|| -> error::Result<Json> {
            let scripts = scripts.iter().map(|(path, file)| Ok((path.clone(), std::fs::read(file)?))).collect::<error::Result<Vec<_>>>()?;
            scan.finish(&infos, contributions, &facts, &scripts)
        })?;
        Ok(PyDocument(document))
    }
}

/// `--embed`: the document added at the archive's top level, stored, as zipfile appends it
#[pyfunction]
fn append_member(py: Python<'_>, archive: PathBuf, name: &str, content: &[u8], epoch: i64) -> PyResult<bool> {
    Ok(py.detach(|| -> error::Result<bool> {
        let location = archive.file_name().map(|name| name.to_string_lossy().into_owned()).unwrap_or_default();
        let opened = wheel::Opened::path(&archive, &location)?;
        if opened.archive.names().any(|member| member == name) {
            return Ok(false);
        }
        let (time, date) = zip::dos_time(epoch);
        let member = zip::NewMember {
            name,
            content,
            deflate: false,
            dos_time: time,
            dos_date: date,
            create_version: 20,
            create_system: 3,
            extract_version: 20,
            internal_attr: 0,
            external_attr: 0o644 << 16,
        };
        let output = opened.archive.append(&member).map_err(|error| opened.zip(error))?;
        drop(opened);
        std::fs::write(&archive, output)?;
        Ok(true)
    })?)
}

#[pymodule(gil_used = false)]
fn _core(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<PyMetadata>()?;
    module.add_class::<PyRecordRows>()?;
    module.add_class::<PyDocument>()?;
    module.add_class::<PyArchiveScan>()?;
    module.add("MAX_COMPONENTS", check::MAX_COMPONENTS)?;
    for function in [
        wrap_pyfunction!(parse_metadata, module)?,
        wrap_pyfunction!(wheel_metadata, module)?,
        wrap_pyfunction!(read_bundled_wheel, module)?,
        wrap_pyfunction!(read_bundled_wheels, module)?,
        wrap_pyfunction!(whl_member_digests, module)?,
        wrap_pyfunction!(write_sbom, module)?,
        wrap_pyfunction!(collect_distributions, module)?,
        wrap_pyfunction!(project_identity, module)?,
        wrap_pyfunction!(describe, module)?,
        wrap_pyfunction!(dumps, module)?,
        wrap_pyfunction!(component_from_metadata, module)?,
        wrap_pyfunction!(declared_licenses, module)?,
        wrap_pyfunction!(tool_components, module)?,
        wrap_pyfunction!(with_header, module)?,
        wrap_pyfunction!(applies_without_extras, module)?,
        wrap_pyfunction!(contributed_properties, module)?,
        wrap_pyfunction!(bundled_wheel_component, module)?,
        wrap_pyfunction!(file_component_from_bytes, module)?,
        wrap_pyfunction!(script_tool, module)?,
        wrap_pyfunction!(schema_error, module)?,
        wrap_pyfunction!(spdx_problems, module)?,
        wrap_pyfunction!(license_problems, module)?,
        wrap_pyfunction!(decode_digest, module)?,
        wrap_pyfunction!(render_spdx, module)?,
        wrap_pyfunction!(spdx_text, module)?,
        wrap_pyfunction!(spdx_file, module)?,
        wrap_pyfunction!(validate_document, module)?,
        wrap_pyfunction!(validate_artifact, module)?,
        wrap_pyfunction!(warm_up, module)?,
        wrap_pyfunction!(append_member, module)?,
    ] {
        module.add_function(function)?;
    }
    Ok(())
}
