//! `python-sbom validate`: every SBOM an artifact holds against the CycloneDX schema and, for one python-sbom wrote,
//! its serial, references, SPDX rendering and license policy.

use std::collections::{BTreeSet, HashMap};
use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;
use serde_json::Value;

use crate::error::Result;
use crate::json::{Json, from_serde};
use crate::names::SBOM_FILE;
use crate::pyrepr::repr;
use crate::wheel::Opened;

/// the archive reader stops at the same size
const MAX_CHARACTERS: usize = 16 * 1024 * 1024;
/// an SBOM lists every file of its wheel at a few hundred bytes each, so this bounds what one member makes us hold
const SBOM_LIMIT: usize = 64 * 1024 * 1024;
pub const MAX_COMPONENTS: usize = 5_000;
const REQUIRED: &[&[&str]] = &[
    &["metadata", "timestamp"],
    &["metadata", "tools", "components"],
    &["metadata", "component", "bom-ref"],
    &["metadata", "component", "name"],
    &["components"],
    &["dependencies"],
];
static SERIAL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\Aurn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z").expect("valid"));

fn list_repr<'a>(items: impl IntoIterator<Item = &'a str>) -> String {
    format!("[{}]", items.into_iter().map(repr).collect::<Vec<_>>().join(", "))
}

/// `validate_document`
pub fn validate_document(raw: &str, allowed: Option<&[String]>, max_components: usize, version: &str) -> Vec<String> {
    let length = raw.chars().count();
    if length > MAX_CHARACTERS {
        return vec![format!("is {length} characters long, over the {MAX_CHARACTERS} character limit")];
    }
    let loaded: Value = match serde_json::from_str(raw) {
        Ok(value) => value,
        Err(error) if error.to_string().starts_with("recursion limit exceeded") => {
            return vec!["does not conform to the CycloneDX 1.6 schema: it nests too deeply to check".to_owned()];
        }
        Err(error) => return vec![format!("is not JSON: {}", json_error(raw).unwrap_or_else(|| error.to_string()))],
    };
    problems(&loaded, allowed, max_components, version)
}

/// json's own wording of why a text is not JSON, asked of Python only once the core refused it
fn json_error(raw: &str) -> Option<String> {
    use pyo3::prelude::*;
    Python::attach(|py| {
        let loads = py.import("json").ok()?.getattr("loads").ok()?;
        match loads.call1((raw,)) {
            Ok(_) => None,
            Err(error) => Some(error.value(py).str().ok()?.to_string()),
        }
    })
}

pub fn is_document(value: &Value) -> bool {
    has(value, &["metadata", "component", "bom-ref"]) && has(value, &["metadata", "component", "name"])
}

fn has(value: &Value, path: &[&str]) -> bool {
    let mut current = value;
    for key in path {
        match current.as_object().and_then(|object| object.get(*key)) {
            Some(next) => current = next,
            None => return false,
        }
    }
    true
}

fn problems(loaded: &Value, allowed: Option<&[String]>, max_components: usize, version: &str) -> Vec<String> {
    let census = census_problems(loaded, max_components);
    if !census.is_empty() {
        return census;
    }
    if let Some(error) = crate::validate::schema_error(loaded) {
        return vec![format!("does not conform to the CycloneDX 1.6 schema: {error}")];
    }
    let suffix = format!(":{SBOM_FILE}");
    let written = loaded
        .get("metadata")
        .and_then(|metadata| metadata.get("properties"))
        .and_then(Value::as_array)
        .is_some_and(|properties| properties.iter().any(|prop| prop.get("name").and_then(Value::as_str).is_some_and(|name| name.ends_with(&suffix))));
    if !written {
        return Vec::new();
    }
    let missing: Vec<String> = REQUIRED.iter().filter(|path| !has(loaded, path)).map(|path| path.join(".")).collect();
    if !missing.is_empty() || !is_document(loaded) {
        return vec![format!("lacks {}, which every document python-sbom writes carries", missing.join(", "))];
    }
    let serial = loaded.get("serialNumber").and_then(Value::as_str).unwrap_or("");
    if !SERIAL.is_match(serial) {
        return vec![format!("serialNumber must be a urn:uuid: RFC 4122 UUID, got {}", repr(serial))];
    }
    let mut found = reference_problems(loaded);
    if found.is_empty() {
        found = match crate::spdx::render(&from_serde(loaded), version) {
            Ok(spdx) => crate::validate::spdx_problems(&to_serde(&spdx)),
            Err(error) => vec![format!("could not be checked, {}", error)],
        };
    }
    if let Some(allowed) = allowed {
        let components = loaded.get("components").and_then(Value::as_array).map_or(&[][..], Vec::as_slice);
        found.extend(crate::validate::license_problems(components, allowed));
    }
    found
}

/// `_census_problems`: components and bom-refs counted in one pass before the schema vouches for any shape
fn census_problems(document: &Value, max_components: usize) -> Vec<String> {
    let mut components = 0usize;
    let mut refs: HashMap<&str, usize> = HashMap::new();
    let mut pending = vec![document];
    while let Some(node) = pending.pop() {
        match node {
            Value::Array(items) => pending.extend(items),
            Value::Object(object) => {
                if let Some(Value::String(reference)) = object.get("bom-ref") {
                    *refs.entry(reference).or_default() += 1;
                }
                if let Some(Value::Array(listed)) = object.get("components") {
                    components += listed.len();
                }
                pending.extend(object.values());
            }
            _ => {}
        }
        if components > max_components {
            return vec![format!(
                "lists more than {max_components} components, nested ones included; pass a higher --max-components to check it"
            )];
        }
    }
    let duplicates: BTreeSet<&str> = refs.into_iter().filter(|(_, count)| *count > 1).map(|(reference, _)| reference).collect();
    if duplicates.is_empty() { Vec::new() } else { vec![format!("bom-ref values are not unique: {}", list_repr(duplicates))] }
}

fn walk(start: Vec<&Value>) -> Vec<&Value> {
    let mut found = Vec::new();
    let mut pending = start;
    while let Some(component) = pending.pop() {
        found.push(component);
        if let Some(children) = component.get("components").and_then(Value::as_array) {
            pending.extend(children);
        }
    }
    found
}

fn reference_problems(document: &Value) -> Vec<String> {
    let metadata = &document["metadata"];
    let root = &metadata["component"];
    let tools: &[Value] = metadata["tools"]["components"].as_array().map_or(&[], Vec::as_slice);
    let direct_components: &[Value] = document["components"].as_array().map_or(&[], Vec::as_slice);
    let mut start = vec![root];
    start.extend(direct_components);
    start.extend(tools);
    let components = walk(start);
    let mut nameless: Vec<&str> = components.iter().filter(|component| component.get("bom-ref").is_none()).filter_map(|component| component["name"].as_str()).collect();
    if !nameless.is_empty() {
        nameless.sort_unstable();
        return vec![format!("components lack a bom-ref: {}", list_repr(nameless))];
    }
    let reference = |value: &'_ Value| value.get("bom-ref").and_then(Value::as_str).map(str::to_owned).unwrap_or_default();
    let mut found = Vec::new();
    let mut dependencies: HashMap<String, BTreeSet<String>> = HashMap::new();
    for entry in document["dependencies"].as_array().map_or(&[][..], Vec::as_slice) {
        let key = entry["ref"].as_str().unwrap_or("").to_owned();
        let depends: BTreeSet<String> =
            entry.get("dependsOn").and_then(Value::as_array).map(|items| items.iter().filter_map(Value::as_str).map(str::to_owned).collect()).unwrap_or_default();
        dependencies.insert(key, depends);
    }
    let refs: BTreeSet<String> = components.iter().map(|component| reference(component)).collect();
    let mut named: BTreeSet<&String> = dependencies.keys().collect();
    for values in dependencies.values() {
        named.extend(values);
    }
    let unknown: Vec<&str> = named.into_iter().filter(|name| !refs.contains(*name)).map(String::as_str).collect();
    if !unknown.is_empty() {
        found.push(format!("dependencies reference bom-refs that do not exist: {}", list_repr(unknown)));
    }
    let direct: BTreeSet<String> = direct_components.iter().map(reference).collect();
    let root_ref = reference(root);
    if dependencies.get(&root_ref) != Some(&direct) {
        let listed: Vec<&str> = dependencies.get(&root_ref).map(|items| items.iter().map(String::as_str).collect()).unwrap_or_default();
        found.push(format!("root dependsOn {} != components {}", list_repr(listed), list_repr(direct.iter().map(String::as_str))));
    }
    let tool_refs: BTreeSet<String> = tools.iter().map(reference).collect();
    for formula in document.get("formulation").and_then(Value::as_array).map_or(&[][..], Vec::as_slice) {
        for workflow in formula.get("workflows").and_then(Value::as_array).map_or(&[][..], Vec::as_slice) {
            let referenced: BTreeSet<&str> = workflow
                .get("resourceReferences")
                .and_then(Value::as_array)
                .map(|items| items.iter().filter_map(|item| item.get("ref").and_then(Value::as_str)).collect())
                .unwrap_or_default();
            let unknown: Vec<&str> = referenced.into_iter().filter(|name| !tool_refs.contains(*name)).collect();
            if !unknown.is_empty() {
                let uid = workflow.get("uid").and_then(Value::as_str).unwrap_or("");
                found.push(format!("workflow {uid} references unknown tools: {}", list_repr(unknown)));
            }
        }
    }
    found
}

pub fn to_serde(value: &Json) -> Value {
    match value {
        Json::Null => Value::Null,
        Json::Bool(flag) => Value::Bool(*flag),
        Json::Num(text) => serde_json::from_str(text).unwrap_or(Value::Null),
        Json::Str(text) => Value::String(text.clone()),
        Json::Arr(items) => Value::Array(items.iter().map(to_serde).collect()),
        Json::Obj(object) => Value::Object(object.0.iter().map(|(key, item)| (key.clone(), to_serde(item))).collect()),
    }
}

/// `_is_sbom`: a document at the top level, or in any top-level .dist-info's sboms
fn is_sbom(name: &str) -> bool {
    let parts: Vec<&str> = name.split('/').collect();
    match parts.as_slice() {
        [file] => file.ends_with(".cdx.json"),
        [dist_info, "sboms", file] => dist_info.ends_with(".dist-info") && file.ends_with(".cdx.json"),
        _ => false,
    }
}

/// `validate`: a wheel or archive's SBOMs, or a document file
pub fn validate_artifact(path: &Path, allowed: Option<&[String]>, max_components: usize, version: &str) -> Result<Vec<String>> {
    let name = path.file_name().map(|name| name.to_string_lossy().into_owned()).unwrap_or_default();
    if !crate::zip::is_zipfile(path) {
        let raw = std::fs::read_to_string(path)?;
        let raw = if raw.contains('\r') { raw.replace("\r\n", "\n").replace('\r', "\n") } else { raw };
        return Ok(validate_document(&raw, allowed, max_components, version));
    }
    let opened = Opened::path(path, &name)?;
    let mut members: Vec<&str> = opened.archive.names().filter(|member| is_sbom(member)).collect();
    members.sort_unstable();
    if members.is_empty() {
        return Ok(vec![format!("no SBOM found in {name}")]);
    }
    let mut documents = Vec::with_capacity(members.len());
    for member in members {
        let raw = String::from_utf8(opened.read_member(member, SBOM_LIMIT)?)
            .map_err(|error| crate::error::Error::Value(format!("'utf-8' codec can't decode {member}: {error}")))?;
        documents.push((member, raw));
    }
    Ok(documents
        .iter()
        .flat_map(|(member, raw)| validate_document(raw, allowed, max_components, version).into_iter().map(move |problem| format!("{member}: {problem}")))
        .collect())
}
