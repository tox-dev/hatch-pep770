//! The CycloneDX document: components from core metadata, the build tools, and the document assembled around them,
//! with every object's keys in the order the Python implementation inserted them.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

use rayon::prelude::*;

use crate::addresses::getaddresses;
use crate::email::Metadata;
use crate::error::{Error, Result};
use crate::facts::Distribution;
use crate::json::{Json, Obj, dumps_sorted};
use crate::licenses::canonicalize_license_expression;
use crate::names::{
    SBOM_FILE, SBOM_REPOSITORY, project_urls, property_prefix, purl, pypi_purl, pypi_url, reference_type, sbom_file_name,
    tool_ref, url_netloc, url_scheme,
};
use crate::pep508::{applies_without_extras, format_marker, parse_requirement};
use crate::record::RecordRow;
use crate::wheel::BundledWheel;

#[derive(Clone, Default)]
pub struct Settings {
    pub supplier: Option<Json>,
    pub repository: Option<String>,
    pub default_branch: String,
    pub bundled_wheels: Vec<String>,
}

pub struct Interpreter {
    pub name: String,
    pub version: String,
    pub implementation: String,
}

pub struct Revision {
    pub commit: String,
    pub dirty: bool,
}

pub struct Facts {
    pub epoch: i64,
    pub epoch_from_environment: bool,
    pub revision: Option<Revision>,
    pub interpreter: Interpreter,
    pub distributions: Vec<Arc<Distribution>>,
}

pub struct BuildScript {
    pub path: String,
    pub sha256: String,
}

pub struct Request {
    pub metadata: Arc<Metadata>,
    pub wheel_name: String,
    pub settings: Settings,
}

pub struct Source {
    pub copyright: Option<String>,
    pub bundled: Vec<Arc<BundledWheel>>,
    pub build_scripts: Vec<BuildScript>,
}

#[derive(Clone, Default)]
pub struct BundledInfo {
    pub properties: Vec<Json>,
    pub supplier: Option<Json>,
}

#[derive(Default)]
pub struct Contributions {
    pub components: Vec<Json>,
    pub dependencies: Vec<Json>,
    pub root_properties: Vec<Json>,
    pub tools: Vec<Json>,
}

pub struct Identity {
    pub property_prefix: String,
    pub repository: Option<String>,
    pub serial_namespace: uuid::Uuid,
}

fn obj(pairs: Vec<(&str, Json)>) -> Json {
    Json::Obj(Obj(pairs.into_iter().map(|(key, value)| (key.to_owned(), value)).collect()))
}

fn property(name: impl Into<String>, value: impl Into<String>) -> Json {
    obj(vec![("name", Json::Str(name.into())), ("value", Json::Str(value.into()))])
}

fn optional_str(value: Option<&str>) -> Json {
    value.map_or(Json::Null, Json::str)
}

/// `project_identity`
pub fn project_identity(metadata: &Metadata, settings: &Settings) -> Identity {
    let project = property_prefix(metadata.get("Name").unwrap_or(""));
    let repository = settings.repository.clone().filter(|repository| !repository.is_empty()).or_else(|| {
        project_urls(metadata)
            .into_iter()
            .find(|(label, _)| reference_type(label) == "vcs")
            .map(|(_, url)| url.trim_end_matches('/').to_owned())
    });
    let base = repository.clone().filter(|repository| !repository.is_empty()).unwrap_or_else(|| format!("https://pypi.org/project/{project}"));
    Identity {
        serial_namespace: uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_URL, format!("{base}/sboms").as_bytes()),
        property_prefix: project,
        repository,
    }
}

/// `component_from_metadata`
pub fn component_from_metadata(metadata: &Metadata) -> Obj {
    let name = metadata.get("Name").unwrap_or("");
    let version = metadata.get("Version");
    let reference = pypi_purl(name, version);
    let mut component = Obj::with_capacity(12);
    component.push("type", Json::str("library"));
    component.push("bom-ref", Json::str(reference.clone()));
    component.push("name", Json::str(name));
    component.push("version", optional_str(version));
    component.push("purl", Json::Str(reference));
    if let Some(summary) = metadata.get("Summary").filter(|summary| !summary.is_empty()) {
        component.push("description", Json::str(summary));
    }
    // maintainers are who users reach today, so they win over the original authors when both are named
    for (names, addresses) in [("Maintainer", "Maintainer-email"), ("Author", "Author-email")] {
        let mut people: Vec<Json> = metadata.get_all(names).filter_map(|name| contact(name, "")).collect();
        people.extend(getaddresses(metadata.get_all(addresses)).iter().filter_map(|(name, email)| contact(name, email)));
        if !people.is_empty() {
            component.push("authors", Json::Arr(people));
            break;
        }
    }
    let declared = licenses(metadata);
    if !declared.is_empty() {
        component.push("licenses", Json::Arr(declared));
    }
    component.push("externalReferences", Json::Arr(project_references(metadata)));
    let mut properties = Vec::new();
    for header in ["Requires-Python", "Requires-Dist", "Provides-Extra", "Classifier", "Keywords"] {
        let key = format!("python:{}", header.to_lowercase());
        properties.extend(metadata.get_all(header).map(|value| property(key.clone(), value)));
    }
    component.push("properties", Json::Arr(properties));
    component
}

/// `_contact`: an address the schema rejects as an email is kept as the name
fn contact(name: &str, email: &str) -> Option<Json> {
    if !email.is_empty() && !is_email(email) {
        let joined: Vec<&str> = [name, email].into_iter().filter(|part| !part.is_empty()).collect();
        return Some(obj(vec![("name", Json::str(joined.join(" ")))]));
    }
    let mut contact = Vec::new();
    if !name.is_empty() {
        contact.push(("name", Json::str(name)));
    }
    if !email.is_empty() {
        contact.push(("email", Json::str(email)));
    }
    (!contact.is_empty()).then(|| obj(contact))
}

/// `re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email)`
fn is_email(email: &str) -> bool {
    if email.chars().any(|character| character.is_whitespace() || ('\x1c'..='\x1f').contains(&character)) {
        return false;
    }
    let mut parts = email.split('@');
    let (Some(local), Some(domain), None) = (parts.next(), parts.next(), parts.next()) else { return false };
    // the domain needs a dot with something on both sides, backtracking to any dot
    !local.is_empty() && domain.char_indices().any(|(index, character)| character == '.' && index > 0 && index + 1 < domain.len())
}

/// `_project_references`
fn project_references(metadata: &Metadata) -> Vec<Json> {
    let mut references = Vec::new();
    if let Some(home) = metadata.get("Home-page").filter(|home| !home.is_empty())
        && matches!(url_scheme(home).as_str(), "http" | "https")
    {
        references.push(obj(vec![("type", Json::str("website")), ("url", Json::str(home))]));
    }
    for (label, url) in project_urls(metadata) {
        references.push(obj(vec![
            ("type", Json::str(reference_type(label))),
            ("url", Json::str(url)),
            ("comment", Json::Str(format!("Project-URL: {label}"))),
        ]));
    }
    references
}

/// `licenses`: a License-Expression as declared, or the License field and classifiers with the SPDX ids they map to
pub fn licenses(metadata: &Metadata) -> Vec<Json> {
    let license = |inner: Vec<(&str, Json)>| obj(vec![("license", obj(inner))]);
    if let Some(expression) = metadata.get("License-Expression").filter(|expression| !expression.is_empty()) {
        return vec![match canonicalize_license_expression(expression) {
            Ok(canonical) => obj(vec![("expression", Json::Str(canonical)), ("acknowledgement", Json::str("declared"))]),
            Err(_) => license(vec![("name", Json::str(expression)), ("acknowledgement", Json::str("declared"))]),
        }];
    }
    let mut names: Vec<&str> = metadata
        .get_all("Classifier")
        .filter(|entry| entry.starts_with("License :: "))
        .map(|entry| entry.rsplit_once(" :: ").map_or(entry, |(_, last)| last))
        .collect();
    if let Some(declared) = metadata.get("License").filter(|declared| !declared.is_empty() && !declared.contains('\n')) {
        names.push(declared);
    }
    let mut found: Vec<Json> =
        names.iter().map(|name| license(vec![("name", Json::str(*name)), ("acknowledgement", Json::str("declared"))])).collect();
    let identifiers: Vec<String> = names.iter().filter_map(|name| spdx_license(name)).collect();
    if identifiers.len() == names.len() {
        let mut seen = BTreeSet::new();
        for identifier in identifiers {
            if seen.insert(identifier.clone()) {
                found.push(license(vec![("id", Json::Str(identifier)), ("acknowledgement", Json::str("concluded"))]));
            }
        }
    }
    found
}

/// `_spdx_license`: the one SPDX license a classifier or License value names, if any
fn spdx_license(name: &str) -> Option<String> {
    let mapped = match name {
        "ISC License (ISCL)" => Some("ISC"),
        "MIT License" => Some("MIT"),
        "MIT No Attribution License (MIT-0)" => Some("MIT-0"),
        "Mozilla Public License 2.0 (MPL 2.0)" => Some("MPL-2.0"),
        "Python Software Foundation License" => Some("PSF-2.0"),
        "The Unlicense (Unlicense)" => Some("Unlicense"),
        _ => None,
    };
    if let Some(identifier) = mapped {
        return Some(identifier.to_owned());
    }
    let canonical = canonicalize_license_expression(name).ok()?;
    (!canonical.is_empty()
        && canonical.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
        && !canonical.starts_with("LicenseRef-"))
    .then_some(canonical)
}

fn evidence(field: &str, technique: &str, value: &str) -> Json {
    obj(vec![
        ("field", Json::str(field)),
        ("confidence", Json::int(1)),
        ("methods", Json::Arr(vec![obj(vec![("technique", Json::str(technique)), ("confidence", Json::int(1)), ("value", Json::str(value))])])),
    ])
}

/// `file_component`
pub fn file_component(parent: &str, row: &RecordRow) -> Json {
    let mut component = Obj::with_capacity(5);
    component.push("type", Json::str("file"));
    component.push("bom-ref", Json::Str(format!("{parent}#{}", row.path)));
    component.push("name", Json::str(row.path.as_str()));
    component.push("hashes", Json::Arr(vec![obj(vec![("alg", Json::str(row.algorithm.as_str())), ("content", Json::str(row.digest.as_str()))])]));
    component.push("properties", Json::Arr(vec![property("size", row.size.as_str())]));
    Json::Obj(component)
}

fn file_components(parent: &str, rows: &[RecordRow]) -> Vec<Json> {
    if rows.len() > 512 {
        rows.par_iter().map(|row| file_component(parent, row)).collect()
    } else {
        rows.iter().map(|row| file_component(parent, row)).collect()
    }
}

fn take_arr(component: &mut Obj, key: &str) -> Vec<Json> {
    match component.get_mut(key) {
        Some(Json::Arr(items)) => std::mem::take(items),
        _ => Vec::new(),
    }
}

/// `bundled_wheel_component`
pub fn bundled_wheel_component(wheel: &BundledWheel, namespace: &str, properties: &[Json], supplier: Option<&Json>) -> Json {
    let metadata = &wheel.metadata;
    let mut component = component_from_metadata(metadata);
    let reference = format!("bundled:{}", wheel.path);
    component.set("bom-ref", Json::str(reference.clone()));
    if let Some(supplier) = supplier {
        component.set("supplier", supplier.clone());
    }
    component.set("hashes", Json::Arr(vec![obj(vec![("alg", Json::str("SHA-256")), ("content", Json::str(wheel.sha256.as_str()))])]));
    let mut references = take_arr(&mut component, "externalReferences");
    references.push(obj(vec![
        ("type", Json::str("distribution")),
        ("url", Json::Str(pypi_url(metadata.get("Name").unwrap_or(""), metadata.get("Version")))),
    ]));
    component.set("externalReferences", Json::Arr(references));
    let own = take_arr(&mut component, "properties");
    let mut combined = Vec::with_capacity(1 + properties.len() + own.len());
    combined.push(property(format!("{namespace}:bundled-wheel"), wheel.path.as_str()));
    combined.extend(properties.iter().cloned());
    combined.extend(own);
    component.set("properties", Json::Arr(combined));
    component.set(
        "evidence",
        obj(vec![("identity", Json::Arr(vec![evidence("purl", "manifest-analysis", &wheel.metadata_name), evidence("hash", "hash-comparison", &wheel.sha256)]))]),
    );
    let mut vendored: BTreeMap<String, Json> = BTreeMap::new();
    for (source, metadata) in &wheel.vendored {
        let mut child = component_from_metadata(metadata);
        let child_ref = child.str("bom-ref").unwrap_or("").to_owned();
        child.set("bom-ref", Json::Str(format!("{reference}#vendored/{child_ref}")));
        let mut child_properties = take_arr(&mut child, "properties");
        child_properties.push(property(format!("{namespace}:vendored-manifest"), source.as_str()));
        child.set("properties", Json::Arr(child_properties));
        child.set("evidence", obj(vec![("identity", Json::Arr(vec![evidence("purl", "manifest-analysis", source)]))]));
        let key = format!("{}=={}", property_prefix(child.str("name").unwrap_or("")), child.str("version").unwrap_or("None"));
        vendored.insert(key, Json::Obj(child));
    }
    let mut children = file_components(&reference, &wheel.files);
    children.extend(vendored.into_values());
    component.set("components", Json::Arr(children));
    Json::Obj(component)
}

fn bom_ref(component: &Json) -> Result<&str> {
    component.as_obj().and_then(|object| object.str("bom-ref")).ok_or_else(|| Error::Key("'bom-ref'".to_owned()))
}

/// `vendored_dependencies`: each bundled wheel depends on the packages it vendors, wherever it sits in the document
pub fn vendored_dependencies(components: &[Json]) -> Result<Vec<Json>> {
    let mut found = Vec::new();
    let mut pending: std::collections::VecDeque<&Json> = components.iter().collect();
    while let Some(component) = pending.pop_front() {
        let children: &[Json] = component.as_obj().and_then(|object| object.arr("components")).unwrap_or(&[]);
        let reference = bom_ref(component)?;
        if reference.starts_with("bundled:") {
            let mut vendored = Vec::new();
            for child in children {
                let child_ref = bom_ref(child)?;
                if child.as_obj().and_then(|object| object.str("type")) == Some("library") && child_ref.contains("#vendored/") {
                    vendored.push(Json::str(child_ref));
                }
            }
            if !vendored.is_empty() {
                found.push(obj(vec![("ref", Json::str(reference)), ("dependsOn", Json::Arr(vendored))]));
            }
        }
        pending.extend(children);
    }
    Ok(found)
}

/// `script_tool`
pub fn script_tool(path: &str, sha256: &str, version: Option<&str>, link: Option<String>) -> Json {
    let name = path.trim_end_matches('/').rsplit('/').next().unwrap_or("");
    let mut tool = Obj::with_capacity(6);
    tool.push("type", Json::str("application"));
    tool.push("bom-ref", Json::Str(tool_ref(path)));
    tool.push("name", Json::str(name));
    tool.push("version", optional_str(version));
    tool.push("hashes", Json::Arr(vec![obj(vec![("alg", Json::str("SHA-256")), ("content", Json::str(sha256))])]));
    if let Some(link) = link {
        tool.push("externalReferences", Json::Arr(vec![obj(vec![("type", Json::str("vcs")), ("url", Json::Str(link))])]));
    }
    Json::Obj(tool)
}

/// `tool_components`: the interpreter and every installed distribution, with their dependencies on each other
pub fn tool_components(facts: &Facts) -> (Vec<Json>, Vec<Json>) {
    let interpreter = &facts.interpreter;
    let package = purl("generic", &interpreter.name, Some(&interpreter.version));
    let mut tools = vec![obj(vec![
        ("type", Json::str("platform")),
        ("bom-ref", Json::Str(tool_ref(&package))),
        ("name", Json::str(interpreter.name.as_str())),
        ("version", Json::str(interpreter.version.as_str())),
        ("purl", Json::Str(package)),
        ("properties", Json::Arr(vec![property("python:implementation", interpreter.implementation.as_str())])),
    ])];
    let refs: HashMap<&str, String> = facts
        .distributions
        .iter()
        .map(|distribution| (distribution.name.as_str(), tool_ref(&pypi_purl(&distribution.name, distribution.metadata.get("Version")))))
        .collect();
    let mut ordered: Vec<&Arc<Distribution>> = facts.distributions.iter().collect();
    ordered.sort_by(|left, right| left.name.cmp(&right.name));
    let built: Vec<(Json, Json)> = ordered
        .par_iter()
        .map(|distribution| {
            let reference = refs[distribution.name.as_str()].clone();
            let mut component = component_from_metadata(&distribution.metadata);
            component.set("bom-ref", Json::str(reference.clone()));
            if !distribution.files.is_empty() {
                component.set("components", Json::Arr(file_components(&reference, &distribution.files)));
            }
            let mut depends: Vec<&String> = distribution.depends_on.iter().filter_map(|name| refs.get(name.as_str())).collect();
            depends.sort();
            let dependency =
                obj(vec![("ref", Json::Str(reference)), ("dependsOn", Json::Arr(depends.into_iter().map(|item| Json::str(item.as_str())).collect()))]);
            (Json::Obj(component), dependency)
        })
        .collect();
    let mut dependencies = Vec::with_capacity(built.len());
    for (tool, dependency) in built {
        tools.push(tool);
        dependencies.push(dependency);
    }
    (tools, dependencies)
}

/// the UTC calendar time of a Unix time: year, month, day, hour, minute, second
pub fn civil(epoch: i64) -> [i64; 6] {
    let days = epoch.div_euclid(86_400);
    let seconds = epoch.rem_euclid(86_400);
    // Howard Hinnant's days-to-civil
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era = (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 { month_index + 3 } else { month_index - 9 };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    [year, month, day, seconds / 3600, seconds % 3600 / 60, seconds % 60]
}

/// `datetime.fromtimestamp(epoch, tz=UTC).isoformat()`
pub fn timestamp(epoch: i64) -> String {
    let [year, month, day, hour, minute, second] = civil(epoch);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}+00:00")
}

/// `formulation`
pub fn formulation(uid: &str, name: &str, tools: &[Json], output: &str, facts: &Facts) -> Result<Json> {
    let mut resources = Vec::with_capacity(tools.len());
    for tool in tools {
        resources.push(obj(vec![("ref", Json::str(bom_ref(tool)?))]));
    }
    let mut workflow = Obj::with_capacity(7);
    workflow.push("bom-ref", Json::Str(format!("workflow:{uid}")));
    workflow.push("uid", Json::str(uid));
    workflow.push("name", Json::str(name));
    workflow.push("taskTypes", Json::Arr(vec![Json::str("build")]));
    workflow.push("resourceReferences", Json::Arr(resources));
    workflow.push("outputs", Json::Arr(vec![obj(vec![("type", Json::str("artifact")), ("resource", obj(vec![("ref", Json::str(output))]))])]));
    if facts.epoch_from_environment {
        workflow.push(
            "inputs",
            Json::Arr(vec![obj(vec![("environmentVars", Json::Arr(vec![property("SOURCE_DATE_EPOCH", facts.epoch.to_string())]))])]),
        );
    }
    Ok(obj(vec![("bom-ref", Json::Str(format!("formula:{uid}"))), ("workflows", Json::Arr(vec![Json::Obj(workflow)]))]))
}

/// `contributed_properties`
pub fn contributed_properties(properties: &[Json], prefix: &str) -> Result<Vec<Json>> {
    let start = format!("{prefix}:");
    let mut claimed: Vec<&str> = Vec::new();
    for prop in properties {
        let name = prop.as_obj().and_then(|object| object.str("name")).ok_or_else(|| Error::Key("'name'".to_owned()))?;
        if name.starts_with(&start) {
            claimed.push(name);
        }
    }
    if !claimed.is_empty() {
        claimed.sort_unstable();
        return Err(Error::Sbom(format!(
            "contributed root properties {} use the {prefix}: prefix python-sbom writes",
            claimed.join(", ")
        )));
    }
    Ok(properties.to_vec())
}

/// `with_header`: the document checked for repeated and unknown bom-refs, then given its content-derived serial
pub fn with_header(body: Obj, namespace: &uuid::Uuid) -> Result<Json> {
    let mut counts: HashMap<&str, usize> = HashMap::new();
    {
        let metadata = body.get("metadata").and_then(Json::as_obj).ok_or_else(|| Error::Key("'metadata'".to_owned()))?;
        let mut pending: Vec<&Json> = Vec::new();
        pending.push(metadata.get("component").ok_or_else(|| Error::Key("'component'".to_owned()))?);
        pending.extend(body.arr("components").unwrap_or(&[]));
        pending.extend(metadata.get("tools").and_then(Json::as_obj).and_then(|tools| tools.arr("components")).unwrap_or(&[]));
        while let Some(component) = pending.pop() {
            *counts.entry(bom_ref(component)?).or_default() += 1;
            pending.extend(component.as_obj().and_then(|object| object.arr("components")).unwrap_or(&[]));
        }
        let mut repeated: Vec<&str> = counts.iter().filter(|(_, count)| **count > 1).map(|(reference, _)| *reference).collect();
        if !repeated.is_empty() {
            repeated.sort_unstable();
            return Err(Error::Sbom(format!("bom-ref values repeat: {}", repeated.join(", "))));
        }
        let mut named = BTreeSet::new();
        for entry in body.arr("dependencies").unwrap_or(&[]) {
            let entry = entry.as_obj().ok_or_else(|| Error::Type("dependency is not an object".to_owned()))?;
            named.insert(entry.str("ref").ok_or_else(|| Error::Key("'ref'".to_owned()))?);
            for item in entry.arr("dependsOn").unwrap_or(&[]) {
                named.insert(item.as_str().unwrap_or(""));
            }
        }
        let unknown: Vec<&str> = named.into_iter().filter(|reference| !counts.contains_key(reference)).collect();
        if !unknown.is_empty() {
            return Err(Error::Sbom(format!("dependencies name bom-refs no component has: {}", unknown.join(", "))));
        }
    }
    let body = Json::Obj(body);
    let serial = uuid::Uuid::new_v5(namespace, &dumps_sorted(&body));
    let Json::Obj(body) = body else { unreachable!() };
    let mut document = Obj::with_capacity(5 + body.0.len());
    document.push("$schema", Json::str("http://cyclonedx.org/schema/bom-1.6.schema.json"));
    document.push("bomFormat", Json::str("CycloneDX"));
    document.push("specVersion", Json::str("1.6"));
    document.push("serialNumber", Json::Str(format!("urn:uuid:{serial}")));
    document.push("version", Json::int(1));
    for (key, value) in body.0 {
        document.set(&key, value);
    }
    Ok(Json::Obj(document))
}

/// `PurePosixPath(pattern).parent`
fn posix_parent(pattern: &str) -> String {
    let absolute = pattern.starts_with('/');
    let parts: Vec<&str> = pattern.split('/').filter(|part| !part.is_empty() && *part != ".").collect();
    let anchor = if pattern.starts_with("//") && !pattern.starts_with("///") { "//" } else if absolute { "/" } else { "" };
    if parts.len() <= 1 {
        return if anchor.is_empty() { ".".to_owned() } else { anchor.to_owned() };
    }
    format!("{anchor}{}", parts[..parts.len() - 1].join("/"))
}

fn scope(settings: &Settings) -> String {
    let declared = "the direct runtime dependencies declared in the wheel's core metadata, which carry no version because the installer resolves them";
    let directories: BTreeSet<String> = settings.bundled_wheels.iter().map(|pattern| posix_parent(pattern)).collect();
    if directories.is_empty() {
        return format!("Components are {declared}.");
    }
    format!("Components are the wheels bundled as data files under {} and {declared}.", directories.into_iter().collect::<Vec<_>>().join(" and "))
}

fn file_link(identity: &Identity, settings: &Settings, path: &str) -> Option<String> {
    identity.repository.as_ref().map(|repository| format!("{repository}/blob/{}/{path}", settings.default_branch))
}

fn declared_dependency(text: &str, namespace: &str) -> Result<Option<Json>> {
    let requirement = parse_requirement(text).map_err(Error::InvalidRequirement)?;
    if let Some(marker) = &requirement.marker
        && !applies_without_extras(marker)
    {
        return Ok(None);
    }
    let mut properties = vec![property(format!("{namespace}:requires-dist"), text)];
    if let Some(marker) = &requirement.marker {
        properties.push(property(format!("{namespace}:environment-marker"), format_marker(marker).map_err(Error::Value)?));
    }
    Ok(Some(obj(vec![
        ("type", Json::str("library")),
        ("bom-ref", Json::Str(format!("requires-dist:{text}"))),
        ("name", Json::str(requirement.name.as_str())),
        ("purl", Json::Str(pypi_purl(&requirement.name, None))),
        ("externalReferences", Json::Arr(vec![obj(vec![("type", Json::str("distribution")), ("url", Json::Str(pypi_url(&requirement.name, None)))])])),
        ("properties", Json::Arr(properties)),
    ])))
}

fn root_component(request: &Request, source: &Source, facts: &Facts, identity: &Identity, contributions: &Contributions) -> Result<Obj> {
    let metadata = &request.metadata;
    let settings = &request.settings;
    let name = metadata.get("Name").unwrap_or("");
    let version = metadata.get("Version");
    let mut root = component_from_metadata(metadata);
    root.set("type", Json::str("application"));
    if let Some(supplier) = &settings.supplier {
        root.set("supplier", supplier.clone());
    }
    if let Some(copyright) = &source.copyright {
        root.set("copyright", Json::str(copyright.as_str()));
    }
    let mut references = take_arr(&mut root, "externalReferences");
    references.push(obj(vec![("type", Json::str("distribution")), ("url", Json::Str(pypi_url(name, version)))]));
    references.push(obj(vec![
        ("type", Json::str("attestation")),
        ("url", Json::Str(format!("https://pypi.org/integrity/{name}/{}/{}/provenance", version.unwrap_or("None"), request.wheel_name))),
    ]));
    if let Some(repository) = identity.repository.as_deref().filter(|repository| !repository.is_empty())
        && url_netloc(repository) == "github.com"
    {
        references.push(obj(vec![("type", Json::str("security-contact")), ("url", Json::Str(format!("{repository}/security/policy")))]));
        references.push(obj(vec![("type", Json::str("advisories")), ("url", Json::Str(format!("{repository}/security/advisories")))]));
    }
    if let Some(first) = metadata.get_all("License-File").next()
        && let Some(link) = file_link(identity, settings, first)
    {
        references.push(obj(vec![("type", Json::str("license")), ("url", Json::Str(link))]));
    }
    let mut properties = take_arr(&mut root, "properties");
    properties.extend(contributed_properties(&contributions.root_properties, &identity.property_prefix)?);
    if let Some(revision) = &facts.revision {
        if let Some(repository) = identity.repository.as_deref().filter(|repository| !repository.is_empty()) {
            let comment = if revision.dirty { "source revision, with uncommitted changes" } else { "exact source revision" };
            references.push(obj(vec![
                ("type", Json::str("vcs")),
                ("url", Json::Str(format!("{repository}/tree/{}", revision.commit))),
                ("comment", Json::str(comment)),
            ]));
        }
        properties.push(property(format!("{}:vcs-commit", identity.property_prefix), revision.commit.as_str()));
        if revision.dirty {
            properties.push(property(format!("{}:vcs-dirty", identity.property_prefix), "true"));
        }
    }
    root.set("externalReferences", Json::Arr(references));
    root.set("properties", Json::Arr(properties));
    Ok(root)
}

/// `describe`: the wheel's document
pub fn describe(request: &Request, source: &Source, facts: &Facts, bundled_info: &HashMap<String, BundledInfo>, contributions: Contributions) -> Result<Json> {
    let identity = project_identity(&request.metadata, &request.settings);
    let root = root_component(request, source, facts, &identity, &contributions)?;
    let root_ref = root.str("bom-ref").unwrap_or("").to_owned();
    let mut bundled = Vec::with_capacity(source.bundled.len());
    for wheel in &source.bundled {
        let info = bundled_info.get(&wheel.path).ok_or_else(|| Error::Key(crate::pyrepr::repr(&wheel.path)))?;
        bundled.push(bundled_wheel_component(wheel, &identity.property_prefix, &info.properties, info.supplier.as_ref()));
    }
    let vendored = vendored_dependencies(&bundled)?;
    let mut components = bundled;
    let mut seen = BTreeSet::new();
    for text in request.metadata.get_all("Requires-Dist") {
        if seen.insert(text)
            && let Some(component) = declared_dependency(text, &identity.property_prefix)?
        {
            components.push(component);
        }
    }
    components.extend(contributions.components);
    let (environment, tool_dependencies) = tool_components(facts);
    let version = request.metadata.get("Version");
    let mut tools = Vec::with_capacity(source.build_scripts.len() + environment.len() + contributions.tools.len());
    for script in &source.build_scripts {
        tools.push(script_tool(&script.path, &script.sha256, version, file_link(&identity, &request.settings, &script.path)));
    }
    tools.extend(environment);
    tools.extend(contributions.tools);
    let mut dependencies = Vec::with_capacity(2 + vendored.len() + tool_dependencies.len() + contributions.dependencies.len());
    let mut direct = Vec::with_capacity(components.len());
    for component in &components {
        direct.push(Json::str(bom_ref(component)?));
    }
    dependencies.push(obj(vec![("ref", Json::str(root_ref.as_str())), ("dependsOn", Json::Arr(direct))]));
    dependencies.extend(vendored);
    dependencies.extend(tool_dependencies);
    dependencies.extend(contributions.dependencies);
    let formula = formulation("wheel-build", "build the wheel and this SBOM", &tools, &root_ref, facts)?;
    let metadata = metadata_block(root, tools, request, &identity, facts);
    let mut body = Obj::with_capacity(5);
    body.push("metadata", metadata);
    body.push("components", Json::Arr(components));
    body.push("dependencies", Json::Arr(dependencies));
    body.push("compositions", Json::Arr(vec![obj(vec![("aggregate", Json::str("incomplete")), ("dependencies", Json::Arr(vec![Json::Str(root_ref)]))])]));
    body.push("formulation", Json::Arr(vec![formula]));
    with_header(body, &identity.serial_namespace)
}

fn metadata_block(root: Obj, tools: Vec<Json>, request: &Request, identity: &Identity, facts: &Facts) -> Json {
    let settings = &request.settings;
    let authors = root.get("authors").cloned();
    let licenses = root.get("licenses").cloned();
    let mut metadata = Obj::with_capacity(9);
    metadata.push("timestamp", Json::Str(timestamp(facts.epoch)));
    metadata.push("lifecycles", Json::Arr(vec![obj(vec![("phase", Json::str("build"))])]));
    metadata.push("tools", obj(vec![("components", Json::Arr(tools))]));
    metadata.push("component", Json::Obj(root));
    if let Some(supplier) = &settings.supplier {
        metadata.push("manufacturer", supplier.clone());
        metadata.push("supplier", supplier.clone());
    }
    if let Some(authors) = authors {
        metadata.push("authors", authors);
    }
    if let Some(licenses) = licenses {
        metadata.push("licenses", licenses);
    }
    let prefix = &identity.property_prefix;
    let mut properties = vec![
        property(format!("{prefix}:sbom:scope"), scope(settings)),
        property(format!("{prefix}:{SBOM_FILE}"), sbom_file_name(request.metadata.get("Name").unwrap_or(""))),
    ];
    if let Some(repository) = &identity.repository {
        properties.push(property(format!("{prefix}:{SBOM_REPOSITORY}"), repository.as_str()));
    }
    metadata.push("properties", Json::Arr(properties));
    Json::Obj(metadata)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn times() {
        assert_eq!(timestamp(1_700_000_000), "2023-11-14T22:13:20+00:00");
        assert_eq!(timestamp(0), "1970-01-01T00:00:00+00:00");
        assert_eq!(timestamp(1_580_601_600), "2020-02-02T00:00:00+00:00");
        assert_eq!(timestamp(-1), "1969-12-31T23:59:59+00:00");
    }

    #[test]
    fn parents() {
        assert_eq!(posix_parent("src/pkg/wheels/*.whl"), "src/pkg/wheels");
        assert_eq!(posix_parent("*.whl"), ".");
        assert_eq!(posix_parent("./a//b/*.whl"), "a/b");
        assert!(is_email("a@b.c"));
        assert!(!is_email("not-an-email"));
        assert!(!is_email("a@b"));
        assert!(!is_email("a@.c"));
    }
}
