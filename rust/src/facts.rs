//! The distributions installed in the build environment, read straight from their .dist-info directories as
//! `importlib.metadata.distributions` finds them.

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rayon::prelude::*;

use crate::email::Metadata;
use crate::error::{Error, Result};
use crate::pep508::{canonicalize_name, evaluate, parse_requirement};
use crate::pyrepr::repr;
use crate::record::{RecordEntry, RecordRow, decode_digest, parse_record};

pub struct Distribution {
    /// the normalized name
    pub name: String,
    pub metadata: Arc<Metadata>,
    pub files: Arc<Vec<RecordRow>>,
    pub depends_on: Vec<String>,
}

/// a warning `warnings.warn` reports for one distribution, in the order the Python reader raised them
pub enum Warning {
    Message(String),
    /// direct_url.json that is not JSON: Python's json module words the error, so it is left to the caller
    DirectUrlNotJson { name: String, text: String },
}

struct Candidate {
    path: PathBuf,
    metadata: Metadata,
}

/// `read_text`: a file of the distribution with universal newlines, or `None` as importlib suppresses its errors
fn read_text(directory: &Path, name: &str) -> Option<String> {
    let path = if name.is_empty() { directory.to_path_buf() } else { directory.join(name) };
    let bytes = std::fs::read(path).ok()?;
    let text = String::from_utf8(bytes).ok()?;
    Some(if text.contains('\r') { text.replace("\r\n", "\n").replace('\r', "\n") } else { text })
}

/// the .dist-info and .egg-info entries of one path entry, grouped by name in first-seen order as importlib's Lookup
/// groups them
fn candidates(root: &str) -> Vec<PathBuf> {
    let directory = if root.is_empty() { Path::new(".") } else { Path::new(root) };
    let Ok(listing) = std::fs::read_dir(directory) else { return Vec::new() };
    let mut groups: Vec<(String, Vec<PathBuf>)> = Vec::new();
    let mut index: HashMap<String, usize> = HashMap::new();
    for child in listing.flatten() {
        let name = child.file_name();
        let Some(name) = name.to_str() else { continue };
        let low = name.to_lowercase();
        if !(low.ends_with(".dist-info") || low.ends_with(".egg-info")) {
            continue;
        }
        let stem = low.rsplit_once('.').map_or(low.as_str(), |(stem, _)| stem);
        let project = stem.split('-').next().unwrap_or("");
        let key = prepared_normalize(project);
        let slot = *index.entry(key.clone()).or_insert_with(|| {
            groups.push((key, Vec::new()));
            groups.len() - 1
        });
        groups[slot].1.push(directory.join(name));
    }
    groups.into_iter().flat_map(|(_, paths)| paths).collect()
}

/// `Prepared.normalize`
fn prepared_normalize(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut run = false;
    for character in name.chars() {
        if matches!(character, '-' | '_' | '.') {
            run = true;
            continue;
        }
        if run {
            out.push('_');
            run = false;
        }
        out.extend(character.to_lowercase());
    }
    if run {
        out.push('_');
    }
    out
}

fn installed_metadata(path: &Path) -> Option<Metadata> {
    let text = read_text(path, "METADATA")
        .filter(|text| !text.is_empty())
        .or_else(|| read_text(path, "PKG-INFO").filter(|text| !text.is_empty()))
        .or_else(|| read_text(path, "").filter(|text| !text.is_empty()))?;
    Some(Metadata::parse_installed(&text))
}

/// `_installed`: every distribution on `paths`, the first of each name winning, with its files and the installed
/// distributions it depends on in `environment`
pub fn collect(paths: &[String], environment: &HashMap<String, String>) -> Result<(Vec<Distribution>, Vec<Vec<Warning>>)> {
    let found: Vec<PathBuf> = paths.par_iter().map(|root| candidates(root)).collect::<Vec<_>>().into_iter().flatten().collect();
    let parsed: Vec<Option<Candidate>> =
        found.into_par_iter().map(|path| installed_metadata(&path).map(|metadata| Candidate { path, metadata })).collect();
    let mut seen = BTreeSet::new();
    let mut kept: Vec<(String, Candidate)> = Vec::new();
    for candidate in parsed.into_iter().flatten() {
        if !(candidate.metadata.contains("Name") && candidate.metadata.contains("Version")) {
            continue;
        }
        let name = canonicalize_name(candidate.metadata.get("Name").unwrap_or(""));
        if seen.insert(name.clone()) {
            kept.push((name, candidate));
        }
    }
    let installed: BTreeSet<&str> = kept.iter().map(|(name, _)| name.as_str()).collect();
    let results: Vec<Result<(Distribution, Vec<Warning>)>> = kept
        .par_iter()
        .map(|(name, candidate)| {
            let mut warnings = Vec::new();
            let files = recorded_files(candidate, &mut warnings)?;
            let depends_on = depends_on(name, candidate, &installed, environment, &mut warnings)?;
            Ok((
                Distribution { name: name.clone(), metadata: Arc::new(candidate.metadata.clone()), files: Arc::new(files), depends_on },
                warnings,
            ))
        })
        .collect();
    let mut distributions = Vec::with_capacity(results.len());
    let mut warnings = Vec::with_capacity(results.len());
    for result in results {
        let (distribution, raised) = result?;
        distributions.push(distribution);
        warnings.push(raised);
    }
    Ok((distributions, warnings))
}

fn display_name(candidate: &Candidate) -> &str {
    candidate.metadata.get("Name").unwrap_or("")
}

/// `_recorded_files`: what a pure, non-editable install recorded, without the files that describe the install itself
fn recorded_files(candidate: &Candidate, warnings: &mut Vec<Warning>) -> Result<Vec<RecordRow>> {
    let wheel = Metadata::parse(&read_text(&candidate.path, "WHEEL").unwrap_or_default());
    if wheel.get("Root-Is-Purelib") != Some("true") || editable(candidate, warnings) {
        return Ok(Vec::new());
    }
    let text = read_text(&candidate.path, "RECORD").unwrap_or_default();
    let rows = match parse_record(&text) {
        Ok(rows) => rows,
        Err(error) => {
            warnings.push(malformed(candidate, &error.message()));
            return Ok(Vec::new());
        }
    };
    let mut entries = Vec::with_capacity(rows.len());
    for row in &rows {
        match RecordEntry::from_elements(row) {
            Ok(entry) => entries.push(entry),
            Err(error) => {
                warnings.push(malformed(candidate, &error.message()));
                return Ok(Vec::new());
            }
        }
    }
    let mut files = Vec::with_capacity(entries.len());
    for entry in entries {
        let Some((name, value)) = entry.hash else { continue };
        if !describes_distribution(entry.path) {
            continue;
        }
        let (algorithm, digest) = decode_digest(&format!("{name}={value}"), entry.path)?;
        files.push(RecordRow { path: entry.path.to_owned(), algorithm: algorithm.to_owned(), digest, size: entry.size_text() });
    }
    Ok(files)
}

fn malformed(candidate: &Candidate, message: &str) -> Warning {
    Warning::Message(format!("listed no files of {}, its RECORD is malformed: {message}", display_name(candidate)))
}

/// `_describes_distribution`
fn describes_distribution(path: &str) -> bool {
    let (directory, name) = path.rsplit_once('/').unwrap_or(("", path));
    !(path.starts_with("../")
        || (directory.ends_with(".dist-info") && matches!(name, "INSTALLER" | "REQUESTED" | "direct_url.json"))
        || (name.starts_with("uv_") && name.ends_with(".json") && !name.contains('\n')))
}

/// `_editable`: direct_url.json read as packaging's DirectUrl validates it
fn editable(candidate: &Candidate, warnings: &mut Vec<Warning>) -> bool {
    let Some(text) = read_text(&candidate.path, "direct_url.json") else { return false };
    let value: serde_json::Value = match serde_json::from_str(&text) {
        Ok(value) => value,
        Err(_) => {
            warnings.push(Warning::DirectUrlNotJson { name: display_name(candidate).to_owned(), text });
            return false;
        }
    };
    match direct_url_editable(&value) {
        Ok(editable) => editable,
        Err(error) => {
            warnings.push(Warning::Message(format!("read the direct_url.json of {} as not editable: {error}", display_name(candidate))));
            false
        }
    }
}

fn type_name(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "NoneType",
        serde_json::Value::Bool(_) => "bool",
        serde_json::Value::Number(number) if number.is_f64() => "float",
        serde_json::Value::Number(_) => "int",
        serde_json::Value::String(_) => "str",
        serde_json::Value::Array(_) => "list",
        serde_json::Value::Object(_) => "dict",
    }
}

struct Invalid {
    message: String,
    context: Option<String>,
}

impl std::fmt::Display for Invalid {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.context {
            Some(context) => write!(formatter, "{} in {}", self.message, repr(context)),
            None => formatter.write_str(&self.message),
        }
    }
}

fn invalid(message: impl Into<String>, context: &str) -> Invalid {
    Invalid { message: message.into(), context: Some(context.to_owned()) }
}

fn within(error: Invalid, key: &str) -> Invalid {
    Invalid { message: error.message, context: Some(error.context.map_or_else(|| key.to_owned(), |inner| format!("{key}.{inner}"))) }
}

type Object = serde_json::Map<String, serde_json::Value>;

fn get<'a>(object: &'a Object, key: &str, expected: &str) -> std::result::Result<Option<&'a serde_json::Value>, Invalid> {
    match object.get(key) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(value) if type_name(value) == expected => Ok(Some(value)),
        Some(value) => Err(invalid(format!("Unexpected type {} (expected {})", type_name(value), match expected {
            "dict" => "Mapping",
            other => other,
        }), key)),
    }
}

fn required<'a>(object: &'a Object, key: &str, expected: &str) -> std::result::Result<&'a serde_json::Value, Invalid> {
    get(object, key, expected)?.ok_or_else(|| invalid("Missing required value", key))
}

/// `DirectUrl.from_dict(...).dir_info.editable is True`
fn direct_url_editable(value: &serde_json::Value) -> std::result::Result<bool, Invalid> {
    let serde_json::Value::Object(object) = value else {
        return Err(Invalid { message: format!("'{}' object has no attribute 'get'", type_name(value)), context: None });
    };
    let url = required(object, "url", "str")?.as_str().unwrap_or("");
    let archive = get(object, "archive_info", "dict")?;
    if let Some(serde_json::Value::Object(archive)) = archive {
        archive_info(archive).map_err(|error| within(error, "archive_info"))?;
    }
    let vcs = get(object, "vcs_info", "dict")?;
    if let Some(serde_json::Value::Object(vcs)) = vcs {
        (|| -> std::result::Result<(), Invalid> {
            required(vcs, "vcs", "str")?;
            get(vcs, "requested_revision", "str")?;
            required(vcs, "commit_id", "str")?;
            Ok(())
        })()
        .map_err(|error| within(error, "vcs_info"))?;
    }
    let dir = get(object, "dir_info", "dict")?;
    let editable = match dir {
        Some(serde_json::Value::Object(dir)) => get(dir, "editable", "bool").map_err(|error| within(error, "dir_info"))?.and_then(serde_json::Value::as_bool),
        _ => None,
    };
    get(object, "subdirectory", "str")?;
    if usize::from(archive.is_some()) + usize::from(vcs.is_some()) + usize::from(dir.is_some()) != 1 {
        return Err(Invalid { message: "Exactly one of vcs_info, archive_info, dir_info must be present".to_owned(), context: None });
    }
    if dir.is_some() {
        if crate::names::url_scheme(url) != "file" {
            return Err(invalid("URL scheme must be file:// when dir_info is present", "url"));
        }
        if !file_url_path(url).starts_with('/') {
            return Err(invalid("File URL must be absolute when dir_info is present", "url"));
        }
    }
    Ok(editable == Some(true))
}

fn archive_info(archive: &Object) -> std::result::Result<(), Invalid> {
    let hashes = get(archive, "hashes", "dict")?.and_then(serde_json::Value::as_object);
    if hashes.is_some_and(|hashes| !hashes.values().all(serde_json::Value::is_string)) {
        return Err(invalid("Hash values must be strings", "hashes"));
    }
    if let Some(legacy) = get(archive, "hash", "str")?.and_then(serde_json::Value::as_str) {
        let Some((algorithm, value)) = legacy.split_once('=') else {
            return Err(invalid("Invalid hash format (expected '<algorithm>=<hash>')", "hash"));
        };
        if let Some(hashes) = hashes {
            match hashes.get(algorithm).and_then(serde_json::Value::as_str) {
                None => {
                    return Err(invalid(format!("Algorithm {} used in hash field is not present in hashes field", repr(algorithm)), "hashes"));
                }
                Some(found) if found != value => {
                    return Err(invalid(format!("Algorithm {} used in hash field has different value in hashes field", repr(algorithm)), "hash"));
                }
                Some(_) => {}
            }
        }
    }
    Ok(())
}

/// `urlsplit(url).path`
fn file_url_path(url: &str) -> String {
    let scheme = crate::names::url_scheme(url);
    let cleaned: String = url.trim_start_matches(|character: char| character <= ' ').chars().filter(|c| !matches!(c, '\t' | '\r' | '\n')).collect();
    let mut rest = if scheme.is_empty() { cleaned.as_str() } else { &cleaned[scheme.len() + 1..] };
    if let Some(after) = rest.strip_prefix("//") {
        rest = after.find(['/', '?', '#']).map_or("", |at| &after[at..]);
    }
    rest.split(['?', '#']).next().unwrap_or("").to_owned()
}

/// `_depends_on`: the installed distributions a distribution requires here
fn depends_on(
    name: &str,
    candidate: &Candidate,
    installed: &BTreeSet<&str>,
    environment: &HashMap<String, String>,
    warnings: &mut Vec<Warning>,
) -> Result<Vec<String>> {
    let declared: Vec<String> = {
        let listed: Vec<String> = candidate.metadata.get_all("Requires-Dist").map(str::to_owned).collect();
        if listed.is_empty() { egg_info_requires(&candidate.path) } else { listed }
    };
    let mut names = BTreeSet::new();
    for line in &declared {
        let requirement = match parse_requirement(line) {
            Ok(requirement) => requirement,
            Err(error) => {
                warnings.push(Warning::Message(format!("left out the requirement {} of {name}: {error}", repr(line))));
                continue;
            }
        };
        let required = canonicalize_name(&requirement.name);
        if !installed.contains(required.as_str()) {
            continue;
        }
        let applies = match &requirement.marker {
            None => true,
            Some(marker) => evaluate(marker, environment).map_err(Error::Value)?,
        };
        if applies {
            names.insert(required);
        }
    }
    Ok(names.into_iter().collect())
}

/// requires.txt sections turned into requirements with markers, as importlib converts an egg-info's
fn egg_info_requires(path: &Path) -> Vec<String> {
    let Some(text) = read_text(path, "requires.txt") else { return Vec::new() };
    let mut section: Option<String> = None;
    let mut out = Vec::new();
    for line in crate::record::splitlines(&text) {
        let line = crate::names::py_strip(line);
        // importlib keeps comment lines, which then fail to parse as requirements
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            section = Some(line.trim_matches(['[', ']']).to_owned());
            continue;
        }
        let section = section.clone().unwrap_or_default();
        let (extra, markers) = section.split_once(':').map_or((section.as_str(), ""), |(extra, markers)| (extra, markers));
        let markers = if !extra.is_empty() && !markers.is_empty() { format!("({markers})") } else { markers.to_owned() };
        let conditions: Vec<String> =
            [markers, if extra.is_empty() { String::new() } else { format!("extra == \"{extra}\"") }].into_iter().filter(|text| !text.is_empty()).collect();
        let space = if line.contains('@') { " " } else { "" };
        let marker = if conditions.is_empty() { String::new() } else { format!("; {}", conditions.join(" and ")) };
        out.push(format!("{line}{space}{marker}"));
    }
    out
}
