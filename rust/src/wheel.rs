//! Wheels: their .dist-info as installer finds it, RECORD verification, bundled wheels, and writing the SBOM in.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;
use std::sync::Arc;

use rayon::prelude::*;
use regex::Regex;

use crate::email::Metadata;
use crate::error::{Error, Result};
use crate::hashes::{Hasher, sha256_hex};
use crate::pep508::parse_requirement;
use crate::record::{RecordEntry, RecordRow, decode_digest, parse_record, record_digest, splitlines};
use crate::zip::{Archive, Entry, NewMember, ZipError, dos_time};

/// metadata files beyond this size are refused, so a hostile wheel cannot exhaust memory
pub const METADATA_LIMIT: usize = 16 * 1024 * 1024;

/// an archive opened as `open_archive` opens it: zipfile's checks, then no two names that differ only by case
pub struct Opened {
    pub archive: Archive,
    pub location: String,
    /// the file name installer parses the wheel's name from
    pub filename: String,
}

pub fn zip_error(location: &str, error: ZipError) -> Error {
    match error {
        ZipError::Io(error) => Error::Io(error),
        other => Error::Wheel(format!("{location} is not a valid zip archive: {other}")),
    }
}

/// `str.casefold()`, for the case-insensitive name check
pub fn casefold(text: &str) -> String {
    let lowered = text.to_lowercase();
    if lowered.contains(['ß', 'ς', 'ſ']) { lowered.replace('ß', "ss").replace('ς', "σ").replace('ſ', "s") } else { lowered }
}

impl Opened {
    pub fn path(path: &Path, location: &str) -> Result<Self> {
        Self::check(Archive::open(path).map_err(|error| zip_error(location, error))?, location, &path.to_string_lossy())
    }

    pub fn bytes(bytes: Vec<u8>, location: &str, filename: &str) -> Result<Self> {
        Self::check(Archive::from_bytes(bytes).map_err(|error| zip_error(location, error))?, location, filename)
    }

    fn check(archive: Archive, location: &str, filename: &str) -> Result<Self> {
        let mut counts: HashMap<String, usize> = HashMap::with_capacity(archive.entries.len());
        for name in archive.names() {
            *counts.entry(casefold(name)).or_default() += 1;
        }
        let clashes: BTreeSet<&String> = counts.iter().filter(|(_, count)| **count > 1).map(|(name, _)| name).collect();
        if !clashes.is_empty() {
            let names: Vec<&str> = clashes.into_iter().map(String::as_str).collect();
            return Err(Error::Wheel(format!("{location} holds more than one member named {}, ignoring case", names.join(", "))));
        }
        Ok(Self { archive, location: location.to_owned(), filename: filename.to_owned() })
    }

    pub fn zip(&self, error: ZipError) -> Error {
        zip_error(&self.location, error)
    }

    /// `read_member`: a member read whole, refused past `limit` bytes
    pub fn read_member(&self, name: &str, limit: usize) -> Result<Vec<u8>> {
        let entry = self.archive.find(name).ok_or_else(|| Error::Wheel(format!("{} has no {name}", self.location)))?;
        match self.archive.read(entry, Some(limit)).map_err(|error| self.zip(error))? {
            Some(content) => Ok(content.into_owned()),
            None => Err(Error::Wheel(format!("{}: {name} is over the {limit} byte limit", self.location))),
        }
    }

    pub fn read_text(&self, name: &str, limit: usize) -> Result<String> {
        String::from_utf8(self.read_member(name, limit)?).map_err(|error| Error::Value(format!("'utf-8' codec can't decode bytes in {name}: {error}")))
    }

    /// installer's `WheelFile.dist_info_dir`, refusing what installer refuses
    pub fn dist_info(&self) -> Result<String> {
        let refuse = |error: String| Error::Wheel(format!("{} is not a wheel: {error}", self.location));
        let basename = self.filename.rsplit(['/', std::path::MAIN_SEPARATOR]).next().unwrap_or("");
        let (distribution, _) = parse_wheel_filename(basename).ok_or_else(|| refuse(format!("Not a valid wheel filename: {basename}")))?;
        let mut tops: Vec<&str> = self
            .archive
            .names()
            .map(|name| name.split('/').next().unwrap_or(""))
            .filter(|top| top.ends_with(".dist-info"))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        tops.sort_unstable();
        let filename = crate::pyrepr::repr(&self.filename);
        if tops.len() != 1 {
            let listed: Vec<String> = tops.iter().map(|top| crate::pyrepr::repr(top)).collect();
            return Err(refuse(format!(
                "Wheel doesn't contain exactly one .dist-info directory (filename={filename}, dist_info={})",
                crate::pyrepr::repr(&format!("[{}]", listed.join(", ")))
            )));
        }
        let dist_info = tops[0];
        let named = dist_info.rsplitn(3, '-').last().unwrap_or("");
        if installer_canonical(named) != installer_canonical(distribution) {
            return Err(refuse(format!(
                "Wheel .dist-info directory doesn't match wheel filename (filename={filename}, dist_info={})",
                crate::pyrepr::repr(dist_info)
            )));
        }
        Ok(dist_info.to_owned())
    }

    /// `read_wheel_metadata`: the .dist-info and its METADATA, read capped
    pub fn wheel_metadata(&self) -> Result<(String, Metadata)> {
        let dist_info = self.dist_info()?;
        let text = self.read_text(&format!("{dist_info}/METADATA"), METADATA_LIMIT)?;
        Ok((dist_info, Metadata::parse(&text)))
    }
}

/// installer's own `canonicalize_name`
fn installer_canonical(name: &str) -> String {
    static RUNS: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| Regex::new(r"[-_.]+").expect("valid"));
    RUNS.replace_all(name, "-").to_lowercase()
}

/// installer's `parse_wheel_filename`: the distribution and version
fn parse_wheel_filename(filename: &str) -> Option<(&str, &str)> {
    static WHEEL: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
        Regex::new(r"^(?P<distribution>.+?)-(?P<version>.*?)(?:-(?P<build_tag>\d[^-]*?))?-(?P<tag>.+?-.+?-.+?)\.whl$").expect("valid")
    });
    let captures = WHEEL.captures(filename)?;
    Some((captures.name("distribution")?.as_str(), captures.name("version").map_or("", |found| found.as_str())))
}

pub struct BundledWheel {
    pub path: String,
    pub sha256: String,
    pub metadata_name: String,
    pub metadata: Arc<Metadata>,
    pub files: Arc<Vec<RecordRow>>,
    pub vendored: Vec<(String, Arc<Metadata>)>,
}

/// `read_bundled_wheel`: a wheel the project ships, verified against its RECORD
pub fn read_bundled_wheel(data: Vec<u8>, path: &str) -> Result<BundledWheel> {
    let location = format!("bundled wheel {path}");
    let sha256 = sha256_hex(&data);
    let opened = Opened::bytes(data, &location, path)?;
    let mut members: Vec<&str> = opened.archive.names().filter(|name| !name.ends_with('/')).collect();
    members.sort_unstable();
    let (dist_info, metadata) = opened.wheel_metadata()?;
    check_named(&metadata, &location, &format!("{dist_info}/METADATA"))?;
    let files = verified_record(&opened, &dist_info)?;
    let mut vendored = vendor_manifest(&opened, &members)?;
    for name in members.iter().filter(|name| name.contains("/_vendor/") && name.ends_with(".dist-info/METADATA")) {
        let metadata = Metadata::parse(&opened.read_text(name, METADATA_LIMIT)?);
        check_named(&metadata, &location, name)?;
        vendored.push(((*name).to_owned(), Arc::new(metadata)));
    }
    Ok(BundledWheel {
        path: path.to_owned(),
        sha256,
        metadata_name: format!("{dist_info}/METADATA"),
        metadata: Arc::new(metadata),
        files: Arc::new(files),
        vendored,
    })
}

fn check_named(metadata: &Metadata, location: &str, name: &str) -> Result<()> {
    if metadata.get("Name").is_none_or(str::is_empty) || metadata.get("Version").is_none_or(str::is_empty) {
        return Err(Error::Wheel(format!("{location}: {name} lacks Name or Version")));
    }
    Ok(())
}

/// `_verified_record`: the RECORD rows, once RECORD agrees with every member of the wheel
fn verified_record(opened: &Opened, dist_info: &str) -> Result<Vec<RecordRow>> {
    let location = &opened.location;
    let record_name = format!("{dist_info}/RECORD");
    let record = opened.read_text(&record_name, METADATA_LIMIT)?;
    let rows = parse_record(&record).map_err(|error| Error::Wheel(format!("{location}: RECORD does not parse: {}", error.message())))?;
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for row in &rows {
        *counts.entry(row[0].as_str()).or_default() += 1;
    }
    let repeated: Vec<&str> = counts.iter().filter(|(_, count)| **count > 1).map(|(path, _)| *path).collect();
    if !repeated.is_empty() {
        return Err(Error::Wheel(format!("{location}: RECORD lists {} more than once", repeated.join(", "))));
    }
    let members: BTreeSet<&str> = opened.archive.entries.iter().filter(|entry| !entry.is_dir()).map(|entry| entry.name.as_str()).collect();
    let recorded: BTreeSet<&str> = counts.keys().copied().collect();
    let unsigned: [String; 3] = [record_name.clone(), format!("{dist_info}/RECORD.jws"), format!("{dist_info}/RECORD.p7s")];
    let missing: Vec<&str> =
        members.difference(&recorded).copied().filter(|name| !unsigned.iter().any(|skip| skip == name)).collect();
    if !missing.is_empty() {
        return Err(Error::Wheel(format!("{location}: RECORD lacks a digest for {}", missing.join(", "))));
    }
    let extra: Vec<&str> = recorded.difference(&members).copied().collect();
    if !extra.is_empty() {
        return Err(Error::Wheel(format!("{location}: RECORD lists {}, which the wheel does not hold", extra.join(", "))));
    }
    let issues = validate_record(opened, dist_info, &rows)?;
    if !issues.is_empty() {
        let prefix = format!("In {}, ", opened.filename);
        let issues: Vec<&str> = issues.iter().map(|issue| issue.strip_prefix(&prefix).unwrap_or(issue)).collect();
        return Err(Error::Wheel(format!("{location}: RECORD disagrees with the wheel: {}", issues.join("; "))));
    }
    let mut found = Vec::with_capacity(rows.len());
    for row in &rows {
        let entry = RecordEntry::from_elements(row).map_err(|error| Error::Wheel(format!("{location}: RECORD does not parse: {}", error.message())))?;
        let Some((name, value)) = entry.hash else { continue };
        let (algorithm, digest) = decode_digest(&format!("{name}={value}"), &format!("{location}: RECORD row for {}", entry.path))?;
        found.push(RecordRow { path: entry.path.to_owned(), algorithm: algorithm.to_owned(), digest, size: entry.size_text() });
    }
    Ok(found)
}

/// `posixpath.commonpath([dist_info, name]) == dist_info`
fn under(dist_info: &str, name: &str) -> bool {
    let parts = |path: &'_ str| path.split('/').filter(|part| !part.is_empty() && *part != ".").map(str::to_owned).collect::<Vec<_>>();
    let base = parts(dist_info);
    let other = parts(name);
    other.len() >= base.len() && other[..base.len()] == base[..]
}

/// installer's `WheelFile.validate_record`, its issues in member order
fn validate_record(opened: &Opened, dist_info: &str, rows: &[[String; 3]]) -> Result<Vec<String>> {
    let filename = &opened.filename;
    let mut mapping: HashMap<&str, &[String; 3]> = rows.iter().map(|row| (row[0].as_str(), row)).collect();
    let record_name = format!("{dist_info}/RECORD");
    let entries: Vec<&Entry> = opened.archive.entries.iter().filter(|entry| !entry.is_dir()).collect();
    // the content checks are independent, so they run in parallel; their issues are collected in member order
    let mut plan = Vec::with_capacity(entries.len());
    for entry in &entries {
        let row = mapping.remove(entry.name.as_str());
        let base = entry.name.rsplit('/').next().unwrap_or("");
        if under(dist_info, &entry.name) && matches!(base, "RECORD.p7s" | "RECORD.jws") {
            plan.push((entry, row, true));
            continue;
        }
        plan.push((entry, row, false));
    }
    let checked: Vec<Result<Vec<String>>> = plan
        .par_iter()
        .map(|(entry, row, signature)| {
            let mut issues = Vec::new();
            if *signature {
                if row.is_some() {
                    issues.push(format!("In {filename}, digital signature file {} is incorrectly contained in RECORD.", entry.name));
                }
                return Ok(issues);
            }
            let Some(row) = row else {
                issues.push(format!("In {filename}, {} is not mentioned in RECORD", entry.name));
                return Ok(issues);
            };
            let record = match RecordEntry::from_elements(row) {
                Ok(record) => record,
                Err(error) => {
                    for issue in error.issues {
                        issues.push(format!("In {filename}, entry in RECORD file for {} is invalid: {issue}", entry.name));
                    }
                    return Ok(issues);
                }
            };
            if entry.name == record_name {
                if record.hash.is_some() || record.size.is_some() {
                    issues.push(format!("In {filename}, RECORD file incorrectly contains hash / size."));
                }
                return Ok(issues);
            }
            if record.hash.is_none() || record.size.is_none() {
                issues.push(format!("In {filename}, hash / size of {} is not included in RECORD", entry.name));
            }
            if !matches_record(opened, entry, &record)? {
                issues.push(format!("In {filename}, hash / size of {} didn't match RECORD", entry.name));
            }
            Ok(issues)
        })
        .collect();
    let mut issues = Vec::new();
    for result in checked {
        issues.extend(result?);
    }
    Ok(issues)
}

/// `RecordEntry.validate_stream`
fn matches_record(opened: &Opened, entry: &Entry, record: &RecordEntry<'_>) -> Result<bool> {
    if let Some((name, value)) = record.hash {
        let Some(mut hasher) = Hasher::new(name) else { return Ok(false) };
        let size = opened.archive.stream(entry, |chunk| hasher.update(chunk)).map_err(|error| opened.zip(error))?;
        if record.size.is_some_and(|expected| expected != i128::from(size)) {
            return Ok(false);
        }
        return Ok(record_digest(&hasher.finish()) == value);
    }
    if let Some(expected) = record.size {
        let size = opened.archive.stream(entry, |_| {}).map_err(|error| opened.zip(error))?;
        return Ok(expected == i128::from(size));
    }
    Ok(true)
}

/// `_vendor_manifest`: pip's _vendor/vendor.txt pins, each as a name and version
fn vendor_manifest(opened: &Opened, members: &[&str]) -> Result<Vec<(String, Arc<Metadata>)>> {
    let location = &opened.location;
    let mut found = Vec::new();
    for name in members.iter().filter(|member| member.ends_with("/_vendor/vendor.txt")) {
        let text = opened.read_text(name, METADATA_LIMIT)?;
        for line in splitlines(&text) {
            let text = crate::names::py_strip(line.split('#').next().unwrap_or(""));
            if text.is_empty() {
                continue;
            }
            let requirement = parse_requirement(text)
                .map_err(|_| Error::Wheel(format!("{location}: vendored requirement in {name} does not parse: {text}")))?;
            let pins = requirement.specifiers();
            if pins.len() != 1 || pins[0].0 != "==" || pins[0].1.contains('*') {
                return Err(Error::Wheel(format!("{location}: vendored requirement in {name} pins no one exact version: {text}")));
            }
            let metadata = Metadata { headers: vec![("Name".to_owned(), requirement.name.clone()), ("Version".to_owned(), pins[0].1.clone())] };
            found.push(((*name).to_owned(), Arc::new(metadata)));
        }
    }
    Ok(found)
}

/// the .whl members of a built wheel by their SHA-256, the last of equal ones winning as a dict keeps it
pub fn whl_member_digests(wheel: &Path) -> Result<Vec<(String, String)>> {
    let location = wheel.to_string_lossy().into_owned();
    let opened = Opened::path(wheel, &location)?;
    let wheels: Vec<&Entry> = opened.archive.entries.iter().filter(|entry| entry.name.ends_with(".whl")).collect();
    wheels
        .par_iter()
        .map(|entry| {
            let mut hasher = Hasher::new("sha256").expect("sha256");
            opened.archive.stream(entry, |chunk| hasher.update(chunk)).map_err(|error| opened.zip(error))?;
            Ok((crate::record::to_hex(&hasher.finish()), entry.name.clone()))
        })
        .collect()
}

/// `write_sbom`: the SBOM written into the wheel's .dist-info/sboms, RECORD rewritten after it
pub fn write_sbom(wheel: &Path, name: &str, content: &[u8], epoch: i64) -> Result<String> {
    let location = wheel.to_string_lossy().into_owned();
    let opened = Opened::path(wheel, &location)?;
    let dist_info = opened.dist_info()?;
    let record = format!("{dist_info}/RECORD");
    let names: BTreeSet<&str> = opened.archive.names().collect();
    let missing: Vec<String> =
        [format!("{dist_info}/METADATA"), record.clone()].into_iter().filter(|needed| !names.contains(needed.as_str())).collect();
    if !missing.is_empty() {
        return Err(Error::Wheel(format!("{location} has no {}", missing.join(", "))));
    }
    let record_entry = opened.archive.find(&record).expect("checked above").clone();
    let record_data = opened.archive.read(&record_entry, None).map_err(|error| opened.zip(error))?.expect("no limit").into_owned();
    let sbom = format!("{dist_info}/sboms/{name}");
    let rewritten = rewritten_record(&record_data, &record, &sbom, content)?;
    let (time, date) = dos_time(epoch);
    let members = [
        NewMember {
            name: &sbom,
            content,
            deflate: true,
            dos_time: time,
            dos_date: date,
            create_version: 20,
            create_system: 3,
            extract_version: 20,
            internal_attr: 0,
            external_attr: (0o100_644) << 16,
        },
        NewMember {
            name: &record,
            content: &rewritten,
            deflate: record_entry.method == 8,
            dos_time: record_entry.dos_time,
            dos_date: record_entry.dos_date,
            create_version: record_entry.create_version,
            create_system: record_entry.create_system,
            extract_version: record_entry.extract_version,
            internal_attr: record_entry.internal_attr,
            external_attr: record_entry.external_attr,
        },
    ];
    let output = opened.archive.rewrite(&[&record, &sbom], &members).map_err(|error| opened.zip(error))?;
    drop(opened);
    replace_file(wheel, &output)?;
    Ok(sbom)
}

/// `_rewritten_record`: the SBOM's row before the row of RECORD itself, in the file's own line endings
fn rewritten_record(record: &[u8], name: &str, sbom: &str, content: &[u8]) -> Result<Vec<u8>> {
    let text = std::str::from_utf8(record).map_err(|error| Error::Value(format!("'utf-8' codec can't decode RECORD: {error}")))?;
    let skip = format!("{sbom},");
    let mut lines: Vec<&str> = splitlines_keepends(text).into_iter().filter(|line| !line.starts_with(&skip)).collect();
    let newline = if lines.first().is_some_and(|line| line.ends_with("\r\n")) { "\r\n" } else { "\n" };
    let own = format!("{name},");
    let at = lines.iter().position(|line| line.starts_with(&own)).unwrap_or(lines.len());
    let digest = {
        let mut hasher = Hasher::new("sha256").expect("sha256");
        hasher.update(content);
        record_digest(&hasher.finish())
    };
    let row = format!("{},{},{}{newline}", csv_field(sbom), csv_field(&format!("sha256={digest}")), content.len());
    lines.insert(at, &row);
    Ok(lines.concat().into_bytes())
}

/// a field as `csv.writer` quotes it under QUOTE_MINIMAL
fn csv_field(field: &str) -> String {
    if field.contains([',', '"', '\r', '\n']) { format!("\"{}\"", field.replace('"', "\"\"")) } else { field.to_owned() }
}

/// `str.splitlines(keepends=True)`
fn splitlines_keepends(text: &str) -> Vec<&str> {
    let mut lines = Vec::new();
    let mut start = 0;
    let mut chars = text.char_indices().peekable();
    while let Some((index, character)) = chars.next() {
        let mut end = index + character.len_utf8();
        match character {
            '\r' => {
                if let Some(&(next, '\n')) = chars.peek() {
                    chars.next();
                    end = next + 1;
                }
            }
            '\n' | '\x0b' | '\x0c' | '\x1c' | '\x1d' | '\x1e' | '\u{85}' | '\u{2028}' | '\u{2029}' => {}
            _ => continue,
        }
        lines.push(&text[start..end]);
        start = end;
    }
    if start < text.len() {
        lines.push(&text[start..]);
    }
    lines
}

/// the new bytes written beside the file, given its mode, and moved over it, so a failure leaves the original
pub fn replace_file(target: &Path, content: &[u8]) -> Result<()> {
    let directory = target.parent().filter(|parent| !parent.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let mut temporary = None;
    for attempt in 0..100u32 {
        let candidate = directory.join(format!(".python-sbom-{}-{attempt}.tmp", std::process::id()));
        match std::fs::OpenOptions::new().write(true).create_new(true).open(&candidate) {
            Ok(file) => {
                temporary = Some((candidate, file));
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
    }
    let (path, mut file) = temporary.ok_or_else(|| Error::Io(std::io::Error::other("no temporary file name left")))?;
    let result = (|| -> std::io::Result<()> {
        use std::io::Write as _;
        file.write_all(content)?;
        drop(file);
        std::fs::set_permissions(&path, std::fs::metadata(target)?.permissions())?;
        std::fs::rename(&path, target)
    })();
    if let Err(error) = result {
        let _ = std::fs::remove_file(&path);
        return Err(error.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wheel_names() {
        assert_eq!(parse_wheel_filename("pip-1.0-py3-none-any.whl"), Some(("pip", "1.0")));
        assert_eq!(parse_wheel_filename("a-1-2b-py3-none-any.whl"), Some(("a", "1")));
        assert_eq!(parse_wheel_filename("nope.whl"), None);
        assert!(under("a.dist-info", "a.dist-info/../RECORD.jws"));
        assert!(!under("a.dist-info", "b/RECORD.jws"));
    }

    #[test]
    fn record_rewrite() {
        let out = rewritten_record(b"a,sha256=x,1\r\nd/RECORD,,\r\n", "d/RECORD", "d/sboms/s.json", b"{}").unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "a,sha256=x,1\r\nd/sboms/s.json,sha256=RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o,2\r\nd/RECORD,,\r\n"
        );
    }
}
