//! The SPDX 2.3 JSON rendering of a CycloneDX document.

use std::collections::BTreeSet;
use std::sync::LazyLock;

use regex::Regex;

use crate::error::{Error, Result};
use crate::hashes::sha256_hex;
use crate::json::{Json, Obj, dumps_sorted};
use crate::names::{SBOM_FILE, SBOM_REPOSITORY, property_prefix};

static LICENSE_REF: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"LicenseRef-[A-Za-z0-9.-]+").expect("valid"));
static NOT_ID: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[^A-Za-z0-9.]+").expect("valid"));

/// SPDX 2.3 JSON names every CycloneDX 1.6 hash algorithm, but by names of its own
fn hash_algorithm(name: &str) -> Option<&'static str> {
    Some(match name {
        "MD5" => "MD5",
        "SHA-1" => "SHA1",
        "SHA-256" => "SHA256",
        "SHA-384" => "SHA384",
        "SHA-512" => "SHA512",
        "SHA3-256" => "SHA3-256",
        "SHA3-384" => "SHA3-384",
        "SHA3-512" => "SHA3-512",
        "BLAKE2b-256" => "BLAKE2b-256",
        "BLAKE2b-384" => "BLAKE2b-384",
        "BLAKE2b-512" => "BLAKE2b-512",
        "BLAKE3" => "BLAKE3",
        _ => return None,
    })
}

fn key_error(key: &str) -> Error {
    Error::Key(crate::pyrepr::repr(key))
}

fn object<'a>(value: &'a Json, what: &str) -> Result<&'a Obj> {
    value.as_obj().ok_or_else(|| Error::Type(format!("{what} is not an object")))
}

fn index<'a>(value: &'a Obj, key: &str) -> Result<&'a Json> {
    value.get(key).ok_or_else(|| key_error(key))
}

/// `str(value)` of a JSON value, as an f-string formats it
fn py_str(value: &Json) -> String {
    match value {
        Json::Str(text) => text.clone(),
        Json::Num(text) => text.clone(),
        Json::Bool(true) => "True".to_owned(),
        Json::Bool(false) => "False".to_owned(),
        Json::Null => "None".to_owned(),
        other => String::from_utf8_lossy(&crate::json::dumps_sorted(other)).into_owned(),
    }
}

fn text(value: &Obj, key: &str) -> Result<String> {
    Ok(py_str(index(value, key)?))
}

fn items<'a>(value: &'a Obj, key: &str) -> &'a [Json] {
    value.arr(key).unwrap_or(&[])
}

fn pair(name: &str, value: Json) -> (String, Json) {
    (name.to_owned(), value)
}

fn spdx_id(reference: &str) -> String {
    let readable = NOT_ID.replace_all(reference, "-");
    format!("SPDXRef-{}-{}", readable.trim_matches('-'), &sha256_hex(reference.as_bytes())[..8])
}

fn creator(name: &str, version: Option<&Json>) -> String {
    match version {
        None => format!("Tool: {name}"),
        Some(version) => format!("Tool: {name}-{}", py_str(version)),
    }
}

/// `render_spdx`
pub fn render(bom: &Json, tool_version: &str) -> Result<Json> {
    let document = object(bom, "document")?;
    let metadata = object(index(document, "metadata")?, "metadata")?;
    let root = index(metadata, "component")?;
    let root_object = object(root, "component")?;
    let root_name = text(root_object, "name")?;
    let project = property_prefix(&root_name);
    let mut recorded: Vec<(String, String)> = Vec::new();
    for prop in items(metadata, "properties") {
        let prop = object(prop, "property")?;
        let name = text(prop, "name")?;
        let value = prop.get("value").map_or_else(String::new, py_str);
        if let Some(slot) = recorded.iter_mut().find(|(known, _)| *known == name) {
            slot.1 = value;
        } else {
            recorded.push((name, value));
        }
    }
    let lookup = |key: String, default: &str| recorded.iter().find(|(name, _)| *name == key).map_or_else(|| default.to_owned(), |(_, value)| value.clone());
    let name = match root_object.get("version") {
        Some(version) => format!("{root_name}-{}", py_str(version)),
        None => root_name.clone(),
    };
    let source = match document.get("serialNumber") {
        Some(serial) => py_str(serial),
        None => format!("sha256:{}", sha256_hex(&dumps_sorted(bom))),
    };
    let repository = lookup(format!("{project}:{SBOM_REPOSITORY}"), "https://spdx.org/spdxdocs");
    let sbom_file = lookup(format!("{project}:{SBOM_FILE}"), "CycloneDX JSON");
    let (tools, tool_creators) = tools(metadata)?;
    let mut starting: Vec<&Json> = vec![root];
    starting.extend(items(document, "components"));
    starting.extend(tools.iter().copied());
    let components = walk(&starting)?;
    let prefix = format!("{project}:");
    let packages = components.iter().map(|component| package(component, &prefix)).collect::<Result<Vec<Obj>>>()?;
    let mut references = BTreeSet::new();
    for package in &packages {
        if let Some(declared) = package.str("licenseDeclared") {
            references.extend(LICENSE_REF.find_iter(declared).map(|found| found.as_str().to_owned()));
        }
    }
    let namespace = format!("{repository}/sboms/{name}-{}", source.strip_prefix("urn:uuid:").unwrap_or(&source));
    let relationships = relationships(document, root, &components, &tools)?;
    let mut spdx = Obj(vec![
        pair("spdxVersion", Json::str("SPDX-2.3")),
        pair("dataLicense", Json::str("CC0-1.0")),
        pair("SPDXID", Json::str("SPDXRef-DOCUMENT")),
        pair("name", Json::Str(name)),
        pair("documentNamespace", Json::Str(namespace)),
        pair(
            "comment",
            Json::Str(format!(
                "Rendered from the CycloneDX SBOM {source} ({sbom_file}), which also carries per-file hashes and the build formulation."
            )),
        ),
        pair("creationInfo", creation_info(metadata, tool_creators, tool_version)?),
        pair("packages", Json::Arr(packages.into_iter().map(Json::Obj).collect())),
        pair("relationships", Json::Arr(relationships)),
    ]);
    if !references.is_empty() {
        let infos = references
            .into_iter()
            .map(|token| {
                Json::Obj(Obj(vec![
                    pair("licenseId", Json::Str(token.clone())),
                    pair("extractedText", Json::Str(format!("{token}, as named in package metadata"))),
                    pair("name", Json::Str(token)),
                ]))
            })
            .collect();
        spdx.push("hasExtractedLicensingInfos", Json::Arr(infos));
    }
    Ok(Json::Obj(spdx))
}

fn tools(metadata: &Obj) -> Result<(Vec<&Json>, Vec<String>)> {
    match metadata.get("tools") {
        None | Some(Json::Null) => Ok((Vec::new(), Vec::new())),
        Some(Json::Arr(legacy)) => {
            let mut creators = Vec::new();
            for tool in legacy {
                let tool = object(tool, "tool")?;
                if let Some(name) = tool.get("name").filter(|name| name.truthy()) {
                    creators.push(creator(&py_str(name), tool.get("version").filter(|version| **version != Json::Null)));
                }
            }
            Ok((Vec::new(), creators))
        }
        Some(Json::Obj(tools)) => {
            let components: Vec<&Json> = items(tools, "components").iter().collect();
            let mut creators = Vec::new();
            for tool in &components {
                let tool = object(tool, "tool")?;
                if index(tool, "type")?.as_str() == Some("application") {
                    creators.push(creator(&text(tool, "name")?, tool.get("version").filter(|version| **version != Json::Null)));
                }
            }
            Ok((components, creators))
        }
        Some(_) => Err(Error::Type("tools is neither a list nor an object".to_owned())),
    }
}

/// `_walk`: every component that is not a file, parents before children
fn walk<'a>(components: &[&'a Json]) -> Result<Vec<&'a Json>> {
    let mut found = Vec::new();
    let mut pending: Vec<&Json> = components.iter().rev().copied().collect();
    while let Some(component) = pending.pop() {
        let object = object(component, "component")?;
        if index(object, "type")?.as_str() != Some("file") {
            found.push(component);
            pending.extend(items(object, "components").iter().rev());
        }
    }
    Ok(found)
}

fn package(component: &Json, prefix: &str) -> Result<Obj> {
    let component = object(component, "component")?;
    let licenses = items(component, "licenses");
    let mut concluded = Vec::new();
    let mut declared = None;
    let mut names = Vec::new();
    for entry in licenses {
        let entry = object(entry, "license entry")?;
        if let Some(license) = entry.get("license") {
            let license = object(license, "license")?;
            if let Some(identifier) = license.get("id") {
                concluded.push(py_str(identifier));
            }
            if let Some(name) = license.get("name") {
                names.push(py_str(name));
            }
        }
        if declared.is_none()
            && let Some(expression) = entry.get("expression")
        {
            declared = Some(py_str(expression));
        }
    }
    let kind = index(component, "type")?;
    let mut package = Obj(vec![
        pair("SPDXID", Json::Str(spdx_id(&text(component, "bom-ref")?))),
        pair("name", index(component, "name")?.clone()),
        pair("downloadLocation", Json::str("NOASSERTION")),
        pair("filesAnalyzed", Json::Bool(false)),
        pair("licenseConcluded", Json::Str(if concluded.is_empty() { "NOASSERTION".to_owned() } else { concluded.join(" AND ") })),
        pair("licenseDeclared", Json::Str(declared.clone().unwrap_or_else(|| "NOASSERTION".to_owned()))),
        pair(
            "primaryPackagePurpose",
            Json::str(match kind.as_str() {
                Some("application") => "APPLICATION",
                Some("library") => "LIBRARY",
                _ => "OTHER",
            }),
        ),
    ]);
    if let Some(version) = component.get("version").filter(|version| version.truthy()) {
        package.push("versionInfo", version.clone());
    }
    if let Some(supplier) = component.get("supplier").filter(|supplier| supplier.truthy())
        && let Some(organization) = object(supplier, "supplier")?.get("name").filter(|name| name.truthy())
    {
        package.push("supplier", Json::Str(format!("Organization: {}", py_str(organization))));
    }
    let mut checksums = Vec::new();
    for entry in items(component, "hashes") {
        let entry = object(entry, "hash")?;
        if let Some(algorithm) = index(entry, "alg")?.as_str().and_then(hash_algorithm) {
            checksums.push(Json::Obj(Obj(vec![pair("algorithm", Json::str(algorithm)), pair("checksumValue", index(entry, "content")?.clone())])));
        }
    }
    if !checksums.is_empty() {
        package.push("checksums", Json::Arr(checksums));
    }
    for reference in items(component, "externalReferences") {
        let reference = object(reference, "reference")?;
        if index(reference, "type")?.as_str() == Some("website") {
            let url = index(reference, "url")?;
            if url.truthy() {
                package.push("homepage", url.clone());
            }
            break;
        }
    }
    if let Some(copyright) = component.get("copyright").filter(|copyright| copyright.truthy()) {
        package.push("copyrightText", copyright.clone());
    }
    if let Some(description) = component.get("description").filter(|description| description.truthy()) {
        package.push("summary", description.clone());
    }
    let mut comment = Vec::new();
    for prop in items(component, "properties") {
        let prop = object(prop, "property")?;
        let name = text(prop, "name")?;
        if name.starts_with(prefix) {
            comment.push(format!("{name}: {}", prop.get("value").map_or_else(String::new, py_str)));
        }
    }
    if !comment.is_empty() {
        package.push("comment", Json::Str(comment.join("\n")));
    }
    if let Some(purl) = component.get("purl").filter(|purl| purl.truthy()) {
        package.push(
            "externalRefs",
            Json::Arr(vec![Json::Obj(Obj(vec![
                pair("referenceCategory", Json::str("PACKAGE-MANAGER")),
                pair("referenceType", Json::str("purl")),
                pair("referenceLocator", purl.clone()),
            ]))]),
        );
    }
    if package.str("licenseDeclared") == Some("NOASSERTION") && !names.is_empty() {
        package.push("licenseComments", Json::Str(format!("Declared in package metadata as: {}", names.join("; "))));
    }
    Ok(package)
}

fn creation_info(metadata: &Obj, tool_creators: Vec<String>, tool_version: &str) -> Result<Json> {
    let created = match metadata.get("timestamp") {
        None => crate::model::civil(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |since| since.as_secs() as i64)),
        Some(timestamp) => {
            let text = timestamp.as_str().ok_or_else(|| Error::Type("fromisoformat: argument must be str".to_owned()))?;
            parse_iso(text).ok_or_else(|| Error::Value(format!("Invalid isoformat string: {}", crate::pyrepr::repr(text))))?
        }
    };
    let [year, month, day, hour, minute, second] = created;
    let organization = match metadata.get("supplier") {
        Some(supplier) => object(supplier, "supplier")?.get("name").map(py_str).unwrap_or_default(),
        None => String::new(),
    };
    let mut creators = Vec::new();
    if !organization.is_empty() {
        creators.push(Json::Str(format!("Organization: {organization}")));
    }
    creators.extend(tool_creators.into_iter().map(Json::Str));
    creators.push(Json::Str(format!("Tool: python-sbom-{tool_version}")));
    Ok(Json::Obj(Obj(vec![
        pair("created", Json::Str(format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z"))),
        pair("creators", Json::Arr(creators)),
    ])))
}

/// `datetime.fromisoformat(text).astimezone(UTC)` for the forms a CycloneDX timestamp takes; a time without an offset
/// counts as UTC
fn parse_iso(text: &str) -> Option<[i64; 6]> {
    let digits = |part: &str| -> Option<i64> { (!part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit())).then(|| part.parse().ok()).flatten() };
    let (date, rest) = if text.len() >= 10 { text.split_at(10) } else { return None };
    let mut date_parts = date.split('-');
    let (year, month, day) = (digits(date_parts.next()?)?, digits(date_parts.next()?)?, digits(date_parts.next()?)?);
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let (mut hour, mut minute, mut second, mut offset) = (0, 0, 0, 0i64);
    if !rest.is_empty() {
        let rest = rest.strip_prefix(['T', ' '])?;
        let (clock, zone) = match rest.find(['+', '-', 'Z']) {
            Some(at) => rest.split_at(at),
            None => (rest, ""),
        };
        let clock = clock.split('.').next()?;
        let mut parts = clock.split(':');
        hour = digits(parts.next()?)?;
        minute = parts.next().map_or(Some(0), digits)?;
        second = parts.next().map_or(Some(0), digits)?;
        if !zone.is_empty() && zone != "Z" {
            let sign = if zone.starts_with('-') { -1 } else { 1 };
            let mut zone_parts = zone[1..].split(':');
            let hours = digits(zone_parts.next()?)?;
            let minutes = zone_parts.next().map_or(Some(0), digits)?;
            offset = sign * (hours * 3600 + minutes * 60);
        }
    }
    let days = days_from_civil(year, month, day);
    Some(crate::model::civil(days * 86_400 + hour * 3600 + minute * 60 + second - offset))
}

fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let day_of_year = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

fn relationship(element: String, kind: &str, related: String) -> Json {
    Json::Obj(Obj(vec![
        pair("spdxElementId", Json::Str(element)),
        pair("relationshipType", Json::str(kind)),
        pair("relatedSpdxElement", Json::Str(related)),
    ]))
}

fn relationships(document: &Obj, root: &Json, components: &[&Json], tools: &[&Json]) -> Result<Vec<Json>> {
    let reference = |component: &Json| -> Result<String> { Ok(spdx_id(&text(object(component, "component")?, "bom-ref")?)) };
    let root_id = reference(root)?;
    let mut found = vec![relationship("SPDXRef-DOCUMENT".to_owned(), "DESCRIBES", root_id.clone())];
    for parent in components {
        let parent_object = object(parent, "component")?;
        for child in items(parent_object, "components") {
            if index(object(child, "component")?, "type")?.as_str() != Some("file") {
                found.push(relationship(reference(parent)?, "CONTAINS", reference(child)?));
            }
        }
    }
    for entry in items(document, "dependencies") {
        let entry = object(entry, "dependency")?;
        for dependency in items(entry, "dependsOn") {
            found.push(relationship(spdx_id(&text(entry, "ref")?), "DEPENDS_ON", spdx_id(&py_str(dependency))));
        }
    }
    for tool in tools {
        found.push(relationship(reference(tool)?, "BUILD_TOOL_OF", root_id.clone()));
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_and_times() {
        assert!(spdx_id("pkg:pypi/a@1").starts_with("SPDXRef-pkg-pypi-a-1-"));
        assert_eq!(parse_iso("2023-11-14T22:13:20+00:00"), Some([2023, 11, 14, 22, 13, 20]));
        assert_eq!(parse_iso("2023-11-14T23:13:20+01:00"), Some([2023, 11, 14, 22, 13, 20]));
        assert_eq!(parse_iso("2023-11-14"), Some([2023, 11, 14, 0, 0, 0]));
    }
}
