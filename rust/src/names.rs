//! Names, links and identifiers derived from project metadata.

use crate::email::Metadata;
use crate::pep508::canonicalize_name;

pub const SBOM_FILE: &str = "sbom:file";
pub const SBOM_REPOSITORY: &str = "sbom:repository";

pub fn property_prefix(name: &str) -> String {
    canonicalize_name(name)
}

pub fn sbom_file_name(name: &str) -> String {
    format!("{}.cdx.json", property_prefix(name))
}

pub fn tool_ref(reference: &str) -> String {
    format!("tool:{reference}")
}

pub fn pypi_url(name: &str, version: Option<&str>) -> String {
    match version {
        Some(version) if !version.is_empty() => format!("https://pypi.org/project/{name}/{version}/"),
        _ => format!("https://pypi.org/project/{name}/"),
    }
}

/// `PackageURL(type=kind, name=name, version=version).to_string()` as packageurl-python builds it: normalized once by
/// the constructor, then again with percent-encoding by `to_string`
pub fn purl(kind: &str, name: &str, version: Option<&str>) -> String {
    let normalize_name = |text: &str| {
        let text = py_strip(text).trim_matches('/');
        if kind == "pypi" { text.to_lowercase().replace('_', "-") } else { text.to_owned() }
    };
    let name = normalize_name(&quote(&normalize_name(name)));
    let mut out = String::with_capacity(16 + name.len());
    out.push_str("pkg:");
    out.push_str(kind);
    out.push('/');
    out.push_str(&name);
    if let Some(version) = version.map(py_strip).filter(|version| !version.is_empty()) {
        let version = quote(py_strip(version));
        if !version.is_empty() {
            out.push('@');
            out.push_str(&version);
        }
    }
    out
}

pub fn pypi_purl(name: &str, version: Option<&str>) -> String {
    purl("pypi", name, version)
}

/// `urllib.parse.quote(text)` with `%3A` turned back into `:`
fn quote(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-' | b'~' | b'/' | b':') {
            out.push(char::from(byte));
        } else {
            out.push('%');
            out.push(char::from(b"0123456789ABCDEF"[usize::from(byte >> 4)]));
            out.push(char::from(b"0123456789ABCDEF"[usize::from(byte & 0xF)]));
        }
    }
    out
}

/// `str.strip()`: Python's whitespace includes the ASCII separators 0x1c to 0x1f
pub fn py_strip(text: &str) -> &str {
    text.trim_matches(|character: char| character.is_whitespace() || ('\x1c'..='\x1f').contains(&character))
}

/// the CycloneDX reference type of a Project-URL label, as cyclonedx-py maps it
pub fn reference_type(label: &str) -> &'static str {
    let key: String = label.to_lowercase().chars().filter(char::is_ascii_lowercase).collect();
    match key.as_str() {
        "bugtracker" | "issuetracker" | "issues" | "issue" | "bugs" | "bugreports" | "tracker" => "issue-tracker",
        "home" | "homepage" => "website",
        "download" => "distribution",
        "documentation" | "docs" => "documentation",
        "changelog" | "changes" | "whatsnew" | "history" | "releasenotes" => "release-notes",
        "source" | "sourcecode" | "repository" | "github" => "vcs",
        "chat" => "chat",
        _ => "other",
    }
}

pub fn project_urls(metadata: &Metadata) -> Vec<(&str, &str)> {
    metadata
        .get_all("Project-URL")
        .filter_map(|entry| entry.split_once(','))
        .map(|(label, url)| (py_strip(label), py_strip(url)))
        .collect()
}

/// `urlsplit(url).scheme`, lowercased as urllib returns it
pub fn url_scheme(url: &str) -> String {
    // urlsplit strips leading C0 controls and spaces, and drops tabs and newlines anywhere
    let cleaned: String =
        url.trim_start_matches(|character: char| character <= ' ').chars().filter(|c| !matches!(c, '\t' | '\r' | '\n')).collect();
    if let Some(colon) = cleaned.find(':') {
        let scheme = &cleaned[..colon];
        if !scheme.is_empty()
            && scheme.as_bytes()[0].is_ascii_alphabetic()
            && scheme.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
        {
            return scheme.to_ascii_lowercase();
        }
    }
    String::new()
}

/// `urlsplit(url).netloc`
pub fn url_netloc(url: &str) -> String {
    let cleaned: String =
        url.trim_start_matches(|character: char| character <= ' ').chars().filter(|c| !matches!(c, '\t' | '\r' | '\n')).collect();
    let scheme = url_scheme(url);
    let rest = if scheme.is_empty() { cleaned.as_str() } else { &cleaned[scheme.len() + 1..] };
    rest.strip_prefix("//").map_or_else(String::new, |after| {
        after.split(['/', '?', '#']).next().unwrap_or("").to_owned()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn purls() {
        assert_eq!(pypi_purl("Pkg.Name", Some("1.0")), "pkg:pypi/pkg.name@1.0");
        assert_eq!(pypi_purl("my_pkg", Some("1.0+local")), "pkg:pypi/my-pkg@1.0%2Blocal");
        assert_eq!(purl("generic", "virtualenv.pyz", Some("20.1")), "pkg:generic/virtualenv.pyz@20.1");
        assert_eq!(pypi_purl("x", None), "pkg:pypi/x");
    }

    #[test]
    fn references() {
        assert_eq!(reference_type("Bug Tracker"), "issue-tracker");
        assert_eq!(reference_type("Funding"), "other");
        assert_eq!(url_netloc("https://github.com/a/b"), "github.com");
        assert_eq!(url_scheme("HTTPS://x"), "https");
        assert_eq!(url_scheme("UNKNOWN"), "");
    }
}
