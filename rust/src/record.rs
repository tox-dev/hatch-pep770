//! Wheel RECORD files: CSV rows as installer parses them, and their digests as CycloneDX names them.

use crate::error::{Error, Result};
use crate::pyrepr::repr;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordRow {
    pub path: String,
    pub algorithm: String,
    pub digest: String,
    pub size: String,
}

/// a row as `installer.records.RecordEntry.from_elements` validates it
pub struct RecordEntry<'a> {
    pub path: &'a str,
    pub hash: Option<(&'a str, &'a str)>,
    pub size: Option<i128>,
}

/// `installer.records.InvalidRecordEntry`, whose message joins its issues
pub struct InvalidRecordEntry {
    pub issues: Vec<String>,
}

impl InvalidRecordEntry {
    pub fn message(&self) -> String {
        self.issues.join(", ")
    }
}

/// the algorithms `hashlib.algorithms_available` names, which installer accepts in a RECORD
const HASHLIB: &[&str] = &[
    "blake2b",
    "blake2s",
    "md5",
    "md5-sha1",
    "ripemd160",
    "sha1",
    "sha224",
    "sha256",
    "sha384",
    "sha3_224",
    "sha3_256",
    "sha3_384",
    "sha3_512",
    "sha512",
    "sha512_224",
    "sha512_256",
    "shake_128",
    "shake_256",
    "sm3",
];

/// `parse_record_file(text.splitlines())`: each row's three elements, with backslashes in the path made forward
pub fn parse_record(text: &str) -> std::result::Result<Vec<[String; 3]>, InvalidRecordEntry> {
    let mut rows = Vec::new();
    for (index, line) in splitlines(text).into_iter().enumerate() {
        let mut elements = csv_row(line);
        if elements.len() != 3 {
            return Err(InvalidRecordEntry {
                issues: vec![format!("Row Index {index}: expected 3 elements, got {}", elements.len())],
            });
        }
        elements[0] = elements[0].replace('\\', "/");
        let size = elements.pop().unwrap_or_default();
        let hash = elements.pop().unwrap_or_default();
        let path = elements.pop().unwrap_or_default();
        rows.push([path, hash, size]);
    }
    Ok(rows)
}

impl<'a> RecordEntry<'a> {
    pub fn from_elements(row: &'a [String; 3]) -> std::result::Result<Self, InvalidRecordEntry> {
        let [path, hash, size] = row;
        let mut issues = Vec::new();
        if path.is_empty() {
            issues.push("`path` cannot be empty".to_owned());
        }
        let mut parsed_hash = None;
        if !hash.is_empty() {
            match hash.split_once('=') {
                Some((name, value)) if HASHLIB.contains(&name) => parsed_hash = Some((name, value)),
                Some((name, _)) => issues.push(format!("invalid hash algorithm '{name}'")),
                None => issues.push("`hash` does not follow the required format".to_owned()),
            }
        }
        let mut parsed_size = None;
        if !size.is_empty() {
            match py_int(size) {
                Some(value) => parsed_size = Some(value),
                None => issues.push("`size` cannot be non-integer".to_owned()),
            }
        }
        if issues.is_empty() { Ok(Self { path, hash: parsed_hash, size: parsed_size }) } else { Err(InvalidRecordEntry { issues }) }
    }

    /// `str(entry.size)`, which is "None" for a row without a size
    pub fn size_text(&self) -> String {
        self.size.map_or_else(|| "None".to_owned(), |size| size.to_string())
    }
}

/// `int(text)`: surrounding whitespace, a sign, and underscores between digits
fn py_int(text: &str) -> Option<i128> {
    let trimmed = crate::names::py_strip(text);
    let (negative, digits) = match trimmed.as_bytes().first() {
        Some(b'-') => (true, &trimmed[1..]),
        Some(b'+') => (false, &trimmed[1..]),
        _ => (false, trimmed),
    };
    if digits.is_empty() || digits.starts_with('_') || digits.ends_with('_') || digits.contains("__") {
        return None;
    }
    let mut value: i128 = 0;
    for character in digits.chars() {
        if character == '_' {
            continue;
        }
        let digit = character.to_digit(10)?;
        value = value.checked_mul(10)?.checked_add(i128::from(digit))?;
    }
    Some(if negative { -value } else { value })
}

/// `str.splitlines()`
pub fn splitlines(text: &str) -> Vec<&str> {
    let mut lines = Vec::new();
    let mut start = 0;
    let mut chars = text.char_indices().peekable();
    while let Some((index, character)) = chars.next() {
        let end = match character {
            '\r' => {
                if let Some(&(_, '\n')) = chars.peek() {
                    chars.next();
                }
                index
            }
            '\n' | '\x0b' | '\x0c' | '\x1c' | '\x1d' | '\x1e' | '\u{85}' | '\u{2028}' | '\u{2029}' => index,
            _ => continue,
        };
        lines.push(&text[start..end]);
        start = chars.peek().map_or(text.len(), |&(next, _)| next);
    }
    if start < text.len() {
        lines.push(&text[start..]);
    }
    lines
}

/// one line through `csv.reader` with the excel dialect
fn csv_row(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    if line.is_empty() {
        return fields;
    }
    let mut field = String::new();
    let mut quoted = false;
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();
    let mut at_start = true;
    while let Some(character) = chars.next() {
        if in_quotes {
            if character == '"' {
                if chars.peek() == Some(&'"') {
                    field.push('"');
                    chars.next();
                } else {
                    in_quotes = false;
                }
            } else {
                field.push(character);
            }
            continue;
        }
        match character {
            ',' => {
                fields.push(std::mem::take(&mut field));
                quoted = false;
                at_start = true;
                continue;
            }
            '"' if at_start && !quoted => {
                quoted = true;
                in_quotes = true;
            }
            _ => field.push(character),
        }
        at_start = false;
    }
    fields.push(field);
    fields
}

/// `decode_digest`: a RECORD digest as the CycloneDX algorithm name and lowercase hex
pub fn decode_digest(digest: &str, location: &str) -> Result<(&'static str, String)> {
    let (name, encoded) = digest.split_once('=').unwrap_or((digest, ""));
    let algorithm = match name {
        "md5" => "MD5",
        "sha1" => "SHA-1",
        "sha256" => "SHA-256",
        "sha384" => "SHA-384",
        "sha512" => "SHA-512",
        _ => return Err(Error::Wheel(format!("{location}: unknown hash algorithm {}", repr(name)))),
    };
    let raw = urlsafe_b64decode(encoded)
        .ok_or_else(|| Error::Wheel(format!("{location}: digest {} is not urlsafe base64", repr(encoded))))?;
    Ok((algorithm, to_hex(&raw)))
}

pub fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0xF)]));
    }
    out
}

/// `base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))`, with binascii's lenient handling of characters
/// outside the alphabet
fn urlsafe_b64decode(encoded: &str) -> Option<Vec<u8>> {
    let padding = (4 - encoded.len() % 4) % 4;
    let mut out = Vec::with_capacity(encoded.len() * 3 / 4);
    let mut quad = 0u32;
    let mut position = 0u8;
    let mut pads = 0u8;
    for byte in encoded.bytes().chain(std::iter::repeat_n(b'=', padding)) {
        let byte = match byte {
            b'-' => b'+',
            b'_' => b'/',
            other => other,
        };
        if byte == b'=' {
            pads += 1;
            if position >= 2 && position + pads >= 4 {
                // a complete quantum: binascii stops here and ignores the rest
                return Some(flush(&mut out, quad, position));
            }
            continue;
        }
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => continue,
        };
        pads = 0;
        quad = (quad << 6) | u32::from(value);
        position += 1;
        if position == 4 {
            out.extend_from_slice(&[(quad >> 16) as u8, (quad >> 8) as u8, quad as u8]);
            quad = 0;
            position = 0;
        }
    }
    (position == 0).then_some(out)
}

fn flush(out: &mut Vec<u8>, quad: u32, position: u8) -> Vec<u8> {
    match position {
        2 => out.push((quad >> 4) as u8),
        3 => out.extend_from_slice(&[(quad >> 10) as u8, (quad >> 2) as u8]),
        _ => {}
    }
    std::mem::take(out)
}

/// the urlsafe base64 RECORD form of a digest, without padding
pub fn record_digest(raw: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digests() {
        let (algorithm, digest) = decode_digest("sha256=47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU", "x").unwrap();
        assert_eq!(algorithm, "SHA-256");
        assert_eq!(digest, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert!(decode_digest("sha256=abcde", "x").is_err());
        assert!(decode_digest("crc=00", "x").is_err());
    }

    #[test]
    fn csv() {
        assert_eq!(csv_row("a,b,c"), vec!["a", "b", "c"]);
        assert_eq!(csv_row("\"a,b\",,"), vec!["a,b", "", ""]);
        assert_eq!(csv_row("a\"b,c"), vec!["a\"b", "c"]);
        assert!(csv_row("").is_empty());
        assert_eq!(splitlines("a\r\nb\rc\n\nd"), vec!["a", "b", "c", "", "d"]);
    }
}
