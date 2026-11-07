//! The document model as an ordered JSON tree, written byte for byte as Python's `json.dumps` writes it.
//!
//! Objects keep insertion order with dict semantics (assigning an existing key keeps its position), numbers keep the
//! text Python would print, and strings are escaped as `ensure_ascii=True` escapes them.

use std::fmt::Write as _;

#[derive(Clone, Debug, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    /// the number exactly as `json.dumps` prints it: an int's digits or a float's `repr`
    Num(String),
    Str(String),
    Arr(Vec<Json>),
    Obj(Obj),
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Obj(pub Vec<(String, Json)>);

impl Obj {
    pub fn with_capacity(capacity: usize) -> Self {
        Self(Vec::with_capacity(capacity))
    }

    /// dict assignment: replace in place, or append a new key
    pub fn set(&mut self, key: &str, value: Json) {
        if let Some(slot) = self.0.iter_mut().find(|(name, _)| name == key) {
            slot.1 = value;
        } else {
            self.0.push((key.to_owned(), value));
        }
    }

    /// append a key the caller knows is new, skipping the lookup
    pub fn push(&mut self, key: &str, value: Json) {
        self.0.push((key.to_owned(), value));
    }

    pub fn get(&self, key: &str) -> Option<&Json> {
        self.0.iter().find(|(name, _)| name == key).map(|(_, value)| value)
    }

    pub fn get_mut(&mut self, key: &str) -> Option<&mut Json> {
        self.0.iter_mut().find(|(name, _)| name == key).map(|(_, value)| value)
    }

    pub fn str(&self, key: &str) -> Option<&str> {
        self.get(key).and_then(Json::as_str)
    }

    pub fn arr(&self, key: &str) -> Option<&[Json]> {
        self.get(key).and_then(Json::as_arr)
    }
}

impl Json {
    pub fn str(value: impl Into<String>) -> Self {
        Self::Str(value.into())
    }

    pub fn int(value: i64) -> Self {
        Self::Num(value.to_string())
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Str(text) => Some(text),
            _ => None,
        }
    }

    pub fn as_arr(&self) -> Option<&[Json]> {
        match self {
            Self::Arr(items) => Some(items),
            _ => None,
        }
    }

    pub fn as_obj(&self) -> Option<&Obj> {
        match self {
            Self::Obj(object) => Some(object),
            _ => None,
        }
    }

    /// Python truthiness, as `if value:` judges a JSON value
    pub fn truthy(&self) -> bool {
        match self {
            Self::Null => false,
            Self::Bool(value) => *value,
            Self::Num(text) => text.bytes().any(|byte| byte.is_ascii_digit() && byte != b'0'),
            Self::Str(text) => !text.is_empty(),
            Self::Arr(items) => !items.is_empty(),
            Self::Obj(object) => !object.0.is_empty(),
        }
    }
}

/// `f"{json.dumps(value, indent=2)}\n".encode()`
pub fn dumps_pretty(value: &Json) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 << 16);
    write_pretty(value, 0, &mut out);
    out.push(b'\n');
    out
}

fn write_pretty(value: &Json, depth: usize, out: &mut Vec<u8>) {
    match value {
        Json::Arr(items) if !items.is_empty() => {
            out.push(b'[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                newline(depth + 1, out);
                write_pretty(item, depth + 1, out);
            }
            newline(depth, out);
            out.push(b']');
        }
        Json::Obj(object) if !object.0.is_empty() => {
            out.push(b'{');
            for (index, (key, item)) in object.0.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                newline(depth + 1, out);
                write_string(key, out);
                out.extend_from_slice(b": ");
                write_pretty(item, depth + 1, out);
            }
            newline(depth, out);
            out.push(b'}');
        }
        scalar => write_scalar(scalar, out),
    }
}

fn newline(depth: usize, out: &mut Vec<u8>) {
    out.push(b'\n');
    out.resize(out.len() + 2 * depth, b' ');
}

/// `json.dumps(value, sort_keys=True)`: default separators, keys in code point order
pub fn dumps_sorted(value: &Json) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 << 16);
    write_sorted(value, &mut out);
    out
}

fn write_sorted(value: &Json, out: &mut Vec<u8>) {
    match value {
        Json::Arr(items) => {
            out.push(b'[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.extend_from_slice(b", ");
                }
                write_sorted(item, out);
            }
            out.push(b']');
        }
        Json::Obj(object) => {
            let mut entries: Vec<&(String, Json)> = object.0.iter().collect();
            // UTF-8 byte order is code point order, which is how Python sorts str keys
            entries.sort_unstable_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
            out.push(b'{');
            for (index, (key, item)) in entries.into_iter().enumerate() {
                if index > 0 {
                    out.extend_from_slice(b", ");
                }
                write_string(key, out);
                out.extend_from_slice(b": ");
                write_sorted(item, out);
            }
            out.push(b'}');
        }
        scalar => write_scalar(scalar, out),
    }
}

fn write_scalar(value: &Json, out: &mut Vec<u8>) {
    match value {
        Json::Null => out.extend_from_slice(b"null"),
        Json::Bool(true) => out.extend_from_slice(b"true"),
        Json::Bool(false) => out.extend_from_slice(b"false"),
        Json::Num(text) => out.extend_from_slice(text.as_bytes()),
        Json::Str(text) => write_string(text, out),
        Json::Arr(_) => out.extend_from_slice(b"[]"),
        Json::Obj(_) => out.extend_from_slice(b"{}"),
    }
}

const HEX: &[u8; 16] = b"0123456789abcdef";

/// a string as `ensure_ascii=True` writes it: printable ASCII as is, everything else escaped
pub fn write_string(text: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    let bytes = text.as_bytes();
    let mut start = 0;
    for (index, &byte) in bytes.iter().enumerate() {
        if (0x20..0x7f).contains(&byte) && byte != b'"' && byte != b'\\' {
            continue;
        }
        if byte >= 0x80 && !is_char_start(byte) {
            continue;
        }
        out.extend_from_slice(&bytes[start..index]);
        if byte >= 0x80 {
            let character = text[index..].chars().next().unwrap_or('\u{fffd}');
            escape_code_point(u32::from(character), out);
            start = index + character.len_utf8();
            continue;
        }
        match byte {
            b'"' => out.extend_from_slice(b"\\\""),
            b'\\' => out.extend_from_slice(b"\\\\"),
            b'\n' => out.extend_from_slice(b"\\n"),
            b'\r' => out.extend_from_slice(b"\\r"),
            b'\t' => out.extend_from_slice(b"\\t"),
            0x08 => out.extend_from_slice(b"\\b"),
            0x0c => out.extend_from_slice(b"\\f"),
            _ => escape_unit(u16::from(byte), out),
        }
        start = index + 1;
    }
    // a multi-byte character at the very end was handled in the loop, so only ASCII can remain
    if start < bytes.len() {
        out.extend_from_slice(&bytes[start..]);
    }
    out.push(b'"');
}

const fn is_char_start(byte: u8) -> bool {
    byte & 0xC0 != 0x80
}

fn escape_code_point(code: u32, out: &mut Vec<u8>) {
    if code > 0xFFFF {
        let value = code - 0x10000;
        escape_unit(0xD800 | ((value >> 10) as u16), out);
        escape_unit(0xDC00 | ((value & 0x3FF) as u16), out);
    } else {
        escape_unit(code as u16, out);
    }
}

fn escape_unit(unit: u16, out: &mut Vec<u8>) {
    out.extend_from_slice(&[
        b'\\',
        b'u',
        HEX[usize::from(unit >> 12)],
        HEX[usize::from((unit >> 8) & 0xF)],
        HEX[usize::from((unit >> 4) & 0xF)],
        HEX[usize::from(unit & 0xF)],
    ]);
}

/// `repr(float)`, as `json.dumps` prints a float
pub fn float_repr(value: f64) -> String {
    if value.is_nan() {
        return "NaN".to_owned();
    }
    if value.is_infinite() {
        return if value > 0.0 { "Infinity" } else { "-Infinity" }.to_owned();
    }
    // the shortest digits that round-trip, as Python's repr picks them
    let scientific = format!("{value:e}");
    let (mantissa, exponent) = scientific.split_once('e').unwrap_or((&scientific, "0"));
    let exponent: i32 = exponent.parse().unwrap_or(0);
    let negative = mantissa.starts_with('-');
    let digits: String = mantissa.chars().filter(char::is_ascii_digit).collect();
    let mut out = String::with_capacity(digits.len() + 8);
    if negative {
        out.push('-');
    }
    if (-4..16).contains(&exponent) {
        let point = exponent + 1;
        if point <= 0 {
            out.push_str("0.");
            out.extend(std::iter::repeat_n('0', point.unsigned_abs() as usize));
            out.push_str(&digits);
        } else {
            let point = point as usize;
            if digits.len() <= point {
                out.push_str(&digits);
                out.extend(std::iter::repeat_n('0', point - digits.len()));
                out.push_str(".0");
            } else {
                out.push_str(&digits[..point]);
                out.push('.');
                out.push_str(&digits[point..]);
            }
        }
    } else {
        out.push_str(&digits[..1]);
        if digits.len() > 1 {
            out.push('.');
            out.push_str(&digits[1..]);
        }
        let _ = write!(out, "e{}{:02}", if exponent < 0 { '-' } else { '+' }, exponent.unsigned_abs());
    }
    out
}

/// a parsed JSON value, as `json.loads` would hand it to `json.dumps`
pub fn from_serde(value: &serde_json::Value) -> Json {
    match value {
        serde_json::Value::Null => Json::Null,
        serde_json::Value::Bool(flag) => Json::Bool(*flag),
        serde_json::Value::Number(number) => Json::Num(number_text(number)),
        serde_json::Value::String(text) => Json::Str(text.clone()),
        serde_json::Value::Array(items) => Json::Arr(items.iter().map(from_serde).collect()),
        serde_json::Value::Object(map) => {
            // json.loads keeps the last of repeated keys, as serde_json does
            Json::Obj(Obj(map.iter().map(|(key, item)| (key.clone(), from_serde(item))).collect()))
        }
    }
}

fn number_text(number: &serde_json::Number) -> String {
    if let Some(integer) = number.as_i64() {
        integer.to_string()
    } else if let Some(integer) = number.as_u64() {
        integer.to_string()
    } else {
        float_repr(number.as_f64().unwrap_or(f64::NAN))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn floats_match_python_repr() {
        for (value, expected) in [
            (1.0, "1.0"),
            (1.5, "1.5"),
            (0.1, "0.1"),
            (1e16, "1e+16"),
            (1e15, "1000000000000000.0"),
            (0.0001, "0.0001"),
            (0.00001, "1e-05"),
            (-2.5e-7, "-2.5e-07"),
            (123_456.789, "123456.789"),
            (1.7976931348623157e308, "1.7976931348623157e+308"),
            (-0.0, "-0.0"),
        ] {
            assert_eq!(float_repr(value), expected);
        }
    }

    #[test]
    fn strings_escape_as_ensure_ascii() {
        let mut out = Vec::new();
        write_string("a\"b\\c\n\u{7f}é😀\u{1}", &mut out);
        assert_eq!(String::from_utf8(out).unwrap(), "\"a\\\"b\\\\c\\n\\u007f\\u00e9\\ud83d\\ude00\\u0001\"");
    }

    #[test]
    fn pretty_and_sorted() {
        let mut object = Obj::default();
        object.push("b", Json::Arr(vec![]));
        object.push("a", Json::Arr(vec![Json::int(1), Json::Obj(Obj::default())]));
        let value = Json::Obj(object);
        assert_eq!(
            String::from_utf8(dumps_pretty(&value)).unwrap(),
            "{\n  \"b\": [],\n  \"a\": [\n    1,\n    {}\n  ]\n}\n"
        );
        assert_eq!(String::from_utf8(dumps_sorted(&value)).unwrap(), "{\"a\": [1, {}], \"b\": []}");
    }
}
