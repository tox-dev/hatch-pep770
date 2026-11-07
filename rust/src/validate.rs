//! The checks the Python validator delegated to cyclonedx-python-lib, spdx-tools and license-expression: the CycloneDX
//! 1.6 schema, the SPDX 2.3 rendering and the license policy. Each mirrors the verdicts of the library it replaces, quirks
//! included, so a document passes here exactly when it passed there.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, OnceLock};

use regex::Regex;
use serde_json::Value;

// the schemas cyclonedx-python-lib 11.12 ships and registers under these URIs
const BOM_SCHEMA: &str = include_str!("../schemas/bom-1.6.SNAPSHOT.schema.json");
const SPDX_SCHEMA: &str = include_str!("../schemas/spdx.SNAPSHOT.schema.json");
const JSF_SCHEMA: &str = include_str!("../schemas/jsf-0.82.SNAPSHOT.schema.json");
const SCHEMA_PREFIX: &str = "http://cyclonedx.org/schema/";
// license-expression 30.4.4's vendored ScanCode index (SPDX list 3.27), reduced to the entries with an SPDX key: key,
// L or E for license or exception, then the other SPDX keys that alias it
const LICENSE_KEYS: &str = include_str!("../schemas/license-keys.tsv");
// the jsonschema error message and path are cut here, as the Python validator cuts them
const MAX_TEXT: usize = 200;

/// Build the compiled schema validator and the license tables once, so callers can time or front-load the cost.
pub fn warm_up() {
    cyclonedx();
    spdx_licensing();
    policy_licensing();
    patterns();
}

/// The first CycloneDX 1.6 schema violation, as `<message> at <JSONPath>`, or `None` for a conforming document.
pub fn schema_error(document: &Value) -> Option<String> {
    let error = cyclonedx().iter_errors(document).next()?;
    let message = python_message(&error);
    let path = json_path(error.instance_path().as_str());
    Some(format!("{} at {}", truncate(&message, MAX_TEXT), truncate(&path, MAX_TEXT)))
}

// the wording of Python jsonschema's error for each keyword, values in Python's repr; enough of the instance is rendered
// for the message to fill the cut, so a megabyte document root costs no more than a short one
fn python_message(error: &jsonschema::ValidationError<'_>) -> String {
    use jsonschema::error::{TypeKind, ValidationErrorKind as Kind};
    let instance = || py_value_repr(error.instance(), MAX_TEXT + 1);
    match error.kind() {
        Kind::Type { kind: TypeKind::Single(kind) } => format!("{} is not of type {}", instance(), py_repr(kind.as_str())),
        Kind::Type { kind: TypeKind::Multiple(kinds) } => format!(
            "{} is not of type {}",
            instance(),
            kinds.iter().map(|kind| py_repr(kind.as_str())).collect::<Vec<_>>().join(", ")
        ),
        Kind::Required { property } => format!("{} is a required property", py_value_repr(property, MAX_TEXT + 1)),
        Kind::Enum { options } => format!("{} is not one of {}", instance(), py_value_repr(options, MAX_TEXT + 1)),
        Kind::Constant { expected_value } => format!("{} was expected", py_value_repr(expected_value, MAX_TEXT + 1)),
        Kind::Pattern { pattern } => {
            let original = pattern.strip_suffix("\\n?$").map_or_else(|| pattern.clone(), |head| format!("{head}$"));
            format!("{} does not match {}", instance(), py_repr(&original))
        }
        Kind::Format { format } => format!("{} is not a {}", instance(), py_repr(format)),
        Kind::AdditionalProperties { unexpected } => {
            let mut names: Vec<&String> = unexpected.iter().collect();
            names.sort();
            let verb = if names.len() == 1 { "was" } else { "were" };
            let names = names.iter().map(|name| py_repr(name)).collect::<Vec<_>>().join(", ");
            format!("Additional properties are not allowed ({names} {verb} unexpected)")
        }
        Kind::AnyOf { .. } | Kind::OneOfNotValid { .. } => {
            format!("{} is not valid under any of the given schemas", instance())
        }
        Kind::OneOfMultipleValid { .. } => format!("{} is valid under each of the given schemas", instance()),
        Kind::UniqueItems => format!("{} has non-unique elements", instance()),
        Kind::MinItems { limit } | Kind::MinLength { limit } => {
            format!("{} {}", instance(), if *limit == 1 { "should be non-empty" } else { "is too short" })
        }
        Kind::MaxItems { limit } | Kind::MaxLength { limit } => {
            format!("{} {}", instance(), if *limit == 0 { "is expected to be empty" } else { "is too long" })
        }
        Kind::MinProperties { limit } => format!(
            "{} {}",
            instance(),
            if *limit == 1 { "should be non-empty" } else { "does not have enough properties" }
        ),
        Kind::Minimum { limit } => format!("{} is less than the minimum of {}", instance(), py_value_repr(limit, MAX_TEXT)),
        Kind::Maximum { limit } => format!("{} is greater than the maximum of {}", instance(), py_value_repr(limit, MAX_TEXT)),
        Kind::FalseSchema => format!("False schema does not allow {}", instance()),
        _ => error.to_string(),
    }
}

// repr() of the Python value json.loads gives, cut once it passes `limit` characters
fn py_value_repr(value: &Value, limit: usize) -> String {
    fn write(value: &Value, out: &mut String, limit: usize) {
        if out.len() > limit * 4 {
            return;
        }
        match value {
            Value::Null => out.push_str("None"),
            Value::Bool(true) => out.push_str("True"),
            Value::Bool(false) => out.push_str("False"),
            Value::Number(number) => out.push_str(&number.to_string()),
            Value::String(text) => out.push_str(&py_repr(text)),
            Value::Array(items) => {
                out.push('[');
                for (index, item) in items.iter().enumerate() {
                    if index > 0 {
                        out.push_str(", ");
                    }
                    write(item, out, limit);
                    if out.len() > limit * 4 {
                        return;
                    }
                }
                out.push(']');
            }
            Value::Object(map) => {
                out.push('{');
                for (index, (key, item)) in map.iter().enumerate() {
                    if index > 0 {
                        out.push_str(", ");
                    }
                    out.push_str(&py_repr(key));
                    out.push_str(": ");
                    write(item, out, limit);
                    if out.len() > limit * 4 {
                        return;
                    }
                }
                out.push('}');
            }
        }
    }
    let mut out = String::new();
    write(value, &mut out, limit);
    out
}

/// What spdx-tools' parser and full-document validator report for an SPDX 2.3 JSON document.
pub fn spdx_problems(spdx: &Value) -> Vec<String> {
    let parsed = match SpdxDocument::parse(spdx) {
        Ok(parsed) => parsed,
        Err(messages) => {
            return messages
                .into_iter()
                .map(|message| format!("SPDX rendering does not parse: {message}"))
                .collect();
        }
    };
    parsed
        .validate()
        .into_iter()
        .map(|message| format!("SPDX rendering invalid: {message}"))
        .collect()
}

/// The license policy: every shipped library must declare SPDX ids within `allowed`, matched without regard to case.
pub fn license_problems(components: &[Value], allowed: &[String]) -> Vec<String> {
    let folded: HashSet<String> = allowed.iter().map(|id| casefold(id)).collect();
    let mut sorted_allowed: Vec<&String> = allowed.iter().collect::<HashSet<_>>().into_iter().collect();
    sorted_allowed.sort();
    let allowed_repr = py_list_repr(sorted_allowed.iter().map(|s| s.as_str()));
    shipped(components)
        .into_iter()
        .filter_map(|component| {
            let problem = judge(component, &folded, &allowed_repr)?;
            let label = component
                .get("bom-ref")
                .or_else(|| component.get("name"))
                .map(py_str)
                .unwrap_or_default();
            Some(format!("{label}: {problem}"))
        })
        .collect()
}

// ------------------------------------------------------------------------------------------------------------------
// CycloneDX schema
// ------------------------------------------------------------------------------------------------------------------

fn cyclonedx() -> &'static jsonschema::Validator {
    static VALIDATOR: OnceLock<jsonschema::Validator> = OnceLock::new();
    VALIDATOR.get_or_init(|| {
        let mut bom: Value = serde_json::from_str(BOM_SCHEMA).expect("the embedded BOM schema is JSON");
        python_patterns(&mut bom);
        let spdx: Value = serde_json::from_str(SPDX_SCHEMA).expect("the embedded SPDX schema is JSON");
        let jsf: Value = serde_json::from_str(JSF_SCHEMA).expect("the embedded JSF schema is JSON");
        // registered under the SNAPSHOT names the BOM schema references and the $id each declares
        let registry = jsonschema::Registry::new()
            .add(format!("{SCHEMA_PREFIX}spdx.SNAPSHOT.schema.json"), spdx.clone())
            .and_then(|registry| registry.add(format!("{SCHEMA_PREFIX}spdx.schema.json"), spdx))
            .and_then(|registry| registry.add(format!("{SCHEMA_PREFIX}jsf-0.82.SNAPSHOT.schema.json"), jsf.clone()))
            .and_then(|registry| registry.add(format!("{SCHEMA_PREFIX}jsf-0.82.schema.json"), jsf))
            .and_then(|registry| registry.prepare())
            .expect("the embedded schemas register");
        jsonschema::draft7::options()
            .with_registry(&registry)
            .should_validate_formats(true)
            // jsonschema's format checker: an e-mail is anything holding "@", a date-time what rfc3339-validator
            // accepts after upper-casing, and an IRI reference what rfc3987-syntax's grammar parses
            .with_format("idn-email", |value: &str| value.contains('@'))
            .with_format("email", |value: &str| value.contains('@'))
            .with_format("date-time", is_rfc3339)
            .with_format("iri-reference", |value: &str| patterns().iri_reference.is_match(value))
            .build(&bom)
            .expect("the embedded BOM schema compiles")
    })
}

// Python's `re.search` lets `$` match before a final newline, which ECMA-262 does not, so every pattern that ends in
// `$` also takes one trailing newline
fn python_patterns(schema: &mut Value) {
    match schema {
        Value::Object(map) => {
            for (key, value) in map.iter_mut() {
                match value {
                    Value::String(pattern) if key == "pattern" && pattern.ends_with('$') => {
                        pattern.insert_str(pattern.len() - 1, "\\n?");
                    }
                    _ => python_patterns(value),
                }
            }
        }
        Value::Array(items) => items.iter_mut().for_each(python_patterns),
        _ => {}
    }
}

fn json_path(pointer: &str) -> String {
    let mut path = String::from("$");
    for segment in pointer.split('/').skip(1) {
        let segment = segment.replace("~1", "/").replace("~0", "~");
        let mut characters = segment.chars();
        if !segment.is_empty() && segment.bytes().all(|byte| byte.is_ascii_digit()) {
            path.push('[');
            path.push_str(&segment);
            path.push(']');
        } else if characters.next().is_some_and(|first| first.is_ascii_alphabetic())
            && characters.all(|rest| rest.is_ascii_alphanumeric() || rest == '_')
        {
            path.push('.');
            path.push_str(&segment);
        } else {
            path.push_str("['");
            path.push_str(&segment.replace('\\', "\\\\").replace('\'', "\\'"));
            path.push_str("']");
        }
    }
    path
}

fn is_rfc3339(value: &str) -> bool {
    let upper = value.to_uppercase();
    let Some(captures) = patterns().rfc3339.captures(&upper) else {
        return false;
    };
    let number = |index: usize| captures[index].parse::<u32>().unwrap_or(0);
    let (year, month, day) = (number(1), number(2), number(3));
    year != 0 && (1..=days_in_month(year, month)).contains(&day)
}

fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ if (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400) => 29,
        _ => 28,
    }
}

struct Patterns {
    rfc3339: Regex,
    iri_reference: Regex,
    url: Regex,
    purl: Regex,
    created: Regex,
    tool: Regex,
    organization: Regex,
    person: Regex,
    scheme: Regex,
}

fn patterns() -> &'static Patterns {
    static PATTERNS: OnceLock<Patterns> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        let compile = |pattern: &str| Regex::new(pattern).expect("the embedded pattern compiles");
        Patterns {
            rfc3339: compile(
                r"\A([0-9]{4})-(0[1-9]|1[0-2])-([0-9]{2})T(?:[01][0-9]|2[0123]):[0-5][0-9]:[0-5][0-9](?:\.[0-9]+)?(?:Z|[+-](?:[01][0-9]|2[0123]):[0-5][0-9])\n?\z",
            ),
            iri_reference: compile(&iri_reference_pattern()),
            // spdx-tools' uri_validators.url_pattern, matched case-insensitively from the start
            url: compile(
                r"(?i)\A(?:http://www\.|https://www\.|http://|https://|ssh://|git://|svn://|sftp://|ftp://)?(?:[\w\-.!~*'()%;:&=+$,]+@)?[a-z0-9]+(?:[\-.][a-z0-9]+){0,100}\.[a-z]{2,5}",
            ),
            // spdx-tools' PURL_REGEX: its optional groups add nothing to what `pkg:.+/.+` already accepts
            purl: compile(r"\Apkg:.+/.+\n?\z"),
            // what datetime.strptime accepts for "%Y-%m-%dT%H:%M:%SZ"
            created: compile(
                r"(?i)\A([0-9]{4})-(1[0-2]|0[1-9]|[1-9])-(3[01]|[12][0-9]|0[1-9]|[1-9]| [1-9])T(2[0-3]|[0-1][0-9]|[0-9]):([0-5][0-9]|[0-9]):(6[0-1]|[0-5][0-9]|[0-9])Z\z",
            ),
            tool: compile(r"\ATool:\s*(.+)"),
            person: compile(r"\APerson:\s*(?:(.*)\((.*)\)|(.*))\n?\z"),
            organization: compile(r"\AOrganization:\s*(?:(.*)\((.*)\)|(.*))\n?\z"),
            scheme: compile(r"\A[A-Za-z][A-Za-z0-9+.\-]*:"),
        }
    })
}

// rfc3987-syntax's Lark grammar for iri_reference, as one regular expression; it departs from RFC 3987 where the grammar
// does: ucschar and iprivate stop at the Basic Multilingual Plane, and an IPv6 literal must spell all eight groups
// around its single "::" in one of the nine fixed layouts the grammar lists
fn iri_reference_pattern() -> String {
    let hexdig = "[0-9A-Fa-f]";
    let ucschar = r"[\u{A0}-\u{D7FF}\u{F900}-\u{FDCF}\u{FDF0}-\u{FFEF}]";
    let iprivate = r"[\u{E000}-\u{F8FF}]";
    let iunreserved = format!(r"(?:[A-Za-z0-9\-._~]|{ucschar})");
    let pct = format!("%{hexdig}{hexdig}");
    let sub_delims = r"[!$&'()*+,;=]";
    let ipchar = format!("(?:{iunreserved}|{pct}|{sub_delims}|[:@])");
    let isegment = format!("{ipchar}*");
    let isegment_nz = format!("{ipchar}+");
    let isegment_nz_nc = format!("(?:{iunreserved}|{pct}|{sub_delims}|@)+");
    let iquery = format!("(?:{ipchar}|{iprivate}|[/?])*");
    let ifragment = format!("(?:{ipchar}|[/?])*");
    let scheme = r"[A-Za-z][A-Za-z0-9+\-.]*";
    let dec_octet = "(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])";
    let ipv4 = format!(r"{dec_octet}\.{dec_octet}\.{dec_octet}\.{dec_octet}");
    let h16 = format!("{hexdig}{{1,4}}");
    let ls32 = format!("(?:{h16}:{h16}|{ipv4})");
    let groups = |count: usize| format!("{h16}:").repeat(count);
    let leading = |count: usize| {
        (0..count).map(|_| h16.clone()).collect::<Vec<_>>().join(":")
    };
    let ipv6 = [
        format!("{}{ls32}", groups(6)),
        format!("::{}{ls32}", groups(5)),
        format!("{}::{}{ls32}", leading(1), groups(4)),
        format!("{}::{}{ls32}", leading(2), groups(3)),
        format!("{}::{}{ls32}", leading(3), groups(2)),
        format!("{}::{}{ls32}", leading(4), groups(1)),
        format!("{}::{ls32}", leading(5)),
        format!("{}::{h16}", leading(6)),
        format!("{}::", leading(7)),
    ]
    .join("|");
    let unreserved = r"[A-Za-z0-9\-._~]";
    let ipvfuture = format!(r"v{hexdig}+\.(?:{unreserved}|{sub_delims}|:)+");
    let ip_literal = format!(r"\[(?:{ipv6}|{ipvfuture})\]");
    let ireg_name = format!("(?:{iunreserved}|{pct}|{sub_delims})*");
    let ihost = format!("(?:{ip_literal}|{ipv4}|{ireg_name})");
    let iuserinfo = format!("(?:{iunreserved}|{pct}|{sub_delims}|:)*");
    let iauthority = format!("(?:{iuserinfo}@)?{ihost}(?::[0-9]*)?");
    let ipath_abempty = format!("(?:/{isegment})*");
    let ipath_absolute = format!("/(?:{isegment_nz}(?:/{isegment})*)?");
    let ipath_noscheme = format!("{isegment_nz_nc}(?:/{isegment})*");
    let ipath_rootless = format!("{isegment_nz}(?:/{isegment})*");
    let ihier_part = format!("(?://{iauthority}{ipath_abempty}|{ipath_absolute}|{ipath_rootless}|)");
    let irelative_part = format!("(?://{iauthority}{ipath_abempty}|{ipath_absolute}|{ipath_noscheme}|)");
    let tail = format!(r"(?:\?{iquery})?(?:#{ifragment})?");
    format!(r"\A(?:{scheme}:{ihier_part}{tail}|{irelative_part}{tail})\z")
}

// ------------------------------------------------------------------------------------------------------------------
// license expressions, as license-expression's Licensing parses them
// ------------------------------------------------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct Symbol {
    key: Arc<str>,
    is_exception: bool,
    known: bool,
}

#[derive(Clone, Debug)]
enum Expr {
    Symbol(Symbol),
    With(Symbol, Symbol),
    And(Vec<Expr>),
    Or(Vec<Expr>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Keyword {
    And,
    Or,
    With,
    LeftParen,
    RightParen,
}

#[derive(Clone, Debug)]
enum TokenValue {
    Unmatched,
    Keyword(Keyword),
    Symbol(Symbol),
}

#[derive(Clone, Debug)]
struct Token {
    start: i64,
    end: i64,
    string: String,
    value: TokenValue,
}

impl Token {
    fn len(&self) -> i64 {
        self.end - self.start + 1
    }
}

// which Python exception a parse ends in: ExpressionParseError, another ExpressionError, or anything else (an
// IndexError or AssertionError from boolean.py's parser)
#[derive(Debug)]
enum LicenseError {
    Parse(String),
    Expression(String),
    Other(String),
}

// boolean.py's ParseError text: the message, the token and, past the first character, its position
fn parse_error(message: &str, token: &str, position: i64) -> LicenseError {
    let mut text = message.to_string();
    if !token.is_empty() {
        text.push_str(&format!(" for token: \"{token}\""));
    }
    if position > 0 {
        text.push_str(&format!(" at position: {position}"));
    }
    LicenseError::Parse(text)
}

const INVALID_EXPRESSION: &str = "Invalid expression";
const INVALID_NESTING: &str = "Invalid expression nesting such as (AND xx)";
const INVALID_EXCEPTION: &str = "A license exception symbol can only be used as an exception in a \"WITH exception\" statement.";
const INVALID_SYMBOL_AS_EXCEPTION: &str = "A plain license symbol cannot be used as an exception in a \"WITH symbol\" statement.";

impl LicenseError {
    fn message(&self) -> &str {
        match self {
            Self::Parse(message) | Self::Expression(message) | Self::Other(message) => message,
        }
    }
}

struct Licensing {
    // every key as its lower-cased word sequence, keyed by its last word: (words, the string as added, value)
    by_last_word: HashMap<String, Vec<(Vec<String>, String, TokenValue)>>,
    known_words: HashSet<String>,
}

impl Licensing {
    fn new(with_aliases: bool) -> Self {
        let mut licensing = Self { by_last_word: HashMap::new(), known_words: HashSet::new() };
        for (text, keyword) in [
            ("and", Keyword::And),
            ("or", Keyword::Or),
            ("(", Keyword::LeftParen),
            (")", Keyword::RightParen),
            ("with", Keyword::With),
        ] {
            licensing.add(text, TokenValue::Keyword(keyword));
        }
        for line in LICENSE_KEYS.lines().filter(|line| !line.is_empty()) {
            let mut fields = line.split('\t');
            let key = fields.next().unwrap_or_default();
            let is_exception = fields.next() == Some("E");
            let symbol = Symbol { key: Arc::from(key), is_exception, known: true };
            licensing.add(key, TokenValue::Symbol(symbol.clone()));
            if with_aliases {
                for alias in fields.filter(|alias| !alias.is_empty()) {
                    let alias = py_split(alias).join(" ");
                    licensing.add(&alias, TokenValue::Symbol(symbol.clone()));
                }
            }
        }
        for entries in licensing.by_last_word.values_mut() {
            // the automaton reports the longest match ending at a word first
            entries.sort_by_key(|(words, _, _)| std::cmp::Reverse(words.len()));
        }
        licensing
    }

    fn add(&mut self, text: &str, value: TokenValue) {
        let words: Vec<String> = word_tokens(&text.to_lowercase())
            .into_iter()
            .filter(|(word, _)| !py_strip(word).is_empty())
            .map(|(word, _)| word)
            .collect();
        let Some(last) = words.last().cloned() else {
            return;
        };
        self.known_words.extend(words.iter().cloned());
        let entries = self.by_last_word.entry(last).or_default();
        // the trie keeps the latest value added for a word sequence
        if let Some(entry) = entries.iter_mut().find(|(existing, _, _)| *existing == words) {
            *entry = (words, text.to_string(), value);
        } else {
            entries.push((words, text.to_string(), value));
        }
    }

    // _pyahocorasick.Trie.tokenize: matched keys and the unmatched words between them, overlaps resolved
    fn match_tokens(&self, expression: &str) -> Vec<Token> {
        let lowered = expression.to_lowercase();
        let original: Vec<char> = expression.chars().collect();
        let slice = |start: i64, end: i64| -> String {
            let start = start.max(0) as usize;
            let end = ((end + 1).max(0) as usize).min(original.len());
            if start >= end { String::new() } else { original[start..end].iter().collect() }
        };
        let mut tokens: Vec<Token> = Vec::new();
        let mut seen: Vec<String> = Vec::new();
        let mut end_pos: i64 = -1;
        for (word, length) in word_tokens(&lowered) {
            end_pos += length as i64;
            if py_strip(&word).is_empty() {
                continue;
            }
            if !self.known_words.contains(&word) {
                // an unknown word resets the automaton: no key spans it
                seen.clear();
                let start = end_pos - length as i64 + 1;
                tokens.push(Token { start, end: end_pos, string: slice(start, end_pos), value: TokenValue::Unmatched });
                continue;
            }
            seen.push(word.clone());
            let mut yielded = false;
            if let Some(entries) = self.by_last_word.get(&word) {
                for (words, text, value) in entries {
                    if words.len() <= seen.len() && seen[seen.len() - words.len()..] == words[..] {
                        let start = end_pos - text.chars().count() as i64 + 1;
                        tokens.push(Token { start, end: end_pos, string: slice(start, end_pos), value: value.clone() });
                        yielded = true;
                    }
                }
            }
            if !yielded {
                let start = end_pos - length as i64 + 1;
                tokens.push(Token { start, end: end_pos, string: slice(start, end_pos), value: TokenValue::Unmatched });
            }
        }
        tokens.retain(|token| !py_strip(&token.string).is_empty());
        filter_overlapping(tokens)
    }

    // Licensing.parse(expression, strict=strict): Ok(None) for a blank expression
    fn parse(&self, expression: &str, strict: bool) -> Result<Option<Expr>, LicenseError> {
        if expression.is_empty() || py_strip(expression).is_empty() {
            return Ok(None);
        }
        let tokens = symbols_from_unknown_tokens(self.match_tokens(expression))?;
        let tokens: Vec<Token> = tokens.into_iter().filter(|token| !py_strip(&token.string).is_empty()).collect();
        let tokens = with_subexpressions(tokens, strict)?;
        parse_boolean(tokens).map(Some)
    }
}

fn spdx_licensing() -> &'static Licensing {
    static LICENSING: OnceLock<Licensing> = OnceLock::new();
    LICENSING.get_or_init(|| Licensing::new(true))
}

fn policy_licensing() -> &'static Licensing {
    static LICENSING: OnceLock<Licensing> = OnceLock::new();
    LICENSING.get_or_init(|| Licensing::new(false))
}

// _pyahocorasick.get_tokens: runs of text, runs of whitespace and single parentheses, with their length in characters
fn word_tokens(text: &str) -> Vec<(String, usize)> {
    #[derive(PartialEq)]
    enum Kind {
        Text,
        Space,
    }
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut length = 0;
    let mut kind = Kind::Text;
    let flush = |current: &mut String, length: &mut usize, tokens: &mut Vec<(String, usize)>| {
        if *length > 0 {
            tokens.push((std::mem::take(current), *length));
            *length = 0;
        }
    };
    for character in text.chars() {
        if character == '(' || character == ')' {
            flush(&mut current, &mut length, &mut tokens);
            tokens.push((character.to_string(), 1));
            continue;
        }
        let this = if py_isspace(character) { Kind::Space } else { Kind::Text };
        if this != kind {
            flush(&mut current, &mut length, &mut tokens);
            kind = this;
        }
        current.push(character);
        length += 1;
    }
    flush(&mut current, &mut length, &mut tokens);
    tokens
}

fn filter_overlapping(mut tokens: Vec<Token>) -> Vec<Token> {
    tokens.sort_by_key(|token| (token.start, -token.len()));
    let mut i = 0;
    while tokens.len() > 1 && i < tokens.len() - 1 {
        let mut j = i + 1;
        while j < tokens.len() {
            let (current, next) = (&tokens[i], &tokens[j]);
            if next.start > current.end {
                break;
            }
            if current.start <= next.start && next.end <= current.end {
                tokens.remove(j);
                continue;
            }
            let overlap = (current.start <= next.start && next.start <= current.end)
                || (current.start <= next.end && next.end <= current.end);
            if overlap {
                if current.len() >= next.len() {
                    tokens.remove(j);
                    continue;
                }
                tokens.remove(i);
                break;
            }
            j += 1;
        }
        i += 1;
    }
    tokens
}

fn symbols_from_unknown_tokens(tokens: Vec<Token>) -> Result<Vec<Token>, LicenseError> {
    let mut result = Vec::with_capacity(tokens.len());
    let mut unmatched: Vec<Token> = Vec::new();
    let flush = |unmatched: &mut Vec<Token>, result: &mut Vec<Token>| -> Result<(), LicenseError> {
        let mut trailing = Vec::new();
        while unmatched.last().is_some_and(|token| py_strip(&token.string).is_empty()) {
            trailing.push(unmatched.pop().expect("checked above"));
        }
        if !unmatched.is_empty() {
            let string = unmatched
                .iter()
                .filter(|token| !py_strip(&token.string).is_empty())
                .map(|token| token.string.as_str())
                .collect::<Vec<_>>()
                .join(" ");
            let key = license_key(&string)?;
            let start = unmatched[0].start;
            let end = unmatched[unmatched.len() - 1].end;
            unmatched.clear();
            result.push(Token {
                start,
                end,
                string,
                value: TokenValue::Symbol(Symbol { key: Arc::from(key), is_exception: false, known: false }),
            });
        }
        result.extend(trailing);
        Ok(())
    };
    for token in tokens {
        if matches!(token.value, TokenValue::Unmatched) {
            if unmatched.is_empty() && py_strip(&token.string).is_empty() {
                result.push(token);
            } else {
                unmatched.push(token);
            }
        } else {
            flush(&mut unmatched, &mut result)?;
            result.push(token);
        }
    }
    flush(&mut unmatched, &mut result)?;
    Ok(result)
}

// LicenseSymbol(key): the key validation an unknown symbol goes through
fn license_key(key: &str) -> Result<String, LicenseError> {
    let stripped = py_strip(key);
    if stripped.is_empty() {
        return Err(LicenseError::Expression(format!("A license key cannot be blank: {}", py_repr(key))));
    }
    let body = stripped.strip_suffix('\n').unwrap_or(stripped);
    let valid = !body.is_empty()
        && body
            .chars()
            .all(|c| matches!(c, '-' | ':' | '.' | '+' | '_') || c.is_alphanumeric() || py_isspace(c));
    if !valid {
        return Err(LicenseError::Expression(format!(
            "Invalid license key: the valid characters are: letters and numbers, underscore, dot, colon or hyphen \
             signs and spaces: {}",
            py_repr(stripped)
        )));
    }
    let normalized = py_split(stripped).join(" ");
    if ["and", "or", "with", "(", ")"].contains(&normalized.to_lowercase().as_str()) {
        return Err(LicenseError::Expression(format!(
            "Invalid license key: a key cannot be a reserved keyword: \"or\", \"and\" or \"with\": {}",
            py_repr(&normalized)
        )));
    }
    Ok(normalized)
}

#[derive(Clone, Debug)]
enum Parsed {
    Keyword(Keyword),
    Symbol(Expr),
}

fn with_subexpressions(tokens: Vec<Token>, strict: bool) -> Result<Vec<(Parsed, String, i64)>, LicenseError> {
    let invalid = |token: &Token, what: &str| parse_error(what, &token.string, token.start);
    let is_with = |triple: &[Token]| {
        matches!(triple[0].value, TokenValue::Symbol(_))
            && matches!(triple[1].value, TokenValue::Keyword(Keyword::With))
            && matches!(triple[2].value, TokenValue::Symbol(_))
    };
    // build_token_groups_for_with_subexpression: a sliding window of three that emits "A WITH B" as one group
    let mut groups: Vec<Vec<Token>> = Vec::new();
    if tokens.len() < 3 {
        groups.extend(tokens.into_iter().map(|token| vec![token]));
    } else {
        let mut triple: std::collections::VecDeque<Token> = std::collections::VecDeque::new();
        for token in tokens {
            if triple.len() == 3 {
                if is_with(triple.make_contiguous()) {
                    groups.push(triple.drain(..).collect());
                } else {
                    groups.push(vec![triple.pop_front().expect("three tokens")]);
                }
            }
            triple.push_back(token);
        }
        if triple.len() == 3 && is_with(triple.make_contiguous()) {
            groups.push(triple.drain(..).collect());
        } else {
            groups.extend(triple.into_iter().map(|token| vec![token]));
        }
    }
    let mut result = Vec::with_capacity(groups.len());
    for group in groups {
        if group.len() == 1 {
            let token = &group[0];
            match &token.value {
                TokenValue::Keyword(Keyword::With) => return Err(invalid(token, INVALID_EXPRESSION)),
                TokenValue::Keyword(keyword) => {
                    result.push((Parsed::Keyword(*keyword), token.string.clone(), token.start));
                }
                TokenValue::Symbol(symbol) => {
                    if strict && symbol.is_exception {
                        return Err(invalid(token, INVALID_EXCEPTION));
                    }
                    result.push((Parsed::Symbol(Expr::Symbol(symbol.clone())), token.string.clone(), token.start));
                }
                TokenValue::Unmatched => return Err(LicenseError::Other("Licensing.tokenize is internally confused".into())),
            }
            continue;
        }
        let (TokenValue::Symbol(license), TokenValue::Symbol(exception)) = (&group[0].value, &group[2].value) else {
            return Err(invalid(&group[0], "A proper license symbol is needed."));
        };
        if strict && license.is_exception {
            return Err(invalid(&group[0], INVALID_EXCEPTION));
        }
        if strict && !exception.is_exception {
            return Err(invalid(&group[2], INVALID_SYMBOL_AS_EXCEPTION));
        }
        let string = format!("{} {} {}", group[0].string, py_strip(&group[1].string), group[2].string);
        result.push((Parsed::Symbol(Expr::With(license.clone(), exception.clone())), string, group[0].start));
    }
    Ok(result)
}

// boolean.py's BooleanAlgebra.parse over license-expression's tokens, with its list-based AST, so the inputs it rejects
// and the exception it rejects them with stay the same
#[derive(Debug)]
enum Node {
    Nil,
    Ast(Vec<Node>),
    And,
    Or,
    LeftParen,
    Expr(Expr),
}

fn precedence(node: &Node) -> Result<u8, LicenseError> {
    match node {
        Node::And => Ok(10),
        Node::Or => Ok(15),
        Node::LeftParen => Ok(20),
        _ => Err(LicenseError::Other("KeyError".into())),
    }
}

fn call(function: &Node, args: Vec<Node>) -> Result<Expr, LicenseError> {
    let and = match function {
        Node::And => true,
        Node::Or => false,
        _ => return Err(LicenseError::Other("TypeError: object is not callable".into())),
    };
    if args.len() < 2 {
        let name = if and { "AND" } else { "OR" };
        return Err(LicenseError::Expression(format!(
            "{name} requires two or more licenses as in: MIT {name} BSD"
        )));
    }
    let mut exprs = Vec::with_capacity(args.len());
    for arg in args {
        match arg {
            Node::Expr(expr) => exprs.push(expr),
            _ => return Err(LicenseError::Other("AssertionError: Bad arguments".into())),
        }
    }
    Ok(if and { Expr::And(exprs) } else { Expr::Or(exprs) })
}

fn take_parent(ast: &mut [Node]) -> Vec<Node> {
    match std::mem::replace(&mut ast[0], Node::Nil) {
        Node::Ast(parent) => parent,
        _ => unreachable!("checked by the caller"),
    }
}

fn start_operation(mut ast: Vec<Node>, operation: Node) -> Result<Vec<Node>, LicenseError> {
    let op_precedence = precedence(&operation)?;
    loop {
        if matches!(ast[1], Node::Nil) {
            ast[1] = operation;
            return Ok(ast);
        }
        let current = precedence(&ast[1])?;
        if current > op_precedence {
            let last = ast.pop().expect("an AST holds at least its parent and operation");
            return Ok(vec![Node::Ast(ast), operation, last]);
        }
        if current == op_precedence {
            return Ok(ast);
        }
        if !matches!(ast[1], Node::And | Node::Or) {
            return Err(parse_error(INVALID_NESTING, "", -1));
        }
        let args: Vec<Node> = ast.drain(2..).collect();
        let subexpression = call(&ast[1], args)?;
        if matches!(ast[0], Node::Nil) {
            return Ok(vec![Node::Nil, operation, Node::Expr(subexpression)]);
        }
        let mut parent = take_parent(&mut ast);
        parent.push(Node::Expr(subexpression));
        ast = parent;
    }
}

fn parse_boolean(tokens: Vec<(Parsed, String, i64)>) -> Result<Expr, LicenseError> {
    let is_operator = |token: &Parsed| matches!(token, Parsed::Keyword(Keyword::And | Keyword::Or));
    let mut ast: Vec<Node> = vec![Node::Nil, Node::Nil];
    let mut previous: Option<Parsed> = None;
    const SYMBOL_SEQUENCE: &str = "Invalid symbols sequence such as (A B)";
    const OPERATOR_SEQUENCE: &str = "Invalid operator sequence without symbols such as AND OR or OR OR";
    for (token, string, position) in tokens {
        if let Some(previous) = &previous {
            if matches!(previous, Parsed::Symbol(_)) && matches!(token, Parsed::Symbol(_)) {
                return Err(parse_error(SYMBOL_SEQUENCE, &string, position));
            }
            if is_operator(previous) && (is_operator(&token) || matches!(token, Parsed::Keyword(Keyword::RightParen))) {
                return Err(parse_error(OPERATOR_SEQUENCE, &string, position));
            }
        } else if is_operator(&token) {
            return Err(parse_error(OPERATOR_SEQUENCE, &string, position));
        }
        match &token {
            Parsed::Symbol(expr) => ast.push(Node::Expr(expr.clone())),
            Parsed::Keyword(Keyword::And) => ast = start_operation(ast, Node::And)?,
            Parsed::Keyword(Keyword::Or) => ast = start_operation(ast, Node::Or)?,
            Parsed::Keyword(Keyword::LeftParen) => {
                if let Some(previous) = &previous
                    && !matches!(previous, Parsed::Keyword(Keyword::And | Keyword::Or | Keyword::LeftParen))
                {
                    return Err(parse_error(INVALID_NESTING, &string, position));
                }
                ast = vec![Node::Ast(ast), Node::LeftParen];
            }
            Parsed::Keyword(Keyword::RightParen) => loop {
                if matches!(ast[0], Node::Nil) {
                    return Err(parse_error("Unbalanced parenthesis", &string, position));
                }
                if matches!(ast[1], Node::LeftParen) {
                    if ast.len() < 3 {
                        return Err(LicenseError::Other("IndexError: list index out of range".into()));
                    }
                    let inner = ast.swap_remove(2);
                    let mut parent = take_parent(&mut ast);
                    parent.push(inner);
                    ast = parent;
                    break;
                }
                if !matches!(ast[1], Node::And | Node::Or) {
                    return Err(parse_error(INVALID_NESTING, &string, position));
                }
                let args: Vec<Node> = ast.drain(2..).collect();
                let subexpression = call(&ast[1], args)?;
                let mut parent = take_parent(&mut ast);
                parent.push(Node::Expr(subexpression));
                ast = parent;
            },
            Parsed::Keyword(Keyword::With) => {
                return Err(parse_error("Unknown token", &string, position));
            }
        }
        previous = Some(token);
    }
    // the final reduction, whose TypeError boolean.py reports as a parse error
    let as_parse = |error: LicenseError| match error {
        LicenseError::Other(message) if message.starts_with("TypeError") => parse_error(INVALID_EXPRESSION, "", -1),
        other => other,
    };
    let parsed = loop {
        if matches!(ast[0], Node::Nil) {
            if matches!(ast[1], Node::Nil) {
                if ast.len() != 3 {
                    return Err(parse_error(INVALID_EXPRESSION, "", -1));
                }
                break ast.pop().expect("three elements");
            }
            let args: Vec<Node> = ast.drain(2..).collect();
            break Node::Expr(call(&ast[1], args).map_err(as_parse)?);
        }
        let args: Vec<Node> = ast.drain(2..).collect();
        let subexpression = call(&ast[1], args).map_err(as_parse)?;
        let mut parent = take_parent(&mut ast);
        parent.push(Node::Expr(subexpression));
        ast = parent;
    };
    match parsed {
        Node::Expr(expr) => Ok(expr),
        _ => Err(LicenseError::Expression("expression must be a LicenseExpression once parsed.".into())),
    }
}

impl Expr {
    // get_literals with decompose: license symbols in order, a WITH contributing its license and its exception
    fn symbols<'a>(&'a self, found: &mut Vec<&'a Symbol>) {
        match self {
            Self::Symbol(symbol) => found.push(symbol),
            Self::With(license, exception) => {
                found.push(license);
                found.push(exception);
            }
            Self::And(args) | Self::Or(args) => args.iter().for_each(|arg| arg.symbols(found)),
        }
    }

    // what a strict parse rejects: an exception on its own or left of WITH, or a license right of WITH
    fn misuses_exceptions(&self) -> bool {
        match self {
            Self::Symbol(symbol) => symbol.is_exception,
            Self::With(license, exception) => license.is_exception || !exception.is_exception,
            Self::And(args) | Self::Or(args) => args.iter().any(Self::misuses_exceptions),
        }
    }

    // _validate/_licenses._allowed: a WITH is judged by its license alone
    fn allowed(&self, folded: &HashSet<String>) -> bool {
        match self {
            Self::Symbol(symbol) | Self::With(symbol, _) => folded.contains(&casefold(&symbol.key)),
            Self::And(args) => args.iter().all(|arg| arg.allowed(folded)),
            Self::Or(args) => args.iter().any(|arg| arg.allowed(folded)),
        }
    }
}

// ------------------------------------------------------------------------------------------------------------------
// license policy
// ------------------------------------------------------------------------------------------------------------------

fn shipped(components: &[Value]) -> Vec<&Value> {
    let mut found = Vec::new();
    let mut pending: Vec<&Value> = components.iter().rev().collect();
    while let Some(component) = pending.pop() {
        let children = component.get("components").and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[]);
        let is_library = component.get("type").and_then(Value::as_str) == Some("library");
        if is_library
            && (component.get("hashes").is_some()
                || children.iter().any(|child| child.get("type").and_then(Value::as_str) == Some("file")))
        {
            found.push(component);
        }
        pending.extend(children.iter().rev());
    }
    found
}

fn judge(component: &Value, folded: &HashSet<String>, allowed_repr: &str) -> Option<String> {
    let licenses = component.get("licenses").and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[]);
    let terms: Vec<&str> = licenses
        .iter()
        .filter_map(|entry| match entry.get("expression") {
            Some(expression) => expression.as_str(),
            None => entry.get("license").and_then(|license| license.get("id")).and_then(Value::as_str),
        })
        .collect();
    if terms.is_empty() {
        let names: Vec<&str> = licenses
            .iter()
            .filter_map(|entry| entry.get("license").and_then(|license| license.get("name")).and_then(Value::as_str))
            .collect();
        if !names.is_empty() {
            return Some(format!("declares license names {} with no SPDX id", py_list_repr(names.into_iter())));
        }
        return Some("declares no license".to_string());
    }
    let mut denied = Vec::new();
    for term in terms {
        let tree = match policy_licensing().parse(term, false) {
            Ok(Some(tree)) => tree,
            Ok(None) => return Some(format!("license expression {} is malformed: it is empty", py_repr(term))),
            Err(LicenseError::Expression(message) | LicenseError::Parse(message)) => {
                return Some(format!("license expression {} is malformed: {message}", py_repr(term)));
            }
            Err(LicenseError::Other(_)) => {
                return Some(format!("license expression {} is malformed: it does not parse", py_repr(term)));
            }
        };
        if !tree.allowed(folded) {
            denied.push(term);
        }
    }
    if denied.is_empty() {
        return None;
    }
    Some(format!("license {} is outside the allowed licenses {allowed_repr}", denied.join(" AND ")))
}

// ------------------------------------------------------------------------------------------------------------------
// SPDX 2.3: spdx-tools' JsonLikeDictParser, then validate_full_spdx_document
// ------------------------------------------------------------------------------------------------------------------

const RELATIONSHIP_TYPES: &[&str] = &[
    "AMENDS", "ANCESTOR_OF", "BUILD_DEPENDENCY_OF", "BUILD_TOOL_OF", "CONTAINED_BY", "CONTAINS", "COPY_OF",
    "DATA_FILE_OF", "DEPENDENCY_MANIFEST_OF", "DEPENDENCY_OF", "DEPENDS_ON", "DESCENDANT_OF", "DESCRIBED_BY",
    "DESCRIBES", "DEV_DEPENDENCY_OF", "DEV_TOOL_OF", "DISTRIBUTION_ARTIFACT", "DOCUMENTATION_OF",
    "DYNAMIC_LINK", "EXAMPLE_OF", "EXPANDED_FROM_ARCHIVE", "FILE_ADDED", "FILE_DELETED", "FILE_MODIFIED",
    "GENERATED_FROM", "GENERATES", "HAS_PREREQUISITE", "METAFILE_OF", "OPTIONAL_COMPONENT_OF",
    "OPTIONAL_DEPENDENCY_OF", "OTHER", "PACKAGE_OF", "PATCH_APPLIED", "PATCH_FOR", "PREREQUISITE_FOR",
    "PROVIDED_DEPENDENCY_OF", "RUNTIME_DEPENDENCY_OF", "STATIC_LINK", "TEST_CASE_OF", "TEST_DEPENDENCY_OF",
    "TEST_OF", "TEST_TOOL_OF", "VARIANT_OF", "REQUIREMENT_DESCRIPTION_FOR", "SPECIFICATION_FOR",
];
const PURPOSES: &[&str] = &[
    "APPLICATION", "FRAMEWORK", "LIBRARY", "CONTAINER", "OPERATING_SYSTEM", "DEVICE", "FIRMWARE", "SOURCE",
    "ARCHIVE", "FILE", "INSTALL", "OTHER",
];

#[derive(Clone, Copy)]
enum Digits {
    Exactly(usize),
    AtLeast(usize),
    UpTo(usize),
}

fn checksum_digits(algorithm: &str) -> Option<Digits> {
    Some(match algorithm {
        "SHA1" => Digits::Exactly(40),
        "SHA224" => Digits::Exactly(56),
        "SHA256" | "SHA3_256" | "BLAKE2B_256" => Digits::Exactly(64),
        "SHA384" | "SHA3_384" | "BLAKE2B_384" => Digits::Exactly(96),
        "SHA512" | "SHA3_512" | "BLAKE2B_512" => Digits::Exactly(128),
        "BLAKE3" => Digits::AtLeast(256),
        "MD2" | "MD4" | "MD5" => Digits::Exactly(32),
        "MD6" => Digits::UpTo(512),
        "ADLER32" => Digits::Exactly(8),
        _ => return None,
    })
}

enum LicenseField {
    Absent,
    NoAssertion,
    Expression(String, Option<Expr>),
}

struct Package {
    spdx_id: String,
    license_concluded: LicenseField,
    license_declared: LicenseField,
    homepage: Option<String>,
    checksums: Vec<(String, String)>,
    external_refs: Vec<(String, String, String)>,
}

struct SpdxDocument {
    spdx_version: String,
    spdx_id: String,
    data_license: Option<String>,
    namespace: String,
    packages: Vec<Package>,
    relationships: Vec<(String, String, Option<String>)>,
    extracted: Vec<(Option<String>, Option<String>)>,
}

fn json_enum(value: &Value) -> Result<String, String> {
    match value {
        Value::String(text) => Ok(text.replace('-', "_").to_uppercase()),
        other => Err(format!("Type for enum must be str not {}", py_type(other))),
    }
}

fn truthy(value: Option<&Value>) -> Option<&Value> {
    value.filter(|value| match value {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::Number(number) => number.as_f64() != Some(0.0),
        Value::String(text) => !text.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(map) => !map.is_empty(),
    })
}

fn required_str(map: &Value, key: &str, owner: &str, errors: &mut Vec<String>) -> String {
    match map.get(key) {
        Some(Value::String(text)) => text.clone(),
        other => {
            errors.push(format!("{owner}: {key} must be a string, got {}", other.map_or("None", py_type)));
            String::new()
        }
    }
}

fn optional_str(map: &Value, key: &str, owner: &str, errors: &mut Vec<String>) {
    if let Some(value) = map.get(key)
        && !matches!(value, Value::String(_) | Value::Null)
    {
        errors.push(format!("{owner}: {key} must be a string, got {}", py_type(value)));
    }
}

fn parse_actor(actor: &Value) -> Result<(), String> {
    let Value::String(actor) = actor else {
        return Err(format!("expected string or bytes-like object, got '{}'", py_type(actor)));
    };
    let patterns = patterns();
    if let Some(captures) = patterns.tool.captures(actor) {
        if py_strip(&captures[1]).is_empty() {
            return Err(format!("No name for Tool provided: {actor}."));
        }
        return Ok(());
    }
    let Some(captures) = patterns.person.captures(actor).or_else(|| patterns.organization.captures(actor)) else {
        return Err(format!("Actor {actor} doesn't match any of person, organization or tool."));
    };
    if captures.get(3).is_some_and(|name| !name.as_str().is_empty()) {
        return Ok(());
    }
    if captures.get(1).is_none_or(|name| name.as_str().is_empty()) {
        return Err(format!("No name for Actor provided: {actor}."));
    }
    Ok(())
}

fn parse_created(created: &Value) -> Result<(), String> {
    let Value::String(created) = created else {
        return Err(format!("Could not convert str to datetime, invalid type: {}", py_type(created)));
    };
    let Some(captures) = patterns().created.captures(created) else {
        return Err(format!("time data {} does not match format '%Y-%m-%dT%H:%M:%SZ'", py_repr(created)));
    };
    let number = |index: usize| py_strip(&captures[index]).parse::<u32>().unwrap_or(0);
    let (year, month, day, second) = (number(1), number(2), number(3), number(6));
    if year == 0 || day > days_in_month(year, month) || second > 59 {
        return Err(format!("time data {} is not a valid date", py_repr(created)));
    }
    Ok(())
}

fn parse_license(value: Option<&Value>, errors: &mut Vec<String>) -> Result<LicenseField, String> {
    let Some(value) = truthy(value) else {
        return Ok(LicenseField::Absent);
    };
    let Value::String(text) = value else {
        errors.push(format!("Error parsing LicenseExpression: \"{value}\": expression must be a string"));
        return Ok(LicenseField::Absent);
    };
    let upper = text.to_uppercase();
    if upper == "NOASSERTION" || upper == "NONE" {
        return Ok(LicenseField::NoAssertion);
    }
    match spdx_licensing().parse(text, false) {
        Ok(tree) => Ok(LicenseField::Expression(text.clone(), tree)),
        Err(LicenseError::Parse(message) | LicenseError::Expression(message)) => {
            errors.push(format!("Error parsing LicenseExpression: \"{text}\": {message}"));
            Ok(LicenseField::Absent)
        }
        // an IndexError or AssertionError escapes spdx-tools' parser altogether
        Err(other @ LicenseError::Other(_)) => Err(other.message().to_string()),
    }
}

impl SpdxDocument {
    fn parse(document: &Value) -> Result<Self, Vec<String>> {
        let mut errors = Vec::new();
        let Value::Object(_) = document else {
            return Err(vec![format!("the document is a {}, not an object", py_type(document))]);
        };
        // creation info, which spdx-tools cannot go on without
        let name = document.get("name").map(py_str).unwrap_or_else(|| "None".into());
        let Some(creation) = document.get("creationInfo").filter(|value| !value.is_null()) else {
            return Err(vec![format!("Error while parsing document {name}: ['CreationInfo does not exist.']")]);
        };
        let mut document_errors = Vec::new();
        match truthy(creation.get("creators")) {
            Some(Value::Array(creators)) => {
                for creator in creators {
                    if let Err(message) = parse_actor(creator) {
                        document_errors.push(message);
                    }
                }
            }
            Some(other) => document_errors.push(format!("creators must be a list, got {}", py_type(other))),
            None => document_errors.push("creators is required".into()),
        }
        match truthy(creation.get("created")) {
            Some(created) => {
                if let Err(message) = parse_created(created) {
                    document_errors.push(message);
                }
            }
            None => document_errors.push("created is required".into()),
        }
        if !document_errors.is_empty() {
            errors.push(format!("Error while parsing Document: {document_errors:?}"));
        }
        let spdx_version = required_str(document, "spdxVersion", "CreationInfo", &mut errors);
        let spdx_id = required_str(document, "SPDXID", "CreationInfo", &mut errors);
        required_str(document, "name", "CreationInfo", &mut errors);
        let namespace = required_str(document, "documentNamespace", "CreationInfo", &mut errors);
        let data_license = match document.get("dataLicense") {
            Some(Value::String(text)) => Some(text.clone()),
            None | Some(Value::Null) => None,
            Some(other) => {
                errors.push(format!("CreationInfo: dataLicense must be a string, got {}", py_type(other)));
                None
            }
        };
        let mut packages = Vec::new();
        if let Some(listed) = truthy(document.get("packages")) {
            match listed {
                Value::Array(items) => {
                    for item in items {
                        match Self::parse_package(item) {
                            Ok(package) => packages.push(package),
                            Err(messages) => errors.extend(messages),
                        }
                    }
                }
                other => errors.push(format!("packages must be a list, got {}", py_type(other))),
            }
        }
        let mut relationships = Vec::new();
        if let Some(listed) = document.get("relationships") {
            match listed {
                Value::Array(items) => {
                    for item in items {
                        match Self::parse_relationship(item) {
                            Ok(relationship) => relationships.push(relationship),
                            Err(message) => errors.push(message),
                        }
                    }
                }
                other => errors.push(format!("relationships must be a list, got {}", py_type(other))),
            }
        }
        let mut extracted = Vec::new();
        if let Some(listed) = truthy(document.get("hasExtractedLicensingInfos")) {
            match listed {
                Value::Array(items) => {
                    for item in items {
                        let mut item_errors = Vec::new();
                        optional_str(item, "licenseId", "ExtractedLicensingInfo", &mut item_errors);
                        optional_str(item, "extractedText", "ExtractedLicensingInfo", &mut item_errors);
                        optional_str(item, "comment", "ExtractedLicensingInfo", &mut item_errors);
                        errors.extend(item_errors);
                        extracted.push((
                            item.get("licenseId").and_then(Value::as_str).map(str::to_string),
                            item.get("extractedText").and_then(Value::as_str).map(str::to_string),
                        ));
                    }
                }
                other => errors.push(format!("hasExtractedLicensingInfos must be a list, got {}", py_type(other))),
            }
        }
        if !errors.is_empty() {
            return Err(errors);
        }
        Ok(Self { spdx_version, spdx_id, data_license, namespace, packages, relationships, extracted })
    }

    fn parse_package(package: &Value) -> Result<Package, Vec<String>> {
        let mut errors = Vec::new();
        let mut field_errors = Vec::new();
        let spdx_id = required_str(package, "SPDXID", "Package", &mut errors);
        required_str(package, "name", "Package", &mut errors);
        match package.get("downloadLocation") {
            Some(Value::String(_)) => {}
            other => errors.push(format!(
                "Package: downloadLocation must be a string, got {}",
                other.map_or("None", py_type)
            )),
        }
        for key in ["versionInfo", "summary", "comment", "licenseComments", "description", "copyrightText", "homepage"] {
            optional_str(package, key, "Package", &mut errors);
        }
        if let Some(files_analyzed) = package.get("filesAnalyzed")
            && !matches!(files_analyzed, Value::Bool(_) | Value::Null | Value::String(_))
        {
            errors.push(format!("Package: filesAnalyzed must be a bool, got {}", py_type(files_analyzed)));
        }
        let mut checksums = Vec::new();
        if let Some(listed) = truthy(package.get("checksums")) {
            match listed {
                Value::Array(items) => {
                    for item in items {
                        let algorithm = match item.get("algorithm").map_or(Ok(String::new()), json_enum) {
                            Ok(algorithm) => algorithm,
                            Err(message) => {
                                field_errors.push(message);
                                continue;
                            }
                        };
                        if checksum_digits(&algorithm).is_none() {
                            field_errors.push(format!("Error while parsing Checksum: ['Invalid ChecksumAlgorithm: {algorithm}']"));
                            continue;
                        }
                        match item.get("checksumValue") {
                            Some(Value::String(value)) => checksums.push((algorithm, value.clone())),
                            other => field_errors.push(format!(
                                "Checksum: value must be a string, got {}",
                                other.map_or("None", py_type)
                            )),
                        }
                    }
                }
                other => field_errors.push(format!("checksums must be a list, got {}", py_type(other))),
            }
        }
        let license_concluded = parse_license(package.get("licenseConcluded"), &mut field_errors).map_err(|e| vec![e])?;
        let license_declared = parse_license(package.get("licenseDeclared"), &mut field_errors).map_err(|e| vec![e])?;
        if let Some(supplier) = truthy(package.get("supplier"))
            && supplier.as_str() != Some("NOASSERTION")
            && let Err(message) = parse_actor(supplier)
        {
            field_errors.push(message);
        }
        if let Some(purpose) = truthy(package.get("primaryPackagePurpose")) {
            match json_enum(purpose) {
                Ok(name) if PURPOSES.contains(&name.as_str()) => {}
                _ => field_errors.push(format!("Invalid PrimaryPackagePurpose: {}", py_str(purpose))),
            }
        }
        let mut external_refs = Vec::new();
        if let Some(listed) = truthy(package.get("externalRefs")) {
            match listed {
                Value::Array(items) => {
                    for item in items {
                        let category = match truthy(item.get("referenceCategory")).map(json_enum) {
                            Some(Ok(category))
                                if ["SECURITY", "PACKAGE_MANAGER", "PERSISTENT_ID", "OTHER"].contains(&category.as_str()) =>
                            {
                                category
                            }
                            _ => {
                                field_errors.push(format!(
                                    "Invalid ExternalPackageRefCategory: {}",
                                    item.get("referenceCategory").map_or("None".into(), py_str)
                                ));
                                continue;
                            }
                        };
                        let (Some(Value::String(kind)), Some(Value::String(locator))) =
                            (item.get("referenceType"), item.get("referenceLocator"))
                        else {
                            field_errors.push("ExternalPackageRef: referenceType and referenceLocator must be strings".into());
                            continue;
                        };
                        external_refs.push((category, kind.clone(), locator.clone()));
                    }
                }
                other => field_errors.push(format!("externalRefs must be a list, got {}", py_type(other))),
            }
        }
        if !field_errors.is_empty() {
            errors.push(format!("Error while parsing Package: {field_errors:?}"));
        }
        if !errors.is_empty() {
            return Err(errors);
        }
        Ok(Package {
            spdx_id,
            license_concluded,
            license_declared,
            homepage: package.get("homepage").and_then(Value::as_str).map(str::to_string),
            checksums,
            external_refs,
        })
    }

    fn parse_relationship(relationship: &Value) -> Result<(String, String, Option<String>), String> {
        let kind = match truthy(relationship.get("relationshipType")).map(json_enum) {
            Some(Ok(kind)) if RELATIONSHIP_TYPES.contains(&kind.as_str()) => kind,
            Some(Ok(kind)) => return Err(format!("Error while parsing Relationship: ['Invalid RelationshipType: {kind}']")),
            Some(Err(message)) => return Err(format!("Error while parsing Relationship: [{message:?}]")),
            None => return Err("Relationship: relationship_type is required".into()),
        };
        let Some(Value::String(element)) = relationship.get("spdxElementId") else {
            return Err("Relationship: spdx_element_id must be a string".into());
        };
        let related = match relationship.get("relatedSpdxElement") {
            Some(Value::String(related)) if related == "NOASSERTION" || related == "NONE" => None,
            Some(Value::String(related)) => Some(related.clone()),
            _ => return Err("Relationship: related_spdx_element_id must be a string".into()),
        };
        Ok((element.clone(), kind, related))
    }

    fn validate(&self) -> Vec<String> {
        let mut messages = Vec::new();
        if self.spdx_version != "SPDX-2.2" && self.spdx_version != "SPDX-2.3" {
            return vec![format!(
                "only SPDX versions \"SPDX-2.2\" and \"SPDX-2.3\" are supported, but the document's spdx_version is: {}",
                self.spdx_version
            )];
        }
        let spdx_22 = self.spdx_version == "SPDX-2.2";
        if self.spdx_id != "SPDXRef-DOCUMENT" {
            messages.push(format!("spdx_id must be SPDXRef-DOCUMENT, but is: {}", self.spdx_id));
        }
        if self.data_license.as_deref() != Some("CC0-1.0") {
            messages.push(format!(
                "data_license must be \"CC0-1.0\", but is: {}",
                self.data_license.as_deref().unwrap_or("None")
            ));
        }
        // uritools.isabsuri: a scheme, and no fragment
        if !patterns().scheme.is_match(&self.namespace) || self.namespace.contains('#') {
            messages.push(format!(
                "document_namespace must be a valid URI specified in RFC-3986 and must contain no fragment (#), but is: {}",
                self.namespace
            ));
        }
        let mut all_ids: Vec<&str> = vec![self.spdx_id.as_str()];
        all_ids.extend(self.packages.iter().map(|package| package.spdx_id.as_str()));
        let present: HashSet<&str> = all_ids.iter().copied().collect();
        let license_refs: Vec<&str> = self.extracted.iter().filter_map(|(id, _)| id.as_deref()).collect();
        for package in &self.packages {
            messages.extend(validate_spdx_id(&package.spdx_id, None));
            for field in [&package.license_concluded, &package.license_declared] {
                if let LicenseField::Expression(text, Some(tree)) = field {
                    messages.extend(validate_license_expression(text, tree, &license_refs));
                }
            }
            if let Some(homepage) = &package.homepage
                && homepage != "NOASSERTION"
                && homepage != "NONE"
                && !patterns().url.is_match(homepage)
            {
                messages.push(format!("homepage must be a valid URL, but is: {homepage}"));
            }
            for (algorithm, value) in &package.checksums {
                let spdx_23_only = ["SHA3_512", "SHA3_384", "SHA3_256", "BLAKE3", "BLAKE2B_512", "BLAKE2B_384", "BLAKE2B_256", "ADLER32"];
                if spdx_22 && spdx_23_only.contains(&algorithm.as_str()) {
                    messages.push(format!("{algorithm} is not supported in SPDX-2.2"));
                    continue;
                }
                let body = value.strip_suffix('\n').unwrap_or(value);
                let lowercase_hex = body.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
                let length_ok = match checksum_digits(algorithm).expect("parsed algorithms are known") {
                    Digits::Exactly(count) => body.len() == count,
                    Digits::AtLeast(count) => body.len() >= count,
                    Digits::UpTo(count) => body.len() <= count,
                };
                if !(lowercase_hex && length_ok) {
                    messages.push(format!("value of {algorithm} must consist of lowercase hexadecimal digits, but is: {value}"));
                }
            }
            for (category, kind, locator) in &package.external_refs {
                messages.extend(validate_external_ref(category, kind, locator, spdx_22));
            }
        }
        for (element, kind, related) in &self.relationships {
            messages.extend(validate_spdx_id(element, Some(&present)));
            if let Some(related) = related {
                messages.extend(validate_spdx_id(related, Some(&present)));
            }
            if spdx_22 && (kind == "SPECIFICATION_FOR" || kind == "REQUIREMENT_DESCRIPTION_FOR") {
                messages.push(format!("RelationshipType.{kind} is not supported in SPDX-2.2"));
            }
        }
        for (id, text) in &self.extracted {
            if let Some(id) = id
                && !id.is_empty()
            {
                if !is_id(id, "LicenseRef-") {
                    messages.push(format!(
                        "license_id must only contain letters, numbers, \".\" and \"-\" and must begin with \"LicenseRef-\", but is: {id}"
                    ));
                }
                if text.as_deref().is_none_or(str::is_empty) {
                    messages.push("extracted_text must be provided if there is a license_id assigned".into());
                }
            }
        }
        let describes = self.relationships.iter().any(|(element, kind, related)| {
            (kind == "DESCRIBES" && *element == self.spdx_id)
                || (kind == "DESCRIBED_BY" && related.as_deref() == Some(self.spdx_id.as_str()))
        });
        if self.packages.len() != 1 && !describes {
            messages.push(format!(
                "there must be at least one relationship \"{0} DESCRIBES ...\" or \"... DESCRIBED_BY {0}\" when there is not only a single package present",
                self.spdx_id
            ));
        }
        let mut seen = HashSet::new();
        let mut duplicated: Vec<&str> = all_ids.iter().copied().filter(|id| !seen.insert(*id)).collect();
        duplicated.sort_unstable();
        duplicated.dedup();
        if !duplicated.is_empty() {
            messages.push(format!(
                "every spdx_id must be unique within the document, but found the following duplicates: {}",
                py_list_repr(duplicated.into_iter())
            ));
        }
        messages
    }
}

fn is_id(id: &str, prefix: &str) -> bool {
    let body = id.strip_suffix('\n').unwrap_or(id);
    body.strip_prefix(prefix).is_some_and(|rest| {
        !rest.is_empty() && rest.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c.is_numeric())
    })
}

fn validate_spdx_id(id: &str, present: Option<&HashSet<&str>>) -> Vec<String> {
    let parts: Vec<&str> = id.split(':').collect();
    if parts.len() > 2 {
        return vec![format!(
            "spdx_id must not contain more than one colon in order to separate the external document reference id from the internal SPDX id, but is: {id}"
        )];
    }
    if parts.len() == 2 {
        // spdx-tools also requires the DocumentRef to be declared, and rendered documents declare none
        return vec![format!("did not find the external document reference \"{}\" in the SPDX document", parts[0])];
    }
    let mut messages = Vec::new();
    if !is_id(id, "SPDXRef-") {
        messages.push(format!(
            "spdx_id must only contain letters, numbers, \".\" and \"-\" and must begin with \"SPDXRef-\", but is: {id}"
        ));
    }
    if let Some(present) = present
        && !present.contains(id)
    {
        messages.push(format!("did not find the referenced spdx_id \"{id}\" in the SPDX document"));
    }
    messages
}

fn validate_license_expression(text: &str, tree: &Expr, license_refs: &[&str]) -> Vec<String> {
    let mut messages = Vec::new();
    let mut symbols = Vec::new();
    tree.symbols(&mut symbols);
    let mut seen = HashSet::new();
    for symbol in symbols.into_iter().filter(|symbol| !symbol.known) {
        let key: &str = &symbol.key;
        if !seen.insert(key) {
            continue;
        }
        if key.contains(':') {
            messages.push(format!("external license reference {key} names no external document of this one"));
        } else if !license_refs.contains(&key) {
            messages.push(format!(
                "Unrecognized license reference: {key}. license_expression must only use IDs from the license list or extracted licensing info, but is: {text}"
            ));
        }
    }
    if tree.misuses_exceptions() {
        messages.push(format!("a license exception is used as a license or a license as an exception in: {text}"));
    }
    messages
}

fn validate_external_ref(category: &str, kind: &str, locator: &str, spdx_22: bool) -> Vec<String> {
    let types: &[&str] = match category {
        "SECURITY" => &["cpe22Type", "cpe23Type", "advisory", "fix", "url", "swid"],
        "PACKAGE_MANAGER" => &["maven-central", "nuget", "npm", "bower", "purl"],
        "PERSISTENT_ID" => &["swh", "gitoid"],
        _ => {
            if locator.contains(' ') {
                return vec![format!("externalPackageRef locator in category OTHER must contain no spaces, but is: {locator}")];
            }
            return Vec::new();
        }
    };
    if spdx_22 && ["advisory", "fix", "url", "swid"].contains(&kind) {
        return vec![format!("externalPackageRef type \"{kind}\" is not supported in SPDX-2.2")];
    }
    if !types.contains(&kind) {
        return vec![format!("externalPackageRef type in category {category} must be one of {types:?}, but is: {kind}")];
    }
    // python-sbom renders purl references only; the other types keep their regular expressions in spdx-tools
    if kind == "purl" && !patterns().purl.is_match(locator) {
        return vec![format!(
            "externalPackageRef locator of type \"purl\" must conform with the regex ^pkg:.+(\\/.+)?\\/.+(@.+)?(\\?.+)?(#.+)?$, but is: {locator}"
        )];
    }
    Vec::new()
}

// ------------------------------------------------------------------------------------------------------------------
// Python string semantics the libraries above rely on
// ------------------------------------------------------------------------------------------------------------------

// str.isspace: Unicode White_Space plus the four information separators Python also counts
fn py_isspace(character: char) -> bool {
    character.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&character)
}

fn py_strip(text: &str) -> &str {
    text.trim_matches(py_isspace)
}

fn py_split(text: &str) -> Vec<&str> {
    text.split(py_isspace).filter(|part| !part.is_empty()).collect()
}

fn casefold(text: &str) -> String {
    text.to_lowercase().replace('ß', "ss")
}

fn py_type(value: &Value) -> &'static str {
    match value {
        Value::Null => "NoneType",
        Value::Bool(_) => "bool",
        Value::Number(number) if number.is_f64() => "float",
        Value::Number(_) => "int",
        Value::String(_) => "str",
        Value::Array(_) => "list",
        Value::Object(_) => "dict",
    }
}

fn py_str(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}

fn py_repr(text: &str) -> String {
    let quote = if text.contains('\'') && !text.contains('"') { '"' } else { '\'' };
    let mut repr = String::with_capacity(text.len() + 2);
    repr.push(quote);
    for character in text.chars() {
        match character {
            '\\' => repr.push_str("\\\\"),
            '\n' => repr.push_str("\\n"),
            '\r' => repr.push_str("\\r"),
            '\t' => repr.push_str("\\t"),
            c if c == quote => {
                repr.push('\\');
                repr.push(c);
            }
            c if (c as u32) < 0x20 || c as u32 == 0x7f => repr.push_str(&format!("\\x{:02x}", c as u32)),
            c if !py_isprintable(c) => {
                let code = c as u32;
                if code <= 0xff {
                    repr.push_str(&format!("\\x{code:02x}"));
                } else if code <= 0xffff {
                    repr.push_str(&format!("\\u{code:04x}"));
                } else {
                    repr.push_str(&format!("\\U{code:08x}"));
                }
            }
            c => repr.push(c),
        }
    }
    repr.push(quote);
    repr
}

// str.isprintable, short of the Unicode tables: controls, format characters, separators other than the space,
// surrogates, private use and noncharacters are escaped; unassigned code points pass as printable
fn py_isprintable(character: char) -> bool {
    let code = character as u32;
    !(character.is_control()
        || (character.is_whitespace() && character != ' ')
        || matches!(code, 0xAD | 0x600..=0x605 | 0x61C | 0x6DD | 0x70F | 0x180E | 0x200B..=0x200F | 0x202A..=0x202E
            | 0x2060..=0x206F | 0xFEFF | 0xFFF0..=0xFFFB | 0xE000..=0xF8FF | 0xFDD0..=0xFDEF | 0xF0000..=0x10FFFF
            | 0xE0001 | 0xE0020..=0xE007F)
        || code & 0xFFFE == 0xFFFE)
}

fn py_list_repr<'a>(items: impl Iterator<Item = &'a str>) -> String {
    format!("[{}]", items.map(py_repr).collect::<Vec<_>>().join(", "))
}

fn truncate(text: &str, limit: usize) -> String {
    text.chars().take(limit).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parses(expression: &str) -> bool {
        policy_licensing().parse(expression, false).is_ok_and(|tree| tree.is_some())
    }

    #[test]
    fn license_expression_grammar() {
        assert!(parses("MIT"));
        assert!(parses("mit OR (Apache-2.0 AND bsd-3-clause)"));
        assert!(parses("GPL-2.0-only WITH Classpath-exception-2.0"));
        assert!(parses("Some Custom License"));
        assert!(!parses("MIT ISC"));
        assert!(!parses("MIT AND"));
        assert!(!parses("()"));
        assert!(!parses("( OR MIT"));
        assert!(!parses("MIT/X11"));
    }

    #[test]
    fn iri_reference() {
        let iri = &patterns().iri_reference;
        for valid in ["https://example.com/a?b#c", "", "relative/path", "//host", "urn:x", "http://[1:2:3:4:5:6:7:8]/"] {
            assert!(iri.is_match(valid), "{valid}");
        }
        for invalid in ["http://[::1]/", "a b", "http://x/%zz", ":nope"] {
            assert!(!iri.is_match(invalid), "{invalid}");
        }
    }

    #[test]
    fn rfc3339() {
        assert!(is_rfc3339("2024-02-29T00:00:00Z"));
        assert!(is_rfc3339("2024-02-29t00:00:00z\n"));
        assert!(!is_rfc3339("2023-02-29T00:00:00Z"));
        assert!(!is_rfc3339("0000-01-01T00:00:00Z"));
    }
}
