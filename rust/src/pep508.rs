// A port of packaging 26.3's dependency specifier parser (_tokenizer.py, _parser.py), its marker formatting and
// evaluation (markers.py), and the extra-only verdict python-sbom draws from a marker. Error messages match packaging's
// text, so a refused requirement reads the same as before.

use std::cmp::Ordering;
use std::collections::HashMap;
use std::fmt::Write as _;
use std::str::FromStr;
use std::sync::LazyLock;

use pep440_rs::Version;
use regex::Regex;

pub enum MarkerVar {
    Variable(String),
    Value(String),
}

pub struct MarkerItem {
    pub lhs: MarkerVar,
    pub op: String,
    pub rhs: MarkerVar,
}

pub enum MarkerNode {
    Item(MarkerItem),
    Group(Vec<MarkerNode>),
    And,
    Or,
}

pub struct Requirement {
    pub name: String,
    #[expect(dead_code, reason = "parsed as packaging parses it; the SBOM keeps the requirement's text instead")]
    pub url: Option<String>,
    #[expect(dead_code, reason = "parsed as packaging parses it; the SBOM keeps the requirement's text instead")]
    pub extras: Vec<String>,
    pub specifier: String,
    pub marker: Option<Vec<MarkerNode>>,
}

impl Requirement {
    /// `list(requirement.specifier)` as `(operator, version)` pairs, in the order written.
    #[must_use]
    pub fn specifiers(&self) -> Vec<(String, String)> {
        split_specifiers(&self.specifier)
            .into_iter()
            .filter_map(|text| split_specifier(text).ok())
            .collect()
    }
}

/// `packaging.utils.canonicalize_name`
#[must_use]
pub fn canonicalize_name(name: &str) -> String {
    let lowered = name.to_lowercase().replace(['_', '.'], "-");
    let mut value = String::with_capacity(lowered.len());
    for character in lowered.chars() {
        if !(character == '-' && value.ends_with('-')) {
            value.push(character);
        }
    }
    value
}

pub fn parse_requirement(source: &str) -> Result<Requirement, String> {
    let mut tokenizer = Tokenizer::new(source);
    let parsed = parse_requirement_tokens(&mut tokenizer).map_err(|error| error.to_string())?;
    // SpecifierSet re-validates each comma-separated piece, which can refuse what the tokenizer let through, such as
    // the comma inside an arbitrary `===` version
    for text in split_specifiers(&parsed.specifier) {
        split_specifier(text)?;
    }
    Ok(Requirement {
        marker: parsed.marker.map(normalize_extra_values),
        ..parsed
    })
}

/// `str(Marker)`: packaging's `_format_marker`.
pub fn format_marker(marker: &[MarkerNode]) -> Result<String, String> {
    format_list(marker, true)
}

/// `Marker.evaluate()` in the "metadata" context: the environment given plus an empty `extra`.
pub fn evaluate(marker: &[MarkerNode], env: &HashMap<String, String>) -> Result<bool, String> {
    let mut environment = env.clone();
    environment.insert("extra".to_owned(), String::new());
    let full = environment
        .get("python_full_version")
        .ok_or_else(|| py_repr("python_full_version"))?;
    if full.ends_with('+') {
        let repaired = format!("{full}local");
        environment.insert("python_full_version".to_owned(), repaired);
    }
    evaluate_markers(marker, &environment)
}

/// Whether a requirement applies when no extra is requested: conditions on `extra` are decided, every other condition
/// stays unknown, and the requirement applies unless its extra conditions alone rule it out.
#[must_use]
pub fn applies_without_extras(marker: &[MarkerNode]) -> bool {
    extra_verdict(marker) != Some(false)
}

// --- tokenizer ---------------------------------------------------------------------------------------------------

// Python's `\s` (str.isspace) also takes the information separators U+001C..U+001F, which Unicode White_Space lacks
const PY_SPACE: &str = r"\s\x1c-\x1f";

fn specifier_pattern() -> String {
    let s = PY_SPACE;
    let pre = r"[-_.]?(?:alpha|beta|preview|pre|a|b|c|rc)[-_.]?[0-9]*";
    let post = r"(?:-[0-9]+)|(?:[-_.]?(?:post|rev|r)[-_.]?[0-9]*)";
    let dev = r"[-_.]?dev[-_.]?[0-9]*";
    let local = r"\+[a-z0-9]+(?:[-_.][a-z0-9]+)*";
    // `(?a:...)` groups in packaging match ASCII only, which `(?-u:...)` mirrors
    format!(
        "(?i:(?:===[{s}]*[^{s};)]*)\
         |(?:(?:==|!=)[{s}]*v?(?:[0-9]+!)?[0-9]+(?:\\.[0-9]+)*\
         (?:\\.\\*|(?-u:{pre})?(?-u:{post})?(?-u:{dev})?(?-u:{local})?)?)\
         |(?:~=[{s}]*v?(?:[0-9]+!)?[0-9]+(?:\\.[0-9]+)+(?:{pre})?(?:{post})?(?:{dev})?)\
         |(?:(?:<=|>=|<|>)[{s}]*v?(?:[0-9]+!)?[0-9]+(?:\\.[0-9]+)*(?-u:{pre})?(?-u:{post})?(?-u:{dev})?))"
    )
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Rule {
    LeftParenthesis,
    RightParenthesis,
    LeftBracket,
    RightBracket,
    Semicolon,
    Comma,
    QuotedString,
    Op,
    BoolOp,
    In,
    Not,
    Variable,
    Specifier,
    At,
    Url,
    Identifier,
    VersionPrefixTrail,
    VersionLocalLabelTrail,
    Ws,
    End,
}

struct Rules {
    patterns: Vec<(Rule, Regex)>,
    full_specifier: Regex,
}

static RULES: LazyLock<Rules> = LazyLock::new(|| {
    let specifier = specifier_pattern();
    let table = [
        (Rule::LeftParenthesis, r"\(".to_owned()),
        (Rule::RightParenthesis, r"\)".to_owned()),
        (Rule::LeftBracket, r"\[".to_owned()),
        (Rule::RightBracket, r"\]".to_owned()),
        (Rule::Semicolon, ";".to_owned()),
        (Rule::Comma, ",".to_owned()),
        (Rule::QuotedString, r#"(?:'[^']*')|(?:"[^"]*")"#.to_owned()),
        (Rule::Op, "===|==|~=|!=|<=|>=|<|>".to_owned()),
        (Rule::BoolOp, r"\b(?:or|and)\b".to_owned()),
        (Rule::In, r"\bin\b".to_owned()),
        (Rule::Not, r"\bnot\b".to_owned()),
        (
            Rule::Variable,
            r"\b(?:python_version|python_full_version|os[._]name|sys[._]platform|platform_(?:release|system)|platform[._](?:version|machine|python_implementation)|python_implementation|implementation_(?:name|version)|extras?|dependency_groups)\b"
                .to_owned(),
        ),
        (Rule::Specifier, specifier.clone()),
        (Rule::At, "@".to_owned()),
        (Rule::Url, r"[^ \t]+".to_owned()),
        (Rule::Identifier, r"\b[a-zA-Z0-9][a-zA-Z0-9._-]*\b".to_owned()),
        (Rule::VersionPrefixTrail, r"\.\*".to_owned()),
        (Rule::VersionLocalLabelTrail, r"\+[a-z0-9]+(?:[-_.][a-z0-9]+)*".to_owned()),
        (Rule::Ws, "[ \t]+".to_owned()),
    ];
    Rules {
        patterns: table
            .into_iter()
            .map(|(rule, pattern)| (rule, Regex::new(&pattern).expect("valid tokenizer pattern")))
            .collect(),
        full_specifier: Regex::new(&format!(r"\A[{PY_SPACE}]*{specifier}[{PY_SPACE}]*\z"))
            .expect("valid specifier pattern"),
    }
});

impl Rules {
    fn pattern(&self, rule: Rule) -> &Regex {
        &self
            .patterns
            .iter()
            .find(|(candidate, _)| *candidate == rule)
            .expect("every rule but END has a pattern")
            .1
    }
}

struct Token {
    text: String,
    position: usize,
}

struct SyntaxError {
    message: String,
    source: String,
    span: (usize, usize),
}

impl std::fmt::Display for SyntaxError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // packaging counts the span in code points
        let start = self.source[..self.span.0].chars().count();
        let end = self.source[..self.span.1].chars().count();
        let marker = format!("{}{}^", " ".repeat(start), "~".repeat(end.saturating_sub(start)));
        write!(formatter, "{}\n    {}\n    {}", self.message, self.source, marker)
    }
}

type Parsed<T> = Result<T, SyntaxError>;

struct Tokenizer<'a> {
    source: &'a str,
    next_token: Option<Token>,
    position: usize,
}

impl<'a> Tokenizer<'a> {
    fn new(source: &'a str) -> Self {
        Self {
            source,
            next_token: None,
            position: 0,
        }
    }

    fn matched(&self, rule: Rule) -> Option<usize> {
        if rule == Rule::End {
            return (self.position == self.source.len()).then_some(0);
        }
        // `re.match` at a position: a match anchored there, with the text before it still giving `\b` its context
        RULES
            .pattern(rule)
            .find_at(self.source, self.position)
            .filter(|found| found.start() == self.position)
            .map(|found| found.len())
    }

    fn check(&mut self, rule: Rule, peek: bool) -> bool {
        debug_assert!(self.next_token.is_none());
        let Some(length) = self.matched(rule) else {
            return false;
        };
        if !peek {
            self.next_token = Some(Token {
                text: self.source[self.position..self.position + length].to_owned(),
                position: self.position,
            });
        }
        true
    }

    fn consume(&mut self, rule: Rule) {
        if self.check(rule, false) {
            self.read();
        }
    }

    fn expect(&mut self, rule: Rule, expected: &str) -> Parsed<Token> {
        if !self.check(rule, false) {
            return Err(self.syntax_error(&format!("Expected {expected}"), None, None));
        }
        Ok(self.read())
    }

    fn read(&mut self) -> Token {
        let token = self.next_token.take().expect("a checked token");
        self.position += token.text.len();
        token
    }

    fn syntax_error(&self, message: &str, span_start: Option<usize>, span_end: Option<usize>) -> SyntaxError {
        SyntaxError {
            message: message.to_owned(),
            source: self.source.to_owned(),
            span: (span_start.unwrap_or(self.position), span_end.unwrap_or(self.position)),
        }
    }

    fn open(&mut self, open: Rule) -> Option<usize> {
        if self.check(open, false) {
            let position = self.position;
            self.read();
            Some(position)
        } else {
            None
        }
    }

    fn close(&mut self, open_position: Option<usize>, close: Rule, open: Rule, around: &str) -> Parsed<()> {
        let Some(open_position) = open_position else {
            return Ok(());
        };
        if !self.check(close, false) {
            let message = format!(
                "Expected matching {} for {}, after {around}",
                rule_name(close),
                rule_name(open)
            );
            return Err(self.syntax_error(&message, Some(open_position), None));
        }
        self.read();
        Ok(())
    }
}

fn rule_name(rule: Rule) -> &'static str {
    match rule {
        Rule::LeftParenthesis => "LEFT_PARENTHESIS",
        Rule::RightParenthesis => "RIGHT_PARENTHESIS",
        Rule::LeftBracket => "LEFT_BRACKET",
        Rule::RightBracket => "RIGHT_BRACKET",
        _ => unreachable!("only brackets enclose"),
    }
}

// --- requirement grammar -----------------------------------------------------------------------------------------

fn parse_requirement_tokens(tokenizer: &mut Tokenizer) -> Parsed<Requirement> {
    tokenizer.consume(Rule::Ws);
    let name = tokenizer
        .expect(Rule::Identifier, "package name at the start of dependency specifier")?
        .text;
    tokenizer.consume(Rule::Ws);
    let extras = parse_extras(tokenizer)?;
    tokenizer.consume(Rule::Ws);
    let (url, specifier, marker) = parse_requirement_details(tokenizer)?;
    tokenizer.expect(Rule::End, "end of dependency specifier")?;
    Ok(Requirement {
        name,
        url: (!url.is_empty()).then_some(url),
        extras,
        specifier,
        marker,
    })
}

type Details = (String, String, Option<Vec<MarkerNode>>);

fn parse_requirement_details(tokenizer: &mut Tokenizer) -> Parsed<Details> {
    if tokenizer.check(Rule::At, false) {
        tokenizer.read();
        tokenizer.consume(Rule::Ws);
        let url_start = tokenizer.position;
        let url = tokenizer.expect(Rule::Url, "URL after @")?.text;
        if tokenizer.check(Rule::End, true) {
            return Ok((url, String::new(), None));
        }
        tokenizer.expect(Rule::Ws, "whitespace after URL")?;
        if tokenizer.check(Rule::End, true) {
            return Ok((url, String::new(), None));
        }
        let marker = parse_requirement_marker(tokenizer, url_start, "semicolon (after URL and whitespace)")?;
        return Ok((url, String::new(), Some(marker)));
    }
    let specifier_start = tokenizer.position;
    let specifier = parse_specifier(tokenizer)?;
    tokenizer.consume(Rule::Ws);
    if tokenizer.check(Rule::End, true) {
        return Ok((String::new(), specifier, None));
    }
    let expected = if specifier.is_empty() {
        "semicolon (after name with no version specifier)"
    } else {
        "comma (within version specifier), semicolon (after version specifier)"
    };
    let marker = parse_requirement_marker(tokenizer, specifier_start, expected)?;
    Ok((String::new(), specifier, Some(marker)))
}

fn parse_requirement_marker(tokenizer: &mut Tokenizer, span_start: usize, expected: &str) -> Parsed<Vec<MarkerNode>> {
    if !tokenizer.check(Rule::Semicolon, false) {
        return Err(tokenizer.syntax_error(&format!("Expected {expected} or end"), Some(span_start), None));
    }
    tokenizer.read();
    let marker = parse_marker(tokenizer)?;
    tokenizer.consume(Rule::Ws);
    Ok(marker)
}

fn parse_extras(tokenizer: &mut Tokenizer) -> Parsed<Vec<String>> {
    if !tokenizer.check(Rule::LeftBracket, true) {
        return Ok(Vec::new());
    }
    let open = tokenizer.open(Rule::LeftBracket);
    tokenizer.consume(Rule::Ws);
    let extras = parse_extras_list(tokenizer)?;
    tokenizer.consume(Rule::Ws);
    tokenizer.close(open, Rule::RightBracket, Rule::LeftBracket, "extras")?;
    Ok(extras)
}

fn parse_extras_list(tokenizer: &mut Tokenizer) -> Parsed<Vec<String>> {
    let mut extras = Vec::new();
    if !tokenizer.check(Rule::Identifier, false) {
        return Ok(extras);
    }
    extras.push(tokenizer.read().text);
    loop {
        tokenizer.consume(Rule::Ws);
        if tokenizer.check(Rule::Identifier, true) {
            return Err(tokenizer.syntax_error("Expected comma between extra names", None, None));
        } else if !tokenizer.check(Rule::Comma, false) {
            break;
        }
        tokenizer.read();
        tokenizer.consume(Rule::Ws);
        extras.push(tokenizer.expect(Rule::Identifier, "extra name after comma")?.text);
    }
    Ok(extras)
}

fn parse_specifier(tokenizer: &mut Tokenizer) -> Parsed<String> {
    let open = tokenizer.open(Rule::LeftParenthesis);
    tokenizer.consume(Rule::Ws);
    let parsed = parse_version_many(tokenizer)?;
    tokenizer.consume(Rule::Ws);
    tokenizer.close(open, Rule::RightParenthesis, Rule::LeftParenthesis, "version specifier")?;
    Ok(parsed)
}

fn parse_version_many(tokenizer: &mut Tokenizer) -> Parsed<String> {
    let mut parsed = String::new();
    while tokenizer.check(Rule::Specifier, false) {
        let span_start = tokenizer.position;
        let specifier = tokenizer.read().text;
        parsed.push_str(&specifier);
        if tokenizer.check(Rule::VersionPrefixTrail, true) {
            let message =
                if specifier.starts_with("!=") || (specifier.starts_with("==") && !specifier.starts_with("===")) {
                    ".* suffix cannot be used with pre-release, post-release, dev or local versions"
                } else {
                    ".* suffix can only be used with `==` or `!=` operators"
                };
            return Err(tokenizer.syntax_error(message, Some(span_start), Some(tokenizer.position + 1)));
        }
        if tokenizer.check(Rule::VersionLocalLabelTrail, true) {
            let message = "Local version label can only be used with `==` or `!=` operators";
            return Err(tokenizer.syntax_error(message, Some(span_start), Some(tokenizer.position)));
        }
        tokenizer.consume(Rule::Ws);
        if !tokenizer.check(Rule::Comma, false) {
            break;
        }
        parsed.push_str(&tokenizer.read().text);
        tokenizer.consume(Rule::Ws);
    }
    Ok(parsed)
}

// --- marker grammar ----------------------------------------------------------------------------------------------

fn parse_marker(tokenizer: &mut Tokenizer) -> Parsed<Vec<MarkerNode>> {
    let mut expression = vec![parse_marker_atom(tokenizer)?];
    while tokenizer.check(Rule::BoolOp, false) {
        let token = tokenizer.read();
        let right = parse_marker_atom(tokenizer)?;
        expression.push(if token.text == "or" {
            MarkerNode::Or
        } else {
            MarkerNode::And
        });
        expression.push(right);
    }
    Ok(expression)
}

fn parse_marker_atom(tokenizer: &mut Tokenizer) -> Parsed<MarkerNode> {
    tokenizer.consume(Rule::Ws);
    let marker = if tokenizer.check(Rule::LeftParenthesis, true) {
        let open = tokenizer.open(Rule::LeftParenthesis);
        tokenizer.consume(Rule::Ws);
        let marker = parse_marker(tokenizer)?;
        tokenizer.consume(Rule::Ws);
        tokenizer.close(open, Rule::RightParenthesis, Rule::LeftParenthesis, "marker expression")?;
        MarkerNode::Group(marker)
    } else {
        MarkerNode::Item(parse_marker_item(tokenizer)?)
    };
    tokenizer.consume(Rule::Ws);
    Ok(marker)
}

fn parse_marker_item(tokenizer: &mut Tokenizer) -> Parsed<MarkerItem> {
    tokenizer.consume(Rule::Ws);
    let lhs = parse_marker_var(tokenizer)?;
    tokenizer.consume(Rule::Ws);
    let op = parse_marker_op(tokenizer)?;
    tokenizer.consume(Rule::Ws);
    let rhs = parse_marker_var(tokenizer)?;
    tokenizer.consume(Rule::Ws);
    Ok(MarkerItem { lhs, op, rhs })
}

fn parse_marker_var(tokenizer: &mut Tokenizer) -> Parsed<MarkerVar> {
    if tokenizer.check(Rule::Variable, false) {
        let name = tokenizer.read().text.replace('.', "_");
        let name = if name == "python_implementation" {
            "platform_python_implementation".to_owned()
        } else {
            name
        };
        return Ok(MarkerVar::Variable(name));
    }
    if tokenizer.check(Rule::QuotedString, false) {
        let token = tokenizer.read();
        return literal_eval_string(&token.text)
            .map(MarkerVar::Value)
            .ok_or_else(|| SyntaxError {
                message: "Invalid quoted string".to_owned(),
                source: tokenizer.source.to_owned(),
                span: (token.position, token.position + token.text.len()),
            });
    }
    Err(tokenizer.syntax_error("Expected a marker variable or quoted string", None, None))
}

fn parse_marker_op(tokenizer: &mut Tokenizer) -> Parsed<String> {
    if tokenizer.check(Rule::In, false) {
        tokenizer.read();
        return Ok("in".to_owned());
    }
    if tokenizer.check(Rule::Not, false) {
        tokenizer.read();
        tokenizer.expect(Rule::Ws, "whitespace after 'not'")?;
        tokenizer.expect(Rule::In, "'in' after 'not'")?;
        return Ok("not in".to_owned());
    }
    if tokenizer.check(Rule::Op, false) {
        return Ok(tokenizer.read().text);
    }
    Err(tokenizer.syntax_error(
        "Expected marker operator, one of <=, <, !=, ==, >=, >, ~=, ===, in, not in",
        None,
        None,
    ))
}

// `ast.literal_eval` of a quoted string the tokenizer matched: Python's string literal escapes; None where Python
// raises SyntaxError or ValueError
fn literal_eval_string(text: &str) -> Option<String> {
    let body = &text[1..text.len() - 1];
    let mut value = String::with_capacity(body.len());
    let mut characters = body.chars().peekable();
    while let Some(character) = characters.next() {
        match character {
            // an unterminated single-line literal, or a null byte compile() refuses
            '\n' | '\r' | '\0' => return None,
            '\\' => {
                // a trailing backslash escapes the closing quote, leaving the literal unterminated
                let escaped = characters.next()?;
                match escaped {
                    '\n' => {}
                    '\r' => {
                        characters.next_if_eq(&'\n');
                    }
                    '\\' | '\'' | '"' => value.push(escaped),
                    'a' => value.push('\x07'),
                    'b' => value.push('\x08'),
                    'f' => value.push('\x0c'),
                    'n' => value.push('\n'),
                    'r' => value.push('\r'),
                    't' => value.push('\t'),
                    'v' => value.push('\x0b'),
                    '0'..='7' => {
                        let mut code = escaped.to_digit(8)?;
                        for _ in 0..2 {
                            match characters.peek().and_then(|next| next.to_digit(8)) {
                                Some(digit) => {
                                    code = code * 8 + digit;
                                    characters.next();
                                }
                                None => break,
                            }
                        }
                        value.push(char::from_u32(code)?);
                    }
                    'x' | 'u' | 'U' => {
                        let width = match escaped {
                            'x' => 2,
                            'u' => 4,
                            _ => 8,
                        };
                        let mut code = 0u32;
                        for _ in 0..width {
                            code = code * 16 + characters.next()?.to_digit(16)?;
                        }
                        // surrogates have no Rust char, and U+110000 and above no code point at all
                        value.push(char::from_u32(code)?);
                    }
                    // \N{name} needs the Unicode name table
                    'N' => return None,
                    // an unknown escape stays as written, with a SyntaxWarning
                    other => {
                        value.push('\\');
                        value.push(other);
                    }
                }
            }
            other => value.push(other),
        }
    }
    Some(value)
}

fn normalize_extra_values(markers: Vec<MarkerNode>) -> Vec<MarkerNode> {
    markers.into_iter().map(normalize_extras).collect()
}

fn normalize_extras(node: MarkerNode) -> MarkerNode {
    match node {
        MarkerNode::Group(items) => MarkerNode::Group(normalize_extra_values(items)),
        MarkerNode::Item(MarkerItem { lhs, op, rhs }) => {
            let (lhs, rhs) = match (lhs, rhs) {
                (MarkerVar::Variable(name), MarkerVar::Value(value)) if name == "extra" => {
                    (MarkerVar::Variable(name), MarkerVar::Value(canonicalize_name(&value)))
                }
                (MarkerVar::Value(value), MarkerVar::Variable(name))
                    if name == "extra" || name == "extras" || name == "dependency_groups" =>
                {
                    (MarkerVar::Value(canonicalize_name(&value)), MarkerVar::Variable(name))
                }
                pair => pair,
            };
            MarkerNode::Item(MarkerItem { lhs, op, rhs })
        }
        other => other,
    }
}

// --- formatting --------------------------------------------------------------------------------------------------

fn format_list(marker: &[MarkerNode], first: bool) -> Result<String, String> {
    if let [only @ (MarkerNode::Group(_) | MarkerNode::Item(_))] = marker {
        return format_node(only, first);
    }
    let inner = marker
        .iter()
        .map(|node| format_node(node, false))
        .collect::<Result<Vec<_>, _>>()?
        .join(" ");
    Ok(if first { inner } else { format!("({inner})") })
}

fn format_node(node: &MarkerNode, first: bool) -> Result<String, String> {
    match node {
        MarkerNode::Group(items) => format_list(items, first),
        MarkerNode::Item(item) => Ok(format!(
            "{} {} {}",
            serialize(&item.lhs)?,
            item.op,
            serialize(&item.rhs)?
        )),
        MarkerNode::And => Ok("and".to_owned()),
        MarkerNode::Or => Ok("or".to_owned()),
    }
}

fn serialize(var: &MarkerVar) -> Result<String, String> {
    match var {
        MarkerVar::Variable(name) => Ok(name.clone()),
        MarkerVar::Value(value) if !value.contains('"') => Ok(format!("\"{value}\"")),
        MarkerVar::Value(value) if !value.contains('\'') => Ok(format!("'{value}'")),
        MarkerVar::Value(_) => Err("Cannot serialize marker value containing both quote characters".to_owned()),
    }
}

// --- evaluation --------------------------------------------------------------------------------------------------

const MARKERS_REQUIRING_VERSION: [&str; 4] = [
    "implementation_version",
    "platform_release",
    "python_full_version",
    "python_version",
];

fn var_text(var: &MarkerVar) -> &str {
    match var {
        MarkerVar::Variable(text) | MarkerVar::Value(text) => text,
    }
}

fn evaluate_markers(markers: &[MarkerNode], environment: &HashMap<String, String>) -> Result<bool, String> {
    // every item is evaluated, as packaging builds the groups before it combines them
    let mut groups: Vec<Vec<bool>> = vec![Vec::new()];
    for marker in markers {
        match marker {
            MarkerNode::Group(items) => {
                let verdict = evaluate_markers(items, environment)?;
                groups.last_mut().expect("a group").push(verdict);
            }
            MarkerNode::Item(item) => {
                let (key, lhs, rhs) = match &item.lhs {
                    MarkerVar::Variable(name) => (name.as_str(), lookup(environment, name)?, var_text(&item.rhs)),
                    MarkerVar::Value(value) => {
                        let key = var_text(&item.rhs);
                        (key, value.as_str(), lookup(environment, key)?)
                    }
                };
                // only the set-valued extras and dependency_groups normalize, and the metadata context has neither
                let verdict = eval_op(lhs, &item.op, rhs, key)?;
                groups.last_mut().expect("a group").push(verdict);
            }
            MarkerNode::Or => groups.push(Vec::new()),
            MarkerNode::And => {}
        }
    }
    Ok(groups.iter().any(|group| group.iter().all(|verdict| *verdict)))
}

fn lookup<'a>(environment: &'a HashMap<String, String>, key: &str) -> Result<&'a str, String> {
    // UndefinedEnvironmentName is a KeyError, whose str is the key's repr
    environment.get(key).map(String::as_str).ok_or_else(|| py_repr(key))
}

fn eval_op(lhs: &str, op: &str, rhs: &str, key: &str) -> Result<bool, String> {
    if MARKERS_REQUIRING_VERSION.contains(&key) {
        let spec = format!("{op}{rhs}");
        if RULES.full_specifier.is_match(&spec) {
            return Ok(specifier_contains(&spec, lhs));
        }
    }
    match op {
        "in" => Ok(rhs.contains(lhs)),
        "not in" => Ok(!rhs.contains(lhs)),
        "<" | ">" => Ok(false),
        "<=" | "==" | ">=" => Ok(lhs == rhs),
        "!=" => Ok(lhs != rhs),
        _ => Err(format!(
            "Undefined <Op({})> on {} and {}.",
            py_repr(op),
            py_repr(lhs),
            py_repr(rhs)
        )),
    }
}

fn split_specifiers(specifier: &str) -> Vec<&str> {
    specifier
        .split(',')
        .map(py_strip)
        .filter(|text| !text.is_empty())
        .collect()
}

// Specifier.__init__: validate, then split into operator and version
fn split_specifier(text: &str) -> Result<(String, String), String> {
    if !RULES.full_specifier.is_match(text) {
        return Err(format!("Invalid specifier: {}", py_repr(text)));
    }
    let spec = py_strip(text);
    let width = if spec.starts_with("===") {
        3
    } else if ["~=", "==", "!=", "<=", ">="]
        .iter()
        .any(|prefix| spec.starts_with(prefix))
    {
        2
    } else {
        1
    };
    Ok((spec[..width].to_owned(), py_strip(&spec[width..]).to_owned()))
}

fn parse_version(text: &str) -> Option<Version> {
    Version::from_str(py_strip(text)).ok()
}

// Specifier(spec).contains(item, prereleases=True), following packaging's _fast_match and range engine
fn specifier_contains(spec: &str, item: &str) -> bool {
    let Ok((op, version_text)) = split_specifier(spec) else {
        return false;
    };
    if op == "===" {
        return item.to_lowercase() == version_text.to_lowercase();
    }
    let Some(parsed) = parse_version(item) else {
        return false;
    };
    let wildcard = version_text.ends_with(".*");
    let Some(version) = parse_version(version_text.strip_suffix(".*").unwrap_or(&version_text)) else {
        return false;
    };
    if !wildcard && parsed.local().is_empty() {
        match op.as_str() {
            ">=" => return parsed >= version,
            "<=" => return parsed <= version,
            "==" => return parsed == version,
            "!=" => return parsed != version,
            "<" | ">" if parsed.epoch() != version.epoch() || trim(parsed.release()) != trim(version.release()) => {
                return if op == "<" { parsed < version } else { parsed > version };
            }
            _ => {}
        }
    }
    if wildcard {
        let lower = base_dev0(&version);
        let upper = next_prefix_dev0(&version);
        return if op == "==" {
            parsed >= lower && parsed < upper
        } else {
            parsed < lower || parsed >= upper
        };
    }
    let has_local = version_text.contains('+');
    match op.as_str() {
        ">=" => parsed >= version,
        "<=" => below_after_locals(&version, &parsed),
        ">" => {
            if let Some(dev) = version.dev() {
                parsed >= version.clone().with_dev(Some(dev + 1)).without_local()
            } else if let Some(post) = version.post() {
                parsed
                    >= version
                        .clone()
                        .with_post(Some(post + 1))
                        .with_dev(Some(0))
                        .without_local()
            } else {
                above_after_posts(&version, &parsed)
            }
        }
        "<" => {
            let bound = if version.any_prerelease() {
                version.clone()
            } else {
                version.clone().with_dev(Some(0)).without_local()
            };
            let minimum = Version::new([0]).with_dev(Some(0));
            bound > minimum && parsed < bound
        }
        "==" => {
            parsed >= version
                && if has_local {
                    parsed <= version
                } else {
                    below_after_locals(&version, &parsed)
                }
        }
        "!=" => {
            parsed < version
                || if has_local {
                    parsed > version
                } else {
                    above_after_locals(&version, &parsed)
                }
        }
        "~=" => {
            let release = version.release();
            let prefix = version.clone().with_release(release[..release.len() - 1].to_vec());
            parsed >= version && parsed < next_prefix_dev0(&prefix)
        }
        _ => false,
    }
}

fn trim(release: &[u64]) -> &[u64] {
    let mut end = release.len();
    while end > 1 && release[end - 1] == 0 {
        end -= 1;
    }
    &release[..end]
}

fn next_prefix_dev0(version: &Version) -> Version {
    let mut release = version.release().to_vec();
    if let Some(last) = release.last_mut() {
        *last += 1;
    }
    Version::new(release).with_epoch(version.epoch()).with_dev(Some(0))
}

fn base_dev0(version: &Version) -> Version {
    Version::new(version.release().to_vec())
        .with_epoch(version.epoch())
        .with_dev(Some(0))
}

// whether parsed shares V's epoch, trimmed release and pre-release, the start of every family test below
fn same_base(version: &Version, parsed: &Version) -> bool {
    let trimmed = trim(version.release());
    let release = parsed.release();
    parsed.epoch() == version.epoch()
        && release.len() >= trimmed.len()
        && release[..trimmed.len()] == *trimmed
        && release[trimmed.len()..].iter().all(|part| *part == 0)
        && parsed.pre() == version.pre()
}

fn above_after_posts(version: &Version, parsed: &Version) -> bool {
    version.cmp(parsed) == Ordering::Less && !same_base(version, parsed)
}

fn above_after_locals(version: &Version, parsed: &Version) -> bool {
    version.cmp(parsed) == Ordering::Less
        && !(same_base(version, parsed) && parsed.post() == version.post() && parsed.dev() == version.dev())
}

fn below_after_locals(version: &Version, parsed: &Version) -> bool {
    version.cmp(parsed) != Ordering::Less
        || (same_base(version, parsed) && parsed.post() == version.post() && parsed.dev() == version.dev())
}

// --- the extra verdict -------------------------------------------------------------------------------------------

fn extra_verdict(markers: &[MarkerNode]) -> Option<bool> {
    // three-valued, "and" binding tighter than "or": ranked False < unknown < True
    let mut groups: Vec<Vec<u8>> = vec![Vec::new()];
    for marker in markers {
        let verdict = match marker {
            MarkerNode::Or => {
                groups.push(Vec::new());
                continue;
            }
            MarkerNode::And => continue,
            MarkerNode::Group(items) => extra_verdict(items),
            MarkerNode::Item(item) => match (&item.lhs, &item.rhs) {
                (MarkerVar::Variable(name), MarkerVar::Value(value)) if name == "extra" => {
                    no_extra_verdict("", &item.op, value)
                }
                (MarkerVar::Value(value), MarkerVar::Variable(name)) if name == "extra" => {
                    no_extra_verdict(value, &item.op, "")
                }
                _ => None,
            },
        };
        groups.last_mut().expect("a group").push(rank(verdict));
    }
    let best = groups
        .iter()
        .map(|group| group.iter().copied().min().unwrap_or(2))
        .max()
        .unwrap_or(2);
    [Some(false), None, Some(true)][usize::from(best)]
}

fn rank(verdict: Option<bool>) -> u8 {
    match verdict {
        Some(false) => 0,
        None => 1,
        Some(true) => 2,
    }
}

fn no_extra_verdict(lhs: &str, op: &str, rhs: &str) -> Option<bool> {
    // extra is no version marker, so only the string operators answer; extra compared as a version stays unknown
    eval_op(lhs, op, rhs, "extra").ok()
}

// --- Python string helpers ---------------------------------------------------------------------------------------

/// `str.isspace`
#[must_use]
pub(crate) fn py_isspace(character: char) -> bool {
    character.is_whitespace() || ('\x1c'..='\x1f').contains(&character)
}

/// `str.strip()`
#[must_use]
pub(crate) fn py_strip(text: &str) -> &str {
    text.trim_matches(py_isspace)
}

/// `repr(str)`
#[must_use]
pub(crate) fn py_repr(text: &str) -> String {
    let quote = if text.contains('\'') && !text.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::with_capacity(text.len() + 2);
    out.push(quote);
    for character in text.chars() {
        match character {
            '\\' => out.push_str("\\\\"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            _ if character == quote => {
                out.push('\\');
                out.push(character);
            }
            _ if (character as u32) < 0x20 || character as u32 == 0x7f => {
                let _ = write!(out, "\\x{:02x}", character as u32);
            }
            _ if (character as u32) < 0x7f || py_isprintable(character) => out.push(character),
            _ if (character as u32) <= 0xff => {
                let _ = write!(out, "\\x{:02x}", character as u32);
            }
            _ if (character as u32) <= 0xffff => {
                let _ = write!(out, "\\u{:04x}", character as u32);
            }
            _ => {
                let _ = write!(out, "\\U{:08x}", character as u32);
            }
        }
    }
    out.push(quote);
    out
}

// str.isprintable for non-ASCII: false for the separator, format, control and private-use categories; unassigned code
// points are not known here, so they count as printable
fn py_isprintable(character: char) -> bool {
    let code = character as u32;
    !(character.is_control()
        || matches!(
            code,
            0xa0 | 0xad
                | 0x600..=0x605
                | 0x61c
                | 0x6dd
                | 0x70f
                | 0x890..=0x891
                | 0x8e2
                | 0x1680
                | 0x180e
                | 0x2000..=0x200f
                | 0x2028..=0x202f
                | 0x205f..=0x2064
                | 0x2066..=0x206f
                | 0x3000
                | 0xd800..=0xf8ff
                | 0xfeff
                | 0xfff9..=0xfffb
                | 0x110bd
                | 0x110cd
                | 0x13430..=0x1343f
                | 0x1bca0..=0x1bca3
                | 0x1d173..=0x1d17a
                | 0xe0001
                | 0xe0020..=0xe007f
                | 0xf_0000..=0x0010_ffff
        ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn marker_of(text: &str) -> Vec<MarkerNode> {
        parse_requirement(&format!("name; {text}"))
            .ok()
            .and_then(|requirement| requirement.marker)
            .expect("marker")
    }

    #[test]
    fn formats_like_packaging() {
        let marker = marker_of("(python_version<'3.8' and os.name=='nt') or extra=='Cli_X'");
        assert_eq!(
            format_marker(&marker).as_deref(),
            Ok(r#"(python_version < "3.8" and os_name == "nt") or extra == "cli-x""#)
        );
        assert_eq!(
            format_marker(&marker_of("(python_version > '3')")).as_deref(),
            Ok(r#"python_version > "3""#)
        );
    }

    #[test]
    fn extra_verdicts() {
        assert!(!applies_without_extras(&marker_of(r#"extra == "cli""#)));
        assert!(applies_without_extras(&marker_of(r#"extra in "a,b""#)));
        assert!(applies_without_extras(&marker_of(r#"python_version < "3""#)));
        assert!(applies_without_extras(&marker_of(r#"extra ~= "1.0""#)));
        assert!(!applies_without_extras(&marker_of(
            r#"extra == "a" and python_version < "3""#
        )));
        assert!(applies_without_extras(&marker_of(
            r#"extra == "a" or python_version < "3""#
        )));
    }

    #[test]
    fn evaluates_versions() {
        let env: HashMap<String, String> = [
            ("python_version", "3.15"),
            ("python_full_version", "3.15.2"),
            ("sys_platform", "linux"),
            ("platform_release", "6.17.0-200.fc45.x86_64"),
        ]
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
        .collect();
        assert_eq!(evaluate(&marker_of(r#"python_version >= "3.8""#), &env), Ok(true));
        assert_eq!(
            evaluate(&marker_of(r#"python_full_version < "3.15.2rc1""#), &env),
            Ok(false)
        );
        assert_eq!(
            evaluate(&marker_of(r#"sys_platform == "win32" or extra == "x""#), &env),
            Ok(false)
        );
        assert_eq!(evaluate(&marker_of(r#"platform_release >= "5""#), &env), Ok(false));
        assert_eq!(
            evaluate(&marker_of(r#""x" in extras"#), &env),
            Err("'extras'".to_owned())
        );
    }

    #[test]
    fn errors_match_packaging() {
        assert_eq!(
            parse_requirement("name >= 1.0 extra").err().as_deref(),
            Some(
                "Expected comma (within version specifier), semicolon (after version specifier) or end\n    name >= 1.0 extra\n         ~~~~~~~^"
            )
        );
        assert_eq!(
            parse_requirement("name===1,2").err().as_deref(),
            Some("Invalid specifier: '2'")
        );
    }

    #[test]
    fn specifiers() {
        let requirement = parse_requirement("urllib3 == 1.26.4").ok().expect("parses");
        assert_eq!(requirement.specifiers(), vec![("==".to_owned(), "1.26.4".to_owned())]);
    }
}
