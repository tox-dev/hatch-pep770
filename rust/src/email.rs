//! Core metadata headers, read as `email.parser.FeedParser(policy=compat32)` reads them.

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Metadata {
    pub headers: Vec<(String, String)>,
}

impl Metadata {
    /// `message[name]` / `message.get(name)`: the first header of that name, ignoring case
    pub fn get(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(key, _)| key.eq_ignore_ascii_case(name)).map(|(_, value)| value.as_str())
    }

    /// `message.get_all(name, [])`
    pub fn get_all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.headers.iter().filter(move |(key, _)| key.eq_ignore_ascii_case(name)).map(|(_, value)| value.as_str())
    }

    pub fn contains(&self, name: &str) -> bool {
        self.headers.iter().any(|(key, _)| key.eq_ignore_ascii_case(name))
    }

    /// what `installer.utils.parse_metadata_file` returns: the headers as written
    pub fn parse(text: &str) -> Self {
        let mut headers = Vec::new();
        let mut current: Option<(&str, String)> = None;
        // the header block ends at the first line that is neither a header nor a continuation, a blank line included
        let lines: Vec<&str> = crack_lines(text).into_iter().take_while(|line| is_header_line(line)).collect();
        let last = lines.len().saturating_sub(1);
        for (number, line) in lines.iter().enumerate() {
            if line.starts_with([' ', '\t']) {
                if let Some((_, value)) = current.as_mut() {
                    value.push_str(line);
                }
                continue;
            }
            if let Some((name, value)) = current.take() {
                headers.push(finish(name, value));
            }
            if line.starts_with("From ") {
                // an mbox envelope line: kept as the unixfrom on the first line, pushed to the body on the last, and
                // dropped as a defect anywhere else
                if number == 0 || number != last {
                    continue;
                }
                break;
            }
            let Some(colon) = line.find(':') else { continue };
            if colon == 0 {
                continue;
            }
            current = Some((&line[..colon], line[colon + 1..].trim_start_matches([' ', '\t']).to_owned()));
        }
        if let Some((name, value)) = current {
            headers.push(finish(name, value));
        }
        Self { headers }
    }

    /// what `importlib.metadata.Distribution.metadata` returns: read with universal newlines, values that hold an
    /// RFC 822 continuation dedented
    pub fn parse_installed(text: &str) -> Self {
        let translated;
        let text = if text.contains('\r') {
            translated = text.replace("\r\n", "\n").replace('\r', "\n");
            translated.as_str()
        } else {
            text
        };
        let mut metadata = Self::parse(text);
        for (_, value) in &mut metadata.headers {
            if value.contains("\n        ") {
                *value = dedent(&format!("        {value}"));
            }
        }
        metadata
    }
}

fn finish(name: &str, value: String) -> (String, String) {
    let trimmed = value.trim_end_matches(['\r', '\n']).len();
    let mut value = value;
    value.truncate(trimmed);
    (name.to_owned(), value)
}

/// lines with their endings, split at `\r\n`, `\r` or `\n` as the feed parser cracks them
fn crack_lines(text: &str) -> Vec<&str> {
    let bytes = text.as_bytes();
    let mut lines = Vec::new();
    let mut start = 0;
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'\n' => {
                lines.push(&text[start..=index]);
                start = index + 1;
            }
            b'\r' => {
                let end = if bytes.get(index + 1) == Some(&b'\n') { index + 1 } else { index };
                lines.push(&text[start..=end]);
                index = end;
                start = end + 1;
            }
            _ => {}
        }
        index += 1;
    }
    if start < bytes.len() {
        lines.push(&text[start..]);
    }
    lines
}

/// `^(From |[\041-\071\073-\176]*:|[\t ])`
fn is_header_line(line: &str) -> bool {
    if line.starts_with("From ") || line.starts_with([' ', '\t']) {
        return true;
    }
    for byte in line.bytes() {
        match byte {
            b':' => return true,
            0x21..=0x39 | 0x3b..=0x7e => {}
            _ => return false,
        }
    }
    false
}

/// `textwrap.dedent` as Python 3.14 and later implement it
pub fn dedent(text: &str) -> String {
    let lines: Vec<&str> = text.split('\n').collect();
    let blank = |line: &str| line.chars().all(char::is_whitespace);
    let non_blank: Vec<&str> = lines.iter().copied().filter(|line| !line.is_empty() && !blank(line)).collect();
    let low = non_blank.iter().copied().min().unwrap_or("");
    let high = non_blank.iter().copied().max().unwrap_or("");
    let mut margin = 0;
    let high_chars: Vec<char> = high.chars().collect();
    for (index, character) in low.chars().enumerate() {
        margin = index;
        if high_chars.get(index) != Some(&character) || !matches!(character, ' ' | '\t') {
            break;
        }
    }
    lines
        .iter()
        .map(|line| {
            if !line.is_empty() && blank(line) {
                ""
            } else {
                line.char_indices().nth(margin).map_or("", |(offset, _)| &line[offset..])
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headers_and_continuations() {
        let metadata = Metadata::parse("Name: a\nSummary:  x  \nLicense: MIT\n  more\r\nVersion: 1\n\nbody: no\n");
        assert_eq!(metadata.get("name"), Some("a"));
        assert_eq!(metadata.get("Summary"), Some("x  "));
        assert_eq!(metadata.get("License"), Some("MIT\n  more"));
        assert_eq!(metadata.get("Version"), Some("1"));
        assert_eq!(metadata.get("body"), None);
    }

    #[test]
    fn installed_dedents() {
        let metadata = Metadata::parse_installed("License: MIT\n        \n        Copyright\nName: a\n");
        assert_eq!(metadata.get("License"), Some("MIT\n\nCopyright"));
    }
}
