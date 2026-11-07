//! `email.utils.getaddresses` in its strict mode, ported from CPython's `email._parseaddr` and `email.utils`.

const SPECIALS: &str = "()<>@,:;.\"[]";
const LWS: &str = " \t";
const FWS: &str = " \t\r\n";

struct Parser {
    field: Vec<char>,
    pos: usize,
    comments: Vec<String>,
}

fn is_atom_end(character: char) -> bool {
    SPECIALS.contains(character) || matches!(character, ' ' | '\t' | '\r' | '\n')
}

fn is_phrase_end(character: char) -> bool {
    character != '.' && is_atom_end(character)
}

impl Parser {
    fn at(&self) -> Option<char> {
        self.field.get(self.pos).copied()
    }

    fn goto_next(&mut self) -> String {
        let mut whitespace = String::new();
        while let Some(character) = self.at() {
            if matches!(character, ' ' | '\t' | '\n' | '\r') {
                if !matches!(character, '\n' | '\r') {
                    whitespace.push(character);
                }
                self.pos += 1;
            } else if character == '(' {
                let comment = self.comment();
                self.comments.push(comment);
            } else {
                break;
            }
        }
        whitespace
    }

    fn address_list(&mut self) -> Vec<(String, String)> {
        let mut result = Vec::new();
        while self.pos < self.field.len() {
            let address = self.address();
            if address.is_empty() {
                result.push((String::new(), String::new()));
            } else {
                result.extend(address);
            }
        }
        result
    }

    fn address(&mut self) -> Vec<(String, String)> {
        self.comments.clear();
        self.goto_next();
        let old_pos = self.pos;
        let old_comments = self.comments.clone();
        let phrases = self.phrase_list();
        self.goto_next();
        let mut found = Vec::new();
        match self.at() {
            None => {
                if let Some(first) = phrases.first() {
                    found.push((self.comments.join(" "), first.clone()));
                }
            }
            Some('.' | '@') => {
                self.pos = old_pos;
                self.comments = old_comments;
                let spec = self.addr_spec();
                found.push((self.comments.join(" "), spec));
            }
            Some(':') => {
                self.pos += 1;
                while self.pos < self.field.len() {
                    self.goto_next();
                    if self.at() == Some(';') {
                        self.pos += 1;
                        break;
                    }
                    let inner = self.address();
                    found.extend(inner);
                }
            }
            Some('<') => {
                let route = self.route_addr();
                if self.comments.is_empty() {
                    found.push((phrases.join(" "), route));
                } else {
                    found.push((format!("{} ({})", phrases.join(" "), self.comments.join(" ")), route));
                }
            }
            Some(character) => {
                if let Some(first) = phrases.first() {
                    found.push((self.comments.join(" "), first.clone()));
                } else if SPECIALS.contains(character) {
                    self.pos += 1;
                }
            }
        }
        self.goto_next();
        if self.at() == Some(',') {
            self.pos += 1;
        }
        found
    }

    fn route_addr(&mut self) -> String {
        if self.at() != Some('<') {
            return String::new();
        }
        let mut expect_route = false;
        self.pos += 1;
        self.goto_next();
        let mut address = String::new();
        while let Some(character) = self.at() {
            if expect_route {
                self.domain();
                expect_route = false;
            } else if character == '>' {
                self.pos += 1;
                break;
            } else if character == '@' {
                self.pos += 1;
                expect_route = true;
            } else if character == ':' {
                self.pos += 1;
            } else {
                address = self.addr_spec();
                self.pos += 1;
                break;
            }
            self.goto_next();
        }
        address
    }

    fn addr_spec(&mut self) -> String {
        let mut parts: Vec<String> = Vec::new();
        self.goto_next();
        while let Some(character) = self.at() {
            let mut preserve = true;
            if character == '.' {
                if parts.last().is_some_and(|last| last.trim().is_empty()) {
                    parts.pop();
                }
                parts.push(".".to_owned());
                self.pos += 1;
                preserve = false;
            } else if character == '"' {
                let quoted = self.quote();
                parts.push(format!("\"{}\"", quoted.replace('\\', "\\\\").replace('"', "\\\"")));
            } else if is_atom_end(character) {
                if parts.last().is_some_and(|last| last.trim().is_empty()) {
                    parts.pop();
                }
                break;
            } else {
                parts.push(self.atom(is_atom_end));
            }
            let whitespace = self.goto_next();
            if preserve && !whitespace.is_empty() {
                parts.push(whitespace);
            }
        }
        if self.at() != Some('@') {
            return parts.concat();
        }
        parts.push("@".to_owned());
        self.pos += 1;
        self.goto_next();
        let domain = self.domain();
        if domain.is_empty() {
            return String::new();
        }
        parts.concat() + &domain
    }

    fn domain(&mut self) -> String {
        let mut parts = String::new();
        while let Some(character) = self.at() {
            if LWS.contains(character) {
                self.pos += 1;
            } else if character == '(' {
                let comment = self.comment();
                self.comments.push(comment);
            } else if character == '[' {
                let literal = self.delimited('[', "]\r", false);
                parts.push('[');
                parts.push_str(&literal);
                parts.push(']');
            } else if character == '.' {
                self.pos += 1;
                parts.push('.');
            } else if character == '@' {
                return String::new();
            } else if is_atom_end(character) {
                break;
            } else {
                parts.push_str(&self.atom(is_atom_end));
            }
        }
        parts
    }

    fn delimited(&mut self, begin: char, ends: &str, allow_comments: bool) -> String {
        if self.at() != Some(begin) {
            return String::new();
        }
        let mut out = String::new();
        let mut quoted = false;
        self.pos += 1;
        while let Some(character) = self.at() {
            if quoted {
                out.push(character);
                quoted = false;
            } else if ends.contains(character) {
                self.pos += 1;
                break;
            } else if allow_comments && character == '(' {
                let comment = self.comment();
                out.push_str(&comment);
                continue;
            } else if character == '\\' {
                quoted = true;
            } else {
                out.push(character);
            }
            self.pos += 1;
        }
        out
    }

    fn quote(&mut self) -> String {
        self.delimited('"', "\"\r", false)
    }

    fn comment(&mut self) -> String {
        self.delimited('(', ")\r", true)
    }

    fn atom(&mut self, ends: fn(char) -> bool) -> String {
        let mut out = String::new();
        while let Some(character) = self.at() {
            if ends(character) {
                break;
            }
            out.push(character);
            self.pos += 1;
        }
        out
    }

    fn phrase_list(&mut self) -> Vec<String> {
        let mut phrases = Vec::new();
        while let Some(character) = self.at() {
            if FWS.contains(character) {
                self.pos += 1;
            } else if character == '"' {
                phrases.push(self.quote());
            } else if character == '(' {
                let comment = self.comment();
                self.comments.push(comment);
            } else if is_phrase_end(character) {
                break;
            } else {
                phrases.push(self.atom(is_phrase_end));
            }
        }
        phrases
    }
}

/// characters with their escapes, as `_iter_escaped_chars` yields them
fn escaped(text: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let mut escape = false;
    let mut last = 0;
    for (position, character) in text.chars().enumerate() {
        last = position;
        if escape {
            out.push((position, format!("\\{character}")));
            escape = false;
        } else if character == '\\' {
            escape = true;
        } else {
            out.push((position, character.to_string()));
        }
    }
    if escape {
        out.push((last, "\\".to_owned()));
    }
    out
}

fn strip_quoted_realnames(text: &str) -> String {
    if !text.contains('"') {
        return text.to_owned();
    }
    let characters: Vec<char> = text.chars().collect();
    let mut start = 0;
    let mut open: Option<usize> = None;
    let mut out = String::new();
    for (position, character) in escaped(text) {
        if character == "\"" {
            match open {
                None => open = Some(position),
                Some(opened) => {
                    if start != opened {
                        out.extend(&characters[start..opened]);
                    }
                    start = position + 1;
                    open = None;
                }
            }
        }
    }
    if start < characters.len() {
        out.extend(&characters[start..]);
    }
    out
}

fn balanced(text: &str) -> bool {
    let stripped = strip_quoted_realnames(text);
    let mut opens = 0i64;
    for (_, character) in escaped(&stripped) {
        if character == "(" {
            opens += 1;
        } else if character == ")" {
            opens -= 1;
            if opens < 0 {
                return false;
            }
        }
    }
    opens == 0
}

/// `getaddresses(values)`, strict
pub fn getaddresses<'a>(values: impl Iterator<Item = &'a str>) -> Vec<(String, String)> {
    let values: Vec<String> = values.map(|value| if balanced(value) { value.to_owned() } else { "('', '')".to_owned() }).collect();
    let joined = values.join(", ");
    let mut parser = Parser { field: joined.chars().collect(), pos: 0, comments: Vec::new() };
    let parsed: Vec<(String, String)> = if joined.is_empty() { Vec::new() } else { parser.address_list() };
    let result: Vec<(String, String)> =
        parsed.into_iter().map(|(name, address)| if address.contains('[') { (String::new(), String::new()) } else { (name, address) }).collect();
    let expected: usize = values.iter().map(|value| 1 + strip_quoted_realnames(value).matches(',').count()).sum();
    if result.len() != expected {
        return vec![(String::new(), String::new())];
    }
    result
}

#[cfg(test)]
mod tests {
    use super::getaddresses;

    fn pairs(values: &[&str]) -> Vec<(String, String)> {
        getaddresses(values.iter().copied())
    }

    #[test]
    fn addresses() {
        assert_eq!(
            pairs(&["Author <author@example.com>, plain@example.com"]),
            vec![("Author".into(), "author@example.com".into()), (String::new(), "plain@example.com".into())]
        );
        assert_eq!(pairs(&["not-an-email"]), vec![(String::new(), "not-an-email".into())]);
        assert_eq!(pairs(&["\"Last, First\" <a@b.c>"]), vec![("Last, First".into(), "a@b.c".into())]);
        assert_eq!(pairs(&["alice@example.com <bob@example.com>"]), vec![(String::new(), String::new())]);
        assert!(pairs(&[]).is_empty());
    }
}
