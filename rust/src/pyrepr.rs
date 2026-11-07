//! `repr()` of a Python str, for messages that quote a value as Python code does.

use std::fmt::Write as _;

pub fn repr(text: &str) -> String {
    let quote = if text.contains('\'') && !text.contains('"') { '"' } else { '\'' };
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
            _ if printable(character) => out.push(character),
            _ => {
                let code = u32::from(character);
                let _ = match code {
                    0..=0xFF => write!(out, "\\x{code:02x}"),
                    0x100..=0xFFFF => write!(out, "\\u{code:04x}"),
                    _ => write!(out, "\\U{code:08x}"),
                };
            }
        }
    }
    out.push(quote);
    out
}

/// `str.isprintable()` for one character, approximated without the Unicode database: controls, separators other than
/// the space, format characters and private use are not printable
fn printable(character: char) -> bool {
    if character == ' ' {
        return true;
    }
    if character.is_control() || character.is_whitespace() {
        return false;
    }
    !matches!(
        u32::from(character),
        0xAD | 0x600..=0x605 | 0x61C | 0x6DD | 0x70F | 0x180E | 0x200B..=0x200F | 0x202A..=0x202E
            | 0x2060..=0x2064 | 0x2066..=0x206F | 0xFEFF | 0xFFF9..=0xFFFB | 0xE000..=0xF8FF
            | 0xE0001 | 0xE0020..=0xE007F | 0xF0000..
    )
}

#[cfg(test)]
mod tests {
    use super::repr;

    #[test]
    fn quotes() {
        assert_eq!(repr("abc"), "'abc'");
        assert_eq!(repr("a'b"), "\"a'b\"");
        assert_eq!(repr("a'b\""), "'a\\'b\"'");
        assert_eq!(repr("é\u{1}\n"), "'é\\x01\\n'");
    }
}
