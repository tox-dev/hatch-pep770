// A port of packaging 26.3's canonicalize_license_expression, error messages included.

use std::collections::HashMap;

use crate::pep508::{py_isspace, py_repr};
use crate::spdx_data;

const OPERATORS: [&str; 5] = ["or", "and", "with", "(", ")"];
const LICENSE_REF_PREFIX: &str = "licenseref-";

pub fn canonicalize_license_expression(raw: &str) -> Result<String, String> {
    let invalid = || format!("Invalid license expression: {}", py_repr(raw));
    if raw.is_empty() {
        return Err(invalid());
    }
    let spaced = raw.replace('(', " ( ").replace(')', " ) ");
    // a LicenseRef keeps the case it was written in, past its prefix; a later spelling of the same ref wins
    let license_refs: HashMap<String, String> = split(&spaced)
        .filter(|reference| reference.to_lowercase().starts_with(LICENSE_REF_PREFIX))
        .map(|reference| {
            let rest: String = reference.chars().skip(LICENSE_REF_PREFIX.len()).collect();
            (reference.to_lowercase(), format!("LicenseRef-{rest}"))
        })
        .collect();
    let lowered = spaced.to_lowercase();
    let tokens: Vec<&str> = split(&lowered).collect();

    let mut python_tokens: Vec<&str> = Vec::with_capacity(tokens.len());
    for token in &tokens {
        let last = python_tokens.last().copied();
        if !OPERATORS.contains(token) {
            python_tokens.push("False");
        } else if *token == "with" {
            python_tokens.push("or");
        } else if (*token == "(" && last.is_some_and(|last| !["or", "and", "("].contains(&last)))
            || (*token == ")" && last == Some("("))
        {
            return Err(invalid());
        } else {
            python_tokens.push(token);
        }
    }
    if !compiles(&python_tokens) {
        return Err(invalid());
    }

    let mut normalized: Vec<String> = Vec::with_capacity(tokens.len());
    let mut last_license_start = false;
    for (index, token) in tokens.iter().enumerate() {
        if OPERATORS.contains(token) {
            if *token == "with"
                && (!last_license_start || index + 1 == tokens.len() || OPERATORS.contains(&tokens[index + 1]))
            {
                return Err(invalid());
            }
            normalized.push(token.to_uppercase());
            last_license_start = false;
            continue;
        }
        if normalized.last().is_some_and(|last| last == "WITH") {
            let Some(id) = spdx_data::exception(token) else {
                return Err(format!("Unknown license exception: {}", py_repr(token)));
            };
            normalized.push(id.to_owned());
            last_license_start = false;
        } else {
            let (final_token, suffix) = match token.strip_suffix('+') {
                Some(stripped) => (stripped, "+"),
                None => (*token, ""),
            };
            if let Some(ref_id) = final_token.strip_prefix(LICENSE_REF_PREFIX) {
                if !suffix.is_empty() || !license_ref_allowed(ref_id) {
                    return Err(format!("Invalid licenseref: {}", py_repr(token)));
                }
                // the map holds every ref the expression spells, so the lookup misses only where Python's KeyError would
                let Some(reference) = license_refs.get(final_token) else {
                    return Err(invalid());
                };
                normalized.push(reference.clone());
            } else {
                let Some(id) = spdx_data::license(final_token) else {
                    return Err(format!("Unknown license: {}", py_repr(final_token)));
                };
                normalized.push(format!("{id}{suffix}"));
            }
            last_license_start = true;
        }
    }
    Ok(normalized.join(" ").replace("( ", "(").replace(" )", ")"))
}

// str.split() with no separator
fn split(text: &str) -> impl Iterator<Item = &str> {
    text.split(py_isspace).filter(|part| !part.is_empty())
}

// ^[A-Za-z0-9.-]+$
fn license_ref_allowed(text: &str) -> bool {
    !text.is_empty()
        && text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'-')
}

// whether `compile(" ".join(tokens), "", "eval")` accepts an expression over False, and, or and parentheses; the
// caller already refused "()", which Python would read as an empty tuple
fn compiles(tokens: &[&str]) -> bool {
    // CPython's tokenizer refuses more than 200 nested parentheses
    const MAX_DEPTH: usize = 200;
    let mut depth = 0usize;
    let mut expect_operand = true;
    for token in tokens {
        match *token {
            "False" if expect_operand => expect_operand = false,
            "(" if expect_operand => {
                depth += 1;
                if depth > MAX_DEPTH {
                    return false;
                }
            }
            ")" if !expect_operand && depth > 0 => depth -= 1,
            "and" | "or" if !expect_operand => expect_operand = true,
            _ => return false,
        }
    }
    !expect_operand && depth == 0
}

#[cfg(test)]
mod tests {
    use super::canonicalize_license_expression;

    #[test]
    fn canonical() {
        assert_eq!(
            canonicalize_license_expression("mit and (apache-2.0 or bsd-2-clause)").as_deref(),
            Ok("MIT AND (Apache-2.0 OR BSD-2-Clause)")
        );
        assert_eq!(
            canonicalize_license_expression("gpl-2.0-only with classpath-exception-2.0").as_deref(),
            Ok("GPL-2.0-only WITH Classpath-exception-2.0")
        );
        assert_eq!(
            canonicalize_license_expression("LicenseRef-Foo.Bar").as_deref(),
            Ok("LicenseRef-Foo.Bar")
        );
    }

    #[test]
    fn errors() {
        assert_eq!(
            canonicalize_license_expression("(mit").err().as_deref(),
            Some("Invalid license expression: '(mit'")
        );
        assert_eq!(
            canonicalize_license_expression("Use-it-after-midnight")
                .err()
                .as_deref(),
            Some("Unknown license: 'use-it-after-midnight'")
        );
        assert_eq!(
            canonicalize_license_expression("").err().as_deref(),
            Some("Invalid license expression: ''")
        );
    }
}
