use crate::{SpfContext, SpfError};
use std::fmt::Write as _;

pub fn expand_domain(
    value: &str,
    context: &SpfContext<'_>,
    domain: &str,
) -> Result<String, SpfError> {
    expand_domain_with_p(value, context, domain, "unknown")
}

pub(crate) fn expand_domain_with_p(
    value: &str,
    context: &SpfContext<'_>,
    domain: &str,
    validated_domain: &str,
) -> Result<String, SpfError> {
    let mut expanded = expand(value, context, domain, false, validated_domain)?;
    while expanded.len() > 253 {
        let Some(dot) = expanded.find('.') else {
            return Err(SpfError::Invalid);
        };
        expanded.drain(..=dot);
    }
    valid_domain(&expanded)
        .then_some(expanded)
        .ok_or(SpfError::Invalid)
}

pub(crate) fn validate(value: &str, explanation: bool) -> Result<(), SpfError> {
    scan(value, explanation, |_, _, _, _| Ok(String::new())).map(|_| ())
}

fn expand(
    value: &str,
    context: &SpfContext<'_>,
    domain: &str,
    explanation: bool,
    validated_domain: &str,
) -> Result<String, SpfError> {
    scan(value, explanation, |letter, digits, reverse, delimiters| {
        let raw = macro_value(letter, context, domain, validated_domain)?;
        let mut parts = raw
            .split(|character| delimiters.contains(&character))
            .collect::<Vec<_>>();
        if reverse {
            parts.reverse();
        }
        if let Some(count) = digits {
            let keep_from = parts.len().saturating_sub(count);
            parts.drain(..keep_from);
        }
        let joined = parts.join(".");
        if letter.is_ascii_uppercase() {
            Ok(url_escape(joined.as_bytes()))
        } else {
            Ok(joined)
        }
    })
}

fn scan<F>(value: &str, explanation: bool, mut macro_value: F) -> Result<String, SpfError>
where
    F: FnMut(char, Option<usize>, bool, &[char]) -> Result<String, SpfError>,
{
    let mut output = String::with_capacity(value.len());
    let mut chars = value.char_indices().peekable();
    while let Some((_, character)) = chars.next() {
        if character != '%' {
            if character.is_ascii_graphic() || (explanation && character == ' ') {
                output.push(character);
                continue;
            }
            return Err(SpfError::Invalid);
        }
        match chars.next() {
            Some((_, '%')) => output.push('%'),
            Some((_, '_')) => output.push(' '),
            Some((_, '-')) => output.push_str("%20"),
            Some((_, '{')) => {
                let (_, letter) = chars.next().ok_or(SpfError::Invalid)?;
                if !allowed_letter(letter, explanation) {
                    return Err(SpfError::Invalid);
                }
                let mut digits = String::new();
                while chars
                    .peek()
                    .is_some_and(|(_, value)| value.is_ascii_digit())
                {
                    if let Some((_, digit)) = chars.next() {
                        digits.push(digit);
                    }
                }
                let digits = if digits.is_empty() {
                    None
                } else {
                    let count = digits.parse::<usize>().map_err(|_| SpfError::Invalid)?;
                    if count == 0 {
                        return Err(SpfError::Invalid);
                    }
                    Some(count)
                };
                let reverse = if chars.peek().is_some_and(|(_, value)| *value == 'r') {
                    chars.next();
                    true
                } else {
                    false
                };
                let mut delimiters = Vec::new();
                while let Some((_, delimiter)) = chars.peek() {
                    if matches!(delimiter, '.' | '-' | '+' | ',' | '/' | '_' | '=') {
                        delimiters.push(*delimiter);
                        chars.next();
                    } else {
                        break;
                    }
                }
                if chars.next().map(|(_, value)| value) != Some('}') {
                    return Err(SpfError::Invalid);
                }
                if delimiters.is_empty() {
                    delimiters.push('.');
                }
                output.push_str(&macro_value(letter, digits, reverse, &delimiters)?);
            }
            _ => return Err(SpfError::Invalid),
        }
    }
    Ok(output)
}

fn allowed_letter(letter: char, explanation: bool) -> bool {
    let letter = letter.to_ascii_lowercase();
    matches!(letter, 's' | 'l' | 'o' | 'd' | 'i' | 'p' | 'v' | 'h')
        || explanation && matches!(letter, 'c' | 'r' | 't')
}

fn macro_value(
    letter: char,
    context: &SpfContext<'_>,
    domain: &str,
    validated_domain: &str,
) -> Result<String, SpfError> {
    let sender = if context.sender.contains('@') {
        context.sender.to_owned()
    } else {
        format!("postmaster@{}", context.sender)
    };
    let (local, sender_domain) = sender.split_once('@').ok_or(SpfError::Invalid)?;
    Ok(match letter.to_ascii_lowercase() {
        's' => sender,
        'l' => local.to_owned(),
        'o' => sender_domain.to_owned(),
        'd' => domain.to_owned(),
        'i' => match context.client_ip {
            std::net::IpAddr::V4(address) => address.to_string(),
            std::net::IpAddr::V6(address) => address
                .octets()
                .iter()
                .flat_map(|byte| [byte >> 4, byte & 0x0f])
                .map(|nibble| char::from_digit(u32::from(nibble), 16).unwrap_or('0'))
                .collect::<Vec<_>>()
                .iter()
                .map(char::to_string)
                .collect::<Vec<_>>()
                .join("."),
        },
        'p' => validated_domain.into(),
        'v' => {
            if context.client_ip.is_ipv4() {
                "in-addr".into()
            } else {
                "ip6".into()
            }
        }
        'h' => context.helo.to_owned(),
        _ => return Err(SpfError::Invalid),
    })
}

fn url_escape(value: &[u8]) -> String {
    let mut output = String::with_capacity(value.len());
    for byte in value {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            output.push(char::from(*byte));
        } else {
            let _ = write!(output, "%{byte:02X}");
        }
    }
    output
}

fn valid_domain(value: &str) -> bool {
    let value = value.strip_suffix('.').unwrap_or(value);
    let mut labels = value.split('.').peekable();
    if value.is_empty() || value.len() > 253 {
        return false;
    }
    while let Some(label) = labels.next() {
        if label.is_empty()
            || label.len() > 63
            || !label.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return false;
        }
        if labels.peek().is_none()
            && (!label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                || !label.bytes().any(|byte| byte.is_ascii_alphabetic())
                || label.starts_with('-')
                || label.ends_with('-'))
        {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn context() -> SpfContext<'static> {
        SpfContext {
            client_ip: IpAddr::from([192, 0, 2, 3]),
            sender: "strong-bad@email.example.com",
            helo: "mx.example.com",
        }
    }

    #[test]
    fn rfc7208_transformers_and_literals() {
        let context = context();
        assert_eq!(
            expand("%{d2}", &context, "email.example.com", false, "unknown"),
            Ok("example.com".into())
        );
        assert_eq!(
            expand("%{d2r}", &context, "email.example.com", false, "unknown"),
            Ok("example.email".into())
        );
        assert_eq!(
            expand("%{l1r-}", &context, "email.example.com", false, "unknown"),
            Ok("strong".into())
        );
        assert_eq!(
            expand("%%.%_.%-", &context, "email.example.com", true, "unknown"),
            Ok("%. .%20".into())
        );
        assert_eq!(
            expand("%{S}", &context, "email.example.com", false, "unknown"),
            Ok("strong-bad%40email.example.com".into())
        );
    }

    #[test]
    fn invalid_or_disallowed_macros_are_rejected() {
        for value in ["%x", "%{q}", "%{d0}", "%{dr1}", "%{c}", "%{d!"] {
            assert_eq!(validate(value, false), Err(SpfError::Invalid));
        }
    }

    #[test]
    fn domain_expansion_accepts_service_labels_and_truncates_left_labels() {
        let context = context();
        assert_eq!(
            expand_domain("_spf.%{d}", &context, "example.com"),
            Ok("_spf.example.com".into())
        );
        let long = format!("{}example.com", "a.".repeat(125));
        let expanded = expand_domain(&long, &context, "example.com").unwrap_or_default();
        assert!(expanded.len() <= 253);
        assert!(expanded.ends_with("example.com"));
    }
}
