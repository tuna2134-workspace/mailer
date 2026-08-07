#![forbid(unsafe_code)]

use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AddressLimits {
    pub max_bytes: usize,
    pub max_addresses: usize,
    pub max_comment_depth: usize,
}

impl Default for AddressLimits {
    fn default() -> Self {
        Self {
            max_bytes: 64 * 1024,
            max_addresses: 1_000,
            max_comment_depth: 8,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Mailbox {
    pub display_name: Option<Vec<u8>>,
    pub local_part: Vec<u8>,
    pub domain: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Group {
    pub display_name: Vec<u8>,
    pub members: Vec<Mailbox>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Address {
    Mailbox(Mailbox),
    Group(Group),
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
#[error("address parse error at byte {position}: {kind}")]
pub struct AddressError {
    pub position: usize,
    pub kind: AddressErrorKind,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum AddressErrorKind {
    #[error("address input exceeds configured limit")]
    TooLarge,
    #[error("too many addresses")]
    TooManyAddresses,
    #[error("comment nesting exceeds configured limit")]
    CommentDepth,
    #[error("unterminated quoted string, comment, group, or angle address")]
    Unterminated,
    #[error("invalid address syntax")]
    InvalidSyntax,
    #[error("SMTPUTF8 address is not enabled")]
    NonAscii,
}

pub fn parse_address_list(
    input: &[u8],
    limits: AddressLimits,
) -> Result<Vec<Address>, AddressError> {
    if input.len() > limits.max_bytes {
        return Err(error(0, AddressErrorKind::TooLarge));
    }
    validate_structure(input, limits.max_comment_depth)?;
    let mut addresses = Vec::new();
    let mut start = 0;
    while start < input.len() {
        start = skip_cfws(input, start)?;
        if start == input.len() {
            break;
        }
        if let Some(colon) = find_top(input, start, b':')? {
            let comma = find_top(input, start, b',')?.unwrap_or(input.len());
            if colon < comma {
                let end = find_top(input, colon + 1, b';')?
                    .ok_or(error(colon, AddressErrorKind::Unterminated))?;
                let mut members = Vec::new();
                for segment in split_top(&input[colon + 1..end], b',')? {
                    if !trim_cfws(segment)?.is_empty() {
                        members.push(parse_mailbox(segment)?);
                    }
                }
                addresses.push(Address::Group(Group {
                    display_name: clean_phrase(&input[start..colon])?,
                    members,
                }));
                start = end + 1;
                let after = skip_cfws(input, start)?;
                start = if input.get(after) == Some(&b',') {
                    after + 1
                } else {
                    after
                };
                check_count(&addresses, limits.max_addresses, start)?;
                continue;
            }
        }
        let end = find_top(input, start, b',')?.unwrap_or(input.len());
        addresses.push(Address::Mailbox(parse_mailbox(&input[start..end])?));
        check_count(&addresses, limits.max_addresses, start)?;
        start = end.saturating_add(1);
    }
    if addresses.is_empty() {
        Err(error(0, AddressErrorKind::InvalidSyntax))
    } else {
        Ok(addresses)
    }
}

fn parse_mailbox(input: &[u8]) -> Result<Mailbox, AddressError> {
    let input = trim_cfws(input)?;
    if let Some(open) = find_top(input, 0, b'<')? {
        let close =
            find_top(input, open + 1, b'>')?.ok_or(error(open, AddressErrorKind::Unterminated))?;
        if !trim_cfws(&input[close + 1..])?.is_empty() {
            return Err(error(close + 1, AddressErrorKind::InvalidSyntax));
        }
        let mut mailbox = parse_addr_spec(trim_cfws(&input[open + 1..close])?)?;
        let phrase = clean_phrase(&input[..open])?;
        if !phrase.is_empty() {
            mailbox.display_name = Some(phrase);
        }
        Ok(mailbox)
    } else {
        parse_addr_spec(input)
    }
}

fn parse_addr_spec(input: &[u8]) -> Result<Mailbox, AddressError> {
    if !input.is_ascii() {
        return Err(error(0, AddressErrorKind::NonAscii));
    }
    let at = find_top(input, 0, b'@')?.ok_or(error(0, AddressErrorKind::InvalidSyntax))?;
    if find_top(input, at + 1, b'@')?.is_some() {
        return Err(error(at + 1, AddressErrorKind::InvalidSyntax));
    }
    let local = trim_cfws(&input[..at])?;
    let domain = trim_cfws(&input[at + 1..])?;
    if !valid_local(local) || !valid_domain(domain) {
        return Err(error(at, AddressErrorKind::InvalidSyntax));
    }
    let local_part = if local.starts_with(b"\"") {
        unquote_local(local)?
    } else {
        local.to_vec()
    };
    Ok(Mailbox {
        display_name: None,
        local_part,
        domain: domain.to_ascii_lowercase(),
    })
}

fn unquote_local(value: &[u8]) -> Result<Vec<u8>, AddressError> {
    let mut output = Vec::with_capacity(value.len().saturating_sub(2));
    let mut escaped = false;
    for byte in &value[1..value.len() - 1] {
        if escaped {
            output.push(*byte);
            escaped = false;
        } else if *byte == b'\\' {
            escaped = true;
        } else {
            output.push(*byte);
        }
    }
    if escaped {
        Err(error(value.len(), AddressErrorKind::InvalidSyntax))
    } else {
        Ok(output)
    }
}

fn valid_local(value: &[u8]) -> bool {
    if value.len() >= 2 && value[0] == b'"' && value[value.len() - 1] == b'"' {
        let mut escaped = false;
        return value[1..value.len() - 1].iter().all(|byte| {
            if escaped {
                escaped = false;
                return matches!(*byte, 32..=126);
            }
            if *byte == b'\\' {
                escaped = true;
                true
            } else {
                matches!(*byte, 32..=33 | 35..=91 | 93..=126)
            }
        }) && !escaped;
    }
    valid_dot_atom(value)
}

fn valid_domain(value: &[u8]) -> bool {
    if value.len() >= 2 && value[0] == b'[' && value[value.len() - 1] == b']' {
        return !value[1..value.len() - 1].is_empty()
            && value[1..value.len() - 1]
                .iter()
                .all(|byte| matches!(*byte, 33..=90 | 94..=126));
    }
    valid_dot_atom(value)
}

fn valid_dot_atom(value: &[u8]) -> bool {
    !value.is_empty()
        && !value.starts_with(b".")
        && !value.ends_with(b".")
        && !value.windows(2).any(|pair| pair == b"..")
        && value
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-/=?^_`{|}~.".contains(byte))
}

fn clean_phrase(input: &[u8]) -> Result<Vec<u8>, AddressError> {
    let mut output = Vec::new();
    let mut index = 0;
    while index < input.len() {
        if input[index] == b'(' {
            index = skip_comment(input, index, usize::MAX)?;
            continue;
        }
        if input[index].is_ascii_control() && !matches!(input[index], b' ' | b'\t') {
            return Err(error(index, AddressErrorKind::InvalidSyntax));
        }
        output.push(input[index]);
        index += 1;
    }
    let start = output
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(output.len());
    let end = output
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .map_or(start, |index| index + 1);
    let output = &output[start..end];
    if output.starts_with(b"\"") && output.ends_with(b"\"") && output.len() >= 2 {
        Ok(output[1..output.len() - 1].to_vec())
    } else {
        Ok(output.to_vec())
    }
}

fn validate_structure(input: &[u8], max_depth: usize) -> Result<(), AddressError> {
    let mut index = 0;
    while index < input.len() {
        index = match input[index] {
            b'(' => skip_comment(input, index, max_depth)?,
            b'"' => skip_quoted(input, index)?,
            b')' => return Err(error(index, AddressErrorKind::InvalidSyntax)),
            _ => index + 1,
        };
    }
    Ok(())
}

fn split_top(input: &[u8], delimiter: u8) -> Result<Vec<&[u8]>, AddressError> {
    let mut parts = Vec::new();
    let mut start = 0;
    while let Some(index) = find_top(input, start, delimiter)? {
        parts.push(&input[start..index]);
        start = index + 1;
    }
    parts.push(&input[start..]);
    Ok(parts)
}

fn find_top(input: &[u8], mut index: usize, needle: u8) -> Result<Option<usize>, AddressError> {
    let mut angle = 0_u8;
    while index < input.len() {
        match input[index] {
            b'(' => index = skip_comment(input, index, usize::MAX)?,
            b'"' => index = skip_quoted(input, index)?,
            b'<' => {
                if needle == b'<' && angle == 0 {
                    return Ok(Some(index));
                }
                angle = angle.saturating_add(1);
                index += 1;
            }
            b'>' => {
                angle = angle.saturating_sub(1);
                if needle == b'>' && angle == 0 {
                    return Ok(Some(index));
                }
                index += 1;
            }
            byte if byte == needle && angle == 0 => return Ok(Some(index)),
            _ => index += 1,
        }
    }
    Ok(None)
}

fn skip_cfws(input: &[u8], mut index: usize) -> Result<usize, AddressError> {
    loop {
        while input.get(index).is_some_and(u8::is_ascii_whitespace) {
            index += 1;
        }
        if input.get(index) == Some(&b'(') {
            index = skip_comment(input, index, usize::MAX)?;
        } else {
            return Ok(index);
        }
    }
}

fn trim_cfws(input: &[u8]) -> Result<&[u8], AddressError> {
    let start = skip_cfws(input, 0)?;
    let mut end = input.len();
    loop {
        while end > start && input[end - 1].is_ascii_whitespace() {
            end -= 1;
        }
        let mut index = start;
        let mut trailing_comment = None;
        while index < end {
            if input[index] == b'(' {
                let comment_end = skip_comment(input, index, usize::MAX)?;
                if comment_end == end {
                    trailing_comment = Some(index);
                }
                index = comment_end;
            } else if input[index] == b'"' {
                index = skip_quoted(input, index)?;
            } else {
                index += 1;
            }
        }
        if let Some(comment_start) = trailing_comment {
            end = comment_start;
        } else {
            break;
        }
    }
    Ok(&input[start..end])
}

fn skip_quoted(input: &[u8], mut index: usize) -> Result<usize, AddressError> {
    index += 1;
    while index < input.len() {
        match input[index] {
            b'\\' => index = index.saturating_add(2),
            b'"' => return Ok(index + 1),
            _ => index += 1,
        }
    }
    Err(error(index, AddressErrorKind::Unterminated))
}

fn skip_comment(input: &[u8], mut index: usize, max_depth: usize) -> Result<usize, AddressError> {
    let mut depth = 0;
    while index < input.len() {
        match input[index] {
            b'\\' => index = index.saturating_add(2),
            b'(' => {
                depth += 1;
                if depth > max_depth {
                    return Err(error(index, AddressErrorKind::CommentDepth));
                }
                index += 1;
            }
            b')' => {
                depth -= 1;
                index += 1;
                if depth == 0 {
                    return Ok(index);
                }
            }
            _ => index += 1,
        }
    }
    Err(error(index, AddressErrorKind::Unterminated))
}

fn check_count(addresses: &[Address], max: usize, position: usize) -> Result<(), AddressError> {
    let count = addresses
        .iter()
        .map(|address| match address {
            Address::Mailbox(_) => 1,
            Address::Group(group) => group.members.len(),
        })
        .sum::<usize>();
    if count > max {
        Err(error(position, AddressErrorKind::TooManyAddresses))
    } else {
        Ok(())
    }
}

fn error(position: usize, kind: AddressErrorKind) -> AddressError {
    AddressError { position, kind }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn parses_mailboxes_comments_quotes_and_groups() -> Result<(), AddressError> {
        let parsed = parse_address_list(
            b"Friends: Alice <alice@example.test>, \"b c\"@example.test;,(note) root@[127.0.0.1]",
            AddressLimits::default(),
        )?;
        assert_eq!(parsed.len(), 2);
        let Address::Group(group) = &parsed[0] else {
            return Err(error(0, AddressErrorKind::InvalidSyntax));
        };
        assert_eq!(group.members.len(), 2);
        let trailing = parse_address_list(b"alice@example.test (work)", AddressLimits::default())?;
        assert!(
            matches!(&trailing[0], Address::Mailbox(mailbox) if mailbox.local_part == b"alice")
        );
        Ok(())
    }

    proptest! {
        #[test]
        fn arbitrary_addresses_never_panic(input in proptest::collection::vec(any::<u8>(), 0..2048)) {
            let _ = parse_address_list(&input, AddressLimits { max_bytes: 2048, ..AddressLimits::default() });
        }
    }
}
