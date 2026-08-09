use serde::Serialize;
use std::collections::BTreeSet;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SmtpReply {
    pub code: u16,
    pub enhanced_status: Option<String>,
    pub multiline: bool,
    pub capabilities: BTreeSet<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SmtpResult {
    pub replies: Vec<SmtpReply>,
    pub tls: bool,
    pub accepted: bool,
    pub connection_closed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ImapResult {
    pub tagged_statuses: Vec<String>,
    pub response_codes: BTreeSet<String>,
    pub untagged_kinds: Vec<String>,
    pub capabilities: BTreeSet<String>,
    pub exists: Vec<u64>,
    pub expunged: Vec<u64>,
    pub final_exists: Option<u64>,
    pub search_result_sizes: Vec<usize>,
    pub tls: bool,
    pub connection_closed: bool,
}

pub fn smtp_reply(lines: &[Vec<u8>]) -> Option<SmtpReply> {
    let first = std::str::from_utf8(lines.first()?).ok()?;
    let code = first.get(..3)?.parse().ok()?;
    let enhanced_status = lines.iter().find_map(|line| {
        std::str::from_utf8(line)
            .ok()?
            .split_ascii_whitespace()
            .find(|word| {
                word.split('.').count() == 3
                    && word
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || byte == b'.')
            })
            .map(str::to_owned)
    });
    let capabilities = lines
        .iter()
        .skip(1)
        .filter_map(|line| {
            let text = std::str::from_utf8(line).ok()?.get(4..)?.trim();
            text.split_ascii_whitespace()
                .next()
                .map(str::to_ascii_uppercase)
        })
        .collect();
    Some(SmtpReply {
        code,
        enhanced_status,
        multiline: lines.len() > 1,
        capabilities,
    })
}

pub fn imap(lines: &[Vec<u8>], tls: bool, closed: bool) -> ImapResult {
    let mut result = ImapResult {
        tagged_statuses: Vec::new(),
        response_codes: BTreeSet::new(),
        untagged_kinds: Vec::new(),
        capabilities: BTreeSet::new(),
        exists: Vec::new(),
        expunged: Vec::new(),
        final_exists: None,
        search_result_sizes: Vec::new(),
        tls,
        connection_closed: closed,
    };
    for line in lines {
        let Ok(text) = std::str::from_utf8(line) else {
            continue;
        };
        let words: Vec<_> = text.split_ascii_whitespace().collect();
        if words.first() == Some(&"*") {
            if words
                .get(2)
                .is_some_and(|word| word.eq_ignore_ascii_case("EXISTS"))
                && let Some(count) = words.get(1).and_then(|word| word.parse().ok())
            {
                result.exists.push(count);
                result.final_exists = Some(count);
            }
            if words
                .get(2)
                .is_some_and(|word| word.eq_ignore_ascii_case("EXPUNGE"))
                && let Some(sequence) = words.get(1).and_then(|word| word.parse().ok())
            {
                result.expunged.push(sequence);
                result.final_exists = result.final_exists.map(|count| count.saturating_sub(1));
            }
            if words
                .get(1)
                .is_some_and(|word| word.eq_ignore_ascii_case("SEARCH"))
            {
                result
                    .search_result_sizes
                    .push(words.len().saturating_sub(2));
            }
        }
        if words
            .first()
            .is_some_and(|value| !matches!(*value, "*" | "+"))
        {
            if let Some(status) = words.get(1) {
                result.tagged_statuses.push(status.to_ascii_uppercase());
            }
        } else if words.first() == Some(&"*")
            && let Some(kind) = words.get(1)
        {
            result.untagged_kinds.push(kind.to_ascii_uppercase());
        }
        for word in &words {
            if let Some(code) = word
                .strip_prefix('[')
                .and_then(|value| value.strip_suffix(']'))
            {
                result.response_codes.insert(
                    code.split_whitespace()
                        .next()
                        .unwrap_or(code)
                        .to_ascii_uppercase(),
                );
            }
        }
        if text.to_ascii_uppercase().contains("CAPABILITY") {
            let start = words
                .iter()
                .position(|word| word.eq_ignore_ascii_case("CAPABILITY"));
            if let Some(start) = start {
                result.capabilities.extend(
                    words
                        .iter()
                        .skip(start + 1)
                        .map(|word| word.trim_matches(']').to_ascii_uppercase()),
                );
            }
        }
    }
    result.untagged_kinds.sort();
    result
}

#[cfg(test)]
mod tests {
    use super::imap;

    #[test]
    fn expunge_and_explicit_exists_have_the_same_final_state() {
        let dovecot = imap(
            &[b"* 1 EXISTS\r\n".to_vec(), b"* 1 EXPUNGE\r\n".to_vec()],
            true,
            false,
        );
        let mailer = imap(
            &[
                b"* 1 EXISTS\r\n".to_vec(),
                b"* 1 EXPUNGE\r\n".to_vec(),
                b"* 0 EXISTS\r\n".to_vec(),
            ],
            true,
            false,
        );
        assert_eq!(mailer.final_exists, dovecot.final_exists);
        assert_eq!(mailer.final_exists, Some(0));
    }
}
