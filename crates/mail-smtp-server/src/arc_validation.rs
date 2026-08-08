use mail_arc::parse_sets;
use mail_dkim::{
    Canonicalization, body_canonicalization, canonicalize_header_relaxed, identity,
    signature_header_without_b, verify_headers, verify_signature_data,
};
use mail_dns::MailResolver;
use std::collections::HashMap;

use crate::authentication::dkim_key;

pub(super) async fn validate(
    headers: &[u8],
    simple_body_hash: &str,
    relaxed_body_hash: &str,
    resolver: &MailResolver,
) -> &'static str {
    let owned = arc_fields(headers);
    let borrowed = owned
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect::<Vec<_>>();
    let Ok(sets) = parse_sets(&borrowed) else {
        return "fail";
    };
    let Some(newest) = sets.last() else {
        return "none";
    };
    let mut keys = HashMap::new();
    let ams = header("ARC-Message-Signature", &newest.message_signature);
    let Some(ams_key) = public_key(resolver, &ams, &mut keys).await else {
        return "fail";
    };
    let body_hash = match body_canonicalization(&ams) {
        Ok(Canonicalization::Simple) => simple_body_hash,
        Ok(Canonicalization::Relaxed) => relaxed_body_hash,
        Err(_) => return "fail",
    };
    if !verify_headers(headers, &ams, &ams_key, body_hash).unwrap_or(false) {
        return "fail";
    }
    for current in sets.iter().rev() {
        let seal = header("ARC-Seal", &current.seal);
        let Some(key) = public_key(resolver, &seal, &mut keys).await else {
            return "fail";
        };
        let mut data = Vec::new();
        for set in sets.iter().take(current.instance as usize) {
            data.extend(canonicalize_header_relaxed(&header(
                "ARC-Authentication-Results",
                &set.authentication_results,
            )));
            data.extend(canonicalize_header_relaxed(&header(
                "ARC-Message-Signature",
                &set.message_signature,
            )));
            let set_seal = header("ARC-Seal", &set.seal);
            if set.instance == current.instance {
                let Ok(unsigned) = signature_header_without_b(&set_seal) else {
                    return "fail";
                };
                data.extend(canonicalize_header_relaxed(&unsigned));
            } else {
                data.extend(canonicalize_header_relaxed(&set_seal));
            }
        }
        if !verify_signature_data(&seal, &key, &data).unwrap_or(false) {
            return "fail";
        }
    }
    "pass"
}

async fn public_key(
    resolver: &MailResolver,
    signature: &[u8],
    cache: &mut HashMap<String, Option<Vec<u8>>>,
) -> Option<Vec<u8>> {
    let (domain, selector) = identity(signature).ok()?;
    let name = format!("{selector}._domainkey.{domain}");
    if let Some(key) = cache.get(&name) {
        return key.clone();
    }
    let key = resolver
        .txt(&name)
        .await
        .ok()?
        .iter()
        .find_map(|record| dkim_key(record));
    cache.insert(name, key.clone());
    key
}

fn header(name: &str, value: &str) -> Vec<u8> {
    format!("{name}: {value}\r\n").into_bytes()
}

fn arc_fields(headers: &[u8]) -> Vec<(String, String)> {
    logical_fields(headers)
        .filter_map(|field| {
            let colon = field.iter().position(|byte| *byte == b':')?;
            let name = std::str::from_utf8(&field[..colon]).ok()?;
            if ![
                "ARC-Seal",
                "ARC-Message-Signature",
                "ARC-Authentication-Results",
            ]
            .iter()
            .any(|candidate| name.eq_ignore_ascii_case(candidate))
            {
                return None;
            }
            let value = std::str::from_utf8(&field[colon + 1..]).ok()?.trim();
            Some((name.to_owned(), value.to_owned()))
        })
        .collect()
}

fn logical_fields(headers: &[u8]) -> impl Iterator<Item = &[u8]> {
    let mut ranges = Vec::new();
    let mut start = 0;
    for (index, byte) in headers.iter().copied().enumerate() {
        if byte == b'\n'
            && headers
                .get(index + 1)
                .is_none_or(|next| !matches!(next, b' ' | b'\t'))
        {
            ranges.push((start, index + 1));
            start = index + 1;
        }
    }
    if start < headers.len() {
        ranges.push((start, headers.len()));
    }
    ranges.into_iter().map(|(start, end)| &headers[start..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_only_complete_arc_fields() {
        let fields = arc_fields(
            b"From: a@example.test\r\nARC-Seal: i=1;\r\n b=x\r\nSubject: no\r\n folded\r\n",
        );
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].0, "ARC-Seal");
        assert!(fields[0].1.contains("b=x"));
    }

    #[tokio::test]
    async fn absent_and_malformed_chains_never_become_pass() {
        let resolver = MailResolver::system().unwrap_or_else(|error| panic!("resolver: {error}"));
        assert_eq!(
            validate(b"From: a@example.test\r\n", "x", "x", &resolver).await,
            "none"
        );
        assert_eq!(
            validate(
                b"ARC-Seal: i=1; cv=none\r\nARC-Seal: i=1; cv=none\r\n\r\n",
                "x",
                "x",
                &resolver
            )
            .await,
            "fail"
        );
    }
}
