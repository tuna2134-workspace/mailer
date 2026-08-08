use crate::{Canonicalization, DkimError, tag_list};
use base64::{Engine as _, engine::general_purpose::STANDARD};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Algorithm {
    RsaSha256,
    Ed25519Sha256,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DkimSignature {
    pub algorithm: Algorithm,
    pub header_canonicalization: Canonicalization,
    pub body_canonicalization: Canonicalization,
    pub domain: String,
    pub selector: String,
    pub identity: Option<String>,
    pub signed_headers: Vec<String>,
    pub body_hash: Vec<u8>,
    pub signature: Vec<u8>,
    pub body_length: Option<usize>,
    pub timestamp: Option<u64>,
    pub expiration: Option<u64>,
}

impl DkimSignature {
    pub fn parse(header: &[u8]) -> Result<Self, DkimError> {
        let tags = tag_list::parse(header)?;
        let is_arc = header
            .get(.."ARC-Message-Signature".len())
            .is_some_and(|name| name.eq_ignore_ascii_case(b"ARC-Message-Signature"));
        let first = tag_list::first_name(header)?;
        if (!is_arc && first != "v") || is_arc && first != "i" {
            return Err(DkimError::Malformed);
        }
        if (!is_arc && tags.get("v").map(String::as_str) != Some("1"))
            || tags.get("v").is_some_and(|version| version != "1")
        {
            return Err(DkimError::Malformed);
        }
        let algorithm = match tags.get("a").map(String::as_str) {
            Some("rsa-sha256") => Algorithm::RsaSha256,
            Some("ed25519-sha256") => Algorithm::Ed25519Sha256,
            Some(_) => return Err(DkimError::Algorithm),
            None => return Err(DkimError::Malformed),
        };
        let (header_canonicalization, body_canonicalization) =
            parse_canonicalization(tags.get("c").map(String::as_str))?;
        let domain = required(&tags, "d")?.to_ascii_lowercase();
        let selector = required(&tags, "s")?.to_owned();
        if !valid_domain(&domain) || !valid_selector(&selector) {
            return Err(DkimError::Malformed);
        }
        let identity = if is_arc {
            None
        } else {
            tags.get("i").map(std::borrow::ToOwned::to_owned)
        };
        if identity
            .as_deref()
            .is_some_and(|value| !valid_identity(value, &domain))
        {
            return Err(DkimError::Malformed);
        }
        let signed_headers = required(&tags, "h")?
            .split(':')
            .map(str::trim)
            .map(str::to_owned)
            .collect::<Vec<_>>();
        if signed_headers.is_empty()
            || signed_headers.iter().any(|name| !valid_header_name(name))
            || !signed_headers
                .iter()
                .any(|name| name.eq_ignore_ascii_case("from"))
        {
            return Err(DkimError::Malformed);
        }
        if let Some(query) = tags.get("q")
            && !query
                .split(':')
                .map(str::trim)
                .any(|method| method.eq_ignore_ascii_case("dns/txt"))
        {
            return Err(DkimError::Algorithm);
        }
        let timestamp = parse_decimal(tags.get("t"))?;
        let expiration = parse_decimal(tags.get("x"))?;
        if expiration.is_some_and(|expiration| timestamp.is_some_and(|time| expiration <= time)) {
            return Err(DkimError::Malformed);
        }
        let body_length = parse_length(tags.get("l"))?;
        let body_hash = decode(required(&tags, "bh")?)?;
        let signature = decode(required(&tags, "b")?)?;
        Ok(Self {
            algorithm,
            header_canonicalization,
            body_canonicalization,
            domain,
            selector,
            identity,
            signed_headers,
            body_hash,
            signature,
            body_length,
            timestamp,
            expiration,
        })
    }

    pub fn validate_time(&self, now: u64) -> Result<(), DkimError> {
        if self.expiration.is_some_and(|expiration| now > expiration) {
            return Err(DkimError::Expired);
        }
        Ok(())
    }
}

fn required<'a>(
    tags: &'a std::collections::HashMap<String, String>,
    name: &str,
) -> Result<&'a str, DkimError> {
    tags.get(name)
        .filter(|value| !value.is_empty())
        .map(String::as_str)
        .ok_or(DkimError::Malformed)
}

fn parse_canonicalization(
    value: Option<&str>,
) -> Result<(Canonicalization, Canonicalization), DkimError> {
    let Some(value) = value else {
        return Ok((Canonicalization::Simple, Canonicalization::Simple));
    };
    let mut values = value.split('/');
    let header = parse_canonicalization_name(values.next().ok_or(DkimError::Malformed)?)?;
    let body = values
        .next()
        .map_or(Ok(Canonicalization::Simple), parse_canonicalization_name)?;
    if values.next().is_some() {
        return Err(DkimError::Malformed);
    }
    Ok((header, body))
}

fn parse_canonicalization_name(value: &str) -> Result<Canonicalization, DkimError> {
    match value.trim() {
        "simple" => Ok(Canonicalization::Simple),
        "relaxed" => Ok(Canonicalization::Relaxed),
        _ => Err(DkimError::Algorithm),
    }
}

fn parse_decimal(value: Option<&String>) -> Result<Option<u64>, DkimError> {
    value
        .map(|value| {
            (!value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
                .then(|| value.parse::<u64>())
                .ok_or(DkimError::Malformed)?
                .map_err(|_| DkimError::Malformed)
        })
        .transpose()
}

fn parse_length(value: Option<&String>) -> Result<Option<usize>, DkimError> {
    let Some(value) = value else {
        return Ok(None);
    };
    if value.is_empty() || value.len() > 76 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(DkimError::Malformed);
    }
    value
        .parse::<usize>()
        .map(Some)
        .map_err(|_| DkimError::Malformed)
}

fn decode(value: &str) -> Result<Vec<u8>, DkimError> {
    STANDARD
        .decode(value.split_ascii_whitespace().collect::<String>())
        .map_err(|_| DkimError::Malformed)
}

fn valid_identity(value: &str, domain: &str) -> bool {
    let Some((_, identity_domain)) = value.rsplit_once('@') else {
        return false;
    };
    identity_domain.eq_ignore_ascii_case(domain)
        || identity_domain.len() > domain.len()
            && identity_domain
                .get(identity_domain.len() - domain.len() - 1..)
                .is_some_and(|suffix| {
                    suffix.starts_with('.') && suffix[1..].eq_ignore_ascii_case(domain)
                })
}

fn valid_domain(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
}

fn valid_selector(value: &str) -> bool {
    valid_domain(value)
}

fn valid_header_name(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b':')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signature(extra: &str) -> Vec<u8> {
        format!(
            "DKIM-Signature: v=1; a=ed25519-sha256; d=example.test; s=s1; h=from:subject; bh=YQ==; b=Yg==; {extra}\r\n"
        )
        .into_bytes()
    }

    #[test]
    fn validates_required_tags_identity_canonicalization_and_time() {
        assert!(DkimSignature::parse(&signature("i=user@sub.example.test; t=10; x=20")).is_ok());
        for extra in [
            "v=1",
            "i=user@other.test",
            "c=unknown/simple",
            "q=http/who-knows",
            "t=20; x=20",
        ] {
            assert!(DkimSignature::parse(&signature(extra)).is_err(), "{extra}");
        }
        let parsed = DkimSignature::parse(&signature("x=20")).unwrap_or_else(|_| panic!("sig"));
        assert_eq!(parsed.validate_time(21), Err(DkimError::Expired));
    }

    #[test]
    fn from_must_be_signed_and_body_length_is_bounded() {
        let without_from = b"DKIM-Signature: v=1; a=rsa-sha256; d=example.test; s=s1; h=subject; bh=YQ==; b=Yg==\r\n";
        assert!(DkimSignature::parse(without_from).is_err());
        assert!(DkimSignature::parse(b"DKIM-Signature: a=rsa-sha256; v=1; d=example.test; s=s1; h=from; bh=YQ==; b=YQ==\r\n").is_err());
        assert!(DkimSignature::parse(&signature("l=184467440737095516160")).is_err());
    }
}
