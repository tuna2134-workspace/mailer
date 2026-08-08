#![forbid(unsafe_code)]

mod key;
mod signature;
mod tag_list;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use ring::{digest, rand::SystemRandom, signature as ring_signature};
use thiserror::Error;

pub use key::{DkimKeyRecord, KeyType};
pub use signature::{Algorithm, DkimSignature};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Canonicalization {
    Simple,
    Relaxed,
}
#[derive(Clone, Debug)]
pub enum SigningKey {
    RsaPkcs8(Vec<u8>),
    Ed25519Pkcs8(Vec<u8>),
}
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum DkimError {
    #[error("malformed DKIM header")]
    Malformed,
    #[error("unsupported algorithm")]
    Algorithm,
    #[error("invalid key: {0}")]
    Key(String),
    #[error("signature verification failed")]
    Verify,
    #[error("signature has expired")]
    Expired,
    #[error("public key has been revoked")]
    Revoked,
}

#[allow(clippy::struct_excessive_bools)] // Each flag tracks independent streaming wire state.
pub struct BodyHasher {
    mode: Canonicalization,
    digest: digest::Context,
    line_has_content: bool,
    pending_space: bool,
    pending_empty_lines: usize,
    any_content: bool,
    pending_cr: bool,
}

impl BodyHasher {
    #[must_use]
    pub fn new(mode: Canonicalization) -> Self {
        Self {
            mode,
            digest: digest::Context::new(&digest::SHA256),
            line_has_content: false,
            pending_space: false,
            pending_empty_lines: 0,
            any_content: false,
            pending_cr: false,
        }
    }

    pub fn update(&mut self, input: &[u8]) {
        for byte in input.iter().copied() {
            if self.pending_cr {
                self.pending_cr = false;
                if byte == b'\n' {
                    self.end_line();
                    continue;
                }
                if self.mode == Canonicalization::Simple {
                    self.content(b'\r');
                }
            }
            match byte {
                b'\r' => self.pending_cr = true,
                b'\n' => self.end_line(),
                value => self.content(value),
            }
        }
    }

    #[must_use]
    pub fn finish(mut self) -> String {
        if self.pending_cr && self.mode == Canonicalization::Simple {
            self.content(b'\r');
        }
        if self.line_has_content {
            self.digest.update(b"\r\n");
            self.any_content = true;
        }
        if !self.any_content {
            self.digest.update(b"\r\n");
        }
        STANDARD.encode(self.digest.finish().as_ref())
    }

    fn content(&mut self, byte: u8) {
        if self.mode == Canonicalization::Relaxed && matches!(byte, b' ' | b'\t') {
            self.pending_space = true;
            return;
        }
        if !self.line_has_content {
            for _ in 0..self.pending_empty_lines {
                self.digest.update(b"\r\n");
            }
            self.pending_empty_lines = 0;
        }
        if self.pending_space && self.line_has_content {
            self.digest.update(b" ");
        }
        self.pending_space = false;
        self.digest.update(&[byte]);
        self.line_has_content = true;
    }

    fn end_line(&mut self) {
        self.pending_space = false;
        if self.line_has_content {
            self.digest.update(b"\r\n");
            self.any_content = true;
            self.line_has_content = false;
        } else {
            self.pending_empty_lines = self.pending_empty_lines.saturating_add(1);
        }
    }
}

pub fn canonicalize_body(body: &[u8], mode: Canonicalization) -> Vec<u8> {
    let mut lines = body
        .split(|byte| *byte == b'\n')
        .map(|line| line.strip_suffix(b"\r").unwrap_or(line).to_vec())
        .collect::<Vec<_>>();
    while lines.last().is_some_and(Vec::is_empty) {
        lines.pop();
    }
    let mut output = Vec::new();
    for line in lines {
        let line = if mode == Canonicalization::Relaxed {
            relax_whitespace(&line)
        } else {
            line
        };
        output.extend_from_slice(&line);
        output.extend_from_slice(b"\r\n");
    }
    if output.is_empty() {
        output.extend_from_slice(b"\r\n");
    }
    output
}

#[must_use]
pub fn body_hash(body: &[u8], mode: Canonicalization) -> String {
    STANDARD.encode(digest::digest(&digest::SHA256, &canonicalize_body(body, mode)).as_ref())
}

pub fn sign(
    message: &[u8],
    domain: &str,
    selector: &str,
    key: SigningKey,
    headers: &[&str],
    header_canon: Canonicalization,
    body_canon: Canonicalization,
) -> Result<Vec<u8>, DkimError> {
    let (_, body) = split_body(message);
    let bh = body_hash(body, body_canon);
    let names = headers.join(":");
    let algorithm = match key {
        SigningKey::RsaPkcs8(_) => "rsa-sha256",
        SigningKey::Ed25519Pkcs8(_) => "ed25519-sha256",
    };
    let unsigned = format!(
        "v=1; a={algorithm}; c={}/{}; d={domain}; s={selector}; h={names}; bh={bh}; b=",
        canon_name(header_canon),
        canon_name(body_canon)
    );
    let dkim_line = format!("DKIM-Signature: {unsigned}\r\n");
    let signing = signing_input(message, dkim_line.as_bytes(), headers, header_canon);
    let signature = sign_bytes(&signing, key)?;
    let prefix = unsigned.strip_suffix("b=").ok_or(DkimError::Malformed)?;
    Ok(format!(
        "DKIM-Signature: {prefix}b={}\r\n",
        STANDARD.encode(signature)
    )
    .into_bytes())
}

#[allow(clippy::too_many_arguments)] // Mirrors sign(), with the body replaced by its hash.
pub fn sign_headers(
    message_headers: &[u8],
    precomputed_body_hash: &str,
    domain: &str,
    selector: &str,
    key: SigningKey,
    headers: &[&str],
    header_canon: Canonicalization,
    body_canon: Canonicalization,
) -> Result<Vec<u8>, DkimError> {
    let names = headers.join(":");
    let algorithm = match key {
        SigningKey::RsaPkcs8(_) => "rsa-sha256",
        SigningKey::Ed25519Pkcs8(_) => "ed25519-sha256",
    };
    let unsigned = format!(
        "v=1; a={algorithm}; c={}/{}; d={domain}; s={selector}; h={names}; bh={precomputed_body_hash}; b=",
        canon_name(header_canon),
        canon_name(body_canon)
    );
    let dkim_line = format!("DKIM-Signature: {unsigned}\r\n");
    let signing = signing_input(message_headers, dkim_line.as_bytes(), headers, header_canon);
    let signature = sign_bytes(&signing, key)?;
    let prefix = unsigned.strip_suffix("b=").ok_or(DkimError::Malformed)?;
    Ok(format!(
        "DKIM-Signature: {prefix}b={}\r\n",
        STANDARD.encode(signature)
    )
    .into_bytes())
}

#[allow(clippy::too_many_arguments)]
pub fn sign_headers_named(
    header_name: &str,
    leading_tags: &str,
    message_headers: &[u8],
    precomputed_body_hash: &str,
    domain: &str,
    selector: &str,
    key: SigningKey,
    headers: &[&str],
) -> Result<Vec<u8>, DkimError> {
    if header_name.contains(['\r', '\n', ':']) || leading_tags.contains(['\r', '\n']) {
        return Err(DkimError::Malformed);
    }
    let algorithm = algorithm_name(&key);
    let unsigned = format!(
        "{leading_tags}a={algorithm}; c=relaxed/relaxed; d={domain}; s={selector}; h={}; bh={precomputed_body_hash}; b=",
        headers.join(":")
    );
    let line = format!("{header_name}: {unsigned}\r\n");
    let signing = signing_input(
        message_headers,
        line.as_bytes(),
        headers,
        Canonicalization::Relaxed,
    );
    let signature = sign_bytes(&signing, key)?;
    Ok(format!(
        "{header_name}: {unsigned}{}\r\n",
        STANDARD.encode(signature)
    )
    .into_bytes())
}

pub fn sign_signature_data(
    unsigned_header: &[u8],
    mut signing_data: Vec<u8>,
    key: SigningKey,
) -> Result<Vec<u8>, DkimError> {
    signing_data.extend(canonicalize_header_relaxed(unsigned_header));
    let signature = sign_bytes(&signing_data, key)?;
    let mut header = unsigned_header
        .strip_suffix(b"\r\n")
        .ok_or(DkimError::Malformed)?
        .to_vec();
    header.extend_from_slice(STANDARD.encode(signature).as_bytes());
    header.extend_from_slice(b"\r\n");
    Ok(header)
}

pub fn verify(message: &[u8], dkim_header: &[u8], public_key: &[u8]) -> Result<bool, DkimError> {
    verify_at(message, dkim_header, public_key, unix_now())
}

pub fn verify_at(
    message: &[u8],
    dkim_header: &[u8],
    public_key: &[u8],
    now: u64,
) -> Result<bool, DkimError> {
    let signature = DkimSignature::parse(dkim_header)?;
    signature.validate_time(now)?;
    let (_, body) = split_body(message);
    let canonicalized = canonicalize_body(body, signature.body_canonicalization);
    let signed_body = match signature.body_length {
        Some(length) if length <= canonicalized.len() => &canonicalized[..length],
        Some(_) => return Err(DkimError::Malformed),
        None => canonicalized.as_slice(),
    };
    if digest::digest(&digest::SHA256, signed_body).as_ref() != signature.body_hash {
        return Ok(false);
    }
    let unsigned = remove_tag_value(dkim_header, "b")?;
    let names = signature
        .signed_headers
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let signing = signing_input(
        message,
        &unsigned,
        &names,
        signature.header_canonicalization,
    );
    let valid = match signature.algorithm {
        Algorithm::RsaSha256 => ring_signature::UnparsedPublicKey::new(
            &ring_signature::RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY,
            public_key,
        )
        .verify(&signing, &signature.signature)
        .is_ok(),
        Algorithm::Ed25519Sha256 => {
            ring_signature::UnparsedPublicKey::new(&ring_signature::ED25519, public_key)
                .verify(&signing, &signature.signature)
                .is_ok()
        }
    };
    Ok(valid)
}

pub fn verify_headers(
    message_headers: &[u8],
    dkim_header: &[u8],
    public_key: &[u8],
    precomputed_body_hash: &str,
) -> Result<bool, DkimError> {
    verify_headers_at(
        message_headers,
        dkim_header,
        public_key,
        precomputed_body_hash,
        unix_now(),
    )
}

pub fn verify_headers_at(
    message_headers: &[u8],
    dkim_header: &[u8],
    public_key: &[u8],
    precomputed_body_hash: &str,
    now: u64,
) -> Result<bool, DkimError> {
    let signature = DkimSignature::parse(dkim_header)?;
    signature.validate_time(now)?;
    if signature.body_length.is_some() {
        return Err(DkimError::Algorithm);
    }
    let body_hash = STANDARD
        .decode(compact(precomputed_body_hash))
        .map_err(|_| DkimError::Malformed)?;
    if signature.body_hash != body_hash {
        return Ok(false);
    }
    let names = signature
        .signed_headers
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let unsigned = remove_tag_value(dkim_header, "b")?;
    let signing = signing_input(
        message_headers,
        &unsigned,
        &names,
        signature.header_canonicalization,
    );
    match signature.algorithm {
        Algorithm::RsaSha256 => Ok(ring_signature::UnparsedPublicKey::new(
            &ring_signature::RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY,
            public_key,
        )
        .verify(&signing, &signature.signature)
        .is_ok()),
        Algorithm::Ed25519Sha256 => Ok(ring_signature::UnparsedPublicKey::new(
            &ring_signature::ED25519,
            public_key,
        )
        .verify(&signing, &signature.signature)
        .is_ok()),
    }
}

pub fn identity(dkim_header: &[u8]) -> Result<(String, String), DkimError> {
    let tags = tag_list::parse(dkim_header)?;
    Ok((required_tag(&tags, "d")?, required_tag(&tags, "s")?))
}

pub fn signature_algorithm(signature_header: &[u8]) -> Result<Algorithm, DkimError> {
    let tags = tag_list::parse(signature_header)?;
    match tags.get("a").map(String::as_str) {
        Some("rsa-sha256") => Ok(Algorithm::RsaSha256),
        Some("ed25519-sha256") => Ok(Algorithm::Ed25519Sha256),
        _ => Err(DkimError::Algorithm),
    }
}

pub fn body_canonicalization(dkim_header: &[u8]) -> Result<Canonicalization, DkimError> {
    let tags = tag_list::parse(dkim_header)?;
    let value = tags.get("c").map_or("simple/simple", String::as_str);
    let body = value.split_once('/').map_or("simple", |(_, body)| body);
    match body {
        "simple" => Ok(Canonicalization::Simple),
        "relaxed" => Ok(Canonicalization::Relaxed),
        _ => Err(DkimError::Algorithm),
    }
}

pub fn signature_header_without_b(header: &[u8]) -> Result<Vec<u8>, DkimError> {
    remove_tag_value(header, "b")
}

#[must_use]
pub fn canonicalize_header_relaxed(header: &[u8]) -> Vec<u8> {
    canonicalize_header(header, Canonicalization::Relaxed)
}

pub fn verify_signature_data(
    signature_header: &[u8],
    public_key: &[u8],
    signing_data: &[u8],
) -> Result<bool, DkimError> {
    let tags = tag_list::parse(signature_header)?;
    let signature = STANDARD
        .decode(compact(tags.get("b").ok_or(DkimError::Malformed)?))
        .map_err(|_| DkimError::Malformed)?;
    match tags.get("a").map(String::as_str) {
        Some("rsa-sha256") => Ok(ring_signature::UnparsedPublicKey::new(
            &ring_signature::RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY,
            public_key,
        )
        .verify(signing_data, &signature)
        .is_ok()),
        Some("ed25519-sha256") => Ok(ring_signature::UnparsedPublicKey::new(
            &ring_signature::ED25519,
            public_key,
        )
        .verify(signing_data, &signature)
        .is_ok()),
        _ => Err(DkimError::Algorithm),
    }
}

fn required_tag(
    tags: &std::collections::HashMap<String, String>,
    name: &str,
) -> Result<String, DkimError> {
    tags.get(name)
        .filter(|value| !value.is_empty())
        .cloned()
        .ok_or(DkimError::Malformed)
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

fn sign_bytes(data: &[u8], key: SigningKey) -> Result<Vec<u8>, DkimError> {
    match key {
        SigningKey::RsaPkcs8(der) => {
            let pair = ring_signature::RsaKeyPair::from_der(&der)
                .map_err(|error| DkimError::Key(error.to_string()))?;
            let mut out = vec![0; pair.public().modulus_len()];
            pair.sign(
                &ring_signature::RSA_PKCS1_SHA256,
                &SystemRandom::new(),
                data,
                &mut out,
            )
            .map_err(|error| DkimError::Key(error.to_string()))?;
            Ok(out)
        }
        SigningKey::Ed25519Pkcs8(der) => ring_signature::Ed25519KeyPair::from_pkcs8(&der)
            .map(|pair| pair.sign(data).as_ref().to_vec())
            .map_err(|error| DkimError::Key(error.to_string())),
    }
}

fn algorithm_name(key: &SigningKey) -> &'static str {
    match key {
        SigningKey::RsaPkcs8(_) => "rsa-sha256",
        SigningKey::Ed25519Pkcs8(_) => "ed25519-sha256",
    }
}
fn split_body(message: &[u8]) -> (&[u8], &[u8]) {
    message
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map_or((message, &[]), |at| {
            (&message[..at + 2], &message[at + 4..])
        })
}
fn signing_input(
    message: &[u8],
    signature_header: &[u8],
    names: &[&str],
    mode: Canonicalization,
) -> Vec<u8> {
    let (headers, _) = split_body(message);
    let mut signing = Vec::new();
    let mut selected = std::collections::HashMap::<String, usize>::new();
    for name in names {
        let used = selected.entry(name.to_ascii_lowercase()).or_default();
        if let Some(line) = find_header_from_bottom(headers, name, *used) {
            signing.extend_from_slice(&canonicalize_header(line, mode));
            *used = used.saturating_add(1);
        }
    }
    signing.extend_from_slice(&canonicalize_header(signature_header, mode));
    signing
}
fn header_fields(headers: &[u8]) -> Vec<&[u8]> {
    let mut fields = Vec::new();
    let mut start = 0;
    let mut field_start = 0;
    while start < headers.len() {
        let end = headers[start..]
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(headers.len(), |offset| start + offset + 1);
        if !matches!(headers.get(start), Some(b' ' | b'\t')) {
            if start > field_start {
                fields.push(&headers[field_start..start]);
            }
            field_start = start;
        }
        start = end;
    }
    if field_start < headers.len() {
        fields.push(&headers[field_start..]);
    }
    fields
}

fn find_header_from_bottom<'a>(headers: &'a [u8], name: &str, skip: usize) -> Option<&'a [u8]> {
    header_fields(headers)
        .into_iter()
        .rev()
        .filter(|field| header_name_matches(field, name))
        .nth(skip)
}

fn header_name_matches(field: &[u8], name: &str) -> bool {
    field
        .get(..name.len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(name.as_bytes()))
        && field.get(name.len()) == Some(&b':')
}
fn canonicalize_header(line: &[u8], mode: Canonicalization) -> Vec<u8> {
    if mode == Canonicalization::Simple {
        return line.to_vec();
    }
    let Some(colon) = line.iter().position(|byte| *byte == b':') else {
        return line.to_vec();
    };
    let mut out = line[..colon]
        .iter()
        .map(u8::to_ascii_lowercase)
        .collect::<Vec<_>>();
    out.push(b':');
    out.extend_from_slice(&relax_whitespace(&line[colon + 1..]));
    if !out.ends_with(b"\r\n") {
        out.extend_from_slice(b"\r\n");
    }
    out
}
fn relax_whitespace(value: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut pending = false;
    for byte in value
        .iter()
        .copied()
        .filter(|byte| *byte != b'\r' && *byte != b'\n')
    {
        if byte == b' ' || byte == b'\t' {
            pending = true;
        } else {
            if pending && !out.is_empty() {
                out.push(b' ');
            }
            pending = false;
            out.push(byte);
        }
    }
    out
}
fn canon_name(mode: Canonicalization) -> &'static str {
    if mode == Canonicalization::Relaxed {
        "relaxed"
    } else {
        "simple"
    }
}
fn compact(value: &str) -> String {
    value.split_ascii_whitespace().collect()
}
fn remove_tag_value(header: &[u8], target: &str) -> Result<Vec<u8>, DkimError> {
    let colon = header
        .iter()
        .position(|byte| *byte == b':')
        .ok_or(DkimError::Malformed)?;
    let mut output = Vec::with_capacity(header.len());
    let mut copied = 0;
    let mut start = colon + 1;
    let mut found = false;
    while start < header.len() {
        let end = header[start..]
            .iter()
            .position(|byte| *byte == b';')
            .map_or(header.len(), |offset| start + offset);
        let segment = &header[start..end];
        if let Some(equals) = segment.iter().position(|byte| *byte == b'=') {
            let name = trim_fws(&segment[..equals]);
            if name.eq_ignore_ascii_case(target.as_bytes()) {
                if found {
                    return Err(DkimError::Malformed);
                }
                found = true;
                let value_start = start + equals + 1;
                output.extend_from_slice(&header[copied..value_start]);
                output.extend(
                    header[value_start..end]
                        .iter()
                        .copied()
                        .filter(|byte| matches!(byte, b' ' | b'\t' | b'\r' | b'\n')),
                );
                copied = end;
            }
        }
        start = end.saturating_add(1);
    }
    if !found {
        return Err(DkimError::Malformed);
    }
    output.extend_from_slice(&header[copied..]);
    Ok(output)
}

fn trim_fws(mut value: &[u8]) -> &[u8] {
    while value
        .first()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
    {
        value = &value[1..];
    }
    while value
        .last()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
    {
        value = &value[..value.len() - 1];
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::KeyPair;
    #[test]
    fn relaxed_body_and_hash_are_bounded() {
        assert_eq!(
            canonicalize_body(b"a  \r\n\r\n", Canonicalization::Relaxed),
            b"a\r\n"
        );
        assert!(!body_hash(b"a", Canonicalization::Simple).is_empty());
    }

    #[test]
    fn streaming_body_hash_matches_whole_body_at_every_boundary() {
        for mode in [Canonicalization::Simple, Canonicalization::Relaxed] {
            for body in [
                b"".as_slice(),
                b"a",
                b"a\r\n",
                b"a  \r\n\r\n",
                b"a\nb\r\nc\rd",
                b" \t\r\nbody\t \r\n\r\n",
            ] {
                let expected = body_hash(body, mode);
                for split in 0..=body.len() {
                    let mut hasher = BodyHasher::new(mode);
                    hasher.update(&body[..split]);
                    hasher.update(&body[split..]);
                    assert_eq!(
                        hasher.finish(),
                        expected,
                        "mode {mode:?}, split {split} for {body:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn signed_header_lookup_includes_continuation_lines() {
        let headers = b"From: a@example.test\r\nSubject: first\r\n second\r\nDate: now\r\n";
        assert_eq!(
            find_header_from_bottom(headers, "Subject", 0),
            Some(b"Subject: first\r\n second\r\n".as_slice())
        );
    }

    #[test]
    fn repeated_headers_are_selected_once_each_from_the_bottom() {
        let headers = b"From: a@example.test\r\nX-Test: first\r\nX-Test: second\r\n";
        let input = signing_input(
            headers,
            b"DKIM-Signature: v=1; b=\r\n",
            &["X-Test", "X-Test"],
            Canonicalization::Simple,
        );
        assert!(input.starts_with(b"X-Test: second\r\nX-Test: first\r\n"));
    }

    #[test]
    fn removing_b_value_preserves_simple_canonicalization_octets() {
        let header = b"DKIM-Signature: v=1; b=YWJj\r\n \tZGVm; x=1\r\n";
        assert_eq!(
            remove_tag_value(header, "b"),
            Ok(b"DKIM-Signature: v=1; b=\r\n \t; x=1\r\n".to_vec())
        );
    }

    #[test]
    fn ed25519_signature_round_trip() {
        let key = ring_signature::Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
            .unwrap_or_else(|_| panic!("key"));
        let pair = ring_signature::Ed25519KeyPair::from_pkcs8(key.as_ref())
            .unwrap_or_else(|_| panic!("key"));
        let message = b"From: a@example.test\r\nSubject: test\r\n\r\nbody\r\n";
        let header = sign(
            message,
            "example.test",
            "s1",
            SigningKey::Ed25519Pkcs8(key.as_ref().to_vec()),
            &["From", "Subject"],
            Canonicalization::Relaxed,
            Canonicalization::Relaxed,
        )
        .unwrap_or_else(|_| panic!("signature"));
        let mut signed = header.clone();
        signed.extend_from_slice(message);
        let unsigned = remove_tag_value(&header, "b").unwrap_or_default();
        assert_eq!(
            signing_input(
                message,
                &unsigned,
                &["From", "Subject"],
                Canonicalization::Relaxed
            ),
            signing_input(
                &signed,
                &unsigned,
                &["From", "Subject"],
                Canonicalization::Relaxed
            )
        );
        let input = signing_input(
            message,
            &unsigned,
            &["From", "Subject"],
            Canonicalization::Relaxed,
        );
        let direct =
            sign_bytes(&input, SigningKey::Ed25519Pkcs8(key.as_ref().to_vec())).unwrap_or_default();
        assert!(
            ring_signature::UnparsedPublicKey::new(&ring_signature::ED25519, pair.public_key())
                .verify(&input, &direct)
                .is_ok()
        );
        let expected_unsigned = format!(
            "DKIM-Signature: v=1; a=ed25519-sha256; c=relaxed/relaxed; d=example.test; s=s1; h=From:Subject; bh={}; b=\r\n",
            body_hash(b"body\r\n", Canonicalization::Relaxed)
        );
        assert_eq!(
            signing_input(
                message,
                expected_unsigned.as_bytes(),
                &["From", "Subject"],
                Canonicalization::Relaxed
            ),
            input
        );
        let result = verify(
            &signed[0..header.len() + message.len()],
            &header,
            pair.public_key().as_ref(),
        );
        assert!(result.unwrap_or(false));
    }
}
