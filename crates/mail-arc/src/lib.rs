#![forbid(unsafe_code)]

use mail_dkim::{SigningKey, canonicalize_header_relaxed, sign_headers_named, sign_signature_data};
use thiserror::Error;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArcSet {
    pub instance: u32,
    pub seal: String,
    pub message_signature: String,
    pub authentication_results: String,
    pub chain_validation: String,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChainStatus {
    None,
    Pass,
    Fail,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArcValidation {
    pub status: ChainStatus,
    pub instances: u32,
}
pub trait ArcSignatureVerifier {
    fn verify(&self, set: &ArcSet) -> bool;
}
#[derive(Debug, Error, Eq, PartialEq)]
pub enum ArcError {
    #[error("missing ARC set {0}")]
    Missing(u32),
    #[error("duplicate ARC instance {0}")]
    Duplicate(u32),
    #[error("invalid ARC instance")]
    InvalidInstance,
    #[error("invalid ARC chain validation")]
    InvalidChain,
    #[error("ARC chain exceeds 50 sets")]
    TooLong,
    #[error("ARC signing failed")]
    Signing,
}

#[derive(Clone, Debug)]
pub struct ArcSealConfig {
    pub domain: String,
    pub selector: String,
    pub key: SigningKey,
}

pub fn seal(
    message_headers: &[u8],
    relaxed_body_hash: &str,
    authentication_results: &str,
    existing_headers: &[(&str, &str)],
    chain_status: ChainStatus,
    config: &ArcSealConfig,
) -> Result<Vec<u8>, ArcError> {
    if authentication_results.contains(['\r', '\n']) {
        return Err(ArcError::Signing);
    }
    let sets = parse_sets(existing_headers)?;
    let instance = u32::try_from(sets.len()).map_err(|_| ArcError::TooLong)? + 1;
    if instance > 50 {
        return Err(ArcError::TooLong);
    }
    let aar = format!("ARC-Authentication-Results: i={instance}; {authentication_results}\r\n")
        .into_bytes();
    let ams = sign_headers_named(
        "ARC-Message-Signature",
        &format!("i={instance}; "),
        message_headers,
        relaxed_body_hash,
        &config.domain,
        &config.selector,
        config.key.clone(),
        &["From", "To", "Cc", "Subject", "Date", "Message-ID"],
    )
    .map_err(|_| ArcError::Signing)?;
    let cv = match chain_status {
        ChainStatus::None => "none",
        ChainStatus::Pass => "pass",
        ChainStatus::Fail => "fail",
    };
    let algorithm = match &config.key {
        SigningKey::RsaPkcs8(_) => "rsa-sha256",
        SigningKey::Ed25519Pkcs8(_) => "ed25519-sha256",
    };
    let unsigned_seal = format!(
        "ARC-Seal: i={instance}; a={algorithm}; cv={cv}; d={}; s={}; b=\r\n",
        config.domain, config.selector
    )
    .into_bytes();
    let mut data = Vec::new();
    if chain_status != ChainStatus::Fail {
        for set in &sets {
            append_set(&mut data, set, false)?;
        }
    }
    data.extend(canonicalize_header_relaxed(&aar));
    data.extend(canonicalize_header_relaxed(&ams));
    let seal = sign_signature_data(&unsigned_seal, data, config.key.clone())
        .map_err(|_| ArcError::Signing)?;
    Ok([seal, ams, aar].concat())
}

fn append_set(output: &mut Vec<u8>, set: &ArcSet, unsigned_seal: bool) -> Result<(), ArcError> {
    for (name, value) in [
        ("ARC-Authentication-Results", &set.authentication_results),
        ("ARC-Message-Signature", &set.message_signature),
        ("ARC-Seal", &set.seal),
    ] {
        let header = format!("{name}: {value}\r\n").into_bytes();
        let header = if unsigned_seal && name == "ARC-Seal" {
            mail_dkim::signature_header_without_b(&header).map_err(|_| ArcError::Signing)?
        } else {
            header
        };
        output.extend(canonicalize_header_relaxed(&header));
    }
    Ok(())
}

pub fn parse_sets(headers: &[(&str, &str)]) -> Result<Vec<ArcSet>, ArcError> {
    let mut sets =
        std::collections::BTreeMap::<u32, (Option<String>, Option<String>, Option<String>)>::new();
    for (name, value) in headers {
        let upper = name.to_ascii_uppercase();
        if !matches!(
            upper.as_str(),
            "ARC-SEAL" | "ARC-MESSAGE-SIGNATURE" | "ARC-AUTHENTICATION-RESULTS"
        ) {
            continue;
        }
        let Some(instance) = tag(value, "i").and_then(|value| value.parse().ok()) else {
            return Err(ArcError::InvalidInstance);
        };
        let entry = sets.entry(instance).or_insert_with(|| (None, None, None));
        let slot = match upper.as_str() {
            "ARC-SEAL" => &mut entry.0,
            "ARC-MESSAGE-SIGNATURE" => &mut entry.1,
            "ARC-AUTHENTICATION-RESULTS" => &mut entry.2,
            _ => unreachable!(),
        };
        if slot.replace((*value).to_owned()).is_some() {
            return Err(ArcError::Duplicate(instance));
        }
    }
    if sets.len() > 50 {
        return Err(ArcError::TooLong);
    }
    let mut output = Vec::new();
    for (expected, (seal, signature, auth)) in sets {
        if expected == 0 {
            return Err(ArcError::InvalidInstance);
        }
        let seal = seal.ok_or(ArcError::Missing(expected))?;
        let signature = signature.ok_or(ArcError::Missing(expected))?;
        let auth = auth.ok_or(ArcError::Missing(expected))?;
        let cv = tag(&seal, "cv").unwrap_or_default();
        if expected == 1 && !cv.eq_ignore_ascii_case("none") {
            return Err(ArcError::InvalidChain);
        }
        if expected > 1 && !cv.eq_ignore_ascii_case("pass") {
            return Err(ArcError::InvalidChain);
        }
        output.push(ArcSet {
            instance: expected,
            seal,
            message_signature: signature,
            authentication_results: auth,
            chain_validation: cv,
        });
    }
    for expected in 1..=u32::try_from(output.len()).map_err(|_| ArcError::TooLong)? {
        if output.iter().all(|set| set.instance != expected) {
            return Err(ArcError::Missing(expected));
        }
    }
    Ok(output)
}

pub fn validate(headers: &[(&str, &str)]) -> Result<ArcValidation, ArcError> {
    let sets = parse_sets(headers)?;
    Ok(ArcValidation {
        status: if sets.is_empty() {
            ChainStatus::None
        } else {
            ChainStatus::Pass
        },
        instances: u32::try_from(sets.len()).map_err(|_| ArcError::TooLong)?,
    })
}

pub fn validate_with<V: ArcSignatureVerifier>(
    headers: &[(&str, &str)],
    verifier: &V,
) -> Result<ArcValidation, ArcError> {
    let validation = validate(headers)?;
    let sets = parse_sets(headers)?;
    if sets.iter().any(|set| !verifier.verify(set)) {
        return Err(ArcError::InvalidChain);
    }
    Ok(validation)
}
fn tag(value: &str, target: &str) -> Option<String> {
    value.split(';').map(str::trim).find_map(|part| {
        part.split_once('=')
            .filter(|(name, _)| name.trim().eq_ignore_ascii_case(target))
            .map(|(_, value)| value.trim().to_owned())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    struct Valid;
    impl ArcSignatureVerifier for Valid {
        fn verify(&self, _: &ArcSet) -> bool {
            true
        }
    }
    #[test]
    fn validates_contiguous_chain() {
        let headers = [
            ("ARC-Seal", "i=1; cv=none"),
            ("ARC-Message-Signature", "i=1; a=rsa-sha256"),
            ("ARC-Authentication-Results", "i=1; mx=example"),
        ];
        assert_eq!(
            validate(&headers).unwrap_or_else(|_| panic!("arc")).status,
            ChainStatus::Pass
        );
        assert_eq!(
            validate_with(&headers, &Valid)
                .unwrap_or_else(|_| panic!("arc"))
                .instances,
            1
        );
    }

    #[test]
    fn rejects_duplicate_fields_and_ignores_unrelated_headers() {
        let duplicate = [
            ("ARC-Seal", "i=1; cv=none"),
            ("ARC-Seal", "i=1; cv=none"),
            ("ARC-Message-Signature", "i=1"),
            ("ARC-Authentication-Results", "i=1"),
        ];
        assert_eq!(parse_sets(&duplicate), Err(ArcError::Duplicate(1)));
        assert_eq!(
            validate(&[("From", "alice@example.test")]),
            Ok(ArcValidation {
                status: ChainStatus::None,
                instances: 0
            })
        );
    }

    #[test]
    fn generates_a_complete_first_arc_set() {
        let key = ring::signature::Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
            .unwrap_or_else(|_| panic!("key"));
        let output = seal(
            b"From: a@example.test\r\nSubject: test\r\n",
            "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=",
            "mx.example; spf=pass",
            &[],
            ChainStatus::None,
            &ArcSealConfig {
                domain: "example.test".into(),
                selector: "s1".into(),
                key: SigningKey::Ed25519Pkcs8(key.as_ref().to_vec()),
            },
        )
        .unwrap_or_else(|_| panic!("seal"));
        let text = String::from_utf8(output).unwrap_or_else(|_| panic!("utf8"));
        let fields = text
            .lines()
            .filter_map(|line| line.split_once(':'))
            .collect::<Vec<_>>();
        let sets = parse_sets(&fields).unwrap_or_else(|_| panic!("set"));
        assert_eq!(sets.len(), 1);
        assert_eq!(sets[0].chain_validation, "none");
    }
}
