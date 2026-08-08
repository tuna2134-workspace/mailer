#![forbid(unsafe_code)]

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
#[derive(Debug, Error)]
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
}

pub fn parse_sets(headers: &[(&str, &str)]) -> Result<Vec<ArcSet>, ArcError> {
    let mut sets = std::collections::BTreeMap::new();
    for (name, value) in headers {
        let upper = name.to_ascii_uppercase();
        let Some(instance) = tag(value, "i").and_then(|value| value.parse().ok()) else {
            return Err(ArcError::InvalidInstance);
        };
        let entry = sets
            .entry(instance)
            .or_insert_with(|| (String::new(), String::new(), String::new(), String::new()));
        match upper.as_str() {
            "ARC-SEAL" => (*value).clone_into(&mut entry.0),
            "ARC-MESSAGE-SIGNATURE" => (*value).clone_into(&mut entry.1),
            "ARC-AUTHENTICATION-RESULTS" => (*value).clone_into(&mut entry.2),
            _ => {}
        }
    }
    if sets.len() > 50 {
        return Err(ArcError::TooLong);
    }
    let mut output = Vec::new();
    for (expected, (seal, signature, auth, _)) in sets {
        if expected == 0 {
            return Err(ArcError::InvalidInstance);
        }
        if seal.is_empty() {
            return Err(ArcError::Missing(expected));
        }
        if signature.is_empty() {
            return Err(ArcError::Missing(expected));
        }
        if auth.is_empty() {
            return Err(ArcError::Missing(expected));
        }
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
}
