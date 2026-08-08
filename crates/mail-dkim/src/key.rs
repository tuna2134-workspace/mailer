use crate::{DkimError, signature::Algorithm, tag_list};
use base64::{Engine as _, engine::general_purpose::STANDARD};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyType {
    Rsa,
    Ed25519,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DkimKeyRecord {
    pub key_type: KeyType,
    pub public_key: Vec<u8>,
    pub testing: bool,
    pub strict_identity: bool,
}

impl DkimKeyRecord {
    pub fn parse(record: &str) -> Result<Self, DkimError> {
        let header = format!("DKIM-Key: {record}\r\n");
        let tags = tag_list::parse(header.as_bytes())?;
        if tags.contains_key("v") && tag_list::first_name(header.as_bytes())? != "v" {
            return Err(DkimError::Malformed);
        }
        if tags.get("v").is_some_and(|value| value != "DKIM1") {
            return Err(DkimError::Malformed);
        }
        let key_type = match tags.get("k").map_or("rsa", String::as_str) {
            "rsa" => KeyType::Rsa,
            "ed25519" => KeyType::Ed25519,
            _ => return Err(DkimError::Algorithm),
        };
        if tags.get("h").is_some_and(|hashes| {
            !hashes
                .split(':')
                .map(str::trim)
                .any(|hash| hash == "sha256")
        }) {
            return Err(DkimError::Algorithm);
        }
        if tags.get("s").is_some_and(|services| {
            !services
                .split(':')
                .map(str::trim)
                .any(|service| matches!(service, "*" | "email"))
        }) {
            return Err(DkimError::Algorithm);
        }
        let public_key = tags.get("p").ok_or(DkimError::Malformed)?;
        if public_key.is_empty() {
            return Err(DkimError::Revoked);
        }
        let public_key = STANDARD
            .decode(public_key.split_ascii_whitespace().collect::<String>())
            .map_err(|_| DkimError::Malformed)?;
        if key_type == KeyType::Ed25519 && public_key.len() != 32 {
            return Err(DkimError::Key(
                "Ed25519 public key must be 32 octets".into(),
            ));
        }
        let flags = tags
            .get("t")
            .map_or_else(Vec::new, |flags| flags.split(':').map(str::trim).collect());
        Ok(Self {
            key_type,
            public_key,
            testing: flags.contains(&"y"),
            strict_identity: flags.contains(&"s"),
        })
    }

    pub fn key_for(
        &self,
        algorithm: Algorithm,
        signing_domain: &str,
        identity: Option<&str>,
    ) -> Result<&[u8], DkimError> {
        let compatible = matches!(
            (algorithm, self.key_type),
            (Algorithm::RsaSha256, KeyType::Rsa) | (Algorithm::Ed25519Sha256, KeyType::Ed25519)
        );
        if !compatible {
            return Err(DkimError::Algorithm);
        }
        if self.strict_identity
            && identity
                .and_then(|value| value.rsplit_once('@'))
                .is_some_and(|(_, domain)| !domain.eq_ignore_ascii_case(signing_domain))
        {
            return Err(DkimError::Verify);
        }
        Ok(&self.public_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revoked_incompatible_and_wrong_service_keys_are_rejected() {
        assert!(matches!(
            DkimKeyRecord::parse("v=DKIM1; p="),
            Err(DkimError::Revoked)
        ));
        assert!(DkimKeyRecord::parse("v=DKIM1; s=other; p=YQ==").is_err());
        assert!(DkimKeyRecord::parse("p=YQ==; v=DKIM1").is_err());
        let ed = DkimKeyRecord::parse(&format!(
            "v=DKIM1; k=ed25519; p={}",
            STANDARD.encode([0_u8; 32])
        ))
        .unwrap_or_else(|_| panic!("key"));
        assert!(
            ed.key_for(Algorithm::RsaSha256, "example.test", None)
                .is_err()
        );
    }
}
