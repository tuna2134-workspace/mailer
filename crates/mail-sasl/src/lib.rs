#![forbid(unsafe_code)]

mod throttle;
pub use throttle::{
    AuthAttemptLimiter, LocalAuthAttemptLimiter, SourceAggregation, ThrottleDecision,
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use ring::{digest, hmac, pbkdf2};
use std::num::NonZeroU32;
use subtle::ConstantTimeEq;
use thiserror::Error;

const KEY_LEN: usize = 32;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScramCredential {
    pub salt: Vec<u8>,
    pub iterations: NonZeroU32,
    pub stored_key: [u8; KEY_LEN],
    pub server_key: [u8; KEY_LEN],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScramMechanism {
    Sha256,
    Sha256Plus,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum ScramError {
    #[error("malformed SCRAM message")]
    Malformed,
    #[error("SCRAM nonce mismatch")]
    Nonce,
    #[error("SCRAM channel binding mismatch")]
    ChannelBinding,
    #[error("SCRAM proof is invalid")]
    InvalidProof,
}

#[must_use]
pub fn derive_credential(password: &[u8], salt: &[u8], iterations: NonZeroU32) -> ScramCredential {
    let mut salted = [0_u8; KEY_LEN];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        iterations,
        salt,
        password,
        &mut salted,
    );
    let client_key = hmac_sha256(&salted, b"Client Key");
    let stored_key = sha256(&client_key);
    let server_key = hmac_sha256(&salted, b"Server Key");
    salted.fill(0);
    ScramCredential {
        salt: salt.to_vec(),
        iterations,
        stored_key,
        server_key,
    }
}

#[derive(Clone, Debug)]
pub struct ScramExchange {
    client_first_bare: String,
    server_first: String,
    combined_nonce: String,
    expected_channel_binding: Vec<u8>,
    credential: ScramCredential,
}

impl ScramExchange {
    pub fn start(
        mechanism: ScramMechanism,
        client_first: &str,
        credential: ScramCredential,
        server_nonce: &str,
        tls_exporter: Option<&[u8]>,
    ) -> Result<(String, String, Self), ScramError> {
        let header = gs2_header(mechanism);
        let client_first_bare = client_first
            .strip_prefix(header)
            .ok_or(ScramError::ChannelBinding)?;
        let attributes = attributes(client_first_bare)?;
        let identity = sasl_name(required(&attributes, 'n')?)?;
        let client_nonce = required(&attributes, 'r')?;
        if client_nonce.len() < 8 || server_nonce.is_empty() {
            return Err(ScramError::Nonce);
        }
        let combined_nonce = format!("{client_nonce}{server_nonce}");
        let server_first = format!(
            "r={combined_nonce},s={},i={}",
            STANDARD.encode(&credential.salt),
            credential.iterations
        );
        let mut expected_channel_binding = header.as_bytes().to_vec();
        if mechanism == ScramMechanism::Sha256Plus {
            expected_channel_binding
                .extend_from_slice(tls_exporter.ok_or(ScramError::ChannelBinding)?);
        }
        Ok((
            identity,
            server_first.clone(),
            Self {
                client_first_bare: client_first_bare.to_owned(),
                server_first,
                combined_nonce,
                expected_channel_binding,
                credential,
            },
        ))
    }

    pub fn finish(self, client_final: &str) -> Result<String, ScramError> {
        let attributes = attributes(client_final)?;
        if required(&attributes, 'r')? != self.combined_nonce {
            return Err(ScramError::Nonce);
        }
        let binding = STANDARD
            .decode(required(&attributes, 'c')?)
            .map_err(|_| ScramError::Malformed)?;
        if !bool::from(binding.ct_eq(&self.expected_channel_binding)) {
            return Err(ScramError::ChannelBinding);
        }
        let proof = STANDARD
            .decode(required(&attributes, 'p')?)
            .map_err(|_| ScramError::Malformed)?;
        if proof.len() != KEY_LEN {
            return Err(ScramError::Malformed);
        }
        let without_proof = client_final
            .rsplit_once(",p=")
            .filter(|(_, value)| !value.contains(','))
            .map(|(value, _)| value)
            .ok_or(ScramError::Malformed)?;
        let auth_message = format!(
            "{},{},{}",
            self.client_first_bare, self.server_first, without_proof
        );
        let signature = hmac_sha256(&self.credential.stored_key, auth_message.as_bytes());
        let mut client_key = [0_u8; KEY_LEN];
        for (output, (proof, signature)) in client_key
            .iter_mut()
            .zip(proof.iter().zip(signature.iter()))
        {
            *output = proof ^ signature;
        }
        if !bool::from(sha256(&client_key).ct_eq(&self.credential.stored_key)) {
            return Err(ScramError::InvalidProof);
        }
        let server_signature = hmac_sha256(&self.credential.server_key, auth_message.as_bytes());
        Ok(format!("v={}", STANDARD.encode(server_signature)))
    }
}

pub fn client_identity(
    mechanism: ScramMechanism,
    client_first: &str,
) -> Result<String, ScramError> {
    let bare = client_first
        .strip_prefix(gs2_header(mechanism))
        .ok_or(ScramError::ChannelBinding)?;
    let values = attributes(bare)?;
    sasl_name(required(&values, 'n')?)
}

const fn gs2_header(mechanism: ScramMechanism) -> &'static str {
    match mechanism {
        ScramMechanism::Sha256 => "n,,",
        ScramMechanism::Sha256Plus => "p=tls-exporter,,",
    }
}

fn attributes(value: &str) -> Result<Vec<(char, &str)>, ScramError> {
    let mut output = Vec::new();
    for part in value.split(',') {
        let bytes = part.as_bytes();
        if bytes.len() < 3 || bytes[1] != b'=' || !bytes[0].is_ascii_alphabetic() {
            return Err(ScramError::Malformed);
        }
        let name = char::from(bytes[0]);
        if name == 'm' || output.iter().any(|(existing, _)| *existing == name) {
            return Err(ScramError::Malformed);
        }
        output.push((name, &part[2..]));
    }
    Ok(output)
}

fn required<'a>(attributes: &[(char, &'a str)], name: char) -> Result<&'a str, ScramError> {
    attributes
        .iter()
        .find_map(|(candidate, value)| (*candidate == name).then_some(*value))
        .filter(|value| !value.is_empty())
        .ok_or(ScramError::Malformed)
}

fn sasl_name(value: &str) -> Result<String, ScramError> {
    let mut output = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(character) = chars.next() {
        if character != '=' {
            output.push(character);
            continue;
        }
        match (chars.next(), chars.next()) {
            (Some('2'), Some('C')) => output.push(','),
            (Some('3'), Some('D')) => output.push('='),
            _ => return Err(ScramError::Malformed),
        }
    }
    Ok(output)
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; KEY_LEN] {
    let key = hmac::Key::new(hmac::HMAC_SHA256, key);
    let mut output = [0_u8; KEY_LEN];
    output.copy_from_slice(hmac::sign(&key, data).as_ref());
    output
}

fn sha256(value: &[u8]) -> [u8; KEY_LEN] {
    let mut output = [0_u8; KEY_LEN];
    output.copy_from_slice(digest::digest(&digest::SHA256, value).as_ref());
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc7677_scram_sha_256_vector() -> Result<(), ScramError> {
        let credential = derive_credential(
            b"pencil",
            &STANDARD
                .decode("W22ZaJ0SNY7soEsUEjb6gQ==")
                .map_err(|_| ScramError::Malformed)?,
            NonZeroU32::new(4096).ok_or(ScramError::Malformed)?,
        );
        let (_, server_first, exchange) = ScramExchange::start(
            ScramMechanism::Sha256,
            "n,,n=user,r=rOprNGfwEbeRWgbNEkqO",
            credential,
            "%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0",
            None,
        )?;
        assert!(server_first.starts_with("r=rOprNGfwEbeRWgbNEkqO"));
        let result = exchange.finish("c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=");
        assert!(result.is_ok(), "{result:?}");
        Ok(())
    }
}
