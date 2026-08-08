use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use mail_sasl::{ScramCredential, ScramExchange, ScramMechanism, client_identity};
use mail_storage::{SmtpRepository, SmtpScramCredential};
use ring::rand::{SecureRandom as _, SystemRandom};
use std::num::NonZeroU32;
use uuid::Uuid;

use crate::SmtpError;

pub(crate) fn decode_plain(response: &str) -> Option<(String, Vec<u8>)> {
    let decoded = STANDARD.decode(response).ok()?;
    let mut fields = decoded.split(|byte| *byte == 0);
    let authorization = fields.next()?;
    let identity = fields.next()?;
    let password = fields.next()?;
    if fields.next().is_some()
        || identity.is_empty()
        || password.is_empty()
        || (!authorization.is_empty() && authorization != identity)
    {
        return None;
    }
    Some((
        String::from_utf8(identity.to_vec()).ok()?,
        password.to_vec(),
    ))
}

pub(crate) async fn authenticate<R: SmtpRepository>(
    repository: &R,
    response: &str,
) -> Result<Option<Uuid>, SmtpError> {
    let Some((identity, password)) = decode_plain(response) else {
        return Ok(None);
    };
    let account = repository
        .smtp_auth_account(&identity)
        .await
        .map_err(|_| SmtpError::Storage)?;
    let hashes = account
        .as_ref()
        .map(|value| value.password_hashes.clone())
        .unwrap_or_default();
    let valid = tokio::task::spawn_blocking(move || {
        if hashes.is_empty() {
            if let Ok(salt) = SaltString::encode_b64(b"maild-dummy-salt") {
                let _ = Argon2::default().hash_password(&password, &salt);
            }
            false
        } else {
            hashes.iter().any(|hash| {
                PasswordHash::new(hash).ok().is_some_and(|parsed| {
                    Argon2::default()
                        .verify_password(&password, &parsed)
                        .is_ok()
                })
            })
        }
    })
    .await
    .map_err(|_| SmtpError::Storage)?;
    let user_id = account.as_ref().map(|value| value.user_id);
    if let Some(account) = account {
        repository
            .record_smtp_auth(account.user_id, valid)
            .await
            .map_err(|_| SmtpError::Storage)?;
    }
    Ok(valid.then_some(user_id).flatten())
}

pub(crate) struct ServerScramAuth {
    user_id: Option<Uuid>,
    exchange: ScramExchange,
}

pub(crate) async fn begin_scram<R: SmtpRepository>(
    repository: &R,
    mechanism: ScramMechanism,
    client_first: &str,
    tls_exporter: Option<&[u8]>,
) -> Result<(String, ServerScramAuth), SmtpError> {
    let identity = client_identity(mechanism, client_first).map_err(|_| SmtpError::Auth)?;
    let account = repository
        .smtp_auth_account(&identity)
        .await
        .map_err(|_| SmtpError::Storage)?;
    let user_id = account.as_ref().map(|value| value.user_id);
    let credential = match account.and_then(|value| value.scram) {
        Some(value) => convert_scram(value)?,
        None => dummy_scram_credential()?,
    };
    let mut nonce = [0_u8; 18];
    SystemRandom::new()
        .fill(&mut nonce)
        .map_err(|_| SmtpError::Storage)?;
    let nonce = STANDARD.encode(nonce);
    let (_, server_first, exchange) =
        ScramExchange::start(mechanism, client_first, credential, &nonce, tls_exporter)
            .map_err(|_| SmtpError::Auth)?;
    Ok((server_first, ServerScramAuth { user_id, exchange }))
}

fn dummy_scram_credential() -> Result<ScramCredential, SmtpError> {
    let mut salt = vec![0_u8; 16];
    let mut stored_key = [0_u8; 32];
    let mut server_key = [0_u8; 32];
    let random = SystemRandom::new();
    random.fill(&mut salt).map_err(|_| SmtpError::Storage)?;
    random
        .fill(&mut stored_key)
        .map_err(|_| SmtpError::Storage)?;
    random
        .fill(&mut server_key)
        .map_err(|_| SmtpError::Storage)?;
    Ok(ScramCredential {
        salt,
        iterations: NonZeroU32::new(4096).ok_or(SmtpError::Auth)?,
        stored_key,
        server_key,
    })
}

pub(crate) async fn finish_scram<R: SmtpRepository>(
    repository: &R,
    auth: ServerScramAuth,
    client_final: &str,
) -> Result<Option<(Uuid, String)>, SmtpError> {
    let result = auth.exchange.finish(client_final).ok();
    if let Some(user_id) = auth.user_id {
        repository
            .record_smtp_auth(user_id, result.is_some())
            .await
            .map_err(|_| SmtpError::Storage)?;
    }
    Ok(auth.user_id.zip(result))
}

fn convert_scram(value: SmtpScramCredential) -> Result<ScramCredential, SmtpError> {
    Ok(ScramCredential {
        salt: value.salt,
        iterations: NonZeroU32::new(value.iterations).ok_or(SmtpError::Auth)?,
        stored_key: value.stored_key.try_into().map_err(|_| SmtpError::Auth)?,
        server_key: value.server_key.try_into().map_err(|_| SmtpError::Auth)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_plain_initial_response() {
        let encoded = STANDARD.encode(b"\0alice@example.test\0secret");
        assert_eq!(
            decode_plain(&encoded),
            Some(("alice@example.test".into(), b"secret".to_vec()))
        );
        assert!(decode_plain("not-base64").is_none());
    }

    #[test]
    fn unknown_scram_accounts_use_complete_non_reusable_dummy_credentials() {
        let first = dummy_scram_credential().unwrap_or_else(|_| panic!("dummy"));
        let second = dummy_scram_credential().unwrap_or_else(|_| panic!("dummy"));
        assert_eq!(first.stored_key.len(), 32);
        assert_ne!(first.salt, second.salt);
    }
}
