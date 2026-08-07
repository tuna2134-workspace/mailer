use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use mail_storage::SmtpRepository;

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
) -> Result<bool, SmtpError> {
    let Some((identity, password)) = decode_plain(response) else {
        return Ok(false);
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
    if let Some(account) = account {
        repository
            .record_smtp_auth(account.user_id, valid)
            .await
            .map_err(|_| SmtpError::Storage)?;
    }
    Ok(valid)
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
}
