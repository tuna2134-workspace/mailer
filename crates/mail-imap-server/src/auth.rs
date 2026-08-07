use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use mail_storage::ImapRepository;
use uuid::Uuid;

use crate::ImapError;

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

pub(crate) async fn authenticate<R: ImapRepository>(
    repository: &R,
    identity: String,
    password: Vec<u8>,
) -> Result<Option<Uuid>, ImapError> {
    let account = repository
        .imap_auth_account(&identity)
        .await
        .map_err(|_| ImapError::Storage)?;
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
    .map_err(|_| ImapError::Storage)?;
    if let Some(account) = &account {
        repository
            .record_imap_auth(account.user_id, valid)
            .await
            .map_err(|_| ImapError::Storage)?;
    }
    Ok(valid.then(|| account.map(|value| value.user_id)).flatten())
}
