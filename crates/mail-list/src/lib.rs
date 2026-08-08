#![forbid(unsafe_code)]

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::hmac;
use std::fmt::Write as _;
use subtle::ConstantTimeEq;
use thiserror::Error;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListHeaders<'a> {
    pub id: &'a str,
    pub help: Option<&'a str>,
    pub subscribe: Option<&'a str>,
    pub unsubscribe: &'a str,
    pub post: Option<&'a str>,
    pub owner: Option<&'a str>,
    pub archive: Option<&'a str>,
    pub one_click: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DmarcMitigation {
    PreserveFrom,
    RewriteFrom,
    WrapMessage,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum ListError {
    #[error("header injection")]
    HeaderInjection,
    #[error("invalid list identifier")]
    InvalidListId,
    #[error("invalid VERP token")]
    InvalidVerp,
    #[error("mail loop detected")]
    Loop,
}

pub fn render_headers(value: &ListHeaders<'_>) -> Result<String, ListError> {
    let mut checked = vec![value.id, value.unsubscribe];
    checked.extend(
        [
            value.help,
            value.subscribe,
            value.post,
            value.owner,
            value.archive,
        ]
        .into_iter()
        .flatten(),
    );
    if checked.iter().any(|item| item.contains(['\r', '\n'])) {
        return Err(ListError::HeaderInjection);
    }
    if value.id.is_empty() || !value.id.contains('.') || value.id.contains(['<', '>']) {
        return Err(ListError::InvalidListId);
    }
    if value.one_click && !value.unsubscribe.starts_with("https://") {
        return Err(ListError::InvalidListId);
    }
    let mut out = format!(
        "List-Id: <{}>\r\nList-Unsubscribe: <{}>\r\n",
        value.id, value.unsubscribe
    );
    for (name, item) in [
        ("List-Help", value.help),
        ("List-Subscribe", value.subscribe),
        ("List-Post", value.post),
        ("List-Owner", value.owner),
        ("List-Archive", value.archive),
    ] {
        if let Some(item) = item {
            write!(out, "{name}: <{item}>\r\n").map_err(|_| ListError::InvalidListId)?;
        }
    }
    if value.one_click {
        out.push_str("List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n");
    }
    Ok(out)
}

pub fn verp_address(
    list_local: &str,
    recipient: &str,
    domain: &str,
    secret: &[u8],
) -> Result<String, ListError> {
    if [list_local, recipient, domain]
        .iter()
        .any(|v| v.contains(['\r', '\n']))
        || list_local.contains(['@', '+'])
        || domain.contains(['@', '+'])
        || recipient.is_empty()
        || !recipient.contains('@')
    {
        return Err(ListError::InvalidVerp);
    }
    let encoded = URL_SAFE_NO_PAD.encode(recipient);
    let tag = hmac::sign(
        &hmac::Key::new(hmac::HMAC_SHA256, secret),
        recipient.as_bytes(),
    );
    Ok(format!(
        "{list_local}+{encoded}.{}@{domain}",
        URL_SAFE_NO_PAD.encode(&tag.as_ref()[..16])
    ))
}

pub fn verify_verp(address: &str, secret: &[u8]) -> Result<String, ListError> {
    let (_, rest) = address.split_once('+').ok_or(ListError::InvalidVerp)?;
    let (token, _) = rest.rsplit_once('@').ok_or(ListError::InvalidVerp)?;
    let (encoded, signature) = token.rsplit_once('.').ok_or(ListError::InvalidVerp)?;
    let recipient = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| ListError::InvalidVerp)?;
    let supplied = URL_SAFE_NO_PAD
        .decode(signature)
        .map_err(|_| ListError::InvalidVerp)?;
    let expected = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, secret), &recipient);
    if supplied
        .as_slice()
        .ct_eq(&expected.as_ref()[..16])
        .unwrap_u8()
        != 1
    {
        return Err(ListError::InvalidVerp);
    }
    String::from_utf8(recipient).map_err(|_| ListError::InvalidVerp)
}

pub fn reject_loop(
    existing_list_ids: &[&str],
    list_id: &str,
    received_count: usize,
    max_hops: usize,
) -> Result<(), ListError> {
    if received_count >= max_hops
        || existing_list_ids
            .iter()
            .any(|id| id.eq_ignore_ascii_case(list_id))
    {
        return Err(ListError::Loop);
    }
    Ok(())
}

#[must_use]
pub fn dmarc_mitigation(
    dmarc_reject: bool,
    arc_valid: bool,
    preserve_from_allowed: bool,
) -> DmarcMitigation {
    if !dmarc_reject || arc_valid || preserve_from_allowed {
        DmarcMitigation::PreserveFrom
    } else {
        DmarcMitigation::RewriteFrom
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headers_verp_loop_and_dmarc_are_safe() {
        let headers = render_headers(&ListHeaders {
            id: "users.example.test",
            help: None,
            subscribe: None,
            unsubscribe: "https://example.test/u/one",
            post: Some("mailto:users@example.test"),
            owner: None,
            archive: None,
            one_click: true,
        })
        .unwrap_or_default();
        assert!(headers.contains("List-Unsubscribe-Post: List-Unsubscribe=One-Click"));
        let address = verp_address(
            "bounce",
            "alice@example.test",
            "lists.example.test",
            b"secret",
        )
        .unwrap_or_default();
        assert_eq!(
            verify_verp(&address, b"secret").unwrap_or_default(),
            "alice@example.test"
        );
        assert_eq!(verify_verp(&address, b"wrong"), Err(ListError::InvalidVerp));
        assert_eq!(
            reject_loop(&["users.example.test"], "users.example.test", 1, 20),
            Err(ListError::Loop)
        );
        assert_eq!(
            dmarc_mitigation(true, false, false),
            DmarcMitigation::RewriteFrom
        );
    }
}
