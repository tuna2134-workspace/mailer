use base64::{Engine as _, engine::general_purpose::STANDARD};
use mail_address::{Address, AddressLimits, parse_address_list};
use mail_dkim::{BodyHasher, Canonicalization, body_canonicalization, identity, verify_headers};
use mail_dmarc::{
    Authentication, DmarcPolicy, evaluate as evaluate_dmarc, organizational_domain,
    parse as parse_dmarc,
};
use mail_dns::MailResolver;
use mail_policy::{AuthenticationResult, authentication_results};
use mail_spf::{SpfContext, SpfResult, evaluate};
use mail_storage::{SmtpRepository, StorageError};
use std::net::IpAddr;
use uuid::Uuid;

const MAX_HEADERS: usize = 256 * 1024;

#[derive(Clone)]
pub struct InboundAuthenticator {
    resolver: MailResolver,
    authserv_id: String,
}

impl InboundAuthenticator {
    #[must_use]
    pub fn new(resolver: MailResolver, authserv_id: String) -> Self {
        Self {
            resolver,
            authserv_id,
        }
    }

    #[allow(clippy::too_many_lines)] // Evaluation order is kept together for auditable headers.
    pub async fn headers<R: SmtpRepository>(
        &self,
        repository: &R,
        ingestion_id: Uuid,
        client_ip: IpAddr,
        sender: &str,
        helo: &str,
    ) -> Result<Vec<u8>, StorageError> {
        let scanned = scan(repository, ingestion_id).await?;
        let spf_sender = safe_identity(if sender.is_empty() { helo } else { sender });
        let spf = evaluate(
            &self.resolver,
            &SpfContext {
                client_ip,
                sender: &spf_sender,
                helo,
            },
        )
        .await
        .unwrap_or(SpfResult::TempError);
        let mut dkim = "none";
        let mut dkim_domain = None;
        for signature in header_fields(&scanned.headers, b"DKIM-Signature") {
            let Ok((domain, selector)) = identity(&signature) else {
                dkim = "permerror";
                continue;
            };
            let Ok(records) = self
                .resolver
                .txt(&format!("{selector}._domainkey.{domain}"))
                .await
            else {
                dkim = "temperror";
                continue;
            };
            let Some(key) = records.iter().find_map(|record| dkim_key(record)) else {
                dkim = "permerror";
                continue;
            };
            let hash = match body_canonicalization(&signature) {
                Ok(Canonicalization::Simple) => &scanned.simple_hash,
                Ok(Canonicalization::Relaxed) => &scanned.relaxed_hash,
                Err(_) => {
                    dkim = "permerror";
                    continue;
                }
            };
            match verify_headers(&scanned.headers, &signature, &key, hash) {
                Ok(true) => {
                    dkim = "pass";
                    dkim_domain = Some(domain);
                    break;
                }
                Ok(false) => dkim = "fail",
                Err(_) => dkim = "permerror",
            }
        }
        let spf_name = spf_name(spf);
        let mut results = vec![AuthenticationResult {
            method: "spf",
            result: spf_name,
            property: Some(("smtp.mailfrom", &spf_sender)),
        }];
        results.push(AuthenticationResult {
            method: "dkim",
            result: dkim,
            property: dkim_domain.as_deref().map(|domain| ("header.d", domain)),
        });
        results.push(AuthenticationResult {
            method: "arc",
            result: crate::arc_validation::validate(
                &scanned.headers,
                &scanned.simple_hash,
                &scanned.relaxed_hash,
                &self.resolver,
            )
            .await,
            property: None,
        });
        let from_domain = from_domain(&scanned.headers);
        let (dmarc, policy_domain) = match from_domain.as_deref() {
            None => ("permerror", None),
            Some(domain) => match discover_dmarc(&self.resolver, domain).await {
                Err(DmarcDiscoveryError::Temporary) => ("temperror", Some(domain.to_owned())),
                Err(DmarcDiscoveryError::Permanent) => ("permerror", Some(domain.to_owned())),
                Ok(None) => ("none", Some(domain.to_owned())),
                Ok(Some((policy_domain, policy))) => {
                    let spf_domain = spf_sender
                        .rsplit_once('@')
                        .map_or(Some(spf_sender.clone()), |(_, domain)| {
                            Some(domain.to_owned())
                        });
                    let evaluated = evaluate_dmarc(
                        &policy,
                        &Authentication {
                            header_from: domain.to_owned(),
                            dkim_domain: dkim_domain.clone(),
                            dkim_pass: dkim == "pass",
                            spf_domain,
                            spf_pass: spf == SpfResult::Pass,
                        },
                    );
                    (
                        if evaluated.pass { "pass" } else { "fail" },
                        Some(policy_domain),
                    )
                }
            },
        };
        results.push(AuthenticationResult {
            method: "dmarc",
            result: dmarc,
            property: policy_domain
                .as_deref()
                .map(|domain| ("header.from", domain)),
        });
        let value = authentication_results(&self.authserv_id, &results)
            .map_err(|error| StorageError::Unavailable(error.to_string()))?;
        Ok(format!(
            "Authentication-Results: {value}\r\nReceived-SPF: {spf_name} client-ip={client_ip}; envelope-from={spf_sender}\r\n"
        )
        .into_bytes())
    }
}

struct ScannedMessage {
    headers: Vec<u8>,
    simple_hash: String,
    relaxed_hash: String,
}

async fn scan<R: SmtpRepository>(
    repository: &R,
    ingestion_id: Uuid,
) -> Result<ScannedMessage, StorageError> {
    let mut headers = Vec::new();
    let mut simple = BodyHasher::new(Canonicalization::Simple);
    let mut relaxed = BodyHasher::new(Canonicalization::Relaxed);
    let mut position = 0;
    let mut in_headers = true;
    let mut boundary = Vec::with_capacity(4);
    loop {
        let chunk = repository.read_smtp_chunk(ingestion_id, position).await?;
        if chunk.is_empty() {
            break;
        }
        for byte in chunk {
            if in_headers {
                headers.push(byte);
                if headers.len() > MAX_HEADERS {
                    return Err(StorageError::Unavailable(
                        "message headers too large".into(),
                    ));
                }
                boundary.push(byte);
                if boundary.len() > 4 {
                    boundary.remove(0);
                }
                if boundary == b"\r\n\r\n" {
                    headers.truncate(headers.len() - 2);
                    in_headers = false;
                }
            } else {
                simple.update(&[byte]);
                relaxed.update(&[byte]);
            }
        }
        position = position.checked_add(1).ok_or(StorageError::Conflict)?;
    }
    if in_headers {
        return Err(StorageError::Unavailable(
            "message has no header/body separator".into(),
        ));
    }
    Ok(ScannedMessage {
        headers,
        simple_hash: simple.finish(),
        relaxed_hash: relaxed.finish(),
    })
}

fn header_fields(headers: &[u8], name: &[u8]) -> Vec<Vec<u8>> {
    let mut fields = Vec::<Vec<u8>>::new();
    for line in headers.split_inclusive(|byte| *byte == b'\n') {
        if matches!(line.first(), Some(b' ' | b'\t')) {
            if let Some(field) = fields.last_mut() {
                field.extend_from_slice(line);
            }
        } else if line
            .get(..name.len())
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(name))
            && line.get(name.len()) == Some(&b':')
        {
            fields.push(line.to_vec());
        }
    }
    fields
}

pub(super) fn dkim_key(record: &str) -> Option<Vec<u8>> {
    if !record.split(';').any(|tag| tag.trim() == "v=DKIM1") {
        return None;
    }
    let value = record
        .split(';')
        .find_map(|tag| tag.trim().strip_prefix("p="))?;
    if value.is_empty() {
        return None;
    }
    STANDARD
        .decode(value.split_ascii_whitespace().collect::<String>())
        .ok()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DmarcDiscoveryError {
    Temporary,
    Permanent,
}

async fn discover_dmarc(
    resolver: &MailResolver,
    from_domain: &str,
) -> Result<Option<(String, DmarcPolicy)>, DmarcDiscoveryError> {
    let organizational = organizational_domain(from_domain);
    let mut domains = vec![from_domain];
    if organizational != from_domain {
        domains.push(&organizational);
    }
    for domain in domains {
        let records = resolver
            .txt(&format!("_dmarc.{domain}"))
            .await
            .map_err(|_| DmarcDiscoveryError::Temporary)?;
        let matching = records
            .iter()
            .filter(|record| record.trim_start().starts_with("v=DMARC1"))
            .collect::<Vec<_>>();
        match matching.as_slice() {
            [] => {}
            [record] => {
                let policy = parse_dmarc(record).map_err(|_| DmarcDiscoveryError::Permanent)?;
                return Ok(Some((domain.to_owned(), policy)));
            }
            _ => return Err(DmarcDiscoveryError::Permanent),
        }
    }
    Ok(None)
}

fn from_domain(headers: &[u8]) -> Option<String> {
    let field = header_fields(headers, b"From").into_iter().next()?;
    let colon = field.iter().position(|byte| *byte == b':')?;
    let mut value = Vec::new();
    for byte in field[colon + 1..].iter().copied() {
        match byte {
            b'\r' | b'\n' => {}
            b'\t' => value.push(b' '),
            byte => value.push(byte),
        }
    }
    let addresses = parse_address_list(&value, AddressLimits::default()).ok()?;
    match addresses.as_slice() {
        [Address::Mailbox(mailbox)] => String::from_utf8(mailbox.domain.clone()).ok(),
        _ => None,
    }
}

fn spf_name(result: SpfResult) -> &'static str {
    match result {
        SpfResult::Pass => "pass",
        SpfResult::Fail => "fail",
        SpfResult::SoftFail => "softfail",
        SpfResult::Neutral => "neutral",
        SpfResult::None => "none",
        SpfResult::TempError => "temperror",
        SpfResult::PermError => "permerror",
    }
}

fn safe_identity(value: &str) -> String {
    if !value.is_empty()
        && value.len() <= 320
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"@._+-".contains(&byte))
    {
        value.to_owned()
    } else {
        "unknown".into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_one_from_domain_and_rejects_ambiguous_from() {
        assert_eq!(
            from_domain(b"From: Alice <alice@Example.Test>\r\nSubject: x\r\n"),
            Some("example.test".into())
        );
        assert_eq!(
            from_domain(b"From: a@example.test, b@example.test\r\n"),
            None
        );
    }

    #[test]
    fn accepts_only_non_revoked_dkim_key_records() {
        assert_eq!(dkim_key("v=DKIM1; k=ed25519; p=YQ=="), Some(vec![b'a']));
        assert_eq!(dkim_key("v=DKIM1; p="), None);
        assert_eq!(dkim_key("v=OTHER; p=YQ=="), None);
    }
}
