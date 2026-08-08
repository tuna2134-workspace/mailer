use mail_address::{Address, AddressLimits, parse_address_list};
use mail_dkim::{
    BodyHasher, Canonicalization, DkimError, DkimKeyRecord, DkimSignature, body_canonicalization,
    verify_headers,
};
use mail_dmarc::{
    AuthenticatedIdentifier, Authentication, DiscoveredPolicy, DmarcPolicy, PolicyScope, Psd,
    evaluate as evaluate_dmarc, parse as parse_dmarc, tree_walk_domains,
};
use mail_dns::MailResolver;
use mail_policy::{AuthenticationResult, authentication_results};
use mail_spf::{SpfContext, SpfError, SpfResult, evaluate};
use mail_storage::{SmtpRepository, StorageError};
use std::{collections::HashMap, net::IpAddr, time::Duration};
use uuid::Uuid;

const MAX_HEADERS: usize = 256 * 1024;
const MAX_DKIM_SIGNATURES: usize = 16;
const SPF_EVALUATION_TIMEOUT: Duration = Duration::from_secs(20);

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
        let spf = match tokio::time::timeout(
            SPF_EVALUATION_TIMEOUT,
            evaluate(
                &self.resolver,
                &SpfContext {
                    client_ip,
                    sender: &spf_sender,
                    helo,
                },
            ),
        )
        .await
        {
            Ok(result) => spf_result(result),
            Err(_) => SpfResult::TempError,
        };
        let mut dkim = "none";
        let mut dkim_domain = None;
        let mut dkim_pass_domains = Vec::new();
        for signature in header_fields(&scanned.headers, b"DKIM-Signature")
            .into_iter()
            .take(MAX_DKIM_SIGNATURES)
        {
            let Ok(parsed) = DkimSignature::parse(&signature) else {
                dkim = "permerror";
                continue;
            };
            let domain = parsed.domain.clone();
            let selector = parsed.selector.clone();
            let Ok(records) = self
                .resolver
                .txt(&format!("{selector}._domainkey.{domain}"))
                .await
            else {
                dkim = "temperror";
                continue;
            };
            let Ok(key) = dkim_key_for(&records, &parsed) else {
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
                    dkim_domain = Some(domain.clone());
                    dkim_pass_domains.push(domain);
                }
                Ok(false) if dkim != "pass" => dkim = "fail",
                Err(_) if dkim != "pass" => dkim = "permerror",
                Ok(false) | Err(_) => {}
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
                Ok(None) => ("none", Some(domain.to_owned())),
                Ok(Some(discovered)) => {
                    let spf_domain = spf_sender
                        .rsplit_once('@')
                        .map_or(spf_sender.as_str(), |(_, domain)| domain);
                    let mut dkim_identifiers = Vec::new();
                    let mut organizational_domains = HashMap::<String, String>::new();
                    for domain in dkim_pass_domains {
                        let organizational = if let Some(cached) =
                            organizational_domains.get(&domain)
                        {
                            cached.clone()
                        } else {
                            let discovered =
                                discover_organizational_domain(&self.resolver, &domain)
                                    .await
                                    .map_err(|error| {
                                        StorageError::Unavailable(format!("DMARC DNS: {error:?}"))
                                    })?;
                            organizational_domains.insert(domain.clone(), discovered.clone());
                            discovered
                        };
                        dkim_identifiers.push(AuthenticatedIdentifier {
                            domain,
                            organizational_domain: organizational,
                            pass: true,
                        });
                    }
                    let spf_identifier = if spf == SpfResult::Pass {
                        Some(AuthenticatedIdentifier {
                            domain: spf_domain.to_owned(),
                            organizational_domain: discover_organizational_domain(
                                &self.resolver,
                                spf_domain,
                            )
                            .await
                            .map_err(|error| {
                                StorageError::Unavailable(format!("DMARC DNS: {error:?}"))
                            })?,
                            pass: true,
                        })
                    } else {
                        None
                    };
                    let evaluated = evaluate_dmarc(
                        &discovered,
                        &Authentication {
                            header_from: domain.to_owned(),
                            dkim: dkim_identifiers,
                            spf: spf_identifier,
                        },
                    );
                    (
                        if evaluated.pass { "pass" } else { "fail" },
                        Some(discovered.policy_domain),
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

fn dkim_key_for(records: &[String], signature: &DkimSignature) -> Result<Vec<u8>, DkimError> {
    let [record] = records else {
        return Err(DkimError::Malformed);
    };
    let key = DkimKeyRecord::parse(record)?;
    key.key_for(
        signature.algorithm,
        &signature.domain,
        signature.identity.as_deref(),
    )
    .map(Vec::from)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DmarcDiscoveryError {
    Temporary,
}

async fn discover_dmarc(
    resolver: &MailResolver,
    from_domain: &str,
) -> Result<Option<DiscoveredPolicy>, DmarcDiscoveryError> {
    let author_exists = resolver
        .txt_with_existence(from_domain)
        .await
        .map_err(|_| DmarcDiscoveryError::Temporary)?
        .name_exists;
    let walked = walk_dmarc(resolver, from_domain).await?;
    let Some((policy_domain, policy)) = select_policy(&walked, from_domain) else {
        return Ok(None);
    };
    let organizational_domain = select_organizational_domain(&walked, from_domain);
    let scope = if policy_domain.eq_ignore_ascii_case(from_domain) {
        PolicyScope::AuthorDomain
    } else if author_exists {
        PolicyScope::ExistingSubdomain
    } else {
        PolicyScope::NonexistentSubdomain
    };
    Ok(Some(DiscoveredPolicy {
        policy_domain,
        organizational_domain,
        scope,
        policy,
    }))
}

async fn discover_organizational_domain(
    resolver: &MailResolver,
    domain: &str,
) -> Result<String, DmarcDiscoveryError> {
    let walked = walk_dmarc(resolver, domain).await?;
    Ok(select_organizational_domain(&walked, domain))
}

async fn walk_dmarc(
    resolver: &MailResolver,
    domain: &str,
) -> Result<Vec<(String, DmarcPolicy)>, DmarcDiscoveryError> {
    let mut found = Vec::new();
    for domain in tree_walk_domains(domain) {
        let records = resolver
            .txt(&format!("_dmarc.{domain}"))
            .await
            .map_err(|_| DmarcDiscoveryError::Temporary)?;
        let matching = records
            .iter()
            .filter_map(|record| parse_dmarc(record).ok())
            .collect::<Vec<_>>();
        if let [record] = matching.as_slice() {
            found.push((domain, (*record).clone()));
            if record.psd != Psd::Unknown {
                break;
            }
        }
    }
    Ok(found)
}

fn select_policy(walked: &[(String, DmarcPolicy)], author: &str) -> Option<(String, DmarcPolicy)> {
    if let Some((domain, policy)) = walked
        .iter()
        .find(|(domain, _)| domain.eq_ignore_ascii_case(author))
    {
        return Some((domain.clone(), policy.clone()));
    }
    let organizational = select_organizational_domain(walked, author);
    walked
        .iter()
        .find(|(domain, _)| domain == &organizational)
        .or_else(|| walked.last())
        .map(|(domain, policy)| (domain.clone(), policy.clone()))
}

fn select_organizational_domain(walked: &[(String, DmarcPolicy)], initial: &str) -> String {
    for (index, (domain, policy)) in walked.iter().enumerate() {
        match policy.psd {
            Psd::No => return domain.clone(),
            Psd::Yes if index > 0 => {
                return child_of(initial, domain).unwrap_or_else(|| initial.to_owned());
            }
            Psd::Yes | Psd::Unknown => {}
        }
    }
    walked.last().map_or_else(
        || initial.trim_end_matches('.').to_ascii_lowercase(),
        |(domain, _)| domain.clone(),
    )
}

fn child_of(initial: &str, parent: &str) -> Option<String> {
    let initial = initial.trim_end_matches('.').to_ascii_lowercase();
    let parent = parent.trim_end_matches('.').to_ascii_lowercase();
    let prefix = initial.strip_suffix(&format!(".{parent}"))?;
    let label = prefix.rsplit('.').next()?;
    Some(format!("{label}.{parent}"))
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

fn spf_result(result: Result<SpfResult, SpfError>) -> SpfResult {
    result.unwrap_or_else(|error| error.result())
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
    fn key_record_must_be_unique_and_match_the_signature_algorithm() {
        let signature = DkimSignature::parse(b"DKIM-Signature: v=1; a=ed25519-sha256; d=example.test; s=s1; h=from; bh=YQ==; b=Yg==\r\n")
            .unwrap_or_else(|_| panic!("signature"));
        assert!(
            dkim_key_for(
                &[
                    "v=DKIM1; k=ed25519; p=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
                    "v=DKIM1; k=ed25519; p=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
                ],
                &signature,
            )
            .is_err()
        );
        assert!(dkim_key_for(&["v=DKIM1; k=rsa; p=YQ==".into()], &signature).is_err());
    }

    #[test]
    fn spf_syntax_and_budget_errors_are_not_reported_as_dns_failures() {
        assert_eq!(spf_result(Err(SpfError::Invalid)), SpfResult::PermError);
        assert_eq!(spf_result(Err(SpfError::LookupLimit)), SpfResult::PermError);
        assert_eq!(
            spf_result(Err(SpfError::Temporary("timeout".into()))),
            SpfResult::TempError
        );
    }
}
