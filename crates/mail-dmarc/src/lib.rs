#![forbid(unsafe_code)]

use std::{collections::HashMap, fmt::Write as _};

use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Policy {
    None,
    Quarantine,
    Reject,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Alignment {
    Relaxed,
    Strict,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Psd {
    Yes,
    No,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DmarcPolicy {
    pub policy: Policy,
    pub subdomain_policy: Option<Policy>,
    pub nonexistent_policy: Option<Policy>,
    pub adkim: Alignment,
    pub aspf: Alignment,
    pub testing: bool,
    pub psd: Psd,
    pub rua: Vec<String>,
    pub ruf: Vec<String>,
    pub fo: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyScope {
    AuthorDomain,
    ExistingSubdomain,
    NonexistentSubdomain,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoveredPolicy {
    pub policy_domain: String,
    pub organizational_domain: String,
    pub scope: PolicyScope,
    pub policy: DmarcPolicy,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedIdentifier {
    pub domain: String,
    pub organizational_domain: String,
    pub pass: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Authentication {
    pub header_from: String,
    pub dkim: Vec<AuthenticatedIdentifier>,
    pub spf: Option<AuthenticatedIdentifier>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DmarcDisposition {
    None,
    Quarantine,
    Reject,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DmarcResult {
    pub requested_disposition: DmarcDisposition,
    pub dkim_aligned: bool,
    pub spf_aligned: bool,
    pub pass: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AggregateRecord {
    pub source_ip: String,
    pub count: u64,
    pub disposition: DmarcDisposition,
    pub dkim: bool,
    pub spf: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AggregateReport {
    pub reporter: String,
    pub policy_domain: String,
    pub records: Vec<AggregateRecord>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FailureReport {
    pub report_domain: String,
    pub arrival_date: String,
    pub headers: Vec<(String, String)>,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum DmarcError {
    #[error("invalid DMARC record")]
    Invalid,
}

pub fn parse(record: &str) -> Result<DmarcPolicy, DmarcError> {
    let mut parts = record
        .split(';')
        .map(str::trim)
        .filter(|part| !part.is_empty());
    let Some(version) = parts.next() else {
        return Err(DmarcError::Invalid);
    };
    let (name, value) = split_tag(version)?;
    if !name.eq_ignore_ascii_case("v") || value != "DMARC1" {
        return Err(DmarcError::Invalid);
    }

    let mut tags = HashMap::new();
    for part in parts {
        let (name, value) = split_tag(part)?;
        let name = name.to_ascii_lowercase();
        // A repeated registered tag is ambiguous.  Do not select one attacker-controlled value.
        if is_registered(&name) && tags.insert(name, value).is_some() {
            return Err(DmarcError::Invalid);
        }
    }

    let rua = uri_list(tags.get("rua").copied());
    let policies = [tags.get("p"), tags.get("sp"), tags.get("np")]
        .map(|value| value.map(|value| policy(value)).transpose());
    let invalid_policy = policies.iter().any(Result::is_err);
    if invalid_policy && rua.is_empty() {
        return Err(DmarcError::Invalid);
    }
    let [policy, subdomain_policy, nonexistent_policy] = if invalid_policy {
        [Some(Policy::None), None, None]
    } else {
        policies.map(Result::unwrap_or_default)
    };
    Ok(DmarcPolicy {
        policy: policy.unwrap_or(Policy::None),
        subdomain_policy,
        nonexistent_policy,
        adkim: alignment(tags.get("adkim").copied()),
        aspf: alignment(tags.get("aspf").copied()),
        testing: yes_no(tags.get("t").copied()),
        psd: psd(tags.get("psd").copied()),
        rua,
        ruf: uri_list(tags.get("ruf").copied()),
        fo: failure_options(tags.get("fo").copied()),
    })
}

#[must_use]
pub fn evaluate(discovered: &DiscoveredPolicy, auth: &Authentication) -> DmarcResult {
    let policy = &discovered.policy;
    let dkim_aligned = auth.dkim.iter().any(|identifier| {
        identifier.pass
            && aligned(
                identifier,
                &auth.header_from,
                &discovered.organizational_domain,
                policy.adkim,
            )
    });
    let spf_aligned = auth.spf.as_ref().is_some_and(|identifier| {
        identifier.pass
            && aligned(
                identifier,
                &auth.header_from,
                &discovered.organizational_domain,
                policy.aspf,
            )
    });
    let pass = dkim_aligned || spf_aligned;
    let requested_disposition = if pass {
        DmarcDisposition::None
    } else {
        let selected = match discovered.scope {
            PolicyScope::AuthorDomain => policy.policy,
            PolicyScope::ExistingSubdomain => policy.subdomain_policy.unwrap_or(policy.policy),
            PolicyScope::NonexistentSubdomain => policy
                .nonexistent_policy
                .or(policy.subdomain_policy)
                .unwrap_or(policy.policy),
        };
        disposition(if policy.testing {
            testing_policy(selected)
        } else {
            selected
        })
    };
    DmarcResult {
        requested_disposition,
        dkim_aligned,
        spf_aligned,
        pass,
    }
}

/// Candidate domains for the bounded RFC 9989 DNS Tree Walk.
#[must_use]
pub fn tree_walk_domains(domain: &str) -> Vec<String> {
    let normalized = normalize_domain(domain);
    let labels = normalized
        .split('.')
        .filter(|label| !label.is_empty())
        .collect::<Vec<_>>();
    if labels.is_empty() {
        return Vec::new();
    }
    let start = if labels.len() > 8 {
        labels.len() - 7
    } else {
        1
    };
    let mut result = vec![normalized.clone()];
    for index in start..labels.len() {
        let candidate = labels[index..].join(".");
        if result.last() != Some(&candidate) {
            result.push(candidate);
        }
    }
    result.truncate(8);
    result
}

/// This is retained for legacy callers. RFC 9989 evaluation uses the
/// organizational domain returned by DNS Tree Walk policy discovery instead.
#[must_use]
pub fn organizational_domain(domain: &str) -> String {
    let normalized = normalize_domain(domain);
    psl::domain_str(&normalized)
        .unwrap_or(&normalized)
        .to_owned()
}

/// Partial reporting helper. It is not advertised as an RFC 9990 report generator.
#[must_use]
pub fn partial_aggregate_xml(report: &AggregateReport) -> String {
    let mut records = String::new();
    for record in &report.records {
        let _ = write!(
            records,
            "<record><row><source_ip>{}</source_ip><count>{}</count><policy_evaluated><disposition>{}</disposition><dkim>{}</dkim><spf>{}</spf></policy_evaluated></row></record>",
            xml_escape(&record.source_ip),
            record.count,
            disposition_name(record.disposition),
            if record.dkim { "pass" } else { "fail" },
            if record.spf { "pass" } else { "fail" }
        );
    }
    format!(
        "<feedback><report_metadata><org_name>{}</org_name></report_metadata><policy_published><domain>{}</domain></policy_published>{records}</feedback>",
        xml_escape(&report.reporter),
        xml_escape(&report.policy_domain)
    )
}

/// Partial privacy-preserving failure report helper, not a complete RFC 9991 generator.
#[must_use]
pub fn partial_failure_report(report: &FailureReport, include_headers: bool) -> Option<String> {
    if !safe_field(&report.report_domain) || !safe_field(&report.arrival_date) {
        return None;
    }
    let mut headers = String::new();
    for (name, value) in &report.headers {
        if !safe_header_name(name) || !safe_field(value) {
            return None;
        }
        let value = if include_headers { value } else { "[redacted]" };
        let _ = write!(headers, "{name}: {value}\r\n");
    }
    Some(format!(
        "Feedback-Type: auth-failure\r\nReport-Domain: {}\r\nArrival-Date: {}\r\n\r\n{headers}",
        report.report_domain, report.arrival_date
    ))
}

fn split_tag(part: &str) -> Result<(&str, &str), DmarcError> {
    let (name, value) = part.split_once('=').ok_or(DmarcError::Invalid)?;
    let name = name.trim();
    let value = value.trim();
    if name.is_empty()
        || value.is_empty()
        || !name.bytes().all(|byte| byte.is_ascii_alphabetic())
        || !value
            .bytes()
            .all(|byte| (0x20..=0x7e).contains(&byte) && byte != b';')
    {
        return Err(DmarcError::Invalid);
    }
    Ok((name, value))
}

fn is_registered(name: &str) -> bool {
    matches!(
        name,
        "p" | "t" | "psd" | "np" | "sp" | "adkim" | "aspf" | "rua" | "ruf" | "fo"
    )
}

fn policy(value: &str) -> Result<Policy, DmarcError> {
    match value {
        "none" => Ok(Policy::None),
        "quarantine" => Ok(Policy::Quarantine),
        "reject" => Ok(Policy::Reject),
        _ => Err(DmarcError::Invalid),
    }
}

fn alignment(value: Option<&str>) -> Alignment {
    if value == Some("s") {
        Alignment::Strict
    } else {
        Alignment::Relaxed
    }
}

fn yes_no(value: Option<&str>) -> bool {
    value == Some("y")
}

fn psd(value: Option<&str>) -> Psd {
    match value.unwrap_or("u") {
        "y" => Psd::Yes,
        "n" => Psd::No,
        _ => Psd::Unknown,
    }
}

fn failure_options(value: Option<&str>) -> Vec<String> {
    value
        .unwrap_or("0")
        .split(':')
        .filter(|part| matches!(*part, "0" | "1" | "d" | "s"))
        .map(str::to_owned)
        .collect()
}

fn uri_list(value: Option<&str>) -> Vec<String> {
    value.map_or_else(Vec::new, |value| {
        value
            .split(',')
            .map(str::trim)
            .filter(|uri| uri.starts_with("mailto:"))
            .map(str::to_owned)
            .collect()
    })
}

fn aligned(
    identifier: &AuthenticatedIdentifier,
    author: &str,
    organizational: &str,
    mode: Alignment,
) -> bool {
    let domain = normalize_domain(&identifier.domain);
    let author = normalize_domain(author);
    match mode {
        Alignment::Strict => domain == author,
        Alignment::Relaxed => normalize_domain(&identifier.organizational_domain) == organizational,
    }
}

fn testing_policy(policy: Policy) -> Policy {
    match policy {
        Policy::None | Policy::Quarantine => Policy::None,
        Policy::Reject => Policy::Quarantine,
    }
}

fn disposition(policy: Policy) -> DmarcDisposition {
    match policy {
        Policy::None => DmarcDisposition::None,
        Policy::Quarantine => DmarcDisposition::Quarantine,
        Policy::Reject => DmarcDisposition::Reject,
    }
}

fn disposition_name(value: DmarcDisposition) -> &'static str {
    match value {
        DmarcDisposition::None => "none",
        DmarcDisposition::Quarantine => "quarantine",
        DmarcDisposition::Reject => "reject",
    }
}

fn normalize_domain(value: &str) -> String {
    value.trim_end_matches('.').to_ascii_lowercase()
}

fn safe_field(value: &str) -> bool {
    !value.contains(['\r', '\n'])
}

fn safe_header_name(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn discovered(record: &str, scope: PolicyScope) -> DiscoveredPolicy {
        DiscoveredPolicy {
            policy_domain: "example.com".into(),
            organizational_domain: "example.com".into(),
            scope,
            policy: parse(record).unwrap_or_else(|_| panic!("policy")),
        }
    }

    fn failed_auth() -> Authentication {
        Authentication {
            header_from: "mail.example.com".into(),
            dkim: Vec::new(),
            spf: None,
        }
    }

    #[test]
    fn version_is_first_and_pct_is_an_ignored_historic_tag() {
        assert!(parse("p=reject; v=DMARC1").is_err());
        assert!(parse("V=DMARC1; P=reject").is_ok());
        let parsed = parse("v=DMARC1; p=reject; pct=0")
            .unwrap_or_else(|_| panic!("unknown historic tags are ignored"));
        assert_eq!(parsed.policy, Policy::Reject);
        assert!(parse("v=DMARC1; p=reject; p=none").is_err());
        assert!(parse("v=DMARC1; p=invalid").is_err());
        assert_eq!(
            parse("v=DMARC1; p=invalid; rua=mailto:reports@example.test")
                .unwrap_or_else(|_| panic!("report-only fallback"))
                .policy,
            Policy::None
        );
    }

    #[test]
    fn subdomain_nonexistent_and_testing_policies_are_applied() {
        let existing = evaluate(
            &discovered(
                "v=DMARC1; p=none; sp=reject",
                PolicyScope::ExistingSubdomain,
            ),
            &failed_auth(),
        );
        assert_eq!(existing.requested_disposition, DmarcDisposition::Reject);
        let nonexistent = evaluate(
            &discovered(
                "v=DMARC1; p=none; sp=quarantine; np=reject; t=y",
                PolicyScope::NonexistentSubdomain,
            ),
            &failed_auth(),
        );
        assert_eq!(
            nonexistent.requested_disposition,
            DmarcDisposition::Quarantine
        );
    }

    #[test]
    fn any_aligned_dkim_signature_passes() {
        let result = evaluate(
            &discovered("v=DMARC1; p=reject", PolicyScope::AuthorDomain),
            &Authentication {
                header_from: "mail.example.com".into(),
                dkim: vec![
                    AuthenticatedIdentifier {
                        domain: "attacker.test".into(),
                        organizational_domain: "attacker.test".into(),
                        pass: true,
                    },
                    AuthenticatedIdentifier {
                        domain: "sign.example.com".into(),
                        organizational_domain: "example.com".into(),
                        pass: true,
                    },
                ],
                spf: None,
            },
        );
        assert!(result.pass);
        assert!(result.dkim_aligned);
    }

    #[test]
    fn tree_walk_is_bounded_and_normalized() {
        assert_eq!(
            tree_walk_domains("A.Mail.Example.COM."),
            [
                "a.mail.example.com",
                "mail.example.com",
                "example.com",
                "com"
            ]
        );
        assert_eq!(
            tree_walk_domains("a.b.c.d.e.f.g.h.i.j.mail.example.com").len(),
            8
        );
    }

    #[test]
    fn partial_reports_escape_xml_and_reject_header_injection() {
        let xml = partial_aggregate_xml(&AggregateReport {
            reporter: "a&b".into(),
            policy_domain: "example.test".into(),
            records: vec![AggregateRecord {
                source_ip: "192.0.2.1".into(),
                count: 1,
                disposition: DmarcDisposition::None,
                dkim: true,
                spf: false,
            }],
        });
        assert!(xml.contains("a&amp;b"));
        assert!(
            partial_failure_report(
                &FailureReport {
                    report_domain: "example.test\r\nBcc: bad@test".into(),
                    arrival_date: "now".into(),
                    headers: Vec::new(),
                },
                false,
            )
            .is_none()
        );
    }
}
