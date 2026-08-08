#![forbid(unsafe_code)]

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
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DmarcPolicy {
    pub policy: Policy,
    pub subdomain_policy: Option<Policy>,
    pub adkim: Alignment,
    pub aspf: Alignment,
    pub pct: u8,
    pub rua: Vec<String>,
    pub ruf: Vec<String>,
    pub fo: Vec<String>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DmarcDisposition {
    None,
    Quarantine,
    Reject,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Authentication {
    pub header_from: String,
    pub dkim_domain: Option<String>,
    pub dkim_pass: bool,
    pub spf_domain: Option<String>,
    pub spf_pass: bool,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DmarcResult {
    pub disposition: DmarcDisposition,
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
#[derive(Debug, Error)]
pub enum DmarcError {
    #[error("invalid DMARC record")]
    Invalid,
    #[error("invalid percentage")]
    Percentage,
}

pub fn parse(record: &str) -> Result<DmarcPolicy, DmarcError> {
    let tags = tags(record)?;
    if !tags
        .get("v")
        .is_some_and(|value| value.eq_ignore_ascii_case("DMARC1"))
    {
        return Err(DmarcError::Invalid);
    }
    let policy_value = policy(tags.get("p").ok_or(DmarcError::Invalid)?)?;
    let pct = tags.get("pct").map_or(Ok(100), |value| {
        value.parse().map_err(|_| DmarcError::Percentage)
    })?;
    if pct > 100 {
        return Err(DmarcError::Percentage);
    }
    Ok(DmarcPolicy {
        policy: policy_value,
        subdomain_policy: tags.get("sp").map(|value| policy(value)).transpose()?,
        adkim: alignment(tags.get("adkim")),
        aspf: alignment(tags.get("aspf")),
        pct,
        rua: uri_list(tags.get("rua")),
        ruf: uri_list(tags.get("ruf")),
        fo: tags.get("fo").map_or_else(Vec::new, |value| {
            value.split(':').map(str::to_owned).collect()
        }),
    })
}

#[must_use]
pub fn evaluate(policy: &DmarcPolicy, auth: &Authentication) -> DmarcResult {
    let dkim_aligned = auth.dkim_pass
        && auth
            .dkim_domain
            .as_deref()
            .is_some_and(|domain| aligned(domain, &auth.header_from, policy.adkim));
    let spf_aligned = auth.spf_pass
        && auth
            .spf_domain
            .as_deref()
            .is_some_and(|domain| aligned(domain, &auth.header_from, policy.aspf));
    let pass = dkim_aligned || spf_aligned;
    let disposition = if pass {
        DmarcDisposition::None
    } else {
        match policy.policy {
            Policy::None => DmarcDisposition::None,
            Policy::Quarantine => DmarcDisposition::Quarantine,
            Policy::Reject => DmarcDisposition::Reject,
        }
    };
    DmarcResult {
        disposition,
        dkim_aligned,
        spf_aligned,
        pass,
    }
}

#[must_use]
pub fn aggregate_xml(report: &AggregateReport) -> String {
    let mut records = String::new();
    for record in &report.records {
        use std::fmt::Write;
        let _ = write!(
            records,
            "<record><row><source_ip>{}</source_ip><count>{}</count><policy_evaluated><disposition>{:?}</disposition><dkim>{}</dkim><spf>{}</spf></policy_evaluated></row></record>",
            xml_escape(&record.source_ip),
            record.count,
            record.disposition,
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

#[must_use]
pub fn failure_report(report: &FailureReport, body_inclusion: bool) -> String {
    let mut headers = String::new();
    for (name, value) in &report.headers {
        use std::fmt::Write;
        let value = if body_inclusion {
            value.as_str()
        } else {
            "[redacted]"
        };
        let _ = writeln!(headers, "{name}: {value}\r");
    }
    format!(
        "Feedback-Type: auth-failure\r\nReport-Domain: {}\r\nArrival-Date: {}\r\n\r\n{headers}",
        report.report_domain, report.arrival_date
    )
}

pub fn organizational_domain(domain: &str) -> String {
    let labels = domain
        .trim_end_matches('.')
        .to_ascii_lowercase()
        .split('.')
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if labels.len() <= 2 {
        labels.join(".")
    } else {
        labels[labels.len() - 2..].join(".")
    }
}
fn aligned(a: &str, b: &str, mode: Alignment) -> bool {
    let a = a.trim_end_matches('.').to_ascii_lowercase();
    let b = b.trim_end_matches('.').to_ascii_lowercase();
    mode == Alignment::Strict && a == b
        || mode == Alignment::Relaxed && organizational_domain(&a) == organizational_domain(&b)
}
fn tags(record: &str) -> Result<std::collections::HashMap<String, String>, DmarcError> {
    record
        .split(';')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(|part| {
            part.split_once('=')
                .ok_or(DmarcError::Invalid)
                .map(|(key, value)| (key.trim().to_ascii_lowercase(), value.trim().to_owned()))
        })
        .collect()
}
fn policy(value: &str) -> Result<Policy, DmarcError> {
    match value.to_ascii_lowercase().as_str() {
        "none" => Ok(Policy::None),
        "quarantine" => Ok(Policy::Quarantine),
        "reject" => Ok(Policy::Reject),
        _ => Err(DmarcError::Invalid),
    }
}
fn alignment(value: Option<&String>) -> Alignment {
    if value.is_some_and(|value| value.eq_ignore_ascii_case("s")) {
        Alignment::Strict
    } else {
        Alignment::Relaxed
    }
}
fn uri_list(value: Option<&String>) -> Vec<String> {
    value.map_or_else(Vec::new, |value| {
        value
            .split(',')
            .map(str::trim)
            .filter(|value| value.starts_with("mailto:"))
            .map(str::to_owned)
            .collect()
    })
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
    #[test]
    fn parses_and_aligns_policy() {
        let policy = parse("v=DMARC1; p=reject; adkim=s; rua=mailto:agg@example.test")
            .unwrap_or_else(|_| panic!("policy"));
        let result = evaluate(
            &policy,
            &Authentication {
                header_from: "example.test".into(),
                dkim_domain: Some("example.test".into()),
                dkim_pass: true,
                spf_domain: None,
                spf_pass: false,
            },
        );
        assert!(result.pass);
        assert_eq!(policy.rua.len(), 1);
        let xml = aggregate_xml(&AggregateReport {
            reporter: "example.test".into(),
            policy_domain: "example.test".into(),
            records: vec![AggregateRecord {
                source_ip: "192.0.2.1".into(),
                count: 1,
                disposition: DmarcDisposition::None,
                dkim: true,
                spf: false,
            }],
        });
        assert!(xml.contains("<source_ip>192.0.2.1</source_ip>"));
        assert!(
            failure_report(
                &FailureReport {
                    report_domain: "example.test".into(),
                    arrival_date: "now".into(),
                    headers: vec![("From".into(), "secret".into())]
                },
                false
            )
            .contains("[redacted]")
        );
    }
}
