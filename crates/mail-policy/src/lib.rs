#![forbid(unsafe_code)]

use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnssecStatus {
    Secure,
    Insecure,
    Bogus,
    Indeterminate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MtaStsMode {
    Enforce,
    Testing,
    None,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MtaStsPolicy {
    pub mode: MtaStsMode,
    pub mx: Vec<String>,
    pub max_age: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TlsRptPolicy {
    pub rua: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TlsaRecord {
    pub usage: u8,
    pub selector: u8,
    pub matching_type: u8,
    pub association: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlsDecision {
    RequireTls,
    Opportunistic,
    Reject,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticationResult<'a> {
    pub method: &'a str,
    pub result: &'a str,
    pub property: Option<(&'a str, &'a str)>,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum PolicyError {
    #[error("invalid policy")]
    Invalid,
    #[error("DNSSEC validation is required")]
    DnssecRequired,
}

pub fn parse_mta_sts(value: &str) -> Result<MtaStsPolicy, PolicyError> {
    let mut mode = MtaStsMode::None;
    let mut mx = Vec::new();
    let mut max_age = 0;
    for part in value.split(';').map(str::trim) {
        let Some((key, val)) = part.split_once('=') else {
            continue;
        };
        match key {
            "version" if val == "STSv1" => {}
            "mode" => {
                mode = match val {
                    "enforce" => MtaStsMode::Enforce,
                    "testing" => MtaStsMode::Testing,
                    "none" => MtaStsMode::None,
                    _ => return Err(PolicyError::Invalid),
                }
            }
            "mx" => mx.push(val.to_owned()),
            "max_age" => max_age = val.parse().map_err(|_| PolicyError::Invalid)?,
            _ => {}
        }
    }
    Ok(MtaStsPolicy { mode, mx, max_age })
}

pub fn parse_tls_rpt(value: &str) -> TlsRptPolicy {
    TlsRptPolicy {
        rua: value
            .split(';')
            .filter_map(|part| part.trim().strip_prefix("rua="))
            .flat_map(|v| v.split(','))
            .map(str::trim)
            .filter(|v| v.starts_with("mailto:") || v.starts_with("https://"))
            .map(str::to_owned)
            .collect(),
    }
}

pub fn decide(
    require_tls: bool,
    mta_sts: Option<&MtaStsPolicy>,
    dnssec: DnssecStatus,
    tlsa: &[TlsaRecord],
) -> Result<TlsDecision, PolicyError> {
    if !tlsa.is_empty() && dnssec != DnssecStatus::Secure {
        return Err(PolicyError::DnssecRequired);
    }
    if require_tls || mta_sts.is_some_and(|p| p.mode == MtaStsMode::Enforce) {
        return Ok(TlsDecision::RequireTls);
    }
    Ok(TlsDecision::Opportunistic)
}

pub fn authentication_results(
    authserv_id: &str,
    results: &[AuthenticationResult<'_>],
) -> Result<String, PolicyError> {
    if authserv_id.contains(['\r', '\n', ';']) {
        return Err(PolicyError::Invalid);
    }
    let mut value = authserv_id.to_owned();
    for result in results {
        if [result.method, result.result]
            .iter()
            .any(|part| part.contains(['\r', '\n', ';']))
        {
            return Err(PolicyError::Invalid);
        }
        value.push_str("; ");
        value.push_str(result.method);
        value.push('=');
        value.push_str(result.result);
        if let Some((name, property)) = result.property {
            if [name, property]
                .iter()
                .any(|part| part.contains(['\r', '\n', ';']))
            {
                return Err(PolicyError::Invalid);
            }
            value.push(' ');
            value.push_str(name);
            value.push('=');
            value.push_str(property);
        }
    }
    Ok(value)
}

#[must_use]
pub fn may_auto_respond(
    auto_submitted: Option<&str>,
    reverse_path_empty: bool,
    precedence_bulk: bool,
) -> bool {
    !reverse_path_empty
        && !precedence_bulk
        && auto_submitted.is_none_or(|value| value.eq_ignore_ascii_case("no"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_and_enforces_modern_tls_policy() {
        let sts = parse_mta_sts("version=STSv1; mode=enforce; mx=mail.example.test; max_age=86400")
            .unwrap_or_else(|_| panic!("policy"));
        assert_eq!(
            decide(false, Some(&sts), DnssecStatus::Insecure, &[]),
            Ok(TlsDecision::RequireTls)
        );
        assert_eq!(
            parse_tls_rpt("version=TLSRPTv1; rua=mailto:tls@example.test")
                .rua
                .len(),
            1
        );
    }
    #[test]
    fn dane_rejects_unvalidated_dnssec() {
        let tlsa = [TlsaRecord {
            usage: 3,
            selector: 1,
            matching_type: 1,
            association: vec![1],
        }];
        assert_eq!(
            decide(false, None, DnssecStatus::Insecure, &tlsa),
            Err(PolicyError::DnssecRequired)
        );
    }

    #[test]
    fn authentication_results_and_auto_response_are_bounded() {
        let value = authentication_results(
            "mx.example.test",
            &[AuthenticationResult {
                method: "dkim",
                result: "pass",
                property: Some(("header.d", "example.test")),
            }],
        )
        .unwrap_or_default();
        assert_eq!(value, "mx.example.test; dkim=pass header.d=example.test");
        assert!(!may_auto_respond(Some("auto-generated"), false, false));
        assert!(!may_auto_respond(None, true, false));
    }
}
