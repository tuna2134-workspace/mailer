#![forbid(unsafe_code)]

use async_trait::async_trait;
use std::net::IpAddr;
use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SpfResult {
    Pass,
    Fail,
    SoftFail,
    Neutral,
    None,
    TempError,
    PermError,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpfContext<'a> {
    pub client_ip: IpAddr,
    pub sender: &'a str,
    pub helo: &'a str,
}

#[async_trait]
pub trait SpfLookup: Send + Sync {
    async fn txt(&self, name: &str) -> Result<Vec<String>, SpfError>;
    async fn addresses(&self, name: &str) -> Result<Vec<IpAddr>, SpfError>;
    async fn mx(&self, name: &str) -> Result<Vec<String>, SpfError>;
}

#[derive(Debug, Error)]
pub enum SpfError {
    #[error("temporary DNS error: {0}")]
    Temporary(String),
    #[error("SPF lookup limit exceeded")]
    LookupLimit,
    #[error("invalid SPF record")]
    Invalid,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SpfLimits {
    pub lookups: u8,
    pub void_lookups: u8,
    pub recursion: u8,
}

pub async fn evaluate<L: SpfLookup>(
    lookup: &L,
    ctx: &SpfContext<'_>,
) -> Result<SpfResult, SpfError> {
    let mut limits = SpfLimits::default();
    evaluate_domain(lookup, ctx, sender_domain(ctx.sender), &mut limits).await
}

async fn evaluate_domain<L: SpfLookup>(
    lookup: &L,
    ctx: &SpfContext<'_>,
    domain: &str,
    limits: &mut SpfLimits,
) -> Result<SpfResult, SpfError> {
    if limits.recursion >= 10 {
        return Err(SpfError::LookupLimit);
    }
    limits.recursion += 1;
    limits.lookups = limits.lookups.checked_add(1).ok_or(SpfError::LookupLimit)?;
    if limits.lookups > 10 {
        return Err(SpfError::LookupLimit);
    }
    let records = lookup.txt(domain).await?;
    let Some(record) = records
        .into_iter()
        .find(|value| value.to_ascii_lowercase().starts_with("v=spf1"))
    else {
        return Ok(SpfResult::None);
    };
    let mut redirect = None;
    for term in record.split_whitespace().skip(1) {
        if let Some(value) = term.strip_prefix("redirect=") {
            redirect = Some(expand(value, ctx, domain));
            continue;
        }
        if term.contains('=') {
            continue;
        }
        let (qualifier, mechanism) = term.split_at(usize::from(matches!(
            term.as_bytes().first(),
            Some(b'+' | b'-' | b'~' | b'?')
        )));
        let result = match_mechanism(lookup, ctx, domain, mechanism, &mut *limits).await?;
        if let Some(result) = result {
            return Ok(apply_qualifier(qualifier, result));
        }
    }
    if let Some(target) = redirect {
        return Box::pin(evaluate_domain(lookup, ctx, &target, limits)).await;
    }
    Ok(SpfResult::Neutral)
}

async fn match_mechanism<L: SpfLookup>(
    lookup: &L,
    ctx: &SpfContext<'_>,
    domain: &str,
    mechanism: &str,
    limits: &mut SpfLimits,
) -> Result<Option<SpfResult>, SpfError> {
    let (name, arg) = mechanism.split_once(':').map_or(
        (mechanism.split('/').next().unwrap_or(mechanism), None),
        |(a, b)| (a, Some(b)),
    );
    let name = name.to_ascii_lowercase();
    match name.as_str() {
        "all" => Ok(Some(SpfResult::Pass)),
        "ip4" | "ip6" => Ok(arg
            .filter(|value| cidr_contains(value, ctx.client_ip))
            .map(|_| SpfResult::Pass)),
        "a" => {
            let target = arg.map_or(domain, |value| value.split('/').next().unwrap_or(value));
            addresses_match(lookup, ctx, &expand(target, ctx, domain), limits).await
        }
        "mx" => {
            limits.lookups = limits.lookups.checked_add(1).ok_or(SpfError::LookupLimit)?;
            let target = arg.map_or(domain, |value| value.split('/').next().unwrap_or(value));
            let hosts = lookup.mx(&expand(target, ctx, domain)).await?;
            if hosts.is_empty() {
                limits.void_lookups = limits
                    .void_lookups
                    .checked_add(1)
                    .ok_or(SpfError::LookupLimit)?;
                if limits.void_lookups > 2 {
                    return Err(SpfError::LookupLimit);
                }
            }
            let mut found = false;
            for host in hosts {
                if addresses_match(lookup, ctx, &host, limits).await?.is_some() {
                    found = true;
                    break;
                }
            }
            Ok(found.then_some(SpfResult::Pass))
        }
        "include" => {
            let target = expand(arg.ok_or(SpfError::Invalid)?, ctx, domain);
            match Box::pin(evaluate_domain(lookup, ctx, &target, limits)).await? {
                SpfResult::Pass => Ok(Some(SpfResult::Pass)),
                SpfResult::TempError => Ok(Some(SpfResult::TempError)),
                SpfResult::PermError => Ok(Some(SpfResult::PermError)),
                _ => Ok(None),
            }
        }
        "exists" => {
            let target = expand(arg.ok_or(SpfError::Invalid)?, ctx, domain);
            limits.lookups = limits.lookups.checked_add(1).ok_or(SpfError::LookupLimit)?;
            Ok((!lookup.addresses(&target).await?.is_empty()).then_some(SpfResult::Pass))
        }
        _ => Ok(None),
    }
}

async fn addresses_match<L: SpfLookup>(
    lookup: &L,
    ctx: &SpfContext<'_>,
    domain: &str,
    limits: &mut SpfLimits,
) -> Result<Option<SpfResult>, SpfError> {
    limits.lookups = limits.lookups.checked_add(1).ok_or(SpfError::LookupLimit)?;
    let addresses = lookup.addresses(domain).await?;
    if addresses.is_empty() {
        limits.void_lookups = limits
            .void_lookups
            .checked_add(1)
            .ok_or(SpfError::LookupLimit)?;
        if limits.void_lookups > 2 {
            return Err(SpfError::LookupLimit);
        }
    }
    Ok(addresses
        .contains(&ctx.client_ip)
        .then_some(SpfResult::Pass))
}

fn apply_qualifier(qualifier: &str, result: SpfResult) -> SpfResult {
    match qualifier {
        "-" => SpfResult::Fail,
        "~" => SpfResult::SoftFail,
        "?" => SpfResult::Neutral,
        _ => result,
    }
}
fn sender_domain(sender: &str) -> &str {
    sender.rsplit_once('@').map_or(sender, |(_, domain)| domain)
}
fn expand(value: &str, ctx: &SpfContext<'_>, domain: &str) -> String {
    value
        .replace("%{i}", &ctx.client_ip.to_string())
        .replace("%{s}", ctx.sender)
        .replace("%{h}", ctx.helo)
        .replace("%{d}", domain)
}
fn cidr_contains(value: &str, ip: IpAddr) -> bool {
    let (network, prefix) = value
        .split_once('/')
        .map_or((value, if ip.is_ipv4() { 32 } else { 128 }), |(n, p)| {
            (n, p.parse().ok().unwrap_or(0))
        });
    let Ok(network) = network.parse::<IpAddr>() else {
        return false;
    };
    if network.is_ipv4() != ip.is_ipv4() {
        return false;
    }
    match (network, ip) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            let (a, b) = (u32::from(a), u32::from(b));
            prefix <= 32 && (a >> (32 - prefix)) == (b >> (32 - prefix))
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            let (a, b) = (u128::from(a), u128::from(b));
            prefix <= 128 && (a >> (128 - prefix)) == (b >> (128 - prefix))
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Dns;
    #[async_trait]
    impl SpfLookup for Dns {
        async fn txt(&self, name: &str) -> Result<Vec<String>, SpfError> {
            Ok(if name == "example.test" {
                vec!["v=spf1 ip4:192.0.2.0/24 -all".into()]
            } else {
                Vec::new()
            })
        }
        async fn addresses(&self, _: &str) -> Result<Vec<IpAddr>, SpfError> {
            Ok(Vec::new())
        }
        async fn mx(&self, _: &str) -> Result<Vec<String>, SpfError> {
            Ok(Vec::new())
        }
    }
    #[tokio::test]
    async fn evaluates_ip_and_qualifiers() {
        let ctx = SpfContext {
            client_ip: "192.0.2.8".parse().unwrap_or_else(|_| panic!("ip")),
            sender: "a@example.test",
            helo: "mx.example.test",
        };
        assert_eq!(
            evaluate(&Dns, &ctx).await.unwrap_or(SpfResult::None),
            SpfResult::Pass
        );
    }
}
