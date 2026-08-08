use crate::SpfError;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Qualifier {
    Pass,
    Fail,
    SoftFail,
    Neutral,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Mechanism {
    All,
    Include(String),
    A {
        domain: Option<String>,
        ipv4_prefix: u8,
        ipv6_prefix: u8,
    },
    Mx {
        domain: Option<String>,
        ipv4_prefix: u8,
        ipv6_prefix: u8,
    },
    Ptr(Option<String>),
    Ip(IpAddr, u8),
    Exists(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Directive {
    pub qualifier: Qualifier,
    pub mechanism: Mechanism,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Record {
    pub directives: Vec<Directive>,
    pub redirect: Option<String>,
    pub explanation: Option<String>,
}

pub(crate) fn parse(value: &str) -> Result<Record, SpfError> {
    if value
        .bytes()
        .any(|byte| byte.is_ascii_whitespace() && byte != b' ')
    {
        return Err(SpfError::Invalid);
    }
    let mut terms = value.split(' ').filter(|term| !term.is_empty());
    if terms.next() != Some("v=spf1") {
        return Err(SpfError::Invalid);
    }
    let mut record = Record {
        directives: Vec::new(),
        redirect: None,
        explanation: None,
    };
    for term in terms {
        if let Some((name, macro_string)) = term.split_once('=') {
            if !valid_name(name) || macro_string.is_empty() {
                return Err(SpfError::Invalid);
            }
            // `c`, `r`, and `t` are allowed in the fetched explanation text,
            // not in the `exp=` domain-spec that names that TXT record.
            crate::macro_expand::validate(macro_string, false)?;
            if name.eq_ignore_ascii_case("redirect") {
                if record.redirect.replace(macro_string.into()).is_some() {
                    return Err(SpfError::Invalid);
                }
            } else if name.eq_ignore_ascii_case("exp")
                && record.explanation.replace(macro_string.into()).is_some()
            {
                return Err(SpfError::Invalid);
            }
            continue;
        }
        record.directives.push(parse_directive(term)?);
    }
    Ok(record)
}

fn parse_directive(term: &str) -> Result<Directive, SpfError> {
    let (qualifier, mechanism) = match term.as_bytes().first() {
        Some(b'+') => (Qualifier::Pass, &term[1..]),
        Some(b'-') => (Qualifier::Fail, &term[1..]),
        Some(b'~') => (Qualifier::SoftFail, &term[1..]),
        Some(b'?') => (Qualifier::Neutral, &term[1..]),
        _ => (Qualifier::Pass, term),
    };
    if mechanism.is_empty() {
        return Err(SpfError::Invalid);
    }
    Ok(Directive {
        qualifier,
        mechanism: parse_mechanism(mechanism)?,
    })
}

fn parse_mechanism(value: &str) -> Result<Mechanism, SpfError> {
    let lower = value.to_ascii_lowercase();
    if lower == "all" {
        return Ok(Mechanism::All);
    }
    if let Some(argument) = strip_name(value, "include:") {
        return nonempty(argument).map(|value| Mechanism::Include(value.into()));
    }
    if let Some(argument) = strip_name(value, "exists:") {
        return nonempty(argument).map(|value| Mechanism::Exists(value.into()));
    }
    if let Some(argument) = strip_name(value, "ip4:") {
        return parse_ip(argument, true);
    }
    if let Some(argument) = strip_name(value, "ip6:") {
        return parse_ip(argument, false);
    }
    if lower == "a" || lower.starts_with("a:") || lower.starts_with("a/") {
        let rest = &value[1..];
        let (domain, ipv4_prefix, ipv6_prefix) = parse_domain_cidr(rest)?;
        return Ok(Mechanism::A {
            domain,
            ipv4_prefix,
            ipv6_prefix,
        });
    }
    if lower == "mx" || lower.starts_with("mx:") || lower.starts_with("mx/") {
        let rest = &value[2..];
        let (domain, ipv4_prefix, ipv6_prefix) = parse_domain_cidr(rest)?;
        return Ok(Mechanism::Mx {
            domain,
            ipv4_prefix,
            ipv6_prefix,
        });
    }
    if lower == "ptr" {
        return Ok(Mechanism::Ptr(None));
    }
    if let Some(argument) = strip_name(value, "ptr:") {
        return nonempty(argument).map(|value| Mechanism::Ptr(Some(value.into())));
    }
    Err(SpfError::Invalid)
}

fn parse_ip(value: &str, ipv4: bool) -> Result<Mechanism, SpfError> {
    let (address, prefix) = value
        .rsplit_once('/')
        .map_or((value, None), |(address, prefix)| (address, Some(prefix)));
    let address = address.parse::<IpAddr>().map_err(|_| SpfError::Invalid)?;
    if address.is_ipv4() != ipv4 {
        return Err(SpfError::Invalid);
    }
    let maximum = if ipv4 { 32 } else { 128 };
    let prefix = prefix.map_or(Ok(maximum), |value| parse_prefix(value, maximum))?;
    Ok(Mechanism::Ip(address, prefix))
}

fn parse_domain_cidr(value: &str) -> Result<(Option<String>, u8, u8), SpfError> {
    let (before_v6, ipv6_prefix) = value
        .split_once("//")
        .map_or(Ok((value, 128)), |(left, prefix)| {
            Ok((left, parse_prefix(prefix, 128)?))
        })?;
    let (domain, ipv4_prefix) = before_v6
        .rsplit_once('/')
        .map_or(Ok((before_v6, 32)), |(domain, prefix)| {
            Ok((domain, parse_prefix(prefix, 32)?))
        })?;
    let domain = match domain.strip_prefix(':') {
        Some("") => return Err(SpfError::Invalid),
        Some(domain) => Some(domain.to_owned()),
        None if domain.is_empty() => None,
        None => return Err(SpfError::Invalid),
    };
    Ok((domain, ipv4_prefix, ipv6_prefix))
}

fn parse_prefix(value: &str, maximum: u8) -> Result<u8, SpfError> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(SpfError::Invalid);
    }
    let prefix = value.parse::<u8>().map_err(|_| SpfError::Invalid)?;
    (prefix <= maximum)
        .then_some(prefix)
        .ok_or(SpfError::Invalid)
}

fn strip_name<'a>(value: &'a str, prefix: &str) -> Option<&'a str> {
    value
        .get(..prefix.len())
        .is_some_and(|value| value.eq_ignore_ascii_case(prefix))
        .then(|| &value[prefix.len()..])
}

fn nonempty(value: &str) -> Result<&str, SpfError> {
    (!value.is_empty())
        .then_some(value)
        .ok_or(SpfError::Invalid)
}

fn valid_name(value: &str) -> bool {
    value
        .as_bytes()
        .first()
        .is_some_and(u8::is_ascii_alphabetic)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

pub(crate) fn contains(network: IpAddr, prefix: u8, address: IpAddr) -> bool {
    match (network, address) {
        (IpAddr::V4(network), IpAddr::V4(address)) => {
            prefix == 0
                || (u32::from(network) >> (32 - prefix)) == (u32::from(address) >> (32 - prefix))
        }
        (IpAddr::V6(network), IpAddr::V6(address)) => {
            prefix == 0
                || (u128::from(network) >> (128 - prefix))
                    == (u128::from(address) >> (128 - prefix))
        }
        _ => false,
    }
}

pub(crate) fn unspecified(ipv4: bool) -> IpAddr {
    if ipv4 {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    } else {
        IpAddr::V6(Ipv6Addr::UNSPECIFIED)
    }
}
