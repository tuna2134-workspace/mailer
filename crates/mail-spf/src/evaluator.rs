use crate::{
    SpfContext, SpfError, SpfLookup, SpfResult,
    macro_expand::expand_domain_with_p,
    parser::{Directive, Mechanism, Qualifier, contains, parse, unspecified},
};
const MAX_DNS_LOOKUPS: u8 = 10;
const MAX_VOID_LOOKUPS: u8 = 2;
const MAX_MX_OR_PTR_NAMES: usize = 10;

#[derive(Default)]
struct Budget {
    dns: u8,
    void: u8,
    depth: u8,
}

pub async fn evaluate<L: SpfLookup>(
    lookup: &L,
    context: &SpfContext<'_>,
) -> Result<SpfResult, SpfError> {
    let domain = sender_domain(context.sender);
    if !valid_initial_domain(domain) {
        return Ok(SpfResult::None);
    }
    evaluate_domain(lookup, context, domain, &mut Budget::default()).await
}

async fn evaluate_domain<L: SpfLookup>(
    lookup: &L,
    context: &SpfContext<'_>,
    domain: &str,
    budget: &mut Budget,
) -> Result<SpfResult, SpfError> {
    if budget.depth >= MAX_DNS_LOOKUPS {
        return Err(SpfError::LookupLimit);
    }
    budget.depth += 1;
    let result = evaluate_record(lookup, context, domain, budget).await;
    budget.depth -= 1;
    result
}

async fn evaluate_record<L: SpfLookup>(
    lookup: &L,
    context: &SpfContext<'_>,
    domain: &str,
    budget: &mut Budget,
) -> Result<SpfResult, SpfError> {
    let records = lookup.txt(domain).await?;
    let matching = records
        .iter()
        .filter(|record| {
            record.as_str() == "v=spf1"
                || record
                    .strip_prefix("v=spf1")
                    .is_some_and(|rest| rest.starts_with(' '))
        })
        .collect::<Vec<_>>();
    let record = match matching.as_slice() {
        [] => return Ok(SpfResult::None),
        [record] => parse(record)?,
        _ => return Err(SpfError::Invalid),
    };
    let has_all = record
        .directives
        .iter()
        .any(|directive| directive.mechanism == Mechanism::All);
    for directive in &record.directives {
        if matches_directive(lookup, context, domain, directive, budget).await? {
            return Ok(qualifier_result(directive.qualifier));
        }
    }
    if !has_all && let Some(redirect) = record.redirect {
        consume_dns(budget)?;
        let target = expand_spec(lookup, &redirect, context, domain, budget).await?;
        let result = Box::pin(evaluate_domain(lookup, context, &target, budget)).await?;
        if result == SpfResult::None {
            return Err(SpfError::Invalid);
        }
        return Ok(result);
    }
    Ok(SpfResult::Neutral)
}

async fn matches_directive<L: SpfLookup>(
    lookup: &L,
    context: &SpfContext<'_>,
    domain: &str,
    directive: &Directive,
    budget: &mut Budget,
) -> Result<bool, SpfError> {
    match &directive.mechanism {
        Mechanism::All => Ok(true),
        Mechanism::Ip(network, prefix) => Ok(contains(*network, *prefix, context.client_ip)),
        Mechanism::Include(specification) => {
            consume_dns(budget)?;
            let target = expand_spec(lookup, specification, context, domain, budget).await?;
            let result = Box::pin(evaluate_domain(lookup, context, &target, budget)).await?;
            match result {
                SpfResult::Pass => Ok(true),
                SpfResult::None => Err(SpfError::Invalid),
                _ => Ok(false),
            }
        }
        Mechanism::A {
            domain: target,
            ipv4_prefix,
            ipv6_prefix,
        } => {
            consume_dns(budget)?;
            let target = target.as_deref().unwrap_or(domain);
            let target = expand_spec(lookup, target, context, domain, budget).await?;
            let addresses = lookup.addresses(&target).await?;
            record_void(addresses.is_empty(), budget)?;
            Ok(addresses.iter().any(|address| {
                let prefix = if address.is_ipv4() {
                    *ipv4_prefix
                } else {
                    *ipv6_prefix
                };
                contains(*address, prefix, context.client_ip)
            }))
        }
        Mechanism::Mx {
            domain: target,
            ipv4_prefix,
            ipv6_prefix,
        } => {
            consume_dns(budget)?;
            let target = target.as_deref().unwrap_or(domain);
            let target = expand_spec(lookup, target, context, domain, budget).await?;
            let hosts = lookup.mx(&target).await?;
            record_void(hosts.is_empty(), budget)?;
            if hosts.len() > MAX_MX_OR_PTR_NAMES {
                return Err(SpfError::Invalid);
            }
            for host in hosts {
                let addresses = lookup.addresses(&host).await?;
                record_void(addresses.is_empty(), budget)?;
                if addresses.len() > MAX_MX_OR_PTR_NAMES {
                    return Err(SpfError::Invalid);
                }
                if addresses.iter().any(|address| {
                    let prefix = if address.is_ipv4() {
                        *ipv4_prefix
                    } else {
                        *ipv6_prefix
                    };
                    contains(*address, prefix, context.client_ip)
                }) {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        Mechanism::Exists(specification) => {
            consume_dns(budget)?;
            let target = expand_spec(lookup, specification, context, domain, budget).await?;
            let addresses = lookup.addresses(&target).await?;
            record_void(addresses.is_empty(), budget)?;
            Ok(!addresses.is_empty())
        }
        Mechanism::Ptr(target) => {
            consume_dns(budget)?;
            let names = lookup.ptr(context.client_ip).await?;
            record_void(names.is_empty(), budget)?;
            let target = expand_spec(
                lookup,
                target.as_deref().unwrap_or(domain),
                context,
                domain,
                budget,
            )
            .await?;
            for name in names.into_iter().take(MAX_MX_OR_PTR_NAMES) {
                let addresses = lookup.addresses(&name).await?;
                record_void(addresses.is_empty(), budget)?;
                if addresses.contains(&context.client_ip) && within_domain(&name, &target) {
                    return Ok(true);
                }
            }
            Ok(false)
        }
    }
}

fn consume_dns(budget: &mut Budget) -> Result<(), SpfError> {
    budget.dns = budget.dns.checked_add(1).ok_or(SpfError::LookupLimit)?;
    (budget.dns <= MAX_DNS_LOOKUPS)
        .then_some(())
        .ok_or(SpfError::LookupLimit)
}

async fn expand_spec<L: SpfLookup>(
    lookup: &L,
    specification: &str,
    context: &SpfContext<'_>,
    domain: &str,
    budget: &mut Budget,
) -> Result<String, SpfError> {
    let p_macros = specification
        .as_bytes()
        .windows(3)
        .filter(|window| {
            window[0] == b'%' && window[1] == b'{' && window[2].eq_ignore_ascii_case(&b'p')
        })
        .count();
    if p_macros == 0 {
        return expand_domain_with_p(specification, context, domain, "unknown");
    }
    for _ in 0..p_macros {
        consume_dns(budget)?;
    }
    let validated = validated_domain(lookup, context.client_ip, domain, budget).await?;
    expand_domain_with_p(
        specification,
        context,
        domain,
        validated.as_deref().unwrap_or("unknown"),
    )
}

async fn validated_domain<L: SpfLookup>(
    lookup: &L,
    ip: std::net::IpAddr,
    domain: &str,
    budget: &mut Budget,
) -> Result<Option<String>, SpfError> {
    let Ok(names) = lookup.ptr(ip).await else {
        return Ok(None);
    };
    record_void(names.is_empty(), budget)?;
    let mut validated = Vec::new();
    for name in names.into_iter().take(MAX_MX_OR_PTR_NAMES) {
        let Ok(addresses) = lookup.addresses(&name).await else {
            return Ok(None);
        };
        record_void(addresses.is_empty(), budget)?;
        if addresses.contains(&ip) {
            validated.push(name);
        }
    }
    Ok(validated
        .iter()
        .find(|name| {
            name.trim_end_matches('.')
                .eq_ignore_ascii_case(domain.trim_end_matches('.'))
        })
        .or_else(|| validated.iter().find(|name| within_domain(name, domain)))
        .or_else(|| validated.first())
        .cloned())
}

fn record_void(empty: bool, budget: &mut Budget) -> Result<(), SpfError> {
    if empty {
        budget.void = budget.void.checked_add(1).ok_or(SpfError::LookupLimit)?;
        if budget.void > MAX_VOID_LOOKUPS {
            return Err(SpfError::LookupLimit);
        }
    }
    Ok(())
}

fn qualifier_result(qualifier: Qualifier) -> SpfResult {
    match qualifier {
        Qualifier::Pass => SpfResult::Pass,
        Qualifier::Fail => SpfResult::Fail,
        Qualifier::SoftFail => SpfResult::SoftFail,
        Qualifier::Neutral => SpfResult::Neutral,
    }
}

fn sender_domain(sender: &str) -> &str {
    sender.rsplit_once('@').map_or(sender, |(_, domain)| domain)
}

fn valid_initial_domain(domain: &str) -> bool {
    if domain.trim_end_matches('.').split('.').count() < 2 {
        return false;
    }
    expand_domain_with_p(
        domain,
        &SpfContext {
            client_ip: unspecified(true),
            sender: "postmaster@example.invalid",
            helo: "example.invalid",
        },
        "example.invalid",
        "unknown",
    )
    .is_ok()
}

fn within_domain(name: &str, domain: &str) -> bool {
    let name = name.trim_end_matches('.');
    let domain = domain.trim_end_matches('.');
    name.eq_ignore_ascii_case(domain)
        || name.len() > domain.len()
            && name
                .get(name.len() - domain.len() - 1..)
                .is_some_and(|suffix| {
                    suffix.starts_with('.') && suffix[1..].eq_ignore_ascii_case(domain)
                })
}
