use std::net::IpAddr;

use hickory_resolver::TokioResolver;
use thiserror::Error;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MailHost {
    pub preference: u16,
    pub name: String,
    pub addresses: Vec<IpAddr>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MailRoute {
    Hosts(Vec<MailHost>),
    NullMx,
}

#[derive(Debug, Error)]
pub enum DnsError {
    #[error("invalid or unusable mail domain")]
    Permanent,
    #[error("temporary DNS failure: {0}")]
    Temporary(String),
}

#[derive(Clone)]
pub struct MailResolver(TokioResolver);

impl MailResolver {
    pub fn system() -> Result<Self, DnsError> {
        TokioResolver::builder_tokio()
            .map(|builder| Self(builder.build()))
            .map_err(|error| DnsError::Temporary(error.to_string()))
    }

    pub async fn route(&self, domain: &str) -> Result<MailRoute, DnsError> {
        let domain = domain.trim_end_matches('.');
        if domain.is_empty() {
            return Err(DnsError::Permanent);
        }
        let exchanges = match self.0.mx_lookup(domain).await {
            Ok(records) => records
                .iter()
                .map(|mx| (mx.preference(), mx.exchange().to_utf8()))
                .collect::<Vec<_>>(),
            Err(error) if error.is_no_records_found() => {
                vec![(0, domain.to_owned())]
            }
            Err(error) => return Err(DnsError::Temporary(error.to_string())),
        };
        let Some(exchanges) = normalize_exchanges(exchanges)? else {
            return Ok(MailRoute::NullMx);
        };

        let mut hosts = Vec::with_capacity(exchanges.len());
        for (preference, exchange) in exchanges {
            let name = exchange.trim_end_matches('.').to_owned();
            match self.0.lookup_ip(name.as_str()).await {
                Ok(lookup) => hosts.push(MailHost {
                    preference,
                    name,
                    addresses: lookup.iter().collect(),
                }),
                Err(error) if error.is_no_records_found() => {}
                Err(error) => return Err(DnsError::Temporary(error.to_string())),
            }
        }
        hosts.retain(|host| !host.addresses.is_empty());
        if hosts.is_empty() {
            Err(DnsError::Permanent)
        } else {
            Ok(MailRoute::Hosts(hosts))
        }
    }
}

fn normalize_exchanges(
    mut exchanges: Vec<(u16, String)>,
) -> Result<Option<Vec<(u16, String)>>, DnsError> {
    exchanges.sort_by_key(|(preference, _)| *preference);
    if exchanges.len() == 1 && exchanges[0] == (0, ".".into()) {
        return Ok(None);
    }
    if exchanges.iter().any(|(_, exchange)| exchange == ".") {
        return Err(DnsError::Permanent);
    }
    Ok(Some(exchanges))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_mx_suppresses_fallback_and_preferences_are_sorted() -> Result<(), DnsError> {
        assert!(normalize_exchanges(vec![(0, ".".into())])?.is_none());
        assert!(normalize_exchanges(vec![(0, ".".into()), (10, "mx.test.".into())]).is_err());
        assert_eq!(
            normalize_exchanges(vec![(20, "b.".into()), (10, "a.".into())])?.unwrap_or_default()[0]
                .1,
            "a."
        );
        Ok(())
    }
}
