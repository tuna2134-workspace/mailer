use std::net::IpAddr;

use hickory_resolver::TokioResolver;
use hickory_resolver::proto::rr::RData;
use mail_spf::{SpfError, SpfLookup};
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
            .and_then(hickory_resolver::ResolverBuilder::build)
            .map(Self)
            .map_err(|error| DnsError::Temporary(error.to_string()))
    }

    pub async fn route(&self, domain: &str) -> Result<MailRoute, DnsError> {
        let domain = domain.trim_end_matches('.');
        if domain.is_empty() {
            return Err(DnsError::Permanent);
        }
        let exchanges = match self.0.mx_lookup(domain).await {
            Ok(records) => records
                .message()
                .answers
                .iter()
                .filter_map(|record| match &record.data {
                    RData::MX(mx) => Some((mx.preference, mx.exchange.to_utf8())),
                    _ => None,
                })
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

    pub async fn txt(&self, name: &str) -> Result<Vec<String>, DnsError> {
        self.0
            .txt_lookup(name)
            .await
            .map(|records| {
                records
                    .message()
                    .answers
                    .iter()
                    .filter_map(|record| match &record.data {
                        RData::TXT(txt) => Some(
                            txt.txt_data
                                .iter()
                                .flat_map(|part| part.iter().copied())
                                .collect::<Vec<_>>(),
                        ),
                        _ => None,
                    })
                    .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
                    .collect()
            })
            .or_else(|error| {
                if error.is_no_records_found() {
                    Ok(Vec::new())
                } else {
                    Err(DnsError::Temporary(error.to_string()))
                }
            })
    }

    pub async fn addresses(&self, name: &str) -> Result<Vec<IpAddr>, DnsError> {
        self.0
            .lookup_ip(name)
            .await
            .map(|records| records.iter().collect())
            .or_else(|error| {
                if error.is_no_records_found() {
                    Ok(Vec::new())
                } else {
                    Err(DnsError::Temporary(error.to_string()))
                }
            })
    }

    pub async fn mx_names(&self, name: &str) -> Result<Vec<String>, DnsError> {
        self.0
            .mx_lookup(name)
            .await
            .map(|records| {
                records
                    .message()
                    .answers
                    .iter()
                    .filter_map(|record| match &record.data {
                        RData::MX(mx) => Some(mx.exchange.to_utf8()),
                        _ => None,
                    })
                    .collect()
            })
            .or_else(|error| {
                if error.is_no_records_found() {
                    Ok(Vec::new())
                } else {
                    Err(DnsError::Temporary(error.to_string()))
                }
            })
    }
}

#[async_trait::async_trait]
impl SpfLookup for MailResolver {
    async fn txt(&self, name: &str) -> Result<Vec<String>, SpfError> {
        MailResolver::txt(self, name).await.map_err(spf_dns)
    }

    async fn addresses(&self, name: &str) -> Result<Vec<IpAddr>, SpfError> {
        MailResolver::addresses(self, name).await.map_err(spf_dns)
    }

    async fn mx(&self, name: &str) -> Result<Vec<String>, SpfError> {
        self.mx_names(name).await.map_err(spf_dns)
    }
}

fn spf_dns(error: DnsError) -> SpfError {
    match error {
        DnsError::Temporary(message) => SpfError::Temporary(message),
        DnsError::Permanent => SpfError::Invalid,
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
