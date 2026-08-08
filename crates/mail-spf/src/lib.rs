#![forbid(unsafe_code)]

mod evaluator;
mod macro_expand;
mod parser;

use async_trait::async_trait;
use std::net::IpAddr;
use thiserror::Error;

pub use evaluator::evaluate;
pub use macro_expand::expand_domain;

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

    async fn ptr(&self, _ip: IpAddr) -> Result<Vec<String>, SpfError> {
        Ok(Vec::new())
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum SpfError {
    #[error("temporary DNS error: {0}")]
    Temporary(String),
    #[error("SPF lookup limit exceeded")]
    LookupLimit,
    #[error("invalid SPF record")]
    Invalid,
}

impl SpfError {
    #[must_use]
    pub const fn result(&self) -> SpfResult {
        match self {
            Self::Temporary(_) => SpfResult::TempError,
            Self::LookupLimit | Self::Invalid => SpfResult::PermError,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[derive(Default)]
    struct Dns {
        txt: HashMap<String, Vec<String>>,
        addresses: HashMap<String, Vec<IpAddr>>,
        mx: HashMap<String, Vec<String>>,
        ptr: HashMap<IpAddr, Vec<String>>,
    }

    #[async_trait]
    impl SpfLookup for Dns {
        async fn txt(&self, name: &str) -> Result<Vec<String>, SpfError> {
            Ok(self.txt.get(name).cloned().unwrap_or_default())
        }

        async fn addresses(&self, name: &str) -> Result<Vec<IpAddr>, SpfError> {
            Ok(self.addresses.get(name).cloned().unwrap_or_default())
        }

        async fn mx(&self, name: &str) -> Result<Vec<String>, SpfError> {
            Ok(self.mx.get(name).cloned().unwrap_or_default())
        }

        async fn ptr(&self, ip: IpAddr) -> Result<Vec<String>, SpfError> {
            Ok(self.ptr.get(&ip).cloned().unwrap_or_default())
        }
    }

    fn context() -> SpfContext<'static> {
        SpfContext {
            client_ip: IpAddr::from([192, 0, 2, 8]),
            sender: "strong-bad@email.example.com",
            helo: "mx.example.com",
        }
    }

    fn records(records: &[&str]) -> Dns {
        Dns {
            txt: HashMap::from([(
                "email.example.com".into(),
                records.iter().map(|value| (*value).into()).collect(),
            )]),
            ..Dns::default()
        }
    }

    #[tokio::test]
    async fn evaluates_ip_and_qualifiers() {
        assert_eq!(
            evaluate(&records(&["v=spf1 ip4:192.0.2.0/24 -all"]), &context()).await,
            Ok(SpfResult::Pass)
        );
    }

    #[tokio::test]
    async fn multiple_spf_records_are_not_selected_arbitrarily() {
        assert_eq!(
            evaluate(&records(&["v=spf1 +all", "v=spf1 -all"]), &context()).await,
            Err(SpfError::Invalid)
        );
    }

    #[tokio::test]
    async fn unknown_mechanism_and_malformed_cidr_are_permanent_errors() {
        for record in [
            "v=spf1 made-up -all",
            "v=spf1 ip4:192.0.2.1/nope -all",
            "v=spf1 ip6:2001:db8::1/129 -all",
            "v=spf1 a/33 -all",
        ] {
            assert_eq!(
                evaluate(&records(&[record]), &context()).await,
                Err(SpfError::Invalid),
                "record={record}"
            );
        }
    }

    #[tokio::test]
    async fn unknown_modifiers_are_ignored_but_duplicates_are_validated() {
        assert_eq!(
            evaluate(
                &records(&["v=spf1 unknown=%{d} ip4:192.0.2.8 -all"]),
                &context()
            )
            .await,
            Ok(SpfResult::Pass)
        );
        for record in [
            "v=spf1 redirect=a.test redirect=b.test",
            "v=spf1 exp=a.test exp=b.test -all",
            "v=spf1 exp=%{c}.example.test -all",
            "v=spf1 bad=%{q} -all",
        ] {
            assert_eq!(
                evaluate(&records(&[record]), &context()).await,
                Err(SpfError::Invalid)
            );
        }
    }

    #[tokio::test]
    async fn redirect_none_and_include_none_are_permanent_errors() {
        for record in [
            "v=spf1 redirect=missing.test",
            "v=spf1 include:missing.test",
        ] {
            assert_eq!(
                evaluate(&records(&[record]), &context()).await,
                Err(SpfError::Invalid),
                "record={record}"
            );
        }
    }

    #[tokio::test]
    async fn void_and_recursive_dns_budgets_are_global() {
        assert_eq!(
            evaluate(
                &records(&["v=spf1 exists:a.test exists:b.test exists:c.test -all"]),
                &context(),
            )
            .await,
            Err(SpfError::LookupLimit)
        );

        let mut dns = Dns::default();
        for index in 0..=10 {
            let domain = if index == 0 {
                "email.example.com".to_owned()
            } else {
                format!("r{index}.test")
            };
            let next = format!("r{}.test", index + 1);
            dns.txt
                .insert(domain, vec![format!("v=spf1 redirect={next}")]);
        }
        assert_eq!(evaluate(&dns, &context()).await, Err(SpfError::LookupLimit));
    }

    #[tokio::test]
    async fn dual_cidr_applies_the_client_address_family_prefix() {
        let mut dns = records(&["v=spf1 a:host.test/24//64 -all"]);
        dns.addresses.insert(
            "host.test".into(),
            vec![
                IpAddr::from([192, 0, 2, 99]),
                "2001:db8::99".parse().unwrap_or(IpAddr::from([0, 0, 0, 0])),
            ],
        );
        assert_eq!(evaluate(&dns, &context()).await, Ok(SpfResult::Pass));
    }

    struct PtrFailure;

    #[async_trait]
    impl SpfLookup for PtrFailure {
        async fn txt(&self, _: &str) -> Result<Vec<String>, SpfError> {
            Ok(vec!["v=spf1 ptr -all".into()])
        }

        async fn addresses(&self, _: &str) -> Result<Vec<IpAddr>, SpfError> {
            Err(SpfError::Temporary("forward lookup failed".into()))
        }

        async fn mx(&self, _: &str) -> Result<Vec<String>, SpfError> {
            Ok(Vec::new())
        }

        async fn ptr(&self, _: IpAddr) -> Result<Vec<String>, SpfError> {
            Ok(vec!["ptr.example.test".into()])
        }
    }

    #[tokio::test]
    async fn ptr_forward_dns_failure_is_not_silently_treated_as_no_match() {
        assert!(matches!(
            evaluate(&PtrFailure, &context()).await,
            Err(SpfError::Temporary(_))
        ));
    }

    #[tokio::test]
    async fn validated_domain_macro_uses_forward_confirmed_ptr_name() {
        let mut dns = records(&["v=spf1 exists:%{p} -all"]);
        dns.ptr
            .insert(context().client_ip, vec!["mail.email.example.com".into()]);
        dns.addresses
            .insert("mail.email.example.com".into(), vec![context().client_ip]);
        assert_eq!(evaluate(&dns, &context()).await, Ok(SpfResult::Pass));
    }

    #[test]
    fn evaluator_errors_have_non_collapsible_results() {
        assert_eq!(
            SpfError::Temporary("dns".into()).result(),
            SpfResult::TempError
        );
        assert_eq!(SpfError::Invalid.result(), SpfResult::PermError);
        assert_eq!(SpfError::LookupLimit.result(), SpfResult::PermError);
    }
}
