use std::{
    collections::VecDeque,
    net::{IpAddr, Ipv6Addr},
    sync::Mutex,
    time::{Duration, Instant},
};

const WINDOW: Duration = Duration::from_secs(300);
const MAX_FAILURES: usize = 10_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ThrottleDecision {
    pub allowed: bool,
    pub delay: Duration,
}

pub trait AuthAttemptLimiter: Send + Sync {
    fn before_attempt(&self, source: IpAddr, account: Option<&str>) -> ThrottleDecision;
    fn record_result(&self, source: IpAddr, account: Option<&str>, succeeded: bool);
}

#[derive(Debug)]
struct Failure {
    at: Instant,
    source: IpAddr,
    account: Option<String>,
}

#[derive(Debug, Default)]
pub struct LocalAuthAttemptLimiter {
    failures: Mutex<VecDeque<Failure>>,
    aggregation: SourceAggregation,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum SourceAggregation {
    Exact,
    #[default]
    Ipv6Prefix64,
}

impl LocalAuthAttemptLimiter {
    #[must_use]
    pub const fn new(aggregation: SourceAggregation) -> Self {
        Self {
            failures: Mutex::new(VecDeque::new()),
            aggregation,
        }
    }
}

impl AuthAttemptLimiter for LocalAuthAttemptLimiter {
    fn before_attempt(&self, source: IpAddr, account: Option<&str>) -> ThrottleDecision {
        let source = aggregate(source, self.aggregation);
        let account = normalized(account);
        let mut failures = lock(&self.failures);
        prune(&mut failures);
        let ip_count = failures.iter().filter(|item| item.source == source).count();
        let account_count = account.as_ref().map_or(0, |account| {
            failures
                .iter()
                .filter(|item| item.account.as_ref() == Some(account))
                .count()
        });
        let pair_count = account.as_ref().map_or(0, |account| {
            failures
                .iter()
                .filter(|item| item.source == source && item.account.as_ref() == Some(account))
                .count()
        });
        let pressure = ip_count
            .max(account_count.saturating_mul(2))
            .max(pair_count.saturating_mul(5));
        ThrottleDecision {
            allowed: ip_count < 50 && account_count < 25 && pair_count < 10,
            delay: Duration::from_millis((pressure as u64).saturating_mul(50).min(2_000)),
        }
    }

    fn record_result(&self, source: IpAddr, account: Option<&str>, succeeded: bool) {
        let source = aggregate(source, self.aggregation);
        let account = normalized(account);
        let mut failures = lock(&self.failures);
        prune(&mut failures);
        if succeeded {
            failures.retain(|item| {
                account
                    .as_ref()
                    .is_none_or(|account| item.account.as_ref() != Some(account))
            });
            return;
        }
        if failures.len() == MAX_FAILURES {
            failures.pop_front();
        }
        failures.push_back(Failure {
            at: Instant::now(),
            source,
            account,
        });
    }
}

fn aggregate(source: IpAddr, aggregation: SourceAggregation) -> IpAddr {
    match (source, aggregation) {
        (IpAddr::V6(address), SourceAggregation::Ipv6Prefix64) => {
            let mut octets = address.octets();
            octets[8..].fill(0);
            IpAddr::V6(Ipv6Addr::from(octets))
        }
        (source, _) => source,
    }
}

fn normalized(account: Option<&str>) -> Option<String> {
    account
        .filter(|value| !value.is_empty() && value.len() <= 254)
        .map(str::to_ascii_lowercase)
}

fn prune(failures: &mut VecDeque<Failure>) {
    let now = Instant::now();
    while failures.front().is_some_and(|failure| {
        now.checked_duration_since(failure.at)
            .is_some_and(|age| age > WINDOW)
    }) {
        failures.pop_front();
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reconnects_share_ip_account_and_pair_budget() {
        let limiter = LocalAuthAttemptLimiter::default();
        let ip = IpAddr::from([192, 0, 2, 1]);
        for _ in 0..10 {
            limiter.record_result(ip, Some("Alice@Example.test"), false);
        }
        let blocked = limiter.before_attempt(ip, Some("alice@example.test"));
        assert!(!blocked.allowed);
        assert!(blocked.delay > Duration::ZERO);

        limiter.record_result(ip, Some("alice@example.test"), true);
        assert!(
            limiter
                .before_attempt(ip, Some("alice@example.test"))
                .allowed
        );
    }

    #[test]
    fn distinct_accounts_still_hit_source_budget_and_storage_is_bounded() {
        let limiter = LocalAuthAttemptLimiter::default();
        let ip = IpAddr::from([2001, 0xdb8, 0, 0, 0, 0, 0, 1]);
        for index in 0..MAX_FAILURES + 10 {
            limiter.record_result(ip, Some(&format!("user{index}")), false);
        }
        assert!(!limiter.before_attempt(ip, Some("new-user")).allowed);
        assert_eq!(lock(&limiter.failures).len(), MAX_FAILURES);
    }

    #[test]
    fn ipv6_prefix_aggregation_is_configurable() {
        let prefix = LocalAuthAttemptLimiter::default();
        let exact = LocalAuthAttemptLimiter::new(SourceAggregation::Exact);
        let first: IpAddr = "2001:db8::1".parse().unwrap_or(IpAddr::from([0, 0, 0, 0]));
        let second: IpAddr = "2001:db8::2".parse().unwrap_or(IpAddr::from([0, 0, 0, 0]));
        prefix.record_result(first, Some("user"), false);
        exact.record_result(first, Some("user"), false);
        assert!(prefix.before_attempt(second, Some("user")).delay > Duration::ZERO);
        assert_eq!(
            exact.before_attempt(second, Some("different-user")).delay,
            Duration::ZERO
        );
    }
}
