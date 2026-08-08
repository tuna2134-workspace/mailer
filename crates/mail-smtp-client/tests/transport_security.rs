use mail_smtp_client::{TlsFailureAction, TransportSecurityPolicy};

#[test]
fn opportunistic_tls_can_retry_plaintext_but_strict_policies_cannot() {
    assert_eq!(
        TransportSecurityPolicy::Opportunistic.on_tls_failure(),
        TlsFailureAction::RetryPlaintext
    );
    for policy in [
        TransportSecurityPolicy::RequireTls,
        TransportSecurityPolicy::MtaSts,
        TransportSecurityPolicy::Dane,
        TransportSecurityPolicy::AdminStrict,
    ] {
        assert_eq!(policy.on_tls_failure(), TlsFailureAction::Defer);
    }
}

#[test]
fn only_requiretls_policy_requires_peer_extension() {
    assert!(TransportSecurityPolicy::RequireTls.requires_requiretls());
    assert!(!TransportSecurityPolicy::MtaSts.requires_requiretls());
    assert!(!TransportSecurityPolicy::Dane.requires_requiretls());
    assert!(!TransportSecurityPolicy::AdminStrict.requires_requiretls());
    assert!(!TransportSecurityPolicy::Opportunistic.requires_requiretls());
}
