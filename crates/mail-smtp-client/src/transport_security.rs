#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportSecurityPolicy {
    Opportunistic,
    RequireTls,
    MtaSts,
    Dane,
    AdminStrict,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlsFailureAction {
    RetryPlaintext,
    Defer,
}

impl TransportSecurityPolicy {
    #[must_use]
    pub const fn on_tls_failure(self) -> TlsFailureAction {
        match self {
            Self::Opportunistic => TlsFailureAction::RetryPlaintext,
            Self::RequireTls | Self::MtaSts | Self::Dane | Self::AdminStrict => {
                TlsFailureAction::Defer
            }
        }
    }

    #[must_use]
    pub const fn requires_requiretls(self) -> bool {
        matches!(self, Self::RequireTls)
    }

    #[must_use]
    pub const fn requires_tls(self) -> bool {
        !matches!(self, Self::Opportunistic)
    }
}
