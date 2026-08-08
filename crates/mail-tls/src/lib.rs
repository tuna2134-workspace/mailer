#![forbid(unsafe_code)]

use rustls::{
    ServerConfig,
    crypto::ring::default_provider,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
    server::{ClientHello, ResolvesServerCert, ResolvesServerCertUsingSni},
    sign::CertifiedKey,
};
use std::{collections::BTreeMap, sync::Arc};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TlsError {
    #[error("certificate PEM contains no certificates")]
    EmptyCertificate,
    #[error("private-key PEM contains no supported private key")]
    EmptyPrivateKey,
    #[error("invalid certificate or private key: {0}")]
    InvalidKey(String),
    #[error("invalid SNI certificate for {name}: {reason}")]
    InvalidSni { name: String, reason: String },
    #[error("TLS provider configuration failed: {0}")]
    Provider(String),
}

#[derive(Clone, Debug)]
pub struct PemIdentity {
    pub names: Vec<String>,
    pub certificate_chain: Vec<u8>,
    pub private_key: Vec<u8>,
}

#[derive(Debug)]
struct SniResolverWithDefault {
    sni: ResolvesServerCertUsingSni,
    default: Arc<CertifiedKey>,
}

impl ResolvesServerCert for SniResolverWithDefault {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.sni
            .resolve(client_hello)
            .or_else(|| Some(Arc::clone(&self.default)))
    }
}

pub fn certified_key(identity: &PemIdentity) -> Result<CertifiedKey, TlsError> {
    let certificates: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(&identity.certificate_chain)
            .collect::<Result<_, _>>()
            .map_err(|error| TlsError::InvalidKey(error.to_string()))?;
    if certificates.is_empty() {
        return Err(TlsError::EmptyCertificate);
    }
    let key = PrivateKeyDer::from_pem_slice(&identity.private_key)
        .map_err(|_| TlsError::EmptyPrivateKey)?;
    CertifiedKey::from_der(certificates, key, &default_provider())
        .map_err(|error| TlsError::InvalidKey(error.to_string()))
}

pub fn sni_resolver(identities: &[PemIdentity]) -> Result<Arc<dyn ResolvesServerCert>, TlsError> {
    let mut resolver = ResolvesServerCertUsingSni::new();
    let default = identities.first().ok_or(TlsError::EmptyCertificate)?;
    let default = Arc::new(certified_key(default)?);
    for identity in identities {
        let key = certified_key(identity)?;
        for name in &identity.names {
            resolver
                .add(name, key.clone())
                .map_err(|error| TlsError::InvalidSni {
                    name: name.clone(),
                    reason: error.to_string(),
                })?;
        }
    }
    Ok(Arc::new(SniResolverWithDefault {
        sni: resolver,
        default,
    }))
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum TlsService {
    AcmeHttps,
    AdminHttps,
    ImapImplicit,
    ImapStartTls,
    SmtpImplicit,
    SmtpStartTls,
}

pub fn service_configs(
    resolver: &Arc<dyn ResolvesServerCert>,
) -> Result<BTreeMap<TlsService, Arc<ServerConfig>>, TlsError> {
    let mut configs = BTreeMap::new();
    for service in [
        TlsService::AcmeHttps,
        TlsService::AdminHttps,
        TlsService::ImapImplicit,
        TlsService::ImapStartTls,
        TlsService::SmtpImplicit,
        TlsService::SmtpStartTls,
    ] {
        let mut config = ServerConfig::builder_with_provider(Arc::new(default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|error| TlsError::Provider(error.to_string()))?
            .with_no_client_auth()
            .with_cert_resolver(Arc::clone(resolver));
        config.alpn_protocols = match service {
            TlsService::AcmeHttps | TlsService::AdminHttps => {
                vec![b"h2".to_vec(), b"http/1.1".to_vec()]
            }
            _ => Vec::new(),
        };
        configs.insert(service, Arc::new(config));
    }
    Ok(configs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_certificate_and_key() {
        let result = certified_key(&PemIdentity {
            names: vec!["mail.example.test".into()],
            certificate_chain: Vec::new(),
            private_key: Vec::new(),
        });
        assert!(matches!(result, Err(TlsError::EmptyCertificate)));
    }
}
