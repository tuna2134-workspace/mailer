#![forbid(unsafe_code)]

use serde::Deserialize;
use std::{fs, net::SocketAddr, path::PathBuf};
use thiserror::Error;

const ADMIN_DEFAULT: &str = "127.0.0.1:8443";
const SMTP_DEFAULT: &str = "0.0.0.0:25";
const SUBMISSION_DEFAULT: &str = "0.0.0.0:587";
const SUBMISSIONS_DEFAULT: &str = "0.0.0.0:465";
const IMAP_DEFAULT: &str = "0.0.0.0:143";
const IMAPS_DEFAULT: &str = "0.0.0.0:993";
const ACME_DEFAULT: &str = "0.0.0.0:443";

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("read configuration file {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("parse configuration file {path}")]
    Parse { path: PathBuf },
    #[error("{0} is required")]
    Required(&'static str),
    #[error("{name} must be a socket address: {value}")]
    Address { name: &'static str, value: String },
    #[error("MAIL_TLS_CERT_FILE and MAIL_TLS_KEY_FILE must be set together")]
    ManualTlsPair,
    #[error("MAIL_HOSTNAME must be a valid ASCII DNS hostname")]
    Hostname,
    #[error("{name} must be an unsigned integer: {value}")]
    Unsigned { name: &'static str, value: String },
}

#[derive(Clone, Eq, PartialEq)]
pub struct ManualTlsConfig {
    pub certificate_file: PathBuf,
    pub private_key_file: PathBuf,
}

#[derive(Clone, Eq, PartialEq)]
pub struct AcmeConfig {
    pub domains: Vec<String>,
    pub contacts: Vec<String>,
    pub cache_key_hex: String,
    pub production: bool,
    pub listen: SocketAddr,
}

#[derive(Clone, Eq, PartialEq)]
pub struct MaildConfig {
    pub database_url: String,
    pub hostname: String,
    pub admin_listen: SocketAddr,
    pub smtp_listen: SocketAddr,
    pub smtp_data_progress_grace_seconds: u64,
    pub smtp_data_min_bytes_per_second: u64,
    pub submission_listen: SocketAddr,
    pub submissions_listen: SocketAddr,
    pub imap_listen: SocketAddr,
    pub imaps_listen: SocketAddr,
    pub manual_tls: Option<ManualTlsConfig>,
    pub acme: Option<AcmeConfig>,
}

impl MaildConfig {
    pub fn load(config_argument: Option<PathBuf>) -> Result<Self, ConfigError> {
        Self::load_with_environment(config_argument, |name| std::env::var(name).ok())
    }

    pub fn load_with_environment(
        config_argument: Option<PathBuf>,
        environment: impl Fn(&str) -> Option<String>,
    ) -> Result<Self, ConfigError> {
        let path = config_argument.or_else(|| environment("MAIL_CONFIG_FILE").map(PathBuf::from));
        let mut raw = match path {
            Some(path) => {
                let content = fs::read_to_string(&path).map_err(|source| ConfigError::Read {
                    path: path.clone(),
                    source,
                })?;
                toml::from_str(&content).map_err(|_| ConfigError::Parse { path })?
            }
            None => RawConfig::default(),
        };
        raw.apply_environment(&environment)?;
        raw.resolve()
    }
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawConfig {
    hostname: Option<String>,
    database: Database,
    tls: ManualTls,
    acme: Acme,
    smtp: Listener,
    submission: Listener,
    submissions: Listener,
    imap: Listener,
    imaps: Listener,
    admin_api: Listener,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Database {
    url: Option<String>,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct ManualTls {
    certificate_file: Option<PathBuf>,
    private_key_file: Option<PathBuf>,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Acme {
    domains: Vec<String>,
    contacts: Vec<String>,
    cache_key_hex: Option<String>,
    production: bool,
    listen: Option<String>,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Listener {
    listen: Option<String>,
    data_progress_grace_seconds: Option<u64>,
    data_min_bytes_per_second: Option<u64>,
}

impl RawConfig {
    fn apply_environment(
        &mut self,
        environment: &impl Fn(&str) -> Option<String>,
    ) -> Result<(), ConfigError> {
        replace(&mut self.database.url, environment("MAIL_DATABASE_URL"));
        replace(&mut self.hostname, environment("MAIL_HOSTNAME"));
        replace(&mut self.smtp.listen, environment("MAIL_SMTP_LISTEN"));
        replace_unsigned(
            &mut self.smtp.data_progress_grace_seconds,
            "MAIL_SMTP_DATA_PROGRESS_GRACE_SECONDS",
            environment("MAIL_SMTP_DATA_PROGRESS_GRACE_SECONDS"),
        )?;
        replace_unsigned(
            &mut self.smtp.data_min_bytes_per_second,
            "MAIL_SMTP_DATA_MIN_BYTES_PER_SECOND",
            environment("MAIL_SMTP_DATA_MIN_BYTES_PER_SECOND"),
        )?;
        replace(
            &mut self.submission.listen,
            environment("MAIL_SUBMISSION_LISTEN"),
        );
        replace(
            &mut self.submissions.listen,
            environment("MAIL_SUBMISSIONS_LISTEN"),
        );
        replace(&mut self.imap.listen, environment("MAIL_IMAP_LISTEN"));
        replace(&mut self.imaps.listen, environment("MAIL_IMAPS_LISTEN"));
        replace(&mut self.admin_api.listen, environment("MAIL_ADMIN_LISTEN"));
        replace(&mut self.acme.listen, environment("MAIL_ACME_LISTEN"));
        replace(
            &mut self.acme.cache_key_hex,
            environment("MAIL_ACME_CACHE_KEY_HEX"),
        );
        if let Some(value) = environment("MAIL_ACME_DOMAINS") {
            self.acme.domains = csv(&value);
        }
        if let Some(value) = environment("MAIL_ACME_CONTACTS") {
            self.acme.contacts = csv(&value);
        }
        if let Some(value) = environment("MAIL_ACME_PRODUCTION") {
            self.acme.production = value == "true";
        }
        if let Some(value) = environment("MAIL_TLS_CERT_FILE") {
            self.tls.certificate_file = Some(value.into());
        }
        if let Some(value) = environment("MAIL_TLS_KEY_FILE") {
            self.tls.private_key_file = Some(value.into());
        }
        Ok(())
    }

    fn resolve(self) -> Result<MaildConfig, ConfigError> {
        let manual_tls = match (self.tls.certificate_file, self.tls.private_key_file) {
            (None, None) => None,
            (Some(certificate_file), Some(private_key_file)) => Some(ManualTlsConfig {
                certificate_file,
                private_key_file,
            }),
            _ => return Err(ConfigError::ManualTlsPair),
        };
        let hostname = self
            .hostname
            .or_else(|| self.acme.domains.first().cloned())
            .ok_or(ConfigError::Required("MAIL_HOSTNAME"))?;
        if !valid_hostname(&hostname) {
            return Err(ConfigError::Hostname);
        }
        let acme = if manual_tls.is_some() {
            None
        } else {
            if self.acme.domains.is_empty() {
                return Err(ConfigError::Required("MAIL_ACME_DOMAINS"));
            }
            if self.acme.contacts.is_empty() {
                return Err(ConfigError::Required("MAIL_ACME_CONTACTS"));
            }
            Some(AcmeConfig {
                domains: self.acme.domains,
                contacts: self.acme.contacts,
                cache_key_hex: self
                    .acme
                    .cache_key_hex
                    .ok_or(ConfigError::Required("MAIL_ACME_CACHE_KEY_HEX"))?,
                production: self.acme.production,
                listen: address("MAIL_ACME_LISTEN", self.acme.listen, ACME_DEFAULT)?,
            })
        };
        Ok(MaildConfig {
            database_url: self
                .database
                .url
                .ok_or(ConfigError::Required("MAIL_DATABASE_URL"))?,
            hostname,
            admin_listen: address("MAIL_ADMIN_LISTEN", self.admin_api.listen, ADMIN_DEFAULT)?,
            smtp_listen: address("MAIL_SMTP_LISTEN", self.smtp.listen, SMTP_DEFAULT)?,
            smtp_data_progress_grace_seconds: self.smtp.data_progress_grace_seconds.unwrap_or(30),
            smtp_data_min_bytes_per_second: self.smtp.data_min_bytes_per_second.unwrap_or(256),
            submission_listen: address(
                "MAIL_SUBMISSION_LISTEN",
                self.submission.listen,
                SUBMISSION_DEFAULT,
            )?,
            submissions_listen: address(
                "MAIL_SUBMISSIONS_LISTEN",
                self.submissions.listen,
                SUBMISSIONS_DEFAULT,
            )?,
            imap_listen: address("MAIL_IMAP_LISTEN", self.imap.listen, IMAP_DEFAULT)?,
            imaps_listen: address("MAIL_IMAPS_LISTEN", self.imaps.listen, IMAPS_DEFAULT)?,
            manual_tls,
            acme,
        })
    }
}

fn replace<T>(target: &mut Option<T>, value: Option<impl Into<T>>) {
    if let Some(value) = value {
        *target = Some(value.into());
    }
}

fn replace_unsigned(
    target: &mut Option<u64>,
    name: &'static str,
    value: Option<String>,
) -> Result<(), ConfigError> {
    if let Some(value) = value {
        *target = Some(
            value
                .parse()
                .map_err(|_| ConfigError::Unsigned { name, value })?,
        );
    }
    Ok(())
}

fn csv(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect()
}

fn address(
    name: &'static str,
    value: Option<String>,
    default: &'static str,
) -> Result<SocketAddr, ConfigError> {
    let value = value.unwrap_or_else(|| default.to_owned());
    value
        .parse()
        .map_err(|_| ConfigError::Address { name, value })
}

fn valid_hostname(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}
