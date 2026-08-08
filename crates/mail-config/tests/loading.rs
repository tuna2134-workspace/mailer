use mail_config::MaildConfig;
use std::{collections::HashMap, fs, path::PathBuf};

fn environment(values: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
    let values: HashMap<String, String> = values
        .iter()
        .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
        .collect();
    move |name| values.get(name).cloned()
}

fn config_file(content: &str) -> Result<(tempfile::TempDir, PathBuf), std::io::Error> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("maild.toml");
    fs::write(&path, content)?;
    Ok((directory, path))
}

#[test]
fn loads_toml_and_applies_defaults() -> Result<(), Box<dyn std::error::Error>> {
    let (_directory, path) = config_file(
        r#"
hostname = "mail.file.test"
[database]
url = "postgresql://file/db"
[tls]
certificate_file = "/run/file.crt"
private_key_file = "/run/file.key"
[smtp]
listen = "127.0.0.1:2525"
data_progress_grace_seconds = 20
data_min_bytes_per_second = 512
"#,
    )?;
    let config = MaildConfig::load_with_environment(Some(path), environment(&[]))?;
    assert_eq!(config.database_url, "postgresql://file/db");
    assert_eq!(config.hostname, "mail.file.test");
    assert_eq!(config.smtp_listen, "127.0.0.1:2525".parse()?);
    assert_eq!(config.smtp_data_progress_grace_seconds, 20);
    assert_eq!(config.smtp_data_min_bytes_per_second, 512);
    assert_eq!(config.imaps_listen, "0.0.0.0:993".parse()?);
    assert!(config.manual_tls.is_some());
    assert!(config.acme.is_none());
    Ok(())
}

#[test]
fn environment_overrides_toml_values() -> Result<(), Box<dyn std::error::Error>> {
    let (_directory, path) = config_file(
        r#"
hostname = "mail.file.test"
[database]
url = "postgresql://file/db"
[tls]
certificate_file = "/run/file.crt"
private_key_file = "/run/file.key"
[smtp]
listen = "127.0.0.1:2525"
"#,
    )?;
    let config = MaildConfig::load_with_environment(
        Some(path),
        environment(&[
            ("MAIL_DATABASE_URL", "postgresql://environment/db"),
            ("MAIL_HOSTNAME", "mail.environment.test"),
            ("MAIL_SMTP_LISTEN", "127.0.0.1:2025"),
            ("MAIL_SMTP_DATA_PROGRESS_GRACE_SECONDS", "15"),
            ("MAIL_SMTP_DATA_MIN_BYTES_PER_SECOND", "1024"),
            ("MAIL_TLS_CERT_FILE", "/run/environment.crt"),
            ("MAIL_TLS_KEY_FILE", "/run/environment.key"),
        ]),
    )?;
    assert_eq!(config.database_url, "postgresql://environment/db");
    assert_eq!(config.hostname, "mail.environment.test");
    assert_eq!(config.smtp_listen, "127.0.0.1:2025".parse()?);
    assert_eq!(config.smtp_data_progress_grace_seconds, 15);
    assert_eq!(config.smtp_data_min_bytes_per_second, 1024);
    assert_eq!(
        config.manual_tls.as_ref().map(|tls| &tls.certificate_file),
        Some(&PathBuf::from("/run/environment.crt"))
    );
    Ok(())
}

#[test]
fn config_argument_wins_over_mail_config_file() -> Result<(), Box<dyn std::error::Error>> {
    let (_first_directory, first) = config_file(
        "hostname='first.test'\n[database]\nurl='postgresql://first/db'\n[tls]\ncertificate_file='first.crt'\nprivate_key_file='first.key'\n",
    )?;
    let (_second_directory, second) = config_file(
        "hostname='second.test'\n[database]\nurl='postgresql://second/db'\n[tls]\ncertificate_file='second.crt'\nprivate_key_file='second.key'\n",
    )?;
    let config = MaildConfig::load_with_environment(
        Some(first),
        environment(&[("MAIL_CONFIG_FILE", second.to_str().ok_or("non-UTF-8 path")?)]),
    )?;
    assert_eq!(config.hostname, "first.test");
    assert_eq!(config.database_url, "postgresql://first/db");
    Ok(())
}

#[test]
fn mail_config_file_environment_selects_toml() -> Result<(), Box<dyn std::error::Error>> {
    let (_directory, path) = config_file(
        "hostname='selected.test'\n[database]\nurl='postgresql://selected/db'\n[tls]\ncertificate_file='selected.crt'\nprivate_key_file='selected.key'\n",
    )?;
    let config = MaildConfig::load_with_environment(
        None,
        environment(&[("MAIL_CONFIG_FILE", path.to_str().ok_or("non-UTF-8 path")?)]),
    )?;
    assert_eq!(config.hostname, "selected.test");
    assert_eq!(config.database_url, "postgresql://selected/db");
    Ok(())
}

#[test]
fn environment_only_startup_remains_supported() -> Result<(), Box<dyn std::error::Error>> {
    let config = MaildConfig::load_with_environment(
        None,
        environment(&[
            ("MAIL_DATABASE_URL", "postgresql://environment/db"),
            ("MAIL_HOSTNAME", "mail.environment.test"),
            ("MAIL_TLS_CERT_FILE", "/run/mail.crt"),
            ("MAIL_TLS_KEY_FILE", "/run/mail.key"),
        ]),
    )?;
    assert_eq!(config.database_url, "postgresql://environment/db");
    assert_eq!(config.admin_listen, "127.0.0.1:8443".parse()?);
    assert!(config.manual_tls.is_some());
    Ok(())
}

#[test]
fn unknown_toml_key_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let (_directory, path) = config_file("unknown=true\n")?;
    assert!(MaildConfig::load_with_environment(Some(path), environment(&[])).is_err());
    Ok(())
}
