#![forbid(unsafe_code)]

mod cases;
mod imap;
mod normalize;
mod report;
mod smtp;
mod transport;

use report::{Classification, Difference, Report, TargetVersions};
use std::{env, fs, path::PathBuf};

const SEED: u64 = 0x4d41_494c_4552;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| "install rustls crypto provider")?;
    let ca = env::var("DIFFERENTIAL_CA_FILE").unwrap_or_else(|_| "/certs/ca.crt".into());
    let mut differences = Vec::new();
    differences.extend(smtp::run(&ca, SEED)?);
    differences.extend(imap::run(&ca, SEED)?);
    let report = Report::new(SEED, versions(), differences);
    let output =
        PathBuf::from(env::var("DIFFERENTIAL_REPORT_DIR").unwrap_or_else(|_| "/reports".into()));
    fs::create_dir_all(&output)?;
    fs::write(
        output.join("report.json"),
        serde_json::to_vec_pretty(&report)?,
    )?;
    fs::write(output.join("report.md"), report.markdown())?;
    println!("{}", report.summary());
    if report
        .results
        .iter()
        .any(|item| item.classification == Classification::MailerSuspect)
    {
        return Err("unexplained MAILER_SUSPECT differential result".into());
    }
    Ok(())
}

fn versions() -> TargetVersions {
    TargetVersions {
        mailer_commit: env::var("MAILER_COMMIT_SHA").unwrap_or_else(|_| "local".into()),
        postfix: reference_version("POSTFIX_REFERENCE_VERSION", smtp::server_version),
        dovecot: reference_version("DOVECOT_REFERENCE_VERSION", imap::server_version),
    }
}

fn reference_version(name: &str, greeting: fn() -> std::io::Result<String>) -> String {
    env::var(name)
        .unwrap_or_else(|_| greeting().unwrap_or_else(|error| format!("unavailable: {error}")))
}

fn compare_with_equivalence(
    protocol: &'static str,
    case: &str,
    mailer: serde_json::Value,
    reference: serde_json::Value,
    equivalent: bool,
    transcript: &[u8],
) -> Difference {
    let (classification, explanation, rfc) = if equivalent {
        (Classification::Match, "semantic results match", None)
    } else if let Some(adjudication) = cases::adjudication(protocol, case) {
        (
            adjudication.classification,
            adjudication.explanation,
            Some(adjudication.rfc),
        )
    } else {
        (
            Classification::MailerSuspect,
            "unadjudicated semantic disagreement",
            None,
        )
    };
    let transcript = report::redacted_transcript(transcript);
    let minimized_transcript =
        (classification != Classification::Match).then(|| transcript.clone());
    Difference {
        protocol,
        case: case.to_owned(),
        classification,
        explanation: explanation.to_owned(),
        rfc: rfc.map(str::to_owned),
        mailer,
        reference,
        transcript,
        minimized_transcript,
    }
}
