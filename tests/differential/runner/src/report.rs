use serde::Serialize;
use std::fmt::Write as _;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Classification {
    Match,
    AllowedDifference,
    MailerSuspect,
    ReferenceSuspect,
    RfcAmbiguous,
    NotComparable,
}

impl Classification {
    const ALL: [Self; 6] = [
        Self::Match,
        Self::AllowedDifference,
        Self::MailerSuspect,
        Self::ReferenceSuspect,
        Self::RfcAmbiguous,
        Self::NotComparable,
    ];
}

#[derive(Debug, Serialize)]
pub struct TargetVersions {
    pub mailer_commit: String,
    pub postfix: String,
    pub dovecot: String,
}

#[derive(Debug, Serialize)]
pub struct Difference {
    pub protocol: &'static str,
    pub case: String,
    pub classification: Classification,
    pub explanation: String,
    pub rfc: Option<String>,
    pub mailer: serde_json::Value,
    pub reference: serde_json::Value,
    pub transcript: String,
    pub minimized_transcript: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub classifications: [Classification; 6],
    pub versions: TargetVersions,
    pub seed: u64,
    pub total: usize,
    pub counts: Counts,
    pub results: Vec<Difference>,
}

#[derive(Debug, Default, Serialize)]
pub struct Counts {
    pub matches: usize,
    pub allowed_differences: usize,
    pub mailer_suspect: usize,
    pub reference_suspect: usize,
    pub rfc_ambiguous: usize,
    pub not_comparable: usize,
}

impl Report {
    pub fn new(seed: u64, versions: TargetVersions, results: Vec<Difference>) -> Self {
        let mut counts = Counts::default();
        for item in &results {
            match item.classification {
                Classification::Match => counts.matches += 1,
                Classification::AllowedDifference => counts.allowed_differences += 1,
                Classification::MailerSuspect => counts.mailer_suspect += 1,
                Classification::ReferenceSuspect => counts.reference_suspect += 1,
                Classification::RfcAmbiguous => counts.rfc_ambiguous += 1,
                Classification::NotComparable => counts.not_comparable += 1,
            }
        }
        Self {
            classifications: Classification::ALL,
            total: results.len(),
            versions,
            seed,
            counts,
            results,
        }
    }
    pub fn summary(&self) -> String {
        format!(
            "differential: total={} match={} allowed={} suspect={}",
            self.total,
            self.counts.matches,
            self.counts.allowed_differences,
            self.counts.mailer_suspect
        )
    }
    pub fn markdown(&self) -> String {
        let mut out = format!(
            "# Differential report\n\n- mailer: `{}`\n- Postfix: `{}`\n- Dovecot: `{}`\n- seed: `{}`\n- {}\n\n| Protocol | Case | Classification | RFC | Explanation |\n|---|---|---|---|---|\n",
            self.versions.mailer_commit,
            self.versions.postfix,
            self.versions.dovecot,
            self.seed,
            self.summary()
        );
        for item in &self.results {
            let _ = writeln!(
                out,
                "| {} | {} | {:?} | {} | {} |",
                item.protocol,
                item.case,
                item.classification,
                item.rfc.as_deref().unwrap_or("-"),
                item.explanation.replace('|', "\\|")
            );
        }
        out
    }
}

pub fn redacted_transcript(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    text.lines()
        .map(|line| {
            if line.to_ascii_uppercase().starts_with("AUTH ")
                || line.to_ascii_uppercase().contains(" LOGIN ")
            {
                "<credentials redacted>"
            } else {
                line
            }
        })
        .collect::<Vec<_>>()
        .join("\\r\\n")
}
