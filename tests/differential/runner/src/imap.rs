use crate::{
    cases::imap::{Case, Step},
    compare_with_equivalence,
    normalize::{self, ImapResult},
    report::Difference,
    transport::{self, Wire},
};
use std::io;
use std::time::Instant;

pub fn run(ca: &str, seed: u64) -> Result<Vec<Difference>, Box<dyn std::error::Error>> {
    let mut cases = crate::cases::imap::deterministic();
    cases.extend(crate::cases::imap::generated(seed));
    cases
        .into_iter()
        .map(|case| {
            let (mailer, transcript) = execute("mailer", 143, &case, ca)?;
            let (reference, _) = execute("dovecot", 143, &case, ca)?;
            let equivalent = mailer.tagged_statuses == reference.tagged_statuses
                && mailer.final_exists == reference.final_exists
                && mailer.expunged == reference.expunged
                && mailer.search_result_sizes == reference.search_result_sizes
                && mailer.tls == reference.tls
                && mailer.connection_closed == reference.connection_closed;
            Ok(compare_with_equivalence(
                "IMAP",
                &case.name,
                serde_json::to_value(mailer)?,
                serde_json::to_value(reference)?,
                equivalent,
                &transcript,
            ))
        })
        .collect()
}

fn execute(
    host: &str,
    port: u16,
    case: &Case,
    ca: &str,
) -> Result<(ImapResult, Vec<u8>), Box<dyn std::error::Error>> {
    let mut wire = Wire::connect((host, port))?;
    let deadline = Instant::now() + transport::CASE_TIMEOUT;
    let mut transcript = Vec::new();
    let mut lines = vec![transport::read_line(&mut wire)?];
    if case.start_tls {
        transport::send_chunks(&mut wire, &[b"A1 STARTTLS\r\n".to_vec()], &mut transcript)?;
        lines.extend(read_until_tag(&mut wire, "A1")?);
        wire = wire.start_tls(host, ca)?;
    }
    for step in &case.steps {
        wire.limit_to_deadline(deadline)?;
        match step {
            Step::Send(chunks) => transport::send_chunks(&mut wire, chunks, &mut transcript)?,
            Step::Continuation => lines.push(read_continuation(&mut wire)?),
            Step::Tagged(tag) => {
                lines.extend(read_until_tag(&mut wire, tag)?);
            }
        }
    }
    Ok((normalize::imap(&lines, case.start_tls, false), transcript))
}

fn read_continuation(wire: &mut Wire) -> io::Result<Vec<u8>> {
    let line = transport::read_line(wire)?;
    if line.first() != Some(&b'+') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "expected IMAP continuation",
        ));
    }
    Ok(line)
}

fn read_until_tag(wire: &mut Wire, tag: &str) -> io::Result<Vec<Vec<u8>>> {
    let mut lines = Vec::new();
    loop {
        let line = transport::read_line(wire)?;
        let done = std::str::from_utf8(&line).ok().is_some_and(|text| {
            text.split_ascii_whitespace()
                .next()
                .is_some_and(|value| value.eq_ignore_ascii_case(tag))
        });
        lines.push(line);
        if done {
            return Ok(lines);
        }
    }
}

pub fn server_version() -> io::Result<String> {
    let mut wire = Wire::connect(("dovecot", 143))?;
    let greeting = transport::read_line(&mut wire)?;
    Ok(format!(
        "Dovecot ({})",
        String::from_utf8_lossy(&greeting).trim()
    ))
}
