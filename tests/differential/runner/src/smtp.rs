use crate::{
    cases::smtp::{Case, Step},
    compare_with_equivalence,
    normalize::{self, SmtpReply, SmtpResult},
    report::Difference,
    transport::{self, Wire},
};
use std::collections::BTreeSet;
use std::io;
use std::time::Instant;

pub fn run(ca: &str, seed: u64) -> Result<Vec<Difference>, Box<dyn std::error::Error>> {
    let mut cases = crate::cases::smtp::deterministic();
    cases.extend(crate::cases::smtp::generated(seed));
    let mut results = Vec::new();
    for case in cases {
        let (mailer, transcript) = execute("mailer", 25, &case, ca)?;
        let (reference, _) = execute("postfix", 25, &case, ca)?;
        let equivalent = reply_codes(&mailer) == reply_codes(&reference)
            && mailer.accepted == reference.accepted
            && mailer.connection_closed == reference.connection_closed;
        results.push(compare_with_equivalence(
            "SMTP",
            &case.name,
            serde_json::to_value(mailer)?,
            serde_json::to_value(reference)?,
            equivalent,
            &transcript,
        ));
    }
    for host in ["mailer", "postfix"] {
        let (result, transcript) = starttls(host, ca)?;
        let reference = if host == "mailer" {
            starttls("postfix", ca)?.0
        } else {
            result.clone()
        };
        if host == "mailer" {
            let equivalent =
                reply_codes(&result) == reply_codes(&reference) && result.tls && reference.tls;
            results.push(compare_with_equivalence(
                "SMTP",
                "starttls",
                serde_json::to_value(result)?,
                serde_json::to_value(reference)?,
                equivalent,
                &transcript,
            ));
        }
    }
    Ok(results)
}

fn execute(host: &str, port: u16, case: &Case, _ca: &str) -> io::Result<(SmtpResult, Vec<u8>)> {
    let mut wire = Wire::connect((host, port))?;
    let deadline = Instant::now() + transport::CASE_TIMEOUT;
    let mut transcript = Vec::new();
    let greeting = read_reply(&mut wire)?;
    let mut replies = vec![greeting];
    let mut closed = false;
    for step in &case.steps {
        wire.limit_to_deadline(deadline)?;
        if let Step::Send(chunks) = step {
            transport::send_chunks(&mut wire, chunks, &mut transcript)?;
            continue;
        }
        if let Step::Disconnect = step {
            wire.shutdown()?;
            closed = true;
            continue;
        }
        match read_reply(&mut wire) {
            Ok(reply) => replies.push(reply),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut
                        | io::ErrorKind::WouldBlock
                        | io::ErrorKind::UnexpectedEof
                        | io::ErrorKind::ConnectionReset
                ) =>
            {
                closed = true;
                replies.push(SmtpReply {
                    code: 0,
                    enhanced_status: None,
                    multiline: false,
                    capabilities: BTreeSet::new(),
                });
                break;
            }
            Err(error) => return Err(error),
        }
    }
    let accepted = case.accepted && replies.last().is_some_and(|reply| reply.code == 250);
    closed |= replies
        .last()
        .is_some_and(|reply| reply.code == 221 || reply.code == 421);
    Ok((
        SmtpResult {
            replies,
            tls: false,
            accepted,
            connection_closed: closed,
        },
        transcript,
    ))
}

fn starttls(host: &str, ca: &str) -> io::Result<(SmtpResult, Vec<u8>)> {
    let mut wire = Wire::connect((host, 25))?;
    let deadline = Instant::now() + transport::CASE_TIMEOUT;
    wire.limit_to_deadline(deadline)?;
    let mut transcript = Vec::new();
    let mut replies = vec![read_reply(&mut wire)?];
    transport::send_chunks(
        &mut wire,
        &[b"EHLO client.example\r\n".to_vec()],
        &mut transcript,
    )?;
    replies.push(read_reply(&mut wire)?);
    transport::send_chunks(&mut wire, &[b"STARTTLS\r\n".to_vec()], &mut transcript)?;
    replies.push(read_reply(&mut wire)?);
    wire = wire.start_tls(host, ca)?;
    wire.limit_to_deadline(deadline)?;
    transport::send_chunks(
        &mut wire,
        &[b"EHLO client.example\r\n".to_vec()],
        &mut transcript,
    )?;
    replies.push(read_reply(&mut wire)?);
    Ok((
        SmtpResult {
            replies,
            tls: true,
            accepted: false,
            connection_closed: false,
        },
        transcript,
    ))
}

fn read_reply(wire: &mut Wire) -> io::Result<SmtpReply> {
    let mut lines = vec![transport::read_line(wire)?];
    let code = lines[0].get(..3).map(<[u8]>::to_vec);
    while lines.last().and_then(|line| line.get(3)).copied() == Some(b'-') {
        let line = transport::read_line(wire)?;
        let finished = code.as_deref().is_some_and(|value| line.starts_with(value))
            && line.get(3) == Some(&b' ');
        lines.push(line);
        if finished {
            break;
        }
    }
    normalize::smtp_reply(&lines)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "malformed SMTP reply"))
}

fn reply_codes(result: &SmtpResult) -> Vec<u16> {
    result.replies.iter().map(|reply| reply.code).collect()
}

pub fn server_version() -> io::Result<String> {
    let mut wire = Wire::connect(("postfix", 25))?;
    let greeting = transport::read_line(&mut wire)?;
    Ok(format!(
        "Postfix ({})",
        String::from_utf8_lossy(&greeting).trim()
    ))
}
