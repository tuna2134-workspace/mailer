#[derive(Clone)]
pub enum Step {
    Send(Vec<Vec<u8>>),
    Reply,
    Disconnect,
}

#[derive(Clone)]
pub struct Case {
    pub name: String,
    pub steps: Vec<Step>,
    pub accepted: bool,
}

fn dialogue(name: &str, commands: &[&[u8]]) -> Case {
    let mut steps = Vec::with_capacity(commands.len() * 2);
    for command in commands {
        steps.push(Step::Send(vec![command.to_vec()]));
        steps.push(Step::Reply);
    }
    Case {
        name: name.into(),
        steps,
        accepted: false,
    }
}

fn transaction(name: &str, body: &[u8]) -> Case {
    let mut case = dialogue(
        name,
        &[
            b"EHLO client.example\r\n",
            b"MAIL FROM:<sender@example.test>\r\n",
            b"RCPT TO:<alice@example.test>\r\n",
            b"DATA\r\n",
            body,
        ],
    );
    case.accepted = true;
    case
}

fn bdat(name: &str, chunks: &[(&[u8], bool)]) -> Case {
    let mut case = dialogue(
        name,
        &[
            b"EHLO client.example\r\n",
            b"MAIL FROM:<sender@example.test>\r\n",
            b"RCPT TO:<alice@example.test>\r\n",
        ],
    );
    for (bytes, last) in chunks {
        let suffix = if *last { " LAST" } else { "" };
        let mut command = format!("BDAT {}{suffix}\r\n", bytes.len()).into_bytes();
        command.extend_from_slice(bytes);
        case.steps.push(Step::Send(vec![command]));
        case.steps.push(Step::Reply);
    }
    case.accepted = chunks.last().is_some_and(|(_, last)| *last);
    case
}

fn noop_line(name: &str, octets: usize) -> Case {
    let mut command = b"NOOP ".to_vec();
    command.resize(octets.saturating_sub(2), b'a');
    command.extend_from_slice(b"\r\n");
    dialogue(name, &[&command])
}

fn data_line(name: &str, line_octets: usize) -> Case {
    let mut body = b"Subject: line limit\r\n\r\n".to_vec();
    body.resize(body.len() + line_octets.saturating_sub(2), b'a');
    body.extend_from_slice(b"\r\n.\r\n");
    transaction(name, &body)
}

pub fn deterministic() -> Vec<Case> {
    let mut cases = basic_cases();
    cases.extend(transaction_cases());
    cases
}

fn basic_cases() -> Vec<Case> {
    vec![
        dialogue("ehlo", &[b"EHLO client.example\r\n"]),
        dialogue("helo", &[b"HELO client.example\r\n"]),
        dialogue(
            "duplicate_ehlo",
            &[b"EHLO client.example\r\n", b"EHLO second.example\r\n"],
        ),
        dialogue(
            "mail_before_greeting",
            &[b"MAIL FROM:<sender@example.test>\r\n"],
        ),
        dialogue(
            "rcpt_before_mail",
            &[
                b"EHLO client.example\r\n",
                b"RCPT TO:<alice@example.test>\r\n",
            ],
        ),
        dialogue(
            "data_before_rcpt",
            &[
                b"EHLO client.example\r\n",
                b"MAIL FROM:<sender@example.test>\r\n",
                b"DATA\r\n",
            ],
        ),
        dialogue(
            "rset",
            &[
                b"EHLO client.example\r\n",
                b"MAIL FROM:<sender@example.test>\r\n",
                b"RSET\r\n",
                b"NOOP\r\n",
            ],
        ),
        dialogue("rset_initial", &[b"RSET\r\n", b"NOOP\r\n"]),
        dialogue(
            "rset_after_rcpt",
            &[
                b"EHLO client.example\r\n",
                b"MAIL FROM:<sender@example.test>\r\n",
                b"RCPT TO:<alice@example.test>\r\n",
                b"RSET\r\n",
                b"NOOP\r\n",
            ],
        ),
        dialogue("noop_initial", &[b"NOOP\r\n"]),
        noop_line("command_line_512", 512),
        noop_line("command_line_513", 513),
        dialogue("vrfy", &[b"EHLO client.example\r\n", b"VRFY alice\r\n"]),
        dialogue(
            "unknown",
            &[b"EHLO client.example\r\n", b"WAT\r\n", b"NOOP\r\n"],
        ),
        dialogue("quit", &[b"QUIT\r\n"]),
        dialogue(
            "pre_tls_auth",
            &[
                b"EHLO client.example\r\n",
                b"AUTH PLAIN AGFsaWNlAHNlY3JldA==\r\n",
            ],
        ),
        dialogue(
            "smtputf8_dsn",
            &[
                b"EHLO client.example\r\n",
                b"MAIL FROM:<sender@example.test> SMTPUTF8 RET=FULL ENVID=diff-1\r\n",
                b"RCPT TO:<alice@example.test> NOTIFY=FAILURE,DELAY ORCPT=rfc822;alice@example.test\r\n",
                b"RSET\r\n",
            ],
        ),
        dialogue(
            "malformed_bdat",
            &[b"EHLO client.example\r\n", b"BDAT nope LAST\r\n"],
        ),
    ]
}

fn transaction_cases() -> Vec<Case> {
    vec![
        transaction(
            "normal",
            b"From: sender@example.test\r\nTo: alice@example.test\r\nSubject: differential\r\n\r\nhello\r\n.\r\n",
        ),
        transaction(
            "dot_transparency",
            b"From: sender@example.test\r\nTo: alice@example.test\r\n\r\n..dot\r\n...two\r\n.\r\n",
        ),
        transaction("zero_length_message", b".\r\n"),
        data_line("data_line_1000", 1000),
        data_line("data_line_1001", 1001),
        {
            let mut case = transaction(
                "null_reverse_path",
                b"From: postmaster@example.test\r\n\r\nnotification\r\n.\r\n",
            );
            case.steps[2] = Step::Send(vec![b"MAIL FROM:<>\r\n".to_vec()]);
            case
        },
        dialogue(
            "multiple_recipients",
            &[
                b"EHLO client.example\r\n",
                b"MAIL FROM:<sender@example.test>\r\n",
                b"RCPT TO:<alice@example.test>\r\n",
                b"RCPT TO:<alice@example.test>\r\n",
                b"RSET\r\n",
            ],
        ),
        dialogue(
            "nonexistent_recipient",
            &[
                b"EHLO client.example\r\n",
                b"MAIL FROM:<sender@example.test>\r\n",
                b"RCPT TO:<nobody@example.test>\r\n",
            ],
        ),
        dialogue(
            "relay_denied",
            &[
                b"EHLO client.example\r\n",
                b"MAIL FROM:<sender@example.test>\r\n",
                b"RCPT TO:<recipient@external.invalid>\r\n",
            ],
        ),
        Case {
            name: "pipelining".into(),
            steps: vec![
                Step::Send(vec![b"EHLO client.example\r\n".to_vec()]),
                Step::Reply,
                Step::Send(vec![b"MAIL FROM:<sender@example.test>\r\nRCPT TO:<alice@example.test>\r\nRSET\r\n".to_vec()]),
                Step::Reply,
                Step::Reply,
                Step::Reply,
            ],
            accepted: false,
        },
        dialogue("bare_lf", &[b"EHLO client.example\n"]),
        dialogue("cr_without_lf", &[b"EHLO client.example\rNOOP\r\n"]),
        dialogue(
            "smuggling_shape",
            &[b"EHLO client.example\r\n", b"MAIL FROM:<sender@example.test>\r\nRCPT TO:<alice@example.test>\nDATA\r\n"],
        ),
        bdat("bdat_zero_last", &[(b"", true)]),
        bdat("bdat_multiple", &[(b"Subject: bdat\r\n\r\n", false), (b"body\r\n", true)]),
        Case {
            name: "truncated_bdat".into(),
            steps: vec![
                Step::Send(vec![b"EHLO client.example\r\n".to_vec()]),
                Step::Reply,
                Step::Send(vec![b"MAIL FROM:<sender@example.test>\r\n".to_vec()]),
                Step::Reply,
                Step::Send(vec![b"RCPT TO:<alice@example.test>\r\n".to_vec()]),
                Step::Reply,
                Step::Send(vec![b"BDAT 5 LAST\r\nabc".to_vec()]),
                Step::Disconnect,
            ],
            accepted: false,
        },
    ]
}

pub fn generated(seed: u64) -> Vec<Case> {
    let forms: [&[u8]; 4] = [
        b"EHLO generated.example\r\n",
        b"ehlo generated.example\r\n",
        b"EhLo generated.example\r\n",
        b"EHLO\tgenerated.example\r\n",
    ];
    forms
        .into_iter()
        .enumerate()
        .map(|(index, command)| {
            let width = u64::try_from(command.len() - 1).unwrap_or(1);
            let offset = (seed + u64::try_from(index).unwrap_or(0) * 7) % width;
            let split = 1 + usize::try_from(offset).unwrap_or(0);
            Case {
                name: format!("generated_ehlo_{index}"),
                steps: vec![
                    Step::Send(vec![command[..split].to_vec(), command[split..].to_vec()]),
                    Step::Reply,
                ],
                accepted: false,
            }
        })
        .collect()
}
