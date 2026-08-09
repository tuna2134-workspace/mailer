#[derive(Clone)]
pub enum Step {
    Send(Vec<Vec<u8>>),
    Continuation,
    Tagged(&'static str),
}

#[derive(Clone)]
pub struct Case {
    pub name: String,
    pub steps: Vec<Step>,
    pub start_tls: bool,
}

fn plain(name: &str, tag: &'static str, chunks: Vec<Vec<u8>>) -> Case {
    Case {
        name: name.into(),
        steps: vec![Step::Send(chunks), Step::Tagged(tag)],
        start_tls: false,
    }
}

fn authenticated(name: &str, command: Vec<u8>, tag: &'static str) -> Case {
    Case {
        name: name.into(),
        steps: vec![
            Step::Send(vec![b"A2 LOGIN imap@example.test secret\r\n".to_vec()]),
            Step::Tagged("A2"),
            Step::Send(vec![command]),
            Step::Tagged(tag),
        ],
        start_tls: true,
    }
}

pub fn deterministic() -> Vec<Case> {
    let mut cases = plain_cases();
    cases.extend(authenticated_cases());
    cases
}

fn plain_cases() -> Vec<Case> {
    vec![
        plain("capability", "A1", vec![b"A1 CAPABILITY\r\n".to_vec()]),
        plain("noop", "A1", vec![b"A1 NOOP\r\n".to_vec()]),
        plain(
            "pre_tls_login",
            "A1",
            vec![b"A1 LOGIN imap@example.test secret\r\n".to_vec()],
        ),
        plain("malformed", "A1", vec![b"A1 @@@\r\n".to_vec()]),
        plain(
            "malformed_literal",
            "A1",
            vec![b"A1 APPEND INBOX {x}\r\n".to_vec()],
        ),
        plain(
            "coalesced",
            "A2",
            vec![b"A1 NOOP\r\nA2 CAPABILITY\r\n".to_vec()],
        ),
        plain(
            "fragmented",
            "A1",
            vec![b"A1 CAP".to_vec(), b"ABILITY\r\n".to_vec()],
        ),
    ]
}

fn authenticated_cases() -> Vec<Case> {
    vec![
        authenticated("login", b"A3 NOOP\r\n".to_vec(), "A3"),
        authenticated("list", b"A3 LIST \"\" \"*\"\r\n".to_vec(), "A3"),
        authenticated(
            "status",
            b"A3 STATUS INBOX (MESSAGES UIDNEXT UIDVALIDITY)\r\n".to_vec(),
            "A3",
        ),
        authenticated("select", b"A3 SELECT INBOX\r\n".to_vec(), "A3"),
        authenticated("examine", b"A3 EXAMINE INBOX\r\n".to_vec(), "A3"),
        append_case(),
        authenticated(
            "fetch",
            b"A3 SELECT INBOX\r\nA4 FETCH 1:* (UID FLAGS RFC822.SIZE)\r\n".to_vec(),
            "A4",
        ),
        authenticated(
            "uid_fetch",
            b"A3 SELECT INBOX\r\nA4 UID FETCH 1:* (UID FLAGS)\r\n".to_vec(),
            "A4",
        ),
        authenticated(
            "search",
            b"A3 SELECT INBOX\r\nA4 SEARCH ALL\r\n".to_vec(),
            "A4",
        ),
        authenticated(
            "uid_search",
            b"A3 SELECT INBOX\r\nA4 UID SEARCH ALL\r\n".to_vec(),
            "A4",
        ),
        authenticated(
            "store",
            b"A3 SELECT INBOX\r\nA4 STORE 1 +FLAGS (\\Seen)\r\n".to_vec(),
            "A4",
        ),
        authenticated(
            "uid_store",
            b"A3 SELECT INBOX\r\nA4 UID STORE 1:* +FLAGS (\\Flagged)\r\n".to_vec(),
            "A4",
        ),
        Case {
            name: "copy_move_expunge".into(),
            steps: vec![
                Step::Send(vec![b"A2 LOGIN imap@example.test secret\r\n".to_vec()]),
                Step::Tagged("A2"),
                Step::Send(vec![b"A3 CREATE DiffArchive\r\n".to_vec()]),
                Step::Tagged("A3"),
                Step::Send(vec![b"A4 SELECT INBOX\r\n".to_vec()]),
                Step::Tagged("A4"),
                Step::Send(vec![b"A5 COPY 1 DiffArchive\r\n".to_vec()]),
                Step::Tagged("A5"),
                Step::Send(vec![b"A6 UID COPY 1:* DiffArchive\r\n".to_vec()]),
                Step::Tagged("A6"),
                Step::Send(vec![b"A7 MOVE 1 DiffArchive\r\n".to_vec()]),
                Step::Tagged("A7"),
                Step::Send(vec![b"A8 EXPUNGE\r\n".to_vec()]),
                Step::Tagged("A8"),
            ],
            start_tls: true,
        },
        Case {
            name: "idle".into(),
            steps: vec![
                Step::Send(vec![b"A2 LOGIN imap@example.test secret\r\n".to_vec()]),
                Step::Tagged("A2"),
                Step::Send(vec![b"A3 SELECT INBOX\r\n".to_vec()]),
                Step::Tagged("A3"),
                Step::Send(vec![b"A4 IDLE\r\n".to_vec()]),
                Step::Continuation,
                Step::Send(vec![b"DONE\r\n".to_vec()]),
                Step::Tagged("A4"),
            ],
            start_tls: true,
        },
        authenticated(
            "condstore",
            b"A3 SELECT INBOX (CONDSTORE)\r\nA4 UID FETCH 1:* (FLAGS) (CHANGEDSINCE 1)\r\n".to_vec(),
            "A4",
        ),
        authenticated(
            "unchangedsince",
            b"A3 SELECT INBOX (CONDSTORE)\r\nA4 UID STORE 1:* (UNCHANGEDSINCE 1) +FLAGS (\\Seen)\r\n".to_vec(),
            "A4",
        ),
        authenticated("logout", b"A3 LOGOUT\r\n".to_vec(), "A3"),
    ]
}

fn append_case() -> Case {
    let message =
        b"From: sender@example.test\r\nTo: imap@example.test\r\nSubject: appended\r\n\r\nbody\r\n";
    Case {
        name: "append_literal_fragmented".into(),
        steps: vec![
            Step::Send(vec![b"A2 LOGIN imap@example.test secret\r\n".to_vec()]),
            Step::Tagged("A2"),
            Step::Send(vec![
                format!("A3 APPEND INBOX {{{}}}\r\n", message.len()).into_bytes(),
            ]),
            Step::Continuation,
            Step::Send(vec![
                message[..17].to_vec(),
                message[17..].to_vec(),
                b"\r\n".to_vec(),
            ]),
            Step::Tagged("A3"),
        ],
        start_tls: true,
    }
}

pub fn generated(seed: u64) -> Vec<Case> {
    ["CAPABILITY", "capability", "CaPaBiLiTy"]
        .into_iter()
        .enumerate()
        .map(|(index, command)| {
            let tag: &'static str = Box::leak(format!("G{index}").into_boxed_str());
            let line = format!("{tag} {command}\r\n").into_bytes();
            let width = u64::try_from(line.len() - 1).unwrap_or(1);
            let offset = (seed + u64::try_from(index).unwrap_or(0) * 5) % width;
            let split = 1 + usize::try_from(offset).unwrap_or(0);
            plain(
                &format!("generated_capability_{index}"),
                tag,
                vec![line[..split].to_vec(), line[split..].to_vec()],
            )
        })
        .collect()
}
