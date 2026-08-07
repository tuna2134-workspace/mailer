#![forbid(unsafe_code)]

use thiserror::Error;

mod extensions;
pub use extensions::{BodyKind, MailParameters, RcptParameters, parse_mail, parse_rcpt};

pub const MAX_COMMAND_LINE: usize = 512;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Command {
    Ehlo(String),
    Helo(String),
    Mail {
        reverse_path: String,
        parameters: MailParameters,
    },
    Rcpt {
        forward_path: String,
        parameters: RcptParameters,
    },
    Data,
    Bdat {
        size: u64,
        last: bool,
    },
    StartTls,
    Auth {
        mechanism: String,
        initial_response: Option<String>,
    },
    Rset,
    Noop(Option<String>),
    Quit,
    Help(Option<String>),
    Vrfy(String),
    Unknown(String),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParseError {
    LineTooLong,
    BareLf,
    InvalidEncoding,
    InvalidSyntax,
}

pub fn parse_command(line: &[u8], allow_bare_lf: bool) -> Result<Command, ParseError> {
    if line.len() > MAX_COMMAND_LINE {
        return Err(ParseError::LineTooLong);
    }
    let content = match line.strip_suffix(b"\r\n") {
        Some(value) => value,
        None if allow_bare_lf => line.strip_suffix(b"\n").ok_or(ParseError::InvalidSyntax)?,
        None if line.ends_with(b"\n") => return Err(ParseError::BareLf),
        None => return Err(ParseError::InvalidSyntax),
    };
    let text = std::str::from_utf8(content).map_err(|_| ParseError::InvalidEncoding)?;
    let (verb, argument) = text
        .split_once(' ')
        .map_or((text, None), |(verb, rest)| (verb, Some(rest)));
    let verb = verb.to_ascii_uppercase();
    match verb.as_str() {
        "EHLO" => hello(argument).map(Command::Ehlo),
        "HELO" => hello(argument).map(Command::Helo),
        "MAIL" => parse_mail(argument).map(|(reverse_path, parameters)| Command::Mail {
            reverse_path,
            parameters,
        }),
        "RCPT" => parse_rcpt(argument).map(|(forward_path, parameters)| Command::Rcpt {
            forward_path,
            parameters,
        }),
        "DATA" if argument.is_none() => Ok(Command::Data),
        "BDAT" => parse_bdat(argument),
        "STARTTLS" if argument.is_none() => Ok(Command::StartTls),
        "AUTH" => parse_auth(argument),
        "RSET" if argument.is_none() => Ok(Command::Rset),
        "NOOP" => Ok(Command::Noop(argument.map(str::to_owned))),
        "QUIT" if argument.is_none() => Ok(Command::Quit),
        "HELP" => Ok(Command::Help(argument.map(str::to_owned))),
        "VRFY" => required(argument).map(Command::Vrfy),
        _ => Ok(Command::Unknown(verb)),
    }
}

fn required(argument: Option<&str>) -> Result<String, ParseError> {
    argument
        .filter(|value| !value.is_empty() && !value.contains(['\r', '\n']))
        .map(str::to_owned)
        .ok_or(ParseError::InvalidSyntax)
}

fn hello(argument: Option<&str>) -> Result<String, ParseError> {
    let value = required(argument)?;
    if value.len() > 255
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'[' | b']' | b':')
        })
    {
        return Err(ParseError::InvalidSyntax);
    }
    Ok(value)
}

fn parse_bdat(argument: Option<&str>) -> Result<Command, ParseError> {
    let mut parts = argument
        .ok_or(ParseError::InvalidSyntax)?
        .split_ascii_whitespace();
    let size = parts
        .next()
        .ok_or(ParseError::InvalidSyntax)?
        .parse()
        .map_err(|_| ParseError::InvalidSyntax)?;
    let last = match parts.next() {
        None => false,
        Some(value) if value.eq_ignore_ascii_case("LAST") => true,
        _ => return Err(ParseError::InvalidSyntax),
    };
    if parts.next().is_some() {
        return Err(ParseError::InvalidSyntax);
    }
    Ok(Command::Bdat { size, last })
}

fn parse_auth(argument: Option<&str>) -> Result<Command, ParseError> {
    let mut parts = argument
        .ok_or(ParseError::InvalidSyntax)?
        .split_ascii_whitespace();
    let mechanism = parts
        .next()
        .filter(|value| !value.is_empty() && value.is_ascii())
        .ok_or(ParseError::InvalidSyntax)?
        .to_ascii_uppercase();
    let initial_response = parts.next().map(str::to_owned);
    if parts.next().is_some() {
        return Err(ParseError::InvalidSyntax);
    }
    Ok(Command::Auth {
        mechanism,
        initial_response,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Reply {
    pub code: u16,
    pub enhanced: Option<&'static str>,
    pub text: &'static str,
}

impl Reply {
    #[must_use]
    pub fn line(&self) -> String {
        self.enhanced.map_or_else(
            || format!("{} {}\r\n", self.code, self.text),
            |enhanced| format!("{} {} {}\r\n", self.code, enhanced, self.text),
        )
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Transaction {
    pub reverse_path: String,
    pub recipients: Vec<String>,
    pub parameters: MailParameters,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::struct_excessive_bools)]
pub struct SessionExtensions {
    pub hostname: String,
    pub max_message_size: u64,
    pub starttls: bool,
    pub auth_plain: bool,
    pub dsn: bool,
    pub chunking: bool,
    pub smtp_utf8: bool,
    pub require_tls: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SessionState {
    Connected,
    Greeted,
    Mail(Transaction),
}

#[derive(Clone, Debug)]
pub struct Session {
    pub state: SessionState,
    pub peer_name: Option<String>,
    max_recipients: usize,
    extensions: SessionExtensions,
    tls_active: bool,
    authenticated: bool,
    extended_hello: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Action {
    Reply(Reply),
    Recipient(String),
    BeginData(Transaction),
    BeginBdat {
        transaction: Transaction,
        size: u64,
        last: bool,
    },
    StartTls(Reply),
    Authenticate {
        mechanism: String,
        initial_response: Option<String>,
    },
    Ehlo {
        greeting: Reply,
        capabilities: Vec<String>,
    },
    Quit(Reply),
}

impl Session {
    #[must_use]
    pub fn new(max_recipients: usize) -> Self {
        Self::with_extensions(
            max_recipients,
            SessionExtensions {
                hostname: "localhost".into(),
                max_message_size: u64::MAX,
                starttls: false,
                auth_plain: false,
                dsn: false,
                chunking: false,
                smtp_utf8: false,
                require_tls: false,
            },
        )
    }

    #[must_use]
    pub fn with_extensions(max_recipients: usize, extensions: SessionExtensions) -> Self {
        Self {
            state: SessionState::Connected,
            peer_name: None,
            max_recipients,
            extensions,
            tls_active: false,
            authenticated: false,
            extended_hello: false,
        }
    }

    #[allow(clippy::too_many_lines)]
    pub fn command(&mut self, command: Command) -> Action {
        match command {
            Command::Ehlo(name) => {
                self.peer_name = Some(name);
                self.state = SessionState::Greeted;
                self.extended_hello = true;
                Action::Ehlo {
                    greeting: Reply {
                        code: 250,
                        enhanced: None,
                        text: "Hello",
                    },
                    capabilities: self.capabilities(),
                }
            }
            Command::Helo(name) => {
                self.peer_name = Some(name);
                self.state = SessionState::Greeted;
                self.extended_hello = false;
                ok("Hello")
            }
            Command::Quit => Action::Quit(Reply {
                code: 221,
                enhanced: Some("2.0.0"),
                text: "Bye",
            }),
            Command::Noop(_) => ok("OK"),
            Command::Help(_) => Action::Reply(Reply {
                code: 214,
                enhanced: None,
                text: "Commands: EHLO HELO MAIL RCPT DATA RSET NOOP QUIT HELP VRFY",
            }),
            Command::Vrfy(_) => Action::Reply(Reply {
                code: 252,
                enhanced: Some("2.5.2"),
                text: "Cannot VRFY user",
            }),
            Command::Rset => {
                self.state = if self.peer_name.is_some() {
                    SessionState::Greeted
                } else {
                    SessionState::Connected
                };
                ok("Reset state")
            }
            Command::StartTls
                if self.extended_hello && self.extensions.starttls && !self.tls_active =>
            {
                Action::StartTls(Reply {
                    code: 220,
                    enhanced: Some("2.0.0"),
                    text: "Ready to start TLS",
                })
            }
            Command::Auth {
                mechanism,
                initial_response,
            } if self.extended_hello
                && self.extensions.auth_plain
                && self.tls_active
                && !self.authenticated =>
            {
                Action::Authenticate {
                    mechanism,
                    initial_response,
                }
            }
            Command::Mail {
                reverse_path,
                parameters,
            } if matches!(self.state, SessionState::Greeted | SessionState::Mail(_)) => {
                if parameters
                    .size
                    .is_some_and(|size| size > self.extensions.max_message_size)
                    || parameters.body == BodyKind::BinaryMime && !self.extensions.chunking
                    || parameters.smtp_utf8 && !self.extensions.smtp_utf8
                    || parameters.require_tls && !self.extensions.require_tls
                    || (parameters.ret.is_some() || parameters.envid.is_some())
                        && !self.extensions.dsn
                {
                    return Action::Reply(Reply {
                        code: 555,
                        enhanced: Some("5.5.4"),
                        text: "Unsupported MAIL FROM parameter",
                    });
                }
                self.state = SessionState::Mail(Transaction {
                    reverse_path,
                    recipients: Vec::new(),
                    parameters,
                });
                ok("Sender OK")
            }
            Command::Rcpt {
                forward_path,
                parameters,
            } => match &self.state {
                SessionState::Mail(transaction)
                    if transaction.recipients.len() >= self.max_recipients =>
                {
                    Action::Reply(Reply {
                        code: 452,
                        enhanced: Some("4.5.3"),
                        text: "Too many recipients",
                    })
                }
                SessionState::Mail(transaction)
                    if (!forward_path.is_ascii() && !transaction.parameters.smtp_utf8)
                        || ((parameters.notify.is_some() || parameters.orcpt.is_some())
                            && !self.extensions.dsn) =>
                {
                    Action::Reply(Reply {
                        code: 555,
                        enhanced: Some("5.5.4"),
                        text: "Unsupported RCPT TO parameter",
                    })
                }
                SessionState::Mail(_) => Action::Recipient(forward_path),
                _ => bad_sequence(),
            },
            Command::Data => match &self.state {
                SessionState::Mail(transaction)
                    if !transaction.recipients.is_empty()
                        && transaction.parameters.body != BodyKind::BinaryMime =>
                {
                    Action::BeginData(transaction.clone())
                }
                _ => bad_sequence(),
            },
            Command::Bdat { size, last } if self.extensions.chunking => match &self.state {
                SessionState::Mail(transaction) if !transaction.recipients.is_empty() => {
                    Action::BeginBdat {
                        transaction: transaction.clone(),
                        size,
                        last,
                    }
                }
                _ => bad_sequence(),
            },
            Command::Mail { .. }
            | Command::Bdat { .. }
            | Command::StartTls
            | Command::Auth { .. } => bad_sequence(),
            Command::Unknown(_) => Action::Reply(Reply {
                code: 500,
                enhanced: Some("5.5.2"),
                text: "Command unrecognized",
            }),
        }
    }

    pub fn accept_recipient(&mut self, recipient: String) {
        if let SessionState::Mail(transaction) = &mut self.state {
            transaction.recipients.push(recipient);
        }
    }

    pub fn finish_data(&mut self) {
        self.state = SessionState::Greeted;
    }

    pub fn reset_after_tls(&mut self) {
        self.state = SessionState::Connected;
        self.peer_name = None;
        self.extended_hello = false;
        self.authenticated = false;
        self.tls_active = true;
    }

    pub fn authentication_succeeded(&mut self) {
        self.authenticated = true;
    }

    fn capabilities(&self) -> Vec<String> {
        let mut values = vec![
            self.extensions.hostname.clone(),
            format!("SIZE {}", self.extensions.max_message_size),
            "PIPELINING".into(),
            "8BITMIME".into(),
            "ENHANCEDSTATUSCODES".into(),
        ];
        if self.extensions.smtp_utf8 {
            values.push("SMTPUTF8".into());
        }
        if self.extensions.dsn {
            values.push("DSN".into());
        }
        if self.extensions.chunking {
            values.push("CHUNKING".into());
            values.push("BINARYMIME".into());
        }
        if self.extensions.starttls && !self.tls_active {
            values.push("STARTTLS".into());
        }
        if self.extensions.auth_plain && self.tls_active {
            values.push("AUTH PLAIN".into());
        }
        if self.extensions.require_tls {
            values.push("REQUIRETLS".into());
        }
        values
    }
}

fn ok(text: &'static str) -> Action {
    Action::Reply(Reply {
        code: 250,
        enhanced: Some("2.0.0"),
        text,
    })
}

fn bad_sequence() -> Action {
    Action::Reply(Reply {
        code: 503,
        enhanced: Some("5.5.1"),
        text: "Bad sequence of commands",
    })
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum DataError {
    #[error("message exceeds configured size")]
    TooLarge,
    #[error("bare LF is forbidden")]
    BareLf,
    #[error("DATA line exceeds the protocol limit")]
    LineTooLong,
}

pub fn unstuff_data_line(line: &[u8], allow_bare_lf: bool) -> Result<Option<&[u8]>, DataError> {
    if line == b".\r\n" || (allow_bare_lf && line == b".\n") {
        return Ok(None);
    }
    if line.ends_with(b"\n") && !line.ends_with(b"\r\n") && !allow_bare_lf {
        return Err(DataError::BareLf);
    }
    Ok(Some(if line.starts_with(b"..") {
        &line[1..]
    } else {
        line
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parser_and_state_transcript() -> Result<(), ParseError> {
        let mut session = Session::new(2);
        assert!(matches!(
            session.command(parse_command(b"DATA\r\n", false)?),
            Action::Reply(Reply { code: 503, .. })
        ));
        assert!(matches!(
            session.command(parse_command(b"EHLO client.example\r\n", false)?),
            Action::Ehlo {
                greeting: Reply { code: 250, .. },
                ..
            }
        ));
        assert!(matches!(
            session.command(parse_command(b"MAIL FROM:<>\r\n", false)?),
            Action::Reply(Reply { code: 250, .. })
        ));
        assert!(matches!(
            session.command(parse_command(b"RCPT TO:<alice@example.test>\r\n", false)?),
            Action::Recipient(_)
        ));
        session.accept_recipient("alice@example.test".into());
        assert!(matches!(
            session.command(parse_command(b"DATA\r\n", false)?),
            Action::BeginData(_)
        ));
        assert_eq!(
            unstuff_data_line(b"..leading\r\n", false).map_err(|_| ParseError::InvalidSyntax)?,
            Some(&b".leading\r\n"[..])
        );
        assert_eq!(
            unstuff_data_line(b".\r\n", false).map_err(|_| ParseError::InvalidSyntax)?,
            None
        );
        Ok(())
    }

    #[test]
    fn rejects_smuggling_shapes() {
        assert_eq!(
            parse_command(b"MAIL FROM:<a@b>\nRCPT TO:<x@y>\r\n", false),
            Err(ParseError::InvalidSyntax)
        );
        assert_eq!(parse_command(b"NOOP\n", false), Err(ParseError::BareLf));
        assert_eq!(
            parse_command(&vec![b'A'; 513], false),
            Err(ParseError::LineTooLong)
        );
    }

    #[test]
    fn parses_phase_seven_parameters_and_rejects_duplicates() {
        assert!(matches!(
            parse_command(
                b"MAIL FROM:<sender@example.test> SIZE=42 BODY=8BITMIME SMTPUTF8\r\n",
                false
            ),
            Ok(Command::Mail {
                parameters: MailParameters {
                    size: Some(42),
                    body: BodyKind::EightBitMime,
                    smtp_utf8: true,
                    ..
                },
                ..
            })
        ));
        assert_eq!(
            parse_command(
                b"MAIL FROM:<sender@example.test> BODY=7BIT BODY=7BIT\r\n",
                false
            ),
            Err(ParseError::InvalidSyntax)
        );
        assert!(
            parse_command(b"MAIL FROM:<sender@example.test> ENVID=job+2Bid\r\n", false).is_ok()
        );
        assert_eq!(
            parse_command(b"MAIL FROM:<sender@example.test> ENVID=job+xx\r\n", false),
            Err(ParseError::InvalidSyntax)
        );
        assert_eq!(
            parse_command(b"BDAT 12 LAST\r\n", false),
            Ok(Command::Bdat {
                size: 12,
                last: true
            })
        );
    }

    #[test]
    fn starttls_resets_session_and_gates_auth() {
        let mut session = Session::with_extensions(
            10,
            SessionExtensions {
                hostname: "mail.example.test".into(),
                max_message_size: 1024,
                starttls: true,
                auth_plain: true,
                dsn: false,
                chunking: true,
                smtp_utf8: false,
                require_tls: false,
            },
        );
        let Action::Ehlo { capabilities, .. } = session.command(Command::Ehlo("client".into()))
        else {
            panic!("EHLO action expected");
        };
        assert!(capabilities.iter().any(|value| value == "STARTTLS"));
        assert!(!capabilities.iter().any(|value| value.starts_with("AUTH")));
        assert!(matches!(
            session.command(Command::StartTls),
            Action::StartTls(_)
        ));
        session.reset_after_tls();
        assert!(matches!(
            session.command(Command::Auth {
                mechanism: "PLAIN".into(),
                initial_response: None,
            }),
            Action::Reply(Reply { code: 503, .. })
        ));
        let Action::Ehlo { capabilities, .. } = session.command(Command::Ehlo("client".into()))
        else {
            panic!("EHLO action expected");
        };
        assert!(!capabilities.iter().any(|value| value == "STARTTLS"));
        assert!(capabilities.iter().any(|value| value == "AUTH PLAIN"));
    }
}
