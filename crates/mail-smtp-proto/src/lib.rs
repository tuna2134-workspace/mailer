#![forbid(unsafe_code)]

use thiserror::Error;

pub const MAX_COMMAND_LINE: usize = 512;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Command {
    Ehlo(String),
    Helo(String),
    Mail { reverse_path: String },
    Rcpt { forward_path: String },
    Data,
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
        "MAIL" => parse_path(argument, "FROM:").map(|reverse_path| Command::Mail { reverse_path }),
        "RCPT" => parse_path(argument, "TO:").and_then(|forward_path| {
            if forward_path.is_empty() {
                Err(ParseError::InvalidSyntax)
            } else {
                Ok(Command::Rcpt { forward_path })
            }
        }),
        "DATA" if argument.is_none() => Ok(Command::Data),
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

fn parse_path(argument: Option<&str>, prefix: &str) -> Result<String, ParseError> {
    let argument = argument.ok_or(ParseError::InvalidSyntax)?;
    let Some(rest) = argument
        .get(..prefix.len())
        .filter(|value| value.eq_ignore_ascii_case(prefix))
        .and_then(|_| argument.get(prefix.len()..))
    else {
        return Err(ParseError::InvalidSyntax);
    };
    let rest = rest.trim_start();
    let end = rest.find('>').ok_or(ParseError::InvalidSyntax)?;
    if !rest.starts_with('<') || !rest[end + 1..].trim().is_empty() {
        return Err(ParseError::InvalidSyntax);
    }
    let path = &rest[1..end];
    if path.contains(['<', '>', '\r', '\n', ' ']) || (!path.is_empty() && !path.contains('@')) {
        return Err(ParseError::InvalidSyntax);
    }
    Ok(path.to_owned())
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
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Action {
    Reply(Reply),
    Recipient(String),
    BeginData(Transaction),
    Quit(Reply),
}

impl Session {
    #[must_use]
    pub fn new(max_recipients: usize) -> Self {
        Self {
            state: SessionState::Connected,
            peer_name: None,
            max_recipients,
        }
    }

    pub fn command(&mut self, command: Command) -> Action {
        match command {
            Command::Ehlo(name) | Command::Helo(name) => {
                self.peer_name = Some(name);
                self.state = SessionState::Greeted;
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
            Command::Mail { reverse_path }
                if matches!(self.state, SessionState::Greeted | SessionState::Mail(_)) =>
            {
                self.state = SessionState::Mail(Transaction {
                    reverse_path,
                    recipients: Vec::new(),
                });
                ok("Sender OK")
            }
            Command::Rcpt { forward_path } => match &self.state {
                SessionState::Mail(transaction)
                    if transaction.recipients.len() >= self.max_recipients =>
                {
                    Action::Reply(Reply {
                        code: 452,
                        enhanced: Some("4.5.3"),
                        text: "Too many recipients",
                    })
                }
                SessionState::Mail(_) => Action::Recipient(forward_path),
                _ => bad_sequence(),
            },
            Command::Data => match &self.state {
                SessionState::Mail(transaction) if !transaction.recipients.is_empty() => {
                    Action::BeginData(transaction.clone())
                }
                _ => bad_sequence(),
            },
            Command::Mail { .. } => bad_sequence(),
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
            Action::Reply(Reply { code: 250, .. })
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
}
