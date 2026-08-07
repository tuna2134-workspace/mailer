use crate::{MAX_COMMAND_LINE, MAX_TAG_BYTES};
use thiserror::Error;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AString(pub Vec<u8>);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MailboxName(Vec<u8>);

impl MailboxName {
    pub fn new(value: Vec<u8>) -> Result<Self, ParseError> {
        if value.is_empty() || value.len() > 4096 || value.contains(&0) {
            return Err(ParseError::InvalidSyntax);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Command {
    pub tag: String,
    pub body: CommandBody,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommandBody {
    Capability,
    Noop,
    Logout,
    StartTls,
    Authenticate {
        mechanism: String,
        initial_response: Option<String>,
    },
    Login {
        username: AString,
        password: AString,
    },
    Enable(Vec<String>),
    Select {
        mailbox: MailboxName,
        examine: bool,
    },
    Create(MailboxName),
    Delete(MailboxName),
    Rename {
        from: MailboxName,
        to: MailboxName,
    },
    Subscribe {
        mailbox: MailboxName,
        subscribe: bool,
    },
    List {
        reference: MailboxName,
        pattern: MailboxName,
        subscribed_only: bool,
    },
    Status {
        mailbox: MailboxName,
        items: String,
    },
    Namespace,
    Close,
    Unselect,
    Check,
    Append {
        mailbox: MailboxName,
        message: Vec<u8>,
    },
    Fetch {
        set: SequenceSet,
        items: String,
        uid: bool,
    },
    Store {
        set: SequenceSet,
        operation: String,
        flags: String,
        uid: bool,
    },
    Search {
        criteria: String,
        uid: bool,
    },
    Copy {
        set: SequenceSet,
        mailbox: MailboxName,
        move_messages: bool,
        uid: bool,
    },
    Expunge {
        uid_set: Option<SequenceSet>,
    },
    Unknown(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SequenceSet(pub Vec<SequenceRange>);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SequenceRange {
    pub start: SequenceValue,
    pub end: SequenceValue,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SequenceValue {
    Number(u32),
    Largest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum ParseError {
    #[error("command line is too long")]
    LineTooLong,
    #[error("invalid command syntax")]
    InvalidSyntax,
    #[error("literal framing mismatch")]
    LiteralMismatch,
}

pub fn parse_command(line: &[u8], literals: &[Vec<u8>]) -> Result<Command, ParseError> {
    if line.len() > MAX_COMMAND_LINE {
        return Err(ParseError::LineTooLong);
    }
    let line = line
        .strip_suffix(b"\r\n")
        .ok_or(ParseError::InvalidSyntax)?;
    if line.contains(&b'\r') || line.contains(&b'\n') {
        return Err(ParseError::InvalidSyntax);
    }
    let tokens = tokenize(line, literals)?;
    if tokens.len() < 2 {
        return Err(ParseError::InvalidSyntax);
    }
    let tag = ascii(&tokens[0])?;
    if tag.is_empty()
        || tag.len() > MAX_TAG_BYTES
        || tag == "+"
        || tag == "*"
        || !valid_atom(tag.as_bytes())
    {
        return Err(ParseError::InvalidSyntax);
    }
    let name = ascii(&tokens[1])?.to_ascii_uppercase();
    if !valid_atom(name.as_bytes()) {
        return Err(ParseError::InvalidSyntax);
    }
    let args = &tokens[2..];
    let body = match name.as_str() {
        "CAPABILITY" if args.is_empty() => CommandBody::Capability,
        "NOOP" if args.is_empty() => CommandBody::Noop,
        "LOGOUT" if args.is_empty() => CommandBody::Logout,
        "STARTTLS" if args.is_empty() => CommandBody::StartTls,
        "AUTHENTICATE" if (1..=2).contains(&args.len()) => CommandBody::Authenticate {
            mechanism: mechanism(&args[0])?,
            initial_response: args.get(1).map(|value| ascii(value)).transpose()?,
        },
        "LOGIN" if args.len() == 2 => CommandBody::Login {
            username: AString(args[0].clone()),
            password: AString(args[1].clone()),
        },
        "ENABLE" if !args.is_empty() => CommandBody::Enable(
            args.iter()
                .map(|value| ascii(value).map(|item| item.to_ascii_uppercase()))
                .collect::<Result<_, _>>()?,
        ),
        "SELECT" if args.len() == 1 => select(args, false)?,
        "EXAMINE" if args.len() == 1 => select(args, true)?,
        "CREATE" if args.len() == 1 => CommandBody::Create(mailbox(&args[0])?),
        "DELETE" if args.len() == 1 => CommandBody::Delete(mailbox(&args[0])?),
        "RENAME" if args.len() == 2 => CommandBody::Rename {
            from: mailbox(&args[0])?,
            to: mailbox(&args[1])?,
        },
        "SUBSCRIBE" if args.len() == 1 => CommandBody::Subscribe {
            mailbox: mailbox(&args[0])?,
            subscribe: true,
        },
        "UNSUBSCRIBE" if args.len() == 1 => CommandBody::Subscribe {
            mailbox: mailbox(&args[0])?,
            subscribe: false,
        },
        "LIST" | "LSUB" if args.len() == 2 => CommandBody::List {
            reference: mailbox_reference(&args[0])?,
            pattern: mailbox_reference(&args[1])?,
            subscribed_only: name == "LSUB",
        },
        "STATUS" if args.len() >= 2 => CommandBody::Status {
            mailbox: mailbox(&args[0])?,
            items: join_ascii(&args[1..])?,
        },
        "NAMESPACE" if args.is_empty() => CommandBody::Namespace,
        "CLOSE" if args.is_empty() => CommandBody::Close,
        "UNSELECT" if args.is_empty() => CommandBody::Unselect,
        "CHECK" if args.is_empty() => CommandBody::Check,
        "APPEND" if args.len() >= 2 && literals.len() == 1 && args.last() == literals.first() => {
            CommandBody::Append {
                mailbox: mailbox(&args[0])?,
                message: args.last().cloned().ok_or(ParseError::InvalidSyntax)?,
            }
        }
        "FETCH" if args.len() >= 2 => fetch(args, false)?,
        "STORE" if args.len() >= 3 => store(args, false)?,
        "SEARCH" if !args.is_empty() => CommandBody::Search {
            criteria: join_ascii(args)?,
            uid: false,
        },
        "COPY" | "MOVE" if args.len() == 2 => copy(args, name == "MOVE", false)?,
        "EXPUNGE" if args.is_empty() => CommandBody::Expunge { uid_set: None },
        "UID" if !args.is_empty() => uid_command(args)?,
        _ => CommandBody::Unknown(name),
    };
    Ok(Command { tag, body })
}

fn mailbox(value: &[u8]) -> Result<MailboxName, ParseError> {
    MailboxName::new(value.to_vec())
}

fn mailbox_reference(value: &[u8]) -> Result<MailboxName, ParseError> {
    if value.len() > 4096 || value.contains(&0) {
        return Err(ParseError::InvalidSyntax);
    }
    Ok(MailboxName(value.to_vec()))
}

fn select(args: &[Vec<u8>], examine: bool) -> Result<CommandBody, ParseError> {
    Ok(CommandBody::Select {
        mailbox: mailbox(&args[0])?,
        examine,
    })
}

fn fetch(args: &[Vec<u8>], uid: bool) -> Result<CommandBody, ParseError> {
    Ok(CommandBody::Fetch {
        set: SequenceSet::parse(&ascii(&args[0])?)?,
        items: join_ascii(&args[1..])?,
        uid,
    })
}

fn store(args: &[Vec<u8>], uid: bool) -> Result<CommandBody, ParseError> {
    Ok(CommandBody::Store {
        set: SequenceSet::parse(&ascii(&args[0])?)?,
        operation: ascii(&args[1])?.to_ascii_uppercase(),
        flags: join_ascii(&args[2..])?,
        uid,
    })
}

fn copy(args: &[Vec<u8>], move_messages: bool, uid: bool) -> Result<CommandBody, ParseError> {
    Ok(CommandBody::Copy {
        set: SequenceSet::parse(&ascii(&args[0])?)?,
        mailbox: mailbox(&args[1])?,
        move_messages,
        uid,
    })
}

fn uid_command(args: &[Vec<u8>]) -> Result<CommandBody, ParseError> {
    let command = ascii(&args[0])?.to_ascii_uppercase();
    let args = &args[1..];
    match command.as_str() {
        "FETCH" if args.len() >= 2 => fetch(args, true),
        "STORE" if args.len() >= 3 => store(args, true),
        "SEARCH" if !args.is_empty() => Ok(CommandBody::Search {
            criteria: join_ascii(args)?,
            uid: true,
        }),
        "COPY" | "MOVE" if args.len() == 2 => copy(args, command == "MOVE", true),
        "EXPUNGE" if args.len() == 1 => Ok(CommandBody::Expunge {
            uid_set: Some(SequenceSet::parse(&ascii(&args[0])?)?),
        }),
        _ => Err(ParseError::InvalidSyntax),
    }
}

fn join_ascii(values: &[Vec<u8>]) -> Result<String, ParseError> {
    values
        .iter()
        .map(|value| ascii(value))
        .collect::<Result<Vec<_>, _>>()
        .map(|values| values.join(" "))
}

fn tokenize(line: &[u8], literals: &[Vec<u8>]) -> Result<Vec<Vec<u8>>, ParseError> {
    let mut tokens = Vec::new();
    let mut index = 0;
    let mut literal = 0;
    while index < line.len() {
        if line[index] == b' ' {
            index += 1;
            continue;
        }
        if line[index] == b'"' {
            let (value, next) = quoted(line, index + 1)?;
            tokens.push(value);
            index = next;
        } else if line[index] == b'{' {
            let end = line[index..]
                .iter()
                .position(|byte| *byte == b'}')
                .map(|offset| index + offset)
                .ok_or(ParseError::InvalidSyntax)?;
            let marker = &line[index + 1..end];
            let digits = marker.strip_suffix(b"+").unwrap_or(marker);
            let length: usize = ascii(digits)?
                .parse()
                .map_err(|_| ParseError::InvalidSyntax)?;
            let value = literals.get(literal).ok_or(ParseError::LiteralMismatch)?;
            if value.len() != length {
                return Err(ParseError::LiteralMismatch);
            }
            tokens.push(value.clone());
            literal += 1;
            index = end + 1;
        } else {
            let end = line[index..]
                .iter()
                .position(|byte| *byte == b' ')
                .map_or(line.len(), |offset| index + offset);
            if end == index {
                return Err(ParseError::InvalidSyntax);
            }
            tokens.push(line[index..end].to_vec());
            index = end;
        }
        if index < line.len() && line[index] != b' ' {
            return Err(ParseError::InvalidSyntax);
        }
    }
    if literal != literals.len() {
        return Err(ParseError::LiteralMismatch);
    }
    Ok(tokens)
}

fn quoted(line: &[u8], mut index: usize) -> Result<(Vec<u8>, usize), ParseError> {
    let mut value = Vec::new();
    while let Some(byte) = line.get(index).copied() {
        match byte {
            b'"' => return Ok((value, index + 1)),
            b'\\' => {
                index += 1;
                match line.get(index).copied() {
                    Some(byte @ (b'"' | b'\\')) => value.push(byte),
                    _ => return Err(ParseError::InvalidSyntax),
                }
            }
            0 | b'\r' | b'\n' => return Err(ParseError::InvalidSyntax),
            byte => value.push(byte),
        }
        index += 1;
    }
    Err(ParseError::InvalidSyntax)
}

fn ascii(value: &[u8]) -> Result<String, ParseError> {
    value
        .is_ascii()
        .then(|| String::from_utf8_lossy(value).into_owned())
        .ok_or(ParseError::InvalidSyntax)
}

fn valid_atom(value: &[u8]) -> bool {
    !value.is_empty()
        && value.iter().all(|byte| {
            (0x21..=0x7e).contains(byte)
                && !matches!(
                    byte,
                    b'(' | b')' | b'{' | b' ' | b'%' | b'*' | b'"' | b'\\' | b']'
                )
        })
}

fn mechanism(value: &[u8]) -> Result<String, ParseError> {
    if !value
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
    {
        return Err(ParseError::InvalidSyntax);
    }
    Ok(ascii(value)?.to_ascii_uppercase())
}

impl SequenceSet {
    pub fn parse(value: &str) -> Result<Self, ParseError> {
        if value.is_empty() {
            return Err(ParseError::InvalidSyntax);
        }
        value
            .split(',')
            .map(|range| {
                let (start, end) = range.split_once(':').unwrap_or((range, range));
                Ok(SequenceRange {
                    start: sequence_value(start)?,
                    end: sequence_value(end)?,
                })
            })
            .collect::<Result<Vec<_>, _>>()
            .map(Self)
    }
}

fn sequence_value(value: &str) -> Result<SequenceValue, ParseError> {
    if value == "*" {
        return Ok(SequenceValue::Largest);
    }
    value
        .parse::<u32>()
        .ok()
        .filter(|number| *number > 0)
        .map(SequenceValue::Number)
        .ok_or(ParseError::InvalidSyntax)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_atoms_quotes_literals_and_sequence_sets() -> Result<(), ParseError> {
        assert_eq!(
            parse_command(b"A1 LOGIN \"a\\\"lice\" {6}\r\n", &[b"secret".to_vec()])?,
            Command {
                tag: "A1".into(),
                body: CommandBody::Login {
                    username: AString(b"a\"lice".to_vec()),
                    password: AString(b"secret".to_vec()),
                },
            }
        );
        assert_eq!(SequenceSet::parse("1:4,8,*:10")?.0.len(), 3);
        assert!(SequenceSet::parse("0").is_err());
        assert!(matches!(
            parse_command(b"A2 UID FETCH 1:* (FLAGS BODY.PEEK[])\r\n", &[])?.body,
            CommandBody::Fetch { uid: true, .. }
        ));
        assert!(matches!(
            parse_command(b"A3 APPEND INBOX {4}\r\n", &[b"test".to_vec()])?.body,
            CommandBody::Append { .. }
        ));
        assert!(matches!(
            parse_command(b"A4 MOVE 2:4 Archive\r\n", &[])?.body,
            CommandBody::Copy {
                move_messages: true,
                ..
            }
        ));
        Ok(())
    }
}
