use super::{CommandError, fetch};
use mail_imap_proto::{AString, SequenceSet};
use mail_storage::ImapMessage;
use time::{Date, OffsetDateTime, format_description, format_description::well_known::Rfc2822};

pub(super) fn messages<'a>(
    messages: &'a [ImapMessage],
    criteria: &[AString],
) -> Result<Vec<&'a ImapMessage>, CommandError> {
    let tokens = tokens(criteria)?;
    let mut parser = Parser {
        tokens: &tokens,
        at: 0,
    };
    let query = parser.and(false)?;
    if parser.at != tokens.len() {
        return Err(CommandError::Bad("invalid search criteria"));
    }
    let largest_sequence = messages.last().map_or(0, |message| message.sequence);
    let largest_uid = messages.last().map_or(0, |message| message.uid);
    Ok(messages
        .iter()
        .filter(|message| query.matches(message, largest_sequence, largest_uid))
        .collect())
}

#[derive(Clone, Debug)]
enum Token {
    Value(String),
    Open,
    Close,
}

fn tokens(values: &[AString]) -> Result<Vec<Token>, CommandError> {
    let mut output = Vec::new();
    for value in values {
        let mut value = String::from_utf8(value.0.clone())
            .map_err(|_| CommandError::Bad("search criteria must be UTF-8"))?;
        while value.starts_with('(') {
            output.push(Token::Open);
            value.remove(0);
        }
        let closes = value
            .chars()
            .rev()
            .take_while(|character| *character == ')')
            .count();
        value.truncate(value.len() - closes);
        if !value.is_empty() {
            output.push(Token::Value(value));
        }
        output.extend((0..closes).map(|_| Token::Close));
    }
    Ok(output)
}

#[derive(Clone, Debug)]
enum Query {
    All,
    And(Vec<Self>),
    Or(Box<Self>, Box<Self>),
    Not(Box<Self>),
    Flag(String, bool),
    Header(String, Vec<u8>),
    Body(Vec<u8>),
    Text(Vec<u8>),
    Larger(usize, bool),
    Date(DateKind, Date),
    Set(SequenceSet, bool),
    Modseq(u64),
}

#[derive(Clone, Copy, Debug)]
enum DateKind {
    Before,
    On,
    Since,
    SentBefore,
    SentOn,
    SentSince,
}

struct Parser<'a> {
    tokens: &'a [Token],
    at: usize,
}
impl Parser<'_> {
    fn and(&mut self, nested: bool) -> Result<Query, CommandError> {
        let mut queries = Vec::new();
        while self.at < self.tokens.len() && !matches!(self.tokens[self.at], Token::Close) {
            queries.push(self.one()?);
        }
        if nested {
            if !matches!(self.tokens.get(self.at), Some(Token::Close)) {
                return Err(CommandError::Bad("unclosed search group"));
            }
            self.at += 1;
        }
        Ok(if queries.len() == 1 {
            queries.pop().ok_or(CommandError::Bad("empty search"))?
        } else {
            Query::And(queries)
        })
    }
    fn one(&mut self) -> Result<Query, CommandError> {
        match self.tokens.get(self.at) {
            Some(Token::Open) => {
                self.at += 1;
                self.and(true)
            }
            Some(Token::Value(value)) => {
                self.at += 1;
                let upper = value.to_ascii_uppercase();
                match upper.as_str() {
                    "ALL" => Ok(Query::All),
                    "NOT" => Ok(Query::Not(Box::new(self.one()?))),
                    "OR" => Ok(Query::Or(Box::new(self.one()?), Box::new(self.one()?))),
                    "ANSWERED" => Ok(Query::Flag("\\Answered".into(), true)),
                    "UNANSWERED" => Ok(Query::Flag("\\Answered".into(), false)),
                    "DELETED" => Ok(Query::Flag("\\Deleted".into(), true)),
                    "UNDELETED" => Ok(Query::Flag("\\Deleted".into(), false)),
                    "DRAFT" => Ok(Query::Flag("\\Draft".into(), true)),
                    "UNDRAFT" => Ok(Query::Flag("\\Draft".into(), false)),
                    "FLAGGED" => Ok(Query::Flag("\\Flagged".into(), true)),
                    "UNFLAGGED" => Ok(Query::Flag("\\Flagged".into(), false)),
                    "SEEN" => Ok(Query::Flag("\\Seen".into(), true)),
                    "UNSEEN" => Ok(Query::Flag("\\Seen".into(), false)),
                    "KEYWORD" => Ok(Query::Flag(self.value()?, true)),
                    "UNKEYWORD" => Ok(Query::Flag(self.value()?, false)),
                    "FROM" | "TO" | "CC" | "BCC" | "SUBJECT" => {
                        Ok(Query::Header(upper, self.bytes()?))
                    }
                    "HEADER" => Ok(Query::Header(self.value()?, self.bytes()?)),
                    "BODY" => Ok(Query::Body(self.bytes()?)),
                    "TEXT" => Ok(Query::Text(self.bytes()?)),
                    "LARGER" => Ok(Query::Larger(self.number()?, true)),
                    "SMALLER" => Ok(Query::Larger(self.number()?, false)),
                    "BEFORE" => Ok(Query::Date(DateKind::Before, self.date()?)),
                    "ON" => Ok(Query::Date(DateKind::On, self.date()?)),
                    "SINCE" => Ok(Query::Date(DateKind::Since, self.date()?)),
                    "SENTBEFORE" => Ok(Query::Date(DateKind::SentBefore, self.date()?)),
                    "SENTON" => Ok(Query::Date(DateKind::SentOn, self.date()?)),
                    "SENTSINCE" => Ok(Query::Date(DateKind::SentSince, self.date()?)),
                    "UID" => Ok(Query::Set(
                        SequenceSet::parse(&self.value()?)
                            .map_err(|_| CommandError::Bad("invalid UID set"))?,
                        true,
                    )),
                    "MODSEQ" => {
                        let first = self.value()?;
                        let value = if first.parse::<u64>().is_ok() {
                            first
                        } else {
                            let kind = self.value()?.to_ascii_lowercase();
                            if !matches!(kind.as_str(), "shared" | "priv" | "all") {
                                return Err(CommandError::Bad("invalid MODSEQ entry type"));
                            }
                            self.value()?
                        };
                        Ok(Query::Modseq(
                            value
                                .parse()
                                .map_err(|_| CommandError::Bad("invalid MODSEQ value"))?,
                        ))
                    }
                    _ => SequenceSet::parse(value)
                        .map(|set| Query::Set(set, false))
                        .map_err(|_| CommandError::Bad("unsupported search criterion")),
                }
            }
            _ => Err(CommandError::Bad("invalid search criteria")),
        }
    }
    fn value(&mut self) -> Result<String, CommandError> {
        match self.tokens.get(self.at) {
            Some(Token::Value(value)) => {
                self.at += 1;
                Ok(value.clone())
            }
            _ => Err(CommandError::Bad("missing search argument")),
        }
    }
    fn bytes(&mut self) -> Result<Vec<u8>, CommandError> {
        self.value().map(String::into_bytes)
    }
    fn number(&mut self) -> Result<usize, CommandError> {
        self.value()?
            .parse()
            .map_err(|_| CommandError::Bad("invalid search number"))
    }
    fn date(&mut self) -> Result<Date, CommandError> {
        let value = self.value()?;
        let format =
            format_description::parse_borrowed::<2>("[day padding:none]-[month repr:short]-[year]")
                .map_err(|_| CommandError::Bad("invalid search date"))?;
        Date::parse(&value, &format).map_err(|_| CommandError::Bad("invalid search date"))
    }
}

impl Query {
    fn matches(&self, message: &ImapMessage, largest_sequence: u32, largest_uid: u32) -> bool {
        match self {
            Self::All => true,
            Self::And(values) => values
                .iter()
                .all(|query| query.matches(message, largest_sequence, largest_uid)),
            Self::Or(a, b) => {
                a.matches(message, largest_sequence, largest_uid)
                    || b.matches(message, largest_sequence, largest_uid)
            }
            Self::Not(query) => !query.matches(message, largest_sequence, largest_uid),
            Self::Flag(flag, wanted) => {
                message
                    .flags
                    .iter()
                    .any(|value| value.eq_ignore_ascii_case(flag))
                    == *wanted
            }
            Self::Header(name, needle) => fetch::header(&message.raw, name)
                .is_some_and(|value| contains_ascii(&value, needle)),
            Self::Body(needle) => contains_ascii(fetch::header_body(&message.raw).1, needle),
            Self::Text(needle) => contains_ascii(&message.raw, needle),
            Self::Larger(size, larger) => {
                (*larger && message.raw.len() > *size) || (!*larger && message.raw.len() < *size)
            }
            Self::Date(kind, date) => {
                let actual = match kind {
                    DateKind::SentBefore | DateKind::SentOn | DateKind::SentSince => {
                        sent_date(&message.raw)
                    }
                    _ => Some(OffsetDateTime::from(message.internal_date).date()),
                };
                actual.is_some_and(|actual| match kind {
                    DateKind::Before | DateKind::SentBefore => actual < *date,
                    DateKind::On | DateKind::SentOn => actual == *date,
                    DateKind::Since | DateKind::SentSince => actual >= *date,
                })
            }
            Self::Set(set, uid) => {
                let value = if *uid { message.uid } else { message.sequence };
                let largest = if *uid { largest_uid } else { largest_sequence };
                set.0.iter().any(|range| {
                    let a = super::sequence(range.start, largest);
                    let b = super::sequence(range.end, largest);
                    value >= a.min(b) && value <= a.max(b)
                })
            }
            Self::Modseq(value) => message.modseq > *value,
        }
    }
}

fn contains_ascii(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    haystack
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle))
}
fn sent_date(raw: &[u8]) -> Option<Date> {
    let value = fetch::header(raw, "Date")?;
    let value = std::str::from_utf8(&value).ok()?;
    OffsetDateTime::parse(value, &Rfc2822)
        .ok()
        .map(OffsetDateTime::date)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::SystemTime;
    fn message() -> ImapMessage {
        ImapMessage {
            sequence: 2,
            uid: 9,
            modseq: 1,
            flags: vec!["\\Seen".into()],
            internal_date: SystemTime::now(),
            raw: b"From: Alice <alice@example.test>\r\nSubject: Quarterly report\r\n\r\nRevenue"
                .to_vec(),
        }
    }
    #[test]
    fn compound_header_body_size_uid_and_not() {
        let sample = message();
        let values = ["OR", "FROM", "alice", "NOT", "BODY", "missing"]
            .map(|value| AString(value.as_bytes().to_vec()));
        assert_eq!(
            messages(std::slice::from_ref(&sample), &values).map_or(0, |found| found.len()),
            1
        );
        let values = ["UID", "9", "LARGER", "10", "SUBJECT", "Quarterly report"]
            .map(|value| AString(value.as_bytes().to_vec()));
        assert_eq!(
            messages(std::slice::from_ref(&sample), &values).map_or(0, |found| found.len()),
            1
        );
        let mut first = sample.clone();
        first.sequence = 1;
        first.uid = 8;
        let last = sample;
        let values = [AString(b"*".to_vec())];
        let found = messages(&[first, last], &values).map_or(Vec::new(), |found| {
            found.into_iter().map(|message| message.uid).collect()
        });
        assert_eq!(found, [9]);
        let values = [AString(b"MODSEQ".to_vec()), AString(b"0".to_vec())];
        assert_eq!(
            messages(std::slice::from_ref(&message()), &values).map_or(0, |found| found.len()),
            1
        );
    }
}
