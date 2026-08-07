#![forbid(unsafe_code)]

use base64::{Engine as _, engine::general_purpose::STANDARD};
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc2822};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MessageLimits {
    pub max_header_bytes: usize,
    pub max_header_line_bytes: usize,
    pub max_header_fields: usize,
}

impl Default for MessageLimits {
    fn default() -> Self {
        Self {
            max_header_bytes: 256 * 1024,
            max_header_line_bytes: 1_000,
            max_header_fields: 1_000,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorSeverity {
    Recoverable,
    Fatal,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
#[error("message parse error at byte {position}: {kind}")]
pub struct ParseError {
    pub position: usize,
    pub severity: ErrorSeverity,
    pub kind: ParseErrorKind,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ParseErrorKind {
    #[error("header section exceeds configured limit")]
    HeaderTooLarge,
    #[error("header line exceeds configured limit")]
    LineTooLong,
    #[error("too many header fields")]
    TooManyFields,
    #[error("bare CR or LF in header section")]
    BareLineEnding,
    #[error("invalid header field name")]
    InvalidFieldName,
    #[error("header continuation has no preceding field")]
    OrphanContinuation,
    #[error("parser is already complete")]
    AlreadyComplete,
    #[error("invalid Message-ID")]
    InvalidMessageId,
    #[error("invalid Date field")]
    InvalidDate,
    #[error("invalid encoded-word")]
    InvalidEncodedWord,
    #[error("message ended before the header/body separator")]
    UnexpectedEof,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HeaderField {
    name: String,
    value: Vec<u8>,
}

impl HeaderField {
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
    #[must_use]
    pub fn value(&self) -> &[u8] {
        &self.value
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HeaderBlock {
    raw: Vec<u8>,
    fields: Vec<HeaderField>,
}

impl HeaderBlock {
    #[must_use]
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }
    #[must_use]
    pub fn fields(&self) -> &[HeaderField] {
        &self.fields
    }
    pub fn get_all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a [u8]> + 'a {
        self.fields
            .iter()
            .filter(move |field| field.name.eq_ignore_ascii_case(name))
            .map(|field| field.value.as_slice())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParseProgress {
    NeedMore,
    Complete {
        headers: HeaderBlock,
        consumed: usize,
    },
}

pub struct MessageParser {
    limits: MessageLimits,
    raw: Vec<u8>,
    line_start: usize,
    complete: bool,
}

impl MessageParser {
    #[must_use]
    pub fn new(limits: MessageLimits) -> Self {
        Self {
            limits,
            raw: Vec::new(),
            line_start: 0,
            complete: false,
        }
    }

    pub fn push(&mut self, input: &[u8]) -> Result<ParseProgress, ParseError> {
        if self.complete {
            return Err(Self::error(0, ParseErrorKind::AlreadyComplete));
        }
        for (index, byte) in input.iter().copied().enumerate() {
            if self.raw.last() == Some(&b'\r') && byte != b'\n' {
                return Err(Self::error(
                    self.raw.len() - 1,
                    ParseErrorKind::BareLineEnding,
                ));
            }
            if self.raw.len() >= self.limits.max_header_bytes {
                return Err(Self::error(self.raw.len(), ParseErrorKind::HeaderTooLarge));
            }
            self.raw.push(byte);
            if byte == b'\n' {
                let length = self.raw.len() - self.line_start;
                if length < 2 || self.raw[self.raw.len() - 2] != b'\r' {
                    return Err(Self::error(
                        self.raw.len() - 1,
                        ParseErrorKind::BareLineEnding,
                    ));
                }
                if length > self.limits.max_header_line_bytes {
                    return Err(Self::error(self.line_start, ParseErrorKind::LineTooLong));
                }
                self.line_start = self.raw.len();
                if length == 2 {
                    self.complete = true;
                    let raw = std::mem::take(&mut self.raw);
                    let fields = parse_fields(&raw, self.limits)?;
                    return Ok(ParseProgress::Complete {
                        headers: HeaderBlock { raw, fields },
                        consumed: index + 1,
                    });
                }
            } else if byte == b'\r' && input.get(index + 1).is_some_and(|next| *next != b'\n') {
                return Err(Self::error(
                    self.raw.len() - 1,
                    ParseErrorKind::BareLineEnding,
                ));
            }
        }
        Ok(ParseProgress::NeedMore)
    }

    pub fn finish(&self) -> Result<(), ParseError> {
        if self.complete {
            Ok(())
        } else {
            Err(Self::error(self.raw.len(), ParseErrorKind::UnexpectedEof))
        }
    }

    fn error(position: usize, kind: ParseErrorKind) -> ParseError {
        ParseError {
            position,
            severity: ErrorSeverity::Fatal,
            kind,
        }
    }
}

fn parse_fields(raw: &[u8], limits: MessageLimits) -> Result<Vec<HeaderField>, ParseError> {
    let mut fields: Vec<HeaderField> = Vec::new();
    let mut offset = 0;
    for line in raw[..raw.len() - 2].split(|byte| *byte == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            break;
        }
        if line[0] == b' ' || line[0] == b'\t' {
            let field = fields.last_mut().ok_or(ParseError {
                position: offset,
                severity: ErrorSeverity::Fatal,
                kind: ParseErrorKind::OrphanContinuation,
            })?;
            field.value.extend_from_slice(line);
        } else {
            if fields.len() >= limits.max_header_fields {
                return Err(ParseError {
                    position: offset,
                    severity: ErrorSeverity::Fatal,
                    kind: ParseErrorKind::TooManyFields,
                });
            }
            let colon = line
                .iter()
                .position(|byte| *byte == b':')
                .ok_or(ParseError {
                    position: offset,
                    severity: ErrorSeverity::Fatal,
                    kind: ParseErrorKind::InvalidFieldName,
                })?;
            if colon == 0
                || !line[..colon]
                    .iter()
                    .all(|byte| matches!(*byte, 33..=57 | 59..=126))
            {
                return Err(ParseError {
                    position: offset,
                    severity: ErrorSeverity::Fatal,
                    kind: ParseErrorKind::InvalidFieldName,
                });
            }
            let name =
                String::from_utf8(line[..colon].to_ascii_lowercase()).map_err(|_| ParseError {
                    position: offset,
                    severity: ErrorSeverity::Fatal,
                    kind: ParseErrorKind::InvalidFieldName,
                })?;
            fields.push(HeaderField {
                name,
                value: line[colon + 1..].to_vec(),
            });
        }
        offset += line.len() + 2;
    }
    Ok(fields)
}

pub fn parse_message_id(input: &[u8]) -> Result<(&[u8], &[u8]), ParseError> {
    let input = trim_ascii(input);
    if input.len() < 5 || input[0] != b'<' || input[input.len() - 1] != b'>' {
        return Err(ParseError {
            position: 0,
            severity: ErrorSeverity::Recoverable,
            kind: ParseErrorKind::InvalidMessageId,
        });
    }
    let inner = &input[1..input.len() - 1];
    let at = inner
        .iter()
        .position(|byte| *byte == b'@')
        .ok_or(ParseError {
            position: 1,
            severity: ErrorSeverity::Recoverable,
            kind: ParseErrorKind::InvalidMessageId,
        })?;
    if !valid_id_left(&inner[..at])
        || !valid_id_right(&inner[at + 1..])
        || inner[at + 1..].contains(&b'@')
    {
        return Err(ParseError {
            position: at + 1,
            severity: ErrorSeverity::Recoverable,
            kind: ParseErrorKind::InvalidMessageId,
        });
    }
    Ok((&inner[..at], &inner[at + 1..]))
}

fn valid_id_left(value: &[u8]) -> bool {
    valid_id_dot_atom(value) || valid_id_quoted(value)
}
fn valid_id_right(value: &[u8]) -> bool {
    valid_id_dot_atom(value)
        || value.len() >= 2
            && value.starts_with(b"[")
            && value.ends_with(b"]")
            && value[1..value.len() - 1]
                .iter()
                .all(|byte| matches!(*byte, 33..=90 | 94..=126))
}
fn valid_id_dot_atom(value: &[u8]) -> bool {
    !value.is_empty()
        && !value.starts_with(b".")
        && !value.ends_with(b".")
        && !value.windows(2).any(|pair| pair == b"..")
        && value
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-/=?^_`{|}~.".contains(byte))
}
fn valid_id_quoted(value: &[u8]) -> bool {
    if value.len() < 2 || !value.starts_with(b"\"") || !value.ends_with(b"\"") {
        return false;
    }
    let mut escaped = false;
    for byte in &value[1..value.len() - 1] {
        if escaped {
            if !matches!(*byte, 32..=126) {
                return false;
            }
            escaped = false;
        } else if *byte == b'\\' {
            escaped = true;
        } else if !matches!(*byte, 33 | 35..=91 | 93..=126) {
            return false;
        }
    }
    !escaped
}

pub fn parse_date(input: &[u8]) -> Result<OffsetDateTime, ParseError> {
    let value = std::str::from_utf8(trim_ascii(input))
        .map_err(|_| typed_error(ParseErrorKind::InvalidDate))?;
    OffsetDateTime::parse(value, &Rfc2822).map_err(|_| typed_error(ParseErrorKind::InvalidDate))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncodedWord {
    pub charset: String,
    pub decoded: Vec<u8>,
}

pub fn decode_encoded_word(input: &[u8]) -> Result<EncodedWord, ParseError> {
    if !input.starts_with(b"=?") || !input.ends_with(b"?=") {
        return Err(typed_error(ParseErrorKind::InvalidEncodedWord));
    }
    let inner = &input[2..input.len() - 2];
    let first = inner
        .iter()
        .position(|byte| *byte == b'?')
        .ok_or_else(|| typed_error(ParseErrorKind::InvalidEncodedWord))?;
    let second = inner[first + 1..]
        .iter()
        .position(|byte| *byte == b'?')
        .map(|offset| first + 1 + offset)
        .ok_or_else(|| typed_error(ParseErrorKind::InvalidEncodedWord))?;
    let charset = &inner[..first];
    if charset.is_empty() || !charset.is_ascii() {
        return Err(typed_error(ParseErrorKind::InvalidEncodedWord));
    }
    let encoded = &inner[second + 1..];
    let decoded = match inner[first + 1..second].to_ascii_lowercase().as_slice() {
        b"b" => STANDARD
            .decode(encoded)
            .map_err(|_| typed_error(ParseErrorKind::InvalidEncodedWord))?,
        b"q" => decode_q(encoded)?,
        _ => return Err(typed_error(ParseErrorKind::InvalidEncodedWord)),
    };
    Ok(EncodedWord {
        charset: String::from_utf8_lossy(charset).to_ascii_lowercase(),
        decoded,
    })
}

fn decode_q(input: &[u8]) -> Result<Vec<u8>, ParseError> {
    let mut output = Vec::with_capacity(input.len());
    let mut index = 0;
    while index < input.len() {
        match input[index] {
            b'_' => {
                output.push(b' ');
                index += 1;
            }
            b'=' if index + 2 < input.len() => {
                let high = hex(input[index + 1])
                    .ok_or_else(|| typed_error(ParseErrorKind::InvalidEncodedWord))?;
                let low = hex(input[index + 2])
                    .ok_or_else(|| typed_error(ParseErrorKind::InvalidEncodedWord))?;
                output.push(high * 16 + low);
                index += 3;
            }
            b'=' => return Err(typed_error(ParseErrorKind::InvalidEncodedWord)),
            byte if matches!(byte, 33..=126) && byte != b'?' => {
                output.push(byte);
                index += 1;
            }
            _ => return Err(typed_error(ParseErrorKind::InvalidEncodedWord)),
        }
    }
    Ok(output)
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn typed_error(kind: ParseErrorKind) -> ParseError {
    ParseError {
        position: 0,
        severity: ErrorSeverity::Recoverable,
        kind,
    }
}

fn trim_ascii(mut input: &[u8]) -> &[u8] {
    while input.first().is_some_and(u8::is_ascii_whitespace) {
        input = &input[1..];
    }
    while input.last().is_some_and(u8::is_ascii_whitespace) {
        input = &input[..input.len() - 1];
    }
    input
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn incremental_split_preserves_raw_and_unfolds() -> Result<(), ParseError> {
        let raw = b"Subject: hello\r\n world\r\nMessage-ID: <a@b>\r\n\r\nbody";
        let header_bytes = raw.len() - 4;
        for split in 0..raw.len() {
            let mut parser = MessageParser::new(MessageLimits::default());
            let (headers, body_start) = match parser.push(&raw[..split])? {
                ParseProgress::NeedMore => {
                    let ParseProgress::Complete { headers, consumed } =
                        parser.push(&raw[split..])?
                    else {
                        return Err(MessageParser::error(0, ParseErrorKind::HeaderTooLarge));
                    };
                    (headers, split + consumed)
                }
                ParseProgress::Complete { headers, consumed } => (headers, consumed),
            };
            assert_eq!(headers.raw(), &raw[..header_bytes]);
            assert_eq!(
                headers.get_all("subject").next(),
                Some(&b" hello world"[..])
            );
            assert_eq!(&raw[body_start..], b"body");
        }
        Ok(())
    }

    #[test]
    fn message_id_date_and_encoded_word_are_typed() -> Result<(), ParseError> {
        assert_eq!(
            parse_message_id(b"<left@example.test>")?,
            (&b"left"[..], &b"example.test"[..])
        );
        assert!(parse_message_id(b"<bad\0@example.test>").is_err());
        assert!(parse_date(b"Fri, 21 Nov 1997 09:55:06 -0600").is_ok());
        assert_eq!(
            decode_encoded_word(b"=?UTF-8?Q?hello_world?=")?.decoded,
            b"hello world"
        );
        Ok(())
    }

    #[test]
    fn empty_header_block_and_truncated_header_are_distinct() -> Result<(), ParseError> {
        let mut empty = MessageParser::new(MessageLimits::default());
        assert!(matches!(
            empty.push(b"\r\nbody")?,
            ParseProgress::Complete { consumed: 2, .. }
        ));
        let mut truncated = MessageParser::new(MessageLimits::default());
        assert_eq!(truncated.push(b"Subject: x\r")?, ParseProgress::NeedMore);
        assert!(matches!(
            truncated.finish(),
            Err(ParseError {
                kind: ParseErrorKind::UnexpectedEof,
                ..
            })
        ));
        Ok(())
    }

    proptest! {
        #[test]
        fn arbitrary_input_never_panics(input in proptest::collection::vec(any::<u8>(), 0..4096)) {
            let mut parser = MessageParser::new(MessageLimits { max_header_bytes: 4096, ..MessageLimits::default() });
            let _ = parser.push(&input);
        }
    }
}
