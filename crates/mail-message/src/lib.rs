#![forbid(unsafe_code)]

use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MessageLimits {
    pub max_header_bytes: usize,
    pub max_header_line_bytes: usize,
    pub max_header_fields: usize,
}

impl Default for MessageLimits {
    fn default() -> Self {
        Self { max_header_bytes: 256 * 1024, max_header_line_bytes: 8 * 1024, max_header_fields: 1_000 }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorSeverity { Recoverable, Fatal }

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
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HeaderField {
    name: String,
    value: Vec<u8>,
}

impl HeaderField {
    #[must_use] pub fn name(&self) -> &str { &self.name }
    #[must_use] pub fn value(&self) -> &[u8] { &self.value }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HeaderBlock {
    raw: Vec<u8>,
    fields: Vec<HeaderField>,
}

impl HeaderBlock {
    #[must_use] pub fn raw(&self) -> &[u8] { &self.raw }
    #[must_use] pub fn fields(&self) -> &[HeaderField] { &self.fields }
    pub fn get_all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a [u8]> + 'a {
        self.fields.iter().filter(move |field| field.name.eq_ignore_ascii_case(name)).map(|field| field.value.as_slice())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParseProgress {
    NeedMore,
    Complete { headers: HeaderBlock, consumed: usize },
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
        Self { limits, raw: Vec::new(), line_start: 0, complete: false }
    }

    pub fn push(&mut self, input: &[u8]) -> Result<ParseProgress, ParseError> {
        if self.complete { return Err(self.error(0, ParseErrorKind::AlreadyComplete)); }
        for (index, byte) in input.iter().copied().enumerate() {
            if self.raw.len() >= self.limits.max_header_bytes {
                return Err(self.error(self.raw.len(), ParseErrorKind::HeaderTooLarge));
            }
            self.raw.push(byte);
            if byte == b'\n' {
                let length = self.raw.len() - self.line_start;
                if length < 2 || self.raw[self.raw.len() - 2] != b'\r' {
                    return Err(self.error(self.raw.len() - 1, ParseErrorKind::BareLineEnding));
                }
                if length > self.limits.max_header_line_bytes {
                    return Err(self.error(self.line_start, ParseErrorKind::LineTooLong));
                }
                self.line_start = self.raw.len();
            } else if byte == b'\r' && input.get(index + 1).is_some_and(|next| *next != b'\n') {
                return Err(self.error(self.raw.len() - 1, ParseErrorKind::BareLineEnding));
            }
            if self.raw.ends_with(b"\r\n\r\n") {
                self.complete = true;
                let raw = std::mem::take(&mut self.raw);
                let fields = parse_fields(&raw, self.limits)?;
                return Ok(ParseProgress::Complete { headers: HeaderBlock { raw, fields }, consumed: index + 1 });
            }
        }
        Ok(ParseProgress::NeedMore)
    }

    fn error(&self, position: usize, kind: ParseErrorKind) -> ParseError {
        ParseError { position, severity: ErrorSeverity::Fatal, kind }
    }
}

fn parse_fields(raw: &[u8], limits: MessageLimits) -> Result<Vec<HeaderField>, ParseError> {
    let mut fields: Vec<HeaderField> = Vec::new();
    let mut offset = 0;
    for line in raw[..raw.len() - 2].split(|byte| *byte == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() { break; }
        if line[0] == b' ' || line[0] == b'\t' {
            let field = fields.last_mut().ok_or(ParseError { position: offset, severity: ErrorSeverity::Fatal, kind: ParseErrorKind::OrphanContinuation })?;
            field.value.extend_from_slice(line);
        } else {
            if fields.len() >= limits.max_header_fields {
                return Err(ParseError { position: offset, severity: ErrorSeverity::Fatal, kind: ParseErrorKind::TooManyFields });
            }
            let colon = line.iter().position(|byte| *byte == b':').ok_or(ParseError { position: offset, severity: ErrorSeverity::Fatal, kind: ParseErrorKind::InvalidFieldName })?;
            if colon == 0 || !line[..colon].iter().all(|byte| matches!(*byte, 33..=57 | 59..=126)) {
                return Err(ParseError { position: offset, severity: ErrorSeverity::Fatal, kind: ParseErrorKind::InvalidFieldName });
            }
            let name = String::from_utf8(line[..colon].to_ascii_lowercase()).map_err(|_| ParseError { position: offset, severity: ErrorSeverity::Fatal, kind: ParseErrorKind::InvalidFieldName })?;
            fields.push(HeaderField { name, value: line[colon + 1..].to_vec() });
        }
        offset += line.len() + 2;
    }
    Ok(fields)
}

pub fn parse_message_id(input: &[u8]) -> Result<(&[u8], &[u8]), ParseError> {
    let input = trim_ascii(input);
    if input.len() < 5 || input[0] != b'<' || input[input.len() - 1] != b'>' {
        return Err(ParseError { position: 0, severity: ErrorSeverity::Recoverable, kind: ParseErrorKind::InvalidMessageId });
    }
    let inner = &input[1..input.len() - 1];
    let at = inner.iter().position(|byte| *byte == b'@').ok_or(ParseError { position: 1, severity: ErrorSeverity::Recoverable, kind: ParseErrorKind::InvalidMessageId })?;
    if at == 0 || at + 1 == inner.len() || inner.iter().any(|byte| byte.is_ascii_whitespace() || matches!(*byte, b'<' | b'>' | b'@') && *byte != b'@') || inner[at + 1..].contains(&b'@') {
        return Err(ParseError { position: at + 1, severity: ErrorSeverity::Recoverable, kind: ParseErrorKind::InvalidMessageId });
    }
    Ok((&inner[..at], &inner[at + 1..]))
}

fn trim_ascii(mut input: &[u8]) -> &[u8] {
    while input.first().is_some_and(u8::is_ascii_whitespace) { input = &input[1..]; }
    while input.last().is_some_and(u8::is_ascii_whitespace) { input = &input[..input.len() - 1]; }
    input
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn incremental_split_preserves_raw_and_unfolds() -> Result<(), ParseError> {
        let raw = b"Subject: hello\r\n world\r\nMessage-ID: <a@b>\r\n\r\nbody";
        for split in 0..raw.len() {
            let mut parser = MessageParser::new(MessageLimits::default());
            assert_eq!(parser.push(&raw[..split])?, ParseProgress::NeedMore);
            let ParseProgress::Complete { headers, consumed } = parser.push(&raw[split..])? else { return Err(parser.error(0, ParseErrorKind::HeaderTooLarge)); };
            assert_eq!(headers.raw(), &raw[..raw.len() - 4]);
            assert_eq!(headers.get_all("subject").next(), Some(&b" hello world"[..]));
            assert_eq!(&raw[split + consumed..], b"body");
        }
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
