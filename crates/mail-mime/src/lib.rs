#![forbid(unsafe_code)]

use base64::{Engine as _, engine::general_purpose::STANDARD};
use mail_message::{HeaderBlock, MessageLimits, MessageParser, ParseProgress};
use quoted_printable::ParseMode;
use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MimeLimits {
    pub max_input_bytes: usize,
    pub max_depth: usize,
    pub max_parts: usize,
    pub max_boundary_bytes: usize,
    pub max_decoded_bytes: usize,
    pub message: MessageLimits,
}

impl Default for MimeLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: 25 * 1024 * 1024,
            max_depth: 20,
            max_parts: 1_000,
            max_boundary_bytes: 70,
            max_decoded_bytes: 32 * 1024 * 1024,
            message: MessageLimits::default(),
        }
    }
}

pub type Parameters = Vec<(String, Vec<u8>)>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MediaType {
    pub top: String,
    pub subtype: String,
    pub parameters: Parameters,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContentDisposition {
    pub kind: String,
    pub parameters: Parameters,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransferEncoding {
    SevenBit,
    EightBit,
    Binary,
    Base64,
    QuotedPrintable,
    Other(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StreamEvent {
    Data(Vec<u8>),
    Boundary { closing: bool },
}

pub struct BoundaryScanner {
    marker: Vec<u8>,
    candidate: Vec<u8>,
    at_line_start: bool,
    previous_cr: bool,
    max_line_bytes: usize,
    max_input_bytes: usize,
    seen: usize,
}

impl BoundaryScanner {
    pub fn new(boundary: &[u8], limits: MimeLimits) -> Result<Self, MimeError> {
        if boundary.is_empty()
            || boundary.len() > limits.max_boundary_bytes
            || !boundary.iter().all(|byte| matches!(*byte, 32..=126))
        {
            return Err(recoverable(0, MimeErrorKind::InvalidBoundary));
        }
        let mut marker = b"--".to_vec();
        marker.extend_from_slice(boundary);
        Ok(Self {
            marker,
            candidate: Vec::new(),
            at_line_start: true,
            previous_cr: false,
            max_line_bytes: limits.message.max_header_line_bytes,
            max_input_bytes: limits.max_input_bytes,
            seen: 0,
        })
    }

    pub fn push(&mut self, input: &[u8]) -> Result<Vec<StreamEvent>, MimeError> {
        self.seen = self
            .seen
            .checked_add(input.len())
            .ok_or_else(|| fatal(0, MimeErrorKind::InputLimit))?;
        if self.seen > self.max_input_bytes {
            return Err(fatal(self.seen, MimeErrorKind::InputLimit));
        }
        let mut events = Vec::new();
        let mut data = Vec::new();
        for byte in input.iter().copied() {
            if !self.candidate.is_empty() || (self.at_line_start && byte == b'-') {
                self.candidate.push(byte);
                if self.candidate.len() > self.max_line_bytes {
                    return Err(fatal(0, MimeErrorKind::InvalidBoundary));
                }
                match candidate_status(&self.candidate, &self.marker) {
                    CandidateStatus::Ongoing => continue,
                    CandidateStatus::Boundary(closing) => {
                        if !data.is_empty() {
                            events.push(StreamEvent::Data(std::mem::take(&mut data)));
                        }
                        events.push(StreamEvent::Boundary { closing });
                        self.candidate.clear();
                        self.at_line_start = true;
                        self.previous_cr = false;
                        continue;
                    }
                    CandidateStatus::Invalid => {
                        data.extend_from_slice(&self.candidate);
                        self.previous_cr = self.candidate.last() == Some(&b'\r');
                        self.at_line_start = false;
                        self.candidate.clear();
                        continue;
                    }
                }
            }
            data.push(byte);
            self.at_line_start = self.previous_cr && byte == b'\n';
            self.previous_cr = byte == b'\r';
        }
        if !data.is_empty() {
            events.push(StreamEvent::Data(data));
        }
        Ok(events)
    }

    pub fn finish(&mut self) -> Option<StreamEvent> {
        if self.candidate.is_empty() {
            None
        } else {
            Some(StreamEvent::Data(std::mem::take(&mut self.candidate)))
        }
    }
}

enum CandidateStatus {
    Ongoing,
    Boundary(bool),
    Invalid,
}

fn candidate_status(candidate: &[u8], marker: &[u8]) -> CandidateStatus {
    if candidate.len() <= marker.len() {
        return if marker.starts_with(candidate) {
            CandidateStatus::Ongoing
        } else {
            CandidateStatus::Invalid
        };
    }
    let suffix = &candidate[marker.len()..];
    if suffix == b"-" {
        return CandidateStatus::Ongoing;
    }
    let (closing, trailing) = if let Some(rest) = suffix.strip_prefix(b"--") {
        (true, rest)
    } else {
        (false, suffix)
    };
    if trailing == b"\r\n" {
        return CandidateStatus::Boundary(closing);
    }
    let whitespace_then_cr = trailing
        .strip_suffix(b"\r")
        .is_some_and(|prefix| prefix.iter().all(|byte| matches!(*byte, b' ' | b'\t')));
    if trailing.iter().all(|byte| matches!(*byte, b' ' | b'\t')) || whitespace_then_cr {
        CandidateStatus::Ongoing
    } else {
        CandidateStatus::Invalid
    }
}

#[derive(Clone, Debug)]
pub struct MimePart<'a> {
    pub headers: HeaderBlock,
    pub media_type: MediaType,
    pub disposition: Option<ContentDisposition>,
    pub transfer_encoding: TransferEncoding,
    pub body: &'a [u8],
    pub children: Vec<MimePart<'a>>,
    decode_limit: usize,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
#[error("MIME parse error at byte {position}: {kind}")]
pub struct MimeError {
    pub position: usize,
    pub recoverable: bool,
    pub kind: MimeErrorKind,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum MimeErrorKind {
    #[error("MIME input exceeds configured limit")]
    InputLimit,
    #[error("invalid message headers")]
    InvalidHeaders,
    #[error("invalid Content-Type or Content-Disposition")]
    InvalidParameter,
    #[error("multipart boundary is missing or invalid")]
    InvalidBoundary,
    #[error("multipart boundary is not closed")]
    UnterminatedMultipart,
    #[error("MIME nesting exceeds configured limit")]
    DepthLimit,
    #[error("MIME part count exceeds configured limit")]
    PartLimit,
    #[error("decoded body exceeds configured limit")]
    DecodeLimit,
    #[error("invalid content-transfer-encoding")]
    InvalidTransferEncoding,
}

pub fn parse_message(input: &[u8], limits: MimeLimits) -> Result<MimePart<'_>, MimeError> {
    if input.len() > limits.max_input_bytes {
        return Err(fatal(limits.max_input_bytes, MimeErrorKind::InputLimit));
    }
    let (headers, body) = split_headers(input, limits.message)?;
    let mut count = 0;
    parse_entity(headers, body, limits, 0, &mut count)
}

fn parse_entity<'a>(
    headers: HeaderBlock,
    body: &'a [u8],
    limits: MimeLimits,
    depth: usize,
    count: &mut usize,
) -> Result<MimePart<'a>, MimeError> {
    if depth > limits.max_depth {
        return Err(fatal(0, MimeErrorKind::DepthLimit));
    }
    *count = count.saturating_add(1);
    if *count > limits.max_parts {
        return Err(fatal(0, MimeErrorKind::PartLimit));
    }
    let media_type = single_header(&headers, "content-type")?
        .map(parse_media_type)
        .transpose()?
        .unwrap_or_else(default_media_type);
    let disposition = single_header(&headers, "content-disposition")?
        .map(parse_disposition)
        .transpose()?;
    let transfer_encoding =
        parse_transfer_encoding(single_header(&headers, "content-transfer-encoding")?);
    let mut children = Vec::new();
    if media_type.top == "multipart" {
        let boundary = parameter(&media_type.parameters, "boundary")
            .ok_or_else(|| recoverable(0, MimeErrorKind::InvalidBoundary))?;
        if boundary.is_empty()
            || boundary.len() > limits.max_boundary_bytes
            || !boundary.iter().all(|byte| matches!(*byte, 32..=126))
        {
            return Err(recoverable(0, MimeErrorKind::InvalidBoundary));
        }
        for child in multipart_slices(body, boundary, limits.max_parts.saturating_add(1))? {
            let (child_headers, child_body) = split_headers(child, limits.message)?;
            children.push(parse_entity(
                child_headers,
                child_body,
                limits,
                depth + 1,
                count,
            )?);
        }
    } else if media_type.top == "message" && media_type.subtype == "rfc822" {
        let (child_headers, child_body) = split_headers(body, limits.message)?;
        children.push(parse_entity(
            child_headers,
            child_body,
            limits,
            depth + 1,
            count,
        )?);
    }
    Ok(MimePart {
        headers,
        media_type,
        disposition,
        transfer_encoding,
        body,
        children,
        decode_limit: limits.max_decoded_bytes,
    })
}

impl MimePart<'_> {
    pub fn decoded_body(&self, limit: usize) -> Result<Vec<u8>, MimeError> {
        let limit = limit.min(self.decode_limit).min(usize::MAX / 2);
        match &self.transfer_encoding {
            TransferEncoding::Base64 => {
                let encoded = self
                    .body
                    .iter()
                    .copied()
                    .filter(|byte| !byte.is_ascii_whitespace())
                    .collect::<Vec<_>>();
                if encoded.len().saturating_add(3) / 4 * 3 > limit {
                    return Err(fatal(0, MimeErrorKind::DecodeLimit));
                }
                let decoded = STANDARD
                    .decode(encoded)
                    .map_err(|_| recoverable(0, MimeErrorKind::InvalidTransferEncoding))?;
                if decoded.len() > limit {
                    Err(fatal(0, MimeErrorKind::DecodeLimit))
                } else {
                    Ok(decoded)
                }
            }
            TransferEncoding::QuotedPrintable => {
                if self.body.len() > limit.saturating_mul(3) {
                    return Err(fatal(0, MimeErrorKind::DecodeLimit));
                }
                let decoded = quoted_printable::decode(self.body, ParseMode::Robust)
                    .map_err(|_| recoverable(0, MimeErrorKind::InvalidTransferEncoding))?;
                if decoded.len() > limit {
                    Err(fatal(0, MimeErrorKind::DecodeLimit))
                } else {
                    Ok(decoded)
                }
            }
            TransferEncoding::Other(_) => {
                Err(recoverable(0, MimeErrorKind::InvalidTransferEncoding))
            }
            _ if self.body.len() > limit => Err(fatal(0, MimeErrorKind::DecodeLimit)),
            _ => Ok(self.body.to_vec()),
        }
    }
}

fn split_headers(input: &[u8], limits: MessageLimits) -> Result<(HeaderBlock, &[u8]), MimeError> {
    let mut parser = MessageParser::new(limits);
    match parser
        .push(input)
        .map_err(|error| fatal(error.position, MimeErrorKind::InvalidHeaders))?
    {
        ParseProgress::Complete { headers, consumed } => Ok((headers, &input[consumed..])),
        ParseProgress::NeedMore => Err(recoverable(input.len(), MimeErrorKind::InvalidHeaders)),
    }
}

fn single_header<'a>(
    headers: &'a HeaderBlock,
    name: &'a str,
) -> Result<Option<&'a [u8]>, MimeError> {
    let mut values = headers.get_all(name);
    let value = values.next();
    if values.next().is_some() {
        Err(recoverable(0, MimeErrorKind::InvalidHeaders))
    } else {
        Ok(value)
    }
}

fn parse_media_type(input: &[u8]) -> Result<MediaType, MimeError> {
    let (value, parameters) = parse_parameterized(input)?;
    let slash = value
        .iter()
        .position(|byte| *byte == b'/')
        .ok_or_else(|| recoverable(0, MimeErrorKind::InvalidParameter))?;
    let top = ascii_token(&value[..slash])?;
    let subtype = ascii_token(&value[slash + 1..])?;
    Ok(MediaType {
        top,
        subtype,
        parameters,
    })
}

fn parse_disposition(input: &[u8]) -> Result<ContentDisposition, MimeError> {
    let (value, parameters) = parse_parameterized(input)?;
    Ok(ContentDisposition {
        kind: ascii_token(value)?,
        parameters,
    })
}

fn parse_parameterized(input: &[u8]) -> Result<(&[u8], Parameters), MimeError> {
    let segments = split_semicolon(input)?;
    let value = trim(segments.first().copied().unwrap_or_default());
    let mut parameters = Vec::new();
    for segment in segments.into_iter().skip(1) {
        let equal = segment
            .iter()
            .position(|byte| *byte == b'=')
            .ok_or_else(|| recoverable(0, MimeErrorKind::InvalidParameter))?;
        let name = ascii_token(trim(&segment[..equal]))?;
        let raw = trim(&segment[equal + 1..]);
        let value = if raw.starts_with(b"\"") && raw.ends_with(b"\"") && raw.len() >= 2 {
            unquote(&raw[1..raw.len() - 1])?
        } else {
            raw.to_vec()
        };
        parameters.push((name, value));
    }
    Ok((value, parameters))
}

fn split_semicolon(input: &[u8]) -> Result<Vec<&[u8]>, MimeError> {
    let mut output = Vec::new();
    let mut start = 0;
    let mut quoted = false;
    let mut escaped = false;
    for (index, byte) in input.iter().copied().enumerate() {
        if escaped {
            escaped = false;
            continue;
        }
        if quoted && byte == b'\\' {
            escaped = true;
        } else if byte == b'"' {
            quoted = !quoted;
        } else if byte == b';' && !quoted {
            output.push(&input[start..index]);
            start = index + 1;
        }
    }
    if quoted || escaped {
        return Err(recoverable(input.len(), MimeErrorKind::InvalidParameter));
    }
    output.push(&input[start..]);
    Ok(output)
}

fn unquote(input: &[u8]) -> Result<Vec<u8>, MimeError> {
    let mut output = Vec::with_capacity(input.len());
    let mut escaped = false;
    for byte in input.iter().copied() {
        if escaped {
            output.push(byte);
            escaped = false;
        } else if byte == b'\\' {
            escaped = true;
        } else if byte == b'\r' || byte == b'\n' {
            return Err(recoverable(0, MimeErrorKind::InvalidParameter));
        } else {
            output.push(byte);
        }
    }
    if escaped {
        Err(recoverable(input.len(), MimeErrorKind::InvalidParameter))
    } else {
        Ok(output)
    }
}

fn multipart_slices<'a>(
    body: &'a [u8],
    boundary: &[u8],
    max_markers: usize,
) -> Result<Vec<&'a [u8]>, MimeError> {
    let mut markers = Vec::new();
    let mut line_start = 0;
    while line_start <= body.len() {
        let line_end = body[line_start..]
            .windows(2)
            .position(|pair| pair == b"\r\n")
            .map_or(body.len(), |offset| line_start + offset);
        let line = &body[line_start..line_end];
        if let Some(rest) = line
            .strip_prefix(b"--")
            .and_then(|line| line.strip_prefix(boundary))
        {
            let closing = rest.starts_with(b"--");
            let trailing = if closing { &rest[2..] } else { rest };
            if trailing.iter().all(|byte| matches!(*byte, b' ' | b'\t')) {
                markers.push((line_start, (line_end + 2).min(body.len()), closing));
                if markers.len() > max_markers {
                    return Err(fatal(line_start, MimeErrorKind::PartLimit));
                }
            }
        }
        if line_end == body.len() {
            break;
        }
        line_start = line_end + 2;
    }
    let mut parts = Vec::new();
    for window in markers.windows(2) {
        let (_, start, closing) = window[0];
        if closing {
            break;
        }
        let (mut end, _, _) = window[1];
        if end >= 2 && &body[end - 2..end] == b"\r\n" {
            end -= 2;
        }
        parts.push(&body[start..end]);
    }
    if !markers.last().is_some_and(|marker| marker.2) {
        return Err(recoverable(
            body.len(),
            MimeErrorKind::UnterminatedMultipart,
        ));
    }
    Ok(parts)
}

#[must_use]
pub fn has_valid_mime_version(headers: &HeaderBlock) -> bool {
    let mut versions = headers.get_all("mime-version");
    matches!(versions.next().map(trim), Some(b"1.0")) && versions.next().is_none()
}

fn parse_transfer_encoding(value: Option<&[u8]>) -> TransferEncoding {
    let value = value.map_or(&b"7bit"[..], trim).to_ascii_lowercase();
    match value.as_slice() {
        b"7bit" => TransferEncoding::SevenBit,
        b"8bit" => TransferEncoding::EightBit,
        b"binary" => TransferEncoding::Binary,
        b"base64" => TransferEncoding::Base64,
        b"quoted-printable" => TransferEncoding::QuotedPrintable,
        _ => TransferEncoding::Other(String::from_utf8_lossy(&value).into_owned()),
    }
}

fn default_media_type() -> MediaType {
    MediaType {
        top: "text".into(),
        subtype: "plain".into(),
        parameters: vec![("charset".into(), b"us-ascii".to_vec())],
    }
}
fn parameter<'a>(parameters: &'a [(String, Vec<u8>)], name: &str) -> Option<&'a [u8]> {
    parameters
        .iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.as_slice())
}
fn ascii_token(input: &[u8]) -> Result<String, MimeError> {
    if input.is_empty()
        || !input
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(byte))
    {
        return Err(recoverable(0, MimeErrorKind::InvalidParameter));
    }
    Ok(String::from_utf8_lossy(input).to_ascii_lowercase())
}
fn trim(mut input: &[u8]) -> &[u8] {
    while input.first().is_some_and(u8::is_ascii_whitespace) {
        input = &input[1..];
    }
    while input.last().is_some_and(u8::is_ascii_whitespace) {
        input = &input[..input.len() - 1];
    }
    input
}
fn fatal(position: usize, kind: MimeErrorKind) -> MimeError {
    MimeError {
        position,
        recoverable: false,
        kind,
    }
}
fn recoverable(position: usize, kind: MimeErrorKind) -> MimeError {
    MimeError {
        position,
        recoverable: true,
        kind,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn nested_multipart_preserves_body_slices_and_decodes() -> Result<(), MimeError> {
        let raw = b"MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=outer\r\n\r\npreamble\r\n--outer\r\nContent-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\naGVsbG8=\r\n--outer--\r\nepilogue";
        let parsed = parse_message(raw, MimeLimits::default())?;
        assert_eq!(parsed.children.len(), 1);
        assert_eq!(parsed.children[0].decoded_body(100)?, b"hello");
        assert!(has_valid_mime_version(&parsed.headers));
        assert_eq!(
            parsed.headers.raw(),
            &raw[..raw
                .windows(4)
                .position(|part| part == b"\r\n\r\n")
                .unwrap_or_default()
                + 4]
        );
        Ok(())
    }

    #[test]
    fn boundary_prefix_is_body_and_decode_limit_is_enforced() -> Result<(), MimeError> {
        let raw = b"MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=x\r\n\r\n--xyz\r\nnot a marker\r\n--x\r\nContent-Transfer-Encoding: base64\r\n\r\naGVsbG8=\r\n--x--\r\n";
        let parsed = parse_message(
            raw,
            MimeLimits {
                max_decoded_bytes: 4,
                ..MimeLimits::default()
            },
        )?;
        assert_eq!(parsed.children.len(), 1);
        assert!(matches!(
            parsed.children[0].decoded_body(100),
            Err(MimeError {
                kind: MimeErrorKind::DecodeLimit,
                ..
            })
        ));
        Ok(())
    }

    #[test]
    fn streaming_boundary_scanner_handles_every_split() -> Result<(), MimeError> {
        let input = b"preamble\r\n--abc\r\npart\r\n--abc--\r\nepilogue";
        for split in 0..input.len() {
            let mut scanner = BoundaryScanner::new(b"abc", MimeLimits::default())?;
            let mut events = scanner.push(&input[..split])?;
            events.extend(scanner.push(&input[split..])?);
            if let Some(event) = scanner.finish() {
                events.push(event);
            }
            assert_eq!(
                events
                    .iter()
                    .filter(|event| matches!(event, StreamEvent::Boundary { .. }))
                    .count(),
                2
            );
            assert!(
                events
                    .iter()
                    .any(|event| matches!(event, StreamEvent::Boundary { closing: true }))
            );
        }
        Ok(())
    }

    proptest! {
        #[test]
        fn arbitrary_mime_never_panics(input in proptest::collection::vec(any::<u8>(), 0..8192)) {
            let _ = parse_message(&input, MimeLimits { max_parts: 32, max_depth: 4, message: MessageLimits { max_header_bytes: 4096, ..MessageLimits::default() }, ..MimeLimits::default() });
        }
    }
}
