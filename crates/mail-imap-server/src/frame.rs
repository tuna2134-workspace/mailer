use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{ImapConfig, ImapError};

pub(crate) struct Frame {
    pub line: Vec<u8>,
    pub literals: Vec<Vec<u8>>,
}

pub(crate) async fn read_frame<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    config: &ImapConfig,
) -> Result<Option<Frame>, ImapError> {
    let Some(mut line) = read_line(stream, mail_imap_proto::MAX_COMMAND_LINE).await? else {
        return Ok(None);
    };
    let mut literals = Vec::new();
    let mut consumed_marker = None;
    loop {
        let Some((length, non_sync, marker_offset)) = literal_marker(&line) else {
            return Ok(Some(Frame { line, literals }));
        };
        if consumed_marker.is_some_and(|offset| marker_offset <= offset) {
            return Ok(Some(Frame { line, literals }));
        }
        if length > config.max_literal_size {
            return Err(ImapError::LiteralTooLarge);
        }
        if !non_sync {
            stream.write_all(b"+ Ready for literal data\r\n").await?;
            stream.flush().await?;
        }
        let mut literal = vec![0; length];
        stream.read_exact(&mut literal).await?;
        literals.push(literal);
        consumed_marker = Some(marker_offset);
        line.truncate(line.len() - 2);
        let continuation = read_line(stream, mail_imap_proto::MAX_COMMAND_LINE)
            .await?
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "literal continuation"))?;
        if line.len().saturating_add(continuation.len()) > mail_imap_proto::MAX_COMMAND_LINE {
            return Err(ImapError::LineTooLong);
        }
        line.extend_from_slice(&continuation);
    }
}

pub(crate) async fn read_line<S: AsyncRead + Unpin>(
    stream: &mut S,
    limit: usize,
) -> Result<Option<Vec<u8>>, ImapError> {
    let mut line = Vec::new();
    loop {
        let mut byte = [0];
        match stream.read_exact(&mut byte).await {
            Ok(_) => line.push(byte[0]),
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof && line.is_empty() => {
                return Ok(None);
            }
            Err(error) => return Err(error.into()),
        }
        if line.len() > limit {
            return Err(ImapError::LineTooLong);
        }
        if line.ends_with(b"\r\n") {
            return Ok(Some(line));
        }
        if line.ends_with(b"\n") {
            return Err(ImapError::BadLineEnding);
        }
    }
}

fn literal_marker(line: &[u8]) -> Option<(usize, bool, usize)> {
    let content = line.strip_suffix(b"\r\n")?;
    let open = content.iter().rposition(|byte| *byte == b'{')?;
    let marker = content.get(open + 1..)?.strip_suffix(b"}")?;
    let (digits, non_sync) = marker
        .strip_suffix(b"+")
        .map_or((marker, false), |digits| (digits, true));
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(digits)
        .ok()?
        .parse()
        .ok()
        .map(|length| (length, non_sync, open))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_terminal_literal_markers_only() {
        assert_eq!(literal_marker(b"A LOGIN {5}\r\n"), Some((5, false, 8)));
        assert_eq!(literal_marker(b"A LOGIN {5+}\r\n"), Some((5, true, 8)));
        assert_eq!(literal_marker(b"A NOOP {x}\r\n"), None);
    }
}
