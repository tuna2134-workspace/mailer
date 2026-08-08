use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{ImapConfig, ImapError};

pub(crate) struct Frame {
    pub line: Vec<u8>,
    pub literals: Vec<Vec<u8>>,
    pub spooled_append: Option<std::fs::File>,
}

const MAX_IN_MEMORY_LITERAL: usize = 64 * 1024;
const COPY_BUFFER_SIZE: usize = 64 * 1024;

pub(crate) async fn read_frame<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    config: &ImapConfig,
) -> Result<Option<Frame>, ImapError> {
    let Some(mut line) = read_line(stream, mail_imap_proto::MAX_COMMAND_LINE).await? else {
        return Ok(None);
    };
    let mut literals = Vec::new();
    let mut spooled_append = None;
    let mut consumed_marker = None;
    loop {
        let Some((length, non_sync, marker_offset)) = literal_marker(&line) else {
            return Ok(Some(Frame {
                line,
                literals,
                spooled_append,
            }));
        };
        if consumed_marker.is_some_and(|offset| marker_offset <= offset) {
            return Ok(Some(Frame {
                line,
                literals,
                spooled_append,
            }));
        }
        if length > config.max_literal_size {
            return Err(ImapError::LiteralTooLarge);
        }
        if !non_sync {
            stream.write_all(b"+ Ready for literal data\r\n").await?;
            stream.flush().await?;
        }
        if length > MAX_IN_MEMORY_LITERAL && is_append(&line) {
            let mut file =
                tokio::fs::File::from_std(tempfile::tempfile().map_err(ImapError::from)?);
            copy_exact(stream, &mut file, length).await?;
            file.flush().await?;
            file.sync_data().await?;
            spooled_append = Some(file.into_std().await);
            literals.push(Vec::new());
            line.splice(marker_offset..line.len() - 2, b"{0}".iter().copied());
        } else {
            let mut literal = vec![0; length];
            stream.read_exact(&mut literal).await?;
            literals.push(literal);
        }
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

async fn copy_exact<R: AsyncRead + Unpin>(
    source: &mut R,
    destination: &mut tokio::fs::File,
    length: usize,
) -> Result<(), ImapError> {
    let mut remaining = length;
    let mut buffer = vec![0; COPY_BUFFER_SIZE.min(length)];
    while remaining > 0 {
        let count = remaining.min(buffer.len());
        source.read_exact(&mut buffer[..count]).await?;
        destination.write_all(&buffer[..count]).await?;
        remaining -= count;
    }
    Ok(())
}

fn is_append(line: &[u8]) -> bool {
    line.split(u8::is_ascii_whitespace)
        .nth(1)
        .is_some_and(|command| command.eq_ignore_ascii_case(b"APPEND"))
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

    #[tokio::test]
    async fn large_append_is_spooled() -> Result<(), ImapError> {
        let size = MAX_IN_MEMORY_LITERAL + 1;
        let wire = [
            format!("A APPEND INBOX {{{size}+}}\r\n").into_bytes(),
            vec![b'x'; size],
            b"\r\n".to_vec(),
        ]
        .concat();
        let mut stream = tokio::io::BufStream::new(std::io::Cursor::new(wire));
        let frame = read_frame(
            &mut stream,
            &ImapConfig {
                max_literal_size: size,
                ..ImapConfig::default()
            },
        )
        .await?
        .ok_or(ImapError::Io("missing frame".into()))?;
        assert_eq!(frame.literals, [Vec::<u8>::new()]);
        assert!(matches!(
            mail_imap_proto::parse_command(&frame.line, &frame.literals)
                .map_err(|error| ImapError::Io(error.to_string()))?
                .body,
            mail_imap_proto::CommandBody::Append { message, .. } if message.is_empty()
        ));
        let file = frame
            .spooled_append
            .as_ref()
            .ok_or(ImapError::Io("missing spool".into()))?;
        assert_eq!(file.metadata()?.len(), size as u64);
        Ok(())
    }
}
