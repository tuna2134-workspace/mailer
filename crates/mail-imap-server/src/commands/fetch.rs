use mail_address::{Address, AddressLimits, Mailbox, parse_address_list};
use mail_mime::{MimeLimits, MimePart, TransferEncoding, parse_message};
use mail_storage::ImapMessage;
use time::{OffsetDateTime, format_description::well_known::Rfc2822};

pub(super) fn response(message: &ImapMessage, items: &str) -> Vec<u8> {
    let upper = items.to_ascii_uppercase();
    let mut fields = Vec::new();
    if upper.contains("FLAGS") {
        fields.push(format!("FLAGS ({})", message.flags.join(" ")).into_bytes());
    }
    if upper.contains("UID") {
        fields.push(format!("UID {}", message.uid).into_bytes());
    }
    if upper.contains("RFC822.SIZE") {
        fields.push(format!("RFC822.SIZE {}", message.raw.len()).into_bytes());
    }
    if upper.contains("INTERNALDATE") {
        let date = OffsetDateTime::from(message.internal_date)
            .format(&Rfc2822)
            .unwrap_or_else(|_| "Thu, 1 Jan 1970 00:00:00 +0000".into());
        fields.push(format!("INTERNALDATE \"{date}\"").into_bytes());
    }
    if upper.contains("ENVELOPE") {
        fields.push(envelope(&message.raw).into_bytes());
    }
    if upper.contains("BODYSTRUCTURE") {
        fields.push(format!("BODYSTRUCTURE {}", body_structure(&message.raw)).into_bytes());
    } else if upper.split_whitespace().any(|item| item == "BODY") {
        fields.push(format!("BODY {}", body_structure(&message.raw)).into_bytes());
    }
    for request in section_requests(&upper) {
        fields.push(literal_field(&message.raw, &request));
    }
    for request in binary_requests(&upper) {
        fields.push(binary_field(&message.raw, &request));
    }
    if upper.contains("RFC822.HEADER") {
        fields.push(literal("RFC822.HEADER", header_body(&message.raw).0, None));
    } else if upper.contains("RFC822.TEXT") {
        fields.push(literal("RFC822.TEXT", header_body(&message.raw).1, None));
    } else if upper.split_whitespace().any(|item| item == "RFC822") {
        fields.push(literal("RFC822", &message.raw, None));
    }
    let mut response = format!("* {} FETCH (", message.sequence).into_bytes();
    for (index, field) in fields.iter().enumerate() {
        if index > 0 {
            response.push(b' ');
        }
        response.extend_from_slice(field);
    }
    response.extend_from_slice(b")\r\n");
    response
}

struct SectionRequest {
    section: String,
    partial: Option<(usize, usize)>,
}

struct BinaryRequest {
    section: String,
    size_only: bool,
    partial: Option<(usize, usize)>,
}

fn section_requests(mut value: &str) -> Vec<SectionRequest> {
    let mut requests = Vec::new();
    while let Some(start) = value.find("BODY[").or_else(|| value.find("BODY.PEEK[")) {
        value = &value[start..];
        let Some(bracket) = value.find('[') else {
            break;
        };
        let Some(end) = value[bracket..].find(']').map(|end| end + bracket) else {
            break;
        };
        let section = value[bracket + 1..end].to_owned();
        let partial = value[end + 1..]
            .strip_prefix('<')
            .and_then(|rest| rest.split_once('>'))
            .and_then(|(range, _)| range.split_once('.'))
            .and_then(|(offset, count)| Some((offset.parse().ok()?, count.parse().ok()?)));
        requests.push(SectionRequest { section, partial });
        value = &value[end + 1..];
    }
    requests
}

fn binary_requests(mut value: &str) -> Vec<BinaryRequest> {
    let mut requests = Vec::new();
    while let Some(start) = value
        .find("BINARY[")
        .or_else(|| value.find("BINARY.PEEK["))
        .or_else(|| value.find("BINARY.SIZE["))
    {
        value = &value[start..];
        let Some(bracket) = value.find('[') else {
            break;
        };
        let Some(end) = value[bracket..].find(']').map(|end| end + bracket) else {
            break;
        };
        let section = value[bracket + 1..end].to_owned();
        let partial = value[end + 1..]
            .strip_prefix('<')
            .and_then(|rest| rest.split_once('>'))
            .and_then(|(range, _)| range.split_once('.'))
            .and_then(|(offset, count)| Some((offset.parse().ok()?, count.parse().ok()?)));
        requests.push(BinaryRequest {
            section,
            size_only: value.starts_with("BINARY.SIZE["),
            partial,
        });
        value = &value[end + 1..];
    }
    requests
}

fn literal_field(raw: &[u8], request: &SectionRequest) -> Vec<u8> {
    let (headers, body) = header_body(raw);
    let bytes = match request.section.as_str() {
        "" => raw.to_vec(),
        "HEADER" | "MIME" | "1.MIME" => headers.to_vec(),
        "TEXT" | "1" | "1.TEXT" => body.to_vec(),
        section if section.starts_with("HEADER.FIELDS.NOT ") => {
            filter_headers(headers, section, true)
        }
        section if section.starts_with("HEADER.FIELDS ") => filter_headers(headers, section, false),
        section => mime_section(raw, section).unwrap_or_default(),
    };
    literal(
        &format!("BODY[{}]", request.section),
        &bytes,
        request.partial,
    )
}

fn binary_field(raw: &[u8], request: &BinaryRequest) -> Vec<u8> {
    let decoded = decoded_section(raw, &request.section).unwrap_or_default();
    if request.size_only {
        return format!("BINARY.SIZE[{}] {}", request.section, decoded.len()).into_bytes();
    }
    literal(
        &format!("BINARY[{}]", request.section),
        &decoded,
        request.partial,
    )
}

fn decoded_section(raw: &[u8], section: &str) -> Option<Vec<u8>> {
    let root = parse_message(raw, mime_limits(raw.len())).ok()?;
    let part = part(&root, section)?;
    part.decoded_body(raw.len().saturating_mul(2).max(1)).ok()
}

fn part<'a, 'raw>(root: &'a MimePart<'raw>, section: &str) -> Option<&'a MimePart<'raw>> {
    if section.is_empty() {
        return Some(root);
    }
    let mut part = root;
    for (depth, component) in section.split('.').enumerate() {
        let index = component.parse::<usize>().ok()?.checked_sub(1)?;
        if depth == 0 && root.children.is_empty() && index == 0 {
            part = root;
        } else {
            part = part.children.get(index)?;
        }
    }
    Some(part)
}

fn literal(label: &str, bytes: &[u8], partial: Option<(usize, usize)>) -> Vec<u8> {
    let (offset, count) = partial.unwrap_or((0, bytes.len()));
    let end = offset.saturating_add(count).min(bytes.len());
    let selected = bytes.get(offset..end).unwrap_or_default();
    let suffix = partial.map_or_else(String::new, |(offset, _)| format!("<{offset}>"));
    let mut field = format!("{label}{suffix} {{{}}}\r\n", selected.len()).into_bytes();
    field.extend_from_slice(selected);
    field
}

pub(super) fn header_body(raw: &[u8]) -> (&[u8], &[u8]) {
    raw.windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map_or((raw, &[]), |at| raw.split_at(at + 4))
}

pub(super) fn header(raw: &[u8], name: &str) -> Option<Vec<u8>> {
    let (headers, _) = header_body(raw);
    let mut value = Vec::new();
    let mut matched = false;
    for line in headers.split(|byte| *byte == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line
            .first()
            .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
        {
            if matched {
                value.push(b' ');
                value.extend_from_slice(line.trim_ascii());
            }
            continue;
        }
        let Some((field, content)) = split_colon(line) else {
            continue;
        };
        matched = field.eq_ignore_ascii_case(name.as_bytes());
        if matched {
            value.extend_from_slice(content.trim_ascii());
        } else if !value.is_empty() {
            break;
        }
    }
    (!value.is_empty()).then_some(value)
}

fn filter_headers(headers: &[u8], section: &str, invert: bool) -> Vec<u8> {
    let Some(open) = section.find('(') else {
        return Vec::new();
    };
    let Some(close) = section.rfind(')') else {
        return Vec::new();
    };
    let names = section[open + 1..close]
        .split_whitespace()
        .collect::<Vec<_>>();
    let mut output = Vec::new();
    let mut keep = false;
    for line in headers.split_inclusive(|byte| *byte == b'\n') {
        if !line
            .first()
            .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
        {
            keep = split_colon(line).is_some_and(|(name, _)| {
                names
                    .iter()
                    .any(|wanted| name.eq_ignore_ascii_case(wanted.as_bytes()))
            });
            keep ^= invert;
        }
        if keep {
            output.extend_from_slice(line);
        }
    }
    output.extend_from_slice(b"\r\n");
    output
}

fn split_colon(line: &[u8]) -> Option<(&[u8], &[u8])> {
    let at = line.iter().position(|byte| *byte == b':')?;
    Some((&line[..at], &line[at + 1..]))
}

fn envelope(raw: &[u8]) -> String {
    let field = |name| header(raw, name).map_or_else(|| "NIL".into(), |value| quoted(&value));
    let addresses = |name| address_list(header(raw, name).as_deref());
    let from = addresses("From");
    let sender = header(raw, "Sender")
        .as_deref()
        .map_or_else(|| from.clone(), |value| address_list(Some(value)));
    let reply_to = header(raw, "Reply-To")
        .as_deref()
        .map_or_else(|| from.clone(), |value| address_list(Some(value)));
    format!(
        "ENVELOPE ({} {} {} {} {} {} {} {} {} {})",
        field("Date"),
        field("Subject"),
        from,
        sender,
        reply_to,
        addresses("To"),
        addresses("Cc"),
        addresses("Bcc"),
        field("In-Reply-To"),
        field("Message-ID")
    )
}

fn address_list(value: Option<&[u8]>) -> String {
    let Some(value) = value else {
        return "NIL".into();
    };
    let Ok(addresses) = parse_address_list(value, AddressLimits::default()) else {
        return "NIL".into();
    };
    let mut output = Vec::new();
    for address in addresses {
        match address {
            Address::Mailbox(mailbox) => output.push(mailbox_address(&mailbox)),
            Address::Group(group) => {
                output.push(format!("({} NIL NIL NIL)", quoted(&group.display_name)));
                output.extend(group.members.iter().map(mailbox_address));
                output.push("(NIL NIL NIL NIL)".into());
            }
        }
    }
    format!("({})", output.join(" "))
}

fn mailbox_address(mailbox: &Mailbox) -> String {
    format!(
        "({} NIL {} {})",
        mailbox
            .display_name
            .as_deref()
            .map_or_else(|| "NIL".into(), quoted),
        quoted(&mailbox.local_part),
        quoted(&mailbox.domain)
    )
}

fn body_structure(raw: &[u8]) -> String {
    if let Ok(root) = parse_message(raw, mime_limits(raw.len())) {
        return structure(&root);
    }
    let content_type = header(raw, "Content-Type").unwrap_or_else(|| b"text/plain".to_vec());
    let media = String::from_utf8_lossy(&content_type);
    let media = media.split(';').next().unwrap_or("text/plain");
    let (kind, subtype) = media.split_once('/').unwrap_or(("text", "plain"));
    let encoding = header(raw, "Content-Transfer-Encoding").unwrap_or_else(|| b"7BIT".to_vec());
    let body = header_body(raw).1;
    let lines = body.split(|byte| *byte == b'\n').count().saturating_sub(1);
    format!(
        "(\"{}\" \"{}\" NIL NIL NIL {} {} {})",
        kind.to_ascii_uppercase(),
        subtype.to_ascii_uppercase(),
        quoted(&encoding),
        body.len(),
        lines
    )
}

fn mime_section(raw: &[u8], section: &str) -> Option<Vec<u8>> {
    let mut components = section.split('.').collect::<Vec<_>>();
    let suffix = components
        .last()
        .filter(|value| matches!(**value, "MIME" | "TEXT" | "HEADER"))
        .copied();
    if suffix.is_some() {
        components.pop();
    }
    if components.is_empty()
        || components
            .iter()
            .any(|value| value.parse::<usize>().ok().is_none_or(|number| number == 0))
    {
        return None;
    }
    let root = parse_message(raw, mime_limits(raw.len())).ok()?;
    let part = part(&root, &components.join("."))?;
    Some(match suffix {
        Some("MIME" | "HEADER") => part.headers.raw().to_vec(),
        Some("TEXT") | None => part.body.to_vec(),
        _ => return None,
    })
}

fn structure(part: &MimePart<'_>) -> String {
    if !part.children.is_empty() && part.media_type.top == "multipart" {
        return format!(
            "({} \"{}\")",
            part.children
                .iter()
                .map(structure)
                .collect::<Vec<_>>()
                .join(" "),
            part.media_type.subtype.to_ascii_uppercase()
        );
    }
    let parameters = if part.media_type.parameters.is_empty() {
        "NIL".into()
    } else {
        format!(
            "({})",
            part.media_type
                .parameters
                .iter()
                .map(|(name, value)| format!("\"{}\" {}", name.to_ascii_uppercase(), quoted(value)))
                .collect::<Vec<_>>()
                .join(" ")
        )
    };
    let encoding = match &part.transfer_encoding {
        TransferEncoding::SevenBit => "7BIT",
        TransferEncoding::EightBit => "8BIT",
        TransferEncoding::Binary => "BINARY",
        TransferEncoding::Base64 => "BASE64",
        TransferEncoding::QuotedPrintable => "QUOTED-PRINTABLE",
        TransferEncoding::Other(value) => value,
    };
    let base = format!(
        "(\"{}\" \"{}\" {parameters} NIL NIL \"{}\" {}",
        part.media_type.top.to_ascii_uppercase(),
        part.media_type.subtype.to_ascii_uppercase(),
        encoding.to_ascii_uppercase(),
        part.body.len()
    );
    if part.media_type.top == "text" {
        format!(
            "{base} {})",
            part.body
                .split(|byte| *byte == b'\n')
                .count()
                .saturating_sub(1)
        )
    } else {
        format!("{base})")
    }
}

fn mime_limits(size: usize) -> MimeLimits {
    MimeLimits {
        max_input_bytes: size.max(1),
        ..MimeLimits::default()
    }
}

fn quoted(value: &[u8]) -> String {
    if value.iter().any(|byte| *byte < 0x20 || *byte >= 0x7f) {
        return format!("{{{}}}\r\n{}", value.len(), String::from_utf8_lossy(value));
    }
    format!(
        "\"{}\"",
        String::from_utf8_lossy(value)
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sections_envelope_structure_and_partials() {
        let raw=b"Date: Thu, 7 Aug 2026 12:00:00 +0000\r\nSubject: test\r\nFrom: Alice <alice@example.test>\r\nTo: bob@example.test\r\nX-Ignore: no\r\nContent-Type: text/plain\r\n\r\nbody\r\n";
        assert_eq!(header_body(raw).1, b"body\r\n");
        assert_eq!(section_requests("BODY[TEXT]<1.2>")[0].partial, Some((1, 2)));
        let field = literal_field(
            raw,
            &SectionRequest {
                section: "HEADER.FIELDS (SUBJECT)".into(),
                partial: None,
            },
        );
        assert!(
            field
                .windows(13)
                .any(|window| window.eq_ignore_ascii_case(b"Subject: test"))
        );
        assert!(envelope(raw).contains("\"test\""));
        assert!(envelope(raw).contains("\"alice\" \"example.test\""));
        assert!(body_structure(raw).starts_with("(\"TEXT\" \"PLAIN\""));
        let multipart=b"Content-Type: multipart/mixed; boundary=x\r\n\r\n--x\r\nContent-Type: text/plain\r\n\r\none\r\n--x\r\nContent-Type: text/html\r\n\r\n<b>two</b>\r\n--x--\r\n";
        assert_eq!(
            mime_section(multipart, "2").as_deref(),
            Some(b"<b>two</b>".as_slice())
        );
        assert!(body_structure(multipart).contains("\"MIXED\""));
        let encoded = b"Content-Transfer-Encoding: base64\r\n\r\nYm9keQ==";
        assert_eq!(decoded_section(encoded, ""), Some(b"body".to_vec()));
        assert!(binary_requests("BINARY.SIZE[]")[0].size_only);
    }
}
