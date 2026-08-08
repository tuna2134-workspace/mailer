use crate::DkimError;
use std::collections::HashMap;

pub(crate) fn parse(header: &[u8]) -> Result<HashMap<String, String>, DkimError> {
    if !header.is_ascii() {
        return Err(DkimError::Malformed);
    }
    let colon = header
        .iter()
        .position(|byte| *byte == b':')
        .ok_or(DkimError::Malformed)?;
    let value = unfold(&header[colon + 1..])?;
    let value = std::str::from_utf8(&value).map_err(|_| DkimError::Malformed)?;
    let mut tags = HashMap::new();
    for part in value
        .split(';')
        .map(str::trim)
        .filter(|part| !part.is_empty())
    {
        let (name, value) = part.split_once('=').ok_or(DkimError::Malformed)?;
        let name = name.trim();
        if !valid_name(name)
            || tags
                .insert(name.to_owned(), value.trim().to_owned())
                .is_some()
        {
            return Err(DkimError::Malformed);
        }
    }
    Ok(tags)
}

pub(crate) fn first_name(header: &[u8]) -> Result<String, DkimError> {
    let colon = header
        .iter()
        .position(|byte| *byte == b':')
        .ok_or(DkimError::Malformed)?;
    let value = unfold(&header[colon + 1..])?;
    let first = value
        .split(|byte| *byte == b';')
        .next()
        .ok_or(DkimError::Malformed)?;
    let equals = first
        .iter()
        .position(|byte| *byte == b'=')
        .ok_or(DkimError::Malformed)?;
    let name = std::str::from_utf8(&first[..equals])
        .map_err(|_| DkimError::Malformed)?
        .trim();
    valid_name(name)
        .then(|| name.to_owned())
        .ok_or(DkimError::Malformed)
}

fn unfold(value: &[u8]) -> Result<Vec<u8>, DkimError> {
    let mut output = Vec::with_capacity(value.len());
    let mut position = 0;
    while position < value.len() {
        match value[position] {
            b'\r'
                if value.get(position + 1) == Some(&b'\n')
                    && value
                        .get(position + 2)
                        .is_some_and(|byte| matches!(byte, b' ' | b'\t')) =>
            {
                output.push(b' ');
                position += 2;
                while value
                    .get(position)
                    .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
                {
                    position += 1;
                }
            }
            b'\r' if value.get(position + 1) == Some(&b'\n') && position + 2 == value.len() => {
                position += 2;
            }
            b'\r' | b'\n' => return Err(DkimError::Malformed),
            byte => {
                output.push(byte);
                position += 1;
            }
        }
    }
    Ok(output)
}

fn valid_name(value: &str) -> bool {
    value.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_duplicate_tags_and_invalid_folding() {
        assert!(parse(b"DKIM-Signature: v=1; v=1\r\n").is_err());
        assert!(parse(b"DKIM-Signature: v=1\r\nx=1\r\n").is_err());
        assert_eq!(
            parse(b"DKIM-Signature: v=1;\r\n a=rsa-sha256\r\n")
                .ok()
                .and_then(|tags| tags.get("a").cloned()),
            Some("rsa-sha256".into())
        );
    }
}
