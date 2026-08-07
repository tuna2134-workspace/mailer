use crate::ParseError;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum BodyKind {
    #[default]
    SevenBit,
    EightBitMime,
    BinaryMime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliverByMode {
    Notify,
    Return,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeliverBy {
    pub seconds: i32,
    pub mode: DeliverByMode,
    pub trace: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FutureRelease {
    HoldFor(u32),
    HoldUntil(SystemTime),
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MailParameters {
    pub size: Option<u64>,
    pub body: BodyKind,
    pub smtp_utf8: bool,
    pub require_tls: bool,
    pub ret: Option<String>,
    pub envid: Option<String>,
    pub deliver_by: Option<DeliverBy>,
    pub future_release: Option<FutureRelease>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RcptParameters {
    pub notify: Option<String>,
    pub orcpt: Option<String>,
}

pub fn parse_mail(argument: Option<&str>) -> Result<(String, MailParameters), ParseError> {
    let (path, words) = path_and_words(argument, "FROM:", true)?;
    let mut parameters = MailParameters::default();
    let mut body_seen = false;
    for word in words {
        let (name, value) = parameter(word);
        match name.as_str() {
            "SIZE" if parameters.size.is_none() => {
                parameters.size = Some(
                    value
                        .ok_or(ParseError::InvalidSyntax)?
                        .parse()
                        .map_err(|_| ParseError::InvalidSyntax)?,
                );
            }
            "BODY" if !body_seen => {
                body_seen = true;
                parameters.body = match value.map(str::to_ascii_uppercase).as_deref() {
                    Some("7BIT") => BodyKind::SevenBit,
                    Some("8BITMIME") => BodyKind::EightBitMime,
                    Some("BINARYMIME") => BodyKind::BinaryMime,
                    _ => return Err(ParseError::InvalidSyntax),
                }
            }
            "SMTPUTF8" if value.is_none() && !parameters.smtp_utf8 => parameters.smtp_utf8 = true,
            "REQUIRETLS" if value.is_none() && !parameters.require_tls => {
                parameters.require_tls = true;
            }
            "RET" if parameters.ret.is_none() => {
                parameters.ret = Some(
                    value
                        .filter(|v| {
                            v.eq_ignore_ascii_case("FULL") || v.eq_ignore_ascii_case("HDRS")
                        })
                        .ok_or(ParseError::InvalidSyntax)?
                        .to_ascii_uppercase(),
                );
            }
            "ENVID" if parameters.envid.is_none() => {
                parameters.envid = Some(xtext(value.ok_or(ParseError::InvalidSyntax)?)?);
            }
            "BY" if parameters.deliver_by.is_none() => {
                parameters.deliver_by =
                    Some(parse_deliver_by(value.ok_or(ParseError::InvalidSyntax)?)?);
            }
            "HOLDFOR" if parameters.future_release.is_none() => {
                let seconds = positive_nine_digits(value.ok_or(ParseError::InvalidSyntax)?)?;
                parameters.future_release = Some(FutureRelease::HoldFor(seconds));
            }
            "HOLDUNTIL" if parameters.future_release.is_none() => {
                parameters.future_release = Some(FutureRelease::HoldUntil(parse_utc_time(
                    value.ok_or(ParseError::InvalidSyntax)?,
                )?));
            }
            _ => return Err(ParseError::InvalidSyntax),
        }
    }
    if !path.is_ascii() && !parameters.smtp_utf8 {
        return Err(ParseError::InvalidSyntax);
    }
    Ok((path, parameters))
}

fn parse_deliver_by(value: &str) -> Result<DeliverBy, ParseError> {
    let mut parts = value.split(';');
    let seconds = parts
        .next()
        .filter(|value| !value.is_empty() && value.len() <= 10)
        .ok_or(ParseError::InvalidSyntax)?
        .parse::<i32>()
        .map_err(|_| ParseError::InvalidSyntax)?;
    if seconds.unsigned_abs() > 999_999_999 {
        return Err(ParseError::InvalidSyntax);
    }
    let mode = match parts.next().map(str::to_ascii_uppercase).as_deref() {
        Some("N") => DeliverByMode::Notify,
        Some("R") if seconds > 0 => DeliverByMode::Return,
        _ => return Err(ParseError::InvalidSyntax),
    };
    let trace = match parts.next() {
        None => false,
        Some(value) if value.eq_ignore_ascii_case("T") => true,
        Some(_) => return Err(ParseError::InvalidSyntax),
    };
    if parts.next().is_some() {
        return Err(ParseError::InvalidSyntax);
    }
    Ok(DeliverBy {
        seconds,
        mode,
        trace,
    })
}

fn positive_nine_digits(value: &str) -> Result<u32, ParseError> {
    if value.is_empty()
        || value.len() > 9
        || value.starts_with('0')
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(ParseError::InvalidSyntax);
    }
    value.parse().map_err(|_| ParseError::InvalidSyntax)
}

fn parse_utc_time(value: &str) -> Result<SystemTime, ParseError> {
    let parsed = OffsetDateTime::parse(value, &Rfc3339).map_err(|_| ParseError::InvalidSyntax)?;
    if parsed.offset() != time::UtcOffset::UTC || !value.ends_with('Z') {
        return Err(ParseError::InvalidSyntax);
    }
    let seconds = u64::try_from(parsed.unix_timestamp()).map_err(|_| ParseError::InvalidSyntax)?;
    Ok(UNIX_EPOCH + Duration::from_secs(seconds))
}

pub fn parse_rcpt(argument: Option<&str>) -> Result<(String, RcptParameters), ParseError> {
    let (path, words) = path_and_words(argument, "TO:", false)?;
    let mut parameters = RcptParameters::default();
    for word in words {
        let (name, value) = parameter(word);
        match name.as_str() {
            "NOTIFY" if parameters.notify.is_none() => {
                parameters.notify = Some(
                    value
                        .filter(|v| valid_notify(v))
                        .ok_or(ParseError::InvalidSyntax)?
                        .to_ascii_uppercase(),
                );
            }
            "ORCPT" if parameters.orcpt.is_none() => {
                parameters.orcpt = Some(xtext(value.ok_or(ParseError::InvalidSyntax)?)?);
            }
            _ => return Err(ParseError::InvalidSyntax),
        }
    }
    Ok((path, parameters))
}

fn path_and_words<'a>(
    argument: Option<&'a str>,
    prefix: &str,
    allow_empty: bool,
) -> Result<(String, Vec<&'a str>), ParseError> {
    let argument = argument.ok_or(ParseError::InvalidSyntax)?;
    let rest = argument
        .get(..prefix.len())
        .filter(|value| value.eq_ignore_ascii_case(prefix))
        .and_then(|_| argument.get(prefix.len()..))
        .ok_or(ParseError::InvalidSyntax)?
        .trim_start();
    let end = rest.find('>').ok_or(ParseError::InvalidSyntax)?;
    if !rest.starts_with('<') {
        return Err(ParseError::InvalidSyntax);
    }
    let path = &rest[1..end];
    if path.contains(['<', '>', '\r', '\n', ' '])
        || (!allow_empty && path.is_empty())
        || (!path.is_empty() && !path.contains('@'))
    {
        return Err(ParseError::InvalidSyntax);
    }
    Ok((
        path.to_owned(),
        rest[end + 1..].split_ascii_whitespace().collect(),
    ))
}

fn parameter(word: &str) -> (String, Option<&str>) {
    word.split_once('=').map_or_else(
        || (word.to_ascii_uppercase(), None),
        |(name, value)| (name.to_ascii_uppercase(), Some(value)),
    )
}
fn xtext(value: &str) -> Result<String, ParseError> {
    if value.is_empty() {
        return Err(ParseError::InvalidSyntax);
    }
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' if bytes.get(index + 1).is_some_and(u8::is_ascii_hexdigit)
                && bytes.get(index + 2).is_some_and(u8::is_ascii_hexdigit) =>
            {
                index += 3;
            }
            b'+' | b'=' | 0..=32 | 127..=u8::MAX => return Err(ParseError::InvalidSyntax),
            _ => index += 1,
        }
    }
    Ok(value.to_owned())
}
fn valid_notify(value: &str) -> bool {
    let values: Vec<_> = value.split(',').map(str::to_ascii_uppercase).collect();
    !values.is_empty()
        && (values == ["NEVER"]
            || values
                .iter()
                .all(|v| matches!(v.as_str(), "SUCCESS" | "FAILURE" | "DELAY")))
}
