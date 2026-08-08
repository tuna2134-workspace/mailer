#![forbid(unsafe_code)]

use thiserror::Error;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FailureNotice<'a> {
    pub sender: &'a str,
    pub recipient: &'a str,
    pub original_recipient: Option<&'a str>,
    pub action: &'a str,
    pub status: &'a str,
    pub diagnostic: &'a str,
    pub remote_mta: Option<&'a str>,
    pub envelope_id: Option<&'a str>,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum DsnError {
    #[error("address contains a line break")]
    HeaderInjection,
    #[error("DSN field is too long")]
    FieldTooLong,
    #[error("invalid enhanced status code")]
    InvalidStatus,
}

pub fn failure_message(notice: &FailureNotice<'_>) -> Result<Vec<u8>, DsnError> {
    for value in [
        notice.sender,
        notice.recipient,
        notice.action,
        notice.diagnostic,
    ] {
        if value.contains(['\r', '\n']) {
            return Err(DsnError::HeaderInjection);
        }
    }
    if notice.diagnostic.len() > 2_000 {
        return Err(DsnError::FieldTooLong);
    }
    if !valid_status(notice.status) {
        return Err(DsnError::InvalidStatus);
    }
    let mut fields = String::from("Reporting-MTA: dns; localhost\r\n");
    if let Some(id) = notice.envelope_id {
        fields.push_str("Original-Envelope-Id: ");
        fields.push_str(id);
        fields.push_str("\r\n");
    }
    fields.push_str("Final-Recipient: rfc822; ");
    fields.push_str(notice.recipient);
    fields.push_str("\r\n");
    if let Some(original) = notice.original_recipient {
        fields.push_str("Original-Recipient: rfc822; ");
        fields.push_str(original);
        fields.push_str("\r\n");
    }
    fields.push_str("Action: ");
    fields.push_str(notice.action);
    fields.push_str("\r\nStatus: ");
    fields.push_str(notice.status);
    fields.push_str("\r\n");
    if let Some(mta) = notice.remote_mta {
        if mta.contains(['\r', '\n']) {
            return Err(DsnError::HeaderInjection);
        }
        fields.push_str("Remote-MTA: dns; ");
        fields.push_str(mta);
        fields.push_str("\r\n");
    }
    fields.push_str("Diagnostic-Code: smtp; ");
    fields.push_str(notice.diagnostic);
    fields.push_str("\r\n");
    let subject = match notice.action {
        "failed" => "Delivery Status Notification (Failure)",
        "delayed" => "Delivery Status Notification (Delay)",
        _ => "Delivery Status Notification",
    };
    Ok(format!(
        "From: {}\r\nTo: <{}>\r\nSubject: {}\r\nAuto-Submitted: auto-generated\r\nMIME-Version: 1.0\r\nContent-Type: multipart/report; report-type=delivery-status; boundary=maild-dsn\r\n\r\n--maild-dsn\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{}\r\n\r\n--maild-dsn\r\nContent-Type: message/delivery-status\r\n\r\n{}\r\n--maild-dsn--\r\n",
        notice.sender, notice.recipient, subject, notice.diagnostic, fields
    ).into_bytes())
}

pub fn mdn_message(
    recipient: &str,
    final_recipient: &str,
    disposition: &str,
) -> Result<Vec<u8>, DsnError> {
    if [recipient, final_recipient, disposition]
        .into_iter()
        .any(|value| value.contains(['\r', '\n']))
    {
        return Err(DsnError::HeaderInjection);
    }
    Ok(format!(
        "From: <{final_recipient}>\r\nTo: <{recipient}>\r\nSubject: Message Disposition Notification\r\nAuto-Submitted: auto-replied\r\nMIME-Version: 1.0\r\nContent-Type: multipart/report; report-type=disposition-notification; boundary=maild-mdn\r\n\r\n--maild-mdn\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nYour message disposition is: {disposition}.\r\n\r\n--maild-mdn\r\nContent-Type: message/disposition-notification\r\n\r\nFinal-Recipient: rfc822; {final_recipient}\r\nDisposition: {disposition}\r\n\r\n--maild-mdn--\r\n",
    ).into_bytes())
}

fn valid_status(value: &str) -> bool {
    let mut parts = value.split('.');
    parts.all(|part| part.len() == 1 && part.as_bytes()[0].is_ascii_digit())
        && value.split('.').count() == 3
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dsn_failure_report_and_injection_guard() {
        let message = failure_message(&FailureNotice {
            sender: "alice@example.test",
            recipient: "bob@example.test",
            original_recipient: Some("alias@example.test"),
            action: "failed",
            status: "5.1.1",
            diagnostic: "user unknown",
            remote_mta: Some("mx.example.test"),
            envelope_id: Some("abc"),
        })
        .unwrap_or_default();
        let text = String::from_utf8_lossy(&message);
        assert!(text.contains("multipart/report; report-type=delivery-status"));
        let injected = FailureNotice {
            sender: "a",
            recipient: "b",
            original_recipient: None,
            action: "failed",
            status: "5.1.1",
            diagnostic: "x\r\nBcc: bad",
            remote_mta: None,
            envelope_id: None,
        };
        assert!(failure_message(&injected).is_err());
    }

    #[test]
    fn mdn_message_and_injection_guard() {
        let message =
            mdn_message("alice@example.test", "bob@example.test", "displayed").unwrap_or_default();
        let text = String::from_utf8_lossy(&message);
        assert!(text.contains("report-type=disposition-notification"));
        assert!(mdn_message("bad\n", "bob@example.test", "deleted").is_err());
    }
}
