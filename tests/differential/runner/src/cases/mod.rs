pub mod imap;
pub mod smtp;

use crate::report::Classification;

pub struct Adjudication {
    pub classification: Classification,
    pub explanation: &'static str,
    pub rfc: &'static str,
}

pub fn adjudication(protocol: &str, case: &str) -> Option<Adjudication> {
    match (protocol, case) {
        ("SMTP", "ehlo") => Some(Adjudication {
            classification: Classification::AllowedDifference,
            explanation: "extension sets are implementation and configuration dependent",
            rfc: "RFC 5321 section 2.2",
        }),
        ("SMTP", "vrfy") => Some(Adjudication {
            classification: Classification::AllowedDifference,
            explanation: "VRFY may be disabled or return implementation-dependent verification detail",
            rfc: "RFC 5321 section 3.5.3",
        }),
        ("SMTP", "bare_lf") => Some(Adjudication {
            classification: Classification::AllowedDifference,
            explanation: "reference tolerance is not a requirement for mailer strict framing",
            rfc: "RFC 5321 sections 2.3.7 and 4.1.1.4",
        }),
        ("SMTP", "mail_before_greeting") => Some(Adjudication {
            classification: Classification::AllowedDifference,
            explanation: "mailer requires EHLO/HELO while Postfix accepts the RFC 5321 compatibility exception",
            rfc: "RFC 5321 sections 3.1 and 4.1.4",
        }),
        ("SMTP", "data_before_rcpt") => Some(Adjudication {
            classification: Classification::AllowedDifference,
            explanation: "both reject invalid sequencing; RFC 5321 permits 503 or 554",
            rfc: "RFC 5321 sections 3.3 and 4.2.1",
        }),
        ("SMTP", "generated_ehlo_3") => Some(Adjudication {
            classification: Classification::ReferenceSuspect,
            explanation: "mailer enforces the required SP while Postfix tolerates HTAB",
            rfc: "RFC 5321 sections 2.3.1 and 4.1.1.1",
        }),
        ("SMTP", "command_line_513") => Some(Adjudication {
            classification: Classification::ReferenceSuspect,
            explanation: "mailer enforces the command-line limit while Postfix accepts one octet beyond it",
            rfc: "RFC 5321 section 4.5.3.1.4",
        }),
        ("SMTP", "data_line_1001") => Some(Adjudication {
            classification: Classification::AllowedDifference,
            explanation: "mailer rejects a line above the interoperability limit while Postfix accepts it",
            rfc: "RFC 5321 section 4.5.3.1.6",
        }),
        ("SMTP", "malformed_bdat") => Some(Adjudication {
            classification: Classification::AllowedDifference,
            explanation: "both permanently reject malformed BDAT syntax with different 5xx codes",
            rfc: "RFC 3030 section 4",
        }),
        ("SMTP", "unknown") => Some(Adjudication {
            classification: Classification::AllowedDifference,
            explanation: "response text/enhanced status differs while both reject",
            rfc: "RFC 5321 section 4.2.4",
        }),
        ("SMTP", "pre_tls_auth") => Some(Adjudication {
            classification: Classification::NotComparable,
            explanation: "Postfix reference intentionally has no SASL backend; mailer must reject cleartext AUTH",
            rfc: "RFC 4954 section 6 and RFC 8314 section 3.3",
        }),
        ("SMTP", "nonexistent_recipient") => Some(Adjudication {
            classification: Classification::NotComparable,
            explanation: "Postfix sink disables local recipient maps while mailer performs repository-backed recipient verification",
            rfc: "RFC 5321 section 3.3",
        }),
        ("SMTP", "relay_denied") => Some(Adjudication {
            classification: Classification::AllowedDifference,
            explanation: "both permanently reject unauthenticated relay; reply-code choice differs",
            rfc: "RFC 5321 sections 3.3 and 4.2.1",
        }),
        ("SMTP", "cr_without_lf") => Some(Adjudication {
            classification: Classification::ReferenceSuspect,
            explanation: "mailer rejects a command containing bare CR while Postfix tolerates it",
            rfc: "RFC 5321 sections 2.3.7 and 4.1.1.4",
        }),
        ("IMAP", "capability") => Some(Adjudication {
            classification: Classification::AllowedDifference,
            explanation: "capability sets differ with implemented extensions",
            rfc: "RFC 9051 section 6.1.1",
        }),
        ("IMAP", "pre_tls_login") => Some(Adjudication {
            classification: Classification::AllowedDifference,
            explanation: "both may enforce TLS using different tagged status/response code",
            rfc: "RFC 9051 section 11.5",
        }),
        _ => None,
    }
}
