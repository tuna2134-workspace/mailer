# RFC 8098 Phase 13 conformance

RFC: RFC 8098
Section: 3
Requirement: An MDN uses multipart/report with report-type=disposition-notification.
Implementation: crates/mail-dsn/src/lib.rs
Test: mdn_message_and_injection_guard
Status: implemented
Notes: Consent and duplicate suppression are explicit policy inputs.
