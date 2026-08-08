# RFC 3464 Phase 13 conformance

RFC: RFC 3464
Section: 2
Requirement: A DSN is a multipart/report with report-type=delivery-status.
Implementation: crates/mail-dsn/src/lib.rs
Test: dsn_failure_report_and_injection_guard
Status: implemented
Notes: Original-message inclusion is disabled by policy.

RFC: RFC 3464
Section: 2.2
Requirement: Delivery-status fields identify recipient, action, and status.
Implementation: crates/mail-dsn/src/lib.rs
Test: dsn_failure_report_and_injection_guard
Status: implemented
Notes: Enhanced status syntax is bounded to x.y.z.
