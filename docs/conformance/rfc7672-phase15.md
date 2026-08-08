# RFC 7672 Phase 15 conformance

RFC: RFC 7672
Section: 2
Requirement: TLSA use requires validated DNSSEC data.
Implementation: crates/mail-policy/src/lib.rs
Test: dane_rejects_unvalidated_dnssec
Status: partial
Notes: The policy core rejects non-Secure DNSSEC state. A production validating resolver and TLSA certificate-association adapter are external and not verified; selecting DANE in the SMTP client therefore defers rather than faking validation.
