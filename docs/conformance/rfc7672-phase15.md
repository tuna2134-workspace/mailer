# RFC 7672 Phase 15 conformance

RFC: RFC 7672
Section: 2
Requirement: TLSA use requires validated DNSSEC data.
Implementation: crates/mail-policy/src/lib.rs
Test: dane_rejects_unvalidated_dnssec
Status: implemented
Notes: Certificate association matching is performed by the TLS adapter.
