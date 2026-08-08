# RFC 8461 Phase 15 conformance

RFC: RFC 8461
Section: 3
Requirement: Parse version, mode, mx, and max_age policy fields.
Implementation: crates/mail-policy/src/lib.rs
Test: parses_and_enforces_modern_tls_policy
Status: partial
Notes: HTTPS retrieval and cache are injected external boundaries.
