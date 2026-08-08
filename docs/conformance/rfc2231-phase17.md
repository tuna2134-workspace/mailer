# RFC 2231 Phase 17 conformance

RFC: RFC 2231
Section: 3 and 4
Requirement: Decode extended parameter values and ordered continuations.
Implementation: crates/mail-mime/src/lib.rs
Test: recognizes_crypto_envelopes_and_rfc2231_parameters
Status: implemented
Notes: Decoded bytes and charset labels remain separate to prevent lossy normalization.
