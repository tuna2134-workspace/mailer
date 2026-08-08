# RFC 6376 Phase 12 conformance

RFC: RFC 6376
Section: 3.4-3.5
Requirement: DKIM signatures use canonicalized header/body bytes for signing and verification.
Implementation: `crates/mail-dkim/src/lib.rs`
Test: `relaxed_body_and_hash_are_bounded`; `ed25519_signature_round_trip`
Status: implemented
Notes: RSA-SHA256 and Ed25519 crypto are local; DNS key retrieval is an external adapter.
