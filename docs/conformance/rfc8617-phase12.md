# RFC 8617 Phase 12 conformance

RFC: RFC 8617
Section: 4
Requirement: ARC sets form a contiguous chain with required ARC-Seal, ARC-Message-Signature, and ARC-Authentication-Results fields.
Implementation: `crates/mail-arc/src/lib.rs`
Test: `validates_contiguous_chain`
Status: implemented
Notes: Inbound validation performs DNS-backed newest AMS and all ARC-Seal verification. Outbound intermediaries generate AAR, AMS, and ARC-Seal when DKIM signing is configured; ARC remains Experimental.

RFC: RFC 8617
Section: 5.2
Requirement: The validator checks the newest AMS and every ARC-Seal before returning a passing chain status.
Implementation: `crates/mail-smtp-server/src/arc_validation.rs`
Test: `absent_and_malformed_chains_never_become_pass`; cryptographic primitives: `ed25519_signature_round_trip`
Status: partial
Notes: The live DNS pass path requires interoperability testing with externally generated ARC chains.
