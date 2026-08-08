# RFC 8617 Phase 12 conformance

RFC: RFC 8617
Section: 4
Requirement: ARC sets form a contiguous chain with required ARC-Seal, ARC-Message-Signature, and ARC-Authentication-Results fields.
Implementation: `crates/mail-arc/src/lib.rs`
Test: `validates_contiguous_chain`
Status: implemented
Notes: Cryptographic key lookup is supplied through `ArcSignatureVerifier`; ARC remains Experimental.
