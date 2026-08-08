# RFC 9989 Phase 12 conformance

RFC: RFC 9989
Section: 4-6
Requirement: DMARC applies DKIM/SPF identifier alignment and an applicable policy disposition.
Implementation: `crates/mail-dmarc/src/lib.rs`
Test: `parses_and_aligns_policy`
Status: implemented
Notes: Organizational-domain lookup is isolated for PSL-backed integration.
