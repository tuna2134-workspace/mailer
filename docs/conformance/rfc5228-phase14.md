# RFC 5228 Phase 14 conformance

RFC: RFC 5228
Section: 2
Requirement: Sieve scripts use commands and tests with bounded execution.
Implementation: crates/mail-sieve/src/lib.rs
Test: parses_and_executes_bounded_filter
Status: partial
Notes: Core subset is implemented; unsupported extensions fail explicitly.

RFC: RFC 5228
Section: 2.10
Requirement: Redirect and generated actions must be resource bounded.
Implementation: crates/mail-sieve/src/lib.rs
Test: enforces_redirect_budget
Status: implemented
