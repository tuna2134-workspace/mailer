# RFC 7208 Phase 12 conformance

RFC: RFC 7208
Section: 4.6.4
Requirement: DNS-based SPF mechanisms are bounded by the ten-lookup and void-lookup limits.
Implementation: `crates/mail-spf/src/lib.rs`
Test: `evaluates_ip_and_qualifiers`
Status: implemented
Notes: DNS transport is injected; the evaluator enforces lookup and recursion budgets.
