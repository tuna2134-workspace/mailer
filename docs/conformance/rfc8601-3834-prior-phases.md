# Authentication and automatic-response conformance

RFC: RFC 8601
Section: 2
Requirement: Authentication-Results values identify the authentication service and methods without permitting injected fields.
Implementation: crates/mail-policy/src/lib.rs
Test: authentication_results_and_auto_response_are_bounded
Status: partial
Notes: Trusted-hop stripping is enforced by the receiving integration.

RFC: RFC 3834
Section: 4
Requirement: Automatic responses avoid null reverse paths, bulk messages, and already automatic messages.
Implementation: crates/mail-policy/src/lib.rs
Test: authentication_results_and_auto_response_are_bounded
Status: implemented
