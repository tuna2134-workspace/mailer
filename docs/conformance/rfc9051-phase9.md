# RFC 9051 Phase 9 connection conformance

RFC: RFC 9051
Section: 2.1, 2.2, 3, 4.1, 4.1.1, 4.3, 6.1, 6.2, 6.3.1, 7
Requirement: A server provides CRLF-framed tagged commands, bounded literals, tagged/untagged/continuation responses, state-dependent command admission, CAPABILITY, NOOP, LOGOUT, STARTTLS, authentication, LOGIN, and ENABLE.
Implementation: crates/mail-imap-proto, crates/mail-imap-server, bins/maild
Test: parses_atoms_quotes_literals_and_sequence_sets; enforces_states_and_resets_after_starttls; capability_noop_literal_and_logout_transcript; split_literals_are_streamed_with_continuations; oversized_literal_is_rejected_before_allocation; starttls_performs_real_handshake_and_resets_capabilities
Status: partial
Notes: The Phase 9 connection subset is implemented. Mailbox and message commands are Phase 10, synchronization is Phase 11.

RFC: RFC 4959
Section: 3
Requirement: AUTHENTICATE may carry an initial client response only when SASL-IR is advertised; `=` represents an empty response.
Implementation: crates/mail-imap-proto, crates/mail-imap-server
Test: starttls_performs_real_handshake_and_resets_capabilities
Status: implemented
Notes: SASL-IR is advertised only after TLS together with the implemented AUTH=PLAIN mechanism.

RFC: RFC 8314
Section: 3
Requirement: Email access supports implicit TLS and avoids cleartext password disclosure.
Implementation: crates/mail-imap-server, bins/maild
Test: starttls_performs_real_handshake_and_resets_capabilities
Status: implemented
Notes: Port 993 uses implicit TLS; port 143 advertises LOGINDISABLED until STARTTLS succeeds.
