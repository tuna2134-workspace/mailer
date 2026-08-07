# Phase 7 SMTP extension conformance

RFC: RFC 1870
Section: 4
Requirement: SIZE advertisement and MAIL FROM SIZE enforcement
Implementation: crates/mail-smtp-proto, crates/mail-smtp-server
Test: parses_phase_seven_parameters_and_rejects_duplicates
Status: implemented
Notes: The configured receive limit is authoritative.

RFC: RFC 3030
Section: 3-4
Requirement: BDAT exact-octet processing and BINARYMIME use with CHUNKING
Implementation: crates/mail-smtp-proto, crates/mail-smtp-server
Test: bdat_streams_exact_octets
Status: partial
Notes: Streaming and size limits are implemented; external interoperability remains pending.

RFC: RFC 3207
Section: 4-5
Requirement: STARTTLS advertisement, handshake, and post-handshake state reset
Implementation: crates/mail-smtp-proto, crates/mail-smtp-server, bins/maild
Test: starttls_resets_session_and_gates_auth
Status: partial
Notes: Live-certificate handshake integration testing remains pending.

RFC: RFC 4954 / RFC 4616
Section: RFC 4954 Sections 4,6; RFC 4616 Section 2
Requirement: AUTH state handling and PLAIN message parsing
Implementation: crates/mail-smtp-proto, crates/mail-smtp-server, crates/mail-postgres
Test: parses_plain_initial_response; starttls_resets_session_and_gates_auth
Status: partial
Notes: AUTH PLAIN is TLS-only. SCRAM-SHA-256 and channel binding are not implemented or advertised.
