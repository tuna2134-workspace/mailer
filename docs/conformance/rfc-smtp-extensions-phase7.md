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
Notes: Streaming, exact-octet framing, transaction reset, and size limits are implemented; external interoperability remains release qualification.

RFC: RFC 3207
Section: 4-5
Requirement: STARTTLS advertisement, handshake, and post-handshake state reset
Implementation: crates/mail-smtp-proto, crates/mail-smtp-server, bins/maild
Test: starttls_resets_session_and_gates_auth; starttls_authenticates_and_submits_without_open_relay
Status: implemented
Notes: A real rustls handshake verifies post-TLS state reset and TLS-only AUTH.

RFC: RFC 4954 / RFC 4616
Section: RFC 4954 Sections 4,6; RFC 4616 Section 2
Requirement: AUTH state handling and PLAIN message parsing
Implementation: crates/mail-smtp-proto, crates/mail-smtp-server, crates/mail-postgres
Test: parses_plain_initial_response; starttls_authenticates_and_submits_without_open_relay; rfc7677_scram_sha_256_vector; scram_sha_256_plus_uses_tls_exporter
Status: implemented
Notes: PLAIN and SCRAM are TLS-only; PLUS binds to the rustls TLS exporter.

RFC: RFC 6531 / RFC 8689 / RFC 3461
Section: RFC 6531 Section 3; RFC 8689 Sections 3-6; RFC 3461 Sections 4.1-4.2
Requirement: SMTPUTF8, REQUIRETLS, and DSN envelope parameters survive queueing and forwarding
Implementation: crates/mail-smtp-proto, crates/mail-smtp-server, crates/mail-postgres, crates/mail-smtp-client
Test: parses_phase_seven_parameters_and_rejects_duplicates; streaming_ingestion_and_atomic_local_delivery; queue_lease_stream_result_and_bounce_are_atomic
Status: implemented
Notes: DSN report-body generation is Phase 13; advanced REQUIRETLS policy is Phase 15.

RFC: RFC 2852 / RFC 4865
Section: RFC 2852 Sections 3-4; RFC 4865 Sections 3-5
Requirement: bounded delivery deadlines and authenticated future-release scheduling
Implementation: crates/mail-smtp-proto, crates/mail-smtp-server, crates/mail-postgres, crates/mail-smtp-client, crates/mail-delivery
Test: deliver_by_and_future_release_are_bounded; queue_lease_stream_result_and_bounce_are_atomic
Status: implemented
Notes: FUTURERELEASE is advertised only by authenticated Submission configurations; release must precede delivery deadline.
