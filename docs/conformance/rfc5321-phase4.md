RFC: RFC 5321
Section: 2.3.7, 4.5.2
Requirement: Lines are CRLF terminated; transparency removes one leading dot and the terminating dot line is not message content.
Implementation: crates/mail-smtp-proto/src/lib.rs, crates/mail-smtp-server/src/lib.rs
Test: parser_and_state_transcript, local_delivery_transcript_and_relay_denial
Status: implemented
Notes: Bare LF is rejected by default; compatibility mode is explicit.

RFC: RFC 5321
Section: 3.1, 4.1.1
Requirement: Support EHLO/HELO, MAIL, RCPT, DATA, RSET, VRFY, NOOP, QUIT and the required sequencing.
Implementation: crates/mail-smtp-proto/src/lib.rs
Test: parser_and_state_transcript
Status: implemented
Notes: HELP is also implemented. VRFY returns 252 without disclosing account existence.

RFC: RFC 5321
Section: 3.6, 4.1.1.3
Requirement: A server may restrict relaying and must make recipient decisions before accepting message content.
Implementation: crates/mail-smtp-server/src/lib.rs, crates/mail-postgres/src/lib.rs
Test: local_delivery_transcript_and_relay_denial, streaming_ingestion_and_atomic_local_delivery
Status: implemented
Notes: Phase 4 accepts active local user INBOX recipients only; unauthenticated relay is impossible.

RFC: RFC 5321
Section: 4.4
Requirement: Add a trace Received field when accepting mail and preserve trace ordering.
Implementation: crates/mail-smtp-server/src/lib.rs, crates/mail-postgres/src/lib.rs
Test: streaming_ingestion_and_atomic_local_delivery
Status: partial
Notes: A safe from/by/with/date Received field and final-delivery Return-Path are prepended. Extended registered clauses wait for later protocol metadata.

RFC: RFC 5321
Section: 4.5.3.1
Requirement: Enforce command, text-line, recipient and message limits without losing protocol synchronization.
Implementation: crates/mail-smtp-proto/src/lib.rs, crates/mail-smtp-server/src/lib.rs
Test: rejects_smuggling_shapes, local_delivery_transcript_and_relay_denial
Status: implemented
Notes: Commands are 512 octets, DATA lines 1000 octets, recipients and total size are configurable and bounded.

RFC: RFC 5321
Section: 4.5.3.2, 4.5.3.2.7
Requirement: Apply per-command and DATA timeouts and avoid holding unlimited resources.
Implementation: crates/mail-smtp-server/src/lib.rs
Test: idle_command_timeout_terminates_session
Status: implemented
Notes: Runtime timeout and connection semaphore are enforced; DATA has a separate longer deadline.
