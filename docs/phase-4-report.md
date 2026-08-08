# Phase 4 implementation report

Status: Phase 4 SMTP receiving subset implemented. RFC 5321 is marked partial, not fully conformant.

## Implemented

- Tokio TCP/25 listener, connection semaphore, greeting and bounded session timeouts.
- Incremental command parser for EHLO, HELO, MAIL FROM, RCPT TO, DATA, RSET, NOOP, QUIT, HELP and privacy-preserving VRFY.
- Explicit SMTP transaction state, multiple recipients, RSET and post-DATA reset.
- 512-octet command and 1000-octet DATA-line limits, total message size and recipient limits.
- CRLF policy, default bare-LF rejection, dot transparency and synchronized draining after oversized DATA.
- Active local-recipient lookup only. Unknown/non-local recipients receive 550 5.1.1, so unauthenticated relay is fail-closed.
- Received and final-delivery Return-Path generation without accepting CR/LF-bearing peer identities.
- 64 KiB PostgreSQL staging chunks; the application never assembles the complete message in memory.
- One final PostgreSQL transaction creates authoritative raw BYTEA messages, hashes content, charges quota, allocates UID/MODSEQ and inserts INBOX delivery relations.
- Startup recovery marks expired ingestions abandoned and removes transient chunks.

## Migration

`202608070004_phase4_smtp.sql` adds `pgcrypto`, bounded ingestion/chunk tables, recovery index, envelope recipients and a BYTEA aggregate used only during finalization.

## Tests

- Parser/state transcript, invalid sequence, dot transparency, bare LF, oversized command and request-smuggling shapes.
- End-to-end in-memory SMTP transcript including open-relay denial and local acceptance.
- Fresh PostgreSQL local-delivery contract verifies raw preservation, Return-Path/Received ordering, message size and UID/MODSEQ/message counters.

## Security considerations

- External input never reaches `panic`, `unwrap` or `expect` paths.
- Lines and total DATA are bounded before persistence; connection count and idle duration are bounded.
- SQL is parameterized and delivery/quota/counters commit atomically.
- SMTP AUTH is not advertised and relay authorization cannot accidentally fall through.
- SMTP STARTTLS is not advertised until Phase 7 wires the RFC 3207 state reset.

## Known limitations

- Address literals, quoted local-parts, obsolete source routes, aliases/catch-all expansion and SMTPUTF8 await the address and extension phases.
- At this checkpoint EHLO advertised no extensions; SIZE, PIPELINING, 8BITMIME, STARTTLS and AUTH were subsequently completed in Phase 7.
- Accepted messages are local deliveries only. MX lookup, remote delivery, queue retry, bounce and DSN begin in Phase 5.
- A `cargo-fuzz` SMTP command/DATA-line target and an idle-timeout test are present. RFC 5321 status remains partial because later extensions and address syntax are separate phases.
