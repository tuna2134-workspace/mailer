# Phase 5 report

## Implemented

- MX preference routing, implicit MX fallback, null MX, and IPv4/IPv6 address lookup through Hickory Resolver 0.25.2.
- Outbound SMTP greeting, EHLO with HELO fallback, MAIL, RCPT, DATA, bounded multiline replies, dot transparency, connection/command/DATA-write timeouts, and per-recipient result classification.
- 64 KiB PostgreSQL `BYTEA` range reads; a message is never loaded in full by the worker.
- `FOR UPDATE SKIP LOCKED` leasing, expired-lease recovery, token-guarded atomic result/attempt recording, deterministic exponential retry, queue expiry, partial-recipient durability, and minimal null-reverse-path failure notifications.
- `mail-queue-worker`, configured by secret-capable `MAIL_DATABASE_URL` and `MAIL_HOSTNAME` environment inputs.

## RFC coverage

RFC 5321 Sections 4.1.1, 4.2, 4.4, 4.5.4.1 and 5 are partial. RFC 7505 Section 3 is implemented. No RFC 3464 conformance is claimed for the minimal failure notice.

## Changed files

Workspace and lockfile; `mail-dns`, `mail-smtp-client`, `mail-delivery`, `mail-queue-worker`; storage/PostgreSQL repositories; RFC matrix, queue design, roadmap and conformance records. No migration was needed because the Phase 1 queue schema already contained recipient state, attempt and lease columns. No HTTP API was added.

## Tests and security

Unit tests cover dot-stuffing across chunks, reply lines, enhanced codes and retry bounds; `smtp_reply` fuzzes arbitrary reply bytes. The PostgreSQL contract covers streaming, exclusive leases, stale-token rejection, defer/fail transitions and bounce creation. Envelope CR/LF injection is rejected; reply and chunk sizes and all network waits are bounded; DB locks are not held across DNS or SMTP I/O; bounces use a null reverse-path.

## Known limitations

Outbound STARTTLS was completed in Phase 7; MTA-STS/DANE/REQUIRETLS policy followed in Phase 15 and RFC 3464 DSNs in Phase 13. The worker remains intentionally sequential per process (safe limit one); PostgreSQL leases provide multi-worker concurrency. Live-MTA interoperability and DNS fault injection are release-qualification boundaries, so RFC 5321 status remains partial.

## Next

Phase 6 implements the bounded Internet Message Format, address and MIME parsers. Phase 7 then adds SMTP extensions, STARTTLS and AUTH.
