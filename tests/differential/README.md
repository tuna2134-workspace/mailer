# SMTP/IMAP differential interoperability suite

This isolated environment runs raw, bounded protocol transcripts against mailer and the
reference servers. A reference disagreement is a signal to adjudicate against the RFC, not an
oracle. Known differences live only in `runner/src/cases/mod.rs` and require an explanation and
RFC section.

Tested image/package baselines:

- Rust builder: `rust:1.88.0-bookworm`
- PostgreSQL: `postgres:17.6-bookworm`
- Postfix: Debian 12.11 package (the exact runtime version is captured in each report)
- Dovecot: Debian 12.11 package (the exact greeting/version is captured in each report)

Run:

```bash
docker compose -f tests/differential/compose.yaml up --build \
  --abort-on-container-exit --exit-code-from differential-runner
```

Reports are written to `target/differential/report.json` and `report.md`. The runner exits
non-zero for any unexplained `MAILER_SUSPECT`. It uses 25-second I/O deadlines (covering the
mailer's bounded authentication-DNS evaluation), a 128 KiB
response ceiling, a 256 KiB transcript ceiling, a fixed seed, and no host networking. The
Compose network is internal and Postfix has both relay and external transports disabled.

Cleanup:

```bash
docker compose -f tests/differential/compose.yaml down -v --remove-orphans
```

To promote a generated disagreement, minimize the transcript by removing commands, parameters,
content, then fragmentation points while re-running the named case. Save the minimal raw input
under `corpus/smtp` or `corpus/imap` and add an RFC-adjudicated case. Reports redact AUTH and
LOGIN lines.

## Coverage and deliberate limits

The deterministic suite exercises SMTP greeting/state ordering, EHLO/HELO, RSET, NOOP, VRFY,
unknown commands, command/DATA line boundaries, DATA acceptance, dot transparency, relay denial,
SMTPUTF8/DSN parameters, PIPELINING-shaped writes, strict framing, BDAT (including zero/truncated
chunks), STARTTLS and post-TLS EHLO. IMAP covers greeting, CAPABILITY, NOOP, pre-TLS login
rejection, malformed/coalesced/fragmented commands and literals, STARTTLS, LOGIN, LIST, STATUS,
SELECT/EXAMINE, APPEND, FETCH/UID FETCH, SEARCH/UID SEARCH, STORE/UID STORE, COPY/UID COPY, MOVE,
EXPUNGE, IDLE and CONDSTORE modifiers. Fixed-seed cases vary capitalization and fragmentation.
Tagged results plus EXISTS, EXPUNGE and SEARCH cardinality are compared; generated UIDs,
timestamps and greeting text are not.

Authenticated SMTP submission, two-session IMAP concurrency, and QRESYNC/VANISHED remain tracked
as `NOT_COMPARABLE` inventory in `expected/coverage.md`. Optional Dovecot
`imaptest` is intentionally not part of the deterministic gate because Debian does not ship it;
run it from a separately pinned image against the same internal network.
