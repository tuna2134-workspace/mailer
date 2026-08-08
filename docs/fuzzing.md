# Parser fuzzing

Fuzzing is optional and requires no network or PostgreSQL. Harnesses reject inputs above their production-relevant bound before invoking a parser.

| Harness | Boundary covered |
| --- | --- |
| `smtp_command` | SMTP command/extension parameters and DATA dot transparency |
| `smtp_reply` | outbound SMTP multiline reply framing |
| `imap_command` | IMAP commands, sequence sets, SEARCH, FETCH/BODY syntax |
| `message_mime_address` | IMF headers, encoded words, addresses, MIME boundaries, transfer decoding and RFC 2231 parameters |
| `mail_authentication` | SPF record/macros, DKIM signature/key records, DMARC records and ARC sets |
| `sieve` | Sieve grammar and nesting/instruction limits |
| `dsn_mdn` | DSN/MDN field validation and CRLF injection resistance |
| `mailbox_flags` | IMAP keyword validation |

IMAP literal and SMTP DATA/BDAT network framing are async stateful readers rather than pure parsers. They are covered by black-box TCP tests with fragmentation, truncation and limits; converting those readers into a byte-only fuzz API would bypass timing and EOF semantics.

Build every harness:

```bash
cargo +stable check --manifest-path fuzz/Cargo.toml --bins
```

Bounded local smoke example:

```bash
cargo +nightly fuzz run smtp_command -- -runs=10000 -max_len=65536 -timeout=5
cargo +nightly fuzz run mail_authentication -- -runs=10000 -max_len=262144 -timeout=5
```

Under a ptrace-restricted container, LeakSanitizer can fail while shutting down even after all runs complete. In that environment only, set `ASAN_OPTIONS=detect_leaks=0`; AddressSanitizer crash and timeout checks remain active. Do not use that setting for the scheduled full sanitizer run.

Crash artifacts and corpora can contain message data. Review and minimize them before committing; never seed with production mail or credentials.
