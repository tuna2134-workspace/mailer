# Security hardening report

Audit date: 2026-08-09. This report records verified behavior and open production blockers; it is not a blanket RFC-compliance declaration.

## Findings and changes

| Severity | Finding/root cause | Resolution and runnable evidence |
| --- | --- | --- |
| High | `RUSTSEC-2023-0071` was ignored globally even though the affected RustCrypto `rsa` package is only a lockfile dependency of SQLx's optional MySQL macro support. A future feature change could have made the exception hide a reachable private-key path. | Removed the audit and cargo-deny exceptions. CI asserts that `cargo tree --workspace --all-features --target all -i rsa@0.9.10` is empty before running unignored RustSec audit. |
| High | DSN optional `Original-Recipient` and `Original-Envelope-Id` fields bypassed the CRLF guard used by required fields. | All optional header fields now pass the same line-break rejection. `mail_dsn::tests::dsn_failure_report_and_injection_guard` covers every field. |
| Medium | A plaintext IMAP listener with no STARTTLS configuration rejected LOGIN but omitted `LOGINDISABLED`, misleading clients about authentication availability. | `mail_imap_proto::session::tests::plaintext_without_starttls_still_advertises_login_disabled` and the TCP black-box suite verify the advertisement and rejection. |
| Medium | Most malformed SMTP/IMAP tests exercised in-memory duplex streams; actual listener accept, TCP fragmentation and pipeline recovery had little coverage. | Added black-box TCP suites for SMTP sequencing, line and message limits, relay-related state, dot transparency, pipelining, BDAT truncation/abort, IMAP fragmentation, pipelining, malformed input, literal limits and STARTTLS state reset. |
| Medium | SPF record grammar and DSN/MDN generation were absent from direct fuzz coverage. | Added direct SPF record validation to the authentication harness, a DSN/MDN harness, explicit input ceilings, CI fuzz-harness build, and `docs/fuzzing.md`. |
| Low | GitHub Actions used mutable release tags. | Pinned checkout, RustSec and cargo-deny actions to immutable release SHAs and disabled checkout credential persistence. |

## RSA private-key audit

- `rsa 0.9.10` is introduced in `Cargo.lock` by `sqlx-mysql`, which is referenced by `sqlx-macros-core`. It is not in the resolved workspace graph: SQLx default features are disabled and the workspace enables PostgreSQL, migrations, macros and UUID only.
- DKIM RSA signing parses a configured PKCS#8 key with `ring::signature::RsaKeyPair` and signs SHA-256 data using ring. ARC signing delegates to the same `mail-dkim` path. Remote message bytes influence the signed digest but cannot select the private key or invoke RustCrypto `rsa`.
- DKIM and ARC RSA verification use ring public-key verification and perform no private-key operation.
- TLS private keys are parsed by rustls and used through the configured ring provider. ACME uses the rustls-compatible provider/cache boundary.
- S/MIME/CMS and OpenPGP private-key operations are explicit external-provider functionality and are not implemented in-process.
- Tests use rcgen/ring-generated keys. No production private key or committed test key was found.

The RustSec ignore can remain absent while the advisory is not reported for this lockfile. If SQLx, cargo-audit or the advisory changes, the graph assertion remains the authoritative guard: enabling MySQL or adding RustCrypto `rsa` is prohibited until the affected version is eliminated.

## Recovery and delivery guarantees

SMTP success is returned only after the repository commit succeeds. DATA/BDAT EOF before commit aborts ingestion. PostgreSQL queue leases and mailbox UID/MODSEQ invariants have repository integration tests, but SMTP cannot guarantee exactly-once remote delivery: a peer may accept the final message and the worker may crash before recording success. That state is delivery-ambiguous and retry can duplicate delivery.

## Remaining production blockers

- Automated Postfix/Dovecot/OpenDKIM/OpenDMARC differential containers are still optional/manual rather than required CI jobs.
- The new SMTP TCP suite does not yet perform SCRAM-SHA-256 over a real socket; existing TLS/SCRAM and SCRAM-PLUS tests use the complete protocol session over an in-memory transport.
- The IMAP TCP suite covers framing and STARTTLS, while repository-backed SELECT/FETCH/STORE/COPY/MOVE/QRESYNC concurrency remains in crate/PostgreSQL tests rather than one end-to-end TCP scenario.
- Per-IP connection admission limits, distributed authentication throttling, TLS-handshake admission limits and production load characterization remain incomplete. The process-local limiter is bounded but resets on process restart and is not shared across nodes.
- Complete MTA-STS retrieval/cache enforcement and DNSSEC-validated DANE remain external/partial. They must not be advertised as production-enforced policy.
- Complete DMARC aggregate/failure reporting and external ARC-chain interoperability remain partial.
- External Gmail, Outlook and Yahoo delivery requires operator-controlled staging evidence described in `docs/external-mail-interop.md`.

## Production-readiness assessment

The server has materially stronger trust-boundary validation and real TCP regression coverage, but it should not yet be presented as generally production-ready for unattended public-Internet deployment. A limited staging deployment is appropriate after completing provider/MTA interoperability, load and restart exercises, validating DNS/reputation, and operating with conservative listener/firewall limits and monitored PostgreSQL backups.
