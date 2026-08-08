# Interoperability test plan

Automated interoperability is a release-qualification suite separate from unit and PostgreSQL contract tests. Passing local mocks is not evidence of compatibility with a named product.

## Topology

- Isolated Docker network with `maild`, PostgreSQL, a private test CA, authoritative test DNS, and one peer per scenario.
- Peer images: Postfix, Exim, and Dovecot with pinned image digests in the eventual harness.
- No Gmail, Microsoft 365, or iCloud credentials in CI. Public-provider checks are manual and use non-production test domains.
- Capture SMTP/IMAP transcripts with secrets and message bodies redacted. Preserve image versions, configuration, IPv4/IPv6 mode, and test seed.

## Automated suites

| Peer | Direction | Required scenarios | Pass evidence |
|---|---|---|---|
| Postfix | inbound and outbound SMTP | EHLO/HELO, multiline replies, PIPELINING, SIZE, 8BITMIME, SMTPUTF8, DSN, dot transparency, large bounded message | transcript assertions plus matching PostgreSQL envelope/body hash |
| Exim | inbound and outbound SMTP | MX preference/fallback, IPv4/IPv6 fallback, 4xx/5xx, DATA disconnect before and after final dot | durable queue state and explicit ambiguity classification |
| Postfix/Exim with private CA | outbound TLS | valid private trust, self-signed/expired/name mismatch, handshake abort, STARTTLS stripping simulation | opportunistic fallback reconnects in clear only when policy permits; strict modes defer and never send plaintext |
| Postfix/Exim | strict transport | REQUIRETLS advertisement/absence; injected valid MTA-STS state; injected DNSSEC-Secure DANE match/mismatch | no plaintext under strict policy; no unvalidated DNS result activates DANE |
| Dovecot | IMAP | CAPABILITY/STARTTLS reset, LOGIN/AUTHENTICATE, SELECT/EXAMINE, UID operations, APPEND/FETCH/STORE/SEARCH/COPY/MOVE/EXPUNGE, IDLE, CONDSTORE/QRESYNC/VANISHED, literals | protocol transcript and mailbox UID/MODSEQ state |
| OpenDKIM/Rspamd | authentication differential | RSA/Ed25519, simple/relaxed, repeated/folded headers, empty body, expiry/revocation, ARC one-hop/multi-hop/broken seal | semantic result comparison; fixture keys and DNS remain local |

The always-on black-box suites are `mail-smtp-server/tests/black_box.rs` and `mail-imap-server/tests/black_box.rs`. They bind an ephemeral localhost TCP listener and use only public server entry points. External Gmail, Outlook and Yahoo staging probes are documented in `docs/external-mail-interop.md` and are never part of public CI.
| pyspf or another maintained SPF oracle | SPF differential | mechanisms, dual CIDR, modifiers, macro transformers, recursion/lookup/void limits, DNS error classes | compare semantic SPF result, never raw diagnostic wording |

## Negative/resource suites

- Malformed multiline SMTP reply, bare LF, overlong command/reply, malformed headers, incomplete dot terminator, oversized and slow DATA/BDAT.
- Oversized/split IMAP literals, malformed sequence sets, concurrent EXPUNGE, unsolicited changes, reconnect synchronization.
- MIME deep nesting, excessive parts, decoded-size overflow, malformed base64/QP/RFC2231, and arbitrary invalid UTF-8 corpus.
- Peer disconnect and container kill at every durable boundary: before DATA, during body, after final dot, after remote `250`, before/after local delivery-state commit.

## Manual release checks

- Thunderbird, Apple Mail, Outlook, mutt/NeoMutt, Roundcube, and SnappyMail against a disposable deployment.
- Public DNS MX/A/AAAA, reverse DNS, STARTTLS, MTA-STS/TLS-RPT, and DANE only where a real validating resolver and DNSSEC-signed zone are available.
- Gmail/Microsoft 365/iCloud delivery and receipt with header inspection; record results as interoperability observations, not RFC conformance.
- systemd non-root capability/sandbox deployment and container `CAP_NET_BIND_SERVICE` deployment.

## CI staging

Keep fmt/clippy/unit/property/PostgreSQL tests in normal CI. Run parser seed corpora in a bounded job. Run Postfix/Exim/Dovecot suites in a separate job with explicit image caches and timeout; make them required only after flakiness is measured and removed.
