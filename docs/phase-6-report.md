# Phase 6 report

## Implemented

- `mail-message`: incremental arbitrary-byte header parsing, exact raw header preservation, bounded line/header/field counts, unfolding, typed error position/severity, Date, Message-ID and B/Q encoded-word helpers.
- `mail-address`: bounded mailbox/list/group parsing with comments, quoted local-parts, name-addr and domain literals; ASCII domain normalization without assuming the entire message is UTF-8.
- `mail-mime`: Content-Type, MIME-Version, Content-Disposition, 7bit/8bit/binary/base64/quoted-printable metadata, bounded decoding, multipart nesting, message/rfc822, preamble/epilogue handling and zero-copy body slices.
- Incremental multipart boundary scanner retaining at most one bounded candidate line, plus property and fuzz coverage over arbitrary bytes.

## RFC coverage

RFC 5322 Sections 2.1.1, 2.2 and 2.2.3 are implemented for modern syntax; Sections 3.3, 3.4 and 3.6.4 are partial. RFC 2045 Sections 4-6, RFC 2046 Sections 5.1/5.2.1, RFC 2047 Sections 2/4 and RFC 2183 Section 2 are partial. RFC 2231 is not yet claimed.

## Dependencies

The existing `base64` 0.22.1 dependency is reused (MIT OR Apache-2.0, MSRV 1.48). `time` 0.3.55 gains only its parsing feature. `quoted_printable` 0.5.2 is 0BSD and forbids unsafe in its crate; its published MSRV and current security history are unverified. `proptest` 1.11.0 is test-only (MIT OR Apache-2.0, MSRV 1.85). All decoders are wrapped by explicit output limits.

## Changed files and migrations

Added `mail-message`, `mail-address`, `mail-mime`, one combined fuzz target, RFC conformance records and documentation updates. No PostgreSQL migration or HTTP API was added; immutable raw `BYTEA` remains authoritative and parsed structures are derived data.

## Tests and security

Tests cover every header/boundary split, raw preservation, folding, empty/truncated headers, mailbox/group syntax, encoded words, nested multipart, false boundary prefixes and decoding limits. Property tests and fuzzing accept arbitrary bytes without panics. Header bytes/lines/fields, comment depth, addresses, MIME depth/parts/boundaries and decoded bytes are all bounded.

`cargo fmt --all -- --check`, workspace Clippy with warnings denied, all workspace tests, fuzz-manifest compilation and all `mail-postgres` contracts against a fresh PostgreSQL 17 container passed. The `cargo-fuzz` runner is not installed in this environment, so the new target was compiled but not executed under libFuzzer.

## Known limitations

- The convenience MIME tree parser needs a resident input slice, although it does not copy bodies; `BoundaryScanner` provides incremental framing but is not yet wired into PostgreSQL ingestion.
- RFC 2231 extended/continued parameters were completed in Phase 17. Adjacent RFC 2047 assembly and charset transcoding remain lossless external presentation concerns; charset labels and decoded bytes stay separate.
- Obsolete RFC 5322 syntax, source routes and SMTPUTF8/EAI are rejected. Field-specific From/Sender cardinality and trace-field validation remain.
- Malformed MIME is reported as recoverable or fatal; no repair is silently presented as canonical. Archive decompression and virus scanning remain external.
- MIME error positions are exact where supplied by the header parser but some structural MIME errors currently identify only the containing entity start.

## Next

Phase 7 integrates SMTP extensions, SMTPUTF8, STARTTLS and AUTH. It must explicitly choose when EAI addresses and 8bit/binary content become legal and advertise only active capabilities.
