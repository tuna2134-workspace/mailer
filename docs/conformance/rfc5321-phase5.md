RFC: RFC 5321
Section: 5
Requirement: Resolve destination MX records in preference order and use implicit MX when MX records are absent.
Implementation: crates/mail-dns/src/lib.rs
Test: null_mx_suppresses_fallback_and_preferences_are_sorted; manual resolver interoperability remains
Status: partial
Notes: A/AAAA and IPv4/IPv6 are supported; DNSSEC policy is Phase 15.

RFC: RFC 5321
Section: 4.1.1, 4.2
Requirement: Send EHLO/HELO, envelope commands and DATA; distinguish transient and permanent replies.
Implementation: crates/mail-smtp-client/src/lib.rs
Test: enhanced_status_is_strict; dot_stuffing_survives_chunk_boundaries
Status: partial
Notes: STARTTLS and extensions are Phase 7.

RFC: RFC 5321
Section: 4.5.4.1
Requirement: Retry transient failures and eventually notify the sender of persistent failure.
Implementation: crates/mail-delivery/src/lib.rs; crates/mail-postgres/src/lib.rs
Test: retry_is_bounded_and_deterministic; queue_lease_stream_result_and_bounce_are_atomic
Status: partial
Notes: Full RFC 3464 DSN format is Phase 13.

RFC: RFC 7505
Section: 3
Requirement: A single preference-zero MX whose exchange is the root label means the domain accepts no mail.
Implementation: crates/mail-dns/src/lib.rs
Test: null_mx_suppresses_fallback_and_preferences_are_sorted
Status: implemented
Notes: No A/AAAA fallback is performed for null MX.
