RFC: RFC 5322
Section: 2.1.1, 2.2, 2.2.3
Requirement: Lines are bounded, header fields have valid names, and folded field bodies unfold by removing CRLF.
Implementation: crates/mail-message/src/lib.rs
Test: incremental_split_preserves_raw_and_unfolds; empty_header_block_and_truncated_header_are_distinct
Status: implemented
Notes: Default line limit is 1000 octets including CRLF; total header bytes and field count are separately bounded.

RFC: RFC 5322
Section: 3.3, 3.6.4
Requirement: Date and Message-ID fields use their defined syntax.
Implementation: crates/mail-message/src/lib.rs
Test: message_id_date_and_encoded_word_are_typed
Status: partial
Notes: Current Date parser accepts modern RFC 2822 form; obsolete zones/comments are not claimed.

RFC: RFC 5322
Section: 3.4
Requirement: Parse mailbox, address-list, group, quoted local-part, comments and domain literals.
Implementation: crates/mail-address/src/lib.rs
Test: parses_mailboxes_comments_quotes_and_groups; arbitrary_addresses_never_panic
Status: partial
Notes: Obsolete source routes and SMTPUTF8 are rejected.
