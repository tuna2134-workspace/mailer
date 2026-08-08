# RFC 9051 Phase 10 conformance

RFC: RFC 9051
Section: 6.3
Requirement: Authenticated-state mailbox management commands and selected-state entry MUST follow their command semantics.
Implementation: `crates/mail-imap-proto/src/parser.rs`, `crates/mail-imap-server/src/commands.rs`, `crates/mail-postgres/src/imap.rs`
Test: `phase10_and_phase11_mailbox_sync_contract`; parser command tests
Status: implemented
Notes: Phase 10 mailbox commands are implemented. LIST-EXTENDED is a later optional-extension phase and is not advertised.

RFC: RFC 9051
Section: 6.4
Requirement: Message access commands MUST distinguish sequence numbers from UIDs and preserve UID monotonicity.
Implementation: `crates/mail-imap-server/src/commands.rs`, `crates/mail-postgres/src/imap.rs`
Test: `phase10_and_phase11_mailbox_sync_contract`; `patterns_and_partial_fetch`
Status: implemented
Notes: Phase 10 operations and UID forms, SEARCH keys and MODSEQ, nested MIME/message-rfc822 FETCH sections, extended BODYSTRUCTURE, APPEND options, large-literal streaming, and atomic STORE are implemented.

RFC: RFC 4315
Section: 3
Requirement: UIDPLUS response codes and UID EXPUNGE semantics.
Implementation: `crates/mail-imap-server/src/commands.rs`
Test: parser UID command tests; `phase10_and_phase11_mailbox_sync_contract`
Status: implemented
Notes: APPENDUID, COPYUID, and UID EXPUNGE are implemented for the Phase 10 command set.

RFC: RFC 6851
Section: 3
Requirement: MOVE MUST behave atomically and MUST NOT leave a message in both mailboxes after success.
Implementation: `crates/mail-postgres/src/imap.rs`
Test: `phase10_and_phase11_mailbox_sync_contract` concurrent MOVE race
Status: implemented
Notes: A single PostgreSQL transaction performs destination UID allocation and source expunge.
