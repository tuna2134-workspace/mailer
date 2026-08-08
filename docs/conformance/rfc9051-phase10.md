# RFC 9051 Phase 10 conformance

RFC: RFC 9051  
Section: 6.3  
Requirement: Authenticated-state mailbox management commands and selected-state entry MUST follow their command semantics.  
Implementation: `crates/mail-imap-proto/src/parser.rs`, `crates/mail-imap-server/src/commands.rs`, `crates/mail-postgres/src/imap.rs`  
Test: `phase10_mailbox_message_and_uid_contract`; parser command tests  
Status: partial  
Notes: Core mailbox commands are implemented; extended LIST options are deferred.

RFC: RFC 9051  
Section: 6.4  
Requirement: Message access commands MUST distinguish sequence numbers from UIDs and preserve UID monotonicity.  
Implementation: `crates/mail-imap-server/src/commands.rs`, `crates/mail-postgres/src/imap.rs`  
Test: `phase10_mailbox_message_and_uid_contract`; `patterns_and_partial_fetch`  
Status: partial  
Notes: Core operations and UID forms, broad SEARCH keys, nested MIME FETCH sections, APPEND options, and command-wide STORE rollback are implemented. Large APPEND streaming and extended BODYSTRUCTURE/message-rfc822 edge cases remain incomplete.

RFC: RFC 4315  
Section: 3  
Requirement: UIDPLUS response codes and UID EXPUNGE semantics.  
Implementation: `crates/mail-imap-server/src/commands.rs`  
Test: parser UID command tests; `phase10_mailbox_message_and_uid_contract`  
Status: partial  
Notes: APPENDUID, COPYUID, and UID EXPUNGE are implemented; exhaustive response-code edge tests remain pending.

RFC: RFC 6851  
Section: 3  
Requirement: MOVE MUST behave atomically and MUST NOT leave a message in both mailboxes after success.  
Implementation: `crates/mail-postgres/src/imap.rs`  
Test: PostgreSQL COPY/EXPUNGE transaction primitives; dedicated concurrent MOVE testing pending  
Status: partial  
Notes: A single PostgreSQL transaction performs destination UID allocation and source expunge.
