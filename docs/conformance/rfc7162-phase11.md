# RFC 7162 Phase 11 conformance

RFC: RFC 7162
Section: 3.1-3.2
Requirement: Servers implementing CONDSTORE expose HIGHESTMODSEQ, MODSEQ search/fetch, CHANGEDSINCE, and conditional STORE semantics.
Implementation: `crates/mail-imap-proto/src/parser.rs`; `crates/mail-imap-server/src/commands.rs`; `crates/mail-postgres/src/imap.rs`
Test: `parses_phase11_synchronization_commands`; `phase10_and_phase11_mailbox_sync_contract`
Status: implemented
Notes: Conditional STORE updates eligible messages and returns failed UIDs in MODIFIED.

RFC: RFC 7162
Section: 3.3-3.4
Requirement: QRESYNC selection and FETCH report expunged UIDs with VANISHED and changed flags with UID/MODSEQ.
Implementation: `crates/mail-imap-server/src/commands.rs`; `crates/mail-imap-server/src/lib.rs`; `crates/mail-postgres/src/imap.rs`
Test: `validates_qresync_selection_parameters`; `idle_pushes_cross_session_changes_and_accepts_done`; `phase10_and_phase11_mailbox_sync_contract`
Status: implemented
Notes: Expunge tombstones persist in PostgreSQL and support reconnect and multi-node synchronization.
