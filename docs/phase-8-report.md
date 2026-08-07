# Phase 8 report

Implemented the mailbox storage foundation in `mail-mailbox`, `mail-storage`, and `mail-postgres`: canonical system flags, bounded IMAP keywords, atomic STORE add/remove/replace semantics, UNCHANGEDSINCE conflict detection, monotonically increasing MODSEQ, non-reused UID allocation, database-generated UIDVALIDITY, persistent tombstones for expunged messages, object IDs, internal/saved dates, and user/tenant quota accounting during local delivery.

PostgreSQL row locks serialize concurrent flag changes without lost updates. Expunge requires `\\Deleted`, assigns a new MODSEQ, preserves the UID tombstone for later QRESYNC, updates message/unseen counters, and releases the user's logical mailbox quota. Tenant physical-storage quota remains charged until later message garbage collection removes the raw PostgreSQL body. Migrations `202608070007_global_domain_identity.sql` and `202608070008_uidvalidity_sequence.sql` enforce globally unambiguous hosted domains and non-cycling UIDVALIDITY allocation.

Tests cover canonical/bounded flags, atomic local delivery, UID/MODSEQ/counter monotonicity, conditional STORE conflicts, simultaneous STORE preservation, expunge tombstones, user/tenant quota charging, and real PostgreSQL migration behavior. `mailbox_flags` fuzzes the keyword trust boundary. `cargo fmt`, strict Clippy, workspace tests, and PostgreSQL container tests are the phase gates.

Known limitations: sequence-number views and IMAP command semantics belong to Phases 9-11. Tombstone and unreferenced-message garbage collection will follow the retention/deletion workflow. PostgreSQL's UIDVALIDITY sequence intentionally fails closed after 32-bit exhaustion rather than reusing a value.
