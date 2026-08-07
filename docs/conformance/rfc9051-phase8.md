# RFC 9051 Phase 8 mailbox-state conformance

RFC: RFC 9051
Section: 2.3.1.1, 2.3.2, 2.3.3, 2.3.4, 7.1
Requirement: UIDs are unique and non-reused within a UIDVALIDITY generation; UIDNEXT and modification state do not move backwards; flags and keywords persist with mailbox-message state.
Implementation: crates/mail-mailbox, crates/mail-storage, crates/mail-postgres
Test: flags_are_canonical_and_keywords_are_bounded; streaming_ingestion_and_atomic_local_delivery; constraints_counters_quota_and_leases
Status: partial
Notes: The persistent storage requirements are implemented. IMAP sequence-number views and commands are Phase 9-11 and are not claimed here.

RFC: RFC 7162
Section: 3.1, 3.2, 3.3
Requirement: Each flag or expunge mutation receives a strictly increasing per-mailbox MODSEQ, and conditional changes detect newer state.
Implementation: crates/mail-storage, crates/mail-postgres
Test: streaming_ingestion_and_atomic_local_delivery
Status: partial
Notes: Atomic STORE-style mutation, UNCHANGEDSINCE conflict behavior, and expunge tombstones are implemented. QRESYNC wire behavior remains Phase 11.
