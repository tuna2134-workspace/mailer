# Phase 11 report

## Implemented

- `IDLE` with continuation/DONE framing, bounded timeout, cancellation-safe split reads, and periodic PostgreSQL change polling.
- `ENABLE CONDSTORE`, `ENABLE QRESYNC`, `SELECT (CONDSTORE)`, and `SELECT (QRESYNC (...))` with UIDVALIDITY validation, known-UID filtering, and validated sequence-match data.
- `HIGHESTMODSEQ`, FETCH `MODSEQ`, `CHANGEDSINCE`, FETCH `VANISHED`, STORE `UNCHANGEDSINCE`, and partial-success `MODIFIED` responses.
- Durable reconnect synchronization from active rows and expunge tombstones; QRESYNC sessions receive `VANISHED`, other selected sessions receive descending sequence-number `EXPUNGE` responses.
- Cross-session and cross-node notifications through PostgreSQL state, without process-local state being authoritative.

## RFC basis

- RFC 9051 Sections 6.3.13 and 7.4: IDLE and unsolicited selected-state responses.
- RFC 7162: CONDSTORE, QRESYNC, MODSEQ, HIGHESTMODSEQ, CHANGEDSINCE, UNCHANGEDSINCE, MODIFIED, and VANISHED.

## Tests

- `parses_phase11_synchronization_commands`
- `enforces_states_and_resets_after_starttls`
- `idle_pushes_cross_session_changes_and_accepts_done`
- `phase10_and_phase11_mailbox_sync_contract` against PostgreSQL 17

## Security and concurrency

- IDLE input is capped at the exact continuation size and does not cancel a partially read line on polling ticks.
- Mailbox ownership is checked on every change query. PostgreSQL row locks and monotonic counters remain authoritative for STORE and EXPUNGE.
- Notification polling exposes only UID, flags, sequence number, MODSEQ, and counts; it never loads or emits message bodies.

## Operational note

Selected sessions poll PostgreSQL once per second while IDLE. This is correct across nodes and intentionally avoids a second notification subsystem; a measured scale bottleneck can later add LISTEN/NOTIFY only as a wake-up hint.
