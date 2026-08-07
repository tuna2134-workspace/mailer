# PostgreSQL schema proposal

All tenant-owned tables include `tenant_id`; IDs are UUID; timestamps are `timestamptz`; secrets are hashes or encrypted blobs. Exact SQL lands in Phase 1 migrations.

Core tables: `tenants`, `tenant_settings`, `tenant_quotas`, `domains`, `domain_aliases`, `users`, `login_identities`, `password_credentials`, `application_passwords`, `external_identities`, `roles`, `role_bindings`, `api_tokens`, `addresses`, `aliases`, `alias_targets`, `mailboxes`, `subscriptions`, `messages`, `message_headers`, `mime_parts`, `mailbox_messages`, `queue_messages`, `queue_recipients`, `delivery_attempts`, `audit_events`, `certificate_accounts`, `certificates`, `ingestions`, `deletion_jobs`.

Critical constraints:

- unique `(tenant_id, normalized_domain)`; unique address ownership within a tenant.
- unique `(mailbox_id, uid)`; mailbox counters are unsigned-by-check and never decremented except counts.
- `uidvalidity > 0`, `uidnext > 0`, `highest_modseq > 0`; allocated UID/MODSEQ use locked mailbox rows.
- unique active content hash/size as the dedupe policy permits; body is immutable.
- queue recipient lease requires owner and expiry together; one terminal state; unique idempotency key in its scope.
- tenant IDs are repeated in composite foreign keys where that prevents cross-tenant references.
- aliases use deferred FK constraints; loop freedom is checked by application traversal at creation and again at expansion with depth/visited limits.
- audit events are append-only to the application role.

`mailbox_messages` holds UID, flags, keywords, MODSEQ, expunged state, saved/internal dates, object ID and search/thread metadata. Raw bytes live in `messages.raw_message BYTEA NOT NULL`; parsed data is an index/cache and never a replacement for raw bytes.

Concurrency: lock mailbox row before allocating UID/MODSEQ; update quota using a conditional atomic statement; lease queue rows with `FOR UPDATE SKIP LOCKED`; lock affected alias version during expansion snapshot; deletion changes user state first and purge is a separate idempotent job.

