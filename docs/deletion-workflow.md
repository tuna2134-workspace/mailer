# Deletion workflow

User/domain deletion defaults to disable plus soft-delete timestamp. New authentication and delivery stop immediately; in-flight transactions either finish against the pre-delete locked version or fail cleanly. A scheduled purge checks retention, legal hold, export state and restored/undo status, then removes relations in bounded transactions before unreferenced bodies.

Restore before purge clears the tombstone through an authorized audited command. Export is separately authorized. Final purge is irreversible in primary storage but backup retention is reported. API DELETE is idempotent and returns job state; it never performs an unbounded synchronous cascade.
