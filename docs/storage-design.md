# Storage design

PostgreSQL is the sole durable store, including raw messages. The initial representation is one immutable `BYTEA` per deduplicated message plus metadata. PostgreSQL TOAST keeps the model simple and transactional; chunking is added only if measured streaming/WAL/replication behavior requires it.

| Option | Advantages | Costs | Decision |
|---|---|---|---|
| Single `BYTEA` | atomic row/FK/backup, TOAST, simple dedupe | WAL and row rewrite pressure; client API must stream | initial |
| Chunk table | bounded reads/writes, resumable | many rows, ordering/orphan cleanup | measured fallback |
| Large Object | streaming API | separate ACL/lifecycle/backup and orphan risk | reject initially |
| Temporary spool then `BYTEA` | bounded SMTP memory, hash/size before commit | encrypted local transient data and recovery | required ingestion path |

The spool uses a private directory, mode 0700, kernel-created random files with exclusive/no-follow semantics, per-tenant/global byte caps, configurable fsync, and a short lifetime. A DB ingestion record names the spool token, never an arbitrary path. Commit order: seal+fsync spool, create ingestion row, stream into PostgreSQL, atomically create message/delivery/queue rows, mark complete, then unlink. Startup reconciles incomplete rows and files. PostgreSQL is authoritative after commit.

Operational impacts: large messages increase WAL, PITR, replication lag, backup time, TOAST vacuum load and quota contention. Enforce maximum message size before/during streaming, monitor dead tuples and lag, avoid updating body rows, partition high-churn queue/audit tables, and verify restore with large bodies. Content hash supports dedupe; quota charges logical mailbox usage under locked quota rows. Orphan cleanup is FK-driven plus a grace-period sweeper.

