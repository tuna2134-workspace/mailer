# PostgreSQL backup, PITR, and disaster recovery

Use encrypted physical base backups plus continuous WAL archiving for PITR; optionally retain logical dumps for inspection, never as the only backup. Backups include roles/schema, raw `BYTEA`, certificate encrypted blobs and migration audit, but encryption keys remain in a separate secret system.

Define and test RPO/RTO per deployment. At minimum: daily base backup, continuous WAL, immutable off-site retention, checksum verification, quarterly isolated restore, and a pre-destructive-migration backup. Restore runbook: freeze writers, choose target time, restore base+WAL, validate schema checksum and message-body hashes, rotate credentials if exposure is possible, reconcile spool/leases, then admit queue workers and listeners in that order. Expired leases are recoverable; delivered recipient state prevents duplicate delivery.

Replication is availability, not backup. Monitor archive gaps, replica lag, backup age/size, restore duration and WAL growth from large messages. Legal holds override normal retention and must survive restore.

