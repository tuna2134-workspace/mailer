CREATE SEQUENCE mailbox_uidvalidity_seq AS bigint MINVALUE 1 MAXVALUE 4294967295 NO CYCLE;

SELECT setval(
    'mailbox_uidvalidity_seq',
    GREATEST(1, COALESCE((SELECT max(uid_validity) FROM mailboxes), 0)),
    COALESCE((SELECT max(uid_validity) FROM mailboxes), 0) > 0
);
