ALTER TABLE mailbox_messages
    DROP CONSTRAINT mailbox_messages_pkey,
    DROP CONSTRAINT mailbox_messages_mailbox_id_uid_key,
    ADD PRIMARY KEY (mailbox_id, uid);

COMMENT ON CONSTRAINT mailbox_messages_pkey ON mailbox_messages IS
    'IMAP identity is mailbox UID; one immutable message may be copied into a mailbox more than once';
