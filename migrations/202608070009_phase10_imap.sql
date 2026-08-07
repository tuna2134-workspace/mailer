CREATE TABLE imap_subscriptions (
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    mailbox_id uuid NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, mailbox_id)
);
