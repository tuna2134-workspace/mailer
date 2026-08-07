ALTER TABLE messages
    ADD COLUMN smtp_utf8 boolean NOT NULL DEFAULT false,
    ADD COLUMN require_tls boolean NOT NULL DEFAULT false,
    ADD COLUMN dsn_ret text CHECK (dsn_ret IN ('FULL', 'HDRS')),
    ADD COLUMN envelope_id text;

CREATE TABLE message_recipient_options (
    message_id uuid NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    recipient text NOT NULL,
    dsn_notify text,
    original_recipient text,
    PRIMARY KEY (message_id, recipient)
);

CREATE TABLE scram_credentials (
    user_id uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    salt bytea NOT NULL CHECK (octet_length(salt) >= 16),
    iterations integer NOT NULL CHECK (iterations >= 4096),
    stored_key bytea NOT NULL CHECK (octet_length(stored_key) = 32),
    server_key bytea NOT NULL CHECK (octet_length(server_key) = 32),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
