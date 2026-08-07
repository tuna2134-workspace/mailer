ALTER TABLE messages
    ADD COLUMN deliver_by_at timestamptz,
    ADD COLUMN deliver_by_mode text CHECK (deliver_by_mode IN ('N', 'R')),
    ADD COLUMN deliver_by_trace boolean NOT NULL DEFAULT false,
    ADD COLUMN release_at timestamptz,
    ADD CONSTRAINT messages_delivery_timing_order
        CHECK (release_at IS NULL OR deliver_by_at IS NULL OR release_at < deliver_by_at);
