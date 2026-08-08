ALTER TABLE queue_recipients DROP CONSTRAINT queue_recipients_state_check;
ALTER TABLE queue_recipients ADD CONSTRAINT queue_recipients_state_check
    CHECK (state IN ('pending','leased','deferred','ambiguous','delivered','failed','cancelled'));

DROP INDEX queue_claim_idx;
CREATE INDEX queue_claim_idx ON queue_recipients (next_attempt_at, id)
    WHERE state IN ('pending','deferred','ambiguous','leased');

ALTER TABLE messages
    ADD COLUMN authentication_results_trusted boolean NOT NULL DEFAULT false;
