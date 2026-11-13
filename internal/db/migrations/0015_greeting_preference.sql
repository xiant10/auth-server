-- How a person likes an agent to greet them when they start a call: personal (by
-- name, with their work), simple (no personal details) or off. Empty means they
-- haven't chosen, which is personal.
ALTER TABLE auth.users
    ADD COLUMN greeting text NOT NULL DEFAULT '' CHECK (greeting IN ('', 'personal', 'simple', 'off'));
