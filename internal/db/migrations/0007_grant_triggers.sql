-- Why a run is running, and consent to runs that start later. A standing grant
-- is a person's consent to future runs: it has no trigger of its own, never
-- mints a token, and each firing is a child with one. Grants from before this
-- were all started by a person, or by a call, which also has a person present.
ALTER TABLE auth.agent_grants
    ADD COLUMN trigger    text NOT NULL DEFAULT 'user',
    ADD COLUMN automation text NOT NULL DEFAULT '',
    ADD COLUMN standing   boolean NOT NULL DEFAULT false;
ALTER TABLE auth.agent_grants
    ADD CONSTRAINT agent_grants_trigger CHECK (
        (standing AND trigger = '' AND parent_id IS NULL)
        OR (NOT standing AND trigger IN ('user', 'voice', 'schedule', 'event', 'webhook', 'agent'))
    ),
    ADD CONSTRAINT agent_grants_automation CHECK (
        (trigger IN ('schedule', 'event', 'webhook')) = (automation <> '') OR trigger = 'agent'
    );
-- Renewing on each refresh reads a person's standing grants.
CREATE INDEX agent_grants_standing ON auth.agent_grants (user_id) WHERE standing AND revoked_at IS NULL;
