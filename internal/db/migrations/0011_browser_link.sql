-- Which browser sign-in an app's session came from, so one sign-out can end them
-- all. It's empty for sessions that didn't come through a browser.
ALTER TABLE auth.sessions
    ADD COLUMN browser_session_id text;

UPDATE auth.sessions s
SET browser_session_id = c.session_id
FROM auth.auth_codes c
WHERE c.issued_session_id = s.id;

CREATE INDEX sessions_browser_session_idx ON auth.sessions (browser_session_id)
    WHERE browser_session_id IS NOT NULL;
