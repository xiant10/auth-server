-- A person's language and theme, so every t10 app and page shows the same ones.
-- Empty means they haven't chosen, and each place uses its own default.
ALTER TABLE auth.users
    ADD COLUMN language text NOT NULL DEFAULT '' CHECK (language IN ('', 'en', 'zh-Hans')),
    ADD COLUMN theme text NOT NULL DEFAULT '' CHECK (theme IN ('', 'system', 'light', 'dark'));
