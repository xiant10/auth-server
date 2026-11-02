-- People can now edit their display name, so it can't mark a sample account.
ALTER TABLE auth.users ADD COLUMN sample boolean NOT NULL DEFAULT false;
UPDATE auth.users SET sample = true, display_name = '' WHERE display_name = 't10 sample account';
