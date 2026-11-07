-- One t10 account per WeChat identity in a mini-program, and one identity per account.
-- Removing a binding keeps the row, for the audit trail.
CREATE TABLE auth.wechat_bindings (
	id         text PRIMARY KEY,
	app_id     text NOT NULL,
	openid     text NOT NULL,
	user_id    text NOT NULL REFERENCES auth.users(id),
	created_at timestamptz NOT NULL DEFAULT now(),
	removed_at timestamptz
);

CREATE UNIQUE INDEX wechat_bindings_identity ON auth.wechat_bindings (app_id, openid) WHERE removed_at IS NULL;
CREATE UNIQUE INDEX wechat_bindings_user ON auth.wechat_bindings (app_id, user_id) WHERE removed_at IS NULL;
