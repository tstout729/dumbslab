-- Add to Slack: a workspace can connect with the host's own Slack app instead of creating one.
-- Such a connection is `shared`: its signing secret is the host's, never stored here. On hosted
-- DumbSlab its bot token isn't stored here either: the directory holds the installation, token
-- included, and jobs ask it for the token each time they act on Slack. This row only names the
-- Slack workspace and keeps the settings (previews, and the channels that get posts).
ALTER TABLE slack_app ADD COLUMN shared INTEGER NOT NULL DEFAULT 0;
-- The bot scopes Slack granted, comma-separated (Add to Slack only).
ALTER TABLE slack_app ADD COLUMN scopes TEXT NOT NULL DEFAULT '';
-- A random value that changes with every change to this row. Work decided against one version (a
-- bot token checked with Slack, a stale connection cleared) changes the row only while it's still
-- that version.
ALTER TABLE slack_app ADD COLUMN version TEXT;

-- Add to Slack under way: the OAuth `state` (hashed) names the admin and the browser session that
-- started it. Each works once, for 15 minutes.
CREATE TABLE IF NOT EXISTS slack_install_requests (
  state_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  session_hash TEXT NOT NULL,
  created_at TEXT NOT NULL
);
