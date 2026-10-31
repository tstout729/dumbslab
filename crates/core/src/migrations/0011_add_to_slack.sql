-- Add to Slack: a workspace can connect with the host's own Slack app instead of creating one.
-- Such an install is `shared`: its signing secret is the host's, never stored here, and on hosted
-- DumbSlab Slack sends its requests to the root domain, which forwards them here.
ALTER TABLE slack_app ADD COLUMN shared INTEGER NOT NULL DEFAULT 0;
-- The bot scopes Slack granted, comma-separated (Add to Slack only).
ALTER TABLE slack_app ADD COLUMN scopes TEXT NOT NULL DEFAULT '';
-- When Add to Slack last finished. Slack doesn't keep events in order, so an uninstall event sent
-- before this is about an earlier install and is ignored.
ALTER TABLE slack_app ADD COLUMN installed_at TEXT;

-- Add to Slack under way: the OAuth `state` (hashed) names the admin and the browser session that
-- started it. Each works once, for 15 minutes.
CREATE TABLE IF NOT EXISTS slack_installs (
  state_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  session_hash TEXT NOT NULL,
  created_at TEXT NOT NULL
);
