-- Add to Slack: a workspace can connect with the host's own Slack app instead of creating one.
-- Such an install is `shared`: its signing secret is the host's, never stored here, and on hosted
-- DumbSlab Slack sends its requests to the root domain, which forwards them here.
ALTER TABLE slack_app ADD COLUMN shared INTEGER NOT NULL DEFAULT 0;
-- The bot scopes Slack granted, comma-separated (Add to Slack only).
ALTER TABLE slack_app ADD COLUMN scopes TEXT NOT NULL DEFAULT '';
-- Goes up with every install. Work about one install (checking a token Slack says was revoked)
-- changes the row only while it's still that install.
ALTER TABLE slack_app ADD COLUMN generation INTEGER NOT NULL DEFAULT 0;
-- Hosted: the id this install claimed its Slack workspace with in the directory. Letting go of a
-- claim names its id, so letting go of an earlier one never removes a later one.
ALTER TABLE slack_app ADD COLUMN claim TEXT;

-- Add to Slack under way: the OAuth `state` (hashed) names the admin and the browser session that
-- started it. Each works once, for 15 minutes.
CREATE TABLE IF NOT EXISTS slack_installs (
  state_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  session_hash TEXT NOT NULL,
  created_at TEXT NOT NULL
);

-- Shared-app bot tokens to revoke: after Disconnect, or once the workspace moved to another Slack
-- workspace. The directory keeps the Slack workspace's claim until Slack has answered the revoke,
-- so no other workspace can be given this token while a revoke of it might still land.
CREATE TABLE IF NOT EXISTS slack_releases (
  team_id TEXT PRIMARY KEY,
  -- The bot token, encrypted.
  bot_token TEXT NOT NULL,
  -- The directory claim to let go of afterwards (hosted).
  claim TEXT,
  -- A job is revoking it until then; others wait.
  revoking_until TEXT,
  created_at TEXT NOT NULL
);

-- Hosted: an Add to Slack between claiming its Slack workspace and saving it holds this, so two at
-- once can't leave the directory and the saved connection out of step. It runs out by itself.
CREATE TABLE IF NOT EXISTS slack_install_lock (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  job TEXT NOT NULL,
  until TEXT NOT NULL
);
