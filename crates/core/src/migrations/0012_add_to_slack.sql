-- Add to Slack: a workspace can connect with the host's own Slack app instead of creating one.
-- Such an install is `shared`: its signing secret is the host's, never stored here, and on hosted
-- DumbSlab Slack sends its requests to the root domain, which forwards them here.
ALTER TABLE slack_app ADD COLUMN shared INTEGER NOT NULL DEFAULT 0;
-- The bot scopes Slack granted, comma-separated (Add to Slack only).
ALTER TABLE slack_app ADD COLUMN scopes TEXT NOT NULL DEFAULT '';
-- A random id for each install (each Add to Slack, and each bot token of the workspace's own app).
-- Work about one install changes the row only while it's still that install. On hosted DumbSlab it
-- also names the install's claim on its Slack workspace in the directory.
ALTER TABLE slack_app ADD COLUMN install_id TEXT;
-- Add to Slack on hosted DumbSlab: the directory confirmed this install's claim. Until it has, the
-- workspace doesn't act on Slack at all: no channel messages, command answers or link previews.
ALTER TABLE slack_app ADD COLUMN confirmed INTEGER NOT NULL DEFAULT 0;

-- Add to Slack under way: the OAuth `state` (hashed) names the admin and the browser session that
-- started it. Each works once, for 15 minutes.
CREATE TABLE IF NOT EXISTS slack_installs (
  state_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  session_hash TEXT NOT NULL,
  created_at TEXT NOT NULL
);

-- Hosted: the Add to Slack going from claiming its Slack workspace to the directory confirming it
-- holds this, so two at once can't leave the directory and the saved connection out of step. It
-- runs out by itself.
CREATE TABLE IF NOT EXISTS slack_install_lock (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  -- The install's id.
  job TEXT NOT NULL,
  until TEXT NOT NULL
);
