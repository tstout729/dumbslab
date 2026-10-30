-- Slack: the workspace's own Slack app (an admin creates it from a manifest DumbSlab generates),
-- the Slack channels that hear about new and updated posts, and recently seen Slack requests.
-- Secrets are encrypted with the server's connector key; nothing here is readable without it.
CREATE TABLE IF NOT EXISTS slack_app (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  -- The bot token (xoxb-…), encrypted.
  bot_token TEXT,
  -- The signing secret that proves requests come from Slack, encrypted.
  signing_secret TEXT,
  -- Which Slack workspace the bot token belongs to, from Slack's auth.test.
  team_id TEXT,
  team_name TEXT NOT NULL DEFAULT '',
  bot_user_id TEXT,
  -- Preview links to posts pasted in Slack.
  unfurls INTEGER NOT NULL DEFAULT 1,
  updated_by TEXT,
  updated_at TEXT NOT NULL
);

-- Slack channels that get a message when posts are published or updated.
CREATE TABLE IF NOT EXISTS slack_channels (
  id TEXT PRIMARY KEY,
  -- A Slack channel id (C0123ABCD) or `#name`.
  channel TEXT NOT NULL,
  -- Posts in this topic (and its org-wide subtopics); every post everyone can see when NULL.
  topic_id TEXT REFERENCES topics(id) ON DELETE CASCADE,
  new_posts INTEGER NOT NULL DEFAULT 1,
  updated_posts INTEGER NOT NULL DEFAULT 0,
  created_by TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

-- Signatures and event ids of Slack requests already handled, so a replayed request is refused
-- and an event Slack sends again is handled once. Rows go once they expire.
CREATE TABLE IF NOT EXISTS slack_seen (
  key TEXT PRIMARY KEY,
  expires_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS slack_seen_expiry ON slack_seen (expires_at);
