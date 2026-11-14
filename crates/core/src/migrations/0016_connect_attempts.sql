-- Each person's latest sign-in with each connected app, and why it failed. The link back to
-- Settings carries only a code (anyone can make such a link), so Settings reads the reason from
-- here, through list_connections (see `connect::remember_failure`).
CREATE TABLE IF NOT EXISTS connect_attempts (
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  provider TEXT NOT NULL,
  -- The latest sign-in: the hash of its OAuth `state`, as in connect_requests. Only it may record
  -- why it failed; starting another or connecting the app takes that from older ones.
  attempt TEXT NOT NULL,
  -- Why it failed: one of DumbSlab's fixed sentences, never text from the app
  -- (`connect::public_reason`). NULL while it's under way, or when there's nothing to say.
  message TEXT,
  -- When it started, then when it failed. Rows older than 15 minutes are never shown, and are
  -- deleted the next time a sign-in starts or fails, or an app is connected, in the workspace.
  created_at TEXT NOT NULL,
  PRIMARY KEY (user_id, provider)
);
