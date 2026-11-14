-- Why a person's last sign-in with an app didn't work, in DumbSlab's words for that app (e.g.
-- "Atlassian didn't give access to a site with Jira…"). The link back to Settings carries only a
-- code (anyone can make such a link), so Settings reads the reason from here, through
-- list_connections. Kept for a few minutes; starting a new sign-in or connecting the app clears
-- it (see `connect::remember_failure`).
CREATE TABLE IF NOT EXISTS connect_failures (
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  provider TEXT NOT NULL,
  message TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (user_id, provider)
);
