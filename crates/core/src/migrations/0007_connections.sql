-- Connected apps: each person can connect their own accounts elsewhere (GitHub, Google Drive,
-- Jira…) to search them, and see link previews, from this workspace. Credentials are encrypted
-- with the server's connector key; nothing here is readable without it.
CREATE TABLE IF NOT EXISTS connections (
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  provider TEXT NOT NULL,
  -- Who the account is, for showing in Settings, e.g. `@ada` or `ada@acme.com`.
  account TEXT NOT NULL DEFAULT '',
  -- Provider settings that aren't secret, as JSON, e.g. which GitHub orgs to search.
  settings TEXT NOT NULL DEFAULT '{}',
  -- The encrypted credentials: access token, refresh token and any secret fields.
  secret TEXT NOT NULL,
  -- When the access token expires and must be refreshed first, if it does.
  expires_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (user_id, provider)
);

-- Sign-ins with another app that are under way: the OAuth `state` (hashed) names who started it.
CREATE TABLE IF NOT EXISTS connect_requests (
  state_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  provider TEXT NOT NULL,
  -- PKCE verifier, for providers that use it.
  verifier TEXT,
  created_at TEXT NOT NULL
);
