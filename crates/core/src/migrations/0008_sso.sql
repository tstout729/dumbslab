-- Single sign-on: people sign in with the workspace's identity provider (Google Workspace,
-- Microsoft Entra ID, Okta, OneLogin, Slack or any OpenID Connect provider). The settings, with the
-- client secret encrypted, are in `settings` under the key `sso`.

-- Accounts at the provider, linked to people here by the provider's issuer and subject (`sub`).
CREATE TABLE IF NOT EXISTS sso_identities (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  issuer TEXT NOT NULL,
  subject TEXT NOT NULL,
  -- The address the provider gave when it was linked, for showing in Settings.
  email TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  last_used_at TEXT,
  UNIQUE (issuer, subject)
);
CREATE INDEX IF NOT EXISTS sso_identities_user ON sso_identities(user_id);

-- Sign-ins under way: the OAuth `state` (hashed) names one, for 15 minutes and one use.
CREATE TABLE IF NOT EXISTS sso_requests (
  state_hash TEXT PRIMARY KEY,
  -- Signing in: the hash of the cookie the browser that started got.
  browser_hash TEXT,
  -- Linking an account: the signed-in person who started.
  user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
  -- The rest, as JSON: nonce, PKCE verifier, the endpoints discovery named, where to go after.
  flow TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS sso_requests_created ON sso_requests(created_at);
