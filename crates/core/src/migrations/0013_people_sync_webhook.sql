-- People sync: Sign in with BambooHR, and the webhook DumbSlab adds in BambooHR itself when an
-- admin saves the sync.

-- How DumbSlab signs in to BambooHR: `api_key` (self-hosted only) or `oauth` (Sign in with
-- BambooHR). The sealed `secret` holds the API key, or the sign-in's access and refresh tokens.
ALTER TABLE people_sync ADD COLUMN auth TEXT NOT NULL DEFAULT 'api_key';
-- When the sign-in's access token expires; NULL for API keys.
ALTER TABLE people_sync ADD COLUMN expires_at TEXT;
-- A request renewing the access token holds this lease: when it runs out, then a random id.
ALTER TABLE people_sync ADD COLUMN refreshing_until TEXT;
-- BambooHR's id for the webhook DumbSlab added, to delete it when the sync is saved again or removed.
-- NULL when DumbSlab added none (an admin added one by hand and pasted its private key, or there is none).
ALTER TABLE people_sync ADD COLUMN webhook_id TEXT;
-- The address that webhook posts to, so Settings can say when the workspace has moved since.
ALTER TABLE people_sync ADD COLUMN webhook_url TEXT;
-- Why DumbSlab couldn't add the webhook, for Settings. NULL when it could, or didn't try.
ALTER TABLE people_sync ADD COLUMN webhook_error TEXT;

-- Sign-ins with BambooHR under way: each link works once, for 15 minutes, for the admin (and the
-- browser session) that started it. Only the state's hash is kept.
CREATE TABLE IF NOT EXISTS people_sync_sign_ins (
  state_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  -- The browser session that started it; NULL when an agent started it with a token.
  session_hash TEXT,
  -- The BambooHR company domain the admin gave.
  subdomain TEXT NOT NULL,
  created_at TEXT NOT NULL
);
