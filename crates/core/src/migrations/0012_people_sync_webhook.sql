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

-- Webhooks DumbSlab added in BambooHR and still has to delete: one a save replaced when BambooHR
-- wouldn't delete it then, one a save added before it stopped partway, or a removed sync's.
CREATE TABLE IF NOT EXISTS people_sync_cleanup (
  id TEXT PRIMARY KEY,
  webhook_id TEXT NOT NULL,
  -- The BambooHR company domain the webhook is in.
  subdomain TEXT NOT NULL,
  -- `api_key` or `oauth`, and the credentials that may delete it, sealed: the API key, or the
  -- sign-in's tokens (refresh token included).
  auth TEXT NOT NULL,
  secret TEXT NOT NULL,
  expires_at TEXT,
  -- SHA-256 of the refresh token, so a renewal of the same sign-in can hand over its new tokens.
  refresh_hash TEXT,
  -- Failed attempts so far. DumbSlab gives up after 5, and says so in the activity log.
  attempts INTEGER NOT NULL DEFAULT 0,
  -- A job deleting it holds this lease: when it runs out, then a random id.
  working_until TEXT,
  created_at TEXT NOT NULL
);
