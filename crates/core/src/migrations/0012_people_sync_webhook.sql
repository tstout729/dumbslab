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

-- Which connection the people sync uses: a random id that changes whenever new credentials or
-- another company are saved, so work begun with the old ones (a sync, a renewal) can tell it's stale.
ALTER TABLE people_sync ADD COLUMN connection TEXT;

-- Credentials DumbSlab still has to look through for its own webhooks in BambooHR, one row per
-- connection: those a save replaced or was about to use, and a removed sync's. A cleanup pass lists
-- the webhooks they can see and deletes every one of this workspace's except the live one, then
-- drops the row. So a webhook whose id was lost (a step rolled back) is still found.
CREATE TABLE IF NOT EXISTS people_sync_cleanup (
  connection TEXT PRIMARY KEY,
  -- The BambooHR company domain.
  subdomain TEXT NOT NULL,
  -- `api_key` or `oauth`, and the credentials, sealed: the API key, or the sign-in's tokens
  -- (refresh token included).
  auth TEXT NOT NULL,
  secret TEXT NOT NULL,
  expires_at TEXT,
  -- SHA-256 of the refresh token, so a renewal of the same sign-in can hand over its new tokens.
  refresh_hash TEXT,
  -- Webhook ids known to be among them, comma-separated, for the activity log if DumbSlab gives up.
  known_ids TEXT NOT NULL DEFAULT '',
  -- Failed passes in a row, which space out the next one (timeouts, 429 and 5xx never end it), and
  -- when the next may run.
  failures INTEGER NOT NULL DEFAULT 0,
  next_attempt_at TEXT,
  -- A pass working on it holds this lease: when it runs out, then a random id.
  working_until TEXT,
  -- Goes up whenever a save or a removal records the connection again, so a pass that began before
  -- leaves the new work for the next pass instead of dropping it.
  version INTEGER NOT NULL DEFAULT 0,
  -- BambooHR refused to renew these credentials once: the next refusal ends the record. A renewal
  -- still under way may hand over new tokens meanwhile (which clears it).
  refused INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);
