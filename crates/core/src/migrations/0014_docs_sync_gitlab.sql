-- Docs sync through DumbSlab's GitLab app: what it adds to the docs sync tables of the migration
-- before (the GitHub app's, which already holds GitLab app sources' links and approvals). Only new
-- tables, so every statement here can run again.

-- Webhooks DumbSlab still has to take off a GitLab project, one row per removed GitLab app folder
-- (see `sync::gitlab_app::Cleanup`). A pass lists the project's webhooks with the folder's tokens,
-- deletes those pointing at the folder, then drops the row. A failed pass waits longer each time.
-- DumbSlab gives up only when GitLab no longer accepts the tokens or shows the project, or after
-- 30 days, and then says so in the activity log with the project and the webhook ids.
CREATE TABLE IF NOT EXISTS docs_hook_cleanup (
  -- The removed folder's id: its webhooks post to `/hooks/docs/<source_id>`.
  source_id TEXT PRIMARY KEY,
  project_id INTEGER NOT NULL,
  -- The project's path when the folder was removed, for the activity log.
  repo TEXT NOT NULL,
  -- Webhook ids known to be the folder's, comma-separated.
  known_ids TEXT NOT NULL DEFAULT '',
  -- Encrypted: the folder's tokens (refresh token included) and the addresses its webhook had.
  secret TEXT NOT NULL,
  expires_at TEXT,
  -- SHA-256 of the refresh token in `secret`: a renewal saves new tokens only over the ones it spent.
  refresh_hash TEXT,
  -- GitLab refused to renew these tokens once. A second refusal of the same token ends the record;
  -- the first may be a refusal of a renewal whose answer is still on its way.
  refused INTEGER NOT NULL DEFAULT 0,
  -- Failed passes in a row, which space out the next one, and when it may run.
  failures INTEGER NOT NULL DEFAULT 0,
  next_attempt_at TEXT,
  -- A pass working on it holds this lease: when it runs out, then a random id.
  working_until TEXT,
  -- The admin who removed the folder: the activity log's entry is theirs if DumbSlab gives up.
  removed_by TEXT NOT NULL,
  created_at TEXT NOT NULL
);
