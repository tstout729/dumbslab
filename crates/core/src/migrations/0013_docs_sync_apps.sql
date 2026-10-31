-- Docs sync without tokens or manual webhooks: DumbSlab's own GitHub App and GitLab app.
-- Credentials are encrypted with the server's connector key, like every other sync's. The GitHub
-- App's private key is the host's and never stored here.

-- How a source reads its repository, when it isn't with a pasted token (no row: a token, or none
-- for a public repository, and a webhook the admin adds). Its own table, so every statement here
-- can run again.
CREATE TABLE IF NOT EXISTS docs_source_links (
  source_id TEXT PRIMARY KEY REFERENCES docs_sources(id) ON DELETE CASCADE,
  -- `github_app` (DumbSlab's GitHub App) or `gitlab_oauth` (an approval of DumbSlab's GitLab app;
  -- DumbSlab adds the webhook itself).
  connection TEXT NOT NULL,
  -- `github_app`: the App's installation that reads the repository, and the repository's id, which
  -- stays the same when it's renamed.
  installation_id INTEGER,
  repo_id INTEGER,
  -- Why the source can't sync now (the App was uninstalled or suspended, or the repository taken
  -- out of it), as a code; NULL when it can. Its posts stay either way.
  disconnected TEXT,
  -- 1 once the repository was renamed (it keeps its id) and its source followed: the next sync
  -- renders every file again, since links out of the folder name the repository.
  renamed INTEGER NOT NULL DEFAULT 0,
  -- `gitlab_oauth`: the project's id, the webhook DumbSlab added to it, and when the access token in
  -- the source's `secret` expires (it's refreshed during a sync, under the sync's lease).
  project_id INTEGER,
  hook_id INTEGER,
  token_expires_at TEXT,
  -- A refresh of its GitLab tokens under way, or refused: `<when>|<the sync's lease, or refused>|<the
  -- spent refresh token's hash>`. Another sync doesn't spend that token meanwhile, and a refusal
  -- of it doesn't count while it might still land.
  refreshing TEXT
);
CREATE INDEX IF NOT EXISTS docs_source_links_installation ON docs_source_links(installation_id, repo_id);

-- Connect GitHub or GitLab under way: a hashed, single-use state, bound to the admin's browser
-- session (see `sync::github_app::begin`). Kept 15 minutes.
CREATE TABLE IF NOT EXISTS docs_connect_requests (
  state_hash TEXT PRIMARY KEY,
  -- `github` or `gitlab`.
  provider TEXT NOT NULL,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  -- The browser session that started it; only it may finish.
  session_hash TEXT NOT NULL,
  -- GitLab's PKCE verifier.
  verifier TEXT,
  created_at TEXT NOT NULL
);

-- Installations of DumbSlab's GitHub App an admin here connected. Another workspace may connect
-- the same installation; each keeps its own row.
CREATE TABLE IF NOT EXISTS github_installations (
  -- GitHub's installation id.
  id INTEGER PRIMARY KEY,
  -- The user or organization it's installed on (an enterprise's slug).
  account TEXT NOT NULL,
  -- `User`, `Organization` or `Enterprise`.
  account_type TEXT NOT NULL DEFAULT '',
  connected_by TEXT REFERENCES users(id) ON DELETE SET NULL,
  suspended_at TEXT,
  -- The admin's account can read more repositories there than were kept.
  more_repositories INTEGER NOT NULL DEFAULT 0,
  -- Hosted DumbSlab: whether the directory forwards this installation's deliveries here: `ok`,
  -- `full` (it serves as many workspaces as it may), or NULL until it said (each sync asks again).
  forwarding TEXT,
  -- Checking it against GitHub (see `sync::github_app::CheckJob`): each change GitHub reports bumps
  -- `requested_gen`; a check records the change it read up to in `applied_gen`. One check at a
  -- time holds `checking_until` (when it runs out, then a random id); one that failed waits until
  -- `next_check_at` before anything but a new change tries again.
  requested_gen INTEGER NOT NULL DEFAULT 0,
  applied_gen INTEGER NOT NULL DEFAULT 0,
  checking_until TEXT,
  next_check_at TEXT,
  check_failures INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

-- The repositories the connecting admin's own GitHub account could read in an installation: the
-- only ones a source here may sync, so one workspace never gets repositories only another
-- workspace's admin can see. Connecting again refreshes them.
CREATE TABLE IF NOT EXISTS github_repositories (
  installation_id INTEGER NOT NULL REFERENCES github_installations(id) ON DELETE CASCADE,
  id INTEGER NOT NULL,
  -- `owner/name`.
  full_name TEXT NOT NULL,
  default_branch TEXT NOT NULL DEFAULT 'main',
  private INTEGER NOT NULL DEFAULT 1,
  -- Set when it was taken out of the installation on GitHub; cleared if it's put back.
  removed_at TEXT,
  PRIMARY KEY (installation_id, id)
);

-- An admin's approval of DumbSlab's GitLab app, waiting for them to pick a project. Picking one
-- moves its tokens onto the new source, so each source refreshes its own.
CREATE TABLE IF NOT EXISTS docs_connections (
  id TEXT PRIMARY KEY,
  -- `gitlab`.
  provider TEXT NOT NULL,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  -- Whose account it is there, e.g. `@ada`.
  account TEXT NOT NULL DEFAULT '',
  -- Encrypted: the access and refresh tokens.
  secret TEXT NOT NULL,
  expires_at TEXT,
  -- Held while a request uses it (listing projects, adding a folder): when it runs out, then a
  -- random id. Only the holder refreshes or takes it, so one approval never ends up in two sources.
  claimed_until TEXT,
  created_at TEXT NOT NULL,
  UNIQUE (provider, user_id)
);

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
