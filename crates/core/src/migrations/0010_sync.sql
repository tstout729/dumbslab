-- People sync (profile details from BambooHR) and docs sync (Markdown from GitHub or GitLab).
-- Credentials are encrypted with the server's connector key, like connected apps'; nothing here
-- is readable without it.

-- Profile details the people sync fills in from the HR system, one row per person it matched.
CREATE TABLE IF NOT EXISTS user_profiles (
  user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  title TEXT NOT NULL DEFAULT '',
  department TEXT NOT NULL DEFAULT '',
  location TEXT NOT NULL DEFAULT '',
  phone TEXT NOT NULL DEFAULT '',
  pronouns TEXT NOT NULL DEFAULT '',
  -- Set when the person's manager is in the workspace too.
  manager_id TEXT REFERENCES users(id) ON DELETE SET NULL,
  updated_at TEXT NOT NULL
);

-- The workspace's people sync. There is at most one.
CREATE TABLE IF NOT EXISTS people_sync (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  provider TEXT NOT NULL DEFAULT 'bamboohr',
  -- The BambooHR company domain: `acme` for acme.bamboohr.com.
  subdomain TEXT NOT NULL,
  -- Encrypted: the API key and, when set, the webhook's private key.
  secret TEXT NOT NULL,
  -- Whether a webhook private key is set, so BambooHR's webhooks start syncs.
  webhook INTEGER NOT NULL DEFAULT 0,
  -- The admin who set it up; the activity log names them.
  owner_id TEXT NOT NULL REFERENCES users(id),
  -- A sync under way holds this lease: when it runs out, then a random id (see `sync::claim`).
  running_until TEXT,
  -- A webhook arrived while a sync was running, so the last sync may have missed a change.
  pending_since TEXT,
  last_started_at TEXT,
  last_finished_at TEXT,
  -- `ok`, `partial` or `failed`.
  last_status TEXT,
  last_error TEXT,
  -- The last sync's result, as JSON.
  last_result TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

-- Signed webhook deliveries seen in the last few minutes, so a replayed one is refused.
CREATE TABLE IF NOT EXISTS hook_deliveries (
  -- Who sent it and its signature, e.g. `bamboohr:<signature>`.
  key TEXT PRIMARY KEY,
  seen_at TEXT NOT NULL
);

-- Docs sync: a repository folder whose Markdown files are kept as posts in a topic.
CREATE TABLE IF NOT EXISTS docs_sources (
  id TEXT PRIMARY KEY,
  provider TEXT NOT NULL CHECK (provider IN ('github', 'gitlab')),
  -- `github.com`, `gitlab.com` or a self-managed GitLab's host.
  host TEXT NOT NULL,
  -- `owner/name`, or a GitLab project's full path (`group/subgroup/project`).
  repo TEXT NOT NULL,
  branch TEXT NOT NULL,
  -- The folder within the repository, without slashes at either end; empty for the whole repository.
  folder TEXT NOT NULL DEFAULT '',
  -- Deleting the topic deletes the source; its posts stay, as ordinary posts.
  topic_id TEXT NOT NULL REFERENCES topics(id) ON DELETE CASCADE,
  -- Encrypted: the read-only token (may be empty for public repositories) and the webhook secret.
  secret TEXT NOT NULL,
  -- The admin who set it up. Synced posts are written as them.
  owner_id TEXT NOT NULL REFERENCES users(id),
  running_until TEXT,
  pending_since TEXT,
  last_started_at TEXT,
  last_finished_at TEXT,
  last_status TEXT,
  last_error TEXT,
  last_result TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

-- What a source synced: each Markdown file's post, each image's uploaded file and each folder's
-- topic, by path within the source's folder.
CREATE TABLE IF NOT EXISTS docs_items (
  source_id TEXT NOT NULL REFERENCES docs_sources(id) ON DELETE CASCADE,
  -- `doc`, `image` or `folder`.
  kind TEXT NOT NULL CHECK (kind IN ('doc', 'image', 'folder')),
  path TEXT NOT NULL,
  -- The post, file or topic. A new file's post id is chosen before the post exists, so links to it
  -- from other files work while a large first sync is still under way.
  target_id TEXT NOT NULL,
  -- The git blob last synced; NULL until it has been.
  sha TEXT,
  -- Paths this file links to or shows, one per line: it's synced again when one of them changes.
  refs TEXT NOT NULL DEFAULT '',
  -- Set when the file is gone from the repository; its post is archived. It stays set until the
  -- file, back again, has been synced and its post published again.
  removed_at TEXT,
  -- A blob that can never be synced (too large, say), and why: skipped until the file changes.
  skipped_sha TEXT,
  skip_reason TEXT,
  synced_at TEXT,
  PRIMARY KEY (source_id, kind, path)
);
CREATE INDEX IF NOT EXISTS docs_items_target ON docs_items(target_id);

-- Memberships of private folder topics that the sync itself gave: the source's topic's members
-- when it made the folder's topic. Only these does it ever take back (when the person is no longer
-- in the source's topic), and only while unchanged: `added_at` is the membership's own, so one
-- someone removed and gave again counts as theirs, not the sync's.
CREATE TABLE IF NOT EXISTS docs_memberships (
  source_id TEXT NOT NULL REFERENCES docs_sources(id) ON DELETE CASCADE,
  topic_id TEXT NOT NULL REFERENCES topics(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  added_at TEXT NOT NULL,
  PRIMARY KEY (topic_id, user_id)
);
