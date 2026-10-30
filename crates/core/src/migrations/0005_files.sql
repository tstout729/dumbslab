-- Uploaded images and files. The bytes live in the workspace database so both hosts store and
-- serve them inside the request's transaction. A Durable Object row holds at most 2 MB, so the
-- bytes are split into chunks of at most 1 MB.
CREATE TABLE IF NOT EXISTS files (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  content_type TEXT NOT NULL,
  size INTEGER NOT NULL,
  sha256 TEXT NOT NULL,
  uploaded_by TEXT NOT NULL REFERENCES users(id),
  -- Set when the file belongs to a post; it then follows the post's visibility.
  post_id TEXT REFERENCES posts(id) ON DELETE CASCADE,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS files_post ON files(post_id, created_at);
CREATE INDEX IF NOT EXISTS files_uploader ON files(uploaded_by, created_at);

CREATE TABLE IF NOT EXISTS file_chunks (
  file_id TEXT NOT NULL REFERENCES files(id) ON DELETE CASCADE,
  seq INTEGER NOT NULL,
  data BLOB NOT NULL,
  PRIMARY KEY (file_id, seq)
);
