-- The resource (RFC 8707) a connected app's grant is for: this server's MCP endpoint, optionally
-- `?toolset=read`. Tokens are only accepted at that address. Older rows have none and stay valid.
ALTER TABLE oauth_codes ADD COLUMN resource TEXT;
ALTER TABLE oauth_refresh_tokens ADD COLUMN resource TEXT;
ALTER TABLE api_tokens ADD COLUMN resource TEXT;
CREATE INDEX oauth_refresh_tokens_grant ON oauth_refresh_tokens(user_id, client_id);
