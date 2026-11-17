-- Who made each API token. Connected apps are the person's own, so a token someone else made for
-- them (an admin's, for a bot) can't use them (see `connect::require_own_credential`). A connected
-- app's token (`oauth`) is always approved by the person themselves. For personal tokens, the
-- activity log names who made each one.
ALTER TABLE api_tokens ADD COLUMN created_by TEXT;
UPDATE api_tokens SET created_by = user_id WHERE kind = 'oauth';
UPDATE api_tokens SET created_by = (
  SELECT a.actor_id FROM activity a
  WHERE a.event = 'token.created' AND a.target_type = 'token' AND a.target_id = api_tokens.id
  ORDER BY a.id LIMIT 1
) WHERE kind = 'personal';
