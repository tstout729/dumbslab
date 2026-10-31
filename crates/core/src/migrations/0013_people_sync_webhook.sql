-- People sync: the webhook DumbSlab adds in BambooHR itself when an admin saves the sync.

-- BambooHR's id for that webhook, to delete it when the sync is saved again or removed. NULL when
-- DumbSlab added none (an admin added one by hand and pasted its private key, or there is none).
ALTER TABLE people_sync ADD COLUMN webhook_id TEXT;
-- The address that webhook posts to, so Settings can say when the workspace has moved since.
ALTER TABLE people_sync ADD COLUMN webhook_url TEXT;
-- Why DumbSlab couldn't add the webhook, for Settings. NULL when it could, or didn't try.
ALTER TABLE people_sync ADD COLUMN webhook_error TEXT;
