-- When a signed-in person last opened this client's consent page. Clients someone has seen are
-- never pruned or evicted, so a registration flood can't break a connection in progress.
ALTER TABLE oauth_clients ADD COLUMN seen_at TEXT;
