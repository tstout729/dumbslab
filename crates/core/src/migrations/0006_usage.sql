-- Hosted workspaces only: rows written per hour (Unix hour), for the rolling 24-hour write
-- allowance. Hours older than a day are deleted as new ones arrive.
CREATE TABLE IF NOT EXISTS usage_hours (
  hour INTEGER PRIMARY KEY,
  rows_written INTEGER NOT NULL DEFAULT 0
);
