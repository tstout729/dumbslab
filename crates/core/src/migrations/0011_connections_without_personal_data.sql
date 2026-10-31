-- Connected apps keep no personal data from Atlassian or Trello (see connect::providers::jira and
-- ::trello): a connection keeps only its site. Rows saved before that named the person. Jira and
-- Confluence labels ("ada@acme.com on acme.atlassian.net") become the saved site, or nothing when
-- there's none. Trello labels ("@ada") become "Trello", and their settings (the member's id and
-- username) are emptied. Credentials stay as they are.
UPDATE connections
SET account = CASE
    WHEN json_valid(settings) THEN COALESCE(CASE WHEN json_type(settings, '$.site') = 'text' THEN json_extract(settings, '$.site') END, '')
    ELSE ''
  END
WHERE provider IN ('jira', 'confluence');

UPDATE connections SET account = 'Trello', settings = '{}' WHERE provider = 'trello';
