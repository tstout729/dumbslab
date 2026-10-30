-- Comment events used to copy the comment's body into the activity log, where it outlived the
-- comment's deletion. Their data held nothing else; webhooks still get the body when it's written.
UPDATE activity SET data = '{}' WHERE event IN ('comment.created', 'comment.updated');
