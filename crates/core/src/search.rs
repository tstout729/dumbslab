//! Full-text search (SQLite FTS5) over posts, comments and topics.

use crate::db::{Db, DbExt};
use crate::error::ApiResult;
use crate::markdown::plain_text;
use crate::params;

fn doc_id(db: &dyn Db, kind: &str, ref_id: &str) -> ApiResult<i64> {
    db.execute("INSERT INTO search_docs (kind, ref_id) VALUES (?, ?) ON CONFLICT(kind, ref_id) DO NOTHING", &params![kind, ref_id])?;
    db.scalar_i64("SELECT id FROM search_docs WHERE kind = ? AND ref_id = ?", &params![kind, ref_id])
}

fn put(db: &dyn Db, kind: &str, ref_id: &str, post_id: Option<&str>, title: &str, body: &str) -> ApiResult<()> {
    let id = doc_id(db, kind, ref_id)?;
    db.execute("DELETE FROM search_index WHERE rowid = ?", &params![id])?;
    db.execute(
        "INSERT INTO search_index (rowid, kind, ref_id, post_id, title, body) VALUES (?, ?, ?, ?, ?, ?)",
        &params![id, kind, ref_id, post_id, title, body],
    )?;
    Ok(())
}

pub fn remove(db: &dyn Db, kind: &str, ref_id: &str) -> ApiResult<()> {
    if let Some(row) = db.one("SELECT id FROM search_docs WHERE kind = ? AND ref_id = ?", &params![kind, ref_id])? {
        db.execute("DELETE FROM search_index WHERE rowid = ?", &params![row.i64("id")])?;
        db.execute("DELETE FROM search_docs WHERE id = ?", &params![row.i64("id")])?;
    }
    Ok(())
}

/// Re-indexes a post (or removes it when trashed or gone).
pub fn index_post(db: &dyn Db, post_id: &str) -> ApiResult<()> {
    match db.one("SELECT title, content, deleted_at FROM posts WHERE id = ?", &params![post_id])? {
        Some(r) if r.opt_str("deleted_at").is_none() => {
            put(db, "post", post_id, Some(post_id), &r.str("title"), &plain_text(&r.str("content")))
        }
        _ => remove(db, "post", post_id),
    }
}

pub fn index_comment(db: &dyn Db, comment_id: &str) -> ApiResult<()> {
    match db.one(
        "SELECT c.post_id, c.body, c.deleted_at, p.title FROM comments c JOIN posts p ON p.id = c.post_id WHERE c.id = ?",
        &params![comment_id],
    )? {
        Some(r) if r.opt_str("deleted_at").is_none() => {
            put(db, "comment", comment_id, Some(&r.str("post_id")), &r.str("title"), &plain_text(&r.str("body")))
        }
        _ => remove(db, "comment", comment_id),
    }
}

pub fn index_topic(db: &dyn Db, topic_id: &str) -> ApiResult<()> {
    match db.one("SELECT name, description FROM topics WHERE id = ?", &params![topic_id])? {
        Some(r) => put(db, "topic", topic_id, None, &r.str("name"), &r.str("description")),
        None => remove(db, "topic", topic_id),
    }
}

/// Keeps comment entries' titles in sync after a post is renamed.
pub fn reindex_post_comments(db: &dyn Db, post_id: &str) -> ApiResult<()> {
    for r in db.query("SELECT id FROM comments WHERE post_id = ? AND deleted_at IS NULL", &params![post_id])? {
        index_comment(db, &r.str("id"))?;
    }
    Ok(())
}

/// Turns free text into a safe FTS5 query. Words are ANDed (or ORed when `any`); `"quoted
/// phrases"` stay phrases; the last bare word matches as a prefix so search-as-you-type works.
pub fn fts_query(q: &str, any: bool) -> Option<String> {
    let mut terms: Vec<String> = vec![];
    let mut rest = q;
    let mut last_is_prefixable = false;
    while !rest.is_empty() {
        if let Some(after) = rest.strip_prefix('"') {
            let (phrase, remainder) = match after.find('"') {
                Some(i) => (&after[..i], &after[i + 1..]),
                None => (after, ""),
            };
            let words: Vec<&str> = phrase.split(|c: char| !c.is_alphanumeric()).filter(|w| !w.is_empty()).collect();
            if !words.is_empty() {
                terms.push(format!("\"{}\"", words.join(" ")));
                last_is_prefixable = false;
            }
            rest = remainder;
            continue;
        }
        let end = rest.find(|c: char| !c.is_alphanumeric()).unwrap_or(rest.len());
        if end == 0 {
            let skip = rest.chars().next().map(char::len_utf8).unwrap_or(1);
            rest = &rest[skip..];
            continue;
        }
        let word = &rest[..end];
        rest = &rest[end..];
        if matches!(word, "AND" | "OR" | "NOT") {
            continue;
        }
        terms.push(format!("\"{word}\""));
        last_is_prefixable = rest.is_empty();
    }
    if terms.is_empty() {
        return None;
    }
    if last_is_prefixable && let Some(last) = terms.last_mut() {
        last.push('*');
    }
    Some(terms.join(if any { " OR " } else { " " }))
}

/// Converts an FTS snippet (with \x01/\x02 markers) into escaped HTML with `<mark>` tags.
pub fn snippet_html(raw: &str) -> String {
    crate::util::html_escape(raw).replace('\u{1}', "<mark>").replace('\u{2}', "</mark>")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_queries() {
        assert_eq!(fts_query("hello world", false).unwrap(), "\"hello\" \"world\"*");
        assert_eq!(fts_query("hello world ", false).unwrap(), "\"hello\" \"world\"");
        assert_eq!(fts_query("\"on call\" rota", false).unwrap(), "\"on call\" \"rota\"*");
        assert_eq!(fts_query("a OR b", true).unwrap(), "\"a\" OR \"b\"*");
        assert_eq!(fts_query("drop\"); --", false).unwrap(), "\"drop\"");
        assert!(fts_query("  !!! ", false).is_none());
    }

    #[test]
    fn snippets_are_escaped() {
        assert_eq!(snippet_html("<b>\u{1}x\u{2}</b>"), "&lt;b&gt;<mark>x</mark>&lt;/b&gt;");
    }
}
