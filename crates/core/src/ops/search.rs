use std::collections::HashMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::clean;
use crate::db::{DbExt, SqlValue};
use crate::error::{ApiError, ApiResult};
use crate::model::*;
use crate::params;
use crate::registry::{Access, Ctx, Op, op};
use crate::search::{fts_query, snippet_html};

pub fn ops() -> Vec<Op> {
    vec![
        op("search", "search", "GET", "/search", Access::Read, search)
            .title("Search")
            .desc("Full-text search across posts, comments and topics you can see. Words are matched with stemming; \"quoted phrases\" match exactly; the last word matches as a prefix. Results are ranked with title matches first and include highlighted snippets.")
            .build(),
    ]
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SearchInput {
    pub q: String,
    /// Any of `post`, `comment`, `topic`. Default all.
    pub types: Option<Vec<String>>,
    /// Only results in this topic (and its subtopics).
    pub topic_id: Option<String>,
    /// Author id, @handle, email or `me`.
    pub author: Option<String>,
    /// Include archived posts. Default false.
    pub include_archived: Option<bool>,
    /// Include drafts you can see. Default true.
    pub include_drafts: Option<bool>,
    pub limit: Option<u32>,
    pub cursor: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct SearchHit {
    /// `post`, `comment` or `topic`.
    pub kind: String,
    /// The post, comment or topic id.
    pub id: String,
    /// For posts and comments: the post id.
    pub post_id: Option<String>,
    pub title: String,
    pub url: String,
    /// HTML-escaped text with matches wrapped in `<mark>`.
    pub snippet: String,
    pub topics: Vec<TopicRef>,
    pub author: Option<UserRef>,
    pub status: Option<String>,
    pub updated_at: Option<String>,
    /// Lower is better (BM25).
    pub score: f64,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct SearchResults {
    pub items: Vec<SearchHit>,
    pub next_cursor: Option<String>,
    /// True when no result matched every word and results matching any word are shown instead.
    pub broadened: bool,
}

fn run(ctx: &Ctx, input: &SearchInput, match_q: &str, limit: i64, offset: i64) -> ApiResult<Vec<crate::db::Row>> {
    let kinds: Vec<String> = input.types.clone().unwrap_or_else(|| vec!["post".into(), "comment".into(), "topic".into()]);
    for k in &kinds {
        if !matches!(k.as_str(), "post" | "comment" | "topic") {
            return Err(ApiError::bad_request(format!("unknown type `{k}`")));
        }
    }
    let mut p: Vec<SqlValue> = vec![];
    let mut prefix = String::new();
    let mut post_filters: Vec<String> = vec![];
    if let Some(tid) = clean(input.topic_id.clone()) {
        load_topic(ctx, &tid)?;
        prefix = "WITH RECURSIVE sub(id) AS (SELECT ? UNION SELECT t.id FROM topics t JOIN sub ON t.parent_id = sub.id) ".into();
        p.push(tid.into());
        post_filters
            .push("EXISTS (SELECT 1 FROM post_topics fpt WHERE fpt.post_id = p.id AND fpt.topic_id IN (SELECT id FROM sub))".into());
    }
    p.push(match_q.into());
    let mut author_id = None;
    if let Some(a) = clean(input.author.clone()) {
        author_id = Some(find_user(ctx, &a)?.str("id"));
    }
    if !input.include_archived.unwrap_or(false) {
        post_filters.push("p.status != 'archived'".into());
    }
    if !input.include_drafts.unwrap_or(true) {
        post_filters.push("p.status != 'draft'".into());
    }
    let mut post_p: Vec<SqlValue> = vec![];
    if let Some(aid) = &author_id {
        post_filters.push("(CASE WHEN s.kind = 'comment' THEN c.author_id ELSE p.author_id END) = ?".into());
        post_p.push(aid.into());
    }
    let post_vis = post_visible_sql(&ctx.actor, "p", &mut post_p);
    post_filters.push(post_vis);
    let mut topic_p: Vec<SqlValue> = vec![];
    let topic_vis = topic_visible_sql(&ctx.actor, "t", &mut topic_p);

    let kind_list = kinds.iter().map(|k| format!("'{k}'")).collect::<Vec<_>>().join(", ");
    let topics_allowed = kinds.iter().any(|k| k == "topic") && author_id.is_none() && input.topic_id.is_none();
    let sql = format!(
        "{prefix}SELECT s.kind, s.ref_id, s.post_id, s.title, s.snip, s.score,
                p.slug AS post_slug, p.status, p.updated_at, p.author_id, c.author_id AS comment_author, t.slug AS topic_slug
         FROM (SELECT kind, ref_id, post_id, title,
                      snippet(search_index, 4, char(1), char(2), '…', 14) AS snip,
                      bm25(search_index, 0.0, 0.0, 0.0, 10.0, 1.0) AS score
               FROM search_index WHERE search_index MATCH ?) s
         LEFT JOIN posts p ON p.id = s.post_id
         LEFT JOIN comments c ON s.kind = 'comment' AND c.id = s.ref_id
         LEFT JOIN topics t ON s.kind = 'topic' AND t.id = s.ref_id
         WHERE s.kind IN ({kind_list}) AND (
           (s.kind = 'topic' AND {topics_allowed} AND t.id IS NOT NULL AND {topic_vis})
           OR (s.kind IN ('post', 'comment') AND p.id IS NOT NULL AND p.deleted_at IS NULL
               AND (s.kind = 'post' OR c.deleted_at IS NULL) AND {}))
         ORDER BY s.score LIMIT ? OFFSET ?",
        post_filters.join(" AND "),
        topics_allowed = if topics_allowed { "1" } else { "0" },
    );
    p.extend(topic_p);
    p.extend(post_p);
    p.push((limit + 1).into());
    p.push(offset.into());
    ctx.db.query(&sql, &p)
}

fn search(ctx: &mut Ctx, input: SearchInput) -> ApiResult<SearchResults> {
    let (limit, offset) = page(input.limit, &input.cursor)?;
    let Some(all_words) = fts_query(&input.q, false) else {
        return Ok(SearchResults { items: vec![], next_cursor: None, broadened: false });
    };
    let mut rows = run(ctx, &input, &all_words, limit, offset)?;
    let mut broadened = false;
    if rows.is_empty()
        && offset == 0
        && let Some(any_word) = fts_query(&input.q, true).filter(|q| *q != all_words)
    {
        rows = run(ctx, &input, &any_word, limit, offset)?;
        broadened = !rows.is_empty();
    }
    let next_cursor = next_cursor(rows.len(), limit, offset);
    rows.truncate(limit as usize);

    let post_ids: Vec<String> = rows.iter().filter_map(|r| r.opt_str("post_id")).collect();
    let mut topics = topics_for_posts(ctx, &post_ids)?;
    let mut user_ids: Vec<String> = rows.iter().filter_map(|r| r.opt_str("author_id")).collect();
    user_ids.extend(rows.iter().filter_map(|r| r.opt_str("comment_author")));
    let users = user_refs(ctx.db, &user_ids)?;
    let mut cache: HashMap<String, Vec<TopicRef>> = HashMap::new();
    let items = rows
        .iter()
        .map(|r| {
            let kind = r.str("kind");
            let id = r.str("ref_id");
            let post_id = r.opt_str("post_id");
            let url = match kind.as_str() {
                "topic" => topic_url(ctx, &id, &r.str("topic_slug")),
                "comment" => format!("{}#comment-{id}", post_url(ctx, post_id.as_deref().unwrap_or_default(), &r.str("post_slug"))),
                _ => post_url(ctx, &id, &r.str("post_slug")),
            };
            let post_topics = match &post_id {
                Some(pid) => cache.entry(pid.clone()).or_insert_with(|| topics.remove(pid).unwrap_or_default()).clone(),
                None => vec![],
            };
            let author = match kind.as_str() {
                "comment" => r.opt_str("comment_author"),
                "post" => r.opt_str("author_id"),
                _ => None,
            }
            .map(|a| user_ref(&users, &a));
            SearchHit {
                snippet: snippet_html(&r.str("snip")),
                title: r.str("title"),
                status: r.opt_str("status"),
                updated_at: r.opt_str("updated_at"),
                score: r.f64("score"),
                topics: post_topics,
                author,
                url,
                post_id,
                kind,
                id,
            }
        })
        .collect();
    Ok(SearchResults { items, next_cursor, broadened })
}

/// Counts index entries; used by tests and diagnostics.
pub fn indexed_count(db: &dyn crate::db::Db) -> ApiResult<i64> {
    db.scalar_i64("SELECT COUNT(*) FROM search_docs", &params![])
}
