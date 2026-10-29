//! Operation definitions, grouped by area. `all()` is the single source of truth for what the
//! API, MCP server and CLI can do.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::{ApiError, ApiResult};
use crate::registry::Op;

pub mod admin;
pub mod comments;
pub mod meta;
pub mod notifications;
pub mod posts;
pub mod search;
pub mod topics;
pub mod users;

pub fn all() -> Vec<Op> {
    let mut ops = vec![];
    ops.extend(users::ops());
    ops.extend(posts::ops());
    ops.extend(topics::ops());
    ops.extend(comments::ops());
    ops.extend(search::ops());
    ops.extend(notifications::ops());
    ops.extend(admin::ops());
    ops.extend(meta::ops());
    ops
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NoInput {}

#[derive(Debug, Serialize, JsonSchema)]
pub struct Done {
    pub ok: bool,
}

pub const DONE: Done = Done { ok: true };

/// Trims a string and treats blank as absent.
pub fn clean(s: Option<String>) -> Option<String> {
    s.map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

pub fn required(s: &str, field: &str, max: usize) -> ApiResult<String> {
    let t = s.trim();
    if t.is_empty() {
        return Err(ApiError::bad_request(format!("`{field}` is required")));
    }
    if t.chars().count() > max {
        return Err(ApiError::bad_request(format!("`{field}` is longer than {max} characters")));
    }
    Ok(t.to_string())
}

pub const MAX_CONTENT: usize = 2_000_000;

pub fn check_content(s: &str) -> ApiResult<()> {
    if s.len() > MAX_CONTENT {
        return Err(ApiError::bad_request("content is larger than 2 MB"));
    }
    Ok(())
}
