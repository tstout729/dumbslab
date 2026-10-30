//! Model Context Protocol server (Streamable HTTP, JSON responses; stdio uses the same handler).
//! Every registry operation is a tool, so agents can do everything the web app can.

use chrono::Utc;
use serde_json::{Value, json};

use crate::auth::{self, Actor, Via};
use crate::db::{Db, DbExt};
use crate::error::ApiError;
use crate::http::{done, new_ctx, unauthorized};
use crate::model::post_visible_sql;
use crate::registry::{Ctx, Op, registry};
use crate::{HostConfig, Outcome, Request, Response, params};

pub const PROTOCOL_VERSIONS: &[&str] = &["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];

const INSTRUCTIONS: &str = "DumbSlab is a team knowledge base. Posts are Markdown documents organized into topics. \
Start with `search` or `list_topics`, read with `get_post`, and write with `create_post` (drafts by default; pass status \"published\" to share). \
For changes to an existing post prefer `edit_post` (find/replace or section edits) and pass `base_version` from `get_post` so you never overwrite someone else's edit. \
Link posts with /p/<id> URLs and mention people with @handle. \
Put a YouTube, Vimeo, Loom, Google Docs/Sheets/Slides/Forms/Drive, Figma, Airtable or Miro link on a line of its own to embed it, and write callouts as `> [!NOTE]` (or TIP, IMPORTANT, WARNING, CAUTION). \
To add an image or file, send it to `upload_file` as base64 (`data_base64`, up to 10 MB) and put the `markdown` it returns in the post: `![name](/files/<id>/<name>)` shows an image, `[name](/files/<id>/<name>)` links a download. \
Every change is recorded in history (`list_post_versions`, `diff_post_versions`) and can be restored.";

/// Which tools to expose. `core` keeps the list short; `call_operation` reaches everything else.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Toolset {
    All,
    Core,
    Read,
}

impl Toolset {
    pub fn parse(s: Option<&str>) -> Toolset {
        match s {
            Some("core") => Toolset::Core,
            Some("read" | "readonly" | "read_only") => Toolset::Read,
            _ => Toolset::All,
        }
    }
}

const CORE: &[&str] = &[
    "whoami",
    "search",
    "list_posts",
    "get_post",
    "create_post",
    "update_post",
    "edit_post",
    "list_topics",
    "get_topic",
    "create_topic",
    "list_comments",
    "create_comment",
    "list_activity",
    "list_operations",
    "describe_operation",
];

/// The toolset a query string asks for, e.g. `toolset=read`.
pub fn requested_toolset(query: &str) -> Toolset {
    Toolset::parse(query.split('&').find_map(|kv| {
        let (k, v) = kv.split_once('=')?;
        (k == "toolset").then_some(v)
    }))
}

pub fn cors(mut out: Outcome) -> Outcome {
    let h = &mut out.response.headers;
    h.push(("access-control-allow-origin".into(), "*".into()));
    h.push(("access-control-allow-methods".into(), "GET, POST, DELETE, OPTIONS".into()));
    h.push((
        "access-control-allow-headers".into(),
        "authorization, content-type, mcp-protocol-version, mcp-session-id, last-event-id".into(),
    ));
    h.push(("access-control-expose-headers".into(), "mcp-session-id, www-authenticate".into()));
    out
}

pub fn handle_http(db: &dyn Db, cfg: &HostConfig, req: &Request) -> Outcome {
    cors(match req.method.as_str() {
        "OPTIONS" => done(Response::empty(204)),
        "POST" => post(db, cfg, req),
        _ => done(Response::json(405, &json!({ "error": "use POST for MCP messages" })).with_header("allow", "POST, OPTIONS")),
    })
}

fn post(db: &dyn Db, cfg: &HostConfig, req: &Request) -> Outcome {
    // MCP clients authenticate with bearer tokens only (never cookies).
    if auth::bearer_token(req).is_none() {
        return unauthorized(cfg, req, "MCP needs a bearer token; connect with OAuth or create an API token");
    }
    let mut actor = match auth::authenticate(db, cfg, req, Utc::now()) {
        Ok(Some(a)) => a,
        Ok(None) => return unauthorized(cfg, req, "invalid token"),
        Err(e) if e.status == 401 => return unauthorized(cfg, req, &e.message),
        Err(e) => return crate::http::failed(&e),
    };
    actor.via = Via::Mcp;
    let message: Value = match serde_json::from_slice(&req.body) {
        Ok(v) => v,
        Err(e) => return done(Response::json(400, &rpc_error(Value::Null, -32700, &format!("parse error: {e}")))),
    };
    if message.is_array() {
        return done(Response::json(
            400,
            &rpc_error(Value::Null, -32600, "JSON-RPC batches are not supported; send one message per request"),
        ));
    }
    let toolset = requested_toolset(&req.query);
    let mut ctx = new_ctx(db, cfg, req, actor);
    let (reply, ok) = handle_message(&mut ctx, toolset, &message);
    // Rolled-back calls must not announce writes that never happened.
    let effects = if ok { std::mem::take(&mut ctx.effects) } else { vec![] };
    match reply {
        Some(body) => Outcome { response: Response::json(200, &body), commit: ok, effects },
        None => Outcome { response: Response::empty(202), commit: ok, effects },
    }
}

pub fn rpc_error(id: Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

fn rpc_result(id: Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

/// Handles one JSON-RPC message. Returns the reply (None for notifications) and whether the
/// transaction should commit (false when a tool failed, so partial writes roll back).
pub fn handle_message(ctx: &mut Ctx, toolset: Toolset, msg: &Value) -> (Option<Value>, bool) {
    let method = msg.get("method").and_then(Value::as_str).unwrap_or_default();
    let Some(id) = msg.get("id").cloned() else {
        return (None, true);
    };
    let params = msg.get("params").cloned().unwrap_or(json!({}));
    let result = match method {
        "initialize" => {
            let requested = params.get("protocolVersion").and_then(Value::as_str).unwrap_or(PROTOCOL_VERSIONS[0]);
            let version = if PROTOCOL_VERSIONS.contains(&requested) { requested } else { PROTOCOL_VERSIONS[0] };
            Ok(json!({
                "protocolVersion": version,
                "capabilities": {
                    "tools": { "listChanged": false },
                    "resources": { "listChanged": false, "subscribe": false },
                    "prompts": { "listChanged": false },
                    "logging": {},
                    "completions": {}
                },
                "serverInfo": { "name": "dumbslab", "title": "DumbSlab", "version": crate::VERSION },
                "instructions": INSTRUCTIONS,
            }))
        }
        "ping" | "logging/setLevel" => Ok(json!({})),
        "tools/list" => Ok(json!({ "tools": tools(&ctx.actor, toolset) })),
        "tools/call" => return call_tool(ctx, toolset, id, &params),
        "resources/list" | "resources/read" if !ctx.actor.scopes.read => Err((-32603, "this credential lacks the read scope".to_string())),
        "resources/list" => list_resources(ctx),
        "resources/templates/list" => Ok(json!({ "resourceTemplates": [
            { "uriTemplate": "dumbslab://posts/{id}", "name": "post", "title": "A post as Markdown", "mimeType": "text/markdown" },
            { "uriTemplate": "dumbslab://topics/{id}", "name": "topic", "title": "A topic and its posts", "mimeType": "text/markdown" }
        ]})),
        "resources/read" => read_resource(ctx, params.get("uri").and_then(Value::as_str).unwrap_or_default()),
        "prompts/list" => Ok(json!({ "prompts": prompts() })),
        "prompts/get" => get_prompt(&params),
        "completion/complete" => Ok(json!({ "completion": { "values": [], "hasMore": false } })),
        _ => Err((-32601, format!("method `{method}` not found"))),
    };
    match result {
        Ok(r) => (Some(rpc_result(id, r)), true),
        Err((code, message)) => (Some(rpc_error(id, code, &message)), true),
    }
}

fn tool_def(op: &Op) -> Value {
    let description = if op.description.is_empty() { op.title.to_string() } else { format!("{}. {}", op.title, op.description) };
    json!({
        "name": op.name,
        "title": op.title,
        "description": description,
        "inputSchema": op.input_schema,
        "outputSchema": op.output_schema,
        "annotations": {
            "title": op.title,
            "readOnlyHint": op.read_only(),
            "destructiveHint": op.destructive,
            "idempotentHint": op.idempotent,
            "openWorldHint": false
        }
    })
}

fn call_operation_def() -> Value {
    json!({
        "name": "call_operation",
        "title": "Call any operation",
        "description": "Call any DumbSlab operation by name, including ones not listed as tools. Use list_operations to see them and describe_operation for an operation's input schema.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": { "type": "string", "description": "Operation name, e.g. verify_post" },
                "arguments": { "type": "object", "description": "The operation's input" }
            },
            "required": ["name"],
            "additionalProperties": false
        },
        "annotations": { "title": "Call any operation", "readOnlyHint": false, "destructiveHint": true, "openWorldHint": false }
    })
}

pub fn tools(actor: &Actor, toolset: Toolset) -> Vec<Value> {
    let mut out: Vec<Value> = registry()
        .ops
        .iter()
        .filter(|op| op.allowed_for(actor))
        .filter(|op| match toolset {
            Toolset::All => true,
            Toolset::Core => CORE.contains(&op.name),
            Toolset::Read => op.read_only(),
        })
        .map(tool_def)
        .collect();
    if toolset == Toolset::Core {
        out.push(call_operation_def());
    }
    out
}

fn call_tool(ctx: &mut Ctx, toolset: Toolset, id: Value, params: &Value) -> (Option<Value>, bool) {
    let name = params.get("name").and_then(Value::as_str).unwrap_or_default();
    let mut args = params.get("arguments").cloned().unwrap_or(json!({}));
    let mut op_name = name.to_string();
    if name == "call_operation" && toolset == Toolset::Core {
        op_name = args.get("name").and_then(Value::as_str).unwrap_or_default().to_string();
        args = args.get("arguments").cloned().unwrap_or(json!({}));
    }
    let Some(op) = registry().get(&op_name) else {
        return (Some(rpc_error(id, -32602, &format!("unknown tool `{op_name}`"))), true);
    };
    if toolset == Toolset::Read && !op.read_only() {
        return (Some(rpc_result(id, tool_error(&ApiError::forbidden("this MCP connection is read-only (toolset=read)")))), true);
    }
    match op.call(ctx, args) {
        Ok(value) => {
            let text = serde_json::to_string(&value).unwrap_or_default();
            (
                Some(rpc_result(
                    id,
                    json!({ "content": [{ "type": "text", "text": text }], "structuredContent": value, "isError": false }),
                )),
                true,
            )
        }
        Err(e) => (Some(rpc_result(id, tool_error(&e))), e.keep_writes),
    }
}

fn tool_error(e: &ApiError) -> Value {
    let mut text = format!("Error ({}): {}", e.code, e.message);
    if let Some(d) = &e.details {
        text.push_str(&format!("\nDetails: {d}"));
    }
    json!({ "content": [{ "type": "text", "text": text }], "isError": true })
}

fn list_resources(ctx: &Ctx) -> Result<Value, (i64, String)> {
    let mut p = params![];
    let vis = post_visible_sql(&ctx.actor, "p", &mut p);
    let rows = ctx
        .db
        .query(
            &format!("SELECT p.id, p.title, p.excerpt, p.updated_at FROM posts p WHERE p.status = 'published' AND p.deleted_at IS NULL AND {vis} ORDER BY p.updated_at DESC LIMIT 50"),
            &p,
        )
        .map_err(internal)?;
    let mut resources = vec![json!({
        "uri": "dumbslab://guide", "name": "guide", "title": "How to use DumbSlab (agent guide)", "mimeType": "text/markdown"
    })];
    resources.extend(rows.iter().map(|r| {
        json!({
            "uri": format!("dumbslab://posts/{}", r.str("id")),
            "name": r.str("id"),
            "title": r.str("title"),
            "description": r.str("excerpt"),
            "mimeType": "text/markdown",
            "annotations": { "lastModified": r.str("updated_at") }
        })
    }));
    Ok(json!({ "resources": resources }))
}

fn internal(e: ApiError) -> (i64, String) {
    (-32603, e.message)
}

fn read_resource(ctx: &mut Ctx, uri: &str) -> Result<Value, (i64, String)> {
    let text = if uri == "dumbslab://guide" {
        crate::openapi::llms_txt(&ctx.base_url)
    } else if let Some(id) = uri.strip_prefix("dumbslab://posts/") {
        let post = crate::model::load_post(ctx, id, false).map_err(|e| (-32002, e.message))?;
        let topics: Vec<String> = crate::model::topics_for_posts(ctx, &[post.str("id")])
            .map_err(internal)?
            .remove(&post.str("id"))
            .unwrap_or_default()
            .into_iter()
            .map(|t| t.name)
            .collect();
        format!(
            "---\ntitle: {}\nid: {}\nurl: {}\nstatus: {}\nversion: {}\ntopics: [{}]\nupdated_at: {}\n---\n\n{}",
            post.str("title"),
            post.str("id"),
            crate::model::post_url(ctx, &post.str("id"), &post.str("slug")),
            post.str("status"),
            post.i64("version"),
            topics.join(", "),
            post.str("updated_at"),
            post.str("content")
        )
    } else if let Some(id) = uri.strip_prefix("dumbslab://topics/") {
        let topic = crate::model::load_topic(ctx, id).map_err(|e| (-32002, e.message))?;
        let list = registry()
            .get("list_posts")
            .expect("list_posts exists")
            .call(ctx, json!({ "topic_id": topic.str("id"), "limit": 100 }))
            .map_err(internal)?;
        let mut md = format!("# {}\n\n{}\n\n", topic.str("name"), topic.str("description"));
        for item in list["items"].as_array().into_iter().flatten() {
            md.push_str(&format!(
                "- [{}]({}) — {}\n",
                item["title"].as_str().unwrap_or_default(),
                item["url"].as_str().unwrap_or_default(),
                item["excerpt"].as_str().unwrap_or_default()
            ));
        }
        md
    } else {
        return Err((-32002, format!("resource not found: {uri}")));
    };
    Ok(json!({ "contents": [{ "uri": uri, "mimeType": "text/markdown", "text": text }] }))
}

fn prompts() -> Vec<Value> {
    vec![
        json!({ "name": "write_post", "title": "Write a post from notes", "description": "Turn rough notes into a well-structured post in the right topic.",
                "arguments": [{ "name": "notes", "description": "Your notes or source material", "required": true }, { "name": "topic", "description": "Topic name (optional)", "required": false }] }),
        json!({ "name": "find_stale_docs", "title": "Find docs that need attention", "description": "Review expired and stale posts and propose updates.", "arguments": [] }),
        json!({ "name": "summarize_topic", "title": "Summarize a topic", "description": "Read a topic's posts and summarize what the team knows.",
                "arguments": [{ "name": "topic", "description": "Topic name or id", "required": true }] }),
    ]
}

fn get_prompt(params: &Value) -> Result<Value, (i64, String)> {
    let name = params.get("name").and_then(Value::as_str).unwrap_or_default();
    let arg = |k: &str| params.get("arguments").and_then(|a| a.get(k)).and_then(Value::as_str).unwrap_or_default().to_string();
    let text = match name {
        "write_post" => format!(
            "Write a DumbSlab post from these notes. First `search` for existing posts on the subject; if one exists, improve it with `edit_post` instead of duplicating it. \
             Otherwise pick a topic with `list_topics`{} and `create_post` with clear headings, short paragraphs and lists. Publish it only if the notes are complete; otherwise leave it as a draft.\n\nNotes:\n{}",
            if arg("topic").is_empty() { String::new() } else { format!(" (preferably “{}”)", arg("topic")) },
            arg("notes")
        ),
        "find_stale_docs" => "Call `get_insights`. For each post whose verification expired or that is stale, read it with `get_post`, \
             check it against related posts (`search`), and list what looks outdated. Propose specific edits; don't change anything until asked."
            .to_string(),
        "summarize_topic" => format!(
            "Find the topic “{}” with `list_topics` (or `get_topic` if it's an id), read its posts with `list_posts` and `get_post`, \
             and write a concise summary of what the team knows, with links (/p/<id>) to the source posts.",
            arg("topic")
        ),
        _ => return Err((-32602, format!("unknown prompt `{name}`"))),
    };
    Ok(json!({ "messages": [{ "role": "user", "content": { "type": "text", "text": text } }] }))
}

/// Runs one stdio message for a local actor (used by `dumbslab mcp`).
pub fn handle_stdio(
    db: &dyn Db,
    cfg: &HostConfig,
    actor: Actor,
    toolset: Toolset,
    line: &str,
) -> (Option<Value>, bool, Vec<crate::Effect>) {
    let msg: Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(e) => return (Some(rpc_error(Value::Null, -32700, &format!("parse error: {e}"))), true, vec![]),
    };
    let req = Request { origin: cfg.base_url.clone().unwrap_or_else(|| "http://localhost:8080".into()), ..Default::default() };
    let mut ctx = new_ctx(db, cfg, &req, actor);
    let (reply, ok) = handle_message(&mut ctx, toolset, &msg);
    let effects = if ok { std::mem::take(&mut ctx.effects) } else { vec![] };
    (reply, ok, effects)
}

/// Used by tests and the CLI to confirm a token resolves.
pub fn token_user(db: &dyn Db, token: &str) -> Option<String> {
    db.one("SELECT user_id FROM api_tokens WHERE token_hash = ?", &params![crate::util::sha256_hex(token)])
        .ok()
        .flatten()
        .map(|r| r.str("user_id"))
}
