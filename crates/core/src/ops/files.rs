//! Uploaded images and files. The bytes live in the workspace database, split into chunks small
//! enough for a Durable Object row, so both hosts store and serve them inside the request's
//! transaction. Posts show them with `![name](/files/<id>/<name>)`.
//!
//! Who can open a file: admins, its uploader, and anyone who can see the post it belongs to. A file
//! that belongs to no post yet is private to its uploader (and admins); saving a post that
//! references your own unattached uploads attaches them to it.

use std::borrow::Cow;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD_PAD_INDIFFERENT, URL_SAFE_PAD_INDIFFERENT};
use chrono::Utc;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

use super::clean;
use crate::auth::{self, Actor, Role};
use crate::db::{Db, DbExt, Row, SqlValue};
use crate::error::{ApiError, ApiResult};
use crate::events::{Event, emit};
use crate::http::{done, failed};
use crate::model::{
    UserRef, find_user, load_post, next_cursor, page, placeholders, post_visible_sql, require_post_edit, user_ref, user_refs,
};
use crate::registry::{Access, Ctx, Op, op};
use crate::util::new_id;
use crate::{HostConfig, Outcome, Request, Response, params};

/// The largest file `upload_file` accepts. Hosts size their upload body limit from it.
pub const MAX_FILE_SIZE: usize = 10 * 1024 * 1024;
/// Bytes per stored chunk. A Durable Object row holds at most 2 MB.
const CHUNK_SIZE: usize = 1024 * 1024;
/// Types shown inline. They're only ever set from the file's own bytes, never from a claim.
pub(crate) const INLINE_TYPES: &[&str] = &["image/png", "image/jpeg", "image/gif", "image/webp", "image/avif"];
const OCTET_STREAM: &str = "application/octet-stream";
const MAX_NAME_CHARS: usize = 200;
/// Unattached uploads one post save can attach.
const MAX_ATTACH: usize = 200;

pub fn ops() -> Vec<Op> {
    vec![
        op("files", "upload_file", "POST", "/files", Access::Write, upload_file)
            .title("Upload an image or file")
            .desc("Store an image or file (up to 10 MB, sent as base64) and get Markdown that shows it in a post. Put `markdown` from the result into create_post, update_post or edit_post: `![name](/files/<id>/<name>)` shows PNG, JPEG, GIF, WebP and AVIF images inline, and `[name](/files/<id>/<name>)` links anything else as a download. Pass `post_id` when the post exists; otherwise the file joins the first post of yours that references it. Members and admins only.")
            .build(),
        op("files", "get_file", "GET", "/files/{id}", Access::Read, get_file)
            .title("Get a file's details")
            .desc("A file's name, type, size, SHA-256, uploader and post. Download the bytes from `url` with the same credentials, or with download_file.")
            .build(),
        op("files", "download_file", "GET", "/files/{id}/content", Access::Read, download_file)
            .title("Download a file")
            .desc("A file's details and its bytes as base64 (`data_base64`), for agents that can't fetch `url` with a token, for example to look at a screenshot in a post.")
            .build(),
        op("files", "list_files", "GET", "/files", Access::Read, list_files)
            .title("List files")
            .desc("Uploaded files you can see, newest first. Filter by the post they belong to (`post_id`) or by uploader (`uploaded_by`). Other people's files that belong to no post aren't listed.")
            .build(),
        op("files", "delete_file", "DELETE", "/files/{id}", Access::Write, delete_file)
            .title("Delete a file")
            .desc("Delete an uploaded file for good and free its storage. Posts that show it get a broken image or link. Only its uploader or an admin can delete it.")
            .destructive()
            .build(),
    ]
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct FileInfo {
    pub id: String,
    /// The file name, used as the link text and in the URL.
    pub name: String,
    /// The type the file is served as. Images and PDFs are detected from the bytes.
    pub content_type: String,
    /// Size in bytes.
    pub size: i64,
    /// Hex SHA-256 of the bytes.
    pub sha256: String,
    /// Whether posts show it inline (PNG, JPEG, GIF, WebP and AVIF). Other files download.
    pub is_image: bool,
    /// Where the bytes are served, relative to the workspace, e.g. `/files/k3v9q0x2mz/shot.png`. Markdown uses this.
    pub path: String,
    /// The bytes' absolute URL. Fetch it signed in, or with `Authorization: Bearer <token>`.
    pub url: String,
    /// Markdown that shows the file in a post: `![name](path)` for images, `[name](path)` for other files.
    pub markdown: String,
    /// The post the file belongs to. Only people who can see that post can open it.
    pub post_id: Option<String>,
    pub uploaded_by: UserRef,
    pub created_at: String,
}

const FILE_COLS: &str = "f.id, f.name, f.content_type, f.size, f.sha256, f.uploaded_by, f.post_id, f.created_at";

/// The path that serves a file's bytes.
pub fn file_path(id: &str, name: &str) -> String {
    format!("/files/{id}/{}", urlencoding::encode(name))
}

/// Escapes characters that would end or restyle Markdown link text.
fn escape_label(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for c in name.chars() {
        if matches!(c, '\\' | '[' | ']' | '*' | '`' | '<' | '>' | '&' | '|') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

fn markdown_for(name: &str, path: &str, is_image: bool) -> String {
    format!("{}[{}]({path})", if is_image { "!" } else { "" }, escape_label(name))
}

fn infos(ctx: &Ctx, rows: &[Row]) -> ApiResult<Vec<FileInfo>> {
    let users = user_refs(ctx.db, &rows.iter().map(|r| r.str("uploaded_by")).collect::<Vec<_>>())?;
    Ok(rows
        .iter()
        .map(|r| {
            let (id, name, content_type) = (r.str("id"), r.str("name"), r.str("content_type"));
            let is_image = INLINE_TYPES.contains(&content_type.as_str());
            let path = file_path(&id, &name);
            FileInfo {
                url: ctx.url(&path),
                markdown: markdown_for(&name, &path, is_image),
                path,
                is_image,
                size: r.i64("size"),
                sha256: r.str("sha256"),
                post_id: r.opt_str("post_id"),
                uploaded_by: user_ref(&users, &r.str("uploaded_by")),
                created_at: r.str("created_at"),
                id,
                name,
                content_type,
            }
        })
        .collect())
}

/// SQL that is true when files alias `f` are visible to the actor: their own uploads, and files in
/// posts they can see. Knowing a file's id is never enough on its own.
fn file_visible_sql(actor: &Actor, p: &mut Vec<SqlValue>) -> String {
    if actor.sees_all() {
        return "1=1".into();
    }
    p.push(actor.user_id.clone().into());
    let vis = post_visible_sql(actor, "fp", p);
    format!("(f.uploaded_by = ? OR EXISTS (SELECT 1 FROM posts fp WHERE fp.id = f.post_id AND {vis}))")
}

fn load_file(db: &dyn Db, actor: &Actor, id: &str) -> ApiResult<Row> {
    let mut p = params![id];
    let vis = file_visible_sql(actor, &mut p);
    db.one(&format!("SELECT {FILE_COLS} FROM files f WHERE f.id = ? AND {vis}"), &p)?
        .ok_or_else(|| ApiError::not_found(format!("file `{id}`")))
}

fn info_for(ctx: &Ctx, id: &str) -> ApiResult<FileInfo> {
    let row = load_file(ctx.db, &ctx.actor, id)?;
    Ok(infos(ctx, std::slice::from_ref(&row))?.remove(0))
}

/// The type a file is served as. The bytes decide for the types we detect; otherwise the
/// client's claim stands, unless it claims an image or PDF the bytes don't back up, or a type a
/// browser would run (HTML, SVG, XML, scripts).
pub fn content_type_for(bytes: &[u8], claimed: Option<&str>) -> String {
    if let Some(t) = sniff(bytes) {
        return t.into();
    }
    match claimed.and_then(normalize_type) {
        Some(t) if !(t.starts_with("image/") || t == "application/pdf" || active_type(&t)) => t,
        _ => OCTET_STREAM.into(),
    }
}

/// Detects PNG, JPEG, GIF, WebP, AVIF and PDF from their first bytes.
pub fn sniff(b: &[u8]) -> Option<&'static str> {
    if b.starts_with(b"\x89PNG\r\n\x1a\n") {
        Some("image/png")
    } else if b.starts_with(&[0xFF, 0xD8, 0xFF]) {
        Some("image/jpeg")
    } else if b.starts_with(b"GIF87a") || b.starts_with(b"GIF89a") {
        Some("image/gif")
    } else if b.len() >= 12 && &b[..4] == b"RIFF" && &b[8..12] == b"WEBP" {
        Some("image/webp")
    } else if is_avif(b) {
        Some("image/avif")
    } else if b.starts_with(b"%PDF-") {
        Some("application/pdf")
    } else {
        None
    }
}

/// An ISO-BMFF `ftyp` box whose major or compatible brands include `avif` or `avis`.
fn is_avif(b: &[u8]) -> bool {
    if b.len() < 16 || &b[4..8] != b"ftyp" {
        return false;
    }
    let size = u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize;
    let end = size.clamp(16, b.len().min(512));
    let (compatible, _) = b[16..end].as_chunks::<4>();
    std::iter::once(&b[8..12]).chain(compatible.iter().map(|c| &c[..])).any(|brand| brand == b"avif" || brand == b"avis")
}

fn normalize_type(raw: &str) -> Option<String> {
    let t = raw.split(';').next().unwrap_or_default().trim().to_ascii_lowercase();
    let token = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"!#$&^_.+-".contains(&b));
    let valid = t.len() <= 100 && t.split_once('/').is_some_and(|(a, b)| token(a) && token(b));
    valid.then_some(t)
}

fn active_type(t: &str) -> bool {
    t.contains("html") || t.contains("script") || t == "text/xml" || t == "application/xml" || t.ends_with("+xml")
}

/// A display name: the last path segment, without control characters, at most 200 characters.
pub fn clean_name(raw: &str) -> String {
    let base = raw.rsplit(['/', '\\']).next().unwrap_or_default();
    let name: String = base.chars().filter(|c| !c.is_control()).collect();
    let name = name.trim();
    // `.` and `..` would change the URL's path.
    if name.is_empty() || name.chars().all(|c| c == '.') {
        return "file".into();
    }
    name.chars().take(MAX_NAME_CHARS).collect::<String>().trim_end().to_string()
}

fn too_large(bytes: usize) -> ApiError {
    // Rounded up, so a file just over the limit doesn't read as exactly 10.0 MB.
    let mb = (bytes as f64 / (1024.0 * 1024.0) * 10.0).ceil() / 10.0;
    ApiError::new(413, "too_large", format!("files can be at most {} MB; this one is {mb:.1} MB", MAX_FILE_SIZE / (1024 * 1024)))
}

/// Decodes `data_base64`. Accepts standard or URL-safe base64, with or without padding and line
/// breaks, and a `data:` URL such as `FileReader.readAsDataURL` produces.
fn decode(data: String) -> ApiResult<Vec<u8>> {
    let mut s = data.trim();
    if let Some(rest) = s.strip_prefix("data:") {
        s = match rest.split_once(',') {
            Some((meta, payload)) if meta.ends_with(";base64") => payload,
            _ => return Err(ApiError::bad_request("`data_base64` is a data URL without base64 data")),
        };
    }
    let compact: Cow<str> = if s.bytes().any(|b| b.is_ascii_whitespace()) {
        Cow::Owned(s.chars().filter(|c| !c.is_ascii_whitespace()).collect())
    } else {
        Cow::Borrowed(s)
    };
    // Refuse oversized files before allocating for them. The estimate is at most 2 bytes over.
    let estimate = base64::decoded_len_estimate(compact.len());
    if estimate > MAX_FILE_SIZE + 2 {
        return Err(too_large(estimate));
    }
    let engine = if compact.contains(['-', '_']) { URL_SAFE_PAD_INDIFFERENT } else { STANDARD_PAD_INDIFFERENT };
    engine.decode(compact.as_bytes()).map_err(|e| ApiError::bad_request(format!("`data_base64` isn't valid base64: {e}")))
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UploadFileInput {
    /// File name with its extension, e.g. `screenshot.png`. It becomes the link text and the end of the URL.
    pub name: String,
    /// MIME type, e.g. `text/csv`. Optional: images and PDFs are detected from their bytes, and a
    /// claimed image or PDF type the bytes don't match is ignored.
    pub content_type: Option<String>,
    /// The file's bytes as base64 (standard or URL-safe; padding, line breaks and a `data:…;base64,` prefix are fine). At most 10 MB once decoded.
    pub data_base64: String,
    /// The post this file is for. Only people who can see the post can then open the file. Without
    /// it, the file joins the first post of yours whose content references it.
    pub post_id: Option<String>,
}

fn upload_file(ctx: &mut Ctx, input: UploadFileInput) -> ApiResult<FileInfo> {
    ctx.actor.require_role(Role::Member)?;
    let name = clean_name(&input.name);
    let post = match clean(input.post_id) {
        Some(pid) => {
            let post = load_post(ctx, &pid, false)?;
            require_post_edit(ctx, &post)?;
            Some(post)
        }
        None => None,
    };
    let bytes = decode(input.data_base64)?;
    if bytes.is_empty() {
        return Err(ApiError::bad_request("the file is empty"));
    }
    if bytes.len() > MAX_FILE_SIZE {
        return Err(too_large(bytes.len()));
    }
    let content_type = content_type_for(&bytes, input.content_type.as_deref());
    let id = new_id();
    let post_id = post.as_ref().map(|p| p.str("id"));
    store(ctx, &id, &name, &content_type, &bytes, post_id.as_deref())?;
    // A file that belongs to no post may be meant for a private one, so its name stays out of
    // the activity everyone sees.
    let summary = match &post {
        Some(p) => format!("uploaded “{name}” to “{}”", p.str("title")),
        None => "uploaded a file".into(),
    };
    let mut event = Event::new("file.uploaded", "file", &id, summary)
        .data(json!({ "size": bytes.len(), "content_type": content_type }))
        .content(json!({ "name": name }));
    // The post's visibility applies to its files' events. A file in no post is private to its
    // uploader, so only admins see that it exists.
    event = match &post_id {
        Some(pid) => event.post(pid),
        None => event.admin_only(),
    };
    emit(ctx, event)?;
    info_for(ctx, &id)
}

/// Stores a file's bytes as the actor's upload, in `post_id` when given. Shared with docs sync,
/// which uploads a repository's images.
pub(crate) fn store(ctx: &Ctx, id: &str, name: &str, content_type: &str, bytes: &[u8], post_id: Option<&str>) -> ApiResult<()> {
    ctx.db.execute(
        "INSERT INTO files (id, name, content_type, size, sha256, uploaded_by, post_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        &params![id, name, content_type, bytes.len(), hex::encode(Sha256::digest(bytes)), ctx.actor.user_id.clone(), post_id, ctx.now_s()],
    )?;
    for (seq, chunk) in bytes.chunks(CHUNK_SIZE).enumerate() {
        ctx.db.execute(
            "INSERT INTO file_chunks (file_id, seq, data) VALUES (?, ?, ?)",
            &[SqlValue::from(id), SqlValue::from(seq), SqlValue::Blob(chunk.to_vec())],
        )?;
    }
    Ok(())
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FileIdInput {
    pub id: String,
}

fn get_file(ctx: &mut Ctx, input: FileIdInput) -> ApiResult<FileInfo> {
    info_for(ctx, input.id.trim())
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct DownloadedFile {
    pub file: FileInfo,
    /// The file's bytes, base64-encoded (standard alphabet, padded).
    pub data_base64: String,
}

fn download_file(ctx: &mut Ctx, input: FileIdInput) -> ApiResult<DownloadedFile> {
    let row = load_file(ctx.db, &ctx.actor, input.id.trim())?;
    let bytes = read_bytes(ctx.db, &row.str("id"), row.i64("size"))?;
    let file = infos(ctx, std::slice::from_ref(&row))?.remove(0);
    Ok(DownloadedFile { file, data_base64: base64::engine::general_purpose::STANDARD.encode(bytes) })
}

/// A file's bytes, read one chunk at a time so the peak memory stays near the file's size.
fn read_bytes(db: &dyn Db, id: &str, size: i64) -> ApiResult<Vec<u8>> {
    let size = size.max(0) as usize;
    let mut body = Vec::with_capacity(size);
    for seq in 0..size.div_ceil(CHUNK_SIZE) {
        let chunk = db.one("SELECT data FROM file_chunks WHERE file_id = ? AND seq = ?", &params![id, seq])?;
        match chunk.as_ref().map(|r| r.get("data")) {
            Some(SqlValue::Blob(b)) => body.extend_from_slice(b),
            _ => return Err(ApiError::internal(format!("file `{id}` is missing part of its data"))),
        }
    }
    if body.len() != size {
        return Err(ApiError::internal(format!("file `{id}` is missing part of its data")));
    }
    Ok(body)
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListFilesInput {
    /// Only files that belong to this post.
    pub post_id: Option<String>,
    /// Only files this person uploaded: user id, `@handle`, email or `me`.
    pub uploaded_by: Option<String>,
    /// 1-200, default 25.
    pub limit: Option<u32>,
    pub cursor: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct FileList {
    pub items: Vec<FileInfo>,
    pub next_cursor: Option<String>,
}

fn list_files(ctx: &mut Ctx, input: ListFilesInput) -> ApiResult<FileList> {
    let (limit, offset) = page(input.limit, &input.cursor)?;
    let mut conds: Vec<String> = vec![];
    let mut p: Vec<SqlValue> = vec![];
    if let Some(pid) = clean(input.post_id) {
        let post = load_post(ctx, &pid, true)?;
        conds.push("f.post_id = ?".into());
        p.push(post.str("id").into());
    }
    if let Some(who) = clean(input.uploaded_by) {
        conds.push("f.uploaded_by = ?".into());
        p.push(find_user(ctx, &who)?.str("id").into());
    }
    conds.push(file_visible_sql(&ctx.actor, &mut p));
    p.push((limit + 1).into());
    p.push(offset.into());
    let mut rows = ctx.db.query(
        &format!("SELECT {FILE_COLS} FROM files f WHERE {} ORDER BY f.created_at DESC, f.id LIMIT ? OFFSET ?", conds.join(" AND ")),
        &p,
    )?;
    let next_cursor = next_cursor(rows.len(), limit, offset);
    rows.truncate(limit as usize);
    Ok(FileList { items: infos(ctx, &rows)?, next_cursor })
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct DeleteFileResult {
    pub ok: bool,
    pub id: String,
}

fn delete_file(ctx: &mut Ctx, input: FileIdInput) -> ApiResult<DeleteFileResult> {
    let row = load_file(ctx.db, &ctx.actor, input.id.trim())?;
    let id = row.str("id");
    if row.str("uploaded_by") != ctx.actor.user_id && ctx.actor.role != Role::Admin {
        return Err(ApiError::forbidden("only the person who uploaded a file or an admin can delete it"));
    }
    ctx.db.execute("DELETE FROM file_chunks WHERE file_id = ?", &params![id.clone()])?;
    ctx.db.execute("DELETE FROM files WHERE id = ?", &params![id.clone()])?;
    let post_id = row.opt_str("post_id");
    let summary = match &post_id {
        Some(_) => format!("deleted “{}”", row.str("name")),
        None => "deleted a file".into(),
    };
    let event = Event::new("file.deleted", "file", &id, summary).content(json!({ "name": row.str("name") }));
    let event = match &post_id {
        Some(pid) => event.post(pid),
        None => event.admin_only(),
    };
    emit(ctx, event)?;
    Ok(DeleteFileResult { ok: true, id })
}

/// Ids of uploads a post's Markdown references through `/files/<id>/…` paths.
fn referenced_ids(content: &str) -> Vec<String> {
    let mut ids: Vec<String> = vec![];
    for (i, _) in content.match_indices("/files/") {
        let id: String = content[i + "/files/".len()..].chars().take_while(char::is_ascii_alphanumeric).take(11).collect();
        if id.len() == 10 && !ids.contains(&id) {
            ids.push(id);
            if ids.len() >= MAX_ATTACH {
                break;
            }
        }
    }
    ids
}

/// Attaches the actor's own uploads that belong to no post yet and that `content` references to
/// the post, so they follow its visibility from then on. Runs whenever a post's content is saved.
pub fn attach_referenced(ctx: &Ctx, post_id: &str, content: &str) -> ApiResult<()> {
    for chunk in referenced_ids(content).chunks(80) {
        let mut p = params![post_id, ctx.actor.user_id.clone()];
        p.extend(chunk.iter().map(|id| SqlValue::from(id.as_str())));
        ctx.db.execute(
            &format!("UPDATE files SET post_id = ? WHERE post_id IS NULL AND uploaded_by = ? AND id IN ({})", placeholders(chunk.len())),
            &p,
        )?;
    }
    Ok(())
}

/// Erases the files that belong to a post. Called when the post is erased.
pub fn delete_for_post(db: &dyn Db, post_id: &str) -> ApiResult<()> {
    db.execute("DELETE FROM file_chunks WHERE file_id IN (SELECT id FROM files WHERE post_id = ?)", &params![post_id])?;
    db.execute("DELETE FROM files WHERE post_id = ?", &params![post_id])?;
    Ok(())
}

/// Serves `GET /files/{id}/{name}` to signed-in people who may open the file (the name is only
/// for people and downloads). Images show inline; everything else downloads.
pub fn serve(db: &dyn Db, cfg: &HostConfig, req: &Request) -> Outcome {
    let mut out = match req.method.as_str() {
        "GET" | "HEAD" => match auth::authenticate(db, cfg, req, Utc::now()) {
            Ok(Some(actor)) if actor.scopes.read => {
                let id = req.path.strip_prefix("/files/").and_then(|rest| rest.split('/').next()).unwrap_or_default();
                match file_response(db, &actor, id, req.header("if-none-match")) {
                    Ok(r) => return done(r),
                    Err(e) => failed(&e),
                }
            }
            Ok(Some(_)) => failed(&ApiError::forbidden("this credential lacks the read scope")),
            Ok(None) => failed(&ApiError::unauthorized("sign in, or send `Authorization: Bearer <token>`, to open files")),
            Err(e) => failed(&e),
        },
        _ => {
            let mut out = failed(&ApiError::new(405, "method_not_allowed", "files are read with GET; upload them with upload_file"));
            out.response.headers.push(("allow".into(), "GET, HEAD".into()));
            out
        }
    };
    out.response.headers.push(("cache-control".into(), "no-store".into()));
    out
}

fn file_response(db: &dyn Db, actor: &Actor, id: &str, if_none_match: Option<&str>) -> ApiResult<Response> {
    let row = load_file(db, actor, id)?;
    let (id, name, content_type) = (row.str("id"), row.str("name"), row.str("content_type"));
    let etag = format!("\"{}\"", row.str("sha256"));
    let inline = INLINE_TYPES.contains(&content_type.as_str());
    let cached = if_none_match.is_some_and(|v| v.split(',').any(|t| t.trim() == etag || t.trim() == "*"));
    let mut resp = if cached {
        Response::empty(304)
    } else {
        let body = read_bytes(db, &id, row.i64("size"))?;
        Response { status: 200, headers: vec![("content-type".into(), content_type)], body }
    };
    let h = &mut resp.headers;
    h.push(("x-content-type-options".into(), "nosniff".into()));
    h.push(("content-security-policy".into(), "default-src 'none'; sandbox".into()));
    h.push(("content-disposition".into(), content_disposition(if inline { "inline" } else { "attachment" }, &name)));
    h.push(("cache-control".into(), "private, max-age=31536000, immutable".into()));
    h.push(("cross-origin-resource-policy".into(), "same-origin".into()));
    h.push(("etag".into(), etag));
    Ok(resp)
}

/// `inline; filename="…"; filename*=UTF-8''…` with an ASCII fallback that is always a valid header.
fn content_disposition(kind: &str, name: &str) -> String {
    let ascii: String = name.chars().map(|c| if c == ' ' || (c.is_ascii_graphic() && c != '"' && c != '\\') { c } else { '_' }).collect();
    format!("{kind}; filename=\"{ascii}\"; filename*=UTF-8''{}", urlencoding::encode(name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_types_from_bytes() {
        assert_eq!(sniff(b"\x89PNG\r\n\x1a\n...."), Some("image/png"));
        assert_eq!(sniff(&[0xFF, 0xD8, 0xFF, 0xE0]), Some("image/jpeg"));
        assert_eq!(sniff(b"GIF89a..."), Some("image/gif"));
        assert_eq!(sniff(b"RIFF\0\0\0\0WEBPVP8 "), Some("image/webp"));
        assert_eq!(sniff(b"\0\0\0\x1cftypavif\0\0\0\0avifmif1miaf"), Some("image/avif"));
        assert_eq!(sniff(b"\0\0\0\x20ftypmif1\0\0\0\0mif1avifmiafMA1B"), Some("image/avif"));
        assert_eq!(sniff(b"\0\0\0\x18ftypheic\0\0\0\0mif1heic"), None);
        assert_eq!(sniff(b"%PDF-1.7\n"), Some("application/pdf"));
        assert_eq!(sniff(b"<svg xmlns='http://www.w3.org/2000/svg'/>"), None);
    }

    #[test]
    fn claims_never_make_a_file_render() {
        let png = b"\x89PNG\r\n\x1a\nrest";
        assert_eq!(content_type_for(png, Some("application/pdf")), "image/png");
        assert_eq!(content_type_for(b"not an image", Some("image/png")), OCTET_STREAM);
        assert_eq!(content_type_for(b"<svg/>", Some("image/svg+xml")), OCTET_STREAM);
        assert_eq!(content_type_for(b"<html>", Some("text/html; charset=utf-8")), OCTET_STREAM);
        assert_eq!(content_type_for(b"<x/>", Some("application/xhtml+xml")), OCTET_STREAM);
        assert_eq!(content_type_for(b"alert(1)", Some("text/javascript")), OCTET_STREAM);
        assert_eq!(content_type_for(b"%PDX", Some("application/pdf")), OCTET_STREAM);
        assert_eq!(content_type_for(b"a,b\n1,2\n", Some("Text/CSV")), "text/csv");
        assert_eq!(content_type_for(b"a,b", Some("bogus")), OCTET_STREAM);
        assert_eq!(content_type_for(b"a,b", None), OCTET_STREAM);
    }

    #[test]
    fn names_are_safe_in_paths_and_markdown() {
        assert_eq!(clean_name("C:\\Users\\me\\shot.png"), "shot.png");
        assert_eq!(clean_name("../../etc/passwd"), "passwd");
        assert_eq!(clean_name(".."), "file");
        assert_eq!(clean_name("  \n "), "file");
        assert_eq!(clean_name("a\u{0}b\r\n.png"), "ab.png");
        assert_eq!(clean_name(&"x".repeat(500)).chars().count(), MAX_NAME_CHARS);
        let path = file_path("abc", "Screenshot 2026 (1) #2?.png");
        assert_eq!(path, "/files/abc/Screenshot%202026%20%281%29%20%232%3F.png");
        assert_eq!(markdown_for("a]b[c.png", &path, true), format!("![a\\]b\\[c.png]({path})"));
        assert_eq!(markdown_for("notes.txt", "/files/abc/notes.txt", false), "[notes.txt](/files/abc/notes.txt)");
        let cd = content_disposition("inline", "résumé \"final\".png");
        assert_eq!(cd, "inline; filename=\"r_sum_ _final_.png\"; filename*=UTF-8''r%C3%A9sum%C3%A9%20%22final%22.png");
    }

    #[test]
    fn decodes_what_clients_send() {
        assert_eq!(decode("aGVsbG8=".into()).unwrap(), b"hello");
        assert_eq!(decode("aGVsbG8".into()).unwrap(), b"hello");
        assert_eq!(decode("aGVs\nbG8=\n".into()).unwrap(), b"hello");
        assert_eq!(decode("data:text/plain;base64,aGVsbG8=".into()).unwrap(), b"hello");
        assert_eq!(decode("-_8=".into()).unwrap(), [0xFB, 0xFF]);
        assert_eq!(decode("+/8=".into()).unwrap(), [0xFB, 0xFF]);
        assert_eq!(decode("data:text/plain,hello".into()).unwrap_err().status, 400);
        assert_eq!(decode("not base64!".into()).unwrap_err().status, 400);
        let big = base64::engine::general_purpose::STANDARD.encode(vec![0u8; MAX_FILE_SIZE + 3]);
        assert_eq!(decode(big).unwrap_err().status, 413);
    }

    #[test]
    fn upload_bodies_fit_the_host_limit() {
        // Base64 of the largest file, wrapped at 76 columns, plus room for the rest of the JSON.
        let encoded = base64::encoded_len(MAX_FILE_SIZE, true).unwrap();
        assert!(encoded + encoded / 76 + 64 * 1024 < crate::http::MAX_UPLOAD_BODY);
        assert_eq!(crate::http::body_limit("/api/v1/files"), crate::http::MAX_UPLOAD_BODY);
        assert_eq!(crate::http::body_limit("/api/v1/operations/upload_file"), crate::http::MAX_UPLOAD_BODY);
        assert_eq!(crate::http::body_limit("/api/v1/posts"), crate::http::MAX_BODY);
    }

    #[test]
    fn finds_referenced_uploads() {
        let md = "![a](/files/abc123def0/a.png) [b](https://x.test/files/zzz999yyy1/b.pdf) /files/short/x /files/abc123def0/again";
        assert_eq!(referenced_ids(md), vec!["abc123def0", "zzz999yyy1"]);
    }

    #[test]
    fn rendered_posts_keep_relative_file_images() {
        let html = crate::markdown::render("![shot](/files/abc123def0/shot%20one.png)\n\n[notes](/files/zzz999yyy1/notes.txt)");
        assert!(html.contains("<img src=\"/files/abc123def0/shot%20one.png\" alt=\"shot\">"), "{html}");
        assert!(html.contains("href=\"/files/zzz999yyy1/notes.txt\""), "{html}");
    }
}
