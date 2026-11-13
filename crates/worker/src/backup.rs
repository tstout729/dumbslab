//! The operator API's backup and restore routes (see `dumbslab_core::backup` and
//! docs/cloudflare.md). The front Worker checks the operator token, finds the object a name refers
//! to and passes the request on unchanged; the object runs the core on its own database.
//!
//! - `GET  /api/operator/backup/objects`: every object to copy.
//! - `POST /api/operator/backup/{manifest,dump,summary,freeze,thaw}?object=<name>`
//! - `POST /api/operator/restore/{begin,page,finish,abort}?object=<name>`

use dumbslab_core::backup::{self, ObjectRef, Target};
use serde_json::json;
use worker::*;

use crate::sql::{call_object_raw, error_response, flag, json_response, read_body_within, var};

pub async fn route(mut req: Request, env: &Env, path: &str) -> Result<Response> {
    let multi = flag(env, "MULTI_TENANT");
    let workspace_name = var(env, "WORKSPACE_NAME").unwrap_or_else(|| "main".into());
    if path == "/api/operator/backup/objects" && req.method() == Method::Get {
        let objects = if multi {
            let mut resp = call_object_raw(env, "DIRECTORY", backup::DIRECTORY_OBJECT, "/_internal/backup/objects", vec![]).await?;
            if resp.status_code() != 200 {
                return Ok(resp);
            }
            resp.json::<serde_json::Value>().await?["objects"].take()
        } else {
            json!([ObjectRef { name: workspace_name, kind: backup::Kind::Workspace, status: None, home: None }])
        };
        return json_response(
            200,
            &json!({
                "format": backup::FORMAT,
                "version": dumbslab_core::VERSION,
                "git_sha": dumbslab_core::GIT_SHA,
                "multi_tenant": multi,
                "objects": objects,
            }),
        );
    }
    let (Some(_), Method::Post) = (backup::action(path), req.method()) else {
        return error_response(404, "not_found", "unknown backup route");
    };
    let url = req.url()?;
    let name = url.query_pairs().find(|(k, _)| k == "object").map(|(_, v)| v.into_owned()).unwrap_or_default();
    let binding = match backup::target(&name, multi, &workspace_name) {
        Some(Target::Directory) => "DIRECTORY",
        Some(Target::Workspace) => "WORKSPACE",
        None => return error_response(404, "not_found", "name an object this deployment holds: ?object=directory or ?object=ws:<address>"),
    };
    let internal = format!("/_internal/{}", path.trim_start_matches("/api/operator/"));
    let limit = dumbslab_core::http::body_limit(&internal);
    let Some(body) = read_body_within(&mut req, limit).await? else {
        return error_response(413, "too_large", "request body too large");
    };
    call_object_raw(env, binding, &name, &internal, body).await
}
