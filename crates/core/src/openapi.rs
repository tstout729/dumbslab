//! Machine-readable docs generated from the registry: OpenAPI 3.1 and `/llms.txt`.

use serde_json::{Map, Value, json};

use crate::registry::{Access, registry};

fn error_schema() -> Value {
    json!({
        "type": "object",
        "properties": { "error": { "type": "object", "properties": {
            "code": { "type": "string" }, "message": { "type": "string" }, "details": {}
        }, "required": ["code", "message"] } },
        "required": ["error"]
    })
}

/// Removes the given properties from an object schema (used to split path params from bodies).
fn without_props(schema: &Value, remove: &[&str]) -> Value {
    let mut s = schema.clone();
    if let Some(props) = s.get_mut("properties").and_then(Value::as_object_mut) {
        for r in remove {
            props.remove(*r);
        }
    }
    if let Some(req) = s.get_mut("required").and_then(Value::as_array_mut) {
        req.retain(|v| !v.as_str().is_some_and(|n| remove.contains(&n)));
    }
    s
}

pub fn spec(base_url: &str) -> Value {
    let mut paths: Map<String, Value> = Map::new();
    for op in &registry().ops {
        let path_params = op.path_params();
        let mut parameters: Vec<Value> = path_params
            .iter()
            .map(|p| json!({ "name": p, "in": "path", "required": true, "schema": op.input_schema["properties"][p].clone() }))
            .collect();
        let mut operation = json!({
            "operationId": op.name,
            "summary": op.title,
            "description": op.description,
            "tags": [op.group],
            "x-access": op.access,
            "responses": {
                "200": { "description": "OK", "content": { "application/json": { "schema": op.output_schema } } },
                "default": { "description": "Error", "content": { "application/json": { "schema": error_schema() } } }
            }
        });
        let rest = without_props(&op.input_schema, &path_params);
        if op.method == "GET" || op.method == "DELETE" {
            let required: Vec<&str> = rest["required"].as_array().map(|a| a.iter().filter_map(Value::as_str).collect()).unwrap_or_default();
            if let Some(props) = rest["properties"].as_object() {
                for (name, schema) in props {
                    parameters
                        .push(json!({ "name": name, "in": "query", "required": required.contains(&name.as_str()), "schema": schema }));
                }
            }
        } else if rest["properties"].as_object().is_some_and(|p| !p.is_empty()) {
            operation["requestBody"] = json!({ "required": true, "content": { "application/json": { "schema": rest } } });
        }
        if !parameters.is_empty() {
            operation["parameters"] = Value::Array(parameters);
        }
        let entry = paths.entry(format!("/api/v1{}", op.path)).or_insert_with(|| json!({}));
        entry[op.method.to_lowercase()] = operation;
    }
    paths.insert(
        "/api/v1/operations/{name}".into(),
        json!({ "post": {
            "operationId": "call_operation",
            "summary": "Call any operation by name",
            "description": "Send the operation's input as the JSON body. Same behavior as its REST route.",
            "tags": ["meta"],
            "parameters": [{ "name": "name", "in": "path", "required": true, "schema": { "type": "string" } }],
            "requestBody": { "content": { "application/json": { "schema": { "type": "object" } } } },
            "responses": { "200": { "description": "The operation's output" } }
        }}),
    );
    json!({
        "openapi": "3.1.0",
        "info": {
            "title": "DumbSlab API",
            "version": crate::VERSION,
            "description": "Every DumbSlab capability. The same operations are available as MCP tools at /mcp.",
            "license": { "name": "MIT OR Apache-2.0" }
        },
        "servers": [{ "url": base_url }],
        "security": [{ "bearerAuth": [] }],
        "components": { "securitySchemes": { "bearerAuth": { "type": "http", "scheme": "bearer", "description": "A personal access token (ds_pat_…) or OAuth access token." } } },
        "paths": paths
    })
}

/// The agent guide served at `/llms.txt` and as the `dumbslab://guide` MCP resource.
pub fn llms_txt(base_url: &str) -> String {
    let mut ops = String::new();
    let mut group = "";
    for op in &registry().ops {
        if op.group != group {
            group = op.group;
            ops.push_str(&format!("\n### {group}\n"));
        }
        let access = match op.access {
            Access::Read => "",
            Access::Write => " (write)",
            Access::Admin => " (admin)",
        };
        ops.push_str(&format!("- `{}` — {} `{} /api/v1{}`{access}\n", op.name, op.title, op.method, op.path));
    }
    format!(
        "# DumbSlab\n\n\
         > An open-source team knowledge base (in the spirit of Slab). Posts are Markdown, organized into topics.\n\
         > Everything a person can do in the web app, an agent can do through MCP or the REST API.\n\n\
         ## Connect\n\n\
         - MCP (Streamable HTTP): `{base_url}/mcp` — sign in with OAuth, or send `Authorization: Bearer <token>`.\n\
           Add `?toolset=core` for a smaller tool list (the rest stay reachable through `call_operation`), or `?toolset=read` for read-only tools.\n\
         - Claude Code: `claude mcp add --transport http dumbslab {base_url}/mcp`\n\
         - REST: `{base_url}/api/v1` with `Authorization: Bearer <token>`. OpenAPI: `{base_url}/api/v1/openapi.json`.\n\
         - Any operation: `POST {base_url}/api/v1/operations/<name>` with the input as JSON.\n\
         - Tokens: create one under Settings → API tokens, or with the `create_api_token` operation.\n\n\
         ## How it works\n\n\
         - Posts have a title and a Markdown body, a status (`draft`, `published`, `archived`), topics, a version number and full history.\n\
         - New posts are drafts unless you pass `status: \"published\"`. Drafts are visible only to their author and admins.\n\
         - Topics nest. Private topics (and posts only in private topics) are visible to their members.\n\
         - Link posts with `/p/<id>` URLs (backlinks are tracked). Mention people with `@handle` to notify them.\n\
         - Edit precisely with `edit_post` (find/replace, append, section edits by heading) and pass `base_version` from `get_post` to avoid overwriting others.\n\
         - `verify_post` marks a post as accurate for N days; `get_insights` lists expired and stale posts.\n\
         - Every change is in `list_activity`; poll it with `after_id`, or have an admin add a webhook.\n\n\
         ## Operations\n{ops}"
    )
}
