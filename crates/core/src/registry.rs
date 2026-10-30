//! The operation registry. Every capability is declared once here with typed input/output; REST
//! routes, the generic operations endpoint, MCP tools, OpenAPI and the CLI are all derived from it.

use std::collections::HashMap;
use std::sync::OnceLock;

use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use schemars::generate::SchemaSettings;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::auth::Actor;
use crate::db::Db;
use crate::error::{ApiError, ApiResult};
use crate::{Effect, HostConfig};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Access {
    /// Needs the `read` scope.
    Read,
    /// Needs the `write` scope. Handlers check roles for content changes.
    Write,
    /// Needs the admin role and the `admin` scope.
    Admin,
}

/// Everything an operation handler can touch.
pub struct Ctx<'a> {
    pub db: &'a dyn Db,
    pub actor: Actor,
    pub now: DateTime<Utc>,
    pub cfg: &'a HostConfig,
    /// The public origin used for absolute links, e.g. `https://dumbslab.com`.
    pub base_url: String,
    pub effects: Vec<Effect>,
}

impl Ctx<'_> {
    pub fn now_s(&self) -> String {
        crate::util::ts(self.now)
    }

    pub fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }
}

type Handler = Box<dyn Fn(&mut Ctx, Value) -> ApiResult<Value> + Send + Sync>;

pub struct Op {
    /// snake_case name used as the MCP tool name and in `/api/v1/operations/{name}`.
    pub name: &'static str,
    pub group: &'static str,
    pub title: &'static str,
    pub description: &'static str,
    pub method: &'static str,
    /// Path under `/api/v1`, with `{param}` segments taken from the input.
    pub path: &'static str,
    pub access: Access,
    pub destructive: bool,
    pub idempotent: bool,
    /// Hosted workspaces: whether the operation counts against the plan's write allowance. Ones
    /// that don't (upgrading, managing billing) keep working once the allowance is used up.
    pub metered: bool,
    pub input_schema: Value,
    pub output_schema: Value,
    handler: Handler,
}

impl Op {
    pub fn read_only(&self) -> bool {
        self.access == Access::Read
    }

    /// Checks scopes and runs the handler.
    pub fn call(&self, ctx: &mut Ctx, input: Value) -> ApiResult<Value> {
        match self.access {
            Access::Read if !ctx.actor.scopes.read => return Err(ApiError::forbidden("this credential lacks the read scope")),
            Access::Write if !ctx.actor.scopes.write => {
                return Err(ApiError::forbidden(format!("`{}` needs the write scope; this credential is read-only", self.name)));
            }
            Access::Admin => ctx.actor.require_admin()?,
            _ => {}
        }
        if self.metered
            && !self.read_only()
            && let Some(hosting) = ctx.cfg.hosting.as_ref()
        {
            crate::plan::check_write(ctx.db, hosting, ctx.now)?;
        }
        (self.handler)(ctx, input)
    }

    /// Whether the actor's scopes allow this operation at all (used to trim tool lists).
    pub fn allowed_for(&self, actor: &Actor) -> bool {
        match self.access {
            Access::Read => actor.scopes.read,
            Access::Write => actor.scopes.write,
            Access::Admin => actor.can_admin(),
        }
    }

    pub fn path_params(&self) -> Vec<&'static str> {
        self.path.split('/').filter_map(|s| s.strip_prefix('{').and_then(|s| s.strip_suffix('}'))).collect()
    }
}

pub struct OpBuilder(Op);

impl OpBuilder {
    pub fn title(mut self, t: &'static str) -> Self {
        self.0.title = t;
        self
    }
    pub fn desc(mut self, d: &'static str) -> Self {
        self.0.description = d;
        self
    }
    pub fn destructive(mut self) -> Self {
        self.0.destructive = true;
        self
    }
    pub fn idempotent(mut self) -> Self {
        self.0.idempotent = true;
        self
    }
    pub fn unmetered(mut self) -> Self {
        self.0.metered = false;
        self
    }
    pub fn build(self) -> Op {
        self.0
    }
}

/// Generates a self-contained JSON Schema (no `$ref`s) for MCP clients and OpenAPI.
pub fn schema_of<T: JsonSchema>() -> Value {
    let generator = SchemaSettings::draft2020_12().with(|s| s.inline_subschemas = true).into_generator();
    let mut value = generator.into_root_schema_for::<T>().to_value();
    if let Some(obj) = value.as_object_mut() {
        obj.remove("$schema");
        obj.remove("title");
    }
    value
}

/// Declares an operation. The handler's input and output types define its schemas.
pub fn op<I, O>(
    group: &'static str,
    name: &'static str,
    method: &'static str,
    path: &'static str,
    access: Access,
    f: fn(&mut Ctx, I) -> ApiResult<O>,
) -> OpBuilder
where
    I: DeserializeOwned + JsonSchema + 'static,
    O: Serialize + JsonSchema + 'static,
{
    let handler: Handler = Box::new(move |ctx, input| {
        let input = if input.is_null() { Value::Object(Default::default()) } else { input };
        let typed: I = serde_json::from_value(input).map_err(|e| ApiError::bad_request(format!("invalid input for `{name}`: {e}")))?;
        let out = f(ctx, typed)?;
        serde_json::to_value(out).map_err(|e| ApiError::internal(e.to_string()))
    });
    OpBuilder(Op {
        name,
        group,
        title: name,
        description: "",
        method,
        path,
        access,
        destructive: false,
        idempotent: method == "GET" || method == "PUT" || method == "DELETE",
        metered: true,
        input_schema: schema_of::<I>(),
        output_schema: schema_of::<O>(),
        handler,
    })
}

pub struct Registry {
    pub ops: Vec<Op>,
    by_name: HashMap<&'static str, usize>,
}

pub enum RouteMatch<'a> {
    Found(&'a Op, Vec<(String, String)>),
    MethodNotAllowed,
    NotFound,
}

impl Registry {
    pub fn new(ops: Vec<Op>) -> Registry {
        let mut by_name = HashMap::new();
        for (i, op) in ops.iter().enumerate() {
            assert!(by_name.insert(op.name, i).is_none(), "duplicate operation {}", op.name);
        }
        Registry { ops, by_name }
    }

    pub fn get(&self, name: &str) -> Option<&Op> {
        self.by_name.get(name).map(|&i| &self.ops[i])
    }

    /// Matches `/posts/abc` against templates like `/posts/{id}`; literal segments win ties.
    pub fn route(&self, method: &str, path: &str) -> RouteMatch<'_> {
        let segs: Vec<&str> = path.trim_end_matches('/').split('/').collect();
        type Candidate<'a> = (usize, &'a Op, Vec<(String, String)>);
        let mut best: Option<Candidate> = None;
        let mut path_matched = false;
        for op in &self.ops {
            let tpl: Vec<&str> = op.path.split('/').collect();
            if tpl.len() != segs.len() {
                continue;
            }
            let mut params = vec![];
            let mut literals = 0;
            let ok = tpl.iter().zip(&segs).all(|(t, s)| {
                if let Some(name) = t.strip_prefix('{').and_then(|t| t.strip_suffix('}')) {
                    if s.is_empty() {
                        return false;
                    }
                    params.push((name.to_string(), urlencoding::decode(s).map(|c| c.into_owned()).unwrap_or_else(|_| s.to_string())));
                    true
                } else {
                    literals += 1;
                    t == s
                }
            });
            if !ok {
                continue;
            }
            path_matched = true;
            if op.method != method {
                continue;
            }
            if best.as_ref().is_none_or(|(l, _, _)| literals > *l) {
                best = Some((literals, op, params));
            }
        }
        match best {
            Some((_, op, params)) => RouteMatch::Found(op, params),
            None if path_matched => RouteMatch::MethodNotAllowed,
            None => RouteMatch::NotFound,
        }
    }
}

pub fn registry() -> &'static Registry {
    static REGISTRY: OnceLock<Registry> = OnceLock::new();
    REGISTRY.get_or_init(|| Registry::new(crate::ops::all()))
}
