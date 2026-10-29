use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{NoInput, check_content};
use crate::error::{ApiError, ApiResult};
use crate::markdown::{self, Heading};
use crate::registry::{Access, Ctx, Op, op, registry};

pub fn ops() -> Vec<Op> {
    vec![
        op("meta", "render_markdown", "POST", "/render", Access::Read, render_markdown)
            .title("Preview Markdown")
            .desc("Render Markdown exactly as a post would show it, plus its outline, mentions and linked posts. Changes nothing.")
            .build(),
        op("meta", "list_operations", "GET", "/operations", Access::Read, list_operations)
            .title("List every operation")
            .desc("Every operation this server supports with its method, path and access level. Use describe_operation for an operation's input schema.")
            .build(),
        op("meta", "describe_operation", "GET", "/operations/{name}", Access::Read, describe_operation)
            .title("Describe an operation")
            .desc("Input and output JSON Schemas for one operation.")
            .build(),
    ]
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RenderInput {
    pub markdown: String,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct Rendered {
    pub html: String,
    pub outline: Vec<Heading>,
    pub mentions: Vec<String>,
    pub linked_post_ids: Vec<String>,
    pub word_count: i64,
}

fn render_markdown(_ctx: &mut Ctx, input: RenderInput) -> ApiResult<Rendered> {
    check_content(&input.markdown)?;
    Ok(Rendered {
        html: markdown::render(&input.markdown),
        outline: markdown::outline(&input.markdown),
        mentions: markdown::mentions(&input.markdown),
        linked_post_ids: markdown::post_links(&input.markdown),
        word_count: markdown::word_count(&input.markdown),
    })
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct OperationInfo {
    pub name: String,
    pub group: String,
    pub title: String,
    pub description: String,
    pub method: String,
    /// REST path under `/api/v1`.
    pub path: String,
    /// `read`, `write` or `admin`.
    pub access: String,
    pub destructive: bool,
    /// Whether your credential can call it.
    pub allowed: bool,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct OperationList {
    pub items: Vec<OperationInfo>,
}

pub fn info(op: &Op, ctx: &Ctx) -> OperationInfo {
    OperationInfo {
        name: op.name.into(),
        group: op.group.into(),
        title: op.title.into(),
        description: op.description.into(),
        method: op.method.into(),
        path: format!("/api/v1{}", op.path),
        access: serde_json::to_value(op.access).ok().and_then(|v| v.as_str().map(String::from)).unwrap_or_default(),
        destructive: op.destructive,
        allowed: op.allowed_for(&ctx.actor),
    }
}

fn list_operations(ctx: &mut Ctx, _: NoInput) -> ApiResult<OperationList> {
    Ok(OperationList { items: registry().ops.iter().map(|o| info(o, ctx)).collect() })
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DescribeInput {
    pub name: String,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct OperationDetail {
    #[serde(flatten)]
    pub info: OperationInfo,
    pub input_schema: Value,
    pub output_schema: Value,
}

fn describe_operation(ctx: &mut Ctx, input: DescribeInput) -> ApiResult<OperationDetail> {
    let op = registry().get(&input.name).ok_or_else(|| ApiError::not_found(format!("operation `{}`", input.name)))?;
    Ok(OperationDetail { info: info(op, ctx), input_schema: op.input_schema.clone(), output_schema: op.output_schema.clone() })
}
