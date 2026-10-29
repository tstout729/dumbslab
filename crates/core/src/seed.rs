//! Starter content created during first-run setup so a new workspace isn't empty.

use crate::error::ApiResult;
use crate::ops::posts::{CreatePostInput, create_post};
use crate::ops::topics::{CreateTopicInput, create_topic};
use crate::registry::Ctx;

pub fn seed_workspace(ctx: &mut Ctx, workspace: &str) -> ApiResult<()> {
    let topic = create_topic(
        ctx,
        CreateTopicInput {
            name: "Getting Started".into(),
            description: Some("How this knowledge base works.".into()),
            icon: Some("📘".into()),
            color: Some("#4f46e5".into()),
            parent_id: None,
            visibility: None,
            members: None,
        },
    )?;
    let topic_id = topic.topic.id.clone();
    let base = ctx.base_url.clone();

    let agents = create_post(
        ctx,
        CreatePostInput {
            title: "Connect your AI agents".into(),
            content: Some(format!(
                "Agents can do anything you can do here: search, read, write and edit posts, comment, organize topics and more.\n\n\
                 ## MCP (recommended)\n\n\
                 The MCP server lives at `{base}/mcp`. Clients that support OAuth (Claude, ChatGPT, Cursor) just need the URL; you approve access in the browser.\n\n\
                 **Claude Code**\n\n\
                 ```sh\nclaude mcp add --transport http dumbslab {base}/mcp\n```\n\n\
                 **With a token instead of OAuth**\n\n\
                 ```sh\nclaude mcp add --transport http dumbslab {base}/mcp --header \"Authorization: Bearer ds_pat_...\"\n```\n\n\
                 Add `?toolset=core` to the URL for a smaller tool list, or `?toolset=read` for read-only tools.\n\n\
                 ## REST API\n\n\
                 Create a token under **Settings → API tokens**, then:\n\n\
                 ```sh\ncurl -H \"Authorization: Bearer $TOKEN\" {base}/api/v1/search?q=onboarding\n```\n\n\
                 - OpenAPI: [{base}/api/v1/openapi.json]({base}/api/v1/openapi.json)\n\
                 - Agent guide: [{base}/llms.txt]({base}/llms.txt)\n\
                 - Call any operation: `POST {base}/api/v1/operations/<name>`\n\n\
                 ## Give each agent its own identity\n\n\
                 Admins can add a bot account under **Settings → People** and mint it a token, so its edits show up under its own name in history and activity.\n"
            )),
            topic_ids: Some(vec![topic_id.clone()]),
            status: Some("published".into()),
            is_template: None,
            template_id: None,
        },
    )?;

    let agents_url = format!("/p/{}/{}", agents.summary.id, agents.summary.slug);
    create_post(
        ctx,
        CreatePostInput {
            title: format!("Welcome to {workspace}"),
            content: Some(format!(
                "This is your team's knowledge base. Write things down once, find them later, and keep them current.\n\n\
                 ## The basics\n\n\
                 - **Posts** are documents written in Markdown. Start one with **New post**.\n\
                 - **Topics** organize posts. A post can live in several topics, and topics can nest.\n\
                 - **Drafts** are private to you until you publish them.\n\
                 - **Search** everything with <kbd>⌘K</kbd> or <kbd>Ctrl K</kbd>.\n\
                 - **Comments** keep discussion next to the doc. Select text to comment on a passage.\n\
                 - **Verification** marks a post as accurate for a while; expired posts show up in Insights so someone re-checks them.\n\
                 - **History** keeps every version. You can compare and restore any of them.\n\n\
                 ## Make it yours\n\n\
                 1. Create a few topics for your teams or areas.\n\
                 2. Invite people under **Settings → People**.\n\
                 3. Connect your AI agents (see [Connect your AI agents]({agents_url})).\n"
            )),
            topic_ids: Some(vec![topic_id.clone()]),
            status: Some("published".into()),
            is_template: None,
            template_id: None,
        },
    )?;

    Ok(())
}
