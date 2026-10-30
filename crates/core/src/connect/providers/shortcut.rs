//! Shortcut: previews of linked stories, from the connected workspace only. People connect with
//! an API token; Shortcut has no sign-in for apps like this.
//!
//! Docs: https://developer.shortcut.com/api/rest/v3 (Authentication; Get Current Member Info,
//! Get Story, List Workflows, List Members).

use serde_json::{Value, json};

use crate::connect::{
    Account, Connector, Credential, Detail, Field, Hit, HttpCall, HttpReply, Preview, ProviderInfo, excerpt, host_of, http_error, opt,
    path_of, s,
};

pub struct Shortcut;

const API: &str = "https://api.app.shortcut.com/api/v3";

static INFO: ProviderInfo = ProviderInfo {
    id: "shortcut",
    name: "Shortcut",
    about: "Preview linked stories from your Shortcut workspace.",
    search: false,
    preview: true,
    oauth: None,
    token_fields: &[Field {
        key: "token",
        label: "API token",
        help: "In Shortcut: Settings › Your account › API Tokens › Generate token.",
        secret: true,
        optional: false,
    }],
    token_help: "https://app.shortcut.com/settings/account/api-tokens",
};

fn api(path: &str, token: &str) -> HttpCall {
    HttpCall::get(format!("{API}{path}")).header("shortcut-token", token)
}

/// Links name their workspace, and an account matches only its own. Without an account (nobody
/// connected), any workspace's link still says it's Shortcut's.
fn in_workspace(account: &Account, workspace: &str) -> bool {
    match account.settings["workspace"].as_str() {
        Some(slug) => slug.eq_ignore_ascii_case(workspace),
        None => account.settings.is_null(),
    }
}

impl Connector for Shortcut {
    fn info(&self) -> &'static ProviderInfo {
        &INFO
    }

    fn profile(&self, cred: &Credential) -> Vec<HttpCall> {
        vec![api("/member", &cred.token)]
    }

    fn read_profile(&self, _cred: &Credential, replies: &[HttpReply]) -> Result<Account, String> {
        let r = replies.first().cloned().unwrap_or_default();
        if !r.ok() {
            return Err(match r.status {
                401 => "Shortcut rejected that token. Check it was copied whole and hasn't been deleted.".into(),
                _ => http_error("Shortcut", &r),
            });
        }
        let m = r.json();
        let workspace = s(&m["workspace2"]["url_slug"]);
        if workspace.is_empty() {
            return Err("Shortcut didn't say which workspace that token is for.".into());
        }
        let who = opt(&m["mention_name"]).map(|n| format!("@{n}")).or_else(|| opt(&m["name"])).unwrap_or_default();
        let label = match opt(&m["workspace2"]["name"]) {
            Some(name) => format!("{who} ({name})"),
            None => who,
        };
        Ok(Account { label, settings: json!({ "workspace": workspace }) })
    }

    // Previews only: Shortcut isn't searched.
    fn search(&self, _cred: &Credential, _account: &Account, _q: &str, _limit: usize) -> Vec<HttpCall> {
        vec![]
    }

    fn read_search(&self, _account: &Account, _replies: &[HttpReply], _limit: usize) -> Result<Vec<Hit>, String> {
        Ok(vec![])
    }

    /// `https://app.shortcut.com/acme/story/123/fix-login` → `123`, for the connected workspace.
    /// Old Clubhouse links still work.
    fn preview_target(&self, account: &Account, url: &str) -> Option<String> {
        if !matches!(host_of(url)?.as_str(), "app.shortcut.com" | "app.clubhouse.io") {
            return None;
        }
        match path_of(url).as_slice() {
            [workspace, kind, id, ..] if kind == "story" && in_workspace(account, workspace) => {
                id.parse::<u64>().ok().map(|n| n.to_string())
            }
            _ => None,
        }
    }

    /// A story names its workflow state and people by id; the workflows and members lists, read
    /// alongside it, name them.
    fn preview(&self, cred: &Credential, _account: &Account, target: &str) -> Vec<HttpCall> {
        vec![api(&format!("/stories/{target}"), &cred.token), api("/workflows", &cred.token), api("/members", &cred.token)]
    }

    fn read_preview(&self, account: &Account, target: &str, replies: &[HttpReply]) -> Result<Preview, String> {
        let r = replies.first().cloned().unwrap_or_default();
        if !r.ok() {
            return Err(match r.status {
                404 => "Shortcut has no such story, or the connected account can't see it.".into(),
                _ => http_error("Shortcut", &r),
            });
        }
        let st = r.json();
        // The lists are a bonus: without them the preview still shows, with fewer names.
        let list = |i: usize| replies.get(i).filter(|r| r.ok()).map(|r| r.json()).unwrap_or(Value::Null);
        let (workflows, members) = (list(1), list(2));
        let state = workflows
            .as_array()
            .into_iter()
            .flatten()
            .flat_map(|w| w["states"].as_array().into_iter().flatten())
            .find(|x| !st["workflow_state_id"].is_null() && x["id"] == st["workflow_state_id"])
            .and_then(|x| opt(&x["name"]));
        let progress = if st["completed"] == true {
            "completed"
        } else if st["started"] == true {
            "started"
        } else {
            "unstarted"
        };
        let status = state.unwrap_or_else(|| progress.to_string());
        let name_of = |id: &Value| -> Option<String> {
            let m = members.as_array()?.iter().find(|m| !id.is_null() && m["id"] == *id)?;
            opt(&m["profile"]["name"]).or_else(|| opt(&m["profile"]["mention_name"]).map(|n| format!("@{n}")))
        };
        let owners: Vec<String> = st["owner_ids"].as_array().into_iter().flatten().filter_map(name_of).collect();
        let mut details = vec![];
        if let Some(kind) = opt(&st["story_type"]) {
            let mut chars = kind.chars();
            let first = chars.next().map(|c| c.to_uppercase().collect::<String>()).unwrap_or_default();
            details.push(Detail { label: "Type".into(), value: first + chars.as_str() });
        }
        if let Some(points) = st["estimate"].as_i64() {
            details.push(Detail { label: "Estimate".into(), value: format!("{points} {}", if points == 1 { "point" } else { "points" }) });
        }
        let labels: Vec<&str> = st["labels"].as_array().into_iter().flatten().filter_map(|l| l["name"].as_str()).collect();
        if !labels.is_empty() {
            details.push(Detail { label: "Labels".into(), value: labels.join(", ") });
        }
        if let Some(deadline) = opt(&st["deadline"]) {
            details.push(Detail { label: "Due".into(), value: deadline.chars().take(10).collect() });
        }
        let workspace = account.settings["workspace"].as_str().unwrap_or_default();
        Ok(Preview {
            provider: "shortcut".into(),
            kind: "story".into(),
            title: s(&st["name"]),
            url: opt(&st["app_url"]).unwrap_or_else(|| format!("https://app.shortcut.com/{workspace}/story/{target}")),
            reference: format!("sc-{target}"),
            status: Some(status),
            assignee: Some(owners.join(", ")).filter(|o| !o.is_empty()),
            author: name_of(&st["requested_by_id"]),
            created_at: opt(&st["created_at"]),
            updated_at: opt(&st["updated_at"]),
            description: excerpt(st["description"].as_str().unwrap_or_default(), 300),
            details,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reply(status: u16, body: Value) -> HttpReply {
        HttpReply { status, body: body.to_string() }
    }

    fn acme() -> Account {
        Account { label: "@ada (Acme)".into(), settings: json!({ "workspace": "acme" }) }
    }

    #[test]
    fn profile_keeps_the_workspace() {
        let calls = Shortcut.profile(&Credential { token: "t".into(), ..Default::default() });
        assert_eq!(calls[0].url, "https://api.app.shortcut.com/api/v3/member");
        assert!(calls[0].headers.contains(&("shortcut-token".into(), "t".into())));
        assert!(!calls[0].headers.iter().any(|(k, _)| k == "authorization"));
        let me = json!({ "id": "u1", "mention_name": "ada", "name": "Ada", "workspace2": { "url_slug": "acme", "name": "Acme" } });
        let account = Shortcut.read_profile(&Credential::default(), &[reply(200, me)]).unwrap();
        assert_eq!((account.label.as_str(), &account.settings["workspace"]), ("@ada (Acme)", &json!("acme")));
        assert!(
            Shortcut.read_profile(&Credential::default(), &[reply(200, json!({ "name": "Ada" }))]).unwrap_err().contains("which workspace")
        );
        assert!(Shortcut.read_profile(&Credential::default(), &[reply(401, json!({}))]).unwrap_err().contains("rejected"));
        assert!(Shortcut.read_profile(&Credential::default(), &[reply(0, json!(null))]).unwrap_err().contains("in time"));
    }

    #[test]
    fn recognizes_stories_in_the_connected_workspace_only() {
        let a = acme();
        assert_eq!(Shortcut.preview_target(&a, "https://app.shortcut.com/acme/story/123/fix-login").as_deref(), Some("123"));
        assert_eq!(Shortcut.preview_target(&a, "https://app.shortcut.com/ACME/story/7?ct_workflow=all#activity").as_deref(), Some("7"));
        assert_eq!(Shortcut.preview_target(&a, "https://app.clubhouse.io/acme/story/9/old").as_deref(), Some("9"));
        // Nobody connected: the link still says it's Shortcut's.
        assert_eq!(Shortcut.preview_target(&Account::default(), "https://app.shortcut.com/beta/story/1").as_deref(), Some("1"));
        for no in [
            "https://app.shortcut.com/beta/story/123/fix-login",
            "https://app.shortcut.com.evil.test/acme/story/123",
            "https://evil-app.shortcut.com/acme/story/123",
            "https://shortcut.com/acme/story/123",
            "https://app.shortcut.com/acme/epic/123",
            "https://app.shortcut.com/acme/story/12a",
            "https://app.shortcut.com/acme/story/-1",
            "https://app.shortcut.com/acme/story",
        ] {
            assert_eq!(Shortcut.preview_target(&a, no), None, "{no}");
        }
        assert_eq!(
            Shortcut.preview_target(&Account { label: String::new(), settings: json!({}) }, "https://app.shortcut.com/acme/story/1"),
            None
        );
    }

    #[test]
    fn previews_stories_with_state_and_people_named() {
        let calls = Shortcut.preview(&Credential { token: "t".into(), ..Default::default() }, &acme(), "123");
        let urls: Vec<&str> = calls.iter().map(|c| c.url.as_str()).collect();
        assert_eq!(
            urls,
            [
                "https://api.app.shortcut.com/api/v3/stories/123",
                "https://api.app.shortcut.com/api/v3/workflows",
                "https://api.app.shortcut.com/api/v3/members"
            ]
        );
        assert!(calls.iter().all(|c| c.headers.contains(&("shortcut-token".into(), "t".into()))));
        let story = json!({ "id": 123, "name": "Fix login", "app_url": "https://app.shortcut.com/acme/story/123/fix-login",
            "description": "Users\n\nloop.", "story_type": "bug", "estimate": 3, "workflow_state_id": 500000012, "completed": false, "started": true,
            "owner_ids": ["u2", "u3"], "requested_by_id": "u1", "labels": [{ "name": "auth" }], "deadline": "2026-11-01T12:00:00Z",
            "created_at": "2026-10-01T00:00:00Z", "updated_at": "2026-10-02T00:00:00Z" });
        let workflows =
            json!([{ "id": 500000001, "states": [{ "id": 500000011, "name": "To Do" }, { "id": 500000012, "name": "In Development" }] }]);
        let members = json!([{ "id": "u1", "profile": { "name": "Ada", "mention_name": "ada" } },
            { "id": "u2", "profile": { "name": "Bo", "mention_name": "bo" } }, { "id": "u3", "profile": { "mention_name": "cy" } }]);
        let p = Shortcut.read_preview(&acme(), "123", &[reply(200, story.clone()), reply(200, workflows), reply(200, members)]).unwrap();
        assert_eq!((p.kind.as_str(), p.reference.as_str(), p.status.as_deref()), ("story", "sc-123", Some("In Development")));
        assert_eq!((p.assignee.as_deref(), p.author.as_deref()), (Some("Bo, @cy"), Some("Ada")));
        assert_eq!(p.description, "Users loop.");
        let details: Vec<(&str, &str)> = p.details.iter().map(|d| (d.label.as_str(), d.value.as_str())).collect();
        assert_eq!(details, [("Type", "Bug"), ("Estimate", "3 points"), ("Labels", "auth"), ("Due", "2026-11-01")]);
        // Without the lists, the story still shows.
        let p = Shortcut.read_preview(&acme(), "123", &[reply(200, story), reply(500, json!({})), reply(429, json!({}))]).unwrap();
        assert_eq!((p.status.as_deref(), p.assignee.as_deref(), p.author.as_deref()), (Some("started"), None, None));

        assert!(Shortcut.read_preview(&acme(), "9", &[reply(404, json!({}))]).unwrap_err().contains("can't see"));
        assert!(Shortcut.read_preview(&acme(), "9", &[reply(401, json!({}))]).unwrap_err().contains("Reconnect"));
        assert!(Shortcut.read_preview(&acme(), "9", &[reply(0, json!(null))]).unwrap_err().contains("in time"));
    }
}
