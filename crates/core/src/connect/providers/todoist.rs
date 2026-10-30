//! Todoist: previews of linked tasks the connected account can see. People connect with their API
//! token or by signing in. Todoist's API v1 replaced REST v2 and the Sync API in 2025 and reads
//! tasks only by their new ids, so old links with numeric ids can't be previewed.
//!
//! Docs: https://developer.todoist.com/api/v1/ (Authorization; Tasks › Get Task; Projects › Get
//! Projects; User › User Info; Migrating from v9 › IDs),
//! https://www.todoist.com/help/todoist/integrations/find-your-api-token-Jpzx9IIlB

use serde_json::{Value, json};

use crate::connect::{
    Account, Connector, Credential, Detail, Field, Hit, HttpCall, HttpReply, OAuthSpec, Preview, ProviderInfo, host_of, http_error, opt,
    path_of, s,
};

pub struct Todoist;

const API: &str = "https://api.todoist.com/api/v1";

static INFO: ProviderInfo = ProviderInfo {
    id: "todoist",
    name: "Todoist",
    about: "Preview linked tasks.",
    search: false,
    preview: true,
    oauth: Some(OAuthSpec {
        authorize_url: "https://app.todoist.com/oauth/authorize",
        token_url: "https://api.todoist.com/oauth/access_token",
        scopes: &["data:read"],
        scope_param: "scope",
        scope_separator: ",",
        extra: &[],
        pkce: false,
    }),
    token_fields: &[Field {
        key: "token",
        label: "API token",
        help: "In Todoist: Settings › Integrations › Developer › Copy API token.",
        secret: true,
        optional: false,
    }],
    token_help: "https://app.todoist.com/app/settings/integrations/developer",
};

fn api(path: &str, token: &str) -> HttpCall {
    HttpCall::get(format!("{API}{path}")).bearer(token)
}

/// Task ids from before API v1 were numbers; v1 refuses them.
fn is_old(id: &str) -> bool {
    id.bytes().all(|b| b.is_ascii_digit())
}

fn query_param(url: &str, key: &str) -> Option<String> {
    let query = url.split_once('?')?.1.split('#').next()?;
    query.split('&').filter_map(|p| p.split_once('=')).find(|(k, _)| *k == key).map(|(_, v)| v.to_string())
}

impl Connector for Todoist {
    fn info(&self) -> &'static ProviderInfo {
        &INFO
    }

    fn profile(&self, cred: &Credential) -> Vec<HttpCall> {
        vec![api("/user", &cred.token)]
    }

    fn read_profile(&self, _cred: &Credential, replies: &[HttpReply]) -> Result<Account, String> {
        let r = replies.first().cloned().unwrap_or_default();
        if !r.ok() {
            return Err(match r.status {
                401 => "Todoist rejected that token. Check it was copied whole and hasn't been replaced by a new one.".into(),
                _ => http_error("Todoist", &r),
            });
        }
        // The answer also holds the account's own API token; only the name is kept.
        let u = r.json();
        let who = opt(&u["email"]).or_else(|| opt(&u["full_name"]));
        match who {
            Some(label) => Ok(Account { label, settings: json!({}) }),
            None => Err("Todoist didn't say whose token that is.".into()),
        }
    }

    // Previews only: Todoist isn't searched.
    fn search(&self, _cred: &Credential, _account: &Account, _q: &str, _limit: usize) -> Vec<HttpCall> {
        vec![]
    }

    fn read_search(&self, _account: &Account, _replies: &[HttpReply], _limit: usize) -> Result<Vec<Hit>, String> {
        Ok(vec![])
    }

    /// `https://app.todoist.com/app/task/buy-milk-6Xqhv4cwxgjwG9w6` (also inside a project or
    /// view, like `…/app/project/home-6Jf8/task/6Xqh…`) or `https://todoist.com/showTask?id=6Xqh…`
    /// → `6Xqhv4cwxgjwG9w6`.
    fn preview_target(&self, _account: &Account, url: &str) -> Option<String> {
        if !matches!(host_of(url)?.as_str(), "todoist.com" | "app.todoist.com") {
            return None;
        }
        let path = path_of(url);
        let id = match path.as_slice() {
            [show] if show.eq_ignore_ascii_case("showtask") => query_param(url, "id")?,
            [app, .., task, last] if app == "app" && task == "task" => last.rsplit('-').next()?.to_string(),
            _ => return None,
        };
        let ok = (1..=40).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_alphanumeric());
        ok.then_some(id)
    }

    /// The task, and the projects list to name its project.
    fn preview(&self, cred: &Credential, _account: &Account, target: &str) -> Vec<HttpCall> {
        if is_old(target) {
            // read_preview explains; there's nothing to ask.
            return vec![];
        }
        vec![api(&format!("/tasks/{target}"), &cred.token), api("/projects?limit=200", &cred.token)]
    }

    fn read_preview(&self, _account: &Account, target: &str, replies: &[HttpReply]) -> Result<Preview, String> {
        if is_old(target) {
            return Err(
                "That's an old Todoist link, which Todoist can no longer look up. Open it in Todoist and copy the task's link again."
                    .into(),
            );
        }
        let r = replies.first().cloned().unwrap_or_default();
        if !r.ok() {
            return Err(match r.status {
                404 => "Todoist has no such open task, or the connected account can't see it. Completed tasks can't be previewed.".into(),
                400 => "Todoist doesn't recognize that task link.".into(),
                _ => http_error("Todoist", &r),
            });
        }
        let t = r.json();
        // The project's name is a bonus: without it the preview still shows.
        let project = replies.get(1).filter(|r| r.ok() && !t["project_id"].is_null()).and_then(|r| {
            let projects = r.json();
            projects["results"].as_array()?.iter().find(|p| p["id"] == t["project_id"]).and_then(|p| opt(&p["name"]))
        });
        let mut details = vec![];
        if let Some(name) = project {
            details.push(Detail { label: "Project".into(), value: name });
        }
        if let Some(date) = opt(&t["due"]["date"]) {
            let repeats = opt(&t["due"]["string"]).filter(|_| t["due"]["is_recurring"] == true);
            let value = match repeats {
                Some(every) => format!("{date} ({every})"),
                None => date,
            };
            details.push(Detail { label: "Due".into(), value });
        }
        if let Some(deadline) = opt(&t["deadline"]["date"]) {
            details.push(Detail { label: "Deadline".into(), value: deadline });
        }
        // The API counts priority up (4 is most urgent); the app shows it as P1 to P4.
        if let Some(p) = t["priority"].as_i64().filter(|p| (2..=4).contains(p)) {
            details.push(Detail { label: "Priority".into(), value: format!("P{}", 5 - p) });
        }
        let labels: Vec<&str> = t["labels"].as_array().into_iter().flatten().filter_map(Value::as_str).collect();
        if !labels.is_empty() {
            details.push(Detail { label: "Labels".into(), value: labels.join(", ") });
        }
        let id = opt(&t["id"]).unwrap_or_else(|| target.to_string());
        Ok(Preview {
            provider: "todoist".into(),
            kind: "task".into(),
            title: s(&t["content"]),
            url: format!("https://app.todoist.com/app/task/{id}"),
            reference: "Todoist task".into(),
            status: Some(if t["checked"] == true { "completed" } else { "open" }.into()),
            assignee: None,
            author: None,
            created_at: opt(&t["added_at"]),
            updated_at: opt(&t["updated_at"]),
            description: crate::connect::markdown_excerpt(t["description"].as_str().unwrap_or_default(), 300),
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

    #[test]
    fn profile_reads_the_account() {
        let calls = Todoist.profile(&Credential { token: "t".into(), ..Default::default() });
        assert_eq!(calls[0].url, "https://api.todoist.com/api/v1/user");
        assert!(calls[0].headers.contains(&("authorization".into(), "Bearer t".into())));
        let me = json!({ "id": "1", "email": "ada@acme.com", "full_name": "Ada", "token": "t" });
        let account = Todoist.read_profile(&Credential::default(), &[reply(200, me)]).unwrap();
        assert_eq!(account, Account { label: "ada@acme.com".into(), settings: json!({}) });
        assert!(Todoist.read_profile(&Credential::default(), &[reply(200, json!({}))]).unwrap_err().contains("whose token"));
        assert!(Todoist.read_profile(&Credential::default(), &[reply(401, json!({}))]).unwrap_err().contains("rejected"));
        assert!(Todoist.read_profile(&Credential::default(), &[reply(0, json!(null))]).unwrap_err().contains("in time"));
        // Signing in answers standard OAuth JSON, with a refresh token for new apps.
        let tokens = Todoist
            .read_token(&reply(200, json!({ "access_token": "a", "token_type": "Bearer", "expires_in": 3600, "refresh_token": "r" })))
            .unwrap();
        assert_eq!((tokens.access_token.as_str(), tokens.refresh_token.as_deref()), ("a", Some("r")));
    }

    #[test]
    fn recognizes_task_links() {
        let a = Account::default();
        for (url, id) in [
            ("https://app.todoist.com/app/task/buy-milk-6Xqhv4cwxgjwG9w6", "6Xqhv4cwxgjwG9w6"),
            ("https://app.todoist.com/app/task/6Xqhv4cwxgjwG9w6?x=1#y", "6Xqhv4cwxgjwG9w6"),
            ("https://app.todoist.com/app/project/home-6Jf8VQXxpwv56VQ7/task/milk-6Xqhv4cwxgjwG9w6", "6Xqhv4cwxgjwG9w6"),
            ("https://todoist.com/app/task/6Xqhv4cwxgjwG9w6", "6Xqhv4cwxgjwG9w6"),
            ("https://todoist.com/showTask?id=6Xqhv4cwxgjwG9w6&sync_id=2", "6Xqhv4cwxgjwG9w6"),
            ("https://www.todoist.com/showTask?id=2995104339", "2995104339"),
        ] {
            assert_eq!(Todoist.preview_target(&a, url).as_deref(), Some(id), "{url}");
        }
        for no in [
            "https://todoist.com.evil.test/app/task/6Xqhv4cwxgjwG9w6",
            "https://eviltodoist.com/app/task/6Xqhv4cwxgjwG9w6",
            "https://app.todoist.com/app/project/home-6Jf8VQXxpwv56VQ7",
            "https://app.todoist.com/app/task/",
            "https://app.todoist.com/app/task/milk-6Xq%2F..",
            "https://app.todoist.com/app/task/milk-6Xq_hv",
            "https://app.todoist.com/task/6Xqhv4cwxgjwG9w6",
            "https://todoist.com/showTask?id=",
            "https://todoist.com/showTask?task=6Xqhv4cwxgjwG9w6",
            "https://todoist.com/showTask?id=6Xq/../user",
        ] {
            assert_eq!(Todoist.preview_target(&a, no), None, "{no}");
        }
    }

    #[test]
    fn previews_tasks() {
        let cred = Credential { token: "t".into(), ..Default::default() };
        let calls = Todoist.preview(&cred, &Account::default(), "6Xqhv4cwxgjwG9w6");
        let urls: Vec<&str> = calls.iter().map(|c| c.url.as_str()).collect();
        assert_eq!(urls, ["https://api.todoist.com/api/v1/tasks/6Xqhv4cwxgjwG9w6", "https://api.todoist.com/api/v1/projects?limit=200"]);
        let task = json!({ "id": "6Xqhv4cwxgjwG9w6", "content": "Buy milk", "description": "Oat,\n\nnot almond.", "checked": false,
            "project_id": "6Jf8VQXxpwv56VQ7", "priority": 4, "labels": ["errands"], "added_at": "2026-10-01T00:00:00Z",
            "updated_at": "2026-10-02T00:00:00Z", "due": { "date": "2026-11-02", "string": "every monday", "is_recurring": true },
            "deadline": { "date": "2026-11-30" } });
        let projects =
            json!({ "results": [{ "id": "1", "name": "Inbox" }, { "id": "6Jf8VQXxpwv56VQ7", "name": "Home" }], "next_cursor": null });
        let p = Todoist.read_preview(&Account::default(), "6Xqhv4cwxgjwG9w6", &[reply(200, task.clone()), reply(200, projects)]).unwrap();
        assert_eq!((p.kind.as_str(), p.title.as_str(), p.status.as_deref()), ("task", "Buy milk", Some("open")));
        assert_eq!(p.url, "https://app.todoist.com/app/task/6Xqhv4cwxgjwG9w6");
        assert_eq!(p.description, "Oat, not almond.");
        let details: Vec<(&str, &str)> = p.details.iter().map(|d| (d.label.as_str(), d.value.as_str())).collect();
        assert_eq!(
            details,
            [
                ("Project", "Home"),
                ("Due", "2026-11-02 (every monday)"),
                ("Deadline", "2026-11-30"),
                ("Priority", "P1"),
                ("Labels", "errands")
            ]
        );
        // Without the projects list the task still shows.
        let mut done = task;
        done["checked"] = json!(true);
        done["priority"] = json!(1);
        let p = Todoist.read_preview(&Account::default(), "6Xqhv4cwxgjwG9w6", &[reply(200, done), reply(500, json!({}))]).unwrap();
        assert_eq!(p.status.as_deref(), Some("completed"));
        assert!(p.details.iter().all(|d| d.label != "Project" && d.label != "Priority"));

        // Old numeric ids: nothing is asked, and the person learns why.
        assert!(Todoist.preview(&cred, &Account::default(), "2995104339").is_empty());
        assert!(Todoist.read_preview(&Account::default(), "2995104339", &[]).unwrap_err().contains("old Todoist link"));

        let a = Account::default();
        assert!(Todoist.read_preview(&a, "6Xq", &[reply(404, json!({}))]).unwrap_err().contains("can't see"));
        assert!(Todoist.read_preview(&a, "6Xq", &[reply(401, json!({}))]).unwrap_err().contains("Reconnect"));
        assert!(Todoist.read_preview(&a, "6Xq", &[reply(0, json!(null))]).unwrap_err().contains("in time"));
    }
}
