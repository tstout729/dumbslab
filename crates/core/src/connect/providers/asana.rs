//! Asana: tasks and projects in the connected person's workspaces (the first three), and previews
//! of linked tasks. Asana's full-text search needs a paid plan (it answers 402), so search uses
//! each workspace's typeahead, which every plan has. The host's OAuth app must be registered with
//! the scopes below, not with "Full permissions".
//!
//! Docs: https://developers.asana.com/docs/oauth, https://developers.asana.com/docs/oauth-scopes,
//! https://developers.asana.com/reference/getuser, https://developers.asana.com/reference/typeaheadforworkspace,
//! https://developers.asana.com/reference/gettask, https://developers.asana.com/docs/errors, and link
//! formats: https://forum.asana.com/t/upcoming-new-v1-asana-url-format-in-the-browser/1011489

use serde_json::{Value, json};

use crate::connect::{
    Account, Connector, Credential, Detail, Field, Hit, HttpCall, HttpReply, OAuthSpec, Preview, ProviderInfo, excerpt, host_of,
    http_error, opt, path_of, s,
};

pub struct Asana;

const API: &str = "https://app.asana.com/api/1.0";
/// The most workspaces searched; each costs two requests.
const MAX_WORKSPACES: usize = 3;
const TASK_FIELDS: &str = "name,completed,notes,modified_at,permalink_url,projects.name";
const PROJECT_FIELDS: &str = "name,archived,notes,modified_at,permalink_url";
const PREVIEW_FIELDS: &str =
    "name,completed,assignee.name,created_at,modified_at,due_on,due_at,notes,permalink_url,projects.name,workspace.name,parent.name";

static INFO: ProviderInfo = ProviderInfo {
    id: "asana",
    name: "Asana",
    about: "Search tasks and projects, and preview linked tasks.",
    search: true,
    preview: true,
    oauth: Some(OAuthSpec {
        authorize_url: "https://app.asana.com/-/oauth_authorize",
        token_url: "https://app.asana.com/-/oauth_token",
        scopes: &["users:read", "workspaces:read", "workspaces.typeahead:read", "tasks:read", "projects:read"],
        scope_param: "scope",
        scope_separator: " ",
        extra: &[],
        pkce: true,
        site: None,
    }),
    token_fields: &[Field {
        key: "token",
        label: "Personal access token",
        help: "Make one in Asana's developer console: My apps › Create new token.",
        secret: true,
        optional: false,
    }],
    token_help: "https://app.asana.com/0/my-apps",
};

fn api(path: &str, token: &str) -> HttpCall {
    HttpCall::get(format!("{API}{path}")).bearer(token).header("accept", "application/json")
}

/// Asana ids are numbers; nothing else reaches a URL.
fn is_gid(id: &str) -> bool {
    !id.is_empty() && id.len() <= 32 && id.bytes().all(|b| b.is_ascii_digit())
}

fn error(r: &HttpReply) -> String {
    match r.status {
        402 => "Asana offers that only on paid plans.".into(),
        _ => http_error("Asana", r),
    }
}

/// The workspaces found when connecting: (gid, name).
fn workspaces(account: &Account) -> Vec<(String, String)> {
    account.settings["workspaces"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|w| Some((w["gid"].as_str().filter(|g| is_gid(g))?.to_string(), s(&w["name"]))))
        .take(MAX_WORKSPACES)
        .collect()
}

fn names(list: &Value) -> Vec<String> {
    list.as_array().into_iter().flatten().filter_map(|x| opt(&x["name"])).collect()
}

fn task_hit(t: &Value, workspace: &str) -> Hit {
    let mut context: Vec<String> = names(&t["projects"]).into_iter().take(1).collect();
    context.extend(Some(workspace.to_string()).filter(|w| !w.is_empty()));
    if t["completed"].as_bool() == Some(true) {
        context.push("completed".into());
    }
    Hit {
        provider: "asana".into(),
        kind: "task".into(),
        title: s(&t["name"]),
        url: opt(&t["permalink_url"]).unwrap_or_else(|| format!("https://app.asana.com/0/0/{}", s(&t["gid"]))),
        context: context.join(" · "),
        snippet: excerpt(t["notes"].as_str().unwrap_or_default(), 240),
        updated_at: opt(&t["modified_at"]),
        author: None,
    }
}

fn project_hit(p: &Value, workspace: &str) -> Hit {
    let mut context = vec!["Project".to_string()];
    context.extend(Some(workspace.to_string()).filter(|w| !w.is_empty()));
    if p["archived"].as_bool() == Some(true) {
        context.push("archived".into());
    }
    Hit {
        provider: "asana".into(),
        kind: "project".into(),
        title: s(&p["name"]),
        url: opt(&p["permalink_url"]).unwrap_or_else(|| format!("https://app.asana.com/0/{}/list", s(&p["gid"]))),
        context: context.join(" · "),
        snippet: excerpt(p["notes"].as_str().unwrap_or_default(), 240),
        updated_at: opt(&p["modified_at"]),
        author: None,
    }
}

impl Connector for Asana {
    fn info(&self) -> &'static ProviderInfo {
        &INFO
    }

    fn profile(&self, cred: &Credential) -> Vec<HttpCall> {
        vec![api("/users/me?opt_fields=name,email,workspaces.name", &cred.token)]
    }

    fn read_profile(&self, _cred: &Credential, replies: &[HttpReply]) -> Result<Account, String> {
        let r = replies.first().cloned().unwrap_or_default();
        if !r.ok() {
            return Err(match r.status {
                401 => "Asana rejected that token. Check it was copied whole and hasn't been revoked.".into(),
                _ => error(&r),
            });
        }
        let me = &r.json()["data"];
        let label = opt(&me["email"]).or_else(|| opt(&me["name"])).ok_or("Asana didn't say whose account that is.")?;
        let spaces: Vec<Value> = me["workspaces"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|w| w["gid"].as_str().is_some_and(is_gid))
            .take(MAX_WORKSPACES)
            .map(|w| json!({ "gid": s(&w["gid"]), "name": s(&w["name"]) }))
            .collect();
        if spaces.is_empty() {
            return Err("That Asana account isn't in any workspace.".into());
        }
        Ok(Account { label, settings: json!({ "workspaces": spaces }) })
    }

    /// For each workspace: its tasks, then its projects.
    fn search(&self, cred: &Credential, account: &Account, q: &str, limit: usize) -> Vec<HttpCall> {
        let query = urlencoding::encode(q).into_owned();
        let count = limit.clamp(1, 20);
        workspaces(account)
            .iter()
            .flat_map(|(gid, _)| {
                [
                    api(
                        &format!("/workspaces/{gid}/typeahead?resource_type=task&query={query}&count={count}&opt_fields={TASK_FIELDS}"),
                        &cred.token,
                    ),
                    api(
                        &format!("/workspaces/{gid}/typeahead?resource_type=project&query={query}&count=2&opt_fields={PROJECT_FIELDS}"),
                        &cred.token,
                    ),
                ]
            })
            .collect()
    }

    fn read_search(&self, account: &Account, replies: &[HttpReply], limit: usize) -> Result<Vec<Hit>, String> {
        let (mut tasks, mut projects, mut answered, mut failed) = (vec![], vec![], false, None);
        for ((_, workspace), pair) in workspaces(account).iter().zip(replies.chunks(2)) {
            let found = &pair[0];
            if !found.ok() {
                failed = failed.or(Some(found));
                continue;
            }
            answered = true;
            tasks.extend(found.json()["data"].as_array().into_iter().flatten().map(|t| task_hit(t, workspace)));
            // Projects are a bonus: the search still counts if only they fail.
            if let Some(found) = pair.get(1).filter(|r| r.ok()) {
                projects.extend(found.json()["data"].as_array().into_iter().flatten().map(|p| project_hit(p, workspace)));
            }
        }
        if let (false, Some(r)) = (answered, failed) {
            return Err(error(r));
        }
        // Leave room for two projects: there are few, and they're named for what they hold.
        projects.truncate(if limit >= 4 { 2 } else { 0 });
        tasks.truncate(limit - projects.len());
        tasks.extend(projects);
        Ok(tasks)
    }

    /// Task links, old and new: `https://app.asana.com/0/<project>/<task>` (also `/0/0/<task>`
    /// and `…/f`), `https://app.asana.com/1/<workspace>/project/<project>/task/<task>` and
    /// `https://app.asana.com/1/<workspace>/task/<task>` → the task's gid.
    fn preview_target(&self, _account: &Account, url: &str) -> Option<String> {
        if host_of(url)? != "app.asana.com" {
            return None;
        }
        let path = path_of(url);
        let task = match path.as_slice() {
            [v, project, task, ..] if v == "0" && is_gid(project) => task,
            [v, workspace, rest @ ..] if v == "1" && is_gid(workspace) => rest.windows(2).find(|w| w[0] == "task").map(|w| &w[1])?,
            _ => return None,
        };
        is_gid(task).then(|| task.clone())
    }

    fn preview(&self, cred: &Credential, _account: &Account, target: &str) -> Vec<HttpCall> {
        vec![api(&format!("/tasks/{target}?opt_fields={PREVIEW_FIELDS}"), &cred.token)]
    }

    fn read_preview(&self, _account: &Account, target: &str, replies: &[HttpReply]) -> Result<Preview, String> {
        let r = replies.first().cloned().unwrap_or_default();
        if !r.ok() {
            return Err(match r.status {
                403 | 404 => "Asana has no such task, or the connected account can't see it.".into(),
                _ => error(&r),
            });
        }
        let t = &r.json()["data"];
        let mut details = vec![];
        if let Some(due) = opt(&t["due_at"]).or_else(|| opt(&t["due_on"])) {
            details.push(Detail { label: "Due".into(), value: due });
        }
        let projects = names(&t["projects"]);
        if !projects.is_empty() {
            let label = if projects.len() == 1 { "Project" } else { "Projects" };
            details.push(Detail { label: label.into(), value: projects.join(", ") });
        }
        if let Some(parent) = opt(&t["parent"]["name"]) {
            details.push(Detail { label: "Subtask of".into(), value: parent });
        }
        Ok(Preview {
            provider: "asana".into(),
            kind: "task".into(),
            title: s(&t["name"]),
            url: opt(&t["permalink_url"]).unwrap_or_else(|| format!("https://app.asana.com/0/0/{target}")),
            reference: s(&t["workspace"]["name"]),
            status: Some(if t["completed"].as_bool() == Some(true) { "completed" } else { "open" }.into()),
            assignee: opt(&t["assignee"]["name"]),
            author: None,
            created_at: opt(&t["created_at"]),
            updated_at: opt(&t["modified_at"]),
            description: excerpt(t["notes"].as_str().unwrap_or_default(), 300),
            details,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connect::OAuthApp;

    fn reply(status: u16, body: Value) -> HttpReply {
        HttpReply { status, body: body.to_string() }
    }

    fn account() -> Account {
        Account {
            label: "ada@acme.com".into(),
            settings: json!({ "workspaces": [{ "gid": "11", "name": "Acme" }, { "gid": "22", "name": "Side" }] }),
        }
    }

    #[test]
    fn profile_keeps_the_first_workspaces() {
        let cred = Credential { token: "t".into(), ..Default::default() };
        let calls = Asana.profile(&cred);
        assert_eq!(calls[0].url, "https://app.asana.com/api/1.0/users/me?opt_fields=name,email,workspaces.name");
        assert!(calls[0].headers.contains(&("authorization".into(), "Bearer t".into())));
        let me = json!({ "data": { "gid": "1", "name": "Ada", "email": "ada@acme.com", "workspaces": [
            { "gid": "11", "name": "Acme" }, { "gid": "x/../12", "name": "Odd" }, { "gid": "22", "name": "Side" },
            { "gid": "33", "name": "Third" }, { "gid": "44", "name": "Fourth" }
        ] } });
        let account = Asana.read_profile(&cred, &[reply(200, me)]).unwrap();
        assert_eq!(account.label, "ada@acme.com");
        assert_eq!(account.settings["workspaces"].as_array().unwrap().len(), 3);
        assert_eq!(account.settings["workspaces"][1], json!({ "gid": "22", "name": "Side" }), "ids that aren't numbers are dropped");
        let none = json!({ "data": { "name": "Ada", "workspaces": [] } });
        assert!(Asana.read_profile(&cred, &[reply(200, none)]).unwrap_err().contains("workspace"));
        assert!(Asana.read_profile(&cred, &[reply(401, json!({}))]).unwrap_err().contains("rejected that token"));
        assert!(Asana.read_profile(&cred, &[reply(0, json!(null))]).unwrap_err().contains("in time"));
    }

    #[test]
    fn signs_in_with_pkce_and_refreshes() {
        let spec = INFO.oauth.unwrap();
        assert!(spec.pkce);
        assert!(spec.scopes.contains(&"workspaces.typeahead:read"));
        let app = OAuthApp { client_id: "id".into(), client_secret: "sec".into() };
        let call = Asana.token_request(
            &app,
            INFO.oauth.unwrap().token_url,
            vec![("grant_type".into(), "refresh_token".into()), ("refresh_token".into(), "r".into())],
        );
        assert_eq!(call.url, "https://app.asana.com/-/oauth_token");
        assert_eq!(call.body.as_deref(), Some("grant_type=refresh_token&refresh_token=r&client_id=id&client_secret=sec"));
        // A refresh answers without a new refresh token; the core keeps the old one.
        let tokens = Asana.read_token(&reply(200, json!({ "access_token": "a2", "expires_in": 3600, "data": { "gid": "1" } }))).unwrap();
        assert_eq!((tokens.access_token.as_str(), tokens.refresh_token, tokens.expires_in), ("a2", None, Some(3600)));
    }

    #[test]
    fn search_uses_each_workspaces_typeahead() {
        let calls = Asana.search(&Credential { token: "t".into(), ..Default::default() }, &account(), "launch plan&x", 5);
        assert_eq!(calls.len(), 4);
        assert_eq!(
            calls[0].url,
            format!(
                "https://app.asana.com/api/1.0/workspaces/11/typeahead?resource_type=task&query=launch%20plan%26x&count=5&opt_fields={TASK_FIELDS}"
            )
        );
        assert!(calls[1].url.contains("/workspaces/11/typeahead?resource_type=project&") && calls[1].url.contains("count=2"));
        assert!(calls[2].url.contains("/workspaces/22/typeahead?resource_type=task&"));
        let tasks = json!({ "data": [
            { "gid": "101", "name": "Write launch plan", "completed": false, "notes": "Draft\n\nthe plan", "modified_at": "2026-10-01T00:00:00.000Z",
              "permalink_url": "https://app.asana.com/1/11/project/7/task/101", "projects": [{ "gid": "7", "name": "Launch" }] },
            { "gid": "102", "name": "Plan launch party", "completed": true, "projects": [] }
        ] });
        let projects = json!({ "data": [{ "gid": "7", "name": "Launch", "archived": false, "permalink_url": "https://app.asana.com/1/11/project/7" }] });
        let side = json!({ "data": [{ "gid": "201", "name": "Launch notes", "completed": false }] });
        let replies = [reply(200, tasks.clone()), reply(200, projects.clone()), reply(200, side), reply(500, json!({}))];
        let hits = Asana.read_search(&account(), &replies, 5).unwrap();
        assert_eq!(hits.iter().map(|h| h.kind.as_str()).collect::<Vec<_>>(), ["task", "task", "task", "project"]);
        assert_eq!((hits[0].context.as_str(), hits[0].snippet.as_str()), ("Launch · Acme", "Draft the plan"));
        assert_eq!((hits[1].context.as_str(), hits[1].url.as_str()), ("Acme · completed", "https://app.asana.com/0/0/102"));
        assert_eq!(hits[2].context, "Side");
        assert_eq!((hits[3].context.as_str(), hits[3].url.as_str()), ("Project · Acme", "https://app.asana.com/1/11/project/7"));
        // A small limit leaves projects out; one workspace failing doesn't fail the search.
        let replies = [reply(200, tasks), reply(200, projects), reply(402, json!({})), reply(402, json!({}))];
        assert_eq!(Asana.read_search(&account(), &replies, 1).unwrap().len(), 1);
        let all_failed = [reply(401, json!({})), reply(401, json!({})), reply(401, json!({})), reply(401, json!({}))];
        assert!(Asana.read_search(&account(), &all_failed, 5).unwrap_err().contains("Reconnect"));
        assert!(Asana.read_search(&account(), &[reply(402, json!({})), reply(402, json!({}))], 5).unwrap_err().contains("paid plans"));
        assert!(Asana.read_search(&account(), &[reply(0, json!(null)), reply(0, json!(null))], 5).unwrap_err().contains("in time"));
    }

    #[test]
    fn previews_tasks_from_old_and_new_links() {
        let a = Account::default();
        for (url, gid) in [
            ("https://app.asana.com/0/1206043162733419/12058909747493732", "12058909747493732"),
            ("https://app.asana.com/0/1206043162733419/12058909747493732/f", "12058909747493732"),
            ("https://app.asana.com/0/0/555", "555"),
            ("https://app.asana.com/1/15793206719/project/1206043162733419/task/12058909747493732?focus=true", "12058909747493732"),
            ("https://app.asana.com/1/15793206719/task/555", "555"),
            ("https://app.asana.com/1/15793206719/project/12/task/555/comment/9", "555"),
            ("https://app.asana.com/1/15793206719/home/task/555", "555"),
        ] {
            assert_eq!(Asana.preview_target(&a, url).as_deref(), Some(gid), "{url}");
        }
        for no in [
            "https://app.asana.com/0/1206043162733419/list",
            "https://app.asana.com/0/1206043162733419",
            "https://app.asana.com/1/15793206719/project/12",
            "https://app.asana.com/1/15793206719/task/..%2F..%2Fusers",
            "https://app.asana.com/0/inbox/1/2/3",
            "https://asana.com/0/1/2",
            "https://app.asana.com.evil.test/0/1/2",
            "https://evil.test/app.asana.com/0/1/2",
        ] {
            assert_eq!(Asana.preview_target(&a, no), None, "{no}");
        }
        let calls = Asana.preview(&Credential { token: "t".into(), ..Default::default() }, &a, "555");
        assert_eq!(calls[0].url, format!("https://app.asana.com/api/1.0/tasks/555?opt_fields={PREVIEW_FIELDS}"));
        let task = json!({ "data": { "gid": "555", "name": "Fix login", "completed": false, "assignee": { "gid": "3", "name": "Bo" },
            "created_at": "2026-09-01T00:00:00.000Z", "modified_at": "2026-10-01T00:00:00.000Z", "due_on": "2026-11-02", "due_at": null,
            "notes": "Steps:\n1. sign in", "permalink_url": "https://app.asana.com/1/11/project/7/task/555",
            "projects": [{ "gid": "7", "name": "Launch" }, { "gid": "8", "name": "Bugs" }], "workspace": { "gid": "11", "name": "Acme" },
            "parent": { "gid": "554", "name": "Auth" } } });
        let p = Asana.read_preview(&a, "555", &[reply(200, task)]).unwrap();
        assert_eq!((p.kind.as_str(), p.reference.as_str(), p.status.as_deref()), ("task", "Acme", Some("open")));
        assert_eq!((p.assignee.as_deref(), p.description.as_str()), (Some("Bo"), "Steps: 1. sign in"));
        assert_eq!(
            p.details,
            vec![
                Detail { label: "Due".into(), value: "2026-11-02".into() },
                Detail { label: "Projects".into(), value: "Launch, Bugs".into() },
                Detail { label: "Subtask of".into(), value: "Auth".into() },
            ]
        );
        let done = json!({ "data": { "name": "Ship", "completed": true, "projects": [] } });
        let p = Asana.read_preview(&a, "556", &[reply(200, done)]).unwrap();
        assert_eq!((p.status.as_deref(), p.url.as_str()), (Some("completed"), "https://app.asana.com/0/0/556"));
        assert!(Asana.read_preview(&a, "555", &[reply(404, json!({}))]).unwrap_err().contains("can't see"));
        assert!(Asana.read_preview(&a, "555", &[reply(401, json!({}))]).unwrap_err().contains("Reconnect"));
    }
}
