//! ClickUp: previews of linked tasks the connected account can open, in the Workspaces it was
//! given. ClickUp's sign-in has no scopes (people pick Workspaces) and its tokens don't expire.
//!
//! Docs: https://developer.clickup.com/docs/authentication, https://developer.clickup.com/reference/getaccesstoken,
//! https://developer.clickup.com/reference/getauthorizeduser, https://developer.clickup.com/reference/gettask,
//! https://developer.clickup.com/docs/common_errors

use chrono::DateTime;
use serde_json::{Value, json};

use crate::connect::{
    Account, Connector, Credential, Detail, Field, Hit, HttpCall, HttpReply, OAuthApp, OAuthSpec, Preview, ProviderInfo, excerpt, host_of,
    http_error, opt, path_of, s,
};
use crate::util::ts;

pub struct ClickUp;

const API: &str = "https://api.clickup.com/api/v2";
const NOT_FOUND: &str = "ClickUp has no such task, or the connected account can't see it.";

static INFO: ProviderInfo = ProviderInfo {
    id: "clickup",
    name: "ClickUp",
    about: "Preview linked tasks.",
    search: false,
    preview: true,
    oauth: Some(OAuthSpec {
        authorize_url: "https://app.clickup.com/api",
        token_url: "https://api.clickup.com/api/v2/oauth/token",
        scopes: &[],
        scope_param: "scope",
        scope_separator: " ",
        extra: &[],
        pkce: false,
        site: None,
    }),
    token_fields: &[Field {
        key: "token",
        label: "Personal API token",
        help: "In ClickUp, Settings › Apps › API Token. It starts with pk_.",
        secret: true,
        optional: false,
    }],
    token_help: "https://app.clickup.com/settings/apps",
};

/// Personal tokens (`pk_…`) go as they are; tokens from signing in are bearer tokens.
fn api(path: &str, cred: &Credential) -> HttpCall {
    let call = HttpCall::get(format!("{API}{path}")).header("accept", "application/json");
    if cred.token.starts_with("pk_") { call.header("authorization", cred.token.clone()) } else { call.bearer(&cred.token) }
}

/// Task ids are letters and digits; custom ones (`DEV-42`) add dashes and underscores.
fn task_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// ClickUp's times are milliseconds since 1970, as strings.
fn millis(v: &Value) -> Option<DateTime<chrono::Utc>> {
    let ms = v.as_str().and_then(|x| x.parse::<i64>().ok()).or_else(|| v.as_i64())?;
    DateTime::from_timestamp_millis(ms)
}

/// "Team not authorized": the task is in a Workspace the token wasn't given.
fn other_workspace(code: &str) -> bool {
    matches!(code, "OAUTH_023" | "OAUTH_026" | "OAUTH_027")
        || code.strip_prefix("OAUTH_0").and_then(|n| n.parse::<u32>().ok()).is_some_and(|n| (29..=45).contains(&n))
}

impl Connector for ClickUp {
    fn info(&self) -> &'static ProviderInfo {
        &INFO
    }

    fn profile(&self, cred: &Credential) -> Vec<HttpCall> {
        vec![api("/user", cred)]
    }

    fn read_profile(&self, _cred: &Credential, replies: &[HttpReply]) -> Result<Account, String> {
        let r = replies.first().cloned().unwrap_or_default();
        if !r.ok() {
            return Err(match r.status {
                401 => "ClickUp rejected that token. Check it was copied whole; personal tokens start with pk_.".into(),
                _ => http_error("ClickUp", &r),
            });
        }
        let u = &r.json()["user"];
        let name = opt(&u["email"]).or_else(|| opt(&u["username"]));
        let Some(label) = name else { return Err("ClickUp didn't say whose token that is.".into()) };
        Ok(Account { label, settings: json!({ "id": u["id"], "username": s(&u["username"]) }) })
    }

    /// ClickUp only previews links.
    fn search(&self, _cred: &Credential, _account: &Account, _q: &str, _limit: usize) -> Vec<HttpCall> {
        vec![]
    }

    fn read_search(&self, _account: &Account, _replies: &[HttpReply], _limit: usize) -> Result<Vec<Hit>, String> {
        Ok(vec![])
    }

    /// `https://app.clickup.com/t/86abc123` → `86abc123`. With a Workspace,
    /// `https://app.clickup.com/t/9012345/86abc123` → `86abc123`, and a custom task id (which
    /// ClickUp finds only with its Workspace) `https://app.clickup.com/t/9012345/DEV-42` → `9012345/DEV-42`.
    fn preview_target(&self, _account: &Account, url: &str) -> Option<String> {
        if host_of(url)? != "app.clickup.com" {
            return None;
        }
        let custom = |id: &str| id.contains('-') || id.contains('_');
        match path_of(url).as_slice() {
            [t, id] if t == "t" && task_id(id) && !custom(id) => Some(id.clone()),
            [t, team, id]
                if t == "t" && !team.is_empty() && team.len() <= 20 && team.bytes().all(|b| b.is_ascii_digit()) && task_id(id) =>
            {
                Some(if custom(id) { format!("{team}/{id}") } else { id.clone() })
            }
            _ => None,
        }
    }

    fn preview(&self, cred: &Credential, _account: &Account, target: &str) -> Vec<HttpCall> {
        let path = match target.split_once('/') {
            Some((team, id)) => format!("/task/{id}?custom_task_ids=true&team_id={team}"),
            None => format!("/task/{target}"),
        };
        vec![api(&path, cred)]
    }

    fn read_preview(&self, _account: &Account, _target: &str, replies: &[HttpReply]) -> Result<Preview, String> {
        let r = replies.first().cloned().unwrap_or_default();
        if !r.ok() {
            let code = s(&r.json()["ECODE"]);
            return Err(match r.status {
                404 => NOT_FOUND.into(),
                400 | 401 if code.starts_with("ITEM_") || other_workspace(&code) => NOT_FOUND.into(),
                _ => http_error("ClickUp", &r),
            });
        }
        let t = r.json();
        let names = |v: &Value| -> Vec<String> {
            v.as_array().into_iter().flatten().filter_map(|p| opt(&p["username"]).or_else(|| opt(&p["email"]))).collect()
        };
        let mut details = vec![];
        if let Some(list) = opt(&t["list"]["name"]) {
            details.push(Detail { label: "List".into(), value: list });
        }
        if let Some(priority) = opt(&t["priority"]["priority"]) {
            details.push(Detail { label: "Priority".into(), value: priority });
        }
        if let Some(due) = millis(&t["due_date"]) {
            details.push(Detail { label: "Due".into(), value: due.format("%Y-%m-%d").to_string() });
        }
        let text = opt(&t["text_content"]).or_else(|| opt(&t["description"])).unwrap_or_default();
        Ok(Preview {
            provider: "clickup".into(),
            kind: "task".into(),
            title: s(&t["name"]),
            url: s(&t["url"]),
            reference: opt(&t["custom_id"]).unwrap_or_else(|| format!("#{}", s(&t["id"]))),
            status: opt(&t["status"]["status"]),
            assignee: Some(names(&t["assignees"]).join(", ")).filter(|a| !a.is_empty()),
            author: opt(&t["creator"]["username"]).or_else(|| opt(&t["creator"]["email"])),
            created_at: millis(&t["date_created"]).map(ts),
            updated_at: millis(&t["date_updated"]).map(ts),
            description: excerpt(&text, 300),
            details,
        })
    }

    /// ClickUp takes only the client and the code. Its tokens don't expire, so nothing refreshes.
    fn token_request(&self, app: &OAuthApp, token_url: &str, form: Vec<(String, String)>) -> HttpCall {
        let code = form.iter().find(|(k, _)| k == "code").map(|(_, v)| v.as_str()).unwrap_or_default();
        let pairs = [("client_id", app.client_id.as_str()), ("client_secret", app.client_secret.as_str()), ("code", code)];
        HttpCall::post_form(token_url, &pairs).header("accept", "application/json")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reply(status: u16, body: Value) -> HttpReply {
        HttpReply { status, body: body.to_string() }
    }

    fn personal() -> Credential {
        Credential { token: "pk_42_ABC".into(), ..Default::default() }
    }

    #[test]
    fn connects_with_a_personal_token_or_by_signing_in() {
        let calls = ClickUp.profile(&personal());
        assert_eq!(calls[0].url, "https://api.clickup.com/api/v2/user");
        assert!(calls[0].headers.contains(&("authorization".into(), "pk_42_ABC".into())), "personal tokens aren't bearer tokens");
        let signed_in = Credential { token: "42_oauth".into(), ..Default::default() };
        assert!(ClickUp.profile(&signed_in)[0].headers.contains(&("authorization".into(), "Bearer 42_oauth".into())));

        let user = json!({ "user": { "id": 123, "username": "Ada L", "email": "ada@acme.com" } });
        let account = ClickUp.read_profile(&personal(), &[reply(200, user)]).unwrap();
        assert_eq!(account.label, "ada@acme.com");
        assert_eq!(account.settings["id"], 123);
        let no_email = ClickUp.read_profile(&personal(), &[reply(200, json!({ "user": { "username": "Ada L" } }))]).unwrap();
        assert_eq!(no_email.label, "Ada L");
        assert!(ClickUp.read_profile(&personal(), &[reply(200, json!({}))]).is_err());
        let rejected = reply(401, json!({ "err": "Token invalid", "ECODE": "OAUTH_025" }));
        assert!(ClickUp.read_profile(&personal(), &[rejected]).unwrap_err().contains("pk_"));

        // The token request carries only the client and the code.
        let app = OAuthApp { client_id: "cid".into(), client_secret: "sec".into() };
        let form =
            vec![("grant_type".into(), "authorization_code".into()), ("code".into(), "c&1".into()), ("redirect_uri".into(), "x".into())];
        let call = ClickUp.token_request(&app, INFO.oauth.unwrap().token_url, form);
        assert_eq!(call.url, "https://api.clickup.com/api/v2/oauth/token");
        assert_eq!(call.body.as_deref(), Some("client_id=cid&client_secret=sec&code=c%261"));
        assert!(ClickUp.info().oauth.unwrap().scopes.is_empty());
        assert!(ClickUp.search(&personal(), &Account::default(), "x", 5).is_empty());
        assert!(ClickUp.read_search(&Account::default(), &[], 5).unwrap().is_empty());
    }

    #[test]
    fn previews_tasks() {
        let a = Account::default();
        assert_eq!(ClickUp.preview_target(&a, "https://app.clickup.com/t/86abc123").as_deref(), Some("86abc123"));
        assert_eq!(ClickUp.preview_target(&a, "https://app.clickup.com/t/9012345/86abc123?comment=1").as_deref(), Some("86abc123"));
        assert_eq!(ClickUp.preview_target(&a, "https://app.clickup.com/t/9012345/DEV-42").as_deref(), Some("9012345/DEV-42"));
        for no in [
            "https://app.clickup.com/t/DEV-42",
            "https://app.clickup.com/t/acme/DEV-42",
            "https://app.clickup.com/t/",
            "https://app.clickup.com/9012345/v/l/s/123",
            "https://app.clickup.com/t/86abc%3Fx%3D1",
            "https://app.clickup.com/t/1/2/3",
            "https://clickup.com/t/86abc123",
            "https://app.clickup.com.evil.test/t/86abc123",
            "https://evil.test/app.clickup.com/t/86abc123",
        ] {
            assert_eq!(ClickUp.preview_target(&a, no), None, "{no}");
        }

        assert_eq!(ClickUp.preview(&personal(), &a, "86abc123")[0].url, "https://api.clickup.com/api/v2/task/86abc123");
        assert_eq!(
            ClickUp.preview(&personal(), &a, "9012345/DEV-42")[0].url,
            "https://api.clickup.com/api/v2/task/DEV-42?custom_task_ids=true&team_id=9012345"
        );

        let task = json!({ "id": "86abc123", "custom_id": null, "name": "Fix deploy", "text_content": "Retry\n\nthe deploy",
            "description": "Retry the deploy", "status": { "status": "in progress" }, "date_created": "1759302000000",
            "date_updated": "1759388400000", "creator": { "id": 1, "username": "Ada L" },
            "assignees": [{ "username": "Bo" }, { "username": null, "email": "cy@acme.com" }], "priority": { "priority": "high" },
            "list": { "name": "Sprint 4" }, "due_date": "1761955200000", "url": "https://app.clickup.com/t/86abc123" });
        let p = ClickUp.read_preview(&a, "86abc123", &[reply(200, task)]).unwrap();
        assert_eq!((p.kind.as_str(), p.title.as_str(), p.reference.as_str()), ("task", "Fix deploy", "#86abc123"));
        assert_eq!(
            (p.status.as_deref(), p.assignee.as_deref(), p.author.as_deref()),
            (Some("in progress"), Some("Bo, cy@acme.com"), Some("Ada L"))
        );
        assert_eq!(p.created_at.as_deref(), Some("2025-10-01T07:00:00.000Z"));
        assert_eq!(p.updated_at.as_deref(), Some("2025-10-02T07:00:00.000Z"));
        assert_eq!(p.description, "Retry the deploy");
        assert_eq!(
            p.details,
            vec![
                Detail { label: "List".into(), value: "Sprint 4".into() },
                Detail { label: "Priority".into(), value: "high".into() },
                Detail { label: "Due".into(), value: "2025-11-01".into() },
            ]
        );
        let custom =
            ClickUp.read_preview(&a, "1/DEV-42", &[reply(200, json!({ "id": "86x", "custom_id": "DEV-42", "name": "Y" }))]).unwrap();
        assert_eq!((custom.reference.as_str(), custom.created_at, custom.details.len()), ("DEV-42", None, 0));

        assert!(ClickUp.read_preview(&a, "x", &[reply(404, json!({}))]).unwrap_err().contains("can't see"));
        let elsewhere = reply(401, json!({ "err": "Team not authorized", "ECODE": "OAUTH_027" }));
        assert!(ClickUp.read_preview(&a, "x", &[elsewhere]).unwrap_err().contains("can't see"), "another Workspace");
        let gone = reply(400, json!({ "err": "Task not found, deleted", "ECODE": "ITEM_013" }));
        assert!(ClickUp.read_preview(&a, "x", &[gone]).unwrap_err().contains("can't see"));
        let revoked = reply(401, json!({ "err": "Token invalid", "ECODE": "OAUTH_025" }));
        assert!(ClickUp.read_preview(&a, "x", &[revoked]).unwrap_err().contains("Reconnect"));
        assert!(ClickUp.read_preview(&a, "x", &[reply(0, Value::Null)]).unwrap_err().contains("in time"));
    }
}
