//! Linear: previews of linked issues, from the connected workspace only. People connect with a
//! personal API key or by signing in.
//!
//! Docs: https://linear.app/developers/graphql, https://linear.app/developers/oauth-2-0-authentication,
//! https://linear.app/developers/rate-limiting, and the schema at
//! https://github.com/linear/linear/blob/master/packages/sdk/src/schema.graphql

use serde_json::{Value, json};

use crate::connect::{
    Account, Connector, Credential, Detail, Field, Hit, HttpCall, HttpReply, OAuthSpec, Preview, ProviderInfo, TokenSet, excerpt, host_of,
    http_error, opt, path_of, s, standard_token,
};

pub struct Linear;

const API: &str = "https://api.linear.app/graphql";
/// Marks a credential that came from signing in: Linear takes OAuth tokens as `Bearer …` and
/// personal API keys bare.
const SIGNED_IN: &str = "signed_in";

static INFO: ProviderInfo = ProviderInfo {
    id: "linear",
    name: "Linear",
    about: "Preview linked issues from your Linear workspace.",
    search: false,
    preview: true,
    oauth: Some(OAuthSpec {
        authorize_url: "https://linear.app/oauth/authorize",
        token_url: "https://api.linear.app/oauth/token",
        scopes: &["read"],
        scope_param: "scope",
        scope_separator: ",",
        extra: &[],
        pkce: true,
    }),
    token_fields: &[Field {
        key: "token",
        label: "Personal API key",
        help: "A key with Read permission. In Linear: Settings › Account › Security & access › New API key.",
        secret: true,
        optional: false,
    }],
    token_help: "https://linear.app/settings/account/security",
};

const PROFILE: &str = "query { viewer { name email } organization { name urlKey } }";
const ISSUE: &str = "query Issue($id: String!) { issue(id: $id) { identifier title url description priorityLabel createdAt updatedAt \
    dueDate state { name } assignee { name } creator { name } team { name } project { name } labels(first: 10) { nodes { name } } } }";

fn graphql(cred: &Credential, query: &str, variables: Value) -> HttpCall {
    let call = HttpCall::post_json(API, &json!({ "query": query, "variables": variables }));
    if cred.field(SIGNED_IN) == "true" { call.bearer(&cred.token) } else { call.header("authorization", cred.token.clone()) }
}

enum Failure {
    Rejected,
    NotFound,
    Other(String),
}

/// The `data` of a GraphQL answer. Linear says "not found" with HTTP 200 and an error, a
/// rejected key with 401 (or 400) and `AUTHENTICATION_ERROR`, and a rate limit with 429.
fn data(r: &HttpReply) -> Result<Value, Failure> {
    let v = r.json();
    let error = &v["errors"][0];
    let code = error["extensions"]["code"].as_str().unwrap_or_default();
    if r.status == 401 || code == "AUTHENTICATION_ERROR" {
        return Err(Failure::Rejected);
    }
    if code == "RATELIMITED" {
        return Err(Failure::Other(http_error("Linear", &HttpReply { status: 429, body: String::new() })));
    }
    if code == "FORBIDDEN" || code == "ENTITY_NOT_FOUND" || s(&error["message"]).starts_with("Entity not found") {
        return Err(Failure::NotFound);
    }
    if !r.ok() {
        return Err(Failure::Other(http_error("Linear", r)));
    }
    if !error.is_null() {
        let why = opt(&error["extensions"]["userPresentableMessage"]).or_else(|| opt(&error["message"])).unwrap_or_default();
        return Err(Failure::Other(format!("Linear couldn't answer: {why}")));
    }
    Ok(v["data"].clone())
}

/// Links name their workspace, and an account matches only its own. Without an account (nobody
/// connected), any workspace's link still says it's Linear's.
fn in_workspace(account: &Account, workspace: &str) -> bool {
    match account.settings["url_key"].as_str() {
        Some(key) => key.eq_ignore_ascii_case(workspace),
        None => account.settings.is_null(),
    }
}

impl Connector for Linear {
    fn info(&self) -> &'static ProviderInfo {
        &INFO
    }

    fn profile(&self, cred: &Credential) -> Vec<HttpCall> {
        vec![graphql(cred, PROFILE, json!({}))]
    }

    fn read_profile(&self, _cred: &Credential, replies: &[HttpReply]) -> Result<Account, String> {
        let r = replies.first().cloned().unwrap_or_default();
        let d = data(&r).map_err(|f| match f {
            Failure::Rejected => "Linear rejected that key. Check it was copied whole and hasn't been revoked.".to_string(),
            Failure::NotFound => "Linear didn't let that key read your account. Give it Read permission.".to_string(),
            Failure::Other(e) => e,
        })?;
        let url_key = s(&d["organization"]["urlKey"]);
        if url_key.is_empty() {
            return Err("Linear didn't say which workspace that key is for.".into());
        }
        let who = opt(&d["viewer"]["email"]).or_else(|| opt(&d["viewer"]["name"])).unwrap_or_default();
        let label = match opt(&d["organization"]["name"]) {
            Some(org) => format!("{who} ({org})"),
            None => who,
        };
        Ok(Account { label, settings: json!({ "url_key": url_key }) })
    }

    // Previews only: Linear isn't searched.
    fn search(&self, _cred: &Credential, _account: &Account, _q: &str, _limit: usize) -> Vec<HttpCall> {
        vec![]
    }

    fn read_search(&self, _account: &Account, _replies: &[HttpReply], _limit: usize) -> Result<Vec<Hit>, String> {
        Ok(vec![])
    }

    /// `https://linear.app/acme/issue/ENG-123/fix-login` → `ENG-123`, for the connected workspace.
    fn preview_target(&self, account: &Account, url: &str) -> Option<String> {
        if host_of(url)? != "linear.app" {
            return None;
        }
        let path = path_of(url);
        let [workspace, kind, id, ..] = path.as_slice() else { return None };
        if kind != "issue" || !in_workspace(account, workspace) {
            return None;
        }
        let (team, number) = id.split_once('-')?;
        let ok = (1..=10).contains(&team.len())
            && team.bytes().all(|b| b.is_ascii_alphanumeric())
            && (1..=9).contains(&number.len())
            && number.bytes().all(|b| b.is_ascii_digit());
        ok.then(|| format!("{}-{number}", team.to_ascii_uppercase()))
    }

    fn preview(&self, cred: &Credential, _account: &Account, target: &str) -> Vec<HttpCall> {
        vec![graphql(cred, ISSUE, json!({ "id": target }))]
    }

    fn read_preview(&self, _account: &Account, target: &str, replies: &[HttpReply]) -> Result<Preview, String> {
        let r = replies.first().cloned().unwrap_or_default();
        let not_found = || "Linear has no such issue, or the connected account can't see it.".to_string();
        let d = data(&r).map_err(|f| match f {
            Failure::Rejected => http_error("Linear", &HttpReply { status: 401, body: String::new() }),
            Failure::NotFound => not_found(),
            Failure::Other(e) => e,
        })?;
        let i = &d["issue"];
        if !i.is_object() {
            return Err(not_found());
        }
        let mut details = vec![];
        if let Some(team) = opt(&i["team"]["name"]) {
            details.push(Detail { label: "Team".into(), value: team });
        }
        if let Some(p) = opt(&i["priorityLabel"]).filter(|p| p != "No priority") {
            details.push(Detail { label: "Priority".into(), value: p });
        }
        if let Some(project) = opt(&i["project"]["name"]) {
            details.push(Detail { label: "Project".into(), value: project });
        }
        let labels: Vec<&str> = i["labels"]["nodes"].as_array().into_iter().flatten().filter_map(|l| l["name"].as_str()).collect();
        if !labels.is_empty() {
            details.push(Detail { label: "Labels".into(), value: labels.join(", ") });
        }
        if let Some(due) = opt(&i["dueDate"]) {
            details.push(Detail { label: "Due".into(), value: due });
        }
        Ok(Preview {
            provider: "linear".into(),
            kind: "issue".into(),
            title: s(&i["title"]),
            url: s(&i["url"]),
            reference: opt(&i["identifier"]).unwrap_or_else(|| target.to_string()),
            status: opt(&i["state"]["name"]),
            assignee: opt(&i["assignee"]["name"]),
            author: opt(&i["creator"]["name"]),
            created_at: opt(&i["createdAt"]),
            updated_at: opt(&i["updatedAt"]),
            // Markdown, shown as text.
            description: excerpt(i["description"].as_str().unwrap_or_default(), 300),
            details,
        })
    }

    fn read_token(&self, reply: &HttpReply) -> Result<TokenSet, String> {
        let mut tokens = standard_token("Linear", reply)?;
        tokens.fields.insert(SIGNED_IN.into(), "true".into());
        Ok(tokens)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reply(status: u16, body: Value) -> HttpReply {
        HttpReply { status, body: body.to_string() }
    }

    fn acme() -> Account {
        Account { label: "ada@acme.com (Acme)".into(), settings: json!({ "url_key": "acme" }) }
    }

    #[test]
    fn keys_go_bare_and_sign_ins_as_bearer() {
        let key = Credential { token: "lin_api_k".into(), ..Default::default() };
        let calls = Linear.profile(&key);
        assert_eq!((calls[0].method, calls[0].url.as_str()), ("POST", "https://api.linear.app/graphql"));
        assert!(calls[0].headers.contains(&("authorization".into(), "lin_api_k".into())));
        assert!(calls[0].headers.contains(&("content-type".into(), "application/json".into())));
        let body: Value = serde_json::from_str(calls[0].body.as_deref().unwrap()).unwrap();
        assert!(body["query"].as_str().unwrap().contains("organization { name urlKey }"));

        let tokens = Linear
            .read_token(&reply(
                200,
                json!({ "access_token": "lin_oauth_a", "refresh_token": "r", "expires_in": 86399, "token_type": "Bearer" }),
            ))
            .unwrap();
        assert_eq!((tokens.refresh_token.as_deref(), tokens.expires_in), (Some("r"), Some(86399)));
        let signed_in = Credential { token: tokens.access_token, fields: tokens.fields, ..Default::default() };
        assert!(Linear.profile(&signed_in)[0].headers.contains(&("authorization".into(), "Bearer lin_oauth_a".into())));
        assert!(Linear.read_token(&reply(400, json!({ "error": "invalid_grant" }))).unwrap_err().contains("invalid_grant"));
    }

    #[test]
    fn profile_keeps_the_workspace() {
        let me = json!({ "data": { "viewer": { "name": "Ada", "email": "ada@acme.com" }, "organization": { "name": "Acme", "urlKey": "acme" } } });
        let account = Linear.read_profile(&Credential::default(), &[reply(200, me)]).unwrap();
        assert_eq!((account.label.as_str(), &account.settings["url_key"]), ("ada@acme.com (Acme)", &json!("acme")));
        let rejected = json!({ "errors": [{ "message": "Authentication required", "extensions": { "code": "AUTHENTICATION_ERROR" } }] });
        assert!(Linear.read_profile(&Credential::default(), &[reply(401, rejected.clone())]).unwrap_err().contains("rejected that key"));
        assert!(Linear.read_profile(&Credential::default(), &[reply(400, rejected)]).unwrap_err().contains("rejected that key"));
        let no_org = json!({ "data": { "viewer": { "name": "Ada" }, "organization": null } });
        assert!(Linear.read_profile(&Credential::default(), &[reply(200, no_org)]).unwrap_err().contains("which workspace"));
        assert!(Linear.read_profile(&Credential::default(), &[reply(0, json!(null))]).unwrap_err().contains("in time"));
    }

    #[test]
    fn recognizes_issues_in_the_connected_workspace_only() {
        let a = acme();
        assert_eq!(Linear.preview_target(&a, "https://linear.app/acme/issue/ENG-123/fix-login").as_deref(), Some("ENG-123"));
        assert_eq!(Linear.preview_target(&a, "https://linear.app/Acme/issue/eng-7#comment-1").as_deref(), Some("ENG-7"));
        // Nobody connected: the link still says it's Linear's.
        assert_eq!(Linear.preview_target(&Account::default(), "https://linear.app/beta/issue/OPS-1/x").as_deref(), Some("OPS-1"));
        for no in [
            "https://linear.app/beta/issue/ENG-123/fix-login",
            "https://linear.app.evil.test/acme/issue/ENG-123",
            "https://evil-linear.app/acme/issue/ENG-123",
            "https://linear.app/acme/project/launch-1",
            "https://linear.app/acme/issue/ENG",
            "https://linear.app/acme/issue/ENG-12a",
            "https://linear.app/acme/issue/E%22NG-1",
            "https://linear.app/acme/issue/-1",
            "https://linear.app/acme",
        ] {
            assert_eq!(Linear.preview_target(&a, no), None, "{no}");
        }
        // A connected account without a workspace matches none.
        assert_eq!(
            Linear.preview_target(&Account { label: String::new(), settings: json!({}) }, "https://linear.app/acme/issue/ENG-1"),
            None
        );
    }

    #[test]
    fn previews_issues() {
        let calls = Linear.preview(&Credential { token: "k".into(), ..Default::default() }, &acme(), "ENG-123");
        let body: Value = serde_json::from_str(calls[0].body.as_deref().unwrap()).unwrap();
        assert_eq!(body["variables"], json!({ "id": "ENG-123" }));
        assert!(body["query"].as_str().unwrap().contains("issue(id: $id)"));
        let issue = json!({ "data": { "issue": { "identifier": "ENG-123", "title": "Fix login", "url": "https://linear.app/acme/issue/ENG-123/fix-login",
            "description": "Users **loop**\n\nforever.", "priorityLabel": "High", "createdAt": "2026-10-01T00:00:00.000Z", "updatedAt": "2026-10-02T00:00:00.000Z",
            "dueDate": "2026-11-01", "state": { "name": "In Progress" }, "assignee": { "name": "Bo" }, "creator": { "name": "Ada" },
            "team": { "name": "Engineering" }, "project": null, "labels": { "nodes": [{ "name": "Bug" }] } } } });
        let p = Linear.read_preview(&acme(), "ENG-123", &[reply(200, issue)]).unwrap();
        assert_eq!(
            (p.reference.as_str(), p.status.as_deref(), p.assignee.as_deref(), p.author.as_deref()),
            ("ENG-123", Some("In Progress"), Some("Bo"), Some("Ada"))
        );
        assert_eq!(p.description, "Users **loop** forever.");
        let labels: Vec<&str> = p.details.iter().map(|d| d.label.as_str()).collect();
        assert_eq!(labels, ["Team", "Priority", "Labels", "Due"]);

        let not_found = json!({ "errors": [{ "message": "Entity not found: Issue", "extensions": { "code": "INPUT_ERROR",
            "userPresentableMessage": "Could not find referenced Issue." } }], "data": null });
        assert!(Linear.read_preview(&acme(), "ENG-9", &[reply(200, not_found)]).unwrap_err().contains("can't see"));
        assert!(
            Linear.read_preview(&acme(), "ENG-9", &[reply(200, json!({ "data": { "issue": null } }))]).unwrap_err().contains("can't see")
        );
        assert!(Linear.read_preview(&acme(), "ENG-9", &[reply(401, json!({}))]).unwrap_err().contains("Reconnect"));
        let limited = json!({ "errors": [{ "message": "Rate limit exceeded", "extensions": { "code": "RATELIMITED" } }] });
        assert!(Linear.read_preview(&acme(), "ENG-9", &[reply(429, limited)]).unwrap_err().contains("rate limit"));
        assert!(Linear.read_preview(&acme(), "ENG-9", &[reply(0, json!(null))]).unwrap_err().contains("in time"));
        let odd = json!({ "errors": [{ "message": "Query too complex" }] });
        assert!(Linear.read_preview(&acme(), "ENG-9", &[reply(200, odd)]).unwrap_err().contains("Query too complex"));
    }
}
