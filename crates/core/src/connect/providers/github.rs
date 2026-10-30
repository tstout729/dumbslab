//! GitHub: issues, pull requests and repositories the connected account can see, limited to the
//! person's own repositories and organizations (or what they choose under "Search in").

use serde_json::{Value, json};

use crate::connect::{
    Account, Connector, Credential, Detail, Field, Hit, HttpCall, HttpReply, OAuthApp, OAuthSpec, Preview, ProviderInfo, excerpt, host_of,
    http_error, opt, path_of, s,
};

pub struct GitHub;

const API: &str = "https://api.github.com";
/// The most organizations searched by default; GitHub caps how long a query can be.
const MAX_ORGS: usize = 10;

static INFO: ProviderInfo = ProviderInfo {
    id: "github",
    name: "GitHub",
    about: "Search issues, pull requests and repositories, and preview linked issues and pull requests.",
    search: true,
    preview: true,
    oauth: Some(OAuthSpec {
        authorize_url: "https://github.com/login/oauth/authorize",
        token_url: "https://github.com/login/oauth/access_token",
        scopes: &["repo", "read:org"],
        scope_param: "scope",
        scope_separator: " ",
        extra: &[("allow_signup", "false")],
        pkce: false,
    }),
    token_fields: &[
        Field {
            key: "token",
            label: "Personal access token",
            help: "A fine-grained token with read-only access to Issues, Pull requests and Metadata, or a classic token with the repo scope.",
            secret: true,
            optional: false,
        },
        Field {
            key: "search_in",
            label: "Search in",
            help: "GitHub qualifiers like `org:acme repo:acme/api`. Leave empty to search your own repositories and organizations.",
            secret: false,
            optional: true,
        },
    ],
    token_help: "https://github.com/settings/personal-access-tokens/new",
};

fn api(path: &str, token: &str) -> HttpCall {
    HttpCall::get(format!("{API}{path}"))
        .bearer(token)
        .header("accept", "application/vnd.github+json")
        .header("x-github-api-version", "2022-11-28")
        .header("user-agent", "DumbSlab")
}

/// Accepts only `org:`, `user:` and `repo:` qualifiers, so "Search in" can't change the query.
pub fn valid_scope(scope: &str) -> Result<String, String> {
    let words: Vec<&str> = scope.split_whitespace().collect();
    if words.len() > 20 {
        return Err("\"Search in\" can name at most 20 organizations, users or repositories.".into());
    }
    for w in &words {
        let ok = match w.split_once(':') {
            Some(("org" | "user", name)) => !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'),
            Some(("repo", name)) => match name.split_once('/') {
                Some((owner, repo)) => {
                    !owner.is_empty()
                        && !repo.is_empty()
                        && owner.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                        && repo.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
                }
                None => false,
            },
            _ => false,
        };
        if !ok {
            return Err(format!("\"Search in\" takes qualifiers like `org:acme` or `repo:acme/api`; `{w}` isn't one."));
        }
    }
    Ok(words.join(" "))
}

impl Connector for GitHub {
    fn info(&self) -> &'static ProviderInfo {
        &INFO
    }

    fn profile(&self, cred: &Credential) -> Vec<HttpCall> {
        vec![api("/user", &cred.token), api("/user/orgs?per_page=100", &cred.token)]
    }

    fn read_profile(&self, cred: &Credential, replies: &[HttpReply]) -> Result<Account, String> {
        let user = replies.first().cloned().unwrap_or_default();
        if !user.ok() {
            return Err(match user.status {
                401 => "GitHub rejected that token. Check it was copied whole and hasn't expired.".into(),
                _ => http_error("GitHub", &user),
            });
        }
        let login = s(&user.json()["login"]);
        if login.is_empty() {
            return Err("GitHub didn't say whose token that is.".into());
        }
        let chosen = valid_scope(cred.field("search_in"))?;
        let search_in = if chosen.is_empty() {
            // A fine-grained token may not list organizations; it still searches the person's own.
            let orgs = replies.get(1).filter(|r| r.ok()).map(|r| r.json()).unwrap_or(Value::Null);
            let mut words = vec![format!("user:{login}")];
            words.extend(
                orgs.as_array().into_iter().flatten().filter_map(|o| o["login"].as_str()).take(MAX_ORGS).map(|o| format!("org:{o}")),
            );
            words.join(" ")
        } else {
            chosen
        };
        Ok(Account { label: format!("@{login}"), settings: json!({ "login": login, "search_in": search_in }) })
    }

    fn search(&self, cred: &Credential, account: &Account, q: &str, limit: usize) -> Vec<HttpCall> {
        let scope = account.settings["search_in"].as_str().unwrap_or_default();
        let query = urlencoding::encode(&format!("{q} {scope}")).into_owned();
        vec![
            api(&format!("/search/issues?q={query}&per_page={}", limit.clamp(1, 20)), &cred.token),
            api(&format!("/search/repositories?q={query}&per_page=3"), &cred.token),
        ]
    }

    fn read_search(&self, _account: &Account, replies: &[HttpReply], limit: usize) -> Result<Vec<Hit>, String> {
        let issues = replies.first().cloned().unwrap_or_default();
        if !issues.ok() {
            return Err(match issues.status {
                422 => "GitHub couldn't search for that. Check \"Search in\" under Settings › Connected apps.".into(),
                _ => http_error("GitHub", &issues),
            });
        }
        let mut hits: Vec<Hit> = issues.json()["items"]
            .as_array()
            .into_iter()
            .flatten()
            .take(limit)
            .map(|i| {
                let repo =
                    s(&i["repository_url"]).rsplitn(3, '/').take(2).collect::<Vec<_>>().into_iter().rev().collect::<Vec<_>>().join("/");
                let pr = !i["pull_request"].is_null();
                Hit {
                    provider: "github".into(),
                    kind: if pr { "pull_request" } else { "issue" }.into(),
                    title: s(&i["title"]),
                    url: s(&i["html_url"]),
                    context: format!("{repo} #{} · {}", i["number"].as_i64().unwrap_or_default(), s(&i["state"])),
                    snippet: excerpt(i["body"].as_str().unwrap_or_default(), 240),
                    updated_at: opt(&i["updated_at"]),
                    author: opt(&i["user"]["login"]).map(|l| format!("@{l}")),
                }
            })
            .collect();
        // Repositories are a bonus: the search still counts if only they fail.
        if let Some(repos) = replies.get(1).filter(|r| r.ok()) {
            hits.extend(repos.json()["items"].as_array().into_iter().flatten().take(3).map(|r| Hit {
                provider: "github".into(),
                kind: "repository".into(),
                title: s(&r["full_name"]),
                url: s(&r["html_url"]),
                context: match opt(&r["language"]) {
                    Some(lang) => format!("Repository · {lang}"),
                    None => "Repository".into(),
                },
                snippet: excerpt(r["description"].as_str().unwrap_or_default(), 240),
                updated_at: opt(&r["pushed_at"]).or_else(|| opt(&r["updated_at"])),
                author: None,
            }));
        }
        Ok(hits)
    }

    /// `https://github.com/acme/api/issues/7` or `/pull/8` → `acme/api/7`.
    fn preview_target(&self, _account: &Account, url: &str) -> Option<String> {
        if host_of(url)? != "github.com" {
            return None;
        }
        match path_of(url).as_slice() {
            [owner, repo, kind, number, ..] if matches!(kind.as_str(), "issues" | "pull") && number.parse::<u64>().is_ok() => {
                Some(format!("{owner}/{repo}/{number}"))
            }
            _ => None,
        }
    }

    fn preview(&self, cred: &Credential, _account: &Account, target: &str) -> Vec<HttpCall> {
        let (repo, number) = target.rsplit_once('/').unwrap_or_default();
        vec![api(&format!("/repos/{repo}/issues/{number}"), &cred.token)]
    }

    fn read_preview(&self, _account: &Account, target: &str, replies: &[HttpReply]) -> Result<Preview, String> {
        let r = replies.first().cloned().unwrap_or_default();
        if !r.ok() {
            return Err(match r.status {
                404 => "GitHub has no such issue, or the connected account can't see it.".into(),
                _ => http_error("GitHub", &r),
            });
        }
        let i = r.json();
        let (repo, number) = target.rsplit_once('/').unwrap_or_default();
        let pr = &i["pull_request"];
        let status = if !pr.is_null() && !pr["merged_at"].is_null() { "merged".to_string() } else { s(&i["state"]) };
        let names = |v: &serde_json::Value, key: &str| -> Vec<String> {
            v.as_array().into_iter().flatten().filter_map(|x| x[key].as_str()).map(str::to_string).collect()
        };
        let assignees = names(&i["assignees"], "login").iter().map(|l| format!("@{l}")).collect::<Vec<_>>().join(", ");
        let labels = names(&i["labels"], "name").join(", ");
        let mut details = vec![];
        if !labels.is_empty() {
            details.push(Detail { label: "Labels".into(), value: labels });
        }
        if let Some(m) = opt(&i["milestone"]["title"]) {
            details.push(Detail { label: "Milestone".into(), value: m });
        }
        Ok(Preview {
            provider: "github".into(),
            kind: if pr.is_null() { "issue" } else { "pull_request" }.into(),
            title: s(&i["title"]),
            url: s(&i["html_url"]),
            reference: format!("{repo} #{number}"),
            status: Some(status).filter(|s| !s.is_empty()),
            assignee: Some(assignees).filter(|a| !a.is_empty()),
            author: opt(&i["user"]["login"]).map(|l| format!("@{l}")),
            created_at: opt(&i["created_at"]),
            updated_at: opt(&i["updated_at"]),
            description: excerpt(i["body"].as_str().unwrap_or_default(), 300),
            details,
        })
    }

    /// GitHub answers in form encoding unless asked for JSON.
    fn token_request(&self, app: &OAuthApp, form: Vec<(String, String)>) -> HttpCall {
        let mut all = form;
        all.push(("client_id".into(), app.client_id.clone()));
        all.push(("client_secret".into(), app.client_secret.clone()));
        let pairs: Vec<(&str, &str)> = all.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        HttpCall::post_form(INFO.oauth.expect("GitHub signs in").token_url, &pairs).header("accept", "application/json")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reply(status: u16, body: Value) -> HttpReply {
        HttpReply { status, body: body.to_string() }
    }

    #[test]
    fn profile_scopes_search_to_the_person() {
        let cred = Credential { token: "t".into(), ..Default::default() };
        let calls = GitHub.profile(&cred);
        assert_eq!(calls[0].url, "https://api.github.com/user");
        assert!(calls[0].headers.contains(&("authorization".into(), "Bearer t".into())));
        assert!(calls[0].headers.iter().any(|(k, _)| k == "user-agent"));
        let account = GitHub
            .read_profile(&cred, &[reply(200, json!({ "login": "ada" })), reply(200, json!([{ "login": "acme" }, { "login": "beta" }]))])
            .unwrap();
        assert_eq!(account.label, "@ada");
        assert_eq!(account.settings["search_in"], "user:ada org:acme org:beta");
        // Organizations can't be listed with some tokens; the person's own repositories still are.
        let account = GitHub.read_profile(&cred, &[reply(200, json!({ "login": "ada" })), reply(403, json!({}))]).unwrap();
        assert_eq!(account.settings["search_in"], "user:ada");
        assert!(GitHub.read_profile(&cred, &[reply(401, json!({})), reply(401, json!({}))]).unwrap_err().contains("rejected"));
        // "Search in" is the person's choice, but only qualifiers that narrow the search.
        let chosen = Credential {
            token: "t".into(),
            fields: [("search_in".to_string(), " org:acme  repo:acme/api.js ".to_string())].into(),
            ..Default::default()
        };
        let account = GitHub.read_profile(&chosen, &[reply(200, json!({ "login": "ada" })), reply(200, json!([]))]).unwrap();
        assert_eq!(account.settings["search_in"], "org:acme repo:acme/api.js");
        for bad in ["is:private", "org:acme OR anything", "repo:acme", "org:a/b"] {
            assert!(valid_scope(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn previews_issues_and_pull_requests() {
        let a = Account::default();
        assert_eq!(GitHub.preview_target(&a, "https://github.com/acme/api/issues/7").as_deref(), Some("acme/api/7"));
        assert_eq!(GitHub.preview_target(&a, "https://www.github.com/acme/api/pull/8/files?w=1#x").as_deref(), Some("acme/api/8"));
        for no in [
            "https://github.com/acme/api",
            "https://github.com/acme/api/issues",
            "https://gitlab.com/acme/api/issues/7",
            "https://github.com.evil.test/a/b/issues/1",
        ] {
            assert_eq!(GitHub.preview_target(&a, no), None, "{no}");
        }
        let calls = GitHub.preview(&Credential { token: "t".into(), ..Default::default() }, &a, "acme/api/8");
        assert_eq!(calls[0].url, "https://api.github.com/repos/acme/api/issues/8");
        let pr = json!({ "title": "Fix deploy", "html_url": "https://github.com/acme/api/pull/8", "state": "closed",
            "pull_request": { "merged_at": "2026-10-02T00:00:00Z" }, "assignees": [{ "login": "bo" }], "labels": [{ "name": "ops" }],
            "user": { "login": "cy" }, "body": "Retries the deploy." });
        let p = GitHub.read_preview(&a, "acme/api/8", &[reply(200, pr)]).unwrap();
        assert_eq!((p.kind.as_str(), p.reference.as_str(), p.status.as_deref()), ("pull_request", "acme/api #8", Some("merged")));
        assert_eq!((p.assignee.as_deref(), p.author.as_deref()), (Some("@bo"), Some("@cy")));
        assert_eq!(p.details, vec![Detail { label: "Labels".into(), value: "ops".into() }]);
        assert!(GitHub.read_preview(&a, "acme/api/8", &[reply(404, json!({}))]).unwrap_err().contains("can't see"));
    }

    #[test]
    fn search_reads_issues_prs_and_repos() {
        let account = Account { label: "@ada".into(), settings: json!({ "search_in": "user:ada org:acme" }) };
        let calls = GitHub.search(&Credential { token: "t".into(), ..Default::default() }, &account, "deploy fails", 5);
        assert_eq!(calls[0].url, "https://api.github.com/search/issues?q=deploy%20fails%20user%3Aada%20org%3Aacme&per_page=5");
        let issues = json!({ "items": [
            { "title": "Deploy fails on Fridays", "html_url": "https://github.com/acme/api/issues/7", "number": 7, "state": "open",
              "repository_url": "https://api.github.com/repos/acme/api", "body": "Steps:\n\n1. deploy", "updated_at": "2026-10-01T00:00:00Z", "user": { "login": "bo" } },
            { "title": "Fix deploy", "html_url": "https://github.com/acme/api/pull/8", "number": 8, "state": "closed", "pull_request": {},
              "repository_url": "https://api.github.com/repos/acme/api", "body": null, "user": { "login": "cy" } }
        ] });
        let repos = json!({ "items": [{ "full_name": "acme/deploy", "html_url": "https://github.com/acme/deploy", "language": "Rust", "description": "Deploy tools" }] });
        let hits = GitHub.read_search(&account, &[reply(200, issues.clone()), reply(200, repos)], 5).unwrap();
        assert_eq!(hits.len(), 3);
        assert_eq!((hits[0].kind.as_str(), hits[0].context.as_str()), ("issue", "acme/api #7 · open"));
        assert_eq!(hits[0].snippet, "Steps: 1. deploy");
        assert_eq!((hits[1].kind.as_str(), hits[1].author.as_deref()), ("pull_request", Some("@cy")));
        assert_eq!((hits[2].kind.as_str(), hits[2].context.as_str()), ("repository", "Repository · Rust"));
        // Repositories failing doesn't fail the search; issues failing does.
        assert_eq!(GitHub.read_search(&account, &[reply(200, issues), reply(500, json!({}))], 1).unwrap().len(), 1);
        assert!(GitHub.read_search(&account, &[reply(401, json!({})), reply(200, json!({}))], 5).unwrap_err().contains("Reconnect"));
        assert!(GitHub.read_search(&account, &[reply(0, json!(null))], 5).unwrap_err().contains("in time"));
    }
}
