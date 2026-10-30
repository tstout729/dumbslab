//! GitLab: previews of linked issues and merge requests, on gitlab.com or a self-managed GitLab.
//! People connect with a personal access token (read_api), or sign in to gitlab.com.
//!
//! Docs: https://docs.gitlab.com/api/issues/#retrieve-a-single-project-issue,
//! https://docs.gitlab.com/api/merge_requests/#retrieve-a-single-merge-request,
//! https://docs.gitlab.com/api/rest/authentication/, https://docs.gitlab.com/api/oauth2/,
//! https://docs.gitlab.com/user/profile/personal_access_tokens/

use serde_json::{Value, json};

use crate::connect::{
    Account, Connector, Credential, Detail, Field, Hit, HttpCall, HttpReply, OAuthSpec, Preview, ProviderInfo, excerpt, host_of,
    http_error, opt, path_of, s,
};

pub struct GitLab;

const DEFAULT_HOST: &str = "gitlab.com";

static INFO: ProviderInfo = ProviderInfo {
    id: "gitlab",
    name: "GitLab",
    about: "Preview linked issues and merge requests, on gitlab.com or your own GitLab.",
    search: false,
    preview: true,
    // Signing in works for gitlab.com only; a self-managed GitLab connects with a token.
    oauth: Some(OAuthSpec {
        authorize_url: "https://gitlab.com/oauth/authorize",
        token_url: "https://gitlab.com/oauth/token",
        scopes: &["read_api"],
        scope_param: "scope",
        scope_separator: " ",
        extra: &[],
        pkce: true,
    }),
    token_fields: &[
        Field {
            key: "token",
            label: "Personal access token",
            help: "A token with the read_api scope. In GitLab: your avatar › Edit profile › Access › Personal access tokens.",
            secret: true,
            optional: false,
        },
        Field {
            key: "base_url",
            label: "GitLab address",
            help: "For a self-managed GitLab, its address, like https://gitlab.example.com. Leave empty for gitlab.com.",
            secret: false,
            optional: true,
        },
    ],
    token_help: "https://gitlab.com/-/user_settings/personal_access_tokens?name=DumbSlab&scopes=read_api",
};

fn api(host: &str, path: &str, token: &str) -> HttpCall {
    HttpCall::get(format!("https://{host}/api/v4{path}")).bearer(token)
}

/// The host of the GitLab address a person typed: `https://` and a hostname, nothing else (no
/// port, path, query or credentials, and not an IP address or a name only a local network knows).
/// Empty means gitlab.com.
pub fn valid_host(base_url: &str) -> Result<String, String> {
    let typed = base_url.trim();
    if typed.is_empty() {
        return Ok(DEFAULT_HOST.into());
    }
    let bad = || format!("\"GitLab address\" must look like https://gitlab.example.com, with nothing after the name; `{typed}` doesn't.");
    let lower = typed.to_ascii_lowercase();
    let host = lower.strip_prefix("https://").ok_or_else(bad)?;
    let host = host.strip_suffix('/').unwrap_or(host);
    let labels: Vec<&str> = host.split('.').collect();
    let tld = labels.last().copied().unwrap_or_default();
    let ok = host.len() <= 253
        && labels.len() >= 2
        && labels.iter().all(|l| {
            (1..=63).contains(&l.len())
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
        // A letter in the last label rules out IP addresses.
        && tld.bytes().any(|b| b.is_ascii_lowercase())
        && !matches!(tld, "localhost" | "local" | "internal" | "arpa");
    if !ok {
        return Err(bad());
    }
    Ok(host.to_string())
}

/// The GitLab an account is on. Without an account (nobody connected), gitlab.com.
fn host_for(account: &Account) -> Option<&str> {
    if account.settings.is_null() {
        return Some(DEFAULT_HOST);
    }
    account.settings["host"].as_str().filter(|h| !h.is_empty())
}

/// One part of a group or project path.
fn valid_segment(p: &str) -> bool {
    !p.is_empty()
        && p != "."
        && p != ".."
        && !p.starts_with('-')
        && p.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

/// `acme/tools/api!34` → (`acme/tools/api`, true, `34`); issues use `#`.
fn split(target: &str) -> (&str, bool, &str) {
    let i = target.rfind(['#', '!']).unwrap_or_default();
    (&target[..i], target[i..].starts_with('!'), target.get(i + 1..).unwrap_or_default())
}

fn handles(users: &Value) -> String {
    users.as_array().into_iter().flatten().filter_map(|u| u["username"].as_str()).map(|u| format!("@{u}")).collect::<Vec<_>>().join(", ")
}

impl Connector for GitLab {
    fn info(&self) -> &'static ProviderInfo {
        &INFO
    }

    fn profile(&self, cred: &Credential) -> Vec<HttpCall> {
        match valid_host(cred.field("base_url")) {
            Ok(host) => vec![api(&host, "/user", &cred.token)],
            // Nothing goes to an address that isn't one; read_profile says what's wrong.
            Err(_) => vec![],
        }
    }

    fn read_profile(&self, cred: &Credential, replies: &[HttpReply]) -> Result<Account, String> {
        let host = valid_host(cred.field("base_url"))?;
        let r = replies.first().cloned().unwrap_or_default();
        if !r.ok() {
            return Err(match r.status {
                0 => format!("{host} didn't answer. Check the GitLab address."),
                401 => "GitLab rejected that token. Check it was copied whole and hasn't expired.".into(),
                403 => "GitLab refused that token: give it the read_api scope.".into(),
                _ => http_error("GitLab", &r),
            });
        }
        let username = s(&r.json()["username"]);
        if username.is_empty() {
            return Err(format!("{host} didn't say whose token that is. Check the GitLab address."));
        }
        let label = if host == DEFAULT_HOST { format!("@{username}") } else { format!("@{username} on {host}") };
        Ok(Account { label, settings: json!({ "host": host, "username": username }) })
    }

    // Previews only: GitLab isn't searched.
    fn search(&self, _cred: &Credential, _account: &Account, _q: &str, _limit: usize) -> Vec<HttpCall> {
        vec![]
    }

    fn read_search(&self, _account: &Account, _replies: &[HttpReply], _limit: usize) -> Result<Vec<Hit>, String> {
        Ok(vec![])
    }

    /// `https://gitlab.com/acme/tools/api/-/issues/12` → `acme/tools/api#12`, and
    /// `…/-/merge_requests/34` → `acme/tools/api!34`. Only links to the account's own GitLab.
    fn preview_target(&self, account: &Account, url: &str) -> Option<String> {
        let host = host_for(account)?;
        if host_of(url)? != host.strip_prefix("www.").unwrap_or(host) {
            return None;
        }
        let path = path_of(url);
        let dash = path.iter().position(|p| p == "-")?;
        let (project, rest) = path.split_at(dash);
        let sep = match rest.get(1)?.as_str() {
            "issues" => '#',
            "merge_requests" => '!',
            _ => return None,
        };
        let iid = rest.get(2)?.parse::<u64>().ok()?;
        // A namespace and a project at least; GitLab nests groups up to 20 deep.
        let ok = (2..=21).contains(&project.len()) && project.iter().all(|p| valid_segment(p));
        ok.then(|| format!("{}{sep}{iid}", project.join("/")))
    }

    fn preview(&self, cred: &Credential, account: &Account, target: &str) -> Vec<HttpCall> {
        let Some(host) = host_for(account) else { return vec![] };
        let (project, mr, iid) = split(target);
        let kind = if mr { "merge_requests" } else { "issues" };
        vec![api(host, &format!("/projects/{}/{kind}/{iid}", urlencoding::encode(project)), &cred.token)]
    }

    fn read_preview(&self, account: &Account, target: &str, replies: &[HttpReply]) -> Result<Preview, String> {
        let (project, mr, iid) = split(target);
        let r = replies.first().cloned().unwrap_or_default();
        if !r.ok() {
            return Err(match r.status {
                404 => format!("GitLab has no such {}, or the connected account can't see it.", if mr { "merge request" } else { "issue" }),
                _ => http_error("GitLab", &r),
            });
        }
        let i = r.json();
        let state = match s(&i["state"]).as_str() {
            "opened" if i["draft"] == true => "draft".to_string(),
            "opened" => "open".to_string(),
            other => other.to_string(),
        };
        let labels: Vec<String> =
            i["labels"].as_array().into_iter().flatten().filter_map(|l| l.as_str().or(l["name"].as_str())).map(str::to_string).collect();
        let mut details = vec![];
        if !labels.is_empty() {
            details.push(Detail { label: "Labels".into(), value: labels.join(", ") });
        }
        if let Some(m) = opt(&i["milestone"]["title"]) {
            details.push(Detail { label: "Milestone".into(), value: m });
        }
        if mr {
            let reviewers = handles(&i["reviewers"]);
            if !reviewers.is_empty() {
                details.push(Detail { label: "Reviewers".into(), value: reviewers });
            }
            if let (Some(from), Some(to)) = (opt(&i["source_branch"]), opt(&i["target_branch"])) {
                details.push(Detail { label: "Branches".into(), value: format!("{from} → {to}") });
            }
        }
        let sep = if mr { '!' } else { '#' };
        let host = host_for(account).unwrap_or(DEFAULT_HOST);
        let kind = if mr { "merge_requests" } else { "issues" };
        Ok(Preview {
            provider: "gitlab".into(),
            kind: if mr { "merge_request" } else { "issue" }.into(),
            title: s(&i["title"]),
            url: opt(&i["web_url"]).unwrap_or_else(|| format!("https://{host}/{project}/-/{kind}/{iid}")),
            reference: opt(&i["references"]["full"]).unwrap_or_else(|| format!("{project}{sep}{iid}")),
            status: Some(state).filter(|s| !s.is_empty()),
            assignee: Some(handles(&i["assignees"])).filter(|a| !a.is_empty()),
            author: opt(&i["author"]["username"]).map(|u| format!("@{u}")),
            created_at: opt(&i["created_at"]),
            updated_at: opt(&i["updated_at"]),
            description: excerpt(i["description"].as_str().unwrap_or_default(), 300),
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

    fn token(base_url: &str) -> Credential {
        Credential { token: "t".into(), fields: [("base_url".to_string(), base_url.to_string())].into(), ..Default::default() }
    }

    fn on(host: &str) -> Account {
        Account { label: "@ada".into(), settings: json!({ "host": host, "username": "ada" }) }
    }

    #[test]
    fn profile_checks_the_gitlab_address() {
        let cred = Credential { token: "t".into(), ..Default::default() };
        let calls = GitLab.profile(&cred);
        assert_eq!(calls[0].url, "https://gitlab.com/api/v4/user");
        assert!(calls[0].headers.contains(&("authorization".into(), "Bearer t".into())));
        let account = GitLab.read_profile(&cred, &[reply(200, json!({ "username": "ada" }))]).unwrap();
        assert_eq!((account.label.as_str(), &account.settings["host"]), ("@ada", &json!("gitlab.com")));
        // A self-managed GitLab, normalized.
        let own = token(" HTTPS://GitLab.Example.com/ ");
        assert_eq!(GitLab.profile(&own)[0].url, "https://gitlab.example.com/api/v4/user");
        let account = GitLab.read_profile(&own, &[reply(200, json!({ "username": "ada" }))]).unwrap();
        assert_eq!((account.label.as_str(), &account.settings["host"]), ("@ada on gitlab.example.com", &json!("gitlab.example.com")));
        // Only an https hostname: nothing is sent anywhere else.
        for bad in [
            "http://gitlab.example.com",
            "gitlab.example.com",
            "https://gitlab.example.com/gitlab",
            "https://gitlab.example.com:8443",
            "https://ada@gitlab.example.com",
            "https://evil.test\\@gitlab.com",
            "https://gitlab.example.com?x=1",
            "https://gitlab.example.com#x",
            "https://gitlab.example.com./",
            "https://gitlab.example.com/../x",
            "https://10.0.0.1",
            "https://[::1]",
            "https://localhost",
            "https://gitlab.local",
            "https://gitlab",
            "https://-x.example.com",
            "https://gitlab .example.com",
        ] {
            assert!(GitLab.profile(&token(bad)).is_empty(), "{bad}");
            assert!(GitLab.read_profile(&token(bad), &[]).unwrap_err().contains("GitLab address"), "{bad}");
        }
        assert!(GitLab.read_profile(&cred, &[reply(401, json!({}))]).unwrap_err().contains("rejected"));
        assert!(GitLab.read_profile(&cred, &[reply(403, json!({}))]).unwrap_err().contains("read_api"));
        assert!(GitLab.read_profile(&own, &[reply(0, json!(null))]).unwrap_err().contains("gitlab.example.com didn't answer"));
        // Something that isn't GitLab answering.
        let not_gitlab = HttpReply { status: 200, body: "<html></html>".into() };
        assert!(GitLab.read_profile(&own, &[not_gitlab]).unwrap_err().contains("didn't say whose"));
    }

    #[test]
    fn recognizes_links_on_the_connected_gitlab_only() {
        let com = on("gitlab.com");
        assert_eq!(GitLab.preview_target(&com, "https://gitlab.com/acme/api/-/issues/12").as_deref(), Some("acme/api#12"));
        assert_eq!(
            GitLab.preview_target(&com, "https://www.gitlab.com/acme/tools/api/-/merge_requests/34/diffs?w=1#note_9").as_deref(),
            Some("acme/tools/api!34")
        );
        // Nobody connected: gitlab.com links still say they're GitLab's.
        assert_eq!(GitLab.preview_target(&Account::default(), "https://gitlab.com/a/b/-/issues/1").as_deref(), Some("a/b#1"));
        let own = on("gitlab.example.com");
        assert_eq!(GitLab.preview_target(&own, "https://gitlab.example.com/a/b/c/-/issues/5").as_deref(), Some("a/b/c#5"));
        for (account, no) in [
            (&com, "https://gitlab.example.com/a/b/-/issues/5"),
            (&own, "https://gitlab.com/a/b/-/issues/5"),
            (&com, "https://gitlab.com.evil.test/a/b/-/issues/1"),
            (&com, "https://evilgitlab.com/a/b/-/issues/1"),
            (&own, "https://example.com/a/b/-/issues/1"),
            (&own, "https://gitlab.example.com@evil.test/a/b/-/issues/1"),
            (&com, "https://gitlab.com/acme/api/issues/12"),
            (&com, "https://gitlab.com/acme/-/issues/12"),
            (&com, "https://gitlab.com/acme/api/-/issues/x"),
            (&com, "https://gitlab.com/acme/api/-/issues"),
            (&com, "https://gitlab.com/acme/api/-/pipelines/12"),
            (&com, "https://gitlab.com/acme/a%2Fb/-/issues/12"),
            (&com, "https://gitlab.com/acme/../api/-/issues/12"),
            (&com, "https://gitlab.com/acme/a%3Fb/-/issues/12"),
        ] {
            assert_eq!(GitLab.preview_target(account, no), None, "{no}");
        }
    }

    #[test]
    fn previews_issues_and_merge_requests() {
        let cred = Credential { token: "t".into(), ..Default::default() };
        let calls = GitLab.preview(&cred, &on("gitlab.com"), "acme/tools/api!34");
        assert_eq!(calls[0].url, "https://gitlab.com/api/v4/projects/acme%2Ftools%2Fapi/merge_requests/34");
        assert!(calls[0].headers.contains(&("authorization".into(), "Bearer t".into())));
        let own = on("gitlab.example.com");
        assert_eq!(GitLab.preview(&cred, &own, "a/b#5")[0].url, "https://gitlab.example.com/api/v4/projects/a%2Fb/issues/5");

        let mr = json!({ "title": "Retry deploys", "state": "merged", "web_url": "https://gitlab.com/acme/tools/api/-/merge_requests/34",
            "references": { "full": "acme/tools/api!34" }, "assignees": [{ "username": "bo" }, { "username": "di" }],
            "reviewers": [{ "username": "cy" }], "author": { "username": "ada" }, "labels": ["ops", "deploy"],
            "milestone": { "title": "v2" }, "source_branch": "retry", "target_branch": "main",
            "created_at": "2026-10-01T00:00:00Z", "updated_at": "2026-10-02T00:00:00Z", "description": "Retries\n\nthe **deploy**." });
        let p = GitLab.read_preview(&on("gitlab.com"), "acme/tools/api!34", &[reply(200, mr)]).unwrap();
        assert_eq!((p.kind.as_str(), p.reference.as_str(), p.status.as_deref()), ("merge_request", "acme/tools/api!34", Some("merged")));
        assert_eq!((p.assignee.as_deref(), p.author.as_deref()), (Some("@bo, @di"), Some("@ada")));
        assert_eq!(p.description, "Retries the **deploy**.");
        let labels: Vec<&str> = p.details.iter().map(|d| d.label.as_str()).collect();
        assert_eq!(labels, ["Labels", "Milestone", "Reviewers", "Branches"]);
        assert_eq!(p.details[3].value, "retry → main");

        let issue = json!({ "title": "Login loops", "state": "opened", "author": { "username": "bo" }, "assignees": [] });
        let p = GitLab.read_preview(&own, "a/b#5", &[reply(200, issue)]).unwrap();
        assert_eq!((p.kind.as_str(), p.status.as_deref(), p.assignee.as_deref()), ("issue", Some("open"), None));
        assert_eq!((p.url.as_str(), p.reference.as_str()), ("https://gitlab.example.com/a/b/-/issues/5", "a/b#5"));
        let draft = json!({ "title": "WIP", "state": "opened", "draft": true });
        assert_eq!(GitLab.read_preview(&own, "a/b!6", &[reply(200, draft)]).unwrap().status.as_deref(), Some("draft"));

        assert!(GitLab.read_preview(&own, "a/b!6", &[reply(404, json!({}))]).unwrap_err().contains("no such merge request"));
        assert!(GitLab.read_preview(&own, "a/b#5", &[reply(404, json!({}))]).unwrap_err().contains("can't see"));
        assert!(GitLab.read_preview(&own, "a/b#5", &[reply(401, json!({}))]).unwrap_err().contains("Reconnect"));
        assert!(GitLab.read_preview(&own, "a/b#5", &[reply(0, json!(null))]).unwrap_err().contains("in time"));
    }
}
