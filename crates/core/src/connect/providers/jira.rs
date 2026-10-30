//! Jira Cloud: issues the connected account can see on one Atlassian site. People connect with an
//! Atlassian API token for their site, or by signing in with Atlassian (OAuth 2.0 3LO), after
//! which requests go through Atlassian's gateway with the site's cloud id. Signing in needs the
//! host's Atlassian app to include the User identity API (`read:me`). The Atlassian parts here
//! (sites, signing in, times, search words) are shared with Confluence.
//!
//! Atlassian's docs:
//! - Issue search, `GET /rest/api/3/search/jql` (`/rest/api/3/search` is being removed):
//!   https://developer.atlassian.com/cloud/jira/platform/rest/v3/api-group-issue-search/
//! - Issues: https://developer.atlassian.com/cloud/jira/platform/rest/v3/api-group-issues/
//! - Current user: https://developer.atlassian.com/cloud/jira/platform/rest/v3/api-group-myself/
//! - Signing in, cloud ids, the gateway, rotating refresh tokens and `/me`:
//!   https://developer.atlassian.com/cloud/jira/platform/oauth-2-3lo-apps/
//! - Scopes (classic ones are recommended): https://developer.atlassian.com/cloud/jira/platform/scopes-for-oauth-2-3LO-and-forge-apps/
//! - API tokens (scoped ones only work through the gateway):
//!   https://support.atlassian.com/atlassian-account/docs/manage-api-tokens-for-your-atlassian-account/
//! - Descriptions (Atlassian Document Format): https://developer.atlassian.com/cloud/jira/platform/apis/document/structure/
//! - Text search: https://support.atlassian.com/jira-software-cloud/docs/search-for-work-items-using-the-text-field/

use chrono::{DateTime, Utc};
use serde_json::{Map, Value, json};

use crate::connect::{
    Account, Connector, Credential, Detail, Field, Hit, HttpCall, HttpReply, OAuthApp, OAuthSpec, Preview, ProviderInfo, excerpt, host_of,
    http_error, opt, path_of, s,
};
use crate::util::ts;

pub struct Jira;

/// Atlassian's API gateway, for accounts connected by signing in.
const GATEWAY: &str = "https://api.atlassian.com";
const TOKEN_URL: &str = "https://auth.atlassian.com/oauth/token";
/// Search issues and read them; who the person is; refresh tokens.
const SCOPES: &[&str] = &["read:jira-work", "read:me", "offline_access"];
/// What search and previews read of an issue. Search answers with only ids unless asked.
const SEARCH_FIELDS: &str = "summary,status,project,updated,reporter,description";
const ISSUE_FIELDS: &str = "summary,status,assignee,reporter,created,updated,description,issuetype,project,priority";

/// Signing in with Atlassian. A refresh token comes only with `offline_access`, and Atlassian
/// replaces it on every refresh.
pub const fn oauth(scopes: &'static [&'static str]) -> OAuthSpec {
    OAuthSpec {
        authorize_url: "https://auth.atlassian.com/authorize",
        token_url: TOKEN_URL,
        scopes,
        scope_param: "scope",
        scope_separator: " ",
        extra: &[("audience", "api.atlassian.com"), ("prompt", "consent")],
        pkce: false,
    }
}

/// What a person fills in to connect Jira or Confluence with an API token.
pub const TOKEN_FIELDS: &[Field] = &[
    Field { key: "site", label: "Site", help: "Your Atlassian site's address, like `acme.atlassian.net`.", secret: false, optional: false },
    Field { key: "email", label: "Email", help: "The email address you sign in to Atlassian with.", secret: false, optional: false },
    Field {
        key: "token",
        label: "API token",
        help: "An API token for your Atlassian account. Choose \"Create API token\", not the one with scopes.",
        secret: true,
        optional: false,
    },
];
pub const TOKEN_HELP: &str = "https://id.atlassian.com/manage-profile/security/api-tokens";

static INFO: ProviderInfo = ProviderInfo {
    id: "jira",
    name: "Jira",
    about: "Search issues, and preview linked issues.",
    search: true,
    preview: true,
    oauth: Some(oauth(SCOPES)),
    token_fields: TOKEN_FIELDS,
    token_help: TOKEN_HELP,
};

/// One label of a host name: lowercase letters, digits and inner hyphens.
fn label_ok(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 63
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// The host in a site's address, with or without `https://` or a path. No ports or user names.
fn bare_host(input: &str) -> Option<String> {
    let lower = input.trim().to_ascii_lowercase();
    let rest = lower.strip_prefix("https://").or_else(|| lower.strip_prefix("http://")).unwrap_or(&lower);
    let host = rest.split(['/', '?', '#']).next()?;
    (host.len() <= 253 && host.contains('.') && host.split('.').all(label_ok)).then(|| host.to_string())
}

/// The site a person typed, as a bare host. Only one name under `atlassian.net`, so their token
/// can't be sent anywhere else.
pub fn site_host(input: &str) -> Result<String, String> {
    bare_host(input)
        .filter(|h| h.strip_suffix(".atlassian.net").is_some_and(label_ok))
        .ok_or_else(|| "The site should be your Atlassian address, like acme.atlassian.net.".into())
}

/// The connected site's host, as [`read_account`] saved it.
pub fn site_of(account: &Account) -> Option<String> {
    account.settings["site"].as_str().and_then(bare_host)
}

fn cloud_id_ok(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-')
}

/// Connected with an API token, rather than by signing in.
pub fn token_mode(cred: &Credential) -> bool {
    cred.fields.contains_key("site")
}

pub fn reconnect(name: &str) -> String {
    format!("{name} needs you to connect it again (Settings › Connected apps).")
}

/// A GET for `path` on the connected site, as Atlassian's REST docs write it (`/rest/api/3/…`,
/// `/wiki/rest/api/…`): to the site itself with an API token, or through the gateway with the
/// site's cloud id. `None` when the saved site or cloud id isn't valid.
pub fn site_get(product: &str, cred: &Credential, account: &Account, path: &str) -> Option<HttpCall> {
    let call = if token_mode(cred) {
        let host = site_host(cred.field("site")).ok()?;
        HttpCall::get(format!("https://{host}{path}")).basic(cred.field("email"), &cred.token)
    } else {
        let id = account.settings["cloud_id"].as_str().filter(|id| cloud_id_ok(id))?;
        HttpCall::get(format!("{GATEWAY}/ex/{product}/{id}{path}")).bearer(&cred.token)
    };
    Some(call.header("accept", "application/json"))
}

/// Requests that check a connection and say whose it is. With an API token: the person on the
/// site (`me_path`). Signed in: the sites the token reaches, and the person's Atlassian profile.
pub fn profile_calls(product: &str, me_path: &str, cred: &Credential) -> Vec<HttpCall> {
    if token_mode(cred) {
        return site_get(product, cred, &Account::default(), me_path).into_iter().collect();
    }
    ["/oauth/token/accessible-resources", "/me"]
        .iter()
        .map(|p| HttpCall::get(format!("{GATEWAY}{p}")).bearer(&cred.token).header("accept", "application/json"))
        .collect()
}

/// Reads the answers to [`profile_calls`]. Atlassian lists each site once per product, so `scope`
/// (one only this product has) picks the product's sites.
pub fn read_account(name: &str, scope: &str, cred: &Credential, replies: &[HttpReply]) -> Result<Account, String> {
    let first = replies.first().cloned().unwrap_or_default();
    if token_mode(cred) {
        let host = site_host(cred.field("site"))?;
        if !first.ok() {
            return Err(match first.status {
                401 => format!("Atlassian rejected that email and API token for {host}. Check both, and that the token hasn't expired."),
                404 => format!("{host} has no {name}, or the address is wrong."),
                _ => http_error(name, &first),
            });
        }
        let me = first.json();
        // Confluence answers with an anonymous person, rather than refusing, when it doesn't know them.
        if opt(&me["accountId"]).is_none() || me["type"] == "anonymous" {
            return Err(format!("Atlassian didn't accept that email and API token for {host}."));
        }
        // People can hide their email; the one they typed signed in, so it's theirs.
        let who = opt(&me["emailAddress"]).or_else(|| opt(&me["email"])).unwrap_or_else(|| cred.field("email").to_string());
        return Ok(Account { label: format!("{who} on {host}"), settings: json!({ "site": host }) });
    }
    if !first.ok() {
        return Err(http_error(name, &first));
    }
    let mut sites: Vec<(String, String)> = first
        .json()
        .as_array()
        .into_iter()
        .flatten()
        .filter(|r| r["scopes"].as_array().is_some_and(|granted| granted.iter().any(|g| g == scope)))
        .filter_map(|r| Some((bare_host(r["url"].as_str()?)?, s(&r["id"]))))
        .filter(|(_, id)| cloud_id_ok(id))
        .collect();
    // Atlassian lists sites in no particular order; pick the same one every time.
    sites.sort();
    let Some((host, cloud_id)) = sites.into_iter().next() else {
        return Err(format!("Atlassian didn't give access to a site with {name}. Connect again and choose a site that has {name}."));
    };
    let me = replies.get(1).filter(|r| r.ok()).map(|r| r.json()).unwrap_or_default();
    let label = match opt(&me["email"]).or_else(|| opt(&me["name"])) {
        Some(who) => format!("{who} on {host}"),
        None => host.clone(),
    };
    Ok(Account { label, settings: json!({ "site": host, "cloud_id": cloud_id }) })
}

/// Atlassian takes token requests as JSON.
pub fn token_call(app: &OAuthApp, form: Vec<(String, String)>) -> HttpCall {
    let mut body: Map<String, Value> = form.into_iter().map(|(k, v)| (k, Value::String(v))).collect();
    body.insert("client_id".into(), app.client_id.clone().into());
    body.insert("client_secret".into(), app.client_secret.clone().into());
    HttpCall::post_json(TOKEN_URL, &Value::Object(body)).header("accept", "application/json")
}

/// An Atlassian time (`2026-10-01T09:30:00.000+0000`, or RFC 3339) the way DumbSlab writes times.
pub fn when(v: &Value) -> Option<String> {
    let raw = opt(v)?;
    let parsed = DateTime::parse_from_rfc3339(&raw).or_else(|_| DateTime::parse_from_str(&raw, "%Y-%m-%dT%H:%M:%S%.f%z"));
    Some(parsed.map(|t| ts(t.with_timezone(&Utc))).unwrap_or(raw))
}

/// The words to search for, safe inside a quoted JQL or CQL string. Anything but letters, digits
/// and a little punctuation becomes a space, and words are lowercased: quotes, backslashes, the
/// text search's operators (`+ - ! ( ) * ? ~ :`…) and `AND`/`OR`/`NOT` would change the query.
pub fn search_words(q: &str) -> String {
    let kept: String = q
        .chars()
        .map(|c| if c.is_alphanumeric() || matches!(c, '.' | ',' | '\'' | '_' | '@' | '#' | '$' | '%') { c } else { ' ' })
        .collect();
    kept.to_lowercase().split_whitespace().collect::<Vec<_>>().join(" ")
}

/// An issue key like `PROJ-123`, uppercased.
fn issue_key(text: &str) -> Option<String> {
    let (project, number) = text.split_once('-')?;
    let ok = project.len() <= 255
        && project.starts_with(|c: char| c.is_ascii_alphabetic())
        && project.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        && !number.is_empty()
        && number.len() <= 18
        && number.bytes().all(|b| b.is_ascii_digit());
    ok.then(|| format!("{}-{number}", project.to_ascii_uppercase()))
}

/// A query parameter's value in a URL.
fn query_param(url: &str, name: &str) -> Option<String> {
    let query = url.split('#').next()?.split_once('?')?.1;
    let (_, value) = query.split('&').filter_map(|p| p.split_once('=')).find(|(k, _)| *k == name)?;
    urlencoding::decode(value).ok().map(|v| v.into_owned())
}

/// The text of a description: Atlassian Document Format (a tree of nodes, with the words in
/// `text` nodes), or plain text from older issues.
pub fn adf_text(doc: &Value) -> String {
    fn walk(node: &Value, out: &mut String) {
        let attrs = &node["attrs"];
        match node["type"].as_str().unwrap_or_default() {
            "text" => out.push_str(node["text"].as_str().unwrap_or_default()),
            "hardBreak" => out.push('\n'),
            "mention" | "status" => out.push_str(attrs["text"].as_str().unwrap_or_default()),
            "emoji" => out.push_str(attrs["text"].as_str().or(attrs["shortName"].as_str()).unwrap_or_default()),
            "inlineCard" => out.push_str(attrs["url"].as_str().unwrap_or_default()),
            _ => {}
        }
        // Paragraphs, headings, list items and the like each end a line.
        if let Some(children) = node["content"].as_array() {
            children.iter().for_each(|c| walk(c, out));
            out.push('\n');
        }
    }
    if let Some(text) = doc.as_str() {
        return text.to_string();
    }
    let mut out = String::new();
    walk(doc, &mut out);
    out
}

impl Connector for Jira {
    fn info(&self) -> &'static ProviderInfo {
        &INFO
    }

    fn profile(&self, cred: &Credential) -> Vec<HttpCall> {
        profile_calls("jira", "/rest/api/3/myself", cred)
    }

    fn read_profile(&self, cred: &Credential, replies: &[HttpReply]) -> Result<Account, String> {
        read_account("Jira", "read:jira-work", cred, replies)
    }

    /// Jira has no relevance order, so the most recently updated come first.
    fn search(&self, cred: &Credential, account: &Account, q: &str, limit: usize) -> Vec<HttpCall> {
        let words = search_words(q);
        if words.is_empty() {
            return vec![];
        }
        let jql = urlencoding::encode(&format!("text ~ \"{words}\" ORDER BY updated DESC")).into_owned();
        let path = format!("/rest/api/3/search/jql?jql={jql}&maxResults={}&fields={SEARCH_FIELDS}", limit.clamp(1, 20));
        site_get("jira", cred, account, &path).into_iter().collect()
    }

    fn read_search(&self, account: &Account, replies: &[HttpReply], limit: usize) -> Result<Vec<Hit>, String> {
        let site = site_of(account).ok_or_else(|| reconnect("Jira"))?;
        // Nothing worth searching for (only punctuation) sent nothing.
        let Some(r) = replies.first() else { return Ok(vec![]) };
        if !r.ok() {
            return Err(match r.status {
                400 => "Jira couldn't search for that. Try other words.".into(),
                _ => http_error("Jira", r),
            });
        }
        Ok(r.json()["issues"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|i| {
                let key = issue_key(i["key"].as_str()?)?;
                let f = &i["fields"];
                let context = [Some(key.clone()), opt(&f["status"]["name"]), opt(&f["project"]["name"])].into_iter().flatten();
                Some(Hit {
                    provider: "jira".into(),
                    kind: "issue".into(),
                    title: s(&f["summary"]),
                    url: format!("https://{site}/browse/{key}"),
                    context: context.collect::<Vec<_>>().join(" · "),
                    snippet: excerpt(&adf_text(&f["description"]), 240),
                    updated_at: when(&f["updated"]),
                    author: opt(&f["reporter"]["displayName"]),
                })
            })
            .take(limit)
            .collect())
    }

    /// Links to an issue on the connected site: `/browse/PROJ-123`, `/jira/…/issues/PROJ-123`, or a
    /// board or list with `?selectedIssue=PROJ-123`.
    fn preview_target(&self, account: &Account, url: &str) -> Option<String> {
        if host_of(url)? != site_of(account)? {
            return None;
        }
        let path = path_of(url);
        match path.first().map(String::as_str) {
            Some("browse") => issue_key(path.get(1)?),
            Some("jira") => query_param(url, "selectedIssue").and_then(|k| issue_key(&k)).or_else(|| {
                let at = path.iter().position(|p| p == "issues")?;
                issue_key(path.get(at + 1)?)
            }),
            _ => None,
        }
    }

    fn preview(&self, cred: &Credential, account: &Account, target: &str) -> Vec<HttpCall> {
        let Some(key) = issue_key(target) else { return vec![] };
        site_get("jira", cred, account, &format!("/rest/api/3/issue/{key}?fields={ISSUE_FIELDS}")).into_iter().collect()
    }

    fn read_preview(&self, account: &Account, target: &str, replies: &[HttpReply]) -> Result<Preview, String> {
        let site = site_of(account).ok_or_else(|| reconnect("Jira"))?;
        let r = replies.first().cloned().unwrap_or_default();
        if !r.ok() {
            return Err(match r.status {
                404 => format!("Jira has no issue {target}, or the connected account can't see it."),
                _ => http_error("Jira", &r),
            });
        }
        let i = r.json();
        let f = &i["fields"];
        // A moved issue answers with its new key.
        let key = i["key"].as_str().and_then(issue_key).or_else(|| issue_key(target)).unwrap_or_default();
        let details = [("Type", &f["issuetype"]["name"]), ("Project", &f["project"]["name"]), ("Priority", &f["priority"]["name"])]
            .into_iter()
            .filter_map(|(label, v)| Some(Detail { label: label.into(), value: opt(v)? }))
            .collect();
        Ok(Preview {
            provider: "jira".into(),
            kind: "issue".into(),
            title: s(&f["summary"]),
            url: format!("https://{site}/browse/{key}"),
            reference: key,
            status: opt(&f["status"]["name"]),
            assignee: opt(&f["assignee"]["displayName"]),
            author: opt(&f["reporter"]["displayName"]),
            created_at: when(&f["created"]),
            updated_at: when(&f["updated"]),
            description: excerpt(&adf_text(&f["description"]), 300),
            details,
        })
    }

    fn token_request(&self, app: &OAuthApp, form: Vec<(String, String)>) -> HttpCall {
        token_call(app, form)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;

    const CLOUD: &str = "1324a887-45db-1bf4-1e99-ef0ff456d421";

    fn reply(status: u16, body: Value) -> HttpReply {
        HttpReply { status, body: body.to_string() }
    }

    fn token_cred(site: &str) -> Credential {
        Credential {
            token: "tok".into(),
            fields: [("site".to_string(), site.to_string()), ("email".to_string(), "ada@acme.com".to_string())].into(),
            ..Default::default()
        }
    }

    fn signed_in() -> Credential {
        Credential { token: "at".into(), refresh_token: Some("rt".into()), ..Default::default() }
    }

    fn site_account() -> Account {
        Account { label: "ada@acme.com on acme.atlassian.net".into(), settings: json!({ "site": "acme.atlassian.net" }) }
    }

    fn header<'a>(call: &'a HttpCall, name: &str) -> Option<&'a str> {
        call.headers.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }

    #[test]
    fn sites_must_be_on_atlassian() {
        for (typed, host) in [
            ("acme.atlassian.net", "acme.atlassian.net"),
            (" https://Acme.atlassian.net/ ", "acme.atlassian.net"),
            ("http://acme-2.atlassian.net/jira/your-work?x=1", "acme-2.atlassian.net"),
        ] {
            assert_eq!(site_host(typed).as_deref(), Ok(host), "{typed}");
        }
        for bad in [
            "",
            "acme",
            "atlassian.net",
            ".atlassian.net",
            "-acme.atlassian.net",
            "a.b.atlassian.net",
            "acme.atlassian.net.evil.test",
            "evil.test/acme.atlassian.net",
            "evil.test?.atlassian.net",
            "evil.test#.atlassian.net",
            "evil.test\\.atlassian.net",
            "acme.atlassian.net@evil.test",
            "ada@acme.atlassian.net",
            "acme.atlassian.net:8443",
            "ac me.atlassian.net",
            "acme.jira.com",
            "ftp://acme.atlassian.net",
        ] {
            assert!(site_host(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn connects_with_an_api_token() {
        let cred = token_cred("https://Acme.atlassian.net/");
        let calls = Jira.profile(&cred);
        assert_eq!(calls[0].url, "https://acme.atlassian.net/rest/api/3/myself");
        let basic = format!("Basic {}", STANDARD.encode("ada@acme.com:tok"));
        assert_eq!(header(&calls[0], "authorization"), Some(basic.as_str()));
        let me = json!({ "accountId": "5b10", "emailAddress": "ada@acme.com", "displayName": "Ada" });
        let account = Jira.read_profile(&cred, &[reply(200, me)]).unwrap();
        assert_eq!(account.label, "ada@acme.com on acme.atlassian.net");
        assert_eq!(account.settings, json!({ "site": "acme.atlassian.net" }));
        // A hidden email falls back to the one typed.
        let account = Jira.read_profile(&cred, &[reply(200, json!({ "accountId": "5b10", "displayName": "Ada" }))]).unwrap();
        assert_eq!(account.label, "ada@acme.com on acme.atlassian.net");
        assert!(Jira.read_profile(&cred, &[reply(401, json!({}))]).unwrap_err().contains("rejected that email and API token"));
        assert!(Jira.read_profile(&cred, &[reply(404, json!({}))]).unwrap_err().contains("acme.atlassian.net has no Jira"));
        assert!(Jira.read_profile(&cred, &[reply(0, json!(null))]).unwrap_err().contains("in time"));
        assert!(Jira.read_profile(&cred, &[reply(200, json!({}))]).is_err());
        // A site elsewhere is refused before anything is sent.
        let elsewhere = token_cred("acme.atlassian.net.evil.test");
        assert!(Jira.profile(&elsewhere).is_empty());
        assert!(Jira.read_profile(&elsewhere, &[]).unwrap_err().contains("like acme.atlassian.net"));
        assert!(Jira.search(&elsewhere, &site_account(), "deploy", 5).is_empty());
    }

    #[test]
    fn connects_by_signing_in() {
        let spec = INFO.oauth.unwrap();
        assert_eq!(spec.authorize_url, "https://auth.atlassian.com/authorize");
        assert!(spec.extra.contains(&("audience", "api.atlassian.com")) && spec.extra.contains(&("prompt", "consent")));
        assert!(spec.scopes.contains(&"offline_access") && spec.scopes.contains(&"read:jira-work"));
        let app = OAuthApp { client_id: "cid".into(), client_secret: "sec".into() };
        let call = Jira.token_request(&app, vec![("grant_type".into(), "refresh_token".into()), ("refresh_token".into(), "rt".into())]);
        assert_eq!(call.url, "https://auth.atlassian.com/oauth/token");
        assert_eq!(header(&call, "content-type"), Some("application/json"));
        let body: Value = serde_json::from_str(call.body.as_deref().unwrap()).unwrap();
        assert_eq!(body, json!({ "grant_type": "refresh_token", "refresh_token": "rt", "client_id": "cid", "client_secret": "sec" }));
        let tokens = Jira
            .read_token(&reply(
                200,
                json!({ "access_token": "at2", "refresh_token": "rt2", "expires_in": 3600, "scope": "read:jira-work" }),
            ))
            .unwrap();
        assert_eq!((tokens.access_token.as_str(), tokens.refresh_token.as_deref()), ("at2", Some("rt2")));

        let cred = signed_in();
        let calls = Jira.profile(&cred);
        assert_eq!(calls[0].url, "https://api.atlassian.com/oauth/token/accessible-resources");
        assert_eq!(calls[1].url, "https://api.atlassian.com/me");
        assert!(calls.iter().all(|c| header(c, "authorization") == Some("Bearer at")));
        let sites = json!([
            { "id": CLOUD, "url": "https://zeta.atlassian.net", "name": "Zeta", "scopes": ["search:confluence"] },
            { "id": "../../evil", "url": "https://bad.atlassian.net", "scopes": ["read:jira-work"] },
            { "id": CLOUD, "url": "https://acme.atlassian.net", "name": "Acme", "scopes": ["read:jira-work", "read:me"] }
        ]);
        let me = json!({ "account_id": "1122", "email": "ada@acme.com", "name": "Ada" });
        let account = Jira.read_profile(&cred, &[reply(200, sites.clone()), reply(200, me)]).unwrap();
        assert_eq!(account.label, "ada@acme.com on acme.atlassian.net");
        assert_eq!(account.settings, json!({ "site": "acme.atlassian.net", "cloud_id": CLOUD }));
        // Without the profile, the site still says which account it is.
        assert_eq!(Jira.read_profile(&cred, &[reply(200, sites), reply(403, json!({}))]).unwrap().label, "acme.atlassian.net");
        let confluence_only = json!([{ "id": CLOUD, "url": "https://zeta.atlassian.net", "scopes": ["search:confluence"] }]);
        assert!(Jira.read_profile(&cred, &[reply(200, confluence_only), reply(200, json!({}))]).unwrap_err().contains("site with Jira"));
        assert!(Jira.read_profile(&cred, &[reply(401, json!({})), reply(401, json!({}))]).unwrap_err().contains("Reconnect"));

        // Signed in, requests go through the gateway with the cloud id.
        let calls = Jira.search(&cred, &account, "deploy", 5);
        assert!(
            calls[0].url.starts_with(&format!("https://api.atlassian.com/ex/jira/{CLOUD}/rest/api/3/search/jql?jql=")),
            "{}",
            calls[0].url
        );
        assert_eq!(header(&calls[0], "authorization"), Some("Bearer at"));
        let calls = Jira.preview(&cred, &account, "PROJ-123");
        assert!(calls[0].url.starts_with(&format!("https://api.atlassian.com/ex/jira/{CLOUD}/rest/api/3/issue/PROJ-123?fields=")));
        let tampered = Account { label: String::new(), settings: json!({ "site": "acme.atlassian.net", "cloud_id": "x/../y" }) };
        assert!(Jira.search(&cred, &tampered, "deploy", 5).is_empty());
    }

    #[test]
    fn search_reads_issues() {
        let account = site_account();
        let calls = Jira.search(&token_cred("acme.atlassian.net"), &account, "Deploy \"fails\" (prod) OR -x\\", 50);
        let jql = urlencoding::encode("text ~ \"deploy fails prod or x\" ORDER BY updated DESC").into_owned();
        assert_eq!(
            calls[0].url,
            format!(
                "https://acme.atlassian.net/rest/api/3/search/jql?jql={jql}&maxResults=20&fields=summary,status,project,updated,reporter,description"
            )
        );
        assert!(header(&calls[0], "authorization").unwrap().starts_with("Basic "));
        let issues = json!({ "isLast": true, "issues": [
            { "key": "PROJ-12", "fields": { "summary": "Deploy fails on Fridays", "status": { "name": "In progress" },
              "project": { "name": "Platform" }, "updated": "2026-10-01T09:30:00.000+0000", "reporter": { "displayName": "Bo" },
              "description": { "type": "doc", "version": 1, "content": [
                { "type": "paragraph", "content": [{ "type": "text", "text": "Steps:" }] },
                { "type": "paragraph", "content": [{ "type": "text", "text": "deploy", "marks": [{ "type": "strong" }] }] } ] } } },
            { "key": "PROJ-13", "fields": { "summary": "Old one", "description": null } },
            { "key": "../evil", "fields": { "summary": "Not a key" } }
        ] });
        let hits = Jira.read_search(&account, &[reply(200, issues.clone())], 5).unwrap();
        assert_eq!(hits.len(), 2);
        assert_eq!((hits[0].kind.as_str(), hits[0].context.as_str()), ("issue", "PROJ-12 · In progress · Platform"));
        assert_eq!(hits[0].url, "https://acme.atlassian.net/browse/PROJ-12");
        assert_eq!(hits[0].snippet, "Steps: deploy");
        assert_eq!((hits[0].updated_at.as_deref(), hits[0].author.as_deref()), (Some("2026-10-01T09:30:00.000Z"), Some("Bo")));
        assert_eq!((hits[1].context.as_str(), hits[1].snippet.as_str()), ("PROJ-13", ""));
        assert_eq!(Jira.read_search(&account, &[reply(200, issues)], 1).unwrap().len(), 1);
        assert!(Jira.read_search(&account, &[reply(400, json!({}))], 5).unwrap_err().contains("other words"));
        assert!(Jira.read_search(&account, &[reply(401, json!({}))], 5).unwrap_err().contains("Reconnect"));
        assert!(Jira.read_search(&account, &[reply(0, json!(null))], 5).unwrap_err().contains("in time"));
        // Only punctuation: nothing to send, nothing found.
        assert!(Jira.search(&token_cred("acme.atlassian.net"), &account, "\"(*)\"", 5).is_empty());
        assert_eq!(Jira.read_search(&account, &[], 5).unwrap(), vec![]);
        assert!(Jira.read_search(&Account::default(), &[], 5).unwrap_err().contains("connect it again"));
    }

    #[test]
    fn previews_issues_on_the_connected_site() {
        let a = site_account();
        for (url, key) in [
            ("https://acme.atlassian.net/browse/PROJ-123", "PROJ-123"),
            ("https://ACME.atlassian.net/browse/proj-7?focusedCommentId=1#c", "PROJ-7"),
            ("https://acme.atlassian.net/jira/software/projects/PROJ/boards/1?selectedIssue=PROJ-9", "PROJ-9"),
            ("https://acme.atlassian.net/jira/software/c/projects/PROJ/issues/PROJ-10?jql=x", "PROJ-10"),
        ] {
            assert_eq!(Jira.preview_target(&a, url).as_deref(), Some(key), "{url}");
        }
        for no in [
            "https://acme.atlassian.net.evil.test/browse/PROJ-1",
            "https://evil.test/acme.atlassian.net/browse/PROJ-1",
            "https://acme.atlassian.net@evil.test/browse/PROJ-1",
            "https://other.atlassian.net/browse/PROJ-1",
            "https://acme.atlassian.net/browse/PROJ",
            "https://acme.atlassian.net/browse/PROJ-1x",
            "https://acme.atlassian.net/browse/1PROJ-1",
            "https://acme.atlassian.net/projects/PROJ?selectedIssue=PROJ-1",
            "https://acme.atlassian.net/jira/software/projects/PROJ/boards/1?selectedIssue=PROJ-1%2F..",
            "https://acme.atlassian.net/wiki/spaces/ENG/pages/1",
        ] {
            assert_eq!(Jira.preview_target(&a, no), None, "{no}");
        }
        // Not connected: no site to match.
        assert_eq!(Jira.preview_target(&Account::default(), "https://acme.atlassian.net/browse/PROJ-1"), None);

        let calls = Jira.preview(&token_cred("acme.atlassian.net"), &a, "PROJ-123");
        assert_eq!(calls[0].url, format!("https://acme.atlassian.net/rest/api/3/issue/PROJ-123?fields={ISSUE_FIELDS}"));
        let issue = json!({ "key": "PROJ-123", "fields": {
            "summary": "Retry deploys", "status": { "name": "Done" }, "assignee": { "displayName": "Bo" },
            "reporter": { "displayName": "Cy" }, "created": "2026-09-30T23:00:00.000-0700", "updated": "2026-10-02T00:00:00.000+0000",
            "issuetype": { "name": "Bug" }, "project": { "name": "Platform" }, "priority": null,
            "description": { "type": "doc", "version": 1, "content": [
                { "type": "heading", "attrs": { "level": 2 }, "content": [{ "type": "text", "text": "Why" }] },
                { "type": "paragraph", "content": [
                    { "type": "mention", "attrs": { "id": "1", "text": "@Ada" } }, { "type": "text", "text": " saw it fail" },
                    { "type": "hardBreak" }, { "type": "text", "text": "twice " }, { "type": "emoji", "attrs": { "shortName": ":fire:" } } ] },
                { "type": "bulletList", "content": [{ "type": "listItem", "content": [
                    { "type": "paragraph", "content": [{ "type": "text", "text": "roll back" }] } ] }] },
                { "type": "codeBlock", "content": [{ "type": "text", "text": "make deploy" }] },
                { "type": "paragraph", "content": [{ "type": "inlineCard", "attrs": { "url": "https://example.com/run/1" } }] }
            ] } } });
        let p = Jira.read_preview(&a, "PROJ-123", &[reply(200, issue)]).unwrap();
        assert_eq!(
            (p.kind.as_str(), p.reference.as_str(), p.url.as_str()),
            ("issue", "PROJ-123", "https://acme.atlassian.net/browse/PROJ-123")
        );
        assert_eq!((p.status.as_deref(), p.assignee.as_deref(), p.author.as_deref()), (Some("Done"), Some("Bo"), Some("Cy")));
        assert_eq!(p.created_at.as_deref(), Some("2026-10-01T06:00:00.000Z"));
        assert_eq!(p.description, "Why @Ada saw it fail twice :fire: roll back make deploy https://example.com/run/1");
        assert_eq!(
            p.details,
            vec![Detail { label: "Type".into(), value: "Bug".into() }, Detail { label: "Project".into(), value: "Platform".into() }]
        );
        // Plain-text descriptions and moved issues.
        let moved = json!({ "key": "NEW-5", "fields": { "summary": "Moved", "description": "Old\n\nplain text" } });
        let p = Jira.read_preview(&a, "PROJ-1", &[reply(200, moved)]).unwrap();
        assert_eq!((p.reference.as_str(), p.description.as_str()), ("NEW-5", "Old plain text"));
        assert!(Jira.read_preview(&a, "PROJ-1", &[reply(404, json!({}))]).unwrap_err().contains("can't see it"));
        assert!(Jira.read_preview(&a, "PROJ-1", &[reply(401, json!({}))]).unwrap_err().contains("Reconnect"));
        assert!(Jira.read_preview(&a, "PROJ-1", &[reply(0, json!(null))]).unwrap_err().contains("in time"));
    }

    #[test]
    fn times_read_both_ways() {
        assert_eq!(when(&json!("2026-10-01T09:30:00.123+0200")).as_deref(), Some("2026-10-01T07:30:00.123Z"));
        assert_eq!(when(&json!("2026-10-01T09:30:00Z")).as_deref(), Some("2026-10-01T09:30:00.000Z"));
        assert_eq!(when(&json!("yesterday")).as_deref(), Some("yesterday"));
        assert_eq!(when(&Value::Null), None);
    }
}
