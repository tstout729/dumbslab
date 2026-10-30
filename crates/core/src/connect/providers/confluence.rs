//! Confluence Cloud: pages and blog posts the connected account can see on one Atlassian site.
//! People connect the same two ways as Jira (an API token for their site, or signing in with
//! Atlassian); [`super::jira`] holds the shared parts. Search only, no previews.
//!
//! Atlassian's docs:
//! - Search by CQL, `GET /wiki/rest/api/search` (excerpts mark matches with `@@@hl@@@`):
//!   https://developer.atlassian.com/cloud/confluence/rest/v1/api-group-search/
//! - CQL's `text` and `type` fields: https://developer.atlassian.com/cloud/confluence/cql-fields/
//! - Current user, `GET /wiki/rest/api/user/current`: https://developer.atlassian.com/cloud/confluence/rest/v1/api-group-users/
//! - Signing in, the gateway and `/me`: https://developer.atlassian.com/cloud/confluence/oauth-2-3lo-apps/
//! - Scopes: https://developer.atlassian.com/cloud/confluence/scopes-for-oauth-2-3LO-and-forge-apps/

use super::jira;
use crate::connect::{Account, Connector, Credential, Hit, HttpCall, HttpReply, OAuthApp, ProviderInfo, excerpt, http_error};

pub struct Confluence;

/// Search pages; who the person is; refresh tokens.
const SCOPES: &[&str] = &["search:confluence", "read:me", "offline_access"];

static INFO: ProviderInfo = ProviderInfo {
    id: "confluence",
    name: "Confluence",
    about: "Search pages and blog posts.",
    search: true,
    preview: false,
    oauth: Some(jira::oauth(SCOPES)),
    token_fields: jira::TOKEN_FIELDS,
    token_help: jira::TOKEN_HELP,
};

/// Search text without Confluence's highlight markers.
fn unmarked(text: &str) -> String {
    text.replace("@@@hl@@@", "").replace("@@@endhl@@@", "")
}

/// Search text as plain text: highlight markers and any tags dropped, entities decoded. Confluence
/// escapes excerpts, so a `<` left in one is markup.
fn plain(text: &str) -> String {
    let mut untagged = String::with_capacity(text.len());
    let mut in_tag = false;
    for c in unmarked(text).chars() {
        match c {
            '<' => in_tag = true,
            '>' if in_tag => in_tag = false,
            _ if !in_tag => untagged.push(c),
            _ => {}
        }
    }
    crate::connect::decode_entities(&untagged)
}

/// A page's address on the site, from the link Confluence gives (relative to `/wiki`).
fn page_url(site: &str, link: &str) -> Option<String> {
    if !link.starts_with('/') || link.starts_with("//") {
        return None;
    }
    let path = link.strip_prefix("/wiki").filter(|p| p.starts_with('/')).unwrap_or(link);
    Some(format!("https://{site}/wiki{path}"))
}

impl Connector for Confluence {
    fn info(&self) -> &'static ProviderInfo {
        &INFO
    }

    fn profile(&self, cred: &Credential) -> Vec<HttpCall> {
        jira::profile_calls("confluence", "/wiki/rest/api/user/current", cred)
    }

    fn read_profile(&self, cred: &Credential, replies: &[HttpReply]) -> Result<Account, String> {
        jira::read_account("Confluence", "search:confluence", cred, replies)
    }

    /// Best matches first, as Confluence ranks them.
    fn search(&self, cred: &Credential, account: &Account, q: &str, limit: usize) -> Vec<HttpCall> {
        let words = jira::search_words(q);
        if words.is_empty() {
            return vec![];
        }
        let cql = urlencoding::encode(&format!("text ~ \"{words}\" AND type in (page, blogpost)")).into_owned();
        let path = format!("/wiki/rest/api/search?cql={cql}&limit={}&excerpt=highlight", limit.clamp(1, 20));
        jira::site_get("confluence", cred, account, &path).into_iter().collect()
    }

    fn read_search(&self, account: &Account, replies: &[HttpReply], limit: usize) -> Result<Vec<Hit>, String> {
        let site = jira::site_of(account).ok_or_else(|| jira::reconnect("Confluence"))?;
        // Nothing worth searching for (only punctuation) sent nothing.
        let Some(r) = replies.first() else { return Ok(vec![]) };
        if !r.ok() {
            return Err(match r.status {
                400 => "Confluence couldn't search for that. Try other words.".into(),
                404 => format!("{site} has no Confluence, or the connected account can't use it."),
                _ => http_error("Confluence", r),
            });
        }
        Ok(r.json()["results"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|x| {
                let content = &x["content"];
                let link = content["_links"]["webui"].as_str().or(x["url"].as_str())?;
                let title = match content["title"].as_str() {
                    Some(t) => unmarked(t),
                    None => plain(x["title"].as_str().unwrap_or_default()),
                };
                Some(Hit {
                    provider: "confluence".into(),
                    kind: "page".into(),
                    title,
                    url: page_url(&site, link)?,
                    context: plain(x["resultGlobalContainer"]["title"].as_str().unwrap_or_default()),
                    snippet: excerpt(&plain(x["excerpt"].as_str().unwrap_or_default()), 240),
                    updated_at: jira::when(&x["lastModified"]),
                    author: None,
                })
            })
            .take(limit)
            .collect())
    }

    fn token_request(&self, app: &OAuthApp, form: Vec<(String, String)>) -> HttpCall {
        jira::token_call(app, form)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

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
        Credential { token: "at".into(), ..Default::default() }
    }

    fn header<'a>(call: &'a HttpCall, name: &str) -> Option<&'a str> {
        call.headers.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }

    #[test]
    fn connects_both_ways() {
        let cred = token_cred("https://acme.atlassian.net/wiki");
        let calls = Confluence.profile(&cred);
        assert_eq!(calls[0].url, "https://acme.atlassian.net/wiki/rest/api/user/current");
        assert!(header(&calls[0], "authorization").unwrap().starts_with("Basic "));
        let me = json!({ "type": "known", "accountId": "5b10", "email": "", "publicName": "Ada" });
        let account = Confluence.read_profile(&cred, &[reply(200, me)]).unwrap();
        assert_eq!(account.label, "ada@acme.com on acme.atlassian.net");
        assert_eq!(account.settings, json!({ "site": "acme.atlassian.net" }));
        // Confluence answers people it doesn't know as anonymous, rather than refusing them.
        let anonymous = json!({ "type": "anonymous", "displayName": "Anonymous" });
        assert!(Confluence.read_profile(&cred, &[reply(200, anonymous)]).unwrap_err().contains("didn't accept"));
        assert!(Confluence.read_profile(&cred, &[reply(401, json!({}))]).unwrap_err().contains("rejected that email"));
        assert!(Confluence.read_profile(&cred, &[reply(404, json!({}))]).unwrap_err().contains("has no Confluence"));
        assert!(Confluence.profile(&token_cred("acme.atlassian.net.evil.test")).is_empty());

        let cred = signed_in();
        let calls = Confluence.profile(&cred);
        assert_eq!(calls[0].url, "https://api.atlassian.com/oauth/token/accessible-resources");
        assert_eq!(header(&calls[1], "authorization"), Some("Bearer at"));
        // Atlassian lists a site once per product; Confluence takes its own.
        let sites = json!([
            { "id": CLOUD, "url": "https://acme.atlassian.net", "scopes": ["read:jira-work"] },
            { "id": CLOUD, "url": "https://wiki.atlassian.net", "scopes": ["search:confluence", "read:me"] }
        ]);
        let account = Confluence.read_profile(&cred, &[reply(200, sites), reply(200, json!({ "name": "Ada" }))]).unwrap();
        assert_eq!(account.label, "Ada on wiki.atlassian.net");
        assert_eq!(account.settings, json!({ "site": "wiki.atlassian.net", "cloud_id": CLOUD }));
        assert!(Confluence.read_profile(&cred, &[reply(0, json!(null)), reply(0, json!(null))]).unwrap_err().contains("in time"));
        let call = Confluence.token_request(&OAuthApp { client_id: "c".into(), client_secret: "s".into() }, vec![]);
        assert_eq!(
            (call.url.as_str(), header(&call, "content-type")),
            ("https://auth.atlassian.com/oauth/token", Some("application/json"))
        );
        assert!(!INFO.preview && Confluence.preview_target(&account, "https://wiki.atlassian.net/wiki/spaces/ENG/pages/1").is_none());
    }

    #[test]
    fn searches_pages_with_cql() {
        let account = Account { label: String::new(), settings: json!({ "site": "acme.atlassian.net" }) };
        let calls = Confluence.search(&token_cred("acme.atlassian.net"), &account, "on-call \"rota\"", 5);
        let cql = urlencoding::encode("text ~ \"on call rota\" AND type in (page, blogpost)").into_owned();
        assert_eq!(calls[0].url, format!("https://acme.atlassian.net/wiki/rest/api/search?cql={cql}&limit=5&excerpt=highlight"));
        let signed_in_account = Account { label: String::new(), settings: json!({ "site": "acme.atlassian.net", "cloud_id": CLOUD }) };
        let calls = Confluence.search(&signed_in(), &signed_in_account, "rota", 50);
        assert_eq!(
            calls[0].url,
            format!(
                "https://api.atlassian.com/ex/confluence/{CLOUD}/wiki/rest/api/search?cql={}&limit=20&excerpt=highlight",
                urlencoding::encode("text ~ \"rota\" AND type in (page, blogpost)")
            )
        );
        assert_eq!(header(&calls[0], "authorization"), Some("Bearer at"));

        let results = json!({ "results": [
            { "content": { "id": "123", "type": "page", "title": "On-call rota", "_links": { "webui": "/spaces/OPS/pages/123/On-call+rota" } },
              "title": "@@@hl@@@On-call@@@endhl@@@ @@@hl@@@rota@@@endhl@@@",
              "excerpt": "Who&#39;s @@@hl@@@on call@@@endhl@@@ this week &amp; next&hellip; &quot;Ops&quot;",
              "url": "/spaces/OPS/pages/123/On-call+rota", "resultGlobalContainer": { "title": "Ops &amp; Support", "displayUrl": "/spaces/OPS" },
              "lastModified": "2026-10-01T09:30:00.000Z" },
            { "title": "Rota @@@hl@@@changes@@@endhl@@@", "excerpt": "", "url": "/wiki/spaces/OPS/blog/2026/10/02/124/Rota+changes",
              "resultGlobalContainer": { "title": "Ops" } },
            { "content": { "title": "Elsewhere", "_links": { "webui": "//evil.test/x" } }, "excerpt": "" }
        ] });
        let hits = Confluence.read_search(&account, &[reply(200, results.clone())], 5).unwrap();
        assert_eq!(hits.len(), 2);
        assert_eq!((hits[0].kind.as_str(), hits[0].title.as_str(), hits[0].context.as_str()), ("page", "On-call rota", "Ops & Support"));
        assert_eq!(hits[0].url, "https://acme.atlassian.net/wiki/spaces/OPS/pages/123/On-call+rota");
        assert_eq!(hits[0].snippet, "Who's on call this week & next… \"Ops\"");
        assert_eq!(hits[0].updated_at.as_deref(), Some("2026-10-01T09:30:00.000Z"));
        assert_eq!(
            (hits[1].title.as_str(), hits[1].url.as_str()),
            ("Rota changes", "https://acme.atlassian.net/wiki/spaces/OPS/blog/2026/10/02/124/Rota+changes")
        );
        assert_eq!(Confluence.read_search(&account, &[reply(200, results)], 1).unwrap().len(), 1);
        assert!(Confluence.read_search(&account, &[reply(400, json!({}))], 5).unwrap_err().contains("other words"));
        assert!(Confluence.read_search(&account, &[reply(404, json!({}))], 5).unwrap_err().contains("has no Confluence"));
        assert!(Confluence.read_search(&account, &[reply(401, json!({}))], 5).unwrap_err().contains("Reconnect"));
        assert!(Confluence.read_search(&account, &[reply(0, json!(null))], 5).unwrap_err().contains("in time"));
        assert!(Confluence.search(&token_cred("acme.atlassian.net"), &account, "~*?", 5).is_empty());
        assert!(Confluence.read_search(&Account::default(), &[], 5).unwrap_err().contains("connect it again"));
    }

    #[test]
    fn excerpts_become_plain_text() {
        assert_eq!(plain("a <span class=\"x\">b</span> &amp;amp; &#x41;&#66; &bogus; & c"), "a b &amp; AB &bogus; & c");
    }
}
