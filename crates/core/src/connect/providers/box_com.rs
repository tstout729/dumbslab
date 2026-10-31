//! Box: files and folders the connected account can open. Box's developer tokens last an hour,
//! so it needs the host's OAuth app, with "Read all files and folders stored in Box" enabled.
//! Each refresh answers with a new refresh token and spends the old one; the core keeps the new
//! one.
//!
//! Docs: https://developer.box.com/reference/get-authorize/, https://developer.box.com/reference/post-oauth2-token/,
//! https://developer.box.com/guides/authentication/tokens/refresh/, https://developer.box.com/reference/get-users-me/,
//! https://developer.box.com/reference/get-search/, https://developer.box.com/guides/getting-started/locating-values/

use serde_json::{Value, json};

use crate::connect::{Account, Connector, Credential, Hit, HttpCall, HttpReply, OAuthSpec, ProviderInfo, excerpt, http_error, opt, s};

pub struct BoxCom;

const API: &str = "https://api.box.com/2.0";
const SEARCH_FIELDS: &str = "name,description,modified_at,path_collection,owned_by";

static INFO: ProviderInfo = ProviderInfo {
    id: "box",
    name: "Box",
    about: "Search files and folders.",
    search: true,
    preview: false,
    oauth: Some(OAuthSpec {
        authorize_url: "https://account.box.com/api/oauth2/authorize",
        token_url: "https://api.box.com/oauth2/token",
        scopes: &["root_readonly"],
        scope_param: "scope",
        scope_separator: " ",
        extra: &[],
        pkce: false,
        site: None,
    }),
    token_fields: &[],
    token_help: "",
};

/// The folders an item sits in, below "All Files".
fn folder_path(item: &Value) -> String {
    let names: Vec<String> = item["path_collection"]["entries"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|f| f["id"].as_str() != Some("0"))
        .filter_map(|f| opt(&f["name"]))
        .collect();
    if names.is_empty() { "All Files".into() } else { names.join(" / ") }
}

impl Connector for BoxCom {
    fn info(&self) -> &'static ProviderInfo {
        &INFO
    }

    fn profile(&self, cred: &Credential) -> Vec<HttpCall> {
        vec![HttpCall::get(format!("{API}/users/me?fields=name,login")).bearer(&cred.token)]
    }

    fn read_profile(&self, _cred: &Credential, replies: &[HttpReply]) -> Result<Account, String> {
        let r = replies.first().cloned().unwrap_or_default();
        if !r.ok() {
            return Err(http_error("Box", &r));
        }
        let me = r.json();
        let label = opt(&me["login"]).or_else(|| opt(&me["name"])).ok_or("Box didn't say whose account that is.")?;
        Ok(Account { label, settings: json!({}) })
    }

    fn search(&self, cred: &Credential, _account: &Account, q: &str, limit: usize) -> Vec<HttpCall> {
        let query = urlencoding::encode(q).into_owned();
        vec![HttpCall::get(format!("{API}/search?query={query}&limit={}&fields={SEARCH_FIELDS}", limit.clamp(1, 20))).bearer(&cred.token)]
    }

    fn read_search(&self, _account: &Account, replies: &[HttpReply], limit: usize) -> Result<Vec<Hit>, String> {
        let r = replies.first().cloned().unwrap_or_default();
        if !r.ok() {
            return Err(http_error("Box", &r));
        }
        Ok(r.json()["entries"]
            .as_array()
            .into_iter()
            .flatten()
            // Web links are bookmarks to other sites; ids are numbers, so they're safe in a URL.
            .filter_map(|e| {
                let kind = e["type"].as_str().filter(|t| matches!(*t, "file" | "folder"))?;
                let id = e["id"].as_str().filter(|id| !id.is_empty() && id.bytes().all(|b| b.is_ascii_digit()))?;
                Some(Hit {
                    provider: "box".into(),
                    kind: kind.into(),
                    title: s(&e["name"]),
                    url: format!("https://app.box.com/{kind}/{id}"),
                    context: folder_path(e),
                    snippet: excerpt(e["description"].as_str().unwrap_or_default(), 240),
                    updated_at: opt(&e["modified_at"]),
                    author: opt(&e["owned_by"]["name"]),
                })
            })
            .take(limit)
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connect::OAuthApp;

    fn reply(status: u16, body: Value) -> HttpReply {
        HttpReply { status, body: body.to_string() }
    }

    #[test]
    fn profile_reads_the_login() {
        let cred = Credential { token: "t".into(), ..Default::default() };
        let calls = BoxCom.profile(&cred);
        assert_eq!(calls[0].url, "https://api.box.com/2.0/users/me?fields=name,login");
        assert!(calls[0].headers.contains(&("authorization".into(), "Bearer t".into())));
        let account =
            BoxCom.read_profile(&cred, &[reply(200, json!({ "type": "user", "id": "1", "name": "Ada", "login": "ada@acme.com" }))]);
        assert_eq!(account.unwrap().label, "ada@acme.com");
        assert!(BoxCom.read_profile(&cred, &[reply(200, json!({ "type": "user" }))]).unwrap_err().contains("whose account"));
        assert!(BoxCom.read_profile(&cred, &[reply(401, json!({}))]).unwrap_err().contains("Reconnect"));
    }

    #[test]
    fn refreshes_keep_the_new_refresh_token() {
        let app = OAuthApp { client_id: "id".into(), client_secret: "sec".into() };
        let call = BoxCom.token_request(
            &app,
            INFO.oauth.unwrap().token_url,
            vec![("grant_type".into(), "refresh_token".into()), ("refresh_token".into(), "r1".into())],
        );
        assert_eq!((call.method, call.url.as_str()), ("POST", "https://api.box.com/oauth2/token"));
        assert_eq!(call.body.as_deref(), Some("grant_type=refresh_token&refresh_token=r1&client_id=id&client_secret=sec"));
        // Box spends the old refresh token: the answer's new one must be kept.
        let answer =
            json!({ "access_token": "a2", "expires_in": 3600, "token_type": "bearer", "refresh_token": "r2", "restricted_to": [] });
        let tokens = BoxCom.read_token(&reply(200, answer)).unwrap();
        assert_eq!((tokens.access_token.as_str(), tokens.refresh_token.as_deref(), tokens.expires_in), ("a2", Some("r2"), Some(3600)));
        let refused = json!({ "error": "invalid_grant", "error_description": "Refresh token has expired" });
        assert!(BoxCom.read_token(&reply(400, refused)).unwrap_err().contains("Refresh token has expired"));
    }

    #[test]
    fn searches_files_and_folders() {
        let calls = BoxCom.search(&Credential { token: "t".into(), ..Default::default() }, &Account::default(), "Q3 plan&type=web_link", 5);
        assert_eq!(
            calls[0].url,
            format!("https://api.box.com/2.0/search?query=Q3%20plan%26type%3Dweb_link&limit=5&fields={SEARCH_FIELDS}")
        );
        let root = json!({ "type": "folder", "id": "0", "name": "All Files" });
        let found = json!({ "entries": [
            { "type": "file", "id": "1234567890", "name": "Q3 plan.pdf", "description": "Plan\nfor Q3", "modified_at": "2026-10-01T10:00:00-07:00",
              "path_collection": { "total_count": 3, "entries": [root, { "type": "folder", "id": "5", "name": "Marketing" }, { "type": "folder", "id": "6", "name": "2026" }] },
              "owned_by": { "type": "user", "id": "9", "name": "Ada", "login": "ada@acme.com" } },
            { "type": "web_link", "id": "77", "name": "Q3 dashboard", "url": "https://example.com" },
            { "type": "folder", "id": "9876543210", "name": "Q3", "path_collection": { "total_count": 1, "entries": [root] } },
            { "type": "file", "id": "../x", "name": "Odd" }
        ] });
        let hits = BoxCom.read_search(&Account::default(), &[reply(200, found.clone())], 5).unwrap();
        assert_eq!(hits.len(), 2);
        assert_eq!((hits[0].kind.as_str(), hits[0].url.as_str()), ("file", "https://app.box.com/file/1234567890"));
        assert_eq!(
            (hits[0].context.as_str(), hits[0].snippet.as_str(), hits[0].author.as_deref()),
            ("Marketing / 2026", "Plan for Q3", Some("Ada"))
        );
        assert_eq!(hits[0].updated_at.as_deref(), Some("2026-10-01T10:00:00-07:00"));
        assert_eq!(
            (hits[1].kind.as_str(), hits[1].url.as_str(), hits[1].context.as_str()),
            ("folder", "https://app.box.com/folder/9876543210", "All Files")
        );
        assert_eq!(BoxCom.read_search(&Account::default(), &[reply(200, found)], 1).unwrap().len(), 1);
        assert!(BoxCom.read_search(&Account::default(), &[reply(401, json!({}))], 5).unwrap_err().contains("Reconnect"));
        assert!(BoxCom.read_search(&Account::default(), &[reply(0, json!(null))], 5).unwrap_err().contains("in time"));
    }
}
