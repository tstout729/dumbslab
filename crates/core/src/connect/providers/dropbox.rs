//! Dropbox: files and folders in the connected account, including its team's space when it has
//! one. Dropbox has no personal tokens, so it needs the host's OAuth app, with the
//! account_info.read and files.metadata.read permissions. Sign-ins use PKCE and ask for
//! offline access, so a refresh token comes back; refreshes don't replace it.
//!
//! Docs: https://docs.dropboxapi.com/dropbox-api/docs/oauth, https://docs.dropboxapi.com/dropbox-api/docs/get-started/authorization,
//! https://docs.dropboxapi.com/dropbox-api/docs/team-files, and the route definitions in
//! https://github.com/dropbox/dropbox-api-spec (users.stone: get_current_account; files.stone: search:2).
//! Dropbox's API has no link to an item on its website; `/home/<folder>?preview=<file>` is the
//! form its website uses for the signed-in person's own files.

use serde_json::{Value, json};

use crate::connect::{
    Account, Connector, Credential, Hit, HttpCall, HttpReply, OAuthApp, OAuthSpec, ProviderInfo, TokenSet, http_error, opt, s,
    standard_token,
};

pub struct Dropbox;

const API: &str = "https://api.dropboxapi.com/2";
const WEB: &str = "https://www.dropbox.com/home";

static INFO: ProviderInfo = ProviderInfo {
    id: "dropbox",
    name: "Dropbox",
    about: "Search files and folders, including your team's space.",
    search: true,
    preview: false,
    oauth: Some(OAuthSpec {
        authorize_url: "https://www.dropbox.com/oauth2/authorize",
        token_url: "https://api.dropboxapi.com/oauth2/token",
        scopes: &["account_info.read", "files.metadata.read"],
        scope_param: "scope",
        scope_separator: " ",
        extra: &[("token_access_type", "offline")],
        pkce: true,
        site: None,
        refresh_revokes: false,
    }),
    token_fields: &[],
    token_help: "",
};

/// Dropbox's API calls are POSTs with JSON; one that takes no arguments takes `null`.
fn rpc(path: &str, token: &str, args: &Value) -> HttpCall {
    HttpCall::post_json(format!("{API}{path}"), args).bearer(token)
}

/// `/A b/c.pdf` → `/A%20b/c.pdf`.
fn encode_path(path: &str) -> String {
    path.split('/').filter(|p| !p.is_empty()).map(|p| format!("/{}", urlencoding::encode(p))).collect()
}

/// Where Dropbox's website shows an item: a folder at its path, a file previewed in its folder.
fn web_url(path: &str, folder: bool) -> String {
    match path.rsplit_once('/') {
        _ if folder => format!("{WEB}{}", encode_path(path)),
        Some((dir, name)) if !name.is_empty() => format!("{WEB}{}?preview={}", encode_path(dir), urlencoding::encode(name)),
        _ => WEB.into(),
    }
}

impl Connector for Dropbox {
    fn info(&self) -> &'static ProviderInfo {
        &INFO
    }

    fn profile(&self, cred: &Credential) -> Vec<HttpCall> {
        vec![rpc("/users/get_current_account", &cred.token, &Value::Null)]
    }

    /// Notes the team space's root when the account has one, so search covers the whole space
    /// rather than only the person's own folder in it.
    fn read_profile(&self, _cred: &Credential, replies: &[HttpReply]) -> Result<Account, String> {
        let r = replies.first().cloned().unwrap_or_default();
        if !r.ok() {
            return Err(http_error("Dropbox", &r));
        }
        let me = r.json();
        let label = opt(&me["email"]).or_else(|| opt(&me["name"]["display_name"])).ok_or("Dropbox didn't say whose account that is.")?;
        let root = &me["root_info"];
        let settings = match (root["root_namespace_id"].as_str(), root["home_namespace_id"].as_str()) {
            (Some(r), Some(h)) if r != h && !r.is_empty() && r.bytes().all(|b| b.is_ascii_digit()) => json!({ "root": r }),
            _ => json!({}),
        };
        Ok(Account { label, settings })
    }

    fn search(&self, cred: &Credential, account: &Account, q: &str, limit: usize) -> Vec<HttpCall> {
        let args = json!({ "query": q, "options": { "max_results": limit.clamp(1, 20), "file_status": "active" } });
        let call = rpc("/files/search_v2", &cred.token, &args);
        match account.settings["root"].as_str().filter(|r| !r.is_empty() && r.bytes().all(|b| b.is_ascii_digit())) {
            Some(root) => vec![call.header("dropbox-api-path-root", json!({ ".tag": "root", "root": root }).to_string())],
            None => vec![call],
        }
    }

    fn read_search(&self, _account: &Account, replies: &[HttpReply], limit: usize) -> Result<Vec<Hit>, String> {
        let r = replies.first().cloned().unwrap_or_default();
        if !r.ok() {
            return Err(http_error("Dropbox", &r));
        }
        Ok(r.json()["matches"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|m| {
                let item = &m["metadata"]["metadata"];
                let kind = item[".tag"].as_str().filter(|t| matches!(*t, "file" | "folder"))?;
                let path = s(&item["path_display"]);
                let folder = path.rsplit_once('/').map(|(dir, _)| dir).unwrap_or_default();
                Some(Hit {
                    provider: "dropbox".into(),
                    kind: kind.into(),
                    title: s(&item["name"]),
                    url: web_url(&path, kind == "folder"),
                    context: if folder.is_empty() { "Dropbox".into() } else { folder.into() },
                    snippet: String::new(),
                    updated_at: opt(&item["server_modified"]),
                    author: None,
                })
            })
            .take(limit)
            .collect())
    }

    /// Sign-ins use PKCE, so the code verifier stands in for the client secret, here and on
    /// refreshes, as Dropbox documents for PKCE.
    fn token_request(&self, app: &OAuthApp, token_url: &str, form: Vec<(String, String)>) -> HttpCall {
        let mut all = form;
        all.push(("client_id".into(), app.client_id.clone()));
        let pairs: Vec<(&str, &str)> = all.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        HttpCall::post_form(token_url, &pairs).header("accept", "application/json")
    }

    /// Some of Dropbox's examples give `expires_in` as a string; read both, so tokens are
    /// refreshed before they expire.
    fn read_token(&self, reply: &HttpReply) -> Result<TokenSet, String> {
        let mut tokens = standard_token("Dropbox", reply)?;
        if tokens.expires_in.is_none() {
            tokens.expires_in = reply.json()["expires_in"].as_str().and_then(|e| e.parse().ok());
        }
        Ok(tokens)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reply(status: u16, body: Value) -> HttpReply {
        HttpReply { status, body: body.to_string() }
    }

    #[test]
    fn signs_in_offline_with_pkce() {
        let spec = INFO.oauth.unwrap();
        assert!(spec.pkce && spec.extra.contains(&("token_access_type", "offline")));
        let app = OAuthApp { client_id: "key".into(), client_secret: "secret".into() };
        let form = vec![
            ("grant_type".into(), "authorization_code".into()),
            ("code".into(), "c".into()),
            ("redirect_uri".into(), "https://w.test/connect/callback".into()),
            ("code_verifier".into(), "v".into()),
        ];
        let call = Dropbox.token_request(&app, INFO.oauth.unwrap().token_url, form);
        assert_eq!((call.method, call.url.as_str()), ("POST", "https://api.dropboxapi.com/oauth2/token"));
        assert_eq!(
            call.body.as_deref(),
            Some(
                "grant_type=authorization_code&code=c&redirect_uri=https%3A%2F%2Fw.test%2Fconnect%2Fcallback&code_verifier=v&client_id=key"
            )
        );
        let refresh = Dropbox.token_request(
            &app,
            INFO.oauth.unwrap().token_url,
            vec![("grant_type".into(), "refresh_token".into()), ("refresh_token".into(), "r".into())],
        );
        assert!(!refresh.body.unwrap().contains("secret"));
        let first =
            json!({ "access_token": "sl.a", "expires_in": 14400, "token_type": "bearer", "refresh_token": "r", "account_id": "dbid:1" });
        let tokens = Dropbox.read_token(&reply(200, first)).unwrap();
        assert_eq!((tokens.refresh_token.as_deref(), tokens.expires_in), (Some("r"), Some(14400)));
        // A refresh answers without a refresh token (the core keeps the first), maybe with a string expiry.
        let tokens =
            Dropbox.read_token(&reply(200, json!({ "access_token": "sl.b", "expires_in": "13220", "token_type": "bearer" }))).unwrap();
        assert_eq!((tokens.access_token.as_str(), tokens.refresh_token, tokens.expires_in), ("sl.b", None, Some(13220)));
        assert!(Dropbox.read_token(&reply(400, json!({ "error": "invalid_grant" }))).unwrap_err().contains("invalid_grant"));
    }

    #[test]
    fn profile_notes_a_team_space() {
        let cred = Credential { token: "t".into(), ..Default::default() };
        let calls = Dropbox.profile(&cred);
        assert_eq!(
            (calls[0].method, calls[0].url.as_str(), calls[0].body.as_deref()),
            ("POST", "https://api.dropboxapi.com/2/users/get_current_account", Some("null"))
        );
        assert!(calls[0].headers.contains(&("content-type".into(), "application/json".into())));
        assert!(calls[0].headers.contains(&("authorization".into(), "Bearer t".into())));
        let personal = json!({ "email": "ada@acme.com", "name": { "display_name": "Ada" },
            "root_info": { ".tag": "user", "root_namespace_id": "1", "home_namespace_id": "1" } });
        let account = Dropbox.read_profile(&cred, &[reply(200, personal)]).unwrap();
        assert_eq!((account.label.as_str(), &account.settings), ("ada@acme.com", &json!({})));
        let team = json!({ "email": "ada@acme.com", "root_info": { ".tag": "team", "root_namespace_id": "7", "home_namespace_id": "1", "home_path": "/Ada" } });
        assert_eq!(Dropbox.read_profile(&cred, &[reply(200, team)]).unwrap().settings, json!({ "root": "7" }));
        let odd = json!({ "email": "ada@acme.com", "root_info": { "root_namespace_id": "7\r\nx: y", "home_namespace_id": "1" } });
        assert_eq!(Dropbox.read_profile(&cred, &[reply(200, odd)]).unwrap().settings, json!({}));
        assert!(Dropbox.read_profile(&cred, &[reply(401, json!({}))]).unwrap_err().contains("Reconnect"));
    }

    #[test]
    fn searches_files_and_links_to_the_website() {
        let cred = Credential { token: "t".into(), ..Default::default() };
        let calls = Dropbox.search(&cred, &Account::default(), "Q3 \"plan\"", 5);
        assert_eq!((calls[0].method, calls[0].url.as_str()), ("POST", "https://api.dropboxapi.com/2/files/search_v2"));
        let body: Value = serde_json::from_str(calls[0].body.as_deref().unwrap()).unwrap();
        assert_eq!(body, json!({ "query": "Q3 \"plan\"", "options": { "max_results": 5, "file_status": "active" } }));
        assert!(!calls[0].headers.iter().any(|(k, _)| k == "dropbox-api-path-root"));
        let team = Account { label: "ada@acme.com".into(), settings: json!({ "root": "7" }) };
        let calls = Dropbox.search(&cred, &team, "plan", 50);
        assert!(calls[0].headers.contains(&("dropbox-api-path-root".into(), r#"{".tag":"root","root":"7"}"#.into())));
        assert!(calls[0].body.as_deref().unwrap().contains("\"max_results\":20"));
        let found = json!({ "has_more": false, "matches": [
            { "match_type": { ".tag": "filename" }, "metadata": { ".tag": "metadata", "metadata": { ".tag": "file", "id": "id:a",
              "name": "Q3 plan #2.pdf", "path_display": "/Marketing/2026 Plans/Q3 plan #2.pdf", "server_modified": "2026-10-01T00:00:00Z" } } },
            { "metadata": { ".tag": "metadata", "metadata": { ".tag": "folder", "id": "id:b", "name": "Plans", "path_display": "/Plans" } } },
            { "metadata": { ".tag": "metadata", "metadata": { ".tag": "file", "name": "Top.txt", "path_display": "/Top.txt" } } },
            { "metadata": { ".tag": "other" } }
        ] });
        let hits = Dropbox.read_search(&team, &[reply(200, found.clone())], 5).unwrap();
        assert_eq!(hits.len(), 3);
        assert_eq!((hits[0].kind.as_str(), hits[0].context.as_str()), ("file", "/Marketing/2026 Plans"));
        assert_eq!(hits[0].url, "https://www.dropbox.com/home/Marketing/2026%20Plans?preview=Q3%20plan%20%232.pdf");
        assert_eq!(hits[0].updated_at.as_deref(), Some("2026-10-01T00:00:00Z"));
        assert_eq!(
            (hits[1].kind.as_str(), hits[1].url.as_str(), hits[1].context.as_str()),
            ("folder", "https://www.dropbox.com/home/Plans", "Dropbox")
        );
        assert_eq!(hits[2].url, "https://www.dropbox.com/home?preview=Top.txt");
        assert_eq!(Dropbox.read_search(&team, &[reply(200, found)], 1).unwrap().len(), 1);
        assert!(Dropbox.read_search(&team, &[reply(401, json!({}))], 5).unwrap_err().contains("Reconnect"));
        assert!(Dropbox.read_search(&team, &[reply(0, json!(null))], 5).unwrap_err().contains("in time"));
    }
}
