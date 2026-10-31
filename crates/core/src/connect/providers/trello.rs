//! Trello: previews of linked cards the connected account can open. People connect with an API
//! key and token, or by signing in with Atlassian (Trello's OAuth 2.0, once the host registered a
//! confidential OAuth 2.0 client in Trello's app admin). Trello's older OAuth 1.0 isn't used.
//!
//! Docs: https://developer.atlassian.com/cloud/trello/guides/rest-api/authorization/,
//! https://developer.atlassian.com/cloud/trello/guides/rest-api/oauth-2-confidential-client-usage/,
//! https://developer.atlassian.com/cloud/trello/scopes-for-oauth-2-3LO-and-forge-apps/,
//! https://developer.atlassian.com/cloud/trello/rest/api-group-cards/

use chrono::DateTime;
use serde_json::{Map, Value, json};

use crate::connect::{
    Account, Connector, Credential, Detail, Field, Hit, HttpCall, HttpReply, OAuthApp, OAuthSpec, Preview, ProviderInfo, excerpt, host_of,
    http_error, opt, path_of, s,
};
use crate::util::ts;

pub struct Trello;

const API: &str = "https://api.trello.com/1";
const NOT_FOUND: &str = "Trello has no such card, or the connected account can't see it.";
const CARD_QUERY: &str = "fields=name,closed,desc,dateLastActivity,due,dueComplete,idShort,url\
    &members=true&member_fields=fullName,username&board=true&board_fields=name&list=true&list_fields=name\
    &actions=createCard&action_fields=date";

static INFO: ProviderInfo = ProviderInfo {
    id: "trello",
    name: "Trello",
    about: "Preview linked cards.",
    search: false,
    preview: true,
    oauth: Some(OAuthSpec {
        authorize_url: "https://auth.atlassian.com/authorize",
        token_url: "https://auth.atlassian.com/oauth/token",
        // offline_access brings a refresh token; access tokens last an hour.
        scopes: &["read:member:trello", "read:board:trello", "offline_access"],
        scope_param: "scope",
        scope_separator: " ",
        extra: &[("prompt", "consent")],
        pkce: true,
        site: None,
    }),
    token_fields: &[
        Field {
            key: "key",
            label: "API key",
            help: "The API key of a Power-Up you made at trello.com/power-ups/admin (its API key tab).",
            secret: false,
            optional: false,
        },
        Field {
            key: "token",
            label: "Token",
            help: "A token for that key: follow the Token link next to the key and allow access.",
            secret: true,
            optional: false,
        },
    ],
    token_help: "https://trello.com/power-ups/admin",
};

/// Keys and tokens are letters and digits.
fn well_formed(v: &str) -> bool {
    !v.is_empty() && v.len() <= 256 && v.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// With an API key, Trello takes the key and token in an OAuth-style header, so neither sits in
/// URLs; tokens from signing in are bearer tokens. A malformed key or token is left out of the
/// header ([`Connector::read_profile`] says what's wrong).
fn api(path: &str, cred: &Credential) -> HttpCall {
    let call = HttpCall::get(format!("{API}{path}")).header("accept", "application/json");
    match cred.fields.get("key") {
        Some(key) => {
            let clean = |v: &str| if well_formed(v) { v.to_string() } else { String::new() };
            call.header("authorization", format!("OAuth oauth_consumer_key=\"{}\", oauth_token=\"{}\"", clean(key), clean(&cred.token)))
        }
        None => call.bearer(&cred.token),
    }
}

/// Trello ids start with when the thing was made: seconds since 1970, in hex.
fn created_at(id: &str) -> Option<String> {
    let secs = i64::from_str_radix(id.get(..8)?, 16).ok()?;
    DateTime::from_timestamp(secs, 0).map(ts)
}

impl Connector for Trello {
    fn info(&self) -> &'static ProviderInfo {
        &INFO
    }

    fn profile(&self, cred: &Credential) -> Vec<HttpCall> {
        vec![api("/members/me?fields=username,fullName", cred)]
    }

    fn read_profile(&self, cred: &Credential, replies: &[HttpReply]) -> Result<Account, String> {
        let with_key = cred.fields.get("key");
        if with_key.is_some_and(|k| !well_formed(k)) {
            return Err(
                "That Trello API key doesn't look right: it's only letters and digits. Copy it again from trello.com/power-ups/admin."
                    .into(),
            );
        }
        if with_key.is_some() && !well_formed(&cred.token) {
            return Err("That Trello token doesn't look right: it's only letters and digits. Copy it again.".into());
        }
        let r = replies.first().cloned().unwrap_or_default();
        if !r.ok() {
            return Err(match r.status {
                400 | 401 if with_key.is_some() => {
                    "Trello rejected that API key and token. Check both were copied whole and the token was made with that key.".into()
                }
                _ => http_error("Trello", &r),
            });
        }
        let m = r.json();
        let username = s(&m["username"]);
        if username.is_empty() {
            return Err("Trello didn't say whose account that is.".into());
        }
        Ok(Account { label: format!("@{username}"), settings: json!({ "id": s(&m["id"]), "username": username }) })
    }

    /// Trello only previews links.
    fn search(&self, _cred: &Credential, _account: &Account, _q: &str, _limit: usize) -> Vec<HttpCall> {
        vec![]
    }

    fn read_search(&self, _account: &Account, _replies: &[HttpReply], _limit: usize) -> Result<Vec<Hit>, String> {
        Ok(vec![])
    }

    /// `https://trello.com/c/AbCd1234/12-fix-deploy` → `AbCd1234` (the card's short link).
    fn preview_target(&self, _account: &Account, url: &str) -> Option<String> {
        if host_of(url)? != "trello.com" {
            return None;
        }
        match path_of(url).as_slice() {
            [c, short, ..] if c == "c" && short.len() <= 24 && well_formed(short) => Some(short.clone()),
            _ => None,
        }
    }

    fn preview(&self, cred: &Credential, _account: &Account, target: &str) -> Vec<HttpCall> {
        vec![api(&format!("/cards/{target}?{CARD_QUERY}"), cred)]
    }

    fn read_preview(&self, _account: &Account, _target: &str, replies: &[HttpReply]) -> Result<Preview, String> {
        let r = replies.first().cloned().unwrap_or_default();
        if !r.ok() {
            return Err(match r.status {
                // Trello answers 401 "unauthorized card permission requested" for cards on boards the
                // account can't open, and 401 "invalid token" for bad credentials.
                400 | 404 => NOT_FOUND.into(),
                401 if r.body.contains("permission") => NOT_FOUND.into(),
                _ => http_error("Trello", &r),
            });
        }
        let c = r.json();
        let board = s(&c["board"]["name"]);
        let members: Vec<String> = c["members"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|m| opt(&m["fullName"]).or_else(|| opt(&m["username"]).map(|u| format!("@{u}"))))
            .collect();
        let mut details = vec![];
        if !board.is_empty() {
            details.push(Detail { label: "Board".into(), value: board.clone() });
        }
        if let Some(list) = opt(&c["list"]["name"]) {
            details.push(Detail { label: "List".into(), value: list });
        }
        if let Some(due) = opt(&c["due"]) {
            let day = due.get(..10).unwrap_or(&due).to_string();
            let value = if c["dueComplete"].as_bool() == Some(true) { format!("{day} (complete)") } else { day };
            details.push(Detail { label: "Due".into(), value });
        }
        let number = c["idShort"].as_i64().map(|n| format!("#{n}")).unwrap_or_default();
        Ok(Preview {
            provider: "trello".into(),
            kind: "card".into(),
            title: s(&c["name"]),
            url: s(&c["url"]),
            reference: [board, number].into_iter().filter(|x| !x.is_empty()).collect::<Vec<_>>().join(" "),
            status: Some(if c["closed"].as_bool() == Some(true) { "archived" } else { "open" }.into()),
            assignee: Some(members.join(", ")).filter(|m| !m.is_empty()),
            author: opt(&c["actions"][0]["memberCreator"]["fullName"]),
            created_at: created_at(c["id"].as_str().unwrap_or_default()),
            updated_at: opt(&c["dateLastActivity"]),
            // Card descriptions are Markdown.
            description: excerpt(&crate::markdown::plain_text(c["desc"].as_str().unwrap_or_default()), 300),
            details,
        })
    }

    /// Atlassian takes the token request as JSON.
    fn token_request(&self, app: &OAuthApp, token_url: &str, form: Vec<(String, String)>) -> HttpCall {
        let mut body: Map<String, Value> = form.into_iter().map(|(k, v)| (k, Value::String(v))).collect();
        body.insert("client_id".into(), app.client_id.clone().into());
        body.insert("client_secret".into(), app.client_secret.clone().into());
        HttpCall::post_json(token_url, &Value::Object(body)).header("accept", "application/json")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reply(status: u16, body: Value) -> HttpReply {
        HttpReply { status, body: body.to_string() }
    }

    fn text(status: u16, body: &str) -> HttpReply {
        HttpReply { status, body: body.into() }
    }

    fn keyed() -> Credential {
        Credential { token: "ATTAtok123".into(), fields: [("key".to_string(), "abc123".to_string())].into(), ..Default::default() }
    }

    #[test]
    fn connects_with_a_key_and_token_or_by_signing_in() {
        let calls = Trello.profile(&keyed());
        assert_eq!(calls[0].url, "https://api.trello.com/1/members/me?fields=username,fullName");
        assert!(
            calls[0].headers.contains(&("authorization".into(), "OAuth oauth_consumer_key=\"abc123\", oauth_token=\"ATTAtok123\"".into())),
            "the key and token stay out of the URL"
        );
        let signed_in = Credential { token: "eyJ.x.y".into(), refresh_token: Some("r".into()), ..Default::default() };
        assert!(Trello.profile(&signed_in)[0].headers.contains(&("authorization".into(), "Bearer eyJ.x.y".into())));

        let account =
            Trello.read_profile(&keyed(), &[reply(200, json!({ "id": "5abb", "username": "ada", "fullName": "Ada L" }))]).unwrap();
        assert_eq!(account.label, "@ada");
        assert_eq!(account.settings["username"], "ada");
        assert!(Trello.read_profile(&keyed(), &[text(401, "invalid key")]).unwrap_err().contains("rejected that API key"));
        assert!(Trello.read_profile(&signed_in, &[text(401, "invalid token")]).unwrap_err().contains("Reconnect"));
        assert!(Trello.read_profile(&keyed(), &[reply(0, Value::Null)]).unwrap_err().contains("in time"));

        // A key or token that could break the header never reaches it.
        let bad = Credential { token: "t\"\r\nx: y".into(), fields: [("key".to_string(), "k".to_string())].into(), ..Default::default() };
        assert!(Trello.profile(&bad)[0].headers.iter().all(|(_, v)| !v.contains('\n') && !v.contains("x: y")));
        assert!(Trello.read_profile(&bad, &[text(401, "invalid token")]).unwrap_err().contains("token doesn't look right"));
        let bad_key = Credential { token: "t".into(), fields: [("key".to_string(), "a b".to_string())].into(), ..Default::default() };
        assert!(Trello.read_profile(&bad_key, &[]).unwrap_err().contains("API key doesn't look right"));
    }

    #[test]
    fn signs_in_with_atlassian() {
        let app = OAuthApp { client_id: "cid".into(), client_secret: "sec".into() };
        let call = Trello.token_request(
            &app,
            INFO.oauth.unwrap().token_url,
            vec![("grant_type".into(), "authorization_code".into()), ("code".into(), "c1".into())],
        );
        assert_eq!(call.url, "https://auth.atlassian.com/oauth/token");
        assert!(call.headers.contains(&("content-type".into(), "application/json".into())));
        let body: Value = serde_json::from_str(call.body.as_deref().unwrap()).unwrap();
        assert_eq!(body, json!({ "grant_type": "authorization_code", "code": "c1", "client_id": "cid", "client_secret": "sec" }));
        assert!(Trello.info().oauth.unwrap().pkce);
        assert!(Trello.search(&keyed(), &Account::default(), "x", 5).is_empty());
        assert!(Trello.read_search(&Account::default(), &[], 5).unwrap().is_empty());
    }

    #[test]
    fn previews_cards() {
        let a = Account::default();
        assert_eq!(Trello.preview_target(&a, "https://trello.com/c/AbCd1234/12-fix-deploy").as_deref(), Some("AbCd1234"));
        assert_eq!(Trello.preview_target(&a, "https://www.trello.com/c/AbCd1234?filter=x#y").as_deref(), Some("AbCd1234"));
        for no in [
            "https://trello.com/b/AbCd1234/roadmap",
            "https://trello.com/c/",
            "https://trello.com/c/Ab-Cd/1",
            "https://trello.com/c/..%2F..%2Fmembers%2Fme",
            "https://trello.com.evil.test/c/AbCd1234",
            "https://nottrello.com/c/AbCd1234",
            "https://evil.test/trello.com/c/AbCd1234",
        ] {
            assert_eq!(Trello.preview_target(&a, no), None, "{no}");
        }

        let calls = Trello.preview(&keyed(), &a, "AbCd1234");
        assert!(calls[0].url.starts_with("https://api.trello.com/1/cards/AbCd1234?fields=name,closed,desc"), "{}", calls[0].url);
        assert!(calls[0].url.contains("&members=true&member_fields=fullName,username&board=true&board_fields=name&list=true"));
        assert!(!calls[0].url.contains("ATTAtok123"));

        let card = json!({ "id": "5f5e1000aaaaaaaaaaaaaaaa", "name": "Fix deploy", "closed": false, "idShort": 12,
            "desc": "**Steps**\n\n1. deploy <b>now</b>", "dateLastActivity": "2026-10-02T10:00:00.000Z", "due": "2026-11-01T12:00:00.000Z",
            "dueComplete": true, "url": "https://trello.com/c/AbCd1234/12-fix-deploy",
            "members": [{ "fullName": "Bo Bell", "username": "bo" }, { "fullName": "", "username": "cy" }],
            "board": { "name": "Platform" }, "list": { "name": "Doing" },
            "actions": [{ "date": "2020-09-13T12:26:40.000Z", "memberCreator": { "fullName": "Ada L" } }] });
        let p = Trello.read_preview(&a, "AbCd1234", &[reply(200, card)]).unwrap();
        assert_eq!((p.kind.as_str(), p.title.as_str(), p.reference.as_str()), ("card", "Fix deploy", "Platform #12"));
        assert_eq!((p.status.as_deref(), p.assignee.as_deref(), p.author.as_deref()), (Some("open"), Some("Bo Bell, @cy"), Some("Ada L")));
        assert_eq!(p.created_at.as_deref(), Some("2020-09-13T12:26:40.000Z"));
        assert_eq!(p.updated_at.as_deref(), Some("2026-10-02T10:00:00.000Z"));
        assert_eq!(p.description, "Steps deploy now");
        assert_eq!(
            p.details,
            vec![
                Detail { label: "Board".into(), value: "Platform".into() },
                Detail { label: "List".into(), value: "Doing".into() },
                Detail { label: "Due".into(), value: "2026-11-01 (complete)".into() },
            ]
        );
        let archived = Trello.read_preview(&a, "x", &[reply(200, json!({ "name": "Old", "closed": true }))]).unwrap();
        assert_eq!((archived.status.as_deref(), archived.reference.as_str(), archived.created_at), (Some("archived"), "", None));

        assert!(Trello.read_preview(&a, "x", &[text(404, "The requested resource was not found.")]).unwrap_err().contains("can't see"));
        assert!(Trello.read_preview(&a, "x", &[text(401, "unauthorized card permission requested")]).unwrap_err().contains("can't see"));
        assert!(Trello.read_preview(&a, "x", &[text(401, "invalid token")]).unwrap_err().contains("Reconnect"));
        assert!(Trello.read_preview(&a, "x", &[reply(0, Value::Null)]).unwrap_err().contains("in time"));
    }
}
