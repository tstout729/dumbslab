//! monday.com: previews of linked items the connected account can open, on that account's own
//! address (`<slug>.monday.com`) only. Signing in uses monday's OAuth 2.1 flow (PKCE, access
//! tokens that expire, rotating refresh tokens), so the host's monday app needs "New OAuth Flow"
//! turned on.
//!
//! Docs: https://developer.monday.com/api-reference/docs/authentication,
//! https://developer.monday.com/api-reference/docs/api-versioning, https://developer.monday.com/apps/docs/oauth,
//! https://developer.monday.com/apps/docs/migrating-to-the-new-oauth-flow, https://developer.monday.com/api-reference/reference/me,
//! https://developer.monday.com/api-reference/reference/account, https://developer.monday.com/api-reference/reference/items,
//! https://developer.monday.com/api-reference/reference/column-values-v2

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use serde_json::{Map, Value, json};

use crate::connect::{
    Account, Connector, Credential, Detail, Field, Hit, HttpCall, HttpReply, OAuthApp, OAuthSpec, Preview, ProviderInfo, TokenSet, excerpt,
    host_of, http_error, opt, path_of, s, standard_token,
};

pub struct Monday;

const API: &str = "https://api.monday.com/v2";
/// The API version asked for; monday keeps each stable for about nine months.
const VERSION: &str = "2026-10";
const NAME: &str = "monday.com";
const NOT_FOUND: &str = "monday.com has no such item, or the connected account can't see it.";
const ME: &str = "query { me { id name email account { slug } } }";
const ITEM: &str = "query ($ids: [ID!]) { items(ids: $ids) { id name url state created_at updated_at creator { name } \
    board { name } group { title } column_values(types: [status]) { text } } }";

static INFO: ProviderInfo = ProviderInfo {
    id: "monday",
    name: NAME,
    about: "Preview linked items.",
    search: false,
    preview: true,
    oauth: Some(OAuthSpec {
        authorize_url: "https://auth.monday.com/oauth2/authorize",
        token_url: "https://auth.monday.com/oauth_ms/oauth/token",
        // account:read for the account's address; users:read for item creators' names.
        scopes: &["me:read", "account:read", "boards:read", "users:read"],
        scope_param: "scope",
        scope_separator: " ",
        extra: &[],
        pkce: true,
    }),
    token_fields: &[Field {
        key: "token",
        label: "Personal API token",
        help: "In monday.com, click your profile picture › Developers › API token › Show.",
        secret: true,
        optional: false,
    }],
    token_help: "https://developer.monday.com/api-reference/docs/authentication",
};

/// Personal tokens go as they are; tokens from signing in (the ones that refresh) are bearer tokens.
fn graphql(cred: &Credential, query: &str, variables: Value) -> HttpCall {
    let call = HttpCall::post_json(API, &json!({ "query": query, "variables": variables })).header("api-version", VERSION);
    if cred.refresh_token.is_some() { call.bearer(&cred.token) } else { call.header("authorization", cred.token.clone()) }
}

/// An account's address on monday.com: `acme` in `acme.monday.com`.
fn valid_slug(slug: &str) -> bool {
    !slug.is_empty() && slug.len() <= 63 && slug.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn numeric(id: &str) -> bool {
    !id.is_empty() && id.len() <= 20 && id.bytes().all(|b| b.is_ascii_digit())
}

/// GraphQL errors arrive with HTTP 200.
fn graphql_error(v: &Value) -> Option<String> {
    let message = opt(&v["errors"][0]["message"]).or_else(|| opt(&v["error_message"]))?;
    Some(format!("monday.com refused: {}", excerpt(&message, 200)))
}

/// Seconds until a JWT access token expires, from its `exp`. monday's token answer has no
/// `expires_in`.
fn jwt_expires_in(token: &str, now: DateTime<Utc>) -> Option<i64> {
    let payload = URL_SAFE_NO_PAD.decode(token.split('.').nth(1)?.trim_end_matches('=')).ok()?;
    let claims: Value = serde_json::from_slice(&payload).ok()?;
    claims["exp"].as_i64().map(|exp| exp - now.timestamp())
}

impl Connector for Monday {
    fn info(&self) -> &'static ProviderInfo {
        &INFO
    }

    fn profile(&self, cred: &Credential) -> Vec<HttpCall> {
        vec![graphql(cred, ME, json!({}))]
    }

    fn read_profile(&self, _cred: &Credential, replies: &[HttpReply]) -> Result<Account, String> {
        let r = replies.first().cloned().unwrap_or_default();
        if !r.ok() {
            return Err(match r.status {
                401 => "monday.com rejected that token. Check it was copied whole and hasn't been regenerated since.".into(),
                _ => http_error(NAME, &r),
            });
        }
        let v = r.json();
        if let Some(e) = graphql_error(&v) {
            return Err(e);
        }
        let me = &v["data"]["me"];
        let slug = s(&me["account"]["slug"]).to_ascii_lowercase();
        if !valid_slug(&slug) {
            return Err("monday.com didn't say which account that token belongs to.".into());
        }
        let label = opt(&me["email"]).or_else(|| opt(&me["name"])).unwrap_or_else(|| format!("{slug}.monday.com"));
        Ok(Account { label, settings: json!({ "id": me["id"], "slug": slug }) })
    }

    /// monday.com only previews links.
    fn search(&self, _cred: &Credential, _account: &Account, _q: &str, _limit: usize) -> Vec<HttpCall> {
        vec![]
    }

    fn read_search(&self, _account: &Account, _replies: &[HttpReply], _limit: usize) -> Result<Vec<Hit>, String> {
        Ok(vec![])
    }

    /// `https://acme.monday.com/boards/123/pulses/456` (or `…/boards/123/views/7/pulses/456`) →
    /// `456`, only on the connected account's own address.
    fn preview_target(&self, account: &Account, url: &str) -> Option<String> {
        let slug = account.settings["slug"].as_str().filter(|x| valid_slug(x))?;
        if host_of(url)? != format!("{slug}.monday.com") {
            return None;
        }
        let path = path_of(url);
        let item = match path.as_slice() {
            [b, board, p, item, ..] if b == "boards" && p == "pulses" && numeric(board) => item,
            [b, board, v, view, p, item, ..] if b == "boards" && v == "views" && p == "pulses" && numeric(board) && numeric(view) => item,
            _ => return None,
        };
        numeric(item).then(|| item.clone())
    }

    fn preview(&self, cred: &Credential, _account: &Account, target: &str) -> Vec<HttpCall> {
        vec![graphql(cred, ITEM, json!({ "ids": [target] }))]
    }

    fn read_preview(&self, account: &Account, target: &str, replies: &[HttpReply]) -> Result<Preview, String> {
        let r = replies.first().cloned().unwrap_or_default();
        if !r.ok() {
            return Err(match r.status {
                404 => NOT_FOUND.into(),
                _ => http_error(NAME, &r),
            });
        }
        let v = r.json();
        if let Some(e) = graphql_error(&v) {
            return Err(e);
        }
        let Some(i) = v["data"]["items"].as_array().and_then(|a| a.first()) else { return Err(NOT_FOUND.into()) };
        let status = i["column_values"].as_array().into_iter().flatten().find_map(|c| opt(&c["text"]));
        let mut details = vec![];
        if let Some(board) = opt(&i["board"]["name"]) {
            details.push(Detail { label: "Board".into(), value: board });
        }
        if let Some(group) = opt(&i["group"]["title"]) {
            details.push(Detail { label: "Group".into(), value: group });
        }
        if let Some(state) = opt(&i["state"]).filter(|x| x != "active") {
            details.push(Detail { label: "State".into(), value: state });
        }
        let slug = account.settings["slug"].as_str().unwrap_or_default();
        let url = opt(&i["url"]).unwrap_or_else(|| format!("https://{slug}.monday.com/pulses/{target}"));
        Ok(Preview {
            provider: "monday".into(),
            kind: "item".into(),
            title: s(&i["name"]),
            url,
            reference: format!("#{}", opt(&i["id"]).unwrap_or_else(|| target.to_string())),
            status,
            assignee: None,
            author: opt(&i["creator"]["name"]),
            created_at: opt(&i["created_at"]),
            updated_at: opt(&i["updated_at"]),
            description: String::new(),
            details,
        })
    }

    /// monday takes the token request as JSON.
    fn token_request(&self, app: &OAuthApp, form: Vec<(String, String)>) -> HttpCall {
        let mut body: Map<String, Value> = form.into_iter().map(|(k, v)| (k, Value::String(v))).collect();
        body.insert("client_id".into(), app.client_id.clone().into());
        body.insert("client_secret".into(), app.client_secret.clone().into());
        HttpCall::post_json(INFO.oauth.expect("monday.com signs in").token_url, &Value::Object(body)).header("accept", "application/json")
    }

    fn read_token(&self, reply: &HttpReply) -> Result<TokenSet, String> {
        let mut tokens = standard_token(NAME, reply)?;
        if tokens.expires_in.is_none() {
            tokens.expires_in = jwt_expires_in(&tokens.access_token, Utc::now());
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

    fn acme() -> Account {
        Account { label: "ada@acme.com".into(), settings: json!({ "slug": "acme" }) }
    }

    fn jwt(claims: Value) -> String {
        format!("eyJhbGciOiJIUzI1NiJ9.{}.sig", URL_SAFE_NO_PAD.encode(claims.to_string()))
    }

    #[test]
    fn connects_with_a_token_or_by_signing_in() {
        let personal = Credential { token: "eyJpersonal".into(), ..Default::default() };
        let call = &Monday.profile(&personal)[0];
        assert_eq!((call.method, call.url.as_str()), ("POST", "https://api.monday.com/v2"));
        assert!(call.headers.contains(&("authorization".into(), "eyJpersonal".into())));
        assert!(call.headers.contains(&("api-version".into(), "2026-10".into())));
        let body: Value = serde_json::from_str(call.body.as_deref().unwrap()).unwrap();
        assert!(body["query"].as_str().unwrap().contains("account { slug }"));
        let signed_in = Credential { token: "eyJoauth".into(), refresh_token: Some("r".into()), ..Default::default() };
        assert!(Monday.profile(&signed_in)[0].headers.contains(&("authorization".into(), "Bearer eyJoauth".into())));

        let me = json!({ "data": { "me": { "id": "42", "name": "Ada", "email": "ada@acme.com", "account": { "slug": "Acme" } } } });
        let account = Monday.read_profile(&personal, &[reply(200, me)]).unwrap();
        assert_eq!(account.label, "ada@acme.com");
        assert_eq!(account.settings["slug"], "acme");
        for slug in ["", "evil.test/x", "acme.evil", "a b"] {
            let me = json!({ "data": { "me": { "email": "ada@acme.com", "account": { "slug": slug } } } });
            assert!(Monday.read_profile(&personal, &[reply(200, me)]).is_err(), "{slug}");
        }
        assert!(Monday.read_profile(&personal, &[reply(401, json!({}))]).unwrap_err().contains("rejected that token"));
        let denied = json!({ "errors": [{ "message": "Permission Denied! Your token doesn't grant access to me:read" }] });
        assert!(Monday.read_profile(&personal, &[reply(200, denied)]).unwrap_err().contains("me:read"));
        assert!(Monday.search(&personal, &acme(), "x", 5).is_empty());
        assert!(Monday.read_search(&acme(), &[], 5).unwrap().is_empty());
    }

    #[test]
    fn signs_in_with_oauth_2_1() {
        let app = OAuthApp { client_id: "cid".into(), client_secret: "sec".into() };
        let call = Monday.token_request(&app, vec![("grant_type".into(), "refresh_token".into()), ("refresh_token".into(), "r1".into())]);
        assert_eq!(call.url, "https://auth.monday.com/oauth_ms/oauth/token");
        let body: Value = serde_json::from_str(call.body.as_deref().unwrap()).unwrap();
        assert_eq!(body, json!({ "grant_type": "refresh_token", "refresh_token": "r1", "client_id": "cid", "client_secret": "sec" }));
        assert!(Monday.info().oauth.unwrap().pkce);

        // The answer has no expires_in: the access token's own `exp` says when it expires.
        let now = DateTime::from_timestamp(1_800_000_000, 0).unwrap();
        assert_eq!(jwt_expires_in(&jwt(json!({ "exp": 1_800_003_600 })), now), Some(3600));
        assert_eq!(jwt_expires_in("not-a-jwt", now), None);
        let token = jwt(json!({ "exp": Utc::now().timestamp() + 3600 }));
        let t = Monday.read_token(&reply(200, json!({ "access_token": token, "refresh_token": "r2", "token_type": "Bearer" }))).unwrap();
        assert_eq!(t.refresh_token.as_deref(), Some("r2"));
        assert!(t.expires_in.is_some_and(|s| (3590..=3600).contains(&s)), "{:?}", t.expires_in);
        assert!(Monday.read_token(&reply(400, json!({ "error": "invalid_grant" }))).unwrap_err().contains("invalid_grant"));
    }

    #[test]
    fn previews_items_on_the_account_only() {
        let a = acme();
        assert_eq!(Monday.preview_target(&a, "https://acme.monday.com/boards/123/pulses/456").as_deref(), Some("456"));
        assert_eq!(Monday.preview_target(&a, "https://ACME.monday.com/boards/123/views/7/pulses/456?x=1#u").as_deref(), Some("456"));
        for no in [
            "https://other.monday.com/boards/123/pulses/456",
            "https://acme.monday.com.evil.test/boards/123/pulses/456",
            "https://acmemonday.com/boards/123/pulses/456",
            "https://x.acme.monday.com/boards/123/pulses/456",
            "https://evil.test/acme.monday.com/boards/123/pulses/456",
            "https://acme.monday.com/boards/123",
            "https://acme.monday.com/boards/123/pulses/45a",
            "https://acme.monday.com/boards/abc/pulses/456",
            "https://acme.monday.com/boards/123/views/x/pulses/456",
        ] {
            assert_eq!(Monday.preview_target(&a, no), None, "{no}");
        }
        assert_eq!(Monday.preview_target(&Account::default(), "https://acme.monday.com/boards/123/pulses/456"), None, "no account");

        let call = &Monday.preview(&Credential { token: "t".into(), ..Default::default() }, &a, "456")[0];
        let body: Value = serde_json::from_str(call.body.as_deref().unwrap()).unwrap();
        assert_eq!(body["variables"], json!({ "ids": ["456"] }));
        assert!(body["query"].as_str().unwrap().contains("items(ids: $ids)"));

        let item = json!({ "data": { "items": [{ "id": "456", "name": "Launch plan", "url": "https://acme.monday.com/boards/123/pulses/456",
            "state": "archived", "created_at": "2026-09-01T10:00:00Z", "updated_at": "2026-10-01T10:00:00Z", "creator": { "name": "Ada" },
            "board": { "name": "Roadmap" }, "group": { "title": "Q4" }, "column_values": [{ "text": "" }, { "text": "Working on it" }] }] } });
        let p = Monday.read_preview(&a, "456", &[reply(200, item)]).unwrap();
        assert_eq!((p.kind.as_str(), p.title.as_str(), p.reference.as_str()), ("item", "Launch plan", "#456"));
        assert_eq!((p.status.as_deref(), p.author.as_deref()), (Some("Working on it"), Some("Ada")));
        assert_eq!((p.created_at.as_deref(), p.updated_at.as_deref()), (Some("2026-09-01T10:00:00Z"), Some("2026-10-01T10:00:00Z")));
        assert_eq!(p.url, "https://acme.monday.com/boards/123/pulses/456");
        assert_eq!(
            p.details,
            vec![
                Detail { label: "Board".into(), value: "Roadmap".into() },
                Detail { label: "Group".into(), value: "Q4".into() },
                Detail { label: "State".into(), value: "archived".into() },
            ]
        );

        assert!(Monday.read_preview(&a, "456", &[reply(200, json!({ "data": { "items": [] } }))]).unwrap_err().contains("can't see"));
        assert!(Monday.read_preview(&a, "456", &[reply(404, json!({}))]).unwrap_err().contains("can't see"));
        assert!(Monday.read_preview(&a, "456", &[reply(401, json!({}))]).unwrap_err().contains("Reconnect"));
        assert!(Monday.read_preview(&a, "456", &[reply(0, Value::Null)]).unwrap_err().contains("in time"));
    }
}
