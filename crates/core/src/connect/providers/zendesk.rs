//! Zendesk: tickets and Help Center articles the connected agent can see, and previews of linked
//! tickets. Every request goes to the connection's one subdomain, kept sealed with its token.
//! People connect one of two ways:
//!
//! - **Signing in** (OAuth), once the host has a Zendesk *global* OAuth client: a client Zendesk
//!   approves for an app made for many customers. Its sign-in page and token endpoint are on each
//!   customer's own `https://<subdomain>.zendesk.com` (`/oauth/authorizations/new`,
//!   `/oauth/tokens`, JSON bodies), so the person names their subdomain first; the core keeps it
//!   with the sign-in and the credential (see [`crate::connect::OAuthSpec::site`]). Sign-in uses
//!   PKCE with the client secret, and asks for `read` (every GET; no granular scope covers search
//!   across tickets and Help Center). Access tokens expire and come with a refresh token that
//!   Zendesk replaces on every refresh; DumbSlab asks for 8-hour access tokens and 90-day refresh
//!   tokens (Zendesk's longest), so a connection lasts while it's used at least every 90 days.
//! - **An API token**, with the subdomain and an agent's email, sent as Basic auth
//!   (`<email>/token:<token>`). Zendesk is retiring them: since October 27, 2026 no account can
//!   create one (accounts opened since July 28, 2026 never could), tokens unused for 30 days are
//!   switched off, and all stop working on April 30, 2027. Zendesk's terms don't let an app made
//!   for many customers use customers' own tokens or OAuth clients; a self-hosted server connecting
//!   its own company's Zendesk is internal use, which they allow. An API token works with any
//!   user's email in the account, so such a connection acts as whoever's email is given.
//!
//! The subdomain is checked strictly (one DNS label, lowercase letters, digits and hyphens) before
//! it's used, and again before every request; a link is previewed only when it's on the
//! connection's own subdomain.
//!
//! Docs: https://developer.zendesk.com/api-reference/introduction/security-and-auth/,
//! https://support.zendesk.com/hc/en-us/articles/10851263566234,
//! https://developer.zendesk.com/documentation/api-basics/authentication/oauth-migration/,
//! https://developer.zendesk.com/documentation/marketplace/building-a-marketplace-app/set-up-a-global-oauth-client/,
//! https://support.zendesk.com/hc/en-us/articles/4408845965210 (authorization requests, refresh tokens),
//! https://developer.zendesk.com/api-reference/ticketing/oauth/grant_type_tokens/ (token requests, scopes, expiry),
//! https://developer.zendesk.com/documentation/api-basics/authentication/oauth-pkce/,
//! https://developer.zendesk.com/api-reference/ticketing/users/users/#show-self,
//! https://developer.zendesk.com/api-reference/ticketing/ticket-management/search/,
//! https://developer.zendesk.com/api-reference/help_center/help-center-api/help_center_search/,
//! https://developer.zendesk.com/api-reference/ticketing/tickets/tickets/#show-ticket,
//! https://developer.zendesk.com/documentation/ticketing/using-the-zendesk-api/side_loading/

use std::collections::BTreeMap;

use serde_json::{Map, Value, json};

use crate::connect::{
    Account, Connector, Credential, Detail, Field, Hit, HttpCall, HttpReply, OAuthApp, OAuthSpec, Preview, ProviderInfo, Site, excerpt,
    host_of, html_text, http_error, opt, path_of, s,
};

pub struct Zendesk;

/// How long access tokens from signing in last: a working day between refreshes.
const ACCESS_TOKEN_SECS: i64 = 8 * 60 * 60;
/// How long refresh tokens last: 90 days, the most Zendesk allows. Each refresh brings a new one.
const REFRESH_TOKEN_SECS: i64 = 90 * 24 * 60 * 60;

/// The subdomain, asked for both before signing in and with an API token.
const SUBDOMAIN: Field = Field {
    key: "subdomain",
    label: "Zendesk subdomain",
    help: "The part before .zendesk.com, like `acme` for acme.zendesk.com. Not a custom domain.",
    secret: false,
    optional: false,
};

static INFO: ProviderInfo = ProviderInfo {
    id: "zendesk",
    name: "Zendesk",
    about: "Search tickets and Help Center articles, and preview linked tickets.",
    search: true,
    preview: true,
    oauth: Some(OAuthSpec {
        // Paths on the customer's own https://<subdomain>.zendesk.com.
        authorize_url: "/oauth/authorizations/new",
        token_url: "/oauth/tokens",
        scopes: &["read"],
        scope_param: "scope",
        scope_separator: " ",
        extra: &[],
        pkce: true,
        site: Some(SUBDOMAIN),
    }),
    token_fields: &[
        SUBDOMAIN,
        Field { key: "email", label: "Email", help: "The email you sign in to Zendesk with.", secret: false, optional: false },
        Field {
            key: "token",
            label: "API token",
            help: "From Admin Center › Apps and integrations › APIs › Zendesk API. Zendesk no longer makes new API tokens, and existing ones stop working on April 30, 2027.",
            secret: true,
            optional: false,
        },
    ],
    token_help: "https://support.zendesk.com/hc/en-us/articles/4408889192858",
};

fn reconnect() -> String {
    "Zendesk needs you to connect it again (Settings › Connected apps).".into()
}

/// A DNS label as Zendesk and Freshdesk use them: `[a-z0-9][a-z0-9-]*`.
fn valid_label(label: &str) -> bool {
    label.len() <= 63
        && label.bytes().next().is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && label.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// A Zendesk subdomain, from `acme`, `acme.zendesk.com` or a link into it.
pub fn subdomain(input: &str) -> Result<String, String> {
    let raw = input.trim().to_ascii_lowercase();
    let host =
        if raw.contains("://") { host_of(&raw).unwrap_or_default() } else { raw.split(['/', '?', '#']).next().unwrap_or_default().into() };
    let label = host.strip_suffix(".zendesk.com").unwrap_or(&host);
    if valid_label(label) {
        Ok(label.to_string())
    } else {
        Err("Enter your Zendesk subdomain: the part before .zendesk.com, like acme.".into())
    }
}

fn valid_email(input: &str) -> Result<String, String> {
    let email = input.trim();
    // `:` would end the Basic auth user name early.
    if crate::util::is_valid_email(email) && !email.contains([':', '/']) {
        Ok(email.to_string())
    } else {
        Err("Enter the email you sign in to Zendesk with.".into())
    }
}

/// The connected account's Zendesk, like `acme.zendesk.com`, checked again before any request.
fn host(account: &Account) -> Option<String> {
    let host = account.settings["host"].as_str()?;
    valid_label(host.strip_suffix(".zendesk.com")?).then(|| host.to_string())
}

/// The host the credential belongs to: its own sealed subdomain, which must also be the account's.
/// So a token only ever goes to the Zendesk it came from, whatever the saved settings say.
fn cred_host(cred: &Credential, account: &Account) -> Option<String> {
    let own = format!("{}.zendesk.com", subdomain(cred.field("subdomain")).ok()?);
    (host(account)? == own).then_some(own)
}

/// Connected by signing in: an OAuth access token, without the email an API token goes with.
fn signed_in(cred: &Credential) -> bool {
    !cred.fields.contains_key("email")
}

fn api(host: &str, path: &str, cred: &Credential) -> HttpCall {
    let call = HttpCall::get(format!("https://{host}/api/v2/{path}"));
    let call =
        if signed_in(cred) { call.bearer(&cred.token) } else { call.basic(&format!("{}/token", cred.field("email").trim()), &cred.token) };
    call.header("accept", "application/json")
}

/// Sideloaded users' names by ID.
fn names(users: &Value) -> BTreeMap<i64, String> {
    users.as_array().into_iter().flatten().filter_map(|u| Some((u["id"].as_i64()?, opt(&u["name"])?))).collect()
}

/// Zendesk's status as people read it: `hold` is shown as "on hold".
fn status(v: &Value) -> Option<String> {
    opt(v).map(|st| if st == "hold" { "on hold".into() } else { st })
}

fn ticket_hit(host: &str, t: &Value, users: &BTreeMap<i64, String>) -> Hit {
    let id = t["id"].as_i64().unwrap_or_default();
    Hit {
        provider: "zendesk".into(),
        kind: "ticket".into(),
        title: opt(&t["subject"]).unwrap_or_else(|| format!("Ticket #{id}")),
        url: format!("https://{host}/agent/tickets/{id}"),
        context: match status(&t["status"]) {
            Some(st) => format!("#{id} · {st}"),
            None => format!("#{id}"),
        },
        snippet: excerpt(t["description"].as_str().unwrap_or_default(), 240),
        updated_at: opt(&t["updated_at"]),
        author: t["requester_id"].as_i64().and_then(|r| users.get(&r).cloned()),
    }
}

fn article_hit(a: &Value) -> Hit {
    let text = opt(&a["snippet"]).or_else(|| opt(&a["body"])).unwrap_or_default();
    Hit {
        provider: "zendesk".into(),
        kind: "article".into(),
        title: s(&a["title"]),
        url: s(&a["html_url"]),
        context: "Help Center".into(),
        snippet: excerpt(&html_text(&text), 240),
        updated_at: opt(&a["updated_at"]),
        author: None,
    }
}

impl Connector for Zendesk {
    fn info(&self) -> &'static ProviderInfo {
        &INFO
    }

    fn profile(&self, cred: &Credential) -> Vec<HttpCall> {
        let email_ok = signed_in(cred) || valid_email(cred.field("email")).is_ok();
        match subdomain(cred.field("subdomain")) {
            Ok(sub) if email_ok => vec![api(&format!("{sub}.zendesk.com"), "users/me.json", cred)],
            // Nothing to ask; read_profile says what to fix.
            _ => vec![],
        }
    }

    fn read_profile(&self, cred: &Credential, replies: &[HttpReply]) -> Result<Account, String> {
        let host = format!("{}.zendesk.com", subdomain(cred.field("subdomain"))?);
        let email = if signed_in(cred) { None } else { Some(valid_email(cred.field("email"))?) };
        let r = replies.first().cloned().unwrap_or_default();
        if !r.ok() {
            return Err(match (r.status, &email) {
                (401, None) => format!("{host} didn't accept the sign-in. Try connecting again."),
                (401, Some(_)) => format!("{host} rejected that email and API token. Check both, and that the token is still active."),
                (404, _) => format!("There's no Zendesk at {host}. Check the subdomain."),
                _ => http_error("Zendesk", &r),
            });
        }
        let user = &r.json()["user"];
        // Without credentials Zendesk answers with an anonymous user, who has no ID.
        let Some(id) = user["id"].as_i64() else {
            return Err(match email {
                None => format!("{host} didn't recognize the sign-in. Try connecting again."),
                Some(_) => format!("{host} didn't recognize that email and API token."),
            });
        };
        let shown = opt(&user["email"]).or(email).or_else(|| opt(&user["name"])).unwrap_or_else(|| format!("User {id}"));
        if user["role"] == "end-user" {
            return Err(format!("{shown} is an end user in Zendesk. Only agents and admins can search tickets, so connect as an agent."));
        }
        Ok(Account { label: format!("{shown} ({host})"), settings: json!({ "host": host, "user_id": id }) })
    }

    fn search(&self, cred: &Credential, account: &Account, q: &str, limit: usize) -> Vec<HttpCall> {
        let Some(host) = cred_host(cred, account) else { return vec![] };
        let n = limit.clamp(1, 20);
        let tickets = urlencoding::encode(&format!("type:ticket {q}")).into_owned();
        let articles = urlencoding::encode(q).into_owned();
        vec![
            api(&host, &format!("search.json?query={tickets}&per_page={n}&include=tickets(users)"), cred),
            api(&host, &format!("help_center/articles/search.json?query={articles}&per_page={n}"), cred),
        ]
    }

    fn read_search(&self, account: &Account, replies: &[HttpReply], limit: usize) -> Result<Vec<Hit>, String> {
        let Some(host) = host(account) else { return Err(reconnect()) };
        let r = replies.first().cloned().unwrap_or_default();
        if !r.ok() {
            return Err(match r.status {
                400 | 422 => "Zendesk couldn't search for that. Try other words.".into(),
                _ => http_error("Zendesk", &r),
            });
        }
        let v = r.json();
        let users = names(&v["users"]);
        let tickets: Vec<Hit> = v["results"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|t| t["result_type"] == "ticket")
            .map(|t| ticket_hit(&host, t, &users))
            .collect();
        // Articles are a bonus: the search still counts if Help Center is off or fails.
        let articles: Vec<Hit> = replies
            .get(1)
            .filter(|r| r.ok())
            .map(|r| r.json()["results"].as_array().into_iter().flatten().map(article_hit).collect())
            .unwrap_or_default();
        // Up to half the results are articles when there are both.
        let mut hits: Vec<Hit> = tickets.into_iter().take(limit - articles.len().min(limit / 2)).collect();
        let room = limit - hits.len();
        hits.extend(articles.into_iter().take(room));
        Ok(hits)
    }

    /// `https://acme.zendesk.com/agent/tickets/123` → `123`, only on the connected account's own
    /// Zendesk. Without a connection (no host), any Zendesk's links are recognized, so the link
    /// can still be named; nothing is fetched for them.
    fn preview_target(&self, account: &Account, url: &str) -> Option<String> {
        let at = host_of(url)?;
        let ours = if account.settings["host"].is_null() {
            at.strip_suffix(".zendesk.com").is_some_and(valid_label)
        } else {
            host(account).is_some_and(|h| h == at)
        };
        if !ours {
            return None;
        }
        match path_of(url).as_slice() {
            [agent, tickets, id, ..] if agent == "agent" && tickets == "tickets" && id.parse::<u64>().is_ok() => Some(id.clone()),
            _ => None,
        }
    }

    fn preview(&self, cred: &Credential, account: &Account, target: &str) -> Vec<HttpCall> {
        match (cred_host(cred, account), target.parse::<u64>()) {
            (Some(host), Ok(id)) => vec![api(&host, &format!("tickets/{id}.json?include=users"), cred)],
            _ => vec![],
        }
    }

    fn read_preview(&self, account: &Account, target: &str, replies: &[HttpReply]) -> Result<Preview, String> {
        let Some(host) = host(account) else { return Err(reconnect()) };
        let r = replies.first().cloned().unwrap_or_default();
        if !r.ok() {
            return Err(match r.status {
                403 | 404 => "Zendesk has no such ticket, or the connected account can't see it.".into(),
                _ => http_error("Zendesk", &r),
            });
        }
        let v = r.json();
        let t = &v["ticket"];
        let users = names(&v["users"]);
        let person = |key: &str| t[key].as_i64().and_then(|id| users.get(&id).cloned());
        let id = t["id"].as_i64().map(|i| i.to_string()).unwrap_or_else(|| target.to_string());
        let mut details = vec![];
        if let Some(p) = opt(&t["priority"]) {
            details.push(Detail { label: "Priority".into(), value: p });
        }
        if let Some(k) = opt(&t["type"]) {
            details.push(Detail { label: "Type".into(), value: k });
        }
        Ok(Preview {
            provider: "zendesk".into(),
            kind: "ticket".into(),
            title: opt(&t["subject"]).unwrap_or_else(|| format!("Ticket #{id}")),
            url: format!("https://{host}/agent/tickets/{id}"),
            reference: format!("#{id}"),
            status: status(&t["status"]),
            assignee: person("assignee_id"),
            author: person("requester_id"),
            created_at: opt(&t["created_at"]),
            updated_at: opt(&t["updated_at"]),
            description: excerpt(t["description"].as_str().unwrap_or_default(), 300),
            details,
        })
    }

    /// `acme`, `ACME`, `acme.zendesk.com` or a link into it → `https://acme.zendesk.com`.
    /// Anything else (another domain, more labels, a port, a user name, characters outside
    /// `[a-z0-9-]`) is refused, never cut down to a part that would pass.
    fn sign_in_site(&self, input: &str) -> Result<Site, String> {
        let name = subdomain(input)?;
        Ok(Site { origin: format!("https://{name}.zendesk.com"), name })
    }

    /// Zendesk takes token requests as JSON, with the scope and how long the tokens should last.
    fn token_request(&self, app: &OAuthApp, token_url: &str, form: Vec<(String, String)>) -> HttpCall {
        let mut body: Map<String, Value> = form.into_iter().map(|(k, v)| (k, Value::String(v))).collect();
        body.insert("client_id".into(), app.client_id.clone().into());
        body.insert("client_secret".into(), app.client_secret.clone().into());
        body.insert("scope".into(), INFO.oauth.expect("Zendesk signs in").scopes.join(" ").into());
        body.insert("expires_in".into(), ACCESS_TOKEN_SECS.into());
        body.insert("refresh_token_expires_in".into(), REFRESH_TOKEN_SECS.into());
        HttpCall::post_json(token_url, &Value::Object(body)).header("accept", "application/json")
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;

    use super::*;

    fn reply(status: u16, body: Value) -> HttpReply {
        HttpReply { status, body: body.to_string() }
    }

    fn cred(subdomain: &str, email: &str) -> Credential {
        Credential {
            token: "tok".into(),
            fields: [("subdomain".to_string(), subdomain.to_string()), ("email".to_string(), email.to_string())].into(),
            ..Default::default()
        }
    }

    fn acme() -> Account {
        Account { label: "ada@acme.com (acme.zendesk.com)".into(), settings: json!({ "host": "acme.zendesk.com", "user_id": 1 }) }
    }

    #[test]
    fn subdomains_are_checked_and_normalized() {
        for ok in [
            "acme",
            " ACME ",
            "acme.zendesk.com",
            "https://acme.zendesk.com",
            "https://acme.zendesk.com/agent/tickets/1",
            "acme.zendesk.com/",
        ] {
            assert_eq!(subdomain(ok).as_deref(), Ok("acme"), "{ok}");
        }
        assert_eq!(subdomain("acme-2").as_deref(), Ok("acme-2"));
        for bad in [
            "",
            "-acme",
            "acme.evil.test",
            "acme.zendesk.com.evil.test",
            "https://evil.test/acme.zendesk.com",
            "a b",
            "acme_x",
            "zendesk.com",
        ] {
            assert!(subdomain(bad).is_err(), "{bad}");
        }
        assert!(subdomain(&"a".repeat(64)).is_err());
    }

    #[test]
    fn profile_checks_the_token_on_the_given_subdomain() {
        let c = cred("https://acme.zendesk.com/", "ada@acme.com");
        let calls = Zendesk.profile(&c);
        assert_eq!(calls[0].url, "https://acme.zendesk.com/api/v2/users/me.json");
        let basic = format!("Basic {}", STANDARD.encode("ada@acme.com/token:tok"));
        assert!(calls[0].headers.contains(&("authorization".into(), basic)));
        let me = json!({ "user": { "id": 7, "name": "Ada", "email": "ada@acme.com", "role": "agent" } });
        let account = Zendesk.read_profile(&c, &[reply(200, me)]).unwrap();
        assert_eq!(account.label, "ada@acme.com (acme.zendesk.com)");
        assert_eq!(account.settings, json!({ "host": "acme.zendesk.com", "user_id": 7 }));
        assert!(Zendesk.read_profile(&c, &[reply(401, json!({ "error": "Couldn't authenticate you" }))]).unwrap_err().contains("rejected"));
        assert!(Zendesk.read_profile(&c, &[reply(404, json!({}))]).unwrap_err().contains("no Zendesk at acme.zendesk.com"));
        assert!(Zendesk.read_profile(&c, &[reply(0, json!(null))]).unwrap_err().contains("in time"));
        let anonymous = json!({ "user": { "id": null, "name": "Anonymous user", "role": "end-user" } });
        assert!(Zendesk.read_profile(&c, &[reply(200, anonymous)]).unwrap_err().contains("didn't recognize"));
        let end_user = json!({ "user": { "id": 8, "email": "ada@acme.com", "role": "end-user" } });
        assert!(Zendesk.read_profile(&c, &[reply(200, end_user)]).unwrap_err().contains("end user"));
        // Bad input never reaches Zendesk.
        for bad in [cred("acme.zendesk.com.evil.test", "ada@acme.com"), cred("acme", "not-an-email"), cred("acme", "ada:x@acme.com")] {
            assert!(Zendesk.profile(&bad).is_empty());
            assert!(Zendesk.read_profile(&bad, &[]).unwrap_err().starts_with("Enter"));
        }
    }

    #[test]
    fn search_reads_tickets_and_articles() {
        let calls = Zendesk.search(&cred("acme", "ada@acme.com"), &acme(), "printer jam", 4);
        assert_eq!(
            calls[0].url,
            "https://acme.zendesk.com/api/v2/search.json?query=type%3Aticket%20printer%20jam&per_page=4&include=tickets(users)"
        );
        assert_eq!(calls[1].url, "https://acme.zendesk.com/api/v2/help_center/articles/search.json?query=printer%20jam&per_page=4");
        assert!(calls.iter().all(|c| c.headers.iter().any(|(k, v)| k == "authorization" && v.starts_with("Basic "))));
        let tickets = json!({ "results": [
            { "result_type": "ticket", "id": 12, "subject": "Printer jams", "description": "It jams\n\nevery day", "status": "hold",
              "updated_at": "2026-10-01T00:00:00Z", "requester_id": 5 },
            { "result_type": "user", "id": 5, "name": "Bo" },
            { "result_type": "ticket", "id": 13, "subject": "", "status": "open" },
            { "result_type": "ticket", "id": 14, "subject": "Third", "status": "new" },
            { "result_type": "ticket", "id": 15, "subject": "Fourth", "status": "new" }
        ], "users": [{ "id": 5, "name": "Bo" }] });
        let articles = json!({ "results": [
            { "result_type": "article", "title": "Clearing a jam", "html_url": "https://help.acme.com/hc/en-us/articles/9-Clearing-a-jam",
              "snippet": "Open the <em>printer</em> &amp; pull the <em>jam</em>", "body": "<p>Long</p>", "updated_at": "2026-09-01T00:00:00Z" },
            { "result_type": "article", "title": "Toner", "html_url": "https://help.acme.com/hc/en-us/articles/10", "body": "<p>Shake it</p><p>gently</p>" }
        ] });
        let hits = Zendesk.read_search(&acme(), &[reply(200, tickets.clone()), reply(200, articles.clone())], 4).unwrap();
        let kinds: Vec<&str> = hits.iter().map(|h| h.kind.as_str()).collect();
        assert_eq!(kinds, ["ticket", "ticket", "article", "article"]);
        let t = &hits[0];
        assert_eq!((t.title.as_str(), t.url.as_str()), ("Printer jams", "https://acme.zendesk.com/agent/tickets/12"));
        assert_eq!((t.context.as_str(), t.snippet.as_str(), t.author.as_deref()), ("#12 · on hold", "It jams every day", Some("Bo")));
        assert_eq!(hits[1].title, "Ticket #13");
        assert_eq!((hits[2].context.as_str(), hits[2].snippet.as_str()), ("Help Center", "Open the printer & pull the jam"));
        assert_eq!(hits[3].snippet, "Shake it gently");
        // Articles failing doesn't fail the search; tickets failing does.
        let hits = Zendesk.read_search(&acme(), &[reply(200, tickets), reply(404, json!({}))], 4).unwrap();
        assert_eq!(hits.len(), 4);
        assert!(hits.iter().all(|h| h.kind == "ticket"));
        assert!(Zendesk.read_search(&acme(), &[reply(401, json!({})), reply(200, articles)], 4).unwrap_err().contains("Reconnect"));
        assert!(Zendesk.read_search(&acme(), &[reply(0, json!(null))], 4).unwrap_err().contains("in time"));
        assert!(Zendesk.read_search(&acme(), &[reply(422, json!({}))], 4).unwrap_err().contains("other words"));
        assert!(Zendesk.search(&Credential::default(), &Account::default(), "x", 4).is_empty());
        assert!(Zendesk.read_search(&Account::default(), &[], 4).unwrap_err().contains("connect it again"));
    }

    #[test]
    fn previews_tickets_on_the_connected_zendesk_only() {
        let a = acme();
        assert_eq!(Zendesk.preview_target(&a, "https://acme.zendesk.com/agent/tickets/123").as_deref(), Some("123"));
        assert_eq!(Zendesk.preview_target(&a, "https://ACME.zendesk.com/agent/tickets/123/events?x=1#y").as_deref(), Some("123"));
        for no in [
            "https://acme.zendesk.com/agent/tickets",
            "https://acme.zendesk.com/agent/tickets/abc",
            "https://acme.zendesk.com/hc/en-us/articles/123",
            "https://beta.zendesk.com/agent/tickets/123",
            "https://acme.zendesk.com.evil.test/agent/tickets/123",
            "https://evil.test/acme.zendesk.com/agent/tickets/123",
            "https://acme.zendesk.co/agent/tickets/123",
        ] {
            assert_eq!(Zendesk.preview_target(&a, no), None, "{no}");
        }
        // Not connected: any Zendesk's ticket links are named, look-alikes still aren't.
        let none = Account::default();
        assert_eq!(Zendesk.preview_target(&none, "https://beta.zendesk.com/agent/tickets/9").as_deref(), Some("9"));
        assert_eq!(Zendesk.preview_target(&none, "https://beta.zendesk.com.evil.test/agent/tickets/9"), None);
        assert!(Zendesk.preview(&Credential::default(), &none, "9").is_empty());
        // A connection with a broken host never matches.
        let broken = Account { settings: json!({ "host": "evil.test" }), ..Default::default() };
        assert_eq!(Zendesk.preview_target(&broken, "https://evil.test/agent/tickets/9"), None);

        let calls = Zendesk.preview(&cred("acme", "ada@acme.com"), &a, "123");
        assert_eq!(calls[0].url, "https://acme.zendesk.com/api/v2/tickets/123.json?include=users");
        assert!(Zendesk.preview(&cred("acme", "ada@acme.com"), &a, "../users").is_empty());
        let ticket = json!({ "ticket": { "id": 123, "subject": "Refund", "status": "pending", "priority": "high", "type": null,
            "assignee_id": 2, "requester_id": 3, "created_at": "2026-10-01T00:00:00Z", "updated_at": "2026-10-02T00:00:00Z",
            "description": "Please refund\norder 9." },
            "users": [{ "id": 2, "name": "Ada" }, { "id": 3, "name": "Cy" }] });
        let p = Zendesk.read_preview(&a, "123", &[reply(200, ticket)]).unwrap();
        assert_eq!((p.kind.as_str(), p.reference.as_str(), p.status.as_deref()), ("ticket", "#123", Some("pending")));
        assert_eq!((p.title.as_str(), p.url.as_str()), ("Refund", "https://acme.zendesk.com/agent/tickets/123"));
        assert_eq!((p.assignee.as_deref(), p.author.as_deref()), (Some("Ada"), Some("Cy")));
        assert_eq!((p.created_at.as_deref(), p.description.as_str()), (Some("2026-10-01T00:00:00Z"), "Please refund order 9."));
        assert_eq!(p.details, vec![Detail { label: "Priority".into(), value: "high".into() }]);
        assert!(Zendesk.read_preview(&a, "123", &[reply(404, json!({}))]).unwrap_err().contains("can't see"));
        assert!(Zendesk.read_preview(&a, "123", &[reply(401, json!({}))]).unwrap_err().contains("Reconnect"));
        assert!(Zendesk.read_preview(&a, "123", &[reply(0, json!(null))]).unwrap_err().contains("in time"));
    }

    fn signed_in_cred(subdomain: &str) -> Credential {
        Credential {
            token: "oauth-at".into(),
            refresh_token: Some("oauth-rt".into()),
            fields: [("subdomain".to_string(), subdomain.to_string())].into(),
        }
    }

    #[test]
    fn sign_in_happens_only_on_one_zendesk_subdomain() {
        for (input, name) in
            [("acme", "acme"), (" ACME ", "acme"), ("Acme.Zendesk.com", "acme"), ("https://acme.zendesk.com/agent", "acme")]
        {
            let site = Zendesk.sign_in_site(input).unwrap();
            assert_eq!((site.name.as_str(), site.origin.as_str()), (name, "https://acme.zendesk.com"), "{input}");
        }
        // Whatever tries to name another host, or smuggle one in, is refused, not tidied up.
        for bad in [
            "evil.com#",
            "evil.com",
            "a.b",
            "acme.zendesk.com.",
            "acme.zendesk.com:443",
            "acme.zendesk.com@evil.com",
            "https://acme.zendesk.com@evil.com/",
            "https://evil.com#.zendesk.com",
            "https://evil.com/.zendesk.com",
            "acme%2eevil.com",
            "acme\\evil.com",
            "ac me",
            "acme\n.evil.com",
            "ácme",
            "acme\u{2024}evil",
            "аcme", // Cyrillic а
            "",
            "-acme",
            "zendesk.com",
            "//evil.com",
        ] {
            assert!(Zendesk.sign_in_site(bad).is_err(), "{bad:?}");
        }
        assert!(Zendesk.sign_in_site(&"a".repeat(64)).is_err());

        // The core puts the spec's paths on that origin, and nowhere else.
        let urls = crate::connect::oauth_urls(&Zendesk, &signed_in_cred("acme")).unwrap();
        assert_eq!(urls, ("https://acme.zendesk.com/oauth/authorizations/new".into(), "https://acme.zendesk.com/oauth/tokens".into()));
        assert!(crate::connect::oauth_urls(&Zendesk, &signed_in_cred("evil.com#")).is_err());
        assert!(crate::connect::oauth_urls(&Zendesk, &Credential::default()).is_err());
    }

    #[test]
    fn tokens_are_asked_for_as_json_with_read_scope() {
        let app = OAuthApp { client_id: "zdg-dumbslab".into(), client_secret: "s3cret".into() };
        let form =
            vec![("grant_type".into(), "authorization_code".into()), ("code".into(), "c1".into()), ("code_verifier".into(), "v1".into())];
        let call = Zendesk.token_request(&app, "https://acme.zendesk.com/oauth/tokens", form);
        assert_eq!((call.method, call.url.as_str()), ("POST", "https://acme.zendesk.com/oauth/tokens"));
        assert!(call.headers.contains(&("content-type".into(), "application/json".into())));
        let body: Value = serde_json::from_str(call.body.as_deref().unwrap()).unwrap();
        assert_eq!(
            body,
            json!({ "grant_type": "authorization_code", "code": "c1", "code_verifier": "v1", "client_id": "zdg-dumbslab",
                "client_secret": "s3cret", "scope": "read", "expires_in": 28800, "refresh_token_expires_in": 7776000 })
        );
        let tokens = Zendesk
            .read_token(&reply(201, json!({ "access_token": "at", "refresh_token": "rt", "token_type": "bearer", "scope": "read", "expires_in": 28800, "refresh_token_expires_in": 7776000 })))
            .unwrap();
        assert_eq!((tokens.access_token.as_str(), tokens.refresh_token.as_deref(), tokens.expires_in), ("at", Some("rt"), Some(28800)));
    }

    #[test]
    fn signed_in_connections_use_bearer_tokens_on_their_own_subdomain() {
        let c = signed_in_cred("acme");
        let calls = Zendesk.profile(&c);
        assert_eq!(calls[0].url, "https://acme.zendesk.com/api/v2/users/me.json");
        assert!(calls[0].headers.contains(&("authorization".into(), "Bearer oauth-at".into())));
        let me = json!({ "user": { "id": 7, "name": "Ada", "email": "ada@acme.com", "role": "agent" } });
        let account = Zendesk.read_profile(&c, &[reply(200, me)]).unwrap();
        assert_eq!(
            (account.label.as_str(), &account.settings),
            ("ada@acme.com (acme.zendesk.com)", &json!({ "host": "acme.zendesk.com", "user_id": 7 }))
        );
        assert!(Zendesk.read_profile(&c, &[reply(401, json!({}))]).unwrap_err().contains("didn't accept the sign-in"));
        let end_user = json!({ "user": { "id": 8, "email": "cy@example.com", "role": "end-user" } });
        assert!(Zendesk.read_profile(&c, &[reply(200, end_user)]).unwrap_err().contains("end user"));

        // Searches and previews go only where the sealed credential belongs, and only when the saved
        // account agrees: a token for one subdomain is never sent to another.
        let searches = Zendesk.search(&c, &acme(), "printer", 4);
        assert!(searches.iter().all(|call| call.url.starts_with("https://acme.zendesk.com/api/v2/")));
        assert!(searches.iter().all(|call| call.headers.contains(&("authorization".into(), "Bearer oauth-at".into()))));
        let beta = Account { settings: json!({ "host": "beta.zendesk.com", "user_id": 1 }), ..Default::default() };
        assert!(Zendesk.search(&c, &beta, "printer", 4).is_empty());
        assert!(Zendesk.preview(&c, &beta, "9").is_empty());
        assert!(Zendesk.search(&signed_in_cred("evil.com#"), &acme(), "printer", 4).is_empty());
        assert_eq!(Zendesk.preview(&c, &acme(), "9")[0].url, "https://acme.zendesk.com/api/v2/tickets/9.json?include=users");
    }

    #[test]
    fn html_becomes_text() {
        assert_eq!(html_text("<p>One</p><p>Two <b>bold</b>er</p>"), " One  Two bolder ");
        assert_eq!(html_text("a<script>alert('<p>')</script>b<STYLE>p{}</STYLE>c"), "a b c");
        assert_eq!(html_text("&lt;tag&gt; &amp;amp; &#39;x&#x27; &nbsp;&bogus; & done"), "<tag> &amp; 'x'  &bogus; & done");
        assert_eq!(html_text("unclosed <a href"), "unclosed ");
    }
}
