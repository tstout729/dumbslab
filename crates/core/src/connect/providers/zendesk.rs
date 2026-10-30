//! Zendesk: tickets and Help Center articles the connected agent can see, and previews of linked
//! tickets. People connect with their Zendesk subdomain, email and an API token, sent as Basic auth
//! (`<email>/token:<token>`); every request goes to that one subdomain.
//!
//! - No sign-in: a Zendesk OAuth client belongs to one Zendesk account, with sign-in URLs on its
//!   subdomain, and Zendesk's terms don't let an app made for many customers use their own clients
//!   or API tokens. That takes a global OAuth client, which Zendesk approves. A self-hosted server
//!   connecting its own company's Zendesk is internal use, which the terms allow.
//! - Zendesk is retiring API tokens: since October 27, 2026 no account can create one (accounts
//!   opened since July 28, 2026 never could), tokens unused for 30 days are switched off, and all
//!   stop working on April 30, 2027.
//! - An API token works with any user's email in the account, so a connection acts as whoever's
//!   email is given. Tokens come from admins, who decide who gets one.
//!
//! Docs: https://developer.zendesk.com/api-reference/introduction/security-and-auth/,
//! https://support.zendesk.com/hc/en-us/articles/10851263566234,
//! https://developer.zendesk.com/documentation/api-basics/authentication/oauth-migration/,
//! https://developer.zendesk.com/api-reference/ticketing/users/users/#show-self,
//! https://developer.zendesk.com/api-reference/ticketing/ticket-management/search/,
//! https://developer.zendesk.com/api-reference/help_center/help-center-api/help_center_search/,
//! https://developer.zendesk.com/api-reference/ticketing/tickets/tickets/#show-ticket,
//! https://developer.zendesk.com/documentation/ticketing/using-the-zendesk-api/side_loading/

use std::collections::BTreeMap;

use serde_json::{Value, json};

use crate::connect::{
    Account, Connector, Credential, Detail, Field, Hit, HttpCall, HttpReply, Preview, ProviderInfo, excerpt, host_of, http_error, opt,
    path_of, s,
};

pub struct Zendesk;

static INFO: ProviderInfo = ProviderInfo {
    id: "zendesk",
    name: "Zendesk",
    about: "Search tickets and Help Center articles, and preview linked tickets.",
    search: true,
    preview: true,
    oauth: None,
    token_fields: &[
        Field {
            key: "subdomain",
            label: "Zendesk subdomain",
            help: "The part before .zendesk.com, like `acme` for acme.zendesk.com.",
            secret: false,
            optional: false,
        },
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

fn api(host: &str, path: &str, cred: &Credential) -> HttpCall {
    HttpCall::get(format!("https://{host}/api/v2/{path}"))
        .basic(&format!("{}/token", cred.field("email").trim()), &cred.token)
        .header("accept", "application/json")
}

/// Sideloaded users' names by ID.
fn names(users: &Value) -> BTreeMap<i64, String> {
    users.as_array().into_iter().flatten().filter_map(|u| Some((u["id"].as_i64()?, opt(&u["name"])?))).collect()
}

/// Zendesk's status as people read it: `hold` is shown as "on hold".
fn status(v: &Value) -> Option<String> {
    opt(v).map(|st| if st == "hold" { "on hold".into() } else { st })
}

/// Help Center HTML as text: tags dropped (all but inline ones leave a space), scripts and
/// styles skipped, entities decoded.
fn html_text(html: &str) -> String {
    const INLINE: &[&str] = &["a", "abbr", "b", "code", "em", "i", "mark", "s", "small", "span", "strong", "sub", "sup", "u"];
    let mut out = String::with_capacity(html.len());
    let mut rest = html;
    while let Some(start) = rest.find('<') {
        out.push_str(&rest[..start]);
        let tag_text = &rest[start..];
        let end = tag_text.find('>').map_or(tag_text.len(), |e| e + 1);
        let closing = tag_text[1..].starts_with('/');
        let name: String = tag_text[1..end]
            .trim_start_matches('/')
            .chars()
            .take_while(char::is_ascii_alphanumeric)
            .collect::<String>()
            .to_ascii_lowercase();
        rest = &tag_text[end..];
        if !closing && matches!(name.as_str(), "script" | "style") {
            let close = format!("</{name}");
            rest = match rest.to_ascii_lowercase().find(&close) {
                Some(i) => {
                    let tail = &rest[i..];
                    &tail[tail.find('>').map_or(tail.len(), |e| e + 1)..]
                }
                None => "",
            };
        }
        if !INLINE.contains(&name.as_str()) {
            out.push(' ');
        }
    }
    out.push_str(rest);
    decode_entities(&out)
}

fn decode_entities(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        let from = &rest[i..];
        let entity = from.find(';').filter(|&e| e <= 10).map(|e| &from[1..e]);
        let ch = entity.and_then(|e| match e {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            "nbsp" => Some(' '),
            _ => match e.strip_prefix("#x").or_else(|| e.strip_prefix("#X")) {
                Some(hex) => u32::from_str_radix(hex, 16).ok(),
                None => e.strip_prefix('#').and_then(|d| d.parse().ok()),
            }
            .and_then(char::from_u32),
        });
        match (ch, entity) {
            (Some(c), Some(e)) => {
                out.push(c);
                rest = &from[e.len() + 2..];
            }
            _ => {
                out.push('&');
                rest = &from[1..];
            }
        }
    }
    out.push_str(rest);
    out
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
        match (subdomain(cred.field("subdomain")), valid_email(cred.field("email"))) {
            (Ok(sub), Ok(_)) => vec![api(&format!("{sub}.zendesk.com"), "users/me.json", cred)],
            // Nothing to ask; read_profile says what to fix.
            _ => vec![],
        }
    }

    fn read_profile(&self, cred: &Credential, replies: &[HttpReply]) -> Result<Account, String> {
        let host = format!("{}.zendesk.com", subdomain(cred.field("subdomain"))?);
        let email = valid_email(cred.field("email"))?;
        let r = replies.first().cloned().unwrap_or_default();
        if !r.ok() {
            return Err(match r.status {
                401 => format!("{host} rejected that email and API token. Check both, and that the token is still active."),
                404 => format!("There's no Zendesk at {host}. Check the subdomain."),
                _ => http_error("Zendesk", &r),
            });
        }
        let user = &r.json()["user"];
        // Without credentials Zendesk answers with an anonymous user, who has no ID.
        let Some(id) = user["id"].as_i64() else { return Err(format!("{host} didn't recognize that email and API token.")) };
        if user["role"] == "end-user" {
            return Err(format!(
                "{email} is an end user in Zendesk. Only agents and admins can search tickets, so connect with an agent's email."
            ));
        }
        let shown = opt(&user["email"]).unwrap_or(email);
        Ok(Account { label: format!("{shown} ({host})"), settings: json!({ "host": host, "user_id": id }) })
    }

    fn search(&self, cred: &Credential, account: &Account, q: &str, limit: usize) -> Vec<HttpCall> {
        let Some(host) = host(account) else { return vec![] };
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
        match (host(account), target.parse::<u64>()) {
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

    #[test]
    fn html_becomes_text() {
        assert_eq!(html_text("<p>One</p><p>Two <b>bold</b>er</p>"), " One  Two bolder ");
        assert_eq!(html_text("a<script>alert('<p>')</script>b<STYLE>p{}</STYLE>c"), "a b c");
        assert_eq!(html_text("&lt;tag&gt; &amp;amp; &#39;x&#x27; &nbsp;&bogus; & done"), "<tag> &amp; 'x'  &bogus; & done");
        assert_eq!(html_text("unclosed <a href"), "unclosed ");
    }
}
