//! Freshdesk: previews of linked tickets, read with the connected agent's own API key (Basic auth,
//! `<key>:X`), so they show only tickets that agent can open. Every request goes to that one
//! helpdesk's `<name>.freshdesk.com`; Freshdesk's API doesn't answer on custom domains.
//!
//! - No search: Freshdesk's ticket search filters by fields (status, priority, tags, custom
//!   fields), not by text.
//! - No sign-in: Freshdesk's API takes each agent's personal API key, from their profile settings.
//! - A ticket names its assignee only by ID, and only admins may look agents up, so a preview
//!   names the assignee only when it's the connected agent.
//!
//! Docs: https://developers.freshdesk.com/api/#authentication, https://developers.freshdesk.com/api/#me,
//! https://developers.freshdesk.com/api/#view_a_ticket, https://developers.freshdesk.com/api/#filter_tickets,
//! https://developers.freshdesk.com/api/#error

use serde_json::{Value, json};

use crate::connect::{
    Account, Connector, Credential, Detail, Field, Hit, HttpCall, HttpReply, Preview, ProviderInfo, excerpt, host_of, http_error, opt,
    path_of,
};

pub struct Freshdesk;

static INFO: ProviderInfo = ProviderInfo {
    id: "freshdesk",
    name: "Freshdesk",
    about: "Preview linked tickets.",
    search: false,
    preview: true,
    oauth: None,
    token_fields: &[
        Field {
            key: "domain",
            label: "Freshdesk domain",
            help: "Your helpdesk's address, like acme.freshdesk.com.",
            secret: false,
            optional: false,
        },
        Field {
            key: "token",
            label: "API key",
            help: "In Freshdesk, click your profile picture, then Profile settings: the key is under \"Your API Key\".",
            secret: true,
            optional: false,
        },
    ],
    token_help: "https://support.freshdesk.com/support/solutions/articles/215517",
};

fn reconnect() -> String {
    "Freshdesk needs you to connect it again (Settings › Connected apps).".into()
}

/// A DNS label as Freshdesk uses them: `[a-z0-9][a-z0-9-]*`.
fn valid_label(label: &str) -> bool {
    label.len() <= 63
        && label.bytes().next().is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && label.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// A helpdesk's host, `acme.freshdesk.com`, from `acme`, `acme.freshdesk.com` or a link into it.
pub fn domain(input: &str) -> Result<String, String> {
    let raw = input.trim().to_ascii_lowercase();
    let host =
        if raw.contains("://") { host_of(&raw).unwrap_or_default() } else { raw.split(['/', '?', '#']).next().unwrap_or_default().into() };
    let label = host.strip_suffix(".freshdesk.com").unwrap_or(&host);
    if valid_label(label) {
        Ok(format!("{label}.freshdesk.com"))
    } else {
        Err("Enter your Freshdesk address, like acme.freshdesk.com.".into())
    }
}

/// The connected account's helpdesk, checked again before any request.
fn host(account: &Account) -> Option<String> {
    let host = account.settings["host"].as_str()?;
    valid_label(host.strip_suffix(".freshdesk.com")?).then(|| host.to_string())
}

fn api(host: &str, path: &str, cred: &Credential) -> HttpCall {
    HttpCall::get(format!("https://{host}/api/v2/{path}")).basic(&cred.token, "X").header("accept", "application/json")
}

/// Freshdesk's built-in statuses. Helpdesks can add their own, which the ticket names only by
/// number; those aren't shown.
fn status(code: i64) -> Option<&'static str> {
    match code {
        2 => Some("Open"),
        3 => Some("Pending"),
        4 => Some("Resolved"),
        5 => Some("Closed"),
        _ => None,
    }
}

fn priority(code: i64) -> Option<&'static str> {
    match code {
        1 => Some("Low"),
        2 => Some("Medium"),
        3 => Some("High"),
        4 => Some("Urgent"),
        _ => None,
    }
}

impl Connector for Freshdesk {
    fn info(&self) -> &'static ProviderInfo {
        &INFO
    }

    fn profile(&self, cred: &Credential) -> Vec<HttpCall> {
        match domain(cred.field("domain")) {
            Ok(host) => vec![api(&host, "agents/me", cred)],
            // Nothing to ask; read_profile says what to fix.
            Err(_) => vec![],
        }
    }

    fn read_profile(&self, cred: &Credential, replies: &[HttpReply]) -> Result<Account, String> {
        let host = domain(cred.field("domain"))?;
        let r = replies.first().cloned().unwrap_or_default();
        if !r.ok() {
            return Err(match r.status {
                401 => format!("{host} rejected that API key. Copy it again from your Freshdesk profile settings."),
                403 => format!("{host} refused that API key. Connect with an agent's key."),
                404 => format!("There's no Freshdesk at {host}. Check the address."),
                _ => http_error("Freshdesk", &r),
            });
        }
        let me = r.json();
        let Some(id) = me["id"].as_i64() else { return Err("Freshdesk didn't say whose API key that is.".into()) };
        let name = opt(&me["contact"]["name"]);
        let shown = opt(&me["contact"]["email"]).or_else(|| name.clone()).unwrap_or_else(|| format!("Agent {id}"));
        Ok(Account { label: format!("{shown} ({host})"), settings: json!({ "host": host, "agent_id": id, "name": name }) })
    }

    fn search(&self, _cred: &Credential, _account: &Account, _q: &str, _limit: usize) -> Vec<HttpCall> {
        vec![]
    }

    fn read_search(&self, _account: &Account, _replies: &[HttpReply], _limit: usize) -> Result<Vec<Hit>, String> {
        Ok(vec![])
    }

    /// `https://acme.freshdesk.com/a/tickets/123` or `/helpdesk/tickets/123` → `123`, only on the
    /// connected account's own helpdesk. Without a connection (no host), any helpdesk's links are
    /// recognized, so the link can still be named; nothing is fetched for them.
    fn preview_target(&self, account: &Account, url: &str) -> Option<String> {
        let at = host_of(url)?;
        let ours = if account.settings["host"].is_null() {
            at.strip_suffix(".freshdesk.com").is_some_and(valid_label)
        } else {
            host(account).is_some_and(|h| h == at)
        };
        if !ours {
            return None;
        }
        match path_of(url).as_slice() {
            [first, tickets, id, ..] if matches!(first.as_str(), "a" | "helpdesk") && tickets == "tickets" && id.parse::<u64>().is_ok() => {
                Some(id.clone())
            }
            _ => None,
        }
    }

    fn preview(&self, cred: &Credential, account: &Account, target: &str) -> Vec<HttpCall> {
        match (host(account), target.parse::<u64>()) {
            (Some(host), Ok(id)) => vec![api(&host, &format!("tickets/{id}?include=requester"), cred)],
            _ => vec![],
        }
    }

    fn read_preview(&self, account: &Account, target: &str, replies: &[HttpReply]) -> Result<Preview, String> {
        let Some(host) = host(account) else { return Err(reconnect()) };
        let r = replies.first().cloned().unwrap_or_default();
        if !r.ok() {
            return Err(match r.status {
                403 | 404 => "Freshdesk has no such ticket, or the connected account can't see it.".into(),
                _ => http_error("Freshdesk", &r),
            });
        }
        let t = r.json();
        let id = t["id"].as_i64().map(|i| i.to_string()).unwrap_or_else(|| target.to_string());
        let requester: &Value = &t["requester"];
        let assignee = match (t["responder_id"].as_i64(), account.settings["agent_id"].as_i64()) {
            (Some(r), Some(me)) if r == me => opt(&account.settings["name"]),
            _ => None,
        };
        let mut details = vec![];
        if let Some(p) = t["priority"].as_i64().and_then(priority) {
            details.push(Detail { label: "Priority".into(), value: p.into() });
        }
        if let Some(k) = opt(&t["type"]) {
            details.push(Detail { label: "Type".into(), value: k });
        }
        Ok(Preview {
            provider: "freshdesk".into(),
            kind: "ticket".into(),
            title: opt(&t["subject"]).unwrap_or_else(|| format!("Ticket #{id}")),
            url: format!("https://{host}/a/tickets/{id}"),
            reference: format!("#{id}"),
            status: t["status"].as_i64().and_then(status).map(str::to_string),
            assignee,
            author: opt(&requester["name"]).or_else(|| opt(&requester["email"])),
            created_at: opt(&t["created_at"]),
            updated_at: opt(&t["updated_at"]),
            description: excerpt(t["description_text"].as_str().unwrap_or_default(), 300),
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

    fn cred(domain: &str) -> Credential {
        Credential { token: "key".into(), fields: [("domain".to_string(), domain.to_string())].into(), ..Default::default() }
    }

    fn acme() -> Account {
        Account {
            label: "ada@acme.com (acme.freshdesk.com)".into(),
            settings: json!({ "host": "acme.freshdesk.com", "agent_id": 7, "name": "Ada" }),
        }
    }

    #[test]
    fn domains_are_checked_and_normalized() {
        for ok in [
            "acme",
            "Acme.Freshdesk.com",
            "https://acme.freshdesk.com",
            "https://acme.freshdesk.com/a/tickets/1?x=1",
            "acme.freshdesk.com/",
        ] {
            assert_eq!(domain(ok).as_deref(), Ok("acme.freshdesk.com"), "{ok}");
        }
        for bad in [
            "",
            "-acme",
            "acme.evil.test",
            "acme.freshdesk.com.evil.test",
            "https://evil.test/acme.freshdesk.com",
            "support.acme.com",
            "a_b",
        ] {
            assert!(domain(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn profile_checks_the_key_with_the_helpdesk() {
        let c = cred("https://acme.freshdesk.com/");
        let calls = Freshdesk.profile(&c);
        assert_eq!(calls[0].url, "https://acme.freshdesk.com/api/v2/agents/me");
        assert!(calls[0].headers.contains(&("authorization".into(), format!("Basic {}", STANDARD.encode("key:X")))));
        let me = json!({ "id": 7, "ticket_scope": 1, "contact": { "name": "Ada", "email": "ada@acme.com" } });
        let account = Freshdesk.read_profile(&c, &[reply(200, me)]).unwrap();
        assert_eq!(account.label, "ada@acme.com (acme.freshdesk.com)");
        assert_eq!(account.settings, json!({ "host": "acme.freshdesk.com", "agent_id": 7, "name": "Ada" }));
        assert!(Freshdesk.read_profile(&c, &[reply(401, json!({ "code": "invalid_credentials" }))]).unwrap_err().contains("rejected"));
        assert!(Freshdesk.read_profile(&c, &[reply(404, json!({}))]).unwrap_err().contains("no Freshdesk at acme.freshdesk.com"));
        assert!(Freshdesk.read_profile(&c, &[reply(0, json!(null))]).unwrap_err().contains("in time"));
        assert!(Freshdesk.read_profile(&c, &[reply(200, json!({}))]).unwrap_err().contains("whose"));
        // A bad address never reaches anyone.
        let bad = cred("acme.freshdesk.com.evil.test");
        assert!(Freshdesk.profile(&bad).is_empty());
        assert!(Freshdesk.read_profile(&bad, &[]).unwrap_err().starts_with("Enter"));
    }

    #[test]
    fn previews_tickets_on_the_connected_helpdesk_only() {
        let a = acme();
        assert_eq!(Freshdesk.preview_target(&a, "https://acme.freshdesk.com/a/tickets/123").as_deref(), Some("123"));
        assert_eq!(Freshdesk.preview_target(&a, "https://acme.freshdesk.com/helpdesk/tickets/124?x=1#y").as_deref(), Some("124"));
        for no in [
            "https://acme.freshdesk.com/a/tickets",
            "https://acme.freshdesk.com/a/tickets/new",
            "https://acme.freshdesk.com/a/contacts/123",
            "https://beta.freshdesk.com/a/tickets/123",
            "https://acme.freshdesk.com.evil.test/a/tickets/123",
            "https://evil.test/acme.freshdesk.com/a/tickets/123",
        ] {
            assert_eq!(Freshdesk.preview_target(&a, no), None, "{no}");
        }
        let none = Account::default();
        assert_eq!(Freshdesk.preview_target(&none, "https://beta.freshdesk.com/a/tickets/9").as_deref(), Some("9"));
        assert_eq!(Freshdesk.preview_target(&none, "https://beta.freshdesk.com.evil.test/a/tickets/9"), None);
        assert!(Freshdesk.preview(&Credential::default(), &none, "9").is_empty());

        let calls = Freshdesk.preview(&cred("acme"), &a, "123");
        assert_eq!(calls[0].url, "https://acme.freshdesk.com/api/v2/tickets/123?include=requester");
        assert!(calls[0].headers.iter().any(|(k, v)| k == "authorization" && v.starts_with("Basic ")));
        let ticket = json!({ "id": 123, "subject": "VPN down", "status": 3, "priority": 4, "type": "Incident", "responder_id": 7,
            "created_at": "2026-10-01T00:00:00Z", "updated_at": "2026-10-02T00:00:00Z",
            "description": "<div>VPN <b>down</b></div>", "description_text": "VPN down\n since 9am",
            "requester": { "id": 3, "name": "Cy", "email": "cy@acme.com" } });
        let p = Freshdesk.read_preview(&a, "123", &[reply(200, ticket.clone())]).unwrap();
        assert_eq!((p.kind.as_str(), p.reference.as_str(), p.status.as_deref()), ("ticket", "#123", Some("Pending")));
        assert_eq!((p.title.as_str(), p.url.as_str()), ("VPN down", "https://acme.freshdesk.com/a/tickets/123"));
        assert_eq!((p.assignee.as_deref(), p.author.as_deref()), (Some("Ada"), Some("Cy")));
        assert_eq!((p.updated_at.as_deref(), p.description.as_str()), (Some("2026-10-02T00:00:00Z"), "VPN down since 9am"));
        assert_eq!(
            p.details,
            vec![Detail { label: "Priority".into(), value: "Urgent".into() }, Detail { label: "Type".into(), value: "Incident".into() }]
        );
        // Another agent's ticket, with a status the helpdesk made up.
        let mut other = ticket;
        other["responder_id"] = json!(8);
        other["status"] = json!(6);
        let p = Freshdesk.read_preview(&a, "123", &[reply(200, other)]).unwrap();
        assert_eq!((p.assignee, p.status), (None, None));
        assert!(Freshdesk.read_preview(&a, "123", &[reply(404, json!({}))]).unwrap_err().contains("can't see"));
        assert!(Freshdesk.read_preview(&a, "123", &[reply(401, json!({}))]).unwrap_err().contains("Reconnect"));
        assert!(Freshdesk.read_preview(&a, "123", &[reply(429, json!({}))]).unwrap_err().contains("rate limit"));
        assert!(Freshdesk.read_preview(&a, "123", &[reply(0, json!(null))]).unwrap_err().contains("in time"));
        assert!(Freshdesk.read_preview(&Account::default(), "123", &[]).unwrap_err().contains("connect it again"));
    }
}
