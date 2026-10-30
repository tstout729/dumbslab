//! Guru: cards the connected person can read, and previews of linked cards. Guru has no sign-in
//! for other apps, so people connect with a user token and the email they sign in with (HTTP
//! Basic). Admins, and people whose role can manage apps and integrations, make user tokens.
//!
//! Docs: https://developer.getguru.com/docs/getting-started, https://help.getguru.com/s/article/how-to-obtain-your-api-credentials,
//! https://developer.getguru.com/reference/getv1whoamiwhoami, https://developer.getguru.com/reference/getv1searchquerysearch,
//! https://developer.getguru.com/reference/getv1cardsgetextendedfact (card links are `https://app.getguru.com/card/<slug>`).

use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

use serde_json::{Value, json};

use crate::connect::{
    Account, Connector, Credential, Detail, Field, Hit, HttpCall, HttpReply, Preview, ProviderInfo, excerpt, host_of, http_error, opt,
    path_of, s,
};

pub struct Guru;

const API: &str = "https://api.getguru.com/api/v1";
const WEB: &str = "https://app.getguru.com";

static INFO: ProviderInfo = ProviderInfo {
    id: "guru",
    name: "Guru",
    about: "Search cards, and preview linked cards.",
    search: true,
    preview: true,
    oauth: None,
    token_fields: &[
        Field { key: "email", label: "Email", help: "The email you sign in to Guru with.", secret: false, optional: false },
        Field {
            key: "token",
            label: "User token",
            help: "A user token from Settings › API access (Generate user token). Guru admins can make one for you.",
            secret: true,
            optional: false,
        },
    ],
    token_help: "https://app.getguru.com/settings/integrations/api-access",
};

fn api(path: &str, cred: &Credential) -> HttpCall {
    HttpCall::get(format!("{API}{path}")).basic(cred.field("email"), &cred.token).header("accept", "application/json")
}

/// A card's id or slug: letters, digits and dashes.
fn is_card_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// Card content as plain text. Guru keeps cards as HTML: a real HTML parser (ammonia's) keeps
/// only block tags, without attributes, so everything between `<` and `>` in what's left is one
/// of those tags, which become spaces. Scripts and styles go with their content.
fn plain_text(html: &str) -> String {
    static BLOCKS: OnceLock<ammonia::Builder<'static>> = OnceLock::new();
    let cleaner = BLOCKS.get_or_init(|| {
        let mut b = ammonia::Builder::empty();
        b.tags("p br div li ul ol h1 h2 h3 h4 h5 h6 tr td th table blockquote pre hr".split(' ').collect())
            .generic_attributes(HashSet::new())
            .tag_attributes(HashMap::new());
        b
    });
    let clean = cleaner.clean(html).to_string();
    let mut text = String::with_capacity(clean.len());
    let mut in_tag = false;
    for c in clean.chars() {
        match c {
            '<' => {
                in_tag = true;
                text.push(' ');
            }
            '>' if in_tag => in_tag = false,
            _ if !in_tag => text.push(c),
            _ => {}
        }
    }
    // What the parser escapes in text; `&amp;` last, so `&amp;lt;` stays `&lt;`.
    text.replace("&lt;", "<").replace("&gt;", ">").replace("&nbsp;", " ").replace("&quot;", "\"").replace("&amp;", "&")
}

fn card_url(card: &Value) -> String {
    let slug = opt(&card["slug"]).or_else(|| opt(&card["id"])).unwrap_or_default();
    let path: String = slug.split('/').filter(|p| !p.is_empty()).map(|p| format!("/{}", urlencoding::encode(p))).collect();
    format!("{WEB}/card{path}")
}

fn person(user: &Value) -> Option<String> {
    let name = format!("{} {}", s(&user["firstName"]), s(&user["lastName"])).trim().to_string();
    Some(name).filter(|n| !n.is_empty()).or_else(|| opt(&user["email"]))
}

fn verification(state: &str) -> Option<String> {
    let shown = match state {
        "TRUSTED" => "Verified",
        "NEEDS_VERIFICATION" => "Unverified",
        "STALE" => "Stale",
        "SYNCED_NO_VERIFICATION" => "Synced",
        _ => return None,
    };
    Some(shown.into())
}

impl Connector for Guru {
    fn info(&self) -> &'static ProviderInfo {
        &INFO
    }

    fn profile(&self, cred: &Credential) -> Vec<HttpCall> {
        vec![api("/whoami", cred)]
    }

    fn read_profile(&self, cred: &Credential, replies: &[HttpReply]) -> Result<Account, String> {
        let email = cred.field("email");
        if !email.contains('@') || email.contains(':') || email.chars().any(char::is_whitespace) {
            return Err("Guru needs the email you sign in with, like ada@acme.com.".into());
        }
        let r = replies.first().cloned().unwrap_or_default();
        if !r.ok() {
            return Err(match r.status {
                401 => "Guru rejected that email and token. Check the token was copied whole and belongs to that email.".into(),
                _ => http_error("Guru", &r),
            });
        }
        let me = r.json();
        if me["tokenType"].as_str() == Some("COLLECTION") {
            return Err("That's a collection token. Connect with a user token, so Guru shows only what you can read.".into());
        }
        let label = opt(&me["user"]["email"]).ok_or("Guru didn't say whose token that is.")?;
        Ok(Account { label, settings: json!({}) })
    }

    fn search(&self, cred: &Credential, _account: &Account, q: &str, limit: usize) -> Vec<HttpCall> {
        let terms = urlencoding::encode(q).into_owned();
        vec![api(&format!("/search/query?searchTerms={terms}&queryType=cards&maxResults={}", limit.clamp(1, 20)), cred)]
    }

    fn read_search(&self, _account: &Account, replies: &[HttpReply], limit: usize) -> Result<Vec<Hit>, String> {
        let r = replies.first().cloned().unwrap_or_default();
        if !r.ok() {
            return Err(http_error("Guru", &r));
        }
        Ok(r.json()
            .as_array()
            .into_iter()
            .flatten()
            .take(limit)
            .map(|c| Hit {
                provider: "guru".into(),
                kind: "card".into(),
                title: s(&c["preferredPhrase"]),
                url: card_url(c),
                context: s(&c["collection"]["name"]),
                snippet: excerpt(&plain_text(c["content"].as_str().unwrap_or_default()), 240),
                updated_at: opt(&c["lastModified"]),
                author: person(&c["owner"]),
            })
            .collect())
    }

    /// `https://app.getguru.com/card/<slug>/<Title>` → `<slug>`.
    fn preview_target(&self, _account: &Account, url: &str) -> Option<String> {
        if host_of(url)? != "app.getguru.com" {
            return None;
        }
        match path_of(url).as_slice() {
            [kind, id, ..] if matches!(kind.as_str(), "card" | "cards") && is_card_id(id) => Some(id.clone()),
            _ => None,
        }
    }

    fn preview(&self, cred: &Credential, _account: &Account, target: &str) -> Vec<HttpCall> {
        vec![api(&format!("/cards/{target}/extended"), cred)]
    }

    fn read_preview(&self, _account: &Account, target: &str, replies: &[HttpReply]) -> Result<Preview, String> {
        let r = replies.first().cloned().unwrap_or_default();
        if !r.ok() {
            return Err(match r.status {
                403 | 404 => "Guru has no such card, or the connected account can't read it.".into(),
                _ => http_error("Guru", &r),
            });
        }
        let c = r.json();
        let mut details = vec![];
        if let Some(collection) = opt(&c["collection"]["name"]) {
            details.push(Detail { label: "Collection".into(), value: collection });
        }
        if let Some(verified) = opt(&c["lastVerified"]) {
            details.push(Detail { label: "Last verified".into(), value: verified });
        }
        Ok(Preview {
            provider: "guru".into(),
            kind: "card".into(),
            title: s(&c["preferredPhrase"]),
            url: card_url(&c),
            reference: target.into(),
            status: verification(c["verificationState"].as_str().unwrap_or_default()),
            assignee: None,
            author: person(&c["owner"]),
            created_at: opt(&c["dateCreated"]),
            updated_at: opt(&c["lastModified"]),
            description: excerpt(&plain_text(c["content"].as_str().unwrap_or_default()), 300),
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

    fn cred(email: &str) -> Credential {
        Credential { token: "tok".into(), fields: [("email".to_string(), email.to_string())].into(), ..Default::default() }
    }

    #[test]
    fn connects_with_email_and_user_token() {
        let calls = Guru.profile(&cred("ada@acme.com"));
        assert_eq!(calls[0].url, "https://api.getguru.com/api/v1/whoami");
        // Basic auth: base64("ada@acme.com:tok").
        assert!(calls[0].headers.contains(&("authorization".into(), "Basic YWRhQGFjbWUuY29tOnRvaw==".into())));
        let me = json!({ "tokenType": "API", "user": { "email": "ada@acme.com", "firstName": "Ada", "lastName": "L" }, "team": { "name": "Acme" } });
        assert_eq!(Guru.read_profile(&cred("ada@acme.com"), &[reply(200, me.clone())]).unwrap().label, "ada@acme.com");
        for bad in ["ada", "ada:x@acme.com", "ada @acme.com", ""] {
            assert!(Guru.read_profile(&cred(bad), &[reply(200, me.clone())]).unwrap_err().contains("email you sign in with"), "{bad}");
        }
        let collection = json!({ "tokenType": "COLLECTION", "collection": { "name": "Support" }, "team": {} });
        assert!(Guru.read_profile(&cred("ada@acme.com"), &[reply(200, collection)]).unwrap_err().contains("user token"));
        assert!(Guru.read_profile(&cred("ada@acme.com"), &[reply(401, json!({}))]).unwrap_err().contains("rejected that email"));
        assert!(Guru.read_profile(&cred("ada@acme.com"), &[reply(0, json!(null))]).unwrap_err().contains("in time"));
    }

    #[test]
    fn card_html_becomes_plain_text() {
        let html = r#"<div class="ghq-card-content__paragraph"><h2 id="x">Refunds</h2><p>Full refund &amp; credit within <b>30</b>&nbsp;days.</p><ul><li>Ask&nbsp;first</li><li>Then &lt;log&gt; it</li></ul><script>alert(1)</script><style>p{}</style><!-- note --><img src=x onerror=alert(1)><a href="javascript:alert(1)" title="a>b">link</a></div>"#;
        assert_eq!(excerpt(&plain_text(html), 500), "Refunds Full refund & credit within 30 days. Ask first Then <log> it link");
        assert_eq!(plain_text("Plain &amp;amp; text"), "Plain &amp; text");
        assert_eq!(excerpt(&plain_text("<p>unclosed <b>tags"), 100), "unclosed tags");
    }

    #[test]
    fn searches_cards() {
        let calls = Guru.search(&cred("ada@acme.com"), &Account::default(), "refund policy&q=x", 5);
        assert_eq!(
            calls[0].url,
            "https://api.getguru.com/api/v1/search/query?searchTerms=refund%20policy%26q%3Dx&queryType=cards&maxResults=5"
        );
        let cards = json!([
            { "id": "0b1c-2d", "slug": "iXpEBagT/Refund-policy", "preferredPhrase": "Refund policy", "content": "<p>Refunds within <b>30</b> days.</p>",
              "collection": { "id": "c1", "name": "Support" }, "lastModified": "2026-10-01T00:00:00.000+0000",
              "owner": { "firstName": "Ada", "lastName": "Lovelace", "email": "ada@acme.com" }, "verificationState": "TRUSTED" },
            { "id": "4e5f", "preferredPhrase": "Refund form", "content": "", "owner": { "email": "bo@acme.com" } }
        ]);
        let hits = Guru.read_search(&Account::default(), &[reply(200, cards.clone())], 5).unwrap();
        assert_eq!(hits.len(), 2);
        assert_eq!(
            (hits[0].kind.as_str(), hits[0].context.as_str(), hits[0].snippet.as_str()),
            ("card", "Support", "Refunds within 30 days.")
        );
        assert_eq!(
            (hits[0].url.as_str(), hits[0].author.as_deref()),
            ("https://app.getguru.com/card/iXpEBagT/Refund-policy", Some("Ada Lovelace"))
        );
        assert_eq!((hits[1].url.as_str(), hits[1].author.as_deref()), ("https://app.getguru.com/card/4e5f", Some("bo@acme.com")));
        assert_eq!(Guru.read_search(&Account::default(), &[reply(200, cards)], 1).unwrap().len(), 1);
        assert!(Guru.read_search(&Account::default(), &[reply(401, json!({}))], 5).unwrap_err().contains("Reconnect"));
        assert!(Guru.read_search(&Account::default(), &[reply(0, json!(null))], 5).unwrap_err().contains("in time"));
    }

    #[test]
    fn previews_linked_cards() {
        let a = Account::default();
        assert_eq!(Guru.preview_target(&a, "https://app.getguru.com/card/iXpEBagT/Refund-policy").as_deref(), Some("iXpEBagT"));
        assert_eq!(Guru.preview_target(&a, "https://app.getguru.com/card/iXpEBagT?q=1#Steps").as_deref(), Some("iXpEBagT"));
        assert_eq!(
            Guru.preview_target(&a, "https://app.getguru.com/cards/0b1c2d3e-aaaa-bbbb-cccc-0123456789ab").as_deref(),
            Some("0b1c2d3e-aaaa-bbbb-cccc-0123456789ab")
        );
        for no in [
            "https://app.getguru.com/collections/abc",
            "https://app.getguru.com/card",
            "https://app.getguru.com/card/..%2Fwhoami",
            "https://app.getguru.com/card/a.b",
            "https://getguru.com/card/iXpEBagT",
            "https://app.getguru.com.evil.test/card/iXpEBagT",
            "https://evil.test/app.getguru.com/card/iXpEBagT",
        ] {
            assert_eq!(Guru.preview_target(&a, no), None, "{no}");
        }
        let calls = Guru.preview(&cred("ada@acme.com"), &a, "iXpEBagT");
        assert_eq!(calls[0].url, "https://api.getguru.com/api/v1/cards/iXpEBagT/extended");
        assert!(calls[0].headers.iter().any(|(k, v)| k == "authorization" && v.starts_with("Basic ")));
        let card = json!({ "id": "0b1c", "slug": "iXpEBagT/Refund-policy", "preferredPhrase": "Refund policy",
            "content": "<h2>Refunds</h2><p>Within 30 days.</p>", "collection": { "name": "Support" }, "verificationState": "NEEDS_VERIFICATION",
            "owner": { "firstName": "Ada", "lastName": "Lovelace" }, "dateCreated": "2026-01-01T00:00:00.000+0000",
            "lastModified": "2026-10-01T00:00:00.000+0000", "lastVerified": "2026-07-01T00:00:00.000+0000" });
        let p = Guru.read_preview(&a, "iXpEBagT", &[reply(200, card)]).unwrap();
        assert_eq!((p.kind.as_str(), p.title.as_str(), p.reference.as_str()), ("card", "Refund policy", "iXpEBagT"));
        assert_eq!((p.status.as_deref(), p.author.as_deref()), (Some("Unverified"), Some("Ada Lovelace")));
        assert_eq!(
            (p.description.as_str(), p.url.as_str()),
            ("Refunds Within 30 days.", "https://app.getguru.com/card/iXpEBagT/Refund-policy")
        );
        assert_eq!(p.details[0], Detail { label: "Collection".into(), value: "Support".into() });
        assert_eq!(p.details[1].label, "Last verified");
        assert!(Guru.read_preview(&a, "iXpEBagT", &[reply(404, json!({}))]).unwrap_err().contains("can't read"));
        assert!(Guru.read_preview(&a, "iXpEBagT", &[reply(401, json!({}))]).unwrap_err().contains("Reconnect"));
    }
}
