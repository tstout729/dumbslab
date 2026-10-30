//! Wrike: previews of linked tasks the connected account can open. Wrike keeps each account in one
//! data center with its own API host (`www`, `app-eu` or `app-us2.wrike.com`): signing in names
//! it, and a permanent token's is found by asking each data center (the others answer 401). Links
//! carry Wrike's numeric task ids, which the API doesn't take; previews look tasks up by permalink
//! instead, in one request, since a preview gets one round of requests.
//!
//! Docs: https://developers.wrike.com/oauth-20-authorization/, https://developers.wrike.com/api/v4/tasks/,
//! https://developers.wrike.com/api/v4/contacts/, https://developers.wrike.com/api/v4/ids/,
//! https://help.wrike.com/hc/en-us/articles/210322805-Permalinks-in-Wrike

use std::collections::BTreeMap;

use serde_json::{Value, json};

use crate::connect::{
    Account, Connector, Credential, Detail, Field, Hit, HttpCall, HttpReply, OAuthSpec, Preview, ProviderInfo, TokenSet, excerpt, host_of,
    http_error, opt, path_of, s, standard_token,
};

pub struct Wrike;

const DEFAULT_HOST: &str = "www.wrike.com";
/// Wrike's data centers, asked in turn for a permanent token's account.
const HOSTS: &[&str] = &["www.wrike.com", "app-eu.wrike.com", "app-us2.wrike.com"];
const NOT_FOUND: &str = "Wrike has no such task, or the connected account can't see it.";

static INFO: ProviderInfo = ProviderInfo {
    id: "wrike",
    name: "Wrike",
    about: "Preview linked tasks.",
    search: false,
    preview: true,
    oauth: Some(OAuthSpec {
        authorize_url: "https://login.wrike.com/oauth2/authorize/v4",
        token_url: "https://login.wrike.com/oauth2/token",
        scopes: &["wsReadOnly"],
        scope_param: "scope",
        scope_separator: ",",
        extra: &[],
        pkce: false,
    }),
    token_fields: &[Field {
        key: "token",
        label: "Permanent access token",
        help: "In Wrike, Apps & Integrations › API: create an app, then Obtain token under Permanent access token.",
        secret: true,
        optional: false,
    }],
    token_help: "https://help.wrike.com/hc/en-us/articles/210409445-Wrike-API",
};

/// One name under wrike.com (`www.wrike.com`, `app-eu.wrike.com`…), so neither a token answer nor
/// stored settings can send the person's token anywhere else.
fn valid_host(host: &str) -> bool {
    host.strip_suffix(".wrike.com").is_some_and(|name| {
        !name.is_empty() && name.len() <= 63 && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    })
}

/// The account's API host: from signing in, else found when connecting, else Wrike's first.
fn api_host<'a>(cred: &'a Credential, account: &'a Account) -> &'a str {
    [cred.field("host"), account.settings["host"].as_str().unwrap_or_default()].into_iter().find(|h| valid_host(h)).unwrap_or(DEFAULT_HOST)
}

/// The hosts [`Connector::profile`] asks, in order.
fn profile_hosts(cred: &Credential) -> Vec<&str> {
    match cred.field("host") {
        h if valid_host(h) => vec![h],
        _ => HOSTS.to_vec(),
    }
}

fn api(host: &str, path: &str, cred: &Credential) -> HttpCall {
    HttpCall::get(format!("https://{host}/api/v4{path}")).bearer(&cred.token)
}

/// A query string's value for `key`.
fn param(query: &str, key: &str) -> Option<String> {
    query.split('&').filter_map(|p| p.split_once('=')).find(|(k, _)| *k == key).map(|(_, v)| v.to_string())
}

/// The text in an HTML description: tags dropped (with what's inside scripts and styles), block
/// boundaries kept as spaces, and entities decoded. The result is only ever shown as text.
fn html_text(html: &str) -> String {
    const BLOCKS: &[&str] =
        &["br", "p", "div", "li", "ul", "ol", "tr", "td", "th", "table", "h1", "h2", "h3", "h4", "h5", "h6", "blockquote", "pre", "hr"];
    let mut out = String::with_capacity(html.len());
    let mut rest = html;
    while let Some(start) = rest.find('<') {
        out.push_str(&rest[..start]);
        rest = &rest[start..];
        if let Some(after) = rest.strip_prefix("<!--") {
            rest = after.find("-->").map_or("", |i| &after[i + 3..]);
            continue;
        }
        let end = rest.find('>').map_or(rest.len(), |i| i + 1);
        let inner = &rest[1..end];
        let closing = inner.starts_with('/');
        let name =
            inner.trim_start_matches('/').split(|c: char| !c.is_ascii_alphanumeric()).next().unwrap_or_default().to_ascii_lowercase();
        rest = &rest[end..];
        if !closing && (name == "script" || name == "style") {
            // ASCII lowercasing keeps byte offsets.
            rest = rest.to_ascii_lowercase().find(&format!("</{name}")).map_or("", |i| &rest[i..]);
        } else if BLOCKS.contains(&name.as_str()) {
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
        rest = &rest[i..];
        let decoded = rest.find(';').filter(|&j| j <= 10).and_then(|j| entity(&rest[1..j]).map(|c| (c, j + 1)));
        match decoded {
            Some((c, len)) => {
                out.push(c);
                rest = &rest[len..];
            }
            None => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

fn entity(name: &str) -> Option<char> {
    match name {
        "amp" => Some('&'),
        "lt" => Some('<'),
        "gt" => Some('>'),
        "quot" => Some('"'),
        "apos" => Some('\''),
        "nbsp" => Some(' '),
        _ => {
            let n = name.strip_prefix('#')?;
            let code = match n.strip_prefix(['x', 'X']) {
                Some(hex) => u32::from_str_radix(hex, 16).ok()?,
                None => n.parse().ok()?,
            };
            char::from_u32(code)
        }
    }
}

impl Connector for Wrike {
    fn info(&self) -> &'static ProviderInfo {
        &INFO
    }

    fn profile(&self, cred: &Credential) -> Vec<HttpCall> {
        profile_hosts(cred).into_iter().map(|h| api(h, "/contacts?me=true", cred)).collect()
    }

    fn read_profile(&self, cred: &Credential, replies: &[HttpReply]) -> Result<Account, String> {
        let hosts = profile_hosts(cred);
        let Some((host, r)) = hosts.iter().zip(replies).find(|(_, r)| r.ok()) else {
            // Data centers that don't hold the account answer 401; another status says more.
            return Err(match replies.iter().find(|r| r.status != 401) {
                Some(r) => http_error("Wrike", r),
                None => "Wrike rejected that token. Check it was copied whole and hasn't been revoked.".into(),
            });
        };
        let me = &r.json()["data"][0];
        let id = s(&me["id"]);
        if id.is_empty() {
            return Err("Wrike didn't say whose token that is.".into());
        }
        let name = format!("{} {}", s(&me["firstName"]), s(&me["lastName"])).trim().to_string();
        let label = opt(&me["primaryEmail"]).or_else(|| opt(&me["profiles"][0]["email"])).unwrap_or(name);
        Ok(Account { label, settings: json!({ "host": host, "id": id }) })
    }

    /// Wrike only previews links.
    fn search(&self, _cred: &Credential, _account: &Account, _q: &str, _limit: usize) -> Vec<HttpCall> {
        vec![]
    }

    fn read_search(&self, _account: &Account, _replies: &[HttpReply], _limit: usize) -> Result<Vec<Hit>, String> {
        Ok(vec![])
    }

    /// `https://www.wrike.com/open.htm?id=123` or `https://www.wrike.com/workspace.htm?acc=1#/task-view?id=123`
    /// → `123`, only on the connected account's own data center (numeric ids aren't unique across them).
    fn preview_target(&self, account: &Account, url: &str) -> Option<String> {
        let own = account.settings["host"].as_str().filter(|h| valid_host(h)).unwrap_or(DEFAULT_HOST);
        if host_of(url)? != own.strip_prefix("www.").unwrap_or(own) {
            return None;
        }
        let (before, fragment) = url.split_once('#').unwrap_or((url, ""));
        let query = before.split_once('?').map(|(_, q)| q).unwrap_or_default();
        let id = match path_of(url).as_slice() {
            [page] if page == "open.htm" => param(query, "id"),
            [page] if page == "workspace.htm" => fragment.strip_prefix("/task-view?").and_then(|q| param(q, "id")),
            _ => None,
        }?;
        (!id.is_empty() && id.len() <= 20 && id.bytes().all(|b| b.is_ascii_digit())).then_some(id)
    }

    fn preview(&self, cred: &Credential, account: &Account, target: &str) -> Vec<HttpCall> {
        let host = api_host(cred, account);
        let permalink = urlencoding::encode(&format!("https://{host}/open.htm?id={target}")).into_owned();
        let fields = urlencoding::encode(r#"["description","responsibleIds","authorIds"]"#).into_owned();
        vec![
            api(host, &format!("/tasks?permalink={permalink}&fields={fields}"), cred),
            // Tasks name people by id; this is where their names are. The preview works without it.
            api(host, "/contacts", cred),
        ]
    }

    fn read_preview(&self, _account: &Account, target: &str, replies: &[HttpReply]) -> Result<Preview, String> {
        let r = replies.first().cloned().unwrap_or_default();
        if !r.ok() {
            return Err(match r.status {
                400 | 404 => NOT_FOUND.into(),
                _ => http_error("Wrike", &r),
            });
        }
        let v = r.json();
        let Some(t) = v["data"].as_array().and_then(|a| a.first()) else { return Err(NOT_FOUND.into()) };
        let contacts = replies.get(1).filter(|c| c.ok()).map(|c| c.json()).unwrap_or(Value::Null);
        let names: BTreeMap<String, String> = contacts["data"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|c| (s(&c["id"]), format!("{} {}", s(&c["firstName"]), s(&c["lastName"])).trim().to_string()))
            .filter(|(id, name)| !id.is_empty() && !name.is_empty())
            .collect();
        let people = |ids: &Value| -> Option<String> {
            let known: Vec<&str> =
                ids.as_array().into_iter().flatten().filter_map(|id| names.get(id.as_str()?)).map(String::as_str).collect();
            Some(known.join(", ")).filter(|x| !x.is_empty())
        };
        let mut details = vec![];
        if let Some(importance) = opt(&t["importance"]) {
            details.push(Detail { label: "Importance".into(), value: importance });
        }
        if let Some(due) = opt(&t["dates"]["due"]) {
            details.push(Detail { label: "Due".into(), value: due.get(..10).unwrap_or(&due).to_string() });
        }
        Ok(Preview {
            provider: "wrike".into(),
            kind: "task".into(),
            title: s(&t["title"]),
            url: s(&t["permalink"]),
            reference: format!("#{target}"),
            status: opt(&t["status"]),
            assignee: people(&t["responsibleIds"]),
            author: people(&t["authorIds"]),
            created_at: opt(&t["createdDate"]),
            updated_at: opt(&t["updatedDate"]),
            description: excerpt(&html_text(t["description"].as_str().unwrap_or_default()), 300),
            details,
        })
    }

    /// Wrike's answer names the account's API host, and gives `expires_in` as a string.
    fn read_token(&self, reply: &HttpReply) -> Result<TokenSet, String> {
        let mut tokens = standard_token(INFO.name, reply)?;
        let v = reply.json();
        if tokens.expires_in.is_none() {
            tokens.expires_in = v["expires_in"].as_str().and_then(|x| x.trim().parse().ok());
        }
        if let Some(host) = opt(&v["host"]) {
            let host = host.trim().to_ascii_lowercase();
            if !valid_host(&host) {
                return Err(format!("Wrike named an API host that isn't Wrike's ({}). Try connecting again.", excerpt(&host, 80)));
            }
            tokens.fields.insert("host".into(), host);
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

    fn permanent() -> Credential {
        Credential { token: "perm".into(), ..Default::default() }
    }

    fn eu() -> Account {
        Account { label: "ada@acme.com".into(), settings: json!({ "host": "app-eu.wrike.com", "id": "KUAAAAAA" }) }
    }

    #[test]
    fn signing_in_names_the_api_host() {
        let answer = json!({ "access_token": "a1", "refresh_token": "r1", "token_type": "bearer", "expires_in": "3600", "host": "App-EU.wrike.com" });
        let t = Wrike.read_token(&reply(200, answer)).unwrap();
        assert_eq!((t.access_token.as_str(), t.refresh_token.as_deref(), t.expires_in), ("a1", Some("r1"), Some(3600)));
        assert_eq!(t.fields.get("host").map(String::as_str), Some("app-eu.wrike.com"));
        let no_host = Wrike.read_token(&reply(200, json!({ "access_token": "a1", "expires_in": 3600 }))).unwrap();
        assert!(no_host.fields.is_empty());
        for bad in
            ["evil.test", "wrike.com.evil.test", "evil.test/.wrike.com", "a.b.wrike.com", ".wrike.com", "www.wrike.com:444", "wrike.com"]
        {
            let answer = json!({ "access_token": "a1", "host": bad });
            assert!(Wrike.read_token(&reply(200, answer)).unwrap_err().contains("isn't Wrike's"), "{bad}");
        }
        assert!(Wrike.read_token(&reply(400, json!({ "error": "invalid_grant" }))).unwrap_err().contains("invalid_grant"));

        // Signed in: the profile asks that host only.
        let cred = Credential { token: "a1".into(), fields: t.fields, ..Default::default() };
        let calls = Wrike.profile(&cred);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].url, "https://app-eu.wrike.com/api/v4/contacts?me=true");
        assert!(calls[0].headers.contains(&("authorization".into(), "Bearer a1".into())));
        let me = json!({ "data": [{ "id": "KUAAAAAA", "firstName": "Ada", "lastName": "L", "primaryEmail": "ada@acme.com" }] });
        let account = Wrike.read_profile(&cred, &[reply(200, me)]).unwrap();
        assert_eq!((account.label.as_str(), account.settings["host"].as_str()), ("ada@acme.com", Some("app-eu.wrike.com")));
    }

    #[test]
    fn a_permanent_token_finds_its_data_center() {
        let calls = Wrike.profile(&permanent());
        let urls: Vec<&str> = calls.iter().map(|c| c.url.as_str()).collect();
        assert_eq!(
            urls,
            [
                "https://www.wrike.com/api/v4/contacts?me=true",
                "https://app-eu.wrike.com/api/v4/contacts?me=true",
                "https://app-us2.wrike.com/api/v4/contacts?me=true"
            ]
        );
        let me = json!({ "data": [{ "id": "KUAAAAAB", "firstName": "Bo", "lastName": "Bell", "profiles": [{ "email": "bo@acme.com" }] }] });
        let account = Wrike.read_profile(&permanent(), &[reply(401, json!({})), reply(200, me), reply(401, json!({}))]).unwrap();
        assert_eq!((account.label.as_str(), account.settings["host"].as_str()), ("bo@acme.com", Some("app-eu.wrike.com")));
        let all_401 = [reply(401, json!({})), reply(401, json!({})), reply(401, json!({}))];
        assert!(Wrike.read_profile(&permanent(), &all_401).unwrap_err().contains("rejected that token"));
        let down = [reply(401, json!({})), reply(0, Value::Null), reply(401, json!({}))];
        assert!(Wrike.read_profile(&permanent(), &down).unwrap_err().contains("in time"));
        assert!(Wrike.read_profile(&permanent(), &[reply(200, json!({ "data": [] }))]).is_err());
        assert!(Wrike.search(&permanent(), &eu(), "x", 5).is_empty());
        assert!(Wrike.read_search(&eu(), &[], 5).unwrap().is_empty());
    }

    #[test]
    fn previews_tasks_by_permalink() {
        let us = Account { label: "ada@acme.com".into(), settings: json!({ "host": "www.wrike.com" }) };
        assert_eq!(Wrike.preview_target(&us, "https://www.wrike.com/open.htm?id=123456").as_deref(), Some("123456"));
        assert_eq!(Wrike.preview_target(&us, "https://wrike.com/open.htm?x=1&id=123456#c").as_deref(), Some("123456"));
        assert_eq!(
            Wrike.preview_target(&us, "https://www.wrike.com/workspace.htm?acc=77#/task-view?id=123456&pid=9").as_deref(),
            Some("123456")
        );
        assert_eq!(Wrike.preview_target(&eu(), "https://app-eu.wrike.com/open.htm?id=123456").as_deref(), Some("123456"));
        for (account, no) in [
            (&eu(), "https://www.wrike.com/open.htm?id=123456"),
            (&us, "https://app-eu.wrike.com/open.htm?id=123456"),
            (&us, "https://www.wrike.com.evil.test/open.htm?id=123456"),
            (&us, "https://evil.test/open.htm?id=123456&www.wrike.com"),
            (&us, "https://notwrike.com/open.htm?id=123456"),
            (&us, "https://www.wrike.com/open.htm?id=IEAAAAAA"),
            (&us, "https://www.wrike.com/open.htm?id="),
            (&us, "https://www.wrike.com/open.htm?ids=123456"),
            (&us, "https://www.wrike.com/workspace.htm?acc=77&id=123456"),
            (&us, "https://www.wrike.com/x/open.htm?id=123456"),
        ] {
            assert_eq!(Wrike.preview_target(account, no), None, "{no}");
        }

        let calls = Wrike.preview(&permanent(), &eu(), "123456");
        let permalink = urlencoding::encode("https://app-eu.wrike.com/open.htm?id=123456");
        assert!(
            calls[0].url.starts_with(&format!("https://app-eu.wrike.com/api/v4/tasks?permalink={permalink}&fields=")),
            "{}",
            calls[0].url
        );
        assert!(calls[0].url.contains(&*urlencoding::encode("\"responsibleIds\"")));
        assert_eq!(calls[1].url, "https://app-eu.wrike.com/api/v4/contacts");
        // A host in the credential (from signing in) wins; a bad one stored anywhere is never called.
        let signed_in =
            Credential { token: "a".into(), fields: [("host".to_string(), "app-us2.wrike.com".to_string())].into(), ..Default::default() };
        assert!(Wrike.preview(&signed_in, &eu(), "1")[0].url.starts_with("https://app-us2.wrike.com/"));
        let tampered = Account { label: String::new(), settings: json!({ "host": "evil.test" }) };
        assert!(Wrike.preview(&permanent(), &tampered, "1").iter().all(|c| c.url.starts_with("https://www.wrike.com/")));

        let task = json!({ "data": [{ "id": "IEAAAAAAKQAAAAAA", "title": "Fix deploy", "status": "Active", "importance": "High",
            "description": "<p>Retry&nbsp;the <b>deploy</b></p><script>alert(1)</script><ul><li>a &amp; b</li><li>&lt;c&gt; &#233;&#x21;</li></ul><!-- x -->",
            "createdDate": "2026-09-01T10:00:00Z", "updatedDate": "2026-10-01T10:00:00Z", "dates": { "due": "2026-11-01T17:00:00" },
            "responsibleIds": ["KUAAAAAB", "KUAAAAAZ"], "authorIds": ["KUAAAAAA"], "permalink": "https://app-eu.wrike.com/open.htm?id=123456" }] });
        let contacts = json!({ "data": [{ "id": "KUAAAAAA", "firstName": "Ada", "lastName": "L" }, { "id": "KUAAAAAB", "firstName": "Bo", "lastName": "" }] });
        let p = Wrike.read_preview(&eu(), "123456", &[reply(200, task.clone()), reply(200, contacts)]).unwrap();
        assert_eq!((p.kind.as_str(), p.title.as_str(), p.reference.as_str()), ("task", "Fix deploy", "#123456"));
        assert_eq!((p.status.as_deref(), p.assignee.as_deref(), p.author.as_deref()), (Some("Active"), Some("Bo"), Some("Ada L")));
        assert_eq!((p.created_at.as_deref(), p.updated_at.as_deref()), (Some("2026-09-01T10:00:00Z"), Some("2026-10-01T10:00:00Z")));
        assert_eq!(p.description, "Retry the deploy a & b <c> é!");
        assert_eq!(p.url, "https://app-eu.wrike.com/open.htm?id=123456");
        assert_eq!(
            p.details,
            vec![Detail { label: "Importance".into(), value: "High".into() }, Detail { label: "Due".into(), value: "2026-11-01".into() }]
        );
        // Without names the preview still works.
        let p = Wrike.read_preview(&eu(), "123456", &[reply(200, task), reply(0, Value::Null)]).unwrap();
        assert_eq!((p.title.as_str(), p.assignee, p.author), ("Fix deploy", None, None));

        assert!(
            Wrike
                .read_preview(&eu(), "1", &[reply(200, json!({ "kind": "tasks", "data": [] })), reply(200, json!({}))])
                .unwrap_err()
                .contains("can't see")
        );
        assert!(Wrike.read_preview(&eu(), "1", &[reply(404, json!({})), reply(200, json!({}))]).unwrap_err().contains("can't see"));
        assert!(Wrike.read_preview(&eu(), "1", &[reply(401, json!({})), reply(401, json!({}))]).unwrap_err().contains("Reconnect"));
        assert!(Wrike.read_preview(&eu(), "1", &[reply(0, Value::Null), reply(0, Value::Null)]).unwrap_err().contains("in time"));
    }

    #[test]
    fn html_becomes_plain_text() {
        assert_eq!(excerpt(&html_text("a<br>b<i>c</i>d"), 50), "a bcd");
        assert_eq!(html_text("<STYLE>p{}</style>ok"), "ok");
        assert_eq!(html_text("&unknown; &amp &#xZZ; &#128512;"), "&unknown; &amp &#xZZ; 😀");
        assert_eq!(html_text("1 < 2"), "1 ", "a stray < swallows up to the next >, or the rest");
        assert_eq!(html_text("x<a href='y'"), "x");
        assert_eq!(html_text("<!-- never closed"), "");
    }
}
