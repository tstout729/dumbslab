//! Slack: messages the connected person can see, from Slack's own search. Only user tokens can
//! search, so people sign in to the host's Slack app and grant it the `search:read` user scope.
//!
//! `search.messages` is a legacy method. Slack recommends its Real-time Search API
//! (`assistant.search.context`) instead, but that API serves only Marketplace-published and
//! internal apps, never unlisted distributed ones. `search.messages` works for any app. Slack's
//! May 2025 rate cut for non-Marketplace apps (1 request a minute) hit `conversations.history` and
//! `conversations.replies`, not search. Slack's API terms do say the Marketplace is the only place
//! to distribute an app commercially, so a hosted DumbSlab's shared Slack app belongs there; a
//! self-hosted server's own Slack app is an internal app.
//!
//! Docs: https://docs.slack.dev/reference/methods/search.messages,
//! https://docs.slack.dev/reference/methods/oauth.v2.access, https://docs.slack.dev/reference/methods/auth.test,
//! https://docs.slack.dev/authentication/installing-with-oauth, https://docs.slack.dev/authentication/using-token-rotation,
//! https://docs.slack.dev/messaging/formatting-message-text, https://docs.slack.dev/apis/web-api/real-time-search-api/,
//! https://docs.slack.dev/changelog/2025/05/29/rate-limit-changes-for-non-marketplace-apps/

use chrono::DateTime;
use serde_json::{Value, json};

use crate::connect::{
    Account, Connector, Credential, Hit, HttpCall, HttpReply, OAuthSpec, ProviderInfo, TokenSet, excerpt, http_error, opt, s,
};

pub struct Slack;

const API: &str = "https://slack.com/api";

static INFO: ProviderInfo = ProviderInfo {
    id: "slack",
    name: "Slack",
    about: "Search messages in the channels and conversations you can see.",
    search: true,
    preview: false,
    oauth: Some(OAuthSpec {
        authorize_url: "https://slack.com/oauth/v2/authorize",
        token_url: "https://slack.com/api/oauth.v2.access",
        // A user token, not a bot token: only user tokens can search, and they see what the person sees.
        scopes: &["search:read"],
        scope_param: "user_scope",
        scope_separator: ",",
        extra: &[],
        pkce: false,
        site: None,
        refresh_revokes: false,
    }),
    token_fields: &[],
    token_help: "",
};

/// Why a call failed, or `None` when it worked. Slack answers most failures with HTTP 200,
/// `"ok": false` and an error code.
fn failure(reply: &HttpReply) -> Option<String> {
    if !reply.ok() {
        return Some(http_error("Slack", reply));
    }
    let v = reply.json();
    if v["ok"].as_bool() == Some(true) {
        return None;
    }
    let Some(code) = v["error"].as_str() else { return Some("Slack sent an answer DumbSlab couldn't read.".into()) };
    Some(match code {
        "invalid_auth" | "not_authed" | "token_revoked" | "token_expired" | "account_inactive" => {
            "Slack rejected the saved credentials. Reconnect Slack in Settings › Connected apps.".into()
        }
        "missing_scope" => "Slack didn't allow searching with this connection. Reconnect Slack in Settings › Connected apps.".into(),
        "ratelimited" => "Slack's rate limit was reached. Try again in a minute.".into(),
        other => format!("Slack couldn't do that ({other})."),
    })
}

/// Slack's message markup as plain text: `<@U1|ada>` → `@ada`, `<#C1|general>` → `#general`,
/// `<!here>` → `@here`, `<https://x|label>` → `label`, and `&amp;`, `&lt;`, `&gt;` decoded. Slack
/// often leaves names out of mentions; the author's own reads `@` and their name, others `@someone`.
pub fn plain(text: &str, author_id: &str, author: Option<&str>) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find('<') {
        out.push_str(&rest[..start]);
        let inner = &rest[start + 1..];
        let Some(end) = inner.find('>') else {
            out.push_str(&rest[start..]);
            rest = "";
            break;
        };
        out.push_str(&markup(&inner[..end], author_id, author));
        rest = &inner[end + 1..];
    }
    out.push_str(rest);
    out.replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&")
}

/// One `<…>`, without its brackets.
fn markup(inner: &str, author_id: &str, author: Option<&str>) -> String {
    let (target, label) = match inner.split_once('|') {
        Some((t, l)) => (t, Some(l).filter(|l| !l.is_empty())),
        None => (inner, None),
    };
    let at = |name: &str| format!("@{}", name.trim_start_matches('@'));
    if let Some(id) = target.strip_prefix('@') {
        return match (label, author) {
            (Some(l), _) => at(l),
            (None, Some(a)) if !id.is_empty() && id == author_id => at(a),
            _ => "@someone".into(),
        };
    }
    if target.starts_with('#') {
        return format!("#{}", label.unwrap_or("channel").trim_start_matches('#'));
    }
    if let Some(special) = target.strip_prefix('!') {
        let name = special.split('^').next().unwrap_or_default();
        return match name {
            "here" | "channel" | "everyone" => format!("@{name}"),
            "subteam" => label.map(at).unwrap_or_else(|| "@group".into()),
            // Dates and anything newer: the fallback text Slack requires.
            _ => label.unwrap_or_default().to_string(),
        };
    }
    label.unwrap_or_else(|| target.strip_prefix("mailto:").unwrap_or(target)).to_string()
}

/// Where a message is: `#general`, a direct message or a group message. A direct message's
/// channel name is the other person's ID, so it isn't shown.
fn place(m: &Value) -> String {
    let channel = &m["channel"];
    if m["type"] == "im" || channel["is_im"] == true {
        return "Direct message".into();
    }
    if m["type"] == "mpim" || channel["is_mpim"] == true {
        return "Group message".into();
    }
    opt(&channel["name"]).map(|n| format!("#{n}")).unwrap_or_else(|| "Slack".into())
}

/// A message's `ts` (`"1508284197.000015"`, seconds since 1970) as a time.
fn time_of(ts: &Value) -> Option<String> {
    let secs = ts.as_str()?.split('.').next()?.parse::<i64>().ok()?;
    DateTime::from_timestamp(secs, 0).map(crate::util::ts)
}

fn hit(m: &Value) -> Hit {
    let user = opt(&m["username"]);
    let text = plain(m["text"].as_str().unwrap_or_default(), m["user"].as_str().unwrap_or_default(), user.as_deref());
    let place = place(m);
    let title = excerpt(&text, 80);
    let long = excerpt(&text, 240);
    Hit {
        provider: "slack".into(),
        kind: "message".into(),
        title: if title.is_empty() { format!("Message in {place}") } else { title.clone() },
        url: s(&m["permalink"]),
        context: match &user {
            Some(u) => format!("{place} · @{u}"),
            None => place,
        },
        snippet: if long == title { String::new() } else { long },
        updated_at: time_of(&m["ts"]),
        author: user.map(|u| format!("@{u}")),
    }
}

impl Connector for Slack {
    fn info(&self) -> &'static ProviderInfo {
        &INFO
    }

    fn profile(&self, cred: &Credential) -> Vec<HttpCall> {
        vec![HttpCall::post_form(format!("{API}/auth.test"), &[]).bearer(&cred.token)]
    }

    fn read_profile(&self, _cred: &Credential, replies: &[HttpReply]) -> Result<Account, String> {
        let r = replies.first().cloned().unwrap_or_default();
        if let Some(e) = failure(&r) {
            return Err(e);
        }
        let v = r.json();
        let (user, team) = (s(&v["user"]), s(&v["team"]));
        if user.is_empty() {
            return Err("Slack didn't say whose account that is.".into());
        }
        let label = if team.is_empty() { format!("@{user}") } else { format!("@{user} · {team}") };
        Ok(Account {
            label,
            settings: json!({ "user": user, "user_id": s(&v["user_id"]), "team": team, "team_id": s(&v["team_id"]), "url": s(&v["url"]) }),
        })
    }

    fn search(&self, cred: &Credential, _account: &Account, q: &str, limit: usize) -> Vec<HttpCall> {
        let query = urlencoding::encode(q);
        vec![HttpCall::get(format!("{API}/search.messages?query={query}&count={}", limit.clamp(1, 20))).bearer(&cred.token)]
    }

    fn read_search(&self, _account: &Account, replies: &[HttpReply], limit: usize) -> Result<Vec<Hit>, String> {
        let r = replies.first().cloned().unwrap_or_default();
        if let Some(e) = failure(&r) {
            return Err(e);
        }
        Ok(r.json()["messages"]["matches"].as_array().into_iter().flatten().take(limit).map(hit).collect())
    }

    /// The user token is under `authed_user`; the top level holds a bot token, which this app
    /// doesn't ask for. Refreshing a rotated user token may answer at the top level instead.
    fn read_token(&self, reply: &HttpReply) -> Result<TokenSet, String> {
        let v = reply.json();
        if !reply.ok() || v["ok"].as_bool() != Some(true) {
            let why = v["error"].as_str().map(str::to_string).unwrap_or_else(|| format!("HTTP {}", reply.status));
            return Err(format!("Slack didn't accept the sign-in ({why}). Try connecting again."));
        }
        let user = if v["authed_user"]["access_token"].is_string() {
            &v["authed_user"]
        } else if v["token_type"] == "user" {
            &v
        } else {
            return Err("Slack didn't give DumbSlab a user token. Try connecting again.".into());
        };
        match opt(&user["access_token"]) {
            Some(token) => Ok(TokenSet {
                access_token: token,
                refresh_token: opt(&user["refresh_token"]),
                expires_in: user["expires_in"].as_i64(),
                ..Default::default()
            }),
            None => Err("Slack didn't give DumbSlab a user token. Try connecting again.".into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reply(status: u16, body: Value) -> HttpReply {
        HttpReply { status, body: body.to_string() }
    }

    fn fail(code: &str) -> HttpReply {
        reply(200, json!({ "ok": false, "error": code }))
    }

    #[test]
    fn signs_in_for_a_user_token() {
        let spec = INFO.oauth.unwrap();
        assert_eq!((spec.scope_param, spec.scopes), ("user_scope", &["search:read"][..]));
        let installed = json!({ "ok": true, "app_id": "A1", "team": { "id": "T1", "name": "Acme" },
            "authed_user": { "id": "U1", "scope": "search:read", "access_token": "xoxp-1", "token_type": "user" } });
        let t = Slack.read_token(&reply(200, installed)).unwrap();
        assert_eq!((t.access_token.as_str(), t.refresh_token, t.expires_in), ("xoxp-1", None, None));
        // With token rotation on, the user token expires and comes with a refresh token.
        let rotating = json!({ "ok": true, "authed_user": { "access_token": "xoxe.xoxp-1", "token_type": "user",
            "refresh_token": "xoxe-1-r", "expires_in": 43200 } });
        let t = Slack.read_token(&reply(200, rotating)).unwrap();
        assert_eq!((t.refresh_token.as_deref(), t.expires_in), (Some("xoxe-1-r"), Some(43200)));
        let refreshed =
            json!({ "ok": true, "access_token": "xoxe.xoxp-2", "token_type": "user", "refresh_token": "xoxe-1-s", "expires_in": 43200 });
        assert_eq!(Slack.read_token(&reply(200, refreshed)).unwrap().access_token, "xoxe.xoxp-2");
        // A bot token alone can't search.
        let bot = json!({ "ok": true, "access_token": "xoxb-1", "token_type": "bot" });
        assert!(Slack.read_token(&reply(200, bot)).unwrap_err().contains("user token"));
        assert!(Slack.read_token(&fail("invalid_code")).unwrap_err().contains("(invalid_code)"));
        assert!(Slack.read_token(&reply(500, json!({}))).unwrap_err().contains("HTTP 500"));
    }

    #[test]
    fn profile_names_the_person_and_workspace() {
        let calls = Slack.profile(&Credential { token: "xoxp-1".into(), ..Default::default() });
        assert_eq!((calls[0].method, calls[0].url.as_str()), ("POST", "https://slack.com/api/auth.test"));
        assert!(calls[0].headers.contains(&("authorization".into(), "Bearer xoxp-1".into())));
        let ok = json!({ "ok": true, "url": "https://acme.slack.com/", "team": "Acme", "user": "ada", "team_id": "T1", "user_id": "U1" });
        let account = Slack.read_profile(&Credential::default(), &[reply(200, ok)]).unwrap();
        assert_eq!(account.label, "@ada · Acme");
        assert_eq!((account.settings["user_id"].as_str(), account.settings["team_id"].as_str()), (Some("U1"), Some("T1")));
        assert!(Slack.read_profile(&Credential::default(), &[fail("invalid_auth")]).unwrap_err().contains("Reconnect"));
        assert!(Slack.read_profile(&Credential::default(), &[reply(200, json!({ "ok": true }))]).unwrap_err().contains("whose"));
    }

    #[test]
    fn search_reads_messages_as_plain_text() {
        let account = Account::default();
        let calls = Slack.search(&Credential { token: "xoxp-1".into(), ..Default::default() }, &account, "deploy & roll back", 5);
        assert_eq!(calls[0].url, "https://slack.com/api/search.messages?query=deploy%20%26%20roll%20back&count=5");
        assert!(calls[0].headers.contains(&("authorization".into(), "Bearer xoxp-1".into())));
        let matches = json!({ "ok": true, "query": "deploy", "messages": { "total": 3, "matches": [
            { "type": "message", "channel": { "id": "C1", "name": "ops", "is_private": false }, "user": "U1", "username": "ada",
              "ts": "1508284197.000015", "permalink": "https://acme.slack.com/archives/C1/p1508284197000015",
              "text": "<@U2> the deploy to <https://api.acme.com|api> failed &amp; <#C2|ops-alerts> paged <!here>. Me, <@U1>, rolling back &lt;now&gt;." },
            { "type": "im", "channel": { "id": "D1", "name": "U9" }, "user": "U9", "username": "bo", "ts": "1508284200.000001",
              "permalink": "https://acme.slack.com/archives/D1/p1", "text": "deploy?" },
            { "type": "message", "channel": { "id": "C3", "name": "general" }, "user": "", "username": "robot", "ts": "1",
              "permalink": "https://acme.slack.com/archives/C3/p2", "text": "" }
        ] } });
        let hits = Slack.read_search(&account, &[reply(200, matches.clone())], 5).unwrap();
        assert_eq!(hits.len(), 3);
        let h = &hits[0];
        assert_eq!((h.kind.as_str(), h.context.as_str(), h.author.as_deref()), ("message", "#ops · @ada", Some("@ada")));
        assert_eq!(h.url, "https://acme.slack.com/archives/C1/p1508284197000015");
        assert_eq!(h.updated_at.as_deref(), Some("2017-10-17T23:49:57.000Z"));
        assert_eq!(h.snippet, "@someone the deploy to api failed & #ops-alerts paged @here. Me, @ada, rolling back <now>.");
        assert!(h.title.chars().count() <= 81 && h.title.ends_with('…'), "{}", h.title);
        assert_eq!((hits[1].context.as_str(), hits[1].title.as_str(), hits[1].snippet.as_str()), ("Direct message · @bo", "deploy?", ""));
        assert_eq!(hits[2].title, "Message in #general");
        assert_eq!(Slack.read_search(&account, &[reply(200, matches)], 1).unwrap().len(), 1);
    }

    #[test]
    fn slack_errors_read_plainly() {
        let a = Account::default();
        for code in ["invalid_auth", "not_authed", "token_revoked", "account_inactive", "token_expired"] {
            assert!(Slack.read_search(&a, &[fail(code)], 5).unwrap_err().contains("Reconnect Slack"), "{code}");
        }
        assert!(Slack.read_search(&a, &[fail("ratelimited")], 5).unwrap_err().contains("Try again"));
        assert!(Slack.read_search(&a, &[fail("missing_scope")], 5).unwrap_err().contains("Reconnect"));
        assert_eq!(Slack.read_search(&a, &[fail("fatal_error")], 5).unwrap_err(), "Slack couldn't do that (fatal_error).");
        assert!(
            Slack.read_search(&a, &[reply(429, json!({ "ok": false, "error": "ratelimited" }))], 5).unwrap_err().contains("rate limit")
        );
        assert!(Slack.read_search(&a, &[reply(0, json!(null))], 5).unwrap_err().contains("in time"));
        assert!(Slack.read_search(&a, &[reply(200, json!(null))], 5).unwrap_err().contains("couldn't read"));
    }

    #[test]
    fn markup_becomes_plain_text() {
        let p = |t: &str| plain(t, "U1", Some("ada"));
        assert_eq!(p("hi <@U1> and <@U2> and <@W3|cy>"), "hi @ada and @someone and @cy");
        assert_eq!(p("<#C1> <#C2|general>"), "#channel #general");
        assert_eq!(p("<!channel> <!everyone> <!here|here> <!subteam^S1> <!subteam^S2|@design>"), "@channel @everyone @here @group @design");
        assert_eq!(p("<!date^1392734382^{date_short}^https://x.test|Feb 18, 2014 PST>"), "Feb 18, 2014 PST");
        assert_eq!(
            p("<https://acme.com> <https://acme.com/a?b=1&amp;c=2|the docs> <mailto:ada@acme.com>"),
            "https://acme.com the docs ada@acme.com"
        );
        assert_eq!(p("a &amp;lt; b, 1 &lt; 2 &gt; 0, unclosed <tag"), "a &lt; b, 1 < 2 > 0, unclosed <tag");
        assert_eq!(plain("<@U1>", "", None), "@someone");
    }
}
