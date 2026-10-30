//! Google Drive: Docs, Sheets, Slides and other files the connected account can open, including
//! shared drives. Google has no personal tokens, so it needs the host's OAuth app. Drive's
//! read-only scope is "restricted": a public app needs Google's verification before more than
//! 100 people can connect.

use serde_json::json;

use crate::connect::{Account, Connector, Credential, Hit, HttpCall, HttpReply, OAuthSpec, ProviderInfo, http_error, opt, s};

pub struct GoogleDrive;

static INFO: ProviderInfo = ProviderInfo {
    id: "google-drive",
    name: "Google Drive",
    about: "Search Docs, Sheets, Slides and other files, including shared drives.",
    search: true,
    preview: false,
    oauth: Some(OAuthSpec {
        authorize_url: "https://accounts.google.com/o/oauth2/v2/auth",
        token_url: "https://oauth2.googleapis.com/token",
        scopes: &["https://www.googleapis.com/auth/drive.readonly", "openid", "email"],
        scope_param: "scope",
        scope_separator: " ",
        // A refresh token, every time: Google sends one only when the person is asked to consent.
        extra: &[("access_type", "offline"), ("prompt", "consent"), ("include_granted_scopes", "true")],
        pkce: true,
    }),
    token_fields: &[],
    token_help: "",
};

/// A Drive query string literal: quotes and backslashes escaped.
fn literal(q: &str) -> String {
    q.replace('\\', "\\\\").replace('\'', "\\'")
}

fn kind(mime: &str) -> (&'static str, &'static str) {
    match mime {
        "application/vnd.google-apps.document" => ("document", "Google Doc"),
        "application/vnd.google-apps.spreadsheet" => ("spreadsheet", "Google Sheet"),
        "application/vnd.google-apps.presentation" => ("presentation", "Google Slides"),
        "application/vnd.google-apps.form" => ("form", "Google Form"),
        "application/vnd.google-apps.folder" => ("folder", "Folder"),
        "application/pdf" => ("file", "PDF"),
        m if m.starts_with("image/") => ("file", "Image"),
        _ => ("file", "File"),
    }
}

impl Connector for GoogleDrive {
    fn info(&self) -> &'static ProviderInfo {
        &INFO
    }

    fn profile(&self, cred: &Credential) -> Vec<HttpCall> {
        vec![HttpCall::get("https://openidconnect.googleapis.com/v1/userinfo").bearer(&cred.token)]
    }

    fn read_profile(&self, _cred: &Credential, replies: &[HttpReply]) -> Result<Account, String> {
        let r = replies.first().cloned().unwrap_or_default();
        if !r.ok() {
            return Err(http_error("Google Drive", &r));
        }
        Ok(Account { label: s(&r.json()["email"]), settings: json!({}) })
    }

    fn search(&self, cred: &Credential, _account: &Account, q: &str, limit: usize) -> Vec<HttpCall> {
        let query = urlencoding::encode(&format!("fullText contains '{}' and trashed = false", literal(q))).into_owned();
        let fields = urlencoding::encode("files(id,name,mimeType,webViewLink,modifiedTime,owners(displayName))").into_owned();
        vec![
            HttpCall::get(format!(
                "https://www.googleapis.com/drive/v3/files?q={query}&pageSize={}&fields={fields}&corpora=allDrives&includeItemsFromAllDrives=true&supportsAllDrives=true",
                limit.clamp(1, 20)
            ))
            .bearer(&cred.token),
        ]
    }

    fn read_search(&self, _account: &Account, replies: &[HttpReply], limit: usize) -> Result<Vec<Hit>, String> {
        let r = replies.first().cloned().unwrap_or_default();
        if !r.ok() {
            return Err(http_error("Google Drive", &r));
        }
        Ok(r.json()["files"]
            .as_array()
            .into_iter()
            .flatten()
            .take(limit)
            .map(|f| {
                let (kind, label) = kind(f["mimeType"].as_str().unwrap_or_default());
                let owner = opt(&f["owners"][0]["displayName"]);
                Hit {
                    provider: "google-drive".into(),
                    kind: kind.into(),
                    title: s(&f["name"]),
                    url: s(&f["webViewLink"]),
                    context: label.into(),
                    snippet: String::new(),
                    updated_at: opt(&f["modifiedTime"]),
                    author: owner,
                }
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn reply(status: u16, body: Value) -> HttpReply {
        HttpReply { status, body: body.to_string() }
    }

    #[test]
    fn searches_full_text_safely() {
        let calls = GoogleDrive.search(&Credential { token: "t".into(), ..Default::default() }, &Account::default(), "Ada's \\ plan", 5);
        let url = &calls[0].url;
        assert!(url.contains(&*urlencoding::encode("fullText contains 'Ada\\'s \\\\ plan' and trashed = false")), "{url}");
        assert!(url.contains("pageSize=5") && url.contains("supportsAllDrives=true"));
        let files = json!({ "files": [
            { "name": "Onboarding", "mimeType": "application/vnd.google-apps.document", "webViewLink": "https://docs.google.com/document/d/1/edit",
              "modifiedTime": "2026-10-01T00:00:00Z", "owners": [{ "displayName": "Ada" }] },
            { "name": "Budget.pdf", "mimeType": "application/pdf", "webViewLink": "https://drive.google.com/file/d/2/view" }
        ] });
        let hits = GoogleDrive.read_search(&Account::default(), &[reply(200, files)], 5).unwrap();
        assert_eq!((hits[0].kind.as_str(), hits[0].context.as_str(), hits[0].author.as_deref()), ("document", "Google Doc", Some("Ada")));
        assert_eq!((hits[1].kind.as_str(), hits[1].context.as_str()), ("file", "PDF"));
        assert!(GoogleDrive.read_search(&Account::default(), &[reply(401, json!({}))], 5).unwrap_err().contains("Reconnect"));
        let account = GoogleDrive.read_profile(&Credential::default(), &[reply(200, json!({ "email": "ada@acme.com" }))]).unwrap();
        assert_eq!(account.label, "ada@acme.com");
    }
}
