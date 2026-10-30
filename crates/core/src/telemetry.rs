//! The web app's session recordings (Quill, a PostHog-compatible server) and error reports
//! (Sentry's browser SDK).
//!
//! Both are off unless the host configures them, so a self-hosted server never reports anywhere.
//! The web app learns the public settings from `GET /api/v1/auth/state` and loads the SDKs only
//! then (`web/telemetry.js`). Every value here is public by design: it ships to browsers.

use serde_json::{Value, json};

/// The commit this build came from, when the build recorded one (`DUMBSLAB_BUILD_GIT_SHA`).
/// Sentry groups the web app's reports by it.
pub fn release() -> Option<&'static str> {
    option_env!("DUMBSLAB_BUILD_GIT_SHA").filter(|sha| !sha.is_empty() && *sha != "unknown")
}

/// Where the web app sends recordings and error reports. Unset or invalid values turn that part off.
#[derive(Clone, Debug, Default)]
pub struct Telemetry {
    /// Quill's origin, e.g. `https://t.staykit.ai`.
    pub quill_host: Option<String>,
    /// The Quill project's public token (`phc_…`).
    pub quill_token: Option<String>,
    pub sentry: Option<Dsn>,
}

impl Telemetry {
    /// Builds the settings from the host's variables, dropping (and describing) any that are invalid.
    pub fn new(quill_host: Option<&str>, quill_token: Option<&str>, sentry_dsn: Option<&str>) -> (Telemetry, Vec<String>) {
        let mut problems = vec![];
        let clean = |v: Option<&str>| v.map(str::trim).filter(|v| !v.is_empty()).map(str::to_string);
        let host = clean(quill_host).and_then(|h| {
            let origin = origin_of(&h);
            if origin.is_none() {
                problems.push(format!("the Quill host {h:?} isn't an origin like https://t.example.com; recordings are off"));
            }
            origin
        });
        let token = clean(quill_token).and_then(|t| {
            let ok = t.strip_prefix("phc_").is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_alphanumeric()));
            if !ok {
                problems.push("the Quill token isn't a public phc_ project token; recordings are off".to_string());
            }
            ok.then_some(t)
        });
        if host.is_some() != token.is_some() && problems.is_empty() {
            problems.push("recordings need both the Quill host and the Quill token; they are off".to_string());
        }
        let sentry = clean(sentry_dsn).and_then(|d| {
            let parsed = Dsn::parse(&d);
            if parsed.is_none() {
                problems.push("the Sentry DSN isn't valid (https://key@host/project-id); error reports are off".to_string());
            }
            parsed
        });
        let (quill_host, quill_token) = match (host, token) {
            (Some(h), Some(t)) => (Some(h), Some(t)),
            _ => (None, None),
        };
        (Telemetry { quill_host, quill_token, sentry }, problems)
    }

    pub fn is_off(&self) -> bool {
        self.quill_host.is_none() && self.sentry.is_none()
    }

    /// What the web app needs, or `null` when both are off. `workspace` is the hosted address.
    pub fn web_config(&self, workspace: Option<&str>) -> Value {
        if self.is_off() {
            return Value::Null;
        }
        let quill = match (&self.quill_host, &self.quill_token) {
            (Some(host), Some(token)) => json!({ "host": host, "token": token }),
            _ => Value::Null,
        };
        let sentry = self.sentry.as_ref().map_or(Value::Null, |d| json!({ "dsn": d.dsn }));
        json!({ "quill": quill, "sentry": sentry, "release": release(), "workspace": workspace })
    }

    /// Origins the web app sends to, for the CSP's `connect-src`.
    pub fn connect_origins(&self) -> Vec<String> {
        self.quill_host.iter().cloned().chain(self.sentry.as_ref().map(|d| d.origin.clone())).collect()
    }
}

/// `scheme://host[:port]` of an http(s) URL with no path, query or credentials.
fn origin_of(url: &str) -> Option<String> {
    let (scheme, host) = url.trim_end_matches('/').split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    let ok = matches!(scheme.as_str(), "http" | "https")
        && !host.is_empty()
        && host.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':' | b'[' | b']'));
    ok.then(|| format!("{scheme}://{}", host.to_ascii_lowercase()))
}

/// A Sentry DSN: `https://<public key>@<host>/<project id>`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dsn {
    pub dsn: String,
    /// Where the browser SDK sends events, e.g. `https://o123.ingest.us.sentry.io`.
    pub origin: String,
}

impl Dsn {
    /// Accepts only a public DSN: a key without a secret, a host and a numeric project id (after an
    /// optional path prefix), with no query or fragment. Browsers get it, so a DSN carrying a
    /// secret (`https://public:secret@host/1`) is refused, as the Worker's reporter refuses it.
    pub fn parse(dsn: &str) -> Option<Dsn> {
        let (scheme, rest) = dsn.trim().split_once("://")?;
        let (key, rest) = rest.split_once('@')?;
        let (host, path) = rest.split_once('/')?;
        let path = path.trim_end_matches('/');
        let project = path.rsplit('/').next().unwrap_or_default();
        let key_ok = !key.is_empty() && key.bytes().all(|b| b.is_ascii_alphanumeric());
        let project_ok = !project.is_empty() && project.bytes().all(|b| b.is_ascii_digit());
        let path_ok = path.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'-' | b'_' | b'.'));
        let origin = origin_of(&format!("{scheme}://{host}"))?;
        let (scheme, host) = origin.split_once("://")?;
        let dsn = format!("{scheme}://{key}@{host}/{path}");
        (key_ok && project_ok && path_ok).then_some(Dsn { dsn, origin })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DSN: &str = "https://85b018c97c1c741350b97406e8556a15@o4511072647970816.ingest.us.sentry.io/4512347076427776";

    #[test]
    fn dsns_name_their_ingest_origin() {
        assert_eq!(Dsn::parse(DSN).unwrap().origin, "https://o4511072647970816.ingest.us.sentry.io");
        let self_hosted = Dsn::parse("http://abc@sentry.local:9000/prefix/7").unwrap();
        assert_eq!(
            (self_hosted.origin.as_str(), self_hosted.dsn.as_str()),
            ("http://sentry.local:9000", "http://abc@sentry.local:9000/prefix/7")
        );
        // Only the public DSN is kept, in a normal form.
        assert_eq!(Dsn::parse(" HTTPS://key@O1.Ingest.Sentry.io/42/ ").unwrap().dsn, "https://key@o1.ingest.sentry.io/42");
        for bad in [
            "",
            "https://sentry.io/1",
            "https://key@sentry.io/",
            "https://key@sentry.io/abc",
            "ftp://key@sentry.io/1",
            "https://k@ho st/1",
            "https://public:secret@sentry.io/42",
            "https://key@sentry.io/42?secret=1",
            "https://key@sentry.io/42#frag",
            "https://key@user@sentry.io/42",
        ] {
            assert!(Dsn::parse(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn telemetry_is_off_unless_configured() {
        let (off, problems) = Telemetry::new(None, Some(""), None);
        assert!(off.is_off() && problems.is_empty());
        assert_eq!(off.web_config(None), Value::Null);
        assert!(off.connect_origins().is_empty());

        let (on, problems) = Telemetry::new(Some("https://T.staykit.ai/"), Some("phc_abc123"), Some(DSN));
        assert!(problems.is_empty(), "{problems:?}");
        assert_eq!(on.connect_origins(), ["https://t.staykit.ai", "https://o4511072647970816.ingest.us.sentry.io"]);
        let web = on.web_config(Some("acme"));
        assert_eq!(web["quill"], json!({ "host": "https://t.staykit.ai", "token": "phc_abc123" }));
        assert_eq!(web["sentry"]["dsn"], DSN);
        assert_eq!(web["workspace"], "acme");

        // Half a Quill setting, a secret where the public token belongs, or a URL with a path
        // turns recordings off.
        let (half, problems) = Telemetry::new(Some("https://t.staykit.ai"), None, None);
        assert!(half.is_off() && problems.len() == 1);
        let (secret, problems) = Telemetry::new(Some("https://t.staykit.ai"), Some("phx_personal-key"), Some("nope"));
        assert!(secret.is_off() && problems.len() == 2);
        let (path, _) = Telemetry::new(Some("https://t.staykit.ai/ingest"), Some("phc_abc"), None);
        assert!(path.is_off());
    }
}
