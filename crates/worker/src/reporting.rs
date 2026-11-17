//! Minimal Sentry envelopes: deliberately accepts no request or error text.
use dumbslab_core::tenancy::Warning;
use serde_json::json;
use worker::Url;

pub(crate) struct Destination {
    pub endpoint: String,
    pub dsn: String,
}

impl Destination {
    pub fn parse(dsn: &str) -> Option<Self> {
        let url = Url::parse(dsn).ok()?;
        let key = url.username();
        let project = url.path().strip_prefix('/')?;
        if url.scheme() != "https"
            || url.host_str().is_none()
            || key.is_empty()
            || !key.bytes().all(|b| b.is_ascii_alphanumeric())
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || project.is_empty()
            || !project.bytes().all(|b| b.is_ascii_digit())
        {
            return None;
        }
        let mut endpoint = url.clone();
        endpoint.set_username("").ok()?;
        endpoint.set_path(&format!("/api/{project}/envelope/"));
        Some(Self { endpoint: endpoint.into(), dsn: dsn.into() })
    }

    pub fn envelope(&self, event_id: &str, failure: Failure) -> String {
        let category = failure.category();
        let event = json!({
            "event_id": event_id,
            "platform": "other",
            "level": "error",
            "logger": "dumbslab.worker",
            "release": concat!("dumbslab@", env!("CARGO_PKG_VERSION")),
            "message": category,
            "fingerprint": ["dumbslab.worker", category],
        });
        format!("{}\n{}\n{}\n", json!({"event_id": event_id, "dsn": self.dsn}), json!({"type": "event"}), event)
    }

    /// A limit's warning: its fixed sentence and the totals, never a workspace or a person.
    pub fn warning_envelope(&self, event_id: &str, warning: &Warning) -> String {
        let event = json!({
            "event_id": event_id,
            "platform": "other",
            "level": if warning.percent >= 100 { "error" } else { "warning" },
            "logger": "dumbslab.capacity",
            "release": concat!("dumbslab@", env!("CARGO_PKG_VERSION")),
            "message": warning.message(),
            "fingerprint": ["dumbslab.capacity", warning.limit, warning.percent.to_string()],
            "extra": { "used": warning.used, "allowed": warning.allowed, "percent": warning.percent },
        });
        format!("{}\n{}\n{}\n", json!({"event_id": event_id, "dsn": self.dsn}), json!({"type": "event"}), event)
    }
}

#[derive(Clone, Copy)]
pub(crate) enum Failure {
    Runtime,
    ServerResponse,
}

impl Failure {
    fn category(self) -> &'static str {
        match self {
            Self::Runtime => "Worker request failed",
            Self::ServerResponse => "Worker or Durable Object returned HTTP 5xx",
        }
    }
}

/// Delivery is best effort and cannot change the application's response.
pub(crate) async fn send(destination: Destination, failure: Failure) -> worker::Result<()> {
    let body = destination.envelope(&new_event_id(), failure);
    post(&destination, body).await
}

/// Tells the operator a hosted limit reached one of its warning levels. Sentry groups each limit
/// and level into one issue, so a new level, or one crossed again after the issue was resolved,
/// sends one email.
pub(crate) async fn send_warning(destination: &Destination, warning: &Warning) -> worker::Result<()> {
    post(destination, destination.warning_envelope(&new_event_id(), warning)).await
}

fn new_event_id() -> String {
    dumbslab_core::util::sha256_hex(&dumbslab_core::util::new_secret(""))[..32].to_string()
}

async fn post(destination: &Destination, body: String) -> worker::Result<()> {
    use worker::*;
    let headers = Headers::new();
    headers.set("content-type", "application/x-sentry-envelope")?;
    let mut init = RequestInit::new();
    init.with_method(Method::Post).with_headers(headers).with_redirect(RequestRedirect::Manual).with_body(Some(body.into()));
    Fetch::Request(Request::new_with_init(&destination.endpoint, &init)?).send().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_destination() {
        let destination = Destination::parse("https://abc123@o1.ingest.sentry.io/42").unwrap();
        assert_eq!(destination.endpoint, "https://o1.ingest.sentry.io/api/42/envelope/");
        for invalid in [
            "",
            "http://key@example.com/42",
            "https://key:secret@example.com/42",
            "https://key@example.com/x",
            "https://key@example.com/42?secret=yes",
            "https://key@example.com/42#fragment",
        ] {
            assert!(Destination::parse(invalid).is_none());
        }
    }

    #[test]
    fn envelope_has_only_allowlisted_fields_and_fixed_categories() {
        let destination = Destination::parse("https://abc123@o1.ingest.sentry.io/42").unwrap();
        for failure in [Failure::Runtime, Failure::ServerResponse] {
            let envelope = destination.envelope("0123456789abcdef0123456789abcdef", failure);
            let lines: Vec<_> = envelope.lines().collect();
            assert_eq!(lines.len(), 3);
            let event: serde_json::Value = serde_json::from_str(lines[2]).unwrap();
            let keys: Vec<_> = event.as_object().unwrap().keys().map(String::as_str).collect();
            assert_eq!(keys, ["event_id", "fingerprint", "level", "logger", "message", "platform", "release"]);
            assert_eq!(event["message"], failure.category());
        }
    }

    #[test]
    fn warning_envelope_carries_only_the_limit_and_totals() {
        let destination = Destination::parse("https://abc123@o1.ingest.sentry.io/42").unwrap();
        let warning = Warning { limit: "free_storage", percent: 75, used: 75, allowed: 100 };
        let envelope = destination.warning_envelope("0123456789abcdef0123456789abcdef", &warning);
        let event: serde_json::Value = serde_json::from_str(envelope.lines().nth(2).unwrap()).unwrap();
        let keys: Vec<_> = event.as_object().unwrap().keys().map(String::as_str).collect();
        assert_eq!(keys, ["event_id", "extra", "fingerprint", "level", "logger", "message", "platform", "release"]);
        assert_eq!(event["level"], "warning");
        assert_eq!(event["fingerprint"], json!(["dumbslab.capacity", "free_storage", "75"]));
        assert_eq!(event["message"], "Free plan: storage is at 75% of the shared cap");
        let reached = Warning { percent: 100, ..warning };
        let event: serde_json::Value =
            serde_json::from_str(destination.warning_envelope("0123456789abcdef0123456789abcdef", &reached).lines().nth(2).unwrap())
                .unwrap();
        assert_eq!(event["level"], "error");
    }
}
