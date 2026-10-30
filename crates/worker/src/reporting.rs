//! Minimal Sentry envelopes: deliberately accepts no request or error text.
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
    use worker::*;
    let id = dumbslab_core::util::sha256_hex(&dumbslab_core::util::new_secret(""))[..32].to_string();
    let body = destination.envelope(&id, failure);
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
}
