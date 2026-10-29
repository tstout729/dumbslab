use serde::Serialize;
use serde_json::{Value, json};

/// An error that maps cleanly onto an HTTP status, a JSON body, and an MCP tool error.
#[derive(Debug, Clone, thiserror::Error)]
#[error("{message}")]
pub struct ApiError {
    pub status: u16,
    pub code: &'static str,
    pub message: String,
    pub details: Option<Value>,
}

pub type ApiResult<T> = Result<T, ApiError>;

impl ApiError {
    pub fn new(status: u16, code: &'static str, message: impl Into<String>) -> Self {
        ApiError { status, code, message: message.into(), details: None }
    }

    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(400, "bad_request", message)
    }
    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self::new(401, "unauthorized", message)
    }
    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::new(403, "forbidden", message)
    }
    pub fn not_found(what: impl Into<String>) -> Self {
        Self::new(404, "not_found", format!("{} not found", what.into()))
    }
    pub fn conflict(message: impl Into<String>) -> Self {
        Self::new(409, "conflict", message)
    }
    pub fn too_many(message: impl Into<String>) -> Self {
        Self::new(429, "rate_limited", message)
    }
    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(500, "internal", message)
    }

    pub fn with_details(mut self, details: impl Serialize) -> Self {
        self.details = serde_json::to_value(details).ok();
        self
    }

    pub fn to_json(&self) -> Value {
        let mut err = json!({ "code": self.code, "message": self.message });
        if let Some(d) = &self.details {
            err["details"] = d.clone();
        }
        json!({ "error": err })
    }
}

impl From<serde_json::Error> for ApiError {
    fn from(e: serde_json::Error) -> Self {
        ApiError::bad_request(format!("invalid input: {e}"))
    }
}
