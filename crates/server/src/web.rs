//! The web app's static files, embedded in the binary. Unknown paths get `index.html` so the
//! single-page app can route them.

use axum::body::Body;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "../../web/"]
#[exclude = "_headers"]
struct Assets;

const CSP: &str = "default-src 'self'; img-src 'self' https: data:; style-src 'self' 'unsafe-inline'; script-src 'self'; \
                   connect-src 'self'; font-src 'self' data:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'";

pub fn serve(path: &str, headers: &HeaderMap) -> Response {
    let wanted = path.trim_start_matches('/');
    let (name, file) = match Assets::get(wanted).filter(|_| !wanted.is_empty()) {
        Some(f) => (wanted.to_string(), f),
        None if wanted.contains('.') && !wanted.ends_with(".html") => {
            return Response::builder().status(StatusCode::NOT_FOUND).body(Body::from("not found")).unwrap_or_default();
        }
        None => match Assets::get("index.html") {
            Some(f) => ("index.html".to_string(), f),
            None => return Response::builder().status(StatusCode::NOT_FOUND).body(Body::from("web app not built")).unwrap_or_default(),
        },
    };
    let etag = format!("\"{}\"", hex(&file.metadata.sha256_hash()[..12]));
    if headers.get("if-none-match").and_then(|v| v.to_str().ok()) == Some(etag.as_str()) {
        return Response::builder().status(StatusCode::NOT_MODIFIED).header("etag", etag).body(Body::empty()).unwrap_or_default();
    }
    let mime = mime_guess::from_path(&name).first_or_octet_stream();
    let mut b = Response::builder()
        .header("content-type", mime.as_ref())
        .header("etag", etag)
        .header("cache-control", "no-cache")
        .header("x-content-type-options", "nosniff")
        .header("referrer-policy", "strict-origin-when-cross-origin");
    if name.ends_with(".html") {
        b = b.header("content-security-policy", CSP).header("x-frame-options", "DENY");
    }
    b.body(Body::from(file.data.into_owned())).unwrap_or_default()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
