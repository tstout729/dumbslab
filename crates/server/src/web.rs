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

/// Matches `web/_headers`, which the Cloudflare host serves. Embeds may frame only the providers
/// in [`dumbslab_core::embed::FRAME_ORIGINS`].
fn csp() -> &'static str {
    static CSP: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    CSP.get_or_init(|| {
        format!(
            "default-src 'self'; img-src 'self' https: data:; style-src 'self' 'unsafe-inline'; script-src 'self'; \
             connect-src 'self'; font-src 'self' data:; {}; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
            dumbslab_core::embed::frame_src_directive()
        )
    })
}

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
        b = b.header("content-security-policy", csp()).header("x-frame-options", "DENY");
    }
    b.body(Body::from(file.data.into_owned())).unwrap_or_default()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn both_hosts_allow_the_same_embed_frames() {
        let headers = include_str!("../../../web/_headers");
        let frame_src = dumbslab_core::embed::frame_src_directive();
        assert!(super::csp().contains(&format!("; {frame_src};")), "{}", super::csp());
        assert!(headers.contains(&format!("; {frame_src};")), "web/_headers must allow: {frame_src}");
    }
}
