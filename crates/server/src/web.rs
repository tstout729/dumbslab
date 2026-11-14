//! The web app's static files, embedded in the binary. Unknown paths get `index.html` so the
//! single-page app can route them.

use axum::body::Body;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use dumbslab_core::assets;
use rust_embed::RustEmbed;

/// Browsers check every file with the server before using their copy.
const CACHE_CONTROL: &str = "no-cache";

#[derive(RustEmbed)]
#[folder = "../../web/"]
#[exclude = "_headers"]
struct Assets;

/// Matches `web/_headers`, which the Cloudflare host serves. Embeds may frame only the providers
/// in [`dumbslab_core::embed::FRAME_ORIGINS`], and play video files only from
/// [`dumbslab_core::embed::MEDIA_ORIGINS`]. `connect` adds the origins the web app sends
/// recordings and error reports to, when they're configured.
pub fn csp(connect: &[String]) -> String {
    let connect: String = connect.iter().map(|o| format!(" {o}")).collect();
    format!(
        "default-src 'self'; img-src 'self' https: data:; style-src 'self' 'unsafe-inline'; script-src 'self'; \
         connect-src 'self'{connect}; font-src 'self' data:; {}; {}; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
        dumbslab_core::embed::media_src_directive(),
        dumbslab_core::embed::frame_src_directive()
    )
}

pub fn serve(path: &str, headers: &HeaderMap, csp: &str) -> Response {
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
    // With the build's commit, like the Cloudflare host's, so each new build replaces every copy.
    let etag = assets::versioned_etag(&hex(&file.metadata.sha256_hash()[..12]), dumbslab_core::GIT_SHA);
    let if_none_match: Vec<&str> = headers.get_all("if-none-match").iter().filter_map(|v| v.to_str().ok()).collect();
    if !if_none_match.is_empty() && assets::none_match(&if_none_match.join(","), &etag) {
        return Response::builder()
            .status(StatusCode::NOT_MODIFIED)
            .header("etag", etag)
            .header("cache-control", CACHE_CONTROL)
            .body(Body::empty())
            .unwrap_or_default();
    }
    let mime = mime_guess::from_path(&name).first_or_octet_stream();
    let mut b = Response::builder()
        .header("content-type", mime.as_ref())
        .header("etag", etag)
        .header("cache-control", CACHE_CONTROL)
        .header("x-content-type-options", "nosniff")
        .header("referrer-policy", "strict-origin-when-cross-origin");
    if name.ends_with(".html") {
        b = b.header("content-security-policy", csp).header("x-frame-options", "DENY");
    }
    b.body(Body::from(file.data.into_owned())).unwrap_or_default()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn both_hosts_allow_the_same_embeds() {
        let headers = include_str!("../../../web/_headers");
        for directive in [dumbslab_core::embed::media_src_directive(), dumbslab_core::embed::frame_src_directive()] {
            assert!(super::csp(&[]).contains(&format!("; {directive};")), "{}", super::csp(&[]));
            assert!(headers.contains(&format!("; {directive};")), "web/_headers must allow: {directive}");
        }
    }

    #[test]
    fn configured_telemetry_hosts_may_be_reached() {
        assert!(super::csp(&[]).contains("; connect-src 'self';"));
        let csp = super::csp(&["https://t.example".into(), "https://o1.ingest.example".into()]);
        assert!(csp.contains("; connect-src 'self' https://t.example https://o1.ingest.example;"), "{csp}");
        assert!(csp.contains("; script-src 'self';"), "scripts stay same-origin: {csp}");
    }
}
