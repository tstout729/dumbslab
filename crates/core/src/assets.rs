//! How the web app's static files are cached, the same on both hosts.
//!
//! Browsers never revalidate DumbSlab's scripts and stylesheets. Safari can keep an empty, broken
//! copy of a file in its memory cache and reuse it whenever the server answers `304 Not Modified`.
//! On dumbslab.com every script and stylesheet then came back empty, while a fresh request got the
//! whole file: the page had no styles and the app never started. So scripts and stylesheets are
//! sent with `Cache-Control: no-store` and without the headers browsers revalidate with
//! ([`VALIDATORS`]). A request for one is always answered in full: the host removes its
//! [`CONDITIONAL_HEADERS`] before it asks its file store. HTML pages, images and other files keep
//! their usual caching and `304`s.

/// Request headers a host removes before it asks its file store for a script or stylesheet, so
/// the store sends the whole file and never `304 Not Modified`.
pub const CONDITIONAL_HEADERS: [&str; 2] = ["if-none-match", "if-modified-since"];

/// Response headers a script or stylesheet goes out without, so browsers have nothing to
/// revalidate it with.
pub const VALIDATORS: [&str; 2] = ["etag", "last-modified"];

/// The `Cache-Control` of every script and stylesheet: browsers keep no copy, so they can't reuse
/// a broken one.
pub const NO_STORE: &str = "no-store";

/// JavaScript's media types (the WHATWG MIME Sniffing list) and CSS's.
const SCRIPT_AND_STYLE_TYPES: [&str; 17] = [
    "application/ecmascript",
    "application/javascript",
    "application/x-ecmascript",
    "application/x-javascript",
    "text/ecmascript",
    "text/javascript",
    "text/javascript1.0",
    "text/javascript1.1",
    "text/javascript1.2",
    "text/javascript1.3",
    "text/javascript1.4",
    "text/javascript1.5",
    "text/jscript",
    "text/livescript",
    "text/x-ecmascript",
    "text/x-javascript",
    "text/css",
];

/// Whether a static file with this `Content-Type` is a script or stylesheet, which goes out as
/// [`NO_STORE`] without [`VALIDATORS`]. Parameters such as `; charset=utf-8` don't matter.
pub fn is_script_or_style(content_type: &str) -> bool {
    let essence = content_type.split(';').next().unwrap_or_default().trim();
    SCRIPT_AND_STYLE_TYPES.iter().any(|t| essence.eq_ignore_ascii_case(t))
}

/// Whether a request for `path` is for a script or stylesheet, judged by its extension, because
/// the host removes the [`CONDITIONAL_HEADERS`] before the file store says the file's type.
pub fn is_script_or_style_path(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or_default();
    let extension = name.rsplit_once('.').map(|(_, ext)| ext).unwrap_or_default();
    ["js", "mjs", "cjs", "css"].iter().any(|ext| extension.eq_ignore_ascii_case(ext))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scripts_and_styles_by_type() {
        for t in [
            "text/javascript",
            "text/javascript; charset=utf-8",
            "application/javascript",
            "Application/JavaScript;charset=UTF-8",
            "application/x-javascript",
            "text/ecmascript",
            "text/css",
            "text/css; charset=utf-8",
            " TEXT/CSS ",
        ] {
            assert!(is_script_or_style(t), "{t}");
        }
        for t in [
            "text/html; charset=utf-8",
            "image/svg+xml",
            "image/png",
            "application/json",
            "application/ld+json",
            "application/manifest+json",
            "text/plain",
            "application/octet-stream",
            "text/cssx",
            "text/javascript2",
            "",
        ] {
            assert!(!is_script_or_style(t), "{t}");
        }
    }

    #[test]
    fn scripts_and_styles_by_path() {
        for p in [
            "/theme-init.js",
            "/app.js",
            "/views/post.js",
            "/vendor/sentry/bundle.min.js",
            "/styles.css",
            "/welcome.CSS",
            "/x.mjs",
            "/x.cjs",
        ] {
            assert!(is_script_or_style_path(p), "{p}");
        }
        for p in [
            "/",
            "/index.html",
            "/favicon.svg",
            "/og.png",
            "/p/123",
            "/js",
            "/css/",
            "/app.js/",
            "/app.json",
            "/styles.css.map",
            "/x.jsx",
            "",
        ] {
            assert!(!is_script_or_style_path(p), "{p}");
        }
    }
}
