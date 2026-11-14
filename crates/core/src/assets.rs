//! ETags for the web app's static files, the same on both hosts.
//!
//! A file's ETag is a hash of its content, so it stays the same across deploys that don't change
//! the file. Then a browser holding a copy it can't use never gets a new one: Safari once cached
//! Zstandard bodies it couldn't decode, and every revalidation got `304 Not Modified`. So each host
//! adds the build's commit ([`crate::GIT_SHA`]) to the ETag, and after each deploy every browser
//! gets every file again once. Hosts ask their file store without the request's
//! [`CONDITIONAL_HEADERS`] and answer revalidations themselves with [`none_match`].

/// Request headers a host removes before it asks its file store for a file, so the store always
/// sends the whole file. The store compares them with its own ETag, which lacks the commit.
pub const CONDITIONAL_HEADERS: [&str; 2] = ["if-none-match", "if-modified-since"];

/// `etag` with `build` added inside the quotes: `"abc"` becomes `"abc-<build>"`. A weak ETag
/// (`W/"abc"`) stays weak, and a bare value (`abc`) gets quotes.
pub fn versioned_etag(etag: &str, build: &str) -> String {
    let (weak, tag) = split_weak(etag.trim());
    let opaque = tag.strip_prefix('"').and_then(|t| t.strip_suffix('"')).unwrap_or(tag);
    format!("{weak}\"{opaque}-{build}\"")
}

/// Whether an `If-None-Match` header matches `etag`, so the host answers `304 Not Modified`.
///
/// This is the weak comparison the header calls for: `W/"abc"` matches `"abc"`, which matters
/// because Cloudflare marks an ETag weak when it compresses a response. Takes a list
/// (`"a", W/"b"`), where a comma inside quotes is part of an ETag, and `*`, which matches any file.
pub fn none_match(if_none_match: &str, etag: &str) -> bool {
    let current = opaque(etag);
    list(if_none_match).any(|entry| entry == "*" || opaque(entry) == current)
}

/// Whether a `304 Not Modified` keeps this header from the file's `200` response: the headers that
/// say how to cache the file and which copy it is. The browser keeps the rest from its copy.
pub fn kept_on_not_modified(name: &str) -> bool {
    ["cache-control", "content-location", "date", "etag", "expires", "last-modified", "vary"]
        .iter()
        .any(|kept| name.eq_ignore_ascii_case(kept))
}

/// Splits off a weak ETag's `W/`. Accepts a lowercase `w/`, which some clients send.
fn split_weak(etag: &str) -> (&str, &str) {
    match etag.get(..2) {
        Some("W/" | "w/") => ("W/", &etag[2..]),
        _ => ("", etag),
    }
}

/// An ETag without `W/` and its quotes, for comparing.
fn opaque(etag: &str) -> &str {
    let (_, tag) = split_weak(etag.trim());
    tag.strip_prefix('"').and_then(|t| t.strip_suffix('"')).unwrap_or(tag)
}

/// The entries of a comma-separated ETag list, trimmed, without empty ones.
fn list(header: &str) -> impl Iterator<Item = &str> {
    let mut rest = header;
    std::iter::from_fn(move || {
        loop {
            rest = rest.trim_start_matches(|c: char| c == ',' || c.is_ascii_whitespace());
            if rest.is_empty() {
                return None;
            }
            let mut quoted = false;
            let end = rest
                .char_indices()
                .find(|&(_, c)| {
                    if c == '"' {
                        quoted = !quoted;
                    }
                    c == ',' && !quoted
                })
                .map_or(rest.len(), |(i, _)| i);
            let (entry, tail) = rest.split_at(end);
            rest = tail;
            let entry = entry.trim();
            if !entry.is_empty() {
                return Some(entry);
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const BUILD: &str = "0123456789abcdef0123456789abcdef01234567";

    #[test]
    fn adds_the_build_inside_the_quotes() {
        assert_eq!(versioned_etag("\"5f2a\"", BUILD), format!("\"5f2a-{BUILD}\""));
        assert_eq!(versioned_etag("W/\"5f2a\"", BUILD), format!("W/\"5f2a-{BUILD}\""));
        assert_eq!(versioned_etag(" 5f2a ", BUILD), format!("\"5f2a-{BUILD}\""));
        assert_eq!(versioned_etag("w/\"5f2a\"", "unknown"), "W/\"5f2a-unknown\"");
    }

    #[test]
    fn another_build_gets_another_etag() {
        let before = versioned_etag("\"5f2a\"", BUILD);
        let after = versioned_etag("\"5f2a\"", "fedcba9876543210fedcba9876543210fedcba98");
        assert_ne!(before, after);
        // A copy from before the commit was added, or from an earlier deploy, never matches.
        assert!(!none_match("\"5f2a\"", &after));
        assert!(!none_match("W/\"5f2a\"", &after));
        assert!(!none_match(&before, &after));
    }

    #[test]
    fn compares_weakly() {
        let etag = versioned_etag("\"5f2a\"", BUILD);
        let weak = format!("W/{etag}");
        assert!(none_match(&etag, &etag));
        // Cloudflare weakened it when it compressed the file; the browser sends it back that way.
        assert!(none_match(&weak, &etag));
        assert!(none_match(&etag, &weak));
        assert!(none_match(&weak, &weak));
        assert!(none_match(&format!("w/{etag}"), &etag));
        assert!(!none_match("\"5f2b\"", &etag));
        // Quotes are part of the comparison: a prefix or suffix isn't a match.
        assert!(!none_match(&format!("\"5f2a-{}\"", &BUILD[..12]), &etag));
        assert!(!none_match("\"\"", &etag));
        assert!(!none_match("", &etag));
    }

    #[test]
    fn reads_lists() {
        let etag = versioned_etag("\"5f2a\"", BUILD);
        assert!(none_match(&format!("\"old\", W/\"older\",{etag}"), &etag));
        assert!(none_match(&format!(" , W/{etag} ,, \"old\" "), &etag));
        assert!(!none_match("\"old\", W/\"older\"", &etag));
        // A comma inside quotes is part of the ETag, not a separator.
        assert!(none_match("\"a,b\"", "\"a,b\""));
        assert!(!none_match("\"a,b\"", "\"b\""));
        assert!(!none_match("\"a,b\"", "\"a\""));
    }

    #[test]
    fn a_star_matches_any_file() {
        let etag = versioned_etag("\"5f2a\"", BUILD);
        assert!(none_match("*", &etag));
        assert!(none_match(" * ", &etag));
        assert!(none_match("\"old\", *", &etag));
    }

    #[test]
    fn not_modified_keeps_only_caching_headers() {
        for name in ["Cache-Control", "etag", "ETag", "Vary", "expires", "date", "last-modified", "content-location"] {
            assert!(kept_on_not_modified(name), "{name}");
        }
        for name in ["content-type", "content-length", "content-encoding", "content-security-policy", "set-cookie"] {
            assert!(!kept_on_not_modified(name), "{name}");
        }
    }
}
