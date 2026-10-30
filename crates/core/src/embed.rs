//! Embeds: a link to a known provider on a line of its own renders inline, the way Slab and Notion
//! show videos, Google Docs and design files. The frame URL is always rebuilt from the parsed link,
//! so a post can never point a frame anywhere outside [`FRAME_ORIGINS`].

use crate::util::html_escape;

/// Every origin an embed frame can load. The web app's `frame-src` policy lists the same origins.
pub const FRAME_ORIGINS: &[&str] = &[
    "https://www.youtube-nocookie.com",
    "https://player.vimeo.com",
    "https://www.loom.com",
    "https://docs.google.com",
    "https://drive.google.com",
    "https://www.figma.com",
    "https://airtable.com",
    "https://miro.com",
    "https://codepen.io",
];

/// The `frame-src` directive for the web app's Content-Security-Policy.
pub fn frame_src_directive() -> String {
    format!("frame-src {}", FRAME_ORIGINS.join(" "))
}

/// Providers, for documentation: shown to agents in the MCP instructions and tool descriptions.
pub const PROVIDERS: &str = "YouTube, Vimeo, Loom, Google Docs, Sheets, Slides, Forms and Drive, Figma, Airtable, Miro and CodePen";

#[derive(Debug, Clone, PartialEq)]
pub struct Embed {
    /// Shown above the frame, e.g. "Google Sheets".
    pub provider: &'static str,
    /// The frame's URL on one of [`FRAME_ORIGINS`].
    pub src: String,
    /// `video` frames keep a 16:9 shape; `document` frames are tall.
    pub shape: Shape,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Shape {
    Video,
    Document,
}

struct Url<'a> {
    host: String,
    /// Path segments without empty ones.
    segments: Vec<&'a str>,
    query: &'a str,
    fragment: &'a str,
}

fn parse(url: &str) -> Option<Url<'_>> {
    let rest = url.strip_prefix("https://").or_else(|| url.strip_prefix("http://"))?;
    let (rest, fragment) = rest.split_once('#').unwrap_or((rest, ""));
    let (rest, query) = rest.split_once('?').unwrap_or((rest, ""));
    let (host, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    if host.is_empty() || host.contains('@') || host.contains(':') {
        return None;
    }
    let host = host.to_ascii_lowercase();
    let host = host.strip_prefix("www.").or_else(|| host.strip_prefix("m.")).unwrap_or(&host).to_string();
    Some(Url { host, segments: path.split('/').filter(|s| !s.is_empty()).collect(), query, fragment })
}

fn query_param<'a>(query: &'a str, name: &str) -> Option<&'a str> {
    query.split('&').find_map(|kv| kv.split_once('=').filter(|(k, _)| *k == name).map(|(_, v)| v))
}

/// Ids are limited to the characters providers use, so nothing else reaches the frame URL.
fn id(s: &str, min: usize, max: usize) -> Option<&str> {
    let ok = (min..=max).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    ok.then_some(s)
}

fn digits(s: &str) -> Option<&str> {
    (!s.is_empty() && s.len() <= 15 && s.bytes().all(|b| b.is_ascii_digit())).then_some(s)
}

/// `90`, `90s`, `1m30s` or `1h2m3s` as seconds.
fn seconds(t: &str) -> Option<u64> {
    if let Ok(n) = t.parse::<u64>() {
        return Some(n);
    }
    let (mut total, mut n) = (0u64, String::new());
    for c in t.chars() {
        match c {
            '0'..='9' => n.push(c),
            'h' | 'm' | 's' => {
                let v: u64 = n.parse().ok()?;
                total += v * match c {
                    'h' => 3600,
                    'm' => 60,
                    _ => 1,
                };
                n.clear();
            }
            _ => return None,
        }
    }
    n.is_empty().then_some(total)
}

fn video(provider: &'static str, src: String) -> Option<Embed> {
    Some(Embed { provider, src, shape: Shape::Video })
}

fn document(provider: &'static str, src: String) -> Option<Embed> {
    Some(Embed { provider, src, shape: Shape::Document })
}

/// The embed for a link, when it points at a provider that can be embedded.
pub fn from_url(url: &str) -> Option<Embed> {
    let u = parse(url.trim())?;
    let seg = |i: usize| u.segments.get(i).copied().unwrap_or("");
    match u.host.as_str() {
        "youtube.com" | "youtube-nocookie.com" | "youtu.be" => {
            let vid = if u.host == "youtu.be" {
                seg(0)
            } else {
                match seg(0) {
                    "watch" => query_param(u.query, "v").unwrap_or(""),
                    "embed" | "shorts" | "live" | "v" => seg(1),
                    _ => "",
                }
            };
            let vid = id(vid, 11, 11)?;
            let start = query_param(u.query, "t").or_else(|| query_param(u.query, "start")).and_then(seconds);
            let mut src = format!("https://www.youtube-nocookie.com/embed/{vid}");
            if let Some(s) = start.filter(|s| *s > 0) {
                src.push_str(&format!("?start={s}"));
            }
            video("YouTube", src)
        }
        "vimeo.com" => {
            let vid = digits(seg(0))?;
            let hash = id(seg(1), 6, 20).or_else(|| query_param(u.query, "h").and_then(|h| id(h, 6, 20)));
            video("Vimeo", vimeo_src(vid, hash))
        }
        "player.vimeo.com" if seg(0) == "video" => {
            let vid = digits(seg(1))?;
            video("Vimeo", vimeo_src(vid, query_param(u.query, "h").and_then(|h| id(h, 6, 20))))
        }
        "loom.com" if matches!(seg(0), "share" | "embed") => {
            let vid = id(seg(1), 16, 64)?;
            video("Loom", format!("https://www.loom.com/embed/{vid}"))
        }
        "docs.google.com" => google_docs(&u),
        "drive.google.com" => {
            if seg(0) == "file" && seg(1) == "d" {
                let fid = id(seg(2), 10, 100)?;
                return document("Google Drive", format!("https://drive.google.com/file/d/{fid}/preview"));
            }
            if seg(0) == "drive" && seg(1) == "folders" {
                let fid = id(seg(2), 10, 100)?;
                return document("Google Drive", format!("https://drive.google.com/embeddedfolderview?id={fid}#list"));
            }
            if seg(0) == "open" {
                let fid = id(query_param(u.query, "id")?, 10, 100)?;
                return document("Google Drive", format!("https://drive.google.com/file/d/{fid}/preview"));
            }
            None
        }
        "figma.com" if matches!(seg(0), "file" | "design" | "proto" | "board" | "slides") => {
            let key = id(seg(1), 10, 64)?;
            let canonical = format!("https://www.figma.com/{}/{key}", seg(0));
            let node =
                query_param(u.query, "node-id").and_then(|n| id(&n.replace("%3A", "-").replace(':', "-"), 1, 40).map(str::to_string));
            let canonical = match node {
                Some(n) => format!("{canonical}?node-id={n}"),
                None => canonical,
            };
            document("Figma", format!("https://www.figma.com/embed?embed_host=dumbslab&url={}", urlencoding::encode(&canonical)))
        }
        "airtable.com" => {
            let segs: Vec<&str> = u.segments.iter().copied().filter(|s| *s != "embed").collect();
            let shared = segs.iter().position(|s| s.starts_with("shr"))?;
            let mut path = vec![];
            if shared == 1 && segs[0].starts_with("app") {
                path.push(id(segs[0], 10, 40)?);
            } else if shared != 0 {
                return None;
            }
            path.push(id(segs[shared], 10, 40)?);
            document("Airtable", format!("https://airtable.com/embed/{}", path.join("/")))
        }
        "miro.com" if seg(0) == "app" && matches!(seg(1), "board" | "live-embed") => {
            let board = id(seg(2).trim_end_matches('='), 6, 40)?;
            let suffix = if seg(2).ends_with('=') { "=" } else { "" };
            document("Miro", format!("https://miro.com/app/live-embed/{board}{suffix}/"))
        }
        "codepen.io" if matches!(seg(1), "pen" | "embed") => {
            let user = id(seg(0), 1, 40)?;
            let pen = id(seg(2), 3, 20)?;
            document("CodePen", format!("https://codepen.io/{user}/embed/{pen}?default-tab=result"))
        }
        _ => None,
    }
}

fn vimeo_src(vid: &str, hash: Option<&str>) -> String {
    match hash {
        Some(h) => format!("https://player.vimeo.com/video/{vid}?h={h}"),
        None => format!("https://player.vimeo.com/video/{vid}"),
    }
}

fn google_docs(u: &Url) -> Option<Embed> {
    // Drop the parts that only pick an account: `/a/example.com/` and `/u/1/`.
    let mut segs: Vec<&str> = u.segments.clone();
    if segs.first() == Some(&"a") && segs.len() > 2 {
        segs.drain(..2);
    }
    if let Some(i) = segs.iter().position(|s| *s == "u")
        && i <= 1
        && segs.get(i + 1).and_then(|s| digits(s)).is_some()
    {
        segs.drain(i..i + 2);
    }
    let seg = |i: usize| segs.get(i).copied().unwrap_or("");
    let (kind, d) = (seg(0), seg(1));
    if d != "d" {
        return None;
    }
    let published = seg(2) == "e";
    let doc = id(seg(2 + usize::from(published)), 10, 140)?;
    let gid = query_param(u.query, "gid").or_else(|| u.fragment.strip_prefix("gid=")).and_then(digits);
    match (kind, published) {
        ("document", false) => document("Google Docs", format!("https://docs.google.com/document/d/{doc}/preview")),
        ("document", true) => document("Google Docs", format!("https://docs.google.com/document/d/e/{doc}/pub?embedded=true")),
        ("spreadsheets", false) => {
            let src = format!("https://docs.google.com/spreadsheets/d/{doc}/preview");
            document(
                "Google Sheets",
                match gid {
                    Some(g) => format!("{src}#gid={g}"),
                    None => src,
                },
            )
        }
        ("spreadsheets", true) => {
            let src = format!("https://docs.google.com/spreadsheets/d/e/{doc}/pubhtml?widget=true&headers=false");
            document(
                "Google Sheets",
                match gid {
                    Some(g) => format!("{src}&gid={g}"),
                    None => src,
                },
            )
        }
        ("presentation", false) => video("Google Slides", format!("https://docs.google.com/presentation/d/{doc}/embed")),
        ("presentation", true) => video("Google Slides", format!("https://docs.google.com/presentation/d/e/{doc}/embed")),
        ("forms", true) => document("Google Forms", format!("https://docs.google.com/forms/d/e/{doc}/viewform?embedded=true")),
        _ => None,
    }
}

/// The trusted HTML for an embed. `href` is the link as written; `label` is its link text, if any.
pub fn html(embed: &Embed, href: &str, label: Option<&str>) -> String {
    let shape = match embed.shape {
        Shape::Video => "embed-video",
        Shape::Document => "embed-document",
    };
    let caption = label.map(str::trim).filter(|l| !l.is_empty() && *l != href).unwrap_or_else(|| display_url(href));
    format!(
        "<figure class=\"embed {shape}\"><div class=\"embed-frame\"><iframe src=\"{src}\" title=\"{title}\" loading=\"lazy\" \
         allow=\"autoplay; clipboard-write; encrypted-media; fullscreen; picture-in-picture\" allowfullscreen \
         referrerpolicy=\"strict-origin-when-cross-origin\" \
         sandbox=\"allow-scripts allow-same-origin allow-popups allow-popups-to-escape-sandbox allow-forms allow-presentation allow-storage-access-by-user-activation\">\
         </iframe></div><figcaption><span class=\"embed-provider\">{provider}</span>\
         <a href=\"{href}\" target=\"_blank\" rel=\"noopener noreferrer\">{caption}</a></figcaption></figure>",
        src = html_escape(&embed.src),
        title = html_escape(&format!("{}: {caption}", embed.provider)),
        provider = html_escape(embed.provider),
        href = html_escape(href),
        caption = html_escape(caption),
    )
}

fn display_url(url: &str) -> &str {
    let u = url.strip_prefix("https://").or_else(|| url.strip_prefix("http://")).unwrap_or(url);
    u.strip_prefix("www.").unwrap_or(u)
}

/// Finds `http(s)://` URLs in plain text, as byte ranges. A URL ends at whitespace or `<`, and
/// trailing punctuation that usually ends a sentence (or an unbalanced closing bracket) is left out.
pub fn find_urls(text: &str) -> Vec<std::ops::Range<usize>> {
    let mut out = vec![];
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < text.len() {
        let rest = &text[i..];
        let scheme = if rest.starts_with("https://") {
            8
        } else if rest.starts_with("http://") {
            7
        } else {
            i += rest.chars().next().map_or(1, char::len_utf8);
            continue;
        };
        let boundary = i == 0 || !(bytes[i - 1].is_ascii_alphanumeric() || matches!(bytes[i - 1], b'/' | b'@' | b'.'));
        let mut end = i + rest.find(|c: char| c.is_whitespace() || c == '<').unwrap_or(rest.len());
        loop {
            let tail = &text[i..end];
            let Some(last) = tail.chars().last() else { break };
            let unbalanced = match last {
                ')' => tail.matches(')').count() > tail.matches('(').count(),
                ']' => tail.matches(']').count() > tail.matches('[').count(),
                '.' | ',' | ':' | ';' | '!' | '?' | '\'' | '"' | '*' | '_' | '~' => true,
                _ => false,
            };
            if !unbalanced {
                break;
            }
            end -= last.len_utf8();
        }
        if boundary && end > i + scheme && text[i + scheme..end].contains(|c: char| c.is_alphanumeric()) {
            out.push(i..end);
            i = end;
        } else {
            i += scheme;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn src(url: &str) -> Option<String> {
        from_url(url).map(|e| e.src)
    }

    #[test]
    fn youtube() {
        let want = Some("https://www.youtube-nocookie.com/embed/9pasx0ghADM".to_string());
        assert_eq!(src("https://www.youtube.com/watch?v=9pasx0ghADM"), want);
        assert_eq!(src("https://youtu.be/9pasx0ghADM"), want);
        assert_eq!(src("youtube.com/embed/9pasx0ghADM?showinfo=0"), None, "needs a scheme");
        assert_eq!(src("https://youtube.com/embed/9pasx0ghADM?showinfo=0"), want);
        assert_eq!(src("https://youtu.be/9pasx0ghADM?t=1m30s").unwrap(), "https://www.youtube-nocookie.com/embed/9pasx0ghADM?start=90");
        assert_eq!(src("https://www.youtube.com/watch?v=short"), None);
        assert_eq!(src("https://www.youtube.com/@channel"), None);
    }

    #[test]
    fn vimeo_and_loom() {
        assert_eq!(src("https://vimeo.com/925549059/56f7392e1c").unwrap(), "https://player.vimeo.com/video/925549059?h=56f7392e1c");
        assert_eq!(src("https://player.vimeo.com/video/938358180").unwrap(), "https://player.vimeo.com/video/938358180");
        assert_eq!(
            src("https://player.vimeo.com/video/921279048?h=45200aa3df").unwrap(),
            "https://player.vimeo.com/video/921279048?h=45200aa3df"
        );
        assert_eq!(src("https://vimeo.com/user215996694"), None);
        assert_eq!(
            src("https://www.loom.com/share/47c11c0657834ed5a987ae2facf3fb9c?source=embed").unwrap(),
            "https://www.loom.com/embed/47c11c0657834ed5a987ae2facf3fb9c"
        );
    }

    #[test]
    fn google() {
        let sheet = "1Sescq7Qe50UoB9UNhjthBSN1YmSV7FkBn3uTv6yd0ak";
        let e = from_url(&format!("https://docs.google.com/spreadsheets/d/{sheet}/edit#gid=564963984")).unwrap();
        assert_eq!(e.provider, "Google Sheets");
        assert_eq!(e.src, format!("https://docs.google.com/spreadsheets/d/{sheet}/preview#gid=564963984"));
        assert_eq!(
            src(&format!("https://docs.google.com/spreadsheets/u/1/d/{sheet}/edit?usp=sharing")).unwrap(),
            format!("https://docs.google.com/spreadsheets/d/{sheet}/preview")
        );
        assert_eq!(
            src("https://docs.google.com/a/example.com/document/u/0/d/1abcDEFghiJKLmnop/edit").unwrap(),
            "https://docs.google.com/document/d/1abcDEFghiJKLmnop/preview"
        );
        assert_eq!(
            src("https://docs.google.com/document/d/1abcDEFghiJKLmnop/edit").unwrap(),
            "https://docs.google.com/document/d/1abcDEFghiJKLmnop/preview"
        );
        assert_eq!(
            src("https://docs.google.com/forms/d/e/1FAIpQLSabcdefghij/viewform").unwrap(),
            "https://docs.google.com/forms/d/e/1FAIpQLSabcdefghij/viewform?embedded=true"
        );
        assert_eq!(src("https://docs.google.com/forms/d/1abcdefghijk/edit"), None, "a form's editor can't be embedded");
        assert_eq!(
            src("https://drive.google.com/file/d/1abcdefghijkl/view?usp=sharing").unwrap(),
            "https://drive.google.com/file/d/1abcdefghijkl/preview"
        );
    }

    #[test]
    fn design_tools() {
        assert_eq!(
            src("https://airtable.com/appABCDEFGHIJ1234/shrABCDEFGHIJ1234").unwrap(),
            "https://airtable.com/embed/appABCDEFGHIJ1234/shrABCDEFGHIJ1234"
        );
        assert_eq!(src("https://airtable.com/appABCDEFGHIJ1234/tblABCDEFGHIJ1234"), None, "only shared views embed");
        assert_eq!(src("https://miro.com/app/board/uXjVabc123=/").unwrap(), "https://miro.com/app/live-embed/uXjVabc123=/");
        assert_eq!(src("https://codepen.io/someone/pen/abcXYZ").unwrap(), "https://codepen.io/someone/embed/abcXYZ?default-tab=result");
        assert!(
            src("https://www.figma.com/design/AbCdEfGhIjKlMn/Name?node-id=1-2")
                .unwrap()
                .starts_with("https://www.figma.com/embed?embed_host=dumbslab&url=")
        );
    }

    #[test]
    fn never_frames_other_origins() {
        for url in [
            "https://evil.com/watch?v=9pasx0ghADM",
            "https://youtube.com.evil.com/watch?v=9pasx0ghADM",
            "https://user@youtube.com/watch?v=9pasx0ghADM",
            "javascript:alert(1)",
            "https://www.youtube.com/watch?v=9pasx0ghAD\"",
        ] {
            assert_eq!(from_url(url), None, "{url}");
        }
        for url in ["https://youtu.be/9pasx0ghADM", "https://vimeo.com/1", "https://docs.google.com/document/d/1abcDEFghiJKLmnop/edit"] {
            let s = src(url).unwrap();
            assert!(FRAME_ORIGINS.iter().any(|o| s.starts_with(&format!("{o}/"))), "{s}");
        }
    }

    #[test]
    fn finds_urls_in_text() {
        let t = "See https://example.com/a_(b), then (https://x.io/y). Not foo://bar or ahttps://no.";
        let found: Vec<&str> = find_urls(t).into_iter().map(|r| &t[r]).collect();
        assert_eq!(found, vec!["https://example.com/a_(b)", "https://x.io/y"]);
        assert!(find_urls("https:// alone").is_empty());
    }
}
