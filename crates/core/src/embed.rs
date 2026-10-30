//! Embeds: a link to a known provider on a line of its own renders inline, the way most wikis
//! show videos, documents, designs and forms. The embed's URL is always rebuilt from the parsed
//! link, so a post can never point a frame anywhere outside [`FRAME_ORIGINS`] or play a video from
//! anywhere outside [`MEDIA_ORIGINS`].

use crate::util::html_escape;

/// Every origin an embed frame can load. The web app's `frame-src` policy lists the same origins.
/// `*.sharepoint.com` is one organization's SharePoint, like `contoso.sharepoint.com`.
pub const FRAME_ORIGINS: &[&str] = &[
    "https://www.youtube-nocookie.com",
    "https://player.vimeo.com",
    "https://www.loom.com",
    "https://docs.google.com",
    "https://drive.google.com",
    "https://www.figma.com",
    "https://airtable.com",
    "https://miro.com",
    "https://fast.wistia.net",
    "https://www.canva.com",
    "https://lucid.app",
    "https://viewer.diagrams.net",
    "https://app.ludus.one",
    "https://www.slideshare.net",
    "https://www.iorad.com",
    "https://view.monday.com",
    "https://app.mode.com",
    "https://app.smartsheet.com",
    "https://app.smartsheet.eu",
    "https://app.smartsheet.au",
    "https://publish.smartsheet.com",
    "https://publish.smartsheet.eu",
    "https://publish.smartsheet.au",
    "https://form.typeform.com",
    "https://form.eu.typeform.com",
    "https://form.jotform.com",
    "https://form.jotformeu.com",
    "https://hipaa.jotform.com",
    "https://codepen.io",
    "https://jsfiddle.net",
    "https://1drv.ms",
    "https://onedrive.live.com",
    "https://*.sharepoint.com",
];

/// Every origin an embedded video file can play from, besides the workspace itself. The web app's
/// `media-src` policy lists the same origins.
pub const MEDIA_ORIGINS: &[&str] = &["https://dl.dropboxusercontent.com"];

/// The `frame-src` directive for the web app's Content-Security-Policy.
pub fn frame_src_directive() -> String {
    format!("frame-src {}", FRAME_ORIGINS.join(" "))
}

/// The `media-src` directive for the web app's Content-Security-Policy.
pub fn media_src_directive() -> String {
    format!("media-src 'self' {}", MEDIA_ORIGINS.join(" "))
}

/// Providers, for documentation: shown to agents in the MCP instructions and tool descriptions.
pub const PROVIDERS: &str = "YouTube, Vimeo, Loom, Wistia, Google Docs, Sheets, Slides, Forms and Drive, \
                             Word, Excel and PowerPoint (OneDrive or SharePoint embed links), Figma, Canva, Miro, Lucid, Draw.io, \
                             Gliffy, Airtable, Smartsheet, monday.com, Mode, Typeform, Jotform, CodePen, JSFiddle, iorad, Ludus, \
                             SlideShare, Dropbox images and videos, and X posts (as a link card)";

#[derive(Debug, Clone, PartialEq)]
pub struct Embed {
    /// Shown above the frame, e.g. "Google Sheets".
    pub provider: &'static str,
    /// The frame's URL on one of [`FRAME_ORIGINS`]; for files, the file's URL; for cards, the link.
    pub src: String,
    /// How it shows: a frame, an image or video file, or a link card.
    pub shape: Shape,
    /// The frame's `sandbox` flags: only what the provider needs. Empty when there is no frame.
    pub sandbox: &'static str,
    /// The frame's `allow` list: browser features it may use. Empty for code and when there is no frame.
    pub allow: &'static str,
    /// For cards: who posted it, e.g. "@handle".
    pub author: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Shape {
    /// A frame that keeps a 16:9 shape.
    Video,
    /// A tall frame.
    Document,
    /// An image file, shown with `<img>`.
    Image,
    /// A video file on one of [`MEDIA_ORIGINS`], played with `<video>`.
    VideoFile,
    /// A link card with no frame, for posts that only embed with the provider's script.
    Card,
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

fn number(s: &str, min: usize, max: usize) -> Option<&str> {
    ((min..=max).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_digit())).then_some(s)
}

fn digits(s: &str) -> Option<&str> {
    number(s, 1, 15)
}

fn hex(s: &str, min: usize, max: usize) -> Option<&str> {
    ((min..=max).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_hexdigit())).then_some(s)
}

/// A UUID (`8-4-4-4-12` hex digits), lowercased.
fn uuid(s: &str) -> Option<String> {
    let parts: Vec<&str> = s.split('-').collect();
    let ok = parts.len() == 5 && parts.iter().zip([8, 4, 4, 4, 12]).all(|(p, n)| hex(p, n, n).is_some());
    ok.then(|| s.to_ascii_lowercase())
}

/// A file or folder name from a path: decoded, refused if it could leave its place in the path,
/// and encoded again.
fn segment(s: &str) -> Option<String> {
    let name = urlencoding::decode(s).ok()?;
    let ok = !matches!(&*name, "" | "." | "..") && name.len() <= 255 && !name.contains(|c: char| c == '/' || c == '\\' || c.is_control());
    ok.then(|| urlencoding::encode(&name).into_owned())
}

/// The one label in front of `base`, as in `acme` for `acme.typeform.com`.
fn subdomain<'a>(host: &'a str, base: &str) -> Option<&'a str> {
    let label = host.strip_suffix(base)?.strip_suffix('.')?;
    let ok = !label.is_empty() && label.len() <= 63 && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-');
    ok.then_some(label)
}

/// `host` is `base` or one subdomain of it.
fn on(host: &str, base: &str) -> bool {
    host == base || subdomain(host, base).is_some()
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

/// Players and viewers: scripts, fullscreen, and popups that stay sandboxed.
const PLAYER: &str = "allow-scripts allow-same-origin allow-popups allow-presentation";
/// Design tools: may also ask for their own cookies after a click, to show the viewer's access.
const APP: &str = "allow-scripts allow-same-origin allow-popups allow-presentation allow-storage-access-by-user-activation";
/// Google: signing in to see a private file needs forms and an unsandboxed sign-in popup.
const GOOGLE: &str = "allow-scripts allow-same-origin allow-popups allow-popups-to-escape-sandbox allow-forms allow-presentation \
                      allow-storage-access-by-user-activation";
/// Form builders: sending a response needs forms.
const FORM: &str = "allow-scripts allow-same-origin allow-popups allow-forms";
/// Microsoft Office: the viewer hands its inner frame an access token with a form, and signing in
/// or opening the file in Word, Excel or PowerPoint needs an unsandboxed tab.
const OFFICE: &str = "allow-scripts allow-same-origin allow-popups allow-popups-to-escape-sandbox allow-forms allow-presentation";
/// Code playgrounds run code anyone wrote, in an inner frame that inherits these flags: scripts,
/// and no popups, forms, dialogs or navigation. Both embed pages need their own origin: without it
/// JSFiddle's scripts don't load, and CodePen covers the result with a phishing warning.
const CODE: &str = "allow-scripts allow-same-origin";

/// What a frame may use: media playback, copying to the clipboard and fullscreen.
const FEATURES: &str = "autoplay; clipboard-write; encrypted-media; fullscreen; picture-in-picture";

fn frame(provider: &'static str, shape: Shape, sandbox: &'static str, src: String) -> Option<Embed> {
    Some(Embed { provider, src, shape, sandbox, allow: FEATURES, author: None })
}

fn video(provider: &'static str, src: String) -> Option<Embed> {
    frame(provider, Shape::Video, if provider.starts_with("Google") { GOOGLE } else { PLAYER }, src)
}

fn document(provider: &'static str, src: String) -> Option<Embed> {
    frame(provider, Shape::Document, if provider.starts_with("Google") { GOOGLE } else { APP }, src)
}

/// An image or video file: no frame, so no sandbox.
fn inline(provider: &'static str, shape: Shape, src: String) -> Option<Embed> {
    Some(Embed { provider, src, shape, sandbox: "", allow: "", author: None })
}

/// A code playground's frame, with no extra features.
fn code(provider: &'static str, src: String) -> Option<Embed> {
    Some(Embed { provider, src, shape: Shape::Document, sandbox: CODE, allow: "", author: None })
}

/// The embed for a link, when it points at a provider that can be embedded.
pub fn from_url(url: &str) -> Option<Embed> {
    let u = parse(url.trim())?;
    let seg = |i: usize| u.segments.get(i).copied().unwrap_or("");
    let host = u.host.as_str();
    match host {
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
        "canva.com" if seg(0) == "design" && matches!(seg(3), "view" | "watch") => {
            // A design's view link; Share > Embed and canva.com/_oembed frame it with `?embed`.
            let (design, token) = (id(seg(1), 8, 20)?, id(seg(2), 10, 40)?);
            video("Canva", format!("https://www.canva.com/design/{design}/{token}/view?embed"))
        }
        "lucid.app" | "lucidchart.com" => lucid(&u),
        "viewer.diagrams.net" | "app.diagrams.net" | "draw.io" => drawio(&u),
        "go.gliffy.com" if seg(0) == "go" && seg(1) == "share" => {
            // Gliffy embeds a shared diagram as an image of its latest published version.
            let diagram = if seg(2) == "image" { seg(3).strip_suffix(".png")? } else { seg(2) };
            inline("Gliffy", Shape::Image, format!("https://go.gliffy.com/go/share/image/{}.png", id(diagram, 10, 40)?))
        }
        // The frame Ludus's oEmbed (app.ludus.one/oembed) returns for a presentation.
        "app.ludus.one" if matches!(seg(1), "" | "embed") => video("Ludus", format!("https://app.ludus.one/{}", uuid(seg(0))?)),
        "iorad.com" if seg(0) == "player" => {
            // iorad's embed code frames the player with `src=iframe&oembed=1`.
            let tutorial = number(seg(1), 1, 12)?;
            let slug = if seg(2).is_empty() { String::new() } else { format!("/{}", id(seg(2), 1, 200)?) };
            frame("iorad", Shape::Document, PLAYER, format!("https://www.iorad.com/player/{tutorial}{slug}?src=iframe&oembed=1"))
        }
        "view.monday.com" => {
            // A board view shared publicly: view.monday.com/{view}; adding /embed/ shows it alone.
            let view = if seg(0) == "embed" { seg(1) } else { seg(0) };
            let (n, key) = view.split_once('-')?;
            let view = format!("{}-{}", number(n, 1, 20)?, hex(key, 32, 32)?);
            // Views outside the US need their region.
            let src = match query_param(u.query, "r").filter(|r| matches!(*r, "use1" | "euc1" | "apse2")) {
                Some(r) => format!("https://view.monday.com/embed/{view}?r={r}"),
                None => format!("https://view.monday.com/embed/{view}"),
            };
            frame("monday.com", Shape::Document, PLAYER, src)
        }
        "app.mode.com" | "modeanalytics.com" => mode(&u),
        "smartsheet.com" | "app.smartsheet.com" | "app.smartsheet.eu" | "app.smartsheet.au" if seg(0) == "b" && seg(1) == "publish" => {
            // A published sheet, report or dashboard.
            let token = hex(query_param(u.query, "EQBCT")?, 32, 32)?;
            let host = if host == "smartsheet.com" { "app.smartsheet.com" } else { host };
            frame("Smartsheet", Shape::Document, PLAYER, format!("https://{host}/b/publish?EQBCT={token}"))
        }
        "publish.smartsheet.com" | "publish.smartsheet.eu" | "publish.smartsheet.au" => {
            // The read-only HTML version of a published item.
            let token = hex(seg(0), 32, 32)?;
            frame("Smartsheet", Shape::Document, PLAYER, format!("https://{host}/{token}"))
        }
        "codepen.io" => codepen(&u),
        "jsfiddle.net" => jsfiddle(&u),
        "1drv.ms" | "onedrive.live.com" => onedrive(&u),
        "dropbox.com" | "dl.dropbox.com" | "dl.dropboxusercontent.com" => dropbox(&u),
        "x.com" | "twitter.com" | "mobile.x.com" | "mobile.twitter.com" => x_post(&u),
        "fast.wistia.net" => wistia(&u),
        h if subdomain(h, "wistia.com").is_some() => wistia(&u),
        h if on(h, "typeform.com") || subdomain(h, "eu.typeform.com").is_some() => typeform(&u),
        h if on(h, "jotform.com") || on(h, "jotformeu.com") => jotform(&u),
        h if on(h, "slideshare.net") => slideshare(&u),
        h if subdomain(h, "sharepoint.com").is_some() => sharepoint(&u),
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

/// {account}.wistia.com/medias/{id} (or /m/{id}), or the player itself,
/// fast.wistia.net/embed/iframe/{id} (https://docs.wistia.com/docs/construct-a-wistia-embed-code).
fn wistia(u: &Url) -> Option<Embed> {
    let seg = |i: usize| u.segments.get(i).copied().unwrap_or("");
    let media = match (seg(0), seg(1)) {
        ("medias" | "m", m) => m,
        ("embed", "iframe" | "medias") => seg(2),
        _ => return None,
    };
    video("Wistia", format!("https://fast.wistia.net/embed/iframe/{}", id(media, 6, 20)?))
}

const LUCID_OEMBED_CLIENT: &str = "2BiVMkDT0QXFJfn1y3Prdd3Tm3V1LiSCW1c9VkAi";

fn lucid(u: &Url) -> Option<Embed> {
    let seg = |i: usize| u.segments.get(i).copied().unwrap_or("");
    // A shared Lucidchart or Lucidspark document gets the frame Lucid's oEmbed (lucid.app/oembed)
    // returns for it. People without access see Lucid's sign-in.
    let shared = |doc: &str| {
        let doc = uuid(doc)?;
        document("Lucid", format!("https://lucid.app/embeds/link?document={doc}&clientId={LUCID_OEMBED_CLIENT}"))
    };
    match (seg(0), seg(1)) {
        ("lucidchart" | "lucidspark", doc) => shared(doc),
        ("documents", "edit" | "view") => shared(seg(2)),
        // An embed code the owner turned on.
        ("documents", "embedded" | "embeddedchart") => document("Lucid", format!("https://lucid.app/documents/embedded/{}", uuid(seg(2))?)),
        // Published as an image.
        ("publicSegments", "view") => {
            inline("Lucid", Shape::Image, format!("https://lucid.app/publicSegments/view/{}/image.png", uuid(seg(2))?))
        }
        _ => None,
    }
}

/// draw.io keeps the diagram in the link's hash: `#R` and the diagram itself, `#G` and a Google
/// Drive file, `#U` and a file's URL, or `#H` and a GitHub path
/// (https://www.drawio.com/docs/reference/supported-location-hash-properties). Only the viewer can
/// be framed, and it gets the diagram itself or a public file on Drive or GitHub, nothing else.
fn drawio(u: &Url) -> Option<Embed> {
    let (kind, rest) = (u.fragment.get(..1).unwrap_or(""), u.fragment.get(1..).unwrap_or(""));
    let file = match kind {
        "R" => {
            // Compressed (base64) or plain XML, URI-encoded. Encoded again, it can only be data.
            let ok = !rest.is_empty()
                && rest.len() <= 500_000
                && rest.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.!~*'()%+/=".contains(&b));
            let data = urlencoding::decode(rest).ok().filter(|_| ok)?;
            return frame("Draw.io", Shape::Document, PLAYER, format!("{DRAWIO_VIEWER}#R{}", urlencoding::encode(&data)));
        }
        "G" => drive_file(rest)?,
        "U" => diagram_file(&urlencoding::decode(rest).ok()?)?,
        "H" => github_file(urlencoding::decode(rest).ok()?.split('/'))?,
        // Older links: viewer.diagrams.net/?url={url}.
        _ => diagram_file(&urlencoding::decode(query_param(u.query, "url")?).ok()?)?,
    };
    frame("Draw.io", Shape::Document, PLAYER, format!("{DRAWIO_VIEWER}#U{}", urlencoding::encode(&file)))
}

const DRAWIO_VIEWER: &str = "https://viewer.diagrams.net/?highlight=0000ff&nav=1";

/// A diagram file the viewer may load: a Drive file shared with anyone, or a file on GitHub.
fn diagram_file(url: &str) -> Option<String> {
    let f = parse(url)?;
    match f.host.as_str() {
        "drive.google.com" if f.segments.first() == Some(&"uc") => drive_file(query_param(f.query, "id")?),
        "raw.githubusercontent.com" => github_file(f.segments.iter().copied()),
        _ => None,
    }
}

fn drive_file(file: &str) -> Option<String> {
    Some(format!("https://drive.google.com/uc?id={}&export=download", id(file, 20, 100)?))
}

/// The raw URL of a draw.io file on GitHub, from `{owner}/{repo}/{ref}/{path}`.
fn github_file<'a>(path: impl Iterator<Item = &'a str>) -> Option<String> {
    let parts = path.filter(|s| !s.is_empty()).map(segment).collect::<Option<Vec<_>>>()?;
    let name = parts.last()?.to_ascii_lowercase();
    let ok = (4..=20).contains(&parts.len()) && [".drawio", ".dio", ".xml", ".svg", ".png"].iter().any(|ext| name.ends_with(ext));
    ok.then(|| format!("https://raw.githubusercontent.com/{}", parts.join("/")))
}

/// A report, or one run of it: app.mode.com/{org}/reports/{report}[/runs/{run}], perhaps followed
/// by /embed, /viz/… or /details; editor links start with /editor. A chart can't be embedded alone,
/// so it shows its report (https://mode.com/help/articles/internal-embeds/).
fn mode(u: &Url) -> Option<Embed> {
    let segs = if u.segments.first() == Some(&"editor") { &u.segments[1..] } else { &u.segments[..] };
    let seg = |i: usize| segs.get(i).copied().unwrap_or("");
    if seg(1) != "reports" {
        return None;
    }
    let (org, report) = (id(seg(0), 1, 64)?, hex(seg(2), 8, 32)?);
    let run = if seg(3) == "runs" { format!("/runs/{}", hex(seg(4), 8, 32)?) } else { String::new() };
    frame("Mode", Shape::Document, PLAYER, format!("https://app.mode.com/{org}/reports/{report}{run}/embed"))
}

/// {account}.typeform.com/to/{form} or form.typeform.com/to/{form}; accounts in the EU are on
/// eu.typeform.com (https://www.typeform.com/developers/embed/custom-embed/).
fn typeform(u: &Url) -> Option<Embed> {
    if u.segments.first() != Some(&"to") {
        return None;
    }
    let form = id(u.segments.get(1)?, 4, 20)?;
    let eu = u.host == "eu.typeform.com" || subdomain(&u.host, "eu.typeform.com").is_some();
    let origin = if eu { "https://form.eu.typeform.com" } else { "https://form.typeform.com" };
    frame("Typeform", Shape::Document, FORM, format!("{origin}/to/{form}"))
}

/// form.jotform.com/{form}, jotform.com/form/{form} or {account}.jotform.com/{form}. Every Jotform
/// host serves every form, so links to the EU and HIPAA hosts keep them and others use form.jotform.com.
fn jotform(u: &Url) -> Option<Embed> {
    let origin = match u.host.as_str() {
        "hipaa.jotform.com" => "https://hipaa.jotform.com",
        "eu.jotform.com" => "https://form.jotformeu.com",
        h if on(h, "jotformeu.com") => "https://form.jotformeu.com",
        _ => "https://form.jotform.com",
    };
    let form = match u.segments.as_slice() {
        ["form", form] | [form] => number(form, 10, 20)?,
        _ => return None,
    };
    frame("Jotform", Shape::Document, FORM, format!("{origin}/{form}"))
}

/// slideshare.net/slideshow/{title}/{deck}, or the embed code's own embed_code/key/{key} or
/// embed_code/{deck}. Older slideshare.net/{user}/{title} links don't carry the deck's number.
fn slideshare(u: &Url) -> Option<Embed> {
    let seg = |i: usize| u.segments.get(i).copied().unwrap_or("");
    if seg(0) != "slideshow" {
        return None;
    }
    let deck = match (seg(1), seg(2)) {
        ("embed_code", "key") => format!("key/{}", id(seg(3), 6, 30)?),
        (_, deck) => number(deck, 1, 12)?.to_string(),
    };
    video("SlideShare", format!("https://www.slideshare.net/slideshow/embed_code/{deck}"))
}

/// codepen.io/{user}/pen/{pen}, or /full/, /details/ or /embed/; a team's pens are under
/// codepen.io/team/{team}/ (https://blog.codepen.io/documentation/embedded-pens/).
fn codepen(u: &Url) -> Option<Embed> {
    let seg = |i: usize| u.segments.get(i).copied().unwrap_or("");
    let (owner, at) = if seg(0) == "team" { (format!("team/{}", id(seg(1), 1, 40)?), 2) } else { (id(seg(0), 1, 40)?.to_string(), 1) };
    if !matches!(seg(at), "pen" | "full" | "details" | "embed") {
        return None;
    }
    let pen = if seg(at + 1) == "preview" { seg(at + 2) } else { seg(at + 1) };
    code("CodePen", format!("https://codepen.io/{owner}/embed/{}?default-tab=result", id(pen, 4, 20)?))
}

/// jsfiddle.net/{fiddle}/ or /{user}/{fiddle}/, either with a /{version}/; embeds add /embedded/
/// and their tabs (https://docs.jsfiddle.net/embedding-fiddles).
fn jsfiddle(u: &Url) -> Option<Embed> {
    let segs: Vec<&str> = u.segments.iter().copied().take_while(|s| !matches!(*s, "embedded" | "show")).collect();
    if segs.first().is_some_and(|s| matches!(*s, "user" | "api" | "boilerplate" | "_display")) {
        return None;
    }
    let version = |v| number(v, 1, 6);
    let (user, fiddle, v) = match segs[..] {
        [fiddle] => (None, fiddle, None),
        [fiddle, v] if version(v).is_some() => (None, fiddle, Some(v)),
        [user, fiddle] => (Some(user), fiddle, None),
        [user, fiddle, v] => (Some(user), fiddle, Some(version(v)?)),
        _ => return None,
    };
    let user = match user {
        Some(user) => format!("{}/", id(user, 1, 40)?),
        None => String::new(),
    };
    let (fiddle, v) = (id(fiddle, 4, 16)?, v.map(|v| format!("/{v}")).unwrap_or_default());
    code("JSFiddle", format!("https://jsfiddle.net/{user}{fiddle}{v}/embedded/result,js,html,css/"))
}

/// Microsoft lets Word, Excel and PowerPoint files be embedded.
fn office(kind: &str) -> Option<(&'static str, Shape)> {
    match kind {
        "w" | "doc" | "docx" | "docm" => Some(("Word", Shape::Document)),
        "x" | "xls" | "xlsx" | "xlsm" | "xlsb" => Some(("Excel", Shape::Document)),
        "p" | "ppt" | "pptx" | "pptm" | "ppsx" => Some(("PowerPoint", Shape::Video)),
        _ => None,
    }
}

/// OneDrive's embed code (Share > Embed) frames 1drv.ms/{w|x|p}/c/{cid}/{token}?em=2, or, in older
/// codes, onedrive.live.com/embed?resid=…&authkey=…. A share link (`?e=…`) carries a different
/// token that Microsoft won't show in a frame, so it stays a link.
fn onedrive(u: &Url) -> Option<Embed> {
    let seg = |i: usize| u.segments.get(i).copied().unwrap_or("");
    if u.host == "1drv.ms" {
        let (provider, shape) = office(seg(0))?;
        if seg(1) != "c" || query_param(u.query, "em") != Some("2") {
            return None;
        }
        let (cid, token) = (hex(seg(2), 15, 16)?, id(seg(3), 20, 80)?);
        return frame(provider, shape, OFFICE, format!("https://1drv.ms/{}/c/{cid}/{token}?em=2", seg(0)));
    }
    if seg(0) != "embed" {
        return None;
    }
    let resid = query_param(u.query, "resid")?.replace("%21", "!");
    let (cid, item) = resid.split_once('!')?;
    let item = match item.strip_prefix('s') {
        Some(guid) => format!("s{}", hex(guid, 32, 32)?),
        None => number(item, 1, 12)?.to_string(),
    };
    let key = query_param(u.query, "authkey")?.replace("%21", "!");
    let (bang, key) = match key.strip_prefix('!') {
        Some(k) => ("%21", k),
        None => ("", key.as_str()),
    };
    let (cid, key) = (hex(cid, 15, 16)?, id(key, 10, 40)?);
    frame(
        "OneDrive",
        Shape::Document,
        OFFICE,
        format!("https://onedrive.live.com/embed?cid={cid}&resid={cid}%21{item}&authkey={bang}{key}&em=2"),
    )
}

/// Word, Excel and PowerPoint for the web embed a file on SharePoint (or OneDrive for work) as
/// {tenant}.sharepoint.com/{site}/_layouts/15/Doc.aspx?sourcedoc={id}&action=embedview. It shows only
/// where the browser sends SharePoint its cookies inside a frame, like Chrome and Edge.
fn sharepoint(u: &Url) -> Option<Embed> {
    let tenant = subdomain(&u.host, "sharepoint.com")?;
    let mut segs = u.segments.as_slice();
    // Links from the address bar can start with /:w:/r/.
    if let [kind, "r", rest @ ..] = segs
        && kind.starts_with(':')
        && kind.ends_with(':')
    {
        segs = rest;
    }
    let [site @ .., "_layouts", "15", page] = segs else { return None };
    if !page.eq_ignore_ascii_case("doc.aspx")
        || site.len() > 3
        || site.first().is_some_and(|s| !matches!(*s, "sites" | "teams" | "personal"))
    {
        return None;
    }
    let site = site.iter().map(|s| segment(s).map(|s| format!("/{s}"))).collect::<Option<String>>()?;
    let doc = query_param(u.query, "sourcedoc")?.replace("%7B", "").replace("%7b", "").replace("%7D", "").replace("%7d", "");
    let doc = uuid(doc.trim_start_matches('{').trim_end_matches('}'))?;
    let (provider, shape) = match query_param(u.query, "file") {
        Some(name) => office(&name.rsplit_once('.')?.1.to_ascii_lowercase())?,
        None => ("SharePoint", Shape::Document),
    };
    frame(
        provider,
        shape,
        OFFICE,
        format!("https://{tenant}.sharepoint.com{site}/_layouts/15/Doc.aspx?sourcedoc=%7B{doc}%7D&action=embedview"),
    )
}

/// Dropbox shares a file as dropbox.com/scl/fi/{id}/{name}?rlkey={key} (before 2023,
/// dropbox.com/s/{id}/{name}). Images and videos show straight from dl.dropboxusercontent.com, where
/// `raw=1` redirects to (https://help.dropbox.com/share/force-download).
fn dropbox(u: &Url) -> Option<Embed> {
    let (item, name, key) = match u.segments.as_slice() {
        ["scl", "fi", item, name] => (format!("scl/fi/{}", id(item, 8, 40)?), *name, Some(id(query_param(u.query, "rlkey")?, 10, 64)?)),
        ["s", item, name] => (format!("s/{}", id(item, 8, 40)?), *name, None),
        _ => return None,
    };
    let name = segment(name)?;
    let shape = match name.rsplit_once('.')?.1.to_ascii_lowercase().as_str() {
        "png" | "jpg" | "jpeg" | "gif" | "webp" | "avif" | "svg" => Shape::Image,
        "mp4" | "m4v" | "mov" | "webm" => Shape::VideoFile,
        _ => return None,
    };
    let src = format!("https://dl.dropboxusercontent.com/{item}/{name}");
    inline(
        "Dropbox",
        shape,
        match key {
            Some(k) => format!("{src}?rlkey={k}"),
            None => src,
        },
    )
}

/// X embeds a post only with its own script, which the web app's policy doesn't allow, so a post
/// shows as a link card: x.com/{handle}/status/{id}, also on twitter.com, /statuses/, and
/// /i/web/status/{id} when the link doesn't name the author.
fn x_post(u: &Url) -> Option<Embed> {
    let (handle, post) = match u.segments.as_slice() {
        ["i", "web", "status", post, ..] | ["i", "status", post, ..] => (None, *post),
        [handle, "status" | "statuses", post, ..] => (Some(*handle), *post),
        _ => return None,
    };
    let post = number(post, 1, 20)?;
    let handle = match handle {
        Some(h) => Some(h).filter(|h| (1..=15).contains(&h.len()) && h.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'))?,
        None => "i",
    };
    Some(Embed {
        provider: "X",
        src: format!("https://x.com/{handle}/status/{post}"),
        shape: Shape::Card,
        sandbox: "",
        allow: "",
        author: (handle != "i").then(|| format!("@{handle}")),
    })
}

/// The trusted HTML for an embed. `href` is the link as written; `label` is its link text, if any.
pub fn html(embed: &Embed, href: &str, label: Option<&str>) -> String {
    let label = label.map(str::trim).filter(|l| !l.is_empty() && *l != href);
    let caption = label.unwrap_or_else(|| display_url(href));
    let src = html_escape(&embed.src);
    let (shape, body) = match embed.shape {
        Shape::Video | Shape::Document => (
            if embed.shape == Shape::Video { "embed-video" } else { "embed-document" },
            format!(
                "<div class=\"embed-frame\"><iframe src=\"{src}\" title=\"{title}\" loading=\"lazy\" {allow}\
                 referrerpolicy=\"strict-origin-when-cross-origin\" \
                 sandbox=\"{sandbox}\">\
                 </iframe></div>",
                sandbox = embed.sandbox,
                title = html_escape(&format!("{}: {caption}", embed.provider)),
                allow = match embed.allow {
                    "" => String::new(),
                    allow if allow.contains("fullscreen") => format!("allow=\"{allow}\" allowfullscreen "),
                    allow => format!("allow=\"{allow}\" "),
                },
            ),
        ),
        Shape::Image => (
            "embed-image",
            format!(
                "<div class=\"embed-file\"><img src=\"{src}\" alt=\"{alt}\" loading=\"lazy\" referrerpolicy=\"no-referrer\"></div>",
                alt = html_escape(caption)
            ),
        ),
        Shape::VideoFile => (
            "embed-video-file",
            format!("<div class=\"embed-file\"><video src=\"{src}\" controls preload=\"metadata\" playsinline></video></div>"),
        ),
        Shape::Card => return card(embed, label),
    };
    format!(
        "<figure class=\"embed {shape}\">{body}<figcaption><span class=\"embed-provider\">{provider}</span>\
         <a href=\"{href}\" target=\"_blank\" rel=\"noopener noreferrer\">{caption}</a></figcaption></figure>",
        provider = html_escape(embed.provider),
        href = html_escape(href),
        caption = html_escape(caption),
    )
}

/// A link card: who posted it, and where.
fn card(embed: &Embed, label: Option<&str>) -> String {
    let post = format!("Post on {}", embed.provider);
    let (title, meta) = match (label, embed.author.as_deref()) {
        (Some(l), Some(a)) => (l.to_string(), format!("{a} · {post}")),
        (Some(l), None) => (l.to_string(), post),
        (None, Some(a)) => (a.to_string(), post),
        (None, None) => (post, display_url(&embed.src).to_string()),
    };
    format!(
        "<figure class=\"embed embed-card\"><a href=\"{src}\" target=\"_blank\" rel=\"noopener noreferrer\">\
         <span class=\"embed-card-title\">{title}</span><span class=\"embed-card-meta\">{meta}</span></a></figure>",
        src = html_escape(&embed.src),
        title = html_escape(&title),
        meta = html_escape(&meta),
    )
}

fn display_url(url: &str) -> &str {
    let u = url.strip_prefix("https://").or_else(|| url.strip_prefix("http://")).unwrap_or(url);
    u.strip_prefix("www.").unwrap_or(u)
}

/// Finds `http(s)://` URLs in plain text, as byte ranges. A URL ends at whitespace or `<`, and
/// trailing punctuation that usually ends a sentence (or an unbalanced closing bracket) is left out.
/// Runs in linear time: every byte is scanned a bounded number of times.
pub fn find_urls(text: &str) -> Vec<std::ops::Range<usize>> {
    let mut out = vec![];
    let bytes = text.as_bytes();
    let mut i = 0;
    while let Some(off) = text[i..].find("http") {
        let start = i + off;
        let rest = &text[start..];
        let scheme = if rest.starts_with("https://") {
            8
        } else if rest.starts_with("http://") {
            7
        } else {
            i = start + 4;
            continue;
        };
        let scan_end = start + rest.find(|c: char| c.is_whitespace() || c == '<').unwrap_or(rest.len());
        i = scan_end.max(start + scheme);
        let boundary = start == 0 || !(bytes[start - 1].is_ascii_alphanumeric() || matches!(bytes[start - 1], b'/' | b'@' | b'.'));
        if !boundary {
            continue;
        }
        let candidate = &bytes[start..scan_end];
        let count = |b: u8| candidate.iter().filter(|&&c| c == b).count();
        let (open_paren, open_bracket) = (count(b'('), count(b'['));
        let (mut close_paren, mut close_bracket) = (count(b')'), count(b']'));
        let mut end = scan_end;
        while end > start + scheme {
            let last = bytes[end - 1];
            let trim = match last {
                b')' => close_paren > open_paren,
                b']' => close_bracket > open_bracket,
                b'.' | b',' | b':' | b';' | b'!' | b'?' | b'\'' | b'"' | b'*' | b'_' | b'~' => true,
                _ => false,
            };
            if !trim {
                break;
            }
            match last {
                b')' => close_paren -= 1,
                b']' => close_bracket -= 1,
                _ => {}
            }
            end -= 1;
        }
        if text[start + scheme..end].contains(|c: char| c.is_alphanumeric()) {
            out.push(start..end);
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
        assert!(
            src("https://www.figma.com/design/AbCdEfGhIjKlMn/Name?node-id=1-2")
                .unwrap()
                .starts_with("https://www.figma.com/embed?embed_host=dumbslab&url=")
        );
    }

    /// Checks each link's frame URL, and that each of `bad` is not embedded.
    fn check(cases: &[(&str, &str)], bad: &[&str]) {
        for (url, want) in cases {
            assert_eq!(src(url).as_deref(), Some(*want), "{url}");
        }
        for url in bad {
            assert_eq!(from_url(url), None, "{url}");
        }
    }

    #[test]
    fn canva() {
        let want = "https://www.canva.com/design/DAGhbGUMnnI/gZyl0pFu9hrdUYmKXUictg/view?embed";
        check(
            &[
                (
                    "https://www.canva.com/design/DAGhbGUMnnI/gZyl0pFu9hrdUYmKXUictg/view?utm_content=DAGhbGUMnnI&utm_campaign=designshare&utm_medium=link",
                    want,
                ),
                ("https://www.canva.com/design/DAGhbGUMnnI/gZyl0pFu9hrdUYmKXUictg/view?embed", want),
                ("https://canva.com/design/DAGhbGUMnnI/gZyl0pFu9hrdUYmKXUictg/watch", want),
            ],
            &[
                "https://www.canva.com/design/DAGhbGUMnnI/gZyl0pFu9hrdUYmKXUictg/edit",
                "https://www.canva.com/design/DAGhbGUMnnI/view",
                "https://www.canva.com.evil.test/design/DAGhbGUMnnI/gZyl0pFu9hrdUYmKXUictg/view",
                "https://www.canva.com/design/../gZyl0pFu9hrdUYmKXUictg/view",
                "https://www.canva.com/design/DAGhbGUMnnI/gZyl0pFu9hrdUYmKX\"ictg/view",
            ],
        );
        assert_eq!(from_url(want).unwrap().shape, Shape::Video);
    }

    #[test]
    fn code_playgrounds() {
        check(
            &[
                ("https://codepen.io/chriscoyier/pen/gfdDu", "https://codepen.io/chriscoyier/embed/gfdDu?default-tab=result"),
                ("https://codepen.io/chriscoyier/full/gfdDu?editors=1100", "https://codepen.io/chriscoyier/embed/gfdDu?default-tab=result"),
                ("https://codepen.io/chriscoyier/embed/preview/gfdDu", "https://codepen.io/chriscoyier/embed/gfdDu?default-tab=result"),
                ("https://codepen.io/team/codepen/pen/PNaGbb", "https://codepen.io/team/codepen/embed/PNaGbb?default-tab=result"),
                ("https://jsfiddle.net/zalun/uc2oyafr/", "https://jsfiddle.net/zalun/uc2oyafr/embedded/result,js,html,css/"),
                ("https://jsfiddle.net/uc2oyafr/7/", "https://jsfiddle.net/uc2oyafr/7/embedded/result,js,html,css/"),
                ("https://jsfiddle.net/zalun/uc2oyafr/7/show", "https://jsfiddle.net/zalun/uc2oyafr/7/embedded/result,js,html,css/"),
                (
                    "https://jsfiddle.net/zalun/NmudS/embedded/js,result/dark/",
                    "https://jsfiddle.net/zalun/NmudS/embedded/result,js,html,css/",
                ),
            ],
            &[
                "https://codepen.io/chriscoyier",
                "https://codepen.io/chriscoyier/pen/",
                "https://codepen.io/chris%22coyier/pen/gfdDu",
                "https://codepen.io.evil.test/chriscoyier/pen/gfdDu",
                "https://cdpn.io/chriscoyier/debug/gfdDu",
                "https://jsfiddle.net/",
                "https://jsfiddle.net/user/dashboard/",
                "https://jsfiddle.net/zalun/uc2oyafr/latest/",
                "https://jsfiddle.net/a/b/c/d/",
                "https://jsfiddle.net/zalun/..%2F..%2Fx/",
            ],
        );
    }

    #[test]
    fn forms() {
        check(
            &[
                ("https://form.typeform.com/to/moe6aa", "https://form.typeform.com/to/moe6aa"),
                ("https://acme.typeform.com/to/u6nXL7?typeform-source=www.acme.test", "https://form.typeform.com/to/u6nXL7"),
                ("https://acme.eu.typeform.com/to/u6nXL7", "https://form.eu.typeform.com/to/u6nXL7"),
                ("https://form.jotform.com/203106355569153", "https://form.jotform.com/203106355569153"),
                ("https://www.jotform.com/form/203106355569153", "https://form.jotform.com/203106355569153"),
                ("https://acme.jotform.com/203106355569153?nojump", "https://form.jotform.com/203106355569153"),
                ("https://eu.jotform.com/203106355569153", "https://form.jotformeu.com/203106355569153"),
                ("https://form.jotformeu.com/72844967018366", "https://form.jotformeu.com/72844967018366"),
                ("https://hipaa.jotform.com/203106355569153", "https://hipaa.jotform.com/203106355569153"),
            ],
            &[
                "https://typeform.com.evil.test/to/moe6aa",
                "https://evil-typeform.com/to/moe6aa",
                "https://acme.typeform.com/forms/moe6aa",
                "https://acme.typeform.com/to/moe'6aa",
                "https://a.b.typeform.com/to/moe6aa",
                "https://www.jotform.com/build/203106355569153",
                "https://form.jotform.com/12345",
                "https://form.jotform.com/203106355569153/../1",
                "https://jotform.com.evil.test/203106355569153",
            ],
        );
        let form = from_url("https://form.jotform.com/203106355569153").unwrap();
        assert!(form.sandbox.contains("allow-forms") && !form.sandbox.contains("escape-sandbox"), "{}", form.sandbox);
    }

    #[test]
    fn players_and_slides() {
        let deck = "3c5f8e07-4d86-4c0d-8356-a352f74b9c0a";
        check(
            &[
                ("https://acme.wistia.com/medias/26sk4lmiix", "https://fast.wistia.net/embed/iframe/26sk4lmiix"),
                ("https://acme.wistia.com/m/26sk4lmiix", "https://fast.wistia.net/embed/iframe/26sk4lmiix"),
                ("https://fast.wistia.net/embed/iframe/26sk4lmiix?videoFoam=true", "https://fast.wistia.net/embed/iframe/26sk4lmiix"),
                (
                    "https://www.iorad.com/player/1622550/How-to-Embed-an-iorad-Tutorial",
                    "https://www.iorad.com/player/1622550/How-to-Embed-an-iorad-Tutorial?src=iframe&oembed=1",
                ),
                (
                    "https://www.iorad.com/player/2535539/Finalsite?iframeHash=trysteps-1",
                    "https://www.iorad.com/player/2535539/Finalsite?src=iframe&oembed=1",
                ),
                ("https://iorad.com/player/2535539", "https://www.iorad.com/player/2535539?src=iframe&oembed=1"),
                (&format!("https://app.ludus.one/{deck}"), &format!("https://app.ludus.one/{deck}")),
                (&format!("https://app.ludus.one/{}/embed#3", deck.to_uppercase()), &format!("https://app.ludus.one/{deck}")),
                (
                    "https://www.slideshare.net/slideshow/the-hubspot-culture-code-creating-a-company-we-love/17415022",
                    "https://www.slideshare.net/slideshow/embed_code/17415022",
                ),
                ("https://de.slideshare.net/slideshow/culture-code/17415022", "https://www.slideshare.net/slideshow/embed_code/17415022"),
                (
                    "https://www.slideshare.net/slideshow/embed_code/key/cTHCJwQlGHBTRS",
                    "https://www.slideshare.net/slideshow/embed_code/key/cTHCJwQlGHBTRS",
                ),
            ],
            &[
                "https://wistia.com.evil.test/medias/26sk4lmiix",
                "https://acme.wistia.com/medias/26sk\"4lmiix",
                "https://acme.wistia.com/s/abc",
                "https://ior.ad/HfY",
                "https://www.iorad.com/player/abc/Title",
                "https://www.iorad.com/player/1622550/Title'onload",
                "https://app.ludus.one/not-a-deck",
                "https://app.ludus.one/3c5f8e07-4d86-4c0d-8356-a352f74b9c0a/edit",
                "https://www.slideshare.net/hubspot/the-hubspot-culture-code-creating-a-company-we-love",
                "https://slideshare.net.evil.test/slideshow/culture-code/17415022",
            ],
        );
    }

    #[test]
    fn diagrams() {
        let doc = "2eec7ba2-0517-498e-aeae-fe33b89c26c0";
        let shared = format!("https://lucid.app/embeds/link?document={doc}&clientId={LUCID_OEMBED_CLIENT}");
        let drive = "https://viewer.diagrams.net/?highlight=0000ff&nav=1#Uhttps%3A%2F%2Fdrive.google.com%2Fuc%3Fid%3D1AbCdEfGhIjKlMnOpQrStUvWxYz012345%26export%3Ddownload";
        let github = "https://viewer.diagrams.net/?highlight=0000ff&nav=1#Uhttps%3A%2F%2Fraw.githubusercontent.com%2Fjgraph%2Fdrawio-diagrams%2Fmaster%2Fdiagrams%2Fschema.xml";
        check(
            &[
                (
                    &format!("https://lucid.app/lucidchart/{doc}/edit?invitationId=inv_d6d0301f-1a2d-41be-aa62-abd66d372e15&page=0_0#"),
                    &shared,
                ),
                (&format!("https://lucid.app/lucidspark/{doc}/view"), &shared),
                (&format!("https://www.lucidchart.com/documents/edit/{doc}/0"), &shared),
                (
                    &format!("https://lucid.app/documents/embedded/{doc}?invitationId=inv_x"),
                    &format!("https://lucid.app/documents/embedded/{doc}"),
                ),
                (&format!("https://lucid.app/documents/embeddedchart/{doc}"), &format!("https://lucid.app/documents/embedded/{doc}")),
                (
                    &format!("https://lucid.app/publicSegments/view/{doc}/image.png"),
                    &format!("https://lucid.app/publicSegments/view/{doc}/image.png"),
                ),
                (
                    "https://viewer.diagrams.net/?tags=%7B%7D&highlight=0000ff&edit=_blank&layers=1&nav=1&title=Flow.drawio#R7Vhtb9o%2BnqT%2Fx=",
                    "https://viewer.diagrams.net/?highlight=0000ff&nav=1#R7Vhtb9o%2BnqT%2Fx%3D",
                ),
                (
                    "https://app.diagrams.net/?lightbox=1#R%3Cmxfile%3E%3Cdiagram%20name%3D'A'%3E%3C%2Fdiagram%3E%3C%2Fmxfile%3E",
                    "https://viewer.diagrams.net/?highlight=0000ff&nav=1#R%3Cmxfile%3E%3Cdiagram%20name%3D%27A%27%3E%3C%2Fdiagram%3E%3C%2Fmxfile%3E",
                ),
                ("https://app.diagrams.net/#G1AbCdEfGhIjKlMnOpQrStUvWxYz012345", drive),
                (
                    "https://viewer.diagrams.net/?highlight=0000ff#Uhttps%3A%2F%2Fdrive.google.com%2Fuc%3Fid%3D1AbCdEfGhIjKlMnOpQrStUvWxYz012345%26export%3Ddownload",
                    drive,
                ),
                (
                    "https://viewer.diagrams.net/#Uhttps%3A%2F%2Fraw.githubusercontent.com%2Fjgraph%2Fdrawio-diagrams%2Fmaster%2Fdiagrams%2Fschema.xml",
                    github,
                ),
                ("https://app.diagrams.net/#Hjgraph%2Fdrawio-diagrams%2Fmaster%2Fdiagrams%2Fschema.xml", github),
                (
                    "https://viewer.diagrams.net/?url=https://raw.githubusercontent.com/jgraph/drawio-diagrams/master/diagrams/schema.xml",
                    github,
                ),
                ("https://go.gliffy.com/go/share/sefi7eidb36b5qqafxcb", "https://go.gliffy.com/go/share/image/sefi7eidb36b5qqafxcb.png"),
                (
                    "https://go.gliffy.com/go/share/image/sefi7eidb36b5qqafxcb.png?utm_medium=live-embed&utm_source=custom",
                    "https://go.gliffy.com/go/share/image/sefi7eidb36b5qqafxcb.png",
                ),
            ],
            &[
                "https://lucid.app/lucidchart/not-a-uuid/edit",
                "https://lucid.app/lucidchart/2eec7ba2-0517-498e-aeae-fe33b89c26c0x/edit",
                "https://lucid.app.evil.test/lucidchart/2eec7ba2-0517-498e-aeae-fe33b89c26c0/edit",
                "https://lucid.app/lucidchart/invitations/accept/inv_d6d0301f-1a2d-41be-aa62-abd66d372e15",
                "https://app.diagrams.net/",
                "https://viewer.diagrams.net.evil.test/#R7Vhtb9o",
                "https://viewer.diagrams.net/#R<script>",
                "https://viewer.diagrams.net/#R7Vh\"tb9o",
                "https://viewer.diagrams.net/#Pplugin",
                "https://viewer.diagrams.net/#Uhttps%3A%2F%2Fevil.test%2Fx.drawio",
                "https://viewer.diagrams.net/#Ujavascript%3Aalert(1)",
                "https://viewer.diagrams.net/#Uhttps%3A%2F%2Fraw.githubusercontent.com%2Fa%2Fb%2Fmain%2F..%2Fx.drawio",
                "https://viewer.diagrams.net/#Uhttps%3A%2F%2Fraw.githubusercontent.com%2Fa%2Fb%2Fmain%2Fpage.html",
                "https://viewer.diagrams.net/?url=https://evil.test/x.drawio",
                "https://www.gliffy.com/go/publish/6229079",
                "https://go.gliffy.com/go/share/image/sefi7eidb36b5qqafxcb.svg",
            ],
        );
        assert_eq!(from_url(&format!("https://lucid.app/publicSegments/view/{doc}/image.png")).unwrap().shape, Shape::Image);
    }

    #[test]
    fn boards_and_reports() {
        let view = "9424258790-ddec9d2cad0c8c255c08eac935803f29";
        let token = "0123456789abcdef0123456789ABCDEF";
        check(
            &[
                (&format!("https://view.monday.com/{view}?r=use1"), &format!("https://view.monday.com/embed/{view}?r=use1")),
                (
                    &format!("https://view.monday.com/embed/{view}?r=euc1&is_sharable_link=true"),
                    &format!("https://view.monday.com/embed/{view}?r=euc1"),
                ),
                (&format!("https://view.monday.com/{view}?r=evil.test"), &format!("https://view.monday.com/embed/{view}")),
                ("https://app.mode.com/acme/reports/0d0d0bbe1e2e", "https://app.mode.com/acme/reports/0d0d0bbe1e2e/embed"),
                (
                    "https://app.mode.com/acme/reports/0d0d0bbe1e2e/runs/a1b2c3d4e5f6",
                    "https://app.mode.com/acme/reports/0d0d0bbe1e2e/runs/a1b2c3d4e5f6/embed",
                ),
                (
                    "https://app.mode.com/acme/reports/0d0d0bbe1e2e/viz/7c8d9e0f1a2b/explore",
                    "https://app.mode.com/acme/reports/0d0d0bbe1e2e/embed",
                ),
                (
                    "https://app.mode.com/editor/acme/reports/0d0d0bbe1e2e/queries/3e4f",
                    "https://app.mode.com/acme/reports/0d0d0bbe1e2e/embed",
                ),
                (
                    "https://modeanalytics.com/acme/reports/0d0d0bbe1e2e/embed?access_key=k&signature=s",
                    "https://app.mode.com/acme/reports/0d0d0bbe1e2e/embed",
                ),
                (
                    &format!("https://app.smartsheet.com/b/publish?EQBCT={token}"),
                    &format!("https://app.smartsheet.com/b/publish?EQBCT={token}"),
                ),
                (
                    &format!("https://www.smartsheet.com/b/publish?EQBCT={token}"),
                    &format!("https://app.smartsheet.com/b/publish?EQBCT={token}"),
                ),
                (
                    &format!("https://app.smartsheet.eu/b/publish?EQBCT={token}"),
                    &format!("https://app.smartsheet.eu/b/publish?EQBCT={token}"),
                ),
                (&format!("https://publish.smartsheet.com/{token}"), &format!("https://publish.smartsheet.com/{token}")),
            ],
            &[
                "https://view.monday.com/9424258790",
                "https://view.monday.com/9424258790-notahash",
                "https://acme.monday.com/boards/9424258790",
                "https://app.mode.com/acme/spaces/0d0d0bbe1e2e",
                "https://app.mode.com/acme/reports/0d0d0bbe1e2x",
                "https://app.mode.com/acme/reports/0d0d0bbe1e2e/runs/zz",
                "https://app.mode.com/ac\"me/reports/0d0d0bbe1e2e",
                "https://app.smartsheet.com/b/publish?EQBCT=0123",
                "https://app.smartsheet.com/sheets/0123456789abcdef0123456789abcdef",
                "https://smartsheet.com.evil.test/b/publish?EQBCT=0123456789abcdef0123456789abcdef",
                "https://publish.smartsheet.com/../0123456789abcdef0123456789abcdef",
            ],
        );
    }

    #[test]
    fn microsoft_office() {
        let guid = "6f3c2a1e-0b4d-4c8e-9f2a-1b2c3d4e5f60";
        let site_doc =
            format!("https://contoso.sharepoint.com/sites/Marketing/_layouts/15/Doc.aspx?sourcedoc=%7B{guid}%7D&action=embedview");
        check(
            &[
                (
                    "https://1drv.ms/x/c/501d3fb1eb052268/IQTl3fqe7dWBR4yXmtb3biJLAcQq4RHDzlDdwrPC2xXOtUw?em=2&wdAllowInteractivity=False",
                    "https://1drv.ms/x/c/501d3fb1eb052268/IQTl3fqe7dWBR4yXmtb3biJLAcQq4RHDzlDdwrPC2xXOtUw?em=2",
                ),
                (
                    "https://onedrive.live.com/embed?cid=ACE6B54B52992AC1&resid=ACE6B54B52992AC1%21123&authkey=%21AHkzP_TJ3aA4NsU&em=2",
                    "https://onedrive.live.com/embed?cid=ACE6B54B52992AC1&resid=ACE6B54B52992AC1%21123&authkey=%21AHkzP_TJ3aA4NsU&em=2",
                ),
                (
                    &format!("https://contoso.sharepoint.com/sites/Marketing/_layouts/15/Doc.aspx?sourcedoc={{{guid}}}&action=embedview"),
                    &site_doc,
                ),
                (
                    &format!(
                        "https://contoso.sharepoint.com/:w:/r/sites/Marketing/_layouts/15/Doc.aspx?sourcedoc=%7B{}%7D&file=Plan.docx&action=default&mobileredirect=true",
                        guid.to_uppercase()
                    ),
                    &site_doc,
                ),
                (
                    &format!(
                        "https://contoso-my.sharepoint.com/personal/jo_contoso_com/_layouts/15/Doc.aspx?sourcedoc=%7B{guid}%7D&file=Deck.pptx"
                    ),
                    &format!(
                        "https://contoso-my.sharepoint.com/personal/jo_contoso_com/_layouts/15/Doc.aspx?sourcedoc=%7B{guid}%7D&action=embedview"
                    ),
                ),
            ],
            &[
                "https://1drv.ms/w/c/501d3fb1eb052268/EXyzEXyzEXyzEXyzEXyzEXyzEXyzEXyz?e=AbC123",
                "https://1drv.ms/b/c/501d3fb1eb052268/IQTl3fqe7dWBR4yXmtb3biJLAcQq4RHDzlDdwrPC2xXOtUw?em=2",
                "https://1drv.ms/x/s!AsEpmlJLteaskCR5Mz_0yd2gODbF?e=abc",
                "https://onedrive.live.com/embed?resid=ACE6B54B52992AC1%21123&em=2",
                "https://onedrive.live.com/embed?resid=ACE6B54B52992AC1%21123&authkey=%21AHk%22zP&em=2",
                "https://contoso.sharepoint.com.evil.test/sites/x/_layouts/15/Doc.aspx?sourcedoc=%7B6f3c2a1e-0b4d-4c8e-9f2a-1b2c3d4e5f60%7D",
                "https://a.b.sharepoint.com/sites/x/_layouts/15/Doc.aspx?sourcedoc=%7B6f3c2a1e-0b4d-4c8e-9f2a-1b2c3d4e5f60%7D",
                "https://contoso.sharepoint.com/sites/x/_layouts/15/Doc.aspx?sourcedoc=not-a-guid",
                "https://contoso.sharepoint.com/sites/x/_layouts/15/Doc.aspx?sourcedoc=%7B6f3c2a1e-0b4d-4c8e-9f2a-1b2c3d4e5f60%7D&file=Report.pdf",
                "https://contoso.sharepoint.com/sites/%2E%2E/_layouts/15/Doc.aspx?sourcedoc=%7B6f3c2a1e-0b4d-4c8e-9f2a-1b2c3d4e5f60%7D",
                "https://contoso.sharepoint.com/evil/_layouts/15/Doc.aspx?sourcedoc=%7B6f3c2a1e-0b4d-4c8e-9f2a-1b2c3d4e5f60%7D",
                "https://contoso.sharepoint.com/:w:/s/Marketing/EXyzEXyzEXyzEXyzEXyz?e=abc",
            ],
        );
        let excel = from_url("https://1drv.ms/x/c/501d3fb1eb052268/IQTl3fqe7dWBR4yXmtb3biJLAcQq4RHDzlDdwrPC2xXOtUw?em=2").unwrap();
        assert_eq!((excel.provider, excel.shape), ("Excel", Shape::Document));
        let slides = from_url(&format!(
            "https://contoso-my.sharepoint.com/personal/jo_contoso_com/_layouts/15/Doc.aspx?sourcedoc=%7B{guid}%7D&file=Deck.pptx"
        ))
        .unwrap();
        assert_eq!((slides.provider, slides.shape), ("PowerPoint", Shape::Video));
        assert!(excel.sandbox.contains("allow-forms"), "the Office viewer needs forms");
    }

    #[test]
    fn dropbox_files() {
        let photo = from_url(
            "https://www.dropbox.com/scl/fi/abc123def456ghi789jkl/Team%20photo.JPG?rlkey=a1b2c3d4e5f6g7h8i9j0k1l2m&st=abcd1234&dl=0",
        )
        .unwrap();
        assert_eq!(
            (photo.src.as_str(), photo.shape, photo.sandbox),
            (
                "https://dl.dropboxusercontent.com/scl/fi/abc123def456ghi789jkl/Team%20photo.JPG?rlkey=a1b2c3d4e5f6g7h8i9j0k1l2m",
                Shape::Image,
                ""
            )
        );
        let clip = from_url("https://www.dropbox.com/s/abc123def456ghi/demo.mp4?dl=0").unwrap();
        assert_eq!((clip.src.as_str(), clip.shape), ("https://dl.dropboxusercontent.com/s/abc123def456ghi/demo.mp4", Shape::VideoFile));
        check(
            &[(
                "https://dl.dropboxusercontent.com/scl/fi/abc123def456ghi789jkl/clip.webm?rlkey=a1b2c3d4e5f6g7h8i9j0k1l2m&raw=1",
                "https://dl.dropboxusercontent.com/scl/fi/abc123def456ghi789jkl/clip.webm?rlkey=a1b2c3d4e5f6g7h8i9j0k1l2m",
            )],
            &[
                "https://www.dropbox.com/scl/fi/abc123def456ghi789jkl/photo.png?dl=0",
                "https://www.dropbox.com/scl/fi/abc123def456ghi789jkl/notes.pdf?rlkey=a1b2c3d4e5f6g7h8i9j0k1l2m",
                "https://www.dropbox.com/scl/fo/abc123def456ghi789jkl/folder?rlkey=a1b2c3d4e5f6g7h8i9j0k1l2m",
                "https://www.dropbox.com/s/abc123def456ghi/..%2F..%2Fx.png",
                "https://www.dropbox.com/s/abc123def456ghi/%2E%2E",
                "https://www.dropbox.com/s/abc123def456ghi/photo.png/extra",
                "https://www.dropbox.com/s/abc\"123def456ghi/photo.png",
                "https://dropbox.com.evil.test/s/abc123def456ghi/demo.mp4",
            ],
        );
        let html = html(&clip, "https://www.dropbox.com/s/abc123def456ghi/demo.mp4?dl=0", None);
        assert!(html.contains("<video src=\"https://dl.dropboxusercontent.com/s/abc123def456ghi/demo.mp4\" controls"), "{html}");
        assert!(!html.contains("<iframe"), "{html}");
        let quoted = from_url("https://www.dropbox.com/s/abc123def456ghi/%22onerror%3D.png").unwrap();
        assert_eq!(quoted.src, "https://dl.dropboxusercontent.com/s/abc123def456ghi/%22onerror%3D.png");
    }

    #[test]
    fn x_posts_are_link_cards() {
        let post = from_url("https://twitter.com/XDevelopers/status/1861122352421351432?s=20&t=abc").unwrap();
        assert_eq!(
            (post.src.as_str(), post.shape, post.sandbox, post.author.as_deref()),
            ("https://x.com/XDevelopers/status/1861122352421351432", Shape::Card, "", Some("@XDevelopers"))
        );
        check(
            &[
                ("https://x.com/jack/status/20", "https://x.com/jack/status/20"),
                ("https://mobile.twitter.com/jack/statuses/20/photo/1", "https://x.com/jack/status/20"),
                ("https://x.com/i/web/status/1861122352421351432", "https://x.com/i/status/1861122352421351432"),
            ],
            &[
                "https://x.com/jack",
                "https://x.com/jack/status/abc",
                "https://x.com/bad-handle/status/20",
                "https://x.com/averyveryverylonghandle/status/20",
                "https://x.com.evil.test/jack/status/20",
                "https://t.co/abc123",
            ],
        );
        let html = html(&post, "https://twitter.com/XDevelopers/status/1861122352421351432", None);
        assert!(!html.contains("<iframe") && !html.contains("<script"), "{html}");
        assert!(
            html.contains("<span class=\"embed-card-title\">@XDevelopers</span><span class=\"embed-card-meta\">Post on X</span>"),
            "{html}"
        );
        let labeled = super::html(&post, "https://x.com/XDevelopers/status/1861122352421351432", Some("Launch <news>"));
        assert!(labeled.contains(">Launch &lt;news&gt;</span><span class=\"embed-card-meta\">@XDevelopers · Post on X<"), "{labeled}");
    }

    /// Whether `src` is on one of `origins`; `https://*.example.com` matches one subdomain.
    fn on_origin(src: &str, origins: &[&str]) -> bool {
        origins.iter().any(|o| match o.strip_prefix("https://*.") {
            Some(base) => {
                src.strip_prefix("https://").and_then(|rest| rest.split_once('/')).is_some_and(|(host, _)| subdomain(host, base).is_some())
            }
            None => src.starts_with(&format!("{o}/")),
        })
    }

    #[test]
    fn never_frames_other_origins() {
        for url in [
            "https://evil.com/watch?v=9pasx0ghADM",
            "https://youtube.com.evil.com/watch?v=9pasx0ghADM",
            "https://user@youtube.com/watch?v=9pasx0ghADM",
            "javascript:alert(1)",
            "javascript:https://www.canva.com/design/DAGhbGUMnnI/gZyl0pFu9hrdUYmKXUictg/view",
            "https://www.youtube.com/watch?v=9pasx0ghAD\"",
            "https://www.canva.com:443@evil.test/design/DAGhbGUMnnI/gZyl0pFu9hrdUYmKXUictg/view",
        ] {
            assert_eq!(from_url(url), None, "{url}");
        }
        // One link per frame origin and file host.
        let links = [
            "https://youtu.be/9pasx0ghADM",
            "https://vimeo.com/1",
            "https://www.loom.com/share/47c11c0657834ed5a987ae2facf3fb9c",
            "https://docs.google.com/document/d/1abcDEFghiJKLmnop/edit",
            "https://drive.google.com/file/d/1abcdefghijkl/view",
            "https://www.figma.com/design/AbCdEfGhIjKlMn/Name",
            "https://airtable.com/appABCDEFGHIJ1234/shrABCDEFGHIJ1234",
            "https://miro.com/app/board/uXjVabc123=/",
            "https://acme.wistia.com/medias/26sk4lmiix",
            "https://www.canva.com/design/DAGhbGUMnnI/gZyl0pFu9hrdUYmKXUictg/view",
            "https://lucid.app/lucidchart/2eec7ba2-0517-498e-aeae-fe33b89c26c0/edit",
            "https://viewer.diagrams.net/#R7Vhtb9o",
            "https://app.ludus.one/3c5f8e07-4d86-4c0d-8356-a352f74b9c0a",
            "https://www.slideshare.net/slideshow/culture-code/17415022",
            "https://www.iorad.com/player/1622550/How-to-Embed-an-iorad-Tutorial",
            "https://view.monday.com/9424258790-ddec9d2cad0c8c255c08eac935803f29",
            "https://app.mode.com/acme/reports/0d0d0bbe1e2e",
            "https://app.smartsheet.com/b/publish?EQBCT=0123456789abcdef0123456789abcdef",
            "https://app.smartsheet.eu/b/publish?EQBCT=0123456789abcdef0123456789abcdef",
            "https://app.smartsheet.au/b/publish?EQBCT=0123456789abcdef0123456789abcdef",
            "https://publish.smartsheet.com/0123456789abcdef0123456789abcdef",
            "https://publish.smartsheet.eu/0123456789abcdef0123456789abcdef",
            "https://publish.smartsheet.au/0123456789abcdef0123456789abcdef",
            "https://acme.typeform.com/to/u6nXL7",
            "https://acme.eu.typeform.com/to/u6nXL7",
            "https://form.jotform.com/203106355569153",
            "https://eu.jotform.com/203106355569153",
            "https://hipaa.jotform.com/203106355569153",
            "https://codepen.io/chriscoyier/pen/gfdDu",
            "https://jsfiddle.net/zalun/uc2oyafr/",
            "https://1drv.ms/p/c/501d3fb1eb052268/IQTl3fqe7dWBR4yXmtb3biJLAcQq4RHDzlDdwrPC2xXOtUw?em=2",
            "https://onedrive.live.com/embed?resid=ACE6B54B52992AC1%21123&authkey=%21AHkzP_TJ3aA4NsU&em=2",
            "https://contoso.sharepoint.com/_layouts/15/Doc.aspx?sourcedoc=%7B6f3c2a1e-0b4d-4c8e-9f2a-1b2c3d4e5f60%7D",
            "https://lucid.app/publicSegments/view/2eec7ba2-0517-498e-aeae-fe33b89c26c0/image.png",
            "https://go.gliffy.com/go/share/sefi7eidb36b5qqafxcb",
            "https://www.dropbox.com/scl/fi/abc123def456ghi789jkl/photo.png?rlkey=a1b2c3d4e5f6g7h8i9j0k1l2m",
            "https://www.dropbox.com/s/abc123def456ghi/demo.mp4",
            "https://x.com/jack/status/20",
        ];
        let mut framed = vec![];
        for url in links {
            let e = from_url(url).unwrap_or_else(|| panic!("{url}"));
            let s = &e.src;
            assert!(!s.contains(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '<' | '>' | '\\')), "{s}");
            match e.shape {
                Shape::Video | Shape::Document => {
                    assert!(on_origin(s, FRAME_ORIGINS), "{s}");
                    assert!(!e.sandbox.is_empty() && !e.sandbox.contains("allow-top-navigation"), "{}", e.sandbox);
                    framed.push(s.clone());
                }
                Shape::VideoFile => assert!(on_origin(s, MEDIA_ORIGINS), "{s}"),
                // `img-src` allows any https: image.
                Shape::Image => assert!(s.starts_with("https://"), "{s}"),
                Shape::Card => assert!(s.starts_with("https://x.com/"), "{s}"),
            }
            if e.shape != Shape::Video && e.shape != Shape::Document {
                assert!(e.sandbox.is_empty() && !html(&e, url, None).contains("<iframe"), "{url}");
            }
        }
        for origin in FRAME_ORIGINS {
            assert!(framed.iter().any(|s| on_origin(s, &[*origin])), "nothing frames {origin}");
        }
    }

    #[test]
    fn frames_get_only_the_permissions_they_need() {
        let yt = from_url("https://youtu.be/9pasx0ghADM").unwrap().sandbox;
        assert!(!yt.contains("allow-forms") && !yt.contains("escape-sandbox"), "{yt}");
        let figma = from_url("https://www.figma.com/design/AbCdEfGhIjKlMn/Name").unwrap().sandbox;
        assert!(!figma.contains("allow-forms") && !figma.contains("escape-sandbox"), "{figma}");
        let sheet = from_url("https://docs.google.com/spreadsheets/d/1Sescq7Qe50UoB9UNhjthBSN1YmSV7FkBn3uTv6yd0ak/edit").unwrap();
        assert!(sheet.sandbox.contains("allow-forms"), "Google sign-in needs forms");
        assert!(html(&sheet, "https://docs.google.com/x", None).contains(&format!("sandbox=\"{}\"", sheet.sandbox)));
        for url in [
            "https://www.canva.com/design/DAGhbGUMnnI/gZyl0pFu9hrdUYmKXUictg/view",
            "https://viewer.diagrams.net/#R7Vhtb9o",
            "https://app.mode.com/acme/reports/0d0d0bbe1e2e",
        ] {
            let sandbox = from_url(url).unwrap().sandbox;
            assert_eq!(sandbox, PLAYER, "{url}");
        }
        let video = html(&from_url("https://youtu.be/9pasx0ghADM").unwrap(), "https://youtu.be/9pasx0ghADM", None);
        assert!(video.contains(&format!("loading=\"lazy\" allow=\"{FEATURES}\" allowfullscreen referrerpolicy=")), "{video}");
    }

    #[test]
    fn code_playgrounds_get_only_scripts_and_their_own_origin() {
        for url in ["https://codepen.io/chriscoyier/pen/gfdDu", "https://jsfiddle.net/zalun/uc2oyafr/"] {
            let e = from_url(url).unwrap();
            assert_eq!((e.sandbox, e.allow), ("allow-scripts allow-same-origin", ""), "{url}");
            let html = html(&e, url, None);
            assert!(
                html.contains(
                    "loading=\"lazy\" referrerpolicy=\"strict-origin-when-cross-origin\" sandbox=\"allow-scripts allow-same-origin\">"
                ),
                "{html}"
            );
            for denied in ["allow=", "allowfullscreen", "clipboard", "popups", "forms", "modals", "top-navigation"] {
                assert!(!html.contains(denied), "{denied}: {html}");
            }
        }
    }

    #[test]
    fn finds_urls_in_text() {
        let t = "See https://example.com/a_(b), then (https://x.io/y). Not foo://bar or ahttps://no.";
        let found: Vec<&str> = find_urls(t).into_iter().map(|r| &t[r]).collect();
        assert_eq!(found, vec!["https://example.com/a_(b)", "https://x.io/y"]);
        assert!(find_urls("https:// alone").is_empty());
        // Long runs that are not URLs, or that only look like the start of one, stay fast.
        let long = format!("x{}", "https://(".repeat(50_000));
        let t = std::time::Instant::now();
        let _ = find_urls(&long);
        assert!(t.elapsed().as_secs() < 2);
    }
}
