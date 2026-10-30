//! Markdown is the canonical post format. This module renders it to sanitized HTML and extracts
//! structure (outline, sections, mentions, links to other posts) used across the app.

use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

use pulldown_cmark::{BlockQuoteKind, CowStr, Event, HeadingLevel, LinkType, Options, Parser, Tag, TagEnd};
use schemars::JsonSchema;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::embed;
use crate::util::{html_escape, slugify};

fn options() -> Options {
    Options::ENABLE_TABLES
        | Options::ENABLE_FOOTNOTES
        | Options::ENABLE_STRIKETHROUGH
        | Options::ENABLE_TASKLISTS
        | Options::ENABLE_HEADING_ATTRIBUTES
        // `> [!NOTE]` style callouts.
        | Options::ENABLE_GFM
}

/// Parses Markdown with adjacent text runs merged, so a URL or `@handle` is never split.
fn parse(md: &str) -> Vec<Event<'_>> {
    let mut out: Vec<Event> = vec![];
    let mut text: Option<String> = None;
    for ev in Parser::new_ext(md, options()) {
        match ev {
            Event::Text(t) => match text.as_mut() {
                Some(buf) => buf.push_str(&t),
                None => text = Some(t.into_string()),
            },
            other => {
                if let Some(buf) = text.take() {
                    out.push(Event::Text(CowStr::from(buf)));
                }
                out.push(other);
            }
        }
    }
    if let Some(buf) = text {
        out.push(Event::Text(CowStr::from(buf)));
    }
    out
}

fn sanitizer() -> &'static ammonia::Builder<'static> {
    static CLEANER: OnceLock<ammonia::Builder<'static>> = OnceLock::new();
    CLEANER.get_or_init(|| {
        let mut b = ammonia::Builder::default();
        b.add_tags(["input", "mark", "details", "summary"]);
        b.add_tag_attributes("input", ["type", "checked", "disabled"]);
        b.add_generic_attributes(["id", "class"]);
        b
    })
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq)]
pub struct Heading {
    pub level: u8,
    pub text: String,
    /// The HTML anchor id, usable as `#id` in links.
    pub anchor: String,
}

fn level_num(l: HeadingLevel) -> u8 {
    l as u8
}

/// Headings in document order with unique anchors.
pub fn outline(md: &str) -> Vec<Heading> {
    let mut out = vec![];
    let mut seen: HashMap<String, usize> = HashMap::new();
    let mut current: Option<(u8, String)> = None;
    for ev in Parser::new_ext(md, options()) {
        match ev {
            Event::Start(Tag::Heading { level, .. }) => current = Some((level_num(level), String::new())),
            Event::Text(t) | Event::Code(t) => {
                if let Some((_, text)) = current.as_mut() {
                    text.push_str(&t);
                }
            }
            Event::End(TagEnd::Heading(_)) => {
                if let Some((level, text)) = current.take() {
                    let anchor = unique_anchor(&mut seen, &text);
                    out.push(Heading { level, text: text.trim().to_string(), anchor });
                }
            }
            _ => {}
        }
    }
    out
}

fn unique_anchor(seen: &mut HashMap<String, usize>, text: &str) -> String {
    let base = slugify(text);
    let n = seen.entry(base.clone()).or_insert(0);
    *n += 1;
    if *n == 1 { base } else { format!("{base}-{}", *n - 1) }
}

/// Splits text into plain runs and `@handle` mentions.
fn split_mentions(text: &str) -> Vec<(bool, String)> {
    let mut parts = vec![];
    let chars: Vec<char> = text.chars().collect();
    let mut buf = String::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        let prev_ok = i == 0 || !(chars[i - 1].is_alphanumeric() || chars[i - 1] == '_');
        if c == '@' && prev_ok {
            let mut j = i + 1;
            while j < chars.len() && (chars[j].is_ascii_alphanumeric() || matches!(chars[j], '_' | '.' | '-')) {
                j += 1;
            }
            // Trailing punctuation belongs to the sentence, not the handle.
            while j > i + 1 && matches!(chars[j - 1], '.' | '-') {
                j -= 1;
            }
            if j > i + 1 {
                if !buf.is_empty() {
                    parts.push((false, std::mem::take(&mut buf)));
                }
                parts.push((true, chars[i + 1..j].iter().collect::<String>().to_lowercase()));
                i = j;
                continue;
            }
        }
        buf.push(c);
        i += 1;
    }
    if !buf.is_empty() {
        parts.push((false, buf));
    }
    parts
}

/// The link a paragraph consists of, when it holds nothing else: a bare URL, `<url>` or
/// `[text](url)`. Returns the URL and the link text.
fn lone_link(events: &[Event]) -> Option<(String, Option<String>)> {
    let content: Vec<&Event> = events.iter().filter(|e| !matches!(e, Event::Text(t) if t.trim().is_empty())).collect();
    match content.as_slice() {
        [Event::Text(t)] => {
            let t = t.trim();
            let found = embed::find_urls(t);
            (found.len() == 1 && found[0] == (0..t.len())).then(|| (t.to_string(), None))
        }
        [Event::Start(Tag::Link { dest_url, .. }), inner @ .., Event::End(TagEnd::Link)] => {
            let mut label = String::new();
            for e in inner {
                match e {
                    Event::Text(t) | Event::Code(t) => label.push_str(t),
                    Event::SoftBreak => label.push(' '),
                    _ => return None,
                }
            }
            Some((dest_url.to_string(), Some(label)))
        }
        _ => None,
    }
}

fn callout_title(kind: BlockQuoteKind) -> (&'static str, &'static str) {
    match kind {
        BlockQuoteKind::Note => ("note", "Note"),
        BlockQuoteKind::Tip => ("tip", "Tip"),
        BlockQuoteKind::Important => ("important", "Important"),
        BlockQuoteKind::Warning => ("warning", "Warning"),
        BlockQuoteKind::Caution => ("caution", "Caution"),
    }
}

/// Splits plain text into runs, links for bare URLs, and `@mention` links.
fn push_text<'a>(out: &mut Vec<Event<'a>>, text: &str) {
    let push_plain = |out: &mut Vec<Event<'a>>, s: &str| {
        if s.is_empty() {
            return;
        }
        if !s.contains('@') {
            out.push(Event::Text(CowStr::from(s.to_string())));
            return;
        }
        for (is_mention, part) in split_mentions(s) {
            if is_mention {
                out.push(Event::InlineHtml(CowStr::from(format!("<a class=\"mention\" href=\"/u/{0}\">@{0}</a>", html_escape(&part)))));
            } else {
                out.push(Event::Text(CowStr::from(part)));
            }
        }
    };
    let mut last = 0;
    for r in embed::find_urls(text) {
        push_plain(out, &text[last..r.start]);
        let url = text[r.clone()].to_string();
        out.push(Event::Start(Tag::Link {
            link_type: LinkType::Autolink,
            dest_url: CowStr::from(url.clone()),
            title: CowStr::from(""),
            id: CowStr::from(""),
        }));
        out.push(Event::Text(CowStr::from(url)));
        out.push(Event::End(TagEnd::Link));
        last = r.end;
    }
    push_plain(out, &text[last..]);
}

/// Renders Markdown to safe HTML: heading anchors, linked `@mentions` and URLs, callouts, embeds
/// (a provider link on its own line, see [`embed`]), sanitized output.
pub fn render(md: &str) -> String {
    let mut seen: HashMap<String, usize> = HashMap::new();
    let events = parse(md);

    // Embeds are cut out before sanitizing and put back after, so the sanitizer never has to allow
    // frames. Each one's placeholder carries a digest of the document, which the document itself
    // can't contain.
    let nonce = hex::encode(&Sha256::digest(md.as_bytes())[..8]);
    let mut embeds: Vec<String> = vec![];

    let mut out_events: Vec<Event> = Vec::with_capacity(events.len());
    let mut i = 0;
    let mut in_code_or_link = 0usize;
    while i < events.len() {
        match &events[i] {
            Event::Start(Tag::Paragraph) if in_code_or_link == 0 => {
                let end = events[i..].iter().position(|e| matches!(e, Event::End(TagEnd::Paragraph))).map(|p| i + p);
                let found = end.and_then(|end| {
                    let (url, label) = lone_link(&events[i + 1..end])?;
                    let e = embed::from_url(&url)?;
                    Some((end, embed::html(&e, &url, label.as_deref())))
                });
                if let Some((end, html)) = found {
                    out_events.push(Event::Html(CowStr::from(format!("<div id=\"ds-embed-{nonce}-{}\"></div>\n", embeds.len()))));
                    embeds.push(html);
                    i = end + 1;
                    continue;
                }
                out_events.push(events[i].clone());
            }
            Event::Start(Tag::BlockQuote(Some(kind))) => {
                let (class, title) = callout_title(*kind);
                out_events.push(Event::Html(CowStr::from(format!(
                    "<blockquote class=\"md-callout md-callout-{class}\">\n<p class=\"md-callout-title\">{title}</p>\n"
                ))));
            }
            Event::Start(Tag::Heading { level, id, classes, attrs }) => {
                let mut text = String::new();
                let mut j = i + 1;
                while j < events.len() {
                    match &events[j] {
                        Event::End(TagEnd::Heading(_)) => break,
                        Event::Text(t) | Event::Code(t) => text.push_str(t),
                        _ => {}
                    }
                    j += 1;
                }
                let anchor = match id {
                    Some(explicit) => explicit.to_string(),
                    None => unique_anchor(&mut seen, &text),
                };
                out_events.push(Event::Start(Tag::Heading {
                    level: *level,
                    id: Some(CowStr::from(anchor)),
                    classes: classes.clone(),
                    attrs: attrs.clone(),
                }));
            }
            Event::Start(t @ (Tag::CodeBlock(_) | Tag::Link { .. } | Tag::Image { .. })) => {
                in_code_or_link += 1;
                out_events.push(Event::Start(t.clone()));
            }
            Event::End(t @ (TagEnd::CodeBlock | TagEnd::Link | TagEnd::Image)) => {
                in_code_or_link = in_code_or_link.saturating_sub(1);
                out_events.push(Event::End(*t));
            }
            Event::Text(t) if in_code_or_link == 0 => push_text(&mut out_events, t),
            other => out_events.push(other.clone()),
        }
        i += 1;
    }

    let mut html = String::with_capacity(md.len() * 2);
    pulldown_cmark::html::push_html(&mut html, out_events.into_iter());
    let html = sanitizer().clean(&html).to_string();
    if embeds.is_empty() {
        return html;
    }
    // One pass, so many embeds don't make rendering quadratic.
    let marker = format!("<div id=\"ds-embed-{nonce}-");
    let mut out = String::with_capacity(html.len() + embeds.iter().map(String::len).sum::<usize>());
    let mut rest = html.as_str();
    while let Some(p) = rest.find(&marker) {
        out.push_str(&rest[..p]);
        let after = &rest[p + marker.len()..];
        let digits = after.bytes().take_while(u8::is_ascii_digit).count();
        let embed = after[..digits].parse::<usize>().ok().and_then(|n| embeds.get(n));
        match (embed, after[digits..].strip_prefix("\"></div>")) {
            (Some(embed), Some(tail)) => {
                out.push_str(embed);
                rest = tail;
            }
            _ => {
                out.push_str(&marker);
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

/// Plain text, for search and excerpts.
pub fn plain_text(md: &str) -> String {
    let mut out = String::with_capacity(md.len());
    for ev in Parser::new_ext(md, options()) {
        match ev {
            Event::Text(t) | Event::Code(t) => out.push_str(&t),
            Event::SoftBreak | Event::HardBreak => out.push(' '),
            Event::End(TagEnd::Paragraph | TagEnd::Heading(_) | TagEnd::Item | TagEnd::CodeBlock | TagEnd::TableCell) => out.push('\n'),
            _ => {}
        }
    }
    out
}

pub fn excerpt(md: &str, max_chars: usize) -> String {
    let text = plain_text(md);
    let collapsed = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.chars().count() <= max_chars {
        return collapsed;
    }
    let cut: String = collapsed.chars().take(max_chars).collect();
    match cut.rfind(' ') {
        Some(i) if i > max_chars / 2 => format!("{}…", &cut[..i]),
        _ => format!("{cut}…"),
    }
}

pub fn word_count(md: &str) -> i64 {
    plain_text(md).split_whitespace().count() as i64
}

/// Lowercased handles mentioned outside code and links.
pub fn mentions(md: &str) -> Vec<String> {
    let mut found = vec![];
    let mut seen = HashSet::new();
    let mut depth = 0usize;
    for ev in Parser::new_ext(md, options()) {
        match ev {
            Event::Start(Tag::CodeBlock(_) | Tag::Link { .. }) => depth += 1,
            Event::End(TagEnd::CodeBlock | TagEnd::Link) => depth = depth.saturating_sub(1),
            Event::Text(t) if depth == 0 => {
                for (is_mention, s) in split_mentions(&t) {
                    if is_mention && seen.insert(s.clone()) {
                        found.push(s);
                    }
                }
            }
            _ => {}
        }
    }
    found
}

/// Ids of posts this document links to via `/p/{id}` URLs (relative or absolute), including bare
/// URLs in the text.
pub fn post_links(md: &str) -> Vec<String> {
    let mut ids = vec![];
    let mut seen = HashSet::new();
    let mut depth = 0usize;
    for ev in parse(md) {
        let found: Vec<String> = match &ev {
            Event::Start(Tag::Link { dest_url, .. }) => post_id_from_url(dest_url).into_iter().collect(),
            Event::Text(t) if depth == 0 => embed::find_urls(t).into_iter().filter_map(|r| post_id_from_url(&t[r])).collect(),
            _ => vec![],
        };
        match &ev {
            Event::Start(Tag::CodeBlock(_) | Tag::Link { .. }) => depth += 1,
            Event::End(TagEnd::CodeBlock | TagEnd::Link) => depth = depth.saturating_sub(1),
            _ => {}
        }
        for id in found {
            if seen.insert(id.clone()) {
                ids.push(id);
            }
        }
    }
    ids
}

fn post_id_from_url(url: &str) -> Option<String> {
    let path = match url.find("://") {
        Some(i) => &url[i + 3..][url[i + 3..].find('/')?..],
        None => url,
    };
    let rest = path.strip_prefix("/p/")?;
    let id: String = rest.chars().take_while(|c| c.is_ascii_alphanumeric()).collect();
    (id.len() >= 6).then_some(id)
}

/// The byte ranges of a heading's section.
#[derive(Debug, Clone, PartialEq)]
pub struct Section {
    pub level: u8,
    /// Start of the heading line.
    pub heading_start: usize,
    /// Start of the body (after the heading line).
    pub body_start: usize,
    /// End of the section: the next heading of the same or higher level, or end of document.
    pub end: usize,
}

fn normalize_heading(s: &str) -> String {
    s.trim().trim_start_matches('#').trim().to_lowercase()
}

/// Finds a section by heading text (case-insensitive; a leading `## ` is ignored).
pub fn find_section(md: &str, heading: &str) -> Option<Section> {
    let want = normalize_heading(heading);
    let mut headings: Vec<(u8, String, std::ops::Range<usize>)> = vec![];
    let mut current: Option<(u8, String, std::ops::Range<usize>)> = None;
    for (ev, range) in Parser::new_ext(md, options()).into_offset_iter() {
        match ev {
            Event::Start(Tag::Heading { level, .. }) => current = Some((level_num(level), String::new(), range)),
            Event::Text(t) | Event::Code(t) => {
                if let Some((_, text, _)) = current.as_mut() {
                    text.push_str(&t);
                }
            }
            Event::End(TagEnd::Heading(_)) => {
                if let Some(h) = current.take() {
                    headings.push(h);
                }
            }
            _ => {}
        }
    }
    let idx = headings.iter().position(|(_, text, _)| normalize_heading(text) == want)?;
    let (level, _, range) = &headings[idx];
    let mut body_start = range.end;
    // Include the newline that ends the heading line.
    if md[body_start..].starts_with('\n') {
        body_start += 1;
    } else if md[body_start..].starts_with("\r\n") {
        body_start += 2;
    }
    let end = headings[idx + 1..].iter().find(|(l, _, _)| l <= level).map(|(_, _, r)| r.start).unwrap_or(md.len());
    Some(Section { level: *level, heading_start: range.start, body_start: body_start.min(end), end })
}

pub fn heading_titles(md: &str) -> Vec<String> {
    outline(md).into_iter().map(|h| h.text).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_and_sanitizes() {
        let html = render("# Hello\n\n<script>alert(1)</script>\n\nHi @trevor and bob@example.com");
        assert!(html.contains("<h1 id=\"hello\">Hello</h1>"), "{html}");
        assert!(!html.contains("<script>"));
        assert!(html.contains("href=\"/u/trevor\""));
        assert!(!html.contains("/u/example.com"));
    }

    #[test]
    fn duplicate_headings_get_unique_anchors() {
        let o = outline("## Setup\ntext\n## Setup\n");
        assert_eq!(o[0].anchor, "setup");
        assert_eq!(o[1].anchor, "setup-1");
    }

    #[test]
    fn finds_mentions_outside_code() {
        let m = mentions("Ping @Alice, then `@bob` and\n\n```\n@carol\n```\n@dave.");
        assert_eq!(m, vec!["alice", "dave"]);
    }

    #[test]
    fn finds_post_links() {
        let links = post_links("[a](/p/abc123def0/hello) [b](https://x.com/p/zzz999yyy1) [c](/t/abc) https://y.com/p/bare123456/x");
        assert_eq!(links, vec!["abc123def0", "zzz999yyy1", "bare123456"]);
    }

    #[test]
    fn links_bare_urls() {
        let html = render("Open https://example.com/a?b=1&c=2. Email @trevor about `https://not.linked`.");
        assert!(
            html.contains(
                "<a href=\"https://example.com/a?b=1&amp;c=2\" rel=\"noopener noreferrer\">https://example.com/a?b=1&amp;c=2</a>."
            ),
            "{html}"
        );
        assert!(html.contains("href=\"/u/trevor\""), "{html}");
        assert!(html.contains("<code>https://not.linked</code>"), "{html}");
        let html = render("[text](https://a.com) and ![alt https://b.com](https://c.com/i.png)");
        assert_eq!(html.matches("<a ").count(), 1, "{html}");
    }

    #[test]
    fn renders_callouts() {
        let html = render("> [!WARNING]\n> Do not use the oven drawer. It gets hot.\n\n> plain quote");
        assert!(html.contains("<blockquote class=\"md-callout md-callout-warning\">"), "{html}");
        assert!(html.contains("<p class=\"md-callout-title\">Warning</p>"), "{html}");
        assert!(html.contains("<blockquote>\n<p>plain quote</p>"), "{html}");
    }

    #[test]
    fn embeds_provider_links_on_their_own_line() {
        let md = "Watch this:\n\nhttps://youtu.be/9pasx0ghADM\n\n[Making a reservation](https://vimeo.com/896568706/b22f1f7053)\n\nInline https://youtu.be/9pasx0ghADM stays a link.";
        let html = render(md);
        assert_eq!(html.matches("<iframe ").count(), 2, "{html}");
        assert!(html.contains("src=\"https://www.youtube-nocookie.com/embed/9pasx0ghADM\""), "{html}");
        assert!(html.contains("src=\"https://player.vimeo.com/video/896568706?h=b22f1f7053\""), "{html}");
        assert!(html.contains(">Making a reservation</a></figcaption>"), "{html}");
        assert!(html.contains("Inline <a href=\"https://youtu.be/9pasx0ghADM\""), "{html}");
        assert!(!html.contains("ds-embed-"), "{html}");
        // An unknown site on its own line is just a link.
        assert!(!render("https://example.com/watch").contains("<iframe"));
    }

    #[test]
    fn raw_frames_are_stripped() {
        let html = render("<iframe src=\"https://evil.example\"></iframe>\n\n<div id=\"ds-embed-0000000000000000-0\"></div>");
        assert!(!html.contains("<iframe"), "{html}");
    }

    #[test]
    fn finds_sections() {
        let md = "# Title\nintro\n## Setup\nstep one\n### Detail\nmore\n## Usage\nuse it\n";
        let s = find_section(md, "setup").unwrap();
        assert_eq!(&md[s.body_start..s.end], "step one\n### Detail\nmore\n");
        let s = find_section(md, "## Usage").unwrap();
        assert_eq!(&md[s.body_start..s.end], "use it\n");
        assert!(find_section(md, "missing").is_none());
    }

    #[test]
    fn excerpts_are_trimmed() {
        let e = excerpt("# Head\n\nSome **bold** words here that go on and on.", 20);
        assert!(e.ends_with('…'));
        assert!(e.chars().count() <= 21);
    }
}
