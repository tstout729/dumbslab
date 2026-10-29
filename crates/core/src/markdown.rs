//! Markdown is the canonical post format. This module renders it to sanitized HTML and extracts
//! structure (outline, sections, mentions, links to other posts) used across the app.

use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

use pulldown_cmark::{CowStr, Event, HeadingLevel, Options, Parser, Tag, TagEnd};
use schemars::JsonSchema;
use serde::Serialize;

use crate::util::{html_escape, slugify};

fn options() -> Options {
    Options::ENABLE_TABLES
        | Options::ENABLE_FOOTNOTES
        | Options::ENABLE_STRIKETHROUGH
        | Options::ENABLE_TASKLISTS
        | Options::ENABLE_HEADING_ATTRIBUTES
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

/// Renders Markdown to safe HTML: heading anchors, linked `@mentions`, sanitized output.
pub fn render(md: &str) -> String {
    let mut seen: HashMap<String, usize> = HashMap::new();
    let events: Vec<Event> = Parser::new_ext(md, options()).collect();

    // Give every heading an anchor id.
    let mut out_events: Vec<Event> = Vec::with_capacity(events.len());
    let mut i = 0;
    let mut in_code_or_link = 0usize;
    while i < events.len() {
        match &events[i] {
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
            Event::Start(t @ (Tag::CodeBlock(_) | Tag::Link { .. })) => {
                in_code_or_link += 1;
                out_events.push(Event::Start(t.clone()));
            }
            Event::End(t @ (TagEnd::CodeBlock | TagEnd::Link)) => {
                in_code_or_link = in_code_or_link.saturating_sub(1);
                out_events.push(Event::End(*t));
            }
            Event::Text(t) if in_code_or_link == 0 && t.contains('@') => {
                for (is_mention, s) in split_mentions(t) {
                    if is_mention {
                        out_events.push(Event::InlineHtml(CowStr::from(format!(
                            "<a class=\"mention\" href=\"/u/{0}\">@{0}</a>",
                            html_escape(&s)
                        ))));
                    } else {
                        out_events.push(Event::Text(CowStr::from(s)));
                    }
                }
            }
            other => out_events.push(other.clone()),
        }
        i += 1;
    }

    let mut html = String::with_capacity(md.len() * 2);
    pulldown_cmark::html::push_html(&mut html, out_events.into_iter());
    sanitizer().clean(&html).to_string()
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

/// Ids of posts this document links to via `/p/{id}` URLs (relative or absolute).
pub fn post_links(md: &str) -> Vec<String> {
    let mut ids = vec![];
    let mut seen = HashSet::new();
    for ev in Parser::new_ext(md, options()) {
        if let Event::Start(Tag::Link { dest_url, .. }) = ev
            && let Some(id) = post_id_from_url(&dest_url)
            && seen.insert(id.clone())
        {
            ids.push(id);
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
        let links = post_links("[a](/p/abc123def0/hello) [b](https://x.com/p/zzz999yyy1) [c](/t/abc)");
        assert_eq!(links, vec!["abc123def0", "zzz999yyy1"]);
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
