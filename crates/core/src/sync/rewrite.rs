//! Markdown from a repository, made into a post: its title (front matter `title:`, a leading
//! `# heading`, or the file name), and its relative links and images pointed at what they became
//! here (posts, uploaded files) or at the repository.

use std::ops::Range;

use pulldown_cmark::{Event, HeadingLevel, LinkType, Options, Parser, Tag, TagEnd};

fn options() -> Options {
    Options::ENABLE_TABLES
        | Options::ENABLE_FOOTNOTES
        | Options::ENABLE_STRIKETHROUGH
        | Options::ENABLE_TASKLISTS
        | Options::ENABLE_HEADING_ATTRIBUTES
        | Options::ENABLE_GFM
}

/// A file name or folder as a title: `getting-started` → `Getting started`.
pub fn humanize(stem: &str) -> String {
    let words = stem.replace(['-', '_'], " ");
    let words = words.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut chars = words.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => "Untitled".into(),
    }
}

/// YAML front matter's `title`, and the Markdown after the front matter.
fn front_matter(md: &str) -> (Option<String>, &str) {
    let Some(rest) = md.strip_prefix("---\n").or_else(|| md.strip_prefix("---\r\n")) else {
        return (None, md);
    };
    let mut at = 0;
    for line in rest.split_inclusive('\n') {
        let bare = line.trim_end();
        if bare == "---" || bare == "..." {
            let yaml = &rest[..at];
            let title = yaml.lines().find_map(|l| l.strip_prefix("title:")).map(|v| {
                let v = v.trim();
                let quoted = v.len() >= 2 && ((v.starts_with('"') && v.ends_with('"')) || (v.starts_with('\'') && v.ends_with('\'')));
                if quoted { v[1..v.len() - 1].to_string() } else { v.to_string() }
            });
            return (title.filter(|t| !t.is_empty()), &rest[at + line.len()..]);
        }
        at += line.len();
    }
    // No closing line: not front matter after all.
    (None, md)
}

/// The post's title and body: the front matter's title, else a leading level-1 heading (taken out
/// of the body, since the post shows its title), else `fallback`. At most 300 characters.
pub fn title_and_body(md: &str, fallback: &str) -> (String, String) {
    let (fm_title, rest) = front_matter(md);
    let mut heading: Option<(String, Range<usize>)> = None;
    let mut iter = Parser::new_ext(rest, options()).into_offset_iter();
    if let Some((Event::Start(Tag::Heading { level: HeadingLevel::H1, .. }), range)) = iter.next() {
        let mut text = String::new();
        for (ev, _) in iter.by_ref() {
            match ev {
                Event::End(TagEnd::Heading(_)) => break,
                Event::Text(t) | Event::Code(t) => text.push_str(&t),
                _ => {}
            }
        }
        heading = Some((text.trim().to_string(), range));
    }
    let (title, body) = match (fm_title, heading) {
        (Some(t), Some((h, range))) if t == h => (t, without(rest, range)),
        (Some(t), _) => (t, rest.to_string()),
        (None, Some((h, range))) if !h.is_empty() => (h, without(rest, range)),
        (None, _) => (fallback.to_string(), rest.to_string()),
    };
    let title: String = title.split_whitespace().collect::<Vec<_>>().join(" ").chars().take(300).collect();
    (if title.is_empty() { fallback.chars().take(300).collect() } else { title }, body)
}

fn without(md: &str, range: Range<usize>) -> String {
    format!("{}{}", &md[..range.start], md[range.end..].trim_start_matches(['\n', '\r']))
}

/// Where a link or image's destination is written in the Markdown.
#[derive(Clone, Debug, PartialEq)]
pub struct Site {
    /// The destination's bytes in the Markdown.
    pub range: Range<usize>,
    pub dest: String,
    pub image: bool,
}

/// The destination of the link or image whose source is `text` (starting at `offset`): it
/// follows the last `](` (or `]:` in a reference definition), maybe in `<…>`. `None` when it's
/// written another way (with escapes, say); such links are left as they are.
fn locate(text: &str, offset: usize, opener: &str, dest: &str) -> Option<Range<usize>> {
    if dest.is_empty() {
        return None;
    }
    let open = text.rfind(opener)? + opener.len();
    let after = &text[open..];
    let skipped = after.len() - after.trim_start().len();
    let mut start = open + skipped;
    if text[start..].starts_with('<') {
        start += 1;
    }
    text[start..].starts_with(dest).then(|| offset + start..offset + start + dest.len())
}

/// Every inline link and image, and every reference definition, with where its destination is.
pub fn sites(md: &str) -> Vec<Site> {
    let iter = Parser::new_ext(md, options()).into_offset_iter();
    let mut out: Vec<Site> = iter
        .reference_definitions()
        .iter()
        .filter_map(|(_, def)| {
            let span = def.span.clone();
            let range = locate(&md[span.clone()], span.start, "]:", &def.dest)?;
            Some(Site { range, dest: def.dest.to_string(), image: false })
        })
        .collect();
    for (ev, range) in iter {
        let (link_type, dest, image) = match ev {
            Event::Start(Tag::Link { link_type, dest_url, .. }) => (link_type, dest_url, false),
            Event::Start(Tag::Image { link_type, dest_url, .. }) => (link_type, dest_url, true),
            _ => continue,
        };
        if link_type != LinkType::Inline {
            // Reference links use their definition's destination, found above; autolinks are absolute.
            continue;
        }
        if let Some(at) = locate(&md[range.clone()], range.start, "](", &dest) {
            out.push(Site { range: at, dest: dest.to_string(), image });
        }
    }
    // An image used through a reference definition is still an image.
    let images: Vec<String> = Parser::new_ext(md, options())
        .filter_map(|ev| match ev {
            Event::Start(Tag::Image { link_type: LinkType::Reference | LinkType::Collapsed | LinkType::Shortcut, dest_url, .. }) => {
                Some(dest_url.to_string())
            }
            _ => None,
        })
        .collect();
    for s in &mut out {
        if !s.image && images.contains(&s.dest) {
            s.image = true;
        }
    }
    out.sort_by_key(|s| s.range.start);
    out.dedup_by_key(|s| s.range.start);
    out
}

/// `md` with each range replaced. Ranges must not overlap.
pub fn replace(md: &str, mut edits: Vec<(Range<usize>, String)>) -> String {
    edits.sort_by_key(|(r, _)| r.start);
    let mut out = String::with_capacity(md.len());
    let mut at = 0;
    for (range, with) in edits {
        if range.start < at {
            continue;
        }
        out.push_str(&md[at..range.start]);
        out.push_str(&with);
        at = range.end;
    }
    out.push_str(&md[at..]);
    out
}

/// Where a relative destination points.
#[derive(Clone, Debug, PartialEq)]
pub enum Target {
    /// A path within the synced folder.
    Inside(String),
    /// A path elsewhere in the repository.
    Repo(String),
}

/// Resolves a destination written in a file in `dir` (within the synced folder `folder`). Returns
/// where it points and its `#fragment` (with the `#`), or `None` for absolute URLs, anchors on the
/// same page, and paths that climb out of the repository.
pub fn resolve(folder: &str, dir: &str, dest: &str) -> Option<(Target, String)> {
    let dest = dest.trim();
    if dest.is_empty() || dest.starts_with('#') || dest.starts_with("//") || has_scheme(dest) {
        return None;
    }
    let (path, fragment) = match dest.find('#') {
        Some(i) => (&dest[..i], dest[i..].to_string()),
        None => (dest, String::new()),
    };
    let path = path.split('?').next().unwrap_or_default();
    if path.is_empty() {
        return None;
    }
    let decoded = urlencoding::decode(path).map(|c| c.into_owned()).unwrap_or_else(|_| path.to_string());
    let joined = match decoded.strip_prefix('/') {
        Some(from_root) => from_root.to_string(),
        None => [folder, dir, &decoded].iter().filter(|s| !s.is_empty()).copied().collect::<Vec<_>>().join("/"),
    };
    let mut parts: Vec<&str> = vec![];
    for seg in joined.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            s => parts.push(s),
        }
    }
    let repo_path = parts.join("/");
    if folder.is_empty() {
        return Some((Target::Inside(repo_path), fragment));
    }
    match repo_path.strip_prefix(folder) {
        Some("") => Some((Target::Inside(String::new()), fragment)),
        Some(rest) if rest.starts_with('/') => Some((Target::Inside(rest[1..].to_string()), fragment)),
        _ => Some((Target::Repo(repo_path), fragment)),
    }
}

fn has_scheme(dest: &str) -> bool {
    match dest.find(':') {
        Some(i) => {
            let scheme = &dest[..i];
            !scheme.is_empty()
                && scheme.starts_with(|c: char| c.is_ascii_alphabetic())
                && scheme.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
        }
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn titles() {
        assert_eq!(title_and_body("# Setup\n\nSteps.\n", "Fallback"), ("Setup".into(), "Steps.\n".into()));
        assert_eq!(title_and_body("Intro\n\n# Later\n", "Install guide"), ("Install guide".into(), "Intro\n\n# Later\n".into()));
        assert_eq!(title_and_body("---\ntitle: \"Deploys\"\nsidebar: 2\n---\nBody\n", "x"), ("Deploys".into(), "Body\n".into()));
        assert_eq!(title_and_body("---\ntitle: Deploys\n---\n# Deploys\n\nBody\n", "x"), ("Deploys".into(), "Body\n".into()));
        assert_eq!(title_and_body("Setext\n======\n\nBody", "x"), ("Setext".into(), "Body".into()));
        assert_eq!(title_and_body("---\nnot closed\n", "x").0, "x");
        assert_eq!(humanize("getting-started_guide"), "Getting started guide");
        assert_eq!(humanize(""), "Untitled");
    }

    #[test]
    fn finds_link_destinations() {
        let md = "See [setup](./setup.md#run) and ![d](img/d.png \"t\").\n[![badge](b.svg)](https://x.test)\n\n[ref]: <../other.md>\n[logo]: logo.png\n\n![Logo][logo] and [r][ref] `[no](code.md)`\n";
        let found: Vec<(String, bool)> = sites(md).into_iter().map(|s| (md[s.range.clone()].to_string(), s.image)).collect();
        assert_eq!(
            found,
            vec![
                ("./setup.md#run".into(), false),
                ("img/d.png".into(), true),
                ("b.svg".into(), true),
                ("https://x.test".into(), false),
                ("../other.md".into(), false),
                ("logo.png".into(), true),
            ]
        );
        let edits = sites(md).into_iter().filter(|s| s.dest.ends_with(".md#run")).map(|s| (s.range, "/p/abc#run".to_string())).collect();
        assert!(replace(md, edits).starts_with("See [setup](/p/abc#run) and"));
    }

    #[test]
    fn resolves_relative_paths() {
        let r = |dir: &str, dest: &str| resolve("docs", dir, dest);
        assert_eq!(r("guides", "../setup.md#x"), Some((Target::Inside("setup.md".into()), "#x".into())));
        assert_eq!(r("", "guides/a%20b.md"), Some((Target::Inside("guides/a b.md".into()), String::new())));
        assert_eq!(r("", "/README.md"), Some((Target::Repo("README.md".into()), String::new())));
        assert_eq!(r("", "/docs/x.md"), Some((Target::Inside("x.md".into()), String::new())));
        assert_eq!(r("", "../src/main.rs"), Some((Target::Repo("src/main.rs".into()), String::new())));
        assert_eq!(r("", "../../../etc/passwd"), None, "out of the repository");
        assert_eq!(r("", "docs2/x.md"), Some((Target::Inside("docs2/x.md".into()), String::new())));
        assert_eq!(resolve("docs", "", "/docs2/x.md"), Some((Target::Repo("docs2/x.md".into()), String::new())));
        for absolute in ["https://x.test/a.md", "mailto:a@b.c", "#top", "//cdn.test/x.png", ""] {
            assert_eq!(r("", absolute), None, "{absolute}");
        }
        assert_eq!(resolve("", "a", "b.md?plain=1"), Some((Target::Inside("a/b.md".into()), String::new())));
    }
}
